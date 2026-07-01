//! Agent side of the Coordination control plane (`docs/protocol/v0.md` §3.1,
//! ADR 0004). The agent hosts the *server*: workers dial in, `Register` their
//! Execution endpoint + capabilities, and keep a `Heartbeat` stream open pushing
//! live capacity. The [`WorkerTable`] this builds is the single source of truth
//! the M5.2 scheduler reads — `live_snapshot()` returns the workers eligible to
//! receive actions, and a worker that stops heartbeating ages out of that set.
//!
//! Liveness is *derived on read* from the last ping's age rather than tracked by
//! a reaper task: a worker is live iff its last ping is younger than
//! `dead_timeout`. That gives the M5.1 "dead within the timeout" guarantee with
//! no background thread and no missed-tick bookkeeping. Long-dead entries are
//! reaped *opportunistically on register* (M7.4) so the table stays bounded
//! across worker restarts without a background task.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sembazuru_proto::v0::{
    Capabilities, HeartbeatPing, HeartbeatPong, PROTOCOL_VERSION, RegisterRequest,
    RegisterResponse, coordination_server::Coordination,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status, Streaming};

/// Default dead-detection window (ADR 0004): three missed 5 s pings ≈ 15 s. A
/// single late ping does not kill a worker; the agent simply stops scheduling to
/// it once it has been silent this long.
pub const DEFAULT_DEAD_TIMEOUT: Duration = Duration::from_secs(15);

/// One worker's record in the table. `running_actions`/`idle_slots`/`idle_cpu_pct`
/// are the last values the worker pushed on a heartbeat; `last_ping` is when the
/// agent last heard from it (register counts as a ping).
#[derive(Clone, Debug)]
pub struct WorkerEntry {
    pub worker_id: String,
    pub execution_endpoint: String,
    pub caps: Capabilities,
    pub running_actions: u32,
    pub idle_slots: u32,
    /// Smoothed host idle-CPU percent (0-100) from the last heartbeat, the ADR
    /// 0010 "good neighbour" signal. `None` = the worker reports no CPU signal
    /// (pre-0010 binary or the feature disabled); the scheduler then falls back to
    /// its legacy slot-based capacity for this worker.
    pub idle_cpu_pct: Option<u32>,
    last_ping: Instant,
}

impl WorkerEntry {
    /// How long since the agent last heard from this worker (a heartbeat or the
    /// initial register). `last_ping` is private so liveness stays derived in this
    /// module; the status surface (M9.1) needs the age to show per-worker health.
    pub fn last_ping_age(&self) -> Duration {
        self.last_ping.elapsed()
    }
}

/// Shared, cloneable worker registry. Cloning shares the underlying map (the
/// Coordination server and the scheduler hold the same table).
#[derive(Clone)]
pub struct WorkerTable {
    inner: Arc<Mutex<HashMap<String, WorkerEntry>>>,
    dead_timeout: Duration,
}

/// A long-dead entry is reaped after this many `dead_timeout`s, so a daemon that
/// sees many worker restarts (each a new pid → new entry) does not grow the table
/// without bound (M7.4; M5.1 B2). Generous so a briefly-flapping worker is not
/// reaped before it would simply re-register.
const REAP_FACTOR: u32 = 20;

impl WorkerTable {
    pub fn new(dead_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            dead_timeout,
        }
    }

    /// Poison-tolerant lock (M7.4; M5.1 B3). A panic while another thread held the
    /// lock must NOT cascade into taking down the whole Coordination service via
    /// `.expect`. The map's operations are idempotent enough that recovering the
    /// guard and continuing is safe — at worst one entry is mid-update.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, WorkerEntry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert or refresh a worker on `Register`.
    ///
    /// First registrant wins while live: a same-`worker_id` registration with a
    /// different `execution_endpoint` is rejected while the existing entry's
    /// `last_ping` is still inside `dead_timeout`. Phase 5 worker-identity
    /// integrity depends on this because a signed capability binds the
    /// `worker_id` string, and that binding is only meaningful if the
    /// routing-table worker_id-to-endpoint mapping cannot be hijacked by a
    /// same-worker_id re-registration while the real owner is still live.
    ///
    /// Returns `true` when accepted: fresh worker, same-endpoint refresh, or
    /// reclaim after the previous owner is no longer live. Returns `false` for a
    /// live same-id/different-endpoint collision. Registration resets capacity
    /// to "fully idle" (the worker just (re)joined) and counts as a fresh ping.
    pub fn upsert_register(
        &self,
        worker_id: String,
        execution_endpoint: String,
        caps: Capabilities,
    ) -> bool {
        let idle = caps.cpu_count;
        let mut map = self.lock();
        // Opportunistic reaping (M7.4; M5.1 B2): drop long-dead entries so a daemon
        // that sees many worker restarts (each a new pid → a new entry) does not
        // grow the table without bound. Tied to register (rare) rather than a
        // background task, matching the derive-liveness-on-read design. A worker
        // re-registering keeps its own entry fresh (its last_ping is now), so this
        // only removes entries that have been silent far past the dead window.
        let reap_after = self.dead_timeout * REAP_FACTOR;
        map.retain(|_, e| e.last_ping.elapsed() < reap_after);
        if let Some(existing) = map.get(&worker_id)
            && existing.execution_endpoint != execution_endpoint
            && existing.last_ping_age() < self.dead_timeout
        {
            return false; // a live worker already owns this identity with a different endpoint
        }
        map.insert(
            worker_id.clone(),
            WorkerEntry {
                worker_id,
                execution_endpoint,
                caps,
                running_actions: 0,
                idle_slots: idle,
                idle_cpu_pct: None, // no CPU sample until the first heartbeat
                last_ping: Instant::now(),
            },
        );
        true
    }

    /// Record a heartbeat: refresh capacity, the CPU signal, and the liveness
    /// clock. A ping for an unknown worker is ignored — registration must come
    /// first. `idle_cpu_pct` is `None` when the worker reports no CPU signal
    /// (pre-0010 or feature off); it is stored verbatim so the scheduler can tell
    /// "no signal" from a genuine low reading.
    pub fn on_ping(
        &self,
        worker_id: &str,
        running_actions: u32,
        idle_slots: u32,
        idle_cpu_pct: Option<u32>,
    ) {
        let mut map = self.lock();
        if let Some(e) = map.get_mut(worker_id) {
            e.running_actions = running_actions;
            e.idle_slots = idle_slots;
            e.idle_cpu_pct = idle_cpu_pct;
            e.last_ping = Instant::now();
        }
    }

    /// Whether a worker is currently live (heard from within `dead_timeout`).
    pub fn is_live(&self, worker_id: &str) -> bool {
        let map = self.lock();
        map.get(worker_id)
            .is_some_and(|e| e.last_ping.elapsed() < self.dead_timeout)
    }

    /// Snapshot of the workers eligible for scheduling right now (live only).
    /// The M5.2 scheduler picks from this set.
    pub fn live_snapshot(&self) -> Vec<WorkerEntry> {
        let map = self.lock();
        map.values()
            .filter(|e| e.last_ping.elapsed() < self.dead_timeout)
            .cloned()
            .collect()
    }

    /// Count of currently-live workers.
    pub fn live_count(&self) -> usize {
        let map = self.lock();
        map.values()
            .filter(|e| e.last_ping.elapsed() < self.dead_timeout)
            .count()
    }
}

/// The agent's Coordination gRPC service over a shared [`WorkerTable`].
pub struct CoordinationService {
    table: WorkerTable,
    start: Instant,
    /// Configured cluster auth token (ADR 0006). `None` = auth disabled, in
    /// which case `Register` accepts unconditionally (M5/M6 back-compat).
    expected_token: Option<String>,
}

impl CoordinationService {
    /// Builds the service with auth **disabled** (M5/M6 LAN back-compat). The
    /// daemon enables auth explicitly via [`serve_coordination_with_token`] with
    /// the env-configured token; this default keeps tests/harnesses unauthenticated
    /// without depending on the process environment.
    pub fn new(table: WorkerTable) -> Self {
        Self::with_token(table, None)
    }

    /// Builds the service with an explicit expected token (`None` = auth
    /// disabled). Tests use this to exercise accept/reject without touching the
    /// process environment.
    pub fn with_token(table: WorkerTable, expected_token: Option<String>) -> Self {
        Self {
            table,
            start: Instant::now(),
            expected_token,
        }
    }
}

#[tonic::async_trait]
impl Coordination for CoordinationService {
    type HeartbeatStream = ReceiverStream<Result<HeartbeatPong, Status>>;

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        if req.worker_id.is_empty() {
            return Err(Status::invalid_argument("worker_id is required"));
        }
        if req.execution_endpoint.is_empty() {
            return Err(Status::invalid_argument("execution_endpoint is required"));
        }
        // Shared-token auth (ADR 0006). With a cluster token configured, a worker
        // presenting the wrong/no token is rejected here — this closes the
        // unauthenticated-Register path that let a rogue worker inject wrong
        // results or black-hole actions (deferred M5.2/M5.5, M6.1). With no token
        // configured this is a no-op accept (M5/M6 LAN back-compat). The reason
        // is a fixed safe string (no secret, no internal path; M7 §5).
        if let Err(reason) =
            sembazuru_proto::auth::check(self.expected_token.as_deref(), &req.auth_token)
        {
            return Ok(Response::new(RegisterResponse {
                protocol_version: PROTOCOL_VERSION,
                accepted: false,
                detail: reason.to_string(),
            }));
        }
        let caps = req.caps.unwrap_or_default();
        let accepted = self
            .table
            .upsert_register(req.worker_id, req.execution_endpoint, caps);
        Ok(Response::new(RegisterResponse {
            protocol_version: PROTOCOL_VERSION,
            accepted,
            detail: if accepted {
                String::new()
            } else {
                "worker_id already registered with a different execution endpoint".to_string()
            },
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<Streaming<HeartbeatPing>>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        let mut inbound = request.into_inner();
        let table = self.table.clone();
        let expected_token = self.expected_token.clone();
        let start = self.start;
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            // Each ping refreshes the worker's capacity + liveness clock; the
            // pong only keeps the stream alive (the agent dates liveness by ping
            // arrival, not pong content).
            while let Ok(Some(ping)) = inbound.message().await {
                if sembazuru_proto::auth::check(expected_token.as_deref(), &ping.auth_token)
                    .is_err()
                {
                    break;
                }
                table.on_ping(
                    &ping.worker_id,
                    ping.running_actions,
                    ping.idle_slots,
                    ping.idle_cpu_pct,
                );
                let pong = HeartbeatPong {
                    agent_monotonic_us: u64::try_from(start.elapsed().as_micros())
                        .unwrap_or(u64::MAX),
                };
                if tx.send(Ok(pong)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Serves the `Coordination` service on an already-bound listener, populating
/// `table` as workers register and heartbeat. Mirrors the worker's
/// `serve_on_listener` (ephemeral-port-friendly for tests and the daemon). Auth
/// **disabled** — the daemon uses [`serve_coordination_with_token`] with the
/// env-configured token (ADR 0006); this plain form is for tests/harnesses.
pub async fn serve_coordination(
    listener: TcpListener,
    table: WorkerTable,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_coordination_with_token(listener, table, None).await
}

/// Like [`serve_coordination`] but with an explicit expected token (`None` =
/// auth disabled). Lets tests stand up an authenticated server deterministically
/// without mutating the process-global environment.
pub async fn serve_coordination_with_token(
    listener: TcpListener,
    table: WorkerTable,
    expected_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::coordination_server::CoordinationServer;

    let svc = CoordinationService::with_token(table, expected_token);
    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(Duration::from_secs(20)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .add_service(CoordinationServer::new(svc))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(cpu: u32) -> Capabilities {
        Capabilities {
            cpu_count: cpu,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn reaper_drops_long_dead_entries_on_register() {
        // Tiny dead window so the reap threshold (dead_timeout * REAP_FACTOR) is
        // short enough to test without a long sleep.
        let table = WorkerTable::new(Duration::from_millis(5));
        table.upsert_register("old".into(), "http://old".into(), caps(4));
        // Wait past the reap threshold.
        tokio::time::sleep(Duration::from_millis(5 * u64::from(REAP_FACTOR) + 60)).await;
        // A new registration triggers the opportunistic reap of the dead "old".
        table.upsert_register("new".into(), "http://new".into(), caps(4));

        let map = table.lock();
        assert!(!map.contains_key("old"), "long-dead entry must be reaped");
        assert!(map.contains_key("new"), "the fresh entry remains");
        assert_eq!(
            map.len(),
            1,
            "table is bounded, not growing across restarts"
        );
    }

    #[test]
    fn upsert_register_rejects_live_worker_id_collision() {
        let table = WorkerTable::new(Duration::from_secs(15));

        assert!(table.upsert_register("w".into(), "http://real".into(), caps(2)));
        assert!(!table.upsert_register("w".into(), "http://attacker".into(), caps(2)));

        let map = table.lock();
        let entry = map.get("w").expect("worker entry remains registered");
        assert_eq!(entry.execution_endpoint, "http://real");
    }

    #[test]
    fn upsert_register_allows_same_endpoint_reregistration() {
        let table = WorkerTable::new(Duration::from_secs(15));

        assert!(table.upsert_register("w".into(), "http://a".into(), caps(2)));
        assert!(table.upsert_register("w".into(), "http://a".into(), caps(2)));
    }

    #[tokio::test]
    async fn upsert_register_allows_reclaiming_after_the_owner_goes_dead() {
        let table = WorkerTable::new(Duration::from_millis(30));

        assert!(table.upsert_register("w".into(), "http://old".into(), caps(2)));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(table.upsert_register("w".into(), "http://new".into(), caps(2)));

        let map = table.lock();
        let entry = map.get("w").expect("worker entry remains registered");
        assert_eq!(entry.execution_endpoint, "http://new");
    }

    #[tokio::test]
    async fn register_rpc_rejects_worker_id_collision() {
        let table = WorkerTable::new(Duration::from_secs(15));
        let service = CoordinationService::new(table);

        let first = service
            .register(Request::new(RegisterRequest {
                worker_id: "w".into(),
                caps: Some(caps(2)),
                execution_endpoint: "http://real".into(),
                auth_token: String::new(),
            }))
            .await
            .expect("first register succeeds")
            .into_inner();
        assert!(first.accepted);

        let second = service
            .register(Request::new(RegisterRequest {
                worker_id: "w".into(),
                caps: Some(caps(2)),
                execution_endpoint: "http://attacker".into(),
                auth_token: String::new(),
            }))
            .await
            .expect("second register returns a response")
            .into_inner();

        assert!(!second.accepted);
        assert_eq!(
            second.detail,
            "worker_id already registered with a different execution endpoint"
        );
    }

    #[test]
    fn poison_tolerant_lock_recovers_after_a_panic() {
        // A panic while holding the lock poisons the mutex; the next access must
        // recover the guard, not cascade the panic (M5.1 B3).
        let table = WorkerTable::new(Duration::from_secs(15));
        let t2 = table.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = t2.lock();
            panic!("poison the mutex while holding it");
        }));
        // The table is still usable: this would panic on a poisoned `.expect`.
        table.upsert_register("w".into(), "http://w".into(), caps(2));
        assert!(table.is_live("w"));
    }
}
