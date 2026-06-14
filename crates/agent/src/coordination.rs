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
//! no background thread and no missed-tick bookkeeping.

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

/// One worker's record in the table. `running_actions`/`idle_slots` are the last
/// values the worker pushed on a heartbeat; `last_ping` is when the agent last
/// heard from it (register counts as a ping).
#[derive(Clone, Debug)]
pub struct WorkerEntry {
    pub worker_id: String,
    pub execution_endpoint: String,
    pub caps: Capabilities,
    pub running_actions: u32,
    pub idle_slots: u32,
    last_ping: Instant,
}

/// Shared, cloneable worker registry. Cloning shares the underlying map (the
/// Coordination server and the scheduler hold the same table).
#[derive(Clone)]
pub struct WorkerTable {
    inner: Arc<Mutex<HashMap<String, WorkerEntry>>>,
    dead_timeout: Duration,
}

impl WorkerTable {
    pub fn new(dead_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            dead_timeout,
        }
    }

    /// Insert or refresh a worker on `Register`. Registration resets capacity to
    /// "fully idle" (the worker just (re)joined) and counts as a fresh ping.
    pub fn upsert_register(
        &self,
        worker_id: String,
        execution_endpoint: String,
        caps: Capabilities,
    ) {
        let idle = caps.cpu_count;
        let mut map = self.inner.lock().expect("worker table poisoned");
        map.insert(
            worker_id.clone(),
            WorkerEntry {
                worker_id,
                execution_endpoint,
                caps,
                running_actions: 0,
                idle_slots: idle,
                last_ping: Instant::now(),
            },
        );
    }

    /// Record a heartbeat: refresh capacity and the liveness clock. A ping for an
    /// unknown worker is ignored — registration must come first.
    pub fn on_ping(&self, worker_id: &str, running_actions: u32, idle_slots: u32) {
        let mut map = self.inner.lock().expect("worker table poisoned");
        if let Some(e) = map.get_mut(worker_id) {
            e.running_actions = running_actions;
            e.idle_slots = idle_slots;
            e.last_ping = Instant::now();
        }
    }

    /// Whether a worker is currently live (heard from within `dead_timeout`).
    pub fn is_live(&self, worker_id: &str) -> bool {
        let map = self.inner.lock().expect("worker table poisoned");
        map.get(worker_id)
            .is_some_and(|e| e.last_ping.elapsed() < self.dead_timeout)
    }

    /// Snapshot of the workers eligible for scheduling right now (live only).
    /// The M5.2 scheduler picks from this set.
    pub fn live_snapshot(&self) -> Vec<WorkerEntry> {
        let map = self.inner.lock().expect("worker table poisoned");
        map.values()
            .filter(|e| e.last_ping.elapsed() < self.dead_timeout)
            .cloned()
            .collect()
    }

    /// Count of currently-live workers.
    pub fn live_count(&self) -> usize {
        let map = self.inner.lock().expect("worker table poisoned");
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
        self.table
            .upsert_register(req.worker_id, req.execution_endpoint, caps);
        Ok(Response::new(RegisterResponse {
            protocol_version: PROTOCOL_VERSION,
            accepted: true,
            detail: String::new(),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<Streaming<HeartbeatPing>>,
    ) -> Result<Response<Self::HeartbeatStream>, Status> {
        let mut inbound = request.into_inner();
        let table = self.table.clone();
        let start = self.start;
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            // Each ping refreshes the worker's capacity + liveness clock; the
            // pong only keeps the stream alive (the agent dates liveness by ping
            // arrival, not pong content).
            while let Ok(Some(ping)) = inbound.message().await {
                table.on_ping(&ping.worker_id, ping.running_actions, ping.idle_slots);
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
