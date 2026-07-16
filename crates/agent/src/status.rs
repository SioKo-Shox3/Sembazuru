//! Loopback-only daemon status surface (M9.1, ADR 0008 §4).
//!
//! The resident GUI (M9) needs to see the daemon's live operational state: the
//! connected workers and their health, the action-cache hit rate, the in-flight
//! action count, and where actions ran (remote / local / fallback). None of that
//! was exposed before M9 — the worker table, the file server's [`ServerStats`],
//! and the CAS size existed internally but no RPC surfaced them, and the cache
//! hit rate and the exec breakdown were not even counted.
//!
//! This module adds two things:
//!   * [`Metrics`] — the daemon-wide counters the intake path increments (cache
//!     hit/miss, the remote/local/fallback exec breakdown, the in-flight gauge);
//!   * the `Status` gRPC service, which aggregates those counters with the live
//!     [`WorkerTable`], the file-server stats, and the CAS size into one
//!     `GetStatus` snapshot for the GUI.
//!
//! This plane is **loopback-only** (the daemon binds it through
//! [`crate::intake::require_loopback`]) and remains separate from the production
//! LocalIntake authenticated named pipe. It exposes operational state to a
//! same-machine GUI, never to workers, so it stays off the LAN-reachable
//! Coordination port and the GUI needs no cluster token (ADR 0008 §4). Read-only
//! in M9.1; the config/eviction admin RPCs arrive with M9.2/M9.3.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sembazuru_proto::v0::{
    ActionActivity, ActivityExecutionKind as ProtoExecutionKind,
    ActivityState as ProtoActivityState, CacheStatus, ExecBreakdown, FileServerStatus,
    GetConfigRequest, GetConfigResponse, GetStatusRequest, GetStatusResponse, SetConfigRequest,
    SetConfigResponse, TriggerEvictionRequest, TriggerEvictionResponse, WorkerStatus,
    status_server::Status as StatusRpc,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

use crate::Execution;
use crate::action_cache::AgentCache;
use crate::action_tracker::{ActionTracker, ActivityState, ExecutionKind};
use crate::config::{DaemonConfig, DaemonConfigLocation, load_canonical_persisted_without_token};
use crate::coordination::WorkerTable;
use crate::fileserver::ServerStats;

/// Daemon-wide operational counters for the status surface (M9.1). All are
/// monotonic since process start except `in_flight`, a gauge of the actions the
/// daemon is currently driving (moved by [`InFlightGuard`]). These are
/// observe-only — never a correctness signal — so relaxed atomics suffice and no
/// ordering across them is required.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Action-cache hits (a 2nd identical build that skipped the worker).
    pub cache_hits: AtomicU64,
    /// Action-cache misses (cache configured but the lookup did not serve it).
    pub cache_misses: AtomicU64,
    /// Actions that ran remotely on a worker.
    pub exec_remote: AtomicU64,
    /// Actions deliberately kept local by the route-away screen (ADR 0007 §a①).
    pub exec_local: AtomicU64,
    /// Actions that wanted a worker but fell back to local (every remote attempt
    /// failed, or no worker was live).
    pub exec_fallback: AtomicU64,
    /// Successful remote runs skipped for cache record because the worker-resolved
    /// compiler digest did not match the agent-side weak-key digest.
    pub compiler_digest_mismatch: AtomicU64,
    /// Actions submitted but not yet terminal (gauge, moved by [`InFlightGuard`]).
    in_flight: AtomicU64,
}

impl Metrics {
    /// Counts one action-cache hit.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one action-cache miss (the cache was consulted and did not serve).
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one worker/agent compiler digest mismatch at the cache record gate.
    pub fn record_compiler_digest_mismatch(&self) {
        self.compiler_digest_mismatch
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Classifies a completed dispatch into the remote/local/fallback breakdown.
    /// A `LocalFallback` whose reason is a route-away is a *deliberate* local run
    /// (policy, ADR 0007 §a①), not a failure fallback. The distinction is carried by
    /// the typed [`LocalFallbackReason`] (MAINT-001 — previously a fragile
    /// `reason.starts_with("route-away")` string contract).
    ///
    /// [`LocalFallbackReason`]: crate::LocalFallbackReason
    pub fn record_outcome(&self, outcome: &Execution) {
        match outcome {
            Execution::Remote(_) => &self.exec_remote,
            Execution::LocalFallback { reason, .. } if reason.is_route_away() => &self.exec_local,
            Execution::LocalFallback { .. } => &self.exec_fallback,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Marks one action in-flight for the returned guard's lifetime.
    pub fn in_flight_guard(self: &Arc<Self>) -> InFlightGuard {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard(Arc::clone(self))
    }

    /// Current in-flight gauge.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }
}

/// Decrements the in-flight gauge when an action finishes (success, failure, or a
/// dropped task), so the gauge cannot leak a slot. Increment/decrement are
/// balanced by construction — one guard per action — so `fetch_sub` never
/// underflows.
pub struct InFlightGuard(Arc<Metrics>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Everything the `Status` service reads to build a snapshot. Cloneable: it holds
/// shared handles (the worker table, the file-server stats, the metrics, and the
/// optional action cache), so the service and the rest of the daemon observe the
/// same live state.
#[derive(Clone)]
pub struct StatusState {
    /// Live worker registry (shared with Coordination + the scheduler).
    pub table: WorkerTable,
    /// File-server content counters (shared with the data-plane file server).
    pub server_stats: Arc<ServerStats>,
    /// Action cache; `None` when the daemon runs without `SEMBAZURU_CACHE_ROOT`.
    pub cache: Option<Arc<AgentCache>>,
    /// Configured CAS size cap in bytes (`SEMBAZURU_CACHE_MAX_BYTES`); `None` =
    /// uncapped. Drives TriggerEviction and is surfaced for the dashboard (M9.2).
    pub cache_max_bytes: Option<u64>,
    /// Daemon-wide counters (shared with the intake path that feeds them).
    pub metrics: Arc<Metrics>,
    /// Recent redacted execution attempts shared with Scheduler and Intake.
    pub tracker: ActionTracker,
    /// Whether the daemon requires a cluster token (ADR 0006) — surfaced so the
    /// GUI can show the cluster's auth posture.
    pub auth_enabled: bool,
    /// Persisted daemon config identity the GetConfig/SetConfig RPCs read and
    /// write (M9.3a), including canonical-vs-override provenance.
    pub config_location: DaemonConfigLocation,
    /// Whether the **mutating** Status RPCs (`SetConfig`, `TriggerEviction`) are
    /// allowed (SEC-001, ADR 0016). Default **false**: the Status plane is
    /// loopback-TCP with no caller authentication, so a low-privilege local user
    /// could otherwise call `SetConfig` to clear the cluster token (disabling LAN
    /// auth) or rewrite listen addresses. Read-only RPCs (`GetStatus`/`GetConfig`)
    /// stay open. Unlike the production LocalIntake authenticated named pipe,
    /// Status remains a separate loopback-TCP plane, so mutating RPCs are denied
    /// by default and require an operator to opt in via
    /// `SEMBAZURU_STATUS_ADMIN=1` / `status_admin = true`.
    pub admin_enabled: bool,
}

impl StatusState {
    /// Gate for the mutating Status RPCs (SEC-001, ADR 0016). The Status
    /// plane is loopback-TCP with no caller authentication, so `SetConfig`
    /// (which can clear the cluster token / rewrite listen addresses) and
    /// `TriggerEviction` are refused unless an operator explicitly opts in.
    /// LocalIntake uses its production authenticated named pipe; this independent
    /// Status admin boundary remains opt-in and default-deny.
    fn require_admin(&self) -> Result<(), Status> {
        if self.admin_enabled {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "Status admin RPCs are disabled; set SEMBAZURU_STATUS_ADMIN=1 (or \
                 status_admin = true) to enable. The loopback Status plane has no \
                 caller authentication, so config-mutation is opt-in (SEC-001 / ADR 0016).",
            ))
        }
    }

    /// Builds the response from the live state. `cas_size_bytes` is passed in (the
    /// CAS scan is a blocking disk walk, run off the async runtime by the caller).
    fn snapshot(&self, cas_size_bytes: u64) -> GetStatusResponse {
        let workers = self
            .table
            .live_snapshot()
            .into_iter()
            .map(|w| WorkerStatus {
                cpu_count: w.caps.cpu_count,
                os_build: w.caps.os_build.clone(),
                arch: w.caps.arch.clone(),
                running_actions: w.running_actions,
                idle_slots: w.idle_slots,
                last_ping_age_ms: w.last_ping_age().as_millis() as u64,
                healthy: true, // live_snapshot returns only currently-live workers
                // Why this live worker is (or is not) schedulable, for the
                // dashboard. Same source of truth the scheduler enforces, so the
                // displayed reason can never drift from the admission decision
                // (ADR 0011 version-mismatch / ADR 0010 cpu-busy).
                exclusion_reason: crate::scheduler::Scheduler::exclusion_reason(&w).to_string(),
                worker_version: w.caps.worker_version.clone(),
                participation_mode: w.caps.participation_mode.clone(),
                worker_id: w.worker_id,
                execution_endpoint: w.execution_endpoint,
                idle_cpu_pct: w.idle_cpu_pct, // ADR 0010: None when the worker reports no CPU signal
            })
            .collect();

        let m = &self.metrics;
        let activities = self
            .tracker
            .snapshot()
            .into_iter()
            .map(|activity| {
                let identity = format!("{}:{}", activity.key.action_id, activity.key.attempt_no);
                ActionActivity {
                    activity_id: sembazuru_cas::Digest::of(identity.as_bytes()).hex()[..16]
                        .to_owned(),
                    attempt_no: activity.key.attempt_no,
                    worker_id: activity.worker_id,
                    execution_kind: match activity.execution_kind {
                        ExecutionKind::Remote => ProtoExecutionKind::Remote as i32,
                        ExecutionKind::Local => ProtoExecutionKind::Local as i32,
                        ExecutionKind::Fallback => ProtoExecutionKind::Fallback as i32,
                    },
                    display_name: activity.display_name,
                    state: match activity.state {
                        ActivityState::Created => ProtoActivityState::Unknown as i32,
                        ActivityState::Queued => ProtoActivityState::Queued as i32,
                        ActivityState::Preparing => ProtoActivityState::Preparing as i32,
                        ActivityState::Running => ProtoActivityState::Running as i32,
                        ActivityState::Completed => ProtoActivityState::Completed as i32,
                        ActivityState::Failed => ProtoActivityState::Failed as i32,
                        ActivityState::Interrupted => ProtoActivityState::Interrupted as i32,
                    },
                    lane_index: activity.lane_index,
                    started_age_ms: clamp_u128(activity.started_age.as_millis()),
                    finished_age_ms: activity.finished_age.map(|age| clamp_u128(age.as_millis())),
                    duration_us: clamp_u128(activity.duration.as_micros()),
                }
            })
            .collect();
        GetStatusResponse {
            workers,
            cache: Some(CacheStatus {
                enabled: self.cache.is_some(),
                size_bytes: cas_size_bytes,
                hits: m.cache_hits.load(Ordering::Relaxed),
                misses: m.cache_misses.load(Ordering::Relaxed),
                max_bytes: self.cache_max_bytes.unwrap_or(0),
            }),
            in_flight: m.in_flight() as u32,
            exec: Some(ExecBreakdown {
                remote: m.exec_remote.load(Ordering::Relaxed),
                local: m.exec_local.load(Ordering::Relaxed),
                fallback: m.exec_fallback.load(Ordering::Relaxed),
            }),
            fileserver: Some(FileServerStatus {
                read_ops: self.server_stats.read_ops.load(Ordering::Relaxed),
                read_bytes: self.server_stats.read_bytes.load(Ordering::Relaxed),
                inline_bytes: self.server_stats.inline_bytes.load(Ordering::Relaxed),
            }),
            auth_enabled: self.auth_enabled,
            activities,
        }
    }
}

fn clamp_u128(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusTokenStorage {
    Machine,
    Toml,
}

impl StatusTokenStorage {
    fn for_location(location: &DaemonConfigLocation) -> Self {
        match location {
            DaemonConfigLocation::Override(_) => Self::Toml,
            DaemonConfigLocation::Canonical => {
                #[cfg(windows)]
                {
                    Self::Machine
                }
                #[cfg(not(windows))]
                {
                    Self::Toml
                }
            }
        }
    }
}

const MACHINE_TOKEN_READ_DIAGNOSTIC: &str =
    "canonical machine cluster token could not be read; refusing to report auth state";
const MACHINE_TOKEN_SET_DIAGNOSTIC: &str = "canonical cluster token changes are offline-only; stop SembazuruDaemon and SembazuruWorker, then run elevated `sembazuru-storectl rotate-token` with the new token redirected to stdin";
const MACHINE_TOKEN_CLEAR_DIAGNOSTIC: &str = "canonical cluster token changes are offline-only; stop SembazuruDaemon and SembazuruWorker, then run elevated `sembazuru-storectl clear-token`";

fn read_status_config(
    path: &std::path::Path,
    storage: StatusTokenStorage,
    read_machine_presence: impl FnOnce() -> Result<bool, String>,
) -> Result<(DaemonConfig, bool, bool), Status> {
    let file_exists = path.try_exists().map_err(|_| {
        Status::failed_precondition("persisted daemon config presence could not be checked")
    })?;
    let cfg = match storage {
        StatusTokenStorage::Machine => load_canonical_persisted_without_token(path),
        StatusTokenStorage::Toml => DaemonConfig::load_or_refuse(path),
    }
    .map_err(Status::failed_precondition)?;
    let token_set = match storage {
        StatusTokenStorage::Machine => read_machine_presence()
            .map_err(|_| Status::failed_precondition(MACHINE_TOKEN_READ_DIAGNOSTIC))?,
        StatusTokenStorage::Toml => cfg.cluster_token.is_some(),
    };
    Ok((cfg, file_exists, token_set))
}

fn write_status_config(
    path: &std::path::Path,
    storage: StatusTokenStorage,
    req: SetConfigRequest,
    save: impl FnOnce(&DaemonConfig) -> Result<(), String>,
) -> Result<(), Status> {
    if storage == StatusTokenStorage::Machine
        && let Some(token) = req.cluster_token.as_deref()
    {
        return Err(Status::failed_precondition(if token.is_empty() {
            MACHINE_TOKEN_CLEAR_DIAGNOSTIC
        } else {
            MACHINE_TOKEN_SET_DIAGNOSTIC
        }));
    }
    let mut cfg = match storage {
        StatusTokenStorage::Machine => load_canonical_persisted_without_token(path),
        StatusTokenStorage::Toml => DaemonConfig::load_or_refuse(path),
    }
    .map_err(Status::failed_precondition)?;
    let keep = |new: String, old: String| if new.trim().is_empty() { old } else { new };
    cfg.coord_addr = keep(req.coord_addr, cfg.coord_addr);
    cfg.intake_addr = keep(req.intake_addr, cfg.intake_addr);
    cfg.fileserver_addr = keep(req.fileserver_addr, cfg.fileserver_addr);
    cfg.status_addr = keep(req.status_addr, cfg.status_addr);
    cfg.cache_root = empty_to_none(req.cache_root);
    cfg.trace_root = empty_to_none(req.trace_root);
    cfg.cache_max_bytes = (req.cache_max_bytes > 0).then_some(req.cache_max_bytes);
    match storage {
        StatusTokenStorage::Machine => cfg.cluster_token = None,
        StatusTokenStorage::Toml => {
            if let Some(token) = req.cluster_token {
                cfg.cluster_token = empty_to_none(token);
            }
        }
    }
    save(&cfg).map_err(|msg| Status::internal(format!("config write failed: {msg}")))
}

#[cfg(windows)]
fn read_machine_token_presence() -> Result<bool, String> {
    sembazuru_config_store::read_machine_cluster_token()
        .map(|secret| secret.is_some())
        .map_err(|_| MACHINE_TOKEN_READ_DIAGNOSTIC.into())
}

#[cfg(not(windows))]
fn read_machine_token_presence() -> Result<bool, String> {
    Ok(false)
}

#[tonic::async_trait]
impl StatusRpc for StatusState {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        // The CAS size is an O(N-blobs) disk walk (ADR 0003 simple version), so it
        // runs off the async runtime. On any I/O error report size 0 rather than
        // failing the whole status call — the GUI polls this often and a transient
        // hiccup must not blank the dashboard.
        let cas_size = match &self.cache {
            Some(c) => {
                let c = Arc::clone(c);
                tokio::task::spawn_blocking(move || c.cas_size().unwrap_or(0))
                    .await
                    .unwrap_or(0)
            }
            None => 0,
        };
        Ok(Response::new(self.snapshot(cas_size)))
    }

    async fn trigger_eviction(
        &self,
        _request: Request<TriggerEvictionRequest>,
    ) -> Result<Response<TriggerEvictionResponse>, Status> {
        self.require_admin()?;
        match (&self.cache, self.cache_max_bytes) {
            (Some(cache), Some(max)) => {
                let (freed, after) = evict_cache_to_cap(Arc::clone(cache), max)
                    .await
                    .map_err(|e| Status::internal(format!("eviction failed: {e}")))?;
                Ok(Response::new(TriggerEvictionResponse {
                    freed_bytes: freed,
                    size_bytes_after: after,
                    cap_configured: true,
                }))
            }
            // No cache, or no cap configured: nothing to evict. Report the current
            // size (if any) and cap_configured = false so the GUI can explain why.
            (cache, _) => {
                let after = match cache {
                    Some(c) => {
                        let c = Arc::clone(c);
                        tokio::task::spawn_blocking(move || c.cas_size().unwrap_or(0))
                            .await
                            .unwrap_or(0)
                    }
                    None => 0,
                };
                Ok(Response::new(TriggerEvictionResponse {
                    freed_bytes: 0,
                    size_bytes_after: after,
                    cap_configured: false,
                }))
            }
        }
    }

    async fn get_config(
        &self,
        _request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let path = self.config_location.path();
        let storage = StatusTokenStorage::for_location(&self.config_location);
        // Read off the runtime (file I/O). The token is deliberately reduced to a
        // presence bool here — never echo the secret over the wire (M9.3a).
        let (cfg, file_exists, cluster_token_set) = tokio::task::spawn_blocking(move || {
            read_status_config(&path, storage, read_machine_token_presence)
        })
        .await
        .map_err(|e| Status::internal(format!("config read failed: {e}")))??;
        Ok(Response::new(GetConfigResponse {
            config_path: self.config_location.path().to_string_lossy().into_owned(),
            file_exists,
            coord_addr: cfg.coord_addr,
            intake_addr: cfg.intake_addr,
            fileserver_addr: cfg.fileserver_addr,
            status_addr: cfg.status_addr,
            cache_root: cfg.cache_root.unwrap_or_default(),
            trace_root: cfg.trace_root.unwrap_or_default(),
            cache_max_bytes: cfg.cache_max_bytes.unwrap_or(0),
            cluster_token_set,
        }))
    }

    async fn set_config(
        &self,
        request: Request<SetConfigRequest>,
    ) -> Result<Response<SetConfigResponse>, Status> {
        self.require_admin()?;
        let req = request.into_inner();
        let location = self.config_location.clone();
        let storage = StatusTokenStorage::for_location(&location);
        let path = location.path();

        let written_path = tokio::task::spawn_blocking(move || {
            write_status_config(&path, storage, req, |cfg| {
                cfg.save_to_location(&location).map_err(|e| e.to_string())
            })?;
            Ok::<_, Status>(path)
        })
        .await
        .map_err(|e| Status::internal(format!("config write failed: {e}")))??;
        Ok(Response::new(SetConfigResponse {
            ok: true,
            detail: format!(
                "saved to {}; restart the daemon to apply",
                written_path.to_string_lossy()
            ),
        }))
    }
}

/// Maps an empty wire string to `None`, keeping a non-empty value **verbatim**
/// (the convention that an empty optional field means "unset"). Deliberately does
/// NOT trim: the cluster token must round-trip byte-for-byte so the daemon and the
/// worker agree on it (ADR 0006; see `config::empty_to_none`).
fn empty_to_none(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// Evicts `cache` down to `max_bytes` off the async runtime, returning
/// `(freed_bytes, size_bytes_after)` (M9.2 / deferred #8). Shared by the Status
/// `TriggerEviction` RPC and the daemon's periodic sweep so both behave and log
/// identically. Eviction is correctness-safe (see [`AgentCache::evict_to`]).
pub async fn evict_cache_to_cap(
    cache: Arc<AgentCache>,
    max_bytes: u64,
) -> std::io::Result<(u64, u64)> {
    tokio::task::spawn_blocking(move || {
        let freed = cache.evict_to(max_bytes)?;
        let after = cache.cas_size()?;
        std::io::Result::Ok((freed, after))
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Serves the loopback-only `Status` service on an already-bound listener. The
/// daemon binds an explicit loopback port (refused if non-loopback, see
/// [`crate::intake::require_loopback`]); tests bind an ephemeral one.
pub async fn serve_status_service(
    listener: TcpListener,
    state: StatusState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::status_server::StatusServer;

    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(StatusServer::new(state))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActionOutcome;
    use std::sync::atomic::AtomicU64;

    static CONFIG_SEQ: AtomicU64 = AtomicU64::new(0);

    fn status_config_path() -> std::path::PathBuf {
        let seq = CONFIG_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("sbz-status-unit-{}-{seq}", std::process::id()))
            .join("daemon.toml")
    }

    fn write_status_bytes(path: &std::path::Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn blank_set() -> SetConfigRequest {
        SetConfigRequest {
            coord_addr: String::new(),
            intake_addr: String::new(),
            fileserver_addr: String::new(),
            status_addr: String::new(),
            cache_root: String::new(),
            trace_root: String::new(),
            cache_max_bytes: 0,
            cluster_token: None,
        }
    }

    #[test]
    fn canonical_status_get_uses_machine_presence_not_toml() {
        let path = status_config_path();
        write_status_bytes(&path, b"coord_addr = '127.0.0.1:1'\n");

        let (_, _, token_set) =
            read_status_config(&path, StatusTokenStorage::Machine, || Ok(true)).unwrap();
        assert!(token_set);
        let (_, _, token_set) =
            read_status_config(&path, StatusTokenStorage::Machine, || Ok(false)).unwrap();
        assert!(!token_set);
    }

    #[test]
    fn canonical_status_get_rejects_every_legacy_token_form_before_machine_read() {
        for legacy in [
            "cluster_token = 'secret'\n",
            "cluster_token = ''\n",
            "cluster_token = 1\n",
            "[cluster_token]\nvalue = 'secret'\n",
        ] {
            let path = status_config_path();
            write_status_bytes(&path, legacy.as_bytes());
            let reads = AtomicU64::new(0);
            let err = read_status_config(&path, StatusTokenStorage::Machine, || {
                reads.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            })
            .unwrap_err();
            assert_eq!(reads.load(Ordering::Relaxed), 0);
            assert_eq!(err.message(), crate::config::LEGACY_TOKEN_DIAGNOSTIC);
        }
    }

    #[test]
    fn canonical_status_get_fails_closed_on_non_utf8_invalid_toml_read_and_machine_errors() {
        for bytes in [b"\xff".as_slice(), b"coord_addr = [".as_slice()] {
            let path = status_config_path();
            write_status_bytes(&path, bytes);
            assert!(read_status_config(&path, StatusTokenStorage::Machine, || Ok(false)).is_err());
        }
        let unreadable = status_config_path();
        std::fs::create_dir_all(&unreadable).unwrap();
        let err =
            read_status_config(&unreadable, StatusTokenStorage::Machine, || Ok(false)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let invalid = std::path::Path::new("presence\0error");
        let err =
            read_status_config(invalid, StatusTokenStorage::Machine, || Ok(false)).unwrap_err();
        assert_eq!(
            err.message(),
            "persisted daemon config presence could not be checked"
        );
        let path = status_config_path();
        write_status_bytes(&path, b"coord_addr = '127.0.0.1:1'\n");
        let err = read_status_config(&path, StatusTokenStorage::Machine, || {
            Err("machine-secret-source-sentinel".into())
        })
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(!err.message().contains("sentinel"));
    }

    #[test]
    fn canonical_status_keep_saves_only_nonsecret_config() {
        let path = status_config_path();
        write_status_bytes(&path, b"coord_addr = '127.0.0.1:1'\n");
        let mut request = blank_set();
        request.coord_addr = "127.0.0.1:9".into();

        write_status_config(&path, StatusTokenStorage::Machine, request, |cfg| {
            cfg.save_to(&path).map_err(|e| e.to_string())
        })
        .unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("127.0.0.1:9"));
        assert!(!text.contains("cluster_token"));
    }

    #[test]
    fn canonical_status_set_and_clear_reject_mixed_requests_without_byte_change() {
        for token in ["new-secret", ""] {
            let path = status_config_path();
            let original = b"\xff unreadable-before-reject";
            write_status_bytes(&path, original);
            let mut request = blank_set();
            request.coord_addr = "127.0.0.1:9".into();
            request.cluster_token = Some(token.into());

            let err = write_status_config(&path, StatusTokenStorage::Machine, request, |_| {
                panic!("rejected token operation must not save")
            })
            .unwrap_err();

            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
            assert_eq!(
                err.message(),
                if token.is_empty() {
                    MACHINE_TOKEN_CLEAR_DIAGNOSTIC
                } else {
                    MACHINE_TOKEN_SET_DIAGNOSTIC
                }
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }

    #[test]
    fn canonical_status_keep_rejects_legacy_without_rewrite() {
        let path = status_config_path();
        let original = b"cluster_token = 'legacy-secret'\n";
        write_status_bytes(&path, original);

        let err = write_status_config(&path, StatusTokenStorage::Machine, blank_set(), |_| {
            panic!("legacy config must not save")
        })
        .unwrap_err();

        assert_eq!(err.message(), crate::config::LEGACY_TOKEN_DIAGNOSTIC);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn status_token_storage_uses_provenance_not_path_equality() {
        assert_eq!(
            StatusTokenStorage::for_location(&DaemonConfigLocation::Override(
                DaemonConfig::default_path()
            )),
            StatusTokenStorage::Toml
        );
        #[cfg(windows)]
        assert_eq!(
            StatusTokenStorage::for_location(&DaemonConfigLocation::Canonical),
            StatusTokenStorage::Machine
        );
        #[cfg(not(windows))]
        assert_eq!(
            StatusTokenStorage::for_location(&DaemonConfigLocation::Canonical),
            StatusTokenStorage::Toml
        );
    }

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::default())
    }

    #[test]
    fn record_outcome_splits_remote_local_and_fallback() {
        let m = metrics();
        m.record_outcome(&Execution::Remote(ActionOutcome::default()));
        m.record_outcome(&Execution::LocalFallback {
            exit_code: 0,
            reason: crate::LocalFallbackReason::RouteAway("cygwin1.dll".into()),
        });
        m.record_outcome(&Execution::LocalFallback {
            exit_code: 0,
            reason: crate::LocalFallbackReason::NoWorker,
        });
        m.record_outcome(&Execution::LocalFallback {
            exit_code: 0,
            reason: crate::LocalFallbackReason::RemoteExhausted(
                "worker w1 exceeded latency budget".into(),
            ),
        });

        assert_eq!(
            m.exec_remote.load(Ordering::Relaxed),
            1,
            "remote run counted"
        );
        assert_eq!(
            m.exec_local.load(Ordering::Relaxed),
            1,
            "route-away is a deliberate local, not a fallback"
        );
        assert_eq!(
            m.exec_fallback.load(Ordering::Relaxed),
            2,
            "genuine fallbacks (no workers / budget) counted as fallback"
        );
    }

    #[test]
    fn cache_hit_and_miss_counters_move() {
        let m = metrics();
        m.record_cache_hit();
        m.record_cache_hit();
        m.record_cache_miss();
        assert_eq!(m.cache_hits.load(Ordering::Relaxed), 2);
        assert_eq!(m.cache_misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn in_flight_gauge_rises_and_falls_with_guards() {
        let m = metrics();
        assert_eq!(m.in_flight(), 0);
        let g1 = m.in_flight_guard();
        let g2 = m.in_flight_guard();
        assert_eq!(m.in_flight(), 2, "two actions in flight");
        drop(g1);
        assert_eq!(m.in_flight(), 1, "one finished");
        drop(g2);
        assert_eq!(m.in_flight(), 0, "all finished — gauge back to zero");
    }
}
