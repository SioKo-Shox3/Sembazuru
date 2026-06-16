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
//! Like LocalIntake this plane is **loopback-only** (the daemon binds it through
//! [`crate::intake::require_loopback`]): it exposes operational state to a
//! same-machine GUI, never to workers, so it stays off the LAN-reachable
//! Coordination port and the GUI needs no cluster token (ADR 0008 §4). Read-only
//! in M9.1; the config/eviction admin RPCs arrive with M9.2/M9.3.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sembazuru_proto::v0::{
    CacheStatus, ExecBreakdown, FileServerStatus, GetConfigRequest, GetConfigResponse,
    GetStatusRequest, GetStatusResponse, SetConfigRequest, SetConfigResponse,
    TriggerEvictionRequest, TriggerEvictionResponse, WorkerStatus,
    status_server::Status as StatusRpc,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

use crate::Execution;
use crate::action_cache::AgentCache;
use crate::config::DaemonConfig;
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

    /// Classifies a completed dispatch into the remote/local/fallback breakdown.
    /// A `LocalFallback` whose reason is a route-away is a *deliberate* local run
    /// (policy, ADR 0007 §a①), not a failure fallback; the reason string is the
    /// only place that distinction survives a dispatch, so it is matched here.
    /// Kept in sync with `scheduler::dispatch`, which prefixes every route-away
    /// reason with the literal "route-away".
    pub fn record_outcome(&self, outcome: &Execution) {
        match outcome {
            Execution::Remote(_) => &self.exec_remote,
            Execution::LocalFallback { reason, .. } if reason.starts_with("route-away") => {
                &self.exec_local
            }
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
    /// Whether the daemon requires a cluster token (ADR 0006) — surfaced so the
    /// GUI can show the cluster's auth posture.
    pub auth_enabled: bool,
    /// Path of the persisted daemon config the GetConfig/SetConfig RPCs read and
    /// write (M9.3a). The GUI edits this file; the daemon applies it on next start.
    pub config_path: PathBuf,
}

impl StatusState {
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
                worker_id: w.worker_id,
                execution_endpoint: w.execution_endpoint,
            })
            .collect();

        let m = &self.metrics;
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
        }
    }
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
        let path = self.config_path.clone();
        // Read off the runtime (file I/O). The token is deliberately reduced to a
        // presence bool here — never echo the secret over the wire (M9.3a).
        let (cfg, file_exists) = tokio::task::spawn_blocking(move || {
            let exists = path.exists();
            (DaemonConfig::load_from(&path), exists)
        })
        .await
        .map_err(|e| Status::internal(format!("config read failed: {e}")))?;
        Ok(Response::new(GetConfigResponse {
            config_path: self.config_path.to_string_lossy().into_owned(),
            file_exists,
            coord_addr: cfg.coord_addr,
            intake_addr: cfg.intake_addr,
            fileserver_addr: cfg.fileserver_addr,
            status_addr: cfg.status_addr,
            cache_root: cfg.cache_root.unwrap_or_default(),
            trace_root: cfg.trace_root.unwrap_or_default(),
            cache_max_bytes: cfg.cache_max_bytes.unwrap_or(0),
            cluster_token_set: cfg.cluster_token.is_some(),
        }))
    }

    async fn set_config(
        &self,
        request: Request<SetConfigRequest>,
    ) -> Result<Response<SetConfigResponse>, Status> {
        let path = self.config_path.clone();
        let req = request.into_inner();
        let written_path = tokio::task::spawn_blocking(move || {
            // Start from the existing persisted config so an absent optional field
            // (cluster_token unchanged) and empty addresses keep their stored
            // values — a GUI editing one knob need not re-send everything.
            let mut cfg = DaemonConfig::load_from(&path);
            let keep = |new: String, old: String| if new.trim().is_empty() { old } else { new };
            cfg.coord_addr = keep(req.coord_addr, cfg.coord_addr);
            cfg.intake_addr = keep(req.intake_addr, cfg.intake_addr);
            cfg.fileserver_addr = keep(req.fileserver_addr, cfg.fileserver_addr);
            cfg.status_addr = keep(req.status_addr, cfg.status_addr);
            // Optional fields: an empty value clears them (unset).
            cfg.cache_root = empty_to_none(req.cache_root);
            cfg.trace_root = empty_to_none(req.trace_root);
            cfg.cache_max_bytes = (req.cache_max_bytes > 0).then_some(req.cache_max_bytes);
            // Token: absent = unchanged; present-empty = clear; present-value = set.
            if let Some(t) = req.cluster_token {
                cfg.cluster_token = empty_to_none(t);
            }
            cfg.save_to(&path).map(|()| path)
        })
        .await
        .map_err(|e| Status::internal(format!("config write failed: {e}")))?
        .map_err(|e| Status::internal(format!("config write failed: {e}")))?;
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

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::default())
    }

    #[test]
    fn record_outcome_splits_remote_local_and_fallback() {
        let m = metrics();
        m.record_outcome(&Execution::Remote(ActionOutcome::default()));
        m.record_outcome(&Execution::LocalFallback {
            exit_code: 0,
            reason: "route-away (cygwin1.dll)".into(),
        });
        m.record_outcome(&Execution::LocalFallback {
            exit_code: 0,
            reason: "no live workers".into(),
        });
        m.record_outcome(&Execution::LocalFallback {
            exit_code: 0,
            reason: "worker w1 exceeded latency budget".into(),
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
