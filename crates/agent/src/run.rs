//! The daemon's runnable core (M9.3b). The setup that used to live in
//! `bin/sembazuru_daemon.rs` is here as [`run_daemon`] so it can be driven from
//! two entry points — the plain CLI (Ctrl-C → shutdown) and the Windows Service
//! wrapper (SCM Stop → shutdown) — and exercised by tests without an SCM.
//!
//! Shutdown is a [`CancellationToken`]: the four servers run as spawned tasks and
//! the call blocks in a `select!` on the LocalIntake server vs the token. When the
//! token is cancelled, `run_daemon` returns; the caller then drops the Tokio
//! runtime, which stops the spawned servers. In-flight remote actions that get cut
//! off are still correct — the agent's local fallback completes the build
//! (DESIGN §2) — so an abrupt stop never breaks a build; a fuller per-server drain
//! is a refinement (M7.4 deferred note).

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::action_cache::AgentCache;
use crate::config::DaemonConfig;
use crate::coordination::{DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination_with_token};
use crate::fileserver::{ServerStats, serve_files_with_stats_token};
use crate::intake::{
    IntakeService, IntakeVfsContext, require_loopback, resolve_loopback_intake,
    serve_intake_service,
};
use crate::scheduler::Scheduler;
use crate::status::{StatusState, evict_cache_to_cap, serve_status_service};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Warns loudly when an unauthenticated daemon exposes a LAN-reachable listener:
/// auth disabled **and** a non-loopback bind means any host on the network can
/// register a worker or read the agent's filesystem (ADR 0006; security F1).
/// Loopback, or auth enabled, is fine and says nothing.
fn warn_if_exposed(role: &str, addr: std::net::SocketAddr, auth_enabled: bool) {
    if !auth_enabled && !addr.ip().is_loopback() {
        eprintln!(
            "sembazuru-daemon: WARNING: {role} listens on {addr} (non-loopback) with worker auth \
             DISABLED — any host on this network can reach it. Set a cluster token (config or \
             SEMBAZURU_CLUSTER_TOKEN) on the daemon and every worker to require auth (ADR 0006)."
        );
    }
}

/// Runs the daemon — Coordination + file supply + Scheduler + LocalIntake + the
/// loopback Status surface — until `shutdown` is cancelled or the LocalIntake
/// server exits. `config` is the already-resolved effective config (file + env).
pub async fn run_daemon(config: DaemonConfig, shutdown: CancellationToken) -> Result<(), BoxError> {
    let cluster_token = config.cluster_token.clone();
    eprintln!(
        "sembazuru-daemon: worker auth {}",
        if cluster_token.is_some() {
            "ENABLED (shared token)"
        } else {
            "disabled (LAN-trusted)"
        }
    );

    let table = WorkerTable::new(DEFAULT_DEAD_TIMEOUT);
    let scheduler = Scheduler::new(table.clone());

    // Coordination: workers register + heartbeat in. Spawned; the table it fills
    // is shared with the scheduler.
    let coord_listener = tokio::net::TcpListener::bind(&config.coord_addr).await?;
    eprintln!(
        "sembazuru-daemon: Coordination on {}",
        coord_listener.local_addr()?
    );
    warn_if_exposed(
        "Coordination",
        coord_listener.local_addr()?,
        cluster_token.is_some(),
    );
    {
        let t = table.clone();
        let tok = cluster_token.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_coordination_with_token(coord_listener, t, tok).await {
                eprintln!("sembazuru-daemon: Coordination server exited: {e}");
            }
        });
    }

    // File supply: workers pull inputs on demand over the data plane. The bound
    // address is what VFS-mode workers dial, so capture it for VfsExecution. Stats
    // are shared with the Status surface (M9.1).
    let file_listener = tokio::net::TcpListener::bind(&config.fileserver_addr).await?;
    let fileserver_addr = file_listener.local_addr()?;
    eprintln!("sembazuru-daemon: file server on {fileserver_addr}");
    warn_if_exposed("file server", fileserver_addr, cluster_token.is_some());
    let server_stats = Arc::new(ServerStats::default());
    {
        let stats = server_stats.clone();
        let tok = cluster_token.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_files_with_stats_token(file_listener, stats, tok).await {
                eprintln!("sembazuru-daemon: file server exited: {e}");
            }
        });
    }

    // Action cache (M4): opt-in via config.cache_root. Per-action trace dirs go
    // under trace_root.
    let cache = match &config.cache_root {
        Some(root) => match AgentCache::open(root) {
            Ok(c) => {
                eprintln!("sembazuru-daemon: action cache at {root}");
                Some(Arc::new(c))
            }
            Err(e) => {
                eprintln!("sembazuru-daemon: action cache disabled (open failed: {e})");
                None
            }
        },
        None => None,
    };
    let cache_max_bytes = config.cache_max_bytes;
    if let Some(max) = cache_max_bytes {
        eprintln!("sembazuru-daemon: action cache size cap {max} bytes");
    }
    let trace_root = config.trace_root.clone().unwrap_or_else(|| {
        std::env::temp_dir()
            .join("sembazuru-trace")
            .to_string_lossy()
            .into_owned()
    });

    let intake = IntakeService::with_vfs(
        scheduler,
        IntakeVfsContext {
            agent_fileserver: fileserver_addr.to_string(),
            cache: cache.clone(),
            scratch_root: std::path::PathBuf::from(trace_root),
        },
    );

    // Status surface (M9.1, ADR 0008 §4): loopback-only read-only plane for the
    // GUI; refuses any non-loopback bind.
    let status_sockaddr = require_loopback(&config.status_addr, "Status")?;
    let status_listener = tokio::net::TcpListener::bind(status_sockaddr).await?;
    eprintln!(
        "sembazuru-daemon: Status on {}",
        status_listener.local_addr()?
    );
    {
        let state = StatusState {
            table: table.clone(),
            server_stats: server_stats.clone(),
            cache: cache.clone(),
            cache_max_bytes,
            metrics: intake.metrics(),
            auth_enabled: cluster_token.is_some(),
            config_path: DaemonConfig::path_from_env(),
        };
        tokio::spawn(async move {
            if let Err(e) = serve_status_service(status_listener, state).await {
                eprintln!("sembazuru-daemon: Status server exited: {e}");
            }
        });
    }

    // Periodic CAS eviction sweep (M9.2 / deferred #8): bounds the cache when a cap
    // is configured. Correctness-safe (only ever a miss).
    if let (Some(c), Some(max)) = (cache.clone(), cache_max_bytes) {
        const EVICTION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(EVICTION_INTERVAL);
            loop {
                tick.tick().await;
                match evict_cache_to_cap(c.clone(), max).await {
                    Ok((freed, after)) if freed > 0 => eprintln!(
                        "sembazuru-daemon: cache eviction freed {freed} bytes (now {after} / cap {max})"
                    ),
                    Ok(_) => {}
                    Err(e) => eprintln!("sembazuru-daemon: cache eviction failed: {e}"),
                }
            }
        });
    }

    // LocalIntake: the build front door (loopback-only). This is the blocking
    // server; the daemon runs until the LocalIntake server exits OR `shutdown` is
    // cancelled (Ctrl-C in CLI mode, SCM Stop in service mode).
    let intake_sockaddr = resolve_loopback_intake(&config.intake_addr)?;
    let intake_listener = tokio::net::TcpListener::bind(intake_sockaddr).await?;
    eprintln!(
        "sembazuru-daemon: LocalIntake on {}",
        intake_listener.local_addr()?
    );
    tokio::select! {
        r = serve_intake_service(intake_listener, intake) => r?,
        _ = shutdown.cancelled() => {
            eprintln!("sembazuru-daemon: shutdown requested; stopping");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// `run_daemon` must return promptly when the shutdown token is cancelled —
    /// the property the Windows Service Stop handler and Ctrl-C both rely on. Uses
    /// ephemeral loopback ports (cache disabled) so no admin/SCM is involved.
    #[tokio::test]
    async fn run_daemon_returns_when_shutdown_is_cancelled() {
        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.1:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run_daemon(config, shutdown.clone()));

        // Let the servers bind, then request shutdown.
        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();

        // It must finish quickly (well under the test's patience) and cleanly.
        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run_daemon did not return within 5s of shutdown")
            .expect("run_daemon task panicked");
        assert!(res.is_ok(), "run_daemon returned an error: {res:?}");
    }
}
