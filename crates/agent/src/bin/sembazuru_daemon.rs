//! Sembazuru agent daemon (M6.0): the long-lived local agent. One process hosts
//! the four pieces a real build needs, where M5's `scale_harness` only stood up
//! Coordination + Scheduler for a benchmark:
//!
//!   - **Coordination** — workers dial in to register and heartbeat (worker ->
//!     agent push, ADR 0004).
//!   - **File supply** — workers pull inputs on demand over the data plane.
//!   - **Scheduler** — places each action across the live workers.
//!   - **LocalIntake** — build-system launchers submit actions over loopback.
//!
//! The single-shot `sembazuru-agent` CLI (M3.1) runs one command against one
//! explicit worker; this daemon is the production front door the launcher talks
//! to. Configuration loads from a TOML file then the `SEMBAZURU_*` environment
//! variables override individual fields (**env > file**, M9.3a / ADR 0008 §3), so
//! the dev/CLI workflow (export env vars) keeps working while a Windows Service —
//! which has no per-shell environment — reads its settings from the file:
//!
//!   SEMBAZURU_CONFIG      config file path (default %ProgramData%\Sembazuru\daemon.toml)
//!   SEMBAZURU_COORD       Coordination listen addr   (default 127.0.0.1:50070)
//!   SEMBAZURU_INTAKE      LocalIntake listen addr     (default 127.0.0.1:50071)
//!   SEMBAZURU_FILESERVER  file-supply listen addr     (default 127.0.0.1:50072)
//!   SEMBAZURU_STATUS      Status (GUI) listen addr    (default 127.0.0.1:50073,
//!                         loopback-only — the resident GUI reads it, M9.1)
//!   SEMBAZURU_CACHE_ROOT / _TRACE_ROOT / _CLUSTER_TOKEN / _CACHE_MAX_BYTES

use std::sync::Arc;

use sembazuru_agent::action_cache::AgentCache;
use sembazuru_agent::config::DaemonConfig;
use sembazuru_agent::coordination::{
    DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination_with_token,
};
use sembazuru_agent::fileserver::{ServerStats, serve_files_with_stats_token};
use sembazuru_agent::intake::{
    IntakeService, IntakeVfsContext, require_loopback, resolve_loopback_intake,
    serve_intake_service,
};
use sembazuru_agent::scheduler::Scheduler;
use sembazuru_agent::status::{StatusState, evict_cache_to_cap, serve_status_service};

/// Warns loudly when an unauthenticated daemon exposes a LAN-reachable listener:
/// auth disabled **and** a non-loopback bind means any host on the network can
/// register a worker or read the agent's filesystem (ADR 0006; security F1).
/// Loopback, or auth enabled, is fine and says nothing.
fn warn_if_exposed(role: &str, addr: std::net::SocketAddr, auth_enabled: bool) {
    if !auth_enabled && !addr.ip().is_loopback() {
        eprintln!(
            "sembazuru-daemon: WARNING: {role} listens on {addr} (non-loopback) with worker auth \
             DISABLED — any host on this network can reach it. Set SEMBAZURU_CLUSTER_TOKEN on the \
             daemon and every worker to require authentication (ADR 0006)."
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Effective config = the persisted file (if any) with SEMBAZURU_* env vars
    // overlaid on top (env > file, M9.3a). The file is the source for a Windows
    // Service (no env); the env keeps the dev/CLI workflow unchanged.
    let config_path = DaemonConfig::path_from_env();
    let config = DaemonConfig::load_effective(&config_path);
    let coord_addr = config.coord_addr.clone();
    let intake_addr = config.intake_addr.clone();
    let file_addr = config.fileserver_addr.clone();
    let status_addr = config.status_addr.clone();

    // Shared cluster token (ADR 0006). When set, workers must present it on both
    // the control plane (Register) and the data-plane handshake; when unset the
    // daemon runs unauthenticated (M5/M6 LAN behaviour). Distributed out-of-band
    // via the config file or SEMBAZURU_CLUSTER_TOKEN to the daemon and every worker.
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
    let coord_listener = tokio::net::TcpListener::bind(&coord_addr).await?;
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
    // address is what VFS-mode workers dial, so capture it for VfsExecution.
    let file_listener = tokio::net::TcpListener::bind(&file_addr).await?;
    let fileserver_addr = file_listener.local_addr()?;
    eprintln!("sembazuru-daemon: file server on {fileserver_addr}");
    warn_if_exposed("file server", fileserver_addr, cluster_token.is_some());
    // Stats are shared with the Status surface (M9.1) so the GUI can see the
    // content bytes pushed over the data plane (≈0 on a cache-hit rebuild, M4).
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

    // Action cache (M4): a 2nd identical build skips the worker. Opt-in via the
    // config's cache_root (SEMBAZURU_CACHE_ROOT), persisted across builds; absent
    // → compile without caching. Per-action trace dirs go under trace_root.
    let cache = match &config.cache_root {
        Some(root) => match AgentCache::open(root) {
            Ok(c) => {
                eprintln!("sembazuru-daemon: action cache at {root}");
                Some(std::sync::Arc::new(c))
            }
            Err(e) => {
                eprintln!("sembazuru-daemon: action cache disabled (open failed: {e})");
                None
            }
        },
        None => None,
    };
    // Optional CAS size cap (M9.2 / deferred #8). When set, the daemon evicts the
    // action cache down to this many bytes — on a periodic sweep below, and on a
    // GUI-driven Status TriggerEviction. Without a cap a long-lived daemon's cache
    // grows until the disk does (the #8 hazard). Eviction is correctness-safe: a
    // wrongly-evicted blob only causes a later cache miss (re-run), never a wrong
    // result.
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

    // Intake runs submissions under the read-VFS, pointing workers at this
    // daemon's file server. The daemon always has a file server, so VFS is always
    // available; the cache is opt-in above.
    let intake = IntakeService::with_vfs(
        scheduler,
        IntakeVfsContext {
            agent_fileserver: fileserver_addr.to_string(),
            cache: cache.clone(),
            scratch_root: std::path::PathBuf::from(trace_root),
        },
    );

    // Status surface (M9.1, ADR 0008 §4): a loopback-only, read-only plane the
    // resident GUI polls for worker health, cache hit rate, in-flight actions,
    // and the remote/local/fallback breakdown. Like LocalIntake it refuses any
    // non-loopback bind — it exposes operational state to a same-machine GUI, not
    // to workers, so it never rides the LAN-reachable Coordination port. It shares
    // the live worker table, the file-server stats, the action cache, and the
    // intake's metrics, so the GUI sees exactly what the daemon is doing.
    let status_sockaddr = require_loopback(&status_addr, "Status")?;
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
            config_path: config_path.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = serve_status_service(status_listener, state).await {
                eprintln!("sembazuru-daemon: Status server exited: {e}");
            }
        });
    }

    // Periodic CAS eviction sweep (M9.2 / deferred #8): a long-lived daemon's
    // action cache would otherwise grow until the disk fills. With a cap set, the
    // daemon sweeps the cache down to it on an interval (the first tick fires at
    // startup, cleaning up after a prior run); the GUI can also force it now via
    // the Status TriggerEviction RPC. Eviction is correctness-safe — only ever a
    // miss, never a wrong result — so this never threatens the determinism gate.
    if let (Some(c), Some(max)) = (cache.clone(), cache_max_bytes) {
        const EVICTION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(EVICTION_INTERVAL);
            loop {
                tick.tick().await;
                match evict_cache_to_cap(c.clone(), max).await {
                    Ok((freed, after)) if freed > 0 => eprintln!(
                        "sembazuru-daemon: cache eviction freed {freed} bytes \
                         (now {after} / cap {max})"
                    ),
                    Ok(_) => {}
                    Err(e) => eprintln!("sembazuru-daemon: cache eviction failed: {e}"),
                }
            }
        });
    }

    // LocalIntake: the blocking server. The daemon runs until killed; the
    // launcher submits actions here over loopback. Intake runs arbitrary
    // submitted commands and is unauthenticated (M7), so it is refused on any
    // non-loopback address — unlike Coordination/the file server, it never needs
    // LAN reach (the launcher only dials 127.0.0.1).
    let intake_sockaddr = resolve_loopback_intake(&intake_addr)?;
    let intake_listener = tokio::net::TcpListener::bind(intake_sockaddr).await?;
    eprintln!(
        "sembazuru-daemon: LocalIntake on {}",
        intake_listener.local_addr()?
    );
    serve_intake_service(intake_listener, intake).await?;
    Ok(())
}
