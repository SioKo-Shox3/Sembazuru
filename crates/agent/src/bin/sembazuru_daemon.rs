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
//! to. Addresses are taken from the environment so a launcher and a worker can
//! be pointed at the same daemon without code changes:
//!
//!   SEMBAZURU_COORD       Coordination listen addr   (default 127.0.0.1:50070)
//!   SEMBAZURU_INTAKE      LocalIntake listen addr     (default 127.0.0.1:50071)
//!   SEMBAZURU_FILESERVER  file-supply listen addr     (default 127.0.0.1:50072)

use std::sync::Arc;

use sembazuru_agent::action_cache::AgentCache;
use sembazuru_agent::coordination::{DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination};
use sembazuru_agent::fileserver::{ServerStats, serve_files_with_stats};
use sembazuru_agent::intake::{
    IntakeService, IntakeVfsContext, resolve_loopback_intake, serve_intake_service,
};
use sembazuru_agent::scheduler::Scheduler;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let coord_addr = env_or("SEMBAZURU_COORD", "127.0.0.1:50070");
    let intake_addr = env_or("SEMBAZURU_INTAKE", "127.0.0.1:50071");
    let file_addr = env_or("SEMBAZURU_FILESERVER", "127.0.0.1:50072");

    let table = WorkerTable::new(DEFAULT_DEAD_TIMEOUT);
    let scheduler = Scheduler::new(table.clone());

    // Coordination: workers register + heartbeat in. Spawned; the table it fills
    // is shared with the scheduler.
    let coord_listener = tokio::net::TcpListener::bind(&coord_addr).await?;
    eprintln!(
        "sembazuru-daemon: Coordination on {}",
        coord_listener.local_addr()?
    );
    {
        let t = table.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_coordination(coord_listener, t).await {
                eprintln!("sembazuru-daemon: Coordination server exited: {e}");
            }
        });
    }

    // File supply: workers pull inputs on demand over the data plane. The bound
    // address is what VFS-mode workers dial, so capture it for VfsExecution.
    let file_listener = tokio::net::TcpListener::bind(&file_addr).await?;
    let fileserver_addr = file_listener.local_addr()?;
    eprintln!("sembazuru-daemon: file server on {fileserver_addr}");
    {
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(async move {
            if let Err(e) = serve_files_with_stats(file_listener, stats).await {
                eprintln!("sembazuru-daemon: file server exited: {e}");
            }
        });
    }

    // Action cache (M4): a 2nd identical build skips the worker. Opt-in via
    // SEMBAZURU_CACHE_ROOT (persisted across builds); absent → compile without
    // caching. Per-action trace dirs go under SEMBAZURU_TRACE_ROOT (or a temp).
    let cache = match std::env::var_os("SEMBAZURU_CACHE_ROOT") {
        Some(root) => match AgentCache::open(&root) {
            Ok(c) => {
                eprintln!(
                    "sembazuru-daemon: action cache at {}",
                    root.to_string_lossy()
                );
                Some(std::sync::Arc::new(c))
            }
            Err(e) => {
                eprintln!("sembazuru-daemon: action cache disabled (open failed: {e})");
                None
            }
        },
        None => None,
    };
    let trace_root = env_or(
        "SEMBAZURU_TRACE_ROOT",
        &std::env::temp_dir()
            .join("sembazuru-trace")
            .to_string_lossy(),
    );

    // Intake runs submissions under the read-VFS, pointing workers at this
    // daemon's file server. The daemon always has a file server, so VFS is always
    // available; the cache is opt-in above.
    let intake = IntakeService::with_vfs(
        scheduler,
        IntakeVfsContext {
            agent_fileserver: fileserver_addr.to_string(),
            cache,
            scratch_root: std::path::PathBuf::from(trace_root),
        },
    );

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
