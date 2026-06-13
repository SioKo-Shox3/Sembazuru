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

use sembazuru_agent::coordination::{DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination};
use sembazuru_agent::fileserver::{ServerStats, serve_files_with_stats};
use sembazuru_agent::intake::{resolve_loopback_intake, serve_intake};
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

    // File supply: workers pull inputs on demand over the data plane. Hosted now
    // so the wiring exists; the compile path that exercises it is M6.1.
    let file_listener = tokio::net::TcpListener::bind(&file_addr).await?;
    eprintln!(
        "sembazuru-daemon: file server on {}",
        file_listener.local_addr()?
    );
    {
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(async move {
            if let Err(e) = serve_files_with_stats(file_listener, stats).await {
                eprintln!("sembazuru-daemon: file server exited: {e}");
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
    serve_intake(intake_listener, scheduler).await?;
    Ok(())
}
