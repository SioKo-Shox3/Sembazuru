//! Sembazuru worker daemon: serves the `Execution` control-plane service and,
//! when pointed at an agent, registers and heartbeats over `Coordination`
//! (`docs/protocol/v0.md` §3.1, ADR 0004). Usage:
//!
//! ```text
//! sembazuru-worker [listen_addr]      # default 127.0.0.1:50061
//! # Set SEMBAZURU_AGENT=http://<agent>:<port> to register for scheduling.
//! # On a multi-host LAN, bind 0.0.0.0:<port> and set
//! # SEMBAZURU_WORKER_ADVERTISE=http://<this-host-ip>:<port> so the agent
//! # dials a routable address rather than the unspecified bind address.
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use sembazuru_worker::coordination::{default_worker_id, register_and_heartbeat};
use sembazuru_worker::{WorkerService, WorkerVfsConfig};

/// Read-VFS install config (M6.1), present only when all four paths are set:
///   SEMBAZURU_LAUNCHER      launcher.exe (DetourCreateProcessWithDll injector)
///   SEMBAZURU_DLL           sbz_interceptor64.dll (the hook)
///   SEMBAZURU_SCRATCH_ROOT  per-action hydrated-input scratch trees go here
///   SEMBAZURU_CAS_ROOT      worker-local content store (persisted across builds)
/// Absent → a plain worker that only spawns processes directly (M5 scale).
fn worker_vfs_config() -> Option<WorkerVfsConfig> {
    let launcher = std::env::var_os("SEMBAZURU_LAUNCHER")?;
    let dll = std::env::var_os("SEMBAZURU_DLL")?;
    let scratch_root = std::env::var_os("SEMBAZURU_SCRATCH_ROOT")?;
    let cas_root = std::env::var_os("SEMBAZURU_CAS_ROOT")?;
    Some(WorkerVfsConfig {
        launcher: PathBuf::from(launcher),
        dll: PathBuf::from(dll),
        scratch_root: PathBuf::from(scratch_root),
        cas_root: PathBuf::from(cas_root),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // SEMBAZURU_CAPACITY sets the admission limit; the scale harness sets it to
    // the worker's pinned core count so each worker runs exactly its share in
    // parallel. Unset → available_parallelism (the normal default).
    let capacity = std::env::var("SEMBAZURU_CAPACITY")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&c| c > 0);

    // Size the runtime to the worker's capacity (its concurrent actions), with a
    // floor of 2 for the always-on accept/heartbeat work. Too few threads and a
    // high-capacity worker drives its concurrent children near-serially; too many
    // (tokio's default = one per machine core) and a core-pinned worker
    // oversubscribes its cores and steals cycles from the very children it spawns.
    let worker_threads = capacity.unwrap_or(2).clamp(2, 64) as usize;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;
    runtime.block_on(run(capacity))
}

async fn run(capacity: Option<u32>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:50061".to_string());
    let addr: std::net::SocketAddr = addr.parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("sembazuru-worker: Execution service on {local}");

    let service = match capacity {
        Some(c) => WorkerService::with_capacity(c),
        None => WorkerService::new(),
    };
    // Enable read-VFS execution (M6.1) when the install paths are configured.
    let service = match worker_vfs_config() {
        Some(cfg) => {
            eprintln!(
                "sembazuru-worker: VFS execution enabled (launcher {}, scratch {})",
                cfg.launcher.display(),
                cfg.scratch_root.display()
            );
            service.with_vfs(cfg)
        }
        None => service,
    };

    // If an agent is configured, register and heartbeat in the background. The
    // worker announces the endpoint the agent should dial for Execution — its
    // own listen address. A worker with no agent (the legacy loopback mode)
    // just serves Execution and is driven directly.
    if let Ok(agent) = std::env::var("SEMBAZURU_AGENT") {
        // The agent dials this endpoint for Execution. Deriving it from the bind
        // address is correct for loopback/single-machine, but an unspecified
        // bind (0.0.0.0) is not routable — the agent would dial 0.0.0.0. Require
        // an explicit advertise address in that case so a LAN deployment cannot
        // silently register a dead endpoint (verifier A3).
        let execution_endpoint = match std::env::var("SEMBAZURU_WORKER_ADVERTISE") {
            Ok(adv) => adv,
            Err(_) if local.ip().is_unspecified() => {
                return Err(format!(
                    "worker bound to unspecified address {local}; set \
                     SEMBAZURU_WORKER_ADVERTISE=http://<host-ip>:{} to the \
                     address the agent should dial",
                    local.port()
                )
                .into());
            }
            Err(_) => format!("http://{local}"),
        };
        let worker_id = default_worker_id();
        let capacity = service.capacity();
        let running = service.running_handle();
        // No graceful-drain trigger wired yet (process exit ends heartbeats);
        // the flag exists so a future Ctrl-C handler can deregister cleanly.
        let stop = Arc::new(AtomicBool::new(false));
        eprintln!("sembazuru-worker: registering with agent {agent} as {worker_id}");
        tokio::spawn(async move {
            if let Err(e) = register_and_heartbeat(
                agent,
                worker_id,
                execution_endpoint,
                capacity,
                running,
                Duration::from_secs(5),
                stop,
            )
            .await
            {
                eprintln!("sembazuru-worker: coordination ended: {e}");
            }
        });
    }

    sembazuru_worker::serve_on_listener_with(listener, service).await
}
