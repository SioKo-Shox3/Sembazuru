//! Sembazuru worker daemon: serves the `Execution` control-plane service and,
//! when pointed at an agent, registers and heartbeats over `Coordination`
//! (`docs/protocol/v0.md` §3.1, ADR 0004). Usage:
//!
//! ```text
//! sembazuru-worker [listen_addr]      # default 127.0.0.1:50061
//! ```
//!
//! Configuration loads from a TOML file then `SEMBAZURU_*` env vars override it
//! (env > file, M9.3c / ADR 0008 §3), so the dev/CLI workflow keeps exporting env
//! vars while a Windows Service — which has no per-shell environment — reads its
//! settings from the file:
//!
//!   SEMBAZURU_WORKER_CONFIG   config file path (default %ProgramData%\Sembazuru\worker.toml)
//!   SEMBAZURU_WORKER_LISTEN   Execution listen address
//!   SEMBAZURU_AGENT           agent Coordination endpoint (register for scheduling)
//!   SEMBAZURU_WORKER_ADVERTISE   the routable address the agent should dial
//!   SEMBAZURU_CLUSTER_TOKEN / _CAPACITY / _ACTION_TIMEOUT_SECS
//!   SEMBAZURU_LAUNCHER / _DLL / _SCRATCH_ROOT / _CAS_ROOT   read-VFS install (M6.1)
//!
//! On a multi-host LAN, bind `0.0.0.0:<port>` and set `SEMBAZURU_WORKER_ADVERTISE`
//! (or `advertise` in the file) so the agent dials a routable address rather than
//! the unspecified bind address.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use sembazuru_worker::config::WorkerConfig;
use sembazuru_worker::coordination::{default_worker_id, register_and_heartbeat};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let mut config = WorkerConfig::load_effective(&WorkerConfig::path_from_env());
    // A positional CLI arg overrides the configured listen address (dev convenience;
    // the service has no argv and uses the file/env value).
    if let Some(addr) = std::env::args().nth(1) {
        config.listen_addr = addr;
    }

    // Size the runtime to the worker's capacity (its concurrent actions), with a
    // floor of 2 for the always-on accept/heartbeat work. Too few threads and a
    // high-capacity worker drives its concurrent children near-serially; too many
    // (tokio's default = one per machine core) and a core-pinned worker
    // oversubscribes its cores and steals cycles from the very children it spawns.
    let worker_threads = config.capacity.unwrap_or(2).clamp(2, 64) as usize;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}

async fn run(config: WorkerConfig) -> Result<(), BoxError> {
    let addr: std::net::SocketAddr = config.listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("sembazuru-worker: Execution service on {local}");

    let service = match config.capacity {
        Some(c) => sembazuru_worker::WorkerService::with_capacity(c),
        None => sembazuru_worker::WorkerService::new(),
    }
    .with_action_timeout_secs(config.action_timeout_secs);
    // Enable read-VFS execution (M6.1) when all four install paths are configured.
    let service = match config.vfs() {
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
    // worker announces the endpoint the agent should dial for Execution. A worker
    // with no agent (the legacy loopback mode) just serves Execution and is driven
    // directly.
    if let Some(agent) = config.agent.clone() {
        // The agent dials this endpoint for Execution. Deriving it from the bind
        // address is correct for loopback/single-machine, but an unspecified bind
        // (0.0.0.0) is not routable — the agent would dial 0.0.0.0. Require an
        // explicit advertise address in that case so a LAN deployment cannot
        // silently register a dead endpoint (verifier A3).
        let execution_endpoint = match config.advertise.clone() {
            Some(adv) => adv,
            None if local.ip().is_unspecified() => {
                return Err(format!(
                    "worker bound to unspecified address {local}; set \
                     SEMBAZURU_WORKER_ADVERTISE=http://<host-ip>:{} (or `advertise` in \
                     worker.toml) to the address the agent should dial",
                    local.port()
                )
                .into());
            }
            None => format!("http://{local}"),
        };
        let worker_id = default_worker_id();
        let capacity = service.capacity();
        let running = service.running_handle();
        // No graceful-drain trigger wired yet (process exit ends heartbeats); the
        // flag exists so the M9.3c shutdown path can deregister cleanly.
        let stop = Arc::new(AtomicBool::new(false));
        // Shared cluster token (ADR 0006), presented on Register. Empty when the
        // cluster runs without auth; the agent then accepts unconditionally. Read
        // verbatim from config (== cluster_token_from_env's bytes), never trimmed.
        let auth_token = config.cluster_token.clone().unwrap_or_default();
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
                auth_token,
            )
            .await
            {
                eprintln!("sembazuru-worker: coordination ended: {e}");
            }
        });
    }

    sembazuru_worker::serve_on_listener_with(listener, service).await
}
