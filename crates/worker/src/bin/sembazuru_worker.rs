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

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use sembazuru_worker::WorkerService;
use sembazuru_worker::coordination::{default_worker_id, register_and_heartbeat};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:50061".to_string());
    let addr: std::net::SocketAddr = addr.parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("sembazuru-worker: Execution service on {local}");

    let service = WorkerService::new();

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
