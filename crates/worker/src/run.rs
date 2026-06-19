//! The worker's runnable core (M9.3c). The setup that used to live in
//! `bin/sembazuru_worker.rs` is here as [`run_worker`] so it can be driven from two
//! entry points — the plain CLI (Ctrl-C → shutdown) and the Windows Service wrapper
//! (SCM Stop → shutdown, M9.3c-c) — and exercised by tests without an SCM. This
//! mirrors the daemon's `sembazuru_agent::run::run_daemon`.
//!
//! Shutdown is a [`CancellationToken`]: the Execution gRPC server is the blocking
//! call and `run_worker` blocks in a `select!` on it vs the token. When the token is
//! cancelled, it sets the heartbeat's stop flag (so the worker stops heartbeating;
//! the agent then ages it out — there is no explicit Deregister RPC in the protocol)
//! and returns. The caller drops the Tokio runtime, which stops the server.
//!
//! In-flight remote actions cut off by an abrupt stop are still correct — the agent's
//! local fallback completes the build (DESIGN §2, non-negotiable #2) — so the worker
//! does NOT wait to drain in-flight actions on shutdown; a stop is always safe.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::WorkerConfig;
use crate::coordination::{default_worker_id, register_and_heartbeat};
use crate::{WorkerService, serve_on_listener_with};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Runs the worker — the Execution service plus (when an agent is configured) a
/// background Coordination register + heartbeat — until `shutdown` is cancelled or
/// the Execution server exits. `config` is the already-resolved effective config
/// (file + env).
pub async fn run_worker(config: WorkerConfig, shutdown: CancellationToken) -> Result<(), BoxError> {
    let addr: std::net::SocketAddr = config.listen_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("sembazuru-worker: Execution service on {local}");

    let service = match config.capacity {
        Some(c) => WorkerService::with_capacity(c),
        None => WorkerService::new(),
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

    // Heartbeat stop flag: cancelling `shutdown` sets it true so the heartbeat loop
    // ends its stream and the worker stops reporting capacity. The agent then ages
    // this worker out on the next dead-timeout (the protocol has no explicit
    // Deregister). Shared with the heartbeat task below.
    let stop = Arc::new(AtomicBool::new(false));

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
        let stop = stop.clone();
        // Shared cluster token (ADR 0006), presented on Register. Empty when the
        // cluster runs without auth; the agent then accepts unconditionally. Read
        // verbatim from config (== cluster_token_from_env's bytes), never trimmed.
        let auth_token = config.cluster_token.clone().unwrap_or_default();
        // Participation policy (ADR 0012, generalizing ADR 0010), resolved from
        // worker.toml / SEMBAZURU_PARTICIPATION_MODE + SEMBAZURU_IDLE_CPU_*
        // (adaptive good neighbour by default).
        let participation = config.participation();
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
                participation,
            )
            .await
            {
                eprintln!("sembazuru-worker: coordination ended: {e}");
            }
        });
    }

    // The Execution server is the blocking server; the worker runs until it exits OR
    // `shutdown` is cancelled (Ctrl-C in CLI mode, SCM Stop in service mode).
    tokio::select! {
        r = serve_on_listener_with(listener, service) => r,
        _ = shutdown.cancelled() => {
            eprintln!("sembazuru-worker: shutdown requested; deregistering and stopping");
            // Signal the heartbeat loop to end its stream (cooperative deregister).
            stop.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run_worker` must return promptly when the shutdown token is cancelled — the
    /// property the Windows Service Stop handler and Ctrl-C both rely on. Uses an
    /// ephemeral loopback port with no agent (no registration), so no admin/SCM and
    /// no network peer are involved.
    #[tokio::test]
    async fn run_worker_returns_when_shutdown_is_cancelled() {
        let config = WorkerConfig {
            listen_addr: "127.0.0.1:0".into(),
            ..WorkerConfig::default()
        };
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run_worker(config, shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();

        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run_worker did not return within 5s of shutdown")
            .expect("run_worker task panicked");
        assert!(res.is_ok(), "run_worker returned an error: {res:?}");
    }

    /// Same, but with an agent configured. The background register/heartbeat dials an
    /// unroutable endpoint and fails on its own; `run_worker`'s shutdown must not
    /// depend on the heartbeat task, so it must still return promptly on cancel.
    #[tokio::test]
    async fn run_worker_with_agent_returns_when_shutdown_is_cancelled() {
        let config = WorkerConfig {
            listen_addr: "127.0.0.1:0".into(),
            // Unroutable agent (TCP discard-ish); the heartbeat task errors out and
            // never blocks shutdown. Loopback bind → advertise derived, not required.
            agent: Some("http://127.0.0.1:1".into()),
            ..WorkerConfig::default()
        };
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run_worker(config, shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();

        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run_worker (with agent) did not return within 5s of shutdown")
            .expect("run_worker task panicked");
        assert!(res.is_ok(), "run_worker returned an error: {res:?}");
    }
}
