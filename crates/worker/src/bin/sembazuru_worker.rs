//! Sembazuru worker daemon: serves the `Execution` control-plane service and, when
//! pointed at an agent, registers and heartbeats over `Coordination`
//! (`docs/protocol/v0.md` §3.1, ADR 0004). The runnable core is
//! `sembazuru_worker::run::run_worker`; this binary is the thin entry point that
//! runs it in the foreground and stops it gracefully on Ctrl-C (M9.3c-b). The
//! Windows Service modes (`install` / `uninstall` / `--service`) are added in
//! M9.3c-c.
//!
//! ```text
//! sembazuru-worker [listen_addr]      # default 127.0.0.1:50061; Ctrl-C stops it
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

use sembazuru_worker::config::WorkerConfig;
use sembazuru_worker::run::run_worker;
use tokio_util::sync::CancellationToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    run_cli()
}

/// Foreground/CLI mode: load the effective config, build a Tokio runtime sized to
/// the worker's capacity, run the worker, and stop it gracefully on Ctrl-C. Dropping
/// the runtime stops the Execution server.
fn run_cli() -> Result<(), BoxError> {
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

    let shutdown = CancellationToken::new();
    {
        let s = shutdown.clone();
        runtime.spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("sembazuru-worker: Ctrl-C received; shutting down");
                s.cancel();
            }
        });
    }

    let result = runtime.block_on(run_worker(config, shutdown));
    drop(runtime);
    result
}
