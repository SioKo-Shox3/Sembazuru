//! Sembazuru worker daemon: serves the `Execution` control-plane service and, when
//! pointed at an agent, registers and heartbeats over `Coordination`
//! (`docs/protocol/v0.md` §3.1, ADR 0004). The runnable core is
//! `sembazuru_worker::run::run_worker`; this binary is the thin entry point that
//! picks how to run it (M9.3c):
//!
//!   sembazuru-worker                  run in the foreground (dev/CLI; Ctrl-C stops it)
//!   sembazuru-worker [listen_addr]    same, overriding the configured listen address
//!   sembazuru-worker --service        run under the Windows SCM (set by the installer)
//!   sembazuru-worker install [--account virtual|system|networkservice]
//!                                     register the auto-start Windows Service (admin)
//!   sembazuru-worker uninstall        remove the Windows Service (admin)
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

use std::path::Path;

use sembazuru_worker::config::WorkerConfig;
use sembazuru_worker::run::run_worker;
use tokio_util::sync::CancellationToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        #[cfg(windows)]
        Some("install") => {
            let account = parse_account(&args);
            sembazuru_worker::service::install(account)?;
            eprintln!(
                "sembazuru-worker: installed service '{}' ({account:?}); start it with `sc start {}`",
                sembazuru_worker::service::SERVICE_NAME,
                sembazuru_worker::service::SERVICE_NAME
            );
            Ok(())
        }
        #[cfg(windows)]
        Some("uninstall") => {
            sembazuru_worker::service::uninstall()?;
            eprintln!("sembazuru-worker: uninstalled service");
            Ok(())
        }
        #[cfg(windows)]
        Some("--service") => Ok(sembazuru_worker::service::run_as_service()?),
        // Seed the default config if absent (run by the MSI; cross-platform).
        Some("seed-config") => seed_config(),
        // Default (and a bare `[listen_addr]`): run in the foreground.
        _ => run_cli(),
    }
}

/// Seeds the default `worker.toml` at the configured path if absent (M9.5d). The MSI
/// runs this as a deferred action after the binaries are laid down: it wires the
/// read-VFS paths to the installed hook binaries (resolved from this exe's own
/// directory = the install folder) and the per-machine data roots
/// (`%ProgramData%\Sembazuru`), so a fresh install is distribution-ready with no
/// manual setup. Idempotent (never overwrites an operator-edited file) and never
/// writes the cluster token.
fn seed_config() -> Result<(), BoxError> {
    let path = WorkerConfig::path_from_env();
    let install_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("cannot resolve the install directory from the current exe")?;
    // The data roots live under %ProgramData%\Sembazuru regardless of any config-path
    // override, because the MSI creates them (ACL'd for the worker) there.
    let data_dir = WorkerConfig::default_path()
        .parent()
        .map(Path::to_path_buf)
        .ok_or("cannot resolve the data directory")?;
    let wrote = WorkerConfig::installer_seed(&install_dir, &data_dir).seed_if_absent(&path)?;
    eprintln!(
        "sembazuru-worker: seed-config {} {}",
        if wrote { "wrote" } else { "kept existing" },
        path.display()
    );
    Ok(())
}

/// `--account <virtual|system|networkservice>`, default **Virtual** (least
/// privilege). Unlike the daemon (which reads the developer's source and defaults to
/// System), the worker only injects into its own child compilers and takes inputs
/// over the data plane, so a least-privilege virtual account is the right default
/// (see `service::ServiceAccount`).
#[cfg(windows)]
fn parse_account(args: &[String]) -> sembazuru_worker::service::ServiceAccount {
    use sembazuru_worker::service::ServiceAccount;
    args.iter()
        .position(|a| a == "--account")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| ServiceAccount::parse(s))
        .unwrap_or(ServiceAccount::Virtual)
}

/// Foreground/CLI mode: load the effective config, build a Tokio runtime sized to
/// the worker's capacity, run the worker, and stop it gracefully on Ctrl-C. Dropping
/// the runtime stops the Execution server.
fn run_cli() -> Result<(), BoxError> {
    // Refuse to start on a present-but-corrupt config (CFG-001): silently defaulting
    // would drop the operator's agent/token/VFS settings. An absent file is fine.
    let mut config = WorkerConfig::load_effective_checked(&WorkerConfig::path_from_env())?;
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
