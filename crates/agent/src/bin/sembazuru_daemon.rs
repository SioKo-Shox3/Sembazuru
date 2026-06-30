//! Sembazuru agent daemon (M6.0): the long-lived local agent hosting Coordination,
//! file supply, the Scheduler, LocalIntake, and the loopback Status surface. The
//! runnable core is `sembazuru_agent::run::run_daemon`; this binary is the thin
//! entry point that picks how to run it (M9.3b):
//!
//!   sembazuru-daemon                  run in the foreground (dev/CLI; Ctrl-C stops it)
//!   sembazuru-daemon --service        run under the Windows SCM (set by the installer)
//!   sembazuru-daemon install [--account system|virtual|networkservice]
//!                                     register the auto-start Windows Service (admin)
//!   sembazuru-daemon uninstall        remove the Windows Service (admin)
//!
//! Configuration loads from a TOML file then `SEMBAZURU_*` env vars override it
//! (env > file, M9.3a / ADR 0008 §3), so the dev/CLI workflow keeps working while a
//! Windows Service — which has no per-shell environment — reads its settings from
//! the file:
//!
//!   SEMBAZURU_CONFIG      config file path (default %ProgramData%\Sembazuru\daemon.toml)
//!   SEMBAZURU_COORD / _INTAKE / _FILESERVER / _STATUS   listen addresses
//!   SEMBAZURU_CACHE_ROOT / _TRACE_ROOT / _CLUSTER_TOKEN / _CACHE_MAX_BYTES

use sembazuru_agent::config::DaemonConfig;
use sembazuru_agent::run::run_daemon;
use tokio_util::sync::CancellationToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        #[cfg(windows)]
        Some("install") => {
            let account = parse_account(&args);
            sembazuru_agent::service::install(account)?;
            if let Some(warning) = account.warning() {
                eprintln!("{warning}");
            }
            eprintln!(
                "sembazuru-daemon: installed service '{}' ({account:?}); start it with `sc start {}`",
                sembazuru_agent::service::SERVICE_NAME,
                sembazuru_agent::service::SERVICE_NAME
            );
            Ok(())
        }
        #[cfg(windows)]
        Some("uninstall") => {
            sembazuru_agent::service::uninstall()?;
            eprintln!("sembazuru-daemon: uninstalled service");
            Ok(())
        }
        #[cfg(windows)]
        Some("--service") => Ok(sembazuru_agent::service::run_as_service()?),
        // Seed the default config if absent (run by the MSI; cross-platform).
        Some("seed-config") => seed_config(),
        // Default (and any unrecognized arg): run in the foreground.
        _ => run_cli(),
    }
}

/// Seeds the default `daemon.toml` at the configured path if absent (M9.5d). The MSI
/// runs this as a deferred action so the file exists for discovery / GUI editing.
/// Idempotent (never overwrites an operator-edited file) and never writes the
/// cluster token.
fn seed_config() -> Result<(), BoxError> {
    let path = DaemonConfig::path_from_env();
    let wrote = DaemonConfig::installer_seed().seed_if_absent(&path)?;
    eprintln!(
        "sembazuru-daemon: seed-config {} {}",
        if wrote { "wrote" } else { "kept existing" },
        path.display()
    );
    Ok(())
}

/// `--account <system|virtual|networkservice>`, default Virtual. The daemon reads
/// the developer's source files to serve them; the default virtual account needs
/// ACL grants, while `--account system` is an explicit opt-in that prints a warning
/// (see `service::ServiceAccount`).
#[cfg(windows)]
fn parse_account(args: &[String]) -> sembazuru_agent::service::ServiceAccount {
    use sembazuru_agent::service::ServiceAccount;
    let parsed = args
        .iter()
        .position(|a| a == "--account")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| ServiceAccount::parse(s));
    ServiceAccount::resolve_self_install(parsed)
}

/// Foreground/CLI mode: build a Tokio runtime, run the daemon, and stop it
/// gracefully on Ctrl-C. Dropping the runtime stops the spawned servers.
fn run_cli() -> Result<(), BoxError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let shutdown = CancellationToken::new();
    {
        let s = shutdown.clone();
        runtime.spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("sembazuru-daemon: Ctrl-C received; shutting down");
                s.cancel();
            }
        });
    }
    // CFG-001/SEC-001: a present-but-unreadable/invalid config must NOT silently
    // fall back to auth-disabling defaults — refuse to start so the operator fixes
    // it (an absent file still uses defaults, the common dev case).
    let config = match DaemonConfig::load_effective_checked(&DaemonConfig::path_from_env()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sembazuru-daemon: {e}");
            return Err(e.into());
        }
    };
    let result = runtime.block_on(run_daemon(config, shutdown));
    drop(runtime);
    result
}
