//! Windows Service wrapper for `sembazuru-daemon` (M9.3b, ADR 0008 §3).
//!
//! The same binary runs three ways: the plain CLI (dev/fallback), as a Windows
//! Service when the SCM launches it with `--service`, and as the `install` /
//! `uninstall` admin commands. The daemon's runnable core is [`crate::run::run_daemon`];
//! this module is only the SCM glue — the dispatcher, the Stop handler that
//! cancels the shutdown token, the StartPending → Running → Stopped status
//! reporting, and `ServiceManager`-based install/uninstall.
//!
//! Windows-only (`#[cfg(windows)]`). The actual SCM lifecycle (install → auto-start
//! → stop) requires Administrator and is verified on a real machine, not in
//! `cargo test`; the testable parts (config loading, the shutdown token returning
//! `run_daemon`, account parsing) live in `config.rs` / `run.rs` and the tests.

use std::ffi::OsString;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::DaemonConfig;
use crate::run::run_daemon;

/// The service's registered name (used by the SCM and `sc.exe`).
pub const SERVICE_NAME: &str = "SembazuruDaemon";
/// Human-readable name shown in services.msc.
pub const DISPLAY_NAME: &str = "Sembazuru Build Daemon";
/// The launch argument the installer registers so the SCM-started process runs as
/// a service rather than the plain CLI.
pub const SERVICE_ARG: &str = "--service";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

fn fatal_service_exit_code() -> ServiceExitCode {
    ServiceExitCode::ServiceSpecific(1)
}

fn daemon_service_exit_code<E>(result: Result<(), E>) -> ServiceExitCode {
    match result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => fatal_service_exit_code(),
    }
}

/// SCM entry point (runs on a background thread). There is no console in service
/// context; diagnostics go to stderr (Event Log integration is a future refinement).
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("sembazuru-daemon: service failed: {e}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let shutdown = CancellationToken::new();

    // The SCM Stop/Shutdown handler signals the async daemon to stop. It runs on a
    // separate (non-async) thread; `CancellationToken::cancel` is sync and
    // thread-safe, so this is the clean cross-thread bridge.
    let handler_shutdown = shutdown.clone();
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_shutdown.cancel();
                ServiceControlHandlerResult::NoError
            }
            // Every service must answer Interrogate (a no-op status report).
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let set = |state, accept, wait_hint, exit_code| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
    };

    // StartPending with a generous wait hint (binding a few listeners is fast; the
    // hint keeps the SCM's ~30s start timer from firing).
    set(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(10),
        ServiceExitCode::Win32(0),
    )?;

    // A multi-thread Tokio runtime on this SCM thread runs the daemon. A service
    // has no per-shell env, so config comes from the file (+ any env), M9.3a.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sembazuru-daemon: runtime build failed: {e}");
            set(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::default(),
                fatal_service_exit_code(),
            )?;
            return Ok(());
        }
    };

    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
        ServiceExitCode::Win32(0),
    )?;

    let config = DaemonConfig::load_effective(&DaemonConfig::path_from_env());
    let result = runtime.block_on(run_daemon(config, shutdown));
    // Dropping the runtime stops the spawned servers.
    drop(runtime);
    let exit_code = daemon_service_exit_code(result.as_ref().map(|_| ()));
    if let Err(e) = result {
        eprintln!("sembazuru-daemon: daemon exited with error: {e}");
    }

    set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
        exit_code,
    )?;
    Ok(())
}

/// Runs the SCM dispatcher; called when the SCM launches the binary with
/// `--service`. Blocks until the service stops.
pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// The account the service runs under. The daemon (the agent) READS the
/// developer's source tree to serve it to workers, so it needs read access to
/// those files. The self-install default is `Virtual` (least privilege; needs ACL
/// grants to read the served source roots). `System` can read everything but is an
/// explicit, security-discouraged opt-in. NetworkService is also available for
/// operators who grant the needed source-root access (ADR 0008 §3 /
/// edr-allowlist). The worker — which only injects into its own child compilers
/// (unprivileged) and reads inputs over the data plane — can run least-privilege
/// without that caveat (handled when the worker is serviced).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccount {
    /// LocalSystem (`account_name = None`). Reads all files; most powerful.
    System,
    /// Virtual service account `NT SERVICE\SembazuruDaemon` (least privilege; needs
    /// ACL grants to read the served source roots).
    Virtual,
    /// `NT AUTHORITY\NetworkService` (low privilege, machine network credentials).
    NetworkService,
}

impl ServiceAccount {
    /// Parses an `--account` value; `None` for an unrecognized string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "system" | "localsystem" => Some(Self::System),
            "virtual" => Some(Self::Virtual),
            "networkservice" | "network" => Some(Self::NetworkService),
            _ => None,
        }
    }

    /// Resolves the self-install account default. The default is the
    /// least-privilege virtual account (`NT SERVICE\SembazuruDaemon`); LocalSystem
    /// (`--account system`) is an explicit, discouraged opt-in.
    pub fn resolve_self_install(parsed: Option<ServiceAccount>) -> ServiceAccount {
        parsed.unwrap_or(ServiceAccount::Virtual)
    }

    /// Returns the service-account warning shown by self-install.
    pub fn warning(self) -> Option<&'static str> {
        match self {
            Self::System => Some(concat!(
                "WARNING: installing SembazuruDaemon as LocalSystem.\n",
                "Running the daemon as LocalSystem means a local low-privilege user who can ",
                "reach LocalIntake could cause SYSTEM-level local-fallback command execution ",
                "(privilege escalation).\n",
                "Prefer the default virtual account. Never use System unless you understand ",
                "the risk and have other mitigations."
            )),
            Self::Virtual | Self::NetworkService => None,
        }
    }

    fn account_name(self) -> Option<OsString> {
        match self {
            Self::System => None,
            Self::Virtual => Some(OsString::from(format!("NT SERVICE\\{SERVICE_NAME}"))),
            Self::NetworkService => Some(OsString::from("NT AUTHORITY\\NetworkService")),
        }
    }
}

/// Installs the daemon as an auto-start Windows Service that runs this binary with
/// `--service`. `account` selects the service identity. Requires Administrator
/// (`CREATE_SERVICE`). The WiX installer (M9.5) is the production path; this
/// self-install exists for dev/test (ADR 0008). No other persistence is created —
/// just this one service (edr-allowlist disclosure).
pub fn install(account: ServiceAccount) -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe = std::env::current_exe().map_err(windows_service::Error::Winapi)?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from(SERVICE_ARG)],
        dependencies: vec![],
        account_name: account.account_name(),
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(
        "Sembazuru distributed-build daemon: schedules compile actions across \
         workers and serves inputs on demand (loopback control + LAN data plane).",
    )?;
    Ok(())
}

/// Stops the daemon service (if running) and then deletes it. Requires
/// Administrator. Stop-then-delete matters: the crate's `delete()` does NOT stop a
/// running service, so deleting first would leave the SCM entry (and the still
/// listening process) lingering until reboot — exactly the kind of persistence
/// residue this tool must avoid. So we stop, wait briefly for `Stopped`, then
/// delete; if it will not stop in time, `delete()` still marks it (removed at the
/// next reboot) as a fallback.
pub fn uninstall() -> windows_service::Result<()> {
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        // Best-effort: an already-stopping/stopped service erroring here is fine.
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            sleep(Duration::from_millis(200));
        }
    }
    service.delete()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_parsing_and_names() {
        assert_eq!(
            ServiceAccount::parse("system"),
            Some(ServiceAccount::System)
        );
        assert_eq!(
            ServiceAccount::parse("LocalSystem"),
            Some(ServiceAccount::System)
        );
        assert_eq!(
            ServiceAccount::parse("virtual"),
            Some(ServiceAccount::Virtual)
        );
        assert_eq!(
            ServiceAccount::parse("networkservice"),
            Some(ServiceAccount::NetworkService)
        );
        assert_eq!(ServiceAccount::parse("nonsense"), None);

        // System = LocalSystem (no explicit account). The hardened accounts map to
        // the documented identities.
        assert_eq!(ServiceAccount::System.account_name(), None);
        assert_eq!(
            ServiceAccount::Virtual.account_name(),
            Some(OsString::from("NT SERVICE\\SembazuruDaemon"))
        );
        assert_eq!(
            ServiceAccount::NetworkService.account_name(),
            Some(OsString::from("NT AUTHORITY\\NetworkService"))
        );
    }

    #[test]
    fn parse_account_defaults_to_virtual() {
        assert_eq!(
            ServiceAccount::resolve_self_install(None),
            ServiceAccount::Virtual
        );
        assert_eq!(
            ServiceAccount::resolve_self_install(ServiceAccount::parse("bogus")),
            ServiceAccount::Virtual
        );
    }

    #[test]
    fn explicit_system_account_still_supported_with_warning() {
        assert_eq!(
            ServiceAccount::resolve_self_install(ServiceAccount::parse("system")),
            ServiceAccount::System
        );
        assert!(ServiceAccount::System.warning().is_some());
        assert!(ServiceAccount::Virtual.warning().is_none());
        assert!(ServiceAccount::NetworkService.warning().is_none());
    }

    #[test]
    fn daemon_service_exit_code_maps_success_to_win32_zero() {
        assert_eq!(
            daemon_service_exit_code(Ok::<(), std::io::Error>(())),
            ServiceExitCode::Win32(0)
        );
    }

    #[test]
    fn daemon_service_exit_code_maps_failure_to_non_zero() {
        let err = std::io::Error::other("fatal daemon exit");
        assert_ne!(
            daemon_service_exit_code(Err(&err)),
            ServiceExitCode::Win32(0)
        );
        assert_ne!(fatal_service_exit_code(), ServiceExitCode::Win32(0));
    }
}
