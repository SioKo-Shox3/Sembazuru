//! Windows Service wrapper for `sembazuru-worker` (M9.3c, ADR 0008 §3).
//!
//! The same binary runs three ways: the plain CLI (dev/fallback), as a Windows
//! Service when the SCM launches it with `--service`, and as the `install` /
//! `uninstall` admin commands. The worker's runnable core is [`crate::run::run_worker`];
//! this module is only the SCM glue — the dispatcher, the Stop handler that cancels
//! the shutdown token, the StartPending → Running → Stopped status reporting, and
//! `ServiceManager`-based install/uninstall.
//!
//! This is a deliberate, near-verbatim mirror of `sembazuru_agent::service`: the
//! worker cannot depend on the agent crate (that would be a dependency cycle), so
//! the SCM glue is duplicated rather than shared. The two copies differ only in the
//! service identity (name/display/description), the config + run core they drive,
//! and the **default account** — the worker defaults to a least-privilege virtual
//! account (the daemon defaults to System). Extracting a shared `winsvc` crate is a
//! tracked follow-up once both copies are proven.
//!
//! Windows-only (`#[cfg(windows)]`). The actual SCM lifecycle (install → auto-start
//! → stop) requires Administrator and is verified on a real machine, not in
//! `cargo test`; the testable parts (config loading, the shutdown token returning
//! `run_worker`, account parsing) live in `config.rs` / `run.rs` and the tests.

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

use crate::config::WorkerConfig;
use crate::run::run_worker;

/// The service's registered name (used by the SCM and `sc.exe`). Distinct from the
/// daemon's `SembazuruDaemon` so both services coexist on one host.
pub const SERVICE_NAME: &str = "SembazuruWorker";
/// Human-readable name shown in services.msc.
pub const DISPLAY_NAME: &str = "Sembazuru Build Worker";
/// The launch argument the installer registers so the SCM-started process runs as a
/// service rather than the plain CLI.
pub const SERVICE_ARG: &str = "--service";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// SCM entry point (runs on a background thread). There is no console in service
/// context; diagnostics go to stderr (Event Log integration is a future refinement).
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("sembazuru-worker: service failed: {e}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let shutdown = CancellationToken::new();

    // The SCM Stop/Shutdown handler signals the async worker to stop. It runs on a
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

    let set = |state, accept, wait_hint| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
    };

    // StartPending with a generous wait hint (binding one listener is fast; the hint
    // keeps the SCM's ~30s start timer from firing).
    set(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(10),
    )?;

    // A service has no per-shell env, so config comes from the file (+ any env),
    // M9.3c. Load it first because the runtime is sized to the worker's capacity.
    let config = WorkerConfig::load_effective(&WorkerConfig::path_from_env());
    let worker_threads = config.capacity.unwrap_or(2).clamp(2, 64) as usize;
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sembazuru-worker: runtime build failed: {e}");
            set(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::default(),
            )?;
            return Ok(());
        }
    };

    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
    )?;

    let result = runtime.block_on(run_worker(config, shutdown));
    // Dropping the runtime stops the Execution server.
    drop(runtime);
    if let Err(e) = result {
        eprintln!("sembazuru-worker: worker exited with error: {e}");
    }

    set(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
    )?;
    Ok(())
}

/// Runs the SCM dispatcher; called when the SCM launches the binary with
/// `--service`. Blocks until the service stops.
pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// The account the service runs under. Unlike the daemon — which READS the
/// developer's source tree to serve it and therefore wants broad read access — the
/// worker only **injects into its own child compilers** (unprivileged) and receives
/// its inputs over the data plane, so it never reads the developer's files directly.
/// A least-privilege virtual account is therefore the *default* for the worker (the
/// daemon defaults to System); this matches the rationale already noted in
/// `sembazuru_agent::service::ServiceAccount` and the EDR disclosure.
///
/// Least privilege is not zero-setup, though: the virtual account still needs write
/// access to the worker's scratch and CAS roots (`crate::WorkerVfsConfig`) and
/// read+execute on `launcher.exe` + the hook DLL. LocalSystem has those implicitly;
/// the virtual account does not, so the production installer (M9.5) must ACL-grant
/// `NT SERVICE\SembazuruWorker` those paths or VFS-mode actions fail at runtime (not
/// at install). This is the worker's analogue of the daemon's "grant read on the
/// served source roots" caveat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccount {
    /// LocalSystem (`account_name = None`). Most powerful; rarely needed for the
    /// worker (offered for parity / awkward ACL situations).
    System,
    /// Virtual service account `NT SERVICE\SembazuruWorker` (least privilege). The
    /// worker's default and recommended identity.
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

    fn account_name(self) -> Option<OsString> {
        match self {
            Self::System => None,
            Self::Virtual => Some(OsString::from(format!("NT SERVICE\\{SERVICE_NAME}"))),
            Self::NetworkService => Some(OsString::from("NT AUTHORITY\\NetworkService")),
        }
    }
}

/// Installs the worker as an auto-start Windows Service that runs this binary with
/// `--service`. `account` selects the service identity (default: `Virtual`, least
/// privilege). Requires Administrator (`CREATE_SERVICE`). The WiX installer (M9.5)
/// is the production path; this self-install exists for dev/test (ADR 0008). No
/// other persistence is created — just this one service (edr-allowlist disclosure).
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
        "Sembazuru distributed-build worker: executes compile actions and streams \
         their outputs back to the agent. Injects the Sembazuru hook only into the \
         compilers it spawns (never an already-running process).",
    )?;
    Ok(())
}

/// Stops the worker service (if running) and then deletes it. Requires
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
        // the documented identities; Virtual carries the worker's own service name.
        assert_eq!(ServiceAccount::System.account_name(), None);
        assert_eq!(
            ServiceAccount::Virtual.account_name(),
            Some(OsString::from("NT SERVICE\\SembazuruWorker"))
        );
        assert_eq!(
            ServiceAccount::NetworkService.account_name(),
            Some(OsString::from("NT AUTHORITY\\NetworkService"))
        );
    }
}
