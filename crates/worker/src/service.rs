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

use crate::config::WorkerConfigLocation;
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

fn fatal_service_exit_code() -> ServiceExitCode {
    ServiceExitCode::ServiceSpecific(1)
}

fn worker_service_exit_code<E>(result: Result<(), E>) -> ServiceExitCode {
    match result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => fatal_service_exit_code(),
    }
}

fn acquire_service_runtime_guard_for_location<T, E>(
    location: &WorkerConfigLocation,
    acquire: impl FnOnce() -> Result<T, E>,
) -> Result<Option<T>, E> {
    match location {
        WorkerConfigLocation::Canonical => acquire().map(Some),
        WorkerConfigLocation::Override(_) => Ok(None),
    }
}

fn acquire_guard_then_load<G, GE, C, LE>(
    location: &WorkerConfigLocation,
    acquire: impl FnOnce() -> Result<G, GE>,
    load: impl FnOnce() -> Result<C, LE>,
) -> Result<(Option<G>, Result<C, LE>), GE> {
    let guard = acquire_service_runtime_guard_for_location(location, acquire)?;
    Ok((guard, load()))
}

fn report_stopped_before_releasing<G, E>(
    guard: Option<G>,
    report_stopped: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    let result = report_stopped();
    drop(guard);
    result
}

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

    // StartPending with a generous wait hint (binding one listener is fast; the hint
    // keeps the SCM's ~30s start timer from firing).
    set(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(10),
        ServiceExitCode::Win32(0),
    )?;

    let config_location = WorkerConfigLocation::from_env();
    let (service_runtime_guard, loaded_config) = match acquire_guard_then_load(
        &config_location,
        sembazuru_config_store::enter_machine_service_runtime,
        || config_location.load_effective_checked(),
    ) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("sembazuru-worker: service runtime guard entry failed: {e}");
            set(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::default(),
                fatal_service_exit_code(),
            )?;
            return Ok(());
        }
    };

    // A service has no per-shell env, so config comes from the file (+ any env),
    // M9.3c. Load it first because the runtime is sized to the worker's capacity.
    // Refuse to run on a present-but-corrupt config (CFG-001): a service silently
    // defaulting (no agent/token/VFS) is the scariest variant — it has no shell to
    // notice the warning. Report Stopped to the SCM so the failure is visible.
    let config = match loaded_config {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sembazuru-worker: {e}");
            return report_stopped_before_releasing(service_runtime_guard, || {
                set(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    Duration::default(),
                    fatal_service_exit_code(),
                )
            });
        }
    };
    let worker_threads = config.capacity.unwrap_or(2).clamp(2, 64) as usize;
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sembazuru-worker: runtime build failed: {e}");
            return report_stopped_before_releasing(service_runtime_guard, || {
                set(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    Duration::default(),
                    fatal_service_exit_code(),
                )
            });
        }
    };

    if let Err(running_error) = set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
        ServiceExitCode::Win32(0),
    ) {
        let stopped = report_stopped_before_releasing(service_runtime_guard, || {
            set(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::default(),
                fatal_service_exit_code(),
            )
        });
        return match stopped {
            Ok(()) => Err(running_error),
            Err(stopped_error) => Err(stopped_error),
        };
    }

    let result = runtime.block_on(run_worker(config, shutdown));
    // Dropping the runtime stops the Execution server.
    drop(runtime);
    let exit_code = worker_service_exit_code(result.as_ref().map(|_| ()));
    if let Err(e) = result {
        eprintln!("sembazuru-worker: worker exited with error: {e}");
    }

    report_stopped_before_releasing(service_runtime_guard, || {
        set(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            Duration::default(),
            exit_code,
        )
    })
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
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;
    use std::rc::Rc;

    use super::*;
    use crate::config::WorkerConfig;

    struct DropSpy(Rc<RefCell<Vec<&'static str>>>);

    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0.borrow_mut().push("dropped");
        }
    }

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

    #[test]
    fn worker_service_runtime_guard_enters_only_for_canonical_location() {
        let calls = Cell::new(0);
        let guard = acquire_service_runtime_guard_for_location(
            &WorkerConfigLocation::Canonical,
            || -> Result<u8, &'static str> {
                calls.set(calls.get() + 1);
                Ok(7)
            },
        )
        .unwrap();
        assert_eq!(guard, Some(7));
        assert_eq!(calls.get(), 1);

        for location in [
            WorkerConfigLocation::Override(PathBuf::new()),
            WorkerConfigLocation::Override(WorkerConfig::default_path()),
        ] {
            let guard: Result<Option<u8>, &'static str> =
                acquire_service_runtime_guard_for_location(&location, || {
                    calls.set(calls.get() + 1);
                    Ok(9)
                });
            assert_eq!(guard.unwrap(), None);
        }
        assert_eq!(calls.get(), 1, "override provenance must bypass the guard");
    }

    #[test]
    fn worker_service_runtime_guard_propagates_entry_failure() {
        let error =
            acquire_service_runtime_guard_for_location(&WorkerConfigLocation::Canonical, || {
                Err::<u8, _>("guard-entry-failed")
            })
            .unwrap_err();
        assert_eq!(error, "guard-entry-failed");
    }

    #[test]
    fn worker_service_runtime_guard_is_released_after_stopped_report() {
        for report_succeeds in [true, false] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let guard = DropSpy(Rc::clone(&events));
            let result = report_stopped_before_releasing(Some(guard), || {
                events.borrow_mut().push("reported");
                if report_succeeds {
                    Ok(())
                } else {
                    Err("stopped-report-failed")
                }
            });

            assert_eq!(&*events.borrow(), &["reported", "dropped"]);
            assert_eq!(result.is_ok(), report_succeeds);
        }
    }

    #[test]
    fn worker_service_guard_holds_across_failed_load_until_stopped() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let (guard, loaded) = acquire_guard_then_load(
            &WorkerConfigLocation::Canonical,
            || {
                events.borrow_mut().push("enter");
                Ok::<_, &'static str>(DropSpy(Rc::clone(&events)))
            },
            || {
                events.borrow_mut().push("load");
                Err::<u8, _>("load-failed")
            },
        )
        .unwrap();
        assert_eq!(loaded, Err("load-failed"));
        report_stopped_before_releasing(guard, || {
            events.borrow_mut().push("reported");
            Ok::<_, &'static str>(())
        })
        .unwrap();
        assert_eq!(&*events.borrow(), &["enter", "load", "reported", "dropped"]);

        let loads = Cell::new(0);
        let failed = acquire_guard_then_load(
            &WorkerConfigLocation::Canonical,
            || Err::<u8, _>("guard-entry-failed"),
            || {
                loads.set(loads.get() + 1);
                Ok::<_, &'static str>(7)
            },
        );
        assert_eq!(failed.unwrap_err(), "guard-entry-failed");
        assert_eq!(loads.get(), 0);

        let (guard, loaded) = acquire_guard_then_load(
            &WorkerConfigLocation::Override(WorkerConfig::default_path()),
            || -> Result<u8, &'static str> { panic!("override entered guard") },
            || Ok::<_, &'static str>(9),
        )
        .unwrap();
        assert!(guard.is_none());
        assert_eq!(loaded, Ok(9));
    }

    #[test]
    fn worker_service_exit_code_maps_success_to_win32_zero() {
        assert_eq!(
            worker_service_exit_code(Ok::<(), &'static str>(())),
            ServiceExitCode::Win32(0)
        );
    }

    #[test]
    fn worker_service_exit_code_maps_failure_to_non_zero() {
        for failure in ["guard", "config", "runtime", "run"] {
            assert_ne!(
                worker_service_exit_code(Err::<(), _>(failure)),
                ServiceExitCode::Win32(0),
                "{failure} failure must be fatal"
            );
        }
    }

    #[test]
    fn worker_service_exit_code_maps_invalid_override_config_to_non_zero() {
        let path = std::env::temp_dir().join(format!(
            "sbz-worker-service-config-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "this is = = not valid toml [[[").unwrap();
        let location = WorkerConfigLocation::Override(path.clone());

        let result = WorkerConfig::load_effective_checked(&location.path());
        let exit_code = worker_service_exit_code(result.as_ref().map(|_| ()));

        assert!(
            result.is_err(),
            "a present invalid override must be refused"
        );
        assert_ne!(exit_code, ServiceExitCode::Win32(0));
        std::fs::remove_file(path).unwrap();
    }
}
