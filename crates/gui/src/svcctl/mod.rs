//! Windows Service control for the local daemon and worker (M9.4e, ADR 0008 §4).
//!
//! Service state can be *queried* without elevation, so the dashboard badges
//! refresh non-elevated. Starting / stopping a service requires Administrator, so
//! the resident (non-elevated, `asInvoker`) GUI re-launches its OWN exe with the
//! hidden `--svcctl <action> <service>` subcommand under the "runas" verb; the
//! elevated child does the SCM op and exits with a status code, and the parent
//! re-queries the (non-elevated) state to confirm.
//!
//! The argument surface that crosses the elevation boundary is a CLOSED enum
//! ([`Service`] × [`Action`]) with hardcoded service names — never free-form text.

/// One of the two local Sembazuru services the GUI can control. Remote workers on
/// other machines are not controllable from here (ADR 0008 §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Service {
    Daemon,
    Worker,
}

impl Service {
    /// The registered Windows service name. Hardcoded to match the daemon's
    /// `service::SERVICE_NAME` ("SembazuruDaemon") and the worker's
    /// ("SembazuruWorker"); nothing free-form crosses the elevation boundary.
    pub fn name(self) -> &'static str {
        match self {
            Service::Daemon => "SembazuruDaemon",
            Service::Worker => "SembazuruWorker",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Service::Daemon => "Daemon",
            Service::Worker => "Worker",
        }
    }

    fn as_arg(self) -> &'static str {
        match self {
            Service::Daemon => "daemon",
            Service::Worker => "worker",
        }
    }

    fn from_arg(arg: &str) -> Option<Self> {
        match arg {
            "daemon" => Some(Service::Daemon),
            "worker" => Some(Service::Worker),
            _ => None,
        }
    }
}

/// The control action. A closed set: only start and stop cross the boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Start,
    Stop,
}

impl Action {
    fn as_arg(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
        }
    }

    fn from_arg(arg: &str) -> Option<Self> {
        match arg {
            "start" => Some(Action::Start),
            "stop" => Some(Action::Stop),
            _ => None,
        }
    }

    /// A present-progressive verb for status messages ("Starting", "Stopping").
    pub fn progressive(self) -> &'static str {
        match self {
            Action::Start => "Starting",
            Action::Stop => "Stopping",
        }
    }
}

/// The live state of a service, as seen non-elevated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    /// The service is not registered (e.g. not installed yet).
    NotInstalled,
    /// The SCM could not be queried (rare).
    Unknown,
}

impl ServiceState {
    pub fn label(self) -> &'static str {
        match self {
            ServiceState::Running => "running",
            ServiceState::Stopped => "stopped",
            ServiceState::NotInstalled => "not installed",
            ServiceState::Unknown => "unknown",
        }
    }
}

/// The action sequence to reach a freshly-(re)started service from `current`. Pure.
pub fn restart_plan(current: ServiceState) -> Vec<Action> {
    match current {
        ServiceState::Running => vec![Action::Stop, Action::Start],
        ServiceState::Stopped => vec![Action::Start],
        ServiceState::NotInstalled | ServiceState::Unknown => vec![],
    }
}

/// Entry point for the hidden `--svcctl <action> <service>` subcommand: the
/// elevated child parses the closed enums, performs the SCM op, and returns a
/// process exit code (0 = ok, 1 = failed, 2 = bad arguments).
pub fn run_cli(args: &[String]) -> i32 {
    match (
        args.get(2).map(String::as_str).and_then(Action::from_arg),
        args.get(3).map(String::as_str).and_then(Service::from_arg),
    ) {
        (Some(action), Some(service)) => run_elevated(service, action),
        _ => 2,
    }
}

pub use imp::{query_state, request_action, run_elevated};

#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::time::{Duration, Instant};

    use windows_service::service::{Service as WinService, ServiceAccess, ServiceState as WsState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{Action, Service, ServiceState};

    /// Performs the SCM start/stop in the elevated child. Returns a process exit
    /// code (0 ok, 1 failed).
    pub fn run_elevated(service: Service, action: Action) -> i32 {
        match perform(service, action) {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }

    fn perform(service: Service, action: Action) -> windows_service::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let access = match action {
            Action::Start => ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            Action::Stop => ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        };
        let svc = manager.open_service(service.name(), access)?;
        match action {
            Action::Start => {
                if svc.query_status()?.current_state == WsState::Stopped {
                    svc.start(&[] as &[&OsStr])?;
                }
                wait_until(&svc, |state| state != WsState::Stopped);
            }
            Action::Stop => {
                if svc.query_status()?.current_state != WsState::Stopped {
                    let _ = svc.stop();
                }
                wait_until(&svc, |state| state == WsState::Stopped);
            }
        }
        Ok(())
    }

    /// Polls the service for up to 8s so the parent's follow-up query sees the
    /// settled state. Best-effort: a query error just ends the wait.
    fn wait_until(svc: &WinService, done: impl Fn(WsState) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            match svc.query_status() {
                Ok(status) if done(status.current_state) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Queries a service's state WITHOUT elevation (`SC_MANAGER_CONNECT` +
    /// `SERVICE_QUERY_STATUS`, which standard users are granted).
    pub fn query_state(service: Service) -> ServiceState {
        let manager =
            match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
                Ok(manager) => manager,
                Err(_) => return ServiceState::Unknown,
            };
        match manager.open_service(service.name(), ServiceAccess::QUERY_STATUS) {
            Ok(svc) => match svc.query_status() {
                Ok(status) if status.current_state == WsState::Stopped => ServiceState::Stopped,
                Ok(_) => ServiceState::Running,
                Err(_) => ServiceState::Unknown,
            },
            // Opening an absent service fails with ERROR_SERVICE_DOES_NOT_EXIST.
            Err(_) => ServiceState::NotInstalled,
        }
    }

    /// Re-launches this exe elevated (`runas`) with the hidden `--svcctl` command,
    /// waits for it, and returns the child's exit code (0 ok / 1 failed). The only
    /// data crossing the boundary is the closed `action`/`service` enum.
    pub fn request_action(service: Service, action: Action) -> Result<i32, String> {
        use std::os::windows::ffi::OsStrExt;

        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_CANCELLED, GetLastError, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        use windows_sys::Win32::UI::Shell::{
            SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

        // We launch the FULL path of our own image (lpFile below), so ShellExecuteEx
        // does no PATH/CWD search — a peer process cannot redirect the elevated launch
        // by planting an exe. The remaining trust assumption is the on-disk integrity
        // of this image itself: the installer must place it where standard users
        // cannot write (Program Files / %ProgramData% with default ACLs), and code
        // signing (M7) is what ultimately ties "elevate this image" to "our binary".
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_w: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let verb_w: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
        let params = format!("--svcctl {} {}", action.as_arg(), service.as_arg());
        let params_w: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: zeroing then filling a plain C struct; the wide strings outlive
        // the ShellExecuteExW call below (they are owned locals).
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb_w.as_ptr();
        info.lpFile = exe_w.as_ptr();
        info.lpParameters = params_w.as_ptr();
        info.nShow = SW_HIDE;

        // SAFETY: `info` is fully initialized per the struct contract.
        let launched = unsafe { ShellExecuteExW(&mut info) };
        if launched == 0 {
            // SAFETY: GetLastError reads thread-local error state.
            let err = unsafe { GetLastError() };
            if err == ERROR_CANCELLED {
                return Err("elevation was declined".to_string());
            }
            return Err(format!(
                "could not launch the elevated helper (error {err})"
            ));
        }

        let handle = info.hProcess;
        if handle.is_null() {
            return Err("no handle to the elevated helper".to_string());
        }

        // SAFETY: `handle` is a live process handle from ShellExecuteExW. The child
        // settles its own state within ~8s (`wait_until`), so 120s only bounds a true
        // hang; on timeout we report it explicitly rather than inferring from the exit
        // code. The handle is closed exactly once on each path.
        let wait = unsafe { WaitForSingleObject(handle, 120_000) };
        if wait == WAIT_TIMEOUT {
            unsafe { CloseHandle(handle) };
            return Err("the elevated helper did not finish in time".to_string());
        }
        let mut code: u32 = 0;
        unsafe {
            GetExitCodeProcess(handle, &mut code);
            CloseHandle(handle);
        }
        Ok(code as i32)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Action, Service, ServiceState};

    pub fn run_elevated(_service: Service, _action: Action) -> i32 {
        1
    }

    pub fn query_state(_service: Service) -> ServiceState {
        ServiceState::Unknown
    }

    pub fn request_action(_service: Service, _action: Action) -> Result<i32, String> {
        Err("service control is only available on Windows".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Service, ServiceState, restart_plan, run_cli};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn run_cli_rejects_bad_or_missing_args_with_code_2() {
        // Bad-args returns 2 BEFORE ever attempting the SCM op (run_elevated).
        assert_eq!(run_cli(&args(&["exe", "--svcctl", "bogus", "bogus"])), 2);
        assert_eq!(
            run_cli(&args(&["exe", "--svcctl", "start"])),
            2,
            "missing service"
        );
        assert_eq!(run_cli(&args(&["exe", "--svcctl"])), 2, "missing both");
        assert_eq!(
            run_cli(&args(&["exe", "--svcctl", "restart", "daemon"])),
            2,
            "unknown action"
        );
    }

    #[test]
    fn arg_parsing_is_a_closed_set() {
        assert_eq!(Action::from_arg("start"), Some(Action::Start));
        assert_eq!(Action::from_arg("stop"), Some(Action::Stop));
        assert_eq!(Action::from_arg("Start"), None, "case-sensitive, closed");
        assert_eq!(Service::from_arg("daemon"), Some(Service::Daemon));
        assert_eq!(Service::from_arg("worker"), Some(Service::Worker));
        assert_eq!(Service::from_arg("../evil"), None);
        // The arg strings round-trip with the parser (what the parent sends, the
        // child accepts).
        assert_eq!(
            Action::from_arg(Action::Start.as_arg()),
            Some(Action::Start)
        );
        assert_eq!(
            Service::from_arg(Service::Worker.as_arg()),
            Some(Service::Worker)
        );
    }

    #[test]
    fn restart_plan_stops_then_starts_when_running() {
        assert_eq!(
            restart_plan(ServiceState::Running),
            vec![Action::Stop, Action::Start]
        );
    }

    #[test]
    fn restart_plan_just_starts_when_stopped() {
        assert_eq!(restart_plan(ServiceState::Stopped), vec![Action::Start]);
    }

    #[test]
    fn restart_plan_noop_when_not_installed() {
        assert!(restart_plan(ServiceState::NotInstalled).is_empty());
    }

    // The hardcoded service names that cross the elevation boundary must match the
    // names the daemon and worker actually register, or start/stop silently targets
    // a non-existent service. (Service modules are Windows-only.)
    #[cfg(windows)]
    #[test]
    fn service_names_match_the_registered_services() {
        assert_eq!(
            Service::Daemon.name(),
            sembazuru_agent::service::SERVICE_NAME
        );
        assert_eq!(
            Service::Worker.name(),
            sembazuru_worker::service::SERVICE_NAME
        );
    }
}
