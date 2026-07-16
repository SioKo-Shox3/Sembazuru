use std::ffi::OsString;

use sembazuru_config_store::{
    MachineStoreErrorClass, commit_machine_store_provision, provision_fresh_machine_store,
    rollback_machine_store_provision, uninstall_committed_machine_store,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verb {
    Provision,
    RollbackProvision,
    CommitProvision,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliError {
    InvalidArguments,
    Unauthorized,
    TokenInspection,
    #[cfg(any(not(windows), test))]
    Unsupported,
    Lifecycle(MachineStoreErrorClass),
}

impl CliError {
    const fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid-arguments",
            Self::Unauthorized => "unauthorized",
            Self::TokenInspection => "token-inspection-failed",
            #[cfg(any(not(windows), test))]
            Self::Unsupported => "unsupported-platform",
            Self::Lifecycle(MachineStoreErrorClass::Unsupported) => "lifecycle-unsupported",
            Self::Lifecycle(MachineStoreErrorClass::NamespaceAlreadyExists) => {
                "lifecycle-namespace-exists"
            }
            Self::Lifecycle(MachineStoreErrorClass::IntegrityViolation) => {
                "lifecycle-integrity-violation"
            }
            Self::Lifecycle(MachineStoreErrorClass::Busy) => "lifecycle-busy",
            Self::Lifecycle(MachineStoreErrorClass::InvalidInput) => "lifecycle-invalid-input",
            Self::Lifecycle(MachineStoreErrorClass::Io) => "lifecycle-io-failed",
        }
    }

    const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidArguments => 2,
            Self::Unauthorized => 3,
            Self::TokenInspection => 4,
            #[cfg(any(not(windows), test))]
            Self::Unsupported => 5,
            Self::Lifecycle(_) => 10,
        }
    }
}

trait LifecycleActions {
    fn invoke(&mut self, verb: Verb) -> Result<(), CliError>;
}

struct MachineStoreLifecycle;

impl LifecycleActions for MachineStoreLifecycle {
    fn invoke(&mut self, verb: Verb) -> Result<(), CliError> {
        let result = match verb {
            Verb::Provision => provision_fresh_machine_store(),
            Verb::RollbackProvision => rollback_machine_store_provision(),
            Verb::CommitProvision => commit_machine_store_provision(),
            Verb::Uninstall => uninstall_committed_machine_store(),
        };
        result.map_err(|error| CliError::Lifecycle(error.classification()))
    }
}

fn parse_args<I>(args: I) -> Result<Verb, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    args.next().ok_or(CliError::InvalidArguments)?;
    let verb = args.next().ok_or(CliError::InvalidArguments)?;
    if args.next().is_some() {
        return Err(CliError::InvalidArguments);
    }

    match verb.to_str() {
        Some("provision") => Ok(Verb::Provision),
        Some("rollback-provision") => Ok(Verb::RollbackProvision),
        Some("commit-provision") => Ok(Verb::CommitProvision),
        Some("uninstall") => Ok(Verb::Uninstall),
        _ => Err(CliError::InvalidArguments),
    }
}

fn run_authorized<A>(
    verb: Verb,
    effective_user_is_local_system: bool,
    actions: &mut A,
) -> Result<(), CliError>
where
    A: LifecycleActions,
{
    if !effective_user_is_local_system {
        return Err(CliError::Unauthorized);
    }
    actions.invoke(verb)
}

#[cfg(windows)]
fn effective_user_is_local_system() -> Result<bool, CliError> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = null_mut();
    // SAFETY: the output pointer is valid and a successful call transfers one
    // token handle, which is immediately wrapped by OwnedHandle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(CliError::TokenInspection);
    }
    // SAFETY: OpenProcessToken returned an owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };

    let mut user_size = 0u32;
    // SAFETY: a null buffer with zero length is the documented size query.
    let measured = unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            null_mut(),
            0,
            &mut user_size,
        )
    };
    if measured != 0
        || user_size < size_of::<TOKEN_USER>() as u32
        || std::io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(CliError::TokenInspection);
    }
    let mut user_buffer = aligned_buffer(user_size);
    // SAFETY: the aligned buffer has the queried byte length and remains live.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            user_buffer.as_mut_ptr().cast(),
            user_size,
            &mut user_size,
        )
    } == 0
    {
        return Err(CliError::TokenInspection);
    }
    // SAFETY: successful TokenUser query initialized TOKEN_USER at this aligned address.
    let user = unsafe { &*(user_buffer.as_ptr().cast::<TOKEN_USER>()) };

    let mut system_sid_size = 0u32;
    // SAFETY: a null output buffer requests the required well-known SID size.
    unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            null_mut(),
            &mut system_sid_size,
        );
    }
    if system_sid_size == 0 {
        return Err(CliError::TokenInspection);
    }
    let mut system_sid = aligned_buffer(system_sid_size);
    // SAFETY: the aligned buffer has the size reported by CreateWellKnownSid.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut system_sid_size,
        )
    } == 0
    {
        return Err(CliError::TokenInspection);
    }

    // SAFETY: both SIDs were initialized by successful Windows API calls and
    // remain live for the exact binary SID comparison.
    Ok(unsafe { EqualSid(user.User.Sid, system_sid.as_mut_ptr().cast()) != 0 })
}

#[cfg(windows)]
fn aligned_buffer(byte_len: u32) -> Vec<usize> {
    let word_size = std::mem::size_of::<usize>();
    vec![0; (byte_len as usize).div_ceil(word_size)]
}

#[cfg(not(windows))]
fn effective_user_is_local_system() -> Result<bool, CliError> {
    Err(CliError::Unsupported)
}

fn run() -> Result<(), CliError> {
    let verb = parse_args(std::env::args_os())?;
    let is_local_system = effective_user_is_local_system()?;
    run_authorized(verb, is_local_system, &mut MachineStoreLifecycle)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("sembazuru-storectl: {}", error.code());
        std::process::exit(error.exit_code());
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[derive(Default)]
    struct RecordingActions {
        calls: Vec<Verb>,
    }

    impl LifecycleActions for RecordingActions {
        fn invoke(&mut self, verb: Verb) -> Result<(), CliError> {
            self.calls.push(verb);
            Ok(())
        }
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parser_accepts_only_the_four_fixed_verbs() {
        for (text, expected) in [
            ("provision", Verb::Provision),
            ("rollback-provision", Verb::RollbackProvision),
            ("commit-provision", Verb::CommitProvision),
            ("uninstall", Verb::Uninstall),
        ] {
            assert_eq!(
                parse_args(args(&["sembazuru-storectl", text])),
                Ok(expected)
            );
        }
    }

    #[test]
    fn parser_rejects_missing_unknown_and_extra_arguments() {
        assert_eq!(
            parse_args(args(&["sembazuru-storectl"])),
            Err(CliError::InvalidArguments)
        );
        assert_eq!(
            parse_args(args(&["sembazuru-storectl", "daemon"])),
            Err(CliError::InvalidArguments)
        );
        assert_eq!(
            parse_args(args(&["sembazuru-storectl", "provision", "C:\\elsewhere"])),
            Err(CliError::InvalidArguments)
        );
    }

    #[test]
    fn sid_decision_rejects_every_non_system_identity_before_dispatch() {
        for verb in [
            Verb::Provision,
            Verb::RollbackProvision,
            Verb::CommitProvision,
            Verb::Uninstall,
        ] {
            let mut actions = RecordingActions::default();
            assert_eq!(
                run_authorized(verb, false, &mut actions),
                Err(CliError::Unauthorized)
            );
            assert!(actions.calls.is_empty());
        }
    }

    #[test]
    fn sid_decision_allows_system_identity_and_dispatches_exactly_once() {
        for verb in [
            Verb::Provision,
            Verb::RollbackProvision,
            Verb::CommitProvision,
            Verb::Uninstall,
        ] {
            let mut actions = RecordingActions::default();
            assert_eq!(run_authorized(verb, true, &mut actions), Ok(()));
            assert_eq!(actions.calls, vec![verb]);
        }
    }

    #[test]
    fn diagnostics_are_fixed_classifications() {
        assert_eq!(CliError::InvalidArguments.code(), "invalid-arguments");
        assert_eq!(CliError::Unauthorized.code(), "unauthorized");
        assert_eq!(CliError::TokenInspection.code(), "token-inspection-failed");
        assert_eq!(CliError::Unsupported.code(), "unsupported-platform");
        assert_eq!(
            CliError::Lifecycle(MachineStoreErrorClass::Unsupported).code(),
            "lifecycle-unsupported"
        );
        assert_eq!(
            CliError::Lifecycle(MachineStoreErrorClass::NamespaceAlreadyExists).code(),
            "lifecycle-namespace-exists"
        );
        assert_eq!(
            CliError::Lifecycle(MachineStoreErrorClass::IntegrityViolation).code(),
            "lifecycle-integrity-violation"
        );
        assert_eq!(
            CliError::Lifecycle(MachineStoreErrorClass::Io).code(),
            "lifecycle-io-failed"
        );
    }
}
