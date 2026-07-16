use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal, Read};

use sembazuru_config_store::{
    MAX_MACHINE_CLUSTER_TOKEN_BYTES, MachineStoreErrorClass, MachineTokenMaintenanceResult,
    MachineTokenUpdateGuard, begin_machine_token_update, clear_machine_cluster_token_storage,
    commit_machine_store_provision, migrate_machine_cluster_token_storage,
    provision_fresh_machine_store, rollback_machine_store_provision,
    rotate_machine_cluster_token_storage, uninstall_committed_machine_store,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verb {
    Provision,
    RollbackProvision,
    CommitProvision,
    Uninstall,
    MigrateToken,
    RotateToken,
    ClearToken,
}

impl Verb {
    const fn is_token_maintenance(self) -> bool {
        matches!(
            self,
            Self::MigrateToken | Self::RotateToken | Self::ClearToken
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentityFacts(bool, bool, bool);

impl IdentityFacts {
    const SYSTEM: Self = Self(true, false, false);

    const fn user(administrators_member: bool, elevated: bool) -> Self {
        Self(false, administrators_member, elevated)
    }
}

struct SecretInput(Zeroizing<String>);

impl SecretInput {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliError {
    InvalidArguments,
    Unauthorized,
    TokenInspection,
    #[cfg(any(not(windows), test))]
    Unsupported,
    Lifecycle(MachineStoreErrorClass),
    TokenMaintenance(MachineStoreErrorClass),
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
            Self::TokenMaintenance(MachineStoreErrorClass::Unsupported) => "token-unsupported",
            Self::TokenMaintenance(MachineStoreErrorClass::NamespaceAlreadyExists) => {
                "token-namespace-exists"
            }
            Self::TokenMaintenance(MachineStoreErrorClass::IntegrityViolation) => {
                "token-integrity-violation"
            }
            Self::TokenMaintenance(MachineStoreErrorClass::Busy) => "token-update-busy",
            Self::TokenMaintenance(MachineStoreErrorClass::InvalidInput) => "invalid-token-input",
            Self::TokenMaintenance(MachineStoreErrorClass::Io) => "token-io-failed",
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
            Self::TokenMaintenance(_) => 11,
        }
    }
}

const fn token_success(verb: Verb, result: MachineTokenMaintenanceResult) -> Option<&'static str> {
    match (verb, result) {
        (_, MachineTokenMaintenanceResult::Unchanged) => Some("token-unchanged"),
        (Verb::MigrateToken, MachineTokenMaintenanceResult::Changed) => Some("token-migrated"),
        (Verb::RotateToken, MachineTokenMaintenanceResult::Changed) => Some("token-rotated"),
        (Verb::ClearToken, MachineTokenMaintenanceResult::Changed) => Some("token-cleared"),
        _ => None,
    }
}

fn invalid_token_input() -> CliError {
    CliError::TokenMaintenance(MachineStoreErrorClass::InvalidInput)
}

fn parse_rotate_stdin(is_terminal: bool, input: &[u8]) -> Result<SecretInput, CliError> {
    if is_terminal {
        return Err(invalid_token_input());
    }
    let mut value = input;
    if let Some(without_lf) = value.strip_suffix(b"\n") {
        value = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);
    }
    if value.is_empty()
        || value.len() > MAX_MACHINE_CLUSTER_TOKEN_BYTES
        || value.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(invalid_token_input());
    }
    std::str::from_utf8(value)
        .map(|value| SecretInput::new(value.to_owned()))
        .map_err(|_| invalid_token_input())
}

fn read_rotate_token<R: Read>(is_terminal: bool, reader: R) -> Result<SecretInput, CliError> {
    if is_terminal {
        return Err(invalid_token_input());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_MACHINE_CLUSTER_TOKEN_BYTES + 3) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::TokenMaintenance(MachineStoreErrorClass::Io))?;
    parse_rotate_stdin(false, &bytes)
}

trait StoreActions {
    type Update;

    fn lifecycle(&mut self, verb: Verb) -> StoreResult<()>;
    fn begin_update(&mut self) -> StoreResult<Self::Update>;
    fn migrate_token(&mut self, update: &mut Self::Update) -> TokenResult;
    fn rotate_token(&mut self, update: &mut Self::Update, secret: &SecretInput) -> TokenResult;
    fn clear_token(&mut self, update: &mut Self::Update) -> TokenResult;
}

type StoreResult<T> = Result<T, MachineStoreErrorClass>;
type TokenResult = StoreResult<MachineTokenMaintenanceResult>;

struct MachineStoreLifecycle;

impl StoreActions for MachineStoreLifecycle {
    type Update = MachineTokenUpdateGuard;

    fn lifecycle(&mut self, verb: Verb) -> StoreResult<()> {
        match verb {
            Verb::Provision => provision_fresh_machine_store(),
            Verb::RollbackProvision => rollback_machine_store_provision(),
            Verb::CommitProvision => commit_machine_store_provision(),
            Verb::Uninstall => uninstall_committed_machine_store(),
            _ => unreachable!("token verb reached lifecycle dispatch"),
        }
        .map_err(|error| error.classification())
    }

    fn begin_update(&mut self) -> StoreResult<Self::Update> {
        begin_machine_token_update().map_err(|error| error.classification())
    }

    fn migrate_token(&mut self, update: &mut Self::Update) -> TokenResult {
        migrate_machine_cluster_token_storage(update).map_err(|error| error.classification())
    }

    fn rotate_token(&mut self, update: &mut Self::Update, secret: &SecretInput) -> TokenResult {
        rotate_machine_cluster_token_storage(update, secret.expose())
            .map_err(|error| error.classification())
    }

    fn clear_token(&mut self, update: &mut Self::Update) -> TokenResult {
        clear_machine_cluster_token_storage(update).map_err(|error| error.classification())
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
        Some("migrate-token") => Ok(Verb::MigrateToken),
        Some("rotate-token") => Ok(Verb::RotateToken),
        Some("clear-token") => Ok(Verb::ClearToken),
        _ => Err(CliError::InvalidArguments),
    }
}

fn authorize(verb: Verb, identity: IdentityFacts) -> Result<(), CliError> {
    let IdentityFacts(local_system, administrators_member, elevated) = identity;
    let authorized =
        local_system || (verb.is_token_maintenance() && administrators_member && elevated);
    if !authorized {
        return Err(CliError::Unauthorized);
    }
    Ok(())
}

fn dispatch<A: StoreActions>(
    verb: Verb,
    secret: Option<&SecretInput>,
    actions: &mut A,
) -> Result<Option<&'static str>, CliError> {
    if !verb.is_token_maintenance() {
        return actions
            .lifecycle(verb)
            .map(|()| None)
            .map_err(CliError::Lifecycle);
    }
    if (verb == Verb::RotateToken) != secret.is_some() {
        return Err(CliError::InvalidArguments);
    }
    let mut update = actions.begin_update().map_err(CliError::TokenMaintenance)?;
    let result = match verb {
        Verb::MigrateToken => actions.migrate_token(&mut update),
        Verb::RotateToken => actions.rotate_token(&mut update, secret.unwrap()),
        Verb::ClearToken => actions.clear_token(&mut update),
        _ => unreachable!("lifecycle verb was handled above"),
    }
    .map_err(CliError::TokenMaintenance)?;
    Ok(token_success(verb, result))
}

fn execute_authorized<A, F>(
    verb: Verb,
    identity: IdentityFacts,
    mut read_rotate: F,
    actions: &mut A,
) -> Result<Option<&'static str>, CliError>
where
    A: StoreActions,
    F: FnMut() -> Result<SecretInput, CliError>,
{
    authorize(verb, identity)?;
    let secret = if verb == Verb::RotateToken {
        Some(read_rotate()?)
    } else {
        None
    };
    dispatch(verb, secret.as_ref(), actions)
}

#[cfg(windows)]
fn effective_identity(verb: Verb) -> Result<IdentityFacts, CliError> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, DuplicateTokenEx, EqualSid, GetTokenInformation,
        SECURITY_MAX_SID_SIZE, SecurityIdentification, TOKEN_DUPLICATE, TOKEN_ELEVATION,
        TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenImpersonation, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
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
    // SAFETY: both SIDs are initialized and remain live for exact comparison.
    let local_system = unsafe { EqualSid(user.User.Sid, system_sid.as_mut_ptr().cast()) != 0 };
    if local_system {
        return Ok(IdentityFacts::SYSTEM);
    }
    if !verb.is_token_maintenance() {
        return Ok(IdentityFacts::user(false, false));
    }

    let mut inspection_token = null_mut();
    // SAFETY: non-SYSTEM token maintenance needs a duplicable handle to this
    // same process token; lifecycle and SYSTEM paths returned before this call.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut inspection_token,
        )
    } == 0
    {
        return Err(CliError::TokenInspection);
    }
    // SAFETY: OpenProcessToken returned an owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(inspection_token.cast()) };

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: the fixed output has the documented type and size.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
        || returned != size_of::<TOKEN_ELEVATION>() as u32
    {
        return Err(CliError::TokenInspection);
    }

    let mut identification = null_mut();
    // SAFETY: the source process token remains live; the successful duplicate
    // handle is immediately transferred to OwnedHandle.
    if unsafe {
        DuplicateTokenEx(
            token.as_raw_handle().cast(),
            TOKEN_QUERY,
            null_mut(),
            SecurityIdentification,
            TokenImpersonation,
            &mut identification,
        )
    } == 0
    {
        return Err(CliError::TokenInspection);
    }
    // SAFETY: DuplicateTokenEx returned one owned handle.
    let identification = unsafe { OwnedHandle::from_raw_handle(identification.cast()) };
    let mut administrators_sid = aligned_buffer(SECURITY_MAX_SID_SIZE);
    let mut administrators_sid_size = SECURITY_MAX_SID_SIZE;
    // SAFETY: SECURITY_MAX_SID_SIZE is the documented maximum SID byte length.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            administrators_sid.as_mut_ptr().cast(),
            &mut administrators_sid_size,
        )
    } == 0
    {
        return Err(CliError::TokenInspection);
    }
    let mut administrators_member = 0;
    // SAFETY: the identification impersonation token and SID are valid and live.
    if unsafe {
        CheckTokenMembership(
            identification.as_raw_handle().cast(),
            administrators_sid.as_mut_ptr().cast(),
            &mut administrators_member,
        )
    } == 0
    {
        return Err(CliError::TokenInspection);
    }

    Ok(IdentityFacts::user(
        administrators_member != 0,
        elevation.TokenIsElevated != 0,
    ))
}

#[cfg(windows)]
fn aligned_buffer(byte_len: u32) -> Vec<usize> {
    let word_size = std::mem::size_of::<usize>();
    vec![0; (byte_len as usize).div_ceil(word_size)]
}

#[cfg(not(windows))]
fn effective_identity(_verb: Verb) -> Result<IdentityFacts, CliError> {
    Err(CliError::Unsupported)
}

fn run() -> Result<Option<&'static str>, CliError> {
    let verb = parse_args(std::env::args_os())?;
    let identity = effective_identity(verb)?;
    execute_authorized(
        verb,
        identity,
        || {
            let stdin = io::stdin();
            read_rotate_token(stdin.is_terminal(), stdin.lock())
        },
        &mut MachineStoreLifecycle,
    )
}

fn main() {
    match run() {
        Ok(success) => {
            if let Some(code) = success {
                println!("{code}");
            }
        }
        Err(error) => {
            eprintln!("sembazuru-storectl: {}", error.code());
            std::process::exit(error.exit_code());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{Cursor, Read};

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Call(&'static str, u8);

    #[derive(Default)]
    struct RecordingActions {
        calls: Vec<Call>,
    }

    macro_rules! token_action {
        ($name:ident, $call:literal) => {
            fn $name(&mut self, update: &mut u8) -> TokenResult {
                self.calls.push(Call($call, *update));
                Ok(MachineTokenMaintenanceResult::Changed)
            }
        };
    }

    impl StoreActions for RecordingActions {
        type Update = u8;
        fn lifecycle(&mut self, _verb: Verb) -> StoreResult<()> {
            self.calls.push(Call("lifecycle", 0));
            Ok(())
        }
        fn begin_update(&mut self) -> StoreResult<u8> {
            self.calls.push(Call("begin", 0));
            Ok(73)
        }
        token_action!(migrate_token, "migrate");
        fn rotate_token(&mut self, update: &mut u8, _secret: &SecretInput) -> TokenResult {
            self.calls.push(Call("rotate", *update));
            Ok(MachineTokenMaintenanceResult::Changed)
        }
        token_action!(clear_token, "clear");
    }

    struct Counter(Cursor<Vec<u8>>, usize);
    impl Read for Counter {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.0.read(buffer)?;
            self.1 += count;
            Ok(count)
        }
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn assert_invalid_token(result: Result<SecretInput, CliError>) {
        assert_eq!(result.unwrap_err(), invalid_token_input());
    }

    #[test]
    fn parser_accepts_only_the_seven_fixed_verbs() {
        for (text, expected) in [
            ("provision", Verb::Provision),
            ("rollback-provision", Verb::RollbackProvision),
            ("commit-provision", Verb::CommitProvision),
            ("uninstall", Verb::Uninstall),
            ("migrate-token", Verb::MigrateToken),
            ("rotate-token", Verb::RotateToken),
            ("clear-token", Verb::ClearToken),
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
        assert_eq!(
            parse_args(args(&[
                "sembazuru-storectl",
                "rotate-token",
                "plaintext-secret"
            ])),
            Err(CliError::InvalidArguments)
        );
    }

    #[test]
    fn authorization_matrix_preserves_lifecycle_and_token_boundaries() {
        for (identity, lifecycle, token) in [
            (IdentityFacts::SYSTEM, true, true),
            (IdentityFacts::user(true, true), false, true),
            (IdentityFacts::user(true, false), false, false),
            (IdentityFacts::user(false, true), false, false),
            (IdentityFacts::user(false, false), false, false),
        ] {
            for verb in [
                Verb::Provision,
                Verb::RollbackProvision,
                Verb::CommitProvision,
                Verb::Uninstall,
            ] {
                assert_eq!(authorize(verb, identity).is_ok(), lifecycle);
            }
            for verb in [Verb::MigrateToken, Verb::RotateToken, Verb::ClearToken] {
                assert_eq!(authorize(verb, identity).is_ok(), token);
            }
        }
    }

    #[test]
    fn rotate_reader_enforces_one_line_terminal_and_bound() {
        for (bytes, expected) in [
            (b"secret\n".as_slice(), "secret"),
            (b" secret \r\n".as_slice(), " secret "),
            (b"no-newline".as_slice(), "no-newline"),
        ] {
            let secret = read_rotate_token(false, Cursor::new(bytes)).unwrap();
            assert_eq!(secret.expose(), expected);
        }
        let oversized = vec![b'x'; MAX_MACHINE_CLUSTER_TOKEN_BYTES + 1];
        for bytes in [
            b"first\nsecond\n".as_slice(),
            b"first\rsecond\n".as_slice(),
            b"nul\0secret\n".as_slice(),
            &[0xff][..],
            b"\n".as_slice(),
            oversized.as_slice(),
        ] {
            assert_invalid_token(parse_rotate_stdin(false, bytes));
        }
        let mut terminal = Counter(Cursor::new(b"secret\n".to_vec()), 0);
        assert_invalid_token(read_rotate_token(true, &mut terminal));
        assert_eq!(terminal.1, 0);
        let mut bounded = Counter(
            Cursor::new(vec![b'x'; MAX_MACHINE_CLUSTER_TOKEN_BYTES + 99]),
            0,
        );
        assert_invalid_token(read_rotate_token(false, &mut bounded));
        assert_eq!(bounded.1, MAX_MACHINE_CLUSTER_TOKEN_BYTES + 3);
    }

    #[test]
    fn authorization_precedes_input_and_exact_backend_dispatch() {
        for identity in [
            IdentityFacts::user(true, false),
            IdentityFacts::user(false, false),
        ] {
            let (mut reads, mut actions) = (0, RecordingActions::default());
            let result = execute_authorized(
                Verb::RotateToken,
                identity,
                || {
                    reads += 1;
                    Ok(SecretInput::new("unreachable".to_owned()))
                },
                &mut actions,
            );
            assert_eq!(
                (result, reads, actions.calls.len()),
                (Err(CliError::Unauthorized), 0, 0)
            );
        }
        for (verb, expected) in [
            (Verb::Provision, vec![Call("lifecycle", 0)]),
            (Verb::RollbackProvision, vec![Call("lifecycle", 0)]),
            (Verb::CommitProvision, vec![Call("lifecycle", 0)]),
            (Verb::Uninstall, vec![Call("lifecycle", 0)]),
            (
                Verb::MigrateToken,
                vec![Call("begin", 0), Call("migrate", 73)],
            ),
            (
                Verb::RotateToken,
                vec![Call("begin", 0), Call("rotate", 73)],
            ),
            (Verb::ClearToken, vec![Call("begin", 0), Call("clear", 73)]),
        ] {
            let (mut reads, mut actions) = (0, RecordingActions::default());
            execute_authorized(
                verb,
                IdentityFacts::SYSTEM,
                || {
                    reads += 1;
                    Ok(SecretInput::new("test-input".to_owned()))
                },
                &mut actions,
            )
            .unwrap();
            assert_eq!(
                (reads, actions.calls),
                (usize::from(verb == Verb::RotateToken), expected)
            );
        }
    }

    #[test]
    fn success_secret_shape_and_redaction_are_fixed() {
        use MachineTokenMaintenanceResult::{Changed, Unchanged};

        let secret = SecretInput::new("cli-secret-sentinel-91827".to_owned());
        let mut actions = RecordingActions::default();
        let error = dispatch(Verb::RotateToken, None, &mut actions).unwrap_err();
        assert_eq!(error, CliError::InvalidArguments);
        dispatch(Verb::RotateToken, Some(&secret), &mut actions).unwrap();
        assert!(!format!("{secret:?}{:?}", actions.calls).contains(secret.expose()));
        for (verb, changed) in [
            (Verb::MigrateToken, "token-migrated"),
            (Verb::RotateToken, "token-rotated"),
            (Verb::ClearToken, "token-cleared"),
        ] {
            assert_eq!(token_success(verb, Changed), Some(changed));
        }
        assert_eq!(
            token_success(Verb::MigrateToken, Unchanged).unwrap(),
            "token-unchanged"
        );
        assert_eq!(dispatch(Verb::Provision, None, &mut actions), Ok(None));
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
        assert_eq!(
            CliError::TokenMaintenance(MachineStoreErrorClass::Busy).code(),
            "token-update-busy"
        );
        assert_eq!(
            CliError::TokenMaintenance(MachineStoreErrorClass::InvalidInput).code(),
            "invalid-token-input"
        );
        assert_eq!(
            CliError::TokenMaintenance(MachineStoreErrorClass::Io).code(),
            "token-io-failed"
        );
    }
}
