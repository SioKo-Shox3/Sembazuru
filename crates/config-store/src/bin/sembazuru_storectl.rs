use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal, Read};

use sembazuru_config_store::{
    JoinPayload, JoinPayloadError, MAX_JOIN_PAYLOAD_BYTES, MAX_MACHINE_CLUSTER_TOKEN_BYTES,
    MachineStoreError, MachineStoreErrorClass, MachineTokenMaintenanceResult,
    MachineTokenUpdateGuard, apply_machine_join_payload, begin_machine_token_update,
    clear_machine_cluster_token_storage, commit_machine_store_provision,
    migrate_machine_cluster_token_storage, provision_fresh_machine_store,
    rollback_machine_store_provision, rotate_machine_cluster_token_storage,
    uninstall_committed_machine_store,
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
    Join,
}

impl Verb {
    const fn operation(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::RollbackProvision => "rollback-provision",
            Self::CommitProvision => "commit-provision",
            Self::Uninstall => "uninstall",
            Self::MigrateToken => "migrate-token",
            Self::RotateToken => "rotate-token",
            Self::ClearToken => "clear-token",
            Self::Join => "join",
        }
    }

    const fn is_token_maintenance(self) -> bool {
        matches!(
            self,
            Self::MigrateToken | Self::RotateToken | Self::ClearToken | Self::Join
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
    /// The join was written, but the services did not come back on the new configuration.
    JoinNotApplied,
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
            Self::JoinNotApplied => "join-saved-not-applied",
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
            Self::JoinNotApplied => 12,
        }
    }
}

const fn token_success(verb: Verb, result: MachineTokenMaintenanceResult) -> Option<&'static str> {
    match (verb, result) {
        (_, MachineTokenMaintenanceResult::Unchanged) => Some("token-unchanged"),
        (Verb::MigrateToken, MachineTokenMaintenanceResult::Changed) => Some("token-migrated"),
        (Verb::RotateToken, MachineTokenMaintenanceResult::Changed) => Some("token-rotated"),
        (Verb::ClearToken, MachineTokenMaintenanceResult::Changed) => Some("token-cleared"),
        (Verb::Join, MachineTokenMaintenanceResult::Changed) => Some("join-applied"),
        _ => None,
    }
}

/// The name of the one-shot pipe the join payload arrives on. It is not a secret: the transport's
/// protection is the pipe's own security descriptor and the peer check, never the name's obscurity.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PipeName(String);

impl PipeName {
    const PREFIX: &'static str = r"\\.\pipe\";
    const MAX_COMPONENT_BYTES: usize = 200;

    fn parse(value: &std::ffi::OsStr) -> Result<Self, CliError> {
        let value = value.to_str().ok_or(CliError::InvalidArguments)?;
        let component = value
            .strip_prefix(Self::PREFIX)
            .ok_or(CliError::InvalidArguments)?;
        // One component of the local pipe namespace, so a name can never redirect this read at a
        // remote server or at another kind of object.
        if component.is_empty()
            || component.len() > Self::MAX_COMPONENT_BYTES
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CliError::InvalidArguments);
        }
        Ok(Self(value.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// The one input a verb may carry. A verb never accepts the other kind.
enum VerbInput<'a> {
    None,
    Secret(&'a SecretInput),
    Join(&'a JoinPayload),
}

impl VerbInput<'_> {
    const fn matches(&self, verb: Verb) -> bool {
        matches!(
            (verb, self),
            (Verb::RotateToken, Self::Secret(_)) | (Verb::Join, Self::Join(_))
        ) || (!matches!(verb, Verb::RotateToken | Verb::Join) && matches!(self, Self::None))
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
    fn join(&mut self, update: &mut Self::Update, payload: &JoinPayload) -> TokenResult;
    /// Takes the machine-wide exclusion that covers one whole stop-update-start sequence.
    ///
    /// The update lease alone cannot do this: it is released before the services are started, and
    /// two joins interleaving their stops and starts would otherwise be free to cross.
    fn begin_join_exclusion(&mut self) -> StoreResult<()>;
    fn end_join_exclusion(&mut self);
    fn stop_services(&mut self) -> StoreResult<()>;
    fn start_services(&mut self) -> StoreResult<()>;
}

type StoreResult<T> = Result<T, MachineStoreErrorClass>;
type TokenResult = StoreResult<MachineTokenMaintenanceResult>;

fn backend_diagnostic(
    operation: &'static str,
    context: &'static str,
    raw_os_error: Option<i32>,
) -> String {
    let raw_os_error = raw_os_error.map_or_else(|| "none".to_owned(), |code| code.to_string());
    format!(
        "sembazuru-storectl: backend operation={operation}; context={context}; raw-os-error={raw_os_error}"
    )
}

fn classify_backend_error(
    operation: &'static str,
    error: MachineStoreError,
) -> MachineStoreErrorClass {
    eprintln!(
        "{}",
        backend_diagnostic(operation, error.context(), error.raw_os_error())
    );
    error.classification()
}

/// The machine-wide exclusion that covers one whole join sequence.
#[cfg(windows)]
mod join_exclusion {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{
        GetLastError, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    use super::{MachineStoreErrorClass, StoreResult};

    /// One name for the whole machine: joins from different sessions have to exclude each other.
    const NAME: &str = r"Global\SembazuruJoinSequence";

    /// A join stops services, writes, and starts them again; this only bounds a true hang.
    const TIMEOUT_MS: u32 = 120_000;

    /// One held join exclusion. Dropping the handle without releasing would leave the mutex
    /// abandoned, so the release is explicit and the handle is closed after it.
    pub(super) struct Exclusion(OwnedHandle);

    pub(super) fn acquire(slot: &mut Option<Exclusion>) -> StoreResult<()> {
        if slot.is_some() {
            // A second acquire in one process would deadlock on a non-recursive wait.
            return Err(MachineStoreErrorClass::Busy);
        }
        let name: Vec<u16> = NAME.encode_utf16().chain(Some(0)).collect();
        // SAFETY: the name is NUL-terminated and live for the call; ownership is taken below.
        let handle = unsafe { CreateMutexW(null_mut(), 0, name.as_ptr()) };
        if handle.is_null() {
            // SAFETY: GetLastError is read immediately after the failing call.
            let _ = unsafe { GetLastError() };
            return Err(MachineStoreErrorClass::Io);
        }
        // SAFETY: CreateMutexW returned one owned kernel handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        // SAFETY: the handle is a live mutex handle.
        match unsafe { WaitForSingleObject(handle.as_raw_handle() as _, TIMEOUT_MS) } {
            // An abandoned mutex means a previous join died holding it. Its own transaction is
            // either journalled or absent, so this join may proceed and the store decides.
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                *slot = Some(Exclusion(handle));
                Ok(())
            }
            WAIT_TIMEOUT => Err(MachineStoreErrorClass::Busy),
            _ => Err(MachineStoreErrorClass::Io),
        }
    }

    pub(super) fn release(slot: &mut Option<Exclusion>) {
        if let Some(exclusion) = slot.take() {
            // SAFETY: this process owns the mutex; releasing before the handle closes keeps the
            // next join from seeing it abandoned.
            unsafe { ReleaseMutex(exclusion.0.as_raw_handle() as _) };
        }
    }
}

#[cfg(not(windows))]
mod join_exclusion {
    use super::{MachineStoreErrorClass, StoreResult};

    pub(super) struct Exclusion;

    pub(super) fn acquire(_slot: &mut Option<Exclusion>) -> StoreResult<()> {
        Err(MachineStoreErrorClass::Unsupported)
    }

    pub(super) fn release(_slot: &mut Option<Exclusion>) {}
}

/// Stopping and starting exactly the two Sembazuru services, in the order their leases allow.
#[cfg(windows)]
mod service_control {
    use std::ffi::OsStr;
    use std::time::{Duration, Instant};

    use windows_service::service::{Service, ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{MachineStoreErrorClass, StoreResult};

    /// The two fixed names, nothing free-form. The worker runs the actions the daemon hands it, so
    /// it stops first and starts last.
    const STOP_ORDER: [&str; 2] = ["SembazuruWorker", "SembazuruDaemon"];
    const START_ORDER: [&str; 2] = ["SembazuruDaemon", "SembazuruWorker"];

    /// A service settles well inside this; the bound only keeps a stuck service from hanging a join.
    const SETTLE: Duration = Duration::from_secs(30);

    fn manager() -> StoreResult<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| MachineStoreErrorClass::Io)
    }

    /// Opens one service, or reports that it is not installed on this machine.
    fn open(name: &str, access: ServiceAccess) -> StoreResult<Option<Service>> {
        match manager()?.open_service(name, access) {
            Ok(service) => Ok(Some(service)),
            // A machine that never installed this service has nothing to stop or start, which is
            // not a join failure. Every other open failure is.
            Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
                Ok(None)
            }
            Err(_) => Err(MachineStoreErrorClass::Io),
        }
    }

    fn settle(service: &Service, done: impl Fn(ServiceState) -> bool) -> StoreResult<()> {
        let deadline = Instant::now() + SETTLE;
        loop {
            let state = service
                .query_status()
                .map_err(|_| MachineStoreErrorClass::Io)?
                .current_state;
            if done(state) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                // An unsettled service is reported, never assumed: the whole point of stopping is
                // that nothing keeps running on the configuration being replaced.
                return Err(MachineStoreErrorClass::Busy);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub(super) fn stop_all() -> StoreResult<()> {
        for name in STOP_ORDER {
            let Some(service) = open(name, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?
            else {
                continue;
            };
            if service
                .query_status()
                .map_err(|_| MachineStoreErrorClass::Io)?
                .current_state
                != ServiceState::Stopped
            {
                service.stop().map_err(|_| MachineStoreErrorClass::Io)?;
            }
            settle(&service, |state| state == ServiceState::Stopped)?;
        }
        Ok(())
    }

    pub(super) fn start_all() -> StoreResult<()> {
        for name in START_ORDER {
            let Some(service) = open(name, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?
            else {
                continue;
            };
            if service
                .query_status()
                .map_err(|_| MachineStoreErrorClass::Io)?
                .current_state
                == ServiceState::Stopped
            {
                service
                    .start(&[] as &[&OsStr])
                    .map_err(|_| MachineStoreErrorClass::Io)?;
            }
            // Running is where the SCM's report ends; whether the daemon is serving is a separate
            // question this sequence does not claim to have answered.
            settle(&service, |state| state == ServiceState::Running)?;
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod service_control {
    use super::{MachineStoreErrorClass, StoreResult};

    pub(super) fn stop_all() -> StoreResult<()> {
        Err(MachineStoreErrorClass::Unsupported)
    }

    pub(super) fn start_all() -> StoreResult<()> {
        Err(MachineStoreErrorClass::Unsupported)
    }
}

#[derive(Default)]
struct MachineStoreLifecycle {
    exclusion: Option<join_exclusion::Exclusion>,
}

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
        .map_err(|error| classify_backend_error(verb.operation(), error))
    }

    fn begin_update(&mut self) -> StoreResult<Self::Update> {
        begin_machine_token_update()
            .map_err(|error| classify_backend_error("begin-token-update", error))
    }

    fn migrate_token(&mut self, update: &mut Self::Update) -> TokenResult {
        migrate_machine_cluster_token_storage(update)
            .map_err(|error| classify_backend_error("migrate-token", error))
    }

    fn rotate_token(&mut self, update: &mut Self::Update, secret: &SecretInput) -> TokenResult {
        rotate_machine_cluster_token_storage(update, secret.expose())
            .map_err(|error| classify_backend_error("rotate-token", error))
    }

    fn clear_token(&mut self, update: &mut Self::Update) -> TokenResult {
        clear_machine_cluster_token_storage(update)
            .map_err(|error| classify_backend_error("clear-token", error))
    }

    fn join(&mut self, update: &mut Self::Update, payload: &JoinPayload) -> TokenResult {
        apply_machine_join_payload(update, payload)
            .map_err(|error| classify_backend_error("join", error))
    }

    fn begin_join_exclusion(&mut self) -> StoreResult<()> {
        join_exclusion::acquire(&mut self.exclusion)
    }

    fn end_join_exclusion(&mut self) {
        join_exclusion::release(&mut self.exclusion);
    }

    fn stop_services(&mut self) -> StoreResult<()> {
        service_control::stop_all()
    }

    fn start_services(&mut self) -> StoreResult<()> {
        service_control::start_all()
    }
}

fn parse_args<I>(args: I) -> Result<(Verb, Option<PipeName>), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    args.next().ok_or(CliError::InvalidArguments)?;
    let verb = args.next().ok_or(CliError::InvalidArguments)?;

    let verb = match verb.to_str() {
        Some("provision") => Verb::Provision,
        Some("rollback-provision") => Verb::RollbackProvision,
        Some("commit-provision") => Verb::CommitProvision,
        Some("uninstall") => Verb::Uninstall,
        Some("migrate-token") => Verb::MigrateToken,
        Some("rotate-token") => Verb::RotateToken,
        Some("clear-token") => Verb::ClearToken,
        Some("join") => Verb::Join,
        _ => return Err(CliError::InvalidArguments),
    };

    let pipe = if verb == Verb::Join {
        let flag = args.next().ok_or(CliError::InvalidArguments)?;
        if flag.to_str() != Some("--pipe") {
            return Err(CliError::InvalidArguments);
        }
        Some(PipeName::parse(
            &args.next().ok_or(CliError::InvalidArguments)?,
        )?)
    } else {
        None
    };
    if args.next().is_some() {
        return Err(CliError::InvalidArguments);
    }
    Ok((verb, pipe))
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
    input: VerbInput<'_>,
    actions: &mut A,
) -> Result<Option<&'static str>, CliError> {
    if !verb.is_token_maintenance() {
        return actions
            .lifecycle(verb)
            .map(|()| None)
            .map_err(CliError::Lifecycle);
    }
    if !input.matches(verb) {
        return Err(CliError::InvalidArguments);
    }
    if let (Verb::Join, VerbInput::Join(payload)) = (verb, &input) {
        return join_sequence(payload, actions);
    }
    let mut update = actions.begin_update().map_err(CliError::TokenMaintenance)?;
    let result = match (verb, input) {
        (Verb::MigrateToken, _) => actions.migrate_token(&mut update),
        (Verb::RotateToken, VerbInput::Secret(secret)) => actions.rotate_token(&mut update, secret),
        (Verb::ClearToken, _) => actions.clear_token(&mut update),
        (Verb::Join, VerbInput::Join(_)) => {
            unreachable!("join runs its own stop-update-start sequence")
        }
        _ => unreachable!("lifecycle verb was handled above"),
    }
    .map_err(CliError::TokenMaintenance)?;
    Ok(token_success(verb, result))
}

/// Runs one join as stop, update, release, start.
///
/// The order is forced by the store: a running service holds its own lease on the root, and the
/// update takes an exclusive one, so the write cannot happen while the services run. The reverse is
/// equally forced — the services cannot take their lease while the update guard is still held — so
/// the guard has to be dropped before anything is started.
///
/// Writing the configuration and running on it are reported separately. A join whose services did
/// not come back is not a successful join, even though the bytes are safely stored.
fn join_sequence<A: StoreActions>(
    payload: &JoinPayload,
    actions: &mut A,
) -> Result<Option<&'static str>, CliError> {
    actions
        .begin_join_exclusion()
        .map_err(CliError::TokenMaintenance)?;
    let outcome = join_under_exclusion(payload, actions);
    actions.end_join_exclusion();
    outcome
}

fn join_under_exclusion<A: StoreActions>(
    payload: &JoinPayload,
    actions: &mut A,
) -> Result<Option<&'static str>, CliError> {
    actions
        .stop_services()
        .map_err(CliError::TokenMaintenance)?;
    let saved = {
        let mut update = actions.begin_update().map_err(CliError::TokenMaintenance)?;
        actions
            .join(&mut update, payload)
            .map_err(CliError::TokenMaintenance)
        // The update guard is released here, before anything is started.
    };
    let saved = match saved {
        Ok(saved) => saved,
        Err(error) => {
            // Nothing was written, so leave the machine running as it was found.
            let _ = actions.start_services();
            return Err(error);
        }
    };
    actions
        .start_services()
        .map_err(|_| CliError::JoinNotApplied)?;
    Ok(token_success(Verb::Join, saved))
}

fn execute_authorized<A, F, G>(
    verb: Verb,
    identity: IdentityFacts,
    mut read_rotate: F,
    mut read_join: G,
    actions: &mut A,
) -> Result<Option<&'static str>, CliError>
where
    A: StoreActions,
    F: FnMut() -> Result<SecretInput, CliError>,
    G: FnMut() -> Result<JoinPayload, CliError>,
{
    // Authorization precedes every read, so an unauthorized caller never makes this process touch
    // the pipe or the terminal.
    authorize(verb, identity)?;
    match verb {
        Verb::RotateToken => {
            let secret = read_rotate()?;
            dispatch(verb, VerbInput::Secret(&secret), actions)
        }
        Verb::Join => {
            let payload = read_join()?;
            dispatch(verb, VerbInput::Join(&payload), actions)
        }
        _ => dispatch(verb, VerbInput::None, actions),
    }
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

fn invalid_join_input(reason: &'static str) -> CliError {
    eprintln!("sembazuru-storectl: join envelope refused; reason={reason}");
    CliError::TokenMaintenance(MachineStoreErrorClass::InvalidInput)
}

/// Reads one whole envelope from the one-shot pipe the caller named.
///
/// `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` caps what a server may do with this elevated
/// token to identification, so a process that took the name first cannot impersonate this one.
#[cfg(windows)]
fn read_join_payload(pipe: &PipeName) -> Result<JoinPayload, CliError> {
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };

    let wide: Vec<u16> = std::ffi::OsStr::new(pipe.as_str())
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: the name is NUL-terminated and live for the call; no attributes are inherited.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            0,
            null_mut(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(CliError::TokenMaintenance(MachineStoreErrorClass::Io));
    }
    // SAFETY: CreateFileW returned one owned kernel handle.
    let file = File::from(unsafe { OwnedHandle::from_raw_handle(handle.cast()) });
    read_join_envelope(file)
}

#[cfg(not(windows))]
fn read_join_payload(_pipe: &PipeName) -> Result<JoinPayload, CliError> {
    Err(CliError::Unsupported)
}

/// Decodes one envelope from a reader that is expected to end after exactly one.
fn read_join_envelope<R: Read>(reader: R) -> Result<JoinPayload, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    // One byte past the bound is enough to tell "at the limit" from "over it" without ever holding
    // an unbounded amount of a peer's output.
    reader
        .take((MAX_JOIN_PAYLOAD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::TokenMaintenance(MachineStoreErrorClass::Io))?;
    if bytes.len() > MAX_JOIN_PAYLOAD_BYTES {
        return Err(invalid_join_input(JoinPayloadError::Length.reason()));
    }
    JoinPayload::decode(&bytes).map_err(|error| invalid_join_input(error.reason()))
}

fn run() -> Result<Option<&'static str>, CliError> {
    let (verb, pipe) = parse_args(std::env::args_os())?;
    let identity = effective_identity(verb)?;
    execute_authorized(
        verb,
        identity,
        || {
            let stdin = io::stdin();
            read_rotate_token(stdin.is_terminal(), stdin.lock())
        },
        || {
            let pipe = pipe.as_ref().ok_or(CliError::InvalidArguments)?;
            read_join_payload(pipe)
        },
        &mut MachineStoreLifecycle::default(),
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

    use sembazuru_config_store::JoinField;

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
        fn join(&mut self, update: &mut u8, _payload: &JoinPayload) -> TokenResult {
            self.calls.push(Call("join", *update));
            Ok(MachineTokenMaintenanceResult::Changed)
        }
        fn begin_join_exclusion(&mut self) -> StoreResult<()> {
            self.calls.push(Call("exclude", 0));
            Ok(())
        }
        fn end_join_exclusion(&mut self) {
            self.calls.push(Call("release-exclusion", 0));
        }
        fn stop_services(&mut self) -> StoreResult<()> {
            self.calls.push(Call("stop", 0));
            Ok(())
        }
        fn start_services(&mut self) -> StoreResult<()> {
            self.calls.push(Call("start", 0));
            Ok(())
        }
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
    fn parser_accepts_only_the_eight_fixed_verbs() {
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
                Ok((expected, None))
            );
        }
        assert_eq!(
            parse_args(args(&[
                "sembazuru-storectl",
                "join",
                "--pipe",
                r"\\.\pipe\sembazuru-join-0123456789abcdef"
            ])),
            Ok((
                Verb::Join,
                Some(PipeName(
                    r"\\.\pipe\sembazuru-join-0123456789abcdef".to_owned()
                ))
            ))
        );
    }

    #[test]
    fn the_join_pipe_name_stays_one_local_pipe_component() {
        for rejected in [
            "join",
            r"\\.\pipe\",
            r"\\server\pipe\sembazuru-join",
            r"\\.\pipe\nested\name",
            r"\\.\pipe\sembazuru join",
            r"\\.\PIPE\sembazuru-join",
            r"C:\pipe\sembazuru-join",
            r"\\.\pipe\..\elsewhere",
        ] {
            assert_eq!(
                PipeName::parse(std::ffi::OsStr::new(rejected)),
                Err(CliError::InvalidArguments),
                "accepted {rejected}"
            );
        }
        let oversized = format!(
            r"\\.\pipe\{}",
            "n".repeat(PipeName::MAX_COMPONENT_BYTES + 1)
        );
        assert_eq!(
            PipeName::parse(std::ffi::OsStr::new(&oversized)),
            Err(CliError::InvalidArguments)
        );
        let longest = format!(r"\\.\pipe\{}", "n".repeat(PipeName::MAX_COMPONENT_BYTES));
        assert!(PipeName::parse(std::ffi::OsStr::new(&longest)).is_ok());
    }

    #[test]
    fn the_join_verb_requires_its_pipe_and_nothing_else() {
        for rejected in [
            vec!["sembazuru-storectl", "join"],
            vec!["sembazuru-storectl", "join", "--pipe"],
            vec!["sembazuru-storectl", "join", r"\\.\pipe\sembazuru-join"],
            vec![
                "sembazuru-storectl",
                "join",
                "--file",
                r"\\.\pipe\sembazuru-join",
            ],
            vec![
                "sembazuru-storectl",
                "join",
                "--pipe",
                r"\\.\pipe\sembazuru-join",
                "extra",
            ],
            vec![
                "sembazuru-storectl",
                "rotate-token",
                "--pipe",
                r"\\.\pipe\sembazuru-join",
            ],
        ] {
            assert_eq!(
                parse_args(args(&rejected)),
                Err(CliError::InvalidArguments),
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn the_join_envelope_reader_is_bounded_and_refuses_anything_else() {
        let payload = JoinPayload::new(
            JoinField::replace(b"cluster-token"),
            JoinField::Preserve,
            JoinField::Remove,
        )
        .expect("fixture payload");
        let bytes = payload.encode().expect("encode");
        assert!(read_join_envelope(Cursor::new(bytes.to_vec())).is_ok());

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        for refused in [Vec::new(), vec![0u8; 8], trailing] {
            assert_eq!(
                read_join_envelope(Cursor::new(refused))
                    .map(|_| ())
                    .unwrap_err(),
                invalid_token_input()
            );
        }

        let mut bounded = Counter(Cursor::new(vec![b'x'; MAX_JOIN_PAYLOAD_BYTES + 99]), 0);
        assert_eq!(
            read_join_envelope(&mut bounded).map(|_| ()).unwrap_err(),
            invalid_token_input()
        );
        assert_eq!(bounded.1, MAX_JOIN_PAYLOAD_BYTES + 1);
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
            for verb in [
                Verb::MigrateToken,
                Verb::RotateToken,
                Verb::ClearToken,
                Verb::Join,
            ] {
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

    /// A fake whose update guard records its own release, so the order of the join sequence is
    /// observable rather than assumed.
    #[derive(Clone, Default)]
    struct SequenceLog(std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>);

    impl SequenceLog {
        fn push(&self, step: &'static str) {
            self.0.borrow_mut().push(step);
        }

        fn steps(&self) -> Vec<&'static str> {
            self.0.borrow().clone()
        }
    }

    struct SequenceGuard(SequenceLog);

    impl Drop for SequenceGuard {
        fn drop(&mut self) {
            self.0.push("guard-released");
        }
    }

    #[derive(Default)]
    struct SequenceActions {
        log: SequenceLog,
        join_fails: bool,
        start_fails: bool,
    }

    impl StoreActions for SequenceActions {
        type Update = SequenceGuard;

        fn lifecycle(&mut self, _verb: Verb) -> StoreResult<()> {
            unreachable!("the join sequence never reaches a lifecycle verb")
        }

        fn begin_update(&mut self) -> StoreResult<SequenceGuard> {
            self.log.push("begin");
            Ok(SequenceGuard(self.log.clone()))
        }

        fn migrate_token(&mut self, _update: &mut SequenceGuard) -> TokenResult {
            unreachable!("not part of the join sequence")
        }

        fn rotate_token(
            &mut self,
            _update: &mut SequenceGuard,
            _secret: &SecretInput,
        ) -> TokenResult {
            unreachable!("not part of the join sequence")
        }

        fn clear_token(&mut self, _update: &mut SequenceGuard) -> TokenResult {
            unreachable!("not part of the join sequence")
        }

        fn join(&mut self, _update: &mut SequenceGuard, _payload: &JoinPayload) -> TokenResult {
            self.log.push("join");
            if self.join_fails {
                return Err(MachineStoreErrorClass::Io);
            }
            Ok(MachineTokenMaintenanceResult::Changed)
        }

        fn begin_join_exclusion(&mut self) -> StoreResult<()> {
            self.log.push("exclude");
            Ok(())
        }

        fn end_join_exclusion(&mut self) {
            self.log.push("release-exclusion");
        }

        fn stop_services(&mut self) -> StoreResult<()> {
            self.log.push("stop");
            Ok(())
        }

        fn start_services(&mut self) -> StoreResult<()> {
            self.log.push("start");
            if self.start_fails {
                return Err(MachineStoreErrorClass::Io);
            }
            Ok(())
        }
    }

    fn sequence_payload() -> JoinPayload {
        JoinPayload::new(
            JoinField::replace(b"cluster-token"),
            JoinField::Preserve,
            JoinField::Preserve,
        )
        .expect("fixture payload")
    }

    #[test]
    fn a_join_releases_its_update_guard_before_anything_is_started() {
        let mut actions = SequenceActions::default();
        let log = actions.log.clone();
        let result = join_sequence(&sequence_payload(), &mut actions);
        assert_eq!(result, Ok(Some("join-applied")));
        assert_eq!(
            log.steps(),
            vec![
                "exclude",
                "stop",
                "begin",
                "join",
                "guard-released",
                "start",
                "release-exclusion"
            ]
        );
    }

    #[test]
    fn a_failed_write_leaves_the_machine_running_as_it_was_found() {
        let mut actions = SequenceActions {
            join_fails: true,
            ..SequenceActions::default()
        };
        let log = actions.log.clone();
        let result = join_sequence(&sequence_payload(), &mut actions);
        assert_eq!(
            result,
            Err(CliError::TokenMaintenance(MachineStoreErrorClass::Io))
        );
        // The services are started again, and the exclusion is still given back.
        assert_eq!(
            log.steps(),
            vec![
                "exclude",
                "stop",
                "begin",
                "join",
                "guard-released",
                "start",
                "release-exclusion"
            ]
        );
    }

    #[test]
    fn a_saved_join_whose_services_stay_down_is_not_a_successful_join() {
        let mut actions = SequenceActions {
            start_fails: true,
            ..SequenceActions::default()
        };
        let log = actions.log.clone();
        let result = join_sequence(&sequence_payload(), &mut actions);
        assert_eq!(result, Err(CliError::JoinNotApplied));
        assert_eq!(CliError::JoinNotApplied.code(), "join-saved-not-applied");
        assert_ne!(CliError::JoinNotApplied.exit_code(), 0);
        assert_eq!(*log.steps().last().expect("a step"), "release-exclusion");
    }

    #[test]
    fn a_join_that_cannot_take_the_exclusion_touches_nothing() {
        struct RefusingActions(SequenceLog);

        impl StoreActions for RefusingActions {
            type Update = SequenceGuard;
            fn lifecycle(&mut self, _verb: Verb) -> StoreResult<()> {
                unreachable!("nothing runs")
            }
            fn begin_update(&mut self) -> StoreResult<SequenceGuard> {
                unreachable!("nothing runs")
            }
            fn migrate_token(&mut self, _update: &mut SequenceGuard) -> TokenResult {
                unreachable!("nothing runs")
            }
            fn rotate_token(
                &mut self,
                _update: &mut SequenceGuard,
                _secret: &SecretInput,
            ) -> TokenResult {
                unreachable!("nothing runs")
            }
            fn clear_token(&mut self, _update: &mut SequenceGuard) -> TokenResult {
                unreachable!("nothing runs")
            }
            fn join(&mut self, _update: &mut SequenceGuard, _payload: &JoinPayload) -> TokenResult {
                unreachable!("nothing runs")
            }
            fn begin_join_exclusion(&mut self) -> StoreResult<()> {
                self.0.push("exclude-refused");
                Err(MachineStoreErrorClass::Busy)
            }
            fn end_join_exclusion(&mut self) {
                unreachable!("an exclusion that was never taken is not given back")
            }
            fn stop_services(&mut self) -> StoreResult<()> {
                unreachable!("nothing runs")
            }
            fn start_services(&mut self) -> StoreResult<()> {
                unreachable!("nothing runs")
            }
        }

        let log = SequenceLog::default();
        let mut actions = RefusingActions(log.clone());
        assert_eq!(
            join_sequence(&sequence_payload(), &mut actions),
            Err(CliError::TokenMaintenance(MachineStoreErrorClass::Busy))
        );
        assert_eq!(log.steps(), vec!["exclude-refused"]);
    }

    #[test]
    fn authorization_precedes_input_and_exact_backend_dispatch() {
        for identity in [
            IdentityFacts::user(true, false),
            IdentityFacts::user(false, false),
        ] {
            for verb in [Verb::RotateToken, Verb::Join] {
                let (mut reads, mut joins) = (0, 0);
                let mut actions = RecordingActions::default();
                let result = execute_authorized(
                    verb,
                    identity,
                    || {
                        reads += 1;
                        Ok(SecretInput::new("unreachable".to_owned()))
                    },
                    || {
                        joins += 1;
                        unreachable!("an unauthorized join must not touch the pipe")
                    },
                    &mut actions,
                );
                assert_eq!(
                    (result, reads, joins, actions.calls.len()),
                    (Err(CliError::Unauthorized), 0, 0, 0)
                );
            }
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
            (
                Verb::Join,
                vec![
                    Call("exclude", 0),
                    Call("stop", 0),
                    Call("begin", 0),
                    Call("join", 73),
                    Call("start", 0),
                    Call("release-exclusion", 0),
                ],
            ),
        ] {
            let (mut reads, mut joins, mut actions) = (0, 0, RecordingActions::default());
            execute_authorized(
                verb,
                IdentityFacts::SYSTEM,
                || {
                    reads += 1;
                    Ok(SecretInput::new("test-input".to_owned()))
                },
                || {
                    joins += 1;
                    JoinPayload::new(
                        JoinField::replace(b"cluster-token"),
                        JoinField::Preserve,
                        JoinField::Preserve,
                    )
                    .map_err(|error| invalid_join_input(error.reason()))
                },
                &mut actions,
            )
            .unwrap();
            assert_eq!(
                (reads, joins, actions.calls),
                (
                    usize::from(verb == Verb::RotateToken),
                    usize::from(verb == Verb::Join),
                    expected
                )
            );
        }
    }

    #[test]
    fn success_secret_shape_and_redaction_are_fixed() {
        use MachineTokenMaintenanceResult::{Changed, Unchanged};

        let secret = SecretInput::new("cli-secret-sentinel-91827".to_owned());
        let mut actions = RecordingActions::default();
        let payload = JoinPayload::new(
            JoinField::replace(b"cluster-token"),
            JoinField::Preserve,
            JoinField::Preserve,
        )
        .expect("fixture payload");
        // A verb never accepts the other verb's input, and never runs without its own.
        for (verb, input) in [
            (Verb::RotateToken, VerbInput::None),
            (Verb::RotateToken, VerbInput::Join(&payload)),
            (Verb::Join, VerbInput::None),
            (Verb::Join, VerbInput::Secret(&secret)),
            (Verb::MigrateToken, VerbInput::Secret(&secret)),
            (Verb::ClearToken, VerbInput::Join(&payload)),
        ] {
            assert_eq!(
                dispatch(verb, input, &mut actions).unwrap_err(),
                CliError::InvalidArguments
            );
        }
        dispatch(Verb::RotateToken, VerbInput::Secret(&secret), &mut actions).unwrap();
        dispatch(Verb::Join, VerbInput::Join(&payload), &mut actions).unwrap();
        assert!(!format!("{payload:?}").contains("cluster-token"));
        assert!(!format!("{secret:?}{:?}", actions.calls).contains(secret.expose()));
        for (verb, changed) in [
            (Verb::MigrateToken, "token-migrated"),
            (Verb::RotateToken, "token-rotated"),
            (Verb::ClearToken, "token-cleared"),
            (Verb::Join, "join-applied"),
        ] {
            assert_eq!(token_success(verb, Changed), Some(changed));
        }
        assert_eq!(
            token_success(Verb::Join, Unchanged).unwrap(),
            "token-unchanged"
        );
        assert_eq!(
            token_success(Verb::MigrateToken, Unchanged).unwrap(),
            "token-unchanged"
        );
        assert_eq!(
            dispatch(Verb::Provision, VerbInput::None, &mut actions),
            Ok(None)
        );
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

    #[test]
    fn backend_diagnostic_is_structured_and_preserves_token_io_exit_contract() {
        let diagnostic = backend_diagnostic("rotate-token", "atomic rename", Some(5));

        assert_eq!(
            diagnostic,
            "sembazuru-storectl: backend operation=rotate-token; context=atomic rename; raw-os-error=5"
        );
        assert!(!diagnostic.contains("cli-secret-sentinel-91827"));
        assert!(!diagnostic.contains("C:\\ProgramData\\Sembazuru"));

        let error = CliError::TokenMaintenance(MachineStoreErrorClass::Io);
        assert_eq!(error.code(), "token-io-failed");
        assert_eq!(error.exit_code(), 11);
    }
}
