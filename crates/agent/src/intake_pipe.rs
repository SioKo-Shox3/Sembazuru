//! Authenticated Windows named-pipe primitives for LocalIntake.
//!
//! The production daemon and tonic transport are wired in a later task. This
//! module owns the security boundary: an explicit protected DACL, client-side
//! server authentication, and caller identity capture before the first bytes
//! read from a connection are exposed to HTTP/2.

use std::ffi::c_void;
use std::fmt;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use tokio_stream::Stream;
use tonic::transport::server::Connected;
use windows_service::service::{ServiceAccess, ServiceState, ServiceType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetTokenInformation,
    PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenImpersonationLevel,
    TokenPrimary, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
    SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, ImpersonateNamedPipeClient};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

pub(crate) const PIPE_NAME: &str = r"\\.\pipe\Sembazuru.LocalIntake.v1";
pub(crate) const PIPE_ENDPOINT: &str = "npipe://Sembazuru.LocalIntake.v1";
// CreateFileW with SECURITY_SQOS_PRESENT needs FILE_READ_ATTRIBUTES in addition
// to the standard rights and read/write data observed here. Authenticated users
// still never get FILE_CREATE_PIPE_INSTANCE (0x4). The separate dynamic ACE
// gives only the concrete server SID the full-duplex handle rights required by
// PIPE_ACCESS_DUPLEX, including the right to create the next server instance.
pub(crate) const PROTECTED_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120083;;;AU)";
pub(crate) const AUTHENTICATED_USERS_ACCESS_MASK: u32 = 0x0012_0083;
const SERVER_INSTANCE_ACCESS_MASK: u32 = 0x0012_019f;
const CLIENT_ACCESS_MASK: u32 = FILE_READ_DATA | FILE_WRITE_DATA;
const SECURITY_IMPERSONATION_LEVEL: u32 = SECURITY_IMPERSONATION;
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

#[derive(Debug, Clone)]
pub(crate) struct AuthError {
    kind: io::ErrorKind,
    message: String,
}

impl AuthError {
    fn from_last_os_error(context: &'static str) -> Self {
        Self::from_io(context, io::Error::last_os_error())
    }

    fn from_io(context: &'static str, error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: format!("{context}: {error}"),
        }
    }

    fn permission_denied(message: impl Into<String>) -> Self {
        Self {
            kind: io::ErrorKind::PermissionDenied,
            message: message.into(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AuthError {}

/// Caller identity established from the pipe impersonation token.
///
/// `primary_token` is already restricted with `DISABLE_MAX_PRIVILEGE`; callers
/// must never replace it with the daemon's token on an execution failure.
#[derive(Clone)]
pub(crate) struct CallerIdentity {
    pub(crate) sid: String,
    pub(crate) primary_token: Arc<OwnedHandle>,
}

impl fmt::Debug for CallerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallerIdentity")
            .field("sid", &self.sid)
            .field("primary_token", &"<owned handle>")
            .finish()
    }
}

#[cfg(test)]
impl CallerIdentity {
    pub(crate) fn restricted_current_for_test() -> io::Result<Self> {
        let mut token = null_mut();
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut token,
            )
        };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
        let sid =
            token_sid(token.as_raw_handle() as HANDLE).map_err(|error| error.to_io_error())?;
        let mut restricted = null_mut();
        let created = unsafe {
            CreateRestrictedToken(
                token.as_raw_handle() as HANDLE,
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                0,
                null(),
                &mut restricted,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            sid,
            primary_token: Arc::new(unsafe {
                OwnedHandle::from_raw_handle(restricted as RawHandle)
            }),
        })
    }
}

type IdentityResult = Result<CallerIdentity, AuthError>;

/// Shared connect info cloned into tonic request extensions before the first
/// read. The same cell is populated only after caller authentication succeeds.
#[derive(Clone, Default)]
pub(crate) struct CallerIdentityConnectInfo(Arc<OnceLock<IdentityResult>>);

impl CallerIdentityConnectInfo {
    pub(crate) fn caller_identity(&self) -> Result<Option<CallerIdentity>, AuthError> {
        match self.0.get() {
            None => Ok(None),
            Some(Ok(identity)) => Ok(Some(identity.clone())),
            Some(Err(error)) => Err(error.clone()),
        }
    }
}

/// Server-side pipe that authenticates the caller on the first successful read.
pub(crate) struct AuthenticatedPipe {
    inner: Option<NamedPipeServer>,
    connect_info: CallerIdentityConnectInfo,
}

impl AuthenticatedPipe {
    pub(crate) fn new(pipe: NamedPipeServer) -> Self {
        Self {
            inner: Some(pipe),
            connect_info: CallerIdentityConnectInfo::default(),
        }
    }

    fn closed_error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "authenticated pipe is closed")
    }

    fn authentication_error(&mut self, before: usize, buffer: &mut ReadBuf<'_>) -> io::Error {
        buffer.set_filled(before);
        self.inner.take();
        self.connect_info
            .0
            .get()
            .and_then(|result| result.as_ref().err())
            .map(AuthError::to_io_error)
            .unwrap_or_else(Self::closed_error)
    }
}

impl Connected for AuthenticatedPipe {
    type ConnectInfo = CallerIdentityConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.connect_info.clone()
    }
}

impl AsyncRead for AuthenticatedPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.connect_info.0.get(), Some(Err(_))) {
            return Poll::Ready(Err(this.authentication_error(buffer.filled().len(), buffer)));
        }

        let before = buffer.filled().len();
        let Some(pipe) = this.inner.as_mut() else {
            return Poll::Ready(Err(Self::closed_error()));
        };
        match Pin::new(&mut *pipe).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() > before => {
                if this.connect_info.0.get().is_none() {
                    let handle = pipe.as_raw_handle() as usize;
                    let result = capture_caller_on_os_thread(handle);
                    let failed = result.is_err();
                    let _ = this.connect_info.0.set(result);
                    if failed {
                        return Poll::Ready(Err(this.authentication_error(before, buffer)));
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for AuthenticatedPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(pipe) = this.inner.as_mut() else {
            return Poll::Ready(Err(Self::closed_error()));
        };
        Pin::new(pipe).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(pipe) = this.inner.as_mut() else {
            return Poll::Ready(Err(Self::closed_error()));
        };
        Pin::new(pipe).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(pipe) = this.inner.as_mut() else {
            return Poll::Ready(Err(Self::closed_error()));
        };
        Pin::new(pipe).poll_shutdown(context)
    }
}

/// Creates the production LocalIntake pipe. Only the first listening instance
/// sets `FILE_FLAG_FIRST_PIPE_INSTANCE`; later instances retain the protected
/// DACL and remote-client rejection.
pub(crate) fn create_server(first_instance: bool) -> io::Result<NamedPipeServer> {
    create_server_at(PIPE_NAME, first_instance)
}

/// Incoming stream for tonic's LocalIntake server.
///
/// The next protected listener is created before a connected instance is
/// yielded. This closes the gap where another process could create the first
/// pipe instance or where a second launcher would see a transient missing pipe.
pub(crate) struct AuthenticatedPipeIncoming {
    inner: Pin<Box<dyn Stream<Item = io::Result<AuthenticatedPipe>> + Send>>,
}

impl AuthenticatedPipeIncoming {
    pub(crate) fn new(first: NamedPipeServer) -> Self {
        Self::with_factory(first, || create_server(false))
    }

    fn with_factory<F>(first: NamedPipeServer, next_factory: F) -> Self
    where
        F: Fn() -> io::Result<NamedPipeServer> + Send + Sync + 'static,
    {
        let stream = async_stream::try_stream! {
            let mut current = first;
            loop {
                current.connect().await?;
                let next = next_factory()?;
                let connected = std::mem::replace(&mut current, next);
                yield AuthenticatedPipe::new(connected);
            }
        };
        Self {
            inner: Box::pin(stream),
        }
    }
}

impl Stream for AuthenticatedPipeIncoming {
    type Item = io::Result<AuthenticatedPipe>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(context)
    }
}

#[cfg(test)]
pub(crate) fn test_incoming_at(name: String) -> io::Result<(AuthenticatedPipeIncoming, String)> {
    let caller_sid = current_process_sid()?;
    let first = create_server_at(&name, true)?;
    let next_name = name.clone();
    Ok((
        AuthenticatedPipeIncoming::with_factory(first, move || create_server_at(&next_name, false)),
        caller_sid,
    ))
}

#[cfg(test)]
pub(crate) fn open_test_client_at(
    name: &str,
    allowed_server_sid: &str,
) -> io::Result<NamedPipeClient> {
    open_client_at(
        name,
        SECURITY_IMPERSONATION_LEVEL,
        &[allowed_server_sid.to_owned()],
    )
}

fn create_server_at(name: &str, first_instance: bool) -> io::Result<NamedPipeServer> {
    let server_sid = current_process_sid()?;
    let sddl = format!("{PROTECTED_SDDL}(A;;0x{SERVER_INSTANCE_ACCESS_MASK:08x};;;{server_sid})");
    create_server_at_with_sddl(name, first_instance, &sddl)
}

fn create_server_at_with_sddl(
    name: &str,
    first_instance: bool,
    sddl: &str,
) -> io::Result<NamedPipeServer> {
    let sddl = wide_null(sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    };
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

/// Opens the production pipe with specific access (never `GENERIC_WRITE`) and
/// authenticates the server before returning a handle that could send HTTP/2.
pub(crate) fn open_authenticated_client() -> io::Result<NamedPipeClient> {
    let caller_sid = current_process_sid()?;
    open_client_at(
        PIPE_NAME,
        SECURITY_IMPERSONATION_LEVEL,
        &[LOCAL_SYSTEM_SID.to_owned(), caller_sid],
    )
}

fn open_client_at(
    name: &str,
    impersonation_level: u32,
    allowed_server_sids: &[String],
) -> io::Result<NamedPipeClient> {
    let wide_name = wide_null(name);
    let handle = unsafe {
        CreateFileW(
            wide_name.as_ptr(),
            CLIENT_ACCESS_MASK,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | impersonation_level,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("CreateFileW({name:?}): {}", io::Error::last_os_error()),
        ));
    }

    let owned = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    let server_sid = server_process_sid(handle)?;
    if !allowed_server_sids
        .iter()
        .any(|allowed| allowed == &server_sid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("named-pipe server SID {server_sid} is not trusted"),
        ));
    }

    let raw = owned.into_raw_handle();
    unsafe { NamedPipeClient::from_raw_handle(raw) }
}

fn capture_caller_on_os_thread(handle: usize) -> IdentityResult {
    std::thread::Builder::new()
        .name("local-intake-caller-auth".into())
        .spawn(move || capture_caller(handle as HANDLE))
        .map_err(|error| AuthError::from_io("spawn caller-auth thread", error))?
        .join()
        .map_err(|_| AuthError {
            kind: io::ErrorKind::Other,
            message: "caller-auth thread panicked".into(),
        })?
}

fn capture_caller(pipe: HANDLE) -> IdentityResult {
    let impersonated = unsafe { ImpersonateNamedPipeClient(pipe) };
    if impersonated == 0 {
        return Err(AuthError::from_last_os_error("ImpersonateNamedPipeClient"));
    }

    let result = capture_impersonated_caller();
    let reverted = unsafe { RevertToSelf() };
    if reverted == 0 {
        return Err(AuthError::from_last_os_error("RevertToSelf"));
    }
    result
}

fn capture_impersonated_caller() -> IdentityResult {
    let mut token = null_mut();
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            1,
            &mut token,
        )
    };
    if opened == 0 {
        return Err(AuthError::from_last_os_error("OpenThreadToken"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };

    let mut level = 0;
    let mut returned = 0;
    let level_ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenImpersonationLevel,
            (&mut level as *mut i32).cast(),
            std::mem::size_of::<i32>() as u32,
            &mut returned,
        )
    };
    if level_ok == 0 {
        return Err(AuthError::from_last_os_error(
            "GetTokenInformation(TokenImpersonationLevel)",
        ));
    }
    if level < SecurityImpersonation {
        return Err(AuthError::permission_denied(format!(
            "caller token impersonation level {level} is below SecurityImpersonation"
        )));
    }

    let sid = token_sid(token.as_raw_handle() as HANDLE)?;
    let mut primary = null_mut();
    let duplicated = unsafe {
        DuplicateTokenEx(
            token.as_raw_handle() as HANDLE,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    };
    if duplicated == 0 {
        return Err(AuthError::from_last_os_error(
            "DuplicateTokenEx(TokenPrimary)",
        ));
    }
    let primary = unsafe { OwnedHandle::from_raw_handle(primary as RawHandle) };

    let mut restricted = null_mut();
    let restricted_ok = unsafe {
        CreateRestrictedToken(
            primary.as_raw_handle() as HANDLE,
            DISABLE_MAX_PRIVILEGE,
            0,
            null(),
            0,
            null(),
            0,
            null(),
            &mut restricted,
        )
    };
    if restricted_ok == 0 {
        return Err(AuthError::from_last_os_error(
            "CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)",
        ));
    }

    Ok(CallerIdentity {
        sid,
        primary_token: Arc::new(unsafe { OwnedHandle::from_raw_handle(restricted as RawHandle) }),
    })
}

fn current_process_sid() -> io::Result<String> {
    let mut token = null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    token_sid(token.as_raw_handle() as HANDLE).map_err(|error| error.to_io_error())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerSidLookupStage {
    OpenProcess,
    OpenProcessToken,
    TokenUser,
}

impl fmt::Display for ServerSidLookupStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug)]
struct ServerSidLookupError {
    stage: ServerSidLookupStage,
    process_id: u32,
    error: io::Error,
}

impl fmt::Display for ServerSidLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}): {}", self.stage, self.process_id, self.error)
    }
}

impl std::error::Error for ServerSidLookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug)]
struct ScmAttestationError {
    direct: ServerSidLookupError,
    scm: io::Error,
}

impl fmt::Display for ScmAttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; SCM attestation failed: {}", self.direct, self.scm)
    }
}

impl std::error::Error for ScmAttestationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.direct)
    }
}

fn route_server_sid<F>(
    direct: Result<String, ServerSidLookupError>,
    attest: F,
) -> io::Result<String>
where
    F: FnOnce(u32) -> io::Result<String>,
{
    match direct {
        Ok(sid) => Ok(sid),
        Err(error)
            if error.stage == ServerSidLookupStage::OpenProcess
                && error.error.raw_os_error() == Some(5) =>
        {
            let process_id = error.process_id;
            attest(process_id).map_err(|scm| {
                let kind = error.error.kind();
                io::Error::new(kind, ScmAttestationError { direct: error, scm })
            })
        }
        Err(error) => {
            let kind = error.error.kind();
            Err(io::Error::new(kind, error))
        }
    }
}

fn direct_server_process_sid(process_id: u32) -> Result<String, ServerSidLookupError> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        let error = io::Error::last_os_error();
        return Err(ServerSidLookupError {
            stage: ServerSidLookupStage::OpenProcess,
            process_id,
            error,
        });
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    let mut token = null_mut();
    let token_ok =
        unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) };
    if token_ok == 0 {
        return Err(ServerSidLookupError {
            stage: ServerSidLookupStage::OpenProcessToken,
            process_id,
            error: io::Error::last_os_error(),
        });
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    token_sid(token.as_raw_handle() as HANDLE).map_err(|error| ServerSidLookupError {
        stage: ServerSidLookupStage::TokenUser,
        process_id,
        error: error.to_io_error(),
    })
}

struct ServiceAttestationFacts<'a> {
    process_id: u32,
    status1_state: ServiceState,
    status1_pid: Option<u32>,
    status1_type: ServiceType,
    config_type: ServiceType,
    account_name: Option<&'a std::ffi::OsStr>,
    status2_state: ServiceState,
    status2_pid: Option<u32>,
    status2_type: ServiceType,
}

fn validate_service_attestation(facts: &ServiceAttestationFacts<'_>) -> Result<(), &'static str> {
    if facts.process_id == 0 {
        return Err("pipe server PID is zero");
    }
    if facts.status1_state != ServiceState::Running || facts.status2_state != ServiceState::Running
    {
        return Err("service was not Running in both status queries");
    }
    if facts.status1_pid != Some(facts.process_id) || facts.status2_pid != Some(facts.process_id) {
        return Err("service PID did not stably match the pipe server PID");
    }
    if facts.status1_type != ServiceType::OWN_PROCESS
        || facts.config_type != ServiceType::OWN_PROCESS
        || facts.status2_type != ServiceType::OWN_PROCESS
    {
        return Err("service type was not exactly OWN_PROCESS in all queries");
    }
    if facts.account_name != Some(std::ffi::OsStr::new("LocalSystem")) {
        return Err("service account was not exactly LocalSystem");
    }
    Ok(())
}

fn scm_error(context: &str, error: impl fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}

fn attest_system_service_process(process_id: u32) -> io::Result<String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| scm_error("open local ServiceManager", error))?;
    let service = manager
        .open_service(
            crate::service::SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        )
        .map_err(|error| scm_error("open SembazuruDaemon service", error))?;
    let status1 = service
        .query_status()
        .map_err(|error| scm_error("query service status 1", error))?;
    let config = service
        .query_config()
        .map_err(|error| scm_error("query service config", error))?;
    let status2 = service
        .query_status()
        .map_err(|error| scm_error("query service status 2", error))?;
    validate_service_attestation(&ServiceAttestationFacts {
        process_id,
        status1_state: status1.current_state,
        status1_pid: status1.process_id,
        status1_type: status1.service_type,
        config_type: config.service_type,
        account_name: config.account_name.as_deref(),
        status2_state: status2.current_state,
        status2_pid: status2.process_id,
        status2_type: status2.service_type,
    })
    .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
    Ok(LOCAL_SYSTEM_SID.to_owned())
}

#[cfg(test)]
pub(crate) fn process_sid_for_test(process_id: u32) -> io::Result<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    let mut token = null_mut();
    let opened =
        unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    token_sid(token.as_raw_handle() as HANDLE).map_err(|error| error.to_io_error())
}

fn server_process_sid(pipe: HANDLE) -> io::Result<String> {
    let mut process_id = 0;
    let pid_ok = unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) };
    if pid_ok == 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "GetNamedPipeServerProcessId: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    route_server_sid(
        direct_server_process_sid(process_id),
        attest_system_service_process,
    )
}

fn token_sid(token: HANDLE) -> Result<String, AuthError> {
    let mut required = 0;
    let first = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required) };
    if first != 0 || required == 0 {
        return Err(AuthError::from_last_os_error(
            "GetTokenInformation(TokenUser size)",
        ));
    }
    let size_error = io::Error::last_os_error();
    if size_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(AuthError::from_io(
            "GetTokenInformation(TokenUser size)",
            size_error,
        ));
    }

    let mut buffer = vec![0u8; required as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if ok == 0 {
        return Err(AuthError::from_last_os_error(
            "GetTokenInformation(TokenUser)",
        ));
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(user.User.Sid)
}

fn sid_to_string(sid: *mut c_void) -> Result<String, AuthError> {
    let mut string_sid = null_mut();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut string_sid) };
    if ok == 0 {
        return Err(AuthError::from_last_os_error("ConvertSidToStringSidW"));
    }

    let mut length = 0;
    unsafe {
        while *string_sid.add(length) != 0 {
            length += 1;
        }
    }
    let value = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(string_sid, length)) };
    unsafe {
        let _ = LocalFree(string_sid.cast());
    }
    Ok(value)
}

fn wide_null(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::ffi::OsStr;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, RawHandle};
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tonic::transport::server::Connected;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CreateWellKnownSid,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_CREATE_PIPE_INSTANCE, SECURITY_IDENTIFICATION,
    };

    use super::*;

    static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

    fn unique_pipe(label: &str) -> String {
        format!(
            r"\\.\pipe\Sembazuru.LocalIntake.v1.test.{}.{}.{}",
            std::process::id(),
            label,
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn known_sid(kind: i32) -> Vec<u8> {
        let mut size = 0;
        unsafe {
            let _ = CreateWellKnownSid(kind, null_mut(), null_mut(), &mut size);
        }
        let mut sid = vec![0u8; size as usize];
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                null_mut(),
                sid.as_mut_ptr().cast::<c_void>(),
                &mut size,
            )
        };
        assert_ne!(ok, 0, "CreateWellKnownSid({kind}) failed");
        sid
    }

    fn lookup_failure(stage: ServerSidLookupStage, error: io::Error) -> ServerSidLookupError {
        ServerSidLookupError {
            stage,
            process_id: 7264,
            error,
        }
    }

    #[test]
    fn scm_routing_is_only_for_open_process_raw_access_denied() {
        let calls = Cell::new(0);
        let sid = route_server_sid(Ok("direct-sid".into()), |_| {
            calls.set(calls.get() + 1);
            Ok(LOCAL_SYSTEM_SID.into())
        })
        .unwrap();
        assert_eq!(sid, "direct-sid");
        assert_eq!(calls.get(), 0);

        let sid = route_server_sid(
            Err(lookup_failure(
                ServerSidLookupStage::OpenProcess,
                io::Error::from_raw_os_error(5),
            )),
            |_| {
                calls.set(calls.get() + 1);
                Ok(LOCAL_SYSTEM_SID.into())
            },
        )
        .unwrap();
        assert_eq!(sid, LOCAL_SYSTEM_SID);
        assert_eq!(calls.get(), 1);
        let error = route_server_sid(
            Err(lookup_failure(
                ServerSidLookupStage::OpenProcess,
                io::Error::from_raw_os_error(5),
            )),
            |_| Err(io::Error::other("SCM query sentinel")),
        )
        .unwrap_err();
        assert!(error.get_ref().unwrap().source().is_some());
        let error = error.to_string();
        assert!(error.contains("OpenProcess(7264)"));
        assert!(error.contains("os error 5"));
        assert!(error.contains("SCM query sentinel"));
        for (stage, error) in [
            (
                ServerSidLookupStage::OpenProcess,
                io::Error::new(io::ErrorKind::PermissionDenied, "no raw code"),
            ),
            (
                ServerSidLookupStage::OpenProcessToken,
                io::Error::from_raw_os_error(5),
            ),
            (
                ServerSidLookupStage::TokenUser,
                io::Error::from_raw_os_error(5),
            ),
            (
                ServerSidLookupStage::OpenProcess,
                io::Error::from_raw_os_error(87),
            ),
        ] {
            assert!(
                route_server_sid(Err(lookup_failure(stage, error)), |_| {
                    calls.set(calls.get() + 1);
                    Ok(LOCAL_SYSTEM_SID.into())
                })
                .is_err()
            );
        }
        assert_eq!(calls.get(), 1);
    }

    fn valid_attestation(pid: u32) -> ServiceAttestationFacts<'static> {
        ServiceAttestationFacts {
            process_id: pid,
            status1_state: ServiceState::Running,
            status1_pid: Some(pid),
            status1_type: ServiceType::OWN_PROCESS,
            config_type: ServiceType::OWN_PROCESS,
            account_name: Some(OsStr::new("LocalSystem")),
            status2_state: ServiceState::Running,
            status2_pid: Some(pid),
            status2_type: ServiceType::OWN_PROCESS,
        }
    }

    #[test]
    fn system_service_attestation_requires_exact_stable_facts() {
        let pid = 7264;
        assert!(validate_service_attestation(&valid_attestation(pid)).is_ok());

        let mut invalid = valid_attestation(pid);
        invalid.status1_type = ServiceType::SHARE_PROCESS;
        assert!(validate_service_attestation(&invalid).is_err());
        invalid = valid_attestation(pid);
        invalid.status2_type = ServiceType::OWN_PROCESS | ServiceType::INTERACTIVE_PROCESS;
        assert!(validate_service_attestation(&invalid).is_err());
        invalid = valid_attestation(pid);
        invalid.config_type = ServiceType::SHARE_PROCESS;
        assert!(validate_service_attestation(&invalid).is_err());

        for state in [ServiceState::StartPending, ServiceState::Stopped] {
            invalid = valid_attestation(pid);
            invalid.status1_state = state;
            assert!(validate_service_attestation(&invalid).is_err());
            invalid = valid_attestation(pid);
            invalid.status2_state = state;
            assert!(validate_service_attestation(&invalid).is_err());
        }
        for bad_pid in [None, Some(0), Some(pid + 1)] {
            invalid = valid_attestation(pid);
            invalid.status1_pid = bad_pid;
            assert!(validate_service_attestation(&invalid).is_err());
            invalid = valid_attestation(pid);
            invalid.status2_pid = bad_pid;
            assert!(validate_service_attestation(&invalid).is_err());
        }
        for account in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("localsystem")),
            Some(OsStr::new("NT AUTHORITY\\SYSTEM")),
            Some(OsStr::new("NT AUTHORITY\\NetworkService")),
            Some(OsStr::new("NT SERVICE\\SembazuruDaemon")),
        ] {
            invalid = valid_attestation(pid);
            invalid.account_name = account;
            assert!(validate_service_attestation(&invalid).is_err());
        }
    }

    unsafe fn ace_mask_for(dacl: *mut ACL, wanted_sid: &[u8], ace_count: u32) -> Option<u32> {
        for index in 0..ace_count {
            let mut raw_ace = null_mut();
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
                panic!(
                    "GetAce({index}) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
            let sid = std::ptr::addr_of!(ace.SidStart).cast::<c_void>();
            if unsafe {
                EqualSid(
                    sid.cast_mut(),
                    wanted_sid.as_ptr().cast::<c_void>().cast_mut(),
                )
            } != 0
            {
                return Some(ace.Mask);
            }
        }
        None
    }

    unsafe fn ace_masks_for_sid_string(
        dacl: *mut ACL,
        wanted_sid: &str,
        ace_count: u32,
    ) -> Vec<u32> {
        let mut masks = Vec::new();
        for index in 0..ace_count {
            let mut raw_ace = null_mut();
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
                panic!(
                    "GetAce({index}) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
            let sid = std::ptr::addr_of!(ace.SidStart).cast::<c_void>().cast_mut();
            if sid_to_string(sid).unwrap() == wanted_sid {
                masks.push(ace.Mask);
            }
        }
        masks
    }

    #[tokio::test]
    async fn pipe_dacl_is_protected_and_exact() {
        assert_eq!(PIPE_NAME, r"\\.\pipe\Sembazuru.LocalIntake.v1");
        assert_eq!(PIPE_ENDPOINT, "npipe://Sembazuru.LocalIntake.v1");
        assert_eq!(
            PROTECTED_SDDL,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120083;;;AU)"
        );

        let server = create_server_at(&unique_pipe("dacl"), true).unwrap();
        let mut dacl = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                server.as_raw_handle() as RawHandle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        assert!(!descriptor.is_null());
        assert!(!dacl.is_null());

        let mut control = 0;
        let mut revision = 0;
        let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        assert_ne!(ok, 0, "GetSecurityDescriptorControl failed");
        assert_ne!(control & SE_DACL_PROTECTED, 0, "DACL must be protected");

        let mut info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        assert_ne!(ok, 0, "GetAclInformation failed");
        assert_eq!(
            info.AceCount, 4,
            "DACL must contain SY, BA, AU, and the concrete server SID"
        );

        let system = known_sid(WinLocalSystemSid);
        let admins = known_sid(WinBuiltinAdministratorsSid);
        let authenticated_users = known_sid(WinAuthenticatedUserSid);
        let system_mask = unsafe { ace_mask_for(dacl, &system, info.AceCount) };
        let admins_mask = unsafe { ace_mask_for(dacl, &admins, info.AceCount) };
        let users_mask = unsafe { ace_mask_for(dacl, &authenticated_users, info.AceCount) };
        // CreateNamedPipe maps the generic GA entries to this object's concrete
        // full-access mask before storing the ACL.
        assert_eq!(system_mask, Some(FILE_ALL_ACCESS));
        assert_eq!(admins_mask, Some(FILE_ALL_ACCESS));
        assert_eq!(users_mask, Some(AUTHENTICATED_USERS_ACCESS_MASK));
        assert_eq!(users_mask.unwrap() & FILE_CREATE_PIPE_INSTANCE, 0);
        let server_sid = current_process_sid().unwrap();
        let server_masks = unsafe { ace_masks_for_sid_string(dacl, &server_sid, info.AceCount) };
        assert_eq!(
            server_masks,
            vec![SERVER_INSTANCE_ACCESS_MASK],
            "server SID must receive exactly the full-duplex handle rights needed to rearm"
        );

        unsafe {
            let _ = LocalFree(descriptor);
        }
    }

    #[tokio::test]
    async fn second_first_instance_is_rejected() {
        let name = unique_pipe("first");
        let _first = create_server_at(&name, true).unwrap();
        let error = create_server_at(&name, true).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn incoming_rearms_before_yielding_each_connected_pipe() {
        use tokio_stream::StreamExt;

        let name = unique_pipe("incoming");
        // The production DACL intentionally denies AU the create-instance bit.
        // The test helper grants only its concrete caller SID GA so this
        // non-elevated test can exercise rearm; the exact production DACL is
        // independently verified above.
        let (mut incoming, caller_sid) = test_incoming_at(name.clone()).unwrap();
        let allowed = vec![caller_sid];

        let _client_a = open_client_at(&name, SECURITY_IMPERSONATION_LEVEL, &allowed).unwrap();
        let _accepted_a = incoming
            .next()
            .await
            .expect("incoming ended after first connection")
            .expect("first pipe connection failed");

        // This open can only succeed if the next listener was created before
        // `_accepted_a` was yielded to tonic.
        let _client_b = open_client_at(&name, SECURITY_IMPERSONATION_LEVEL, &allowed).unwrap();
        let _accepted_b = incoming
            .next()
            .await
            .expect("incoming ended after second connection")
            .expect("second pipe connection failed");
    }

    #[tokio::test]
    async fn production_dacl_rearms_for_same_user_without_au_create_instance() {
        use tokio_stream::StreamExt;

        let name = unique_pipe("production-rearm");
        let first = create_server_at(&name, true).unwrap();
        let next_name = name.clone();
        let mut incoming = AuthenticatedPipeIncoming::with_factory(first, move || {
            create_server_at(&next_name, false)
        });
        let allowed = vec![current_process_sid().unwrap()];

        let _client_a = open_client_at(&name, SECURITY_IMPERSONATION_LEVEL, &allowed).unwrap();
        let _accepted_a = incoming
            .next()
            .await
            .expect("incoming ended after first connection")
            .expect("production DACL could not create the next same-user instance");
        let _client_b = open_client_at(&name, SECURITY_IMPERSONATION_LEVEL, &allowed).unwrap();
        let _accepted_b = incoming
            .next()
            .await
            .expect("incoming ended after second connection")
            .expect("second production-style pipe connection failed");
    }

    #[tokio::test]
    async fn identification_level_client_cannot_submit() {
        let name = unique_pipe("identification");
        let server = create_server_at(&name, true).unwrap();
        let allowed = vec![current_process_sid().unwrap()];
        let mut client = open_client_at(&name, SECURITY_IDENTIFICATION, &allowed).unwrap();
        server.connect().await.unwrap();
        let mut authenticated = AuthenticatedPipe::new(server);

        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let error = authenticated.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(authenticated.connect_info().caller_identity().is_err());
    }

    #[tokio::test]
    async fn caller_identity_is_captured_only_after_first_authenticated_read() {
        let name = unique_pipe("identity");
        let server = create_server_at(&name, true).unwrap();
        let expected_sid = current_process_sid().unwrap();
        let mut client = open_client_at(
            &name,
            SECURITY_IMPERSONATION_LEVEL,
            std::slice::from_ref(&expected_sid),
        )
        .unwrap();
        server.connect().await.unwrap();
        let mut authenticated = AuthenticatedPipe::new(server);
        let info = authenticated.connect_info();
        assert!(info.caller_identity().unwrap().is_none());

        client.write_all(b"P").await.unwrap();
        let mut byte = [0u8; 1];
        authenticated.read_exact(&mut byte).await.unwrap();

        let identity = info
            .caller_identity()
            .unwrap()
            .expect("identity must be published after the first read");
        assert_eq!(identity.sid, expected_sid);
        assert!(!identity.primary_token.as_raw_handle().is_null());
    }

    #[tokio::test]
    async fn rejected_server_identity_receives_no_http2_preface() {
        let name = unique_pipe("server-sid");
        let server = create_server_at(&name, true).unwrap();
        let error =
            open_client_at(&name, SECURITY_IMPERSONATION_LEVEL, &["S-1-0-0".into()]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        server.connect().await.unwrap();

        let mut byte = [0u8; 1];
        let read = server.try_read(&mut byte);
        assert!(
            matches!(
                read,
                Err(ref error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    )
            ) || matches!(read, Ok(0)),
            "server unexpectedly received bytes before identity rejection: {read:?}"
        );
    }
}
