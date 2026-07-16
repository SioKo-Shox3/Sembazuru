use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
    FreeSid, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    SECURITY_ATTRIBUTES, SECURITY_RESOURCE_MANAGER_AUTHORITY, SID_AND_ATTRIBUTES,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenIsRestricted,
    TokenUser, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinMediumLabelSid,
    WinRestrictedCodeSid, WinWorldSid,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_INTEGRITY, SECURITY_MANDATORY_MEDIUM_RID,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::job::JobObject;

struct ActionSid(*mut c_void);

// SAFETY: the allocation is uniquely owned, is never dereferenced without the
// owning `ActionToken`, and Windows permits SID inspection/freeing on any thread.
unsafe impl Send for ActionSid {}

pub(crate) fn secure_random_hex() -> io::Result<String> {
    let mut nonce = [0u8; 16];
    // SAFETY: a null algorithm plus SYSTEM_PREFERRED uses the OS CSPRNG and nonce is writable.
    if unsafe {
        BCryptGenRandom(
            null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err(io::Error::other("secure random generator unavailable"));
    }
    Ok(nonce.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl ActionSid {
    fn random() -> io::Result<Self> {
        let mut nonce = [0u32; 4];
        // SAFETY: a null algorithm plus SYSTEM_PREFERRED uses the OS CSPRNG and nonce is writable.
        if unsafe {
            BCryptGenRandom(
                null_mut(),
                nonce.as_mut_ptr().cast(),
                size_of_val(&nonce) as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } != 0
        {
            return Err(io::Error::other("action identity unavailable"));
        }
        let mut sid = null_mut();
        // The first four subauthorities publicly encode "Sembazuru.action"; the remaining
        // 128 random bits are independent of remote action ids, PIDs, and wall time.
        // SAFETY: authority and out pointer are valid; success transfers a FreeSid allocation.
        if unsafe {
            AllocateAndInitializeSid(
                &SECURITY_RESOURCE_MANAGER_AUTHORITY,
                8,
                0x626d_6553,
                0x7275_7a61,
                0x6361_2e75,
                0x6e6f_6974,
                nonce[0],
                nonce[1],
                nonce[2],
                nonce[3],
                &mut sid,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sid))
    }
}

impl Drop for ActionSid {
    fn drop(&mut self) {
        // SAFETY: self.0 is the outstanding AllocateAndInitializeSid result.
        unsafe { FreeSid(self.0) };
    }
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "wired by following sandbox phases")
)]
pub(crate) struct ActionToken {
    token: OwnedHandle,
    action_sid: ActionSid,
    broker_user: Vec<usize>,
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "wired by following sandbox phases")
)]
impl ActionToken {
    pub(crate) fn create() -> io::Result<Self> {
        let token = current_token(
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
        )?;
        Self::create_from_token(token.as_raw_handle() as HANDLE)
    }

    fn create_from_token(source: HANDLE) -> io::Result<Self> {
        if token_u32(source, TokenIsRestricted)? != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let action_sid = ActionSid::random()?;
        let broker_user = token_info(source, TokenUser)?;
        let mut sid_storage = Vec::new();
        for kind in [
            WinWorldSid,
            WinAuthenticatedUserSid,
            WinBuiltinUsersSid,
            WinRestrictedCodeSid,
        ] {
            sid_storage.push(well_known_sid(kind)?);
        }
        let mut restrictions = vec![SID_AND_ATTRIBUTES {
            Sid: action_sid.0,
            Attributes: 0,
        }];
        restrictions.extend(sid_storage.iter_mut().map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_mut_ptr().cast(),
            Attributes: 0,
        }));
        let mut restricted = null_mut();
        // SAFETY: source is queryable/duplicable; the SID pointers remain alive for this call;
        // the returned primary token is transferred to OwnedHandle and never ambient-fallbacks.
        if unsafe {
            CreateRestrictedToken(
                source,
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                restrictions.len() as u32,
                restrictions.as_ptr(),
                &mut restricted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateRestrictedToken returned a unique live handle.
        let token = unsafe { OwnedHandle::from_raw_handle(restricted as RawHandle) };
        lower_to_medium_if_needed(token.as_raw_handle() as HANDLE)?;
        Ok(Self {
            token,
            action_sid,
            broker_user,
        })
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.token.as_raw_handle() as HANDLE
    }

    fn broker_sid(&self) -> *mut c_void {
        // SAFETY: broker_user owns a complete, aligned TOKEN_USER for self's lifetime.
        unsafe { (*(self.broker_user.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    pub(crate) fn impersonated<T>(
        &self,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe { windows_sys::Win32::Security::RevertToSelf() };
            }
        }
        if unsafe { windows_sys::Win32::Security::ImpersonateLoggedOnUser(self.handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _revert = Revert;
        operation()
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the pointer is the outstanding LocalAlloc result.
        unsafe { LocalFree(self.0) };
    }
}

fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut value = null_mut();
    // SAFETY: sid is live and value receives a LocalAlloc NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(value.cast());
    let mut length = 0;
    // SAFETY: allocation remains live and points at a NUL-terminated UTF-16 string.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the preceding scan established the initialized string length.
    Ok(unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(value, length)) })
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
pub(crate) struct PrivateScratch(Option<PathBuf>);

#[allow(dead_code, reason = "wired by sandbox integration phase")]
impl PrivateScratch {
    pub(crate) fn create(root: &Path, leaf: &str, token: &ActionToken) -> io::Result<Self> {
        let components: Vec<_> = Path::new(leaf).components().collect();
        if leaf.contains([':', '\0']) || !matches!(components.as_slice(), [Component::Normal(_)]) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let path = root.join(leaf);
        let sddl = format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;GRGWGXSD;;;{})(A;OICI;RC;;;OW)",
            sid_string(token.broker_sid())?,
            sid_string(token.broker_sid())?,
            sid_string(token.action_sid.0)?
        );
        create_secured_directory(&path, &sddl)?;
        Ok(Self(Some(path)))
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.as_deref().expect("private scratch path is owned")
    }

    /// Transfers cleanup ownership to an asynchronous caller. Setup failures keep
    /// ownership here and are cleaned synchronously by `Drop`; a successfully
    /// launched action calls this only after its process tree and VFS server stop.
    pub(crate) fn into_path(mut self) -> PathBuf {
        self.0.take().expect("private scratch path is owned")
    }
}

impl Drop for PrivateScratch {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
pub(crate) struct PrivateRuntime {
    path: PathBuf,
    launcher: PathBuf,
    interceptor64: PathBuf,
    interceptor32: Option<PathBuf>,
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
impl PrivateRuntime {
    pub(crate) fn stage(
        scratch: &PrivateScratch,
        launcher: &Path,
        interceptor64: &Path,
        token: &ActionToken,
    ) -> io::Result<Self> {
        fn copy_file(source: &Path, target: &Path) -> io::Result<()> {
            let mut source = File::open(source)?;
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(target)?;
            io::copy(&mut source, &mut target)?;
            target.sync_all()
        }

        fn source_name(path: &Path) -> io::Result<&std::ffi::OsStr> {
            if !path.is_file() {
                return Err(io::ErrorKind::NotFound.into());
            }
            path.file_name()
                .ok_or_else(|| io::ErrorKind::InvalidInput.into())
        }
        let launcher_name = source_name(launcher)?;
        let interceptor64_name = source_name(interceptor64)?;
        let interceptor32_source = interceptor64
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join("sbz_interceptor32.dll");
        let interceptor32_name = interceptor32_source
            .is_file()
            .then(|| interceptor32_source.file_name().unwrap());
        let mut names = vec![
            launcher_name.to_string_lossy().to_ascii_lowercase(),
            interceptor64_name.to_string_lossy().to_ascii_lowercase(),
        ];
        if let Some(name) = interceptor32_name {
            names.push(name.to_string_lossy().to_ascii_lowercase());
        }
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "runtime source file names collide",
            ));
        }

        let path = scratch.path().join(".runtime");
        let sddl = format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;GRGX;;;{})",
            sid_string(token.broker_sid())?,
            sid_string(token.broker_sid())?,
            sid_string(token.action_sid.0)?
        );
        create_secured_directory(&path, &sddl)?;
        let launcher_staged = path.join(launcher_name);
        let interceptor64_staged = path.join(interceptor64_name);
        let interceptor32_staged = interceptor32_name.map(|name| path.join(name));
        let copy_result = (|| {
            copy_file(launcher, &launcher_staged)?;
            copy_file(interceptor64, &interceptor64_staged)?;
            if let Some(target) = &interceptor32_staged {
                copy_file(&interceptor32_source, target)?;
            }
            Ok(())
        })();
        if let Err(error) = copy_result {
            if let Err(cleanup) = std::fs::remove_dir_all(&path) {
                return Err(io::Error::other(format!(
                    "runtime staging failed ({error}); cleanup failed ({cleanup})"
                )));
            }
            return Err(error);
        }
        Ok(Self {
            path,
            launcher: launcher_staged,
            interceptor64: interceptor64_staged,
            interceptor32: interceptor32_staged,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn launcher(&self) -> &Path {
        &self.launcher
    }

    pub(crate) fn interceptor64(&self) -> &Path {
        &self.interceptor64
    }

    pub(crate) fn interceptor32(&self) -> Option<&Path> {
        self.interceptor32.as_deref()
    }
}

#[derive(Clone)]
pub(crate) struct ActionPipeSecurity(String);

pub(crate) const ACTION_PIPE_CLIENT_ACCESS: u32 = 0x0012_0083;

impl ActionPipeSecurity {
    #[allow(dead_code, reason = "wired by sandbox integration phase")]
    pub(crate) fn new(token: &ActionToken) -> io::Result<Self> {
        Ok(Self(format!(
            "O:{}D:P(A;;FA;;;{})(A;;0x{ACTION_PIPE_CLIENT_ACCESS:08x};;;{})",
            sid_string(token.broker_sid())?,
            sid_string(token.broker_sid())?,
            sid_string(token.action_sid.0)?
        )))
    }

    /// Builds a fresh descriptor for one synchronous CreateNamedPipe call. The raw
    /// pointer must not be retained by `operation` and never crosses an await point.
    pub(crate) fn with_attributes<T>(
        &self,
        operation: impl FnOnce(*mut c_void) -> io::Result<T>,
    ) -> io::Result<T> {
        let wide: Vec<u16> = self.0.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalAllocation(descriptor);
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        operation((&mut attributes as *mut SECURITY_ATTRIBUTES).cast())
    }
}

fn create_secured_directory(path: &Path, sddl: &str) -> io::Result<()> {
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = null_mut();
    // SAFETY: the SDDL is NUL-terminated and descriptor is a valid out pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: the path and protected descriptor are live for this atomic create call.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn current_token(access: u32) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: token is a valid out pointer; success returns a unique handle we immediately own.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a unique live handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

fn token_info(token: HANDLE, class: i32) -> io::Result<Vec<usize>> {
    let mut needed = 0;
    // SAFETY: a null buffer with zero length is the documented sizing query.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    // usize storage guarantees alignment for the Windows token structures read below.
    let mut info = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: info has at least the reported byte capacity and remains alive for the call.
    if needed == 0
        || unsafe {
            GetTokenInformation(token, class, info.as_mut_ptr().cast(), needed, &mut needed)
        } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn token_u32(token: HANDLE, class: i32) -> io::Result<u32> {
    let value = token_info(token, class)?
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("token information was truncated"))? as u32;
    Ok(value)
}

fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    let mut size = 0;
    // SAFETY: the first call is the documented sizing query.
    unsafe { CreateWellKnownSid(kind, null_mut(), null_mut(), &mut size) };
    let mut sid = vec![0; size as usize];
    // SAFETY: sid has the exact reported size and is a valid output buffer.
    if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

fn integrity_rid(token: HANDLE) -> io::Result<u32> {
    let info = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: TokenIntegrityLevel returns TOKEN_MANDATORY_LABEL with a valid label SID.
    let sid = unsafe { (*(info.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())).Label.Sid };
    // SAFETY: the label SID is valid for both accessor calls while info is alive.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        Ok(*GetSidSubAuthority(sid, u32::from(count - 1)))
    }
}

fn lower_to_medium_if_needed(token: HANDLE) -> io::Result<()> {
    if integrity_rid(token)? <= SECURITY_MANDATORY_MEDIUM_RID as u32 {
        return Ok(());
    }
    set_medium_integrity(token)
}

fn set_medium_integrity(token: HANDLE) -> io::Result<()> {
    let mut sid = well_known_sid(WinMediumLabelSid)?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid.as_mut_ptr().cast(),
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    // SAFETY: token has TOKEN_ADJUST_DEFAULT and label points to a live medium-integrity SID.
    if unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            (size_of::<TOKEN_MANDATORY_LABEL>() as u32) + GetLengthSid(label.Label.Sid),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
pub(crate) struct RestrictedCommand {
    application: PathBuf,
    cwd: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
impl RestrictedCommand {
    pub(crate) fn new(application: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            application: application.into(),
            cwd: cwd.into(),
            arguments: Vec::new(),
            environment: Vec::new(),
        }
    }

    pub(crate) fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.arguments.push(value.into());
        self
    }

    pub(crate) fn env(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.push((name.into(), value.into()));
        self
    }
}

struct PreparedCommand {
    application: Vec<u16>,
    command_line: Vec<u16>,
    cwd: Vec<u16>,
    environment: Vec<u16>,
}

fn prepare_command(command: &RestrictedCommand) -> io::Result<PreparedCommand> {
    fn path(value: &Path) -> io::Result<Vec<u16>> {
        if !value.is_absolute() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut wide: Vec<_> = value.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        wide.push(0);
        Ok(wide)
    }
    let application = path(&command.application)?;
    let cwd = path(&command.cwd)?;
    let mut command_line = Vec::new();
    append_quoted(&mut command_line, &application[..application.len() - 1]);
    for argument in &command.arguments {
        let wide: Vec<_> = argument.encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        command_line.push(b' ' as u16);
        append_quoted(&mut command_line, &wide);
    }
    command_line.push(0);
    if command_line.len() > 32_767 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut entries = Vec::new();
    for (name, value) in &command.environment {
        let name: Vec<_> = name.encode_wide().collect();
        let value: Vec<_> = value.encode_wide().collect();
        if name.is_empty()
            || name.contains(&0)
            || name.contains(&(b'=' as u16))
            || value.contains(&0)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        entries.push((name, value));
    }
    entries.sort_by_key(|(name, _)| String::from_utf16_lossy(name).to_lowercase());
    if entries.windows(2).any(|pair| {
        String::from_utf16_lossy(&pair[0].0).to_lowercase()
            == String::from_utf16_lossy(&pair[1].0).to_lowercase()
    }) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut environment = Vec::new();
    for (name, value) in entries {
        environment.extend(name);
        environment.push(b'=' as u16);
        environment.extend(value);
        environment.push(0);
    }
    environment.push(0);
    if environment.len() == 1 {
        environment.push(0);
    }
    Ok(PreparedCommand {
        application,
        command_line,
        cwd,
        environment,
    })
}

fn append_quoted(output: &mut Vec<u16>, argument: &[u16]) {
    let quote = argument.is_empty()
        || argument
            .iter()
            .any(|value| matches!(*value, 0x20 | 0x09 | 0x22));
    if !quote {
        output.extend_from_slice(argument);
        return;
    }
    output.push(b'"' as u16);
    let mut slashes = 0;
    for &value in argument {
        if value == b'\\' as u16 {
            slashes += 1;
        } else {
            output.extend(std::iter::repeat_n(
                b'\\' as u16,
                slashes * (1 + usize::from(value == b'"' as u16)),
            ));
            if value == b'"' as u16 {
                output.push(b'\\' as u16);
            }
            output.push(value);
            slashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
}

struct AttributeList<'a> {
    storage: Vec<usize>,
    initialized: bool,
    _handles: PhantomData<&'a [HANDLE]>,
}

impl<'a> AttributeList<'a> {
    fn handles(handles: &'a [HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: the null first call is the documented size query.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut result = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
            _handles: PhantomData,
        };
        // SAFETY: usize storage is aligned and has the queried capacity.
        if unsafe { InitializeProcThreadAttributeList(result.ptr(), 1, 0, &mut bytes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        result.initialized = true;
        if unsafe {
            UpdateProcThreadAttribute(
                result.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of_val(handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }

    fn ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList<'_> {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: initialized records the single successful initialization.
            unsafe { DeleteProcThreadAttributeList(self.ptr()) };
        }
    }
}

fn stdio_pipe(child_reads: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    // SAFETY: out pointers and attributes are valid; both returned handles are owned below.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreatePipe returned two unique live handles.
    let read = unsafe { OwnedHandle::from_raw_handle(read as RawHandle) };
    let write = unsafe { OwnedHandle::from_raw_handle(write as RawHandle) };
    let (child, parent) = if child_reads {
        (read, write)
    } else {
        (write, read)
    };
    // SAFETY: parent is live and must never be inherited by the child.
    if unsafe { SetHandleInformation(parent.as_raw_handle() as HANDLE, HANDLE_FLAG_INHERIT, 0) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((child, parent))
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq)]
enum SpawnFailure {
    AfterCreate,
    BeforeResume,
}

struct SuspendedGuardian(Option<OwnedHandle>);

impl SuspendedGuardian {
    fn disarm(mut self) -> OwnedHandle {
        self.0.take().unwrap()
    }
}

impl Drop for SuspendedGuardian {
    fn drop(&mut self) {
        if let Some(process) = &self.0 {
            // SAFETY: a suspended child is still live; terminate then synchronously reap it.
            unsafe {
                TerminateProcess(process.as_raw_handle() as HANDLE, 1);
                WaitForSingleObject(process.as_raw_handle() as HANDLE, INFINITE);
            }
        }
    }
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
pub(crate) struct RestrictedProcess {
    process: Option<OwnedHandle>,
    stdout: Option<OwnedHandle>,
    stderr: Option<OwnedHandle>,
    job: Arc<JobObject>,
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
impl RestrictedProcess {
    pub(crate) fn spawn(token: &ActionToken, command: &RestrictedCommand) -> io::Result<Self> {
        Self::spawn_inner(
            token,
            command,
            #[cfg(test)]
            None,
        )
    }

    fn spawn_inner(
        token: &ActionToken,
        command: &RestrictedCommand,
        #[cfg(test)] failure: Option<SpawnFailure>,
    ) -> io::Result<Self> {
        let mut prepared = prepare_command(command)?;
        let job = Arc::new(JobObject::new_kill_on_close()?);
        let (stdin, stdin_parent) = stdio_pipe(true)?;
        let (stdout, stdout_parent) = stdio_pipe(false)?;
        let (stderr, stderr_parent) = stdio_pipe(false)?;
        drop(stdin_parent); // EOF is explicit; actions cannot wait on ambient broker input.
        let inherited = [
            stdin.as_raw_handle() as HANDLE,
            stdout.as_raw_handle() as HANDLE,
            stderr.as_raw_handle() as HANDLE,
        ];
        let mut attributes = AttributeList::handles(&inherited)?;
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0];
        startup.StartupInfo.hStdOutput = inherited[1];
        startup.StartupInfo.hStdError = inherited[2];
        startup.lpAttributeList = attributes.ptr();
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: all UTF-16 buffers are NUL-terminated and live; command_line is mutable;
        // only the three inheritable stdio handles in the attribute list can cross the boundary.
        if unsafe {
            CreateProcessAsUserW(
                token.handle(),
                prepared.application.as_ptr(),
                prepared.command_line.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                prepared.environment.as_ptr().cast(),
                prepared.cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(io::Error::other(format!(
                "create_process: OS error {}",
                io::Error::last_os_error().raw_os_error().unwrap_or(0)
            )));
        }
        // SAFETY: CreateProcessAsUserW returned unique live process/thread handles.
        let guardian = SuspendedGuardian(Some(unsafe {
            OwnedHandle::from_raw_handle(info.hProcess as RawHandle)
        }));
        let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) };
        #[cfg(test)]
        if failure == Some(SpawnFailure::AfterCreate) {
            return Err(io::Error::other("after_create: injected failure"));
        }
        job.assign_verified(guardian.0.as_ref().unwrap().as_raw_handle())?;
        #[cfg(test)]
        if failure == Some(SpawnFailure::BeforeResume) {
            return Err(io::Error::other("before_resume: injected failure"));
        }
        drop(attributes);
        drop((stdin, stdout, stderr));
        // This is deliberately the final fallible setup step: no child instruction ran earlier.
        let prior = unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) };
        if prior != 1 {
            return Err(io::Error::other(format!(
                "resume_thread: unexpected count {prior}"
            )));
        }
        Ok(Self {
            process: Some(guardian.disarm()),
            stdout: Some(stdout_parent),
            stderr: Some(stderr_parent),
            job,
        })
    }

    pub(crate) fn is_in_job(&self) -> io::Result<bool> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| io::Error::other("process already reaped"))?;
        self.job.contains(process.as_raw_handle())
    }

    pub(crate) fn job(&self) -> Arc<JobObject> {
        Arc::clone(&self.job)
    }

    /// Transfers both output pipes exactly once. Callers must drain both concurrently with
    /// [`wait`](Self::wait); waiting first can deadlock when either pipe buffer fills.
    pub(crate) fn take_output(&mut self) -> io::Result<(tokio::fs::File, tokio::fs::File)> {
        if self.stdout.is_none() || self.stderr.is_none() {
            return Err(io::Error::other("output already taken"));
        }
        let stdout = self
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("output already taken"))?;
        let stderr = self
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("output already taken"))?;
        Ok((
            tokio::fs::File::from_std(File::from(stdout)),
            tokio::fs::File::from_std(File::from(stderr)),
        ))
    }

    /// Waits using an independently-owned process handle. Cancelling this future does not kill
    /// the action or invalidate the detached blocking waiter; the caller must call
    /// [`terminate`](Self::terminate) and then `wait` again on abort/timeout. Normal completion
    /// terminates any descendants still alive in the Job after the top process exits.
    pub(crate) async fn wait(&mut self) -> io::Result<u32> {
        let source = self
            .process
            .as_ref()
            .ok_or_else(|| io::Error::other("process already reaped"))?;
        let duplicate = {
            let mut duplicate = null_mut();
            // SAFETY: source and both pseudo-process handles are live. Success transfers one
            // process-handle reference into `duplicate`, which becomes OwnedHandle below.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source.as_raw_handle() as HANDLE,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: DuplicateHandle returned a unique owned handle. Keep the raw pointer
            // inside this synchronous scope so the async future remains `Send`.
            unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) }
        };
        let code = tokio::task::spawn_blocking(move || {
            let handle = duplicate.as_raw_handle() as HANDLE;
            if unsafe { WaitForSingleObject(handle, INFINITE) } != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let mut code = 0;
            if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(code)
        })
        .await
        .map_err(|_| io::Error::other("process waiter failed"))??;
        self.job.terminate();
        self.process.take();
        Ok(code)
    }

    /// Terminates the complete Job tree and the direct process as a fail-safe.
    pub(crate) fn terminate(&self) {
        self.job.terminate();
        if let Some(process) = &self.process {
            // SAFETY: the handle remains owned by self; this is a fail-safe if Job
            // termination could not reach the direct process during teardown.
            unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) };
        }
    }

    /// Concurrently drains both pipes, then kills descendants as soon as the top process exits.
    pub(crate) async fn wait_with_output(mut self) -> io::Result<(u32, Vec<u8>, Vec<u8>)> {
        async fn drain(mut file: tokio::fs::File) -> io::Result<Vec<u8>> {
            use tokio::io::AsyncReadExt;

            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).await?;
            Ok(bytes)
        }
        let (stdout, stderr) = self.take_output()?;
        let (code, stdout, stderr) = tokio::try_join!(self.wait(), drain(stdout), drain(stderr))?;
        Ok((code, stdout, stderr))
    }
}

impl Drop for RestrictedProcess {
    fn drop(&mut self) {
        self.terminate();
        if let Some(process) = self.process.take() {
            // SAFETY: process is owned here; direct terminate covers pre/post-job teardown.
            unsafe {
                TerminateProcess(process.as_raw_handle() as HANDLE, 1);
                WaitForSingleObject(process.as_raw_handle() as HANDLE, INFINITE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Foundation::{
        GENERIC_WRITE, INVALID_HANDLE_VALUE, LUID, LocalFree, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, ImpersonateLoggedOnUser, LookupPrivilegeValueW,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, RevertToSelf, SE_CHANGE_NOTIFY_NAME,
        SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, TOKEN_GROUPS,
        TOKEN_PRIVILEGES, TOKEN_USER, TokenGroups, TokenPrivileges, TokenRestrictedSids, TokenUser,
        WinCreatorOwnerRightsSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_READ, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{
        CreateEventW, OpenProcess, PROCESS_SYNCHRONIZE, SetEvent,
    };

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct RevertGuard;
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            // SAFETY: the guard is created only after this thread was impersonated.
            unsafe { RevertToSelf() };
        }
    }

    impl ActionToken {
        fn only_change_notify_enabled(&self) -> io::Result<bool> {
            let info = token_info(self.handle(), TokenPrivileges)?;
            // SAFETY: TokenPrivileges returns a header followed by PrivilegeCount entries.
            let privileges = unsafe { &*(info.as_ptr().cast::<TOKEN_PRIVILEGES>()) };
            let mut allowed = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            // SAFETY: SE_CHANGE_NOTIFY_NAME is static NUL-terminated data and allowed is valid.
            if unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut allowed) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the variable array contains PrivilegeCount entries in bytes.
            let entries = unsafe {
                std::slice::from_raw_parts(
                    privileges.Privileges.as_ptr(),
                    privileges.PrivilegeCount as usize,
                )
            };
            Ok(entries.iter().all(|entry| {
                entry.Attributes & SE_PRIVILEGE_ENABLED == 0
                    || (entry.Luid.LowPart == allowed.LowPart
                        && entry.Luid.HighPart == allowed.HighPart)
            }))
        }

        fn can_open_test_file(&self, action_acl: Option<&ActionToken>) -> io::Result<bool> {
            let mut sddl = format!("D:P(A;;GRGW;;;{})", current_user_sid_string()?);
            if let Some(action) = action_acl {
                sddl.push_str(&format!("(A;;GR;;;{})", sid_string(action.action_sid.0)?));
            }
            let path = create_protected_file(&sddl)?;
            let result = self.impersonated_can_open(&path);
            let _ = std::fs::remove_file(path);
            result
        }

        fn impersonated_can_open(&self, path: &std::path::Path) -> io::Result<bool> {
            // SAFETY: handle is a live restricted token. RevertGuard restores the thread token.
            if unsafe { ImpersonateLoggedOnUser(self.handle()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let _guard = RevertGuard;
            match File::open(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(false),
                Err(error) => Err(error),
            }
        }
    }

    fn token_groups_contain(token: HANDLE, class: i32, sid: *mut c_void) -> io::Result<bool> {
        let info = token_info(token, class)?;
        // SAFETY: both token group classes return a header followed by GroupCount entries.
        let groups = unsafe { &*(info.as_ptr().cast::<TOKEN_GROUPS>()) };
        // SAFETY: the variable array contains GroupCount entries in bytes.
        let entries = unsafe {
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        // SAFETY: each returned SID and the target SID are valid while their owners are alive.
        Ok(entries
            .iter()
            .any(|entry| unsafe { EqualSid(entry.Sid, sid) } != 0))
    }

    fn current_user_sid_string() -> io::Result<String> {
        let token = current_token(TOKEN_QUERY)?;
        let info = token_info(token.as_raw_handle() as HANDLE, TokenUser)?;
        // SAFETY: TokenUser returns TOKEN_USER with a valid SID while info is alive.
        let user = unsafe { &*(info.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    }

    fn sid_string(sid: *mut c_void) -> io::Result<String> {
        let mut value = null_mut();
        // SAFETY: sid is valid and value receives a LocalAlloc NUL-terminated string.
        if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: value is a valid NUL-terminated allocation.
        let text = unsafe {
            while *value.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
        };
        // SAFETY: value is the outstanding LocalAlloc result.
        unsafe { LocalFree(value.cast()) };
        Ok(text)
    }

    fn create_protected_file(sddl: &str) -> io::Result<std::path::PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "sembazuru-action-acl-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = null_mut();
        // SAFETY: input is NUL-terminated and descriptor is a valid out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let wide_path: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
        // SAFETY: path and descriptor are live; the returned handle is immediately owned.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                &attributes,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        // SAFETY: descriptor is the outstanding LocalAlloc result.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned a unique live handle.
        let _handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        Ok(path)
    }

    fn private_scratch_root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sembazuru-private-scratch-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        create_secured_directory(&path, "D:P(A;OICI;FA;;;WD)").unwrap();
        path
    }

    type ScratchAcl = (String, u16, Vec<(String, u8, u32)>);
    fn scratch_acl(path: &Path) -> io::Result<ScratchAcl> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
        // SAFETY: path is NUL-terminated and all requested outputs are valid.
        let error = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let _descriptor = LocalAllocation(descriptor);
        let (mut control, mut revision) = (0, 0);
        // SAFETY: descriptor and its DACL remain live through _descriptor.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut aces = Vec::new();
        // SAFETY: descriptor owns a non-null DACL with AceCount live entries.
        for index in 0..unsafe { (*dacl).AceCount } as u32 {
            let mut raw = null_mut();
            // SAFETY: index is within AceCount and raw receives an ACE owned by descriptor.
            if unsafe { GetAce(dacl, index, &mut raw) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let ace = unsafe { &*(raw.cast::<ACCESS_ALLOWED_ACE>()) };
            assert_eq!(ace.Header.AceType, ACCESS_ALLOWED_ACE_TYPE as u8);
            aces.push((
                sid_string((&ace.SidStart as *const u32).cast_mut().cast())?,
                ace.Header.AceFlags,
                ace.Mask,
            ));
        }
        Ok((sid_string(owner)?, control, aces))
    }

    fn can_open_directory(path: &Path, access: u32) -> bool {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: path is NUL-terminated and any returned handle is closed below.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            false
        } else {
            // SAFETY: CreateFileW returned a unique live handle.
            drop(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) });
            true
        }
    }

    fn can_open_file(path: &Path, access: u32) -> bool {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            false
        } else {
            drop(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) });
            true
        }
    }

    #[test]
    fn action_token_identity_and_limits() {
        let a = ActionToken::create().unwrap();
        let b = ActionToken::create().unwrap();
        assert!(!token_groups_contain(a.handle(), TokenGroups, a.action_sid.0).unwrap());
        assert!(token_groups_contain(a.handle(), TokenRestrictedSids, a.action_sid.0).unwrap());
        // SAFETY: both action SIDs are valid for the compared token lifetimes.
        assert_eq!(unsafe { EqualSid(a.action_sid.0, b.action_sid.0) }, 0);
        assert!(a.only_change_notify_enabled().unwrap());
        assert!(integrity_rid(a.handle()).unwrap() <= 0x2000);
        set_medium_integrity(a.handle()).unwrap();
    }

    #[test]
    fn action_token_acl_matrix_and_public_tool() {
        let a = ActionToken::create().unwrap();
        let b = ActionToken::create().unwrap();
        assert!(a.can_open_test_file(Some(&a)).unwrap());
        assert!(!a.can_open_test_file(None).unwrap());
        assert!(!a.can_open_test_file(Some(&b)).unwrap());
        let tool = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/where.exe");
        assert!(a.impersonated_can_open(&tool).unwrap());
    }

    #[test]
    fn already_restricted_broker_token_is_rejected() {
        let restricted = ActionToken::create().unwrap();
        assert!(ActionToken::create_from_token(restricted.handle()).is_err());
    }

    #[test]
    fn private_scratch_atomic_acl_and_fail_closed_creation() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "action", &token).unwrap();
        assert_eq!(scratch.path(), root.join("action"));
        std::fs::write(scratch.path().join("sentinel"), b"keep").unwrap();
        assert!(PrivateScratch::create(&root, "action", &token).is_err());
        assert!(PrivateScratch::create(&root.join("missing"), "action", &token).is_err());
        assert!(!root.join("missing").exists());
        assert_eq!(
            std::fs::read(scratch.path().join("sentinel")).unwrap(),
            b"keep"
        );
        for leaf in ["", ".", "..", "a/b", "a\\b", "C:", "a:b", "a\0b"] {
            assert!(
                PrivateScratch::create(&root, leaf, &token).is_err(),
                "{leaf:?}"
            );
        }
        let (owner, control, aces) = scratch_acl(scratch.path()).unwrap();
        assert_eq!(owner, sid_string(token.broker_sid()).unwrap());
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let inherit = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;
        let expected = vec![
            (
                sid_string(token.broker_sid()).unwrap(),
                inherit,
                FILE_ALL_ACCESS,
            ),
            (
                sid_string(token.action_sid.0).unwrap(),
                inherit,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            ),
            (
                sid_string(
                    well_known_sid(WinCreatorOwnerRightsSid)
                        .unwrap()
                        .as_mut_ptr()
                        .cast(),
                )
                .unwrap(),
                inherit,
                READ_CONTROL,
            ),
        ];
        assert_eq!(aces, expected);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_scratch_matching_action_can_mutate_without_acl_control() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "action", &token).unwrap();
        token
            .impersonated(|| {
                let nested = scratch.path().join("nested");
                std::fs::create_dir(&nested)?;
                let file = nested.join("file");
                std::fs::write(&file, b"value")?;
                assert_eq!(std::fs::read(&file)?, b"value");
                let renamed = nested.join("renamed");
                std::fs::rename(&file, &renamed)?;
                std::fs::remove_file(renamed)?;
                std::fs::remove_dir(nested)?;
                assert!(!can_open_directory(scratch.path(), WRITE_DAC));
                assert!(!can_open_directory(scratch.path(), WRITE_OWNER));
                Ok(())
            })
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_scratch_other_action_cannot_discover_or_open() {
        let a = ActionToken::create().unwrap();
        let b = ActionToken::create().unwrap();
        let root = private_scratch_root();
        assert!(
            b.impersonated(|| Ok(std::fs::read_dir(&root).is_ok()))
                .unwrap()
        );
        let scratch = PrivateScratch::create(&root, "action-a", &a).unwrap();
        std::fs::write(scratch.path().join("known"), b"secret").unwrap();
        b.impersonated(|| {
            assert_eq!(
                std::fs::read_dir(scratch.path()).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                File::open(scratch.path().join("known")).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                File::create(scratch.path().join("new")).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_runtime_stages_read_execute_only_tools() {
        let action = ActionToken::create().unwrap();
        let other = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "runtime-action", &action).unwrap();
        let source = root.join("runtime-source");
        std::fs::create_dir(&source).unwrap();
        let launcher = source.join("launcher-test.exe");
        let dll64 = source.join("sbz_interceptor64.dll");
        let dll32 = source.join("sbz_interceptor32.dll");
        std::fs::write(&launcher, b"launcher").unwrap();
        std::fs::write(&dll64, b"dll64").unwrap();
        std::fs::write(&dll32, b"dll32").unwrap();

        let runtime = PrivateRuntime::stage(&scratch, &launcher, &dll64, &action).unwrap();
        assert_eq!(std::fs::read(runtime.launcher()).unwrap(), b"launcher");
        assert_eq!(std::fs::read(runtime.interceptor64()).unwrap(), b"dll64");
        assert_eq!(
            std::fs::read(runtime.interceptor32().unwrap()).unwrap(),
            b"dll32"
        );
        let (owner, control, aces) = scratch_acl(runtime.path()).unwrap();
        assert_eq!(owner, sid_string(action.broker_sid()).unwrap());
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let inherit = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;
        assert_eq!(
            aces,
            vec![
                (
                    sid_string(action.broker_sid()).unwrap(),
                    inherit,
                    FILE_ALL_ACCESS
                ),
                (
                    sid_string(action.action_sid.0).unwrap(),
                    inherit,
                    FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
                )
            ]
        );
        action
            .impersonated(|| {
                assert_eq!(std::fs::read(runtime.launcher())?, b"launcher");
                assert!(can_open_file(runtime.launcher(), FILE_GENERIC_EXECUTE));
                assert!(!can_open_file(runtime.launcher(), FILE_GENERIC_WRITE));
                assert!(!can_open_file(runtime.launcher(), DELETE));
                assert!(!can_open_directory(runtime.path(), FILE_GENERIC_WRITE));
                assert!(!can_open_directory(runtime.path(), DELETE));
                assert!(!can_open_directory(runtime.path(), WRITE_DAC));
                assert!(!can_open_directory(runtime.path(), WRITE_OWNER));
                assert!(std::fs::write(runtime.launcher(), b"replace").is_err());
                assert!(std::fs::remove_file(runtime.launcher()).is_err());
                assert!(File::create(runtime.path().join("new")).is_err());
                assert!(std::fs::remove_dir(runtime.path()).is_err());
                assert!(
                    std::fs::rename(runtime.path(), scratch.path().join(".runtime-renamed"))
                        .is_err()
                );
                assert!(runtime.path().is_dir());
                assert_eq!(std::fs::read(runtime.launcher())?, b"launcher");
                assert_eq!(std::fs::read(runtime.interceptor64())?, b"dll64");
                assert_eq!(std::fs::read(runtime.interceptor32().unwrap())?, b"dll32");
                Ok(())
            })
            .unwrap();
        other
            .impersonated(|| {
                assert_eq!(
                    std::fs::read(runtime.launcher()).unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
                Ok(())
            })
            .unwrap();
        std::fs::write(runtime.path().join("broker"), b"ok").unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_runtime_failures_leave_no_partial_tree() {
        let action = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "runtime-fail", &action).unwrap();
        let source = root.join("failure-source");
        std::fs::create_dir(&source).unwrap();
        let launcher = source.join("same.bin");
        let dll = root.join("other").join("same.bin");
        std::fs::create_dir(dll.parent().unwrap()).unwrap();
        std::fs::write(&launcher, b"launcher").unwrap();
        std::fs::write(&dll, b"dll").unwrap();
        assert!(PrivateRuntime::stage(&scratch, &launcher, &dll, &action).is_err());
        assert!(!scratch.path().join(".runtime").exists());
        assert!(
            PrivateRuntime::stage(&scratch, &launcher, &source.join("missing"), &action).is_err()
        );
        assert!(!scratch.path().join(".runtime").exists());
        let distinct = source.join("distinct.dll");
        std::fs::write(&distinct, b"distinct").unwrap();
        std::fs::create_dir(scratch.path().join(".runtime")).unwrap();
        assert!(PrivateRuntime::stage(&scratch, &launcher, &distinct, &action).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn action_pipe_security_contains_only_broker_and_action() {
        let action = ActionToken::create().unwrap();
        let security = ActionPipeSecurity::new(&action).unwrap();
        assert_eq!(
            security.0,
            format!(
                "O:{}D:P(A;;FA;;;{})(A;;0x00120083;;;{})",
                sid_string(action.broker_sid()).unwrap(),
                sid_string(action.broker_sid()).unwrap(),
                sid_string(action.action_sid.0).unwrap()
            )
        );
        assert_eq!(
            ACTION_PIPE_CLIENT_ACCESS
                & windows_sys::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE,
            0
        );
    }

    #[test]
    fn restricted_process_command_contract() {
        let quoted = |value: &str| {
            let mut output = Vec::new();
            append_quoted(&mut output, &value.encode_utf16().collect::<Vec<_>>());
            String::from_utf16(&output).unwrap()
        };
        assert_eq!(quoted(""), "\"\"");
        assert_eq!(quoted("a b"), "\"a b\"");
        assert_eq!(quoted("a\"b"), "\"a\\\"b\"");
        assert_eq!(quoted("a \\"), "\"a \\\\\"");
        let command = RestrictedCommand::new("C:\\Program Files\\tool.exe", "C:\\work")
            .arg("plain")
            .arg("")
            .env("z", "1")
            .env("A", "2");
        let prepared = prepare_command(&command).unwrap();
        assert_eq!(
            String::from_utf16(&prepared.command_line[..prepared.command_line.len() - 1]).unwrap(),
            "\"C:\\Program Files\\tool.exe\" plain \"\""
        );
        assert_eq!(
            String::from_utf16_lossy(&prepared.environment),
            "A=2\0z=1\0\0"
        );
        assert!(prepare_command(&RestrictedCommand::new("tool.exe", "C:\\work")).is_err());
        assert!(prepare_command(&RestrictedCommand::new("C:\\tool.exe", "work")).is_err());
        for (name, value) in [("", "v"), ("A=B", "v"), ("A\0B", "v"), ("A", "v\0x")] {
            assert!(
                prepare_command(
                    &RestrictedCommand::new("C:\\tool.exe", "C:\\work").env(name, value)
                )
                .is_err()
            );
        }
        assert!(
            prepare_command(
                &RestrictedCommand::new("C:\\tool.exe", "C:\\work")
                    .env("Path", "a")
                    .env("PATH", "b")
            )
            .is_err()
        );
        assert!(
            prepare_command(
                &RestrictedCommand::new("C:\\tool.exe", "C:\\work").arg("x".repeat(32_767))
            )
            .is_err()
        );
    }

    #[test]
    #[ignore]
    fn restricted_process_child_probe() {
        assert_eq!(std::env::var("SBZ_CHILD_PROBE").unwrap(), "1");
        let handle = std::env::var("SBZ_EVENT_HANDLE")
            .unwrap()
            .parse::<usize>()
            .unwrap() as HANDLE;
        // A numeric handle value can be reused for an unrelated child-local handle, so the
        // return value is not evidence. Best-effort signaling leaves an observable mark only
        // if this is the broker's inherited event; the parent makes the authoritative check.
        // SAFETY: an invalid or non-event handle fails without changing the broker's event.
        let _ = unsafe { SetEvent(handle) };
        println!(
            "EVENT_INHERITED=0\nOUT:{}\n{}",
            std::env::var("SBZ_TEST").unwrap(),
            std::env::current_dir().unwrap().display()
        );
        std::io::stdout().write_all(&vec![b'X'; 131_072]).unwrap();
        eprintln!("ERR");
    }

    #[test]
    #[ignore]
    fn restricted_process_wait_probe() {
        if std::env::var_os("SBZ_GRANDCHILD").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
        if std::env::var_os("SBZ_SPAWN_GRANDCHILD").is_some() {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "sandbox::tests::restricted_process_wait_probe",
                ])
                .env("SBZ_GRANDCHILD", "1")
                .spawn()
                .unwrap();
            println!("GRANDCHILD_PID={}", child.id());
            std::io::stdout().flush().unwrap();
            let _ = child.wait_with_output();
        } else {
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    }

    fn restricted_process_wait_command(
        token: &ActionToken,
        scratch: &PrivateScratch,
        spawn_grandchild: bool,
    ) -> RestrictedProcess {
        let probe = scratch.path().join("wait-probe.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
        let mut command = RestrictedCommand::new(probe, scratch.path())
            .arg("--ignored")
            .arg("--exact")
            .arg("sandbox::tests::restricted_process_wait_probe")
            .arg("--nocapture")
            .env("SystemRoot", std::env::var_os("SystemRoot").unwrap());
        if spawn_grandchild {
            command = command.env("SBZ_SPAWN_GRANDCHILD", "1");
        }
        RestrictedProcess::spawn(token, &command).unwrap()
    }

    #[tokio::test]
    async fn restricted_process_cancelled_wait_can_be_retried() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "cancel-wait", &token).unwrap();
        let mut process = restricted_process_wait_command(&token, &scratch, false);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), process.wait())
                .await
                .is_err()
        );
        assert!(process.is_in_job().unwrap());
        process.terminate();
        assert_ne!(process.wait().await.unwrap(), 0);
        drop(process);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn restricted_process_terminate_can_be_reaped() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "terminate", &token).unwrap();
        let mut process = restricted_process_wait_command(&token, &scratch, false);
        process.terminate();
        assert_ne!(process.wait().await.unwrap(), 0);
        assert!(process.is_in_job().is_err());
        drop(process);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn restricted_process_job_clone_retains_tree_kill() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "job-clone", &token).unwrap();
        let mut process = restricted_process_wait_command(&token, &scratch, true);
        let job = process.job();
        let (stdout, mut stderr) = process.take_output().unwrap();
        let mut stdout = BufReader::new(stdout);
        let mut transcript = String::new();
        let pid_result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                if stdout.read_line(&mut line).await? == 0 {
                    return Err(io::Error::other("stdout closed before grandchild pid"));
                }
                transcript.push_str(&line);
                if let Some((_, value)) = line.split_once("GRANDCHILD_PID=")
                    && let Some(value) = value.split_whitespace().next()
                    && let Ok(pid) = value.parse::<u32>()
                {
                    return Ok(pid);
                }
            }
        })
        .await;
        let grandchild_pid = match pid_result {
            Ok(Ok(pid)) => pid,
            failure => {
                process.terminate();
                let _ = process.wait().await;
                let _ = stdout.read_to_string(&mut transcript).await;
                let mut error = String::new();
                let _ = stderr.read_to_string(&mut error).await;
                panic!(
                    "grandchild pid missing: {failure:?}; stdout={transcript:?}; stderr={error:?}"
                );
            }
        };
        assert_ne!(grandchild_pid, 0);
        let grandchild = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, grandchild_pid) };
        assert!(!grandchild.is_null());
        let grandchild = unsafe { OwnedHandle::from_raw_handle(grandchild as RawHandle) };
        job.terminate();
        assert_ne!(process.wait().await.unwrap(), 0);
        assert_eq!(
            unsafe { WaitForSingleObject(grandchild.as_raw_handle() as HANDLE, 5_000) },
            WAIT_OBJECT_0
        );
        drop(job);
        drop(process);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn restricted_process_runs_suspended_in_job_with_only_stdio_handles() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "process", &token).unwrap();
        let system_root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let probe = scratch.path().join("probe.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let event = unsafe { CreateEventW(&attributes, 0, 0, null()) };
        assert!(!event.is_null());
        let event_value = event as usize;
        let event = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
        let command = RestrictedCommand::new(probe, scratch.path())
            .arg("--ignored")
            .arg("--exact")
            .arg("sandbox::tests::restricted_process_child_probe")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("SBZ_CHILD_PROBE", "1")
            .env("SBZ_EVENT_HANDLE", event_value.to_string())
            .env("SBZ_TEST", "VALUE")
            .env("SystemRoot", system_root);
        let process = RestrictedProcess::spawn(&token, &command).unwrap();
        assert!(process.is_in_job().unwrap());
        let (code, out, err) = process.wait_with_output().await.unwrap();
        let (out, err) = (String::from_utf8_lossy(&out), String::from_utf8_lossy(&err));
        assert_eq!(code, 0, "out={out:?} err={err:?}");
        assert!(
            out.contains("EVENT_INHERITED=0")
                && out.contains("OUT:VALUE")
                && out
                    .to_ascii_lowercase()
                    .contains(&scratch.path().display().to_string().to_ascii_lowercase())
        );
        assert!(out.chars().filter(|&value| value == 'X').count() >= 131_072);
        assert!(err.contains("ERR"));
        assert_eq!(
            unsafe { WaitForSingleObject(event.as_raw_handle() as HANDLE, 0) },
            WAIT_TIMEOUT
        );
        drop(event);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restricted_process_setup_failures_never_resume_child() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "failures", &token).unwrap();
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe");
        for (index, failure) in [SpawnFailure::AfterCreate, SpawnFailure::BeforeResume]
            .into_iter()
            .enumerate()
        {
            let marker = scratch.path().join(format!("marker-{index}"));
            let command = RestrictedCommand::new(&cmd, scratch.path())
                .arg("/d")
                .arg("/c")
                .arg(format!("echo ran>\"{}\"", marker.display()));
            assert!(RestrictedProcess::spawn_inner(&token, &command, Some(failure)).is_err());
            assert!(
                !marker.exists(),
                "suspended child executed its first instruction"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
