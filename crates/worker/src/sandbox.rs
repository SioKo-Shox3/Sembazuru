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
    IsTokenRestricted, SECURITY_ATTRIBUTES, SECURITY_RESOURCE_MANAGER_AUTHORITY,
    SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel,
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

pub(crate) struct ActionToken {
    token: OwnedHandle,
    action_sid: ActionSid,
    broker_user: Vec<usize>,
}

impl ActionToken {
    pub(crate) fn create() -> io::Result<Self> {
        let token = current_token(
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
        )?;
        Self::create_from_token(token.as_raw_handle() as HANDLE)
    }

    fn create_from_token(source: HANDLE) -> io::Result<Self> {
        if is_token_restricted(source) {
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

pub(crate) struct PrivateScratch(Option<PathBuf>);

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

pub(crate) struct PrivateRuntime {
    #[allow(
        dead_code,
        reason = "read by sandbox tests that verify the staged runtime ACL"
    )]
    path: PathBuf,
    launcher: PathBuf,
    interceptor64: PathBuf,
    #[allow(
        dead_code,
        reason = "read by sandbox tests that verify optional 32-bit staging"
    )]
    interceptor32: Option<PathBuf>,
}

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

    #[allow(
        dead_code,
        reason = "sandbox tests inspect the staged runtime ACL through this path"
    )]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn launcher(&self) -> &Path {
        &self.launcher
    }

    pub(crate) fn interceptor64(&self) -> &Path {
        &self.interceptor64
    }

    #[allow(
        dead_code,
        reason = "sandbox tests verify optional 32-bit interceptor staging"
    )]
    pub(crate) fn interceptor32(&self) -> Option<&Path> {
        self.interceptor32.as_deref()
    }
}

#[derive(Clone)]
pub(crate) struct ActionPipeSecurity(String);

pub(crate) const ACTION_PIPE_CLIENT_ACCESS: u32 = 0x0012_0083;

impl ActionPipeSecurity {
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
    process_token(unsafe { GetCurrentProcess() }, access)
}

fn process_token(process: HANDLE, access: u32) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: token is a valid out pointer; success returns a unique handle we immediately own.
    if unsafe { OpenProcessToken(process, access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a unique live handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

fn is_token_restricted(token: HANDLE) -> bool {
    // SAFETY: callers supply a live queryable token. The documented predicate is
    // SKU-independent; false is treated fail-closed for action child validation.
    unsafe { IsTokenRestricted(token) != 0 }
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

pub(crate) struct RestrictedCommand {
    application: PathBuf,
    cwd: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

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
    ChildTokenOpen,
    ChildTokenUnrestricted,
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

pub(crate) struct RestrictedProcess {
    process: Option<OwnedHandle>,
    stdout: Option<OwnedHandle>,
    stderr: Option<OwnedHandle>,
    job: Arc<JobObject>,
}

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
        #[cfg(test)]
        if failure == Some(SpawnFailure::ChildTokenOpen) {
            return Err(io::Error::other("child_token_open: injected failure"));
        }
        let child_token = process_token(
            guardian.0.as_ref().unwrap().as_raw_handle() as HANDLE,
            TOKEN_QUERY,
        )?;
        #[cfg(test)]
        let child_restricted = if failure == Some(SpawnFailure::ChildTokenUnrestricted) {
            false
        } else {
            is_token_restricted(child_token.as_raw_handle() as HANDLE)
        };
        #[cfg(not(test))]
        let child_restricted = is_token_restricted(child_token.as_raw_handle() as HANDLE);
        if !child_restricted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "suspended child token is not restricted",
            ));
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

    #[allow(
        dead_code,
        reason = "sandbox tests verify suspended assignment before execution"
    )]
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
    #[allow(
        dead_code,
        reason = "sandbox tests exercise the owned concurrent-drain convenience path"
    )]
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
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::IntoRawHandle;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread::JoinHandle;

    use sembazuru_dataplane::wire::{Reader, Writer};

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
        GetHandleInformation, GetLastError, INVALID_HANDLE_VALUE, LUID, LocalFree, SetLastError,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, ImpersonateLoggedOnUser, LookupPrivilegeValueW,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, RevertToSelf, SE_CHANGE_NOTIFY_NAME,
        SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_USER,
        TokenAppContainerSid, TokenCapabilities, TokenGroups, TokenIsAppContainer, TokenPrivileges,
        TokenRestrictedSids, TokenUser, WinCreatorOwnerRightsSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_READ, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::JobObjects::{IsProcessInJob, JOB_OBJECT_UILIMIT_HANDLES};
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseWindowStation, CreateWindowStationW, GetProcessWindowStation,
        GetUserObjectInformationW, OpenWindowStationW, SetProcessWindowStation, UOI_NAME, UOI_TYPE,
    };
    use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, MAXIMUM_ALLOWED};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, OpenProcess, PROCESS_SYNCHRONIZE, SetEvent,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CWF_CREATE_ONLY, WINSTA_ACCESSCLIPBOARD, WINSTA_ACCESSGLOBALATOMS, WINSTA_CREATEDESKTOP,
        WINSTA_ENUMDESKTOPS, WINSTA_ENUMERATE, WINSTA_EXITWINDOWS, WINSTA_READATTRIBUTES,
        WINSTA_READSCREEN, WINSTA_WRITEATTRIBUTES,
    };

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    const WINDOW_STATION_SCM_SMOKE_BASENAME: &str = "SbzWindowStationScmSmoke.exe";
    const WINDOW_STATION_SCM_SMOKE_SERVICE: &str = "SembazuruWindowStationProbeSmoke";
    const WINDOW_STATION_SCM_SMOKE_SELECTOR: &str =
        "sandbox::tests::window_station_scm_dispatcher_smoke_role";
    const WINDOW_STATION_SCM_SMOKE_SUCCESS: u32 = 0x5342_5a31;
    const WINDOW_STATION_SCM_SMOKE_CONTRACT_FAILURE: u32 = 0x5342_5aff;

    fn validate_window_station_scm_process_argv(argv: &[OsString]) -> Result<(), &'static str> {
        let expected = [
            "--ignored",
            "--exact",
            WINDOW_STATION_SCM_SMOKE_SELECTOR,
            "--nocapture",
            "--test-threads=1",
        ];
        if argv.len() != expected.len() + 1 {
            return Err("process argv cardinality");
        }
        if Path::new(&argv[0]).file_name() != Some(OsStr::new(WINDOW_STATION_SCM_SMOKE_BASENAME)) {
            return Err("process executable basename");
        }
        if argv[1..]
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual != OsStr::new(expected))
        {
            return Err("process argv exact order/value");
        }
        Ok(())
    }

    fn validate_window_station_scm_main_args(args: &[OsString]) -> Result<(), &'static str> {
        if args.len() != 1 {
            return Err("ServiceMain args cardinality");
        }
        if args[0] != OsStr::new(WINDOW_STATION_SCM_SMOKE_SERVICE) {
            return Err("ServiceMain service name");
        }
        Ok(())
    }

    #[test]
    fn window_station_scm_contract_rejects_aliases_and_extra_arguments() {
        assert_ne!(
            WINDOW_STATION_SCM_SMOKE_SUCCESS,
            WINDOW_STATION_SCM_SMOKE_CONTRACT_FAILURE
        );
        let valid_process: Vec<OsString> = [
            WINDOW_STATION_SCM_SMOKE_BASENAME,
            "--ignored",
            "--exact",
            WINDOW_STATION_SCM_SMOKE_SELECTOR,
            "--nocapture",
            "--test-threads=1",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert!(validate_window_station_scm_process_argv(&valid_process).is_ok());
        assert!(
            validate_window_station_scm_main_args(&[OsString::from(
                WINDOW_STATION_SCM_SMOKE_SERVICE
            )])
            .is_ok()
        );
        for invalid in [
            valid_process[..valid_process.len() - 1].to_vec(),
            [valid_process.clone(), vec![OsString::from("extra")]].concat(),
            {
                let mut value = valid_process.clone();
                value[0] = OsString::from("SbzWindowStationScmSmoke-copy.exe");
                value
            },
            {
                let mut value = valid_process.clone();
                value.swap(1, 2);
                value
            },
            {
                let mut value = valid_process.clone();
                value[3] = OsString::from("sandbox::tests::other");
                value
            },
        ] {
            assert!(validate_window_station_scm_process_argv(&invalid).is_err());
        }
        for index in 1..valid_process.len() {
            let mut invalid = valid_process.clone();
            invalid[index].push("-not-exact");
            assert!(validate_window_station_scm_process_argv(&invalid).is_err());
        }
        for invalid in [
            Vec::new(),
            vec![OsString::from("other")],
            vec![
                OsString::from(WINDOW_STATION_SCM_SMOKE_SERVICE),
                OsString::from("extra-start-argument"),
            ],
        ] {
            assert!(validate_window_station_scm_main_args(&invalid).is_err());
        }
    }

    windows_service::define_windows_service!(
        ffi_window_station_scm_smoke_main,
        window_station_scm_smoke_main
    );

    fn window_station_scm_smoke_main(args: Vec<OsString>) {
        let exit_code = if validate_window_station_scm_main_args(&args).is_ok() {
            WINDOW_STATION_SCM_SMOKE_SUCCESS
        } else {
            WINDOW_STATION_SCM_SMOKE_CONTRACT_FAILURE
        };
        let _ = run_window_station_scm_smoke(exit_code);
    }

    fn run_window_station_scm_smoke(exit_code: u32) -> windows_service::Result<()> {
        use windows_service::service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        };
        use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

        let handler = |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status = service_control_handler::register(WINDOW_STATION_SCM_SMOKE_SERVICE, handler)?;
        let set = |current_state, service_exit_code, wait_hint| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: service_exit_code,
                checkpoint: 0,
                wait_hint,
                process_id: None,
            })
        };
        set(
            ServiceState::StartPending,
            ServiceExitCode::Win32(0),
            std::time::Duration::from_secs(10),
        )?;
        if exit_code == WINDOW_STATION_SCM_SMOKE_SUCCESS {
            set(
                ServiceState::Running,
                ServiceExitCode::Win32(0),
                std::time::Duration::default(),
            )?;
        }
        set(
            ServiceState::Stopped,
            ServiceExitCode::ServiceSpecific(exit_code),
            std::time::Duration::default(),
        )
    }

    #[test]
    #[ignore]
    fn window_station_scm_dispatcher_smoke_role() {
        let argv: Vec<_> = std::env::args_os().collect();
        validate_window_station_scm_process_argv(&argv).expect("SCM smoke process argv contract");
        windows_service::service_dispatcher::start(
            WINDOW_STATION_SCM_SMOKE_SERVICE,
            ffi_window_station_scm_smoke_main,
        )
        .expect("SCM dispatcher smoke");
    }

    #[derive(Clone, Debug)]
    struct HandleDeliveryRecord {
        nonce: String,
        raw_lookup_succeeded: bool,
        raw_error: u32,
        raw_type: String,
        raw_name: String,
        raw_inheritable: bool,
        same_access_succeeded: bool,
        duplicate_type: String,
        duplicate_name: String,
        duplicate_inheritable: bool,
        escalation: Vec<(u32, bool, u32)>,
    }

    impl HandleDeliveryRecord {
        const MAGIC: u32 = 0x4844_4c52;
        const VERSION: u32 = 2;
        const MAX_BYTES: usize = 4096;
        const MAX_ESCALATION: usize = 32;

        fn encode(&self) -> Result<Vec<u8>, String> {
            validate_nonce(&self.nonce)?;
            let mut payload = Writer::new();
            payload.bool(self.raw_lookup_succeeded);
            payload.u32(self.raw_error);
            write_text(&mut payload, &self.raw_type)?;
            write_text(&mut payload, &self.raw_name)?;
            payload.bool(self.raw_inheritable);
            payload.bool(self.same_access_succeeded);
            write_text(&mut payload, &self.duplicate_type)?;
            write_text(&mut payload, &self.duplicate_name)?;
            payload.bool(self.duplicate_inheritable);
            if self.escalation.len() > Self::MAX_ESCALATION {
                return Err("escalation count".into());
            }
            payload.u32(self.escalation.len() as u32);
            for &(mask, succeeded, error) in &self.escalation {
                payload.u32(mask);
                payload.bool(succeeded);
                payload.u32(error);
            }
            let payload = payload.into_bytes();
            if payload.len() > Self::MAX_BYTES {
                return Err("delivery record too large".into());
            }
            let mut bytes = Vec::with_capacity(40 + payload.len());
            bytes.extend_from_slice(&Self::MAGIC.to_le_bytes());
            bytes.extend_from_slice(&Self::VERSION.to_le_bytes());
            bytes.extend_from_slice(self.nonce.as_bytes());
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }

        fn decode(bytes: &[u8], expected_nonce: &str) -> Result<Self, String> {
            validate_nonce(expected_nonce)?;
            if !(40..=40 + Self::MAX_BYTES).contains(&bytes.len())
                || u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != Self::MAGIC
                || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != Self::VERSION
            {
                return Err("delivery record header/length".into());
            }
            let nonce = std::str::from_utf8(&bytes[8..40]).map_err(|_| "delivery nonce utf8")?;
            if nonce != expected_nonce {
                return Err("delivery nonce mismatch".into());
            }
            let mut payload = Reader::new(&bytes[40..]);
            let record = Self {
                nonce: nonce.into(),
                raw_lookup_succeeded: read_strict_bool(&mut payload)?,
                raw_error: payload.u32().map_err(|_| "delivery raw error")?,
                raw_type: read_text(&mut payload)?,
                raw_name: read_text(&mut payload)?,
                raw_inheritable: read_strict_bool(&mut payload)?,
                same_access_succeeded: read_strict_bool(&mut payload)?,
                duplicate_type: read_text(&mut payload)?,
                duplicate_name: read_text(&mut payload)?,
                duplicate_inheritable: read_strict_bool(&mut payload)?,
                escalation: {
                    let count = payload.u32().map_err(|_| "escalation count")? as usize;
                    if count > Self::MAX_ESCALATION {
                        return Err("escalation count".into());
                    }
                    let mut values = Vec::with_capacity(count);
                    for _ in 0..count {
                        values.push((
                            payload.u32().map_err(|_| "escalation mask")?,
                            read_strict_bool(&mut payload)?,
                            payload.u32().map_err(|_| "escalation error")?,
                        ));
                    }
                    values
                },
            };
            payload.finish().map_err(|_| "delivery record trailing")?;
            Ok(record)
        }

        fn publish(&self, directory: &Path) -> io::Result<()> {
            let record = directory.join(format!("{}.rec", self.nonce));
            let temporary = directory.join(format!("{}.tmp", self.nonce));
            let bytes = self.encode().map_err(io::Error::other)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(temporary, record)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct UiHandleSourceRecord {
        handle_info_succeeded: bool,
        handle_info_error: u32,
        inheritable: bool,
        identity_succeeded: bool,
        identity_error: u32,
        object_type: String,
        object_name: String,
        same_access_succeeded: bool,
        same_access_error: u32,
        escalation: Vec<(u32, bool, u32)>,
    }

    impl UiHandleSourceRecord {
        fn empty() -> Self {
            Self {
                handle_info_succeeded: false,
                handle_info_error: 0,
                inheritable: false,
                identity_succeeded: false,
                identity_error: 0,
                object_type: String::new(),
                object_name: String::new(),
                same_access_succeeded: false,
                same_access_error: 0,
                escalation: Vec::new(),
            }
        }

        fn encode_into(&self, payload: &mut Writer) -> Result<(), String> {
            payload.bool(self.handle_info_succeeded);
            payload.u32(self.handle_info_error);
            payload.bool(self.inheritable);
            payload.bool(self.identity_succeeded);
            payload.u32(self.identity_error);
            write_text(payload, &self.object_type)?;
            write_text(payload, &self.object_name)?;
            payload.bool(self.same_access_succeeded);
            payload.u32(self.same_access_error);
            validate_escalation_matrix_shape(&self.escalation).map_err(str::to_owned)?;
            payload.u32(self.escalation.len() as u32);
            for &(mask, succeeded, error) in &self.escalation {
                payload.u32(mask);
                payload.bool(succeeded);
                payload.u32(error);
            }
            Ok(())
        }

        fn decode_from(payload: &mut Reader<'_>) -> Result<Self, String> {
            let handle_info_succeeded = read_strict_bool(payload)?;
            let handle_info_error = payload.u32().map_err(|_| "UI handle info error")?;
            let inheritable = read_strict_bool(payload)?;
            let identity_succeeded = read_strict_bool(payload)?;
            let identity_error = payload.u32().map_err(|_| "UI identity error")?;
            let object_type = read_text(payload)?;
            let object_name = read_text(payload)?;
            let same_access_succeeded = read_strict_bool(payload)?;
            let same_access_error = payload.u32().map_err(|_| "UI same-access error")?;
            let count = payload.u32().map_err(|_| "UI escalation count")? as usize;
            if count > HandleDeliveryRecord::MAX_ESCALATION {
                return Err("UI escalation count".into());
            }
            let mut escalation = Vec::with_capacity(count);
            for _ in 0..count {
                escalation.push((
                    payload.u32().map_err(|_| "UI escalation mask")?,
                    read_strict_bool(payload)?,
                    payload.u32().map_err(|_| "UI escalation error")?,
                ));
            }
            validate_escalation_matrix_shape(&escalation).map_err(str::to_owned)?;
            Ok(Self {
                handle_info_succeeded,
                handle_info_error,
                inheritable,
                identity_succeeded,
                identity_error,
                object_type,
                object_name,
                same_access_succeeded,
                same_access_error,
                escalation,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum UiNameOpenRecord {
        NotOpened { raw_error: u32 },
        Opened(UiHandleSourceRecord),
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct UiHandleLimitRecord {
        nonce: String,
        raw_lease: UiHandleSourceRecord,
        ambient_current: UiHandleSourceRecord,
        name_open: UiNameOpenRecord,
    }

    impl UiHandleLimitRecord {
        const MAGIC: u32 = 0x5548_4c52;
        const VERSION: u32 = 1;
        const MAX_BYTES: usize = 8192;

        fn encode(&self) -> Result<Vec<u8>, String> {
            validate_nonce(&self.nonce)?;
            let mut payload = Writer::new();
            self.raw_lease.encode_into(&mut payload)?;
            self.ambient_current.encode_into(&mut payload)?;
            match &self.name_open {
                UiNameOpenRecord::NotOpened { raw_error } => {
                    payload.bool(false);
                    payload.u32(*raw_error);
                }
                UiNameOpenRecord::Opened(source) => {
                    payload.bool(true);
                    source.encode_into(&mut payload)?;
                }
            }
            let payload = payload.into_bytes();
            if payload.len() > Self::MAX_BYTES {
                return Err("UI handle-limit record too large".into());
            }
            let mut bytes = Vec::with_capacity(40 + payload.len());
            bytes.extend_from_slice(&Self::MAGIC.to_le_bytes());
            bytes.extend_from_slice(&Self::VERSION.to_le_bytes());
            bytes.extend_from_slice(self.nonce.as_bytes());
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }

        fn decode(bytes: &[u8], expected_nonce: &str) -> Result<Self, String> {
            validate_nonce(expected_nonce)?;
            if !(40..=40 + Self::MAX_BYTES).contains(&bytes.len())
                || u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != Self::MAGIC
                || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != Self::VERSION
            {
                return Err("UI handle-limit record header/length".into());
            }
            let nonce = std::str::from_utf8(&bytes[8..40]).map_err(|_| "UI nonce utf8")?;
            if nonce != expected_nonce {
                return Err("UI nonce mismatch".into());
            }
            let mut payload = Reader::new(&bytes[40..]);
            let raw_lease = UiHandleSourceRecord::decode_from(&mut payload)?;
            let ambient_current = UiHandleSourceRecord::decode_from(&mut payload)?;
            let name_open = if read_strict_bool(&mut payload)? {
                UiNameOpenRecord::Opened(UiHandleSourceRecord::decode_from(&mut payload)?)
            } else {
                UiNameOpenRecord::NotOpened {
                    raw_error: payload.u32().map_err(|_| "UI name-open error")?,
                }
            };
            payload.finish().map_err(|_| "UI record trailing")?;
            Ok(Self {
                nonce: nonce.into(),
                raw_lease,
                ambient_current,
                name_open,
            })
        }

        fn publish(&self, directory: &Path) -> io::Result<()> {
            let record = directory.join(format!("{}.ui.rec", self.nonce));
            let temporary = directory.join(format!("{}.ui.tmp", self.nonce));
            let bytes = self.encode().map_err(io::Error::other)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(temporary, record)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_handle_delivery(
        record: &HandleDeliveryRecord,
        expected_nonce: &str,
        parent_type: &str,
        parent_name: &str,
        parent_inheritable: bool,
        child_restricted: bool,
        status_success: bool,
        entry_exists: bool,
        record_exists: bool,
    ) -> Result<(), &'static str> {
        if !status_success {
            return Err("child failed");
        }
        if !entry_exists {
            return Err("child entry marker missing");
        }
        if !record_exists {
            return Err("child record missing");
        }
        if record.nonce != expected_nonce {
            return Err("nonce mismatch");
        }
        if !record.raw_lookup_succeeded || record.raw_error != 0 {
            return Err("raw lookup failed");
        }
        if !child_restricted {
            return Err("child token is unrestricted");
        }
        if record.raw_type != parent_type || record.raw_name != parent_name {
            return Err("raw object identity mismatch");
        }
        if !parent_inheritable || !record.raw_inheritable {
            return Err("raw inheritance flag mismatch");
        }
        if !record.same_access_succeeded {
            return Err("same-access duplicate failed");
        }
        if record.duplicate_type != parent_type || record.duplicate_name != parent_name {
            return Err("duplicate object identity mismatch");
        }
        if record.duplicate_inheritable {
            return Err("same-access duplicate remained inheritable");
        }
        Ok(())
    }

    const ESCALATION_MASKS: &[u32] = &[
        DELETE,
        READ_CONTROL,
        WRITE_DAC,
        WRITE_OWNER,
        WINSTA_ENUMDESKTOPS as u32,
        WINSTA_ACCESSCLIPBOARD as u32,
        WINSTA_CREATEDESKTOP as u32,
        WINSTA_ENUMERATE as u32,
        WINSTA_EXITWINDOWS as u32,
        WINSTA_ACCESSGLOBALATOMS as u32,
        WINSTA_WRITEATTRIBUTES as u32,
        WINSTA_READSCREEN as u32,
        GENERIC_READ,
        GENERIC_WRITE,
        GENERIC_EXECUTE,
        GENERIC_ALL,
        MAXIMUM_ALLOWED,
    ];

    #[derive(Debug, PartialEq, Eq)]
    enum EscalationAssessment {
        Denied,
        Unsafe,
        Indeterminate,
    }

    struct AuditWindowStation(Option<HANDLE>);
    impl AuditWindowStation {
        fn handle(&self) -> HANDLE {
            self.0.unwrap()
        }
        fn close(mut self) -> io::Result<()> {
            let handle = self.0.unwrap();
            // SAFETY: handle is the unique CreateWindowStationW result consumed here.
            if unsafe { CloseWindowStation(handle) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.0.take();
            Ok(())
        }
    }
    impl Drop for AuditWindowStation {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                // SAFETY: early-error cleanup owns the remaining CreateWindowStationW result.
                unsafe {
                    CloseWindowStation(handle);
                }
            }
        }
    }

    fn validate_escalation_matrix_shape(values: &[(u32, bool, u32)]) -> Result<(), &'static str> {
        if values.len() != ESCALATION_MASKS.len() {
            return Err("escalation cardinality");
        }
        for ((mask, _, _), expected) in values.iter().zip(ESCALATION_MASKS) {
            if mask != expected {
                return Err("escalation mask/order");
            }
        }
        Ok(())
    }

    fn assess_escalation_matrix(
        values: &[(u32, bool, u32)],
    ) -> Result<EscalationAssessment, &'static str> {
        validate_escalation_matrix_shape(values)?;
        let (maximum, specific) = values.split_last().expect("matrix is non-empty");
        if specific.iter().any(|(_, succeeded, _)| *succeeded) {
            return Ok(EscalationAssessment::Unsafe);
        }
        if specific
            .iter()
            .any(|(_, _, error)| *error != ERROR_ACCESS_DENIED)
        {
            return Ok(EscalationAssessment::Indeterminate);
        }
        if maximum.1 || maximum.2 != ERROR_ACCESS_DENIED {
            Ok(EscalationAssessment::Indeterminate)
        } else {
            Ok(EscalationAssessment::Denied)
        }
    }

    #[test]
    fn window_handle_escalation_classifier_classifies_exact_matrix() {
        let valid: Vec<_> = ESCALATION_MASKS
            .iter()
            .map(|&mask| (mask, false, ERROR_ACCESS_DENIED))
            .collect();
        assert_eq!(
            assess_escalation_matrix(&valid).unwrap(),
            EscalationAssessment::Denied
        );
        let mut unsafe_value = valid.clone();
        unsafe_value[0].1 = true;
        assert_eq!(
            assess_escalation_matrix(&unsafe_value).unwrap(),
            EscalationAssessment::Unsafe
        );
        let mut maximum_only = valid.clone();
        *maximum_only.last_mut().unwrap() = (MAXIMUM_ALLOWED, true, 0);
        assert_eq!(
            assess_escalation_matrix(&maximum_only).unwrap(),
            EscalationAssessment::Indeterminate
        );
        let mut indeterminate = valid.clone();
        indeterminate[0].2 = 0;
        assert_eq!(
            assess_escalation_matrix(&indeterminate).unwrap(),
            EscalationAssessment::Indeterminate
        );
        for mut invalid in [
            Vec::new(),
            valid[..valid.len() - 1].to_vec(),
            {
                let mut v = valid.clone();
                v.push(valid[0]);
                v
            },
            {
                let mut v = valid.clone();
                v[0].0 ^= 1;
                v
            },
        ] {
            assert!(
                assess_escalation_matrix(&invalid).is_err(),
                "invalid matrix accepted: {invalid:?}"
            );
            invalid.clear();
        }
    }

    #[test]
    fn window_handle_delivery_classifier_rejects_every_invalid_outcome() {
        let valid = HandleDeliveryRecord {
            nonce: "0123456789abcdef0123456789abcdef".into(),
            raw_lookup_succeeded: true,
            raw_error: 0,
            raw_type: "WindowStation".into(),
            raw_name: "WinSta0".into(),
            raw_inheritable: true,
            same_access_succeeded: true,
            duplicate_type: "WindowStation".into(),
            duplicate_name: "WinSta0".into(),
            duplicate_inheritable: false,
            escalation: Vec::new(),
        };
        let accept = |record: &HandleDeliveryRecord,
                      nonce,
                      parent_type,
                      parent_name,
                      parent_inheritable,
                      child_restricted,
                      status_success,
                      entry_exists,
                      record_exists| {
            accept_handle_delivery(
                record,
                nonce,
                parent_type,
                parent_name,
                parent_inheritable,
                child_restricted,
                status_success,
                entry_exists,
                record_exists,
            )
        };
        assert!(
            accept(
                &valid,
                &valid.nonce,
                "WindowStation",
                "WinSta0",
                true,
                true,
                true,
                true,
                true
            )
            .is_ok(),
            "valid delivery fixture must be accepted"
        );
        let bytes = valid.encode().unwrap();
        assert_eq!(
            HandleDeliveryRecord::decode(&bytes, &valid.nonce)
                .unwrap()
                .raw_type,
            "WindowStation"
        );
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        let mut version = bytes.clone();
        version[4] ^= 1;
        let mut strict_bool = bytes.clone();
        strict_bool[40] = 2;
        let mut nonce = bytes.clone();
        nonce[8] ^= 1;
        for bad in [
            magic,
            version,
            strict_bool,
            bytes[..39].to_vec(),
            [bytes.clone(), vec![0]].concat(),
            nonce,
        ] {
            assert!(HandleDeliveryRecord::decode(&bad, &valid.nonce).is_err());
        }
        for mutate in [
            Box::new(|value: &mut HandleDeliveryRecord| {
                value.nonce = "ffffffffffffffffffffffffffffffff".into()
            }) as Box<dyn Fn(&mut HandleDeliveryRecord)>,
            Box::new(|value| value.raw_type = "Desktop".into()),
            Box::new(|value| value.raw_name = "other".into()),
            Box::new(|value| value.raw_lookup_succeeded = false),
            Box::new(|value| value.raw_error = 5),
            Box::new(|value| value.raw_inheritable = false),
            Box::new(|value| value.same_access_succeeded = false),
            Box::new(|value| value.duplicate_type = "Desktop".into()),
            Box::new(|value| value.duplicate_name = "other".into()),
            Box::new(|value| value.duplicate_inheritable = true),
        ] {
            let mut invalid = valid.clone();
            mutate(&mut invalid);
            assert!(
                accept(
                    &invalid,
                    &valid.nonce,
                    "WindowStation",
                    "WinSta0",
                    true,
                    true,
                    true,
                    true,
                    true
                )
                .is_err(),
                "invalid child record was accepted: {invalid:?}"
            );
        }
        for (status_success, entry_exists, record_exists) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(
                accept(
                    &valid,
                    &valid.nonce,
                    "WindowStation",
                    "WinSta0",
                    true,
                    true,
                    status_success,
                    entry_exists,
                    record_exists,
                )
                .is_err()
            );
        }
        assert!(
            accept(
                &valid,
                &valid.nonce,
                "WindowStation",
                "WinSta0",
                true,
                false,
                true,
                true,
                true,
            )
            .is_err()
        );
    }

    fn user_object_text(handle: HANDLE, index: i32) -> io::Result<String> {
        let mut buffer = vec![0u16; 1024];
        let mut used = 0;
        // SAFETY: buffer is writable and the live USER object handle belongs to this process.
        if unsafe {
            GetUserObjectInformationW(
                handle,
                index,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * size_of::<u16>()) as u32,
                &mut used,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let length = (used as usize / size_of::<u16>()).min(buffer.len());
        if length == 0 || buffer[length - 1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated USER object text",
            ));
        }
        Ok(String::from_utf16_lossy(&buffer[..length - 1]))
    }

    fn user_object_identity(handle: HANDLE) -> io::Result<(String, String)> {
        Ok((
            user_object_text(handle, UOI_TYPE)?,
            user_object_text(handle, UOI_NAME)?,
        ))
    }

    fn inheritable(handle: HANDLE) -> io::Result<bool> {
        let mut flags = 0;
        if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags & HANDLE_FLAG_INHERIT != 0)
    }

    struct RawDeliveryProcess {
        process: OwnedHandle,
        _job: Arc<JobObject>,
        stdout: Option<JoinHandle<io::Result<()>>>,
        stderr: Option<JoinHandle<io::Result<String>>>,
        child_restricted: bool,
        ui_restrictions: u32,
        reaped: bool,
    }

    struct HandleDeliveryEvidence {
        record: HandleDeliveryRecord,
        child_restricted: bool,
        status_success: bool,
        entry_exists: bool,
        record_exists: bool,
        parent: (String, String),
        parent_inheritable: bool,
    }

    impl Drop for RawDeliveryProcess {
        fn drop(&mut self) {
            if !self.reaped {
                // SAFETY: this process is uniquely owned by the test probe; bounded reap avoids orphans.
                unsafe {
                    TerminateProcess(self.process.as_raw_handle() as HANDLE, 1);
                    WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 30_000);
                }
            }
        }
    }

    fn drain_delivery_pipe(handle: OwnedHandle, retain: bool) -> io::Result<String> {
        let mut file = unsafe { File::from_raw_handle(handle.into_raw_handle()) };
        let mut buffer = [0u8; 8192];
        let mut output = Vec::new();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if retain && output.len() < 64 * 1024 {
                let take = (64 * 1024 - output.len()).min(read);
                output.extend_from_slice(&buffer[..take]);
            }
        }
        Ok(String::from_utf8_lossy(&output).into_owned())
    }

    fn spawn_handle_delivery_child(
        token: &ActionToken,
        command: &RestrictedCommand,
        station: HANDLE,
        wire_station: bool,
        with_ui_handle_limit: bool,
    ) -> io::Result<RawDeliveryProcess> {
        let mut prepared = prepare_command(command)?;
        let job = Arc::new(if with_ui_handle_limit {
            JobObject::new_kill_on_close_with_ui_handle_limit_for_test()?
        } else {
            JobObject::new_kill_on_close()?
        });
        let ui_restrictions = job.ui_restrictions_for_test()?;
        // SAFETY: the current-process pseudo-handle is valid for this membership query.
        if job.contains(unsafe { GetCurrentProcess() } as RawHandle)? {
            return Err(io::Error::other("parent unexpectedly belongs to probe job"));
        }
        let (stdin, stdin_parent) = stdio_pipe(true)?;
        let (stdout, stdout_parent) = stdio_pipe(false)?;
        let (stderr, stderr_parent) = stdio_pipe(false)?;
        drop(stdin_parent);
        let mut inherited = vec![
            stdin.as_raw_handle() as HANDLE,
            stdout.as_raw_handle() as HANDLE,
            stderr.as_raw_handle() as HANDLE,
        ];
        if wire_station {
            inherited.push(station);
        }
        let mut attributes = AttributeList::handles(&inherited)?;
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0];
        startup.StartupInfo.hStdOutput = inherited[1];
        startup.StartupInfo.hStdError = inherited[2];
        startup.lpAttributeList = attributes.ptr();
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the command buffers and only-listed inheritable handles remain live.
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
                "spawn API error {}",
                io::Error::last_os_error().raw_os_error().unwrap_or(0)
            )));
        }
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) };
        let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread as RawHandle) };
        let child_token = match process_token(process.as_raw_handle() as HANDLE, TOKEN_QUERY) {
            Ok(token) => token,
            Err(error) => {
                unsafe {
                    TerminateProcess(process.as_raw_handle() as HANDLE, 1);
                    WaitForSingleObject(process.as_raw_handle() as HANDLE, 30_000);
                }
                return Err(error);
            }
        };
        let child_restricted = is_token_restricted(child_token.as_raw_handle() as HANDLE);
        if !child_restricted {
            unsafe {
                TerminateProcess(process.as_raw_handle() as HANDLE, 1);
                WaitForSingleObject(process.as_raw_handle() as HANDLE, 30_000);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "suspended child token is not restricted",
            ));
        }
        if let Err(error) = job.assign_verified(process.as_raw_handle()) {
            unsafe {
                TerminateProcess(process.as_raw_handle() as HANDLE, 1);
                WaitForSingleObject(process.as_raw_handle() as HANDLE, 30_000);
            }
            return Err(error);
        }
        drop(attributes);
        drop((stdin, stdout, stderr));
        if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } != 1 {
            // SAFETY: resume failed before the child could run; bounded reap prevents a suspended orphan.
            unsafe {
                TerminateProcess(process.as_raw_handle() as HANDLE, 1);
                WaitForSingleObject(process.as_raw_handle() as HANDLE, 30_000);
            }
            return Err(io::Error::other("resume child failed"));
        }
        let stdout =
            std::thread::spawn(move || drain_delivery_pipe(stdout_parent, false).map(|_| ()));
        let stderr = std::thread::spawn(move || drain_delivery_pipe(stderr_parent, true));
        Ok(RawDeliveryProcess {
            process,
            _job: job,
            stdout: Some(stdout),
            stderr: Some(stderr),
            child_restricted,
            ui_restrictions,
            reaped: false,
        })
    }

    fn wait_for_delivery_child(
        mut child: RawDeliveryProcess,
    ) -> io::Result<(bool, String, bool, u32)> {
        let wait = unsafe { WaitForSingleObject(child.process.as_raw_handle() as HANDLE, 30_000) };
        if wait != WAIT_OBJECT_0 {
            // SAFETY: the bounded wait expired or failed; terminate then bounded-reap this test child.
            let (terminated, reap) = unsafe {
                (
                    TerminateProcess(child.process.as_raw_handle() as HANDLE, 1),
                    WaitForSingleObject(child.process.as_raw_handle() as HANDLE, 30_000),
                )
            };
            child.reaped = reap == WAIT_OBJECT_0;
            return Err(io::Error::new(
                if wait == WAIT_TIMEOUT {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::Other
                },
                format!("child wait={wait}; terminate={terminated}; reap={reap}"),
            ));
        }
        child.reaped = true;
        let mut code = 0;
        // SAFETY: process is live and code is writable.
        if unsafe { GetExitCodeProcess(child.process.as_raw_handle() as HANDLE, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        child
            .stdout
            .take()
            .expect("stdout drain is owned")
            .join()
            .map_err(|_| io::Error::other("stdout drain panicked"))??;
        let text = child
            .stderr
            .take()
            .expect("stderr drain is owned")
            .join()
            .map_err(|_| io::Error::other("stderr drain panicked"))??;
        Ok((
            code == 0,
            text,
            child.child_restricted,
            child.ui_restrictions,
        ))
    }

    fn handle_delivery_evidence(wire_station: bool) -> Result<HandleDeliveryEvidence, String> {
        let token = ActionToken::create().map_err(|error| format!("token setup: {error}"))?;
        struct RootCleanup(PathBuf);
        impl Drop for RootCleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root_path = std::env::temp_dir().join(format!(
            "sembazuru-handle-delivery-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let root_sddl = format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;GRGX;;;{})",
            sid_string(token.broker_sid()).map_err(|error| format!("root broker SID: {error}"))?,
            sid_string(token.broker_sid()).map_err(|error| format!("root broker SID: {error}"))?,
            sid_string(token.action_sid.0).map_err(|error| format!("root action SID: {error}"))?,
        );
        create_secured_directory(&root_path, &root_sddl)
            .map_err(|error| format!("root setup: {error}"))?;
        let root = RootCleanup(root_path);
        let scratch = PrivateScratch::create(&root.0, "handle-delivery", &token)
            .map_err(|error| format!("scratch setup: {error}"))?;
        let executable = scratch.path().join("handle-delivery-probe.exe");
        std::fs::copy(
            std::env::current_exe().map_err(|error| format!("preflight exe: {error}"))?,
            &executable,
        )
        .map_err(|error| format!("preflight copy: {error}"))?;
        if !executable.is_absolute() || !executable.is_file() || !scratch.path().is_dir() {
            return Err("preflight absolute exe/cwd/record dir failed".into());
        }
        let nonce = secure_random_hex().map_err(|error| format!("nonce: {error}"))?;
        let current = unsafe { GetProcessWindowStation() };
        if current.is_null() {
            return Err("parent current station missing".into());
        }
        let mut low = null_mut();
        // SAFETY: current is live; low receives an independently owned, inheritable low-rights handle.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                current,
                GetCurrentProcess(),
                &mut low,
                WINSTA_READATTRIBUTES as u32,
                1,
                0,
            )
        } == 0
        {
            return Err(format!(
                "parent low-rights duplicate: {}",
                io::Error::last_os_error()
            ));
        }
        let low = unsafe { OwnedHandle::from_raw_handle(low as RawHandle) };
        let parent = user_object_identity(current)
            .map_err(|error| format!("parent current identity: {error}"))?;
        let low_identity = user_object_identity(low.as_raw_handle() as HANDLE)
            .map_err(|error| format!("parent low identity: {error}"))?;
        let low_inheritable = inheritable(low.as_raw_handle() as HANDLE)
            .map_err(|error| format!("parent low inherit: {error}"))?;
        if parent != low_identity || !low_inheritable {
            return Err("parent low-rights station validation failed".into());
        }
        let system_root =
            PathBuf::from(std::env::var_os("SystemRoot").ok_or("preflight SystemRoot missing")?);
        let command = RestrictedCommand::new(&executable, scratch.path())
            .arg("--ignored")
            .arg("--exact")
            .arg("sandbox::tests::window_handle_delivery_child")
            .arg("--quiet")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .arg("--")
            .arg(scratch.path())
            .arg(&nonce)
            .env("Path", system_root.join("System32"))
            .env(
                "SystemDrive",
                std::env::var_os("SystemDrive").ok_or("preflight SystemDrive missing")?,
            )
            .env("SystemRoot", system_root)
            .env("SBZ_HANDLE_RAW", (low.as_raw_handle() as usize).to_string());
        let child = spawn_handle_delivery_child(
            &token,
            &command,
            low.as_raw_handle() as HANDLE,
            wire_station,
            false,
        )
        .map_err(|error| format!("delivery not confirmed: {error}"))?;
        let (status_success, stderr, child_restricted, _) =
            wait_for_delivery_child(child).map_err(|error| format!("wait child: {error}"))?;
        let entry = scratch.path().join(format!("{nonce}.entry"));
        let record_path = scratch.path().join(format!("{nonce}.rec"));
        if !status_success {
            return Err(format!(
                "delivery not confirmed: child nonzero; stderr={stderr:?}"
            ));
        }
        if !entry.is_file() {
            return Err("delivery not confirmed: child entry marker missing".into());
        }
        if !record_path.is_file() {
            return Err("delivery not confirmed: child record missing".into());
        }
        let bytes = std::fs::read(&record_path).map_err(|error| format!("record read: {error}"))?;
        let record = HandleDeliveryRecord::decode(&bytes, &nonce)
            .map_err(|error| format!("record decode/nonce: {error}"))?;
        Ok(HandleDeliveryEvidence {
            record,
            child_restricted,
            status_success,
            entry_exists: entry.is_file(),
            record_exists: record_path.is_file(),
            parent,
            parent_inheritable: low_inheritable,
        })
    }

    #[test]
    fn window_handle_delivery_probe_requires_handle_list_delivery() {
        let evidence = handle_delivery_evidence(false).unwrap();
        assert!(
            evidence.child_restricted
                && evidence.status_success
                && evidence.entry_exists
                && evidence.record_exists,
            "spawn/token/entry/record evidence missing"
        );
        assert!(
            !evidence.record.raw_lookup_succeeded,
            "numeric alias unexpectedly resolved"
        );
        eprintln!("unwired raw lookup error={}", evidence.record.raw_error);
    }

    #[test]
    fn window_handle_delivery_probe_confirms_handle_list_delivery() {
        let evidence = handle_delivery_evidence(true).unwrap();
        accept_handle_delivery(
            &evidence.record,
            &evidence.record.nonce,
            &evidence.parent.0,
            &evidence.parent.1,
            evidence.parent_inheritable,
            evidence.child_restricted,
            evidence.status_success,
            evidence.entry_exists,
            evidence.record_exists,
        )
        .expect("delivery confirmed");
    }

    #[test]
    fn window_handle_escalation_probe_rejects_current_station_lease() {
        let evidence = handle_delivery_evidence(true).expect("delivery evidence");
        accept_handle_delivery(
            &evidence.record,
            &evidence.record.nonce,
            &evidence.parent.0,
            &evidence.parent.1,
            evidence.parent_inheritable,
            evidence.child_restricted,
            evidence.status_success,
            evidence.entry_exists,
            evidence.record_exists,
        )
        .expect("delivery confirmed");
        eprintln!(
            "current-station escalation results: {:x?}",
            evidence.record.escalation
        );
        // Any successful duplicate proves that this current-station lease must remain forbidden.
        assert_eq!(
            assess_escalation_matrix(&evidence.record.escalation).expect("matrix shape"),
            EscalationAssessment::Unsafe,
            "all-denied/indeterminate result requires a fresh lease-design review"
        );
    }

    #[test]
    fn ui_handle_limit_cannot_replace_private_station() {
        let ordinary = ui_handle_limit_evidence(false).expect("ordinary UI evidence");
        assert_eq!(
            ordinary.ui_restrictions & JOB_OBJECT_UILIMIT_HANDLES,
            0,
            "ordinary test job unexpectedly has UILIMIT_HANDLES"
        );
        assert_eq!(
            ordinary.raw_lease,
            UiHandleAssessment::Unsafe,
            "ordinary raw lease must prove the probe remains live"
        );
        assert_eq!(
            ordinary.ambient,
            UiHandleAssessment::Unsafe,
            "ordinary ambient station must prove the probe remains live"
        );
        let evidence = ui_handle_limit_evidence(true).expect("UI handle-limit evidence");
        assert_ne!(
            evidence.ui_restrictions & JOB_OBJECT_UILIMIT_HANDLES,
            0,
            "handle-limited test job lacks UILIMIT_HANDLES"
        );
        assert!(
            !matches!(evidence.ambient, UiHandleAssessment::Indeterminate)
                && !matches!(evidence.name_open, UiHandleAssessment::Indeterminate),
            "UILIMIT_HANDLES result is indeterminate: ambient={:?} name={:?}",
            evidence.ambient,
            evidence.name_open
        );
        assert!(
            matches!(evidence.ambient, UiHandleAssessment::Unsafe)
                || matches!(evidence.name_open, UiHandleAssessment::Unsafe),
            "UILIMIT_HANDLES unexpectedly confined both ambient and name-open handles"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct UiHandleLimitEvidence {
        raw_lease: UiHandleAssessment,
        ambient: UiHandleAssessment,
        name_open: UiHandleAssessment,
        ui_restrictions: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum UiHandleAssessment {
        Denied,
        IdentityOnlyOrConfined,
        Unsafe,
        Indeterminate,
    }

    fn raw_error(error: io::Error) -> u32 {
        error.raw_os_error().unwrap_or(0) as u32
    }

    fn probe_window_station_source(handle: HANDLE) -> UiHandleSourceRecord {
        let mut source = UiHandleSourceRecord::empty();
        let mut flags = 0;
        // SAFETY: `flags` is writable; failure is captured as a typed result below.
        if unsafe { GetHandleInformation(handle, &mut flags) } != 0 {
            source.handle_info_succeeded = true;
            source.inheritable = flags & HANDLE_FLAG_INHERIT != 0;
        } else {
            source.handle_info_error = raw_error(io::Error::last_os_error());
        }
        match user_object_identity(handle) {
            Ok((object_type, object_name)) => {
                source.identity_succeeded = true;
                source.object_type = object_type;
                source.object_name = object_name;
            }
            Err(error) => source.identity_error = raw_error(error),
        }
        let mut same_access = null_mut();
        // SAFETY: source handle belongs to this process or is a documented pseudo-handle;
        // the duplicate out pointer is writable and success is immediately owned below.
        source.same_access_succeeded = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut same_access,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ) != 0
        };
        if source.same_access_succeeded {
            // SAFETY: successful DuplicateHandle returns a normal kernel-handle ownership.
            drop(unsafe { OwnedHandle::from_raw_handle(same_access as RawHandle) });
        } else {
            source.same_access_error = raw_error(io::Error::last_os_error());
        }
        for &mask in ESCALATION_MASKS {
            let mut duplicate = null_mut();
            // SAFETY: `duplicate` is a writable out pointer; every successful duplicate is
            // immediately closed using ordinary kernel-handle ownership.
            unsafe { SetLastError(0) };
            let succeeded = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    GetCurrentProcess(),
                    &mut duplicate,
                    mask,
                    0,
                    0,
                ) != 0
            };
            let error = if succeeded {
                0
            } else {
                unsafe { GetLastError() }
            };
            if succeeded {
                // SAFETY: successful DuplicateHandle returns a normal kernel-handle ownership.
                drop(unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) });
            }
            source.escalation.push((mask, succeeded, error));
        }
        source
    }

    fn assess_ui_handle_source(
        source: &UiHandleSourceRecord,
        expected_handle_list_identity: Option<&(String, String)>,
    ) -> Result<UiHandleAssessment, &'static str> {
        if let Some(expected) = expected_handle_list_identity
            && (!source.handle_info_succeeded
                || !source.inheritable
                || !source.identity_succeeded
                || source.object_type != expected.0
                || source.object_name != expected.1)
        {
            return Ok(UiHandleAssessment::Indeterminate);
        }
        match assess_escalation_matrix(&source.escalation)? {
            EscalationAssessment::Unsafe => Ok(UiHandleAssessment::Unsafe),
            EscalationAssessment::Indeterminate => Ok(UiHandleAssessment::Indeterminate),
            EscalationAssessment::Denied if source.identity_succeeded => {
                Ok(UiHandleAssessment::IdentityOnlyOrConfined)
            }
            EscalationAssessment::Denied => Ok(UiHandleAssessment::Indeterminate),
        }
    }

    fn assess_ui_name_open(record: &UiNameOpenRecord) -> Result<UiHandleAssessment, &'static str> {
        match record {
            UiNameOpenRecord::NotOpened {
                raw_error: 5 | 6 | 1400,
            } => Ok(UiHandleAssessment::Denied),
            UiNameOpenRecord::NotOpened { .. } => Ok(UiHandleAssessment::Indeterminate),
            UiNameOpenRecord::Opened(source) => assess_ui_handle_source(source, None),
        }
    }

    fn ui_handle_limit_evidence(with_handle_limit: bool) -> Result<UiHandleLimitEvidence, String> {
        let token = ActionToken::create().map_err(|error| format!("token setup: {error}"))?;
        struct RootCleanup(PathBuf);
        impl Drop for RootCleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root_path = std::env::temp_dir().join(format!(
            "sembazuru-ui-handle-limit-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let broker =
            sid_string(token.broker_sid()).map_err(|error| format!("broker SID: {error}"))?;
        let action =
            sid_string(token.action_sid.0).map_err(|error| format!("action SID: {error}"))?;
        create_secured_directory(
            &root_path,
            &format!("O:{broker}D:P(A;OICI;FA;;;{broker})(A;OICI;GRGX;;;{action})"),
        )
        .map_err(|error| format!("root setup: {error}"))?;
        let root = RootCleanup(root_path);
        let scratch = PrivateScratch::create(&root.0, "ui-handle-limit", &token)
            .map_err(|error| format!("scratch setup: {error}"))?;
        let executable = scratch.path().join("ui-handle-limit-probe.exe");
        std::fs::copy(
            std::env::current_exe().map_err(|error| format!("probe executable: {error}"))?,
            &executable,
        )
        .map_err(|error| format!("probe copy: {error}"))?;
        let nonce = secure_random_hex().map_err(|error| format!("nonce: {error}"))?;
        let current = unsafe { GetProcessWindowStation() };
        if current.is_null() {
            return Err("parent current station missing".into());
        }
        let parent = user_object_identity(current)
            .map_err(|error| format!("parent current identity: {error}"))?;
        let mut low = null_mut();
        // SAFETY: current is live; success returns an independently-owned, inheritable lease.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                current,
                GetCurrentProcess(),
                &mut low,
                WINSTA_READATTRIBUTES as u32,
                1,
                0,
            )
        } == 0
        {
            return Err(format!(
                "parent low-right lease: {}",
                io::Error::last_os_error()
            ));
        }
        let low = unsafe { OwnedHandle::from_raw_handle(low as RawHandle) };
        if user_object_identity(low.as_raw_handle() as HANDLE)
            .map_err(|error| format!("parent low identity: {error}"))?
            != parent
            || !inheritable(low.as_raw_handle() as HANDLE)
                .map_err(|error| format!("parent low inheritance: {error}"))?
        {
            return Err("parent low-right lease validation failed".into());
        }
        let system_root =
            PathBuf::from(std::env::var_os("SystemRoot").ok_or("preflight SystemRoot missing")?);
        let command = RestrictedCommand::new(&executable, scratch.path())
            .arg("--ignored")
            .arg("--exact")
            .arg("sandbox::tests::ui_handle_limit_child")
            .arg("--quiet")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .arg("--")
            .arg(scratch.path())
            .arg(&nonce)
            .env("Path", system_root.join("System32"))
            .env(
                "SystemDrive",
                std::env::var_os("SystemDrive").ok_or("preflight SystemDrive missing")?,
            )
            .env("SystemRoot", system_root)
            .env("SBZ_HANDLE_RAW", (low.as_raw_handle() as usize).to_string())
            .env("SBZ_PARENT_STATION", &parent.1);
        let child = spawn_handle_delivery_child(
            &token,
            &command,
            low.as_raw_handle() as HANDLE,
            true,
            with_handle_limit,
        )
        .map_err(|error| format!("spawn/assign/restricted evidence: {error}"))?;
        let (status_success, stderr, child_restricted, ui_restrictions) =
            wait_for_delivery_child(child).map_err(|error| format!("child reap: {error}"))?;
        if !status_success {
            return Err(format!("child nonzero; stderr={stderr:?}"));
        }
        if !child_restricted {
            return Err("child token was not restricted".into());
        }
        let entry = scratch.path().join(format!("{nonce}.entry"));
        let record_path = scratch.path().join(format!("{nonce}.ui.rec"));
        if !entry.is_file() || !record_path.is_file() {
            return Err(format!(
                "child bounded evidence missing: entry={} record={}",
                entry.is_file(),
                record_path.is_file()
            ));
        }
        let record = UiHandleLimitRecord::decode(
            &std::fs::read(&record_path).map_err(|error| format!("record read: {error}"))?,
            &nonce,
        )
        .map_err(|error| format!("record decode: {error}"))?;
        let raw_lease = assess_ui_handle_source(&record.raw_lease, Some(&parent))
            .map_err(|error| format!("raw lease classifier: {error}"))?;
        let ambient = assess_ui_handle_source(&record.ambient_current, None)
            .map_err(|error| format!("ambient classifier: {error}"))?;
        let name_open = assess_ui_name_open(&record.name_open)
            .map_err(|error| format!("name-open classifier: {error}"))?;
        eprintln!(
            "ui-handle-limit={} flags={ui_restrictions:#x} raw={raw_lease:?} ambient={ambient:?} name={name_open:?}; raw-matrix={:x?}; ambient-matrix={:x?}; name={:?}",
            with_handle_limit,
            record.raw_lease.escalation,
            record.ambient_current.escalation,
            record.name_open,
        );
        Ok(UiHandleLimitEvidence {
            raw_lease,
            ambient,
            name_open,
            ui_restrictions,
        })
    }

    #[test]
    #[ignore]
    fn ui_handle_limit_child() {
        let args: Vec<_> = std::env::args_os().collect();
        let separator = args
            .iter()
            .position(|arg| arg == "--")
            .expect("record separator");
        let values = &args[separator + 1..];
        assert_eq!(values.len(), 2, "record argv");
        let directory = PathBuf::from(&values[0]);
        let nonce = values[1].to_str().expect("nonce utf8").to_owned();
        validate_nonce(&nonce).expect("nonce format");
        let entry = directory.join(format!("{nonce}.entry"));
        let mut entry_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&entry)
            .expect("entry create_new");
        entry_file.write_all(b"entry").expect("entry write");
        entry_file.sync_all().expect("entry sync");
        drop(entry_file);
        let raw = std::env::var("SBZ_HANDLE_RAW")
            .expect("raw handle env")
            .parse::<usize>()
            .expect("raw handle integer") as HANDLE;
        let ambient = unsafe { GetProcessWindowStation() };
        let station_name = std::env::var("SBZ_PARENT_STATION").expect("parent station name");
        let station_name: Vec<u16> = OsStr::new(&station_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: the UTF-16 station name is NUL-terminated and remains live for the call.
        let opened =
            unsafe { OpenWindowStationW(station_name.as_ptr(), 0, WINSTA_READATTRIBUTES as u32) };
        let name_open = if opened.is_null() {
            UiNameOpenRecord::NotOpened {
                raw_error: raw_error(io::Error::last_os_error()),
            }
        } else {
            let source = probe_window_station_source(opened);
            // SAFETY: OpenWindowStationW grants this distinct USER-object ownership.
            if unsafe { CloseWindowStation(opened) } == 0 {
                panic!(
                    "OpenWindowStationW handle close failed: {}",
                    io::Error::last_os_error()
                );
            }
            UiNameOpenRecord::Opened(source)
        };
        UiHandleLimitRecord {
            nonce,
            raw_lease: probe_window_station_source(raw),
            ambient_current: probe_window_station_source(ambient),
            name_open,
        }
        .publish(&directory)
        .expect("publish UI handle-limit record");
    }

    #[test]
    fn ui_handle_limit_raw_classifier_requires_parent_identity() {
        let parent: (String, String) = ("WindowStation".into(), "WinSta0".into());
        let valid = UiHandleSourceRecord {
            handle_info_succeeded: true,
            handle_info_error: 0,
            inheritable: true,
            identity_succeeded: true,
            identity_error: 0,
            object_type: parent.0.clone(),
            object_name: parent.1.clone(),
            same_access_succeeded: true,
            same_access_error: 0,
            escalation: ESCALATION_MASKS
                .iter()
                .map(|&mask| (mask, true, 0))
                .collect(),
        };
        assert_eq!(
            assess_ui_handle_source(&valid, Some(&parent)).unwrap(),
            UiHandleAssessment::Unsafe
        );
        let mut missing = valid.clone();
        missing.identity_succeeded = false;
        assert_eq!(
            assess_ui_handle_source(&missing, Some(&parent)).unwrap(),
            UiHandleAssessment::Indeterminate
        );
        let mut mismatch = valid;
        mismatch.object_name = "other".into();
        assert_eq!(
            assess_ui_handle_source(&mismatch, Some(&parent)).unwrap(),
            UiHandleAssessment::Indeterminate
        );
    }

    #[test]
    fn ui_handle_limit_record_codec_rejects_malformed_inputs() {
        let source = UiHandleSourceRecord {
            handle_info_succeeded: true,
            handle_info_error: 0,
            inheritable: false,
            identity_succeeded: true,
            identity_error: 0,
            object_type: "WindowStation".into(),
            object_name: "WinSta0".into(),
            same_access_succeeded: true,
            same_access_error: 0,
            escalation: ESCALATION_MASKS
                .iter()
                .map(|&mask| (mask, false, ERROR_ACCESS_DENIED))
                .collect(),
        };
        let record = UiHandleLimitRecord {
            nonce: "0123456789abcdef0123456789abcdef".into(),
            raw_lease: source.clone(),
            ambient_current: source.clone(),
            name_open: UiNameOpenRecord::Opened(source),
        };
        let bytes = record.encode().expect("record encode");
        assert_eq!(
            UiHandleLimitRecord::decode(&bytes, &record.nonce).unwrap(),
            record
        );
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        let mut version = bytes.clone();
        version[4] ^= 1;
        let mut strict_bool = bytes.clone();
        strict_bool[40] = 2;
        let mut nonce = bytes.clone();
        nonce[8] ^= 1;
        for bad in [
            magic,
            version,
            strict_bool,
            bytes[..39].to_vec(),
            [bytes.clone(), vec![0]].concat(),
            nonce,
        ] {
            assert!(UiHandleLimitRecord::decode(&bad, &record.nonce).is_err());
        }
        let mut missing = record.clone();
        missing.raw_lease.escalation.pop();
        assert!(missing.encode().is_err(), "short matrix encoded");
        let mut reordered = record;
        reordered.ambient_current.escalation.swap(0, 1);
        assert!(reordered.encode().is_err(), "reordered matrix encoded");
    }

    #[test]
    fn private_station_unnamed_create_rejects_connected_logon_station() {
        let token = ActionToken::create().expect("action token");
        let broker = sid_string(token.broker_sid()).expect("broker SID");
        let current = unsafe { GetProcessWindowStation() };
        let before = user_object_identity(current).expect("current identity before create");
        let sddl = format!("O:{broker}D:P(D;;WD;;;OW)(A;;0x00020002;;;{broker})");
        let created = ActionPipeSecurity(sddl).with_attributes(|attributes| {
            // SAFETY: attributes points to the live protected descriptor for this synchronous call.
            let handle = unsafe {
                CreateWindowStationW(
                    null(),
                    CWF_CREATE_ONLY,
                    READ_CONTROL | WINSTA_READATTRIBUTES as u32,
                    attributes.cast(),
                )
            };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(AuditWindowStation(Some(handle)))
        });
        match created {
            Err(error) => {
                let after = user_object_identity(unsafe { GetProcessWindowStation() })
                    .expect("current identity after failed create");
                assert_eq!(before, after, "current station changed after failed create");
                if matches!(error.raw_os_error(), Some(183 | 5)) {
                    eprintln!(
                        "unsupported unnamed station identity: raw_error={:?}",
                        error.raw_os_error()
                    );
                } else {
                    panic!(
                        "indeterminate unnamed create: raw_error={:?}",
                        error.raw_os_error()
                    );
                }
            }
            Ok(station) => {
                // SAFETY: current is the original live process window-station handle.
                let restore_ok = unsafe { SetProcessWindowStation(current) } != 0;
                let restore_error = (!restore_ok).then(io::Error::last_os_error);
                let restored =
                    restore_ok.then(|| user_object_identity(unsafe { GetProcessWindowStation() }));
                let identity = user_object_identity(station.handle());
                let close = station.close();
                eprintln!(
                    "unnamed station cleanup: restore_ok={restore_ok} restore_error={:?} close_error={:?}",
                    restore_error.as_ref().and_then(io::Error::raw_os_error),
                    close.as_ref().err().and_then(io::Error::raw_os_error),
                );
                assert!(
                    restore_ok,
                    "original process station restore failed: {restore_error:?}"
                );
                assert_eq!(
                    restored.unwrap().expect("restored identity"),
                    before,
                    "restored process station identity differs"
                );
                let identity = identity.expect("created identity");
                assert!(close.is_ok(), "created station close failed: {close:?}");
                if identity != before {
                    panic!("fresh unnamed station supported; design review required: {identity:?}");
                }
                eprintln!("unsupported unnamed station aliases current: {identity:?}");
            }
        }
    }

    #[test]
    #[ignore]
    fn window_handle_delivery_child() {
        let args: Vec<_> = std::env::args_os().collect();
        let separator = args
            .iter()
            .position(|arg| arg == "--")
            .expect("record separator");
        let values = &args[separator + 1..];
        assert_eq!(values.len(), 2, "record argv");
        let directory = PathBuf::from(&values[0]);
        let nonce = values[1].to_str().expect("nonce utf8").to_owned();
        validate_nonce(&nonce).expect("nonce format");
        let entry = directory.join(format!("{nonce}.entry"));
        let mut entry_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&entry)
            .expect("entry create_new");
        entry_file.write_all(b"entry").expect("entry write");
        entry_file.sync_all().expect("entry sync");
        drop(entry_file);
        let raw = std::env::var("SBZ_HANDLE_RAW")
            .expect("raw handle env")
            .parse::<usize>()
            .expect("raw handle integer") as HANDLE;
        let mut record = HandleDeliveryRecord {
            nonce,
            raw_lookup_succeeded: false,
            raw_error: 0,
            raw_type: String::new(),
            raw_name: String::new(),
            raw_inheritable: false,
            same_access_succeeded: false,
            duplicate_type: String::new(),
            duplicate_name: String::new(),
            duplicate_inheritable: false,
            escalation: Vec::new(),
        };
        match user_object_identity(raw) {
            Ok(identity) => {
                record.raw_lookup_succeeded = true;
                record.raw_type = identity.0;
                record.raw_name = identity.1;
                record.raw_inheritable = inheritable(raw).expect("raw inherit flag");
                let mut duplicate = null_mut();
                record.same_access_succeeded = unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        raw,
                        GetCurrentProcess(),
                        &mut duplicate,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    ) != 0
                };
                if record.same_access_succeeded {
                    let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) };
                    let identity = user_object_identity(duplicate.as_raw_handle() as HANDLE)
                        .expect("duplicate identity");
                    record.duplicate_type = identity.0;
                    record.duplicate_name = identity.1;
                    record.duplicate_inheritable = inheritable(duplicate.as_raw_handle() as HANDLE)
                        .expect("duplicate inherit flag");
                }
                for &mask in ESCALATION_MASKS {
                    let mut duplicate = null_mut();
                    unsafe { SetLastError(0) };
                    let succeeded = unsafe {
                        DuplicateHandle(
                            GetCurrentProcess(),
                            raw,
                            GetCurrentProcess(),
                            &mut duplicate,
                            mask,
                            0,
                            0,
                        ) != 0
                    };
                    let error = if succeeded {
                        0
                    } else {
                        unsafe { GetLastError() }
                    };
                    if succeeded {
                        drop(unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) });
                    }
                    record.escalation.push((mask, succeeded, error));
                }
            }
            Err(error) => record.raw_error = error.raw_os_error().unwrap_or(0) as u32,
        }
        record.publish(&directory).expect("publish delivery record");
    }

    #[test]
    fn sandbox_probe_record_codec_round_trips() {
        let record = SandboxProbeRecord::fixture();
        let bytes = record.encode().unwrap();
        assert_eq!(
            SandboxProbeRecord::decode(&bytes, &record.nonce).unwrap(),
            record
        );
    }

    #[test]
    fn sandbox_probe_record_rejects_malformed_inputs() {
        let record = SandboxProbeRecord::fixture();
        let bytes = record.encode().unwrap();
        for mutation in [
            (0usize, 0u8),  // magic
            (4usize, 0u8),  // version
            (40usize, 0u8), // field count
            (44usize, 0u8), // payload length
        ] {
            let mut bad = bytes.clone();
            bad[mutation.0] ^= mutation.1.wrapping_add(1);
            assert!(SandboxProbeRecord::decode(&bad, &record.nonce).is_err());
        }
        for end in [0usize, 1, 7, 8, 39, 40, 47, 48, bytes.len() - 1] {
            assert!(SandboxProbeRecord::decode(&bytes[..end], &record.nonce).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SandboxProbeRecord::decode(&trailing, &record.nonce).is_err());
        let mut invalid_utf8 = bytes.clone();
        // AppContainer SID's length prefix starts at payload offset 49; point it at one byte.
        invalid_utf8[49..53].copy_from_slice(&1u32.to_le_bytes());
        invalid_utf8[53] = 0xff;
        assert!(SandboxProbeRecord::decode(&invalid_utf8, &record.nonce).is_err());
        let mut duplicate_env = SandboxProbeRecord::fixture();
        duplicate_env.environment = vec![("Path".into(), "a".into()), ("PATH".into(), "b".into())];
        assert!(duplicate_env.encode().is_err());
        let mut unsorted_sids = SandboxProbeRecord::fixture();
        unsorted_sids.groups = vec![
            ProbeSid {
                sid: "S-2".into(),
                attributes: 0,
            },
            ProbeSid {
                sid: "S-1".into(),
                attributes: 0,
            },
        ];
        assert!(unsorted_sids.encode().is_err());
        assert!(SandboxProbeRecord::decode(&bytes, "ffffffffffffffffffffffffffffffff").is_err());
        let mut duplicate_sid = SandboxProbeRecord::fixture();
        duplicate_sid.capabilities = vec![
            ProbeSid {
                sid: "S-1".into(),
                attributes: 0,
            },
            ProbeSid {
                sid: "S-1".into(),
                attributes: 0,
            },
        ];
        assert!(duplicate_sid.encode().is_err());
        let mut oversized = SandboxProbeRecord::fixture();
        oversized.privileges = vec![(0, 0, 0); SANDBOX_PROBE_MAX_LIST as usize + 1];
        assert!(oversized.encode().is_err());
        let mut oversized_env = SandboxProbeRecord::fixture();
        oversized_env.environment = (0..=SANDBOX_PROBE_MAX_LIST)
            .map(|index| (format!("V{index:03}"), "x".into()))
            .collect();
        assert!(oversized_env.encode().is_err());
        let mut overflow = bytes.clone();
        overflow[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SandboxProbeRecord::decode(&overflow, &record.nonce).is_err());
        assert!(read_strict_bool(&mut Reader::new(&[2])).is_err());
        overflow[40..44].copy_from_slice(&SANDBOX_PROBE_FIELDS.to_le_bytes());
        overflow[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SandboxProbeRecord::decode(&overflow, &record.nonce).is_err());
        let mut bad_bool = bytes.clone();
        bad_bool[48] = 2;
        assert!(SandboxProbeRecord::decode(&bad_bool, &record.nonce).is_err());
        let mut attributes = SandboxProbeRecord::fixture();
        attributes.groups[0].attributes ^= 1;
        assert_ne!(attributes.encode().unwrap(), bytes);
    }

    const SANDBOX_PROBE_MAGIC: u32 = 0x5350_5252;
    const SANDBOX_PROBE_VERSION: u32 = 1;
    const SANDBOX_PROBE_FIELDS: u32 = 9;
    const SANDBOX_PROBE_MAX_TOTAL: usize = 1 << 20;
    const SANDBOX_PROBE_MAX_LIST: u32 = 256;
    const SANDBOX_PROBE_MAX_TEXT: usize = 32 * 1024;

    #[derive(Debug, PartialEq, Eq)]
    struct ProbeSid {
        sid: String,
        attributes: u32,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SandboxProbeRecord {
        nonce: String,
        is_appcontainer: bool,
        appcontainer_sid: String,
        restricted_sids: Vec<ProbeSid>,
        groups: Vec<ProbeSid>,
        capabilities: Vec<ProbeSid>,
        integrity_rid: u32,
        privileges: Vec<(u32, i32, u32)>,
        environment: Vec<(String, String)>,
        in_job: bool,
    }

    impl SandboxProbeRecord {
        fn fixture() -> Self {
            Self {
                nonce: "0123456789abcdef0123456789abcdef".into(),
                is_appcontainer: false,
                appcontainer_sid: String::new(),
                restricted_sids: vec![ProbeSid {
                    sid: "S-1-1-0".into(),
                    attributes: 0,
                }],
                groups: vec![ProbeSid {
                    sid: "S-1-5-32-545".into(),
                    attributes: 4,
                }],
                capabilities: Vec::new(),
                integrity_rid: 0x2000,
                privileges: vec![(23, 0, 2)],
                environment: vec![("Path".into(), "C:\\Windows\\System32".into())],
                in_job: true,
            }
        }

        fn encode(&self) -> Result<Vec<u8>, String> {
            validate_nonce(&self.nonce)?;
            validate_sids(&self.restricted_sids, "restricted SID")?;
            validate_sids(&self.groups, "group")?;
            validate_sids(&self.capabilities, "capability")?;
            validate_environment(&self.environment)?;
            write_text(&mut Writer::new(), &self.appcontainer_sid)?;
            if self.privileges.len() as u32 > SANDBOX_PROBE_MAX_LIST
                || self.environment.len() as u32 > SANDBOX_PROBE_MAX_LIST
            {
                return Err("list count".into());
            }
            let mut payload = Writer::new();
            payload.bool(self.is_appcontainer);
            payload.str(&self.appcontainer_sid);
            write_sid_list(&mut payload, &self.restricted_sids)?;
            write_sid_list(&mut payload, &self.groups)?;
            write_sid_list(&mut payload, &self.capabilities)?;
            payload.u32(self.integrity_rid);
            payload.u32(self.privileges.len() as u32);
            for &(low, high, attributes) in &self.privileges {
                payload.u32(low);
                payload.u32(high as u32);
                payload.u32(attributes);
            }
            payload.u32(self.environment.len() as u32);
            for (name, value) in &self.environment {
                write_text(&mut payload, name)?;
                write_text(&mut payload, value)?;
            }
            payload.bool(self.in_job);
            let payload = payload.into_bytes();
            if payload.len() > SANDBOX_PROBE_MAX_TOTAL {
                return Err("payload too large".into());
            }
            let mut bytes = Vec::with_capacity(48 + payload.len());
            bytes.extend_from_slice(&SANDBOX_PROBE_MAGIC.to_le_bytes());
            bytes.extend_from_slice(&SANDBOX_PROBE_VERSION.to_le_bytes());
            bytes.extend_from_slice(self.nonce.as_bytes());
            bytes.extend_from_slice(&SANDBOX_PROBE_FIELDS.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }

        fn decode(bytes: &[u8], expected_nonce: &str) -> Result<Self, String> {
            validate_nonce(expected_nonce)?;
            if bytes.len() < 48 || bytes.len() > 48 + SANDBOX_PROBE_MAX_TOTAL {
                return Err("record length".into());
            }
            let u32_at = |offset: usize| -> u32 {
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
            };
            if u32_at(0) != SANDBOX_PROBE_MAGIC || u32_at(4) != SANDBOX_PROBE_VERSION {
                return Err("header".into());
            }
            let nonce = std::str::from_utf8(&bytes[8..40])
                .map_err(|_| "nonce utf8")?
                .to_owned();
            validate_nonce(&nonce)?;
            if nonce != expected_nonce || u32_at(40) != SANDBOX_PROBE_FIELDS {
                return Err("nonce or fields".into());
            }
            let total = u32_at(44) as usize;
            if total != bytes.len() - 48 {
                return Err("total length".into());
            }
            let mut reader = Reader::new(&bytes[48..]);
            let result = Self {
                nonce,
                is_appcontainer: read_strict_bool(&mut reader)?,
                appcontainer_sid: read_text(&mut reader)?,
                restricted_sids: read_sid_list(&mut reader, "restricted SID")?,
                groups: read_sid_list(&mut reader, "group")?,
                capabilities: read_sid_list(&mut reader, "capability")?,
                integrity_rid: reader.u32().map_err(|_| "integrity")?,
                privileges: read_privileges(&mut reader)?,
                environment: read_environment(&mut reader)?,
                in_job: read_strict_bool(&mut reader)?,
            };
            reader.finish().map_err(|_| "trailing")?;
            validate_sids(&result.restricted_sids, "restricted SID")?;
            validate_sids(&result.groups, "group")?;
            validate_sids(&result.capabilities, "capability")?;
            validate_environment(&result.environment)?;
            Ok(result)
        }

        fn collect(nonce: String) -> Result<Self, String> {
            validate_nonce(&nonce)?;
            let token = current_token(TOKEN_QUERY).map_err(|error| error.to_string())?;
            let handle = token.as_raw_handle() as HANDLE;
            let flag =
                token_info(handle, TokenIsAppContainer).map_err(|error| error.to_string())?;
            let is_appcontainer = unsafe { *flag.as_ptr().cast::<u32>() } == 1;
            let appcontainer_sid = {
                let info =
                    token_info(handle, TokenAppContainerSid).map_err(|error| error.to_string())?;
                let sid = unsafe {
                    (*(info.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>())).TokenAppContainer
                };
                if sid.is_null() {
                    String::new()
                } else {
                    sid_string(sid).map_err(|error| error.to_string())?
                }
            };
            let mut in_job = 0;
            if unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut in_job) } == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            let mut record = Self {
                nonce,
                is_appcontainer,
                appcontainer_sid,
                restricted_sids: token_sid_list(handle, TokenRestrictedSids)?,
                groups: token_sid_list(handle, TokenGroups)?,
                capabilities: token_sid_list(handle, TokenCapabilities)?,
                integrity_rid: integrity_rid(handle).map_err(|error| error.to_string())?,
                privileges: token_privileges(handle)?,
                environment: normalized_environment()?,
                in_job: in_job != 0,
            };
            // The record is a canonical comparison surface, so Windows group duplication is
            // intentionally represented as one SID rather than a transport ambiguity.
            for values in [
                &mut record.restricted_sids,
                &mut record.groups,
                &mut record.capabilities,
            ] {
                values.sort_unstable_by(|left, right| {
                    (&left.sid, left.attributes).cmp(&(&right.sid, right.attributes))
                });
                values.dedup_by(|left, right| {
                    left.sid == right.sid && left.attributes == right.attributes
                });
            }
            record.privileges.sort_unstable();
            record
                .environment
                .sort_by_key(|(name, _)| name.to_ascii_lowercase());
            Ok(record)
        }
    }

    fn token_sid_list(token: HANDLE, class: i32) -> Result<Vec<ProbeSid>, String> {
        let info = token_info(token, class).map_err(|error| error.to_string())?;
        let groups = unsafe { &*(info.as_ptr().cast::<TOKEN_GROUPS>()) };
        let header = std::mem::offset_of!(TOKEN_GROUPS, Groups);
        let entries_len = (groups.GroupCount as usize)
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .ok_or("group count overflow")?;
        let required = header
            .checked_add(entries_len)
            .ok_or("group bytes overflow")?;
        if required
            > info
                .len()
                .checked_mul(size_of::<usize>())
                .ok_or("group buffer overflow")?
        {
            return Err("group buffer truncated".into());
        }
        // SAFETY: the checked header plus GroupCount array byte length is within the owned
        // `token_info` allocation, and TOKEN_GROUPS guarantees each entry is initialized.
        let entries = unsafe {
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        entries
            .iter()
            .map(|entry| {
                Ok(ProbeSid {
                    sid: sid_string(entry.Sid).map_err(|error| error.to_string())?,
                    attributes: entry.Attributes,
                })
            })
            .collect()
    }

    fn token_privileges(token: HANDLE) -> Result<Vec<(u32, i32, u32)>, String> {
        let info = token_info(token, TokenPrivileges).map_err(|error| error.to_string())?;
        let value = unsafe { &*(info.as_ptr().cast::<TOKEN_PRIVILEGES>()) };
        let header = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
        let entries_len = (value.PrivilegeCount as usize)
            .checked_mul(size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>())
            .ok_or("privilege count overflow")?;
        let required = header
            .checked_add(entries_len)
            .ok_or("privilege bytes overflow")?;
        if required
            > info
                .len()
                .checked_mul(size_of::<usize>())
                .ok_or("privilege buffer overflow")?
        {
            return Err("privilege buffer truncated".into());
        }
        // SAFETY: the checked header plus PrivilegeCount array byte length is inside the
        // owned `token_info` allocation returned for TOKEN_PRIVILEGES.
        let entries = unsafe {
            std::slice::from_raw_parts(value.Privileges.as_ptr(), value.PrivilegeCount as usize)
        };
        Ok(entries
            .iter()
            .map(|entry| (entry.Luid.LowPart, entry.Luid.HighPart, entry.Attributes))
            .collect())
    }

    fn normalized_environment() -> Result<Vec<(String, String)>, String> {
        let mut values: Vec<_> = std::env::vars_os()
            .map(|(name, value)| {
                Ok((
                    name.into_string().map_err(|_| "non-utf8 env")?,
                    value.into_string().map_err(|_| "non-utf8 env")?,
                ))
            })
            .collect::<Result<_, &str>>()?;
        values.sort_by_key(|(name, _)| name.to_ascii_lowercase());
        validate_environment(&values)?;
        Ok(values)
    }

    #[test]
    #[ignore]
    fn sandbox_probe_record_child() {
        let args: Vec<_> = std::env::args_os().collect();
        let separator = args
            .iter()
            .position(|arg| arg == "--")
            .expect("record separator");
        let values = &args[separator + 1..];
        assert_eq!(values.len(), 2, "record argv");
        let directory = PathBuf::from(&values[0]);
        let nonce = values[1].to_str().expect("nonce utf8").to_owned();
        validate_nonce(&nonce).expect("nonce format");
        assert!(directory.is_dir(), "record directory");
        let record = directory.join(format!("{nonce}.rec"));
        let temporary = directory.join(format!("{nonce}.tmp"));
        assert!(!record.exists(), "stale destination");
        struct TempCleanup(Option<PathBuf>);
        impl Drop for TempCleanup {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let mut cleanup = TempCleanup(Some(temporary.clone()));
        let bytes = SandboxProbeRecord::collect(nonce)
            .expect("collect record")
            .encode()
            .expect("encode record");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .expect("create tmp");
        file.write_all(&bytes).expect("write tmp");
        file.sync_all().expect("sync tmp");
        drop(file);
        std::fs::rename(&temporary, &record).expect("publish record");
        cleanup.0.take();
    }

    fn record_child_command(directory: &Path, nonce: &str) -> std::process::Command {
        let root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env("SystemRoot", &root)
            .env("SystemDrive", std::env::var_os("SystemDrive").unwrap())
            .env("Path", root.join("System32"))
            .env("MiXeD_CaSe", "record-only-test")
            .args([
                "--ignored",
                "--exact",
                "sandbox::tests::sandbox_probe_record_child",
                "--nocapture",
                "--test-threads=1",
                "--",
            ])
            .arg(directory)
            .arg(nonce);
        command
    }

    fn accepts_record(status_success: bool, record_exists: bool) -> bool {
        status_success && record_exists
    }

    struct RecordScratch(PathBuf);
    impl Drop for RecordScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record_scratch_root() -> RecordScratch {
        let path = std::env::temp_dir().join(format!(
            "sembazuru-record-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed),
        ));
        let sid = current_user_sid_string().unwrap();
        create_secured_directory(&path, &format!("D:P(A;OICI;FA;;;{sid})")).unwrap();
        RecordScratch(path)
    }

    #[test]
    fn sandbox_probe_record_round_trip_uses_file_not_stdout() {
        let root = record_scratch_root();
        let directory = root.0.join("record");
        std::fs::create_dir(&directory).unwrap();
        let nonce = secure_random_hex().unwrap();
        let status = record_child_command(&directory, &nonce).status().unwrap();
        let path = directory.join(format!("{nonce}.rec"));
        assert!(
            accepts_record(status.success(), path.exists()),
            "status={status}"
        );
        let record = SandboxProbeRecord::decode(&std::fs::read(&path).unwrap(), &nonce).unwrap();
        let expected = SandboxProbeRecord::collect(nonce.clone()).unwrap();
        assert_eq!(record.is_appcontainer, expected.is_appcontainer);
        assert_eq!(record.appcontainer_sid, expected.appcontainer_sid);
        assert_eq!(record.restricted_sids, expected.restricted_sids);
        assert_eq!(record.groups, expected.groups);
        assert_eq!(record.capabilities, expected.capabilities);
        assert_eq!(record.integrity_rid, expected.integrity_rid);
        assert_eq!(record.privileges, expected.privileges);
        // A plain probe is not assigned a new Job, but inherits the test harness Job when
        // one exists; the parent-side process observation is the exact expectation.
        assert_eq!(record.in_job, expected.in_job);
        assert_eq!(record.environment, normalized_environment_for_child());
    }

    #[test]
    fn sandbox_probe_record_stale_destination_is_not_success() {
        let root = record_scratch_root();
        let directory = root.0.join("record");
        std::fs::create_dir(&directory).unwrap();
        let nonce = secure_random_hex().unwrap();
        let path = directory.join(format!("{nonce}.rec"));
        std::fs::write(&path, b"sentinel").unwrap();
        let status = record_child_command(&directory, &nonce).status().unwrap();
        assert!(!accepts_record(status.success(), path.exists()));
        assert_eq!(std::fs::read(&path).unwrap(), b"sentinel");
        assert!(!directory.join(format!("{nonce}.tmp")).exists());
    }

    #[test]
    fn sandbox_probe_record_acceptance_rejects_noop_and_record_only() {
        assert!(!accepts_record(true, false));
        assert!(!accepts_record(false, true));
    }

    fn normalized_environment_for_child() -> Vec<(String, String)> {
        let root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let mut values: Vec<(String, String)> = vec![
            ("MiXeD_CaSe".into(), "record-only-test".into()),
            ("Path".into(), root.join("System32").display().to_string()),
            ("SystemDrive".into(), std::env::var("SystemDrive").unwrap()),
            ("SystemRoot".into(), root.display().to_string()),
        ];
        values.sort_by_key(|(name, _)| name.to_ascii_lowercase());
        values
    }

    fn validate_nonce(nonce: &str) -> Result<(), String> {
        if nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err("nonce".into())
        }
    }
    fn write_text(writer: &mut Writer, text: &str) -> Result<(), String> {
        if text.len() > SANDBOX_PROBE_MAX_TEXT {
            Err("text too long".into())
        } else {
            writer.str(text);
            Ok(())
        }
    }
    fn write_sid_list(writer: &mut Writer, values: &[ProbeSid]) -> Result<(), String> {
        if values.len() as u32 > SANDBOX_PROBE_MAX_LIST {
            return Err("list count".into());
        }
        writer.u32(values.len() as u32);
        for value in values {
            write_text(writer, &value.sid)?;
            writer.u32(value.attributes);
        }
        Ok(())
    }
    fn read_text(reader: &mut Reader<'_>) -> Result<String, String> {
        let value = reader.str().map_err(|_| "utf8 or truncation")?;
        if value.len() > SANDBOX_PROBE_MAX_TEXT {
            Err("text too long".into())
        } else {
            Ok(value)
        }
    }
    fn read_sid_list(reader: &mut Reader<'_>, label: &str) -> Result<Vec<ProbeSid>, String> {
        let count = reader.u32().map_err(|_| "count")?;
        if count > SANDBOX_PROBE_MAX_LIST {
            return Err(format!("{label} count"));
        }
        (0..count)
            .map(|_| {
                Ok(ProbeSid {
                    sid: read_text(reader)?,
                    attributes: reader.u32().map_err(|_| "SID attributes")?,
                })
            })
            .collect()
    }
    fn read_privileges(reader: &mut Reader<'_>) -> Result<Vec<(u32, i32, u32)>, String> {
        let count = reader.u32().map_err(|_| "priv count")?;
        if count > SANDBOX_PROBE_MAX_LIST {
            return Err("priv count".into());
        }
        (0..count)
            .map(|_| {
                Ok((
                    reader.u32().map_err(|_| "priv")?,
                    reader.u32().map_err(|_| "priv")? as i32,
                    reader.u32().map_err(|_| "priv")?,
                ))
            })
            .collect()
    }
    fn read_environment(reader: &mut Reader<'_>) -> Result<Vec<(String, String)>, String> {
        let count = reader.u32().map_err(|_| "env count")?;
        if count > SANDBOX_PROBE_MAX_LIST {
            return Err("env count".into());
        }
        (0..count)
            .map(|_| Ok((read_text(reader)?, read_text(reader)?)))
            .collect()
    }
    fn validate_sids(values: &[ProbeSid], label: &str) -> Result<(), String> {
        if values.windows(2).all(|pair| {
            (pair[0].sid.as_str(), pair[0].attributes) < (pair[1].sid.as_str(), pair[1].attributes)
        }) {
            Ok(())
        } else {
            Err(format!("{label} order"))
        }
    }
    fn read_strict_bool(reader: &mut Reader<'_>) -> Result<bool, String> {
        match reader.u8().map_err(|_| "bool")? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("bool value".into()),
        }
    }
    fn validate_environment(values: &[(String, String)]) -> Result<(), String> {
        if values.iter().any(|(name, value)| {
            name.is_empty()
                || name.contains('=')
                || name.len() > SANDBOX_PROBE_MAX_TEXT
                || value.len() > SANDBOX_PROBE_MAX_TEXT
        }) {
            return Err("environment text".into());
        }
        if values
            .windows(2)
            .all(|pair| pair[0].0.to_ascii_lowercase() < pair[1].0.to_ascii_lowercase())
        {
            Ok(())
        } else {
            Err("environment order".into())
        }
    }

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
        let broker = current_token(TOKEN_QUERY).unwrap();
        assert!(!is_token_restricted(broker.as_raw_handle() as HANDLE));
        assert!(is_token_restricted(a.handle()));
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
        for (index, failure) in [
            SpawnFailure::AfterCreate,
            SpawnFailure::ChildTokenOpen,
            SpawnFailure::ChildTokenUnrestricted,
            SpawnFailure::BeforeResume,
        ]
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
