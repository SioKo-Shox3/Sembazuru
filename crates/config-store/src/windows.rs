use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
#[cfg(test)]
use std::os::windows::io::OwnedHandle;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, LocalFree, RtlNtStatusToDosError, STATUS_OBJECT_NAME_COLLISION,
    UNICODE_STRING,
};
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED,
};
#[cfg(test)]
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TRAVERSE, FileAttributeTagInfo, FileDispositionInfoEx, FileIdExtdDirectoryInfo,
    FileIdExtdDirectoryRestartInfo, FileIdInfo, GetFileInformationByHandleEx, READ_CONTROL,
    SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;
#[cfg(test)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

use crate::{MachineStoreError, MachineStoreErrorClass};

const ROOT_NAME: &str = "Sembazuru";
const SCRATCH_NAME: &str = "scratch";
const CAS_NAME: &str = "cas";
const MARKER_NAME: &str = ".provisioning-v1";
const MARKER_MAGIC: &[u8; 10] = b"SEMBSTORE\0";
const MARKER_VERSION: u32 = 1;
const IDENTITY_BYTES: usize = 24;
const MARKER_BYTES: usize = MARKER_MAGIC.len() + 4 + IDENTITY_BYTES * 3;

const ROOT_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-934400648-3059976913-1740392721-646658299-1483742795)";
const CHILD_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-934400648-3059976913-1740392721-646658299-1483742795)";

#[derive(Clone)]
struct SecurityPolicy {
    root: String,
    child: String,
}

#[cfg(test)]
pub(crate) struct TestSecurityPolicy(SecurityPolicy);

#[cfg(test)]
impl TestSecurityPolicy {
    pub(crate) fn root_sddl(&self) -> &str {
        self.0.root_sddl()
    }

    pub(crate) fn child_sddl(&self) -> &str {
        self.0.child_sddl()
    }
}

impl SecurityPolicy {
    fn production() -> Self {
        Self {
            root: ROOT_SDDL.to_owned(),
            child: CHILD_SDDL.to_owned(),
        }
    }

    pub(crate) fn root_sddl(&self) -> &str {
        &self.root
    }

    pub(crate) fn child_sddl(&self) -> &str {
        &self.child
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    volume: u64,
    file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PathInspection {
    pub(crate) identity: FileIdentity,
    pub(crate) is_directory: bool,
    pub(crate) is_reparse: bool,
}

#[cfg(test)]
type RootDropHook = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
static AFTER_ROOT_DROP_HOOKS: std::sync::Mutex<Vec<(FileIdentity, RootDropHook)>> =
    std::sync::Mutex::new(Vec::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Marker {
    root: FileIdentity,
    scratch: FileIdentity,
    cas: FileIdentity,
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, MachineStoreError> {
        let wide = OsStr::new(sddl)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and remains live; the successful API
        // result is a LocalAlloc allocation owned by `SecurityDescriptor`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io_error("convert machine-store SDDL"));
        }
        Ok(Self(descriptor))
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from the SDDL conversion API and is
        // released exactly once using its documented allocator pair.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo returned this LocalAlloc allocation.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

pub(super) fn provision_canonical() -> Result<(), MachineStoreError> {
    let program_data = program_data_path()?;
    let parent = open_directory_path_nofollow(&program_data)?;
    provision_at_handle(
        &parent,
        OsStr::new(ROOT_NAME),
        &SecurityPolicy::production(),
    )
}

pub(super) fn rollback_canonical() -> Result<(), MachineStoreError> {
    let program_data = program_data_path()?;
    let parent = open_directory_path_nofollow(&program_data)?;
    rollback_at_handle(
        &parent,
        OsStr::new(ROOT_NAME),
        &SecurityPolicy::production(),
    )
}

pub(super) fn commit_canonical() -> Result<(), MachineStoreError> {
    let program_data = program_data_path()?;
    let parent = open_directory_path_nofollow(&program_data)?;
    commit_at_handle(
        &parent,
        OsStr::new(ROOT_NAME),
        &SecurityPolicy::production(),
    )
}

pub(super) fn uninstall_canonical() -> Result<(), MachineStoreError> {
    let program_data = program_data_path()?;
    let parent = open_directory_path_nofollow(&program_data)?;
    uninstall_at_handle(
        &parent,
        OsStr::new(ROOT_NAME),
        &SecurityPolicy::production(),
    )
}

fn program_data_path() -> Result<PathBuf, MachineStoreError> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: the output pointer is valid; the API allocates a NUL-terminated
    // string which is released with CoTaskMemFree below.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut raw) };
    if result < 0 {
        return Err(MachineStoreError::with_io(
            MachineStoreErrorClass::Io,
            "resolve canonical ProgramData",
            io::Error::from_raw_os_error(result),
        ));
    }
    let mut length = 0usize;
    // SAFETY: successful SHGetKnownFolderPath returned a valid NUL-terminated
    // UTF-16 allocation.
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    // SAFETY: the measured range is initialized UTF-16 data.
    let path = unsafe { OsString::from_wide(std::slice::from_raw_parts(raw, length)) };
    // SAFETY: allocator pair documented by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(PathBuf::from(path))
}

fn open_directory_path_nofollow(path: &Path) -> Result<File, MachineStoreError> {
    let mut options = OpenOptions::new();
    options
        .access_mode(
            DELETE
                | READ_CONTROL
                | FILE_LIST_DIRECTORY
                | FILE_READ_ATTRIBUTES
                | FILE_TRAVERSE
                | SYNCHRONIZE,
        )
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|error| map_io("open machine-store parent without following", error))?;
    let inspection = inspect_handle(&file)?;
    if !inspection.is_directory || inspection.is_reparse {
        return Err(integrity("machine-store parent is not a plain directory"));
    }
    Ok(file)
}

enum CreateFailure {
    Collision,
    Error(MachineStoreError),
}

fn nt_relative(
    parent: &File,
    name: &OsStr,
    disposition: u32,
    is_directory: Option<bool>,
    desired_access: u32,
    descriptor: Option<&SecurityDescriptor>,
) -> Result<File, CreateFailure> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty()
        || name
            .iter()
            .any(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
    {
        return Err(CreateFailure::Error(MachineStoreError::new(
            MachineStoreErrorClass::IntegrityViolation,
            "machine-store relative name is invalid",
        )));
    }
    let byte_len = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            CreateFailure::Error(MachineStoreError::new(
                MachineStoreErrorClass::IntegrityViolation,
                "machine-store relative name is too long",
            ))
        })?;
    let unicode_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle().cast(),
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE as u32,
        SecurityDescriptor: descriptor.map_or(std::ptr::null_mut(), |sd| sd.as_ptr()),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut io_status = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let kind_option = match is_directory {
        Some(true) => FILE_DIRECTORY_FILE,
        Some(false) => FILE_NON_DIRECTORY_FILE,
        None => 0,
    };
    // SAFETY: parent/name/attributes/output storage stay valid for this
    // synchronous call. A successful handle is transferred once to `File`.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &attributes,
            io_status.as_mut_ptr(),
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition,
            kind_option | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status == STATUS_OBJECT_NAME_COLLISION {
        return Err(CreateFailure::Collision);
    }
    if status < 0 {
        // SAFETY: status came directly from NtCreateFile.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(CreateFailure::Error(map_io(
            "open machine-store namespace entry",
            io::Error::from_raw_os_error(code as i32),
        )));
    }
    // SAFETY: successful NtCreateFile returned one owned kernel handle.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn create_relative_directory(
    parent: &File,
    name: &OsStr,
    descriptor: &SecurityDescriptor,
) -> Result<File, CreateFailure> {
    nt_relative(
        parent,
        name,
        FILE_CREATE,
        Some(true),
        DELETE
            | READ_CONTROL
            | FILE_LIST_DIRECTORY
            | FILE_READ_ATTRIBUTES
            | FILE_TRAVERSE
            | SYNCHRONIZE,
        Some(descriptor),
    )
}

fn create_relative_marker(
    parent: &File,
    descriptor: &SecurityDescriptor,
) -> Result<File, CreateFailure> {
    nt_relative(
        parent,
        OsStr::new(MARKER_NAME),
        FILE_CREATE,
        Some(false),
        DELETE | READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE | 0x4000_0000,
        Some(descriptor),
    )
}

fn open_relative(
    parent: &File,
    name: &OsStr,
    is_directory: bool,
) -> Result<File, MachineStoreError> {
    let access =
        DELETE | READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
    match nt_relative(parent, name, FILE_OPEN, Some(is_directory), access, None) {
        Ok(file) => Ok(file),
        Err(CreateFailure::Collision) => unreachable!("FILE_OPEN cannot report create collision"),
        Err(CreateFailure::Error(error)) => Err(error),
    }
}

fn open_relative_any(parent: &File, name: &OsStr) -> Result<File, MachineStoreError> {
    match nt_relative(
        parent,
        name,
        FILE_OPEN,
        None,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        None,
    ) {
        Ok(file) => Ok(file),
        Err(CreateFailure::Collision) => unreachable!("FILE_OPEN cannot report create collision"),
        Err(CreateFailure::Error(error)) => Err(error),
    }
}

fn is_not_found(error: &MachineStoreError) -> bool {
    error
        .source
        .as_ref()
        .is_some_and(|source| source.kind() == io::ErrorKind::NotFound)
}

fn open_relative_optional(
    parent: &File,
    name: &OsStr,
    is_directory: bool,
) -> Result<Option<File>, MachineStoreError> {
    match open_relative(parent, name, is_directory) {
        Ok(file) => Ok(Some(file)),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn provision_at_handle(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<(), MachineStoreError> {
    let root_sd = SecurityDescriptor::from_sddl(policy.root_sddl())?;
    let child_sd = SecurityDescriptor::from_sddl(policy.child_sddl())?;
    let root = match create_relative_directory(parent, root_name, &root_sd) {
        Ok(root) => root,
        Err(CreateFailure::Collision) => {
            return Err(MachineStoreError::new(
                MachineStoreErrorClass::NamespaceAlreadyExists,
                "machine-store namespace already exists",
            ));
        }
        Err(CreateFailure::Error(error)) => return Err(error),
    };
    let root_identity = match verify_directory(&root, &root_sd) {
        Ok(identity) => identity,
        Err(error) => {
            return provision_failure(parent, root_name, root, policy.root_sddl(), error);
        }
    };
    let result = (|| {
        let scratch = create_relative_directory(&root, OsStr::new(SCRATCH_NAME), &child_sd)
            .map_err(create_failure_to_error)?;
        let scratch_identity = verify_directory(&scratch, &child_sd)?;
        let cas = create_relative_directory(&root, OsStr::new(CAS_NAME), &child_sd)
            .map_err(create_failure_to_error)?;
        let cas_identity = verify_directory(&cas, &child_sd)?;
        let marker = Marker {
            root: root_identity,
            scratch: scratch_identity,
            cas: cas_identity,
        };
        drop(scratch);
        drop(cas);
        let mut marker_file =
            create_relative_marker(&root, &root_sd).map_err(create_failure_to_error)?;
        verify_plain_file(&marker_file, &root_sd)?;
        marker_file
            .write_all(&encode_marker(marker))
            .map_err(|error| map_io("write machine-store provision marker", error))?;
        marker_file
            .sync_all()
            .map_err(|error| map_io("flush machine-store provision marker", error))?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => provision_failure(parent, root_name, root, policy.root_sddl(), error),
    }
}

fn create_failure_to_error(error: CreateFailure) -> MachineStoreError {
    match error {
        CreateFailure::Collision => integrity("machine-store child unexpectedly already exists"),
        CreateFailure::Error(error) => error,
    }
}

fn provision_failure(
    parent: &File,
    root_name: &OsStr,
    root: File,
    expected_sddl: &str,
    primary: MachineStoreError,
) -> Result<(), MachineStoreError> {
    let cleanup = remove_tree_bound(parent, root_name, root, expected_sddl);
    match cleanup {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(MachineStoreError::with_io(
            MachineStoreErrorClass::IntegrityViolation,
            "machine-store provision failed and identity-bound rollback failed",
            io::Error::other(format!("primary: {primary}; rollback: {cleanup}")),
        )),
    }
}

struct ValidatedProvision {
    root: File,
    marker: File,
}

fn reopen_validated_provision(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<ValidatedProvision, MachineStoreError> {
    let root_sd = SecurityDescriptor::from_sddl(policy.root_sddl())?;
    let child_sd = SecurityDescriptor::from_sddl(policy.child_sddl())?;
    let root = open_relative(parent, root_name, true).map_err(|_| {
        integrity("provisioned machine-store root is missing or cannot be opened safely")
    })?;
    let root_identity = verify_directory(&root, &root_sd)?;
    let mut marker = open_relative(&root, OsStr::new(MARKER_NAME), false)
        .map_err(|_| integrity("machine-store provision marker is missing"))?;
    verify_plain_file(&marker, &root_sd)?;
    let mut bytes = Vec::new();
    marker
        .read_to_end(&mut bytes)
        .map_err(|error| map_io("read machine-store provision marker", error))?;
    let recorded = parse_marker(&bytes)?;
    if recorded.root != root_identity {
        return Err(integrity(
            "machine-store root identity differs from provision marker",
        ));
    }
    let scratch = open_relative(&root, OsStr::new(SCRATCH_NAME), true)
        .map_err(|_| integrity("machine-store scratch directory is missing"))?;
    let cas = open_relative(&root, OsStr::new(CAS_NAME), true)
        .map_err(|_| integrity("machine-store CAS directory is missing"))?;
    if verify_directory(&scratch, &child_sd)? != recorded.scratch {
        return Err(integrity(
            "machine-store scratch identity differs from provision marker",
        ));
    }
    if verify_directory(&cas, &child_sd)? != recorded.cas {
        return Err(integrity(
            "machine-store CAS identity differs from provision marker",
        ));
    }
    Ok(ValidatedProvision { root, marker })
}

fn commit_at_handle(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<(), MachineStoreError> {
    let validated = reopen_validated_provision(parent, root_name, policy)?;
    delete_held_handle(&validated.marker)?;
    drop(validated.marker);
    if open_relative_optional(&validated.root, OsStr::new(MARKER_NAME), false)?.is_some() {
        return Err(integrity("machine-store marker remained after commit"));
    }
    Ok(())
}

fn rollback_at_handle(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<(), MachineStoreError> {
    let ValidatedProvision { root, marker } =
        reopen_validated_provision(parent, root_name, policy)?;
    drop(marker);
    remove_tree_bound(parent, root_name, root, policy.root_sddl())
}

fn uninstall_at_handle(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<(), MachineStoreError> {
    let root_sd = SecurityDescriptor::from_sddl(policy.root_sddl())?;
    let child_sd = SecurityDescriptor::from_sddl(policy.child_sddl())?;
    let root = open_relative(parent, root_name, true)
        .map_err(|_| integrity("committed machine-store root is missing or unsafe"))?;
    verify_directory(&root, &root_sd)?;
    if open_relative_optional(&root, OsStr::new(MARKER_NAME), false)?.is_some() {
        return Err(integrity(
            "refusing to uninstall an uncommitted machine store",
        ));
    }
    let scratch = open_relative(&root, OsStr::new(SCRATCH_NAME), true)
        .map_err(|_| integrity("committed machine-store scratch directory is missing"))?;
    let cas = open_relative(&root, OsStr::new(CAS_NAME), true)
        .map_err(|_| integrity("committed machine-store CAS directory is missing"))?;
    verify_directory(&scratch, &child_sd)?;
    verify_directory(&cas, &child_sd)?;
    drop(scratch);
    drop(cas);
    remove_tree_bound(parent, root_name, root, policy.root_sddl())
}

fn remove_tree_bound(
    parent: &File,
    root_name: &OsStr,
    root: File,
    expected_sddl: &str,
) -> Result<(), MachineStoreError> {
    let expected = inspect_handle(&root)?.identity;
    let descriptor = SecurityDescriptor::from_sddl(expected_sddl)?;
    verify_directory(&root, &descriptor)?;
    remove_directory_contents(&root)?;
    verify_directory(&root, &descriptor)?;
    // The original root handle excludes FILE_SHARE_DELETE. Windows therefore
    // prevents rename/replacement for its lifetime; reopening with DELETE here
    // would conflict with that deliberate share mode.
    delete_held_handle(&root)?;
    drop(root);
    run_after_root_drop_hook(expected);
    verify_removed_or_replaced(parent, root_name, expected)
}

#[cfg(test)]
fn run_after_root_drop_hook(identity: FileIdentity) {
    let hook = {
        let mut hooks = AFTER_ROOT_DROP_HOOKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hooks
            .iter()
            .position(|(expected, _)| *expected == identity)
            .map(|index| hooks.swap_remove(index).1)
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_after_root_drop_hook(_identity: FileIdentity) {}

fn verify_removed_or_replaced(
    parent: &File,
    name: &OsStr,
    removed: FileIdentity,
) -> Result<(), MachineStoreError> {
    match open_relative_any(parent, name) {
        Err(error) if is_not_found(&error) => Ok(()),
        Err(_) => Err(integrity(
            "machine-store namespace absence cannot be proven after deletion",
        )),
        Ok(file) => {
            let actual = inspect_handle(&file)?.identity;
            if actual == removed {
                Err(integrity(
                    "machine-store namespace remained after disposition",
                ))
            } else {
                Err(integrity(
                    "machine-store namespace was replaced during deletion",
                ))
            }
        }
    }
}

fn delete_held_handle(file: &File) -> Result<(), MachineStoreError> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: file is a live DELETE-capable no-follow handle and the immutable
    // disposition buffer is correctly sized for this synchronous call.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        return Err(io_error("delete identity-bound machine-store entry"));
    }
    Ok(())
}

#[derive(Debug)]
struct EnumeratedChild {
    name: OsString,
    identity: FileIdentity,
    attributes: u32,
}

fn enumerate_children(dir: &File) -> Result<Vec<EnumeratedChild>, MachineStoreError> {
    let volume = inspect_handle(dir)?.identity.volume;
    let mut result = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0u64; 8192];
        let class = if restart {
            FileIdExtdDirectoryRestartInfo
        } else {
            FileIdExtdDirectoryInfo
        };
        restart = false;
        // SAFETY: the live directory handle and aligned writable buffer remain
        // valid for the synchronous variable-record query.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.as_raw_handle().cast(),
                class,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * std::mem::size_of::<u64>()) as u32,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(map_io("enumerate machine-store directory", error));
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<u8>(),
                buffer.len() * std::mem::size_of::<u64>(),
            )
        };
        result.extend(parse_directory_records(bytes, volume)?);
    }
    Ok(result)
}

fn parse_directory_records(
    buffer: &[u8],
    volume: u64,
) -> Result<Vec<EnumeratedChild>, MachineStoreError> {
    let header = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
    let mut entries = Vec::new();
    let mut offset = 0usize;
    loop {
        let header_end = offset
            .checked_add(header)
            .filter(|end| *end <= buffer.len())
            .ok_or_else(|| integrity("malformed machine-store directory enumeration"))?;
        let read_u32 = |field_offset: usize| -> Result<u32, MachineStoreError> {
            let start = offset
                .checked_add(field_offset)
                .ok_or_else(|| integrity("malformed machine-store directory enumeration"))?;
            let end = start
                .checked_add(4)
                .filter(|end| *end <= header_end)
                .ok_or_else(|| integrity("malformed machine-store directory enumeration"))?;
            Ok(u32::from_ne_bytes(buffer[start..end].try_into().unwrap()))
        };
        let next = read_u32(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, NextEntryOffset))? as usize;
        let attributes = read_u32(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileAttributes))?;
        let name_len =
            read_u32(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileNameLength))? as usize;
        if !name_len.is_multiple_of(2) {
            return Err(integrity("malformed machine-store directory enumeration"));
        }
        let id_start = offset + std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileId);
        let id_end = id_start
            .checked_add(16)
            .filter(|end| *end <= header_end)
            .ok_or_else(|| integrity("malformed machine-store directory enumeration"))?;
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&buffer[id_start..id_end]);
        let name_end = header_end
            .checked_add(name_len)
            .filter(|end| *end <= buffer.len())
            .ok_or_else(|| integrity("malformed machine-store directory enumeration"))?;
        let wide = buffer[header_end..name_end]
            .chunks_exact(2)
            .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
            .collect::<Vec<_>>();
        let name = OsString::from_wide(&wide);
        if name != OsStr::new(".") && name != OsStr::new("..") {
            entries.push(EnumeratedChild {
                name,
                identity: FileIdentity { volume, file_id },
                attributes,
            });
        }
        if next == 0 {
            break;
        }
        let span = header
            .checked_add(name_len)
            .ok_or_else(|| integrity("malformed machine-store directory enumeration"))?;
        if !next.is_multiple_of(8)
            || next < span
            || offset
                .checked_add(next)
                .and_then(|next_offset| next_offset.checked_add(header))
                .is_none_or(|end| end > buffer.len())
        {
            return Err(integrity("malformed machine-store directory enumeration"));
        }
        offset += next;
    }
    Ok(entries)
}

fn remove_directory_contents(dir: &File) -> Result<(), MachineStoreError> {
    for entry in enumerate_children(dir)? {
        let is_directory = entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let child = open_relative(dir, &entry.name, is_directory)?;
        let actual = inspect_handle(&child)?;
        if actual.identity != entry.identity
            || actual.is_directory != is_directory
            || actual.is_reparse != (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        {
            return Err(integrity("machine-store child changed after enumeration"));
        }
        if actual.is_directory && !actual.is_reparse {
            remove_directory_contents(&child)?;
        }
        delete_held_handle(&child)?;
        drop(child);
        match open_relative_optional(dir, &entry.name, is_directory)? {
            None => {}
            Some(replacement) => {
                if inspect_handle(&replacement)?.identity == entry.identity {
                    return Err(integrity("machine-store child remained after disposition"));
                }
                return Err(integrity(
                    "machine-store child was replaced during deletion",
                ));
            }
        }
    }
    Ok(())
}

fn inspect_handle(file: &File) -> Result<PathInspection, MachineStoreError> {
    let mut identity = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    let mut tag = std::mem::MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::uninit();
    // SAFETY: file is live and both output structures are correctly sized and
    // observed only after successful initialization.
    let identity_ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            identity.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if identity_ok == 0 {
        return Err(io_error("read machine-store file identity"));
    }
    // SAFETY: same contract as the identity query above.
    let tag_ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileAttributeTagInfo,
            tag.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if tag_ok == 0 {
        return Err(io_error("read machine-store file attributes"));
    }
    // SAFETY: both APIs returned success.
    let identity = unsafe { identity.assume_init() };
    let tag = unsafe { tag.assume_init() };
    Ok(PathInspection {
        identity: FileIdentity {
            volume: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        is_directory: tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        is_reparse: tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    })
}

fn verify_directory(
    file: &File,
    expected_security: &SecurityDescriptor,
) -> Result<FileIdentity, MachineStoreError> {
    let inspection = inspect_handle(file)?;
    if !inspection.is_directory || inspection.is_reparse {
        return Err(integrity(
            "machine-store directory type or reparse state is unsafe",
        ));
    }
    verify_security(file, expected_security)?;
    Ok(inspection.identity)
}

fn verify_plain_file(
    file: &File,
    expected_security: &SecurityDescriptor,
) -> Result<FileIdentity, MachineStoreError> {
    let inspection = inspect_handle(file)?;
    if inspection.is_directory || inspection.is_reparse {
        return Err(integrity(
            "machine-store marker type or reparse state is unsafe",
        ));
    }
    verify_security(file, expected_security)?;
    Ok(inspection.identity)
}

fn verify_security(file: &File, expected: &SecurityDescriptor) -> Result<(), MachineStoreError> {
    if security_equal(file, expected)? {
        Ok(())
    } else {
        Err(integrity("machine-store security descriptor is not exact"))
    }
}

fn security_equal(file: &File, expected: &SecurityDescriptor) -> Result<bool, MachineStoreError> {
    let mut actual_owner: PSID = std::ptr::null_mut();
    let mut actual_dacl = std::ptr::null_mut();
    let mut actual_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: file is a live READ_CONTROL handle and all output pointers remain
    // valid. The returned descriptor owns the embedded owner/DACL pointers.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            std::ptr::null_mut(),
            &mut actual_dacl,
            std::ptr::null_mut(),
            &mut actual_sd,
        )
    };
    if status != 0 {
        return Err(map_io(
            "read machine-store security descriptor",
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    let actual_guard = LocalSecurityDescriptor(actual_sd);
    let mut expected_owner: PSID = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut expected_dacl = std::ptr::null_mut();
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut actual_control = 0u16;
    let mut expected_control = 0u16;
    let mut revision = 0u32;
    // SAFETY: both descriptors are live, and all output pointers are valid.
    let metadata_ok = unsafe {
        GetSecurityDescriptorOwner(expected.as_ptr(), &mut expected_owner, &mut owner_defaulted)
            != 0
            && GetSecurityDescriptorDacl(
                expected.as_ptr(),
                &mut dacl_present,
                &mut expected_dacl,
                &mut dacl_defaulted,
            ) != 0
            && GetSecurityDescriptorControl(actual_guard.0, &mut actual_control, &mut revision) != 0
            && GetSecurityDescriptorControl(expected.as_ptr(), &mut expected_control, &mut revision)
                != 0
    };
    if !metadata_ok
        || actual_owner.is_null()
        || expected_owner.is_null()
        || actual_dacl.is_null()
        || expected_dacl.is_null()
    {
        return Err(io_error("parse machine-store security descriptor"));
    }
    // SAFETY: owner SIDs are validated by their source descriptors.
    let owner_equal = unsafe { EqualSid(actual_owner, expected_owner) != 0 };
    let protected =
        actual_control & SE_DACL_PROTECTED != 0 && expected_control & SE_DACL_PROTECTED != 0;
    // SAFETY: non-null DACL pointers refer to ACL headers inside live security
    // descriptors; AclSize bounds each byte comparison.
    let dacl_equal = unsafe {
        let actual_size = (*actual_dacl).AclSize as usize;
        let expected_size = (*expected_dacl).AclSize as usize;
        actual_size == expected_size
            && std::slice::from_raw_parts(actual_dacl.cast::<u8>(), actual_size)
                == std::slice::from_raw_parts(expected_dacl.cast::<u8>(), expected_size)
    };
    Ok(owner_equal && protected && dacl_present != 0 && dacl_equal)
}

fn encode_marker(marker: Marker) -> [u8; MARKER_BYTES] {
    let mut bytes = [0u8; MARKER_BYTES];
    bytes[..MARKER_MAGIC.len()].copy_from_slice(MARKER_MAGIC);
    let mut offset = MARKER_MAGIC.len();
    bytes[offset..offset + 4].copy_from_slice(&MARKER_VERSION.to_le_bytes());
    offset += 4;
    for identity in [marker.root, marker.scratch, marker.cas] {
        bytes[offset..offset + 8].copy_from_slice(&identity.volume.to_le_bytes());
        bytes[offset + 8..offset + IDENTITY_BYTES].copy_from_slice(&identity.file_id);
        offset += IDENTITY_BYTES;
    }
    bytes
}

fn parse_marker(bytes: &[u8]) -> Result<Marker, MachineStoreError> {
    if bytes.len() != MARKER_BYTES || &bytes[..MARKER_MAGIC.len()] != MARKER_MAGIC {
        return Err(integrity("machine-store provision marker is malformed"));
    }
    let mut offset = MARKER_MAGIC.len();
    let version = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    if version != MARKER_VERSION {
        return Err(integrity(
            "machine-store provision marker version is unsupported",
        ));
    }
    offset += 4;
    let mut read_identity = || {
        let volume = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&bytes[offset + 8..offset + IDENTITY_BYTES]);
        offset += IDENTITY_BYTES;
        FileIdentity { volume, file_id }
    };
    Ok(Marker {
        root: read_identity(),
        scratch: read_identity(),
        cas: read_identity(),
    })
}

fn integrity(context: &'static str) -> MachineStoreError {
    MachineStoreError::new(MachineStoreErrorClass::IntegrityViolation, context)
}

fn io_error(context: &'static str) -> MachineStoreError {
    map_io(context, io::Error::last_os_error())
}

fn map_io(context: &'static str, source: io::Error) -> MachineStoreError {
    MachineStoreError::with_io(MachineStoreErrorClass::Io, context, source)
}

#[cfg(test)]
pub(crate) fn current_user_test_policy() -> Result<TestSecurityPolicy, MachineStoreError> {
    let mut token = std::ptr::null_mut();
    // SAFETY: output pointer is valid; successful token handle is transferred
    // to OwnedHandle immediately.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io_error("open current process token"));
    }
    // SAFETY: OpenProcessToken returned one owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut required = 0u32;
    // SAFETY: null buffer/zero length is the documented size query.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(io_error("measure current token user"));
    }
    let mut buffer = vec![0u8; required as usize];
    // SAFETY: the buffer has the queried size and all pointers remain live.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    if ok == 0 {
        return Err(io_error("read current token user"));
    }
    // SAFETY: successful TokenUser query initialized TOKEN_USER at the buffer start.
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: token buffer and SID remain live; output is LocalAlloc-owned.
    let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_string) };
    if ok == 0 {
        return Err(io_error("convert current token SID"));
    }
    let mut length = 0usize;
    // SAFETY: successful conversion returned NUL-terminated UTF-16.
    unsafe {
        while *sid_string.add(length) != 0 {
            length += 1;
        }
    }
    let sid = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, length)) };
    // SAFETY: documented LocalFree allocator pair.
    unsafe {
        LocalFree(sid_string.cast());
    }
    let sddl = format!("O:{sid}G:{sid}D:P(A;OICI;FA;;;{sid})");
    Ok(TestSecurityPolicy(SecurityPolicy {
        root: sddl.clone(),
        child: sddl,
    }))
}

#[cfg(test)]
pub(crate) fn provision_at_for_test(
    parent: &Path,
    root_name: &OsStr,
    policy: &TestSecurityPolicy,
) -> Result<(), MachineStoreError> {
    let parent = open_directory_path_nofollow(parent)?;
    provision_at_handle(&parent, root_name, &policy.0)
}

#[cfg(test)]
pub(crate) fn rollback_at_for_test(
    parent: &Path,
    root_name: &OsStr,
    policy: &TestSecurityPolicy,
) -> Result<(), MachineStoreError> {
    let parent = open_directory_path_nofollow(parent)?;
    rollback_at_handle(&parent, root_name, &policy.0)
}

#[cfg(test)]
pub(crate) fn commit_at_for_test(
    parent: &Path,
    root_name: &OsStr,
    policy: &TestSecurityPolicy,
) -> Result<(), MachineStoreError> {
    let parent = open_directory_path_nofollow(parent)?;
    commit_at_handle(&parent, root_name, &policy.0)
}

#[cfg(test)]
pub(crate) fn uninstall_at_for_test(
    parent: &Path,
    root_name: &OsStr,
    policy: &TestSecurityPolicy,
) -> Result<(), MachineStoreError> {
    let parent = open_directory_path_nofollow(parent)?;
    uninstall_at_handle(&parent, root_name, &policy.0)
}

#[cfg(test)]
pub(crate) fn inspect_path_nofollow_for_test(
    path: &Path,
) -> Result<PathInspection, MachineStoreError> {
    let mut options = OpenOptions::new();
    options
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|error| map_io("inspect test path without following", error))?;
    inspect_handle(&file)
}

#[cfg(test)]
pub(crate) fn security_matches_for_test(
    path: &Path,
    sddl: &str,
) -> Result<bool, MachineStoreError> {
    let mut options = OpenOptions::new();
    options
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|error| map_io("open test security target", error))?;
    let expected = SecurityDescriptor::from_sddl(sddl)?;
    security_equal(&file, &expected)
}

#[cfg(test)]
pub(crate) fn create_secure_test_directory(
    parent: &Path,
    name: &OsStr,
    sddl: &str,
) -> Result<(), MachineStoreError> {
    let parent = open_directory_path_nofollow(parent)?;
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    create_relative_directory(&parent, name, &descriptor)
        .map(drop)
        .map_err(create_failure_to_error)
}

#[cfg(test)]
pub(crate) fn parse_marker_for_test(bytes: &[u8]) -> Result<(), MachineStoreError> {
    parse_marker(bytes).map(drop)
}

#[cfg(test)]
pub(crate) fn install_after_root_drop_hook_for_test(
    root: &Path,
    hook: impl FnOnce() + Send + 'static,
) -> Result<(), MachineStoreError> {
    let identity = inspect_path_nofollow_for_test(root)?.identity;
    AFTER_ROOT_DROP_HOOKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push((identity, Box::new(hook)));
    Ok(())
}
