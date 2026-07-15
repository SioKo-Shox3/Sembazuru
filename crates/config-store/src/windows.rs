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
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NtCreateFile,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, HANDLE, LocalFree, RtlNtStatusToDosError, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_EXISTS, UNICODE_STRING,
};
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
#[cfg(test)]
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FILE_TRAVERSE, FILE_WRITE_DATA, FileAttributeTagInfo,
    FileDispositionInfoEx, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, FileIdInfo,
    FileStandardInfo, GetFileInformationByHandleEx, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;
#[cfg(test)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

use crate::{MachineConfigTarget, MachineStoreError, MachineStoreErrorClass};

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
const CONFIG_SDDL: &str = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;S-1-5-80-934400648-3059976913-1740392721-646658299-1483742795)";
const TEMP_CREATE_ATTEMPTS: usize = 8;

#[derive(Clone)]
struct SecurityPolicy {
    root: String,
    child: String,
    config: String,
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
            config: CONFIG_SDDL.to_owned(),
        }
    }

    pub(crate) fn root_sddl(&self) -> &str {
        &self.root
    }

    pub(crate) fn child_sddl(&self) -> &str {
        &self.child
    }

    pub(crate) fn config_sddl(&self) -> &str {
        &self.config
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
    pub(crate) link_count: u32,
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

pub(super) fn replace_config_canonical(
    target: MachineConfigTarget,
    contents: &[u8],
) -> Result<(), MachineStoreError> {
    let program_data = program_data_path()?;
    let parent = open_config_parent_path_nofollow(&program_data)?;
    let policy = SecurityPolicy::production();
    let root = reopen_validated_committed(&parent, OsStr::new(ROOT_NAME), &policy)?;
    replace_config_at_handle(&root, target, contents, &policy)
}

pub(super) fn seed_config_canonical(
    target: MachineConfigTarget,
    contents: &[u8],
) -> Result<bool, MachineStoreError> {
    let program_data = program_data_path()?;
    let parent = open_config_parent_path_nofollow(&program_data)?;
    let policy = SecurityPolicy::production();
    let root = reopen_validated_provision_for_config(&parent, OsStr::new(ROOT_NAME), &policy)?;
    seed_config_at_handle(&root, target, contents, &policy)
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

fn open_config_parent_path_nofollow(path: &Path) -> Result<File, MachineStoreError> {
    let mut options = OpenOptions::new();
    options
        .access_mode(
            READ_CONTROL | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
        )
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|error| map_io("open machine-config parent without following", error))?;
    let inspection = inspect_handle(&file)?;
    if !inspection.is_directory || inspection.is_reparse {
        return Err(integrity("machine-config parent is not a plain directory"));
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

fn open_config_relative(
    parent: &File,
    name: &OsStr,
    is_directory: bool,
) -> Result<File, MachineStoreError> {
    let access = if is_directory {
        READ_CONTROL | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE
    } else {
        READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
    };
    match nt_relative(parent, name, FILE_OPEN, Some(is_directory), access, None) {
        Ok(file) => Ok(file),
        Err(CreateFailure::Collision) => unreachable!("FILE_OPEN cannot report create collision"),
        Err(CreateFailure::Error(error)) => Err(error),
    }
}

fn open_config_relative_optional(
    parent: &File,
    name: &OsStr,
    is_directory: bool,
) -> Result<Option<File>, MachineStoreError> {
    match open_config_relative(parent, name, is_directory) {
        Ok(file) => Ok(Some(file)),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
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

fn reopen_validated_committed(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<File, MachineStoreError> {
    let root_sd = SecurityDescriptor::from_sddl(policy.root_sddl())?;
    let child_sd = SecurityDescriptor::from_sddl(policy.child_sddl())?;
    let root = open_config_relative(parent, root_name, true)
        .map_err(|_| integrity("committed machine-store root is missing or unsafe"))?;
    verify_directory(&root, &root_sd)?;
    if open_config_relative_optional(&root, OsStr::new(MARKER_NAME), false)?.is_some() {
        return Err(integrity(
            "refusing configuration replacement in an uncommitted machine store",
        ));
    }
    let scratch = open_config_relative(&root, OsStr::new(SCRATCH_NAME), true)
        .map_err(|_| integrity("committed machine-store scratch directory is missing"))?;
    let cas = open_config_relative(&root, OsStr::new(CAS_NAME), true)
        .map_err(|_| integrity("committed machine-store CAS directory is missing"))?;
    verify_directory(&scratch, &child_sd)?;
    verify_directory(&cas, &child_sd)?;
    Ok(root)
}

fn reopen_validated_provision_for_config(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<File, MachineStoreError> {
    let root_sd = SecurityDescriptor::from_sddl(policy.root_sddl())?;
    let child_sd = SecurityDescriptor::from_sddl(policy.child_sddl())?;
    let root = open_config_relative(parent, root_name, true).map_err(|_| {
        integrity("provisioned machine-store root is missing or cannot be opened safely")
    })?;
    let root_identity = verify_directory(&root, &root_sd)?;
    let mut marker = open_config_relative(&root, OsStr::new(MARKER_NAME), false)
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
    let scratch = open_config_relative(&root, OsStr::new(SCRATCH_NAME), true)
        .map_err(|_| integrity("machine-store scratch directory is missing"))?;
    let cas = open_config_relative(&root, OsStr::new(CAS_NAME), true)
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
    Ok(root)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigWriteMode {
    Replace,
    Seed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigWriteFault {
    None,
    #[cfg(test)]
    PartialWrite,
    #[cfg(test)]
    AfterSync,
    #[cfg(test)]
    Rename,
}

fn replace_config_at_handle(
    root: &File,
    target: MachineConfigTarget,
    contents: &[u8],
    policy: &SecurityPolicy,
) -> Result<(), MachineStoreError> {
    let mut nonce = random_nonce;
    write_config_at_handle(
        root,
        target,
        contents,
        policy,
        ConfigWriteMode::Replace,
        &mut nonce,
        ConfigWriteFault::None,
    )
    .map(drop)
}

fn seed_config_at_handle(
    root: &File,
    target: MachineConfigTarget,
    contents: &[u8],
    policy: &SecurityPolicy,
) -> Result<bool, MachineStoreError> {
    let mut nonce = random_nonce;
    write_config_at_handle(
        root,
        target,
        contents,
        policy,
        ConfigWriteMode::Seed,
        &mut nonce,
        ConfigWriteFault::None,
    )
    .map(|(created, _)| created)
}

fn write_config_at_handle(
    root: &File,
    target: MachineConfigTarget,
    contents: &[u8],
    policy: &SecurityPolicy,
    mode: ConfigWriteMode,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
    fault: ConfigWriteFault,
) -> Result<(bool, Option<FileIdentity>), MachineStoreError> {
    #[cfg(not(test))]
    let _ = fault;
    let final_name = config_leaf(target);
    let config_sd = SecurityDescriptor::from_sddl(policy.config_sddl())?;
    if let Some(existing) = open_config_optional(root, OsStr::new(final_name))? {
        verify_config_file(&existing, &config_sd)?;
        if mode == ConfigWriteMode::Seed {
            return Ok((false, None));
        }
    }

    let (temp_name, mut temp, temp_identity) =
        create_unique_config_temp(root, target, &config_sd, next_nonce)?;
    let result = (|| {
        #[cfg(test)]
        if fault == ConfigWriteFault::PartialWrite {
            let partial = contents.len().div_ceil(2);
            temp.write_all(&contents[..partial])
                .map_err(|error| map_io("write partial machine configuration", error))?;
            return Err(integrity("injected partial machine configuration write"));
        }
        temp.write_all(contents)
            .map_err(|error| map_io("write machine configuration", error))?;
        temp.sync_all()
            .map_err(|error| map_io("flush machine configuration", error))?;
        #[cfg(test)]
        if fault == ConfigWriteFault::AfterSync {
            return Err(integrity(
                "injected post-flush machine configuration failure",
            ));
        }
        if verify_config_file(&temp, &config_sd)? != temp_identity {
            return Err(integrity(
                "machine configuration temp identity changed before rename",
            ));
        }
        #[cfg(test)]
        if fault == ConfigWriteFault::Rename {
            return Err(integrity("injected machine configuration rename failure"));
        }
        rename_config_handle(
            &temp,
            root,
            OsStr::new(final_name),
            mode == ConfigWriteMode::Replace,
        )
    })();

    match result {
        Ok(RenameResult::Renamed) => {
            drop(temp);
            let final_file = open_config_optional(root, OsStr::new(final_name))?
                .ok_or_else(|| integrity("machine configuration vanished after rename"))?;
            if verify_config_file(&final_file, &config_sd)? != temp_identity {
                return Err(integrity(
                    "machine configuration identity changed after rename",
                ));
            }
            Ok((true, Some(temp_identity)))
        }
        Ok(RenameResult::Collision) if mode == ConfigWriteMode::Seed => {
            remove_temp_or_combine(root, &temp_name, temp, temp_identity, None)?;
            let winner = open_config_optional(root, OsStr::new(final_name))?
                .ok_or_else(|| integrity("seed collision did not leave a configuration"))?;
            verify_config_file(&winner, &config_sd)?;
            Ok((false, None))
        }
        Ok(RenameResult::Collision) => {
            let primary = integrity("replacement rename unexpectedly collided");
            remove_temp_or_combine(root, &temp_name, temp, temp_identity, Some(primary))?;
            unreachable!("cleanup with a primary error always returns Err")
        }
        Err(primary) => {
            remove_temp_or_combine(root, &temp_name, temp, temp_identity, Some(primary))?;
            unreachable!("cleanup with a primary error always returns Err")
        }
    }
}

fn config_leaf(target: MachineConfigTarget) -> &'static str {
    match target {
        MachineConfigTarget::Daemon => "daemon.toml",
        MachineConfigTarget::Worker => "worker.toml",
    }
}

fn random_nonce() -> Result<[u8; 16], MachineStoreError> {
    let mut nonce = [0u8; 16];
    // SAFETY: the writable fixed-size buffer is live for the synchronous call;
    // a null algorithm handle is required with the system-preferred RNG flag.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(nt_status_error(
            "generate machine configuration temp nonce",
            status,
        ));
    }
    Ok(nonce)
}

fn config_temp_name(target: MachineConfigTarget, nonce: [u8; 16]) -> OsString {
    let mut hex = String::with_capacity(32);
    for byte in nonce {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    OsString::from(format!(".{}.{hex}.tmp", config_leaf(target)))
}

fn create_unique_config_temp(
    root: &File,
    target: MachineConfigTarget,
    descriptor: &SecurityDescriptor,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
) -> Result<(OsString, File, FileIdentity), MachineStoreError> {
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let name = config_temp_name(target, next_nonce()?);
        match nt_relative(
            root,
            &name,
            FILE_CREATE,
            Some(false),
            DELETE
                | READ_CONTROL
                | FILE_READ_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_DATA
                | SYNCHRONIZE,
            Some(descriptor),
        ) {
            Ok(file) => {
                let identity = match inspect_handle(&file) {
                    Ok(inspection) => inspection.identity,
                    Err(primary) => {
                        return cleanup_unidentified_temp(root, &name, file, primary);
                    }
                };
                if let Err(primary) = verify_config_file(&file, descriptor) {
                    remove_temp_or_combine(root, &name, file, identity, Some(primary))?;
                    unreachable!("cleanup with a primary error always returns Err");
                }
                return Ok((name, file, identity));
            }
            Err(CreateFailure::Collision) => continue,
            Err(CreateFailure::Error(error)) => return Err(error),
        }
    }
    Err(integrity(
        "machine configuration temp namespace collision limit reached",
    ))
}

fn cleanup_unidentified_temp<T>(
    root: &File,
    name: &OsStr,
    temp: File,
    primary: MachineStoreError,
) -> Result<T, MachineStoreError> {
    let deleted = delete_held_handle(&temp);
    drop(temp);
    let absent = matches!(
        open_relative_any(root, name),
        Err(error) if is_not_found(&error)
    );
    Err(MachineStoreError::with_io(
        MachineStoreErrorClass::IntegrityViolation,
        "machine configuration temp identity could not be read",
        io::Error::other(format!(
            "primary: {primary}; disposition: {}; absence proven: {absent}",
            deleted
                .as_ref()
                .map(|()| "ok".to_owned())
                .unwrap_or_else(|error| error.to_string())
        )),
    ))
}

fn open_config_optional(root: &File, name: &OsStr) -> Result<Option<File>, MachineStoreError> {
    match nt_relative(
        root,
        name,
        FILE_OPEN,
        None,
        READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        None,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(CreateFailure::Collision) => unreachable!("FILE_OPEN cannot report create collision"),
        Err(CreateFailure::Error(error)) if is_not_found(&error) => Ok(None),
        Err(CreateFailure::Error(_)) => Err(integrity(
            "machine configuration cannot be opened safely without following",
        )),
    }
}

fn verify_config_file(
    file: &File,
    expected_security: &SecurityDescriptor,
) -> Result<FileIdentity, MachineStoreError> {
    let inspection = inspect_handle(file)?;
    if inspection.is_directory || inspection.is_reparse || inspection.link_count != 1 {
        return Err(integrity(
            "machine configuration type, reparse state, or link count is unsafe",
        ));
    }
    verify_security(file, expected_security)?;
    Ok(inspection.identity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenameResult {
    Renamed,
    Collision,
}

fn rename_config_handle(
    temp: &File,
    root: &File,
    final_name: &OsStr,
    replace: bool,
) -> Result<RenameResult, MachineStoreError> {
    let wide = final_name.encode_wide().collect::<Vec<_>>();
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| integrity("machine configuration final name is too long"))?;
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let buffer_len = header
        .checked_add(name_bytes as usize)
        .ok_or_else(|| integrity("machine configuration rename buffer overflow"))?;
    let mut storage = vec![0u64; buffer_len.div_ceil(std::mem::size_of::<u64>())];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: the u64-backed storage satisfies structure alignment and is at
    // least header + exact UTF-16 payload bytes. Every written field fits.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = u8::from(replace);
        (*information).RootDirectory = root.as_raw_handle().cast();
        (*information).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
            wide.len(),
        );
    }
    let mut io_status = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    // SAFETY: both handles, the aligned variable-length buffer, and output
    // status remain live for this synchronous native rename operation.
    let status = unsafe {
        NtSetInformationFile(
            temp.as_raw_handle().cast(),
            io_status.as_mut_ptr(),
            information.cast(),
            buffer_len as u32,
            FileRenameInformation,
        )
    };
    if status == STATUS_OBJECT_NAME_COLLISION || status == STATUS_OBJECT_NAME_EXISTS {
        return Ok(RenameResult::Collision);
    }
    if status < 0 {
        return Err(nt_status_error(
            "rename machine configuration by held identity",
            status,
        ));
    }
    Ok(RenameResult::Renamed)
}

fn remove_temp_or_combine(
    root: &File,
    name: &OsStr,
    temp: File,
    identity: FileIdentity,
    primary: Option<MachineStoreError>,
) -> Result<(), MachineStoreError> {
    let cleanup = (|| {
        if inspect_handle(&temp)?.identity != identity {
            return Err(integrity(
                "machine configuration temp identity changed before cleanup",
            ));
        }
        delete_held_handle(&temp)?;
        drop(temp);
        match open_relative_any(root, name) {
            Err(error) if is_not_found(&error) => Ok(()),
            Err(_) => Err(integrity(
                "machine configuration temp absence cannot be proven",
            )),
            Ok(entry) if inspect_handle(&entry)?.identity == identity => Err(integrity(
                "machine configuration temp remained after cleanup",
            )),
            Ok(_) => Err(integrity(
                "machine configuration temp was replaced during cleanup",
            )),
        }
    })();
    match (primary, cleanup) {
        (None, Ok(())) => Ok(()),
        (Some(primary), Ok(())) => Err(primary),
        (primary, Err(cleanup)) => Err(MachineStoreError::with_io(
            MachineStoreErrorClass::IntegrityViolation,
            "machine configuration operation failed and identity-bound cleanup failed",
            io::Error::other(match primary {
                Some(primary) => format!("primary: {primary}; cleanup: {cleanup}"),
                None => format!("cleanup: {cleanup}"),
            }),
        )),
    }
}

fn nt_status_error(context: &'static str, status: i32) -> MachineStoreError {
    // SAFETY: status came directly from an NT API.
    let code = unsafe { RtlNtStatusToDosError(status) };
    map_io(context, io::Error::from_raw_os_error(code as i32))
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
    let mut standard = std::mem::MaybeUninit::<FILE_STANDARD_INFO>::uninit();
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
    // SAFETY: same contract as the identity query above.
    let standard_ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileStandardInfo,
            standard.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if standard_ok == 0 {
        return Err(io_error("read machine-store file link count"));
    }
    // SAFETY: all three APIs returned success.
    let identity = unsafe { identity.assume_init() };
    let tag = unsafe { tag.assume_init() };
    let standard = unsafe { standard.assume_init() };
    Ok(PathInspection {
        identity: FileIdentity {
            volume: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        is_directory: tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        is_reparse: tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        link_count: standard.NumberOfLinks,
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
    let mut actual_group: PSID = std::ptr::null_mut();
    let mut actual_dacl = std::ptr::null_mut();
    let mut actual_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: file is a live READ_CONTROL handle and all output pointers remain
    // valid. The returned descriptor owns the embedded owner/DACL pointers.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            &mut actual_group,
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
    let mut expected_group: PSID = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut group_defaulted = 0;
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
            && GetSecurityDescriptorGroup(
                expected.as_ptr(),
                &mut expected_group,
                &mut group_defaulted,
            ) != 0
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
        || actual_group.is_null()
        || expected_owner.is_null()
        || expected_group.is_null()
        || actual_dacl.is_null()
        || expected_dacl.is_null()
    {
        return Err(io_error("parse machine-store security descriptor"));
    }
    // SAFETY: owner SIDs are validated by their source descriptors.
    let owner_equal = unsafe { EqualSid(actual_owner, expected_owner) != 0 };
    // SAFETY: group SIDs are validated by their source descriptors.
    let group_equal = unsafe { EqualSid(actual_group, expected_group) != 0 };
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
    Ok(owner_equal && group_equal && protected && dacl_present != 0 && dacl_equal)
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
    let config_sddl = format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})");
    Ok(TestSecurityPolicy(SecurityPolicy {
        root: sddl.clone(),
        child: sddl,
        config: config_sddl,
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

#[cfg(test)]
mod machine_config_tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use tempfile::TempDir;

    struct ConfigFixture {
        _temp: TempDir,
        parent: PathBuf,
        root: PathBuf,
        policy: SecurityPolicy,
    }

    impl ConfigFixture {
        fn provisioned() -> Self {
            let temp = tempfile::tempdir().expect("create machine-config test directory");
            let parent = temp.path().join("parent");
            fs::create_dir(&parent).expect("create machine-config parent");
            let root = parent.join(ROOT_NAME);
            let policy = current_user_test_policy().expect("current-user policy").0;
            let parent_handle = open_directory_path_nofollow(&parent).unwrap();
            provision_at_handle(&parent_handle, OsStr::new(ROOT_NAME), &policy).unwrap();
            Self {
                _temp: temp,
                parent,
                root,
                policy,
            }
        }

        fn committed() -> Self {
            let fixture = Self::provisioned();
            let parent = open_directory_path_nofollow(&fixture.parent).unwrap();
            commit_at_handle(&parent, OsStr::new(ROOT_NAME), &fixture.policy).unwrap();
            fixture
        }

        fn final_path(&self, target: MachineConfigTarget) -> PathBuf {
            self.root.join(config_leaf(target))
        }
    }

    fn nonce(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn run_config_write(
        fixture: &ConfigFixture,
        mode: ConfigWriteMode,
        target: MachineConfigTarget,
        contents: &[u8],
        nonces: &[[u8; 16]],
        fault: ConfigWriteFault,
    ) -> Result<(bool, Option<FileIdentity>), MachineStoreError> {
        let parent = open_config_parent_path_nofollow(&fixture.parent)?;
        let mut queue = VecDeque::from(nonces.to_vec());
        let mut next = || {
            queue
                .pop_front()
                .ok_or_else(|| integrity("test nonce source exhausted"))
        };
        match mode {
            ConfigWriteMode::Replace => {
                let root =
                    reopen_validated_committed(&parent, OsStr::new(ROOT_NAME), &fixture.policy)?;
                write_config_at_handle(
                    &root,
                    target,
                    contents,
                    &fixture.policy,
                    mode,
                    &mut next,
                    fault,
                )
            }
            ConfigWriteMode::Seed => {
                let root = reopen_validated_provision_for_config(
                    &parent,
                    OsStr::new(ROOT_NAME),
                    &fixture.policy,
                )?;
                write_config_at_handle(
                    &root,
                    target,
                    contents,
                    &fixture.policy,
                    mode,
                    &mut next,
                    fault,
                )
            }
        }
    }

    fn temp_entries(fixture: &ConfigFixture) -> Vec<OsString> {
        fs::read_dir(&fixture.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect()
    }

    fn create_junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                link.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "mklink failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn machine_config_replace_absent_and_existing_is_complete_and_exact() {
        let fixture = ConfigFixture::committed();
        let target = MachineConfigTarget::Daemon;

        let (created, temp_identity) = run_config_write(
            &fixture,
            ConfigWriteMode::Replace,
            target,
            b"first=1\n",
            &[nonce(1)],
            ConfigWriteFault::None,
        )
        .unwrap();
        assert!(created);
        let first = inspect_path_nofollow_for_test(&fixture.final_path(target)).unwrap();
        assert_eq!(Some(first.identity), temp_identity);
        assert_eq!(first.link_count, 1);
        assert!(
            security_matches_for_test(&fixture.final_path(target), fixture.policy.config_sddl())
                .unwrap()
        );

        let (created, temp_identity) = run_config_write(
            &fixture,
            ConfigWriteMode::Replace,
            target,
            b"second=2\ncomplete=true\n",
            &[nonce(2)],
            ConfigWriteFault::None,
        )
        .unwrap();
        assert!(created);
        let second = inspect_path_nofollow_for_test(&fixture.final_path(target)).unwrap();
        assert_eq!(Some(second.identity), temp_identity);
        assert_ne!(first.identity, second.identity);
        assert_eq!(
            fs::read(fixture.final_path(target)).unwrap(),
            b"second=2\ncomplete=true\n"
        );
        assert!(temp_entries(&fixture).is_empty());
    }

    #[test]
    fn machine_config_seed_existing_is_false_and_unchanged() {
        let fixture = ConfigFixture::provisioned();
        let target = MachineConfigTarget::Worker;
        assert!(
            run_config_write(
                &fixture,
                ConfigWriteMode::Seed,
                target,
                b"winner",
                &[nonce(3)],
                ConfigWriteFault::None,
            )
            .unwrap()
            .0
        );
        let before = inspect_path_nofollow_for_test(&fixture.final_path(target)).unwrap();

        let result = run_config_write(
            &fixture,
            ConfigWriteMode::Seed,
            target,
            b"loser",
            &[nonce(4)],
            ConfigWriteFault::None,
        )
        .unwrap();

        assert_eq!(result, (false, None));
        assert_eq!(fs::read(fixture.final_path(target)).unwrap(), b"winner");
        assert_eq!(
            inspect_path_nofollow_for_test(&fixture.final_path(target))
                .unwrap()
                .identity,
            before.identity
        );
        assert!(temp_entries(&fixture).is_empty());
    }

    #[test]
    fn machine_config_concurrent_seed_has_exactly_one_winner() {
        let fixture = ConfigFixture::provisioned();
        let parent = Arc::new(fixture.parent.clone());
        let policy = Arc::new(fixture.policy.clone());
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for (value, bytes) in [(11u8, b"alpha".to_vec()), (12u8, b"beta".to_vec())] {
            let parent = Arc::clone(&parent);
            let policy = Arc::clone(&policy);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                let parent = open_config_parent_path_nofollow(&parent).unwrap();
                let root =
                    reopen_validated_provision_for_config(&parent, OsStr::new(ROOT_NAME), &policy)
                        .unwrap();
                let mut once = Some(nonce(value));
                let mut next = || Ok(once.take().unwrap());
                barrier.wait();
                let outcome = write_config_at_handle(
                    &root,
                    MachineConfigTarget::Daemon,
                    &bytes,
                    &policy,
                    ConfigWriteMode::Seed,
                    &mut next,
                    ConfigWriteFault::None,
                )
                .unwrap();
                (outcome.0, bytes)
            }));
        }
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|(created, _)| *created).count(), 1);
        assert_eq!(results.iter().filter(|(created, _)| !*created).count(), 1);
        let expected = &results.iter().find(|(created, _)| *created).unwrap().1;
        assert_eq!(
            fs::read(fixture.final_path(MachineConfigTarget::Daemon)).unwrap(),
            *expected
        );
        assert!(temp_entries(&fixture).is_empty());
    }

    #[test]
    fn machine_config_lifecycle_mismatch_fails_closed() {
        let committed = ConfigFixture::committed();
        let seed_error = run_config_write(
            &committed,
            ConfigWriteMode::Seed,
            MachineConfigTarget::Daemon,
            b"seed",
            &[nonce(20)],
            ConfigWriteFault::None,
        )
        .unwrap_err();
        assert_eq!(
            seed_error.classification(),
            MachineStoreErrorClass::IntegrityViolation
        );

        let provisioned = ConfigFixture::provisioned();
        let replace_error = run_config_write(
            &provisioned,
            ConfigWriteMode::Replace,
            MachineConfigTarget::Daemon,
            b"replace",
            &[nonce(21)],
            ConfigWriteFault::None,
        )
        .unwrap_err();
        assert_eq!(
            replace_error.classification(),
            MachineStoreErrorClass::IntegrityViolation
        );

        let tampered = ConfigFixture::provisioned();
        fs::write(tampered.root.join(MARKER_NAME), b"tampered").unwrap();
        assert_eq!(
            run_config_write(
                &tampered,
                ConfigWriteMode::Seed,
                MachineConfigTarget::Daemon,
                b"seed",
                &[nonce(22)],
                ConfigWriteFault::None,
            )
            .unwrap_err()
            .classification(),
            MachineStoreErrorClass::IntegrityViolation
        );

        let partial = ConfigFixture::provisioned();
        fs::remove_dir(partial.root.join(SCRATCH_NAME)).unwrap();
        assert_eq!(
            run_config_write(
                &partial,
                ConfigWriteMode::Seed,
                MachineConfigTarget::Daemon,
                b"seed",
                &[nonce(23)],
                ConfigWriteFault::None,
            )
            .unwrap_err()
            .classification(),
            MachineStoreErrorClass::IntegrityViolation
        );

        for (index, child) in [SCRATCH_NAME, CAS_NAME].into_iter().enumerate() {
            let missing_child = ConfigFixture::committed();
            fs::remove_dir(missing_child.root.join(child)).unwrap();
            assert_eq!(
                run_config_write(
                    &missing_child,
                    ConfigWriteMode::Replace,
                    MachineConfigTarget::Daemon,
                    b"replace",
                    &[nonce(24 + index as u8)],
                    ConfigWriteFault::None,
                )
                .unwrap_err()
                .classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
        }
    }

    #[test]
    fn machine_config_temp_collisions_are_bounded_and_never_followed() {
        let fixture = ConfigFixture::committed();
        let external = fixture.parent.join("external");
        fs::create_dir(&external).unwrap();
        let sentinel = external.join("sentinel");
        fs::write(&sentinel, b"outside").unwrap();
        let mut nonces = Vec::new();
        for value in 30..(30 + TEMP_CREATE_ATTEMPTS as u8) {
            let current = nonce(value);
            let collision = fixture
                .root
                .join(config_temp_name(MachineConfigTarget::Daemon, current));
            fs::hard_link(&sentinel, &collision).unwrap();
            nonces.push(current);
        }

        let error = run_config_write(
            &fixture,
            ConfigWriteMode::Replace,
            MachineConfigTarget::Daemon,
            b"new",
            &nonces,
            ConfigWriteFault::None,
        )
        .unwrap_err();

        assert_eq!(
            error.classification(),
            MachineStoreErrorClass::IntegrityViolation,
            "{error:?}"
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        assert!(!fixture.final_path(MachineConfigTarget::Daemon).exists());
    }

    #[test]
    fn machine_config_temp_reparse_collision_is_not_followed() {
        let fixture = ConfigFixture::committed();
        let external = fixture.parent.join("external-reparse");
        fs::create_dir(&external).unwrap();
        let sentinel = external.join("sentinel");
        fs::write(&sentinel, b"outside").unwrap();
        let current = nonce(39);
        create_junction(
            &fixture
                .root
                .join(config_temp_name(MachineConfigTarget::Daemon, current)),
            &external,
        );

        assert!(
            run_config_write(
                &fixture,
                ConfigWriteMode::Replace,
                MachineConfigTarget::Daemon,
                b"new",
                &[current],
                ConfigWriteFault::None,
            )
            .is_err()
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        assert!(!fixture.final_path(MachineConfigTarget::Daemon).exists());
    }

    #[test]
    fn machine_config_temp_collision_retry_preserves_external_sentinel() {
        let fixture = ConfigFixture::committed();
        let sentinel = fixture.parent.join("sentinel");
        fs::write(&sentinel, b"outside").unwrap();
        let first = nonce(41);
        let collision = fixture
            .root
            .join(config_temp_name(MachineConfigTarget::Worker, first));
        fs::hard_link(&sentinel, &collision).unwrap();

        let outcome = run_config_write(
            &fixture,
            ConfigWriteMode::Replace,
            MachineConfigTarget::Worker,
            b"inside",
            &[first, nonce(42)],
            ConfigWriteFault::None,
        )
        .unwrap();

        assert!(outcome.0);
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        assert_eq!(
            fs::read(fixture.final_path(MachineConfigTarget::Worker)).unwrap(),
            b"inside"
        );
    }

    #[test]
    fn machine_config_unsafe_final_is_rejected_without_mutating_sentinel() {
        for mode in [ConfigWriteMode::Replace, ConfigWriteMode::Seed] {
            let fixture = if mode == ConfigWriteMode::Replace {
                ConfigFixture::committed()
            } else {
                ConfigFixture::provisioned()
            };
            let sentinel = fixture.parent.join("hardlink-sentinel");
            fs::write(&sentinel, b"hardlink").unwrap();
            fs::hard_link(&sentinel, fixture.final_path(MachineConfigTarget::Daemon)).unwrap();
            let error = run_config_write(
                &fixture,
                mode,
                MachineConfigTarget::Daemon,
                b"mutate",
                &[nonce(50)],
                ConfigWriteFault::None,
            )
            .unwrap_err();
            assert_eq!(
                error.classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
            assert_eq!(fs::read(&sentinel).unwrap(), b"hardlink");
        }

        for mode in [ConfigWriteMode::Replace, ConfigWriteMode::Seed] {
            let fixture = if mode == ConfigWriteMode::Replace {
                ConfigFixture::committed()
            } else {
                ConfigFixture::provisioned()
            };
            let external = fixture.parent.join("junction-target");
            fs::create_dir(&external).unwrap();
            let sentinel = external.join("sentinel");
            fs::write(&sentinel, b"junction").unwrap();
            create_junction(&fixture.final_path(MachineConfigTarget::Worker), &external);
            let error = run_config_write(
                &fixture,
                mode,
                MachineConfigTarget::Worker,
                b"mutate",
                &[nonce(51)],
                ConfigWriteFault::None,
            )
            .unwrap_err();
            assert_eq!(
                error.classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
            assert_eq!(fs::read(&sentinel).unwrap(), b"junction");
        }

        for mode in [ConfigWriteMode::Replace, ConfigWriteMode::Seed] {
            let fixture = if mode == ConfigWriteMode::Replace {
                ConfigFixture::committed()
            } else {
                ConfigFixture::provisioned()
            };
            let final_path = fixture.final_path(MachineConfigTarget::Daemon);
            fs::write(&final_path, b"wrong-security").unwrap();
            let before = inspect_path_nofollow_for_test(&final_path).unwrap();
            let error = run_config_write(
                &fixture,
                mode,
                MachineConfigTarget::Daemon,
                b"mutate",
                &[nonce(52)],
                ConfigWriteFault::None,
            )
            .unwrap_err();
            assert_eq!(
                error.classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
            assert_eq!(fs::read(&final_path).unwrap(), b"wrong-security");
            assert_eq!(inspect_path_nofollow_for_test(&final_path).unwrap(), before);
        }
    }

    #[test]
    fn machine_config_wrong_owner_is_rejected_for_replace_and_seed() {
        for mode in [ConfigWriteMode::Replace, ConfigWriteMode::Seed] {
            let fixture = if mode == ConfigWriteMode::Replace {
                ConfigFixture::committed()
            } else {
                ConfigFixture::provisioned()
            };
            let target = MachineConfigTarget::Worker;
            run_config_write(
                &fixture,
                mode,
                target,
                b"sentinel",
                &[nonce(55)],
                ConfigWriteFault::None,
            )
            .unwrap();
            let before = inspect_path_nofollow_for_test(&fixture.final_path(target)).unwrap();
            let parent = open_config_parent_path_nofollow(&fixture.parent).unwrap();
            let root = if mode == ConfigWriteMode::Replace {
                reopen_validated_committed(&parent, OsStr::new(ROOT_NAME), &fixture.policy).unwrap()
            } else {
                reopen_validated_provision_for_config(
                    &parent,
                    OsStr::new(ROOT_NAME),
                    &fixture.policy,
                )
                .unwrap()
            };
            let mut wrong_owner = fixture.policy.clone();
            wrong_owner.config = "O:SYG:SYD:P(A;;FA;;;SY)".to_owned();
            let mut once = Some(nonce(56));
            let mut next = || Ok(once.take().unwrap());

            let error = write_config_at_handle(
                &root,
                target,
                b"mutate",
                &wrong_owner,
                mode,
                &mut next,
                ConfigWriteFault::None,
            )
            .unwrap_err();

            assert_eq!(
                error.classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
            assert_eq!(fs::read(fixture.final_path(target)).unwrap(), b"sentinel");
            assert_eq!(
                inspect_path_nofollow_for_test(&fixture.final_path(target)).unwrap(),
                before
            );
        }
    }

    #[test]
    fn machine_config_root_mismatch_and_replacement_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let parent_path = temp.path().join("parent");
        fs::create_dir(&parent_path).unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        let sentinel = external.join("sentinel");
        fs::write(&sentinel, b"outside").unwrap();
        create_junction(&parent_path.join(ROOT_NAME), &external);
        let parent = open_directory_path_nofollow(&parent_path).unwrap();
        let policy = current_user_test_policy().unwrap().0;
        assert_eq!(
            reopen_validated_committed(&parent, OsStr::new(ROOT_NAME), &policy)
                .unwrap_err()
                .classification(),
            MachineStoreErrorClass::IntegrityViolation
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");

        let wrong_security = ConfigFixture::committed();
        let parent = open_config_parent_path_nofollow(&wrong_security.parent).unwrap();
        let mut wrong_policy = wrong_security.policy.clone();
        wrong_policy.root = ROOT_SDDL.to_owned();
        assert_eq!(
            reopen_validated_committed(&parent, OsStr::new(ROOT_NAME), &wrong_policy)
                .unwrap_err()
                .classification(),
            MachineStoreErrorClass::IntegrityViolation
        );

        let fixture = ConfigFixture::committed();
        let parent = open_config_parent_path_nofollow(&fixture.parent).unwrap();
        let root =
            reopen_validated_committed(&parent, OsStr::new(ROOT_NAME), &fixture.policy).unwrap();
        let moved = fixture.parent.join("moved-root");
        assert!(fs::rename(&fixture.root, &moved).is_err());
        let mut once = Some(nonce(60));
        let mut next = || Ok(once.take().unwrap());
        assert!(
            write_config_at_handle(
                &root,
                MachineConfigTarget::Daemon,
                b"held-root",
                &fixture.policy,
                ConfigWriteMode::Replace,
                &mut next,
                ConfigWriteFault::None,
            )
            .unwrap()
            .0
        );
    }

    #[test]
    fn machine_config_injected_failures_preserve_old_identity_and_remove_temp() {
        for (index, fault) in [
            ConfigWriteFault::PartialWrite,
            ConfigWriteFault::AfterSync,
            ConfigWriteFault::Rename,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = ConfigFixture::committed();
            let target = MachineConfigTarget::Daemon;
            run_config_write(
                &fixture,
                ConfigWriteMode::Replace,
                target,
                b"old-complete",
                &[nonce(70)],
                ConfigWriteFault::None,
            )
            .unwrap();
            let before = inspect_path_nofollow_for_test(&fixture.final_path(target)).unwrap();

            let error = run_config_write(
                &fixture,
                ConfigWriteMode::Replace,
                target,
                b"new-incomplete",
                &[nonce(71 + index as u8)],
                fault,
            )
            .unwrap_err();

            assert_eq!(
                error.classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
            assert_eq!(
                fs::read(fixture.final_path(target)).unwrap(),
                b"old-complete"
            );
            assert_eq!(
                inspect_path_nofollow_for_test(&fixture.final_path(target))
                    .unwrap()
                    .identity,
                before.identity
            );
            assert!(temp_entries(&fixture).is_empty());
        }
    }

    #[test]
    fn machine_config_existing_no_delete_share_handle_blocks_replace() {
        let fixture = ConfigFixture::committed();
        let target = MachineConfigTarget::Worker;
        run_config_write(
            &fixture,
            ConfigWriteMode::Replace,
            target,
            b"old",
            &[nonce(80)],
            ConfigWriteFault::None,
        )
        .unwrap();
        let final_path = fixture.final_path(target);
        let before = inspect_path_nofollow_for_test(&final_path).unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&final_path)
            .unwrap();

        assert!(
            run_config_write(
                &fixture,
                ConfigWriteMode::Replace,
                target,
                b"new",
                &[nonce(81)],
                ConfigWriteFault::None,
            )
            .is_err()
        );
        assert_eq!(fs::read(&final_path).unwrap(), b"old");
        assert_eq!(inspect_handle(&held).unwrap().identity, before.identity);
        assert!(temp_entries(&fixture).is_empty());
    }

    #[test]
    fn machine_config_nonce_name_uses_all_128_bits_as_hex() {
        let value = [
            0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x80, 0x81, 0x82, 0x83, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        assert_eq!(
            config_temp_name(MachineConfigTarget::Daemon, value),
            OsStr::new(".daemon.toml.000102031011121380818283fcfdfeff.tmp")
        );
    }
}
