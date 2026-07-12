//! The digest-addressed blob store (M4.1).
//!
//! On-disk layout under `<root>/cas/`:
//!
//! ```text
//! <root>/cas/<algo>/<hex[0..2]>/<hex>
//! ```
//!
//! The two-char shard keeps any one directory from collecting every blob (NTFS
//! degrades on huge directories), and the `<algo>` segment keeps two hash
//! algorithms from ever colliding on a same-length hex. Because the path is
//! built only from a validated [`Digest`] (lowercase hex, fixed length), it
//! cannot contain a separator or `..` — that validation *is* the path-traversal
//! defense, so no untrusted string ever reaches the filesystem here.
//!
//! Writes are atomic: bytes go to a uniquely-named temp sibling and are renamed
//! onto the final path, so a reader never sees a half-written blob and a crash
//! mid-write leaves only a stray temp, never a corrupt blob at a valid digest.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::{Digest, DigestError};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

/// Monotonic counter making temp filenames unique within this process; combined
/// with the pid it is unique across processes sharing one store, so concurrent
/// puts of the same blob never collide on their temp files.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
static REPAIR_CRITICAL_SECTION: std::sync::Mutex<()> = std::sync::Mutex::new(());
const LIFECYCLE_LOCK_NAME: &str = ".lifecycle.lock";
const EPHEMERAL_OWNER_MARKER_SUFFIX: &str = ".ephemeral-owner.lock";

/// Errors from store operations.
#[derive(Debug)]
pub enum CasError {
    Io(io::Error),
    /// A `put_verified` was handed bytes whose real digest is not the claimed
    /// one — a corrupted transfer or a forgery attempt. The bytes are rejected,
    /// never stored, so a lie can't poison the address space.
    DigestMismatch {
        claimed: Digest,
        actual: Digest,
    },
    /// A stored blob's bytes no longer hash to the digest it is filed under
    /// (on-disk corruption or tampering), surfaced by `get_verified`.
    Corrupt {
        digest: Digest,
    },
    /// A digest string from disk/wire failed validation.
    Digest(DigestError),
}

impl std::fmt::Display for CasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CasError::Io(e) => write!(f, "cas io: {e}"),
            CasError::DigestMismatch { claimed, actual } => {
                write!(f, "digest mismatch: claimed {claimed}, got {actual}")
            }
            CasError::Corrupt { digest } => write!(f, "stored blob {digest} is corrupt"),
            CasError::Digest(e) => write!(f, "digest: {e}"),
        }
    }
}

impl std::error::Error for CasError {}

impl From<io::Error> for CasError {
    fn from(e: io::Error) -> Self {
        CasError::Io(e)
    }
}

/// A content-addressed blob store rooted at a directory.
///
/// Data-plane handles intentionally have no destructive close authority:
///
/// ```compile_fail
/// # use sembazuru_cas::BlobStore;
/// let store: BlobStore = todo!();
/// store.close();
/// ```
#[derive(Clone)]
pub struct BlobStore {
    #[cfg(test)]
    cas_root: PathBuf,
    shared: Arc<StoreShared>,
}

struct EphemeralStoreOwnerState {
    shared: Arc<StoreShared>,
}

struct EphemeralCleanupJobState {
    owner: Arc<EphemeralStoreOwnerState>,
}

impl Drop for EphemeralCleanupJobState {
    fn drop(&mut self) {
        self.owner.revoke();
    }
}

pub type EphemeralStoreRevoker = Box<dyn Fn() + Send + Sync + 'static>;
pub type EphemeralStoreCleanupJob = Box<dyn FnOnce() -> io::Result<()> + Send + 'static>;

struct StoreShared {
    lifecycle: Mutex<StoreLifecycle>,
    drain: Condvar,
    closed: Condvar,
    cleanup: Option<EphemeralCleanup>,
    #[cfg(test)]
    test_hooks: TestHooks,
}

#[cfg(test)]
struct TestBarrier {
    reached: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum TestPoint {
    BeforePut,
    AfterOpenRead,
    AfterLifecycleLock,
    PublishTemp,
    BeforeActiveDecrement,
    BeforeRootDisposition,
    AfterRootDisposition,
    AfterRootNamespaceAbsent,
    ChildOpen,
    ChildFinalDelete,
    ChildDeleteQuery,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstructionFailurePoint {
    Identity,
    CasCreate,
    CasOpen,
    Operation,
    LifecycleLock,
}

#[cfg(test)]
static CONSTRUCTION_FAILURE: Mutex<Vec<(OsString, ConstructionFailurePoint)>> =
    Mutex::new(Vec::new());

#[cfg(test)]
static ROLLBACK_VERIFICATION_FAILURE: Mutex<Option<OsString>> = Mutex::new(None);

#[cfg(test)]
static ROOT_DISPOSITION_FAILURE: Mutex<Option<SecureFileIdentity>> = Mutex::new(None);

#[cfg(test)]
type TestHooks = Mutex<Vec<(TestPoint, Option<OsString>, TestBarrier)>>;

#[cfg(test)]
fn wait_test_hook(hooks: &TestHooks, point: TestPoint, name: Option<&OsStr>) {
    let hook = {
        let mut hooks = hooks.lock().unwrap_or_else(|p| p.into_inner());
        hooks
            .iter()
            .position(|(p, n, _)| *p == point && n.as_deref() == name)
            .map(|index| hooks.swap_remove(index).2)
    };
    if let Some(hook) = hook {
        let _ = hook.reached.send(());
        let _ = hook.release.recv();
    }
}

#[cfg(test)]
struct CreateRootBarrier {
    root_name: OsString,
    barrier: TestBarrier,
}

#[cfg(test)]
static CREATE_ROOT_BARRIER: Mutex<Option<CreateRootBarrier>> = Mutex::new(None);

#[cfg(test)]
static BEFORE_ROOT_CREATE_BARRIER: Mutex<Option<CreateRootBarrier>> = Mutex::new(None);

#[cfg(test)]
static OPEN_MARKER_RECHECK_BARRIER: Mutex<Option<CreateRootBarrier>> = Mutex::new(None);

#[cfg(test)]
fn wait_named_barrier(slot: &Mutex<Option<CreateRootBarrier>>, root_name: &OsStr) {
    let hook = {
        let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|hook| hook.root_name == root_name)
        {
            slot.take().map(|hook| hook.barrier)
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        let _ = hook.reached.send(());
        let _ = hook.release.recv();
    }
}

struct StoreLifecycle {
    phase: StorePhase,
    active_operations: usize,
    cas_dir: Option<Arc<Dir>>,
    close_result: Option<Result<(), CloseFailure>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StorePhase {
    Open,
    Closing,
    Cleaning,
    Closed,
    Failed,
}

struct EphemeralCleanup {
    parent: Arc<Dir>,
    root_name: OsString,
    owner_marker_name: OsString,
    identity: SecureFileIdentity,
    root: Mutex<Option<Dir>>,
    owner_marker: Mutex<Option<File>>,
    #[cfg(test)]
    test_hooks: TestHooks,
}

#[cfg(windows)]
impl EphemeralCleanup {
    fn wait_after_child_open(&self, entry_name: &OsStr) {
        #[cfg(test)]
        wait_test_hook(&self.test_hooks, TestPoint::ChildOpen, Some(entry_name));
        #[cfg(not(test))]
        let _ = (self, entry_name);
    }

    fn wait_before_child_final_delete(&self, entry_name: &OsStr) {
        #[cfg(test)]
        wait_test_hook(
            &self.test_hooks,
            TestPoint::ChildFinalDelete,
            Some(entry_name),
        );
        #[cfg(not(test))]
        let _ = (self, entry_name);
    }

    fn wait_after_child_delete_query(&self, entry_name: &OsStr) {
        #[cfg(test)]
        wait_test_hook(
            &self.test_hooks,
            TestPoint::ChildDeleteQuery,
            Some(entry_name),
        );
        #[cfg(not(test))]
        let _ = (self, entry_name);
    }
}

#[derive(Clone)]
struct CloseFailure {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

struct StoreOperation {
    cas_dir: Option<Arc<Dir>>,
    shared: Arc<StoreShared>,
}

impl StoreOperation {
    fn cas_dir(&self) -> &Dir {
        self.cas_dir
            .as_deref()
            .expect("CAS operation retains its directory capability")
    }
}

impl Drop for StoreOperation {
    fn drop(&mut self) {
        drop(self.cas_dir.take());
        #[cfg(test)]
        wait_test_hook(
            &self.shared.test_hooks,
            TestPoint::BeforeActiveDecrement,
            None,
        );
        let mut lifecycle = self
            .shared
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(lifecycle.active_operations > 0);
        lifecycle.active_operations -= 1;
        if lifecycle.active_operations == 0 {
            self.shared.drain.notify_all();
        }
    }
}

impl CloseFailure {
    fn capture(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn into_io_error(self) -> io::Error {
        match self.raw_os_error {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(self.kind, self.message),
        }
    }
}

impl EphemeralStoreOwnerState {
    fn revoke(&self) {
        let revoked_capability = {
            let mut lifecycle = self
                .shared
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if lifecycle.phase == StorePhase::Open {
                lifecycle.phase = StorePhase::Closing;
                lifecycle.cas_dir.take()
            } else {
                None
            }
        };
        drop(revoked_capability);
    }

    /// Drains operations admitted before revocation and removes the root.
    fn cleanup(&self) -> io::Result<()> {
        self.revoke();
        loop {
            let mut lifecycle = self
                .shared
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match lifecycle.phase {
                StorePhase::Closed | StorePhase::Failed => return close_result(&lifecycle),
                StorePhase::Cleaning => {
                    while lifecycle.phase == StorePhase::Cleaning {
                        lifecycle = self
                            .shared
                            .closed
                            .wait(lifecycle)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    return close_result(&lifecycle);
                }
                StorePhase::Closing if lifecycle.active_operations == 0 => {
                    lifecycle.phase = StorePhase::Cleaning;
                    break;
                }
                StorePhase::Open | StorePhase::Closing => {
                    lifecycle = self
                        .shared
                        .drain
                        .wait(lifecycle)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    drop(lifecycle);
                }
            }
        }

        let result = self
            .shared
            .cleanup
            .as_ref()
            .ok_or_else(|| io::Error::other("persistent CAS has no ephemeral cleanup owner"))
            .and_then(remove_ephemeral_store)
            .and_then(|()| {
                let cleanup = self
                    .shared
                    .cleanup
                    .as_ref()
                    .expect("ephemeral cleanup remains present through close");
                let marker = cleanup
                    .owner_marker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .ok_or_else(|| io::Error::other("ephemeral owner marker is missing"))?;
                delete_ephemeral_owner_marker(&cleanup.parent, &cleanup.owner_marker_name, marker)
            })
            .map_err(|error| CloseFailure::capture(&error));
        let returned = result.clone();
        {
            let mut lifecycle = self
                .shared
                .lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            lifecycle.phase = if returned.is_ok() {
                StorePhase::Closed
            } else {
                StorePhase::Failed
            };
            lifecycle.close_result = Some(result);
            self.shared.closed.notify_all();
        }
        returned.map_err(CloseFailure::into_io_error)
    }
}

fn close_result(lifecycle: &StoreLifecycle) -> io::Result<()> {
    lifecycle
        .close_result
        .as_ref()
        .expect("terminal CAS lifecycle has a cleanup result")
        .clone()
        .map_err(CloseFailure::into_io_error)
}

fn validate_ephemeral_root_name(path: &Path) -> io::Result<&OsStr> {
    let mut components = path.components();
    let name = match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => name,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ephemeral CAS root must be one relative path component",
            ));
        }
    };
    Ok(name)
}

#[cfg(windows)]
fn ephemeral_root_desired_access() -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
    };

    DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE
}

#[cfg(windows)]
fn create_ephemeral_root(parent: &Dir, root_name: &OsStr) -> io::Result<Dir> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;

    let mut name = root_name.encode_wide().collect::<Vec<_>>();
    let byte_len = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ephemeral root name is too long",
            )
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
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = std::ptr::null_mut();
    let mut io_status = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    // SAFETY: `parent` remains alive for the call; `unicode_name` points into
    // `name`, whose UTF-16 buffer and byte length remain stable; all output
    // pointers are valid for writes. `FILE_CREATE` returns a newly-owned handle
    // only on non-negative NTSTATUS, which is transferred exactly once below.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            ephemeral_root_desired_access(),
            &attributes,
            io_status.as_mut_ptr(),
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: `status` is the NTSTATUS returned by `NtCreateFile`; this
        // conversion has no pointer or ownership preconditions.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: successful `NtCreateFile` initialized `handle` with one owned
    // kernel handle. `File` assumes that ownership and closes it exactly once.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    Ok(Dir::from_std_file(file))
}

#[cfg(not(windows))]
fn create_ephemeral_root(parent: &Dir, root_name: &OsStr) -> io::Result<Dir> {
    parent.create_dir(root_name)?;
    parent.open_dir_nofollow(root_name)
}

fn secure_directory_identity(dir: &Dir) -> io::Result<SecureFileIdentity> {
    let file = dir.try_clone()?.into_std_file();
    if !file.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ephemeral CAS root is not a directory",
        ));
    }
    platform_secure_directory_identity(&file)
}

fn ephemeral_owner_marker_name(root_name: &OsStr) -> OsString {
    let mut marker_name = root_name.to_os_string();
    marker_name.push(EPHEMERAL_OWNER_MARKER_SUFFIX);
    marker_name
}

fn create_ephemeral_owner_marker(parent: &Dir, marker_name: &OsStr) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options.follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    parent
        .open_with(marker_name, &options)
        .map(cap_std::fs::File::into_std)
}

fn reject_ephemeral_owner_marker(parent: &Dir, marker_name: &OsStr) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    match parent.open_with(marker_name, &options) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "CAS root is owned by an active ephemeral store",
        )),
        Err(error) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("ephemeral owner marker cannot be verified: {error}"),
        )),
    }
}

#[cfg(windows)]
fn delete_ephemeral_owner_marker(
    _parent: &Dir,
    _marker_name: &OsStr,
    marker: File,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: the marker handle was opened with DELETE access before the root
    // was created and remains owned here. The disposition buffer is valid for
    // the duration of this call; ownership is dropped only after disposition.
    let ok = unsafe {
        SetFileInformationByHandle(
            marker.as_raw_handle().cast(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(marker);
    Ok(())
}

struct EphemeralConstruction {
    parent: Arc<Dir>,
    root_name: OsString,
    marker_name: OsString,
    marker: Option<File>,
    root: Option<Dir>,
    identity: Option<SecureFileIdentity>,
    drop_rollback_enabled: bool,
}

impl EphemeralConstruction {
    fn rollback(&mut self) -> io::Result<()> {
        if let Some(root) = self.root.as_ref() {
            rollback_ephemeral_root(&self.parent, &self.root_name, root, self.identity)?;
            drop(self.root.take());
            verify_rollback_root_removed(&self.parent, &self.root_name, self.identity)?;
        }
        if let Some(marker) = self.marker.take() {
            delete_ephemeral_owner_marker(&self.parent, &self.marker_name, marker)?;
        }
        Ok(())
    }

    fn rollback_error(&mut self, cause: io::Error) -> io::Error {
        let rollback = self.rollback();
        self.drop_rollback_enabled = false;
        match rollback {
            Ok(()) => cause,
            Err(rollback) => io::Error::new(
                rollback.kind(),
                format!("ephemeral CAS construction failed ({cause}); rollback failed: {rollback}"),
            ),
        }
    }

    fn commit(&mut self, cleanup: &EphemeralCleanup) {
        let root = self
            .root
            .take()
            .expect("construction owns its root until commit");
        let marker = self
            .marker
            .take()
            .expect("construction owns its marker until commit");
        *cleanup
            .root
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(root);
        *cleanup
            .owner_marker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(marker);
        self.drop_rollback_enabled = false;
    }
}

impl Drop for EphemeralConstruction {
    fn drop(&mut self) {
        if self.drop_rollback_enabled {
            let _ = self.rollback();
        }
    }
}

#[cfg(windows)]
fn rollback_ephemeral_root(
    parent: &Dir,
    root_name: &OsStr,
    root: &Dir,
    identity: Option<SecureFileIdentity>,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
    };
    if let Some(expected) = identity {
        if secure_directory_identity(root)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "constructed CAS root identity changed before rollback",
            ));
        }
        let cleanup = EphemeralCleanup {
            parent: Arc::new(parent.try_clone()?),
            root_name: root_name.to_os_string(),
            owner_marker_name: OsString::new(),
            identity: expected,
            root: Mutex::new(None),
            owner_marker: Mutex::new(None),
            #[cfg(test)]
            test_hooks: Mutex::new(Vec::new()),
        };
        remove_directory_contents_windows(root, &cleanup)?;
    }
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: this is the original DELETE-capable root handle returned by
    // `FILE_CREATE`; it remains owned by the construction guard for the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            root.as_raw_handle().cast(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn rollback_ephemeral_root(
    parent: &Dir,
    root_name: &OsStr,
    root: &Dir,
    _identity: Option<SecureFileIdentity>,
) -> io::Result<()> {
    root.try_clone()?.remove_open_dir_all()?;
    Ok(())
}

fn verify_rollback_root_removed(
    parent: &Dir,
    root_name: &OsStr,
    identity: Option<SecureFileIdentity>,
) -> io::Result<()> {
    #[cfg(test)]
    {
        let injected = ROLLBACK_VERIFICATION_FAILURE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take_if(|name| name == root_name)
            .is_some();
        if injected {
            parent.create_dir(root_name)?;
            let replacement = parent.open_dir_nofollow(root_name)?;
            let mut marker = replacement.create("replacement-marker")?.into_std();
            std::io::Write::write_all(&mut marker, b"replacement")?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected rollback namespace verification failure",
            ));
        }
    }
    #[cfg(windows)]
    if let Some(expected) = identity {
        return verify_namespace_entry_removed(parent, root_name, expected);
    }
    #[cfg(not(windows))]
    let _ = identity;
    match parent.open_dir_nofollow(root_name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other(
            "constructed CAS root remains visible after rollback",
        )),
    }
}

#[cfg(test)]
fn inject_construction_failure(
    root_name: &OsStr,
    point: ConstructionFailurePoint,
) -> io::Result<()> {
    let mut injection = CONSTRUCTION_FAILURE
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(index) = injection
        .iter()
        .position(|(name, injected)| name == root_name && *injected == point)
    {
        injection.swap_remove(index);
        Err(io::Error::other(format!(
            "injected ephemeral construction failure at {point:?}"
        )))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn delete_ephemeral_owner_marker(
    parent: &Dir,
    marker_name: &OsStr,
    marker: File,
) -> io::Result<()> {
    parent.remove_file(marker_name)?;
    drop(marker);
    Ok(())
}

#[cfg(windows)]
fn platform_secure_directory_identity(file: &File) -> io::Result<SecureFileIdentity> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let (identity, attributes) = platform_handle_identity_and_attributes(file)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ephemeral CAS directory is a reparse point",
        ));
    }
    Ok(identity)
}

#[cfg(windows)]
fn platform_handle_identity_and_attributes(file: &File) -> io::Result<(SecureFileIdentity, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO, FileAttributeTagInfo, FileIdInfo,
        GetFileInformationByHandleEx,
    };

    let handle = file.as_raw_handle().cast();
    let mut identity = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    // SAFETY: `file` owns a valid handle for the duration of the call;
    // `identity` is correctly aligned and sized for `FILE_ID_INFO` and is read
    // only after the API reports success.
    let identity_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            identity.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if identity_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = std::mem::MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::uninit();
    // SAFETY: the same live handle is queried into an aligned, correctly-sized
    // `FILE_ATTRIBUTE_TAG_INFO`; initialization is observed only on success.
    let attributes_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            attributes.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if attributes_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both `GetFileInformationByHandleEx` calls returned success, so
    // their complete output structures are initialized.
    let attributes = unsafe { attributes.assume_init() };
    // SAFETY: see above; the identity query succeeded.
    let identity = unsafe { identity.assume_init() };
    Ok((
        SecureFileIdentity {
            volume: identity.VolumeSerialNumber,
            index: u128::from_ne_bytes(identity.FileId.Identifier),
        },
        attributes.FileAttributes,
    ))
}

#[cfg(unix)]
fn platform_secure_directory_identity(file: &File) -> io::Result<SecureFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(SecureFileIdentity {
        volume: metadata.dev(),
        index: u128::from(metadata.ino()),
    })
}

#[cfg(not(any(windows, unix)))]
fn platform_secure_directory_identity(_file: &File) -> io::Result<SecureFileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable ephemeral CAS directory identity is unsupported on this platform",
    ))
}

fn remove_ephemeral_store(cleanup: &EphemeralCleanup) -> io::Result<()> {
    let root = cleanup
        .root
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or_else(|| io::Error::other("ephemeral root capability is missing"))?;
    let actual = secure_directory_identity(&root)?;
    if actual != cleanup.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ephemeral CAS root identity changed before cleanup",
        ));
    }
    remove_ephemeral_root(cleanup, root)
}

#[cfg(windows)]
fn remove_ephemeral_root(cleanup: &EphemeralCleanup, root: Dir) -> io::Result<()> {
    remove_directory_contents_windows(&root, cleanup)?;
    #[cfg(test)]
    wait_test_hook(&cleanup.test_hooks, TestPoint::BeforeRootDisposition, None);
    dispose_ephemeral_root_handle(cleanup, &root)?;
    drop(root);
    #[cfg(test)]
    wait_test_hook(&cleanup.test_hooks, TestPoint::AfterRootDisposition, None);
    verify_ephemeral_root_namespace_absent(&cleanup.parent, &cleanup.root_name)?;
    #[cfg(test)]
    wait_test_hook(
        &cleanup.test_hooks,
        TestPoint::AfterRootNamespaceAbsent,
        None,
    );
    Ok(())
}

#[cfg(windows)]
fn dispose_ephemeral_root_handle(_cleanup: &EphemeralCleanup, root: &Dir) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    #[cfg(test)]
    {
        let injected = ROOT_DISPOSITION_FAILURE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take_if(|identity| *identity == _cleanup.identity)
            .is_some();
        if injected {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "injected same-handle root disposition failure",
            ));
        }
    }

    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: `root` is the original DELETE-capable handle returned by
    // `FILE_CREATE`; it stays alive through this disposition call and is
    // explicitly dropped before namespace verification. The input buffer is
    // correctly sized and valid for the duration of the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            root.as_raw_handle().cast(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn verify_ephemeral_root_namespace_absent(parent: &Dir, name: &OsStr) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::{FileNamesInformation, NtQueryDirectoryFile};
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, UNICODE_STRING,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name = name.encode_wide().collect::<Vec<_>>();
    let byte_len = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root name is too long"))?;
    let query_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name.as_mut_ptr(),
    };
    let mut io_status = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let mut buffer = vec![0u64; 8192];
    // SAFETY: `parent`, `query_name`, `io_status`, and `buffer` remain live for
    // the synchronous query. The query returns at most one names-only record
    // and does not open, classify, or mutate the matching namespace entry.
    let status = unsafe {
        NtQueryDirectoryFile(
            parent.as_raw_handle().cast(),
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            io_status.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            (buffer.len() * std::mem::size_of::<u64>()) as u32,
            FileNamesInformation,
            1,
            &query_name,
            1,
        )
    };
    if status == STATUS_NO_SUCH_FILE || status == STATUS_NO_MORE_FILES {
        return Ok(());
    }
    if status >= 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ephemeral CAS root namespace was replaced after disposition",
        ));
    }
    // SAFETY: `status` is the NTSTATUS returned by `NtQueryDirectoryFile`.
    let code = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "ephemeral CAS root namespace cannot be proven absent: {}",
            io::Error::from_raw_os_error(code as i32)
        ),
    ))
}

#[cfg(windows)]
struct EnumeratedChild {
    name: OsString,
    identity: SecureFileIdentity,
    attributes: u32,
    reparse_tag: u32,
}

#[cfg(windows)]
fn valid_file_id_next_offset(
    current_offset: usize,
    next_offset: usize,
    header_len: usize,
    record_span: usize,
    buffer_len: usize,
) -> bool {
    next_offset.is_multiple_of(8)
        && next_offset >= record_span
        && current_offset
            .checked_add(next_offset)
            .and_then(|next| next.checked_add(header_len))
            .is_some_and(|next_header_end| next_header_end <= buffer_len)
}

#[cfg(windows)]
fn enumerate_children_windows(dir: &Dir) -> io::Result<Vec<EnumeratedChild>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, GetFileInformationByHandleEx,
    };

    let file = dir.try_clone()?.into_std_file();
    let volume = secure_directory_identity(dir)?.volume;
    let mut children = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0u64; 8192];
        let class = if restart {
            FileIdExtdDirectoryRestartInfo
        } else {
            FileIdExtdDirectoryInfo
        };
        restart = false;
        // SAFETY: `file` owns a live directory handle; the `u64` allocation is
        // 8-byte aligned, writable for its full 64 KiB, and remains alive while
        // the API writes `FILE_ID_EXTD_DIR_INFO` records into it.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
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
            return Err(error);
        }

        let buffer_len = buffer.len() * std::mem::size_of::<u64>();
        // SAFETY: the zero-initialized allocation remains alive and every byte
        // is valid to observe; the parser performs byte copies, not typed reads.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_len) };
        children.extend(parse_file_id_extd_directory_buffer(bytes, volume)?);
    }
    Ok(children)
}

#[cfg(windows)]
fn parse_file_id_extd_directory_buffer(
    buffer: &[u8],
    volume: u64,
) -> io::Result<Vec<EnumeratedChild>> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO;
    let header = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed FileIdExtdDirectoryInfo",
        )
    };
    let mut children = Vec::new();
    let mut offset = 0usize;
    loop {
        let header_end = offset
            .checked_add(header)
            .filter(|&n| n <= buffer.len())
            .ok_or_else(bad)?;
        let field = |field_offset: usize, len: usize| {
            let start = offset.checked_add(field_offset)?;
            let end = start.checked_add(len)?;
            (end <= header_end).then(|| &buffer[start..end])
        };
        let u32_field = |field_offset| -> io::Result<u32> {
            Ok(u32::from_ne_bytes(
                field(field_offset, 4).ok_or_else(bad)?.try_into().unwrap(),
            ))
        };
        let next =
            u32_field(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, NextEntryOffset))? as usize;
        let attributes = u32_field(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileAttributes))?;
        let name_bytes =
            u32_field(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileNameLength))? as usize;
        let reparse_tag = u32_field(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, ReparsePointTag))?;
        let mut file_id = [0; 16];
        file_id.copy_from_slice(
            field(std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileId), 16).ok_or_else(bad)?,
        );
        let name_end = header_end
            .checked_add(name_bytes)
            .filter(|&n| n <= buffer.len())
            .ok_or_else(bad)?;
        if !name_bytes.is_multiple_of(2) {
            return Err(bad());
        }
        // Byte-copy every field and UTF-16 unit: no struct/u16 reference is
        // formed, so i686 never depends on FILE_ID_EXTD_DIR_INFO alignment.
        let wide = buffer[header_end..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_ne_bytes([b[0], b[1]]))
            .collect::<Vec<_>>();
        let name = OsString::from_wide(&wide);
        if name != OsStr::new(".") && name != OsStr::new("..") {
            children.push(EnumeratedChild {
                name,
                identity: SecureFileIdentity {
                    volume,
                    index: u128::from_ne_bytes(file_id),
                },
                attributes,
                reparse_tag,
            });
        }
        if next == 0 {
            break;
        }
        if !valid_file_id_next_offset(offset, next, header, header + name_bytes, buffer.len()) {
            return Err(bad());
        }
        offset = offset.checked_add(next).ok_or_else(bad)?;
    }
    Ok(children)
}
#[cfg(windows)]
fn remove_directory_contents_windows(dir: &Dir, cleanup: &EphemeralCleanup) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    for entry in enumerate_children_windows(dir)? {
        cleanup.wait_after_child_open(&entry.name);
        if entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to clean reparse entry {:?} with tag {:#x}",
                    entry.name, entry.reparse_tag
                ),
            ));
        }
        if entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            let child = dir.open_dir_nofollow(&entry.name)?;
            if secure_directory_identity(&child)? != entry.identity {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ephemeral CAS child directory changed after enumeration",
                ));
            }
            remove_directory_contents_windows(&child, cleanup)?;
            drop(child);
            cleanup.wait_before_child_final_delete(&entry.name);
            delete_entry_identity_bound(dir, &entry.name, entry.identity, true, Some(cleanup))?;
        } else {
            delete_entry_identity_bound(dir, &entry.name, entry.identity, false, Some(cleanup))?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn delete_entry_identity_bound(
    parent: &Dir,
    name: &OsStr,
    expected: SecureFileIdentity,
    expect_directory: bool,
    cleanup: Option<&EphemeralCleanup>,
) -> io::Result<()> {
    use cap_std::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    let mut options = OpenOptions::new();
    options
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options)?.into_std();
    let (actual, attributes) = platform_handle_identity_and_attributes(&file)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ephemeral CAS entry became a reparse point before deletion",
        ));
    }
    if actual != expected || (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != expect_directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ephemeral CAS entry identity changed at deletion boundary",
        ));
    }
    if let Some(cleanup) = cleanup {
        cleanup.wait_after_child_delete_query(name);
    }

    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: `file` owns a live DELETE-capable handle; `disposition` is a
    // correctly-sized immutable input buffer valid for the duration of the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(file);
    verify_namespace_entry_removed(parent, name, expected)
}

#[cfg(windows)]
fn verify_namespace_entry_removed(
    parent: &Dir,
    name: &OsStr,
    removed_identity: SecureFileIdentity,
) -> io::Result<()> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No);
    match parent.open_with(name, &options) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("ephemeral CAS namespace removal is incomplete: {error}"),
        )),
        Ok(file) => {
            let file = file.into_std();
            let (visible_identity, _) = platform_handle_identity_and_attributes(&file)?;
            if visible_identity == removed_identity {
                Err(io::Error::other(
                    "ephemeral CAS entry remains visible after disposition",
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ephemeral CAS entry was replaced during namespace removal",
                ))
            }
        }
    }
}

#[cfg(not(windows))]
fn remove_ephemeral_root(_cleanup: &EphemeralCleanup, root: Dir) -> io::Result<()> {
    root.remove_open_dir_all()
}

struct LifecycleLock {
    file: File,
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum StoreEntryKind {
    Temp,
    Blob,
}

fn persistent_marker_location(root: &Path) -> Option<(&Path, &OsStr)> {
    Some((
        root.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
        root.file_name()?,
    ))
}

#[cfg(windows)]
fn open_persistent_root(parent: &Dir, name: &OsStr) -> io::Result<Dir> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TRAVERSE, SYNCHRONIZE,
    };
    let mut options = OpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    options.follow(FollowSymlinks::No);
    parent
        .open_with(name, &options)
        .map(cap_std::fs::File::into_std)
        .map(Dir::from_std_file)
}

#[cfg(not(windows))]
fn open_persistent_root(parent: &Dir, name: &OsStr) -> io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn authoritative_root_name(root: &Dir) -> io::Result<OsString> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_NONE,
    };
    let file = root.try_clone()?.into_std_file();
    let mut name = vec![0u16; 32_768];
    // SAFETY: `file` owns a live root handle and `name` is writable for the
    // advertised length. The handle, not the caller path, selects the object.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            name.as_mut_ptr(),
            name.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_NONE,
        )
    };
    if len == 0 || len as usize >= name.len() {
        return Err(if len == 0 {
            io::Error::last_os_error()
        } else {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "normalized CAS root name is too long",
            )
        });
    }
    PathBuf::from(OsString::from_wide(&name[..len as usize]))
        .file_name()
        .map(OsStr::to_os_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CAS root has no final name"))
}

#[cfg(not(windows))]
fn authoritative_root_name(_root: &Dir, opened_name: &OsStr) -> io::Result<OsString> {
    Ok(opened_name.to_os_string())
}

struct StoreEntry {
    #[cfg(test)]
    path: PathBuf,
    dir: Arc<Dir>,
    name: std::ffi::OsString,
    size: u64,
    mtime: std::time::SystemTime,
    kind: StoreEntryKind,
}

impl BlobStore {
    /// Opens (creating if needed) a store under `root`. Blobs live in
    /// `root/cas/`; the action cache (M4.3) will use `root/ac/` alongside.
    pub fn open(root: impl AsRef<Path>) -> io::Result<BlobStore> {
        let root = root.as_ref();
        let marker = persistent_marker_location(root)
            .map(|(parent_path, root_name)| {
                std::fs::create_dir_all(parent_path)?;
                let parent = Dir::open_ambient_dir(parent_path, ambient_authority())?;
                let marker_name = ephemeral_owner_marker_name(root_name);
                reject_ephemeral_owner_marker(&parent, &marker_name)?;
                Ok::<_, io::Error>((parent, root_name, marker_name))
            })
            .transpose()?;
        std::fs::create_dir_all(root)?;
        let root_dir = match &marker {
            Some((parent, root_name, _)) => open_persistent_root(parent, root_name)?,
            None => Dir::open_ambient_dir(root, ambient_authority())?,
        };
        let authoritative_marker = match &marker {
            Some((parent, _opened_name, _)) => {
                #[cfg(windows)]
                let root_name = authoritative_root_name(&root_dir)?;
                #[cfg(not(windows))]
                let root_name = authoritative_root_name(&root_dir, _opened_name)?;
                let marker_name = ephemeral_owner_marker_name(&root_name);
                reject_ephemeral_owner_marker(parent, &marker_name)?;
                Some((parent, root_name, marker_name))
            }
            None => None,
        };
        match root_dir.create_dir("cas") {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let cas_dir = Arc::new(root_dir.open_dir_nofollow("cas")?);
        if let Some((parent, _root_name, marker_name)) = &authoritative_marker {
            #[cfg(test)]
            wait_named_barrier(&OPEN_MARKER_RECHECK_BARRIER, _root_name);
            reject_ephemeral_owner_marker(parent, marker_name)?;
        }
        let store = BlobStore {
            #[cfg(test)]
            cas_root: root.join("cas"),
            shared: Arc::new(StoreShared {
                lifecycle: Mutex::new(StoreLifecycle {
                    phase: StorePhase::Open,
                    active_operations: 0,
                    cas_dir: Some(cas_dir),
                    close_result: None,
                }),
                drain: Condvar::new(),
                closed: Condvar::new(),
                cleanup: None,
                #[cfg(test)]
                test_hooks: Mutex::new(Vec::new()),
            }),
        };
        let operation = store.operation()?;
        drop(store.open_lifecycle_lock(&operation)?);
        Ok(store)
    }

    /// Creates a new, exclusively-owned ephemeral store below `parent`.
    ///
    /// Unlike [`BlobStore::open`], this rejects every pre-existing final entry
    /// and returns the sole owner allowed to begin destructive cleanup.
    pub fn create_ephemeral(
        parent: Dir,
        root_name: impl AsRef<Path>,
    ) -> io::Result<(BlobStore, EphemeralStoreRevoker, EphemeralStoreCleanupJob)> {
        let root_name = validate_ephemeral_root_name(root_name.as_ref())?.to_os_string();
        let owner_marker_name = ephemeral_owner_marker_name(&root_name);
        let parent = Arc::new(parent);
        let owner_marker = create_ephemeral_owner_marker(&parent, &owner_marker_name)?;
        let mut construction = EphemeralConstruction {
            parent: Arc::clone(&parent),
            root_name: root_name.clone(),
            marker_name: owner_marker_name.clone(),
            marker: Some(owner_marker),
            root: None,
            identity: None,
            drop_rollback_enabled: true,
        };
        #[cfg(test)]
        wait_named_barrier(&BEFORE_ROOT_CREATE_BARRIER, &root_name);
        let built = (|| -> io::Result<(BlobStore, Arc<StoreShared>)> {
            construction.root = Some(create_ephemeral_root(&parent, &root_name)?);
            #[cfg(test)]
            wait_named_barrier(&CREATE_ROOT_BARRIER, &root_name);
            #[cfg(test)]
            inject_construction_failure(&root_name, ConstructionFailurePoint::Identity)?;
            let identity = secure_directory_identity(
                construction
                    .root
                    .as_ref()
                    .expect("constructed root is retained until commit"),
            )?;
            construction.identity = Some(identity);
            #[cfg(test)]
            inject_construction_failure(&root_name, ConstructionFailurePoint::CasCreate)?;
            let root = construction
                .root
                .as_ref()
                .expect("constructed root is retained until commit");
            root.create_dir("cas")?;
            #[cfg(test)]
            inject_construction_failure(&root_name, ConstructionFailurePoint::CasOpen)?;
            let cas_dir = Arc::new(root.open_dir_nofollow("cas")?);
            let shared = Arc::new(StoreShared {
                lifecycle: Mutex::new(StoreLifecycle {
                    phase: StorePhase::Open,
                    active_operations: 0,
                    cas_dir: Some(cas_dir),
                    close_result: None,
                }),
                drain: Condvar::new(),
                closed: Condvar::new(),
                cleanup: Some(EphemeralCleanup {
                    parent: Arc::clone(&parent),
                    root_name: root_name.clone(),
                    owner_marker_name: owner_marker_name.clone(),
                    identity,
                    root: Mutex::new(None),
                    owner_marker: Mutex::new(None),
                    #[cfg(test)]
                    test_hooks: Mutex::new(Vec::new()),
                }),
                #[cfg(test)]
                test_hooks: Mutex::new(Vec::new()),
            });
            let store = BlobStore {
                #[cfg(test)]
                cas_root: PathBuf::from(&root_name).join("cas"),
                shared: Arc::clone(&shared),
            };
            #[cfg(test)]
            inject_construction_failure(&root_name, ConstructionFailurePoint::Operation)?;
            let operation = store.operation()?;
            #[cfg(test)]
            inject_construction_failure(&root_name, ConstructionFailurePoint::LifecycleLock)?;
            drop(store.open_lifecycle_lock(&operation)?);
            Ok((store, shared))
        })();
        let (store, shared) = match built {
            Ok(built) => built,
            Err(error) => return Err(construction.rollback_error(error)),
        };
        construction.commit(
            shared
                .cleanup
                .as_ref()
                .expect("ephemeral cleanup is installed before commit"),
        );
        let owner = Arc::new(EphemeralStoreOwnerState { shared });
        let revoker_owner = Arc::clone(&owner);
        let revoker: EphemeralStoreRevoker = Box::new(move || revoker_owner.revoke());
        let cleanup_state = EphemeralCleanupJobState { owner };
        let cleanup_job: EphemeralStoreCleanupJob = Box::new(move || cleanup_state.owner.cleanup());
        Ok((store, revoker, cleanup_job))
    }

    fn operation(&self) -> io::Result<StoreOperation> {
        let mut lifecycle = self
            .shared
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if lifecycle.phase != StorePhase::Open {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ephemeral CAS store is closing",
            ));
        }
        lifecycle.active_operations = lifecycle
            .active_operations
            .checked_add(1)
            .ok_or_else(|| io::Error::other("CAS operation count overflow"))?;
        let cas_dir =
            lifecycle.cas_dir.as_ref().cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "CAS capability revoked")
            })?;
        Ok(StoreOperation {
            cas_dir: Some(cas_dir),
            shared: Arc::clone(&self.shared),
        })
    }

    #[cfg(test)]
    fn install_test_hook(
        &self,
        point: TestPoint,
        name: Option<OsString>,
        reached: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        let hooks = match point {
            TestPoint::BeforePut
            | TestPoint::AfterOpenRead
            | TestPoint::AfterLifecycleLock
            | TestPoint::PublishTemp
            | TestPoint::BeforeActiveDecrement => &self.shared.test_hooks,
            _ => {
                &self
                    .shared
                    .cleanup
                    .as_ref()
                    .expect("test hook requires an ephemeral store")
                    .test_hooks
            }
        };
        hooks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((point, name, TestBarrier { reached, release }));
    }

    fn open_lifecycle_lock(&self, operation: &StoreOperation) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        operation
            .cas_dir()
            .open_with(LIFECYCLE_LOCK_NAME, &options)
            .map(cap_std::fs::File::into_std)
    }

    fn lock_shared_lifecycle(&self, operation: &StoreOperation) -> io::Result<LifecycleLock> {
        let file = self.open_lifecycle_lock(operation)?;
        file.lock_shared()?;
        Ok(LifecycleLock { file })
    }

    fn lock_exclusive_lifecycle(&self, operation: &StoreOperation) -> io::Result<LifecycleLock> {
        let file = self.open_lifecycle_lock(operation)?;
        file.lock()?;
        Ok(LifecycleLock { file })
    }

    /// The final on-disk path for a digest. Safe because `digest.hex()` is
    /// validated lowercase hex of fixed length (no separators, no `..`).
    #[cfg(test)]
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        let hex = digest.hex();
        self.cas_root
            .join(algo_dir(digest))
            .join(&hex[0..2])
            .join(hex)
    }

    fn shard_rel_and_name(&self, digest: &Digest) -> (PathBuf, String) {
        let hex = digest.hex();
        (
            PathBuf::from(algo_dir(digest)).join(&hex[0..2]),
            hex.to_owned(),
        )
    }

    fn open_shard(
        &self,
        operation: &StoreOperation,
        digest: &Digest,
        create: bool,
    ) -> io::Result<Option<Arc<Dir>>> {
        let (shard_rel, _) = self.shard_rel_and_name(digest);
        if create {
            operation.cas_dir().create_dir_all(&shard_rel)?;
        }
        match operation.cas_dir().open_dir_nofollow(&shard_rel) {
            Ok(dir) => Ok(Some(Arc::new(dir))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Stores `bytes`, returning their digest. Idempotent: if the content is
    /// already present, no write happens (content addressing means an existing
    /// blob at this digest has identical bytes).
    pub fn put(&self, bytes: &[u8]) -> io::Result<Digest> {
        let operation = self.operation()?;
        let digest = Digest::of(bytes);
        #[cfg(test)]
        wait_test_hook(&self.shared.test_hooks, TestPoint::BeforePut, None);
        self.store_digest_known(&operation, bytes, &digest)?;
        Ok(digest)
    }

    /// Stores worker-returned `bytes` only if they actually hash to `claimed`.
    /// This is the trust boundary (`docs/protocol/v0.md` §5): agents treat
    /// worker outputs as untrusted until digest-verified, so a forged or
    /// corrupted blob is rejected before it can occupy a valid address.
    pub fn put_verified(&self, bytes: &[u8], claimed: &Digest) -> Result<Digest, CasError> {
        let operation = self.operation()?;
        let actual = Digest::of(bytes);
        if &actual != claimed {
            return Err(CasError::DigestMismatch {
                claimed: claimed.clone(),
                actual,
            });
        }
        self.store_digest_known(&operation, bytes, &actual)?;
        Ok(actual)
    }

    /// Replaces a corrupt blob with digest-verified bytes without exposing a
    /// partially written final path. Unlike [`BlobStore::put_verified`], this
    /// operation deliberately replaces an existing entry and verifies the
    /// resulting final path before reporting success.
    pub fn repair_verified(&self, bytes: &[u8], claimed: &Digest) -> Result<Digest, CasError> {
        let operation = self.operation()?;
        let actual = Digest::of(bytes);
        if &actual != claimed {
            return Err(CasError::DigestMismatch {
                claimed: claimed.clone(),
                actual,
            });
        }

        self.store_digest_known(&operation, bytes, &actual)?;
        Ok(actual)
    }

    fn store_digest_known(
        &self,
        operation: &StoreOperation,
        bytes: &[u8],
        digest: &Digest,
    ) -> io::Result<()> {
        let _repair_guard = REPAIR_CRITICAL_SECTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _lifecycle = self.lock_shared_lifecycle(operation)?;
        #[cfg(test)]
        wait_test_hook(&self.shared.test_hooks, TestPoint::AfterLifecycleLock, None);
        match self.get_verified_with(operation, digest) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(CasError::Corrupt { .. }) | Err(CasError::Io(_)) => {
                self.remove_blob_entry(operation, digest)?;
            }
            Err(error) => return Err(io::Error::other(error)),
        }
        self.publish_cas_blob(operation, bytes, digest)
    }

    fn remove_blob_entry(&self, operation: &StoreOperation, digest: &Digest) -> io::Result<()> {
        let Some(shard) = self.open_shard(operation, digest, false)? else {
            return Ok(());
        };
        let (_, name) = self.shard_rel_and_name(digest);
        match shard.remove_file(&name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn publish_cas_blob(
        &self,
        operation: &StoreOperation,
        bytes: &[u8],
        digest: &Digest,
    ) -> io::Result<()> {
        #[cfg(test)]
        {
            self.publish_cas_blob_impl(operation, bytes, digest, None)
        }
        #[cfg(not(test))]
        {
            self.publish_cas_blob_impl(operation, bytes, digest)
        }
    }

    #[cfg(test)]
    fn publish_cas_blob_with_hooks<Before, After>(
        &self,
        bytes: &[u8],
        digest: &Digest,
        mut before_publish: Before,
        mut after_publish: After,
    ) -> io::Result<()>
    where
        Before: FnMut(&Path) -> io::Result<()>,
        After: FnMut(&Path) -> io::Result<()>,
    {
        let operation = self.operation()?;
        let mut hooks = PublishTestHooks {
            before_publish: &mut before_publish,
            after_publish: &mut after_publish,
        };
        self.publish_cas_blob_impl(&operation, bytes, digest, Some(&mut hooks))
    }

    fn publish_cas_blob_impl(
        &self,
        operation: &StoreOperation,
        bytes: &[u8],
        digest: &Digest,
        #[cfg(test)] mut hooks: Option<&mut PublishTestHooks<'_>>,
    ) -> io::Result<()> {
        use std::io::Write;

        let shard = self.open_shard(operation, digest, true)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "CAS shard disappeared after creation",
            )
        })?;
        let (_, final_name) = self.shard_rel_and_name(digest);
        let mut temp = loop {
            let sequence = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let temp_name = format!(".tmp.{}.{sequence}", process::id());
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            options.follow(FollowSymlinks::No);
            match shard.open_with(&temp_name, &options) {
                Ok(file) => break SecureCasTemp::new(Arc::clone(&shard), temp_name, file)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        temp.file_mut().write_all(bytes)?;
        temp.file_mut().flush()?;
        let expected = temp.snapshot();
        if secure_file_snapshot(temp.file_mut())? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CAS temp identity changed while writing",
            ));
        }
        #[cfg(test)]
        wait_test_hook(&self.shared.test_hooks, TestPoint::PublishTemp, None);
        temp.close();

        #[cfg(test)]
        if let Some(hooks) = hooks.as_mut() {
            (hooks.before_publish)(&self.blob_path(digest).with_file_name(temp.name()))?;
        }

        verify_secure_file(&shard, temp.name(), Some(expected), digest)?;
        match shard.rename(temp.name(), &shard, &final_name) {
            Ok(()) => temp.mark_moved(),
            Err(rename_error) => {
                if verify_secure_file(&shard, &final_name, None, digest).is_ok() {
                    return Ok(());
                }
                let _ = shard.remove_file(&final_name);
                return Err(rename_error);
            }
        }

        #[cfg(test)]
        if let Some(hooks) = hooks.as_mut()
            && let Err(error) = (hooks.after_publish)(&self.blob_path(digest))
        {
            let _ = shard.remove_file(&final_name);
            return Err(error);
        }

        if let Err(error) = verify_secure_file(&shard, &final_name, Some(expected), digest) {
            let _ = shard.remove_file(&final_name);
            return Err(error);
        }
        Ok(())
    }

    /// Reads a blob's bytes, or `None` if absent. Does not re-verify (the hot
    /// path); use [`BlobStore::get_verified`] where tamper detection is wanted.
    ///
    /// INVARIANT (relied on by [`BlobStore::evict_to`]): the read handle does not
    /// grant `FILE_SHARE_DELETE` on Windows. A concurrent eviction's
    /// `remove_file` therefore fails (and skips the blob) until this whole-blob
    /// read closes its handle, rather than deleting bytes out from under it.
    pub fn get(&self, digest: &Digest) -> io::Result<Option<Vec<u8>>> {
        let operation = self.operation()?;
        self.get_with(&operation, digest)
    }

    fn get_with(&self, operation: &StoreOperation, digest: &Digest) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = self.open_blob_read(operation, digest)? else {
            return Ok(None);
        };
        #[cfg(test)]
        wait_test_hook(&self.shared.test_hooks, TestPoint::AfterOpenRead, None);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    /// Reads at most `len` bytes starting at `offset`, or `None` if absent.
    /// Offsets at or beyond EOF return an empty byte vector.
    pub fn get_range(
        &self,
        digest: &Digest,
        offset: u64,
        len: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        let operation = self.operation()?;
        let Some(mut file) = self.open_blob_read(&operation, digest)? else {
            return Ok(None);
        };
        read_range_from(&mut file, offset, len).map(Some)
    }

    fn open_blob_read(
        &self,
        operation: &StoreOperation,
        digest: &Digest,
    ) -> io::Result<Option<File>> {
        let Some(shard) = self.open_shard(operation, digest, false)? else {
            return Ok(None);
        };
        let (_, name) = self.shard_rel_and_name(digest);
        match open_secure_file(&shard, &name) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Reads a blob and re-verifies its bytes hash to `digest`; a mismatch is
    /// `Corrupt` (on-disk corruption or tampering). `None` if absent.
    pub fn get_verified(&self, digest: &Digest) -> Result<Option<Vec<u8>>, CasError> {
        let operation = self.operation()?;
        self.get_verified_with(&operation, digest)
    }

    fn get_verified_with(
        &self,
        operation: &StoreOperation,
        digest: &Digest,
    ) -> Result<Option<Vec<u8>>, CasError> {
        let Some(bytes) = self.get_with(operation, digest)? else {
            return Ok(None);
        };
        if &Digest::of(&bytes) != digest {
            return Err(CasError::Corrupt {
                digest: digest.clone(),
            });
        }
        Ok(Some(bytes))
    }

    /// Whether a blob is present.
    pub fn has(&self, digest: &Digest) -> bool {
        let Ok(operation) = self.operation() else {
            return false;
        };
        self.open_blob_read(&operation, digest)
            .is_ok_and(|file| file.is_some())
    }

    /// Presence of many digests in one call, in request order — the local side
    /// of the `Has(digests[])` batch probe (`docs/protocol/v0.md` §4.3) that
    /// lets the data plane skip transferring blobs the peer already holds.
    pub fn has_batch(&self, digests: &[Digest]) -> Vec<bool> {
        let Ok(operation) = self.operation() else {
            return vec![false; digests.len()];
        };
        digests
            .iter()
            .map(|digest| {
                self.open_blob_read(&operation, digest)
                    .is_ok_and(|file| file.is_some())
            })
            .collect()
    }

    /// Instantaneous total bytes occupied by blobs and canonical temp siblings.
    /// Writers intentionally share the lifecycle lock, so this measurement does
    /// not lock: an in-progress temp may grow while metadata is sampled.
    pub fn total_size(&self) -> io::Result<u64> {
        let operation = self.operation()?;
        let mut total = 0u64;
        for entry in self.list_entries(&operation)? {
            total = total.saturating_add(entry.size);
        }
        Ok(total)
    }

    /// Evicts least-recently-modified blobs until the store is at or below
    /// `max_bytes`, returning the bytes freed. A simple size-capped LRU
    /// (`docs/decisions/0003`… "M4 simple version"); modification time is the
    /// recency proxy because Windows commonly disables last-access updates.
    ///
    /// A blob currently open for reading cannot be deleted on Windows; that
    /// delete fails and the blob is skipped rather than aborting eviction, so a
    /// concurrent read is never torn.
    pub fn evict_to(&self, max_bytes: u64) -> io::Result<u64> {
        let operation = self.operation()?;
        let _lifecycle = self.lock_exclusive_lifecycle(&operation)?;
        let mut entries = self.list_entries(&operation)?;
        let mut total = entries
            .iter()
            .fold(0u64, |sum, entry| sum.saturating_add(entry.size));
        if total <= max_bytes {
            return Ok(0);
        }
        // Reclaim abandoned temps before blobs, oldest first within each kind.
        entries.sort_by_key(|entry| (entry.kind, entry.mtime));
        let mut freed = 0u64;
        for entry in entries {
            if total <= max_bytes {
                break;
            }
            match entry.dir.remove_file(&entry.name) {
                Ok(()) => {
                    total = total.saturating_sub(entry.size);
                    freed = freed.saturating_add(entry.size);
                }
                // In use (open read) or already gone: skip, never tear a reader.
                Err(_) => continue,
            }
        }
        Ok(freed)
    }

    /// Walks valid algorithm shards, yielding canonical blobs and recoverable
    /// temp siblings. mtime falls back to the epoch so eviction sorting is total.
    fn list_entries(&self, operation: &StoreOperation) -> io::Result<Vec<StoreEntry>> {
        let mut out = Vec::new();
        let algo_name = "blake3";
        let algo_dir = match operation.cas_dir().open_dir_nofollow(algo_name) {
            Ok(dir) => Arc::new(dir),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(error) => return Err(error),
        };
        for shard_entry in algo_dir.read_dir(".")? {
            let shard_entry = shard_entry?;
            let shard_name_os = shard_entry.file_name();
            let Some(shard_name) = shard_name_os.to_str() else {
                continue;
            };
            if !is_lower_hex(shard_name, 2)
                || !shard_entry.file_type().is_ok_and(|kind| kind.is_dir())
            {
                continue;
            }
            let shard_dir = match algo_dir.open_dir_nofollow(shard_name) {
                Ok(dir) => Arc::new(dir),
                Err(_) => continue,
            };
            for entry in shard_dir.read_dir(".")? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    continue;
                };
                let kind = if is_lower_hex(name_str, 64) && name_str.starts_with(shard_name) {
                    StoreEntryKind::Blob
                } else if is_canonical_temp_name(name_str) {
                    StoreEntryKind::Temp
                } else {
                    continue;
                };
                let file = match open_secure_file(&shard_dir, name_str) {
                    Ok(file) => file,
                    Err(_) => continue,
                };
                let metadata = file.metadata()?;
                let mtime = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
                out.push(StoreEntry {
                    #[cfg(test)]
                    path: self.cas_root.join(algo_name).join(shard_name).join(&name),
                    dir: Arc::clone(&shard_dir),
                    name,
                    size: metadata.len(),
                    mtime,
                    kind,
                });
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecureFileSnapshot {
    identity: SecureFileIdentity,
    link_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecureFileIdentity {
    volume: u64,
    index: u128,
}

#[cfg(test)]
struct PublishTestHooks<'a> {
    before_publish: &'a mut dyn FnMut(&Path) -> io::Result<()>,
    after_publish: &'a mut dyn FnMut(&Path) -> io::Result<()>,
}

struct SecureCasTemp {
    dir: Arc<Dir>,
    name: String,
    file: Option<File>,
    snapshot: SecureFileSnapshot,
    moved: bool,
}

impl SecureCasTemp {
    fn new(dir: Arc<Dir>, name: String, file: cap_std::fs::File) -> io::Result<Self> {
        let file = file.into_std();
        let snapshot = secure_file_snapshot(&file)?;
        Ok(Self {
            dir,
            name,
            file: Some(file),
            snapshot,
            moved: false,
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("CAS temp file is still open")
    }

    fn snapshot(&self) -> SecureFileSnapshot {
        self.snapshot
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn mark_moved(&mut self) {
        self.moved = true;
    }
}

impl Drop for SecureCasTemp {
    fn drop(&mut self) {
        self.close();
        if !self.moved {
            let _ = self.dir.remove_file(&self.name);
        }
    }
}

fn open_secure_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = dir.open_with(name, &options)?.into_std();
    secure_file_snapshot(&file)?;
    Ok(file)
}

fn verify_secure_file(
    dir: &Dir,
    name: &str,
    expected: Option<SecureFileSnapshot>,
    digest: &Digest,
) -> io::Result<()> {
    let mut file = open_secure_file(dir, name)?;
    let actual = secure_file_snapshot(&file)?;
    if expected.is_some_and(|expected| actual != expected) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CAS file identity changed during publish",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if &Digest::of(&bytes) != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CAS file digest does not match its address",
        ));
    }
    Ok(())
}

fn secure_file_snapshot(file: &File) -> io::Result<SecureFileSnapshot> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CAS entry is not a regular file",
        ));
    }
    let snapshot = platform_secure_file_snapshot(file)?;
    if snapshot.link_count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CAS entry has an unexpected hardlink count",
        ));
    }
    Ok(snapshot)
}

#[cfg(windows)]
fn platform_secure_file_snapshot(file: &File) -> io::Result<SecureFileSnapshot> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a live handle for the call and `information` is an
    // aligned, correctly-sized output buffer that is read only on success.
    let ok = unsafe {
        GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr())
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `GetFileInformationByHandle` returned success and initialized the
    // complete `BY_HANDLE_FILE_INFORMATION` output structure.
    let information = unsafe { information.assume_init() };
    Ok(SecureFileSnapshot {
        identity: SecureFileIdentity {
            volume: u64::from(information.dwVolumeSerialNumber),
            index: (u128::from(information.nFileIndexHigh) << 32)
                | u128::from(information.nFileIndexLow),
        },
        link_count: u64::from(information.nNumberOfLinks),
    })
}

#[cfg(unix)]
fn platform_secure_file_snapshot(file: &File) -> io::Result<SecureFileSnapshot> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(SecureFileSnapshot {
        identity: SecureFileIdentity {
            volume: metadata.dev(),
            index: u128::from(metadata.ino()),
        },
        link_count: metadata.nlink(),
    })
}

#[cfg(not(any(windows, unix)))]
fn platform_secure_file_snapshot(_file: &File) -> io::Result<SecureFileSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable CAS file identity is unsupported on this platform",
    ))
}

fn is_canonical_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".tmp.") else {
        return false;
    };
    let mut parts = rest.split('.');
    let (Some(pid), Some(sequence), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    is_canonical_decimal::<u32>(pid) && is_canonical_decimal::<u64>(sequence)
}

fn is_canonical_decimal<T>(value: &str) -> bool
where
    T: std::str::FromStr,
{
    !(value.is_empty() || value.len() > 1 && value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<T>().is_ok()
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_range_from<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let end = reader.seek(SeekFrom::End(0))?;
    if offset >= end {
        return Ok(Vec::new());
    }

    reader.seek(SeekFrom::Start(offset))?;
    let requested = u64::try_from(len).unwrap_or(u64::MAX);
    let limit = requested.min(end - offset);
    let mut bytes = Vec::new();
    reader.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The per-algorithm subdirectory name. Kept as a free function so the layout is
/// defined in one place.
fn algo_dir(digest: &Digest) -> &'static str {
    match digest.algo() {
        crate::DigestAlgo::Blake3 => "blake3",
    }
}

/// Lists a directory's entries as paths; an absent directory yields an empty
/// list (the store may not have created every shard yet).
#[cfg(test)]
fn read_dir_some(dir: &Path) -> io::Result<Vec<PathBuf>> {
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            let mut paths = Vec::new();
            for ent in rd {
                paths.push(ent?.path());
            }
            Ok(paths)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to `final_path` atomically: create the parent shard, write a
/// uniquely-named temp sibling, fsync-free rename onto the final name (rename is
/// atomic within a volume, and the temp is a sibling so it is same-volume).
/// Shared with the action cache, which is keyed (not content-addressed) but
/// needs the same crash- and reader-safe publish.
struct AtomicTemp {
    path: PathBuf,
    file: Option<File>,
    moved: bool,
}

impl AtomicTemp {
    fn path(&self) -> &Path {
        &self.path
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn mark_moved(&mut self) {
        self.moved = true;
    }
}

impl Drop for AtomicTemp {
    fn drop(&mut self) {
        self.close();
        if !self.moved {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn write_temp_sibling(final_path: &Path, bytes: &[u8]) -> io::Result<AtomicTemp> {
    use std::io::Write;

    write_temp_sibling_with(final_path, |file| file.write_all(bytes))
}

fn write_temp_sibling_with<F>(final_path: &Path, operation: F) -> io::Result<AtomicTemp>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let parent = final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "blob path has no parent"))?;
    std::fs::create_dir_all(parent)?;

    // Create the temp with `create_new` (O_EXCL / CREATE_NEW), not a plain
    // write: the name is predictable (`.tmp.<pid>.<seq>`), and a plain write
    // truncates whatever sits there — including a symlink a co-located actor
    // might have pre-planted to redirect the bytes. `create_new` refuses to
    // open an existing path, so a planted target makes us fail (and retry with
    // the next seq) rather than write through it. The pid+seq makes a genuine
    // collision effectively impossible; the retry loop is belt-and-suspenders.
    loop {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".tmp.{}.{seq}", process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                let mut temp = AtomicTemp {
                    path: candidate,
                    file: Some(file),
                    moved: false,
                };
                operation(temp.file.as_mut().unwrap())?;
                return Ok(temp);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

pub(crate) fn write_atomic(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut temp = write_temp_sibling(final_path, bytes)?;
    temp.close();
    match std::fs::rename(temp.path(), final_path) {
        Ok(()) => {
            temp.mark_moved();
            Ok(())
        }
        Err(e) => {
            // Lost the race (another writer published the same content) or a
            // real failure: drop our temp either way and report the error.
            if final_path.exists() {
                Ok(()) // same content is now present; idempotent success
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use std::time::Duration;

    struct CountingReader {
        inner: std::io::Cursor<Vec<u8>>,
        bytes_requested: usize,
        max_request: usize,
    }

    impl CountingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                inner: std::io::Cursor::new(bytes),
                bytes_requested: 0,
                max_request: 0,
            }
        }

        fn bytes_requested(&self) -> usize {
            self.bytes_requested
        }

        fn max_request(&self) -> usize {
            self.max_request
        }
    }

    impl Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.bytes_requested += buf.len();
            self.max_request = self.max_request.max(buf.len());
            self.inner.read(buf)
        }
    }

    impl Seek for CountingReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    fn tmp_root() -> PathBuf {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sbz-cas-test.{}.{seq}", process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn ephemeral_parent(path: &Path) -> Dir {
        std::fs::create_dir_all(path).unwrap();
        Dir::open_ambient_dir(path, ambient_authority()).unwrap()
    }

    struct TestEphemeralOwner {
        revoker: EphemeralStoreRevoker,
        cleanup_job: Mutex<Option<EphemeralStoreCleanupJob>>,
    }

    impl TestEphemeralOwner {
        fn revoke(&self) {
            (self.revoker)();
        }

        fn close(&self) -> io::Result<()> {
            self.revoke();
            self.cleanup_job
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .expect("ephemeral cleanup job is single-use")()
        }
    }

    fn ephemeral_store() -> (PathBuf, PathBuf, BlobStore, Arc<TestEphemeralOwner>) {
        let parent_path = tmp_root();
        let root = parent_path.join("store");
        let (store, revoker, cleanup_job) =
            BlobStore::create_ephemeral(ephemeral_parent(&parent_path), "store").unwrap();
        let owner = Arc::new(TestEphemeralOwner {
            revoker,
            cleanup_job: Mutex::new(Some(cleanup_job)),
        });
        (parent_path, root, store, owner)
    }

    #[test]
    fn persistent_marker_location_skips_filesystem_root() {
        assert!(persistent_marker_location(Path::new(std::path::MAIN_SEPARATOR_STR)).is_none());
        assert!(persistent_marker_location(Path::new("nested/store")).is_some());
    }

    fn test_hook(
        store: &BlobStore,
        point: TestPoint,
        name: Option<OsString>,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (reached_tx, reached) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        store.install_test_hook(point, name, reached_tx, release_rx);
        (reached, release)
    }

    fn close_async(owner: &Arc<TestEphemeralOwner>) -> std::thread::JoinHandle<io::Result<()>> {
        let owner = Arc::clone(owner);
        std::thread::spawn(move || owner.close())
    }

    #[cfg(windows)]
    #[test]
    fn ephemeral_root_create_handle_blocks_pre_identity_replacement() {
        let parent_path = tmp_root();
        std::fs::create_dir_all(&parent_path).unwrap();
        let root_name = OsString::from("atomic-create-race");
        let root = parent_path.join(&root_name);
        let displaced = parent_path.join("displaced");
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *CREATE_ROOT_BARRIER
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(CreateRootBarrier {
            root_name: root_name.clone(),
            barrier: TestBarrier {
                reached: reached_tx,
                release: release_rx,
            },
        });

        let parent = ephemeral_parent(&parent_path);
        let creator = std::thread::spawn(move || BlobStore::create_ephemeral(parent, &root_name));
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let rename = std::fs::rename(&root, &displaced);
        if rename.is_ok() {
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("replacement-marker"), b"replacement").unwrap();
        }
        release_tx.send(()).unwrap();
        let created = creator.join().unwrap();
        drop(created);
        std::fs::remove_dir_all(&parent_path).ok();

        assert!(
            rename.is_err(),
            "the atomic create handle must block root replacement before identity capture"
        );
    }

    #[cfg(windows)]
    #[test]
    fn ephemeral_root_handle_blocks_replacement_for_active_lifetime() {
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

        let (parent_path, root, store, owner) = ephemeral_store();
        let displaced = parent_path.join("displaced-active-root");
        owner.revoke();
        let error = std::fs::rename(&root, &displaced)
            .expect_err("the retained no-share-delete root handle must reject rename");
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32),
            "active-lifetime rename must be rejected by the retained root capability"
        );

        owner.close().unwrap();
        assert!(!root.exists());
        drop((store, owner));
        std::fs::remove_dir_all(parent_path).ok();
    }

    #[test]
    fn independent_open_rejects_an_active_ephemeral_root() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let independently_opened = BlobStore::open(&root);
        let was_accepted = independently_opened.is_ok();
        drop(independently_opened);
        owner.close().unwrap();
        drop(store);
        std::fs::remove_dir_all(&parent_path).ok();

        assert!(
            !was_accepted,
            "an active ephemeral root must reject an independent BlobStore::open"
        );
    }

    #[test]
    fn constructor_failures_rollback_root_and_marker() {
        for point in [
            ConstructionFailurePoint::Identity,
            ConstructionFailurePoint::CasCreate,
            ConstructionFailurePoint::CasOpen,
            ConstructionFailurePoint::Operation,
            ConstructionFailurePoint::LifecycleLock,
        ] {
            let parent = tmp_root();
            let name = OsString::from(format!("rollback-{point:?}"));
            CONSTRUCTION_FAILURE
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((name.clone(), point));
            let result = BlobStore::create_ephemeral(ephemeral_parent(&parent), &name);
            let error = match result {
                Err(error) => Some(error.to_string()),
                Ok((store, revoke, cleanup)) => {
                    revoke();
                    cleanup().unwrap();
                    drop(store);
                    None
                }
            };
            assert!(error.is_some(), "{point:?} injection was not consumed");
            assert!(!parent.join(&name).exists(), "{point:?} root leaked");
            assert!(
                !parent.join(ephemeral_owner_marker_name(&name)).exists(),
                "{point:?} marker leaked: {error:?}"
            );
            std::fs::remove_dir_all(parent).ok();
        }
    }

    #[test]
    fn rollback_verification_failure_preserves_marker_and_replacement() {
        let parent = tmp_root();
        let name = OsString::from("rollback-verification-failure");
        CONSTRUCTION_FAILURE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((name.clone(), ConstructionFailurePoint::CasCreate));
        *ROLLBACK_VERIFICATION_FAILURE
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(name.clone());

        let error = match BlobStore::create_ephemeral(ephemeral_parent(&parent), &name) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("construction and rollback verification must fail"),
        };
        assert!(error.contains("rollback failed"), "{error}");
        assert_eq!(
            std::fs::read(parent.join(&name).join("replacement-marker")).unwrap(),
            b"replacement"
        );
        let owner_marker = parent.join(ephemeral_owner_marker_name(&name));
        assert!(
            owner_marker.exists(),
            "failed rollback must retain tombstone"
        );

        std::fs::remove_dir_all(parent.join(&name)).unwrap();
        std::fs::remove_file(owner_marker).unwrap();
        std::fs::remove_dir_all(parent).ok();
    }

    #[cfg(windows)]
    #[test]
    fn short_path_alias_cannot_bypass_ephemeral_owner_marker() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

        let parent = tmp_root();
        let name = "active-ephemeral-root-with-a-long-name";
        let root = parent.join(name);
        let (store, revoke, cleanup) =
            BlobStore::create_ephemeral(ephemeral_parent(&parent), name).unwrap();
        let input = root
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut output = vec![0u16; 32_768];
        // SAFETY: `input` is NUL-terminated and both buffers remain valid for the call.
        let len =
            unsafe { GetShortPathNameW(input.as_ptr(), output.as_mut_ptr(), output.len() as u32) };
        assert!(
            len > 0 && (len as usize) < output.len(),
            "GetShortPathNameW fixture failed"
        );
        let short = PathBuf::from(OsString::from_wide(&output[..len as usize]));
        assert_ne!(
            short.file_name(),
            root.file_name(),
            "8.3 alias fixture is unavailable"
        );

        let bypass = BlobStore::open(short);
        let accepted = bypass.is_ok();
        drop(bypass);
        revoke();
        cleanup().unwrap();
        drop(store);
        std::fs::remove_dir_all(parent).ok();
        assert!(
            !accepted,
            "8.3 alias must not bypass the long-name owner marker"
        );
    }

    #[cfg(windows)]
    #[test]
    fn file_replacement_after_enumeration_is_rejected_by_identity() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let entry_name = OsString::from("attack-file");
        let entry = root.join(&entry_name);
        let displaced = root.join("displaced-file");
        std::fs::write(&entry, b"original").unwrap();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::ChildOpen, Some(entry_name));
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        std::fs::rename(&entry, &displaced).unwrap();
        std::fs::write(&entry, b"replacement-marker").unwrap();
        release_tx.send(()).unwrap();
        let cleanup_error = closer.join().unwrap().unwrap_err();

        assert_eq!(
            cleanup_error.kind(),
            io::ErrorKind::PermissionDenied,
            "enumeration/open identity mismatch must fail before disposition"
        );
        assert_eq!(std::fs::read(&entry).unwrap(), b"replacement-marker");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"original");
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn directory_replacement_after_enumeration_is_rejected_by_identity() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let entry_name = OsString::from("attack-dir");
        let entry = root.join(&entry_name);
        let displaced = root.join("displaced-dir");
        std::fs::create_dir(&entry).unwrap();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::ChildOpen, Some(entry_name));
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        std::fs::rename(&entry, &displaced).unwrap();
        std::fs::create_dir(&entry).unwrap();
        std::fs::write(entry.join("replacement-marker"), b"replacement").unwrap();
        release_tx.send(()).unwrap();
        let cleanup_error = closer.join().unwrap().unwrap_err();

        assert_eq!(cleanup_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(entry.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(displaced.is_dir());
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn directory_replacement_before_final_delete_is_rejected_by_identity() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let entry_name = OsString::from("attack-dir-final");
        let entry = root.join(&entry_name);
        let displaced = root.join("displaced-dir-final");
        std::fs::create_dir(&entry).unwrap();
        let (reached_rx, release_tx) =
            test_hook(&store, TestPoint::ChildFinalDelete, Some(entry_name));
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        std::fs::rename(&entry, &displaced).unwrap();
        std::fs::create_dir(&entry).unwrap();
        std::fs::write(entry.join("replacement-marker"), b"replacement").unwrap();
        release_tx.send(()).unwrap();
        let cleanup_error = closer.join().unwrap().unwrap_err();

        assert_eq!(cleanup_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(entry.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(displaced.is_dir());
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reparse_child_is_rejected_without_touching_external_target() {
        use std::process::{Command, Stdio};

        let (parent_path, root, store, owner) = ephemeral_store();
        let outside = parent_path.join("outside-child-target");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("external-marker"), b"external").unwrap();
        let junction = root.join("child-junction");
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "child junction fixture must not be skipped"
        );

        let cleanup_error = owner.close().unwrap_err();
        assert_eq!(cleanup_error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(outside.join("external-marker")).unwrap(),
            b"external"
        );
        assert!(junction.exists());
        std::fs::remove_dir(&junction).unwrap();
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn successful_close_uses_retained_root_handle_for_final_disposition() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let (parent_path, root, store, owner) = ephemeral_store();
        let held_root = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root)
            .unwrap();

        let result = owner.close();
        let root_is_invisible = !root.exists();
        let held_handle_remains_valid = held_root.metadata().is_ok();

        assert!(result.is_ok(), "same-handle POSIX cleanup must succeed");
        assert!(
            root_is_invisible,
            "cleanup success requires immediate namespace invisibility"
        );
        assert!(
            held_handle_remains_valid,
            "share-delete readers may retain the unlinked directory object"
        );
        drop(held_root);
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[cfg(windows)]
    #[test]
    fn disposition_failure_keeps_root_and_owner_marker_without_name_fallback() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let marker = sibling_owner_marker(&root);
        *ROOT_DISPOSITION_FAILURE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(
            store
                .shared
                .cleanup
                .as_ref()
                .expect("failure fixture requires ephemeral cleanup")
                .identity,
        );

        let error = owner.close().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            root.is_dir(),
            "failed same-handle disposition must leak the root"
        );
        assert!(
            marker.is_file(),
            "failed same-handle disposition must retain the owner tombstone"
        );
        drop((store, owner));
        std::fs::remove_dir_all(parent_path).unwrap();
    }

    #[test]
    fn ephemeral_cleanup_state_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<EphemeralCleanup>();
        assert_send_sync::<EphemeralStoreOwnerState>();
    }

    #[test]
    fn concurrent_and_repeated_cleanup_share_one_cached_result() {
        let (parent_path, root, store, public_owner) = ephemeral_store();
        let owner = Arc::new(EphemeralStoreOwnerState {
            shared: Arc::clone(&store.shared),
        });
        let first = {
            let owner = Arc::clone(&owner);
            std::thread::spawn(move || owner.cleanup())
        };
        let second = {
            let owner = Arc::clone(&owner);
            std::thread::spawn(move || owner.cleanup())
        };

        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        assert!(
            owner.cleanup().is_ok(),
            "terminal cleanup result must be cached"
        );
        assert!(!root.exists());
        drop((store, public_owner, owner));
        std::fs::remove_dir_all(parent_path).ok();
    }

    #[test]
    fn admitted_put_finishes_after_close_starts_and_new_operations_fail() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let held = store.clone();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::BeforePut, None);
        let putter = std::thread::spawn(move || held.put(b"admitted bytes"));
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let closer = close_async(&owner);
        while store.operation().is_ok() {
            std::thread::yield_now();
        }
        let digest = Digest::of(b"admitted bytes");
        assert!(store.put(b"new put").is_err());
        assert!(store.get(&digest).is_err());
        assert!(!store.has(&digest));

        release_tx.send(()).unwrap();
        assert_eq!(putter.join().unwrap().unwrap(), digest);
        closer.join().unwrap().unwrap();
        assert!(!root.exists());
        assert!(store.put(b"stale").is_err());
        assert!(!root.exists(), "a stale clone must not recreate the root");
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[test]
    fn open_read_handle_keeps_cleanup_drained_until_release() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let digest = store.put(b"read barrier bytes").unwrap();
        let held = store.clone();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::AfterOpenRead, None);
        let reader = std::thread::spawn(move || held.get(&digest));
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let closer = close_async(&owner);
        while store.operation().is_ok() {
            std::thread::yield_now();
        }
        assert!(root.exists(), "cleanup must wait for the open read handle");
        release_tx.send(()).unwrap();
        assert_eq!(
            reader.join().unwrap().unwrap().unwrap(),
            b"read barrier bytes"
        );
        closer.join().unwrap().unwrap();
        assert!(!root.exists());
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[test]
    fn lifecycle_lock_keeps_cleanup_drained_until_release() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let held = store.clone();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::AfterLifecycleLock, None);
        let putter = std::thread::spawn(move || held.put(b"lifecycle lock bytes"));
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let closer = close_async(&owner);
        while store.operation().is_ok() {
            std::thread::yield_now();
        }
        assert!(root.exists(), "cleanup must wait for the lifecycle lock");
        release_tx.send(()).unwrap();
        putter.join().unwrap().unwrap();
        closer.join().unwrap().unwrap();
        assert!(!root.exists());
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[test]
    fn publish_temp_handle_keeps_cleanup_drained_until_release() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let held = store.clone();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::PublishTemp, None);
        let putter = std::thread::spawn(move || held.put(b"publish temp bytes"));
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let closer = close_async(&owner);
        while store.operation().is_ok() {
            std::thread::yield_now();
        }
        assert!(
            root.exists(),
            "cleanup must wait for the publish temp handle"
        );
        release_tx.send(()).unwrap();
        putter.join().unwrap().unwrap();
        closer.join().unwrap().unwrap();
        assert!(!root.exists());
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[cfg(windows)]
    #[test]
    fn operation_drops_all_handles_before_active_count_decrement() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let displaced_cas = root.join("cas-displaced");
        let held = store.clone();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::BeforeActiveDecrement, None);
        let putter = std::thread::spawn(move || held.put(b"drop-order bytes"));
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let closer = close_async(&owner);
        while store.operation().is_ok() {
            std::thread::yield_now();
        }

        std::fs::rename(root.join("cas"), &displaced_cas)
            .expect("all operation-derived handles must be gone before active count drops");
        std::fs::rename(&displaced_cas, root.join("cas")).unwrap();
        release_tx.send(()).unwrap();
        putter.join().unwrap().unwrap();
        closer.join().unwrap().unwrap();
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[cfg(windows)]
    #[test]
    fn panic_drops_all_handles_before_active_count_decrement() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let displaced_cas = root.join("cas-displaced");
        let held = store.clone();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::BeforeActiveDecrement, None);
        let panicker = std::thread::spawn(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let operation = held.operation().unwrap();
                let _lifecycle = held.lock_shared_lifecycle(&operation).unwrap();
                let digest = Digest::of(b"panic drop order");
                let shard = held.open_shard(&operation, &digest, true).unwrap().unwrap();
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                options.follow(FollowSymlinks::No);
                let _temp = shard.open_with("panic-temp", &options).unwrap();
                panic!("intentional operation unwind");
            }))
            .is_err()
        });
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let closer = close_async(&owner);
        while store.operation().is_ok() {
            std::thread::yield_now();
        }
        std::fs::rename(root.join("cas"), &displaced_cas)
            .expect("panic must drop operation-derived handles before active count drops");
        std::fs::rename(&displaced_cas, root.join("cas")).unwrap();
        release_tx.send(()).unwrap();
        assert!(panicker.join().unwrap());
        closer.join().unwrap().unwrap();
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[cfg(windows)]
    #[test]
    fn synchronous_revocation_precedes_blocking_cleanup() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::BeforeRootDisposition, None);

        owner.revoke();
        assert!(store.put(b"revoked").is_err());
        assert!(
            root.exists(),
            "synchronous revocation must not perform blocking cleanup"
        );

        let cleanup = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            root.exists(),
            "cleanup must still be pending at its barrier"
        );
        release_tx.send(()).unwrap();
        cleanup.join().unwrap().unwrap();
        assert!(!root.exists());
        drop(store);
        std::fs::remove_dir_all(&parent_path).ok();
    }

    #[cfg(windows)]
    #[test]
    fn root_replacement_after_disposition_is_not_removed_and_keeps_marker() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let marker = sibling_owner_marker(&root);
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::AfterRootDisposition, None);
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(!root.exists(), "original root must already be disposed");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("replacement-marker"), b"replacement").unwrap();
        release_tx.send(()).unwrap();
        let error = closer.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(root.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(
            marker.exists(),
            "replacement detection retains the tombstone"
        );
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn root_replacement_after_observed_absence_is_never_touched() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let marker = sibling_owner_marker(&root);
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::AfterRootNamespaceAbsent, None);
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(
            !root.exists(),
            "namespace query must already have observed absence"
        );
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("replacement-marker"), b"post-absence").unwrap();
        release_tx.send(()).unwrap();

        closer.join().unwrap().unwrap();
        assert_eq!(
            std::fs::read(root.join("replacement-marker")).unwrap(),
            b"post-absence"
        );
        assert!(
            !marker.exists(),
            "only the independently held marker is removed"
        );
        drop((store, owner));
        std::fs::remove_dir_all(parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn root_junction_replacement_at_delete_boundary_fails_closed() {
        use std::process::{Command, Stdio};

        let (parent_path, root, store, owner) = ephemeral_store();
        let outside = parent_path.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("external-marker"), b"external").unwrap();
        let marker = sibling_owner_marker(&root);
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::AfterRootDisposition, None);
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(!root.exists(), "original root must already be disposed");
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&root)
            .arg(&outside)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "junction replacement fixture must not be skipped"
        );
        release_tx.send(()).unwrap();

        assert!(closer.join().unwrap().is_err());
        assert_eq!(
            std::fs::read(outside.join("external-marker")).unwrap(),
            b"external"
        );
        assert!(root.exists(), "junction replacement must remain present");
        assert!(
            marker.exists(),
            "junction replacement retains the tombstone"
        );
        std::fs::remove_dir(&root).unwrap();
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn root_directory_symlink_replacement_at_delete_boundary_fails_closed() {
        let (parent_path, root, store, owner) = ephemeral_store();
        let outside = parent_path.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("external-marker"), b"external").unwrap();
        let marker = sibling_owner_marker(&root);
        let (reached_rx, release_tx) = test_hook(&store, TestPoint::AfterRootDisposition, None);
        let closer = close_async(&owner);
        reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(!root.exists(), "original root must already be disposed");
        std::os::windows::fs::symlink_dir(&outside, &root)
            .expect("directory symlink replacement requires Windows symlink capability");
        release_tx.send(()).unwrap();

        assert!(closer.join().unwrap().is_err());
        assert_eq!(
            std::fs::read(outside.join("external-marker")).unwrap(),
            b"external"
        );
        assert!(root.exists(), "symlink replacement must remain present");
        assert!(marker.exists(), "symlink replacement retains the tombstone");
        std::fs::remove_dir(&root).unwrap();
        drop(store);
        drop(owner);
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[test]
    fn ephemeral_creation_rejects_prepositioned_real_directory() {
        let parent_path = tmp_root();
        let root = parent_path.join("store");
        let marker = sibling_owner_marker(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("marker"), b"replacement marker").unwrap();

        assert!(BlobStore::create_ephemeral(ephemeral_parent(&parent_path), "store").is_err());
        assert_eq!(
            std::fs::read(root.join("marker")).unwrap(),
            b"replacement marker"
        );
        assert!(
            !marker.exists(),
            "root-create failure must disposition its marker by the original handle"
        );
        std::fs::remove_dir_all(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn ephemeral_creation_rejects_prepositioned_junction() {
        use std::process::{Command, Stdio};

        let parent_path = tmp_root();
        let outside = tmp_root();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("marker"), b"outside marker").unwrap();
        std::fs::create_dir_all(&parent_path).unwrap();
        let junction = parent_path.join("store");
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "junction fixture must not be skipped");

        assert!(BlobStore::create_ephemeral(ephemeral_parent(&parent_path), "store").is_err());
        assert_eq!(
            std::fs::read(outside.join("marker")).unwrap(),
            b"outside marker"
        );
        std::fs::remove_dir(&junction).unwrap();
        std::fs::remove_dir_all(&parent_path).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn ephemeral_creation_rejects_prepositioned_directory_symlink() {
        let parent_path = tmp_root();
        let outside = tmp_root();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("marker"), b"outside marker").unwrap();
        std::fs::create_dir_all(&parent_path).unwrap();
        let symlink = parent_path.join("store");
        std::os::windows::fs::symlink_dir(&outside, &symlink)
            .expect("directory symlink fixture must not be skipped");

        assert!(BlobStore::create_ephemeral(ephemeral_parent(&parent_path), "store").is_err());
        assert_eq!(
            std::fs::read(outside.join("marker")).unwrap(),
            b"outside marker"
        );
        std::fs::remove_dir(&symlink).unwrap();
        std::fs::remove_dir_all(&parent_path).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn put_get_round_trips_and_dedups() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let d1 = store.put(b"some content").unwrap();
        let d2 = store.clone().put(b"some content").unwrap();
        assert_eq!(d1, d2); // content-addressed: same bytes, same digest
        assert!(store.has(&d1));
        assert_eq!(
            store.get(&d1).unwrap().as_deref(),
            Some(&b"some content"[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn persistent_store_is_not_revoked_by_ephemeral_cleanup_authority() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();

        let digest = store.put(b"persistent data").unwrap();
        let independently_opened = BlobStore::open(&root).unwrap();
        assert_eq!(
            independently_opened.get(&digest).unwrap().as_deref(),
            Some(&b"persistent data"[..])
        );
        assert!(store.put(b"persistent remains open").is_ok());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn get_absent_is_none() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let absent = Digest::of(b"never stored");
        assert!(!store.has(&absent));
        assert!(store.get(&absent).unwrap().is_none());
        assert!(store.get_verified(&absent).unwrap().is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn get_range_covers_zero_middle_eof_exact_eof_missing_and_beyond() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(b"0123456789").unwrap();

        assert_eq!(store.get_range(&digest, 0, 0).unwrap(), Some(vec![]));
        assert_eq!(
            store.get_range(&digest, 3, 4).unwrap(),
            Some(b"3456".to_vec())
        );
        assert_eq!(
            store.get_range(&digest, 8, 8).unwrap(),
            Some(b"89".to_vec())
        );
        assert_eq!(store.get_range(&digest, 10, 1).unwrap(), Some(vec![]));
        assert_eq!(store.get_range(&digest, 11, 1).unwrap(), Some(vec![]));
        assert_eq!(
            store.get_range(&Digest::of(b"missing"), 0, 4).unwrap(),
            None
        );
        assert_eq!(
            store.get_range(&digest, 1, usize::MAX).unwrap(),
            Some(b"123456789".to_vec())
        );
        assert_eq!(
            store.get_range(&digest, u64::MAX, usize::MAX).unwrap(),
            Some(vec![])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn counting_reader_never_reads_beyond_requested_range() {
        let mut reader = CountingReader::new(vec![0x11; 1024 * 1024]);
        let bytes = read_range_from(&mut reader, 128, 4096).unwrap();
        assert_eq!(bytes.len(), 4096);
        assert_eq!(reader.bytes_requested(), 4096);
        assert!(reader.max_request() <= 4096);

        let mut short_reader = CountingReader::new(b"tiny".to_vec());
        let bytes = read_range_from(&mut short_reader, 1, usize::MAX).unwrap();
        assert_eq!(bytes, b"iny");
        assert_eq!(short_reader.bytes_requested(), 3);
        assert!(short_reader.max_request() <= 3);
    }

    #[cfg(windows)]
    #[test]
    fn open_reader_blocks_eviction_until_drop() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(b"pinned").unwrap();
        let path = store.blob_path(&digest);
        let operation = store.operation().unwrap();
        let file = store.open_blob_read(&operation, &digest).unwrap().unwrap();
        assert!(std::fs::remove_file(&path).is_err());
        drop(file);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn put_verified_rejects_forged_digest() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let lie = Digest::of(b"a different thing");
        let err = store.put_verified(b"the real bytes", &lie).unwrap_err();
        assert!(matches!(err, CasError::DigestMismatch { .. }));
        // Nothing was stored under the lie.
        assert!(!store.has(&lie));
        // The honest path works.
        let truth = Digest::of(b"the real bytes");
        assert_eq!(
            store.put_verified(b"the real bytes", &truth).unwrap(),
            truth
        );
        assert!(store.has(&truth));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn put_repairs_a_corrupt_existing_digest_entry() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"put must not trust existence";
        let digest = store.put(bytes).unwrap();
        std::fs::write(store.blob_path(&digest), b"corrupt").unwrap();

        assert_eq!(store.put(bytes).unwrap(), digest);
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&bytes[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn put_verified_repairs_a_corrupt_existing_digest_entry() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"verified put must not trust existence";
        let digest = store.put(bytes).unwrap();
        std::fs::write(store.blob_path(&digest), b"corrupt").unwrap();

        assert_eq!(store.put_verified(bytes, &digest).unwrap(), digest);
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&bytes[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn hardlink_blob_is_not_present_or_readable() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"external hardlink bytes";
        let digest = Digest::of(bytes);
        let final_path = store.blob_path(&digest);
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let external = root.join("external-hardlink-peer");
        std::fs::write(&external, bytes).unwrap();
        std::fs::hard_link(&external, &final_path).unwrap();

        assert!(!store.has(&digest));
        assert!(store.get_range(&digest, 0, bytes.len()).is_err());
        assert_eq!(std::fs::read(&external).unwrap(), bytes);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn symlink_blob_is_not_present_or_readable_when_supported() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"external symlink bytes";
        let digest = Digest::of(bytes);
        let final_path = store.blob_path(&digest);
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let external = root.join("external-symlink-target");
        std::fs::write(&external, bytes).unwrap();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&external, &final_path);
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&external, &final_path);
        if let Err(error) = linked {
            #[cfg(windows)]
            if error.raw_os_error() == Some(1314) {
                std::fs::remove_dir_all(&root).ok();
                return;
            }
            panic!("failed to create test symlink: {error}");
        }

        assert!(!store.has(&digest));
        assert!(store.get_range(&digest, 0, bytes.len()).is_err());
        assert_eq!(std::fs::read(&external).unwrap(), bytes);
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn parent_junction_escape_is_not_readable_when_supported() {
        use std::process::{Command, Stdio};

        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"junction escape bytes";
        let digest = Digest::of(bytes);
        let outside_algo = root.join("outside-algo");
        let outside_blob = outside_algo.join(&digest.hex()[0..2]).join(digest.hex());
        std::fs::create_dir_all(outside_blob.parent().unwrap()).unwrap();
        std::fs::write(&outside_blob, bytes).unwrap();
        let junction = store.cas_root.join("blake3");
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside_algo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if !status.success() {
            std::fs::remove_dir_all(&root).ok();
            return;
        }

        assert!(store.get_range(&digest, 0, bytes.len()).is_err());
        assert_eq!(std::fs::read(&outside_blob).unwrap(), bytes);
        std::fs::remove_dir(&junction).unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn get_verified_detects_tampering() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let d = store.put(b"original").unwrap();
        // Tamper with the on-disk blob behind the store's back.
        let path = store.blob_path(&d);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(matches!(
            store.get_verified(&d).unwrap_err(),
            CasError::Corrupt { .. }
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    fn hydrate_temp_siblings(store: &BlobStore, digest: &Digest) -> Vec<PathBuf> {
        let parent = store.blob_path(digest).parent().unwrap().to_path_buf();
        read_dir_some(&parent)
            .unwrap()
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".tmp."))
            })
            .collect()
    }

    #[test]
    fn repair_verified_replaces_corrupt_blob_without_temp_residue() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"verified repair bytes";
        let digest = store.put(correct).unwrap();
        std::fs::write(store.blob_path(&digest), b"corrupt").unwrap();

        assert_eq!(store.repair_verified(correct, &digest).unwrap(), digest);
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&correct[..])
        );
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn repair_verified_creates_a_missing_blob() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"verified missing repair";
        let digest = Digest::of(correct);
        assert!(!store.has(&digest));

        assert_eq!(store.repair_verified(correct, &digest).unwrap(), digest);
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&correct[..])
        );
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn publish_rejects_temp_swapped_to_a_hardlink() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"secure publish hardlink swap";
        let digest = Digest::of(bytes);
        let external = root.join("publish-hardlink-peer");
        std::fs::write(&external, b"external peer stays unchanged").unwrap();

        let result = store.publish_cas_blob_with_hooks(
            bytes,
            &digest,
            |temp| {
                std::fs::remove_file(temp)?;
                std::fs::hard_link(&external, temp)
            },
            |_| Ok(()),
        );

        assert!(result.is_err());
        assert!(!store.blob_path(&digest).exists());
        assert_eq!(
            std::fs::read(&external).unwrap(),
            b"external peer stays unchanged"
        );
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn publish_rejects_temp_swapped_to_a_different_regular_file() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"secure publish regular swap";
        let digest = Digest::of(bytes);

        let result = store.publish_cas_blob_with_hooks(
            bytes,
            &digest,
            |temp| {
                std::fs::remove_file(temp)?;
                std::fs::write(temp, b"different file object")
            },
            |_| Ok(()),
        );

        assert!(result.is_err());
        assert!(!store.blob_path(&digest).exists());
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn publish_rejects_temp_swapped_to_a_symlink_when_supported() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"secure publish symlink swap";
        let digest = Digest::of(bytes);
        let external = root.join("publish-symlink-target");
        std::fs::write(&external, b"external symlink target stays unchanged").unwrap();
        let mut unsupported = false;

        let result = store.publish_cas_blob_with_hooks(
            bytes,
            &digest,
            |temp| {
                std::fs::remove_file(temp)?;
                #[cfg(windows)]
                let linked = std::os::windows::fs::symlink_file(&external, temp);
                #[cfg(unix)]
                let linked = std::os::unix::fs::symlink(&external, temp);
                match linked {
                    Err(error) if cfg!(windows) && error.raw_os_error() == Some(1314) => {
                        unsupported = true;
                        Err(error)
                    }
                    result => result,
                }
            },
            |_| Ok(()),
        );
        if unsupported {
            std::fs::remove_dir_all(&root).ok();
            return;
        }

        assert!(result.is_err());
        assert!(!store.blob_path(&digest).exists());
        assert_eq!(
            std::fs::read(&external).unwrap(),
            b"external symlink target stays unchanged"
        );
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn post_publish_identity_failure_removes_only_the_final_entry() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let bytes = b"secure post-publish verification";
        let digest = Digest::of(bytes);
        let external = root.join("post-publish-hardlink-peer");
        std::fs::write(&external, b"peer must not be mutated").unwrap();

        let result = store.publish_cas_blob_with_hooks(
            bytes,
            &digest,
            |_| Ok(()),
            |final_path| {
                std::fs::remove_file(final_path)?;
                std::fs::hard_link(&external, final_path)
            },
        );

        assert!(result.is_err());
        assert!(!store.blob_path(&digest).exists());
        assert_eq!(
            std::fs::read(&external).unwrap(),
            b"peer must not be mutated"
        );
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn temp_writer_error_removes_partial_sibling() {
        use std::io::Write;

        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = Digest::of(b"temp writer error");
        let final_path = store.blob_path(&digest);
        let result = write_temp_sibling_with(&final_path, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected temp write error"))
        });
        assert!(result.is_err());
        assert!(!final_path.exists());
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn temp_writer_panic_removes_partial_sibling() {
        use std::io::Write;
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = Digest::of(b"temp writer panic");
        let final_path = store.blob_path(&digest);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = write_temp_sibling_with(&final_path, |file| {
                file.write_all(b"partial")?;
                panic!("injected temp write panic")
            });
        }));
        assert!(panic.is_err());
        assert!(!final_path.exists());
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn repair_verified_rejects_mismatch_without_touching_existing_blob() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(b"claimed bytes").unwrap();
        let path = store.blob_path(&digest);
        std::fs::write(&path, b"existing corrupt bytes").unwrap();

        let error = store
            .repair_verified(b"different repair bytes", &digest)
            .unwrap_err();
        assert!(matches!(error, CasError::DigestMismatch { .. }));
        assert_eq!(std::fs::read(path).unwrap(), b"existing corrupt bytes");
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn repair_verified_does_not_tear_an_open_reader() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"correct after reader closes";
        let digest = store.put(correct).unwrap();
        std::fs::write(store.blob_path(&digest), b"old corrupt bytes").unwrap();
        let operation = store.operation().unwrap();
        let mut reader = store.open_blob_read(&operation, &digest).unwrap().unwrap();

        assert!(store.repair_verified(correct, &digest).is_err());
        let mut observed = Vec::new();
        reader.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, b"old corrupt bytes");
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());

        drop(reader);
        store.repair_verified(correct, &digest).unwrap();
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&correct[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn concurrent_repairs_converge_to_verified_bytes() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"one convergent repair".to_vec();
        let digest = store.put(&correct).unwrap();
        for round in 0..16 {
            std::fs::write(store.blob_path(&digest), format!("corrupt round {round}")).unwrap();
            let start = std::sync::Arc::new(std::sync::Barrier::new(9));
            let mut threads = Vec::new();
            for index in 0..8 {
                let store = if index % 2 == 0 {
                    store.clone()
                } else {
                    BlobStore::open(&root).unwrap()
                };
                let digest = digest.clone();
                let correct = correct.clone();
                let start = std::sync::Arc::clone(&start);
                threads.push(std::thread::spawn(move || {
                    start.wait();
                    store.repair_verified(&correct, &digest)
                }));
            }
            start.wait();
            let mut results = Vec::new();
            for thread in threads {
                results.push(thread.join().unwrap());
            }
            assert!(
                results.iter().all(Result::is_ok),
                "all concurrent repairs should observe the verified final blob in round {round}: {results:?}"
            );
        }
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(correct.as_slice())
        );
        assert!(hydrate_temp_siblings(&store, &digest).is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn poisoned_repair_serialization_recovers() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = REPAIR_CRITICAL_SECTION.lock().unwrap();
            panic!("inject repair mutex poison")
        }));
        assert!(poisoned.is_err());

        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"repair after poison";
        let digest = store.put(correct).unwrap();
        std::fs::write(store.blob_path(&digest), b"corrupt").unwrap();
        assert_eq!(store.repair_verified(correct, &digest).unwrap(), digest);
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&correct[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn repair_verified_replaces_only_the_hardlink_entry() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"hardlink repair bytes";
        let digest = Digest::of(correct);
        let final_path = store.blob_path(&digest);
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let outside = root.join("outside-hardlink-target");
        std::fs::write(&outside, b"hardlink target must stay corrupt").unwrap();
        std::fs::hard_link(&outside, &final_path).unwrap();

        store.repair_verified(correct, &digest).unwrap();
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"hardlink target must stay corrupt"
        );
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&correct[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn repair_verified_replaces_only_the_symlink_entry_when_supported() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let correct = b"symlink repair bytes";
        let digest = Digest::of(correct);
        let final_path = store.blob_path(&digest);
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let outside = root.join("outside-symlink-target");
        std::fs::write(&outside, b"symlink target must stay corrupt").unwrap();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside, &final_path);
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside, &final_path);
        if let Err(error) = linked {
            #[cfg(windows)]
            if error.raw_os_error() == Some(1314) {
                std::fs::remove_dir_all(&root).ok();
                return;
            }
            panic!("failed to create test symlink: {error}");
        }

        store.repair_verified(correct, &digest).unwrap();
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"symlink target must stay corrupt"
        );
        assert_eq!(
            store.get_verified(&digest).unwrap().as_deref(),
            Some(&correct[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn listing_ignores_malformed_unknown_and_symlink_entries() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(b"abc").unwrap();
        let legitimate = store.blob_path(&digest);
        let shard = legitimate.parent().unwrap();
        let temp = shard.join(".tmp.attacker.1");
        std::fs::write(&temp, vec![0u8; 101]).unwrap();
        let malformed_temps = [
            ".tmp.01.2",
            ".tmp.1.02",
            ".tmp.1.2.3",
            ".tmp.4294967296.1",
            ".tmp.1.18446744073709551616",
            ".tmp..1",
            ".tmp.1.",
        ]
        .map(|name| shard.join(name));
        for malformed in &malformed_temps {
            std::fs::write(malformed, vec![0u8; 101]).unwrap();
        }
        std::fs::write(shard.join("A".repeat(64)), vec![0u8; 102]).unwrap();
        std::fs::write(shard.join(format!("ff{}", "0".repeat(62))), vec![0u8; 103]).unwrap();
        let unknown = store
            .cas_root
            .join("unknown")
            .join("00")
            .join("0".repeat(64));
        std::fs::create_dir_all(unknown.parent().unwrap()).unwrap();
        std::fs::write(&unknown, vec![0u8; 104]).unwrap();

        let hardlink_digest = Digest::of(b"hardlink listing entry");
        let hardlink = store.blob_path(&hardlink_digest);
        std::fs::create_dir_all(hardlink.parent().unwrap()).unwrap();
        let hardlink_target = root.join("outside-listing-hardlink-target");
        std::fs::write(&hardlink_target, vec![0u8; 106]).unwrap();
        std::fs::hard_link(&hardlink_target, &hardlink).unwrap();

        let symlink_digest = Digest::of(b"symlink listing entry");
        let symlink = store.blob_path(&symlink_digest);
        std::fs::create_dir_all(symlink.parent().unwrap()).unwrap();
        let outside = root.join("outside-listing-target");
        std::fs::write(&outside, vec![0u8; 105]).unwrap();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside, &symlink);
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside, &symlink);
        let temp_symlink = shard.join(".tmp.1.2");
        #[cfg(windows)]
        let linked_temp = std::os::windows::fs::symlink_file(&outside, &temp_symlink);
        #[cfg(unix)]
        let linked_temp = std::os::unix::fs::symlink(&outside, &temp_symlink);

        let operation = store.operation().unwrap();
        let listed = store.list_entries(&operation).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed.iter().any(|entry| entry.path == legitimate));
        assert!(!store.has(&hardlink_digest));
        assert_eq!(store.total_size().unwrap(), 3);
        assert_eq!(store.evict_to(0).unwrap(), 3);
        assert!(
            temp.exists(),
            "temporary-looking files are not eviction targets"
        );
        assert!(malformed_temps.iter().all(|path| path.exists()));
        assert!(
            hardlink.exists(),
            "invalid hardlink entries are not CAS eviction targets"
        );
        assert_eq!(std::fs::read(&hardlink_target).unwrap(), vec![0u8; 106]);
        assert_eq!(std::fs::read(&outside).unwrap(), vec![0u8; 105]);
        if linked.is_ok() {
            assert!(symlink.symlink_metadata().unwrap().file_type().is_symlink());
        }
        if linked_temp.is_ok() {
            assert!(
                temp_symlink
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn crash_shaped_valid_temp_is_counted_and_evicted() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let shard = store.cas_root.join("blake3").join("aa");
        std::fs::create_dir_all(&shard).unwrap();
        let stale = shard.join(".tmp.123.456");
        std::fs::write(&stale, vec![0u8; 64]).unwrap();

        assert_eq!(store.total_size().unwrap(), 64);
        assert_eq!(store.evict_to(0).unwrap(), 64);
        assert!(!stale.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn eviction_reclaims_temp_before_blob() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(&[0u8; 100]).unwrap();
        let stale = store.blob_path(&digest).parent().unwrap().join(".tmp.7.8");
        std::fs::write(&stale, vec![0u8; 10]).unwrap();

        assert_eq!(store.total_size().unwrap(), 110);
        assert_eq!(store.evict_to(100).unwrap(), 10);
        assert!(!stale.exists());
        assert!(store.has(&digest));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn eviction_waits_for_a_shared_writer_lifecycle_lock() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(b"eviction lock blob").unwrap();
        let operation = store.operation().unwrap();
        let writer_lock = store.lock_shared_lifecycle(&operation).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let evicting_store = store.clone();
        let evictor = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = evicting_store.evict_to(0);
            finished_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        let probe = store.open_lifecycle_lock(&operation).unwrap();
        assert!(
            probe.try_lock().is_err(),
            "exclusive eviction lock must conflict with a live shared writer"
        );
        assert!(matches!(
            finished_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(store.has(&digest));

        drop(writer_lock);
        assert_eq!(
            finished_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap(),
            18
        );
        evictor.join().unwrap();
        assert!(!store.has(&digest));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn two_shared_writer_locks_do_not_serialize_each_other() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let operation = store.operation().unwrap();
        let first = store.lock_shared_lifecycle(&operation).unwrap();
        let second_store = store.clone();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            let operation = second_store.operation().unwrap();
            let lock = second_store.lock_shared_lifecycle(&operation).unwrap();
            acquired_tx.send(()).unwrap();
            lock
        });

        acquired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a second shared writer lock must acquire while the first is held");
        drop(first);
        drop(second.join().unwrap());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn writer_waits_for_an_exclusive_eviction_lifecycle_lock() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let operation = store.operation().unwrap();
        let eviction_lock = store.lock_exclusive_lifecycle(&operation).unwrap();
        let writer_store = store.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(writer_store.put(b"blocked writer"))
                .unwrap();
        });

        started_rx.recv().unwrap();
        let probe = store.open_lifecycle_lock(&operation).unwrap();
        assert!(
            probe.try_lock_shared().is_err(),
            "shared writer lock must conflict with a live exclusive eviction"
        );
        assert!(matches!(
            finished_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(matches!(
            finished_rx.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        drop(eviction_lock);
        let digest = finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        assert_eq!(
            store.get(&digest).unwrap().as_deref(),
            Some(&b"blocked writer"[..])
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    #[ignore]
    fn lifecycle_crash_child_fixture() {
        let root = std::env::var_os("SEMBAZURU_CAS_CRASH_ROOT")
            .expect("crash fixture requires a CAS root");
        let store = BlobStore::open(root).unwrap();
        let operation = store.operation().unwrap();
        let _lock = store.lock_shared_lifecycle(&operation).unwrap();
        let digest = Digest::of(b"crash temp payload");
        let _temp = write_temp_sibling(&store.blob_path(&digest), b"crash temp payload").unwrap();
        process::exit(0);
    }

    #[test]
    fn crashed_writer_releases_os_lock_and_leaves_reclaimable_temp() {
        use std::process::{Command, Stdio};

        let root = tmp_root();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "store::tests::lifecycle_crash_child_fixture",
            ])
            .env("SEMBAZURU_CAS_CRASH_ROOT", &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

        let store = BlobStore::open(&root).unwrap();
        assert_eq!(store.total_size().unwrap(), 18);
        assert_eq!(store.evict_to(0).unwrap(), 18);
        assert_eq!(store.total_size().unwrap(), 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn has_batch_matches_individual() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let a = store.put(b"aaa").unwrap();
        let b = Digest::of(b"bbb"); // not stored
        let c = store.put(b"ccc").unwrap();
        assert_eq!(store.has_batch(&[a, b, c]), vec![true, false, true]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn empty_blob_round_trips() {
        // A zero-length blob is a valid digest (BLAKE3 of ""), and must store,
        // read back, and not perturb size accounting / eviction.
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let d = store.put(b"").unwrap();
        assert!(store.has(&d));
        assert_eq!(store.get(&d).unwrap().as_deref(), Some(&b""[..]));
        assert_eq!(store.get_verified(&d).unwrap().as_deref(), Some(&b""[..]));
        // Size accounting tolerates the zero-length file.
        let _ = store.total_size().unwrap();
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn evict_to_drops_blobs_until_under_cap() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        // Three 1000-byte blobs = 3000 bytes total.
        let _a = store.put(&vec![1u8; 1000]).unwrap();
        let _b = store.put(&vec![2u8; 1000]).unwrap();
        let _c = store.put(&vec![3u8; 1000]).unwrap();
        assert_eq!(store.total_size().unwrap(), 3000);

        let freed = store.evict_to(1500).unwrap();
        assert!(freed >= 1500, "freed {freed}");
        assert!(store.total_size().unwrap() <= 1500);

        // Under cap: a no-op.
        assert_eq!(store.evict_to(10_000).unwrap(), 0);
        std::fs::remove_dir_all(&root).ok();
    }

    fn sibling_owner_marker(root: &Path) -> PathBuf {
        let mut name = root.file_name().unwrap().to_os_string();
        name.push(".ephemeral-owner.lock");
        root.with_file_name(name)
    }

    fn named_barrier(
        slot: &Mutex<Option<CreateRootBarrier>>,
        name: &OsStr,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(CreateRootBarrier {
            root_name: name.to_os_string(),
            barrier: TestBarrier {
                reached: reached_tx,
                release: release_rx,
            },
        });
        (reached_rx, release_tx)
    }

    #[cfg(windows)]
    fn put_parser_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    #[cfg(windows)]
    #[test]
    fn file_id_extd_parser_accepts_unaligned_buffer_and_root_traversal() {
        use windows_sys::Win32::Storage::FileSystem::{FILE_ID_EXTD_DIR_INFO, FILE_TRAVERSE};
        let header = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
        let mut storage = vec![0u8; header + 3];
        let record = &mut storage[1..];
        put_parser_u32(
            record,
            std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileNameLength),
            2,
        );
        record[header..].copy_from_slice(&u16::from(b'x').to_ne_bytes());
        let parsed = parse_file_id_extd_directory_buffer(record, 7).unwrap();
        assert_eq!(
            (
                parsed.len(),
                parsed[0].name.as_os_str(),
                parsed[0].identity.volume
            ),
            (1, OsStr::new("x"), 7)
        );
        assert_ne!(ephemeral_root_desired_access() & FILE_TRAVERSE, 0);
    }

    #[cfg(windows)]
    #[test]
    fn file_id_extd_parser_rejects_malformed_spans() {
        use windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO;
        assert!(
            !valid_file_id_next_offset(0, 92, 88, 90, 256),
            "unaligned next"
        );
        assert!(!valid_file_id_next_offset(0, 88, 88, 90, 256), "overlap");
        let header = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
        let mut bytes = vec![0u8; header];
        assert!(parse_file_id_extd_directory_buffer(&bytes[..header - 1], 0).is_err());
        put_parser_u32(
            &mut bytes,
            std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileNameLength),
            2,
        );
        assert!(
            parse_file_id_extd_directory_buffer(&bytes, 0).is_err(),
            "truncated name"
        );
    }

    #[test]
    fn sibling_marker_linearizes_constructor_and_open() {
        let parent = tmp_root();
        std::fs::create_dir_all(&parent).unwrap();
        let pre_name = OsString::from("marker-pre");
        let pre_root = parent.join(&pre_name);
        let (reached, release) = named_barrier(&BEFORE_ROOT_CREATE_BARRIER, &pre_name);
        let pre_parent = ephemeral_parent(&parent);
        let creator = std::thread::spawn(move || BlobStore::create_ephemeral(pre_parent, pre_name));
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            sibling_owner_marker(&pre_root).exists(),
            "marker precedes root"
        );
        assert!(
            BlobStore::open(&pre_root).is_err(),
            "pre-create open rejected"
        );
        release.send(()).unwrap();
        drop(creator.join().unwrap());

        let post_name = OsString::from("marker-post");
        let post_root = parent.join(&post_name);
        let (open_reached, open_release) = named_barrier(&OPEN_MARKER_RECHECK_BARRIER, &post_name);
        let open_path = post_root.clone();
        let opener = std::thread::spawn(move || BlobStore::open(open_path));
        open_reached.recv_timeout(Duration::from_secs(5)).unwrap();
        let (create_reached, create_release) =
            named_barrier(&BEFORE_ROOT_CREATE_BARRIER, &post_name);
        let post_parent = ephemeral_parent(&parent);
        let creator =
            std::thread::spawn(move || BlobStore::create_ephemeral(post_parent, post_name));
        create_reached.recv_timeout(Duration::from_secs(5)).unwrap();
        open_release.send(()).unwrap();
        assert!(opener.join().unwrap().is_err(), "post-open recheck");
        create_release.send(()).unwrap();
        assert!(creator.join().unwrap().is_err(), "existing root wins");
        std::fs::remove_dir_all(parent).ok();
    }

    #[cfg(windows)]
    #[test]
    fn sibling_marker_covers_closing_and_failed_cleanup() {
        let (parent, root, store, owner) = ephemeral_store();
        let (reached, release) = test_hook(&store, TestPoint::BeforeRootDisposition, None);
        let closer = close_async(&owner);
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(BlobStore::open(&root).is_err(), "Closing marker");
        release.send(()).unwrap();
        closer.join().unwrap().unwrap();
        drop((store, owner));
        std::fs::remove_dir_all(parent).ok();

        let (parent, root, store, owner) = ephemeral_store();
        let (reached, release) = test_hook(&store, TestPoint::AfterRootDisposition, None);
        let closer = close_async(&owner);
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!root.exists(), "original root must already be disposed");
        std::fs::create_dir(&root).unwrap();
        release.send(()).unwrap();
        assert!(closer.join().unwrap().is_err());
        assert!(BlobStore::open(&root).is_err(), "Failed marker tombstone");
        drop((store, owner));
        std::fs::remove_dir_all(parent).ok();
    }

    #[test]
    fn sibling_marker_success_removal_and_case_alias() {
        let (parent, root, store, owner) = ephemeral_store();
        let marker = sibling_owner_marker(&root);
        assert!(marker.exists());
        #[cfg(windows)]
        assert!(BlobStore::open(parent.join("STORE")).is_err(), "case alias");
        owner.close().unwrap();
        assert!(!marker.exists());
        assert!(BlobStore::open(&root).is_ok(), "persistent reopen");
        drop((store, owner));
        std::fs::remove_dir_all(parent).ok();
    }

    #[cfg(windows)]
    #[test]
    fn write_capability_is_excluded_at_delete_boundaries() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let writer = |path: &Path| {
            std::fs::OpenOptions::new()
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path)
        };

        let (parent, root, store, owner) = ephemeral_store();
        let name = OsString::from("held-writer");
        let entry = root.join(&name);
        std::fs::write(&entry, b"held").unwrap();
        let dir = store
            .shared
            .cleanup
            .as_ref()
            .expect("writer-boundary fixture requires ephemeral cleanup")
            .root
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .expect("original root capability remains retained")
            .try_clone()
            .unwrap();
        let file = dir.open(&name).unwrap().into_std();
        let identity = platform_handle_identity_and_attributes(&file).unwrap().0;
        drop(file);
        let held = writer(&entry).unwrap();
        assert!(
            delete_entry_identity_bound(&dir, &name, identity, false, None).is_err(),
            "pre-writer"
        );
        drop((held, dir));
        std::fs::remove_file(&entry).unwrap();
        owner.close().unwrap();
        drop((store, owner));
        std::fs::remove_dir_all(parent).ok();

        let (parent, root, store, owner) = ephemeral_store();
        let name = OsString::from("query-window");
        let entry = root.join(&name);
        std::fs::write(&entry, b"bound").unwrap();
        let (reached, release) = test_hook(&store, TestPoint::ChildDeleteQuery, Some(name));
        let closer = close_async(&owner);
        reached.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(writer(&entry).is_err(), "query/disposition window");
        release.send(()).unwrap();
        closer.join().unwrap().unwrap();
        assert!(!root.exists());
        drop((store, owner));
        std::fs::remove_dir_all(parent).ok();
    }
}
