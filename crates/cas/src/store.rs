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

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
#[derive(Clone)]
pub struct BlobStore {
    #[cfg(test)]
    cas_root: PathBuf,
    cas_dir: Arc<Dir>,
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
        std::fs::create_dir_all(root.as_ref())?;
        let root_dir = Dir::open_ambient_dir(root.as_ref(), ambient_authority())?;
        match root_dir.create_dir("cas") {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let cas_dir = Arc::new(root_dir.open_dir_nofollow("cas")?);
        let store = BlobStore {
            #[cfg(test)]
            cas_root: root.as_ref().join("cas"),
            cas_dir,
        };
        drop(store.open_lifecycle_lock()?);
        Ok(store)
    }

    fn open_lifecycle_lock(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        self.cas_dir
            .open_with(LIFECYCLE_LOCK_NAME, &options)
            .map(cap_std::fs::File::into_std)
    }

    fn lock_shared_lifecycle(&self) -> io::Result<LifecycleLock> {
        let file = self.open_lifecycle_lock()?;
        file.lock_shared()?;
        Ok(LifecycleLock { file })
    }

    fn lock_exclusive_lifecycle(&self) -> io::Result<LifecycleLock> {
        let file = self.open_lifecycle_lock()?;
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

    fn open_shard(&self, digest: &Digest, create: bool) -> io::Result<Option<Arc<Dir>>> {
        let (shard_rel, _) = self.shard_rel_and_name(digest);
        if create {
            self.cas_dir.create_dir_all(&shard_rel)?;
        }
        match self.cas_dir.open_dir_nofollow(&shard_rel) {
            Ok(dir) => Ok(Some(Arc::new(dir))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Stores `bytes`, returning their digest. Idempotent: if the content is
    /// already present, no write happens (content addressing means an existing
    /// blob at this digest has identical bytes).
    pub fn put(&self, bytes: &[u8]) -> io::Result<Digest> {
        let digest = Digest::of(bytes);
        self.store_digest_known(bytes, &digest)?;
        Ok(digest)
    }

    /// Stores worker-returned `bytes` only if they actually hash to `claimed`.
    /// This is the trust boundary (`docs/protocol/v0.md` §5): agents treat
    /// worker outputs as untrusted until digest-verified, so a forged or
    /// corrupted blob is rejected before it can occupy a valid address.
    pub fn put_verified(&self, bytes: &[u8], claimed: &Digest) -> Result<Digest, CasError> {
        let actual = Digest::of(bytes);
        if &actual != claimed {
            return Err(CasError::DigestMismatch {
                claimed: claimed.clone(),
                actual,
            });
        }
        self.store_digest_known(bytes, &actual)?;
        Ok(actual)
    }

    /// Replaces a corrupt blob with digest-verified bytes without exposing a
    /// partially written final path. Unlike [`BlobStore::put_verified`], this
    /// operation deliberately replaces an existing entry and verifies the
    /// resulting final path before reporting success.
    pub fn repair_verified(&self, bytes: &[u8], claimed: &Digest) -> Result<Digest, CasError> {
        let actual = Digest::of(bytes);
        if &actual != claimed {
            return Err(CasError::DigestMismatch {
                claimed: claimed.clone(),
                actual,
            });
        }

        self.store_digest_known(bytes, &actual)?;
        Ok(actual)
    }

    fn store_digest_known(&self, bytes: &[u8], digest: &Digest) -> io::Result<()> {
        let _repair_guard = REPAIR_CRITICAL_SECTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _lifecycle = self.lock_shared_lifecycle()?;
        match self.get_verified(digest) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(CasError::Corrupt { .. }) | Err(CasError::Io(_)) => {
                self.remove_blob_entry(digest)?;
            }
            Err(error) => return Err(io::Error::other(error)),
        }
        self.publish_cas_blob(bytes, digest)
    }

    fn remove_blob_entry(&self, digest: &Digest) -> io::Result<()> {
        let Some(shard) = self.open_shard(digest, false)? else {
            return Ok(());
        };
        let (_, name) = self.shard_rel_and_name(digest);
        match shard.remove_file(&name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn publish_cas_blob(&self, bytes: &[u8], digest: &Digest) -> io::Result<()> {
        #[cfg(test)]
        {
            self.publish_cas_blob_impl(bytes, digest, None)
        }
        #[cfg(not(test))]
        {
            self.publish_cas_blob_impl(bytes, digest)
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
        let mut hooks = PublishTestHooks {
            before_publish: &mut before_publish,
            after_publish: &mut after_publish,
        };
        self.publish_cas_blob_impl(bytes, digest, Some(&mut hooks))
    }

    fn publish_cas_blob_impl(
        &self,
        bytes: &[u8],
        digest: &Digest,
        #[cfg(test)] mut hooks: Option<&mut PublishTestHooks<'_>>,
    ) -> io::Result<()> {
        use std::io::Write;

        let shard = self.open_shard(digest, true)?.ok_or_else(|| {
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
        let Some(mut file) = self.open_blob_read(digest)? else {
            return Ok(None);
        };
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
        let Some(mut file) = self.open_blob_read(digest)? else {
            return Ok(None);
        };
        read_range_from(&mut file, offset, len).map(Some)
    }

    fn open_blob_read(&self, digest: &Digest) -> io::Result<Option<File>> {
        let Some(shard) = self.open_shard(digest, false)? else {
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
        let Some(bytes) = self.get(digest)? else {
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
        self.open_blob_read(digest).is_ok_and(|file| file.is_some())
    }

    /// Presence of many digests in one call, in request order — the local side
    /// of the `Has(digests[])` batch probe (`docs/protocol/v0.md` §4.3) that
    /// lets the data plane skip transferring blobs the peer already holds.
    pub fn has_batch(&self, digests: &[Digest]) -> Vec<bool> {
        digests.iter().map(|d| self.has(d)).collect()
    }

    /// Instantaneous total bytes occupied by blobs and canonical temp siblings.
    /// Writers intentionally share the lifecycle lock, so this measurement does
    /// not lock: an in-progress temp may grow while metadata is sampled.
    pub fn total_size(&self) -> io::Result<u64> {
        let mut total = 0u64;
        for entry in self.list_entries()? {
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
        let _lifecycle = self.lock_exclusive_lifecycle()?;
        let mut entries = self.list_entries()?;
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
    fn list_entries(&self) -> io::Result<Vec<StoreEntry>> {
        let mut out = Vec::new();
        let algo_name = "blake3";
        let algo_dir = match self.cas_dir.open_dir_nofollow(algo_name) {
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
    let ok = unsafe {
        GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr())
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
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
        let file = store.open_blob_read(&digest).unwrap().unwrap();
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
        let mut reader = store.open_blob_read(&digest).unwrap().unwrap();

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

        let listed = store.list_entries().unwrap();
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
        let writer_lock = store.lock_shared_lifecycle().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let evicting_store = store.clone();
        let evictor = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = evicting_store.evict_to(0);
            finished_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        let probe = store.open_lifecycle_lock().unwrap();
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
        let first = store.lock_shared_lifecycle().unwrap();
        let second_store = store.clone();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            let lock = second_store.lock_shared_lifecycle().unwrap();
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
        let eviction_lock = store.lock_exclusive_lifecycle().unwrap();
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
        let probe = store.open_lifecycle_lock().unwrap();
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
        let _lock = store.lock_shared_lifecycle().unwrap();
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
}
