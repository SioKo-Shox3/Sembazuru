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
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Digest, DigestError};

/// Monotonic counter making temp filenames unique within this process; combined
/// with the pid it is unique across processes sharing one store, so concurrent
/// puts of the same blob never collide on their temp files.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
static REPAIR_CRITICAL_SECTION: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    cas_root: PathBuf,
}

impl BlobStore {
    /// Opens (creating if needed) a store under `root`. Blobs live in
    /// `root/cas/`; the action cache (M4.3) will use `root/ac/` alongside.
    pub fn open(root: impl AsRef<Path>) -> io::Result<BlobStore> {
        let cas_root = root.as_ref().join("cas");
        std::fs::create_dir_all(&cas_root)?;
        Ok(BlobStore { cas_root })
    }

    /// The final on-disk path for a digest. Safe because `digest.hex()` is
    /// validated lowercase hex of fixed length (no separators, no `..`).
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        let hex = digest.hex();
        self.cas_root
            .join(algo_dir(digest))
            .join(&hex[0..2])
            .join(hex)
    }

    /// Stores `bytes`, returning their digest. Idempotent: if the content is
    /// already present, no write happens (content addressing means an existing
    /// blob at this digest has identical bytes).
    pub fn put(&self, bytes: &[u8]) -> io::Result<Digest> {
        let digest = Digest::of(bytes);
        let path = self.blob_path(&digest);
        if path.exists() {
            return Ok(digest);
        }
        write_atomic(&path, bytes)?;
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
        let path = self.blob_path(&actual);
        if !path.exists() {
            write_atomic(&path, bytes)?;
        }
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

        let _repair_guard = REPAIR_CRITICAL_SECTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.get_verified(claimed) {
            Ok(Some(_)) => return Ok(actual),
            Ok(None) | Err(CasError::Corrupt { .. }) => {}
            Err(error) => return Err(error),
        }

        let final_path = self.blob_path(claimed);
        let mut temp = write_temp_sibling(&final_path, bytes)?;
        temp.close();
        let replace_error = match replace_atomic(temp.path(), &final_path) {
            Ok(()) => {
                temp.mark_moved();
                None
            }
            Err(error) => Some(error),
        };

        match self.get_verified(claimed) {
            Ok(Some(_)) => Ok(actual),
            Ok(None) => Err(CasError::Io(replace_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "repaired CAS blob disappeared before verification",
                )
            }))),
            Err(error) => Err(replace_error.map_or(error, CasError::Io)),
        }
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
        match open_read_only(&self.blob_path(digest)) {
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
        self.blob_path(digest).exists()
    }

    /// Presence of many digests in one call, in request order — the local side
    /// of the `Has(digests[])` batch probe (`docs/protocol/v0.md` §4.3) that
    /// lets the data plane skip transferring blobs the peer already holds.
    pub fn has_batch(&self, digests: &[Digest]) -> Vec<bool> {
        digests.iter().map(|d| self.has(d)).collect()
    }

    /// Total bytes occupied by stored blobs.
    pub fn total_size(&self) -> io::Result<u64> {
        let mut total = 0u64;
        for (_, size, _) in self.list_blobs()? {
            total += size;
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
        let mut blobs = self.list_blobs()?;
        let mut total: u64 = blobs.iter().map(|(_, s, _)| *s).sum();
        if total <= max_bytes {
            return Ok(0);
        }
        // Oldest first.
        blobs.sort_by_key(|(_, _, mtime)| *mtime);
        let mut freed = 0u64;
        for (path, size, _) in blobs {
            if total <= max_bytes {
                break;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    total -= size;
                    freed += size;
                }
                // In use (open read) or already gone: skip, never tear a reader.
                Err(_) => continue,
            }
        }
        Ok(freed)
    }

    /// Walks the store, yielding `(path, size, mtime)` for every blob file.
    /// mtime falls back to the UNIX epoch when unavailable so sorting is total.
    fn list_blobs(&self) -> io::Result<Vec<(PathBuf, u64, std::time::SystemTime)>> {
        let mut out = Vec::new();
        // cas/<algo>/<shard>/<blob>: walk exactly three levels.
        for algo in read_dir_some(&self.cas_root)? {
            if algo.file_name().and_then(|name| name.to_str()) != Some("blake3")
                || !is_real_directory(&algo)
            {
                continue;
            }
            for shard in read_dir_some(&algo)? {
                let Some(shard_name) = shard.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !is_lower_hex(shard_name, 2) || !is_real_directory(&shard) {
                    continue;
                }
                for blob in read_dir_some(&shard)? {
                    let Some(blob_name) = blob.file_name().and_then(|name| name.to_str()) else {
                        continue;
                    };
                    if !is_lower_hex(blob_name, 64) || !blob_name.starts_with(shard_name) {
                        continue;
                    }
                    let md = match std::fs::symlink_metadata(&blob) {
                        Ok(md) if md.file_type().is_file() => md,
                        _ => continue,
                    };
                    let mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
                    out.push((blob, md.len(), mtime));
                }
            }
        }
        Ok(out)
    }
}

fn is_real_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn open_read_only(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
    }

    #[cfg(not(windows))]
    {
        File::open(path)
    }
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

fn replace_atomic(source: &Path, final_path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let source = source
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let final_path = final_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                final_path.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(not(windows))]
    {
        std::fs::rename(source, final_path)
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
    fn blob_listing_ignores_temp_malformed_unknown_and_symlink_entries() {
        let root = tmp_root();
        let store = BlobStore::open(&root).unwrap();
        let digest = store.put(b"abc").unwrap();
        let legitimate = store.blob_path(&digest);
        let shard = legitimate.parent().unwrap();
        let temp = shard.join(".tmp.attacker.1");
        std::fs::write(&temp, vec![0u8; 101]).unwrap();
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

        let listed = store.list_blobs().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|entry| entry.0 == legitimate));
        assert!(listed.iter().any(|entry| entry.0 == hardlink));
        assert_eq!(store.total_size().unwrap(), 109);
        assert_eq!(store.evict_to(0).unwrap(), 109);
        assert!(
            temp.exists(),
            "temporary-looking files are not eviction targets"
        );
        assert_eq!(std::fs::read(&hardlink_target).unwrap(), vec![0u8; 106]);
        assert_eq!(std::fs::read(&outside).unwrap(), vec![0u8; 105]);
        if linked.is_ok() {
            assert!(symlink.symlink_metadata().unwrap().file_type().is_symlink());
        }
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
