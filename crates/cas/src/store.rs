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

use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Digest, DigestError};

/// Monotonic counter making temp filenames unique within this process; combined
/// with the pid it is unique across processes sharing one store, so concurrent
/// puts of the same blob never collide on their temp files.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

    /// Reads a blob's bytes, or `None` if absent. Does not re-verify (the hot
    /// path); use [`BlobStore::get_verified`] where tamper detection is wanted.
    ///
    /// INVARIANT (relied on by [`BlobStore::evict_to`]): this reads via
    /// `std::fs::read`, a short-lived open→read→close with no
    /// `FILE_SHARE_DELETE`. That is what makes a concurrent eviction's
    /// `remove_file` *fail* (and skip the blob) rather than delete bytes out
    /// from under a reader. If this is ever changed to a streaming or
    /// memory-mapped read, the no-torn-read guarantee changes with it — a
    /// mapped blob deleted mid-read can fault the process — so revisit eviction
    /// (e.g. copy-then-serve, or refcount) before doing so.
    pub fn get(&self, digest: &Digest) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.blob_path(digest)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
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
            for shard in read_dir_some(&algo)? {
                for blob in read_dir_some(&shard)? {
                    let md = match std::fs::metadata(&blob) {
                        Ok(md) if md.is_file() => md,
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
pub(crate) fn write_atomic(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
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
    let tmp = loop {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".tmp.{}.{seq}", process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(bytes)?;
                break candidate;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    match std::fs::rename(&tmp, final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Lost the race (another writer published the same content) or a
            // real failure: drop our temp either way and report the error.
            let _ = std::fs::remove_file(&tmp);
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
        let d2 = store.put(b"some content").unwrap();
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
