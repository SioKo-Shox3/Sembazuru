//! Agent-side file-supply server (`docs/protocol/v0.md` §4): answers a worker's
//! StatBatch / OpenRead / Read / DirList / Has / WriteBack over the data plane.
//! This is the supply side of the read VFS — the worker sees the agent's files
//! on demand.
//!
//! **Snapshot consistency (M4, §4.1).** Content is *pinned at first touch*: the
//! first OpenRead of a path ingests its bytes into the agent's content store
//! (CAS) and records `path → digest`. Every later read of that path in the
//! session serves the **pinned blob** from the CAS, not a fresh disk read, so a
//! mid-build local edit cannot tear a running action. The digest is the
//! end-to-end key (ADR 0003: BLAKE3); ranged `Read` is served by digest from
//! the CAS, which is also where worker outputs and the action cache live (M4.3).
//!
//! Path scoping/auth is deferred to M7 — on a trusted LAN the agent presents
//! its filesystem to the worker.
//!
//! A [`PathMap`] optionally remaps a requested *logical* path to a different
//! *backing* file. Identity mapping is the real deployment; the remap exists so
//! a single-machine test can serve bytes that differ from whatever happens to
//! sit at the logical path locally (proving content provenance).

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for content bytes the agent actually pushed over the data plane —
/// the quantity the M4 "Done when" (transfer ≈ 0 on a rebuild) is measured by.
/// Only *content* counts: `Read` response bytes and inlined OpenRead first
/// chunks. Stat/probe/Has carry no content and are not counted.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Number of `Read` ops served.
    pub read_ops: AtomicU64,
    /// Content bytes returned in `Read` responses.
    pub read_bytes: AtomicU64,
    /// Content bytes inlined in OpenRead first chunks.
    pub inline_bytes: AtomicU64,
}

impl ServerStats {
    /// Total content bytes pushed over the data plane (Read + inline).
    pub fn content_bytes(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed) + self.inline_bytes.load(Ordering::Relaxed)
    }
}

use sembazuru_cas::{BlobStore, Digest, DigestHasher};
use sembazuru_dataplane::async_io::{read_frame, write_frame};
use sembazuru_dataplane::ops::{
    DirEntry, DirListRequest, DirListResponse, HasRequest, HasResponse, OpenReadRequest,
    OpenReadResponse, ReadRequest, ReadResponse, StatEntry, StatRequest, StatResponse,
    WriteBackRequest, WriteBackResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const INLINE_CHUNK: usize = 64 * 1024;

/// Disambiguates per-server agent CAS directories within a process.
static CAS_SEQ: AtomicU64 = AtomicU64::new(0);

/// Resolves a requested (agent-side logical) path to the actual file to read.
#[derive(Clone)]
pub enum PathMap {
    /// Read the requested path as-is (the real deployment).
    Identity,
    /// Read paths under `logical_root` from `backing_root` instead.
    Remap {
        logical_root: String, // lowercased, no trailing separator
        backing_root: PathBuf,
    },
}

impl PathMap {
    fn resolve(&self, requested: &str) -> PathBuf {
        match self {
            PathMap::Identity => PathBuf::from(requested),
            PathMap::Remap {
                logical_root,
                backing_root,
            } => {
                let req = requested.replace('/', "\\").to_lowercase();
                let root = logical_root.trim_end_matches('\\');
                if let Some(rest) = req.strip_prefix(root) {
                    let tail = rest.trim_start_matches('\\');
                    if rest.is_empty() || rest.starts_with('\\') {
                        return backing_root.join(tail);
                    }
                }
                PathBuf::from(requested)
            }
        }
    }
}

/// In-progress streamed WriteBack for one output path: the temp file being
/// appended to, how many bytes have landed (the next expected offset), and the
/// running digest so the whole output is verified without buffering it.
struct WritebackState {
    tmp: PathBuf,
    written: u64,
    hasher: DigestHasher,
}

/// The per-session file-supply state: the agent's content store, the first-touch
/// pin map that gives snapshot consistency, and any in-progress streamed outputs.
struct Session {
    cas: BlobStore,
    /// Requested logical path → the digest pinned at its first OpenRead. Once a
    /// path is here, its content is frozen for the session.
    pinned: Mutex<HashMap<String, Digest>>,
    /// Output path → in-progress streamed WriteBack.
    writebacks: Mutex<HashMap<String, WritebackState>>,
    stats: Arc<ServerStats>,
}

impl Session {
    fn new(stats: Arc<ServerStats>) -> io::Result<Session> {
        let seq = CAS_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sbz-agent-cas.{}.{seq}", std::process::id()));
        Ok(Session {
            cas: BlobStore::open(root)?,
            pinned: Mutex::new(HashMap::new()),
            writebacks: Mutex::new(HashMap::new()),
            stats,
        })
    }

    /// Returns the pinned `(digest, size)` for `requested`, ingesting its bytes
    /// into the CAS on first touch. `None` if the file does not exist. A later
    /// call for the same path returns the *same* digest even if the on-disk
    /// file has since changed (snapshot consistency).
    async fn ingest(&self, requested: &str, actual: PathBuf) -> Option<(Digest, u64)> {
        if let Some(d) = self.pinned.lock().await.get(requested).cloned() {
            // Already pinned: serve the frozen blob's size from the CAS.
            let size = self.cas.get(&d).ok().flatten().map(|b| b.len() as u64)?;
            return Some((d, size));
        }
        let bytes = tokio::fs::read(&actual).await.ok()?;
        let size = bytes.len() as u64;
        let digest = self.cas.put(&bytes).ok()?;
        self.pinned
            .lock()
            .await
            .entry(requested.to_string())
            .or_insert_with(|| digest.clone());
        Some((digest, size))
    }
}

/// Serves the file session identity-mapped on an already-bound listener.
pub async fn serve_files(listener: TcpListener) -> io::Result<()> {
    serve_with_map(
        listener,
        PathMap::Identity,
        Arc::new(ServerStats::default()),
    )
    .await
}

/// Like [`serve_files`] but with a caller-held [`ServerStats`], so a test or the
/// M4 rebuild gate can read how many content bytes the agent actually served.
pub async fn serve_files_with_stats(
    listener: TcpListener,
    stats: Arc<ServerStats>,
) -> io::Result<()> {
    serve_with_map(listener, PathMap::Identity, stats).await
}

/// Serves with paths under `logical_root` remapped to `backing_root`. For tests
/// that need agent-served bytes to differ from the local original.
pub async fn serve_files_remap(
    listener: TcpListener,
    logical_root: &str,
    backing_root: PathBuf,
) -> io::Result<()> {
    let map = PathMap::Remap {
        logical_root: logical_root.replace('/', "\\").to_lowercase(),
        backing_root,
    };
    serve_with_map(listener, map, Arc::new(ServerStats::default())).await
}

async fn serve_with_map(
    listener: TcpListener,
    map: PathMap,
    stats: Arc<ServerStats>,
) -> io::Result<()> {
    let session = Arc::new(Session::new(stats)?);
    let map = Arc::new(map);
    loop {
        let (sock, _peer) = listener.accept().await?;
        let s = session.clone();
        let m = map.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, s, m).await;
        });
    }
}

async fn handle_conn(
    mut sock: TcpStream,
    session: Arc<Session>,
    map: Arc<PathMap>,
) -> io::Result<()> {
    loop {
        let (header, payload) = match read_frame(&mut sock).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp_payload = dispatch(header.op, &payload, &session, &map).await;
        let resp_header = FrameHeader {
            request_id: header.request_id,
            op: header.op,
            is_response: true,
        };
        write_frame(&mut sock, resp_header, &resp_payload).await?;
    }
}

async fn dispatch(op: OpCode, payload: &[u8], session: &Arc<Session>, map: &PathMap) -> Vec<u8> {
    match op {
        OpCode::StatBatch => match StatRequest::decode(payload) {
            Ok(req) => stat_batch(req, map).await.encode(),
            Err(_) => StatResponse { entries: vec![] }.encode(),
        },
        OpCode::OpenRead => match OpenReadRequest::decode(payload) {
            Ok(req) => open_read(req, session, map).await.encode(),
            Err(_) => not_found_open().encode(),
        },
        OpCode::Read => match ReadRequest::decode(payload) {
            Ok(req) => read_range(req, session).await.encode(),
            Err(_) => ReadResponse { bytes: vec![] }.encode(),
        },
        OpCode::DirList => match DirListRequest::decode(payload) {
            Ok(req) => dir_list(req, map).await.encode(),
            Err(_) => DirListResponse {
                exists: false,
                entries: vec![],
            }
            .encode(),
        },
        OpCode::Has => match HasRequest::decode(payload) {
            Ok(req) => has(req, session).await.encode(),
            // A malformed probe answers "present for none" — safe (the peer
            // will then transfer, never skip a blob the agent lacks).
            Err(_) => HasResponse { present: vec![] }.encode(),
        },
        OpCode::WriteBack => match WriteBackRequest::decode(payload) {
            Ok(req) => write_back(req, session).await.encode(),
            Err(_) => WriteBackResponse {
                ok: false,
                detail: "malformed WriteBack request".to_string(),
            }
            .encode(),
        },
    }
}

fn wb_err(detail: String) -> WriteBackResponse {
    WriteBackResponse { ok: false, detail }
}

/// A same-directory temp sibling, so the eventual rename is same-volume (atomic).
fn tmp_sibling(final_path: &std::path::Path) -> PathBuf {
    let mut tmp = final_path.to_path_buf();
    let mut name = final_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".sbz-writeback-tmp");
    tmp.set_file_name(name);
    tmp
}

/// Receives a streamed worker output (`docs/protocol/v0.md` §4.1): each chunk is
/// appended to a temp sibling and hashed incrementally; the final chunk verifies
/// the whole output against `digest_hex` and atomically renames the temp onto
/// the final name, so the build never sees a torn output (§3.2) and a large
/// `.pdb`/`.exe` is never buffered whole in memory (M4.4). WriteBack is NOT
/// remapped — the agent publishes where it wants the artifact.
async fn write_back(req: WriteBackRequest, session: &Session) -> WriteBackResponse {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    let final_path = PathBuf::from(&req.path);
    let mut wbs = session.writebacks.lock().await;

    // offset 0 (re)starts the stream: ensure the dir, create a fresh temp.
    if req.offset == 0 {
        if let Some(parent) = final_path.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return wb_err(format!("create output dir: {e}"));
        }
        let tmp = tmp_sibling(&final_path);
        if let Err(e) = tokio::fs::File::create(&tmp).await {
            return wb_err(format!("create temp: {e}"));
        }
        wbs.insert(
            req.path.clone(),
            WritebackState {
                tmp,
                written: 0,
                hasher: DigestHasher::new(),
            },
        );
    }

    // Append this chunk to the temp and fold it into the running digest.
    {
        let Some(state) = wbs.get_mut(&req.path) else {
            return wb_err("WriteBack chunk arrived without a begin (offset 0)".into());
        };
        if req.offset != state.written {
            return wb_err(format!(
                "out-of-order WriteBack chunk: offset {} but {} bytes written",
                req.offset, state.written
            ));
        }
        match tokio::fs::OpenOptions::new()
            .write(true)
            .open(&state.tmp)
            .await
        {
            Ok(mut f) => {
                if let Err(e) = f.seek(std::io::SeekFrom::Start(req.offset)).await {
                    return wb_err(format!("seek temp: {e}"));
                }
                if let Err(e) = f.write_all(&req.bytes).await {
                    return wb_err(format!("write temp: {e}"));
                }
            }
            Err(e) => return wb_err(format!("open temp: {e}")),
        }
        state.hasher.update(&req.bytes);
        state.written += req.bytes.len() as u64;
    }

    if !req.last {
        return WriteBackResponse {
            ok: true,
            detail: String::new(),
        };
    }

    // Final chunk: verify the whole output and publish atomically.
    let state = wbs
        .remove(&req.path)
        .expect("state present (just appended)");
    let actual = state.hasher.finalize().canonical();
    if actual != req.digest_hex {
        let _ = tokio::fs::remove_file(&state.tmp).await;
        return wb_err(format!(
            "digest mismatch: declared {}, got {actual}",
            req.digest_hex
        ));
    }
    if let Err(e) = tokio::fs::rename(&state.tmp, &final_path).await {
        let _ = tokio::fs::remove_file(&state.tmp).await;
        return wb_err(format!("atomic publish: {e}"));
    }
    WriteBackResponse {
        ok: true,
        detail: String::new(),
    }
}

fn not_found_open() -> OpenReadResponse {
    OpenReadResponse {
        exists: false,
        size: 0,
        digest_hex: String::new(),
        first_chunk: vec![],
    }
}

/// Existence + attributes only (no digest): header resolution probes many
/// non-existent paths, so this stays cheap and ingests nothing. Digest/content
/// come from OpenRead (which is also where snapshot pinning happens).
async fn stat_batch(req: StatRequest, map: &PathMap) -> StatResponse {
    let mut entries = Vec::with_capacity(req.paths.len());
    for p in &req.paths {
        let actual = map.resolve(p);
        let entry = match tokio::fs::metadata(&actual).await {
            Ok(md) => StatEntry {
                exists: true,
                is_dir: md.is_dir(),
                size: md.len(),
                digest_hex: String::new(),
            },
            Err(_) => StatEntry {
                exists: false,
                is_dir: false,
                size: 0,
                digest_hex: String::new(),
            },
        };
        entries.push(entry);
    }
    StatResponse { entries }
}

async fn open_read(req: OpenReadRequest, session: &Session, map: &PathMap) -> OpenReadResponse {
    let actual = map.resolve(&req.path);
    let Some((digest, size)) = session.ingest(&req.path, actual).await else {
        return not_found_open();
    };
    // Inline the first chunk only if asked. A worker-local-cache client sends
    // `want_inline = false` so a cache hit transfers no content at all.
    let first_chunk = if req.want_inline {
        match session.cas.get(&digest) {
            Ok(Some(bytes)) => bytes[..bytes.len().min(INLINE_CHUNK)].to_vec(),
            _ => vec![],
        }
    } else {
        vec![]
    };
    session
        .stats
        .inline_bytes
        .fetch_add(first_chunk.len() as u64, Ordering::Relaxed);
    OpenReadResponse {
        exists: true,
        size,
        digest_hex: digest.canonical(),
        first_chunk,
    }
}

/// Serves a ranged read from the *pinned* blob in the CAS (not a fresh disk
/// read), so content is consistent for the whole session.
async fn read_range(req: ReadRequest, session: &Session) -> ReadResponse {
    let Ok(digest) = Digest::parse(&req.digest_hex) else {
        return ReadResponse { bytes: vec![] };
    };
    let bytes = match session.cas.get(&digest) {
        Ok(Some(b)) => b,
        _ => return ReadResponse { bytes: vec![] }, // unknown/absent digest
    };
    let start = (req.offset as usize).min(bytes.len());
    let end = start.saturating_add(req.len as usize).min(bytes.len());
    let out = bytes[start..end].to_vec();
    session.stats.read_ops.fetch_add(1, Ordering::Relaxed);
    session
        .stats
        .read_bytes
        .fetch_add(out.len() as u64, Ordering::Relaxed);
    ReadResponse { bytes: out }
}

/// Answers which of the probed digests the agent's CAS already holds (§4.3).
async fn has(req: HasRequest, session: &Session) -> HasResponse {
    let present = req
        .digests
        .iter()
        .map(|s| match Digest::parse(s) {
            Ok(d) => session.cas.has(&d),
            Err(_) => false,
        })
        .collect();
    HasResponse { present }
}

/// Lists a directory's immediate children (depth is reserved for deeper
/// prefetch; M3.2 serves one level, which covers the include-dir snapshot case).
async fn dir_list(req: DirListRequest, map: &PathMap) -> DirListResponse {
    let actual = map.resolve(&req.path);
    let mut rd = match tokio::fs::read_dir(&actual).await {
        Ok(rd) => rd,
        Err(_) => {
            return DirListResponse {
                exists: false,
                entries: vec![],
            };
        }
    };
    let mut entries = Vec::new();
    while let Ok(Some(ent)) = rd.next_entry().await {
        let name = ent.file_name().to_string_lossy().into_owned();
        let (is_dir, size) = match ent.metadata().await {
            Ok(md) => (md.is_dir(), md.len()),
            Err(_) => (false, 0),
        };
        entries.push(DirEntry {
            rel_path: name,
            is_dir,
            size,
        });
    }
    // Stable order so a directory snapshot hashes/compares the same run-to-run.
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    DirListResponse {
        exists: true,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remap_redirects_under_logical_root() {
        let map = PathMap::Remap {
            logical_root: "c:\\virtual\\proj".to_string(),
            backing_root: PathBuf::from("d:\\backing"),
        };
        assert_eq!(
            map.resolve("c:\\virtual\\proj\\src\\a.cpp"),
            PathBuf::from("d:\\backing\\src\\a.cpp")
        );
        // A path outside the logical root is read as-is.
        assert_eq!(
            map.resolve("c:\\other\\b.h"),
            PathBuf::from("c:\\other\\b.h")
        );
        // The boundary must be a separator: a sibling is not remapped.
        assert_eq!(
            map.resolve("c:\\virtual\\projector\\x"),
            PathBuf::from("c:\\virtual\\projector\\x")
        );
    }

    #[test]
    fn identity_passes_paths_through() {
        assert_eq!(
            PathMap::Identity.resolve("c:\\x\\y.h"),
            PathBuf::from("c:\\x\\y.h")
        );
    }
}
