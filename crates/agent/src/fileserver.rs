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
    DirEntry, DirListRequest, DirListResponse, HasRequest, HasResponse, HelloRequest,
    HelloResponse, OpenReadRequest, OpenReadResponse, ReadRequest, ReadResponse, StatEntry,
    StatRequest, StatResponse, WriteBackRequest, WriteBackResponse,
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
    /// Where `cas` lives, so the session scrubs it on drop (M5.3). NOTE: today
    /// one `Session` lives for the whole agent process (the serve loop holds it),
    /// so this fires at process exit and stops the per-run temp tree from leaking
    /// across runs. True mid-life per-session eviction in a long-lived multi-
    /// session agent (deferred #8) needs the daemon's session lifecycle (M5.5).
    cas_root: PathBuf,
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
        let cas_root =
            std::env::temp_dir().join(format!("sbz-agent-cas.{}.{seq}", std::process::id()));
        Ok(Session {
            cas: BlobStore::open(&cas_root)?,
            cas_root,
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

impl Drop for Session {
    fn drop(&mut self) {
        // Scrub the session's temp CAS tree. Best-effort: a leaked temp dir is
        // not a correctness problem, so a failure here is ignored rather than
        // surfaced from a destructor.
        let _ = std::fs::remove_dir_all(&self.cas_root);
    }
}

/// Serves the file session identity-mapped on an already-bound listener. Auth
/// **disabled** (for tests/harnesses); the daemon uses
/// [`serve_files_with_stats_token`] with the env-configured token (ADR 0006).
pub async fn serve_files(listener: TcpListener) -> io::Result<()> {
    serve_with_map(
        listener,
        PathMap::Identity,
        Arc::new(ServerStats::default()),
        None,
    )
    .await
}

/// Like [`serve_files`] but with a caller-held [`ServerStats`], so a test or the
/// M4 rebuild gate can read how many content bytes the agent actually served.
/// Auth disabled.
pub async fn serve_files_with_stats(
    listener: TcpListener,
    stats: Arc<ServerStats>,
) -> io::Result<()> {
    serve_with_map(listener, PathMap::Identity, stats, None).await
}

/// Like [`serve_files_with_stats`] but requires the shared cluster token on the
/// data-plane handshake (M7, ADR 0006). `expected_token == None` disables auth.
/// The daemon calls this with [`sembazuru_proto::auth::cluster_token_from_env`].
pub async fn serve_files_with_stats_token(
    listener: TcpListener,
    stats: Arc<ServerStats>,
    expected_token: Option<String>,
) -> io::Result<()> {
    serve_with_map(listener, PathMap::Identity, stats, expected_token).await
}

/// Serves with paths under `logical_root` remapped to `backing_root`. For tests
/// that need agent-served bytes to differ from the local original. Auth disabled.
pub async fn serve_files_remap(
    listener: TcpListener,
    logical_root: &str,
    backing_root: PathBuf,
) -> io::Result<()> {
    let map = PathMap::Remap {
        logical_root: logical_root.replace('/', "\\").to_lowercase(),
        backing_root,
    };
    serve_with_map(listener, map, Arc::new(ServerStats::default()), None).await
}

async fn serve_with_map(
    listener: TcpListener,
    map: PathMap,
    stats: Arc<ServerStats>,
    expected_token: Option<String>,
) -> io::Result<()> {
    let session = Arc::new(Session::new(stats)?);
    let map = Arc::new(map);
    let expected_token = Arc::new(expected_token);
    loop {
        let (sock, _peer) = listener.accept().await?;
        let s = session.clone();
        let m = map.clone();
        let tok = expected_token.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, s, m, tok).await;
        });
    }
}

async fn handle_conn(
    sock: TcpStream,
    session: Arc<Session>,
    map: Arc<PathMap>,
    expected_token: Arc<Option<String>>,
) -> io::Result<()> {
    // Pipelining (M5.3): read requests off the connection and dispatch each on
    // its own task, writing responses (tagged with the request id) as they
    // finish — possibly out of order. The client correlates by request id, so a
    // slow op no longer head-of-line-blocks the ones behind it. The write half is
    // mutex-shared because a frame must be written whole.
    let (mut rd, mut wr) = sock.into_split();

    // Session-open handshake (M7.0 auth + M7.1 path scoping). ALWAYS the first
    // frame: the peer must open the session with a Hello before any op. The agent
    // validates the shared token (closing the unauthenticated file-supply path)
    // and records the declared input root, then refuses to supply any path
    // outside it (closing the arbitrary-absolute-path read). An empty root means
    // unscoped (legacy/tests); an empty configured token means auth off.
    let scope_root = match handshake(&mut rd, &mut wr, expected_token.as_deref()).await? {
        HandshakeResult::Reject => return Ok(()), // rejected; connection closed
        HandshakeResult::Accept(root) => Arc::new(root),
    };

    let wr = Arc::new(Mutex::new(wr));
    loop {
        let (header, payload) = match read_frame(&mut rd).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let session = session.clone();
        let map = map.clone();
        let wr = wr.clone();
        let root = scope_root.clone();
        tokio::spawn(async move {
            let resp_payload = dispatch(header.op, &payload, &session, &map, &root).await;
            let resp_header = FrameHeader {
                request_id: header.request_id,
                op: header.op,
                is_response: true,
            };
            let mut w = wr.lock().await;
            let _ = write_frame(&mut *w, resp_header, &resp_payload).await;
        });
    }
}

/// Outcome of the session-open handshake.
enum HandshakeResult {
    /// Bad token (or malformed/absent Hello): a rejection was sent; close.
    Reject,
    /// Accepted; the declared input root to scope file supply to (`None` =
    /// unscoped, the legacy/test case).
    Accept(Option<String>),
}

/// Normalizes a declared root for prefix comparison: lowercased, `/`→`\`, no
/// trailing separator. Empty in → `None` (unscoped).
fn normalize_root(root: &str) -> Option<String> {
    let r = root.replace('/', "\\").to_lowercase();
    let r = r.trim_end_matches('\\');
    if r.is_empty() {
        None
    } else {
        Some(r.to_string())
    }
}

/// Whether the requested (agent-side logical) path is within the session's
/// declared root. `None` root = unscoped (always in). The comparison normalizes
/// separators and case and requires a path-component boundary, so `…\proj` does
/// not match a sibling `…\project`. Path-form edge cases (8.3 short names,
/// `\\?\`, UNC, symlinks) are the known residuals tracked in `docs/deferred.md`;
/// they fail CLOSED here (treated as out of scope) rather than leak.
fn path_in_scope(requested: &str, root: &Option<String>) -> bool {
    let Some(root) = root else {
        return true;
    };
    let req = requested.replace('/', "\\").to_lowercase();
    let req = req.trim_end_matches('\\');
    req == root.as_str() || req.starts_with(&format!("{root}\\"))
}

/// Server side of the session-open handshake (M7.0 auth + M7.1 scoping). The
/// peer's first frame must be a `Hello` carrying the cluster token and the
/// declared root; this validates the token and replies with the verdict, then
/// returns the normalized root to scope supply to. A rejection is sent before
/// closing so the client surfaces a clean `PermissionDenied`, not a bare reset.
/// EOF before the handshake is just a peer that connected and left. The reason
/// is a fixed safe string (no secret, no internal path; M7 §5).
async fn handshake(
    rd: &mut tokio::net::tcp::OwnedReadHalf,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    expected: Option<&str>,
) -> io::Result<HandshakeResult> {
    use tokio::io::AsyncWriteExt;

    // Slow-loris defense (security F4): a peer that connects and then never sends
    // a Hello must not pin a connection task forever. Bound the wait; a timeout is
    // treated as a (silent) rejection and the connection is closed.
    const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    let (header, payload) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(rd)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Ok(HandshakeResult::Reject);
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(HandshakeResult::Reject),
    };
    // Validate the token; on success carry the declared root out.
    let decision: Result<Option<String>, &'static str> = if header.op == OpCode::Hello {
        match HelloRequest::decode(&payload) {
            Ok(h) => match sembazuru_proto::auth::check(expected, &h.token) {
                Ok(()) => Ok(normalize_root(&h.root)),
                Err(reason) => Err(reason),
            },
            Err(_) => Err("malformed handshake"),
        }
    } else {
        Err("session handshake required")
    };
    let (ok, detail) = match &decision {
        Ok(_) => (true, String::new()),
        Err(reason) => (false, reason.to_string()),
    };
    let resp = HelloResponse { ok, detail }.encode();
    write_frame(
        wr,
        FrameHeader {
            request_id: header.request_id,
            op: OpCode::Hello,
            is_response: true,
        },
        &resp,
    )
    .await?;
    wr.flush().await?;
    Ok(match decision {
        Ok(root) => HandshakeResult::Accept(root),
        Err(_) => HandshakeResult::Reject,
    })
}

async fn dispatch(
    op: OpCode,
    payload: &[u8],
    session: &Arc<Session>,
    map: &PathMap,
    root: &Option<String>,
) -> Vec<u8> {
    match op {
        OpCode::StatBatch => match StatRequest::decode(payload) {
            Ok(req) => stat_batch(req, map, root).await.encode(),
            Err(_) => StatResponse { entries: vec![] }.encode(),
        },
        OpCode::OpenRead => match OpenReadRequest::decode(payload) {
            Ok(req) => open_read(req, session, map, root).await.encode(),
            Err(_) => not_found_open().encode(),
        },
        OpCode::Read => match ReadRequest::decode(payload) {
            Ok(req) => read_range(req, session).await.encode(),
            Err(_) => ReadResponse { bytes: vec![] }.encode(),
        },
        OpCode::DirList => match DirListRequest::decode(payload) {
            Ok(req) => dir_list(req, map, root).await.encode(),
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
        // A Hello only belongs as the first frame (handled in `handshake`); one
        // arriving mid-stream is a protocol error, answered with a rejection.
        OpCode::Hello => HelloResponse {
            ok: false,
            detail: "unexpected handshake after session open".to_string(),
        }
        .encode(),
    }
}

fn wb_err(detail: String) -> WriteBackResponse {
    WriteBackResponse { ok: false, detail }
}

/// Sanitizes an agent-side WriteBack I/O error for the wire (M7.1, error-leak
/// hardening). The raw `io::Error` carries the agent's output/temp filesystem
/// paths; that detail is logged on the AGENT's own stderr and only the coarse,
/// path-free `category` is returned to the (untrusted) worker. Digest-mismatch
/// and protocol-misuse responses stay verbatim — they carry hashes/offsets, not
/// paths, and are the useful signal.
fn wb_io_err(category: &'static str, detail: impl std::fmt::Display) -> WriteBackResponse {
    eprintln!("sembazuru-agent: writeback {category}: {detail}");
    wb_err(category.to_string())
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
            return wb_io_err("create output dir failed", e);
        }
        let tmp = tmp_sibling(&final_path);
        if let Err(e) = tokio::fs::File::create(&tmp).await {
            return wb_io_err("create temp failed", e);
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
                    return wb_io_err("seek temp failed", e);
                }
                if let Err(e) = f.write_all(&req.bytes).await {
                    return wb_io_err("write temp failed", e);
                }
            }
            Err(e) => return wb_io_err("open temp failed", e),
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
        return wb_io_err("atomic publish failed", e);
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
async fn stat_batch(req: StatRequest, map: &PathMap, root: &Option<String>) -> StatResponse {
    let mut entries = Vec::with_capacity(req.paths.len());
    for p in &req.paths {
        // Out-of-scope paths report "does not exist" — same as a real negative
        // probe, so a rogue worker cannot even learn whether a path outside the
        // declared root is present (M7.1 path scoping).
        if !path_in_scope(p, root) {
            entries.push(StatEntry {
                exists: false,
                is_dir: false,
                size: 0,
                digest_hex: String::new(),
            });
            continue;
        }
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

async fn open_read(
    req: OpenReadRequest,
    session: &Session,
    map: &PathMap,
    root: &Option<String>,
) -> OpenReadResponse {
    // Out-of-scope open reports "not found" (existence-hiding) and ingests
    // nothing, so no out-of-root content ever enters the session CAS (M7.1).
    if !path_in_scope(&req.path, root) {
        return not_found_open();
    }
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
async fn dir_list(req: DirListRequest, map: &PathMap, root: &Option<String>) -> DirListResponse {
    // Out-of-scope directory reports "does not exist" (existence-hiding, M7.1).
    if !path_in_scope(&req.path, root) {
        return DirListResponse {
            exists: false,
            entries: vec![],
        };
    }
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

    #[test]
    fn normalize_root_lowercases_and_strips_trailing_sep() {
        assert_eq!(normalize_root(""), None);
        assert_eq!(normalize_root("\\"), None);
        assert_eq!(
            normalize_root("C:\\Work\\Proj\\"),
            Some("c:\\work\\proj".to_string())
        );
        assert_eq!(
            normalize_root("C:/Work/Proj"),
            Some("c:\\work\\proj".to_string())
        );
    }

    #[test]
    fn path_in_scope_enforces_root_with_a_boundary() {
        let root = normalize_root("C:\\work\\proj");
        // In root: the root itself and anything under it (any case/separator).
        assert!(path_in_scope("C:\\work\\proj", &root));
        assert!(path_in_scope("C:\\work\\proj\\src\\a.cpp", &root));
        assert!(path_in_scope("c:/WORK/proj/inc/h.h", &root));
        // A sibling that merely shares the prefix string is NOT in scope.
        assert!(!path_in_scope("C:\\work\\project\\x", &root));
        // Outside the root entirely.
        assert!(!path_in_scope(
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            &root
        ));
        assert!(!path_in_scope("C:\\users\\dev\\.ssh\\id_rsa", &root));
        // No root = unscoped: everything is allowed (legacy/tests).
        assert!(path_in_scope("C:\\anything\\at\\all", &None));
    }

    #[test]
    fn dropping_a_session_scrubs_its_temp_cas() {
        let session = Session::new(Arc::new(ServerStats::default())).unwrap();
        let root = session.cas_root.clone();
        assert!(root.exists(), "Session::new creates the CAS dir");
        drop(session);
        assert!(
            !root.exists(),
            "dropping the session removes its temp CAS tree (M5.3 cleanup)"
        );
    }
}
