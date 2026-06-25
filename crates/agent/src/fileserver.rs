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

use crate::session_registry::{SessionCapability, SessionRegistry, WritebackState};
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

/// Serves the file session identity-mapped on an already-bound listener. Auth
/// **disabled** (for tests/harnesses); the daemon uses
/// [`serve_files_with_stats_token`] with the env-configured token (ADR 0006).
pub async fn serve_files(listener: TcpListener) -> io::Result<()> {
    serve_with_map(
        listener,
        PathMap::Identity,
        Arc::new(ServerStats::default()),
        None,
        Arc::new(SessionRegistry::new()?),
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
    serve_with_map(
        listener,
        PathMap::Identity,
        stats,
        None,
        Arc::new(SessionRegistry::new()?),
    )
    .await
}

/// Like [`serve_files_with_stats`] but requires the shared cluster token on the
/// data-plane handshake (M7, ADR 0006) and uses the daemon's shared
/// [`SessionRegistry`] (ADR 0013), so a worker's Hello session id binds to the
/// agent-authoritative session the scheduler created. `expected_token == None`
/// disables auth. The daemon calls this with the env-configured token and the
/// one registry it also hands to intake.
pub async fn serve_files_with_stats_token(
    listener: TcpListener,
    stats: Arc<ServerStats>,
    expected_token: Option<String>,
    registry: Arc<SessionRegistry>,
) -> io::Result<()> {
    serve_with_map(listener, PathMap::Identity, stats, expected_token, registry).await
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
    serve_with_map(
        listener,
        map,
        Arc::new(ServerStats::default()),
        None,
        Arc::new(SessionRegistry::new()?),
    )
    .await
}

async fn serve_with_map(
    listener: TcpListener,
    map: PathMap,
    stats: Arc<ServerStats>,
    expected_token: Option<String>,
    registry: Arc<SessionRegistry>,
) -> io::Result<()> {
    let map = Arc::new(map);
    let expected_token = Arc::new(expected_token);
    loop {
        let (sock, _peer) = listener.accept().await?;
        let reg = registry.clone();
        let m = map.clone();
        let st = stats.clone();
        let tok = expected_token.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, reg, m, st, tok).await;
        });
    }
}

async fn handle_conn(
    sock: TcpStream,
    registry: Arc<SessionRegistry>,
    map: Arc<PathMap>,
    stats: Arc<ServerStats>,
    expected_token: Arc<Option<String>>,
) -> io::Result<()> {
    // Pipelining (M5.3): read requests off the connection and dispatch each on
    // its own task, writing responses (tagged with the request id) as they
    // finish — possibly out of order. The client correlates by request id, so a
    // slow op no longer head-of-line-blocks the ones behind it. The write half is
    // mutex-shared because a frame must be written whole.
    let (mut rd, mut wr) = sock.into_split();

    // Session-open handshake (M7.0 auth + ADR 0013 session binding). ALWAYS the
    // first frame: the agent validates the shared token, then reads the Hello's
    // agent-minted session id. When the id names a session the scheduler created,
    // bind this connection to the agent's OWN authoritative capability — its scope
    // root, per-session pin partition, allowed-digest set, and output scope —
    // **ignoring the worker-declared root** (closing the worker-can-widen-scope
    // hole, SEC-004). An empty/unknown id (a pre-ADR-0013 worker or a test) gets a
    // legacy per-connection capability that uses the worker-declared root — the
    // old behaviour, so a mixed cluster and the existing tests keep working.
    let (session_id, worker_root) =
        match handshake(&mut rd, &mut wr, expected_token.as_deref()).await? {
            HandshakeResult::Reject => return Ok(()), // rejected; connection closed
            HandshakeResult::Accept {
                session_id,
                worker_root,
            } => (session_id, worker_root),
        };
    let cap = match registry.get(&session_id).await {
        Some(c) => c,
        None => SessionRegistry::legacy_capability(worker_root),
    };
    // Hold a connection guard for the connection's whole life so the idle sweeper
    // never reaps a session that still has a live data-plane connection.
    let _conn = SessionRegistry::bind(cap.clone());

    let wr = Arc::new(Mutex::new(wr));
    loop {
        let (header, payload) = match read_frame(&mut rd).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let registry = registry.clone();
        let cap = cap.clone();
        let map = map.clone();
        let stats = stats.clone();
        let wr = wr.clone();
        tokio::spawn(async move {
            let resp_payload =
                dispatch(header.op, &payload, &cap, registry.store(), &map, &stats).await;
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
    /// Accepted: the agent-minted `session_id` from the Hello (empty = a
    /// pre-ADR-0013 worker), and the worker-declared root normalized for the
    /// legacy fallback (`None` = unscoped). A bound session ignores `worker_root`
    /// and uses its own authoritative root.
    Accept {
        session_id: String,
        worker_root: Option<String>,
    },
}

/// Normalizes a declared root for prefix comparison: lowercased, `/`→`\`, no
/// trailing separator. Empty in → `None` (unscoped). Exposed (ADR 0013) so the
/// scheduler/intake can derive a session's authoritative root in the SAME form
/// `path_in_scope` compares against.
pub fn normalize_root(root: &str) -> Option<String> {
    let r = root.replace('/', "\\").to_lowercase();
    let r = r.trim_end_matches('\\');
    if r.is_empty() {
        None
    } else {
        Some(r.to_string())
    }
}

/// Lexically normalizes an agent-side requested path for scope comparison:
/// lowercases, unifies separators, and collapses `.`/`..` components WITHOUT
/// touching the filesystem (so it works for the many non-existent probe paths
/// and never resolves symlinks). Returns `None` — which the caller treats as out
/// of scope (fail closed) — for anything that is not a drive-absolute `x:\…`
/// path or that escapes its drive root via `..`.
///
/// Collapsing `..` here is the load-bearing security step (security M7.1 BLOCK-1):
/// without it a request like `c:\root\..\..\users\dev\.ssh\id_rsa` string-prefix-
/// matches the root yet the OS resolves it OUTSIDE the root. This mirrors the
/// C++ hook's `GetFullPathName`-then-prefix discipline (`interceptor.cpp`). UNC,
/// `\\?\`, drive-relative `x:foo`, and 8.3 forms are rejected (fail closed),
/// matching the known residuals in `docs/deferred.md`.
fn normalize_requested(path: &str) -> Option<String> {
    let p = path.replace('/', "\\").to_lowercase();
    let b = p.as_bytes();
    // Require a drive-absolute path: "x:\...". Drive-relative "x:foo", UNC
    // "\\host\share", and "\\?\..." are not the form a hooked compiler emits for
    // a vfs_root read.
    let drive_abs = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if !drive_abs {
        return None;
    }
    let drive = &p[..2]; // "x:"
    let mut stack: Vec<&str> = Vec::new();
    for comp in p[3..].split('\\') {
        match comp {
            "" | "." => {}
            ".." => {
                stack.pop()?; // `..` above the drive root: escape → fail closed
            }
            other => stack.push(other),
        }
    }
    Some(format!("{drive}\\{}", stack.join("\\")))
}

/// Whether the requested (agent-side logical) path is within the session's
/// declared root. `None` root = unscoped (always in). The requested path is
/// lexically normalized first ([`normalize_requested`] collapses `.`/`..`), then
/// matched against the root with a path-component boundary, so `…\proj` does not
/// match a sibling `…\project` and `…\proj\..\secret` does not escape. A path
/// that will not normalize (non-absolute, UNC, `\\?\`, drive-escaping) is OUT of
/// scope (fail closed).
fn path_in_scope(requested: &str, root: Option<&str>) -> bool {
    let Some(root) = root else {
        return true;
    };
    let Some(norm) = normalize_requested(requested) else {
        return false;
    };
    norm == root || norm.starts_with(&format!("{root}\\"))
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
    // Validate the token; on success carry the agent-minted session id and the
    // worker-declared root (the latter only used for the legacy fallback) out.
    let decision: Result<(String, Option<String>), &'static str> = if header.op == OpCode::Hello {
        match HelloRequest::decode(&payload) {
            Ok(h) => match sembazuru_proto::auth::check(expected, &h.token) {
                Ok(()) => Ok((h.session_id, normalize_root(&h.root))),
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
        Ok((session_id, worker_root)) => HandshakeResult::Accept {
            session_id,
            worker_root,
        },
        Err(_) => HandshakeResult::Reject,
    })
}

async fn dispatch(
    op: OpCode,
    payload: &[u8],
    cap: &SessionCapability,
    store: &BlobStore,
    map: &PathMap,
    stats: &ServerStats,
) -> Vec<u8> {
    match op {
        OpCode::StatBatch => match StatRequest::decode(payload) {
            Ok(req) => stat_batch(req, map, cap.root()).await.encode(),
            Err(_) => StatResponse { entries: vec![] }.encode(),
        },
        OpCode::OpenRead => match OpenReadRequest::decode(payload) {
            Ok(req) => open_read(req, cap, store, map, stats).await.encode(),
            Err(_) => not_found_open().encode(),
        },
        OpCode::Read => match ReadRequest::decode(payload) {
            Ok(req) => read_range(req, cap, store, stats).await.encode(),
            Err(_) => ReadResponse { bytes: vec![] }.encode(),
        },
        OpCode::DirList => match DirListRequest::decode(payload) {
            Ok(req) => dir_list(req, map, cap.root()).await.encode(),
            Err(_) => DirListResponse {
                exists: false,
                entries: vec![],
            }
            .encode(),
        },
        OpCode::Has => match HasRequest::decode(payload) {
            Ok(req) => has(req, cap, store).await.encode(),
            // A malformed probe answers "present for none" — safe (the peer
            // will then transfer, never skip a blob the agent lacks).
            Err(_) => HasResponse { present: vec![] }.encode(),
        },
        OpCode::WriteBack => match WriteBackRequest::decode(payload) {
            Ok(req) => write_back(req, cap).await.encode(),
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
/// `.pdb`/`.exe` is never buffered whole in memory (M4.4).
///
/// **Output scope (SEC-003, ADR 0013).** A bound session may only write to its
/// declared outputs (or, when none were declared, to within its authoritative
/// root) — closing the hole where a worker named any absolute agent-side path. A
/// legacy/unscoped session keeps the pre-ADR-0013 any-path behaviour. The target
/// is otherwise NOT remapped — the agent publishes where the action's output goes.
async fn write_back(req: WriteBackRequest, cap: &SessionCapability) -> WriteBackResponse {
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    // Gate the target BEFORE creating any directory or temp: a bound session's
    // output must normalize to a drive-absolute path that is declared (or within
    // its root). A non-normalizable form (UNC/relative/drive-escaping) is refused.
    if cap.enforces() {
        let within_root = path_in_scope(&req.path, cap.root());
        let allowed = match normalize_requested(&req.path) {
            Some(norm) => cap.output_allowed(&norm, within_root),
            None => false,
        };
        if !allowed {
            return wb_err("WriteBack target is outside the session's output scope".into());
        }
    }

    let final_path = PathBuf::from(&req.path);
    let mut wbs = cap.writebacks().lock().await;

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
async fn stat_batch(req: StatRequest, map: &PathMap, root: Option<&str>) -> StatResponse {
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
    cap: &SessionCapability,
    store: &BlobStore,
    map: &PathMap,
    stats: &ServerStats,
) -> OpenReadResponse {
    // Out-of-scope open reports "not found" (existence-hiding) and ingests
    // nothing, so no out-of-root content ever enters the store. The scope is the
    // session's AUTHORITATIVE root (the agent's, not the worker's) — SEC-004.
    if !path_in_scope(&req.path, cap.root()) {
        return not_found_open();
    }
    let actual = map.resolve(&req.path);
    // Pin (single-flight) into the session's partition; this also records the
    // digest in the session's allowed-digest ACL so the later Read/Has succeeds.
    let Some((digest, size)) = cap.pin(store, &req.path, actual).await else {
        return not_found_open();
    };
    // Inline the first chunk only if asked. A worker-local-cache client sends
    // `want_inline = false` so a cache hit transfers no content at all.
    let first_chunk = if req.want_inline {
        match store.get(&digest) {
            Ok(Some(bytes)) => bytes[..bytes.len().min(INLINE_CHUNK)].to_vec(),
            _ => vec![],
        }
    } else {
        vec![]
    };
    stats
        .inline_bytes
        .fetch_add(first_chunk.len() as u64, Ordering::Relaxed);
    OpenReadResponse {
        exists: true,
        size,
        digest_hex: digest.canonical(),
        first_chunk,
    }
}

/// Serves a ranged read from the *pinned* blob in the store (not a fresh disk
/// read), so content is consistent for the whole session.
async fn read_range(
    req: ReadRequest,
    cap: &SessionCapability,
    store: &BlobStore,
    stats: &ServerStats,
) -> ReadResponse {
    let Ok(digest) = Digest::parse(&req.digest_hex) else {
        return ReadResponse { bytes: vec![] };
    };
    // ADR 0013: a bound session may only read digests it has itself pinned, so a
    // digest learned out-of-band (e.g. from another session) cannot be fetched
    // here. A legacy/unscoped session reads any present digest (old behaviour).
    if !cap.digest_visible(&digest).await {
        return ReadResponse { bytes: vec![] };
    }
    let bytes = match store.get(&digest) {
        Ok(Some(b)) => b,
        _ => return ReadResponse { bytes: vec![] }, // unknown/absent digest
    };
    let start = (req.offset as usize).min(bytes.len());
    let end = start.saturating_add(req.len as usize).min(bytes.len());
    let out = bytes[start..end].to_vec();
    stats.read_ops.fetch_add(1, Ordering::Relaxed);
    stats
        .read_bytes
        .fetch_add(out.len() as u64, Ordering::Relaxed);
    ReadResponse { bytes: out }
}

/// Answers which of the probed digests the agent's store already holds (§4.3),
/// gated by the session's allowed-digest ACL so a bound session cannot probe
/// another session's digest (ADR 0013).
async fn has(req: HasRequest, cap: &SessionCapability, store: &BlobStore) -> HasResponse {
    let mut present = Vec::with_capacity(req.digests.len());
    for s in &req.digests {
        let ok = match Digest::parse(s) {
            Ok(d) => cap.digest_visible(&d).await && store.has(&d),
            Err(_) => false,
        };
        present.push(ok);
    }
    HasResponse { present }
}

/// Lists a directory's immediate children (depth is reserved for deeper
/// prefetch; M3.2 serves one level, which covers the include-dir snapshot case).
async fn dir_list(req: DirListRequest, map: &PathMap, root: Option<&str>) -> DirListResponse {
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
        let root = root.as_deref();
        // In root: the root itself and anything under it (any case/separator).
        assert!(path_in_scope("C:\\work\\proj", root));
        assert!(path_in_scope("C:\\work\\proj\\src\\a.cpp", root));
        assert!(path_in_scope("c:/WORK/proj/inc/h.h", root));
        // A sibling that merely shares the prefix string is NOT in scope.
        assert!(!path_in_scope("C:\\work\\project\\x", root));
        // Outside the root entirely.
        assert!(!path_in_scope(
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            root
        ));
        assert!(!path_in_scope("C:\\users\\dev\\.ssh\\id_rsa", root));
        // No root = unscoped: everything is allowed (legacy/tests).
        assert!(path_in_scope("C:\\anything\\at\\all", None));
    }

    #[test]
    fn path_in_scope_blocks_dotdot_traversal() {
        // security M7.1 BLOCK-1: a `..` request that string-prefix-matches the
        // root but resolves OUTSIDE it must be rejected.
        let root = normalize_root("C:\\work\\proj");
        let root = root.as_deref();
        assert!(!path_in_scope(
            "C:\\work\\proj\\..\\..\\users\\dev\\.ssh\\id_rsa",
            root
        ));
        assert!(!path_in_scope("C:\\work\\proj\\..\\secret.txt", root));
        assert!(!path_in_scope("c:/work/proj/../../etc/hosts", root));
        // Interior `..` that stays inside the root is fine (collapses in-root).
        assert!(path_in_scope("C:\\work\\proj\\src\\..\\inc\\h.h", root));
        // `.` components are harmless.
        assert!(path_in_scope("C:\\work\\proj\\.\\a.cpp", root));
    }

    #[test]
    fn normalize_requested_rejects_non_absolute_and_escaping_forms() {
        // Drive-relative, UNC, \\?\, bare relative, and drive-escaping all fail.
        assert_eq!(normalize_requested("c:foo\\bar"), None);
        assert_eq!(normalize_requested("\\\\host\\share\\x"), None);
        assert_eq!(normalize_requested("\\\\?\\c:\\work\\x"), None);
        assert_eq!(normalize_requested("relative\\path"), None);
        assert_eq!(normalize_requested("c:\\..\\x"), None); // escapes drive root
        // A normal drive-absolute path collapses `.`/`..` correctly.
        assert_eq!(
            normalize_requested("C:\\work\\.\\proj\\sub\\..\\a.cpp"),
            Some("c:\\work\\proj\\a.cpp".to_string())
        );
        // None of these forms are in scope (fail closed).
        let root = normalize_root("C:\\work\\proj");
        let root = root.as_deref();
        assert!(!path_in_scope("c:foo", root));
        assert!(!path_in_scope("\\\\host\\share\\work\\proj\\x", root));
        assert!(!path_in_scope("\\\\?\\c:\\work\\proj\\x", root));
    }
    // (The temp content-store scrub-on-drop is now `SessionRegistry`'s; it is
    // covered by the session_registry module's own tests, ADR 0013.)
}
