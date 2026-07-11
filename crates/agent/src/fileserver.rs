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
//! **Auth + scope (M7 + ADR 0013).** The data-plane Hello is token-gated (M7,
//! ADR 0006). Scope is agent-authoritative: when the Hello names a session the
//! scheduler created (via the [`crate::session_registry::SessionRegistry`]), the
//! connection binds to that session's capability and reads are scoped to the
//! AGENT's root (not the worker-declared one), pins are per-session, and Read/Has
//! are gated to the session's pinned digests. A worker that sends an unknown or
//! expired non-empty session id is rejected and is never downgraded to legacy
//! scoping. An empty session id is rejected in production; only explicit
//! test/harness compatibility mode accepts it as the legacy per-connection scope
//! by the worker-declared root.
//!
//! A [`PathMap`] optionally remaps a requested *logical* path to a different
//! *backing* file. Identity mapping is the real deployment; the remap exists so
//! a single-machine test can serve bytes that differ from whatever happens to
//! sit at the logical path locally (proving content provenance).

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

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

use crate::rootdir::{FileSnapshot, RootDir, file_snapshot};
use crate::session_registry::{
    SessionCapability, SessionRegistry, WritebackState, create_staging_temp, remove_root_file,
};
use sembazuru_cas::{BlobStore, Digest, DigestHasher};
use sembazuru_dataplane::async_io::{read_frame, read_frame_with_body_guard, write_frame};
use sembazuru_dataplane::ops::{
    DirEntry, DirListRequest, DirListResponse, HasRequest, HasResponse, HelloRequest,
    HelloResponse, MAX_DIRLIST_ENTRIES, OpenReadRequest, OpenReadResponse, ReadRequest,
    ReadResponse, StatEntry, StatRequest, StatResponse, WriteBackRequest, WriteBackResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

pub const MAX_UNAUTHENTICATED_HANDSHAKES: usize = 64;
pub const MAX_DATA_PLANE_IN_FLIGHT_REQUESTS: usize = 256;

#[derive(Clone, Copy)]
struct QuotaLimits {
    max_unauthenticated_handshakes: usize,
    max_data_plane_in_flight_requests: usize,
}

#[derive(Clone)]
struct ConnShared {
    registry: Arc<SessionRegistry>,
    map: Arc<PathMap>,
    stats: Arc<ServerStats>,
    expected_token: Arc<Option<String>>,
    legacy_sessions_enabled: bool,
    request_slots: Arc<Semaphore>,
}

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
        true,
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
        true,
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
    legacy_sessions_enabled: bool,
) -> io::Result<()> {
    serve_with_map(
        listener,
        PathMap::Identity,
        stats,
        expected_token,
        registry,
        legacy_sessions_enabled,
    )
    .await
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
        true,
    )
    .await
}

async fn serve_with_map(
    listener: TcpListener,
    map: PathMap,
    stats: Arc<ServerStats>,
    expected_token: Option<String>,
    registry: Arc<SessionRegistry>,
    legacy_sessions_enabled: bool,
) -> io::Result<()> {
    serve_with_map_and_quotas(
        listener,
        map,
        stats,
        expected_token,
        registry,
        legacy_sessions_enabled,
        QuotaLimits {
            max_unauthenticated_handshakes: MAX_UNAUTHENTICATED_HANDSHAKES,
            max_data_plane_in_flight_requests: MAX_DATA_PLANE_IN_FLIGHT_REQUESTS,
        },
    )
    .await
}

async fn serve_with_map_and_quotas(
    listener: TcpListener,
    map: PathMap,
    stats: Arc<ServerStats>,
    expected_token: Option<String>,
    registry: Arc<SessionRegistry>,
    legacy_sessions_enabled: bool,
    quotas: QuotaLimits,
) -> io::Result<()> {
    let handshake_slots = Arc::new(Semaphore::new(quotas.max_unauthenticated_handshakes));
    let shared = ConnShared {
        registry,
        map: Arc::new(map),
        stats,
        expected_token: Arc::new(expected_token),
        legacy_sessions_enabled,
        request_slots: Arc::new(Semaphore::new(quotas.max_data_plane_in_flight_requests)),
    };
    loop {
        let (sock, _peer) = listener.accept().await?;
        let Ok(handshake_permit) = Arc::clone(&handshake_slots).try_acquire_owned() else {
            drop(sock);
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, shared, handshake_permit).await;
        });
    }
}

async fn handle_conn(
    sock: TcpStream,
    shared: ConnShared,
    handshake_permit: OwnedSemaphorePermit,
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
    // hole, SEC-004). Unknown or expired non-empty ids are rejected and never
    // downgraded to legacy. Empty ids are rejected in production and accepted only
    // when a test/harness explicitly enables legacy compatibility.
    let cap = match handshake(
        &mut rd,
        &mut wr,
        shared.expected_token.as_deref(),
        shared.registry.as_ref(),
        shared.legacy_sessions_enabled,
    )
    .await?
    {
        HandshakeResult::Reject => return Ok(()), // rejected; connection closed
        HandshakeResult::Accept { cap } => cap,
    };
    drop(handshake_permit);
    // Hold a connection guard for the connection's whole life so the idle sweeper
    // never reaps a session that still has a live data-plane connection.
    let _conn = SessionRegistry::bind(cap.clone());

    let wr = Arc::new(Mutex::new(wr));
    loop {
        let (header, payload, request_permit) = match read_frame_with_body_guard(&mut rd, |_| {
            acquire_request_slot(&shared.request_slots)
        })
        .await
        {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let registry = shared.registry.clone();
        let cap = cap.clone();
        let map = shared.map.clone();
        let stats = shared.stats.clone();
        let wr = wr.clone();
        tokio::spawn(async move {
            let _request_permit = request_permit;
            let resp_payload =
                dispatch(header.op, &payload, &cap, registry.store(), &map, &stats).await;
            match resp_payload {
                Ok(resp_payload) => {
                    let resp_header = FrameHeader {
                        request_id: header.request_id,
                        op: header.op,
                        is_response: true,
                    };
                    let mut w = wr.lock().await;
                    let _ = write_response_or_shutdown(&mut *w, resp_header, &resp_payload).await;
                }
                Err(_) => {
                    let mut w = wr.lock().await;
                    shutdown_response_writer(&mut *w).await;
                }
            }
        });
    }
}

async fn acquire_request_slot(slots: &Arc<Semaphore>) -> io::Result<OwnedSemaphorePermit> {
    Arc::clone(slots).acquire_owned().await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "data-plane request limiter closed",
        )
    })
}

async fn write_response_or_shutdown<W>(
    w: &mut W,
    header: FrameHeader,
    payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match write_frame(&mut *w, header, payload).await {
        Ok(()) => Ok(()),
        Err(e) => {
            shutdown_response_writer(w).await;
            Err(e)
        }
    }
}

async fn shutdown_response_writer<W: AsyncWrite + Unpin>(w: &mut W) {
    let _ = w.shutdown().await;
}

/// Outcome of the session-open handshake.
enum HandshakeResult {
    /// Bad token (or malformed/absent Hello): a rejection was sent; close.
    Reject,
    /// Accepted: the resolved session capability. A bound session uses the
    /// agent-authoritative root; an explicitly enabled legacy empty-id session
    /// uses the worker-declared root.
    Accept { cap: Arc<SessionCapability> },
}

async fn resolve_session(
    registry: &SessionRegistry,
    legacy_sessions_enabled: bool,
    session_id: String,
    worker_root: Option<String>,
) -> Result<Arc<SessionCapability>, &'static str> {
    // Belt-and-suspenders: registry.get also returns None for an empty id,
    // so neither check alone is assumed to be the sole guard.
    if session_id.is_empty() {
        if legacy_sessions_enabled {
            Ok(SessionRegistry::legacy_capability(worker_root))
        } else {
            Err("session id required")
        }
    } else {
        registry
            .get(&session_id)
            .await
            .ok_or("unknown or expired session id")
    }
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

/// Lexically normalizes an agent-side requested/output path for scope and
/// declared-output comparison: lowercases, unifies separators, and collapses
/// `.`/`..` components WITHOUT touching the filesystem (so it works for the many
/// non-existent probe/output paths and never resolves symlinks). Returns `None`
/// — which the caller treats as out of scope (fail closed) — for anything that
/// is not a drive-absolute `x:\…` path or that escapes its drive root via `..`.
/// Exposed so intake and integration tests normalize declared output paths in
/// the same form WriteBack authorizes.
///
/// Collapsing `..` here is the load-bearing security step (security M7.1 BLOCK-1):
/// without it a request like `c:\root\..\..\users\dev\.ssh\id_rsa` string-prefix-
/// matches the root yet the OS resolves it OUTSIDE the root. This mirrors the
/// C++ hook's `GetFullPathName`-then-prefix discipline (`interceptor.cpp`). UNC,
/// `\\?\`, drive-relative `x:foo`, and 8.3 forms are rejected (fail closed).
pub fn normalize_requested(path: &str) -> Option<String> {
    normalize_requested_inner(path, ShortAliasPolicy::Reject)
}

pub(crate) fn normalize_declared_output(path: &str, root: Option<&str>) -> Option<String> {
    normalize_scoped_requested(path, root)
}

pub(crate) fn normalize_prefetch_path(path: &str, root: Option<&str>) -> Option<String> {
    normalize_scoped_requested(path, root)
}

fn normalize_scoped_requested(path: &str, root: Option<&str>) -> Option<String> {
    let Some(root) = root else {
        return normalize_requested(path);
    };
    let normalized = normalize_requested_inner(path, ShortAliasPolicy::Allow)?;
    root_relative_path(path, root)?;
    Some(normalized)
}

#[derive(Copy, Clone)]
enum ShortAliasPolicy {
    Reject,
    Allow,
}

fn normalize_requested_inner(path: &str, short_alias_policy: ShortAliasPolicy) -> Option<String> {
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
            other if is_ambiguous_windows_component(other) => return None,
            other
                if matches!(short_alias_policy, ShortAliasPolicy::Reject)
                    && is_short_name_alias_component(other) =>
            {
                return None;
            }
            other => stack.push(other),
        }
    }
    Some(format!("{drive}\\{}", stack.join("\\")))
}

fn is_ambiguous_windows_component(component: &str) -> bool {
    if component.is_empty() || component == "." {
        return false;
    }
    if component.contains(':') || component.ends_with('.') || component.ends_with(' ') {
        return true;
    }

    let stem = component.split('.').next().unwrap_or(component);
    let stem_upper = stem.to_ascii_uppercase();
    matches!(
        stem_upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || {
        let bytes = stem_upper.as_bytes();
        bytes.len() == 4
            && matches!(&bytes[..3], b"COM" | b"LPT")
            && (b'1'..=b'9').contains(&bytes[3])
    }
}

fn is_short_name_alias_component(component: &str) -> bool {
    let (name, ext) = component
        .split_once('.')
        .map_or((component, None), |(name, ext)| (name, Some(ext)));
    let Some((prefix, generation)) = name.split_once('~') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.len() <= 6
        && !generation.is_empty()
        && generation
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit())
        && ext.is_none_or(|ext| !ext.is_empty() && ext.len() <= 3 && !ext.contains('.'))
}

/// Whether the requested (agent-side logical) path is within the session's
/// declared root. `None` root = unscoped (always in). The requested path is
/// lexically normalized first (collapsing `.`/`..`), then matched against the
/// root with a path-component boundary, so `…\proj` does not match a sibling
/// `…\project` and `…\proj\..\secret` does not escape. A path that will not
/// normalize (non-absolute, UNC, `\\?\`, drive-escaping) is OUT of scope (fail
/// closed). 8.3-like components are allowed only in the already-declared root
/// prefix; the root-relative suffix still rejects them fail-closed.
pub(crate) fn path_in_scope(requested: &str, root: Option<&str>) -> bool {
    let Some(root) = root else {
        return true;
    };
    let Some(norm) = normalize_requested_inner(requested, ShortAliasPolicy::Allow) else {
        return false;
    };
    if norm == root {
        return true;
    }
    let Some(rel) = norm
        .strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('\\'))
    else {
        return false;
    };
    !rel.split('\\').any(is_short_name_alias_component)
}

fn root_relative_path(requested: &str, root: &str) -> Option<String> {
    let norm = normalize_requested_inner(requested, ShortAliasPolicy::Allow)?;
    if norm == root {
        Some(".".to_string())
    } else {
        let rel = norm
            .strip_prefix(root)
            .and_then(|rest| rest.strip_prefix('\\'))?;
        if rel.split('\\').any(is_short_name_alias_component) {
            None
        } else {
            Some(rel.to_owned())
        }
    }
}

fn contained_root_access(
    cap: &SessionCapability,
    map: &PathMap,
    requested: &str,
) -> Option<(RootDir, String)> {
    if !matches!(map, PathMap::Identity) {
        return None;
    }
    let root = cap.root()?;
    let root_dir = cap.root_dir()?.clone();
    let rel = root_relative_path(requested, root)?;
    Some((root_dir, rel))
}

async fn root_metadata(root_dir: RootDir, rel: String) -> io::Result<cap_std::fs::Metadata> {
    tokio::task::spawn_blocking(move || root_dir.metadata(&rel))
        .await
        .map_err(blocking_join_to_io)?
}

async fn root_dir_entries(root_dir: RootDir, rel: String) -> io::Result<Vec<DirEntry>> {
    tokio::task::spawn_blocking(move || {
        let rd = root_dir.read_dir(&rel)?;
        let mut entries = Vec::new();
        for ent in rd {
            let Ok(ent) = ent else {
                break;
            };
            let name = ent.file_name().to_string_lossy().into_owned();
            let (is_dir, size) = match ent.metadata() {
                Ok(md) => (md.is_dir(), md.len()),
                Err(_) => (false, 0),
            };
            entries.push(DirEntry {
                rel_path: name,
                is_dir,
                size,
            });
            if entries.len() > MAX_DIRLIST_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DirList entry quota exceeded",
                ));
            }
        }
        entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        Ok(entries)
    })
    .await
    .map_err(blocking_join_to_io)?
}

fn blocking_join_to_io(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("blocking filesystem task failed: {e}"))
}

/// Server side of the session-open handshake (M7.0 auth + M7.1 scoping). The
/// peer's first frame must be a `Hello` carrying the cluster token and the
/// declared root; this validates the token, resolves the session id, and replies
/// with the verdict. Unknown/expired non-empty ids are rejected and never
/// downgraded to legacy. Empty ids are rejected unless the caller explicitly
/// enabled legacy test/harness compatibility. A rejection is sent before closing
/// so the client surfaces a clean `PermissionDenied`, not a bare reset. EOF
/// before the handshake is just a peer that connected and left. The reason is a
/// fixed safe string (no secret, no internal path; M7 §5).
async fn handshake(
    rd: &mut tokio::net::tcp::OwnedReadHalf,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
    expected: Option<&str>,
    registry: &SessionRegistry,
    legacy_sessions_enabled: bool,
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
    // Validate the token; on success resolve the agent-minted session id to the
    // capability this connection will hold for its lifetime.
    let decision: Result<Arc<SessionCapability>, &'static str> = if header.op == OpCode::Hello {
        match HelloRequest::decode(&payload) {
            Ok(h) => match sembazuru_proto::auth::check(expected, &h.token) {
                Ok(()) => {
                    let worker_root = normalize_root(&h.root);
                    resolve_session(registry, legacy_sessions_enabled, h.session_id, worker_root)
                        .await
                }
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
        Ok(cap) => HandshakeResult::Accept { cap },
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
) -> io::Result<Vec<u8>> {
    if cap.is_closed() {
        // ADD-001: finished sessions may leave a lingering connection; no late
        // op may run, and WriteBack is a hard reject.
        return Ok(closed_response(op));
    }

    Ok(match op {
        OpCode::StatBatch => match StatRequest::decode(payload) {
            Ok(req) => stat_batch(req, map, cap).await.encode(),
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
            Ok(req) => dir_list(req, map, cap).await?.encode(),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed DirList request",
                ));
            }
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
    })
}

fn closed_response(op: OpCode) -> Vec<u8> {
    match op {
        OpCode::StatBatch => StatResponse { entries: vec![] }.encode(),
        OpCode::OpenRead => not_found_open().encode(),
        OpCode::Read => ReadResponse { bytes: vec![] }.encode(),
        OpCode::DirList => DirListResponse {
            exists: false,
            entries: vec![],
        }
        .encode(),
        OpCode::Has => HasResponse { present: vec![] }.encode(),
        OpCode::WriteBack => WriteBackResponse {
            ok: false,
            detail: "session is closed".to_string(),
        }
        .encode(),
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

/// Receives a streamed worker output (`docs/protocol/v0.md` §4.1): each chunk is
/// appended to a temp sibling and hashed incrementally; the final chunk verifies
/// the whole output against `digest_hex` and records the verified staging path.
/// The agent's intake path publishes it only after the action succeeds (3.3), so
/// failed/aborted/closed actions discard staging and never expose partial or late
/// final output. A large `.pdb`/`.exe` is never buffered whole in memory (M4.4).
///
/// **Output scope (SEC-003, ADR 0013).** The worker names only an `output_id`.
/// The bound session resolves that id to the agent-owned final path and
/// per-output size cap. Unknown ids are rejected before any directory or temp
/// file is created.
async fn write_back(req: WriteBackRequest, cap: &SessionCapability) -> WriteBackResponse {
    let spec = match cap.output_spec(req.output_id) {
        Some(spec) => spec,
        None => return wb_err("unknown output id".into()),
    };

    let final_path = spec.final_path.clone();
    let mut wbs = cap.writebacks().lock().await;

    // offset 0 (re)starts the stream: ensure the dir, create a fresh temp.
    if req.offset == 0 {
        let temp = match create_staging_temp(&final_path).await {
            Ok(temp) => temp,
            Err(e) => return wb_io_err("create temp failed", e),
        };
        let old = wbs.insert(
            req.output_id,
            WritebackState {
                tmp: temp.path,
                tmp_rel: temp.rel,
                parent_dir: temp.parent_dir,
                file: Arc::new(StdMutex::new(temp.file)),
                snapshot: temp.snapshot,
                written: 0,
                hasher: DigestHasher::new(),
            },
        );
        if let Some(old) = old {
            drop(old.file);
            let _ = remove_root_file(old.parent_dir, old.tmp_rel).await;
        }
    }

    let new_written = {
        let Some(state) = wbs.get_mut(&req.output_id) else {
            return wb_err("WriteBack chunk arrived without a begin (offset 0)".into());
        };
        if req.offset != state.written {
            return wb_err(format!(
                "out-of-order WriteBack chunk: offset {} but {} bytes written",
                req.offset, state.written
            ));
        }
        match state.written.checked_add(req.bytes.len() as u64) {
            Some(new_written) if new_written <= spec.max_size => Ok(new_written),
            _ => Err((
                state.parent_dir.clone(),
                state.tmp_rel.clone(),
                state.file.clone(),
            )),
        }
    };
    let new_written = match new_written {
        Ok(new_written) => new_written,
        Err((parent_dir, tmp_rel, file)) => {
            wbs.remove(&req.output_id);
            drop(file);
            let _ = remove_root_file(parent_dir, tmp_rel).await;
            return wb_err("output exceeds max size".into());
        }
    };

    // Append this chunk to the temp and fold it into the running digest.
    {
        let state = wbs
            .get_mut(&req.output_id)
            .expect("state present after size check");
        if let Err(e) =
            write_staging_file_at(state.file.clone(), req.offset, req.bytes.clone()).await
        {
            return wb_io_err("write temp failed", e);
        }
        state.hasher.update(&req.bytes);
        state.written = new_written;
    }

    if !req.last {
        return WriteBackResponse {
            ok: true,
            detail: String::new(),
        };
    }

    // Final chunk: verify the whole output and stage it for intake-owned publish.
    let state = wbs
        .remove(&req.output_id)
        .expect("state present (just appended)");
    drop(wbs);
    let WritebackState {
        tmp,
        tmp_rel,
        parent_dir,
        file,
        snapshot,
        written: _,
        hasher,
    } = state;
    let actual = hasher.finalize().canonical();
    if actual != req.digest_hex {
        drop(file);
        let _ = remove_root_file(parent_dir, tmp_rel).await;
        return wb_err(format!(
            "digest mismatch: declared {}, got {actual}",
            req.digest_hex
        ));
    }
    if let Err(e) =
        verify_root_file_snapshot_and_digest(parent_dir.clone(), tmp_rel.clone(), snapshot, &actual)
            .await
    {
        drop(file);
        let _ = remove_root_file(parent_dir, tmp_rel).await;
        return wb_io_err("verify temp failed", e);
    }
    drop(file);
    if cap
        .record_staged(req.output_id, tmp, final_path, actual, snapshot, parent_dir)
        .await
    {
        WriteBackResponse {
            ok: true,
            detail: String::new(),
        }
    } else {
        wb_err("session closed during writeback".into())
    }
}

async fn write_staging_file_at(
    file: Arc<StdMutex<cap_std::fs::File>>,
    offset: u64,
    bytes: Vec<u8>,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut file = file
            .lock()
            .map_err(|_| io::Error::other("staging file lock poisoned"))?;
        use std::io::{Seek as _, Write as _};
        file.seek(std::io::SeekFrom::Start(offset))?;
        file.write_all(&bytes)
    })
    .await
    .map_err(blocking_join_to_io)?
}

async fn verify_root_file_snapshot_and_digest(
    root_dir: RootDir,
    rel: String,
    expected_snapshot: FileSnapshot,
    expected: &str,
) -> io::Result<()> {
    let expected = expected.to_string();
    tokio::task::spawn_blocking(move || {
        let mut file = root_dir.open_read(&rel)?;
        let actual_snapshot = file_snapshot(&file)?;
        if actual_snapshot.identity != expected_snapshot.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staging temp file identity changed before final writeback verification",
            ));
        }
        if actual_snapshot.link_count != expected_snapshot.link_count {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staging temp hardlink count changed before final writeback verification",
            ));
        }
        let mut hasher = DigestHasher::new();
        let mut buf = [0u8; 64 * 1024];
        use std::io::Read as _;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hasher.finalize().canonical();
        if actual == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staging temp path no longer contains the verified bytes",
            ))
        }
    })
    .await
    .map_err(blocking_join_to_io)?
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
async fn stat_batch(req: StatRequest, map: &PathMap, cap: &SessionCapability) -> StatResponse {
    let mut entries = Vec::with_capacity(req.paths.len());
    for p in &req.paths {
        // Out-of-scope paths report "does not exist" — same as a real negative
        // probe, so a rogue worker cannot even learn whether a path outside the
        // declared root is present (M7.1 path scoping).
        if !path_in_scope(p, cap.root()) {
            entries.push(StatEntry {
                exists: false,
                is_dir: false,
                size: 0,
                digest_hex: String::new(),
            });
            continue;
        }
        if cap.requires_contained_root() {
            entries.push(StatEntry {
                exists: false,
                is_dir: false,
                size: 0,
                digest_hex: String::new(),
            });
            continue;
        }
        let contained = contained_root_access(cap, map, p);
        let entry = match contained {
            Some((root_dir, rel)) => match root_metadata(root_dir, rel).await {
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
            },
            None => {
                let actual = map.resolve(p);
                match tokio::fs::metadata(&actual).await {
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
                }
            }
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
    if cap.requires_contained_root() {
        return not_found_open();
    }
    let actual = map.resolve(&req.path);
    let contained = contained_root_access(cap, map, &req.path);
    // Pin (single-flight) into the session's partition; this also records the
    // digest in the session's allowed-digest ACL so the later Read/Has succeeds.
    let Some((digest, size)) = cap.pin_contained(store, &req.path, actual, contained).await else {
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
async fn dir_list(
    req: DirListRequest,
    map: &PathMap,
    cap: &SessionCapability,
) -> io::Result<DirListResponse> {
    // Out-of-scope directory reports "does not exist" (existence-hiding, M7.1).
    if !path_in_scope(&req.path, cap.root()) {
        return Ok(DirListResponse {
            exists: false,
            entries: vec![],
        });
    }
    if cap.requires_contained_root() {
        return Ok(DirListResponse {
            exists: false,
            entries: vec![],
        });
    }
    if let Some((root_dir, rel)) = contained_root_access(cap, map, &req.path) {
        return match root_dir_entries(root_dir, rel).await {
            Ok(entries) => Ok(DirListResponse {
                exists: true,
                entries,
            }),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(e),
            Err(_) => Ok(DirListResponse {
                exists: false,
                entries: vec![],
            }),
        };
    }
    let actual = map.resolve(&req.path);
    let mut rd = match tokio::fs::read_dir(&actual).await {
        Ok(rd) => rd,
        Err(_) => {
            return Ok(DirListResponse {
                exists: false,
                entries: vec![],
            });
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
        if entries.len() > MAX_DIRLIST_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DirList entry quota exceeded",
            ));
        }
    }
    // Stable order so a directory snapshot hashes/compares the same run-to-run.
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(DirListResponse {
        exists: true,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::path::{Path, PathBuf};
    #[cfg(windows)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(windows)]
    static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

    #[cfg(windows)]
    struct ScratchDir {
        path: PathBuf,
        reparse_dirs: Vec<PathBuf>,
    }

    #[cfg(windows)]
    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sbz-fs-{}-{tag}-{seq}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self {
                path,
                reparse_dirs: Vec::new(),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn register_reparse_dir(&mut self, path: PathBuf) {
            self.reparse_dirs.push(path);
        }
    }

    #[cfg(windows)]
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            for path in self.reparse_dirs.iter().rev() {
                let _ = std::fs::remove_dir(path);
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(windows)]
    fn create_junction(
        root: &mut ScratchDir,
        link_name: &str,
        target: &Path,
    ) -> Result<(), String> {
        let link = root.path().join(link_name);
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target)
            .output()
            .map_err(|e| format!("failed to spawn mklink /J: {e}"))?;
        if output.status.success() {
            root.register_reparse_dir(link);
            Ok(())
        } else {
            Err(format!(
                "mklink /J failed with status {:?}; stdout: {}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

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

    #[tokio::test]
    async fn unauthenticated_handshake_flood_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(SessionRegistry::new().unwrap());
        tokio::spawn(async move {
            let _ = serve_with_map_and_quotas(
                listener,
                PathMap::Identity,
                Arc::new(ServerStats::default()),
                None,
                registry,
                true,
                QuotaLimits {
                    max_unauthenticated_handshakes: 1,
                    max_data_plane_in_flight_requests: MAX_DATA_PLANE_IN_FLIGHT_REQUESTS,
                },
            )
            .await;
        });

        let slow = TcpStream::connect(addr).await.unwrap();
        let mut overflow = TcpStream::connect(addr).await.unwrap();
        let overflow_result =
            tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut overflow))
                .await;
        assert!(
            overflow_result.is_ok(),
            "overflow unauthenticated connection should be closed promptly, not pinned"
        );

        drop(slow);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match sembazuru_worker::fileclient::FileClient::connect(addr).await {
                Ok(client) => {
                    drop(client);
                    break;
                }
                Err(err) if tokio::time::Instant::now() < deadline => {
                    let _ = err;
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(err) => {
                    panic!(
                        "valid client should connect after the slow handshake releases its slot: {err}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn server_request_in_flight_cap_blocks_until_a_slot_is_released() {
        let slots = Arc::new(Semaphore::new(1));
        let first = acquire_request_slot(&slots).await.unwrap();
        let waiting_slots = Arc::clone(&slots);
        let second = tokio::spawn(async move { acquire_request_slot(&waiting_slots).await });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !second.is_finished(),
            "request dispatch must wait while all request slots are held"
        );

        drop(first);
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await
            .expect("request slot should become available")
            .unwrap()
            .unwrap();
        drop(second);
    }

    #[tokio::test]
    async fn response_write_failure_shuts_down_writer() {
        use sembazuru_dataplane::wire::{HEADER_BYTES, MAX_FRAME_BODY};
        use tokio::io::AsyncReadExt;

        let (mut writer, mut peer) = tokio::io::duplex(64);
        let header = FrameHeader {
            request_id: 42,
            op: OpCode::Read,
            is_response: true,
        };
        let payload = vec![0u8; MAX_FRAME_BODY - HEADER_BYTES + 1];

        let err = write_response_or_shutdown(&mut writer, header, &payload)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let mut one = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), peer.read(&mut one))
            .await
            .expect("peer should observe EOF promptly")
            .unwrap();
        assert_eq!(n, 0);
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

    #[test]
    fn path_corpus_normalize_requested_rejects_ambiguous_windows_forms() {
        for requested in [
            "C:\\work\\proj\\out.obj:ads",
            "\\\\?\\C:\\work\\proj\\out.obj",
            "\\??\\C:\\work\\proj\\out.obj",
            "\\\\server\\share\\proj\\out.obj",
            "C:work\\proj\\out.obj",
            "\\work\\proj\\out.obj",
            "C:\\work\\proj\\out.",
            "C:\\work\\proj\\out ",
            "C:\\work\\proj\\con",
            "C:\\work\\proj\\nul.txt",
            "C:\\work\\proj\\com1.obj",
            "C:\\work\\proj\\lpt9.log",
            "C:\\work\\proj\\PROGRA~1\\tool.exe",
            "C:\\work\\proj\\LONGFI~12.TXT",
        ] {
            assert_eq!(
                normalize_requested(requested),
                None,
                "{requested:?} must fail closed"
            );
        }

        assert_eq!(
            normalize_requested("C:\\work\\proj\\obj\\file~backup.obj"),
            Some("c:\\work\\proj\\obj\\file~backup.obj".to_string())
        );
    }

    #[test]
    fn path_corpus_scope_allows_short_name_component_in_declared_root_prefix_only() {
        let root =
            normalize_root("C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-x").expect("root");
        let root = root.as_str();

        assert!(
            path_in_scope(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-x\\src\\in.h",
                Some(root)
            ),
            "a short-name component inherited from the declared root prefix must not break supply"
        );
        assert_eq!(
            root_relative_path(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-x\\src\\in.h",
                root
            ),
            Some("src\\in.h".to_string())
        );
        assert!(
            !path_in_scope(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-x\\PROGRA~1\\tool.exe",
                Some(root)
            ),
            "a short-name component in the root-relative suffix must still fail closed"
        );
        assert_eq!(
            root_relative_path(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-x\\PROGRA~1\\tool.exe",
                root
            ),
            None
        );
    }

    #[test]
    fn path_corpus_declared_output_normalization_allows_short_alias_root_prefix_only() {
        let root =
            normalize_root("C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root").expect("root");

        assert_eq!(
            normalize_declared_output(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\obj\\out.obj",
                Some(&root)
            ),
            Some(
                "c:\\users\\kingka~1\\appdata\\local\\temp\\sbz-dp-root\\obj\\out.obj".to_string()
            )
        );
        assert_eq!(
            normalize_declared_output(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\PROGRA~1\\tool.obj",
                Some(&root)
            ),
            None
        );
        assert_eq!(
            normalize_declared_output(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\outside\\obj\\out.obj",
                Some(&root)
            ),
            None
        );

        for rejected in [
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\obj\\out.obj:ads",
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\NUL.txt",
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\obj\\bad.",
            "\\\\host\\share\\obj\\out.obj",
            "C:obj\\out.obj",
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\..\\outside\\out.obj",
        ] {
            assert_eq!(normalize_declared_output(rejected, Some(&root)), None);
        }

        assert_eq!(
            normalize_declared_output(
                "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\obj\\out.obj",
                None
            ),
            None
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_enforcing_session_without_root_handle_fails_closed() {
        let root = ScratchDir::new("missing-root-handle");
        let root_path = root.path().join("declared");
        let requested = root_path.join("src").join("in.h");
        let root_norm = normalize_root(&root_path.to_string_lossy()).expect("absolute temp root");
        let registry = SessionRegistry::new().unwrap();
        let cap = registry
            .create("missing-root-handle".into(), Some(root_norm), Vec::new())
            .await;
        assert!(cap.enforces());
        assert!(cap.root().is_some());
        assert!(
            cap.root_dir().is_none(),
            "test setup requires the authoritative root handle to be unavailable"
        );
        std::fs::create_dir_all(requested.parent().unwrap()).unwrap();
        std::fs::write(&requested, b"must not be served ambiently").unwrap();
        let requested = requested.to_string_lossy().into_owned();

        let stat = stat_batch(
            StatRequest {
                paths: vec![requested.clone()],
            },
            &PathMap::Identity,
            &cap,
        )
        .await;
        assert!(
            !stat.entries[0].exists,
            "stat must fail closed instead of falling back to ambient metadata"
        );

        let open = open_read(
            OpenReadRequest {
                path: requested.clone(),
                want_inline: true,
            },
            &cap,
            registry.store(),
            &PathMap::Identity,
            &ServerStats::default(),
        )
        .await;
        assert!(
            !open.exists,
            "open_read must fail closed instead of ambiently reading under an unopened root"
        );

        let listed = dir_list(
            DirListRequest {
                path: root_path.to_string_lossy().into_owned(),
                depth: 1,
            },
            &PathMap::Identity,
            &cap,
        )
        .await
        .unwrap();
        assert!(
            !listed.exists,
            "dir_list must fail closed instead of ambiently listing under an unopened root"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_writeback_rejects_staging_temp_replaced_by_hardlink_between_chunks() {
        use sembazuru_dataplane::ops::WriteBackRequest;

        let root = ScratchDir::new("wb-hardlink-root");
        let outside = ScratchDir::new("wb-hardlink-outside");
        let final_path = root.path().join("out").join("final.obj");
        let external_peer = outside.path().join("peer.obj");
        std::fs::write(&external_peer, b"ABCDEFGH").unwrap();

        let registry = SessionRegistry::new().unwrap();
        let cap = registry
            .create(
                "path-corpus-hardlink".into(),
                None,
                vec![crate::session_registry::OutputSpec {
                    id: 7,
                    final_path: final_path.clone(),
                    max_size: 64,
                }],
            )
            .await;
        let digest = Digest::of(b"ABCDEFGH").canonical();

        let first = write_back(
            WriteBackRequest {
                output_id: 7,
                offset: 0,
                bytes: b"ABCD".to_vec(),
                last: false,
                digest_hex: digest.clone(),
            },
            &cap,
        )
        .await;
        assert!(
            first.ok,
            "first chunk should stage normally: {}",
            first.detail
        );

        let tmp_path = {
            let wbs = cap.writebacks().lock().await;
            wbs.get(&7).expect("writeback state").tmp.clone()
        };
        let replaced = match std::fs::remove_file(&tmp_path) {
            Ok(()) => {
                std::fs::hard_link(&external_peer, &tmp_path).unwrap();
                true
            }
            Err(e) => {
                eprintln!("staging temp removal refused while file handle is open: {e}");
                false
            }
        };

        let second = write_back(
            WriteBackRequest {
                output_id: 7,
                offset: 4,
                bytes: b"EFGH".to_vec(),
                last: true,
                digest_hex: digest,
            },
            &cap,
        )
        .await;

        if replaced {
            assert!(
                !second.ok,
                "writeback must reject a staging temp replaced by a same-content external hardlink"
            );
        } else {
            assert!(
                second.ok,
                "writeback may continue when the open staging temp could not be replaced: {}",
                second.detail
            );
        }
        assert_eq!(
            std::fs::read(&external_peer).unwrap(),
            b"ABCDEFGH",
            "a chunk append must not modify the external hardlink peer"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn identity_stat_open_and_dir_list_reject_intermediate_junction_escape() {
        let outside = ScratchDir::new("outside");
        std::fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
        let mut root = ScratchDir::new("root");
        create_junction(&mut root, "escape", outside.path())
            .expect("mklink /J should create an unprivileged junction on Windows");
        let requested = root
            .path()
            .join("escape")
            .join("secret.txt")
            .to_string_lossy()
            .into_owned();
        let root = normalize_root(&root.path().to_string_lossy()).expect("absolute temp root");
        let registry = SessionRegistry::new().unwrap();
        let cap = registry
            .create("junction-read".into(), Some(root), Vec::new())
            .await;

        let stat = stat_batch(
            StatRequest {
                paths: vec![requested.clone()],
            },
            &PathMap::Identity,
            &cap,
        )
        .await;
        assert!(
            !stat.entries[0].exists,
            "stat must not follow an intermediate junction outside the session root"
        );

        let open = open_read(
            OpenReadRequest {
                path: requested,
                want_inline: true,
            },
            &cap,
            registry.store(),
            &PathMap::Identity,
            &ServerStats::default(),
        )
        .await;
        assert!(
            !open.exists,
            "open_read must not pin bytes reached through an out-of-root junction"
        );

        let listed = dir_list(
            DirListRequest {
                path: root_path_string(cap.root().unwrap(), "escape"),
                depth: 1,
            },
            &PathMap::Identity,
            &cap,
        )
        .await
        .unwrap();
        assert!(
            !listed.exists,
            "dir_list must not enumerate through an out-of-root junction"
        );
    }

    #[cfg(windows)]
    fn root_path_string(root: &str, child: &str) -> String {
        format!("{root}\\{child}")
    }
    // (The temp content-store scrub-on-drop is now `SessionRegistry`'s; it is
    // covered by the session_registry module's own tests, ADR 0013.)
}
