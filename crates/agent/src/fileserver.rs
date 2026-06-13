//! Agent-side file-supply server (`docs/protocol/v0.md` §4): answers a worker's
//! StatBatch / OpenRead / Read / DirList over the data plane, reading from the
//! agent's own filesystem. This is the supply side of the read VFS — the worker
//! sees the agent's files on demand.
//!
//! **M3.2 scope.** Snapshot consistency (§4.1) is simplified: digests are
//! computed on first OpenRead and cached for the session, which pins content
//! for the rest of that session, but mid-build edits before first touch are not
//! guarded (a single-action loopback worker does not hit this; full pinning is
//! M3.x). Path scoping/auth is deferred to M7 — on a trusted LAN the agent
//! presents its filesystem to the worker; here it serves the absolute paths the
//! hooked process requests.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use sembazuru_dataplane::async_io::{read_frame, write_frame};
use sembazuru_dataplane::ops::{
    DirEntry, DirListRequest, DirListResponse, OpenReadRequest, OpenReadResponse, ReadRequest,
    ReadResponse, StatEntry, StatRequest, StatResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use sembazuru_tracer::determinism::sha256_hex;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Bytes of a file inlined in an OpenRead response so open + first read is one
/// round-trip (§4.1).
const INLINE_CHUNK: usize = 64 * 1024;

/// Per-session content map: digest -> the path it was hashed from, so a later
/// `Read(digest, ...)` can serve ranges. Populated on OpenRead.
#[derive(Default)]
struct Session {
    by_digest: HashMap<String, PathBuf>,
}

/// Serves the file session on an already-bound listener until it errors. One
/// shared content map backs every connection of the session.
pub async fn serve_files(listener: TcpListener) -> io::Result<()> {
    let session = Arc::new(Mutex::new(Session::default()));
    loop {
        let (sock, _peer) = listener.accept().await?;
        let s = session.clone();
        tokio::spawn(async move {
            // A connection error just ends that connection; the server lives on.
            let _ = handle_conn(sock, s).await;
        });
    }
}

async fn handle_conn(mut sock: TcpStream, session: Arc<Mutex<Session>>) -> io::Result<()> {
    loop {
        let (header, payload) = match read_frame(&mut sock).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp_payload = dispatch(header.op, &payload, &session).await;
        let resp_header = FrameHeader {
            request_id: header.request_id,
            op: header.op,
            is_response: true,
        };
        write_frame(&mut sock, resp_header, &resp_payload).await?;
    }
}

/// Decodes the request for `op`, serves it, and returns the encoded response
/// payload. A malformed request payload yields an empty response rather than
/// tearing down the connection (the worker sees a missing/empty result and can
/// fall back).
async fn dispatch(op: OpCode, payload: &[u8], session: &Arc<Mutex<Session>>) -> Vec<u8> {
    match op {
        OpCode::StatBatch => match StatRequest::decode(payload) {
            Ok(req) => stat_batch(req).await.encode(),
            Err(_) => StatResponse { entries: vec![] }.encode(),
        },
        OpCode::OpenRead => match OpenReadRequest::decode(payload) {
            Ok(req) => open_read(req, session).await.encode(),
            Err(_) => not_found_open().encode(),
        },
        OpCode::Read => match ReadRequest::decode(payload) {
            Ok(req) => read_range(req, session).await.encode(),
            Err(_) => ReadResponse { bytes: vec![] }.encode(),
        },
        OpCode::DirList => match DirListRequest::decode(payload) {
            Ok(req) => dir_list(req).await.encode(),
            Err(_) => DirListResponse {
                exists: false,
                entries: vec![],
            }
            .encode(),
        },
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
/// non-existent paths, so this must stay cheap. Digest/content come from
/// OpenRead.
async fn stat_batch(req: StatRequest) -> StatResponse {
    let mut entries = Vec::with_capacity(req.paths.len());
    for p in &req.paths {
        let entry = match tokio::fs::metadata(p).await {
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

async fn open_read(req: OpenReadRequest, session: &Arc<Mutex<Session>>) -> OpenReadResponse {
    let bytes = match tokio::fs::read(&req.path).await {
        Ok(b) => b,
        Err(_) => return not_found_open(),
    };
    let digest_hex = sha256_hex(&bytes);
    session
        .lock()
        .await
        .by_digest
        .insert(digest_hex.clone(), PathBuf::from(&req.path));
    let first = &bytes[..bytes.len().min(INLINE_CHUNK)];
    OpenReadResponse {
        exists: true,
        size: bytes.len() as u64,
        digest_hex,
        first_chunk: first.to_vec(),
    }
}

async fn read_range(req: ReadRequest, session: &Arc<Mutex<Session>>) -> ReadResponse {
    let path = match session.lock().await.by_digest.get(&req.digest_hex).cloned() {
        Some(p) => p,
        None => return ReadResponse { bytes: vec![] }, // unknown digest
    };
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return ReadResponse { bytes: vec![] },
    };
    let start = (req.offset as usize).min(bytes.len());
    let end = start.saturating_add(req.len as usize).min(bytes.len());
    ReadResponse {
        bytes: bytes[start..end].to_vec(),
    }
}

/// Lists a directory's immediate children (depth is reserved for deeper
/// prefetch; M3.2 serves one level, which covers the include-dir snapshot case).
async fn dir_list(req: DirListRequest) -> DirListResponse {
    let mut rd = match tokio::fs::read_dir(&req.path).await {
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
