//! Worker-side data-plane client (`docs/protocol/v0.md` §4): the worker's view
//! of the agent filesystem. It issues StatBatch / OpenRead / Read / DirList /
//! Has and pulls file content for hydrate-on-open — verifying the content
//! digest end-to-end (§5: integrity is free; ADR 0003: BLAKE3).
//!
//! **Digest-first fetch (M4).** [`FileClient::probe_digest`] resolves a path to
//! its digest *without* transferring bytes (`want_inline = false`), so the
//! worker can consult its local cache and fetch only on a miss. [`FileClient::
//! fetch`] keeps the inline-first-chunk fast path for callers that always want
//! the bytes.
//!
//! **Multiplexed connection (M5.3).** One persistent connection is shared (it is
//! `Clone`, an `Arc` inside) and supports many concurrent in-flight ops: a reader
//! task fans each response back to the waiting caller by request id, so calls no
//! longer serialize one round-trip at a time. This is both the connection pool
//! (one socket per session instead of one per hydrate) and the pipelining that
//! the request-id wire format was built for.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sembazuru_cas::Digest;
use sembazuru_dataplane::async_io::{read_frame, write_frame};
use sembazuru_dataplane::ops::{
    DirListRequest, DirListResponse, HasRequest, HasResponse, OpenReadRequest, OpenReadResponse,
    ReadRequest, ReadResponse, StatRequest, StatResponse, WriteBackRequest, WriteBackResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{Mutex, oneshot};

/// How much to request per Read after the inlined first chunk.
const READ_CHUNK: u32 = 256 * 1024;

/// WriteBack chunk size for streaming outputs (ADR 0003: large files stream in
/// fixed chunks). A small output fits in a single chunk.
const WRITEBACK_CHUNK: usize = 1024 * 1024;

/// A decoded frame (header + payload), handed from the reader task to a waiter.
type Frame = (FrameHeader, Vec<u8>);
/// Outstanding requests by id, each awaiting its correlated response frame.
type PendingMap = HashMap<u64, oneshot::Sender<Frame>>;

/// The multiplexed connection state behind a [`FileClient`]. The write half is
/// mutex-guarded (frames are written whole); the reader task owns the read half
/// and routes each response to its waiting caller via `pending`.
struct Mux {
    write: Mutex<OwnedWriteHalf>,
    pending: Mutex<PendingMap>,
    /// Set once the reader task exits (connection dead). Checked under the
    /// `pending` lock so a call cannot register a waiter that will never be woken
    /// — without it, a request issued after the reader stopped would hang forever.
    closed: AtomicBool,
    next_id: AtomicU64,
    /// Synthetic per-op latency for benchmarking against a single machine, where
    /// clumsy/QoS cannot shape loopback (docs/research/m3-prestudy.md §2). Zero
    /// in production. Applied per op so it measures round-trips x RTT, the
    /// quantity the data plane is judged on — and pipelined ops overlap it.
    rtt: Duration,
}

impl Mux {
    /// Reads responses forever, waking the matching waiter. On a read error or
    /// EOF the connection is dead: drop all waiters (their `recv` errors, which
    /// callers surface as a broken-pipe `io::Error`).
    async fn read_loop(self: Arc<Self>, mut rd: OwnedReadHalf) {
        // Until the connection errors/EOFs, route each response to its waiter.
        // A response with no waiter (duplicate / unsolicited) is dropped.
        while let Ok((header, payload)) = read_frame(&mut rd).await {
            let waiter = self.pending.lock().await.remove(&header.request_id);
            if let Some(tx) = waiter {
                let _ = tx.send((header, payload));
            }
        }
        // Connection dead. Mark closed *before* draining, then drain under the
        // lock: any call that already registered is woken (with an error) here,
        // and any call that has not yet locked `pending` will see `closed` and
        // bail instead of registering a waiter nobody will ever wake.
        self.closed.store(true, Ordering::SeqCst);
        self.pending.lock().await.clear();
    }

    /// One request/response over the multiplexed connection. Registers a waiter
    /// under a fresh id, writes the request, and awaits its correlated response.
    async fn call(&self, op: OpCode, payload: &[u8]) -> io::Result<Vec<u8>> {
        if !self.rtt.is_zero() {
            // Emulate one network round-trip. Spin-wait, not tokio::time::sleep:
            // the OS/timer granularity on Windows (~15 ms) makes sub-15 ms sleeps
            // wildly inaccurate, which would dwarf a true 1 ms RTT and make the
            // measurement meaningless. This is a benchmark-only shim (rtt is ZERO
            // in production), so the brief busy-wait is acceptable.
            let start = Instant::now();
            while start.elapsed() < self.rtt {
                std::hint::spin_loop();
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if self.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "data-plane connection closed",
                ));
            }
            pending.insert(id, tx);
        }
        let write_result = {
            let mut w = self.write.lock().await;
            write_frame(
                &mut *w,
                FrameHeader {
                    request_id: id,
                    op,
                    is_response: false,
                },
                payload,
            )
            .await
        };
        if let Err(e) = write_result {
            // The request never went out: remove our waiter so a failed write
            // does not leave a dangling pending entry until the connection dies.
            self.pending.lock().await.remove(&id);
            return Err(e);
        }
        let (header, resp) = rx.await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "data-plane connection closed")
        })?;
        if header.request_id != id || !header.is_response || header.op != op {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data-plane response did not correlate to its request",
            ));
        }
        Ok(resp)
    }
}

/// A handle to a multiplexed data-plane connection. Cheap to [`Clone`] (it is an
/// `Arc` inside); every clone shares the one socket and can issue ops
/// concurrently, so a whole session's hydrates pool onto a single connection.
#[derive(Clone)]
pub struct FileClient {
    mux: Arc<Mux>,
}

impl FileClient {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Self::connect_with_rtt(addr, Duration::ZERO).await
    }

    /// Connects with a synthetic per-op RTT injected at the framing layer (for
    /// the M3.5 latency benchmark; pass `Duration::ZERO` in production). No auth
    /// token and no declared root (unscoped) — used by tests/examples.
    pub async fn connect_with_rtt<A: ToSocketAddrs>(addr: A, rtt: Duration) -> io::Result<Self> {
        Self::connect_with_rtt_session(addr, rtt, String::new(), String::new(), String::new()).await
    }

    /// Connects with an explicit `token` but no declared root. Back-compat shim
    /// for callers that only need auth; equivalent to declaring an empty root.
    pub async fn connect_with_rtt_token<A: ToSocketAddrs>(
        addr: A,
        rtt: Duration,
        token: String,
    ) -> io::Result<Self> {
        Self::connect_with_rtt_session(addr, rtt, token, String::new(), String::new()).await
    }

    /// Connects and performs the session-open handshake (M7.0 auth + M7.1 path
    /// scoping) before any op: it writes a single `Hello` frame carrying the
    /// shared `token` (may be empty when auth is off), the declared session `root`
    /// (may be empty for no scoping), and the agent-minted `session_id` (ADR 0013;
    /// empty for the legacy/unscoped path), then waits for the agent's verdict —
    /// failing the connect if the agent rejects it (bad token). When `session_id`
    /// names a known session the agent ignores `root` and uses its own
    /// authoritative root for that session. The handshake runs on the raw stream
    /// *before* the multiplexing reader task starts, so it cannot race ops.
    pub async fn connect_with_rtt_session<A: ToSocketAddrs>(
        addr: A,
        rtt: Duration,
        token: String,
        root: String,
        session_id: String,
    ) -> io::Result<Self> {
        use tokio::io::AsyncWriteExt;

        let mut stream = TcpStream::connect(addr).await?;
        let payload = sembazuru_dataplane::ops::HelloRequest {
            token,
            root,
            session_id,
        }
        .encode();
        write_frame(
            &mut stream,
            FrameHeader {
                request_id: 0,
                op: OpCode::Hello,
                is_response: false,
            },
            &payload,
        )
        .await?;
        stream.flush().await?;
        let (header, resp) = read_frame(&mut stream).await?;
        if header.op != OpCode::Hello || !header.is_response {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data-plane handshake response did not correlate",
            ));
        }
        let hello = sembazuru_dataplane::ops::HelloResponse::decode(&resp).map_err(to_io)?;
        if !hello.ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("data-plane session rejected: {}", hello.detail),
            ));
        }
        let (rd, wr) = stream.into_split();
        let mux = Arc::new(Mux {
            write: Mutex::new(wr),
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            rtt,
        });
        tokio::spawn(Arc::clone(&mux).read_loop(rd));
        Ok(FileClient { mux })
    }

    async fn call(&self, op: OpCode, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.mux.call(op, payload).await
    }

    pub async fn stat_batch(&self, paths: &[String]) -> io::Result<StatResponse> {
        let payload = StatRequest {
            paths: paths.to_vec(),
        }
        .encode();
        let resp = self.call(OpCode::StatBatch, &payload).await?;
        StatResponse::decode(&resp).map_err(to_io)
    }

    /// Resolves `path`, optionally inlining its first chunk. With
    /// `want_inline = false` this is a cheap *digest probe* (no content bytes).
    pub async fn open_read(&self, path: &str, want_inline: bool) -> io::Result<OpenReadResponse> {
        let payload = OpenReadRequest {
            path: path.to_string(),
            want_inline,
        }
        .encode();
        let resp = self.call(OpCode::OpenRead, &payload).await?;
        OpenReadResponse::decode(&resp).map_err(to_io)
    }

    pub async fn read(&self, digest: &str, offset: u64, len: u32) -> io::Result<ReadResponse> {
        let payload = ReadRequest {
            digest_hex: digest.to_string(),
            offset,
            len,
        }
        .encode();
        let resp = self.call(OpCode::Read, &payload).await?;
        ReadResponse::decode(&resp).map_err(to_io)
    }

    /// Asks the agent which of `digests` it already holds (`§4.3`). Used before
    /// uploading outputs so a rebuild re-sends nothing the agent already has.
    pub async fn has(&self, digests: &[String]) -> io::Result<Vec<bool>> {
        let payload = HasRequest {
            digests: digests.to_vec(),
        }
        .encode();
        let resp = self.call(OpCode::Has, &payload).await?;
        Ok(HasResponse::decode(&resp).map_err(to_io)?.present)
    }

    /// Returns a produced output to the agent for atomic publication at `path`,
    /// streamed in fixed chunks so a large output is never buffered whole on
    /// either side. The agent verifies the full digest on the final chunk, so a
    /// corrupted transfer is rejected rather than published. A small output is a
    /// single chunk.
    pub async fn write_back(&self, path: &str, bytes: &[u8]) -> io::Result<WriteBackResponse> {
        let digest = Digest::of(bytes).canonical();
        let mut offset = 0usize;
        loop {
            let end = (offset + WRITEBACK_CHUNK).min(bytes.len());
            let last = end == bytes.len();
            let payload = WriteBackRequest {
                path: path.to_string(),
                digest_hex: digest.clone(),
                offset: offset as u64,
                bytes: bytes[offset..end].to_vec(),
                last,
            }
            .encode();
            let resp = self.call(OpCode::WriteBack, &payload).await?;
            let resp = WriteBackResponse::decode(&resp).map_err(to_io)?;
            // Stop on the last chunk or on any agent-side rejection (the agent
            // drops its temp, so nothing is left half-published).
            if last || !resp.ok {
                return Ok(resp);
            }
            offset = end;
        }
    }

    pub async fn dir_list(&self, path: &str, depth: u32) -> io::Result<DirListResponse> {
        let payload = DirListRequest {
            path: path.to_string(),
            depth,
        }
        .encode();
        let resp = self.call(OpCode::DirList, &payload).await?;
        DirListResponse::decode(&resp).map_err(to_io)
    }

    /// Digest-first resolve: the path's `(digest, size)` with **no content
    /// transfer** (`want_inline = false`), or `None` if it does not exist. The
    /// caller checks its local cache against the digest and fetches only on a
    /// miss — the core of the no-re-transfer worker cache (M4).
    pub async fn probe_digest(&self, path: &str) -> io::Result<Option<(Digest, u64)>> {
        let open = self.open_read(path, false).await?;
        if !open.exists {
            return Ok(None);
        }
        let digest = Digest::parse(&open.digest_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad digest: {e}")))?;
        Ok(Some((digest, open.size)))
    }

    /// Fetches the full content of `digest` (whose size is `size`) by ranged
    /// `Read`, verifying the assembled bytes against the digest. For the cache
    /// path: probe first, then fetch only on a miss.
    pub async fn fetch_by_digest(&self, digest: &Digest, size: u64) -> io::Result<Vec<u8>> {
        let size = size as usize;
        let mut bytes = Vec::with_capacity(size);
        let digest_str = digest.canonical();
        while bytes.len() < size {
            let want = READ_CHUNK.min((size - bytes.len()) as u32);
            let chunk = self.read(&digest_str, bytes.len() as u64, want).await?;
            if chunk.bytes.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent returned no bytes before the file was fully read",
                ));
            }
            bytes.extend_from_slice(&chunk.bytes);
        }
        verify(&bytes, digest)?;
        Ok(bytes)
    }

    /// Pulls the full contents of `path` for hydration, using the inline-first-
    /// chunk fast path. Returns `None` if the file does not exist on the agent.
    /// The fetched bytes are verified against the agent-reported digest.
    pub async fn fetch(&self, path: &str) -> io::Result<Option<(Vec<u8>, Digest)>> {
        let open = self.open_read(path, true).await?;
        if !open.exists {
            return Ok(None);
        }
        let digest = Digest::parse(&open.digest_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad digest: {e}")))?;
        let size = open.size as usize;
        let mut bytes = open.first_chunk;
        let digest_str = open.digest_hex;
        while bytes.len() < size {
            let want = READ_CHUNK.min((size - bytes.len()) as u32);
            let chunk = self.read(&digest_str, bytes.len() as u64, want).await?;
            if chunk.bytes.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent returned no bytes before the file was fully read",
                ));
            }
            bytes.extend_from_slice(&chunk.bytes);
        }
        verify(&bytes, &digest)?;
        Ok(Some((bytes, digest)))
    }
}

/// Integrity check: the assembled bytes must hash to the digest the agent
/// reported. A mismatch is a corrupted transfer (or a lying peer), never
/// silently accepted.
fn verify(bytes: &[u8], digest: &Digest) -> io::Result<()> {
    let actual = Digest::of(bytes);
    if &actual != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("digest mismatch: agent said {digest}, got {actual}"),
        ));
    }
    Ok(())
}

fn to_io(e: sembazuru_dataplane::wire::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
