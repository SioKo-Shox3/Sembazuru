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
    DirListRequest, DirListResponse, HasRequest, HasResponse, MAX_HAS_DIGESTS, MAX_STAT_PATHS,
    OpenReadRequest, OpenReadResponse, ReadRequest, ReadResponse, StatRequest, StatResponse,
    WriteBackRequest, WriteBackResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{Mutex, Semaphore, oneshot};

/// How much to request per Read after the inlined first chunk.
const READ_CHUNK: u32 = 256 * 1024;

/// Per-op deadline for a data-plane response (RES-001). Generous (a single op —
/// Stat/OpenRead/a bounded Read chunk — is fast on a LAN), but finite: a peer that
/// accepts the frame and then never answers must not hang a hydrate forever.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// WriteBack chunk size for streaming outputs (ADR 0003: large files stream in
/// fixed chunks). A small output fits in a single chunk.
const WRITEBACK_CHUNK: usize = 1024 * 1024;

pub const MAX_IN_FLIGHT_REQUESTS: usize = 128;

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
    in_flight: Semaphore,
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
        let _permit = self.in_flight.acquire().await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "data-plane in-flight limiter closed",
            )
        })?;
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
        let (header, resp) = match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "data-plane connection closed",
                ));
            }
            // The server accepted our frame but never answered within the deadline.
            // Remove our pending waiter (don't leak it) and fail the op, so a
            // hydrate cannot hang forever on an accept-but-never-respond peer
            // (RES-001). The connection itself is left to the reader task / next op.
            Err(_) => {
                self.pending.lock().await.remove(&id);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "data-plane op timed out waiting for a response",
                ));
            }
        };
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
        Self::connect_inner(addr, rtt, token, root, session_id, MAX_IN_FLIGHT_REQUESTS).await
    }

    async fn connect_inner<A: ToSocketAddrs>(
        addr: A,
        rtt: Duration,
        token: String,
        root: String,
        session_id: String,
        max_in_flight: usize,
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
            in_flight: Semaphore::new(max_in_flight),
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
        if paths.is_empty() {
            return Ok(StatResponse {
                entries: Vec::new(),
            });
        }
        let mut entries = Vec::with_capacity(paths.len());
        for chunk in paths.chunks(MAX_STAT_PATHS) {
            let payload = StatRequest {
                paths: chunk.to_vec(),
            }
            .encode();
            let resp = self.call(OpCode::StatBatch, &payload).await?;
            entries.extend(StatResponse::decode(&resp).map_err(to_io)?.entries);
        }
        Ok(StatResponse { entries })
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
        if digests.is_empty() {
            return Ok(Vec::new());
        }
        let mut present = Vec::with_capacity(digests.len());
        for chunk in digests.chunks(MAX_HAS_DIGESTS) {
            let payload = HasRequest {
                digests: chunk.to_vec(),
            }
            .encode();
            let resp = self.call(OpCode::Has, &payload).await?;
            present.extend(HasResponse::decode(&resp).map_err(to_io)?.present);
        }
        Ok(present)
    }

    /// Returns a produced output to the agent for atomic publication at the
    /// agent-authoritative target named by `output_id`, streamed in fixed chunks
    /// so a large output is never buffered whole on either side. The agent
    /// verifies the full digest on the final chunk, so a corrupted transfer is
    /// rejected rather than published. A small output is a single chunk.
    pub async fn write_back(&self, output_id: u32, bytes: &[u8]) -> io::Result<WriteBackResponse> {
        let digest = Digest::of(bytes).canonical();
        let mut offset = 0usize;
        loop {
            let end = (offset + WRITEBACK_CHUNK).min(bytes.len());
            let last = end == bytes.len();
            let payload = WriteBackRequest {
                output_id,
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
        let (mut bytes, size) = content_buffer(Vec::new(), size)?;
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
        let (mut bytes, size) = content_buffer(open.first_chunk, open.size)?;
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

fn content_buffer(mut initial: Vec<u8>, declared_size: u64) -> io::Result<(Vec<u8>, usize)> {
    let size = usize::try_from(declared_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("content size {declared_size} exceeds this worker's address space"),
        )
    })?;
    initial
        .try_reserve_exact(size.saturating_sub(initial.len()))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("content size {declared_size} cannot be buffered safely: {error}"),
            )
        })?;
    Ok((initial, size))
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

#[cfg(test)]
mod tests {
    use super::*;
    use sembazuru_dataplane::ops::{HelloResponse, StatEntry};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    async fn accept_test_handshake(listener: TcpListener) -> TcpStream {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (header, _) = read_frame(&mut sock).await.unwrap();
        let payload = HelloResponse {
            ok: true,
            detail: String::new(),
        }
        .encode();
        write_frame(
            &mut sock,
            FrameHeader {
                request_id: header.request_id,
                op: OpCode::Hello,
                is_response: true,
            },
            &payload,
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        sock
    }

    async fn start_scripted_read_server(
        responses: Vec<(u64, u32, Vec<u8>)>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut sock = accept_test_handshake(listener).await;
            for (expected_offset, expected_len, bytes) in responses {
                let (header, payload) = read_frame(&mut sock).await.unwrap();
                let request = ReadRequest::decode(&payload).unwrap();
                assert_eq!(header.op, OpCode::Read);
                assert_eq!(request.offset, expected_offset);
                assert_eq!(request.len, expected_len);
                let response = ReadResponse { bytes }.encode();
                write_frame(
                    &mut sock,
                    FrameHeader {
                        request_id: header.request_id,
                        op: OpCode::Read,
                        is_response: true,
                    },
                    &response,
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
            }
        });
        addr
    }

    async fn start_no_read_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut sock = accept_test_handshake(listener).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), read_frame(&mut sock))
                    .await
                    .is_err(),
                "oversized content must be rejected before a Read request is sent"
            );
        });
        (addr, server)
    }

    async fn start_oversized_open_server(
        size: u64,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut sock = accept_test_handshake(listener).await;
            let (header, payload) = read_frame(&mut sock).await.unwrap();
            let request = OpenReadRequest::decode(&payload).unwrap();
            assert_eq!(header.op, OpCode::OpenRead);
            assert!(request.want_inline);
            let response = OpenReadResponse {
                exists: true,
                size,
                digest_hex: Digest::of(b"").canonical(),
                first_chunk: Vec::new(),
            }
            .encode();
            write_frame(
                &mut sock,
                FrameHeader {
                    request_id: header.request_id,
                    op: OpCode::OpenRead,
                    is_response: true,
                },
                &response,
            )
            .await
            .unwrap();
            sock.flush().await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), read_frame(&mut sock))
                    .await
                    .is_err(),
                "oversized content must be rejected before a Read request is sent"
            );
        });
        (addr, server)
    }

    #[tokio::test]
    async fn fetch_by_digest_rejects_unbufferable_size_before_read() {
        let (addr, server) = start_no_read_server().await;
        let client = FileClient::connect(addr).await.unwrap();

        let error = client
            .fetch_by_digest(&Digest::of(b""), u64::MAX)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("content size"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_rejects_unbufferable_size_before_read() {
        let (addr, server) = start_oversized_open_server(u64::MAX).await;
        let client = FileClient::connect(addr).await.unwrap();

        let error = client.fetch(r"c:\src\oversized.h").await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("content size"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_by_digest_rejects_blob_removed_between_ranges() {
        let body = vec![0x41; READ_CHUNK as usize + 17];
        let digest = Digest::of(&body);
        let addr = start_scripted_read_server(vec![
            (0, READ_CHUNK, body[..READ_CHUNK as usize].to_vec()),
            (READ_CHUNK as u64, 17, Vec::new()),
        ])
        .await;
        let client = FileClient::connect(addr).await.unwrap();

        let error = client
            .fetch_by_digest(&digest, body.len() as u64)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn fetch_by_digest_rejects_blob_changed_between_ranges() {
        let body = vec![0x41; READ_CHUNK as usize + 17];
        let digest = Digest::of(&body);
        let addr = start_scripted_read_server(vec![
            (0, READ_CHUNK, body[..READ_CHUNK as usize].to_vec()),
            (READ_CHUNK as u64, 17, vec![0x42; 17]),
        ])
        .await;
        let client = FileClient::connect(addr).await.unwrap();

        let error = client
            .fetch_by_digest(&digest, body.len() as u64)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn fileclient_in_flight_requests_are_bounded() {
        const TEST_MAX_IN_FLIGHT: usize = 2;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let sock = accept_test_handshake(listener).await;
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(sock);
        });
        let client = FileClient::connect_inner(
            addr,
            Duration::ZERO,
            String::new(),
            String::new(),
            String::new(),
            TEST_MAX_IN_FLIGHT,
        )
        .await
        .unwrap();

        let mut calls = Vec::new();
        for i in 0..TEST_MAX_IN_FLIGHT {
            let c = client.clone();
            calls.push(tokio::spawn(async move {
                let _ = c.open_read(&format!("c:\\blocked\\{i}.h"), false).await;
            }));
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if client.mux.pending.lock().await.len() == TEST_MAX_IN_FLIGHT {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cap requests should enter the pending map");

        let extra_client = client.clone();
        let extra = tokio::spawn(async move {
            let _ = extra_client.open_read("c:\\blocked\\extra.h", false).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !extra.is_finished(),
            "cap+1 request must wait while all in-flight slots are held"
        );
        assert_eq!(client.mux.pending.lock().await.len(), TEST_MAX_IN_FLIGHT);

        for call in calls {
            call.abort();
        }
        extra.abort();
        server.abort();
    }

    #[tokio::test]
    async fn stat_batch_chunks_requests_and_concatenates_entries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server_seen = Arc::clone(&seen);
        let server = tokio::spawn(async move {
            let mut sock = accept_test_handshake(listener).await;
            while let Ok((header, payload)) = read_frame(&mut sock).await {
                let req = StatRequest::decode(&payload).unwrap();
                server_seen.lock().await.push(req.paths.len());
                let entries = req
                    .paths
                    .into_iter()
                    .map(|path| StatEntry {
                        exists: true,
                        is_dir: false,
                        size: path.len() as u64,
                        digest_hex: String::new(),
                    })
                    .collect();
                let resp = StatResponse { entries }.encode();
                write_frame(
                    &mut sock,
                    FrameHeader {
                        request_id: header.request_id,
                        op: OpCode::StatBatch,
                        is_response: true,
                    },
                    &resp,
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
            }
        });
        let client = FileClient::connect(addr).await.unwrap();
        let paths = (0..(MAX_STAT_PATHS + 1))
            .map(|i| format!("c:\\src\\file-{i}.h"))
            .collect::<Vec<_>>();

        let response = client.stat_batch(&paths).await.unwrap();

        assert_eq!(response.entries.len(), paths.len());
        assert_eq!(*seen.lock().await, vec![MAX_STAT_PATHS, 1]);
        server.abort();
    }

    #[tokio::test]
    async fn has_chunks_requests_and_concatenates_results() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server_seen = Arc::clone(&seen);
        let server = tokio::spawn(async move {
            let mut sock = accept_test_handshake(listener).await;
            while let Ok((header, payload)) = read_frame(&mut sock).await {
                let req = HasRequest::decode(&payload).unwrap();
                server_seen.lock().await.push(req.digests.len());
                let resp = HasResponse {
                    present: req
                        .digests
                        .iter()
                        .enumerate()
                        .map(|(i, _)| i % 2 == 0)
                        .collect(),
                }
                .encode();
                write_frame(
                    &mut sock,
                    FrameHeader {
                        request_id: header.request_id,
                        op: OpCode::Has,
                        is_response: true,
                    },
                    &resp,
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
            }
        });
        let client = FileClient::connect(addr).await.unwrap();
        let digests = (0..(MAX_HAS_DIGESTS + 1))
            .map(|i| format!("blake3:{i:064x}"))
            .collect::<Vec<_>>();

        let present = client.has(&digests).await.unwrap();

        assert_eq!(present.len(), digests.len());
        assert_eq!(*seen.lock().await, vec![MAX_HAS_DIGESTS, 1]);
        assert!(present[0]);
        assert!(!present[1]);
        assert!(present[MAX_HAS_DIGESTS]);
        server.abort();
    }
}
