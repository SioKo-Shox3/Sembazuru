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
//! **M3.2 scope.** Calls are sequential (one request, await its response). The
//! frame format already carries request ids for out-of-order completion; the
//! pipelining that exploits that is M5 latency work.

use std::io;
use std::time::{Duration, Instant};

use sembazuru_cas::Digest;
use sembazuru_dataplane::async_io::{read_frame, write_frame};
use sembazuru_dataplane::ops::{
    DirListRequest, DirListResponse, HasRequest, HasResponse, OpenReadRequest, OpenReadResponse,
    ReadRequest, ReadResponse, StatRequest, StatResponse, WriteBackRequest, WriteBackResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use tokio::net::{TcpStream, ToSocketAddrs};

/// How much to request per Read after the inlined first chunk.
const READ_CHUNK: u32 = 256 * 1024;

/// WriteBack chunk size for streaming outputs (ADR 0003: large files stream in
/// fixed chunks). A small output fits in a single chunk.
const WRITEBACK_CHUNK: usize = 1024 * 1024;

pub struct FileClient {
    stream: TcpStream,
    next_id: u64,
    /// Synthetic per-op latency for benchmarking against a single machine, where
    /// clumsy/QoS cannot shape loopback (docs/research/m3-prestudy.md §2). Zero
    /// in production. Applied identically to every op so it measures
    /// round-trips x RTT, the quantity the data plane is judged on.
    rtt: Duration,
}

impl FileClient {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Self::connect_with_rtt(addr, Duration::ZERO).await
    }

    /// Connects with a synthetic per-op RTT injected at the framing layer (for
    /// the M3.5 latency benchmark; pass `Duration::ZERO` in production).
    pub async fn connect_with_rtt<A: ToSocketAddrs>(addr: A, rtt: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(FileClient {
            stream,
            next_id: 1,
            rtt,
        })
    }

    /// One request/response round-trip. Verifies the response correlates to the
    /// request (same id, response flag, same op) so a desynchronized stream is
    /// caught rather than silently mis-parsed.
    async fn call(&mut self, op: OpCode, payload: &[u8]) -> io::Result<Vec<u8>> {
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
        let id = self.next_id;
        self.next_id += 1;
        write_frame(
            &mut self.stream,
            FrameHeader {
                request_id: id,
                op,
                is_response: false,
            },
            payload,
        )
        .await?;
        let (header, resp) = read_frame(&mut self.stream).await?;
        if header.request_id != id || !header.is_response || header.op != op {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data-plane response did not correlate to its request",
            ));
        }
        Ok(resp)
    }

    pub async fn stat_batch(&mut self, paths: &[String]) -> io::Result<StatResponse> {
        let payload = StatRequest {
            paths: paths.to_vec(),
        }
        .encode();
        let resp = self.call(OpCode::StatBatch, &payload).await?;
        StatResponse::decode(&resp).map_err(to_io)
    }

    /// Resolves `path`, optionally inlining its first chunk. With
    /// `want_inline = false` this is a cheap *digest probe* (no content bytes).
    pub async fn open_read(
        &mut self,
        path: &str,
        want_inline: bool,
    ) -> io::Result<OpenReadResponse> {
        let payload = OpenReadRequest {
            path: path.to_string(),
            want_inline,
        }
        .encode();
        let resp = self.call(OpCode::OpenRead, &payload).await?;
        OpenReadResponse::decode(&resp).map_err(to_io)
    }

    pub async fn read(&mut self, digest: &str, offset: u64, len: u32) -> io::Result<ReadResponse> {
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
    pub async fn has(&mut self, digests: &[String]) -> io::Result<Vec<bool>> {
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
    pub async fn write_back(&mut self, path: &str, bytes: &[u8]) -> io::Result<WriteBackResponse> {
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

    pub async fn dir_list(&mut self, path: &str, depth: u32) -> io::Result<DirListResponse> {
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
    pub async fn probe_digest(&mut self, path: &str) -> io::Result<Option<(Digest, u64)>> {
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
    pub async fn fetch_by_digest(&mut self, digest: &Digest, size: u64) -> io::Result<Vec<u8>> {
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
    pub async fn fetch(&mut self, path: &str) -> io::Result<Option<(Vec<u8>, Digest)>> {
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
