//! Worker-side data-plane client (`docs/protocol/v0.md` §4): the worker's view
//! of the agent filesystem. It issues StatBatch / OpenRead / Read / DirList and,
//! via [`FileClient::fetch`], pulls a whole file's bytes for hydrate-on-open
//! (M3.2) — verifying the content digest end-to-end (§5: integrity is free).
//!
//! **M3.2 scope.** Calls are sequential (one request, await its response). The
//! frame format already carries request ids for out-of-order completion; the
//! pipelining that exploits that is M3.5 latency work.

use std::io;

use sembazuru_dataplane::async_io::{read_frame, write_frame};
use sembazuru_dataplane::ops::{
    DirListRequest, DirListResponse, OpenReadRequest, OpenReadResponse, ReadRequest, ReadResponse,
    StatRequest, StatResponse,
};
use sembazuru_dataplane::wire::{FrameHeader, OpCode};
use sembazuru_tracer::determinism::sha256_hex;
use tokio::net::{TcpStream, ToSocketAddrs};

/// How much to request per Read after the inlined first chunk.
const READ_CHUNK: u32 = 256 * 1024;

pub struct FileClient {
    stream: TcpStream,
    next_id: u64,
}

impl FileClient {
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(FileClient { stream, next_id: 1 })
    }

    /// One request/response round-trip. Verifies the response correlates to the
    /// request (same id, response flag, same op) so a desynchronized stream is
    /// caught rather than silently mis-parsed.
    async fn call(&mut self, op: OpCode, payload: &[u8]) -> io::Result<Vec<u8>> {
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

    pub async fn open_read(&mut self, path: &str) -> io::Result<OpenReadResponse> {
        let payload = OpenReadRequest {
            path: path.to_string(),
        }
        .encode();
        let resp = self.call(OpCode::OpenRead, &payload).await?;
        OpenReadResponse::decode(&resp).map_err(to_io)
    }

    pub async fn read(
        &mut self,
        digest_hex: &str,
        offset: u64,
        len: u32,
    ) -> io::Result<ReadResponse> {
        let payload = ReadRequest {
            digest_hex: digest_hex.to_string(),
            offset,
            len,
        }
        .encode();
        let resp = self.call(OpCode::Read, &payload).await?;
        ReadResponse::decode(&resp).map_err(to_io)
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

    /// Pulls the full contents of `path` for hydration. Returns `None` if the
    /// file does not exist on the agent. The fetched bytes are verified against
    /// the digest the agent reported; a mismatch is an integrity error.
    pub async fn fetch(&mut self, path: &str) -> io::Result<Option<(Vec<u8>, String)>> {
        let open = self.open_read(path).await?;
        if !open.exists {
            return Ok(None);
        }
        let size = open.size as usize;
        let mut bytes = open.first_chunk;
        while bytes.len() < size {
            let want = READ_CHUNK.min((size - bytes.len()) as u32);
            let chunk = self
                .read(&open.digest_hex, bytes.len() as u64, want)
                .await?;
            if chunk.bytes.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent returned no bytes before the file was fully read",
                ));
            }
            bytes.extend_from_slice(&chunk.bytes);
        }
        let actual = sha256_hex(&bytes);
        if actual != open.digest_hex {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "digest mismatch fetching {path}: agent said {}, got {actual}",
                    open.digest_hex
                ),
            ));
        }
        Ok(Some((bytes, open.digest_hex)))
    }
}

fn to_io(e: sembazuru_dataplane::wire::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}
