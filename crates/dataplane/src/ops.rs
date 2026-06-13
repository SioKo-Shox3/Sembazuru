//! Op payload codecs (`docs/protocol/v0.md` §4.1). Every op is batch-first; the
//! singular forms are just batches of one. Each request/response encodes to and
//! decodes from a payload buffer that travels inside a framed message
//! (`crate::wire`). A digest is carried as its canonical `algo:hex` string
//! (e.g. `blake3:ab12…`, ADR 0003); an empty string means "no digest" (e.g. a
//! negative stat result).
//!
//! M3.2 read path: StatBatch / OpenRead / Read / DirList. WriteBack is M3.3.
//! `Has` (M4) is the batch existence probe (§4.3); PrefetchHint (M5) is added
//! when that milestone lands.

use crate::wire::{Error, Reader, Writer};

/// Bounds an up-front `Vec::with_capacity` hint taken from an untrusted count,
/// so a hostile length can't drive a huge allocation before the per-element
/// reads fail. The loop still runs the real count; it just doesn't pre-reserve
/// for it.
fn cap_hint(n: usize) -> usize {
    n.min(4096)
}

// --- StatBatch -----------------------------------------------------------

/// Existence + attributes + digest for many paths in one round-trip. Header
/// resolution probes many *non-existent* paths, so negative results are normal
/// and batchable (`exists == false`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatRequest {
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatEntry {
    pub exists: bool,
    pub is_dir: bool,
    pub size: u64,
    /// Lowercase hex content digest, or empty when absent (missing, a dir, or
    /// not yet hashed).
    pub digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResponse {
    /// One entry per requested path, in request order.
    pub entries: Vec<StatEntry>,
}

impl StatRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.paths.len() as u32);
        for p in &self.paths {
            w.str(p);
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let n = r.u32()? as usize;
        let mut paths = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            paths.push(r.str()?);
        }
        r.finish()?;
        Ok(StatRequest { paths })
    }
}

impl StatResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            w.bool(e.exists);
            w.bool(e.is_dir);
            w.u64(e.size);
            w.str(&e.digest_hex);
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let n = r.u32()? as usize;
        let mut entries = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            entries.push(StatEntry {
                exists: r.bool()?,
                is_dir: r.bool()?,
                size: r.u64()?,
                digest_hex: r.str()?,
            });
        }
        r.finish()?;
        Ok(StatResponse { entries })
    }
}

// --- OpenRead ------------------------------------------------------------

/// Open-for-read resolves to content identity; the first chunk MAY be inlined so
/// `open` + first `read` is a single round-trip.
///
/// `want_inline` lets the caller suppress the inlined first chunk. A
/// worker-local-cache client (M4) wants only the digest first — if it already
/// holds that content it fetches nothing, so inlining bytes it may discard would
/// defeat the "no re-transfer" goal. It sets `want_inline = false` (a *digest
/// probe*) and only `Read`s on a cache miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReadRequest {
    pub path: String,
    pub want_inline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReadResponse {
    pub exists: bool,
    pub size: u64,
    pub digest_hex: String,
    /// The leading bytes of the file, inlined to save a round-trip. May be empty
    /// (the file is empty, or the server chose not to inline).
    pub first_chunk: Vec<u8>,
}

impl OpenReadRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(&self.path);
        w.bool(self.want_inline);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let path = r.str()?;
        let want_inline = r.bool()?;
        r.finish()?;
        Ok(OpenReadRequest { path, want_inline })
    }
}

impl OpenReadResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bool(self.exists);
        w.u64(self.size);
        w.str(&self.digest_hex);
        w.bytes(&self.first_chunk);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let exists = r.bool()?;
        let size = r.u64()?;
        let digest_hex = r.str()?;
        let first_chunk = r.bytes()?;
        r.finish()?;
        Ok(OpenReadResponse {
            exists,
            size,
            digest_hex,
            first_chunk,
        })
    }
}

// --- Read ----------------------------------------------------------------

/// Content fetch by digest (CAS-mediated; the worker's local cache is consulted
/// first from M4). Ranged so large files stream in bounded chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub digest_hex: String,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResponse {
    pub bytes: Vec<u8>,
}

impl ReadRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(&self.digest_hex);
        w.u64(self.offset);
        w.u32(self.len);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let digest_hex = r.str()?;
        let offset = r.u64()?;
        let len = r.u32()?;
        r.finish()?;
        Ok(ReadRequest {
            digest_hex,
            offset,
            len,
        })
    }
}

impl ReadResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.bytes);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let bytes = r.bytes()?;
        r.finish()?;
        Ok(ReadResponse { bytes })
    }
}

// --- DirList -------------------------------------------------------------

/// Bulk directory snapshot, prefetching metadata for the stats likely to follow.
/// `depth` is how many levels to include (0 = the directory itself only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirListRequest {
    pub path: String,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Path relative to the requested directory (so one response describes a
    /// subtree without repeating the root).
    pub rel_path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirListResponse {
    pub exists: bool,
    pub entries: Vec<DirEntry>,
}

impl DirListRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(&self.path);
        w.u32(self.depth);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let path = r.str()?;
        let depth = r.u32()?;
        r.finish()?;
        Ok(DirListRequest { path, depth })
    }
}

impl DirListResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bool(self.exists);
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            w.str(&e.rel_path);
            w.bool(e.is_dir);
            w.u64(e.size);
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let exists = r.bool()?;
        let n = r.u32()? as usize;
        let mut entries = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            entries.push(DirEntry {
                rel_path: r.str()?,
                is_dir: r.bool()?,
                size: r.u64()?,
            });
        }
        r.finish()?;
        Ok(DirListResponse { exists, entries })
    }
}

// --- WriteBack -----------------------------------------------------------

/// Worker -> Agent output return (`docs/protocol/v0.md` §4.1), streamed.
///
/// An output is sent as one or more chunks at increasing `offset`; `digest_hex`
/// is the **whole file's** digest (constant across the stream). The agent
/// appends each chunk to a temp file and, on the chunk with `last == true`,
/// verifies the assembled file against `digest_hex` and atomically renames it
/// onto `path` (§3.2). A small output is just a single chunk with `offset == 0`
/// and `last == true` — so this one shape covers both the M3.3 single-shot case
/// and the M4.4 large-output case without holding the whole blob in memory
/// (ADR 0003: large files stream in fixed chunks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBackRequest {
    /// Agent-side logical path to publish the output at.
    pub path: String,
    /// Digest of the *entire* output (every chunk of one output repeats it).
    pub digest_hex: String,
    /// Byte offset of this chunk within the output (must equal the bytes
    /// received so far for `path`; chunks are in order).
    pub offset: u64,
    /// This chunk's bytes.
    pub bytes: Vec<u8>,
    /// True on the final chunk: triggers digest verification and atomic publish.
    pub last: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBackResponse {
    pub ok: bool,
    /// Cause when `ok == false` (digest mismatch, write/rename failure).
    pub detail: String,
}

impl WriteBackRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(&self.path);
        w.str(&self.digest_hex);
        w.u64(self.offset);
        w.bytes(&self.bytes);
        w.bool(self.last);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let path = r.str()?;
        let digest_hex = r.str()?;
        let offset = r.u64()?;
        let bytes = r.bytes()?;
        let last = r.bool()?;
        r.finish()?;
        Ok(WriteBackRequest {
            path,
            digest_hex,
            offset,
            bytes,
            last,
        })
    }
}

impl WriteBackResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bool(self.ok);
        w.str(&self.detail);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let ok = r.bool()?;
        let detail = r.str()?;
        r.finish()?;
        Ok(WriteBackResponse { ok, detail })
    }
}

// --- Has ----------------------------------------------------------------

/// Batch existence probe (`docs/protocol/v0.md` §4.3): "which of these digests
/// do you already hold?" Before transferring a blob, the peer asks `Has` and
/// sends only the missing ones — the upload-side dedup that keeps a rebuild's
/// output transfer near zero. (The read-side worker cache checks its own local
/// store directly and needs no round-trip.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HasRequest {
    /// Canonical `algo:hex` digest strings.
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HasResponse {
    /// One flag per requested digest, in request order: true = present.
    pub present: Vec<bool>,
}

impl HasRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.digests.len() as u32);
        for d in &self.digests {
            w.str(d);
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let n = r.u32()? as usize;
        let mut digests = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            digests.push(r.str()?);
        }
        r.finish()?;
        Ok(HasRequest { digests })
    }
}

impl HasResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.present.len() as u32);
        for &p in &self.present {
            w.bool(p);
        }
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let n = r.u32()? as usize;
        let mut present = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            present.push(r.bool()?);
        }
        r.finish()?;
        Ok(HasResponse { present })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_round_trips_including_negative_results() {
        let req = StatRequest {
            paths: vec!["c:\\inc\\stdio.h".into(), "c:\\nope.h".into()],
        };
        assert_eq!(StatRequest::decode(&req.encode()).unwrap(), req);

        let resp = StatResponse {
            entries: vec![
                StatEntry {
                    exists: true,
                    is_dir: false,
                    size: 1234,
                    digest_hex: "abcd".into(),
                },
                StatEntry {
                    exists: false,
                    is_dir: false,
                    size: 0,
                    digest_hex: String::new(),
                },
            ],
        };
        assert_eq!(StatResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn open_read_round_trips_with_inline_chunk() {
        let resp = OpenReadResponse {
            exists: true,
            size: 5,
            digest_hex: "deadbeef".into(),
            first_chunk: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(OpenReadResponse::decode(&resp.encode()).unwrap(), resp);

        let req = OpenReadRequest {
            path: "c:\\src\\a.cpp".into(),
            want_inline: true,
        };
        assert_eq!(OpenReadRequest::decode(&req.encode()).unwrap(), req);
        // The digest-probe form (no inline) round-trips too.
        let probe = OpenReadRequest {
            path: "c:\\src\\a.cpp".into(),
            want_inline: false,
        };
        assert_eq!(OpenReadRequest::decode(&probe.encode()).unwrap(), probe);
    }

    #[test]
    fn has_round_trips() {
        let req = HasRequest {
            digests: vec!["blake3:aa".into(), "blake3:bb".into()],
        };
        assert_eq!(HasRequest::decode(&req.encode()).unwrap(), req);
        let resp = HasResponse {
            present: vec![true, false, true],
        };
        assert_eq!(HasResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn read_round_trips() {
        let req = ReadRequest {
            digest_hex: "ff00".into(),
            offset: 4096,
            len: 65536,
        };
        assert_eq!(ReadRequest::decode(&req.encode()).unwrap(), req);
        let resp = ReadResponse {
            bytes: vec![0xAB; 10],
        };
        assert_eq!(ReadResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn dirlist_round_trips() {
        let req = DirListRequest {
            path: "c:\\inc".into(),
            depth: 1,
        };
        assert_eq!(DirListRequest::decode(&req.encode()).unwrap(), req);
        let resp = DirListResponse {
            exists: true,
            entries: vec![
                DirEntry {
                    rel_path: "stdio.h".into(),
                    is_dir: false,
                    size: 800,
                },
                DirEntry {
                    rel_path: "sys".into(),
                    is_dir: true,
                    size: 0,
                },
            ],
        };
        assert_eq!(DirListResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn write_back_round_trips() {
        let req = WriteBackRequest {
            path: "c:\\out\\a.obj".into(),
            digest_hex: "blake3:feedface".into(),
            offset: 0,
            bytes: vec![0u8, 1, 2, 255, 128],
            last: true,
        };
        assert_eq!(WriteBackRequest::decode(&req.encode()).unwrap(), req);
        // A mid-stream chunk (nonzero offset, not last) round-trips too.
        let mid = WriteBackRequest {
            path: "c:\\out\\big.pdb".into(),
            digest_hex: "blake3:abcd".into(),
            offset: 1_048_576,
            bytes: vec![7u8; 16],
            last: false,
        };
        assert_eq!(WriteBackRequest::decode(&mid.encode()).unwrap(), mid);
        let resp = WriteBackResponse {
            ok: false,
            detail: "digest mismatch".into(),
        };
        assert_eq!(WriteBackResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = OpenReadRequest {
            path: "x".into(),
            want_inline: true,
        }
        .encode();
        bytes.push(0); // junk after the struct
        assert_eq!(OpenReadRequest::decode(&bytes), Err(Error::TrailingBytes));
    }
}
