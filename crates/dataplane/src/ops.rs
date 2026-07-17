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

use crate::wire::{Error, HEADER_BYTES, MAX_FRAME_BODY, Reader, Writer};

pub const MAX_STAT_PATHS: usize = 4096;
pub const MAX_HAS_DIGESTS: usize = 4096;
pub const MAX_DIRLIST_ENTRIES: usize = 4096;
/// MetadataBatchV1 shares StatBatch's request cardinality limit. Keeping this
/// separate makes the versioned codec's bound explicit at its call sites.
pub const MAX_METADATA_PATHS: usize = 4096;

/// Bounds an up-front `Vec::with_capacity` hint taken from an untrusted count,
/// so a hostile length can't drive a huge allocation before the per-element
/// reads fail. The loop still runs the real count; it just doesn't pre-reserve
/// for it.
fn cap_hint(n: usize) -> usize {
    n.min(MAX_STAT_PATHS)
}

// --- MetadataBatchV1 ----------------------------------------------------

/// A metadata-only request for Win32 attribute APIs. This is intentionally a
/// new operation rather than an extension of StatBatch: old peers retain the
/// exact StatBatch framing and new peers can reject malformed fixed-width
/// replies before they reach the DLL boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataRequest {
    pub paths: Vec<String>,
}

/// Metadata for one path, in request order. `FilesystemError` preserves the
/// raw Win32 error code (for example ERROR_FILE_NOT_FOUND) so the hook can
/// preserve the native API contract without hydrating bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataEntry {
    Present {
        attributes: u32,
        size: u64,
        creation_time: u64,
        access_time: u64,
        write_time: u64,
    },
    FilesystemError {
        raw_error: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataResponse {
    pub entries: Vec<MetadataEntry>,
}

const METADATA_ENTRY_BYTES: usize = 41;
const METADATA_PRESENT: u8 = 0;
const METADATA_FILESYSTEM_ERROR: u8 = 1;

/// Returns whether a Win32 error is a stable metadata result that can cross
/// the protocol boundary. Other errors are infrastructure failures and must
/// cause local fallback instead of being cached as a filesystem answer.
pub const fn is_metadata_filesystem_error(raw_error: u32) -> bool {
    matches!(raw_error, 2 | 3 | 5 | 123 | 161 | 206 | 267)
}

impl MetadataRequest {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.paths.len() > MAX_METADATA_PATHS {
            return Err(Error::TooLarge);
        }
        let mut body = 4usize;
        for path in &self.paths {
            if path.len() > u32::MAX as usize {
                return Err(Error::TooLarge);
            }
            body = body
                .checked_add(4)
                .and_then(|body| body.checked_add(path.len()))
                .ok_or(Error::TooLarge)?;
        }
        if body.checked_add(HEADER_BYTES).ok_or(Error::TooLarge)? > MAX_FRAME_BODY {
            return Err(Error::TooLarge);
        }
        let mut w = Writer::new();
        w.u32(self.paths.len() as u32);
        for path in &self.paths {
            w.str(path);
        }
        Ok(w.into_bytes())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let n = r.u32()? as usize;
        if n > MAX_METADATA_PATHS {
            return Err(Error::TooLarge);
        }
        let mut paths = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            paths.push(r.str()?);
        }
        r.finish()?;
        Ok(Self { paths })
    }
}

impl MetadataResponse {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.entries.len() > MAX_METADATA_PATHS {
            return Err(Error::TooLarge);
        }
        let body = 4usize
            .checked_add(
                self.entries
                    .len()
                    .checked_mul(METADATA_ENTRY_BYTES)
                    .ok_or(Error::TooLarge)?,
            )
            .ok_or(Error::TooLarge)?;
        if body.checked_add(HEADER_BYTES).ok_or(Error::TooLarge)? > MAX_FRAME_BODY {
            return Err(Error::TooLarge);
        }
        let mut w = Writer::new();
        w.u32(self.entries.len() as u32);
        for entry in &self.entries {
            match entry {
                MetadataEntry::Present {
                    attributes,
                    size,
                    creation_time,
                    access_time,
                    write_time,
                } => {
                    if *attributes == u32::MAX {
                        return Err(Error::InvalidValue);
                    }
                    w.u8(METADATA_PRESENT);
                    w.u32(*attributes);
                    w.u64(*size);
                    w.u64(*creation_time);
                    w.u64(*access_time);
                    w.u64(*write_time);
                    w.u32(0);
                }
                MetadataEntry::FilesystemError { raw_error } => {
                    if !is_metadata_filesystem_error(*raw_error) {
                        return Err(Error::InvalidValue);
                    }
                    w.u8(METADATA_FILESYSTEM_ERROR);
                    w.u32(0);
                    w.u64(0);
                    w.u64(0);
                    w.u64(0);
                    w.u64(0);
                    w.u32(*raw_error);
                }
            }
        }
        Ok(w.into_bytes())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let n = r.u32()? as usize;
        if n > MAX_METADATA_PATHS {
            return Err(Error::TooLarge);
        }
        let byte_len = n
            .checked_mul(METADATA_ENTRY_BYTES)
            .and_then(|body| body.checked_add(4))
            .ok_or(Error::TooLarge)?;
        if buf.len() != byte_len {
            return Err(if buf.len() < byte_len {
                Error::Truncated
            } else {
                Error::TrailingBytes
            });
        }
        let mut entries = Vec::with_capacity(cap_hint(n));
        for _ in 0..n {
            let tag = r.u8()?;
            let attributes = r.u32()?;
            let size = r.u64()?;
            let creation_time = r.u64()?;
            let access_time = r.u64()?;
            let write_time = r.u64()?;
            let raw_error = r.u32()?;
            match tag {
                METADATA_PRESENT if attributes != u32::MAX && raw_error == 0 => {
                    entries.push(MetadataEntry::Present {
                        attributes,
                        size,
                        creation_time,
                        access_time,
                        write_time,
                    });
                }
                METADATA_FILESYSTEM_ERROR
                    if attributes == 0
                        && size == 0
                        && creation_time == 0
                        && access_time == 0
                        && write_time == 0
                        && is_metadata_filesystem_error(raw_error) =>
                {
                    entries.push(MetadataEntry::FilesystemError { raw_error });
                }
                _ => return Err(Error::InvalidValue),
            }
        }
        r.finish()?;
        Ok(Self { entries })
    }
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
        if n > MAX_STAT_PATHS {
            return Err(Error::TooLarge);
        }
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
        if n > MAX_DIRLIST_ENTRIES {
            return Err(Error::TooLarge);
        }
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
/// onto the agent-authoritative output target named by `output_id`. The worker
/// never names an agent-side path on this operation. A small output is just a
/// single chunk with `offset == 0` and `last == true` — so this one shape covers
/// both the M3.3 single-shot case and the M4.4 large-output case without holding
/// the whole blob in memory (ADR 0003: large files stream in fixed chunks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBackRequest {
    /// Agent-minted output id. The agent resolves it to the final path.
    pub output_id: u32,
    /// Digest of the *entire* output (every chunk of one output repeats it).
    pub digest_hex: String,
    /// Byte offset of this chunk within the output (must equal the bytes
    /// received so far for `output_id`; chunks are in order).
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
        w.u32(self.output_id);
        w.str(&self.digest_hex);
        w.u64(self.offset);
        w.bytes(&self.bytes);
        w.bool(self.last);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let output_id = r.u32()?;
        let digest_hex = r.str()?;
        let offset = r.u64()?;
        let bytes = r.bytes()?;
        let last = r.bool()?;
        r.finish()?;
        Ok(WriteBackRequest {
            output_id,
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
        if n > MAX_HAS_DIGESTS {
            return Err(Error::TooLarge);
        }
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

// --- Hello (session auth handshake, M7 / ADR 0006) -----------------------

/// The worker's session-opening handshake. Always the first frame on a data-
/// plane connection (M7.1): it presents the shared cluster token (M7.0, may be
/// empty when auth is off) and DECLARES the session's input root (M7.1) so the
/// agent can scope file supply to that subtree — an empty root means "no
/// scoping" (legacy/tests). See [`crate::wire::OpCode::Hello`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloRequest {
    pub token: String,
    /// Agent-side logical root the worker will read under (its `vfs_root`).
    /// The agent refuses to supply paths outside it. Empty = unscoped.
    ///
    /// As of ADR 0013 this field is **advisory**: when `session_id` names a known
    /// agent-minted session, the agent uses *its own* authoritative root for that
    /// session and ignores this one (closing the worker-can-widen-scope hole,
    /// SEC-004). It is still sent for the legacy/unscoped path (empty session_id).
    pub root: String,
    /// The agent-minted, unpredictable data-plane session id (ADR 0013). When it
    /// names a known session, the agent binds this connection to that session's
    /// authoritative root, per-session pin partition, allowed-digest set, and
    /// declared outputs. Empty = a pre-ADR-0013 worker (or a test) → the legacy
    /// per-connection, worker-declared-root path.
    pub session_id: String,
}

/// The agent's verdict on the handshake. `ok == false` means the agent will
/// close the connection; `detail` is a fixed safe string (no secret, no path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloResponse {
    pub ok: bool,
    pub detail: String,
}

impl HelloRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.str(&self.token);
        w.str(&self.root);
        w.str(&self.session_id);
        w.into_bytes()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(buf);
        let token = r.str()?;
        let root = r.str()?;
        // Tolerate an old 2-field frame (a pre-ADR-0013 worker sends no
        // session_id): `Reader::take` does not advance on EOF, so a read past the
        // end leaves the cursor put and yields the empty (legacy/unscoped) id.
        // `finish` still rejects genuinely trailing/partial bytes.
        let session_id = r.str().unwrap_or_default();
        r.finish()?;
        Ok(HelloRequest {
            token,
            root,
            session_id,
        })
    }
}

impl HelloResponse {
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
        Ok(HelloResponse { ok, detail })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    mod fuzz {
        use super::*;

        macro_rules! decode_all_ops {
            ($buf:expr; $($ty:ty),+ $(,)?) => {
                $(
                    let _ = <$ty>::decode($buf);
                )+
            };
        }

        proptest! {
            #[test]
            fn op_decoders_never_panic(buf in any::<Vec<u8>>()) {
                decode_all_ops!(
                    &buf;
                    HelloRequest,
                    HelloResponse,
                    StatRequest,
                    StatResponse,
                    OpenReadRequest,
                    OpenReadResponse,
                    ReadRequest,
                    ReadResponse,
                    DirListRequest,
                    DirListResponse,
                    WriteBackRequest,
                    WriteBackResponse,
                    HasRequest,
                    HasResponse,
                );
            }

            #[test]
            fn read_request_round_trips(
                digest_hex in any::<String>(),
                offset in any::<u64>(),
                len in any::<u32>(),
            ) {
                let req = ReadRequest {
                    digest_hex,
                    offset,
                    len,
                };
                prop_assert_eq!(ReadRequest::decode(&req.encode()).unwrap(), req);
            }

            #[test]
            fn write_back_request_round_trips(
                output_id in any::<u32>(),
                digest_hex in any::<String>(),
                offset in any::<u64>(),
                bytes in any::<Vec<u8>>(),
                last in any::<bool>(),
            ) {
                let req = WriteBackRequest {
                    output_id,
                    digest_hex,
                    offset,
                    bytes,
                    last,
                };
                prop_assert_eq!(WriteBackRequest::decode(&req.encode()).unwrap(), req);
            }
        }
    }

    #[test]
    fn hello_round_trips_and_tolerates_a_legacy_two_field_frame() {
        // ADR 0013: the 3-field Hello (token, root, session_id) round-trips.
        let h = HelloRequest {
            token: "s3cret".into(),
            root: "c:\\proj".into(),
            session_id: "0123456789abcdef0123456789abcdef".into(),
        };
        assert_eq!(HelloRequest::decode(&h.encode()).unwrap(), h);

        // A pre-ADR-0013 worker sends only token+root; decode must tolerate that
        // and yield an empty session_id (→ the legacy per-connection scoping path),
        // because `Reader::take` does not advance the cursor on an EOF read.
        let mut w = Writer::new();
        w.str("tok");
        w.str("c:\\legacy");
        let legacy = w.into_bytes();
        let decoded = HelloRequest::decode(&legacy).unwrap();
        assert_eq!(decoded.token, "tok");
        assert_eq!(decoded.root, "c:\\legacy");
        assert_eq!(
            decoded.session_id, "",
            "an old 2-field Hello must decode to an empty session id"
        );

        // Genuinely trailing bytes after a valid frame are still rejected — the
        // tolerant 3rd read does not turn `finish`'s trailing-junk guard off.
        let mut bad = h.encode();
        bad.push(0xff);
        assert!(
            HelloRequest::decode(&bad).is_err(),
            "trailing junk after a Hello must be rejected, not silently eaten"
        );
    }

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
    fn stat_request_decode_rejects_too_many_paths() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_STAT_PATHS + 1) as u32).to_le_bytes());

        assert_eq!(StatRequest::decode(&bytes), Err(Error::TooLarge));
    }

    #[test]
    fn metadata_v1_is_canonical_fixed_width_and_round_trips() {
        let request = MetadataRequest {
            paths: vec!["C:\\src\\one.h".to_owned(), "C:\\src\\missing.h".to_owned()],
        };
        assert_eq!(
            MetadataRequest::decode(&request.encode().unwrap()).unwrap(),
            request
        );

        let response = MetadataResponse {
            entries: vec![
                MetadataEntry::Present {
                    attributes: 0x20,
                    size: 0x1_0000_0005,
                    creation_time: 1,
                    access_time: 2,
                    write_time: 3,
                },
                MetadataEntry::FilesystemError { raw_error: 2 },
            ],
        };
        let encoded = response.encode().unwrap();
        assert_eq!(encoded.len(), 4 + 2 * METADATA_ENTRY_BYTES);
        assert_eq!(MetadataResponse::decode(&encoded).unwrap(), response);
    }

    #[test]
    fn metadata_v1_rejects_bad_cardinality_and_noncanonical_entries() {
        let mut too_many = Vec::new();
        too_many.extend_from_slice(&((MAX_METADATA_PATHS + 1) as u32).to_le_bytes());
        assert_eq!(MetadataRequest::decode(&too_many), Err(Error::TooLarge));
        assert_eq!(MetadataResponse::decode(&too_many), Err(Error::TooLarge));

        let mut noncanonical = MetadataResponse {
            entries: vec![MetadataEntry::Present {
                attributes: 1,
                size: 2,
                creation_time: 3,
                access_time: 4,
                write_time: 5,
            }],
        }
        .encode()
        .unwrap();
        *noncanonical.last_mut().unwrap() = 1;
        assert!(MetadataResponse::decode(&noncanonical).is_err());
        assert!(MetadataResponse::decode(&noncanonical[..noncanonical.len() - 1]).is_err());
    }

    #[test]
    fn metadata_v1_production_encoders_enforce_bounds_and_canonical_error() {
        let too_many = MetadataRequest {
            paths: vec![String::new(); MAX_METADATA_PATHS + 1],
        };
        assert_eq!(too_many.encode(), Err(Error::TooLarge));
        let too_many_response = MetadataResponse {
            entries: vec![MetadataEntry::FilesystemError { raw_error: 2 }; MAX_METADATA_PATHS + 1],
        };
        assert_eq!(too_many_response.encode(), Err(Error::TooLarge));
        assert_eq!(
            MetadataResponse {
                entries: vec![MetadataEntry::FilesystemError { raw_error: 0 }],
            }
            .encode(),
            Err(Error::InvalidValue)
        );

        let mut unknown_tag = MetadataResponse {
            entries: vec![MetadataEntry::FilesystemError { raw_error: 2 }],
        }
        .encode()
        .unwrap();
        unknown_tag[4] = 0xff;
        assert_eq!(
            MetadataResponse::decode(&unknown_tag),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn metadata_v1_filesystem_error_allowlist_is_exact() {
        for raw_error in [2, 3, 5, 123, 161, 206, 267] {
            assert!(is_metadata_filesystem_error(raw_error));
            let response = MetadataResponse {
                entries: vec![MetadataEntry::FilesystemError { raw_error }],
            };
            let encoded = response.encode().unwrap();
            assert_eq!(MetadataResponse::decode(&encoded).unwrap(), response);
        }

        for raw_error in [0, 4, 8, 21, 32] {
            assert!(!is_metadata_filesystem_error(raw_error));
            assert_eq!(
                MetadataResponse {
                    entries: vec![MetadataEntry::FilesystemError { raw_error }],
                }
                .encode(),
                Err(Error::InvalidValue)
            );

            let mut encoded = MetadataResponse {
                entries: vec![MetadataEntry::FilesystemError { raw_error: 2 }],
            }
            .encode()
            .unwrap();
            encoded[41..45].copy_from_slice(&raw_error.to_le_bytes());
            assert_eq!(MetadataResponse::decode(&encoded), Err(Error::InvalidValue));
        }
    }

    #[test]
    fn metadata_v1_rejects_invalid_file_attributes_sentinel() {
        assert_eq!(
            MetadataResponse {
                entries: vec![MetadataEntry::Present {
                    attributes: u32::MAX,
                    size: 1,
                    creation_time: 2,
                    access_time: 3,
                    write_time: 4,
                }],
            }
            .encode(),
            Err(Error::InvalidValue)
        );

        let mut encoded = MetadataResponse {
            entries: vec![MetadataEntry::Present {
                attributes: 0x20,
                size: 1,
                creation_time: 2,
                access_time: 3,
                write_time: 4,
            }],
        }
        .encode()
        .unwrap();
        encoded[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(MetadataResponse::decode(&encoded), Err(Error::InvalidValue));
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
    fn has_request_decode_rejects_too_many_digests() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_HAS_DIGESTS + 1) as u32).to_le_bytes());

        assert_eq!(HasRequest::decode(&bytes), Err(Error::TooLarge));
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
    fn dir_list_response_decode_rejects_too_many_entries() {
        let mut bytes = Vec::new();
        bytes.push(1);
        bytes.extend_from_slice(&((MAX_DIRLIST_ENTRIES + 1) as u32).to_le_bytes());

        assert_eq!(DirListResponse::decode(&bytes), Err(Error::TooLarge));
    }

    #[test]
    fn write_back_round_trips() {
        let req = WriteBackRequest {
            output_id: 0,
            digest_hex: "blake3:feedface".into(),
            offset: 0,
            bytes: vec![0u8, 1, 2, 255, 128],
            last: true,
        };
        assert_eq!(WriteBackRequest::decode(&req.encode()).unwrap(), req);
        // A mid-stream chunk (nonzero offset, not last) round-trips too.
        let mid = WriteBackRequest {
            output_id: 7,
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
