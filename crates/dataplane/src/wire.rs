//! Wire primitives for the data plane (`docs/protocol/v0.md` §4.2):
//! length-prefixed binary frames with a fixed small header (request id, op,
//! flags), payloads defined per op. Request ids allow out-of-order completion
//! over a single connection. Little-endian throughout, matching the trace
//! format's convention; std-only, no protobuf on this hot path.

use std::fmt;

/// Hard cap on a single frame's body, so a malformed or hostile length prefix
/// can't drive an unbounded allocation. Read responses are chunked well under
/// this (the `Read` op's `len` is a u32 the caller chooses).
pub const MAX_FRAME_BODY: usize = 64 * 1024 * 1024;

/// Errors from decoding a frame or an op payload. All are recoverable at the
/// connection level (drop the frame / close the stream); none panic.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The buffer ended before a field could be read.
    Truncated,
    /// A length field exceeds `MAX_FRAME_BODY` or the remaining buffer.
    TooLarge,
    /// A string field was not valid UTF-8.
    BadUtf8,
    /// The op byte does not name a known operation.
    UnknownOp(u8),
    /// Trailing bytes remained after a payload was fully decoded.
    TrailingBytes,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "frame truncated"),
            Error::TooLarge => write!(f, "length field too large"),
            Error::BadUtf8 => write!(f, "string field not valid UTF-8"),
            Error::UnknownOp(op) => write!(f, "unknown op byte {op}"),
            Error::TrailingBytes => write!(f, "trailing bytes after payload"),
        }
    }
}

impl std::error::Error for Error {}

/// The data-plane operations (`docs/protocol/v0.md` §4.1). WriteBack and
/// PrefetchHint arrive with M3.3 / M5; the read ops are M3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    StatBatch = 1,
    OpenRead = 2,
    Read = 3,
    DirList = 4,
    WriteBack = 5,
}

impl OpCode {
    fn from_u8(v: u8) -> Result<OpCode, Error> {
        match v {
            1 => Ok(OpCode::StatBatch),
            2 => Ok(OpCode::OpenRead),
            3 => Ok(OpCode::Read),
            4 => Ok(OpCode::DirList),
            5 => Ok(OpCode::WriteBack),
            other => Err(Error::UnknownOp(other)),
        }
    }
}

/// The fixed frame header that precedes every payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Correlates a response with its request; lets responses complete out of
    /// order on one connection.
    pub request_id: u64,
    pub op: OpCode,
    /// True for a response frame, false for a request.
    pub is_response: bool,
}

const FLAG_RESPONSE: u8 = 0x01;
// request_id(8) + op(1) + flags(1) + reserved(2)
const HEADER_BYTES: usize = 12;

/// Builds a complete frame ready to write to a stream: a `u32` length prefix
/// (covering the header and payload) followed by the header and payload.
pub fn encode_frame(header: FrameHeader, payload: &[u8]) -> Vec<u8> {
    let body_len = HEADER_BYTES + payload.len();
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
    out.extend_from_slice(&header.request_id.to_le_bytes());
    out.push(header.op as u8);
    out.push(if header.is_response { FLAG_RESPONSE } else { 0 });
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(payload);
    out
}

/// Parses a frame body (the `length`-prefixed bytes *after* the `u32` prefix has
/// been read by the transport). Returns the header and the payload slice.
pub fn decode_frame_body(body: &[u8]) -> Result<(FrameHeader, &[u8]), Error> {
    if body.len() < HEADER_BYTES {
        return Err(Error::Truncated);
    }
    let request_id = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let op = OpCode::from_u8(body[8])?;
    let is_response = body[9] & FLAG_RESPONSE != 0;
    // body[10..12] reserved, ignored.
    Ok((
        FrameHeader {
            request_id,
            op,
            is_response,
        },
        &body[HEADER_BYTES..],
    ))
}

/// Convenience for tests / non-streaming callers: parse a whole frame including
/// its `u32` length prefix. Returns the header, the payload, and the number of
/// bytes consumed (so a caller can find the next frame).
pub fn decode_frame(buf: &[u8]) -> Result<(FrameHeader, &[u8], usize), Error> {
    if buf.len() < 4 {
        return Err(Error::Truncated);
    }
    let body_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if body_len > MAX_FRAME_BODY {
        return Err(Error::TooLarge);
    }
    let end = 4usize.checked_add(body_len).ok_or(Error::TooLarge)?;
    if buf.len() < end {
        return Err(Error::Truncated);
    }
    let (header, payload) = decode_frame_body(&buf[4..end])?;
    Ok((header, payload, end))
}

// --- Payload primitives --------------------------------------------------

/// Appends LE-encoded fields to a payload buffer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// A length-prefixed byte string (`u32` count + bytes).
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }
    /// A length-prefixed UTF-8 string.
    pub fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
}

/// A bounds-checked cursor over a payload buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::TooLarge)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Result<bool, Error> {
        Ok(self.u8()? != 0)
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u32()? as usize;
        if n > MAX_FRAME_BODY {
            return Err(Error::TooLarge);
        }
        Ok(self.take(n)?.to_vec())
    }
    pub fn str(&mut self) -> Result<String, Error> {
        let b = self.bytes()?;
        String::from_utf8(b).map_err(|_| Error::BadUtf8)
    }

    /// Asserts the payload was fully consumed; rejects trailing junk so a
    /// truncated-struct-but-extra-bytes frame is an error, not silent.
    pub fn finish(self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_with_length_prefix() {
        let payload = b"hello-data-plane";
        let h = FrameHeader {
            request_id: 0x0102_0304_0506_0708,
            op: OpCode::Read,
            is_response: true,
        };
        let framed = encode_frame(h, payload);
        let (got, body, consumed) = decode_frame(&framed).unwrap();
        assert_eq!(got, h);
        assert_eq!(body, payload);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn two_frames_decode_sequentially() {
        let a = encode_frame(
            FrameHeader {
                request_id: 1,
                op: OpCode::StatBatch,
                is_response: false,
            },
            b"a",
        );
        let b = encode_frame(
            FrameHeader {
                request_id: 2,
                op: OpCode::DirList,
                is_response: false,
            },
            b"bb",
        );
        let mut both = a.clone();
        both.extend_from_slice(&b);
        let (h1, p1, n1) = decode_frame(&both).unwrap();
        assert_eq!(h1.request_id, 1);
        assert_eq!(p1, b"a");
        let (h2, p2, _) = decode_frame(&both[n1..]).unwrap();
        assert_eq!(h2.request_id, 2);
        assert_eq!(p2, b"bb");
    }

    #[test]
    fn truncated_frame_is_an_error_not_a_panic() {
        let framed = encode_frame(
            FrameHeader {
                request_id: 9,
                op: OpCode::OpenRead,
                is_response: false,
            },
            b"payload",
        );
        // Hand the decoder every short prefix; none may panic.
        for n in 0..framed.len() {
            assert!(matches!(
                decode_frame(&framed[..n]),
                Err(Error::Truncated) | Err(Error::TooLarge) | Err(Error::UnknownOp(_))
            ));
        }
    }

    #[test]
    fn unknown_op_is_rejected() {
        let mut framed = encode_frame(
            FrameHeader {
                request_id: 1,
                op: OpCode::Read,
                is_response: false,
            },
            b"",
        );
        framed[12] = 99; // the op byte (after u32 len + u64 request_id)
        assert_eq!(decode_frame(&framed), Err(Error::UnknownOp(99)));
    }

    #[test]
    fn reader_primitives_round_trip() {
        let mut w = Writer::new();
        w.u8(0xAB);
        w.bool(true);
        w.u32(0xDEAD_BEEF);
        w.u64(0x0102_0304_0506_0708);
        w.str("héllo"); // multibyte UTF-8
        w.bytes(&[1, 2, 3]);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert!(r.bool().unwrap());
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.str().unwrap(), "héllo");
        assert_eq!(r.bytes().unwrap(), vec![1, 2, 3]);
        r.finish().unwrap();
    }

    #[test]
    fn reader_rejects_overlong_length() {
        // A string claiming 0xFFFF_FFFF bytes must fail cleanly, not allocate.
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut r = Reader::new(&buf);
        assert_eq!(r.str(), Err(Error::TooLarge));
    }
}
