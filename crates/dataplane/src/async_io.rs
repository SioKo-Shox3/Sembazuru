//! Async frame I/O over any `tokio` byte stream (TCP baseline today; the QUIC
//! candidate plugs in the same way — both are just `AsyncRead + AsyncWrite`).
//! Gated by the `tokio` feature so the codec stays runtime-free.
//!
//! A frame on the wire is a `u32` little-endian length prefix followed by that
//! many body bytes (`crate::wire`). These helpers read/write exactly one frame.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{FrameHeader, MAX_FRAME_BODY, decode_frame_body, encode_frame};

/// Writes one complete frame (length prefix + header + payload). Does not flush;
/// the caller flushes when it wants the bytes on the wire.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    header: FrameHeader,
    payload: &[u8],
) -> io::Result<()> {
    let framed = encode_frame(header, payload);
    w.write_all(&framed).await
}

/// Reads one complete frame, returning its header and an owned payload. A length
/// prefix exceeding `MAX_FRAME_BODY` is rejected before allocating, so a hostile
/// peer cannot drive an unbounded allocation. EOF before a full frame surfaces
/// as `UnexpectedEof`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(FrameHeader, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let body_len = u32::from_le_bytes(len_buf) as usize;
    if body_len > MAX_FRAME_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "data-plane frame exceeds MAX_FRAME_BODY",
        ));
    }
    let mut body = vec![0u8; body_len];
    r.read_exact(&mut body).await?;
    let (header, payload) =
        decode_frame_body(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok((header, payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::OpCode;

    #[tokio::test]
    async fn frame_round_trips_over_a_duplex_stream() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let header = FrameHeader {
            request_id: 42,
            op: OpCode::OpenRead,
            is_response: false,
        };
        write_frame(&mut a, header, b"payload-bytes").await.unwrap();
        let (got, payload) = read_frame(&mut b).await.unwrap();
        assert_eq!(got, header);
        assert_eq!(payload, b"payload-bytes");
    }

    #[tokio::test]
    async fn eof_before_a_frame_is_an_error() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a); // close the writer
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
