//! Async frame I/O over any `tokio` byte stream (TCP baseline today; the QUIC
//! candidate plugs in the same way — both are just `AsyncRead + AsyncWrite`).
//! Gated by the `tokio` feature so the codec stays runtime-free.
//!
//! A frame on the wire is a `u32` little-endian length prefix followed by that
//! many body bytes (`crate::wire`). These helpers read/write exactly one frame.

use std::{future::Future, io};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{FrameHeader, MAX_FRAME_BODY, decode_frame_body, try_encode_frame};

/// Writes one complete frame (length prefix + header + payload). Does not flush;
/// the caller flushes when it wants the bytes on the wire.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    header: FrameHeader,
    payload: &[u8],
) -> io::Result<()> {
    let framed = try_encode_frame(header, payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    w.write_all(&framed).await
}

/// Reads one complete frame, returning its header and an owned payload. A length
/// prefix exceeding `MAX_FRAME_BODY` is rejected before allocating, so a hostile
/// peer cannot drive an unbounded allocation. EOF before a full frame surfaces
/// as `UnexpectedEof`.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(FrameHeader, Vec<u8>)> {
    let (header, payload, ()) = read_frame_with_body_guard(r, |_| async { Ok(()) }).await?;
    Ok((header, payload))
}

/// Reads one complete frame after acquiring a caller-provided body guard. The
/// guard is awaited after the length prefix is validated and before the body
/// allocation/read, then returned so the caller can hold it through processing.
pub async fn read_frame_with_body_guard<R, G, F, Fut>(
    r: &mut R,
    acquire_body_guard: F,
) -> io::Result<(FrameHeader, Vec<u8>, G)>
where
    R: AsyncRead + Unpin,
    F: FnOnce(usize) -> Fut,
    Fut: Future<Output = io::Result<G>>,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let body_len = u32::from_le_bytes(len_buf) as usize;
    if body_len > MAX_FRAME_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "data-plane frame exceeds MAX_FRAME_BODY",
        ));
    }
    let guard = acquire_body_guard(body_len).await?;
    let mut body = vec![0u8; body_len];
    r.read_exact(&mut body).await?;
    let (header, payload) =
        decode_frame_body(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok((header, payload.to_vec(), guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{HEADER_BYTES, OpCode};

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

    #[tokio::test]
    async fn write_frame_rejects_body_larger_than_max_frame_body() {
        let mut sink = tokio::io::sink();
        let header = FrameHeader {
            request_id: 42,
            op: OpCode::OpenRead,
            is_response: false,
        };
        let payload = vec![0u8; MAX_FRAME_BODY - HEADER_BYTES + 1];

        let err = write_frame(&mut sink, header, &payload).await.unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_frame_with_body_guard_waits_before_reading_body() {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        use std::task::{Context, Poll, Waker};

        struct Gate {
            released: Arc<AtomicBool>,
            waker: Arc<Mutex<Option<Waker>>>,
        }

        impl Future for Gate {
            type Output = io::Result<&'static str>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.released.load(Ordering::SeqCst) {
                    Poll::Ready(Ok("held"))
                } else {
                    *self.waker.lock().unwrap() = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }

        let (mut writer, mut reader) = tokio::io::duplex(8);
        let header = FrameHeader {
            request_id: 42,
            op: OpCode::Read,
            is_response: false,
        };
        let frame = try_encode_frame(header, &[1u8; 16]).unwrap();
        let body = frame[4..].to_vec();
        writer.write_all(&frame[..4]).await.unwrap();

        let released = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None));
        let guard_released = Arc::clone(&released);
        let guard_waker = Arc::clone(&waker);
        let read = tokio::spawn(async move {
            read_frame_with_body_guard(&mut reader, |_| Gate {
                released: guard_released,
                waker: guard_waker,
            })
            .await
        });
        let write_body = tokio::spawn(async move {
            writer.write_all(&body).await.unwrap();
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !write_body.is_finished(),
            "body bytes must not be drained before the guard is acquired"
        );

        released.store(true, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        write_body.await.unwrap();
        let (got_header, got_payload, guard) = read.await.unwrap().unwrap();
        assert_eq!(got_header, header);
        assert_eq!(got_payload, [1u8; 16]);
        assert_eq!(guard, "held");
    }
}
