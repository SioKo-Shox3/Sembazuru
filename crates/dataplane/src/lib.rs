//! Sembazuru file-supply **data plane** (`docs/protocol/v0.md` §4).
//!
//! This crate is the latency-critical half of the protocol: it makes a
//! worker-side process see the agent-side filesystem with the fewest possible
//! round-trips. It is deliberately separate from `sembazuru-proto` (the gRPC
//! control plane) so that **no protobuf touches this hot path** (§4.2) — the
//! split is enforced physically by the crate boundary.
//!
//! Two layers, both transport-agnostic and std-only:
//!   * [`wire`] — length-prefixed binary frames (request id, op, flags) and the
//!     primitives to encode/decode payloads;
//!   * [`ops`] — the batch-first operation payloads (StatBatch / OpenRead /
//!     Read / DirList).
//!
//! The actual byte transport (TCP baseline, QUIC candidate — chosen by the
//! M3.5 benchmark, §4.4) lives with the agent/worker behind a trait; this crate
//! defines only what goes *on* the wire, so it unit-tests without a runtime.

pub mod ops;
pub mod wire;

#[cfg(feature = "tokio")]
pub mod async_io;

pub use wire::{Error, FrameHeader, OpCode, decode_frame, decode_frame_body, try_encode_frame};
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_root_try_encode_frame_encodes_valid_frame() {
        let header = FrameHeader {
            request_id: 7,
            op: OpCode::Read,
            is_response: true,
        };

        let framed = try_encode_frame(header, b"ok").unwrap();
        let (got, payload, consumed) = decode_frame(&framed).unwrap();

        assert_eq!(got, header);
        assert_eq!(payload, b"ok");
        assert_eq!(consumed, framed.len());
    }
}
