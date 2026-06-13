//! Sembazuru control-plane protocol, v0 (see `docs/protocol/v0.md` §3).
//!
//! gRPC service definitions (`Coordination`, `Execution`) generated from
//! `proto/sembazuru/v0/control.proto`. **Protobuf appears only in this crate.**
//! The latency-critical file-supply data plane (v0 §4) is hand-rolled binary
//! framing in `sembazuru-dataplane`, with no protobuf on the hot path (§4.2).

/// Generated types and gRPC stubs for protocol version 0.
pub mod v0 {
    tonic::include_proto!("sembazuru.v0");

    /// The protocol version this build speaks (v0 §6), negotiated at Register
    /// time. v0 makes no compatibility promises until M3 ships.
    pub const PROTOCOL_VERSION: u32 = 0;
}
