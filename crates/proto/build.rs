//! Generates the control-plane gRPC stubs from
//! `proto/sembazuru/v0/control.proto`.
//!
//! A vendored protoc binary is used so builds and CI need no system protobuf
//! install and no PATH dependency — the toolchain stays deterministic, in the
//! same spirit as the determinism work in M2.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: a build script runs single-threaded before any other code in this
    // process, so setting a process-wide env var here cannot race another
    // thread. (`std::env::set_var` is `unsafe` as of edition 2024.)
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/sembazuru/v0/control.proto"], &["proto"])?;
    Ok(())
}
