//! M3.2a end-to-end data-plane test: the agent file server supplies real files
//! to the worker's `FileClient` over loopback TCP. This proves the read VFS's
//! supply path in Rust — StatBatch (incl. negative results), OpenRead, ranged
//! Read with digest verification, and DirList — before the C++ hook/pipe (M3.2b)
//! is layered on. No compiler or DLL involved.

use std::path::PathBuf;
use std::time::Duration;

use sembazuru_worker::fileclient::FileClient;

/// A self-cleaning temp directory, so the test needs no `tempfile` dependency.
struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        // Unique per process + tag; the test is single-threaded per tag.
        let path = std::env::temp_dir().join(format!("sbz-dp-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
    fn write(&self, rel: &str, bytes: &[u8]) -> String {
        let p = self.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, bytes).unwrap();
        p.to_string_lossy().into_owned()
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Starts the agent file server on an ephemeral port; returns its address.
async fn start_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files(listener).await;
    });
    addr
}

#[tokio::test]
async fn fetch_returns_exact_bytes_and_verifies_digest() {
    let dir = TempDir::new("fetch");
    // A file larger than the 64 KiB inline chunk, to exercise the Read loop.
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let path = dir.write("sub/main.cpp", &big);

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    let (bytes, digest) = client
        .fetch(&path)
        .await
        .expect("rpc ok")
        .expect("file exists");
    assert_eq!(bytes, big, "fetched bytes must match on disk exactly");
    // BLAKE3 (ADR 0003): canonical "blake3:<64 hex>".
    assert_eq!(digest.algo(), sembazuru_cas::DigestAlgo::Blake3);
    assert_eq!(digest.hex().len(), 64, "blake3 hex digest");

    // A missing file fetches as None, not an error.
    let missing = dir.join("nope.h").to_string_lossy().into_owned();
    assert!(client.fetch(&missing).await.unwrap().is_none());
}

#[tokio::test]
async fn snapshot_pins_content_against_midbuild_edits() {
    // §4.1 snapshot consistency: once a path is opened in a session, a later
    // ranged Read serves the *pinned* bytes even if the on-disk file changed —
    // a mid-build local edit must not tear a running action.
    let dir = TempDir::new("snap");
    let v1 = b"version-ONE-content".to_vec();
    let path = dir.write("hdr.h", &v1);

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    // Digest-first open pins v1 in the agent's CAS.
    let (digest, size) = client
        .probe_digest(&path)
        .await
        .expect("rpc ok")
        .expect("exists");
    assert_eq!(size, v1.len() as u64);

    // Edit the file on disk after the pin (different length and bytes).
    std::fs::write(&path, b"version-TWO-is-longer-now").unwrap();

    // The pinned blob is still served verbatim, not the edited file.
    let bytes = client
        .fetch_by_digest(&digest, size)
        .await
        .expect("pinned read ok");
    assert_eq!(
        bytes, v1,
        "session must serve the pinned snapshot, not the edit"
    );
}

#[tokio::test]
async fn has_probe_reports_agent_cas_membership() {
    // §4.3 Has(): after a path is opened (ingested into the agent CAS), its
    // digest probes present; an unknown digest probes absent. This is the
    // upload-side dedup the output path uses to skip re-sending known blobs.
    let dir = TempDir::new("has");
    let path = dir.write("a.h", b"ingest me\n");

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    let (digest, _) = client.probe_digest(&path).await.unwrap().expect("exists");
    let absent = sembazuru_cas::Digest::of(b"never ingested").canonical();

    let present = client
        .has(&[digest.canonical(), absent])
        .await
        .expect("rpc ok");
    assert_eq!(present, vec![true, false]);
}

#[tokio::test]
async fn stat_batch_reports_existence_per_path() {
    let dir = TempDir::new("stat");
    let present = dir.write("a.h", b"#pragma once\n");
    let absent = dir.join("b.h").to_string_lossy().into_owned();

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    let resp = client.stat_batch(&[present, absent]).await.expect("rpc ok");
    assert_eq!(resp.entries.len(), 2);
    assert!(resp.entries[0].exists && !resp.entries[0].is_dir);
    assert_eq!(resp.entries[0].size, b"#pragma once\n".len() as u64);
    assert!(!resp.entries[1].exists, "negative stat is batchable");
}

#[tokio::test]
async fn write_back_publishes_atomically_and_verifies_digest() {
    use sembazuru_dataplane::ops::{WriteBackRequest, WriteBackResponse};
    use sembazuru_dataplane::wire::{FrameHeader, OpCode, decode_frame, encode_frame};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = TempDir::new("wb");
    let out = dir.join("out/a.obj").to_string_lossy().into_owned();
    let bytes = b"\x00\x01OBJ-bytes\xff".to_vec();

    let addr = start_server().await;

    // A good WriteBack publishes the bytes at the requested path.
    let client = sembazuru_worker::fileclient::FileClient::connect(addr)
        .await
        .unwrap();
    let resp = client.write_back(&out, &bytes).await.unwrap();
    assert!(resp.ok, "write-back should succeed: {}", resp.detail);
    assert_eq!(std::fs::read(&out).unwrap(), bytes, "published bytes match");

    // Re-publishing over an existing output must replace it atomically (the
    // rename-over-existing case a rebuild hits every time).
    let bytes2 = b"\x02REBUILT-obj\x03".to_vec();
    let resp2 = client.write_back(&out, &bytes2).await.unwrap();
    assert!(resp2.ok, "re-publish should replace: {}", resp2.detail);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        bytes2,
        "output replaced on rebuild"
    );

    // A corrupted transfer (digest does not match the bytes) is rejected, and no
    // torn output is published. Send a hand-built frame with a wrong digest.
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let bad = dir.join("out/bad.obj").to_string_lossy().into_owned();
    let payload = WriteBackRequest {
        path: bad.clone(),
        digest_hex: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        offset: 0,
        bytes: b"these-bytes-do-not-match-that-digest".to_vec(),
        last: true,
    }
    .encode();
    let framed = encode_frame(
        FrameHeader {
            request_id: 1,
            op: OpCode::WriteBack,
            is_response: false,
        },
        &payload,
    );
    sock.write_all(&framed).await.unwrap();
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
    sock.read_exact(&mut body).await.unwrap();
    let full = [&len[..], &body[..]].concat();
    let (_h, rp, _n) = decode_frame(&full).unwrap();
    let wbr = WriteBackResponse::decode(rp).unwrap();
    assert!(!wbr.ok, "digest mismatch must be rejected");
    assert!(
        !std::path::Path::new(&bad).exists(),
        "no torn output published"
    );
}

#[tokio::test]
async fn write_back_streams_large_output_in_chunks() {
    // M4.4: an output larger than the 1 MiB WriteBack chunk is streamed across
    // several chunks, verified against the whole-file digest, and published
    // atomically — without buffering it whole.
    let dir = TempDir::new("wb-big");
    let out = dir.join("out/big.pdb").to_string_lossy().into_owned();
    // ~3.5 MiB of non-trivial bytes → 4 chunks (1+1+1+0.5).
    let big: Vec<u8> = (0..3_600_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    let resp = client.write_back(&out, &big).await.unwrap();
    assert!(
        resp.ok,
        "chunked write-back should succeed: {}",
        resp.detail
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        big,
        "the streamed output is published byte-for-byte"
    );
}

#[tokio::test]
async fn dir_list_snapshots_a_directory() {
    let dir = TempDir::new("dir");
    dir.write("inc/stdio.h", b"x");
    dir.write("inc/stdlib.h", b"yy");
    std::fs::create_dir_all(dir.join("inc/sys")).unwrap();

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    let inc = dir.join("inc").to_string_lossy().into_owned();
    let resp = client.dir_list(&inc, 0).await.expect("rpc ok");
    assert!(resp.exists);
    let names: Vec<&str> = resp.entries.iter().map(|e| e.rel_path.as_str()).collect();
    // Sorted, immediate children only.
    assert_eq!(names, vec!["stdio.h", "stdlib.h", "sys"]);
    let sys = resp.entries.iter().find(|e| e.rel_path == "sys").unwrap();
    assert!(sys.is_dir);
}

#[tokio::test]
async fn one_connection_multiplexes_concurrent_ops() {
    // M5.3 pipelining: many ops issued concurrently over a single (cloned)
    // FileClient must all complete correctly. The shared connection correlates
    // each response to its caller by request id, so in-flight requests overlap
    // instead of serializing one round-trip at a time.
    let dir = TempDir::new("mux");
    let mut paths = Vec::new();
    for i in 0..32 {
        // Distinct contents so a mis-routed response (wrong digest/bytes) fails.
        let body = format!("translation-unit-{i}-contents").repeat(i + 1);
        paths.push((dir.write(&format!("tu{i}.cpp"), body.as_bytes()), body));
    }

    let addr = start_server().await;
    let client = FileClient::connect(addr).await.unwrap();

    // Fire all fetches concurrently on clones of the one connection.
    let mut handles = Vec::new();
    for (path, expected) in paths {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            let (bytes, _digest) = c.fetch(&path).await.expect("rpc ok").expect("exists");
            assert_eq!(
                bytes,
                expected.as_bytes(),
                "each concurrent fetch got its own correct bytes"
            );
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn calls_fail_fast_when_the_connection_dies() {
    // M5.3 liveness: if the agent connection dies, in-flight and subsequent calls
    // must surface an error promptly, never hang forever waiting on a response
    // the dead reader task will never deliver (which would wedge a hydrate with
    // no chance of fallback).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept one connection, then drop it — the worker's reader sees EOF.
        if let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });

    let client = FileClient::connect(addr).await.unwrap();

    // In-flight call: the server closed, so this errors (does not hang).
    let first =
        tokio::time::timeout(Duration::from_secs(5), client.open_read("c:\\x", false)).await;
    assert!(first.is_ok(), "a call on a dead connection must not hang");
    assert!(
        first.unwrap().is_err(),
        "a dead connection surfaces an error"
    );

    // Subsequent call after the reader exited: must fail fast via the closed
    // flag, not register a waiter nobody will wake.
    let second =
        tokio::time::timeout(Duration::from_secs(5), client.open_read("c:\\y", false)).await;
    assert!(
        second.is_ok() && second.unwrap().is_err(),
        "calls after the connection died fail fast, not hang"
    );
}

// ---- M7.0 data-plane shared-token handshake (ADR 0006) -------------------

/// Starts an agent file server that requires `token` on the handshake.
async fn start_server_with_token(token: &str) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = std::sync::Arc::new(sembazuru_agent::fileserver::ServerStats::default());
    let token = token.to_string();
    tokio::spawn(async move {
        let _ =
            sembazuru_agent::fileserver::serve_files_with_stats_token(listener, stats, Some(token))
                .await;
    });
    addr
}

#[tokio::test]
async fn handshake_right_token_serves_files() {
    let dir = TempDir::new("auth-ok");
    let path = dir.write("a.h", b"authed-bytes");
    let addr = start_server_with_token("s3cret").await;

    // The worker presents the right token and then reads normally.
    let client = FileClient::connect_with_rtt_token(addr, Duration::ZERO, "s3cret".to_string())
        .await
        .expect("handshake with the right token succeeds");
    let (bytes, _digest) = client.fetch(&path).await.unwrap().expect("file exists");
    assert_eq!(bytes, b"authed-bytes");
}

#[tokio::test]
async fn handshake_wrong_token_is_refused() {
    let addr = start_server_with_token("s3cret").await;
    // Wrong token: the agent rejects the handshake, so connect itself fails with
    // PermissionDenied — no op is ever served.
    match FileClient::connect_with_rtt_token(addr, Duration::ZERO, "nope".to_string()).await {
        Ok(_) => panic!("handshake with the wrong token must fail"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
    }
}

#[tokio::test]
async fn handshake_missing_token_against_authed_server_is_refused() {
    let dir = TempDir::new("auth-missing");
    let path = dir.write("a.h", b"unreachable");
    let addr = start_server_with_token("s3cret").await;

    // A tokenless client (M6-style `connect`) sends no Hello; its first frame is
    // an op, which the authed server refuses — the op must not return data.
    let client = FileClient::connect(addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), client.fetch(&path)).await;
    assert!(
        got.is_ok(),
        "the call must not hang against an authed server"
    );
    assert!(
        got.unwrap().is_err(),
        "a tokenless client gets no files from an authed agent"
    );
}
