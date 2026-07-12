//! M3.2a end-to-end data-plane test: the agent file server supplies real files
//! to the worker's `FileClient` over loopback TCP. This proves the read VFS's
//! supply path in Rust — StatBatch (incl. negative results), OpenRead, ranged
//! Read with digest verification, and DirList — before the C++ hook/pipe (M3.2b)
//! is layered on. No compiler or DLL involved.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use sembazuru_agent::session_registry::{DEFAULT_OUTPUT_MAX_BYTES, OutputSpec, staging_temp};
use sembazuru_dataplane::ops::MAX_DIRLIST_ENTRIES;
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

fn output_specs(paths: &[(u32, &str)]) -> Vec<OutputSpec> {
    paths
        .iter()
        .map(|(id, path)| OutputSpec {
            id: *id,
            final_path: PathBuf::from(path),
            max_size: DEFAULT_OUTPUT_MAX_BYTES,
        })
        .collect()
}

fn output_spec(id: u32, path: &str, max_size: u64) -> OutputSpec {
    OutputSpec {
        id,
        final_path: PathBuf::from(path),
        max_size,
    }
}

fn staging_files(dir: &std::path::Path) -> Vec<PathBuf> {
    if !dir.exists() {
        return Vec::new();
    }
    let mut files = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".sbz-staging-"))
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// Starts the production-mode agent file server on an ephemeral port; returns
/// its address and a pre-created unscoped bound session id.
async fn start_server() -> (
    std::net::SocketAddr,
    String,
    Arc<sembazuru_agent::fileserver::ServerStats>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = std::sync::Arc::new(sembazuru_agent::fileserver::ServerStats::default());
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let session_id = "authsess".to_string();
    registry
        .create(session_id.clone(), None, Default::default())
        .await;
    let served_stats = Arc::clone(&stats);
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files_with_stats_token(
            listener,
            served_stats,
            None,
            registry,
            false,
        )
        .await;
    });
    (addr, session_id, stats)
}

/// Starts the legacy no-token helper with empty-session compatibility enabled.
async fn start_legacy_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files(listener).await;
    });
    addr
}

async fn connect_bound(addr: std::net::SocketAddr, session_id: &str) -> FileClient {
    FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        session_id.to_string(),
    )
    .await
    .unwrap()
}

async fn connect_raw_bound(addr: std::net::SocketAddr, session_id: &str) -> tokio::net::TcpStream {
    use sembazuru_dataplane::async_io::{read_frame, write_frame};
    use sembazuru_dataplane::ops::{HelloRequest, HelloResponse};
    use sembazuru_dataplane::wire::{FrameHeader, OpCode};
    use tokio::io::AsyncWriteExt;

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let hello_payload = HelloRequest {
        token: String::new(),
        root: String::new(),
        session_id: session_id.to_string(),
    }
    .encode();
    write_frame(
        &mut sock,
        FrameHeader {
            request_id: 0,
            op: OpCode::Hello,
            is_response: false,
        },
        &hello_payload,
    )
    .await
    .unwrap();
    sock.flush().await.unwrap();
    let (hello_header, hello_payload) = read_frame(&mut sock).await.unwrap();
    assert_eq!(hello_header.op, OpCode::Hello);
    assert!(hello_header.is_response);
    assert!(HelloResponse::decode(&hello_payload).unwrap().ok);
    sock
}

async fn send_raw_writeback(
    sock: &mut tokio::net::TcpStream,
    request_id: u64,
    payload: Vec<u8>,
) -> sembazuru_dataplane::ops::WriteBackResponse {
    use sembazuru_dataplane::async_io::{read_frame, write_frame};
    use sembazuru_dataplane::ops::WriteBackResponse;
    use sembazuru_dataplane::wire::{FrameHeader, OpCode};
    use tokio::io::AsyncWriteExt;

    write_frame(
        sock,
        FrameHeader {
            request_id,
            op: OpCode::WriteBack,
            is_response: false,
        },
        &payload,
    )
    .await
    .unwrap();
    sock.flush().await.unwrap();
    let (_h, rp) = read_frame(sock).await.unwrap();
    WriteBackResponse::decode(&rp).unwrap()
}

#[tokio::test]
async fn fetch_returns_exact_bytes_and_verifies_digest() {
    let dir = TempDir::new("fetch");
    // Inline 64 KiB, two full 256 KiB reads, then a trailing partial read.
    let big: Vec<u8> = (0..700_123u32).map(|i| (i % 251) as u8).collect();
    let path = dir.write("sub/main.cpp", &big);

    let (addr, session_id, stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;
    let before = stats.read_ops.load(Ordering::Relaxed);

    let (bytes, digest) = client
        .fetch(&path)
        .await
        .expect("rpc ok")
        .expect("file exists");
    assert_eq!(bytes, big, "fetched bytes must match on disk exactly");
    assert_eq!(stats.read_ops.load(Ordering::Relaxed) - before, 3);
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

    let (addr, session_id, _stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;

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

    let (addr, session_id, _stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;

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

    let (addr, session_id, _stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;

    let resp = client.stat_batch(&[present, absent]).await.expect("rpc ok");
    assert_eq!(resp.entries.len(), 2);
    assert!(resp.entries[0].exists && !resp.entries[0].is_dir);
    assert_eq!(resp.entries[0].size, b"#pragma once\n".len() as u64);
    assert!(!resp.entries[1].exists, "negative stat is batchable");
}

#[tokio::test]
async fn write_back_publishes_atomically_and_verifies_digest() {
    use sembazuru_dataplane::ops::WriteBackRequest;

    let dir = TempDir::new("wb");
    let out = dir.join("out/a.obj").to_string_lossy().into_owned();
    let bad = dir.join("out/bad.obj").to_string_lossy().into_owned();
    let bytes = b"\x00\x01OBJ-bytes\xff".to_vec();

    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let session_id = "wb-atomic".to_string();
    let cap = registry
        .create(
            session_id.clone(),
            None,
            output_specs(&[(0, out.as_str()), (1, bad.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;

    // A good WriteBack stages the bytes at the path resolved from output id 0.
    let client = connect_bound(addr, &session_id).await;
    let resp = client.write_back(0, &bytes).await.unwrap();
    assert!(resp.ok, "write-back should succeed: {}", resp.detail);
    assert!(
        !std::path::Path::new(&out).exists(),
        "write-back stages only; intake publishes after action success"
    );
    assert_eq!(
        staging_files(std::path::Path::new(&out).parent().unwrap()).len(),
        1,
        "verified output is staged"
    );
    cap.publish_staged().await.unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), bytes, "published bytes match");

    // Publishing over an existing output must replace it atomically (the
    // rename-over-existing case a rebuild hits every time), but only when intake
    // explicitly publishes the staged output.
    let bytes2 = b"\x02REBUILT-obj\x03".to_vec();
    let resp2 = client.write_back(0, &bytes2).await.unwrap();
    assert!(resp2.ok, "re-publish should replace: {}", resp2.detail);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        bytes,
        "existing output is unchanged until publish"
    );
    cap.publish_staged().await.unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        bytes2,
        "output replaced on rebuild"
    );

    // A corrupted transfer (digest does not match the bytes) is rejected, and no
    // torn output is published. Send a hand-built frame with a wrong digest to
    // output id 1.
    let mut sock = connect_raw_bound(addr, &session_id).await;
    let payload = WriteBackRequest {
        output_id: 1,
        digest_hex: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        offset: 0,
        bytes: b"these-bytes-do-not-match-that-digest".to_vec(),
        last: true,
    }
    .encode();
    let wbr = send_raw_writeback(&mut sock, 1, payload).await;
    assert!(!wbr.ok, "digest mismatch must be rejected");
    assert!(
        !std::path::Path::new(&bad).exists(),
        "no torn output published"
    );
    assert!(
        staging_files(std::path::Path::new(&bad).parent().unwrap()).is_empty(),
        "digest mismatch removes staging and records no staged output"
    );
    cap.publish_staged().await.unwrap();
    assert!(
        !std::path::Path::new(&bad).exists(),
        "publish has nothing to publish after digest mismatch"
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

    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let session_id = "wb-big".to_string();
    let cap = registry
        .create(session_id.clone(), None, output_specs(&[(0, out.as_str())]))
        .await;
    let addr = start_server_with_registry(registry).await;
    let client = connect_bound(addr, &session_id).await;

    let resp = client.write_back(0, &big).await.unwrap();
    assert!(
        resp.ok,
        "chunked write-back should succeed: {}",
        resp.detail
    );
    assert!(
        !std::path::Path::new(&out).exists(),
        "large write-back stages only"
    );
    cap.publish_staged().await.unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        big,
        "the streamed output is published byte-for-byte"
    );
}

#[tokio::test]
async fn failed_action_does_not_publish_writeback() {
    let dir = TempDir::new("wb-failed-action");
    let out = dir.join("out/failed.obj").to_string_lossy().into_owned();
    let bytes = b"verified but action fails".to_vec();

    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let cap = registry
        .create(
            "wb-failed-action".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let client = connect_bound(addr, "wb-failed-action").await;

    let resp = client.write_back(0, &bytes).await.unwrap();
    assert!(resp.ok, "write-back should stage: {}", resp.detail);
    assert!(
        !std::path::Path::new(&out).exists(),
        "staged write-back must not publish before action success"
    );
    let out_dir = std::path::Path::new(&out).parent().unwrap();
    let staged = staging_files(out_dir);
    assert_eq!(
        staged.len(),
        1,
        "verified output should have one staging temp"
    );

    cap.discard_staged().await;

    assert!(
        !std::path::Path::new(&out).exists(),
        "failed action must not publish staged output"
    );
    assert!(!staged[0].exists(), "discard removes the staging temp");
    assert!(
        staging_files(out_dir).is_empty(),
        "no staging temp remains after discard"
    );
}

#[tokio::test]
async fn late_writeback_after_exit_rejected() {
    let dir = TempDir::new("late-writeback-exit");
    let out = dir.join("out/late.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let cap = registry
        .create(
            "late-writeback-exit".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry.clone()).await;
    let client = connect_bound(addr, "late-writeback-exit").await;

    assert!(registry.finish("late-writeback-exit").await);
    let resp = client.write_back(0, b"too late").await.unwrap();

    assert!(!resp.ok, "late WriteBack must be rejected");
    assert_eq!(resp.detail, "session is closed");
    assert!(
        !std::path::Path::new(&out).exists(),
        "late WriteBack must not publish"
    );
    cap.discard_staged().await;
}

#[tokio::test]
async fn digest_mismatch_removes_staging() {
    use sembazuru_dataplane::ops::WriteBackRequest;

    let dir = TempDir::new("wb-digest-staging-cleanup");
    let out = dir.join("out/bad.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let cap = registry
        .create(
            "wb-digest-staging-cleanup".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let mut sock = connect_raw_bound(addr, "wb-digest-staging-cleanup").await;

    let payload = WriteBackRequest {
        output_id: 0,
        digest_hex: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        offset: 0,
        bytes: b"wrong digest bytes".to_vec(),
        last: true,
    }
    .encode();
    let resp = send_raw_writeback(&mut sock, 1, payload).await;

    assert!(!resp.ok, "digest mismatch must be refused");
    let out_dir = std::path::Path::new(&out).parent().unwrap();
    assert!(
        staging_files(out_dir).is_empty(),
        "digest mismatch removes its staging temp"
    );
    cap.publish_staged().await.unwrap();
    assert!(
        !std::path::Path::new(&out).exists(),
        "publish has nothing to publish after digest mismatch"
    );
}

#[tokio::test]
async fn crash_like_disconnect_leaves_no_final_output() {
    use sembazuru_dataplane::ops::WriteBackRequest;

    let dir = TempDir::new("wb-disconnect");
    let out = dir.join("out/partial.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let cap = registry
        .create(
            "wb-disconnect".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let mut sock = connect_raw_bound(addr, "wb-disconnect").await;

    let chunk = b"partial output chunk".to_vec();
    let payload = WriteBackRequest {
        output_id: 0,
        digest_hex: sembazuru_cas::Digest::of(&chunk).canonical(),
        offset: 0,
        bytes: chunk,
        last: false,
    }
    .encode();
    let resp = send_raw_writeback(&mut sock, 1, payload).await;
    assert!(resp.ok, "first chunk should be accepted: {}", resp.detail);
    drop(sock);

    cap.discard_staged().await;

    let out_dir = std::path::Path::new(&out).parent().unwrap();
    assert!(
        !std::path::Path::new(&out).exists(),
        "disconnect before final chunk must not publish"
    );
    assert!(
        staging_files(out_dir).is_empty(),
        "discard removes the in-progress staging temp"
    );
}

#[test]
fn staging_temp_is_unique_and_create_new() {
    let dir = TempDir::new("staging-temp");
    let final_path = dir.join("out/final.obj");
    let a = staging_temp(&final_path);
    let b = staging_temp(&final_path);

    assert_ne!(a, b, "staging temp names should be CSPRNG-unique");
    assert_eq!(a.parent(), final_path.parent());
    assert_eq!(b.parent(), final_path.parent());
    for path in [&a, &b] {
        let name = path.file_name().and_then(|name| name.to_str()).unwrap();
        let suffix = name.strip_prefix(".sbz-staging-").unwrap();
        assert_eq!(suffix.len(), 32, "staging suffix is 32 hex chars");
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "staging suffix must be lowercase hex: {suffix}"
        );
    }

    std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
    let _first = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&a)
        .unwrap();
    let second_same = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&a);
    assert_eq!(
        second_same.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    let _different = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&b)
        .unwrap();
}

#[tokio::test]
async fn dir_list_snapshots_a_directory() {
    let dir = TempDir::new("dir");
    dir.write("inc/stdio.h", b"x");
    dir.write("inc/stdlib.h", b"yy");
    std::fs::create_dir_all(dir.join("inc/sys")).unwrap();

    let (addr, session_id, _stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;

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
async fn dir_list_over_entry_quota_fails_remote_call_without_partial_entries() {
    let dir = TempDir::new("dir-quota");
    std::fs::create_dir_all(dir.join("inc")).unwrap();
    for i in 0..(MAX_DIRLIST_ENTRIES + 1) {
        std::fs::write(dir.join(&format!("inc/h{i}.h")), b"x").unwrap();
    }

    let (addr, session_id, _stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;

    let inc = dir.join("inc").to_string_lossy().into_owned();
    let err = client
        .dir_list(&inc, 0)
        .await
        .expect_err("over-quota directory snapshots must fail, not truncate");

    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        "over-quota DirList should fail closed, got {err:?}"
    );
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

    let (addr, session_id, _stats) = start_server().await;
    let client = connect_bound(addr, &session_id).await;

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
        use sembazuru_dataplane::async_io::{read_frame, write_frame};
        use sembazuru_dataplane::ops::HelloResponse;
        use sembazuru_dataplane::wire::{FrameHeader, OpCode};
        use tokio::io::AsyncWriteExt;
        // Accept one connection, COMPLETE the session handshake so connect()
        // succeeds, then drop it — the worker's reader then sees EOF mid-session.
        if let Ok((mut sock, _)) = listener.accept().await {
            if let Ok((h, _)) = read_frame(&mut sock).await {
                let resp = HelloResponse {
                    ok: true,
                    detail: String::new(),
                }
                .encode();
                let _ = write_frame(
                    &mut sock,
                    FrameHeader {
                        request_id: h.request_id,
                        op: OpCode::Hello,
                        is_response: true,
                    },
                    &resp,
                )
                .await;
                let _ = sock.flush().await;
            }
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
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let token = token.to_string();
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files_with_stats_token(
            listener,
            stats,
            Some(token),
            registry,
            true,
        )
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
async fn declared_root_scopes_file_supply() {
    // M7.1 path scoping: a worker declares its input root on the session handshake
    // and the agent refuses to supply anything outside it — even though the agent
    // process can read those files. Defends against a rogue/buggy worker reading
    // arbitrary agent-side files (e.g. ~/.ssh/id_rsa) over the data plane.
    let root = TempDir::new("scope-root");
    let in_root = root.write("src/in.h", b"inside the declared root");
    // A file the agent CAN read but that lives OUTSIDE the declared root.
    let outside = TempDir::new("scope-outside");
    let secret = outside.write("secret.txt", b"must never be supplied");

    let addr = start_legacy_server().await; // agent is unscoped; scope comes from the client
    let client = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),                      // auth off
        root.path.to_string_lossy().into(), // declared root
        String::new(),                      // no agent-minted session (legacy scoping)
    )
    .await
    .unwrap();

    // In-root file is served normally.
    let got = client
        .fetch(&in_root)
        .await
        .unwrap()
        .expect("in-root file served");
    assert_eq!(got.0, b"inside the declared root");

    // Out-of-root file: fetch resolves to None (existence-hidden), not its bytes.
    assert!(
        client.fetch(&secret).await.unwrap().is_none(),
        "a path outside the declared root must not be supplied"
    );

    // `..` traversal (security M7.1 BLOCK-1): a path that string-prefix-matches
    // the root but climbs out with `..` must ALSO be refused. The OS would resolve
    // this to the real `secret` outside the root.
    let outside_name = outside
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let traversal = format!(
        "{}\\..\\{}\\secret.txt",
        root.path.to_string_lossy(),
        outside_name
    );
    assert!(
        client.fetch(&traversal).await.unwrap().is_none(),
        "a `..` traversal escaping the declared root must not be supplied"
    );
    // And a stat probe of it reports "does not exist".
    let stat = client
        .stat_batch(std::slice::from_ref(&secret))
        .await
        .unwrap();
    assert!(
        !stat.entries[0].exists,
        "out-of-root stat must report non-existence (no existence leak)"
    );
    // Sanity: the same agent, unscoped, WOULD have served it (proves the file is
    // real and readable, so the scoping is what blocked it).
    let addr2 = start_legacy_server().await;
    let unscoped = FileClient::connect(addr2).await.unwrap();
    assert!(
        unscoped.fetch(&secret).await.unwrap().is_some(),
        "unscoped agent serves the same file — scoping, not absence, blocked it"
    );
}

#[tokio::test]
async fn handshake_missing_token_against_authed_server_is_refused() {
    let addr = start_server_with_token("s3cret").await;

    // A tokenless client opens the session with an empty token; the authed server
    // rejects the handshake, so connect itself fails — no op is ever served.
    match FileClient::connect(addr).await {
        Ok(_) => panic!("a tokenless client must be rejected by an authed agent"),
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(
                e.to_string().contains("missing cluster auth token"),
                "reason should be the safe missing-token string, got: {e}"
            );
        }
    }
}

// --- ADR 0013: agent-authoritative session-capability enforcement ----------

/// Starts the agent file server sharing `registry`, so a test can pre-create a
/// bound session and then connect a client carrying that session id (ADR 0013).
async fn start_server_with_registry(
    registry: std::sync::Arc<sembazuru_agent::session_registry::SessionRegistry>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = std::sync::Arc::new(sembazuru_agent::fileserver::ServerStats::default());
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files_with_stats_token(
            listener, stats, None, registry, false,
        )
        .await;
    });
    addr
}

#[tokio::test]
async fn writeback_unknown_output_id_rejected() {
    let dir = TempDir::new("wb-unknown-output-id");
    let out = dir.join("out/known.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create(
            "wb-unknown-output-id".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let client = connect_bound(addr, "wb-unknown-output-id").await;

    let resp = client.write_back(99, b"not declared").await.unwrap();

    assert!(!resp.ok, "unknown output id must be refused");
    assert!(
        resp.detail.contains("unknown output id"),
        "detail should mention unknown id, got: {}",
        resp.detail
    );
    assert!(
        !std::path::Path::new(&out).exists(),
        "unknown id must not publish the declared output"
    );
}

#[tokio::test]
async fn writeback_other_session_output_id_rejected() {
    let dir = TempDir::new("wb-other-session-output-id");
    let a_out = dir.join("out/a.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create("A".into(), None, output_specs(&[(0, a_out.as_str())]))
        .await;
    registry.create("B".into(), None, Vec::new()).await;
    let addr = start_server_with_registry(registry).await;
    let client_b = connect_bound(addr, "B").await;

    let resp = client_b
        .write_back(0, b"session B cannot use A id")
        .await
        .unwrap();

    assert!(!resp.ok, "another session's id must be refused");
    assert!(
        resp.detail.contains("unknown output id"),
        "detail should mention unknown id, got: {}",
        resp.detail
    );
    assert!(
        !std::path::Path::new(&a_out).exists(),
        "session B must not publish session A's output"
    );
}

#[tokio::test]
async fn writeback_path_field_not_accepted_in_v2() {
    use sembazuru_dataplane::wire::Writer;

    let dir = TempDir::new("wb-old-path-field");
    let out = dir.join("out/old.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create(
            "wb-old-path-field".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let mut sock = connect_raw_bound(addr, "wb-old-path-field").await;

    // Old v1 was path, digest, offset, bytes, last. The first u32 of that old
    // path string is now decoded as output_id. This payload is crafted so the v2
    // decoder succeeds and reaches the unknown-id rejection path.
    let mut payload = Writer::new();
    payload.str("\0\0\0\0"); // old path field, length 4 -> v2 output_id 4
    let old_digest = String::from_utf8(vec![0, 0, 0, 0, 12, 0, 0, 0]).unwrap();
    payload.str(&old_digest);
    payload.u64(0);
    payload.bytes(&[]);
    payload.bool(true);

    let resp = send_raw_writeback(&mut sock, 1, payload.into_bytes()).await;

    assert!(!resp.ok, "old path-based WriteBack must be refused");
    assert!(
        resp.detail.contains("unknown output id"),
        "detail should mention unknown id, got: {}",
        resp.detail
    );
    assert!(
        !std::path::Path::new(&out).exists(),
        "old path-based frame must not publish"
    );
}

#[tokio::test]
async fn writeback_size_limit_enforced() {
    let dir = TempDir::new("wb-size-limit");
    let out = dir.join("out/limited.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create(
            "wb-size-limit".into(),
            None,
            vec![output_spec(0, out.as_str(), 10)],
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let client = connect_bound(addr, "wb-size-limit").await;

    let resp = client.write_back(0, &[0u8; 100]).await.unwrap();

    assert!(!resp.ok, "oversized output must be refused");
    assert!(
        resp.detail.contains("output exceeds max size"),
        "detail should mention size cap, got: {}",
        resp.detail
    );
    assert!(
        !std::path::Path::new(&out).exists(),
        "oversized output must not be published"
    );
}

#[tokio::test]
async fn writeback_digest_mismatch_rejected() {
    use sembazuru_dataplane::ops::WriteBackRequest;

    let dir = TempDir::new("wb-digest-mismatch");
    let out = dir.join("out/bad.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create(
            "wb-digest-mismatch".into(),
            None,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry).await;
    let mut sock = connect_raw_bound(addr, "wb-digest-mismatch").await;

    let payload = WriteBackRequest {
        output_id: 0,
        digest_hex: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        offset: 0,
        bytes: b"these bytes do not match".to_vec(),
        last: true,
    }
    .encode();
    let resp = send_raw_writeback(&mut sock, 1, payload).await;

    assert!(!resp.ok, "digest mismatch must be refused");
    assert!(
        resp.detail.contains("digest mismatch"),
        "detail should mention digest mismatch, got: {}",
        resp.detail
    );
    assert!(
        !std::path::Path::new(&out).exists(),
        "digest mismatch must not publish"
    );
}

#[tokio::test]
async fn late_open_read_after_finish_is_rejected() {
    let dir = TempDir::new("late-open");
    let path = dir.write("input.h", b"input bytes");
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let root = sembazuru_agent::fileserver::normalize_root(&dir.path.to_string_lossy());
    registry
        .create("late-open".into(), root, Default::default())
        .await;
    let addr = start_server_with_registry(registry.clone()).await;
    let client = connect_bound(addr, "late-open").await;

    let got = client.fetch(&path).await.unwrap().expect("live fetch");
    assert_eq!(got.0, b"input bytes");
    assert!(registry.finish("late-open").await);

    let late = client.open_read(&path, false).await.unwrap();
    assert!(!late.exists, "a finished session must hide late OpenRead");
}

#[tokio::test]
async fn late_read_after_finish_is_rejected() {
    let dir = TempDir::new("late-read");
    let path = dir.write("input.h", b"read me after pin");
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let root = sembazuru_agent::fileserver::normalize_root(&dir.path.to_string_lossy());
    registry
        .create("late-read".into(), root, Default::default())
        .await;
    let addr = start_server_with_registry(registry.clone()).await;
    let client = connect_bound(addr, "late-read").await;

    let (digest, size) = client.probe_digest(&path).await.unwrap().expect("exists");
    assert!(registry.finish("late-read").await);
    assert!(
        client.fetch_by_digest(&digest, size).await.is_err(),
        "a finished session must reject late Read"
    );
}

#[tokio::test]
async fn late_writeback_after_finish_is_rejected() {
    let dir = TempDir::new("late-writeback");
    let input = dir.write("input.h", b"prove connection is live");
    let out = dir.join("out/late.obj").to_string_lossy().into_owned();
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let root = sembazuru_agent::fileserver::normalize_root(&dir.path.to_string_lossy());
    registry
        .create(
            "late-writeback".into(),
            root,
            output_specs(&[(0, out.as_str())]),
        )
        .await;
    let addr = start_server_with_registry(registry.clone()).await;
    let client = connect_bound(addr, "late-writeback").await;

    assert!(client.fetch(&input).await.unwrap().is_some());
    assert!(registry.finish("late-writeback").await);

    let resp = client.write_back(0, b"must not publish").await.unwrap();
    assert!(!resp.ok, "late WriteBack must be a hard reject");
    assert_eq!(resp.detail, "session is closed");
    assert!(
        !std::path::Path::new(&out).exists(),
        "late WriteBack must not create the output"
    );
}

fn assert_permission_denied_contains(result: std::io::Result<FileClient>, needle: &str) {
    match result {
        Ok(_) => panic!("connect should have been rejected"),
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(
                e.to_string().contains(needle),
                "expected error to contain {needle:?}, got: {e}"
            );
        }
    }
}

#[tokio::test]
async fn hello_unknown_nonempty_session_id_is_rejected() {
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let addr = start_server_with_registry(registry).await;

    let result = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "nosuch".into(),
    )
    .await;
    assert_permission_denied_contains(result, "unknown or expired");
}

#[tokio::test]
async fn hello_expired_session_id_is_rejected() {
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create("expired".into(), None, Default::default())
        .await;
    assert!(registry.finish("expired").await);
    let addr = start_server_with_registry(registry).await;

    let result = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "expired".into(),
    )
    .await;
    assert_permission_denied_contains(result, "unknown or expired");
}

#[tokio::test]
async fn hello_empty_session_id_rejected_in_production_mode() {
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let addr = start_server_with_registry(registry).await;

    let result = FileClient::connect(addr).await;
    assert_permission_denied_contains(result, "session id required");
}

#[tokio::test]
async fn legacy_empty_session_id_allowed_only_in_test_compat_mode() {
    let dir = TempDir::new("legacy-empty");
    let path = dir.write("ok.h", b"legacy bytes");

    let legacy_addr = start_legacy_server().await;
    let legacy = FileClient::connect(legacy_addr)
        .await
        .expect("legacy helper accepts empty session id");
    let got = legacy
        .fetch(&path)
        .await
        .unwrap()
        .expect("legacy server serves file");
    assert_eq!(got.0, b"legacy bytes");

    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let prod_addr = start_server_with_registry(registry).await;
    let result = FileClient::connect(prod_addr).await;
    assert_permission_denied_contains(result, "session id required");
}

#[tokio::test]
async fn unknown_session_cannot_open_any_file() {
    let dir = TempDir::new("unknown-open");
    let path = dir.write("src.h", b"session-bound");
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    registry
        .create("valid".into(), None, Default::default())
        .await;
    let addr = start_server_with_registry(registry).await;

    let result = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "unknown".into(),
    )
    .await;
    assert_permission_denied_contains(result, "unknown or expired");

    let valid = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "valid".into(),
    )
    .await
    .unwrap();
    let got = valid
        .fetch(&path)
        .await
        .unwrap()
        .expect("valid session serves");
    assert_eq!(got.0, b"session-bound");
}

#[tokio::test]
async fn unknown_session_cannot_writeback_any_path() {
    let dir = TempDir::new("unknown-wb");
    let out = dir.join("out/evil.obj");
    let registry =
        std::sync::Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap());
    let addr = start_server_with_registry(registry).await;

    let result = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "unknown".into(),
    )
    .await;
    assert_permission_denied_contains(result, "unknown or expired");
    assert!(
        !out.exists(),
        "unknown session must not be able to publish an output"
    );
}

#[tokio::test]
async fn bound_session_uses_agent_root_not_worker_declared() {
    // SEC-004: when the Hello names a session the agent created, the file server
    // scopes supply to the AGENT'S authoritative root, IGNORING the root the
    // worker declares — so a worker that declares a wider root cannot widen scope.
    use sembazuru_agent::session_registry::SessionRegistry;
    let parent = TempDir::new("authroot");
    let proj = parent.path.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let inside = parent.write("proj\\in.h", b"inside the agent root");
    let outside = parent.write("sibling\\secret.txt", b"must never be supplied");

    let registry = std::sync::Arc::new(SessionRegistry::new().unwrap());
    let agent_root = sembazuru_agent::fileserver::normalize_root(&proj.to_string_lossy());
    registry
        .create("sess".into(), agent_root, Default::default())
        .await;
    let addr = start_server_with_registry(registry.clone()).await;

    // The worker binds the session id but DECLARES the wider `parent` root (trying
    // to widen its scope); the agent must ignore that and use `proj`.
    let client = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        parent.path.to_string_lossy().into(), // worker claims the wider root...
        "sess".into(),                        // ...but binds to the agent session
    )
    .await
    .unwrap();

    let got = client
        .fetch(&inside)
        .await
        .unwrap()
        .expect("in-root file served");
    assert_eq!(got.0, b"inside the agent root");
    assert!(
        client.fetch(&outside).await.unwrap().is_none(),
        "the agent must scope to its OWN root, not the worker-declared wider one (SEC-004)"
    );
}

#[tokio::test]
async fn each_session_has_its_own_pin_so_no_stale_across_actions() {
    // COR-001: action A's pin is frozen for A, but a LATER action B (a different
    // session) gets its own partition and observes the CURRENT bytes — the old
    // process-wide pin map served A's frozen v1 to B forever.
    use sembazuru_agent::session_registry::SessionRegistry;
    let dir = TempDir::new("perssesspin");
    let src = dir.write("a.cpp", b"v1-original");

    let registry = std::sync::Arc::new(SessionRegistry::new().unwrap());
    let root = sembazuru_agent::fileserver::normalize_root(&dir.path.to_string_lossy());
    registry
        .create("A".into(), root.clone(), Default::default())
        .await;
    registry.create("B".into(), root, Default::default()).await;
    let addr = start_server_with_registry(registry.clone()).await;

    let a = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "A".into(),
    )
    .await
    .unwrap();
    let a_v1 = a.fetch(&src).await.unwrap().expect("A reads v1");
    assert_eq!(a_v1.0, b"v1-original");

    // The source is edited on disk.
    std::fs::write(&src, b"v2-edited").unwrap();

    // A re-reads: still v1 — its pin is frozen (snapshot consistency within A).
    let a_again = a.fetch(&src).await.unwrap().expect("A re-reads");
    assert_eq!(a_again.0, b"v1-original", "A's pin stays frozen (snapshot)");

    // Session B (a different action) reads the NEW v2, not A's frozen v1.
    let b = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "B".into(),
    )
    .await
    .unwrap();
    let b_v2 = b.fetch(&src).await.unwrap().expect("B reads");
    assert_eq!(
        b_v2.0, b"v2-edited",
        "a later session must see current bytes, not a stale cross-session pin (COR-001)"
    );
}

#[tokio::test]
async fn bound_session_cannot_read_another_sessions_digest() {
    // SEC-004 (digest oracle): a bound session may only Read a digest it pinned.
    // A digest learned out-of-band (here, A's digest handed to B directly) is
    // refused for B even though the shared store physically holds the blob.
    use sembazuru_agent::session_registry::SessionRegistry;
    let dir = TempDir::new("digestacl");
    let f = dir.write("h.h", b"some header contents that are non-empty");

    let registry = std::sync::Arc::new(SessionRegistry::new().unwrap());
    let root = sembazuru_agent::fileserver::normalize_root(&dir.path.to_string_lossy());
    registry
        .create("A".into(), root.clone(), Default::default())
        .await;
    registry.create("B".into(), root, Default::default()).await;
    let addr = start_server_with_registry(registry.clone()).await;

    let a = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "A".into(),
    )
    .await
    .unwrap();
    let (bytes, digest) = a.fetch(&f).await.unwrap().expect("A pins the file");
    let size = bytes.len() as u64;

    // A can Read the digest it pinned.
    assert!(a.fetch_by_digest(&digest, size).await.is_ok());

    // B never opened that path, so the digest is not in B's allowed set — Read is
    // refused (the agent returns no bytes), even though the blob exists in the
    // shared store.
    let b = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        "B".into(),
    )
    .await
    .unwrap();
    assert!(
        b.fetch_by_digest(&digest, size).await.is_err(),
        "a bound session must not read another session's digest (SEC-004)"
    );
}
