//! M3.2a end-to-end data-plane test: the agent file server supplies real files
//! to the worker's `FileClient` over loopback TCP. This proves the read VFS's
//! supply path in Rust — StatBatch (incl. negative results), OpenRead, ranged
//! Read with digest verification, and DirList — before the C++ hook/pipe (M3.2b)
//! is layered on. No compiler or DLL involved.

use std::path::PathBuf;

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
    let mut client = FileClient::connect(addr).await.unwrap();

    let (bytes, digest) = client
        .fetch(&path)
        .await
        .expect("rpc ok")
        .expect("file exists");
    assert_eq!(bytes, big, "fetched bytes must match on disk exactly");
    assert_eq!(digest.len(), 64, "sha-256 hex digest");

    // A missing file fetches as None, not an error.
    let missing = dir.join("nope.h").to_string_lossy().into_owned();
    assert!(client.fetch(&missing).await.unwrap().is_none());
}

#[tokio::test]
async fn stat_batch_reports_existence_per_path() {
    let dir = TempDir::new("stat");
    let present = dir.write("a.h", b"#pragma once\n");
    let absent = dir.join("b.h").to_string_lossy().into_owned();

    let addr = start_server().await;
    let mut client = FileClient::connect(addr).await.unwrap();

    let resp = client.stat_batch(&[present, absent]).await.expect("rpc ok");
    assert_eq!(resp.entries.len(), 2);
    assert!(resp.entries[0].exists && !resp.entries[0].is_dir);
    assert_eq!(resp.entries[0].size, b"#pragma once\n".len() as u64);
    assert!(!resp.entries[1].exists, "negative stat is batchable");
}

#[tokio::test]
async fn dir_list_snapshots_a_directory() {
    let dir = TempDir::new("dir");
    dir.write("inc/stdio.h", b"x");
    dir.write("inc/stdlib.h", b"yy");
    std::fs::create_dir_all(dir.join("inc/sys")).unwrap();

    let addr = start_server().await;
    let mut client = FileClient::connect(addr).await.unwrap();

    let inc = dir.join("inc").to_string_lossy().into_owned();
    let resp = client.dir_list(&inc, 0).await.expect("rpc ok");
    assert!(resp.exists);
    let names: Vec<&str> = resp.entries.iter().map(|e| e.rel_path.as_str()).collect();
    // Sorted, immediate children only.
    assert_eq!(names, vec!["stdio.h", "stdlib.h", "sys"]);
    let sys = resp.entries.iter().find(|e| e.rel_path == "sys").unwrap();
    assert!(sys.is_dir);
}
