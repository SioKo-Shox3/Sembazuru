//! M3.2b Rust-side VFS test: the worker's named-pipe server hydrates a path on
//! behalf of a (here, Rust-stand-in) hook DLL, pulling the bytes from the agent
//! file server and materializing them into a scratch tree. Proves the
//! pipe -> worker -> agent -> hydrate path end-to-end before the real C++ hook
//! client (M3.2c) drives it.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;

struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("sbz-vfs-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

async fn start_file_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files(listener).await;
    });
    addr
}

/// Sends one hydrate request over the pipe and returns (status, local_path).
async fn pipe_hydrate(full: &str, logical: &str) -> (u8, String) {
    let mut client = loop {
        match ClientOptions::new().open(full) {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    let payload = logical.as_bytes();
    client
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await
        .unwrap();
    client.write_all(payload).await.unwrap();
    client.flush().await.unwrap();

    let mut len = [0u8; 4];
    client.read_exact(&mut len).await.unwrap();
    let n = u32::from_le_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    client.read_exact(&mut buf).await.unwrap();
    (buf[0], String::from_utf8(buf[1..].to_vec()).unwrap())
}

#[tokio::test]
async fn pipe_hydrates_file_into_scratch() {
    let dir = TempDir::new("hydrate");
    let content = b"int answer() { return 42; }\n";
    let logical = dir.join("proj/lib.cpp");
    std::fs::create_dir_all(logical.parent().unwrap()).unwrap();
    std::fs::write(&logical, content).unwrap();
    let logical_str = logical.to_string_lossy().into_owned();

    let addr = start_file_server().await;
    let scratch = dir.join("scratch");
    let pipe_name = format!("sbz-vfs-test-{}", std::process::id());
    let full = format!(r"\\.\pipe\{pipe_name}");
    {
        let pn = pipe_name.clone();
        let sc = scratch.clone();
        tokio::spawn(async move {
            let _ = sembazuru_worker::vfs_pipe::serve_vfs(&pn, addr, sc).await;
        });
    }

    // Hydrate: must succeed, return a scratch path distinct from the logical
    // one, and that scratch file must hold the agent's exact bytes.
    let (status, local) = pipe_hydrate(&full, &logical_str).await;
    assert_eq!(status, 0, "hydrate should succeed");
    assert_ne!(
        local.to_lowercase(),
        logical_str.to_lowercase(),
        "the DLL must be redirected to a scratch copy, not the original path"
    );
    let scratch_prefix = scratch.to_string_lossy().to_lowercase();
    assert!(
        local.to_lowercase().starts_with(&scratch_prefix),
        "hydrated path {local} must live under the scratch root"
    );
    assert_eq!(std::fs::read(&local).unwrap(), content, "bytes must match");

    // A missing file reports not-found (status 1), so the DLL can fall back.
    let missing = dir.join("nope.h").to_string_lossy().into_owned();
    let (status, _) = pipe_hydrate(&full, &missing).await;
    assert_eq!(status, 1, "missing file is reported not-found");
}
