//! M3.2b Rust-side VFS test: the worker's named-pipe server hydrates a path on
//! behalf of a (here, Rust-stand-in) hook DLL, pulling the bytes from the agent
//! file server and materializing them into a scratch tree. Proves the
//! pipe -> worker -> agent -> hydrate path end-to-end before the real C++ hook
//! client (M3.2c) drives it.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

async fn start_file_server_with_token(token: &str) -> std::net::SocketAddr {
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

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(previous) = self.previous.take() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

/// Sends one hydrate request over the pipe and returns (status, local_path).
async fn pipe_hydrate(full: &str, logical: &str) -> (u8, String) {
    // Retry until the pipe is up, but with a deadline: `serve_vfs` swallows
    // early start-up errors, so without one a failed server would hang the test
    // (a CI job kill) instead of failing cleanly with a readable message.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut client = loop {
        match ClientOptions::new().open(full) {
            Ok(c) => break c,
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    panic!("vfs pipe {full} never opened within 10s: {e}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
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
        let cas = dir.join("worker-cas");
        tokio::spawn(async move {
            let _ = sembazuru_worker::vfs_pipe::serve_vfs(
                &pn,
                addr,
                sc,
                cas,
                std::time::Duration::ZERO,
                String::new(), // unscoped harness
            )
            .await;
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

#[tokio::test]
async fn dataplane_uses_config_token_not_env() {
    let _guard = ENV_LOCK.lock().await;
    let _env = EnvVarGuard::set("SEMBAZURU_CLUSTER_TOKEN", "env-wrong");

    let dir = TempDir::new("cfg-token");
    let content = b"int token_source() { return 7; }\n";
    let logical = dir.join("proj/token.cpp");
    std::fs::create_dir_all(logical.parent().unwrap()).unwrap();
    std::fs::write(&logical, content).unwrap();
    let logical_str = logical.to_string_lossy().into_owned();

    let addr = start_file_server_with_token("cfg-tok").await;
    let scratch = dir.join("scratch");
    let pipe_name = format!("sbz-vfs-token-{}", std::process::id());
    let full = format!(r"\\.\pipe\{pipe_name}");
    {
        let pn = pipe_name.clone();
        let sc = scratch.clone();
        let cas = dir.join("worker-cas");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = sembazuru_worker::vfs_pipe::serve_vfs_with_prefetch_ready(
                &pn,
                addr,
                sc,
                cas,
                Duration::ZERO,
                Vec::new(),
                ready_tx,
                String::new(),
                String::new(),
                "cfg-tok".to_string(),
            )
            .await;
        });
        ready_rx.await.expect("VFS pipe should become ready");
    }

    let (status, local) = pipe_hydrate(&full, &logical_str).await;
    assert_eq!(
        status, 0,
        "hydrate should authenticate with the config token, not the env token"
    );
    assert_eq!(std::fs::read(&local).unwrap(), content, "bytes must match");
}

/// M4.2 "Done when" core: a second build transfers no file content for a path
/// the worker has already cached. Two VFS sessions (separate pipes, simulating
/// two builds) share one worker CAS root; the agent's [`ServerStats`] proves the
/// second hydrate pushes **zero** additional content bytes over the data plane.
#[tokio::test]
async fn worker_cache_eliminates_retransfer_on_second_build() {
    use sembazuru_agent::fileserver::ServerStats;
    use std::sync::Arc;

    let dir = TempDir::new("recache");
    // Content larger than a trivial header, so a real fetch is non-zero bytes.
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let logical = dir.join("proj/big.h");
    std::fs::create_dir_all(logical.parent().unwrap()).unwrap();
    std::fs::write(&logical, &content).unwrap();
    let logical_str = logical.to_string_lossy().into_owned();

    // Agent file server with a stats handle we keep.
    let stats = Arc::new(ServerStats::default());
    let addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = listener.local_addr().unwrap();
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = sembazuru_agent::fileserver::serve_files_with_stats(listener, s).await;
        });
        a
    };

    // One worker CAS shared across both "builds".
    let cas_root = dir.join("worker-cas");

    // --- Build 1: cold cache → the file is fetched once. ---
    let pipe1 = format!("sbz-recache-1-{}", std::process::id());
    let full1 = format!(r"\\.\pipe\{pipe1}");
    {
        let (pn, sc, cas) = (pipe1.clone(), dir.join("scratch1"), cas_root.clone());
        tokio::spawn(async move {
            let _ = sembazuru_worker::vfs_pipe::serve_vfs(
                &pn,
                addr,
                sc,
                cas,
                Duration::ZERO,
                String::new(),
            )
            .await;
        });
    }
    let (status, local1) = pipe_hydrate(&full1, &logical_str).await;
    assert_eq!(status, 0, "build 1 hydrate should succeed");
    assert_eq!(
        std::fs::read(&local1).unwrap(),
        content,
        "build 1 bytes match"
    );
    let after_build1 = stats.content_bytes();
    assert!(
        after_build1 >= content.len() as u64,
        "build 1 must transfer the file content once (got {after_build1})"
    );

    // --- Build 2: warm cache (same CAS root) → zero content transfer. ---
    let pipe2 = format!("sbz-recache-2-{}", std::process::id());
    let full2 = format!(r"\\.\pipe\{pipe2}");
    {
        let (pn, sc, cas) = (pipe2.clone(), dir.join("scratch2"), cas_root.clone());
        tokio::spawn(async move {
            let _ = sembazuru_worker::vfs_pipe::serve_vfs(
                &pn,
                addr,
                sc,
                cas,
                Duration::ZERO,
                String::new(),
            )
            .await;
        });
    }
    let (status, local2) = pipe_hydrate(&full2, &logical_str).await;
    assert_eq!(status, 0, "build 2 hydrate should succeed");
    assert_eq!(
        std::fs::read(&local2).unwrap(),
        content,
        "build 2 serves identical bytes from the worker cache"
    );
    let after_build2 = stats.content_bytes();
    assert_eq!(
        after_build2, after_build1,
        "build 2 must transfer ZERO additional content (cache hit), \
         but content bytes went {after_build1} -> {after_build2}"
    );
}
