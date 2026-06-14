//! Worker-side VFS named-pipe server (M3.2b). The injected hook DLL, when in
//! VFS mode, asks this server to *hydrate* a path it is about to open for read:
//! the server materializes the bytes into a per-session scratch tree and replies
//! with the local scratch path the DLL should open instead (hydrate-on-open,
//! `docs/decisions/0001-vfs-approach.md`). Keeping the DLL on a local pipe
//! (never the network transport) keeps its re-entrancy-safe surface tiny — the
//! three-layer split is DLL -> worker(pipe) -> agent(data plane).
//!
//! **Worker-local cache (M4).** Hydration is digest-first: the worker asks the
//! agent for the path's *digest only* (no bytes), and if its local content store
//! (CAS) already holds that digest — a header seen in a previous build — it
//! materializes from the local blob and transfers **no content over the
//! network** (the make-or-break of the M4 "Done when"). Only a cache miss pulls
//! bytes, which are then verified and stored for next time. The CAS lives at a
//! caller-provided root so it persists across builds.
//!
//! **Wire (byte-mode pipe, matches the C++ client):** each message is a `u32`
//! little-endian length prefix followed by the payload.
//!   * request payload  = the UTF-8 path to hydrate.
//!   * response payload = 1 status byte (0=ok, 1=not-found, 2=error) followed by
//!     the UTF-8 local path to open (empty unless status==0).
//!
//! **Connection pooling (M5.3).** The agent connection is established once per
//! session and shared (lazily, so worker/agent startup order does not matter):
//! every hydrate reuses the one multiplexed [`FileClient`] instead of dialing a
//! fresh TCP connection. The scratch tree persists for the session and is not yet
//! scrubbed (M3.3 owns output fencing/cleanup).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sembazuru_cas::BlobStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{Mutex, OnceCell};

use crate::fileclient::FileClient;

const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_ERROR: u8 = 2;
const MAX_MSG: u32 = 64 * 1024; // a path message; generous bound

/// Shared state for the VFS server: the per-session path→scratch cache (so a
/// re-open is a pipe round-trip with no work), the cross-build content store, and
/// the one pooled agent connection shared by every hydrate this session.
struct VfsState {
    scratch_root: PathBuf,
    /// Logical path → materialized scratch path, for this session.
    hydrated: Mutex<HashMap<String, String>>,
    /// Content-addressed store, persisting across builds: a blob seen once is
    /// never re-fetched.
    cas: BlobStore,
    agent_addr: SocketAddr,
    rtt: Duration,
    /// Shared cluster token (M7, ADR 0006) presented on the data-plane handshake.
    /// Empty when the cluster runs without auth.
    auth_token: String,
    /// The action's agent-side input root (`VfsExecution.vfs_root`), declared on
    /// the handshake so the agent scopes file supply to it (M7.1). Empty = the
    /// agent does not scope (legacy/tests).
    session_root: String,
    /// The session's pooled, multiplexed agent connection, dialed on first
    /// hydrate. `OnceCell::get_or_try_init` retries if the first dial fails, so a
    /// worker that starts before the agent is listening recovers on a later open.
    client: OnceCell<FileClient>,
}

impl VfsState {
    /// The shared agent connection, dialed once and reused. A clone is an `Arc`
    /// bump; all hydrates issue ops concurrently over the one socket.
    async fn client(&self) -> io::Result<FileClient> {
        self.client
            .get_or_try_init(|| {
                FileClient::connect_with_rtt_session(
                    self.agent_addr,
                    self.rtt,
                    self.auth_token.clone(),
                    self.session_root.clone(),
                )
            })
            .await
            .cloned()
    }

    /// Dependency-prediction prefetch (M5.4): warm `paths` into the session
    /// before the compiler asks for them. Each path is hydrated concurrently —
    /// the multiplexed connection (M5.3) overlaps the probes/fetches, so N
    /// predicted files warm in roughly one round-trip's wall time instead of N.
    /// Best-effort: a path that fails to warm is simply hydrated for real later.
    async fn prefetch_warm(self: &Arc<Self>, paths: &[String]) {
        let mut tasks = Vec::with_capacity(paths.len());
        for p in paths {
            let state = Arc::clone(self);
            let p = p.clone();
            tasks.push(tokio::spawn(async move {
                let _ = hydrate(&p, &state).await;
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }
}

/// Maps an agent-side logical path to its location in the scratch tree by
/// flattening the drive letter: `C:\work\a.cpp` -> `<scratch>\C\work\a.cpp`. The
/// exact scratch layout is invisible to the compiler (it opens the handle we
/// return but records the logical path it asked for), so any stable, collision-
/// free mapping is fine here.
fn scratch_mirror(scratch_root: &Path, logical: &str) -> PathBuf {
    let mut rel = String::with_capacity(logical.len());
    for ch in logical.chars() {
        match ch {
            ':' => {}              // drop the drive colon
            '/' => rel.push('\\'), // normalize separators
            c => rel.push(c),
        }
    }
    let rel = rel.trim_start_matches('\\');
    scratch_root.join(rel)
}

/// Serves the VFS pipe until an unrecoverable error. `pipe_name` is the bare
/// name (the `\\.\pipe\` prefix is added here). `cas_root` is the worker's
/// content store directory (persisted across builds for the worker-local cache).
pub async fn serve_vfs(
    pipe_name: &str,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    cas_root: PathBuf,
    rtt: Duration,
    vfs_root: String,
) -> io::Result<()> {
    serve_vfs_with_prefetch(
        pipe_name,
        agent_addr,
        scratch_root,
        cas_root,
        rtt,
        Vec::new(),
        vfs_root,
    )
    .await
}

/// Like [`serve_vfs`], but warms `predicted_paths` (a prior build's inputs, from
/// `ExecuteRequest.predicted_paths`) into the session in the background as it
/// starts serving — so the compiler's first opens hit an already-warm cache
/// instead of paying the round-trip (M5.4 dependency-prediction prefetch).
pub async fn serve_vfs_with_prefetch(
    pipe_name: &str,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    cas_root: PathBuf,
    rtt: Duration,
    predicted_paths: Vec<String>,
    vfs_root: String,
) -> io::Result<()> {
    // No readiness signal wanted (the dev harness/tests poll the pipe path or
    // tolerate the race); discard it.
    let (ready, _rx) = tokio::sync::oneshot::channel();
    serve_vfs_with_prefetch_ready(
        pipe_name,
        agent_addr,
        scratch_root,
        cas_root,
        rtt,
        predicted_paths,
        ready,
        vfs_root,
    )
    .await
}

/// Like [`serve_vfs_with_prefetch`], but fires `ready` the instant the first
/// pipe instance exists in the namespace, BEFORE blocking on a client.
///
/// This closes a real race the worker's `Execute` path would otherwise hit
/// (Plan review M6.1, risk 1): the first pipe instance is created inside this
/// future, so a caller that spawns this as a task and immediately launches the
/// hooked compiler can have the compiler dial `\\.\pipe\<name>` before
/// `create()` has run — getting `ERROR_FILE_NOT_FOUND` and silently falling
/// back to the real filesystem (no redirect). By awaiting `ready` before
/// launching, the worker guarantees the pipe is listening first — deterministic,
/// not a sleep-poll. If `create()` fails, `ready` is dropped without firing, so
/// the caller's `rx.await` errors and the action fails closed.
#[allow(clippy::too_many_arguments)]
pub async fn serve_vfs_with_prefetch_ready(
    pipe_name: &str,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    cas_root: PathBuf,
    rtt: Duration,
    predicted_paths: Vec<String>,
    ready: tokio::sync::oneshot::Sender<()>,
    vfs_root: String,
) -> io::Result<()> {
    let full = format!(r"\\.\pipe\{pipe_name}");
    let state = Arc::new(VfsState {
        scratch_root,
        hydrated: Mutex::new(HashMap::new()),
        cas: BlobStore::open(cas_root)?,
        agent_addr,
        rtt,
        // Production token comes from the environment (ADR 0006); empty disables
        // auth (the agent then accepts unconditionally).
        auth_token: sembazuru_proto::auth::cluster_token_from_env().unwrap_or_default(),
        // Declared input root the agent scopes file supply to (M7.1).
        session_root: vfs_root,
        client: OnceCell::new(),
    });

    // Warm predicted inputs ahead of process I/O, concurrently with serving.
    if !predicted_paths.is_empty() {
        let warm = Arc::clone(&state);
        tokio::spawn(async move {
            warm.prefetch_warm(&predicted_paths).await;
        });
    }

    // Create the first instance synchronously, THEN signal readiness: once
    // `create()` returns the pipe is in the namespace and a client dial will
    // connect (or wait), never miss. Only after this do we let the caller launch.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&full)?;
    let _ = ready.send(());

    loop {
        server.connect().await?;
        let connected = server;
        // Pre-create the next instance so a client never races a missing pipe.
        server = ServerOptions::new().create(&full)?;

        let state = state.clone();
        tokio::spawn(async move {
            let _ = handle_client(connected, state).await;
        });
    }
}

async fn handle_client(mut pipe: NamedPipeServer, state: Arc<VfsState>) -> io::Result<()> {
    loop {
        let path = match read_msg(&mut pipe).await {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(p) => p,
                Err(_) => {
                    write_response(&mut pipe, STATUS_ERROR, "").await?;
                    continue;
                }
            },
            Ok(None) => return Ok(()), // client closed
            Err(e) => return Err(e),
        };

        let (status, local) = hydrate(&path, &state).await;
        write_response(&mut pipe, status, &local).await?;
    }
}

async fn hydrate(path: &str, state: &VfsState) -> (u8, String) {
    if let Some(local) = state.hydrated.lock().await.get(path) {
        return (STATUS_OK, local.clone());
    }

    // Reuse the session's pooled connection (dialed once); a clone shares the
    // one socket and multiplexes with other in-flight hydrates.
    let client = match state.client().await {
        Ok(c) => c,
        Err(_) => return (STATUS_ERROR, String::new()),
    };

    // Digest-first: learn the content identity without transferring bytes.
    let (digest, size) = match client.probe_digest(path).await {
        Ok(Some(v)) => v,
        Ok(None) => return (STATUS_NOT_FOUND, String::new()),
        Err(_) => return (STATUS_ERROR, String::new()),
    };

    // Local cache hit → no content crosses the network. Verify on the way out
    // of the store so on-disk corruption can't feed the compiler bad bytes.
    let bytes = match state.cas.get_verified(&digest) {
        Ok(Some(b)) => b,
        _ => {
            // Miss (or corrupt): fetch from the agent, verify, and store.
            let fetched = match client.fetch_by_digest(&digest, size).await {
                Ok(b) => b,
                Err(_) => return (STATUS_ERROR, String::new()),
            };
            if state.cas.put_verified(&fetched, &digest).is_err() {
                return (STATUS_ERROR, String::new());
            }
            fetched
        }
    };

    let local = scratch_mirror(&state.scratch_root, path);
    if let Some(parent) = local.parent()
        && tokio::fs::create_dir_all(parent).await.is_err()
    {
        return (STATUS_ERROR, String::new());
    }
    if tokio::fs::write(&local, &bytes).await.is_err() {
        return (STATUS_ERROR, String::new());
    }
    let local_str = local.to_string_lossy().into_owned();
    state
        .hydrated
        .lock()
        .await
        .insert(path.to_string(), local_str.clone());
    (STATUS_OK, local_str)
}

/// Reads one length-prefixed message. Returns `None` on a clean EOF before any
/// bytes (client disconnected between requests).
async fn read_msg(pipe: &mut NamedPipeServer) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match pipe.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vfs pipe message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    pipe.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_response(pipe: &mut NamedPipeServer, status: u8, local: &str) -> io::Result<()> {
    let mut payload = Vec::with_capacity(1 + local.len());
    payload.push(status);
    payload.extend_from_slice(local.as_bytes());
    pipe.write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    pipe.write_all(&payload).await?;
    pipe.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sembazuru_agent::fileserver::ServerStats;

    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn temp(tag: &str) -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "sbz-vfsprefetch-{}-{tag}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// M6.1 (Plan risk 1): the readiness signal fires only after the first pipe
    /// instance exists, so a client dialing the instant `ready` resolves connects
    /// without a retry/poll. Without the synchronous create-before-signal, the
    /// worker's launched compiler could miss the pipe and silently skip the VFS.
    #[tokio::test]
    async fn ready_signal_means_the_pipe_is_dialable() {
        use tokio::net::windows::named_pipe::ClientOptions;

        let name = format!(
            "sbz-ready-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let full = format!(r"\\.\pipe\{name}");
        let (tx, rx) = tokio::sync::oneshot::channel();

        let serve_name = name.clone();
        let scratch = temp("ready-scratch");
        let cas = temp("ready-cas");
        tokio::spawn(async move {
            let _ = serve_vfs_with_prefetch_ready(
                &serve_name,
                "127.0.0.1:1".parse().unwrap(), // never dialed in this test
                scratch,
                cas,
                Duration::ZERO,
                Vec::new(),
                tx,
                String::new(), // unscoped (this test never dials the agent)
            )
            .await;
        });

        // Block until the pipe is reported ready, then dial it ONCE — no retry.
        rx.await
            .expect("serve task created the pipe and signaled readiness");
        let client = ClientOptions::new().open(&full);
        assert!(
            client.is_ok(),
            "the pipe must be connectable the instant readiness fires, got {:?}",
            client.err()
        );
    }

    /// M5.4: prefetch_warm pulls the predicted files ahead of time, so the
    /// compiler's later opens are served from the warm session cache with NO
    /// further content crossing the data plane.
    #[tokio::test]
    async fn prefetch_warm_makes_later_opens_zero_transfer() {
        // Agent file server with stats so we can measure content bytes served.
        let src = temp("src");
        let mut paths = Vec::new();
        for i in 0..6 {
            let body = format!("header-{i}-contents\n").repeat(50);
            let p = src.join(format!("h{i}.h"));
            std::fs::write(&p, &body).unwrap();
            paths.push(p.to_string_lossy().into_owned());
        }
        let stats = Arc::new(ServerStats::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let stats = stats.clone();
            tokio::spawn(async move {
                let _ = sembazuru_agent::fileserver::serve_files_with_stats(listener, stats).await;
            });
        }

        let state = Arc::new(VfsState {
            scratch_root: temp("scratch"),
            hydrated: Mutex::new(HashMap::new()),
            cas: BlobStore::open(temp("cas")).unwrap(),
            agent_addr: addr,
            rtt: Duration::ZERO,
            auth_token: String::new(),   // auth-disabled harness
            session_root: String::new(), // unscoped harness
            client: OnceCell::new(),
        });

        // Warm all predicted paths. Content is pulled once here.
        state.prefetch_warm(&paths).await;
        let after_warm = stats.content_bytes();
        assert!(
            after_warm > 0,
            "prefetch should pull predicted content (got {after_warm} bytes)"
        );

        // The compiler's opens now hit the warm session cache: each hydrate
        // returns OK and transfers NO further content.
        for path in &paths {
            let (status, local) = hydrate(path, &state).await;
            assert_eq!(status, STATUS_OK, "warmed path hydrates as a hit");
            assert!(!local.is_empty());
        }
        assert_eq!(
            stats.content_bytes(),
            after_warm,
            "opens after prefetch transfer zero additional content"
        );
    }
}
