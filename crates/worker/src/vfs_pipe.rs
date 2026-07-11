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
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use sembazuru_cas::BlobStore;
use sembazuru_proto::quotas::MAX_PREDICTED_PATHS;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{Mutex, Notify, OnceCell};

use crate::fileclient::FileClient;

const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_ERROR: u8 = 2;
const MAX_MSG: u32 = 64 * 1024; // a path message; generous bound
const PREFETCH_CONCURRENCY: usize = 32;

#[derive(Clone, Default)]
pub(crate) struct MaterializationTracker {
    inner: Arc<MaterializationTrackerInner>,
}

#[derive(Default)]
struct MaterializationTrackerInner {
    active: AtomicUsize,
    idle: Notify,
}

struct MaterializationGuard(Arc<MaterializationTrackerInner>);

impl Drop for MaterializationGuard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, AtomicOrdering::AcqRel) == 1 {
            self.0.idle.notify_one();
        }
    }
}

impl MaterializationTracker {
    pub(crate) fn spawn_blocking<F, T>(&self, operation: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.inner.active.fetch_add(1, AtomicOrdering::AcqRel);
        let guard = MaterializationGuard(Arc::clone(&self.inner));
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            operation()
        })
    }

    pub(crate) async fn wait_idle(&self) {
        loop {
            if self.inner.active.load(AtomicOrdering::Acquire) == 0 {
                return;
            }
            let notified = self.inner.idle.notified();
            if self.inner.active.load(AtomicOrdering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

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
    /// agent does not scope (legacy/tests). Advisory as of ADR 0013: when
    /// `session_id` names a known session the agent uses its own authoritative
    /// root instead (closing the worker-can-widen-scope hole, SEC-004).
    session_root: String,
    /// The agent-minted session id (ADR 0013), presented on the data-plane
    /// handshake so the agent binds this connection to the authoritative session
    /// (root, per-session pin partition, allowed-digest set, declared outputs).
    /// Empty = legacy per-connection scoping by the worker-declared `session_root`.
    session_id: String,
    /// The session's pooled, multiplexed agent connection, dialed on first
    /// hydrate. `OnceCell::get_or_try_init` retries if the first dial fails, so a
    /// worker that starts before the agent is listening recovers on a later open.
    client: OnceCell<FileClient>,
    materializations: MaterializationTracker,
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
                    self.session_id.clone(),
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
        let paths = bounded_prefetch_paths(paths).cloned().collect::<Vec<_>>();
        let state = Arc::clone(self);
        for_each_prefetch_bounded(paths, PREFETCH_CONCURRENCY, move |path| {
            let state = Arc::clone(&state);
            async move {
                let _ = hydrate(&path, &state).await;
            }
        })
        .await;
    }
}

fn bounded_prefetch_paths(paths: &[String]) -> impl Iterator<Item = &String> {
    paths.iter().take(MAX_PREDICTED_PATHS)
}

async fn for_each_prefetch_bounded<I, F, Fut>(paths: I, limit: usize, f: F)
where
    I: IntoIterator<Item = String>,
    F: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut paths = paths.into_iter();
    let mut tasks = FuturesUnordered::new();
    for _ in 0..limit.max(1) {
        let Some(path) = paths.next() else {
            break;
        };
        let f = f.clone();
        tasks.push(f(path));
    }
    while tasks.next().await.is_some() {
        let Some(path) = paths.next() else {
            continue;
        };
        let f = f.clone();
        tasks.push(f(path));
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
        // Wrappers serve the legacy/test path with no agent-minted session id
        // and no auth token.
        String::new(),
        String::new(),
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
    session_id: String,
    auth_token: String,
) -> io::Result<()> {
    serve_vfs_with_prefetch_ready_tracked(
        pipe_name,
        agent_addr,
        scratch_root,
        cas_root,
        rtt,
        predicted_paths,
        ready,
        vfs_root,
        session_id,
        auth_token,
        MaterializationTracker::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_vfs_with_prefetch_ready_tracked(
    pipe_name: &str,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    cas_root: PathBuf,
    rtt: Duration,
    predicted_paths: Vec<String>,
    ready: tokio::sync::oneshot::Sender<()>,
    vfs_root: String,
    session_id: String,
    auth_token: String,
    materializations: MaterializationTracker,
) -> io::Result<()> {
    let full = format!(r"\\.\pipe\{pipe_name}");
    let state = Arc::new(VfsState {
        scratch_root,
        hydrated: Mutex::new(HashMap::new()),
        cas: BlobStore::open(cas_root)?,
        agent_addr,
        rtt,
        auth_token,
        // Declared input root the agent scopes file supply to (M7.1).
        session_root: vfs_root,
        // Agent-minted session id (ADR 0013); empty on the wrapper/legacy path.
        session_id,
        client: OnceCell::new(),
        materializations,
    });

    // Create the first instance synchronously, THEN signal readiness: once
    // `create()` returns the pipe is in the namespace and a client dial will
    // connect (or wait), never miss. Only after this do we let the caller launch.
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&full)?;
    let _ = ready.send(());

    // Keep warm and connected-client work inside this future so cancelling the
    // pipe server synchronously drops every in-flight hydrate.
    let warm_state = Arc::clone(&state);
    let warm = warm_state.prefetch_warm(&predicted_paths);
    serve_pipe_with_owned_futures(&full, server, warm, move |connected| {
        handle_client(connected, Arc::clone(&state))
    })
    .await
}

async fn serve_pipe_with_owned_futures<Warm, Handle, Client>(
    full: &str,
    mut server: NamedPipeServer,
    warm: Warm,
    mut handle_client: Handle,
) -> io::Result<()>
where
    Warm: Future<Output = ()>,
    Handle: FnMut(NamedPipeServer) -> Client,
    Client: Future<Output = io::Result<()>>,
{
    let mut warm_done = false;
    tokio::pin!(warm);
    let mut clients = FuturesUnordered::new();

    loop {
        tokio::select! {
            () = &mut warm, if !warm_done => warm_done = true,
            result = server.connect() => {
                result?;
                let connected = server;
                // Pre-create immediately so a client never races a missing pipe.
                server = ServerOptions::new().create(full)?;
                clients.push(handle_client(connected));
            }
            Some(_result) = clients.next(), if !clients.is_empty() => {}
        }
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
    let local_for_write = local.clone();
    let materialize = state.materializations.spawn_blocking(move || {
        if let Some(parent) = local_for_write.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&local_for_write, &bytes)
    });
    if materialize.await.map_or(true, |result| result.is_err()) {
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
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use sembazuru_agent::fileserver::ServerStats;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct HydrateActivityGuard(Arc<AtomicUsize>);

    impl Drop for HydrateActivityGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

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
                String::new(), // no agent-minted session (legacy path)
                String::new(), // no auth token
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
            session_id: String::new(),   // no agent-minted session (legacy path)
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
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

    #[tokio::test]
    async fn prefetch_peak_concurrency_never_exceeds_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let paths = (0..200).map(|i| format!("c:\\proj\\h{i}.h"));

        for_each_prefetch_bounded(paths, 32, {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let completed = Arc::clone(&completed);
            move |_| {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                let completed = Arc::clone(&completed);
                async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .await;

        assert_eq!(completed.load(Ordering::SeqCst), 200);
        assert!(peak.load(Ordering::SeqCst) <= 32);
    }

    #[tokio::test]
    async fn prefetch_zero_limit_still_processes_every_path() {
        let completed = Arc::new(AtomicUsize::new(0));
        let paths = (0..5).map(|i| format!("c:\\proj\\zero-limit-{i}.h"));

        for_each_prefetch_bounded(paths, 0, {
            let completed = Arc::clone(&completed);
            move |_| {
                let completed = Arc::clone(&completed);
                async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .await;

        assert_eq!(completed.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn dropping_pipe_future_drops_all_warm_futures_before_return() {
        use tokio::net::windows::named_pipe::ClientOptions;

        let active = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();

        let warm = for_each_prefetch_bounded((0..64).map(|i| format!("warm-{i}")), 32, {
            let active = Arc::clone(&active);
            let writes = Arc::clone(&writes);
            let release = Arc::clone(&release);
            let started_tx = started_tx.clone();
            move |_| {
                let active = Arc::clone(&active);
                let writes = Arc::clone(&writes);
                let release = Arc::clone(&release);
                let started_tx = started_tx.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = HydrateActivityGuard(active);
                    started_tx.send(()).unwrap();
                    release.notified().await;
                    writes.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        let name = format!(
            "sbz-owned-futures-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let full = format!(r"\\.\pipe\{name}");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&full)
            .unwrap();

        let client_active = Arc::clone(&active);
        let client_writes = Arc::clone(&writes);
        let client_release = Arc::clone(&release);
        let client_started = started_tx.clone();
        let serve_full = full.clone();
        let outer = tokio::spawn(async move {
            serve_pipe_with_owned_futures(&serve_full, server, warm, move |pipe| {
                let active = Arc::clone(&client_active);
                let writes = Arc::clone(&client_writes);
                let release = Arc::clone(&client_release);
                let started_tx = client_started.clone();
                async move {
                    let _pipe = pipe;
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = HydrateActivityGuard(active);
                    started_tx.send(()).unwrap();
                    release.notified().await;
                    writes.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await
        });

        let _client = ClientOptions::new().open(&full).unwrap();
        for _ in 0..33 {
            tokio::time::timeout(Duration::from_secs(5), started_rx.recv())
                .await
                .expect("warm and connected-client hydrate futures should start")
                .expect("pipe future should retain the start sender");
        }
        assert_eq!(active.load(Ordering::SeqCst), 33);

        outer.abort();
        let aborted = outer.await.unwrap_err();
        assert!(aborted.is_cancelled());
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "abort + await must synchronously drop every owned hydrate future"
        );

        let writes_after_abort = writes.load(Ordering::SeqCst);
        release.notify_waiters();
        tokio::task::yield_now().await;
        assert_eq!(writes.load(Ordering::SeqCst), writes_after_abort);
    }

    #[tokio::test]
    async fn shutdown_waits_for_detached_blocking_materialization_before_cleanup() {
        let scratch = temp("blocking-drain");
        std::fs::remove_dir_all(&scratch).unwrap();
        let local = scratch.join("nested").join("header.h");
        let local_for_job = local.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let tracker = MaterializationTracker::default();

        let hydrate_tracker = tracker.clone();
        let hydrate_task = tokio::spawn(async move {
            hydrate_tracker
                .spawn_blocking(move || {
                    let _ = started_tx.send(());
                    release_rx.recv().unwrap();
                    std::fs::create_dir_all(local_for_job.parent().unwrap())?;
                    std::fs::write(local_for_job, b"tracked materialization")
                })
                .await
        });

        started_rx
            .await
            .expect("blocking materialization should start");
        let shutdown_tracker = tracker.clone();
        let mut shutdown = tokio::spawn(async move {
            hydrate_task.abort();
            let _ = hydrate_task.await;
            shutdown_tracker.wait_idle().await;
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown must remain pending while the detached blocking job is parked"
        );

        release_tx.send(()).unwrap();
        shutdown.await.unwrap();
        assert_eq!(std::fs::read(&local).unwrap(), b"tracked materialization");
        std::fs::remove_dir_all(&scratch).unwrap();
        assert!(
            !scratch.exists(),
            "no blocking writer may recreate scratch after shutdown returns"
        );
    }

    #[test]
    fn prefetch_warm_caps_predicted_path_tasks_to_quota() {
        let paths = (0..(MAX_PREDICTED_PATHS + 1))
            .map(|i| format!("c:\\src\\h{i}.h"))
            .collect::<Vec<_>>();

        let bounded = bounded_prefetch_paths(&paths).collect::<Vec<_>>();

        assert_eq!(bounded.len(), MAX_PREDICTED_PATHS);
        assert_eq!(
            bounded[MAX_PREDICTED_PATHS - 1].as_str(),
            format!("c:\\src\\h{}.h", MAX_PREDICTED_PATHS - 1)
        );
    }
}
