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
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
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
static HYDRATE_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Default)]
struct MaterializationTracker {
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
    fn spawn_blocking<F, T>(&self, operation: F) -> tokio::task::JoinHandle<T>
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

    async fn wait_idle(&self) {
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

/// Owns one action's VFS serve task and every blocking materialization it
/// started.
///
/// Dropping this handle stops new work by aborting the serve task, but cannot
/// asynchronously wait for blocking materializations. Callers that remove the
/// action scratch tree must retain this handle and await
/// [`ActionVfsServer::shutdown`] before cleanup; only `shutdown` guarantees that
/// already-running blocking work has drained.
#[must_use = "retain the VFS owner and await shutdown before cleaning its scratch tree"]
pub struct ActionVfsServer {
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
    materializations: MaterializationTracker,
}

impl ActionVfsServer {
    /// Stops the pipe task, synchronously drops its warm/client futures, then
    /// waits for already-running blocking filesystem work to finish.
    /// Scratch cleanup is safe only after this future returns.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.materializations.wait_idle().await;
    }
}

impl Drop for ActionVfsServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
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
    /// Normalized logical path -> action-lifetime single-flight gate.
    hydrating: Mutex<HashMap<String, Arc<Mutex<()>>>>,
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
                let _ = hydrate(&path, &state, || hydrate_uncached(&path, &state)).await;
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

fn hydration_key(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

async fn hydration_gate(state: &VfsState, key: &str) -> Arc<Mutex<()>> {
    let mut gates = state.hydrating.lock().await;
    Arc::clone(
        gates
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

fn hydrate_temp_path(final_path: &Path) -> PathBuf {
    let id = HYDRATE_TEMP_ID.fetch_add(1, AtomicOrdering::Relaxed);
    let mut name = final_path.as_os_str().to_os_string();
    name.push(format!(".sbz-tmp-{}-{id}", std::process::id()));
    PathBuf::from(name)
}

struct AtomicPublishTemp {
    path: PathBuf,
    file: Option<std::fs::File>,
    committed: bool,
}

impl Drop for AtomicPublishTemp {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn atomic_publish<F>(final_path: &Path, operation: F) -> io::Result<()>
where
    F: FnOnce(&mut std::fs::File) -> io::Result<()>,
{
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = hydrate_temp_path(final_path);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    let mut temp = AtomicPublishTemp {
        path: temp_path,
        file: Some(file),
        committed: false,
    };

    operation(temp.file.as_mut().expect("open atomic publish file"))?;
    temp.file
        .as_mut()
        .expect("open atomic publish file")
        .flush()?;
    drop(temp.file.take());
    std::fs::rename(&temp.path, final_path)?;
    temp.committed = true;
    Ok(())
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

/// Starts an action-owned VFS server and returns only after its first pipe
/// instance is dialable. A caller that later cleans the supplied scratch tree
/// must call [`ActionVfsServer::shutdown`] first.
#[allow(clippy::too_many_arguments)]
pub async fn start_action_vfs(
    pipe_name: String,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    cas_root: PathBuf,
    rtt: Duration,
    predicted_paths: Vec<String>,
    vfs_root: String,
    session_id: String,
    auth_token: String,
) -> io::Result<ActionVfsServer> {
    start_action_vfs_owner(move |materializations, ready_tx| async move {
        serve_vfs_with_prefetch_ready_tracked(
            &pipe_name,
            agent_addr,
            scratch_root,
            cas_root,
            rtt,
            predicted_paths,
            ready_tx,
            vfs_root,
            session_id,
            auth_token,
            materializations,
        )
        .await
    })
    .await
}

async fn start_action_vfs_owner<Start, Serve>(start: Start) -> io::Result<ActionVfsServer>
where
    Start: FnOnce(MaterializationTracker, tokio::sync::oneshot::Sender<()>) -> Serve,
    Serve: Future<Output = io::Result<()>> + Send + 'static,
{
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let materializations = MaterializationTracker::default();
    let task_materializations = materializations.clone();
    let task = tokio::spawn(start(task_materializations, ready_tx));
    let server = ActionVfsServer {
        task: Some(task),
        materializations,
    };
    if ready_rx.await.is_err() {
        server.shutdown().await;
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "VFS pipe server failed to start",
        ));
    }
    Ok(server)
}

#[allow(clippy::too_many_arguments)]
async fn serve_vfs_with_prefetch_ready_tracked(
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
        hydrating: Mutex::new(HashMap::new()),
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

        let (status, local) = hydrate(&path, &state, || hydrate_uncached(&path, &state)).await;
        write_response(&mut pipe, status, &local).await?;
    }
}

async fn hydrate<F, Fut>(path: &str, state: &VfsState, operation: F) -> (u8, String)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = (u8, String)>,
{
    let key = hydration_key(path);
    if let Some(local) = state.hydrated.lock().await.get(&key).cloned() {
        return (STATUS_OK, local);
    }
    let gate = hydration_gate(state, &key).await;
    let _guard = gate.lock().await;
    if let Some(local) = state.hydrated.lock().await.get(&key).cloned() {
        return (STATUS_OK, local);
    }

    let result = operation().await;
    if result.0 == STATUS_OK {
        state.hydrated.lock().await.insert(key, result.1.clone());
    }
    result
}

async fn hydrate_uncached(path: &str, state: &VfsState) -> (u8, String) {
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
    let materialize = state
        .materializations
        .spawn_blocking(move || atomic_publish(&local_for_write, |file| file.write_all(&bytes)));
    if materialize.await.map_or(true, |result| result.is_err()) {
        return (STATUS_ERROR, String::new());
    }
    let local_str = local.to_string_lossy().into_owned();
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
    use sembazuru_cas::Digest;
    use sembazuru_dataplane::async_io::{read_frame, write_frame};
    use sembazuru_dataplane::ops::{
        HelloResponse, OpenReadRequest, OpenReadResponse, ReadRequest, ReadResponse,
    };
    use sembazuru_dataplane::wire::{FrameHeader, OpCode};
    use tokio::net::{TcpListener, TcpStream};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct HydrateActivityGuard(Arc<AtomicUsize>);

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

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

    fn test_state() -> VfsState {
        VfsState {
            scratch_root: temp("gate-scratch"),
            hydrated: Mutex::new(HashMap::new()),
            hydrating: Mutex::new(HashMap::new()),
            cas: BlobStore::open(temp("gate-cas")).unwrap(),
            agent_addr: "127.0.0.1:0".parse().unwrap(),
            rtt: Duration::ZERO,
            auth_token: String::new(),
            session_root: String::new(),
            session_id: String::new(),
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
        }
    }

    #[tokio::test]
    async fn same_key_gate_stays_single_flight_across_failed_waiters() {
        let state = Arc::new(test_state());
        let start = Arc::new(tokio::sync::Barrier::new(33));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let entries = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for i in 0..32 {
            let state = Arc::clone(&state);
            let start = Arc::clone(&start);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let entries = Arc::clone(&entries);
            tasks.push(tokio::spawn(async move {
                start.wait().await;
                let path = if i % 2 == 0 {
                    "C:/SRC/Shared.H"
                } else {
                    "c:\\src\\shared.h"
                };
                let active_for_op = Arc::clone(&active);
                let peak_for_op = Arc::clone(&peak);
                let entries_for_op = Arc::clone(&entries);
                let result = hydrate(path, &state, || async move {
                    entries_for_op.fetch_add(1, Ordering::SeqCst);
                    let now = active_for_op.fetch_add(1, Ordering::SeqCst) + 1;
                    peak_for_op.fetch_max(now, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    active_for_op.fetch_sub(1, Ordering::SeqCst);
                    (STATUS_ERROR, String::new())
                })
                .await;
                assert_eq!(result.0, STATUS_ERROR);
            }));
        }
        start.wait().await;
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert_eq!(entries.load(Ordering::SeqCst), 32);
        assert_eq!(state.hydrating.lock().await.len(), 1);
    }

    #[test]
    fn hydration_key_normalizes_case_and_separators() {
        assert_eq!(
            hydration_key("C:/SRC/Shared.H"),
            hydration_key("c:\\src\\shared.h")
        );
    }

    #[test]
    fn atomic_publish_operation_failure_removes_temp_without_final() {
        use std::io::Write;

        let root = temp("atomic-operation-failure");
        let final_path = root.join("nested").join("shared.h");
        let result = atomic_publish(&final_path, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("injected write failure"))
        });

        assert!(result.is_err());
        assert!(
            !final_path.exists(),
            "partial final file must not be visible"
        );
        assert_no_hydrate_temps(final_path.parent().unwrap());
    }

    #[test]
    fn atomic_publish_operation_panic_removes_temp_without_final() {
        use std::io::Write;
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let root = temp("atomic-operation-panic");
        let final_path = root.join("nested").join("shared.h");
        let panic = catch_unwind(AssertUnwindSafe(|| {
            atomic_publish(&final_path, |file| {
                file.write_all(b"partial")?;
                panic!("injected operation panic");
            })
        }));

        assert!(panic.is_err());
        assert!(
            !final_path.exists(),
            "partial final file must not be visible"
        );
        assert_no_hydrate_temps(final_path.parent().unwrap());
    }

    #[test]
    fn atomic_publish_rename_failure_removes_temp_without_replacing_final() {
        let root = temp("atomic-rename-failure");
        let final_path = root.join("shared.h");
        std::fs::create_dir(&final_path).unwrap();

        let result = atomic_publish(&final_path, |file| {
            use std::io::Write;
            file.write_all(b"complete")
        });

        assert!(result.is_err());
        assert!(
            final_path.is_dir(),
            "failed rename must not replace final path"
        );
        assert_no_hydrate_temps(&root);
    }

    fn assert_no_hydrate_temps(root: &Path) {
        let leftovers = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.to_string_lossy().contains(".sbz-tmp-"))
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "temporary files remained: {leftovers:?}"
        );
    }

    async fn accept_scripted_handshake(listener: TcpListener) -> TcpStream {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (header, _) = read_frame(&mut sock).await.unwrap();
        let response = HelloResponse {
            ok: true,
            detail: String::new(),
        }
        .encode();
        write_frame(
            &mut sock,
            FrameHeader {
                request_id: header.request_id,
                op: OpCode::Hello,
                is_response: true,
            },
            &response,
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        sock
    }

    async fn start_scripted_hydrate_server(
        expected_path: String,
        digest: Digest,
        size: u64,
        responses: Vec<(u64, u32, Vec<u8>)>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut sock = accept_scripted_handshake(listener).await;
            let (header, payload) = read_frame(&mut sock).await.unwrap();
            let request = OpenReadRequest::decode(&payload).unwrap();
            assert_eq!(header.op, OpCode::OpenRead);
            assert_eq!(request.path, expected_path);
            assert!(!request.want_inline);
            let response = OpenReadResponse {
                exists: true,
                size,
                digest_hex: digest.canonical(),
                first_chunk: Vec::new(),
            }
            .encode();
            write_frame(
                &mut sock,
                FrameHeader {
                    request_id: header.request_id,
                    op: OpCode::OpenRead,
                    is_response: true,
                },
                &response,
            )
            .await
            .unwrap();
            sock.flush().await.unwrap();

            for (expected_offset, expected_len, bytes) in responses {
                let (header, payload) = read_frame(&mut sock).await.unwrap();
                let request = ReadRequest::decode(&payload).unwrap();
                assert_eq!(header.op, OpCode::Read);
                assert_eq!(request.offset, expected_offset);
                assert_eq!(request.len, expected_len);
                let response = ReadResponse { bytes }.encode();
                write_frame(
                    &mut sock,
                    FrameHeader {
                        request_id: header.request_id,
                        op: OpCode::Read,
                        is_response: true,
                    },
                    &response,
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
            }
        });
        (addr, server)
    }

    #[tokio::test]
    async fn hydrate_does_not_publish_scratch_after_midstream_truncate() {
        const READ_CHUNK: u32 = 256 * 1024;
        let path = r"c:\src\truncated.h";
        let body = vec![0x41; READ_CHUNK as usize + 17];
        let digest = Digest::of(&body);
        let (agent_addr, server) = start_scripted_hydrate_server(
            path.to_string(),
            digest,
            body.len() as u64,
            vec![
                (0, READ_CHUNK, body[..READ_CHUNK as usize].to_vec()),
                (READ_CHUNK as u64, 17, Vec::new()),
            ],
        )
        .await;
        let scratch_root = temp("midstream-truncate-scratch");
        let final_path = scratch_mirror(&scratch_root, path);
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let state = VfsState {
            scratch_root,
            hydrated: Mutex::new(HashMap::new()),
            hydrating: Mutex::new(HashMap::new()),
            cas: BlobStore::open(temp("midstream-truncate-cas")).unwrap(),
            agent_addr,
            rtt: Duration::ZERO,
            auth_token: String::new(),
            session_root: String::new(),
            session_id: String::new(),
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
        };

        let (status, local) = hydrate_uncached(path, &state).await;

        assert_eq!(status, STATUS_ERROR);
        assert!(local.is_empty());
        assert!(!final_path.exists());
        assert_no_hydrate_temps(final_path.parent().unwrap());
        server.await.unwrap();
    }

    async fn test_pipe_hydrate(full_pipe: &str, logical: &str) -> (u8, String) {
        use tokio::net::windows::named_pipe::ClientOptions;

        let mut client = ClientOptions::new().open(full_pipe).unwrap();
        let payload = logical.as_bytes();
        client
            .write_all(&(payload.len() as u32).to_le_bytes())
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();
        let mut len = [0u8; 4];
        client.read_exact(&mut len).await.unwrap();
        let mut response = vec![0u8; u32::from_le_bytes(len) as usize];
        client.read_exact(&mut response).await.unwrap();
        (
            response[0],
            String::from_utf8(response[1..].to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn action_vfs_warms_received_hint_before_foreground_open() {
        let source = temp("owned-warm-source");
        let logical_path = source.join("received-hint.h");
        let body = vec![0x3c; 700_000];
        std::fs::write(&logical_path, &body).unwrap();
        let logical = logical_path.to_string_lossy().into_owned();

        let stats = Arc::new(ServerStats::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served_stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let _ =
                sembazuru_agent::fileserver::serve_files_with_stats(listener, served_stats).await;
        });

        let pipe_name = format!(
            "sbz-owned-warm-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let full_pipe = format!(r"\\.\pipe\{pipe_name}");
        let server = start_action_vfs(
            pipe_name,
            addr,
            temp("owned-warm-scratch"),
            temp("owned-warm-cas"),
            Duration::ZERO,
            vec![logical.clone()],
            String::new(),
            String::new(),
            String::new(),
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.content_bytes() != body.len() as u64 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let after_warm = stats.content_bytes();

        let (status, local) = test_pipe_hydrate(&full_pipe, &logical).await;
        assert_eq!(status, STATUS_OK);
        assert_eq!(std::fs::read(local).unwrap(), body);
        assert_eq!(stats.content_bytes(), after_warm);
        server.shutdown().await;
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
            hydrating: Mutex::new(HashMap::new()),
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
            let (status, local) = hydrate(path, &state, || hydrate_uncached(path, &state)).await;
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
    async fn action_vfs_server_shutdown_drains_real_blocking_io_before_cleanup() {
        let scratch = temp("blocking-drain");
        std::fs::remove_dir_all(&scratch).unwrap();
        let local = scratch.join("nested").join("header.h");
        let local_for_job = local.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let (outer_dropped_tx, outer_dropped_rx) = tokio::sync::oneshot::channel();
        let server = start_action_vfs_owner(move |tracker, ready| async move {
            let _drop_signal = DropSignal(Some(outer_dropped_tx));
            let materialize = tracker.spawn_blocking(move || {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                std::fs::create_dir_all(local_for_job.parent().unwrap())?;
                std::fs::write(local_for_job, b"tracked materialization")
            });
            let _ = ready.send(());
            materialize
                .await
                .expect("blocking materialization should join")?;
            Ok(())
        })
        .await
        .expect("owner factory should report ready");

        started_rx
            .await
            .expect("blocking materialization should start");
        let shutdown = tokio::spawn(async move {
            server.shutdown().await;
        });

        outer_dropped_rx
            .await
            .expect("shutdown must synchronously drop the outer serve future");
        tokio::task::yield_now().await;
        assert!(
            !shutdown.is_finished(),
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

    #[tokio::test]
    async fn dropping_action_vfs_server_aborts_outer_task() {
        let (outer_dropped_tx, outer_dropped_rx) = tokio::sync::oneshot::channel();
        let server = start_action_vfs_owner(move |_tracker, ready| async move {
            let _drop_signal = DropSignal(Some(outer_dropped_tx));
            let _ = ready.send(());
            std::future::pending::<io::Result<()>>().await
        })
        .await
        .expect("owner factory should report ready");

        drop(server);

        tokio::time::timeout(Duration::from_secs(5), outer_dropped_rx)
            .await
            .expect("dropping the owner must abort its outer task")
            .expect("outer task should publish its drop signal");
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
