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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use sembazuru_cas::{BlobStore, CasError};
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

#[derive(Clone, Copy)]
enum BlockingWorkKind {
    CasVerifiedRead,
    CasPersistAndScratchPublish,
    #[cfg(test)]
    TestBlocker,
}

#[derive(Clone, Default)]
struct MaterializationTracker {
    inner: Arc<MaterializationTrackerInner>,
}

#[derive(Default)]
struct MaterializationTrackerInner {
    active: AtomicUsize,
    idle: Notify,
    #[cfg(test)]
    cas_verified_reads: AtomicUsize,
    #[cfg(test)]
    cas_persist_and_scratch_publishes: AtomicUsize,
    #[cfg(test)]
    test_blockers: AtomicUsize,
}

struct MaterializationGuard {
    inner: Arc<MaterializationTrackerInner>,
    #[cfg(test)]
    kind: BlockingWorkKind,
}

impl Drop for MaterializationGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        self.inner
            .kind_counter(self.kind)
            .fetch_sub(1, AtomicOrdering::AcqRel);
        if self.inner.active.fetch_sub(1, AtomicOrdering::AcqRel) == 1 {
            self.inner.idle.notify_one();
        }
    }
}

#[cfg(test)]
impl MaterializationTrackerInner {
    fn kind_counter(&self, kind: BlockingWorkKind) -> &AtomicUsize {
        match kind {
            BlockingWorkKind::CasVerifiedRead => &self.cas_verified_reads,
            BlockingWorkKind::CasPersistAndScratchPublish => {
                &self.cas_persist_and_scratch_publishes
            }
            BlockingWorkKind::TestBlocker => &self.test_blockers,
        }
    }
}

impl MaterializationTracker {
    fn spawn_blocking<F, T>(
        &self,
        kind: BlockingWorkKind,
        operation: F,
    ) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.inner.active.fetch_add(1, AtomicOrdering::AcqRel);
        #[cfg(test)]
        self.inner
            .kind_counter(kind)
            .fetch_add(1, AtomicOrdering::AcqRel);
        #[cfg(not(test))]
        let _ = kind;
        let guard = MaterializationGuard {
            inner: Arc::clone(&self.inner),
            #[cfg(test)]
            kind,
        };
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

    #[cfg(test)]
    fn in_flight(&self, kind: BlockingWorkKind) -> usize {
        self.inner.kind_counter(kind).load(AtomicOrdering::Acquire)
    }
}

async fn run_tracked_blocking<F, T>(
    tracker: &MaterializationTracker,
    kind: BlockingWorkKind,
    operation: F,
) -> Result<T, tokio::task::JoinError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tracker.spawn_blocking(kind, operation).await
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
    /// Normalized logical path -> current in-flight hydration generation.
    hydrating: StdMutex<HashMap<String, Weak<HydrationFlight>>>,
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

struct HydrationFlight {
    result: OnceCell<(u8, String)>,
}

struct HydrationLease<'a> {
    key: String,
    flight: Arc<HydrationFlight>,
    registry: &'a StdMutex<HashMap<String, Weak<HydrationFlight>>>,
}

fn lock_hydration_registry(
    registry: &StdMutex<HashMap<String, Weak<HydrationFlight>>>,
) -> std::sync::MutexGuard<'_, HashMap<String, Weak<HydrationFlight>>> {
    registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl<'a> HydrationLease<'a> {
    fn join(registry: &'a StdMutex<HashMap<String, Weak<HydrationFlight>>>, key: String) -> Self {
        let flight = {
            let mut flights = lock_hydration_registry(registry);
            if let Some(flight) = flights.get(&key).and_then(Weak::upgrade).filter(
                |flight| !matches!(flight.result.get(), Some((status, _)) if *status != STATUS_OK),
            ) {
                flight
            } else {
                let flight = Arc::new(HydrationFlight {
                    result: OnceCell::new(),
                });
                flights.insert(key.clone(), Arc::downgrade(&flight));
                flight
            }
        };
        Self {
            key,
            flight,
            registry,
        }
    }

    async fn get_or_init<F, Fut>(&self, operation: F) -> (u8, String)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = (u8, String)>,
    {
        self.flight.result.get_or_init(operation).await.clone()
    }
}

impl Drop for HydrationLease<'_> {
    fn drop(&mut self) {
        let mut flights = lock_hydration_registry(self.registry);
        let is_current = flights
            .get(&self.key)
            .is_some_and(|registered| Weak::ptr_eq(registered, &Arc::downgrade(&self.flight)));
        if is_current && Arc::strong_count(&self.flight) == 1 {
            flights.remove(&self.key);
        }
    }
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
        hydrating: StdMutex::new(HashMap::new()),
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
    let lease = HydrationLease::join(&state.hydrating, key.clone());
    lease
        .get_or_init(|| async {
            if let Some(local) = state.hydrated.lock().await.get(&key).cloned() {
                return (STATUS_OK, local);
            }

            let result = operation().await;
            if result.0 == STATUS_OK {
                state.hydrated.lock().await.insert(key, result.1.clone());
            }
            result
        })
        .await
}

async fn hydrate_uncached(path: &str, state: &VfsState) -> (u8, String) {
    enum CacheRead {
        Hit(Vec<u8>),
        Missing,
        Corrupt,
    }

    enum CacheWrite {
        None,
        Put,
        Repair,
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

    // Local cache hit → no content crosses the network. Both whole-blob read and
    // digest verification are blocking work, so keep them off Tokio's workers.
    let cas_for_read = state.cas.clone();
    let digest_for_read = digest.clone();
    let cached = run_tracked_blocking(
        &state.materializations,
        BlockingWorkKind::CasVerifiedRead,
        move || cas_for_read.get_verified(&digest_for_read),
    )
    .await;
    let cache_read = match cached {
        Ok(Ok(Some(bytes))) => CacheRead::Hit(bytes),
        Ok(Ok(None)) => CacheRead::Missing,
        Ok(Err(CasError::Corrupt { .. })) => CacheRead::Corrupt,
        Ok(Err(_)) | Err(_) => return (STATUS_ERROR, String::new()),
    };
    let repair = matches!(&cache_read, CacheRead::Corrupt);
    let (bytes, cache_write) = match cache_read {
        CacheRead::Hit(bytes) => (bytes, CacheWrite::None),
        CacheRead::Missing | CacheRead::Corrupt => {
            // Miss (or corrupt): fetch from the agent, then persist or repair the
            // local CAS before publishing scratch.
            let fetched = match client.fetch_by_digest(&digest, size).await {
                Ok(bytes) => bytes,
                Err(_) => return (STATUS_ERROR, String::new()),
            };
            (
                fetched,
                if repair {
                    CacheWrite::Repair
                } else {
                    CacheWrite::Put
                },
            )
        }
    };

    let local = scratch_mirror(&state.scratch_root, path);
    let local_for_write = local.clone();
    let cas_for_write = state.cas.clone();
    let digest_for_write = digest.clone();
    let materialize = run_tracked_blocking(
        &state.materializations,
        BlockingWorkKind::CasPersistAndScratchPublish,
        move || {
            let persisted = match cache_write {
                CacheWrite::None => Ok(digest_for_write.clone()),
                CacheWrite::Put => cas_for_write.put_verified(&bytes, &digest_for_write),
                CacheWrite::Repair => cas_for_write.repair_verified(&bytes, &digest_for_write),
            };
            if let Err(error) = persisted {
                match error {
                    CasError::DigestMismatch { .. } | CasError::Digest(_) => {
                        return Err(io::Error::other(format!(
                            "CAS rejected fetched hydrate bytes: {error}"
                        )));
                    }
                    // Persistence is an optimization. Sharing conflicts, transient
                    // I/O, or a still-corrupt cache must not turn verified agent
                    // bytes into a failed hydrate; publish scratch and let a later
                    // action fetch again.
                    CasError::Io(_) | CasError::Corrupt { .. } => {}
                }
            }
            atomic_publish(&local_for_write, |file| file.write_all(&bytes))
        },
    );
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
    use std::time::Instant;

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
            hydrating: StdMutex::new(HashMap::new()),
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
    async fn same_key_failure_is_shared_then_a_later_caller_retries() {
        let state = Arc::new(test_state());
        let start = Arc::new(tokio::sync::Barrier::new(33));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let entries = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let mut tasks = Vec::new();
        for i in 0..32 {
            let state = Arc::clone(&state);
            let start = Arc::clone(&start);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let entries = Arc::clone(&entries);
            let release = Arc::clone(&release);
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
                hydrate(path, &state, || async move {
                    let attempt = entries_for_op.fetch_add(1, Ordering::SeqCst) + 1;
                    let now = active_for_op.fetch_add(1, Ordering::SeqCst) + 1;
                    peak_for_op.fetch_max(now, Ordering::SeqCst);
                    if attempt == 1 {
                        release.notified().await;
                    }
                    active_for_op.fetch_sub(1, Ordering::SeqCst);
                    (STATUS_ERROR, format!("attempt-{attempt}"))
                })
                .await
            }));
        }
        start.wait().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let joined = {
                    let flights = lock_hydration_registry(&state.hydrating);
                    flights
                        .get(&hydration_key(r"c:\src\shared.h"))
                        .is_some_and(|flight| Weak::strong_count(flight) == 32)
                };
                if joined {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all same-key callers must join one failure generation");
        release.notify_one();
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert_eq!(entries.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|result| result == &results[0]));
        assert_eq!(results[0], (STATUS_ERROR, "attempt-1".to_string()));
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);

        let entries_for_retry = Arc::clone(&entries);
        let retry = hydrate("c:\\src\\shared.h", &state, || async move {
            let attempt = entries_for_retry.fetch_add(1, Ordering::SeqCst) + 1;
            (STATUS_ERROR, format!("attempt-{attempt}"))
        })
        .await;
        assert_eq!(retry, (STATUS_ERROR, "attempt-2".to_string()));
        assert_eq!(entries.load(Ordering::SeqCst), 2);
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);
    }

    #[tokio::test]
    async fn late_caller_starts_a_new_generation_while_failed_flight_is_still_alive() {
        let state = Arc::new(test_state());
        let key = hydration_key(r"c:\src\late-failure.h");
        let old_lease = HydrationLease::join(&state.hydrating, key.clone());
        let operations = Arc::new(AtomicUsize::new(0));

        let first_operations = Arc::clone(&operations);
        let first = hydrate(r"c:\src\late-failure.h", &state, || async move {
            first_operations.fetch_add(1, Ordering::SeqCst);
            (STATUS_ERROR, "first-generation".to_string())
        })
        .await;
        assert_eq!(first, (STATUS_ERROR, "first-generation".to_string()));
        assert_eq!(operations.load(Ordering::SeqCst), 1);

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let late_state = Arc::clone(&state);
        let late_operations = Arc::clone(&operations);
        let late = tokio::spawn(async move {
            hydrate(r"C:/SRC/LATE-FAILURE.H", &late_state, || async move {
                late_operations.fetch_add(1, Ordering::SeqCst);
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                (STATUS_ERROR, "second-generation".to_string())
            })
            .await
        });
        entered_rx
            .await
            .expect("a late caller must initialize a new failure generation");
        assert_eq!(operations.load(Ordering::SeqCst), 2);

        drop(old_lease);
        assert_eq!(
            lock_hydration_registry(&state.hydrating).len(),
            1,
            "dropping the old generation must not remove the new entry"
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            late.await.unwrap(),
            (STATUS_ERROR, "second-generation".to_string())
        );
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);
    }

    #[tokio::test]
    async fn same_key_success_runs_once_and_later_callers_use_the_cache() {
        let state = Arc::new(test_state());
        let start = Arc::new(tokio::sync::Barrier::new(17));
        let entries = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let state = Arc::clone(&state);
            let start = Arc::clone(&start);
            let entries = Arc::clone(&entries);
            let release = Arc::clone(&release);
            tasks.push(tokio::spawn(async move {
                start.wait().await;
                hydrate(r"c:\src\success.h", &state, || async move {
                    let attempt = entries.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempt == 1 {
                        release.notified().await;
                    }
                    (STATUS_OK, r"c:\scratch\success.h".to_string())
                })
                .await
            }));
        }
        start.wait().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let joined = {
                    let flights = lock_hydration_registry(&state.hydrating);
                    flights
                        .get(&hydration_key(r"c:\src\success.h"))
                        .is_some_and(|flight| Weak::strong_count(flight) == 16)
                };
                if joined {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all same-key callers must join one success generation");
        release.notify_one();
        for task in tasks {
            assert_eq!(
                task.await.unwrap(),
                (STATUS_OK, r"c:\scratch\success.h".to_string())
            );
        }
        assert_eq!(entries.load(Ordering::SeqCst), 1);
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);

        let cached = hydrate(r"C:/SRC/SUCCESS.H", &state, || async {
            panic!("the hydrated cache must bypass a new operation")
        })
        .await;
        assert_eq!(cached, (STATUS_OK, r"c:\scratch\success.h".to_string()));
    }

    #[tokio::test]
    async fn cancelled_initializer_hands_the_flight_to_a_waiter() {
        let state = Arc::new(test_state());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let first_state = Arc::clone(&state);
        let first = tokio::spawn(async move {
            hydrate(r"c:\src\cancel.h", &first_state, || async move {
                let _ = entered_tx.send(());
                std::future::pending::<(u8, String)>().await
            })
            .await
        });
        entered_rx.await.unwrap();

        let second_state = Arc::clone(&state);
        let second = tokio::spawn(async move {
            hydrate(r"C:/SRC/CANCEL.H", &second_state, || async {
                (STATUS_ERROR, "handoff-after-cancel".to_string())
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let joined = {
                    let flights = lock_hydration_registry(&state.hydrating);
                    Weak::strong_count(
                        flights
                            .get(&hydration_key(r"c:\src\cancel.h"))
                            .expect("the active flight must be registered"),
                    ) >= 2
                };
                if joined {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the cancellation waiter must join the active flight");

        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let result = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("a cancelled initializer must not strand its waiter")
            .unwrap();
        assert_eq!(result, (STATUS_ERROR, "handoff-after-cancel".to_string()));
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);
    }

    #[tokio::test]
    async fn uniquely_owned_cancelled_flight_is_removed() {
        let state = Arc::new(test_state());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let first_state = Arc::clone(&state);
        let first = tokio::spawn(async move {
            hydrate(r"c:\src\unique-cancel.h", &first_state, || async move {
                let _ = entered_tx.send(());
                std::future::pending::<(u8, String)>().await
            })
            .await
        });
        entered_rx.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);
    }

    #[tokio::test]
    async fn panicking_initializer_hands_the_flight_to_a_waiter() {
        let state = Arc::new(test_state());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (panic_tx, panic_rx) = tokio::sync::oneshot::channel();
        let first_state = Arc::clone(&state);
        let first = tokio::spawn(async move {
            hydrate(r"c:\src\panic.h", &first_state, || async move {
                let _ = entered_tx.send(());
                let _ = panic_rx.await;
                panic!("injected hydrate initializer panic")
            })
            .await
        });
        entered_rx.await.unwrap();

        let second_state = Arc::clone(&state);
        let second = tokio::spawn(async move {
            hydrate(r"C:/SRC/PANIC.H", &second_state, || async {
                (STATUS_ERROR, "handoff-after-panic".to_string())
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let joined = {
                    let flights = lock_hydration_registry(&state.hydrating);
                    Weak::strong_count(
                        flights
                            .get(&hydration_key(r"c:\src\panic.h"))
                            .expect("the active flight must be registered"),
                    ) >= 2
                };
                if joined {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the panic waiter must join the active flight");

        panic_tx.send(()).unwrap();
        assert!(first.await.unwrap_err().is_panic());
        let result = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("a panicking initializer must not strand its waiter")
            .unwrap();
        assert_eq!(result, (STATUS_ERROR, "handoff-after-panic".to_string()));
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);
    }

    #[test]
    fn production_cas_read_queues_off_runtime_and_does_not_block_an_unrelated_hydrate() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let source = temp("production-blocking-source");
            let logical_path = source.join("cas-hit.h");
            let body = vec![0x71; 300_000];
            std::fs::write(&logical_path, &body).unwrap();
            let logical = logical_path.to_string_lossy().into_owned();

            let cas = BlobStore::open(temp("production-blocking-cas")).unwrap();
            let digest = cas.put(&body).unwrap();
            let (agent_addr, server) = start_scripted_hydrate_server(
                logical.clone(),
                digest,
                body.len() as u64,
                Vec::new(),
            )
            .await;
            let state = Arc::new(VfsState {
                scratch_root: temp("production-blocking-scratch"),
                hydrated: Mutex::new(HashMap::new()),
                hydrating: StdMutex::new(HashMap::new()),
                cas,
                agent_addr,
                rtt: Duration::ZERO,
                auth_token: String::new(),
                session_root: String::new(),
                session_id: String::new(),
                client: OnceCell::new(),
                materializations: MaterializationTracker::default(),
            });

            let (occupied_tx, occupied_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
            let occupied =
                state
                    .materializations
                    .spawn_blocking(BlockingWorkKind::TestBlocker, move || {
                        let _ = occupied_tx.send(());
                        release_rx.recv().unwrap();
                    });
            occupied_rx.await.unwrap();

            let actual_state = Arc::clone(&state);
            let actual_logical = logical.clone();
            let actual =
                tokio::spawn(async move { hydrate_uncached(&actual_logical, &actual_state).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if state
                        .materializations
                        .in_flight(BlockingWorkKind::CasVerifiedRead)
                        == 1
                        && state.materializations.inner.active.load(Ordering::Acquire) == 2
                        && state
                            .materializations
                            .in_flight(BlockingWorkKind::CasPersistAndScratchPublish)
                            == 0
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("production CAS get_verified must queue on the blocking pool");

            let unrelated = hydrate(r"c:\src\unrelated.h", &state, || async {
                (STATUS_OK, r"c:\scratch\unrelated.h".to_string())
            });
            let result = tokio::time::timeout(Duration::from_millis(100), unrelated)
                .await
                .expect("queued CAS work on path A must not stop path B");
            assert_eq!(result, (STATUS_OK, r"c:\scratch\unrelated.h".to_string()));

            release_tx.send(()).unwrap();
            occupied.await.unwrap();
            let (status, local) = actual.await.unwrap();
            assert_eq!(status, STATUS_OK);
            assert_eq!(std::fs::read(local).unwrap(), body);
            state.materializations.wait_idle().await;
            assert_eq!(
                state
                    .materializations
                    .in_flight(BlockingWorkKind::CasVerifiedRead),
                0
            );
            assert_eq!(
                state
                    .materializations
                    .in_flight(BlockingWorkKind::CasPersistAndScratchPublish),
                0
            );
            server.await.unwrap();
        });
    }

    #[tokio::test]
    async fn blocking_work_kind_bookkeeping_tracks_submit_through_drop() {
        let tracker = MaterializationTracker::default();
        let (release_read_tx, release_read_rx) = std::sync::mpsc::sync_channel(0);
        let (release_publish_tx, release_publish_rx) = std::sync::mpsc::sync_channel(0);
        let read = tracker.spawn_blocking(BlockingWorkKind::CasVerifiedRead, move || {
            release_read_rx.recv().unwrap();
        });
        let publish =
            tracker.spawn_blocking(BlockingWorkKind::CasPersistAndScratchPublish, move || {
                release_publish_rx.recv().unwrap();
            });

        assert_eq!(tracker.in_flight(BlockingWorkKind::CasVerifiedRead), 1);
        assert_eq!(
            tracker.in_flight(BlockingWorkKind::CasPersistAndScratchPublish),
            1
        );
        assert_eq!(tracker.in_flight(BlockingWorkKind::TestBlocker), 0);

        release_read_tx.send(()).unwrap();
        release_publish_tx.send(()).unwrap();
        read.await.unwrap();
        publish.await.unwrap();
        assert_eq!(tracker.in_flight(BlockingWorkKind::CasVerifiedRead), 0);
        assert_eq!(
            tracker.in_flight(BlockingWorkKind::CasPersistAndScratchPublish),
            0
        );
    }

    #[tokio::test]
    async fn poisoned_flight_registry_recovers_and_cleans_up() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let state = test_state();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = state.hydrating.lock().unwrap();
            panic!("inject registry poison")
        }));
        assert!(poisoned.is_err());

        let result = hydrate(r"c:\src\after-poison.h", &state, || async {
            (STATUS_ERROR, "recovered".to_string())
        })
        .await;
        assert_eq!(result, (STATUS_ERROR, "recovered".to_string()));
        assert_eq!(lock_hydration_registry(&state.hydrating).len(), 0);
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
            hydrating: StdMutex::new(HashMap::new()),
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

    #[tokio::test]
    async fn corrupt_cas_is_repaired_across_aliases_and_reused_by_the_next_action() {
        let source = temp("repair-source");
        let body = vec![0x5a; 700_000];
        let mut aliases = Vec::new();
        for index in 0..4 {
            let path = source.join(format!("alias-{index}.h"));
            std::fs::write(&path, &body).unwrap();
            aliases.push(path.to_string_lossy().into_owned());
        }

        let stats = Arc::new(ServerStats::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let agent_addr = listener.local_addr().unwrap();
        let served_stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let _ =
                sembazuru_agent::fileserver::serve_files_with_stats(listener, served_stats).await;
        });

        let cas_root = temp("repair-cas");
        let cas = BlobStore::open(&cas_root).unwrap();
        let digest = cas.put(&body).unwrap();
        let corrupt_path = cas_root
            .join("cas")
            .join("blake3")
            .join(&digest.hex()[..2])
            .join(digest.hex());
        std::fs::write(&corrupt_path, b"corrupt worker cache").unwrap();

        let state = Arc::new(VfsState {
            scratch_root: temp("repair-action-one-scratch"),
            hydrated: Mutex::new(HashMap::new()),
            hydrating: StdMutex::new(HashMap::new()),
            cas: BlobStore::open(&cas_root).unwrap(),
            agent_addr,
            rtt: Duration::ZERO,
            auth_token: String::new(),
            session_root: String::new(),
            session_id: String::new(),
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
        });
        let first = hydrate_uncached(&aliases[0], &state);
        let second = hydrate_uncached(&aliases[1], &state);
        let third = hydrate_uncached(&aliases[2], &state);
        let results = tokio::join!(first, second, third);
        for (status, local) in [results.0, results.1, results.2] {
            assert_eq!(status, STATUS_OK);
            assert_eq!(std::fs::read(local).unwrap(), body);
        }
        assert_eq!(
            cas.get_verified(&digest).unwrap().as_deref(),
            Some(body.as_slice())
        );
        assert!(
            std::fs::read_dir(corrupt_path.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".tmp.")))
        );

        let before_next_action = stats.content_bytes();
        let next_state = VfsState {
            scratch_root: temp("repair-action-two-scratch"),
            hydrated: Mutex::new(HashMap::new()),
            hydrating: StdMutex::new(HashMap::new()),
            cas: BlobStore::open(&cas_root).unwrap(),
            agent_addr,
            rtt: Duration::ZERO,
            auth_token: String::new(),
            session_root: String::new(),
            session_id: String::new(),
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
        };
        let (status, local) = hydrate_uncached(&aliases[3], &next_state).await;
        assert_eq!(status, STATUS_OK);
        assert_eq!(std::fs::read(local).unwrap(), body);
        assert_eq!(stats.content_bytes(), before_next_action);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn sharing_conflict_in_cas_repair_does_not_fail_current_hydrate() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let source = temp("repair-sharing-source");
        let logical_path = source.join("sharing-conflict.h");
        let body = vec![0x3d; 300_000];
        std::fs::write(&logical_path, &body).unwrap();
        let logical = logical_path.to_string_lossy().into_owned();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let agent_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = sembazuru_agent::fileserver::serve_files(listener).await;
        });

        let cas_root = temp("repair-sharing-cas");
        let cas = BlobStore::open(&cas_root).unwrap();
        let digest = cas.put(&body).unwrap();
        let corrupt_path = cas_root
            .join("cas")
            .join("blake3")
            .join(&digest.hex()[..2])
            .join(digest.hex());
        std::fs::write(&corrupt_path, b"corrupt but reader-held").unwrap();
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&corrupt_path)
            .unwrap();

        let state = VfsState {
            scratch_root: temp("repair-sharing-scratch"),
            hydrated: Mutex::new(HashMap::new()),
            hydrating: StdMutex::new(HashMap::new()),
            cas,
            agent_addr,
            rtt: Duration::ZERO,
            auth_token: String::new(),
            session_root: String::new(),
            session_id: String::new(),
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
        };
        let (status, local) = hydrate_uncached(&logical, &state).await;
        assert_eq!(status, STATUS_OK);
        assert_eq!(std::fs::read(local).unwrap(), body);
        assert!(matches!(
            state.cas.get_verified(&digest).unwrap_err(),
            CasError::Corrupt { .. }
        ));
        assert!(
            std::fs::read_dir(corrupt_path.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".tmp.")))
        );
        drop(reader);
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
            hydrating: StdMutex::new(HashMap::new()),
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
            let materialize = tracker.spawn_blocking(BlockingWorkKind::TestBlocker, move || {
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

    const BENCH_PATH_COUNT: usize = 512;
    const BENCH_PATH_BYTES: u64 = 64 * 1024;
    const BENCH_SAMPLES: usize = 40;
    const BENCH_RTT: Duration = Duration::from_millis(2);

    async fn benchmark_hydrate(
        path: String,
        state: Arc<VfsState>,
        stats: Arc<ServerStats>,
        task_counters: Option<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
    ) {
        let returned_path = path.clone();
        let result = hydrate(&path, &state, || async move {
            let _activity = task_counters.map(|(active, peak)| {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                HydrateActivityGuard(active)
            });
            tokio::time::sleep(BENCH_RTT).await;
            stats.read_ops.fetch_add(1, Ordering::Relaxed);
            stats
                .read_bytes
                .fetch_add(BENCH_PATH_BYTES, Ordering::Relaxed);
            (STATUS_OK, returned_path)
        })
        .await;
        assert_eq!(result.0, STATUS_OK);
    }

    async fn prefetch_benchmark_sample(limit: usize) -> (Duration, Duration, usize, u64) {
        let scratch_root = temp("benchmark-scratch");
        let cas_root = temp("benchmark-cas");
        let state = Arc::new(VfsState {
            scratch_root: scratch_root.clone(),
            hydrated: Mutex::new(HashMap::new()),
            hydrating: StdMutex::new(HashMap::new()),
            cas: BlobStore::open(&cas_root).unwrap(),
            agent_addr: "127.0.0.1:0".parse().unwrap(),
            rtt: BENCH_RTT,
            auth_token: String::new(),
            session_root: String::new(),
            session_id: String::new(),
            client: OnceCell::new(),
            materializations: MaterializationTracker::default(),
        });
        let stats = Arc::new(ServerStats::default());
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let paths = (0..BENCH_PATH_COUNT)
            .map(|index| format!(r"c:\bench\header-{index}.h"))
            .collect::<Vec<_>>();
        let foreground_path = paths.last().unwrap().clone();

        let prefetch = {
            let state = Arc::clone(&state);
            let stats = Arc::clone(&stats);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            async move {
                let started = Instant::now();
                for_each_prefetch_bounded(paths, limit, move |path| {
                    let state = Arc::clone(&state);
                    let stats = Arc::clone(&stats);
                    let active = Arc::clone(&active);
                    let peak = Arc::clone(&peak);
                    async move {
                        benchmark_hydrate(path, state, stats, Some((active, peak))).await;
                    }
                })
                .await;
                started.elapsed()
            }
        };
        let foreground = {
            let state = Arc::clone(&state);
            let stats = Arc::clone(&stats);
            let active = Arc::clone(&active);
            async move {
                while active.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
                let started = Instant::now();
                benchmark_hydrate(foreground_path, state, stats, None).await;
                started.elapsed()
            }
        };

        let (prefetch_elapsed, foreground_elapsed) = tokio::join!(prefetch, foreground);
        // Benchmark-only metrics: `peak_tasks` is the maximum number of prefetch
        // callbacks executing concurrently. `transfer_bytes` is simulated content
        // added to ServerStats, not bytes measured from OS or network I/O.
        let peak_tasks = peak.load(Ordering::SeqCst);
        let transfer_bytes = stats.content_bytes();
        assert_eq!(transfer_bytes, BENCH_PATH_COUNT as u64 * BENCH_PATH_BYTES);
        assert!(peak_tasks <= limit);

        drop(state);
        std::fs::remove_dir_all(scratch_root).unwrap();
        std::fs::remove_dir_all(cas_root).unwrap();
        (
            prefetch_elapsed,
            foreground_elapsed,
            peak_tasks,
            transfer_bytes,
        )
    }

    fn benchmark_percentile_ms(samples: &mut [Duration], percentile: usize) -> f64 {
        samples.sort_unstable();
        let rank = (samples.len() * percentile).div_ceil(100).max(1);
        samples[rank - 1].as_secs_f64() * 1000.0
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "manual prefetch concurrency measurement"]
    async fn prefetch_concurrency_benchmark() {
        for concurrency in [8, 16, 32, 64] {
            let mut prefetch_samples = Vec::with_capacity(BENCH_SAMPLES);
            let mut foreground_samples = Vec::with_capacity(BENCH_SAMPLES);
            let mut peak_tasks = 0;
            let mut transfer_bytes = 0;
            for _ in 0..BENCH_SAMPLES {
                let (prefetch, foreground, peak, transferred) =
                    prefetch_benchmark_sample(concurrency).await;
                prefetch_samples.push(prefetch);
                foreground_samples.push(foreground);
                peak_tasks = peak_tasks.max(peak);
                transfer_bytes = transferred;
            }
            let prefetch_p50_ms = benchmark_percentile_ms(&mut prefetch_samples, 50);
            let prefetch_p95_ms = benchmark_percentile_ms(&mut prefetch_samples, 95);
            let foreground_p50_ms = benchmark_percentile_ms(&mut foreground_samples, 50);
            let foreground_p95_ms = benchmark_percentile_ms(&mut foreground_samples, 95);
            println!(
                "PREFETCH_BENCH {{\"concurrency\":{concurrency},\"prefetch_p50_ms\":{prefetch_p50_ms:.3},\"prefetch_p95_ms\":{prefetch_p95_ms:.3},\"foreground_p50_ms\":{foreground_p50_ms:.3},\"foreground_p95_ms\":{foreground_p95_ms:.3},\"peak_tasks\":{peak_tasks},\"transfer_bytes\":{transfer_bytes}}}"
            );
        }
    }
}
