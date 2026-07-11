//! Agent-authoritative per-action session registry (ADR 0013).
//!
//! The data-plane file server (`fileserver.rs`) used to keep a **single,
//! process-wide** `Session`: one content store, one pin map, one writeback table
//! shared by every connection for the daemon's whole life. That conflated four
//! concerns the review flagged:
//!   * **COR-001** — a path pinned by action A was served, frozen, to action B
//!     forever (a stale input across unrelated builds);
//!   * **SEC-004** — the supply scope was whatever *root* the worker declared on
//!     its Hello, so a token-holding worker could widen it to `c:\`;
//!   * **SEC-003** — WriteBack wrote any worker-named absolute path;
//!   * **PROTO-001** — the session id was a guessable `intake-{n}` counter.
//!
//! This registry makes the agent the authority. The scheduler/intake mints an
//! unpredictable `session_id` (see `intake::mint_session_id`) and `create`s a
//! [`SessionCapability`] holding the agent's *own* normalized input root, the
//! action's declared output specs, a **per-session** pin partition (with per-path
//! single-flight so two concurrent first-touches cannot pin different bytes), and
//! an allowed-digest ACL grown as the session pins inputs. The worker forwards the
//! id on its data-plane Hello; the file server looks the session up and enforces
//! the capability, dropping the whole partition when the action finishes.
//!
//! **One shared content store, per-session ACL overlay.** The registry owns a
//! single [`BlobStore`] for the daemon, so a blob a session pins is physically
//! available to others (cross-session dedup/prefetch keep working). Isolation is
//! the per-session `allowed_digests` *capability list*, not a byte copy: a session
//! can only `Read`/`Has` a digest it actually pinned (by opening that path), so a
//! guessed/sniffed digest from another session gets nothing. This store is the
//! *ephemeral file-supply* CAS — distinct from the persistent action cache
//! (`AgentCache`), whose M9.2 eviction never touches sessions.
//!
//! **Residual (LAN-trusted, ADR 0013):** the data-plane Hello authenticates with
//! the *shared* cluster token, so the agent cannot prove the peer presenting a
//! session id is the worker it was dispatched to. A token-holding worker that
//! *captures* another session's (128-bit, unguessable) id can bind it and reach
//! that session's scope — but only its authoritative root + output specs,
//! never `c:\`/arbitrary writes. Closing the theft needs proof that the peer
//! presenting the id is the worker the action was dispatched to, which the data
//! plane cannot do under a flat shared token; the fix is a per-session capability
//! token (reserved proto field 11), a small additive follow-up, not mTLS. (Until
//! that lands there is no per-worker identity to record, so no theft-detection
//! signal is wired here — it would have nothing to compare the peer against.)

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use crate::rootdir::{FileSnapshot, RootDir, file_snapshot};
use cap_std::fs::OpenOptions;
use sembazuru_cas::{BlobStore, Digest, DigestHasher};
use tokio::sync::{Mutex, OnceCell};

/// Default per-output WriteBack cap (8 GiB).
pub const DEFAULT_OUTPUT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Agent-authoritative publish target + size cap for one declared output; worker
/// references it by id only and never names a path.
#[derive(Debug, Clone)]
pub struct OutputSpec {
    pub id: u32,
    pub final_path: std::path::PathBuf,
    pub max_size: u64,
}

/// Disambiguates the registry's temp content-store directory within a process.
static STORE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct PinPersistOwner {
    inner: Arc<PinPersistOwnerInner>,
}

struct PinPersistOwnerInner {
    state: StdMutex<PinPersistState>,
    store_root: PathBuf,
    #[cfg(test)]
    before_publish_hook: StdMutex<Option<PinPublishHook>>,
}

#[cfg(test)]
struct PinPublishHook {
    reached: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

struct PinPersistState {
    accepting: bool,
    active: usize,
    cleanup_started: bool,
}

struct PinPersistGuard {
    owner: PinPersistOwner,
}

impl PinPersistOwner {
    fn new(store_root: PathBuf) -> Self {
        Self {
            inner: Arc::new(PinPersistOwnerInner {
                state: StdMutex::new(PinPersistState {
                    accepting: true,
                    active: 0,
                    cleanup_started: false,
                }),
                store_root,
                #[cfg(test)]
                before_publish_hook: StdMutex::new(None),
            }),
        }
    }

    fn register(&self) -> Result<PinPersistGuard, ()> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return Err(());
        }
        state.active = state.active.checked_add(1).ok_or(())?;
        Ok(PinPersistGuard {
            owner: self.clone(),
        })
    }

    fn close(&self) {
        let cleanup = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.accepting = false;
            if state.active == 0 && !state.cleanup_started {
                state.cleanup_started = true;
                true
            } else {
                false
            }
        };
        if cleanup {
            self.cleanup();
        }
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.inner.store_root);
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
    }

    #[cfg(test)]
    fn store_root(&self) -> &Path {
        &self.inner.store_root
    }

    #[cfg(test)]
    fn install_before_publish_hook(
        &self,
        reached: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        *self
            .inner
            .before_publish_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(PinPublishHook { reached, release });
    }

    #[cfg(test)]
    async fn wait_before_publish(&self) {
        let hook = self
            .inner
            .before_publish_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            let _ = hook.reached.send(());
            let _ = hook.release.await;
        }
    }
}

impl Drop for PinPersistGuard {
    fn drop(&mut self) {
        let cleanup = {
            let mut state = self
                .owner
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.active == 0 {
                return;
            }
            state.active -= 1;
            if !state.accepting && state.active == 0 && !state.cleanup_started {
                state.cleanup_started = true;
                true
            } else {
                false
            }
        };
        if cleanup {
            self.owner.cleanup();
        }
    }
}

/// The single-flight result for one pinned path. The publish guard crosses the
/// blocking CAS write and remains armed until the result is both ACL-authorized
/// and installed in the [`OnceCell`]. It is then taken exactly once by whichever
/// caller first observes the published value.
struct PinnedValue {
    digest: Digest,
    size: u64,
    publish_guard: StdMutex<Option<PinPersistGuard>>,
}

impl PinnedValue {
    fn new(digest: Digest, size: u64, publish_guard: PinPersistGuard) -> Self {
        Self {
            digest,
            size,
            publish_guard: StdMutex::new(Some(publish_guard)),
        }
    }

    fn release_publish_guard(&self) {
        let guard = self
            .publish_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(guard);
    }
}

/// `Arc` so concurrent racers of the same path share one publication cell.
type PinCell = Arc<OnceCell<PinnedValue>>;

async fn persist_pin_bytes(
    owner: PinPersistOwner,
    store: BlobStore,
    bytes: Vec<u8>,
) -> Result<(Digest, PinPersistGuard), ()> {
    let guard = owner.register()?;
    let (result, guard) = tokio::task::spawn_blocking(move || (store.put(&bytes), guard))
        .await
        .map_err(|_| ())?;
    Ok((result.map_err(|_| ())?, guard))
}

/// A newly-created staging sibling and the parent directory capability that
/// contains it.
pub struct StagingTemp {
    pub path: PathBuf,
    pub rel: String,
    pub parent_dir: RootDir,
    pub file: cap_std::fs::File,
    pub(crate) snapshot: FileSnapshot,
}

/// In-progress streamed WriteBack for one output id: the temp file being
/// appended to, how many bytes have landed (the next expected offset), and the
/// running digest so the whole output is verified without buffering it. Lives
/// per session now (was a field of the process-wide `Session`).
pub struct WritebackState {
    pub tmp: PathBuf,
    pub tmp_rel: String,
    pub parent_dir: RootDir,
    pub file: Arc<StdMutex<cap_std::fs::File>>,
    pub(crate) snapshot: FileSnapshot,
    pub written: u64,
    pub hasher: DigestHasher,
}

/// A worker-produced output that has been fully streamed and digest-verified,
/// but is not yet published to its final path. Intake publishes these only after
/// the remote action exits successfully.
struct StagedOutput {
    pub staging_path: PathBuf,
    pub final_path: PathBuf,
    pub digest_hex: String,
    snapshot: FileSnapshot,
    /// The directory handle opened once at staging time (`create_staging_temp`)
    /// for `final_path`'s immediate parent. Reused unchanged at commit time so a
    /// delete+recreate of that directory between staging and commit cannot
    /// redirect the publish rename onto attacker-controlled bytes.
    pub parent_dir: RootDir,
}

/// The agent's authority over one action's data-plane session: the scope root it
/// dispatched, the action's output specs, the per-session pin partition (with
/// per-path single-flight), the allowed-digest ACL, and the in-progress streamed
/// outputs. Shared (`Arc`) across every data-plane connection that opens with this
/// session's id; dropped — partition and all — when the action finishes.
pub struct SessionCapability {
    /// The agent-authoritative normalized scope root (`None` = unscoped). This is
    /// the value the agent dispatched, NOT the worker-declared Hello root, so a
    /// worker cannot widen its own scope (SEC-004).
    root: Option<String>,
    /// Handle-based containment for the authoritative scope root. For an
    /// enforcing session with `root.is_some()`, `None` means setup could not open
    /// the root and file supply must fail closed rather than ambiently reading.
    root_dir: Option<RootDir>,
    /// Output id → agent-authoritative output spec. WriteBack names only the id;
    /// the path and size cap remain controlled by the agent — SEC-003.
    outputs: HashMap<u32, OutputSpec>,
    /// Requested logical path → a single-flight cell yielding the `(digest, size)`
    /// pinned at first touch. The `OnceCell` makes exactly one task read the file
    /// and ingest it; concurrent racers await it and observe the SAME frozen
    /// digest, closing the drop-the-lock-then-read race the old `ingest` had.
    pinned: Mutex<HashMap<String, PinCell>>,
    /// Digests this session has legitimately pinned. For a bound session, `Read`
    /// and `Has` are gated to this set, so a digest learned out-of-band (e.g. from
    /// another session) cannot be fetched/probed here.
    allowed_digests: Mutex<HashSet<Digest>>,
    /// Output id → in-progress streamed WriteBack, per session.
    writebacks: Mutex<HashMap<u32, WritebackState>>,
    /// Output id → fully streamed and digest-verified output waiting for the
    /// intake action-success gate to publish it.
    staged: Mutex<HashMap<u32, StagedOutput>>,
    created: Instant,
    /// Live data-plane connections bound to this session (RAII via [`ConnGuard`]),
    /// so the idle sweeper never reaps a session with work in flight.
    conns: AtomicUsize,
    /// Terminal ADD-001 gate: finished sessions reject late data-plane ops.
    closed: AtomicBool,
    /// `true` for a registry-bound session (enforce authoritative root + digest
    /// ACL + output scope). `false` for the legacy/unscoped capability an old
    /// worker (empty session id) or a test gets — it preserves the pre-ADR-0013
    /// behaviour for reads (worker-declared root, any CAS digest readable). It
    /// still has no output specs, so WriteBack ids remain unauthorized.
    enforce: bool,
    pin_persist_owner: PinPersistOwner,
}

impl SessionCapability {
    fn new(
        root: Option<String>,
        outputs: HashMap<u32, OutputSpec>,
        enforce: bool,
        pin_persist_owner: PinPersistOwner,
    ) -> Self {
        let root_dir = root
            .as_deref()
            .and_then(|path| RootDir::open_root(Path::new(path)).ok());
        SessionCapability {
            root,
            root_dir,
            outputs,
            pinned: Mutex::new(HashMap::new()),
            allowed_digests: Mutex::new(HashSet::new()),
            writebacks: Mutex::new(HashMap::new()),
            staged: Mutex::new(HashMap::new()),
            created: Instant::now(),
            conns: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            enforce,
            pin_persist_owner,
        }
    }

    /// The agent-authoritative scope root (`None` = unscoped). The file server
    /// scopes Stat/OpenRead/DirList against THIS, ignoring the worker's Hello root.
    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }

    /// Handle-based containment for the authoritative root, if setup opened it.
    pub fn root_dir(&self) -> Option<&RootDir> {
        self.root_dir.as_ref()
    }

    /// Whether an enforcing scoped session lost its handle authority and must not
    /// fall back to ambient filesystem access.
    pub fn requires_contained_root(&self) -> bool {
        self.enforce && self.root.is_some() && self.root_dir.is_none()
    }

    /// Whether this is a bound (enforcing) session vs a legacy/unscoped one.
    pub fn enforces(&self) -> bool {
        self.enforce
    }

    /// Marks this capability closed after its action session finishes.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Whether this capability has been closed by session finish.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Pins `requested`'s current bytes into `store` on first touch and returns
    /// the frozen `(digest, size)`; a later call for the same path returns the
    /// SAME digest even if the on-disk file has since changed (snapshot
    /// consistency, v0 §4.1). `None` if the file is absent/unreadable — that is
    /// NOT cached, so a later open can still succeed if the file appears. The
    /// digest is recorded in the allowed-digest ACL so the session may later
    /// `Read`/`Has` it.
    ///
    /// Single-flight: two concurrent first-touches of one path share one cell, so
    /// only one disk read + ingest runs and both observe the identical digest —
    /// closing the race where the old `ingest` dropped its lock between the
    /// pin-check and the read and could pin different bytes under a mid-build edit.
    pub async fn pin(
        &self,
        store: &BlobStore,
        requested: &str,
        actual: PathBuf,
    ) -> Option<(Digest, u64)> {
        self.pin_contained(store, requested, actual, None).await
    }

    pub(crate) async fn pin_contained(
        &self,
        store: &BlobStore,
        requested: &str,
        actual: PathBuf,
        root_read: Option<(RootDir, String)>,
    ) -> Option<(Digest, u64)> {
        let cell = {
            let mut pinned = self.pinned.lock().await;
            pinned
                .entry(requested.to_string())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        let res: Result<&PinnedValue, ()> = cell
            .get_or_try_init(|| async move {
                let bytes = match root_read {
                    Some((root_dir, rel)) => read_root_file(root_dir, rel).await.map_err(|_| ())?,
                    None => tokio::fs::read(&actual).await.map_err(|_| ())?,
                };
                let size = bytes.len() as u64;
                let (digest, publish_guard) =
                    persist_pin_bytes(self.pin_persist_owner.clone(), store.clone(), bytes).await?;
                let value = PinnedValue::new(digest.clone(), size, publish_guard);
                #[cfg(test)]
                self.pin_persist_owner.wait_before_publish().await;
                self.allowed_digests.lock().await.insert(digest.clone());
                Ok(value)
            })
            .await;
        res.ok().map(|value| {
            value.release_publish_guard();
            (value.digest.clone(), value.size)
        })
    }

    /// Whether `digest` may be served/probed on this session. A legacy session
    /// allows any digest in the shared store (pre-ADR-0013 behaviour); a bound
    /// session allows only digests it has itself pinned (closing the cross-session
    /// digest oracle — SEC-004 / PROTO-001).
    pub async fn digest_visible(&self, digest: &Digest) -> bool {
        !self.enforce || self.allowed_digests.lock().await.contains(digest)
    }

    /// Returns the agent-authoritative output spec for `output_id`, if this
    /// session declared it. Unknown ids have no WriteBack authority.
    pub fn output_spec(&self, output_id: u32) -> Option<OutputSpec> {
        self.outputs.get(&output_id).cloned()
    }

    /// The in-progress streamed-output table for this session (the file server's
    /// `write_back` locks it per chunk).
    pub fn writebacks(&self) -> &Mutex<HashMap<u32, WritebackState>> {
        &self.writebacks
    }

    /// Records a fully streamed and digest-verified output for later publish by
    /// the agent's intake path. This does not touch the final path.
    ///
    /// Returns false and deletes staging_path if the session is already closed.
    /// The closed check is performed under the same lock that discard_staged drains,
    /// so no temp can be inserted after discard has run.
    pub(crate) async fn record_staged(
        &self,
        output_id: u32,
        staging_path: PathBuf,
        final_path: PathBuf,
        digest_hex: String,
        snapshot: FileSnapshot,
        parent_dir: RootDir,
    ) -> bool {
        let old = {
            let mut staged = self.staged.lock().await;
            if self.is_closed() {
                drop(staged);
                if let Ok(tmp_rel) = file_name_string(&staging_path) {
                    let _ = remove_root_file(parent_dir, tmp_rel).await;
                }
                return false;
            }
            staged.insert(
                output_id,
                StagedOutput {
                    staging_path,
                    final_path,
                    digest_hex,
                    snapshot,
                    parent_dir,
                },
            )
        };
        if let Some(old) = old
            && let Ok(tmp_rel) = file_name_string(&old.staging_path)
        {
            let _ = remove_root_file(old.parent_dir, tmp_rel).await;
        }
        true
    }

    /// Publishes all verified staged outputs by atomically renaming each staging
    /// sibling onto its final path. All entries are attempted; the first error is
    /// returned after the drain completes.
    pub async fn publish_staged(&self) -> io::Result<()> {
        let entries = {
            let mut staged = self.staged.lock().await;
            staged.drain().map(|(_, staged)| staged).collect::<Vec<_>>()
        };

        let mut first_err = None;
        for staged in entries {
            if let Err(e) = publish_staged_output(staged).await
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Drops any verified-but-unpublished staged outputs and any in-progress
    /// WriteBack temps. Used after failed/aborted/closed actions and after the
    /// publish attempt to avoid leaving session-owned temp files behind.
    pub async fn discard_staged(&self) {
        let staged_entries = {
            let mut staged = self.staged.lock().await;
            staged.drain().map(|(_, staged)| staged).collect::<Vec<_>>()
        };
        let writeback_entries = {
            let mut writebacks = self.writebacks.lock().await;
            writebacks
                .drain()
                .map(|(_, state)| state)
                .collect::<Vec<_>>()
        };

        for staged in staged_entries {
            if let Ok(tmp_rel) = file_name_string(&staged.staging_path) {
                let _ = remove_root_file(staged.parent_dir, tmp_rel).await;
            }
        }
        for state in writeback_entries {
            let WritebackState {
                parent_dir,
                tmp_rel,
                file,
                ..
            } = state;
            drop(file);
            let _ = remove_root_file(parent_dir, tmp_rel).await;
        }
    }
}

async fn read_root_file(root_dir: RootDir, rel: String) -> io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let mut file = root_dir.open_read(&rel)?;
        let mut bytes = Vec::new();
        use std::io::Read as _;
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
    .await
    .map_err(join_error_to_io)?
}

fn join_error_to_io(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("blocking filesystem task failed: {e}"))
}

/// A same-directory, CSPRNG-named staging sibling. Keeping staging beside the
/// final path makes the publish rename same-volume and therefore atomic.
pub fn staging_temp(final_path: &Path) -> PathBuf {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable while naming a staging output");
    let hex = buf.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let name = format!(".sbz-staging-{hex}");
    match final_path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

pub async fn create_staging_temp(final_path: &Path) -> io::Result<StagingTemp> {
    let parent = final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output path has no parent"))?;
    let parent_dir = open_or_create_dir_all_contained(parent.to_path_buf()).await?;
    loop {
        let path = staging_temp(final_path);
        let rel = file_name_string(&path)?;
        match create_new_root_file(parent_dir.clone(), rel.clone()).await {
            Ok(file) => {
                let snapshot = file_snapshot(&file)?;
                if snapshot.link_count != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "new writeback staging temp has unexpected hardlink count",
                    ));
                }
                return Ok(StagingTemp {
                    path,
                    rel,
                    parent_dir,
                    file,
                    snapshot,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn open_or_create_dir_all_contained(path: PathBuf) -> io::Result<RootDir> {
    tokio::task::spawn_blocking(move || open_or_create_dir_all_contained_sync(&path))
        .await
        .map_err(join_error_to_io)?
}

#[cfg(windows)]
fn open_or_create_dir_all_contained_sync(path: &Path) -> io::Result<RootDir> {
    let path = path.to_string_lossy().replace('/', "\\");
    let b = path.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output parent must be drive-absolute",
        ));
    }
    let mut dir = RootDir::open_root(Path::new(&path[..3]))?;
    for component in path[3..].split('\\') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "output parent must not contain '..'",
            ));
        }
        dir = open_or_create_child_dir(dir, component)?;
    }
    Ok(dir)
}

#[cfg(not(windows))]
fn open_or_create_dir_all_contained_sync(path: &Path) -> io::Result<RootDir> {
    let mut components = path.components();
    let Some(std::path::Component::RootDir) = components.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output parent must be absolute",
        ));
    };
    let mut dir = RootDir::open_root(Path::new("/"))?;
    for component in components {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "output parent must not contain '..'",
                ));
            }
            std::path::Component::Normal(name) => {
                let name = name.to_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "output parent is not UTF-8")
                })?;
                dir = open_or_create_child_dir(dir, name)?;
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected output parent component",
                ));
            }
        }
    }
    Ok(dir)
}

fn open_or_create_child_dir(parent: RootDir, child: &str) -> io::Result<RootDir> {
    match parent.open_dir(child) {
        Ok(dir) => Ok(dir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            parent.create_dir(child)?;
            parent.open_dir(child)
        }
        Err(e) => Err(e),
    }
}

async fn publish_staged_output(staged: StagedOutput) -> io::Result<()> {
    let parent = staged
        .final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output path has no parent"))?;
    if staged.staging_path.parent() != Some(parent) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "staging path is not a sibling of final path",
        ));
    }
    let tmp_rel = file_name_string(&staged.staging_path)?;
    let final_rel = file_name_string(&staged.final_path)?;
    let parent_dir = staged.parent_dir;
    if let Err(e) = verify_root_file_snapshot_and_digest(
        parent_dir.clone(),
        tmp_rel.clone(),
        staged.snapshot,
        staged.digest_hex.clone(),
    )
    .await
    {
        let _ = remove_root_file(parent_dir, tmp_rel).await;
        return Err(e);
    }
    match rename_root_file(parent_dir.clone(), tmp_rel.clone(), final_rel).await {
        Ok(()) => {
            if let Err(e) = verify_root_file_snapshot_and_digest(
                parent_dir.clone(),
                file_name_string(&staged.final_path)?,
                staged.snapshot,
                staged.digest_hex,
            )
            .await
            {
                let _ = remove_root_file(parent_dir, file_name_string(&staged.final_path)?).await;
                return Err(e);
            }
            Ok(())
        }
        Err(e) => {
            let _ = remove_root_file(parent_dir, tmp_rel).await;
            Err(e)
        }
    }
}

async fn verify_root_file_snapshot_and_digest(
    root_dir: RootDir,
    rel: String,
    expected_snapshot: FileSnapshot,
    expected: String,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut file = root_dir.open_read(&rel)?;
        let actual_snapshot = file_snapshot(&file)?;
        if actual_snapshot.identity != expected_snapshot.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staging temp file identity changed before publish",
            ));
        }
        if actual_snapshot.link_count != expected_snapshot.link_count {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staging temp hardlink count changed before publish",
            ));
        }
        let mut hasher = DigestHasher::new();
        let mut buf = [0u8; 64 * 1024];
        use std::io::Read as _;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hasher.finalize().canonical();
        if actual == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staging temp path no longer contains the verified bytes",
            ))
        }
    })
    .await
    .map_err(join_error_to_io)?
}

fn file_name_string(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no UTF-8 file name"))
}

async fn create_new_root_file(root_dir: RootDir, rel: String) -> io::Result<cap_std::fs::File> {
    tokio::task::spawn_blocking(move || {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        root_dir.open_with(&rel, &opts)
    })
    .await
    .map_err(join_error_to_io)?
}

async fn rename_root_file(root_dir: RootDir, from: String, to: String) -> io::Result<()> {
    tokio::task::spawn_blocking(move || root_dir.rename(&from, &to))
        .await
        .map_err(join_error_to_io)?
}

pub(crate) async fn remove_root_file(root_dir: RootDir, rel: String) -> io::Result<()> {
    tokio::task::spawn_blocking(move || root_dir.remove_file(&rel))
        .await
        .map_err(join_error_to_io)?
}

/// RAII tracker for a live connection bound to a session, so the idle sweeper
/// never reaps a session that still has a data-plane connection open.
pub struct ConnGuard(Arc<SessionCapability>);

impl ConnGuard {
    /// The capability this guard keeps alive.
    pub fn capability(&self) -> &Arc<SessionCapability> {
        &self.0
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The daemon's authority over all live data-plane sessions: one shared content
/// store plus a `session_id → capability` map. Built once in `run_daemon` and
/// shared (`Arc`) into both the intake/scheduler (which `create`/`finish`) and the
/// file server (which `get`s by the Hello's session id).
pub struct SessionRegistry {
    store: BlobStore,
    pin_persist_owner: PinPersistOwner,
    sessions: Mutex<HashMap<String, Arc<SessionCapability>>>,
}

impl SessionRegistry {
    /// Opens the registry with a fresh temp content store (scrubbed on drop).
    pub fn new() -> io::Result<SessionRegistry> {
        let seq = STORE_SEQ.fetch_add(1, Ordering::Relaxed);
        let store_root =
            std::env::temp_dir().join(format!("sbz-agent-cas.{}.{seq}", std::process::id()));
        let store = BlobStore::open(&store_root)?;
        Ok(SessionRegistry {
            store,
            pin_persist_owner: PinPersistOwner::new(store_root),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// The shared file-supply content store (the file server pins into and reads
    /// from this).
    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    /// Mints a bound session: the scheduler/intake calls this right after minting
    /// the (unpredictable) `session_id`, with the agent's OWN normalized input
    /// root and the action's output specs. Returns the capability (also stored
    /// in the map so the data-plane Hello can find it).
    pub async fn create(
        &self,
        session_id: String,
        root: Option<String>,
        outputs: Vec<OutputSpec>,
    ) -> Arc<SessionCapability> {
        let outputs = outputs
            .into_iter()
            .map(|spec| (spec.id, spec))
            .collect::<HashMap<_, _>>();
        let cap = Arc::new(SessionCapability::new(
            root,
            outputs,
            true,
            self.pin_persist_owner.clone(),
        ));
        self.sessions.lock().await.insert(session_id, cap.clone());
        cap
    }

    /// Returns the bound capability for a known session id, or `None` for an empty
    /// or unknown/expired id; in production the file server now rejects that at the
    /// handshake (only an explicitly-enabled legacy-compat mode treats an empty id
    /// as the legacy/unscoped path).
    pub async fn get(&self, session_id: &str) -> Option<Arc<SessionCapability>> {
        if session_id.is_empty() {
            return None;
        }
        self.sessions.lock().await.get(session_id).cloned()
    }

    /// Destroys a session when its action finishes (any outcome), removing the
    /// registry entry and marking the live capability closed so a lingering
    /// data-plane connection cannot run late ops (ADD-001). The shared store's
    /// blobs are NOT deleted (other sessions may share them). Returns whether an
    /// entry was present.
    pub async fn finish(&self, session_id: &str) -> bool {
        match self.sessions.lock().await.remove(session_id) {
            Some(cap) => {
                cap.close();
                true
            }
            None => false,
        }
    }

    /// Binds a live connection to a session, bumping its connection refcount and
    /// returning a guard that decrements it on drop. The file server holds this for
    /// the connection's lifetime so a lingering connection cannot be reaped.
    pub fn bind(cap: Arc<SessionCapability>) -> ConnGuard {
        cap.conns.fetch_add(1, Ordering::SeqCst);
        ConnGuard(cap)
    }

    /// A legacy/unscoped, NON-registered capability for the pre-ADR-0013 path: an
    /// old worker (empty session id) or a test. It uses the worker-declared `root`,
    /// reads any digest in the shared store, but has no declared output specs, so
    /// WriteBack ids are still rejected unless a caller explicitly created a bound
    /// session with specs. Each connection gets its own pins (connection-local),
    /// which is at worst tighter than the old shared pin map and never staler.
    pub fn legacy_capability(&self, root: Option<String>) -> Arc<SessionCapability> {
        Arc::new(SessionCapability::new(
            root,
            HashMap::new(),
            false,
            self.pin_persist_owner.clone(),
        ))
    }

    /// Reaps bound sessions older than `ttl` that have no live connection — a
    /// backstop for an intake task that died before calling [`finish`]. Returns
    /// the number reaped. Mirrors the `WorkerTable` opportunistic reaper.
    pub async fn sweep_idle(&self, ttl: Duration) -> usize {
        let reaped = {
            let mut sessions = self.sessions.lock().await;
            let mut reaped = Vec::new();
            sessions.retain(|_, cap| {
                let keep = cap.conns.load(Ordering::SeqCst) > 0 || cap.created.elapsed() < ttl;
                if !keep {
                    reaped.push(Arc::clone(cap));
                }
                keep
            });
            reaped
        };

        for cap in &reaped {
            cap.discard_staged().await;
        }
        reaped.len()
    }

    /// Number of live sessions (for the status dashboard / tests).
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

impl Drop for SessionRegistry {
    fn drop(&mut self) {
        // Scrub the shared temp content store. Best-effort: a leaked temp dir is
        // not a correctness problem, so a failure here is ignored (this is a
        // destructor), matching the old per-server `Session` drop.
        self.pin_persist_owner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::AtomicU64;

    static T: AtomicU64 = AtomicU64::new(0);
    fn tmp(tag: &str) -> PathBuf {
        let seq = T.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("sbz-sessreg-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn root_str(p: &Path) -> Option<String> {
        Some(p.to_string_lossy().to_lowercase().replace('/', "\\"))
    }

    #[cfg(windows)]
    fn create_junction(link: &Path, target: &Path) -> Result<(), String> {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map_err(|e| format!("failed to spawn mklink /J: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "mklink /J failed with status {:?}; stdout: {}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(windows)]
    fn create_directory_symlink(link: &Path, target: &Path) -> Result<(), String> {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/D"])
            .arg(link)
            .arg(target)
            .output()
            .map_err(|e| format!("failed to spawn mklink /D: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "mklink /D failed with status {:?}; stdout: {}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[cfg(windows)]
    fn create_relative_directory_symlink(
        parent: &Path,
        link_name: &str,
        target: &Path,
    ) -> Result<(), String> {
        let target_name = target
            .file_name()
            .ok_or_else(|| format!("relative symlink target has no file name: {target:?}"))?;
        let relative_target = Path::new("..").join(target_name);
        let output = std::process::Command::new("cmd")
            .current_dir(parent)
            .args(["/C", "mklink", "/D"])
            .arg(link_name)
            .arg(&relative_target)
            .output()
            .map_err(|e| format!("failed to spawn mklink /D: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "mklink /D failed with status {:?}; stdout: {}; stderr: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    #[tokio::test]
    async fn create_get_finish_lifecycle() {
        let reg = SessionRegistry::new().unwrap();
        assert_eq!(reg.session_count().await, 0);

        let cap = reg
            .create(
                "sess-A".into(),
                root_str(Path::new("c:\\proj")),
                vec![OutputSpec {
                    id: 7,
                    final_path: PathBuf::from("c:\\proj\\obj\\a.obj"),
                    max_size: 123,
                }],
            )
            .await;
        assert!(cap.enforces());
        assert_eq!(cap.root(), Some("c:\\proj"));
        let spec = cap.output_spec(7).expect("declared output spec");
        assert_eq!(spec.final_path, PathBuf::from("c:\\proj\\obj\\a.obj"));
        assert_eq!(spec.max_size, 123);
        assert!(
            cap.output_spec(8).is_none(),
            "unknown output ids have no authority"
        );
        assert!(reg.get("sess-A").await.is_some());
        assert!(
            reg.get("").await.is_none(),
            "an empty id never names a session"
        );
        assert!(reg.get("unknown").await.is_none());
        assert_eq!(reg.session_count().await, 1);

        assert!(reg.finish("sess-A").await);
        assert!(!reg.finish("sess-A").await, "second finish is a no-op");
        assert!(reg.get("sess-A").await.is_none());
        assert_eq!(reg.session_count().await, 0);
    }

    #[tokio::test]
    async fn finish_marks_live_connection_capability_closed() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg.create("sess-live".into(), None, Vec::new()).await;
        let held = cap.clone();
        let _guard = SessionRegistry::bind(held.clone());

        assert!(!held.is_closed());
        assert!(reg.finish("sess-live").await);
        assert!(
            held.is_closed(),
            "finish must close a still-referenced capability"
        );
        assert_eq!(reg.session_count().await, 0);
    }

    #[tokio::test]
    async fn closed_session_cleanup_does_not_panic() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg.create("sess-cleanup".into(), None, Vec::new()).await;
        let guard = SessionRegistry::bind(cap);

        assert!(reg.finish("sess-cleanup").await);
        drop(guard);
        assert_eq!(reg.sweep_idle(Duration::ZERO).await, 0);
        assert_eq!(reg.session_count().await, 0);
    }

    #[tokio::test]
    async fn record_staged_on_closed_session_discards_and_does_not_stage() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg.create("sess-closed".into(), None, Vec::new()).await;
        let dir = tmp("closed-stage");
        let staging_path = dir.join("staged.tmp");
        let final_path = dir.join("out.bin");
        std::fs::write(&staging_path, b"verified bytes").unwrap();
        let parent_dir = RootDir::open_root(&dir).unwrap();
        let file = parent_dir.open_read("staged.tmp").unwrap();
        let snapshot = file_snapshot(&file).unwrap();
        drop(file);

        assert!(reg.finish("sess-closed").await);
        let staged = cap
            .record_staged(
                0,
                staging_path.clone(),
                final_path.clone(),
                Digest::of(b"verified bytes").canonical(),
                snapshot,
                parent_dir,
            )
            .await;

        assert!(!staged);
        assert!(!staging_path.exists());
        cap.publish_staged().await.unwrap();
        assert!(!final_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn publish_staged_rejects_immediate_parent_junction_swap() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("sess-parent-swap".into(), None, Vec::new())
            .await;
        let root = tmp("publish-junction-root");
        let outside = tmp("publish-junction-outside");
        let parent = root.join("out");
        std::fs::create_dir_all(&parent).unwrap();
        let staging_path = parent.join(".sbz-staging-fixed");
        let final_path = parent.join("final.obj");
        std::fs::write(&staging_path, b"verified bytes").unwrap();
        let parent_dir = RootDir::open_root(&parent).unwrap();
        let file = parent_dir.open_read(".sbz-staging-fixed").unwrap();
        let snapshot = file_snapshot(&file).unwrap();
        drop(file);
        assert!(
            cap.record_staged(
                0,
                staging_path.clone(),
                final_path,
                Digest::of(b"verified bytes").canonical(),
                snapshot,
                parent_dir
            )
            .await
        );

        std::fs::remove_file(&staging_path).unwrap();
        if std::fs::remove_dir(&parent).is_ok() {
            eprintln!(
                "writeback junction parent remove_dir succeeded while RootDir handle was open"
            );
            create_junction(&parent, &outside)
                .expect("mklink /J should create an unprivileged junction on Windows");
            std::fs::write(outside.join(".sbz-staging-fixed"), b"attacker bytes").unwrap();
        } else {
            eprintln!("writeback junction parent remove_dir refused while RootDir handle was open");
        }

        let result = cap.publish_staged().await;

        assert!(
            result.is_err(),
            "publish must reject an immediate parent replaced by an out-of-root junction"
        );
        assert!(
            !outside.join("final.obj").exists(),
            "publish must not create the final output through the junction target"
        );

        let _ = std::fs::remove_dir(&parent);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn publish_staged_does_not_publish_attacker_bytes_after_plain_parent_recreate() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("sess-parent-recreate".into(), None, Vec::new())
            .await;
        let root = tmp("publish-parent-recreate-root");
        let parent = root.join("out");
        std::fs::create_dir_all(&parent).unwrap();
        let final_path = parent.join("final.obj");
        let StagingTemp {
            path: staging_path,
            rel: _,
            parent_dir,
            file: _,
            snapshot,
        } = create_staging_temp(&final_path).await.unwrap();
        std::fs::write(&staging_path, b"verified bytes").unwrap();
        assert!(
            cap.record_staged(
                0,
                staging_path.clone(),
                final_path.clone(),
                Digest::of(b"verified bytes").canonical(),
                snapshot,
                parent_dir
            )
            .await
        );

        std::fs::remove_file(&staging_path).unwrap();
        match std::fs::remove_dir(&parent) {
            Ok(()) => {
                eprintln!("writeback parent remove_dir succeeded while RootDir handle was open");
                std::fs::create_dir(&parent).unwrap();
                std::fs::write(&staging_path, b"attacker bytes").unwrap();
            }
            Err(e) => {
                eprintln!("writeback parent remove_dir refused while RootDir handle was open: {e}");
            }
        }

        let _ = cap.publish_staged().await;

        assert_ne!(
            std::fs::read(&final_path).ok().as_deref(),
            Some(b"attacker bytes".as_slice()),
            "writeback publish must never expose bytes staged in a recreated plain parent directory"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_create_staging_temp_rejects_ancestor_junction_escape() {
        let root = tmp("path-corpus-stage-junction-root");
        let outside = tmp("path-corpus-stage-junction-outside");
        let link = root.join("escape");
        create_junction(&link, &outside)
            .expect("mklink /J should create an unprivileged junction on Windows");

        let final_path = link.join("deep").join("final.obj");
        let result = create_staging_temp(&final_path).await;

        assert!(
            result.is_err(),
            "staging must reject an output parent whose ancestor is an out-of-root junction"
        );
        assert!(
            !outside.join("deep").exists(),
            "staging must not create parent directories through the junction target"
        );

        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_create_staging_temp_rejects_ancestor_directory_symlink_escape() {
        let root = tmp("path-corpus-stage-symlink-root");
        let outside = tmp("path-corpus-stage-symlink-outside");
        let link = root.join("escape");
        create_directory_symlink(&link, &outside)
            .expect("mklink /D failed; Windows Developer Mode or admin rights may be required for directory symlink path-corpus evidence");

        let final_path = link.join("deep").join("final.obj");
        let result = create_staging_temp(&final_path).await;

        assert!(
            result.is_err(),
            "staging must reject an output parent whose ancestor is an out-of-root symlink"
        );
        assert!(
            !outside.join("deep").exists(),
            "staging must not create parent directories through the symlink target"
        );

        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_create_staging_temp_rejects_relative_ancestor_directory_symlink_escape() {
        let root = tmp("path-corpus-stage-relative-symlink-root");
        let outside = tmp("path-corpus-stage-relative-symlink-outside");
        create_relative_directory_symlink(&root, "escape", &outside)
            .expect("mklink /D failed; Windows Developer Mode or admin rights may be required for relative directory symlink path-corpus evidence");

        let final_path = root.join("escape").join("deep").join("final.obj");
        let result = create_staging_temp(&final_path).await;

        assert!(
            result.is_err(),
            "staging must reject an output parent whose ancestor is a relative out-of-root symlink"
        );
        assert!(
            !outside.join("deep").exists(),
            "staging must not create parent directories through the relative symlink target"
        );

        let _ = std::fs::remove_dir(root.join("escape"));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_publish_staged_preserves_external_hardlink_peer_or_fails_closed() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("sess-final-hardlink".into(), None, Vec::new())
            .await;
        let root = tmp("path-corpus-final-hardlink-root");
        let outside = tmp("path-corpus-final-hardlink-outside");
        let parent = root.join("out");
        std::fs::create_dir_all(&parent).unwrap();
        let final_path = parent.join("final.obj");
        let external_peer = outside.join("peer.obj");
        std::fs::write(&external_peer, b"external-old").unwrap();
        std::fs::hard_link(&external_peer, &final_path).unwrap();

        let StagingTemp {
            path: staging_path,
            rel: _,
            parent_dir,
            file: _,
            snapshot,
        } = create_staging_temp(&final_path).await.unwrap();
        std::fs::write(&staging_path, b"verified-new").unwrap();
        assert!(
            cap.record_staged(
                0,
                staging_path.clone(),
                final_path.clone(),
                Digest::of(b"verified-new").canonical(),
                snapshot,
                parent_dir
            )
            .await
        );

        match cap.publish_staged().await {
            Ok(()) => {
                assert_eq!(
                    std::fs::read(&final_path).unwrap(),
                    b"verified-new",
                    "successful publish must replace the final path with staged bytes"
                );
                assert_eq!(
                    std::fs::read(&external_peer).unwrap(),
                    b"external-old",
                    "publishing over an existing hardlink must not rewrite the external peer"
                );
            }
            Err(_) => {
                // Fail-closed satisfies the Phase 7.3 invariant here: the
                // publish is abandoned instead of writing through an ambiguous
                // existing hardlink, so both peers keep their old bytes.
                assert_eq!(std::fs::read(&final_path).unwrap(), b"external-old");
                assert_eq!(std::fs::read(&external_peer).unwrap(), b"external-old");
            }
        }

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn path_corpus_publish_staged_rejects_replaced_staging_temp() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("sess-replaced-staging".into(), None, Vec::new())
            .await;
        let root = tmp("path-corpus-replaced-staging-root");
        let final_path = root.join("out").join("final.obj");
        let StagingTemp {
            path: staging_path,
            rel: _,
            parent_dir,
            file: _,
            snapshot,
        } = create_staging_temp(&final_path).await.unwrap();
        std::fs::write(&staging_path, b"verified bytes").unwrap();
        assert!(
            cap.record_staged(
                0,
                staging_path.clone(),
                final_path.clone(),
                Digest::of(b"verified bytes").canonical(),
                snapshot,
                parent_dir
            )
            .await
        );

        std::fs::remove_file(&staging_path).unwrap();
        std::fs::write(&staging_path, b"attacker bytes").unwrap();
        let result = cap.publish_staged().await;

        assert!(
            result.is_err(),
            "publish must fail closed when staging bytes change after record_staged"
        );
        assert_ne!(
            std::fs::read(&final_path).ok().as_deref(),
            Some(b"attacker bytes".as_slice()),
            "publish must never expose attacker bytes swapped into the staging temp"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_publish_staged_rejects_same_content_hardlink_staging_swap() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("sess-hardlink-staging-swap".into(), None, Vec::new())
            .await;
        let root = tmp("path-corpus-hardlink-staging-swap-root");
        let outside = tmp("path-corpus-hardlink-staging-swap-outside");
        let final_path = root.join("out").join("final.obj");
        let external_peer = outside.join("peer.obj");
        let StagingTemp {
            path: staging_path,
            rel: _,
            parent_dir,
            file: _,
            snapshot,
        } = create_staging_temp(&final_path).await.unwrap();
        std::fs::write(&staging_path, b"same verified bytes").unwrap();
        assert!(
            cap.record_staged(
                0,
                staging_path.clone(),
                final_path.clone(),
                Digest::of(b"same verified bytes").canonical(),
                snapshot,
                parent_dir
            )
            .await
        );

        std::fs::write(&external_peer, b"same verified bytes").unwrap();
        std::fs::remove_file(&staging_path).unwrap();
        std::fs::hard_link(&external_peer, &staging_path).expect(
            "failed to create hardlink required for writeback staging identity path-corpus evidence",
        );
        let result = cap.publish_staged().await;

        assert!(
            result.is_err(),
            "publish must fail closed when the verified staging temp is replaced by a same-content external hardlink"
        );
        assert!(
            !final_path.exists(),
            "publish must not rename an external hardlink into the final output"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn path_corpus_discard_staged_removes_in_progress_writeback_temp() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("sess-discard-writeback".into(), None, Vec::new())
            .await;
        let root = tmp("discard-writeback-temp");
        let final_path = root.join("out.bin");
        let StagingTemp {
            path: staging_path,
            rel,
            parent_dir,
            file,
            snapshot,
        } = create_staging_temp(&final_path).await.unwrap();
        assert!(staging_path.exists());
        cap.writebacks().lock().await.insert(
            1,
            WritebackState {
                tmp: staging_path.clone(),
                tmp_rel: rel,
                parent_dir,
                file: Arc::new(StdMutex::new(file)),
                snapshot,
                written: 0,
                hasher: DigestHasher::new(),
            },
        );

        cap.discard_staged().await;

        assert!(
            !staging_path.exists(),
            "discard_staged must drop the open writeback handle before removing the temp"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn sweep_idle_discards_staging_of_reaped_sessions() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg.create("sess-reaped".into(), None, Vec::new()).await;
        let dir = tmp("sweep-stage");
        let staging_path = dir.join("staged.tmp");
        let final_path = dir.join("out.bin");
        std::fs::write(&staging_path, b"verified bytes").unwrap();
        let parent_dir = RootDir::open_root(&dir).unwrap();
        let file = parent_dir.open_read("staged.tmp").unwrap();
        let snapshot = file_snapshot(&file).unwrap();
        drop(file);
        assert!(
            cap.record_staged(
                0,
                staging_path.clone(),
                final_path,
                Digest::of(b"verified bytes").canonical(),
                snapshot,
                parent_dir
            )
            .await
        );

        let reaped = reg.sweep_idle(Duration::ZERO).await;

        assert!(reaped >= 1);
        assert!(!staging_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn single_flight_pin_freezes_one_digest_under_concurrency() {
        // Two concurrent first-touches of the SAME path must observe the SAME
        // frozen digest even if the file changes between them — the race the old
        // lock-drop `ingest` had. After pinning, an edit must NOT change what the
        // session serves (snapshot consistency).
        let reg = SessionRegistry::new().unwrap();
        let dir = tmp("pin");
        let f = dir.join("a.cpp");
        std::fs::write(&f, b"v1-original").unwrap();
        let cap = reg.create("s".into(), None, Vec::new()).await;

        let (r1, r2) = tokio::join!(
            cap.pin(reg.store(), "a.cpp", f.clone()),
            cap.pin(reg.store(), "a.cpp", f.clone()),
        );
        let (d1, _) = r1.expect("pin 1");
        let (d2, _) = r2.expect("pin 2");
        assert_eq!(
            d1, d2,
            "concurrent first-touch must pin one identical digest"
        );
        assert!(
            cap.digest_visible(&d1).await,
            "a pinned digest is allowed to read"
        );

        // Edit the file: the pin is frozen, so a later pin returns the SAME digest.
        std::fs::write(&f, b"v2-edited-different-length").unwrap();
        let (d3, _) = cap
            .pin(reg.store(), "a.cpp", f.clone())
            .await
            .expect("re-pin");
        assert_eq!(
            d1, d3,
            "a pinned path stays frozen for the session (snapshot)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn production_pin_persist_queues_off_runtime_while_sentinel_is_exclusive() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let reg = SessionRegistry::new().unwrap();
            let dir = tmp("pin-blocking-persist");
            let actual = dir.join("queued.h");
            let bytes = vec![0x6b; 1_000_000];
            std::fs::write(&actual, &bytes).unwrap();
            let expected = Digest::of(&bytes);
            let cap = reg.create("pin-blocking".into(), None, Vec::new()).await;

            let sentinel = reg
                .pin_persist_owner
                .store_root()
                .join("cas")
                .join(".lifecycle.lock");
            let (locked_tx, locked_rx) = std::sync::mpsc::channel();
            let (observed_tx, observed_rx) = std::sync::mpsc::channel();
            let (foreground_tx, foreground_rx) = std::sync::mpsc::channel();
            let pin_persist_owner = cap.pin_persist_owner.clone();
            let lock_thread = std::thread::spawn(move || {
                let sentinel = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(sentinel)
                    .unwrap();
                sentinel.lock().unwrap();
                locked_tx.send(()).unwrap();

                let deadline = Instant::now() + Duration::from_secs(3);
                let observed = loop {
                    if pin_persist_owner.active() == 1 {
                        break true;
                    }
                    if Instant::now() >= deadline {
                        break false;
                    }
                    std::thread::yield_now();
                };
                observed_tx.send(observed).unwrap();
                let foreground_received = observed
                    && foreground_rx.recv_timeout(Duration::from_secs(3)).is_ok();
                sentinel.unlock().unwrap();
                (observed, foreground_received)
            });
            locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();

            let pin_cap = Arc::clone(&cap);
            let pin_store = reg.store().clone();
            let pin_actual = actual.clone();
            let pin = tokio::spawn(async move {
                pin_cap
                    .pin(&pin_store, "queued.h", pin_actual)
                    .await
            });
            let observed = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match observed_rx.try_recv() {
                        Ok(observed) => break observed,
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            tokio::task::yield_now().await;
                        }
                        Err(error) => panic!("pin observation channel failed: {error}"),
                    }
                }
            })
            .await
            .expect("external lock thread must finish its bounded queue observation");
            assert!(
                observed,
                "production pin persistence must queue a blocking job before waiting on CAS"
            );

            let foreground = tokio::spawn(async move {
                tokio::task::yield_now().await;
                foreground_tx.send(()).unwrap();
            });
            foreground.await.unwrap();
            let (thread_observed, foreground_received) = lock_thread.join().unwrap();
            assert!(thread_observed);
            assert!(
                foreground_received,
                "current-thread runtime must execute unrelated async work while CAS persistence waits"
            );

            let (digest, size) = pin.await.unwrap().expect("pin should complete after unlock");
            assert_eq!(digest, expected);
            assert_eq!(size, bytes.len() as u64);
            assert_eq!(
                reg.store().get_verified(&digest).unwrap().as_deref(),
                Some(bytes.as_slice())
            );
            assert!(cap.digest_visible(&digest).await);
            assert_eq!(cap.pin_persist_owner.active(), 0);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn cancelled_pin_persist_does_not_freeze_cell_or_grant_acl() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let reg = SessionRegistry::new().unwrap();
            let dir = tmp("pin-cancel-persist");
            let actual = dir.join("cancelled.h");
            let bytes = vec![0x2a; 300_000];
            std::fs::write(&actual, &bytes).unwrap();
            let expected = Digest::of(&bytes);
            let cap = reg.create("pin-cancel".into(), None, Vec::new()).await;

            let sentinel = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(
                    reg.pin_persist_owner
                        .store_root()
                        .join("cas")
                        .join(".lifecycle.lock"),
                )
                .unwrap();
            sentinel.lock().unwrap();
            let pin_cap = Arc::clone(&cap);
            let pin_store = reg.store().clone();
            let pin_actual = actual.clone();
            let pin =
                tokio::spawn(
                    async move { pin_cap.pin(&pin_store, "cancelled.h", pin_actual).await },
                );
            tokio::time::timeout(Duration::from_secs(5), async {
                while cap.pin_persist_owner.active() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("production pin persistence must enter the blocking pool");

            pin.abort();
            assert!(pin.await.unwrap_err().is_cancelled());
            assert!(
                !cap.digest_visible(&expected).await,
                "a cancelled initializer must not grant digest visibility"
            );
            sentinel.unlock().unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while cap.pin_persist_owner.active() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancelled pin's blocking persistence must still drain");

            let (digest, size) = cap
                .pin(reg.store(), "cancelled.h", actual)
                .await
                .expect("a later caller must retry the cancelled generation");
            assert_eq!(digest, expected);
            assert_eq!(size, bytes.len() as u64);
            assert!(cap.digest_visible(&digest).await);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn pin_persist_observation_is_isolated_between_registries() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        runtime.block_on(async {
            let reg_a = SessionRegistry::new().unwrap();
            let reg_b = SessionRegistry::new().unwrap();
            let dir = tmp("pin-owner-isolation");
            let actual_a = dir.join("a.h");
            let actual_b = dir.join("b.h");
            std::fs::write(&actual_a, b"registry-a").unwrap();
            std::fs::write(&actual_b, b"registry-b").unwrap();
            let cap_a = reg_a.create("A".into(), None, Vec::new()).await;
            let cap_b = reg_b.create("B".into(), None, Vec::new()).await;

            let sentinel_a = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(
                    reg_a
                        .pin_persist_owner
                        .store_root()
                        .join("cas")
                        .join(".lifecycle.lock"),
                )
                .unwrap();
            let sentinel_b = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(
                    reg_b
                        .pin_persist_owner
                        .store_root()
                        .join("cas")
                        .join(".lifecycle.lock"),
                )
                .unwrap();
            sentinel_a.lock().unwrap();
            sentinel_b.lock().unwrap();

            let pin_a_cap = Arc::clone(&cap_a);
            let store_a = reg_a.store().clone();
            let pin_a = tokio::spawn(async move { pin_a_cap.pin(&store_a, "a.h", actual_a).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                while cap_a.pin_persist_owner.active() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("registry A must report its queued persist");
            assert_eq!(cap_b.pin_persist_owner.active(), 0);

            let pin_b_cap = Arc::clone(&cap_b);
            let store_b = reg_b.store().clone();
            let pin_b = tokio::spawn(async move { pin_b_cap.pin(&store_b, "b.h", actual_b).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                while cap_b.pin_persist_owner.active() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("registry B must report only its own queued persist");
            assert_eq!(cap_a.pin_persist_owner.active(), 1);

            sentinel_a.unlock().unwrap();
            sentinel_b.unlock().unwrap();
            assert!(pin_a.await.unwrap().is_some());
            assert!(pin_b.await.unwrap().is_some());
            assert_eq!(cap_a.pin_persist_owner.active(), 0);
            assert_eq!(cap_b.pin_persist_owner.active(), 0);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn registry_drop_defers_cleanup_until_cancelled_persist_drains() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let reg = SessionRegistry::new().unwrap();
            let store_root = reg.pin_persist_owner.store_root().to_path_buf();
            let held_store = reg.store().clone();
            let dir = tmp("pin-owner-drop-race");
            let actual = dir.join("drop.h");
            std::fs::write(&actual, vec![0x4d; 400_000]).unwrap();
            let cap = reg.create("drop-race".into(), None, Vec::new()).await;

            let sentinel_path = store_root.join("cas").join(".lifecycle.lock");
            let (locked_tx, locked_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let lock_thread = std::thread::spawn(move || {
                let sentinel = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(sentinel_path)
                    .unwrap();
                sentinel.lock().unwrap();
                locked_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                sentinel.unlock().unwrap();
            });
            locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();

            let pin_cap = Arc::clone(&cap);
            let pin_store = held_store.clone();
            let pin = tokio::spawn(async move { pin_cap.pin(&pin_store, "drop.h", actual).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                while cap.pin_persist_owner.active() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("persist must be registered before registry drop");
            pin.abort();
            assert!(pin.await.unwrap_err().is_cancelled());

            drop(reg);
            assert!(
                store_root.exists(),
                "active persistence must defer registry cleanup"
            );
            release_tx.send(()).unwrap();
            lock_thread.join().unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while store_root.exists() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("last persist guard must clean the closed registry store");
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !store_root.exists(),
                "a detached persist must not recreate the cleaned store"
            );
            drop(held_store);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn registry_drop_keeps_store_until_pin_persist_result_is_published() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let reg = SessionRegistry::new().unwrap();
            let store_root = reg.pin_persist_owner.store_root().to_path_buf();
            let store = reg.store().clone();
            let dir = tmp("pin-publish-drop-race");
            let actual = dir.join("publish.h");
            let bytes = vec![0x73; 400_000];
            std::fs::write(&actual, &bytes).unwrap();
            let expected = Digest::of(&bytes);
            let cap = reg.create("publish-race".into(), None, Vec::new()).await;

            let sentinel = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(store_root.join("cas").join(".lifecycle.lock"))
                .unwrap();
            sentinel.lock().unwrap();
            let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            cap.pin_persist_owner
                .install_before_publish_hook(reached_tx, release_rx);

            let pin_cap = Arc::clone(&cap);
            let pin_store = store.clone();
            let pin =
                tokio::spawn(async move { pin_cap.pin(&pin_store, "publish.h", actual).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                while cap.pin_persist_owner.active() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("persist must be registered before registry drop");

            drop(reg);
            assert!(store_root.exists());
            sentinel.unlock().unwrap();
            tokio::time::timeout(Duration::from_secs(5), reached_rx)
                .await
                .expect("pin initializer must reach the pre-publish barrier")
                .expect("pin initializer must signal the pre-publish barrier");
            assert!(
                store_root.exists(),
                "store cleanup must wait until ACL and OnceCell publication complete"
            );
            release_tx.send(()).unwrap();

            let result = pin
                .await
                .unwrap()
                .expect("a non-cancelled pin must publish its result after registry close");
            assert_eq!(result, (expected.clone(), bytes.len() as u64));
            assert!(cap.digest_visible(&expected).await);
            assert_eq!(
                cap.pin(&store, "publish.h", PathBuf::from("missing-after-publish"))
                    .await,
                Some(result),
                "the successful result must be frozen in the OnceCell"
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                while store_root.exists() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("store cleanup must run after result publication releases its guard");
            drop(store);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[tokio::test]
    async fn registry_close_rejects_new_pin_persist_without_acl_grant() {
        let reg = SessionRegistry::new().unwrap();
        let store = reg.store().clone();
        let dir = tmp("pin-owner-closed");
        let actual = dir.join("closed.h");
        let bytes = b"closed registry";
        std::fs::write(&actual, bytes).unwrap();
        let digest = Digest::of(bytes);
        let cap = reg.create("closed".into(), None, Vec::new()).await;

        drop(reg);
        assert!(cap.pin(&store, "closed.h", actual).await.is_none());
        assert!(!cap.digest_visible(&digest).await);
        assert_eq!(cap.pin_persist_owner.active(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_persist_owner_starts_cleanup_only_once() {
        let store_root = tmp("pin-owner-clean-once");
        let owner = PinPersistOwner::new(store_root.clone());
        owner.close();
        assert!(!store_root.exists());

        std::fs::create_dir_all(&store_root).unwrap();
        owner.close();
        assert!(
            store_root.exists(),
            "cleanup_started must prevent a second destructive cleanup"
        );
        let _ = std::fs::remove_dir_all(&store_root);
    }

    #[tokio::test]
    async fn bound_session_gates_digests_legacy_does_not() {
        // A bound session may only read/probe digests it pinned; a foreign digest
        // (pinned by another session) is invisible even though the shared store
        // physically holds it. A legacy session sees any digest.
        let reg = SessionRegistry::new().unwrap();
        let dir = tmp("acl");
        let mine = dir.join("mine.h");
        let theirs = dir.join("theirs.h");
        std::fs::write(&mine, b"mine").unwrap();
        std::fs::write(&theirs, b"theirs").unwrap();

        let a = reg.create("A".into(), None, Vec::new()).await;
        let b = reg.create("B".into(), None, Vec::new()).await;
        let (d_mine, _) = a.pin(reg.store(), "mine.h", mine.clone()).await.unwrap();
        let (d_theirs, _) = b
            .pin(reg.store(), "theirs.h", theirs.clone())
            .await
            .unwrap();

        // The blob B pinned is physically in the shared store...
        assert!(reg.store().has(&d_theirs));
        // ...but session A may NOT read it (it never pinned that path).
        assert!(a.digest_visible(&d_mine).await);
        assert!(
            !a.digest_visible(&d_theirs).await,
            "a bound session must not read another session's digest (SEC-004)"
        );

        // A legacy session has no ACL: any present digest is visible.
        let legacy = reg.legacy_capability(None);
        assert!(legacy.digest_visible(&d_theirs).await);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn writeback_scope_restricts_to_declared_outputs() {
        // Declared output specs gate WriteBack for a bound session; with none
        // declared all WriteBack ids are refused.
        let mut outs = HashMap::new();
        outs.insert(
            0,
            OutputSpec {
                id: 0,
                final_path: PathBuf::from("c:\\proj\\obj\\a.obj"),
                max_size: DEFAULT_OUTPUT_MAX_BYTES,
            },
        );
        let reg = SessionRegistry::new().unwrap();
        let bound = SessionCapability::new(
            root_str(Path::new("c:\\proj")),
            outs,
            true,
            reg.pin_persist_owner.clone(),
        );
        let spec = bound.output_spec(0).expect("declared output allowed");
        assert_eq!(spec.final_path, PathBuf::from("c:\\proj\\obj\\a.obj"));
        assert_eq!(spec.max_size, DEFAULT_OUTPUT_MAX_BYTES);
        assert!(bound.output_spec(1).is_none(), "unknown id is refused");

        // No declared outputs → no WriteBack authority, even within root.
        let bound_no_decl = SessionCapability::new(
            root_str(Path::new("c:\\proj")),
            HashMap::new(),
            true,
            reg.pin_persist_owner.clone(),
        );
        assert!(
            bound_no_decl.output_spec(0).is_none(),
            "no id is valid when nothing is declared (SEC-003)"
        );

        // Legacy has no output specs, so WriteBack ids are not authorized there.
        let legacy = reg.legacy_capability(None);
        assert!(legacy.output_spec(0).is_none());
    }

    #[tokio::test]
    async fn idle_sweeper_reaps_only_old_unconnected_sessions() {
        let reg = SessionRegistry::new().unwrap();
        let old = reg.create("old".into(), None, Vec::new()).await;
        let _young = reg.create("young".into(), None, Vec::new()).await;

        // A connection on `old` protects it from the sweeper even though it is old.
        let guard = SessionRegistry::bind(old.clone());
        // ttl = 0: everything is "old enough", but a bound connection is spared.
        assert_eq!(
            reg.sweep_idle(Duration::ZERO).await,
            1,
            "only the unconnected one reaps"
        );
        assert!(
            reg.get("old").await.is_some(),
            "a connected session is never reaped"
        );
        assert!(reg.get("young").await.is_none());

        drop(guard);
        assert_eq!(
            reg.sweep_idle(Duration::ZERO).await,
            1,
            "now the unconnected old one reaps"
        );
        assert_eq!(reg.session_count().await, 0);
    }

    #[tokio::test]
    async fn an_absent_pin_is_not_cached_so_a_later_appearance_is_seen() {
        // `pin` must NOT cache a miss: a file absent at first touch but created
        // later must become pinnable (the single-flight init fails WITHOUT setting
        // the cell, so a retry re-reads). This guards the snapshot/retry contract.
        let reg = SessionRegistry::new().unwrap();
        let dir = tmp("absent-pin");
        let f = dir.join("late.h");
        let cap = reg.create("s".into(), None, Vec::new()).await;

        // Absent at first touch → None, and NOT frozen.
        assert!(cap.pin(reg.store(), "late.h", f.clone()).await.is_none());
        // The file appears; a later pin now succeeds (the miss was not cached).
        std::fs::write(&f, b"now here").unwrap();
        let pinned = cap.pin(reg.store(), "late.h", f.clone()).await;
        assert!(
            pinned.is_some(),
            "an absent pin must not be cached; the file appearing must be seen"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
