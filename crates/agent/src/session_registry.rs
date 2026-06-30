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
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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

/// The single-flight cell for one pinned path: yields the `(digest, size)` frozen
/// at first touch. `Arc` so concurrent racers of the same path share one cell.
type PinCell = Arc<OnceCell<(Digest, u64)>>;

/// In-progress streamed WriteBack for one output id: the temp file being
/// appended to, how many bytes have landed (the next expected offset), and the
/// running digest so the whole output is verified without buffering it. Lives
/// per session now (was a field of the process-wide `Session`).
pub struct WritebackState {
    pub tmp: PathBuf,
    pub written: u64,
    pub hasher: DigestHasher,
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
}

impl SessionCapability {
    fn new(root: Option<String>, outputs: HashMap<u32, OutputSpec>, enforce: bool) -> Self {
        SessionCapability {
            root,
            outputs,
            pinned: Mutex::new(HashMap::new()),
            allowed_digests: Mutex::new(HashSet::new()),
            writebacks: Mutex::new(HashMap::new()),
            created: Instant::now(),
            conns: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            enforce,
        }
    }

    /// The agent-authoritative scope root (`None` = unscoped). The file server
    /// scopes Stat/OpenRead/DirList against THIS, ignoring the worker's Hello root.
    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
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
        let cell = {
            let mut pinned = self.pinned.lock().await;
            pinned
                .entry(requested.to_string())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        let res: Result<&(Digest, u64), ()> = cell
            .get_or_try_init(|| async {
                let bytes = tokio::fs::read(&actual).await.map_err(|_| ())?;
                let size = bytes.len() as u64;
                let digest = store.put(&bytes).map_err(|_| ())?;
                self.allowed_digests.lock().await.insert(digest.clone());
                Ok((digest, size))
            })
            .await;
        res.ok().map(|(d, s)| (d.clone(), *s))
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
    store_root: PathBuf,
    sessions: Mutex<HashMap<String, Arc<SessionCapability>>>,
}

impl SessionRegistry {
    /// Opens the registry with a fresh temp content store (scrubbed on drop).
    pub fn new() -> io::Result<SessionRegistry> {
        let seq = STORE_SEQ.fetch_add(1, Ordering::Relaxed);
        let store_root =
            std::env::temp_dir().join(format!("sbz-agent-cas.{}.{seq}", std::process::id()));
        Ok(SessionRegistry {
            store: BlobStore::open(&store_root)?,
            store_root,
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
        let cap = Arc::new(SessionCapability::new(root, outputs, true));
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
    pub fn legacy_capability(root: Option<String>) -> Arc<SessionCapability> {
        Arc::new(SessionCapability::new(root, HashMap::new(), false))
    }

    /// Reaps bound sessions older than `ttl` that have no live connection — a
    /// backstop for an intake task that died before calling [`finish`]. Returns
    /// the number reaped. Mirrors the `WorkerTable` opportunistic reaper.
    pub async fn sweep_idle(&self, ttl: Duration) -> usize {
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions
            .retain(|_, cap| cap.conns.load(Ordering::SeqCst) > 0 || cap.created.elapsed() < ttl);
        before - sessions.len()
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
        let _ = std::fs::remove_dir_all(&self.store_root);
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
        let legacy = SessionRegistry::legacy_capability(None);
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
        let bound = SessionCapability::new(root_str(Path::new("c:\\proj")), outs, true);
        let spec = bound.output_spec(0).expect("declared output allowed");
        assert_eq!(spec.final_path, PathBuf::from("c:\\proj\\obj\\a.obj"));
        assert_eq!(spec.max_size, DEFAULT_OUTPUT_MAX_BYTES);
        assert!(bound.output_spec(1).is_none(), "unknown id is refused");

        // No declared outputs → no WriteBack authority, even within root.
        let bound_no_decl =
            SessionCapability::new(root_str(Path::new("c:\\proj")), HashMap::new(), true);
        assert!(
            bound_no_decl.output_spec(0).is_none(),
            "no id is valid when nothing is declared (SEC-003)"
        );

        // Legacy has no output specs, so WriteBack ids are not authorized there.
        let legacy = SessionRegistry::legacy_capability(None);
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
