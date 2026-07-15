//! LocalIntake (M6): the build-system launcher's entry into the agent daemon.
//!
//! A compiler launcher (`sembazuru <compiler> <args...>`, set as
//! `CMAKE_<LANG>_COMPILER_LAUNCHER` or an MSBuild `CLToolExe` shim) is a
//! short-lived process. It hands its one action to the long-lived daemon over a
//! machine-local transport; the daemon schedules it across workers (or runs it
//! locally on fallback) and streams the result back so the launcher exits exactly
//! as the compiler would have (`docs/protocol/v0.md` §3.2; see `LocalIntake` in
//! `control.proto`).
//!
//! This plane never leaves the machine. Windows uses a DACL-protected named pipe
//! with caller/server SID authentication; non-Windows uses loopback TCP.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_cas::Digest;
use sembazuru_cas::toolchain::ToolchainIdentity;
use sembazuru_proto::v0::{
    ActionState, Command, ExitStatus, OutputChunk, StateChange, SubmitActionEvent,
    SubmitActionRequest, VfsExecution, local_intake_client::LocalIntakeClient,
    local_intake_server::LocalIntake, submit_action_event::Event,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

use crate::action_cache::{AgentCache, CacheLookup};
use crate::action_tracker::{ActionTracker, ActivityState, ExecutionKind, display_name};
use crate::scheduler::Scheduler;
use crate::session_registry::{
    DEFAULT_OUTPUT_MAX_BYTES, DaemonTaskScope, OutputSpec, SessionCapability, SessionRegistry,
    SubmissionDeadline, SubmissionPhase,
};
use crate::status::Metrics;
use crate::{
    ExecOptions, ExecuteError, Execution, LocalExecutionContext, LocalFallbackReason,
    run_local_with_context,
};

#[cfg(windows)]
use crate::intake_pipe::CallerIdentityConnectInfo;

#[cfg(test)]
struct SubmissionBarrier {
    reached: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
struct SubmissionDropSignal(Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
impl Drop for SubmissionDropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
std::thread_local! {
    static NEXT_SUBMISSION_BARRIER: std::cell::RefCell<Option<SubmissionBarrier>> = const {
        std::cell::RefCell::new(None)
    };
    static NEXT_SUBMISSION_DEADLINE: std::cell::RefCell<
        Option<tokio::sync::oneshot::Sender<Arc<SubmissionDeadline>>>
    > = const { std::cell::RefCell::new(None) };
    static PANIC_NEXT_SUBMISSION_AFTER_CREATE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
fn install_next_submission_barrier(barrier: SubmissionBarrier) {
    NEXT_SUBMISSION_BARRIER.with(|slot| {
        assert!(slot.borrow_mut().replace(barrier).is_none());
    });
}

#[cfg(test)]
fn observe_next_submission_deadline(sender: tokio::sync::oneshot::Sender<Arc<SubmissionDeadline>>) {
    NEXT_SUBMISSION_DEADLINE.with(|slot| {
        assert!(slot.borrow_mut().replace(sender).is_none());
    });
}

#[cfg(test)]
async fn wait_at_submission_barrier() {
    let barrier = NEXT_SUBMISSION_BARRIER.with(|slot| slot.borrow_mut().take());
    if let Some(barrier) = barrier {
        let _drop_signal = SubmissionDropSignal(barrier.dropped);
        let _ = barrier.reached.send(());
        let _ = barrier.release.await;
    }
}

async fn hold_eof_until_submission_is_safe<F>(
    deadline: Arc<SubmissionDeadline>,
    inner: F,
    _eof_lease: mpsc::Sender<Result<SubmitActionEvent, Status>>,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let mut inner = tokio::spawn(inner);
    let force = deadline.force_token();
    let inner_failed = tokio::select! {
        biased;
        result = &mut inner => result.is_err(),
        _ = force.cancelled() => {
            if deadline.try_abort_no_child() {
                inner.abort();
                inner.await.is_err()
            } else {
                inner.await.is_err()
            }
        }
    };
    if inner_failed && deadline.phase() == SubmissionPhase::Idle {
        let _ = deadline.try_abort_no_child();
    }
    wait_for_safe_submission_terminal(&deadline).await;
}

async fn wait_for_safe_submission_terminal(deadline: &SubmissionDeadline) {
    loop {
        match deadline.phase() {
            SubmissionPhase::Idle
            | SubmissionPhase::NaturalReaped
            | SubmissionPhase::RetrySafeReaped
            | SubmissionPhase::ForcedReaped
            | SubmissionPhase::AbortedNoChild => return,
            SubmissionPhase::ForceFailed => std::future::pending::<()>().await,
            SubmissionPhase::SettingUp | SubmissionPhase::Active | SubmissionPhase::Terminating => {
                let _ = deadline.wait_terminal().await;
            }
        }
    }
}

/// Per-action options the launcher hands to the daemon alongside the command
/// (the non-command fields of [`SubmitActionRequest`]). Bundled so adding a knob
/// does not churn every call site. All default to the compiler-compatible
/// behavior: declare nothing, deterministic, non-strict, input root = cwd.
#[derive(Default, Clone)]
pub struct SubmitOptions {
    /// Output paths to record (empty = discover from the trace, ADR 0007 §b).
    pub declared_outputs: Vec<String>,
    /// Distribute but never cache (non-byte-reproducible, ADR 0007 §c).
    pub non_deterministic: bool,
    /// Fail an unsuppliable read under the input root instead of a local open
    /// (ADR 0007 §a②).
    pub strict_vfs: bool,
    /// Declared input root; empty = use cwd (ADR 0007 / M8.3).
    pub input_root: String,
}

fn state_ev(state: ActionState, detail: &str) -> SubmitActionEvent {
    SubmitActionEvent {
        event: Some(Event::State(StateChange {
            state: state as i32,
            detail: detail.to_string(),
        })),
    }
}

fn exit_ev(code: i32, wall_us: u64) -> SubmitActionEvent {
    SubmitActionEvent {
        event: Some(Event::Exit(ExitStatus {
            exit_code: code,
            wall_time_us: wall_us,
            user_time_us: 0,
            kernel_time_us: 0,
            resolved_tool_digest: String::new(),
        })),
    }
}

fn stdio_ev(is_stderr: bool, data: Vec<u8>) -> SubmitActionEvent {
    SubmitActionEvent {
        event: Some(Event::Stdio(OutputChunk { is_stderr, data })),
    }
}

/// Read-VFS + action-cache context for the daemon's intake (M6.1). With it, each
/// submitted compile runs under the read-VFS — inputs supplied on demand by the
/// agent file server at `agent_fileserver` — and, when `cache` is set, is checked
/// against the action cache (a 2nd identical build skips the worker) and recorded
/// after a successful run. Without a context, intake plain-dispatches (M6.0 path
/// and tests).
#[derive(Clone)]
pub struct IntakeVfsContext {
    /// host:port of the agent data-plane file server (goes into `VfsExecution`).
    pub agent_fileserver: String,
    /// Action cache; `None` runs VFS compiles without resolve/record (no cache).
    pub cache: Option<Arc<AgentCache>>,
    /// Where per-action trace dirs are created (only used when `cache` is set).
    pub scratch_root: PathBuf,
    /// The daemon's session registry (ADR 0013). Intake `create`s a session right
    /// before dispatching a VFS action — binding the agent-authoritative scope
    /// root the file server will enforce against the worker's Hello session id —
    /// and `finish`es it when the action returns. Shared (`Arc`) with the file
    /// server so both planes see the same sessions.
    pub registry: Arc<SessionRegistry>,
}

/// The LocalIntake gRPC service. Wraps the daemon's [`Scheduler`]; every
/// submitted action is dispatched (affinity → least-loaded → local fallback)
/// and its terminal outcome is mirrored back as a [`SubmitActionEvent`] stream.
#[derive(Clone)]
pub struct IntakeService {
    scheduler: Scheduler,
    /// Per-daemon action counter. It names the per-action `trace-{n}` dir and the
    /// `action_id` (the abort key) — the *reproducible* identifiers, kept clock-
    /// and RNG-free so the daemon's on-disk artifacts and cache keys (which key on
    /// content/argv, never on these ids) stay stable run to run. The `session_id`
    /// is deliberately NOT derived from this counter: it must be unpredictable
    /// (ADR 0013 / PROTO-001), so it is minted from the OS CSPRNG instead. That is
    /// safe for reproducibility because `session_id` names no artifact and enters
    /// no cache key or build output — only the in-memory/wire data-plane session.
    seq: Arc<AtomicU64>,
    /// Read-VFS + cache context; `None` → plain dispatch (M6.0/tests).
    vfs: Option<Arc<IntakeVfsContext>>,
    /// Daemon-wide counters (M9.1): every submission feeds cache hit/miss, the
    /// remote/local/fallback exec breakdown, and the in-flight gauge here. The
    /// daemon hands the same `Arc` to the Status service via [`Self::metrics`].
    metrics: Arc<Metrics>,
    task_scope: Option<DaemonTaskScope>,
    tracker: ActionTracker,
    authority: IntakeAuthority,
}

#[derive(Clone, Copy, Debug)]
enum IntakeAuthority {
    TrustedCurrentProcess,
    #[cfg(windows)]
    AuthenticatedCaller,
}

impl IntakeAuthority {
    fn execution_context<T>(self, request: &Request<T>) -> Result<LocalExecutionContext, Status> {
        match self {
            Self::TrustedCurrentProcess => Ok(LocalExecutionContext::CurrentProcess),
            #[cfg(windows)]
            Self::AuthenticatedCaller => {
                let connect_info = request
                    .extensions()
                    .get::<CallerIdentityConnectInfo>()
                    .ok_or_else(|| Status::unauthenticated("caller identity is missing"))?;
                let identity = connect_info
                    .caller_identity()
                    .map_err(|error| {
                        Status::unauthenticated(format!("caller authentication failed: {error}"))
                    })?
                    .ok_or_else(|| Status::unauthenticated("caller identity is not established"))?;
                Ok(LocalExecutionContext::AuthenticatedCaller(identity))
            }
        }
    }
}

/// Mints an unpredictable 128-bit data-plane session id as 32 lowercase hex
/// chars from the OS CSPRNG (ADR 0013 / PROTO-001). Unlike `action_id` /
/// `trace-{n}` it is deliberately non-reproducible: guessability is exactly the
/// threat it closes, so an attacker must capture a live session id rather than
/// predict the next one. It names no artifact and enters no cache key or build
/// output, so making it random does not affect the daemon's reproducibility.
fn mint_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable while minting a session id");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl IntakeService {
    /// Plain intake: submissions are dispatched directly (no VFS, no cache).
    pub fn new(scheduler: Scheduler) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
            vfs: None,
            metrics: Arc::new(Metrics::default()),
            task_scope: None,
            tracker: ActionTracker::default(),
            authority: IntakeAuthority::TrustedCurrentProcess,
        }
    }

    /// Intake front door used by the authenticated Windows named-pipe server.
    /// Requests without pipe-established caller identity fail before submission
    /// ids, sessions, scratch paths, or commands can be created.
    #[cfg(all(windows, test))]
    pub(crate) fn authenticated(scheduler: Scheduler) -> Self {
        let mut service = Self::new(scheduler);
        service.require_authenticated_caller();
        service
    }

    #[cfg(windows)]
    pub(crate) fn require_authenticated_caller(&mut self) {
        self.authority = IntakeAuthority::AuthenticatedCaller;
    }

    /// Intake that runs submissions under the read-VFS (and the action cache when
    /// `ctx.cache` is set) — the production daemon's compile front door (M6.1).
    pub fn with_vfs(scheduler: Scheduler, ctx: IntakeVfsContext) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
            vfs: Some(Arc::new(ctx)),
            metrics: Arc::new(Metrics::default()),
            task_scope: None,
            tracker: ActionTracker::default(),
            authority: IntakeAuthority::TrustedCurrentProcess,
        }
    }

    /// Production daemon constructor: submission tasks share the daemon's owned
    /// descendant scope with file-supply connections and requests.
    #[allow(dead_code)] // Backward-compatible internal wrapper for existing callers.
    pub(crate) fn with_vfs_tracked(
        scheduler: Scheduler,
        ctx: IntakeVfsContext,
        task_scope: DaemonTaskScope,
    ) -> Self {
        Self::with_vfs_tracked_and_tracker(scheduler, ctx, task_scope, ActionTracker::default())
    }

    pub(crate) fn with_vfs_tracked_and_tracker(
        scheduler: Scheduler,
        ctx: IntakeVfsContext,
        task_scope: DaemonTaskScope,
        tracker: ActionTracker,
    ) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
            vfs: Some(Arc::new(ctx)),
            metrics: Arc::new(Metrics::default()),
            task_scope: Some(task_scope),
            tracker,
            authority: IntakeAuthority::TrustedCurrentProcess,
        }
    }

    /// The daemon-wide metrics this intake feeds. The daemon grabs this `Arc`
    /// after construction and hands it to the Status service, so the GUI reads the
    /// exact counters the action path increments (M9.1).
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }
}

#[tonic::async_trait]
impl LocalIntake for IntakeService {
    type SubmitActionStream = ReceiverStream<Result<SubmitActionEvent, Status>>;

    async fn submit_action(
        &self,
        request: Request<SubmitActionRequest>,
    ) -> Result<Response<Self::SubmitActionStream>, Status> {
        let execution_context = self.authority.execution_context(&request)?;
        let req = request.into_inner();
        let command = req
            .command
            .ok_or_else(|| Status::invalid_argument("SubmitActionRequest.command is required"))?;
        if command.argv.is_empty() {
            return Err(Status::invalid_argument("command.argv must be non-empty"));
        }

        // `n` names the per-action trace dir (reproducible); `action_id` is the
        // worker's abort key. `session_id` binds the data-plane file session and
        // is minted from the OS CSPRNG so it cannot be guessed (ADR 0013): an
        // attacker must capture a live session id, not predict the next one.
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let action_id = format!("intake-{n}");
        let session_id = mint_session_id();

        let (tx, rx) = mpsc::channel(8);
        let eof_lease = tx.clone();
        let submission = run_submission(
            self.scheduler.clone(),
            self.vfs.clone(),
            self.metrics.clone(),
            self.tracker.clone(),
            execution_context,
            command,
            req.declared_outputs,
            req.non_deterministic,
            req.strict_vfs,
            req.input_root,
            action_id,
            session_id,
            n,
            tx,
        );
        if let Some(scope) = &self.task_scope {
            let deadline = Arc::new(SubmissionDeadline::new());
            #[cfg(test)]
            if let Some(observer) = NEXT_SUBMISSION_DEADLINE.with(|slot| slot.borrow_mut().take()) {
                let _ = observer.send(Arc::clone(&deadline));
            }
            let wrapped = hold_eof_until_submission_is_safe(
                Arc::clone(&deadline),
                crate::with_submission_deadline(Arc::clone(&deadline), submission),
                eof_lease,
            );
            if !scope.spawn_drain(deadline, wrapped) {
                return Err(Status::unavailable("daemon is shutting down"));
            }
        } else {
            drop(eof_lease);
            tokio::spawn(submission);
        }
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// COR-004: the toolchain basenames whose byte-reproducibility the M2 determinism
/// harness proves (ADR 0007 §c) — the verified-deterministic cache profile. Only
/// these (plus any operator opt-ins) are RECORDED to the action cache by default; an
/// arbitrary tool is distributed but never cached, because its output can depend on
/// vectors the action key does not cover (registry values, directory enumeration,
/// read-modify-write pre-state, system time/locale/codepage, …). Caching those by
/// default would risk a stale hit.
const VERIFIED_TOOLS: &[&str] = &["cl", "clang-cl", "clang", "clang++", "dxc"];

/// Whether `argv0`'s toolchain is in the verified-deterministic cache profile
/// ([`VERIFIED_TOOLS`], matched on the case-insensitive, extension-stripped
/// basename) or opted in by the operator via the comma-separated
/// `SEMBAZURU_VERIFIED_TOOLS` env var. A bare `cl`, an absolute `C:\…\clang-cl.exe`,
/// and `clang-cl` all match `clang-cl`/`cl`.
/// This check matches tool NAME (basename) only, not a verified binary identity
/// from M2 byte-reproducibility. It is sound in homogeneous/LAN-trusted
/// environments because, whenever `argv0` resolves to a real file — the normal
/// case, including a real `cl.exe` *or* a `cl.bat`/`cl.cmd` shim, since resolution
/// is extension-agnostic (`candidate_with_exe` checks `is_file()` before adding
/// `.exe`) — the weak_key folds that file's content digest: a same-named tool with
/// different bytes yields a different key and cannot pollute existing entries or be
/// served stale. The residual is an `argv0` that resolves to NO real file (e.g. a
/// bare name absent from PATH): `toolchain_digest` then falls back to a content-blind
/// name-constant, so a name-verified-but-unresolvable tool would be keyed by name
/// alone. Heterogeneous worker != agent identity closure is deferred to COR-005
/// worker re-verification.
fn is_verified_tool(argv0: &str) -> bool {
    if argv0.is_empty() {
        return false;
    }
    let base = std::path::Path::new(argv0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0)
        .to_ascii_lowercase();
    VERIFIED_TOOLS.contains(&base.as_str())
        || std::env::var("SEMBAZURU_VERIFIED_TOOLS")
            .ok()
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(&base)))
}

fn worker_tool_matches(reported: &str, expected: &Digest) -> bool {
    !reported.is_empty() && reported == expected.to_string()
}

fn should_record_cache(
    tool_verified: bool,
    agent_identity: &ToolchainIdentity,
    worker_reported_digest: &str,
) -> bool {
    tool_verified
        && agent_identity.is_content()
        && worker_tool_matches(worker_reported_digest, agent_identity.digest())
}

fn declared_output_specs(declared_outputs: &[String], root: Option<&str>) -> Vec<OutputSpec> {
    declared_outputs
        .iter()
        .filter_map(|p| crate::fileserver::normalize_declared_output(p, root))
        .enumerate()
        .map(|(id, normalized)| OutputSpec {
            id: id as u32,
            final_path: PathBuf::from(normalized),
            max_size: DEFAULT_OUTPUT_MAX_BYTES,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn publish_remote_or_fallback(
    outcome: Execution,
    cap: &SessionCapability,
    fallback_command: &Command,
    execution_context: &LocalExecutionContext,
    tracker: &ActionTracker,
    action_id: &str,
    attempt_no: u32,
    display: &str,
) -> Execution {
    if let Execution::Remote(o) = &outcome
        && o.exit_code == Some(0)
        && let Err(e) = cap.publish_staged().await
    {
        eprintln!("sembazuru-agent: publishing staged outputs failed: {e}");
        let detail = format!("remote writeback publish failed: {e}");
        let mut tracked = tracker.begin_attempt_lease(
            action_id,
            attempt_no,
            "local",
            ExecutionKind::Fallback,
            display,
        );
        if let Some(lease) = &tracked {
            lease.transition(ActivityState::Running);
        }
        let exit_code = run_local_with_context(fallback_command, execution_context)
            .await
            .unwrap_or(-1);
        if let Some(lease) = &mut tracked {
            lease.finish(if exit_code == 0 {
                ActivityState::Completed
            } else {
                ActivityState::Failed
            });
        }
        return Execution::LocalFallback {
            exit_code,
            reason: LocalFallbackReason::RemoteExhausted(detail),
        };
    }
    outcome
}

/// Drives one submission to completion and mirrors its terminal events. Without
/// a VFS context this is a plain dispatch (M6.0). With one, the compile runs
/// under the read-VFS; with a cache it is resolved first (a hit skips the worker)
/// and recorded after a successful run so the next identical build hits.
#[allow(clippy::too_many_arguments, clippy::collapsible_if)]
async fn run_submission(
    scheduler: Scheduler,
    vfs: Option<Arc<IntakeVfsContext>>,
    metrics: Arc<Metrics>,
    tracker: ActionTracker,
    execution_context: LocalExecutionContext,
    command: Command,
    declared_outputs: Vec<String>,
    non_deterministic: bool,
    strict_vfs: bool,
    input_root: String,
    action_id: String,
    session_id: String,
    n: u64,
    tx: mpsc::Sender<Result<SubmitActionEvent, Status>>,
) {
    // Counts this action toward the in-flight gauge until it terminates — every
    // return path below (cache hit, plain dispatch, VFS dispatch) drops it (M9.1).
    let _in_flight = metrics.in_flight_guard();
    let display = display_name(&command);

    let Some(ctx) = vfs else {
        // Plain dispatch (M6.0 / tests): no VFS config, no cache.
        let observed = scheduler
            .dispatch_observed_with_context(
                command,
                action_id,
                session_id,
                ExecOptions::default(),
                display,
                &execution_context,
            )
            .await;
        metrics.record_outcome(&observed.execution);
        emit_outcome(&tx, observed.execution).await;
        return;
    };

    // The action's effective build root for the cache: the declared input root
    // (so the relativize/anchor/publish root spans obj\ and bin\ in one tree),
    // or the command's cwd when none is declared. The *same* value roots both
    // record (relativize) and resolve (publish), so the two stay symmetric
    // (BLOCK-B). `root_decl` is the normalized-once override threaded into the
    // trace adapters; `None` falls back to the run's cwd inside the adapter.
    // Normalize the declared input root EXACTLY ONCE; this single value roots
    // relativize/anchor (record), publish (resolve), and the trace adapters, so
    // the gate and the `build_root.join(logical)` write use the identical string
    // (closes the record/resolve asymmetry — BLOCK-B, ADR 0007 §b). Trimmed the
    // same way `effective_root` trims, so a whitespace-only value falls back to
    // cwd consistently on both sides.
    let root_decl: Option<String> = {
        let t = input_root.trim();
        (!t.is_empty()).then(|| sembazuru_tracer::normalize_for_compare(t))
    };
    let build_root = match &root_decl {
        Some(r) => PathBuf::from(r),
        None => PathBuf::from(&command.cwd),
    };

    // COR-004: only a VERIFIED-deterministic toolchain — one whose byte-reproducibility
    // the M2 determinism harness proves (ADR 0007 §c) — is cacheable BY DEFAULT. An
    // unknown/arbitrary tool is still DISTRIBUTED (correctness via local fallback is
    // unaffected) but NEVER RECORDED: its output can depend on vectors the action key
    // does not cover (registry values, directory enumeration, read-modify-write
    // pre-state, system time/locale, …, see COR-004), so caching it by default risks a
    // stale hit. An operator opts a known-good tool in via `SEMBAZURU_VERIFIED_TOOLS`.
    let argv0 = command.argv.first().cloned().unwrap_or_default();
    let tool_verified = is_verified_tool(&argv0);

    // The weak key keys resolve, predicted_paths, and record. Computed off the
    // async runtime: weak_key_and_tool hashes the toolchain binary from disk.
    let (weak, agent_tool_identity) = match &ctx.cache {
        Some(cache) => {
            let cache = cache.clone();
            let argv = command.argv.clone();
            let cwd = command.cwd.clone();
            let mut env: Vec<(String, String)> = command
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            env.sort();
            match tokio::task::spawn_blocking(move || cache.weak_key_and_tool(&argv, &env, &cwd))
                .await
            {
                Ok((weak, identity)) => (Some(weak), Some(identity)),
                Err(_) => (None, None),
            }
        }
        None => (None, None),
    };

    // Cache resolve: a hit republishes the outputs and skips the worker entirely.
    if let (Some(cache), Some(weak)) = (&ctx.cache, &weak) {
        let cache = cache.clone();
        let weak = weak.clone();
        let br = build_root.clone();
        match tokio::task::spawn_blocking(move || cache.resolve(&weak, &br)).await {
            Ok(Ok(CacheLookup::Hit {
                exit_code,
                stdout,
                stderr,
            })) => {
                metrics.record_cache_hit();
                let _ = tx
                    .send(Ok(state_ev(ActionState::Completed, "cache hit")))
                    .await;
                // Replay the recorded compiler console output before exiting, so a
                // cached build shows the same diagnostics (warnings, notes) a fresh
                // run did — exactly as the remote run path forwards them (COR-007).
                if !stdout.is_empty() {
                    let _ = tx.send(Ok(stdio_ev(false, stdout))).await;
                }
                if !stderr.is_empty() {
                    let _ = tx.send(Ok(stdio_ev(true, stderr))).await;
                }
                let _ = tx.send(Ok(exit_ev(exit_code, 0))).await;
                return;
            }
            // A miss, a resolve error, or a join error all mean "run the action":
            // the cache was consulted and did not serve it, so count one miss.
            _ => metrics.record_cache_miss(),
        }
    }

    // The declared input root scopes the worker's reads (M8.3); empty = cwd, the
    // compiler default (the project tree is the cwd). An arbitrary process may
    // read above its cwd, so the integration can declare a broader root. Single-
    // machine: anything outside resolves to the same local bytes (fail-open);
    // strict mode + a too-narrow root would fail-close those reads, which is why
    // the root is declarable. As of ADR 0013 this same value is the AGENT-
    // AUTHORITATIVE scope root registered for the session, so the file server
    // scopes supply to the agent's value, NOT whatever the worker declares.
    let vfs_root = if input_root.is_empty() {
        command.cwd.clone()
    } else {
        input_root.clone()
    };
    let normalized_vfs_root = crate::fileserver::normalize_root(&vfs_root);

    // Prior build's inputs to warm ahead of process I/O (M5.4 prefetch).
    let predicted_paths = match (&ctx.cache, &weak) {
        (Some(cache), Some(weak)) => {
            let cache = cache.clone();
            let weak = weak.clone();
            let root = normalized_vfs_root.clone();
            tokio::task::spawn_blocking(move || cache.predicted_paths(&weak, root.as_deref()))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };

    // Per-action trace dir (only needed when recording to the cache). The worker
    // points the injected DLL's trace at it; on a single machine the daemon reads
    // it back to build the input manifest (VfsExecution.trace_dir is single-
    // machine-only, see control.proto).
    let trace_dir = if ctx.cache.is_some() {
        let d = ctx.scratch_root.join(format!("trace-{n}"));
        let _ = tokio::fs::create_dir_all(&d).await;
        d.to_string_lossy().into_owned()
    } else {
        String::new()
    };

    let opts = ExecOptions {
        predicted_paths,
        vfs: Some(VfsExecution {
            agent_fileserver: ctx.agent_fileserver.clone(),
            vfs_root: vfs_root.clone(),
            trace_dir: trace_dir.clone(),
            strict: strict_vfs,
            allow_original_cwd: false,
        }),
    };

    // Open the agent-authoritative session BEFORE dispatch (ADR 0013), so the
    // worker's Hello — carrying this session_id — finds it and binds to the
    // agent's scope root + per-session pin partition + allowed-digest ACL +
    // normalized output-id authority. Trace-discovered outputs are cache record
    // inputs only; they do not grant WriteBack authority (SEC-003).
    let outputs = declared_output_specs(&declared_outputs, normalized_vfs_root.as_deref());
    let cap = ctx
        .registry
        .create(session_id.clone(), normalized_vfs_root, outputs)
        .await;
    #[cfg(test)]
    wait_at_submission_barrier().await;
    #[cfg(test)]
    if PANIC_NEXT_SUBMISSION_AFTER_CREATE.with(|panic| panic.replace(false)) {
        panic!("injected submission panic after session create");
    }

    let fallback_command = command.clone();
    let observed = scheduler
        .dispatch_observed_with_context(
            command,
            action_id.clone(),
            session_id.clone(),
            opts,
            display.clone(),
            &execution_context,
        )
        .await;

    // dispatch() returns only after the worker's terminal Execute event (after
    // the child exits): the action is done and no legitimate data-plane op
    // remains. Finish before cache record/publish so lingering/detached
    // connections cannot run late post-processing ops, future 2-machine
    // WriteBack cannot race cache record/publish, the ADD-001 closed gate
    // rejects any late detached read, and the idle sweeper stays a crash backstop.
    ctx.registry.finish(&session_id).await;
    let outcome = publish_remote_or_fallback(
        observed.execution,
        &cap,
        &fallback_command,
        &execution_context,
        &tracker,
        &action_id,
        observed.next_attempt_no,
        &display,
    )
    .await;
    cap.discard_staged().await;

    // Record a successful remote run so the next identical build hits. Needs the
    // trace (from the DLL); the outputs come from the launcher's declaration when
    // it had one, else they are discovered from the trace itself (ADR 0007 §b —
    // the compiler-independent path, so dxc and other verified non-clang-cl tools
    // cache too). Recording is gated on: the action declared deterministic
    // (`!non_deterministic`, ADR 0007 §c — else a later byte-identical-input hit
    // would serve a stale result) AND its toolchain is a VERIFIED profile
    // (`tool_verified`, COR-004 — an arbitrary tool is distributed but not cached).
    // Without a trace or any discoverable output, recording is skipped (the build
    // is still correct, just uncached).
    if let (Some(cache), Some(weak), Some(identity)) = (&ctx.cache, &weak, &agent_tool_identity)
        && let Execution::Remote(o) = &outcome
        && o.exit_code == Some(0)
        && !trace_dir.is_empty()
        && !non_deterministic
        && tool_verified
    {
        if should_record_cache(tool_verified, identity, &o.resolved_tool_digest) {
            let cache = cache.clone();
            let weak = weak.clone();
            let br = build_root.clone();
            let declared = declared_outputs.clone();
            let td = trace_dir.clone();
            let rd = root_decl.clone();
            let identity = (*identity).clone();
            // The remote run's console output, captured so a later hit replays the same
            // diagnostics (COR-007). Cloned (not moved) — `outcome` is still emitted below.
            let rec_stdout = o.stdout.clone();
            let rec_stderr = o.stderr.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let root = rd.as_deref();
                let outs: Vec<String> = if !declared.is_empty() {
                    declared
                } else {
                    cache.outputs_from_trace_dir(&td, root).unwrap_or_default()
                };
                // record() self-gates on manifest.cacheable (input-side fail-closed)
                // and on each output staying under the build root, so a manifest that
                // could not cover a real source, or an out-of-scope output, simply
                // does not get stored — the build stays correct, just uncached.
                if !outs.is_empty()
                    && let Ok(manifest) =
                        cache.manifest_from_trace_dir_verified_tool(&td, root, &identity)
                {
                    let _ = cache.record(&weak, &manifest, &br, &outs, 0, &rec_stdout, &rec_stderr);
                }
            })
            .await;
        } else if identity.is_content() {
            eprintln!(
                "sembazuru-agent: heterogeneous toolchain digest mismatch for argv[0]={:?}; \
                 worker reported {:?}, agent expected {}; skipping cache record",
                argv0,
                o.resolved_tool_digest,
                identity.digest()
            );
            metrics.record_compiler_digest_mismatch();
        } else {
            eprintln!(
                "sembazuru-agent: verified tool {:?} did not resolve to a file; \
                 skipping cache record (name-only identity)",
                argv0
            );
        }
    }

    // Remove this action's trace dir now that the manifest has been ingested
    // (deferred #8 / M9.2). Previously every traced submission left a `trace-{n}`
    // dir under SEMBAZURU_TRACE_ROOT for the daemon's whole life — the agent-side
    // monotonic disk grower. It is created whenever a cache is configured, so it
    // is cleaned regardless of whether recording ran (a non-deterministic action
    // skips recording but still made the dir). Best-effort: a uniquely-named
    // residual dir is harmless, so a failure is not fatal.
    if !trace_dir.is_empty() {
        let _ = tokio::fs::remove_dir_all(&trace_dir).await;
    }

    metrics.record_outcome(&outcome);
    if crate::current_submission_deadline().is_some_and(|deadline| {
        !matches!(
            deadline.phase(),
            SubmissionPhase::Idle | SubmissionPhase::NaturalReaped
        )
    }) {
        return;
    }
    emit_outcome(&tx, outcome).await;
}

/// Mirrors a dispatch outcome as the terminal events. dispatch always completes
/// (remote or local fallback), so there is always an exit code. For a remote run
/// the compiler's captured stdout/stderr are forwarded first so the launcher can
/// replay them before exiting (M6.1). A local fallback inherits the developer's
/// console directly, so there is nothing to forward.
async fn emit_outcome(tx: &mpsc::Sender<Result<SubmitActionEvent, Status>>, outcome: Execution) {
    let (code, wall, note) = match outcome {
        Execution::Remote(o) => {
            if !o.stdout.is_empty() {
                let _ = tx.send(Ok(stdio_ev(false, o.stdout))).await;
            }
            if !o.stderr.is_empty() {
                let _ = tx.send(Ok(stdio_ev(true, o.stderr))).await;
            }
            (
                o.exit_code.unwrap_or(-1),
                o.wall_time_us,
                "remote".to_string(),
            )
        }
        Execution::LocalFallback { exit_code, reason } => {
            (exit_code, 0, format!("local fallback: {reason}"))
        }
    };
    let _ = tx.send(Ok(state_ev(ActionState::Completed, &note))).await;
    let _ = tx.send(Ok(exit_ev(code, wall))).await;
}

/// Resolves `addr` for a **loopback-only** listener, refusing any non-loopback
/// address. Used by the two same-machine planes: LocalIntake (executes arbitrary
/// submitted commands, unauthenticated until M7 — `SEMBAZURU_INTAKE=0.0.0.0:…`
/// would expose remote command execution, security-reviewer M6.0 MEDIUM) and the
/// Status surface (operational state for a same-machine GUI, ADR 0008 §4).
/// Coordination and the file server are deliberately *not* guarded — they
/// legitimately need LAN reach for workers; these planes do not. `plane` names
/// the plane in error messages. Fails closed if *any* resolved address is
/// non-loopback (a hostname could resolve to both).
pub fn require_loopback(addr: &str, plane: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("invalid {plane} address {addr:?}: {e}"))?
        .collect();
    let first = resolved
        .first()
        .copied()
        .ok_or_else(|| format!("{plane} address {addr:?} resolved to no socket address"))?;
    if let Some(bad) = resolved.iter().find(|a| !a.ip().is_loopback()) {
        return Err(format!(
            "refusing to bind {plane} to non-loopback address {bad}: this plane is loopback-only \
             (same-machine access). Use a loopback address such as 127.0.0.1:<port>."
        ));
    }
    Ok(first)
}

/// Loopback guard for the LocalIntake listener (see [`require_loopback`]).
pub fn resolve_loopback_intake(addr: &str) -> Result<std::net::SocketAddr, String> {
    require_loopback(addr, "LocalIntake")
}

/// LocalIntake transport. Windows production accepts only the authenticated
/// named pipe; loopback TCP remains an explicit fixture/non-Windows transport.
#[derive(Clone, Debug)]
pub enum LocalIntakeTransport {
    /// Explicit loopback TCP fixture, and the non-Windows production transport.
    LoopbackTcp(SocketAddr),
    #[cfg(windows)]
    /// Protected Windows named pipe with mutual caller/server authentication.
    NamedPipe,
}

pub(crate) enum BoundLocalIntake {
    LoopbackTcp(TcpListener),
    #[cfg(windows)]
    NamedPipe(tokio::net::windows::named_pipe::NamedPipeServer),
}

impl LocalIntakeTransport {
    /// Explicit loopback TCP transport for non-Windows and test fixtures.
    pub fn loopback_tcp(addr: &str) -> Result<Self, String> {
        Ok(Self::LoopbackTcp(require_loopback(addr, "LocalIntake")?))
    }

    /// Validates a production daemon LocalIntake config.
    #[cfg(windows)]
    pub fn production_server(endpoint: &str) -> Result<Self, String> {
        if endpoint == crate::intake_pipe::PIPE_ENDPOINT {
            Ok(Self::NamedPipe)
        } else {
            Err(format!(
                "Windows LocalIntake must use {}; refusing legacy or unauthenticated endpoint {endpoint:?}",
                crate::intake_pipe::PIPE_ENDPOINT
            ))
        }
    }

    /// Non-Windows production keeps the loopback-only TCP transport.
    #[cfg(not(windows))]
    pub fn production_server(endpoint: &str) -> Result<Self, String> {
        Self::loopback_tcp(endpoint.strip_prefix("http://").unwrap_or(endpoint))
    }

    /// Client-side LocalIntake transport from the launcher's endpoint string.
    pub fn from_endpoint(endpoint: &str) -> Result<Self, String> {
        #[cfg(windows)]
        {
            Self::production_server(endpoint)
        }
        #[cfg(not(windows))]
        {
            let addr = endpoint.strip_prefix("http://").unwrap_or(endpoint);
            Self::loopback_tcp(addr)
        }
    }

    pub(crate) async fn bind(self) -> Result<BoundLocalIntake, std::io::Error> {
        match self {
            Self::LoopbackTcp(addr) => Ok(BoundLocalIntake::LoopbackTcp(
                TcpListener::bind(addr).await?,
            )),
            #[cfg(windows)]
            Self::NamedPipe => Ok(BoundLocalIntake::NamedPipe(
                crate::intake_pipe::create_server(true)?,
            )),
        }
    }

    /// Serve LocalIntake over this transport.
    pub async fn serve(
        self,
        service: IntakeService,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.bind().await? {
            BoundLocalIntake::LoopbackTcp(listener) => {
                serve_intake_service(listener, service).await
            }
            #[cfg(windows)]
            BoundLocalIntake::NamedPipe(first) => serve_named_pipe_service(first, service).await,
        }
    }

    /// Connect a launcher-side LocalIntake client over this transport.
    pub async fn connect(&self) -> Result<LocalIntakeClient<Channel>, ExecuteError> {
        match self {
            Self::LoopbackTcp(addr) => {
                let channel = Endpoint::from_shared(format!("http://{addr}"))
                    .map_err(ExecuteError::Transport)?
                    .connect_timeout(Duration::from_millis(500))
                    .connect()
                    .await
                    .map_err(ExecuteError::Transport)?;
                Ok(LocalIntakeClient::new(channel))
            }
            #[cfg(windows)]
            Self::NamedPipe => Ok(LocalIntakeClient::new(
                connect_named_pipe_with_opener(crate::intake_pipe::open_authenticated_client)
                    .await?,
            )),
        }
    }
}

#[cfg(windows)]
async fn connect_named_pipe_with_opener<F>(opener: F) -> Result<Channel, ExecuteError>
where
    F: Fn() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient>
        + Clone
        + Send
        + Sync
        + 'static,
{
    use hyper_util::rt::TokioIo;
    use tower::service_fn;

    Endpoint::from_static("http://localhost")
        .connect_timeout(Duration::from_millis(500))
        .connect_with_connector(service_fn(move |_uri: tonic::transport::Uri| {
            let opener = opener.clone();
            async move { opener().map(TokioIo::new) }
        }))
        .await
        .map_err(ExecuteError::Transport)
}

/// Serves a plain LocalIntake (no VFS, no cache) on an already-bound listener.
/// The daemon binds an explicit loopback port; tests bind an ephemeral one and
/// learn it before serving.
pub async fn serve_intake(
    listener: TcpListener,
    scheduler: Scheduler,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_intake_service(listener, IntakeService::new(scheduler)).await
}

/// Serves a caller-built [`IntakeService`] — used by the daemon to enable
/// read-VFS execution and the action cache ([`IntakeService::with_vfs`]).
pub async fn serve_intake_service(
    listener: TcpListener,
    service: IntakeService,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::local_intake_server::LocalIntakeServer;

    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(LocalIntakeServer::new(service))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

pub(crate) async fn serve_intake_service_with_shutdown(
    listener: TcpListener,
    service: IntakeService,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::local_intake_server::LocalIntakeServer;

    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(LocalIntakeServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown.cancelled_owned())
        .await?;
    Ok(())
}

#[cfg(windows)]
fn harden_named_pipe_service(mut service: IntakeService) -> IntakeService {
    service.require_authenticated_caller();
    service
}

#[cfg(windows)]
async fn serve_named_pipe_service(
    first: tokio::net::windows::named_pipe::NamedPipeServer,
    service: IntakeService,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::local_intake_server::LocalIntakeServer;

    let service = harden_named_pipe_service(service);
    tonic::transport::Server::builder()
        .add_service(LocalIntakeServer::new(service))
        .serve_with_incoming(crate::intake_pipe::AuthenticatedPipeIncoming::new(first))
        .await?;
    Ok(())
}

#[cfg(windows)]
pub(crate) async fn serve_named_pipe_service_with_shutdown(
    first: tokio::net::windows::named_pipe::NamedPipeServer,
    service: IntakeService,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_named_pipe_incoming_with_shutdown(
        crate::intake_pipe::AuthenticatedPipeIncoming::new(first),
        service,
        shutdown,
    )
    .await
}

#[cfg(windows)]
async fn serve_named_pipe_incoming_with_shutdown(
    incoming: crate::intake_pipe::AuthenticatedPipeIncoming,
    service: IntakeService,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::local_intake_server::LocalIntakeServer;

    let service = harden_named_pipe_service(service);
    tonic::transport::Server::builder()
        // Deliberately only LocalIntake. Status and its mutating admin RPCs stay
        // on the independently bound loopback Status listener.
        .add_service(LocalIntakeServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown.cancelled_owned())
        .await?;
    Ok(())
}

/// Launcher side: submit `command` to the daemon at `endpoint` and return the
/// exit code plus the daemon's terminal state note ("remote", "cache hit", or
/// "local fallback: …") once the stream closes. A transport/RPC error here is
/// exactly the signal the launcher turns into a local fallback (the daemon may be
/// down) — the build must still complete (DESIGN.md §2). The note is surfaced so
/// a developer (and the M6.1 gate) can see how the action ran.
pub async fn submit_to_daemon(
    endpoint: String,
    command: Command,
    opts: SubmitOptions,
) -> Result<(i32, String), ExecuteError> {
    let transport = LocalIntakeTransport::from_endpoint(&endpoint)
        .map_err(|e| ExecuteError::Rpc(Status::invalid_argument(e)))?;
    submit_with_transport(transport, command, opts).await
}

/// Explicit TCP seam for unit/integration fixtures. Production launchers call
/// [`submit_to_daemon`], which rejects TCP endpoints on Windows.
#[doc(hidden)]
pub async fn submit_to_loopback_fixture(
    endpoint: String,
    command: Command,
    opts: SubmitOptions,
) -> Result<(i32, String), ExecuteError> {
    let addr = endpoint.strip_prefix("http://").unwrap_or(&endpoint);
    let transport = LocalIntakeTransport::loopback_tcp(addr)
        .map_err(|e| ExecuteError::Rpc(Status::invalid_argument(e)))?;
    submit_with_transport(transport, command, opts).await
}

async fn submit_with_transport(
    transport: LocalIntakeTransport,
    command: Command,
    opts: SubmitOptions,
) -> Result<(i32, String), ExecuteError> {
    let mut client = transport.connect().await?;
    let request = SubmitActionRequest {
        command: Some(command),
        declared_outputs: opts.declared_outputs,
        non_deterministic: opts.non_deterministic,
        strict_vfs: opts.strict_vfs,
        input_root: opts.input_root,
    };
    let mut stream = client.submit_action(request).await?.into_inner();
    let mut exit_code: Option<i32> = None;
    let mut note = String::new();
    while let Some(ev) = stream.message().await? {
        match ev.event {
            Some(Event::Exit(e)) => exit_code = Some(e.exit_code),
            Some(Event::State(s)) if !s.detail.is_empty() => note = s.detail,
            Some(Event::Stdio(c)) => {
                // Replay the remote compiler's output to this launcher's console
                // so the developer sees diagnostics as if the build ran locally.
                use std::io::Write;
                if c.is_stderr {
                    let _ = std::io::stderr().write_all(&c.data);
                } else {
                    let _ = std::io::stdout().write_all(&c.data);
                }
            }
            _ => {}
        }
    }
    exit_code.map(|c| (c, note)).ok_or_else(|| {
        ExecuteError::Rpc(Status::internal(
            "daemon closed the stream with no exit status",
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use super::{
        IntakeService, IntakeVfsContext, LocalIntakeTransport, SubmissionBarrier, SubmitOptions,
        declared_output_specs, hold_eof_until_submission_is_safe, install_next_submission_barrier,
        is_verified_tool, mint_session_id, observe_next_submission_deadline,
        publish_remote_or_fallback, resolve_loopback_intake, serve_intake_service_with_shutdown,
        should_record_cache, submit_to_loopback_fixture, worker_tool_matches,
    };
    #[cfg(windows)]
    use super::{connect_named_pipe_with_opener, serve_named_pipe_incoming_with_shutdown};
    use crate::action_tracker::{ActionTracker, ActivityState, ExecutionKind};
    use crate::coordination::WorkerTable;
    use crate::scheduler::Scheduler;
    use crate::session_registry::{
        DaemonTaskScope, SessionRegistry, StagingTemp, SubmissionDeadline, SubmissionPhase,
        create_staging_temp,
    };
    use crate::status::Metrics;
    use crate::{Execution, LocalExecutionContext};
    use sembazuru_cas::Digest;
    use sembazuru_cas::toolchain::ToolchainIdentity;
    use sembazuru_proto::v0::local_intake_server::LocalIntake;
    use sembazuru_proto::v0::submit_action_event::Event;
    use sembazuru_proto::v0::{ActionState, Command, SubmitActionRequest};
    use tokio::net::TcpListener;
    use tokio_stream::StreamExt;

    #[cfg(windows)]
    #[tokio::test]
    async fn missing_caller_identity_rejects_before_side_effects() {
        let scheduler = Scheduler::new(WorkerTable::new(Duration::from_secs(60)));
        let service = IntakeService::authenticated(scheduler);
        let sentinel = std::env::temp_dir().join(format!(
            "sbz-missing-caller-identity-{}-sentinel",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&sentinel);

        let error = LocalIntake::submit_action(
            &service,
            tonic::Request::new(SubmitActionRequest {
                command: Some(Command {
                    argv: vec![
                        "cmd".into(),
                        "/D".into(),
                        "/S".into(),
                        "/C".into(),
                        format!("type nul > \"{}\"", sentinel.display()),
                    ],
                    env: Default::default(),
                    cwd: std::env::temp_dir().to_string_lossy().into_owned(),
                }),
                declared_outputs: Vec::new(),
                non_deterministic: false,
                strict_vfs: false,
                input_root: String::new(),
            }),
        )
        .await
        .expect_err("authenticated intake must reject a request without caller identity");

        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(service.seq.load(Ordering::Relaxed), 0);
        assert!(service.tracker.snapshot().is_empty());
        assert!(
            !sentinel.exists(),
            "rejected request ran its command before caller authentication"
        );
    }

    #[tokio::test]
    async fn outer_eof_lease_waits_after_inner_ok_until_natural_reaped() {
        let deadline = Arc::new(SubmissionDeadline::new());
        assert!(deadline.try_begin_setup());
        assert!(deadline.publish_active());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let gate_deadline = Arc::clone(&deadline);
        let gate = tokio::spawn(async move {
            hold_eof_until_submission_is_safe(gate_deadline, async {}, tx).await;
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "inner Ok released EOF while the local process was still Active"
        );
        assert!(deadline.publish_natural_reaped());
        gate.await.unwrap();
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn outer_eof_lease_never_releases_after_force_failed() {
        let deadline = Arc::new(SubmissionDeadline::new());
        assert!(deadline.try_begin_setup());
        assert!(deadline.publish_force_failed());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let gate_deadline = Arc::clone(&deadline);
        let gate = tokio::spawn(async move {
            hold_eof_until_submission_is_safe(gate_deadline, async {}, tx).await;
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "ForceFailed released EOF and allowed an unsafe retry"
        );
        gate.abort();
        assert!(gate.await.unwrap_err().is_cancelled());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn tracked_intake_drains_live_submission_and_rejects_late_submit() {
        let registry = Arc::new(SessionRegistry::new().unwrap());
        let scope = DaemonTaskScope::new();
        let scheduler = Scheduler::new(WorkerTable::new(Duration::from_secs(60)));
        let service = IntakeService::with_vfs_tracked(
            scheduler,
            IntakeVfsContext {
                agent_fileserver: "127.0.0.1:1".into(),
                cache: None,
                scratch_root: std::env::temp_dir(),
                registry: Arc::clone(&registry),
            },
            scope.clone(),
        );
        let request = || SubmitActionRequest {
            command: Some(Command {
                argv: vec!["cmd".into(), "/c".into(), "exit".into(), "0".into()],
                env: Default::default(),
                cwd: std::env::temp_dir().to_string_lossy().into_owned(),
            }),
            declared_outputs: Vec::new(),
            non_deterministic: false,
            strict_vfs: false,
            input_root: String::new(),
        };
        let dropped = Arc::new(AtomicBool::new(false));
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        install_next_submission_barrier(SubmissionBarrier {
            reached: reached_tx,
            release: release_rx,
            dropped: Arc::clone(&dropped),
        });

        let response = LocalIntake::submit_action(&service, tonic::Request::new(request()))
            .await
            .expect("tracked intake must accept a live submission");
        let mut stream = response.into_inner();
        reached_rx
            .await
            .expect("submission did not reach its post-create barrier");
        assert_eq!(registry.session_count().await, 1);

        scope.begin_shutdown();
        scope.wait_cancel().await;
        assert!(
            !dropped.load(Ordering::SeqCst),
            "begin_shutdown must not drop a drain-mode submission"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), scope.wait_drain())
                .await
                .is_err(),
            "drain completed before the live submission was released"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.next())
                .await
                .is_err(),
            "client stream completed before the live submission was released"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), scope.wait_drain())
            .await
            .expect("task scope did not drain the released submission");
        let mut exit_code = None;
        while let Some(event) = stream.next().await {
            if let Some(Event::Exit(exit)) = event.unwrap().event {
                exit_code = Some(exit.exit_code);
            }
        }
        registry.shutdown_sessions().await;
        assert_eq!(registry.session_count().await, 0);
        assert_eq!(registry.active_pin_count(), 0);

        let late = LocalIntake::submit_action(&service, tonic::Request::new(request())).await;
        registry.shutdown_sessions().await;
        let cleanup_registry = Arc::clone(&registry);
        tokio::task::spawn_blocking(move || cleanup_registry.shutdown_cleanup_blocking())
            .await
            .unwrap()
            .unwrap();

        assert!(
            dropped.load(Ordering::SeqCst),
            "released submission did not finish"
        );
        assert_eq!(
            exit_code,
            Some(0),
            "natural drain must preserve the real Exit"
        );
        let error = late.expect_err("closed task scope must reject a late submission");
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(registry.session_count().await, 0);
        assert_eq!(registry.active_pin_count(), 0);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn submission_panic_publishes_aborted_no_child_before_client_eof() {
        let registry = Arc::new(SessionRegistry::new().unwrap());
        let scope = DaemonTaskScope::new();
        let service = IntakeService::with_vfs_tracked(
            Scheduler::new(WorkerTable::new(Duration::from_secs(60))),
            IntakeVfsContext {
                agent_fileserver: "127.0.0.1:1".into(),
                cache: None,
                scratch_root: std::env::temp_dir(),
                registry: Arc::clone(&registry),
            },
            scope.clone(),
        );
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        observe_next_submission_deadline(deadline_tx);
        super::PANIC_NEXT_SUBMISSION_AFTER_CREATE.with(|panic| panic.set(true));
        let response = LocalIntake::submit_action(
            &service,
            tonic::Request::new(SubmitActionRequest {
                command: Some(Command {
                    argv: vec!["cmd".into(), "/c".into(), "exit".into(), "0".into()],
                    env: Default::default(),
                    cwd: std::env::temp_dir().to_string_lossy().into_owned(),
                }),
                declared_outputs: Vec::new(),
                non_deterministic: false,
                strict_vfs: false,
                input_root: String::new(),
            }),
        )
        .await
        .unwrap();
        let deadline = deadline_rx.await.unwrap();
        let mut stream = response.into_inner();
        let events = tokio::time::timeout(Duration::from_secs(5), async {
            let mut events = Vec::new();
            while let Some(event) = stream.next().await {
                events.push(event.unwrap());
            }
            events
        })
        .await
        .expect("panic did not produce a retry-safe EOF");

        assert!(events.is_empty(), "panic path must not publish a fake Exit");
        assert_eq!(deadline.phase(), SubmissionPhase::AbortedNoChild);
        scope.begin_shutdown();
        scope.wait_drain().await;
        registry.shutdown_sessions().await;
        let cleanup_registry = Arc::clone(&registry);
        tokio::task::spawn_blocking(move || cleanup_registry.shutdown_cleanup_blocking())
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn job_creation_failure_has_retry_safe_eof_without_fake_exit() {
        let _guard = crate::LOCAL_JOB_TEST_LOCK.lock().await;
        let registry = Arc::new(SessionRegistry::new().unwrap());
        let scope = DaemonTaskScope::new();
        let service = IntakeService::with_vfs_tracked(
            Scheduler::new(WorkerTable::new(Duration::from_secs(60))),
            IntakeVfsContext {
                agent_fileserver: "127.0.0.1:1".into(),
                cache: None,
                scratch_root: std::env::temp_dir(),
                registry: Arc::clone(&registry),
            },
            scope.clone(),
        );
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel();
        observe_next_submission_deadline(deadline_tx);
        let mut command = Command {
            argv: vec!["cmd".into(), "/c".into(), "exit".into(), "0".into()],
            env: Default::default(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        };
        let control = crate::local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.install(5);
        let response = LocalIntake::submit_action(
            &service,
            tonic::Request::new(SubmitActionRequest {
                command: Some(command),
                declared_outputs: Vec::new(),
                non_deterministic: false,
                strict_vfs: false,
                input_root: String::new(),
            }),
        )
        .await
        .unwrap();
        let deadline = deadline_rx.await.unwrap();
        let events = tokio::time::timeout(Duration::from_secs(5), async {
            response.into_inner().collect::<Vec<_>>().await
        })
        .await
        .expect("Job creation failure did not reach retry-safe EOF");

        assert!(
            events.is_empty(),
            "Job creation failure published fake events"
        );
        assert_eq!(deadline.phase(), SubmissionPhase::RetrySafeReaped);
        scope.begin_shutdown();
        scope.wait_drain().await;
        registry.shutdown_sessions().await;
        let cleanup_registry = Arc::clone(&registry);
        tokio::task::spawn_blocking(move || cleanup_registry.shutdown_cleanup_blocking())
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_intake_shutdown_drains_existing_rpc_before_server_join() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(SessionRegistry::new().unwrap());
        let scope = DaemonTaskScope::new();
        let service = IntakeService::with_vfs_tracked(
            Scheduler::new(WorkerTable::new(Duration::from_secs(60))),
            IntakeVfsContext {
                agent_fileserver: "127.0.0.1:1".into(),
                cache: None,
                scratch_root: std::env::temp_dir(),
                registry: Arc::clone(&registry),
            },
            scope.clone(),
        );
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let mut server = tokio::spawn(async move {
            serve_intake_service_with_shutdown(listener, service, server_shutdown)
                .await
                .unwrap();
        });
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        install_next_submission_barrier(SubmissionBarrier {
            reached: reached_tx,
            release: release_rx,
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let transport = LocalIntakeTransport::LoopbackTcp(addr);
        let mut client = transport.connect().await.unwrap();
        let mut stream = client
            .submit_action(SubmitActionRequest {
                command: Some(Command {
                    argv: vec!["cmd".into(), "/c".into(), "exit".into(), "0".into()],
                    env: Default::default(),
                    cwd: std::env::temp_dir().to_string_lossy().into_owned(),
                }),
                declared_outputs: Vec::new(),
                non_deterministic: false,
                strict_vfs: false,
                input_root: String::new(),
            })
            .await
            .unwrap()
            .into_inner();
        reached_rx.await.unwrap();

        scope.begin_shutdown();
        shutdown.cancel();
        scope.wait_cancel().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut server)
                .await
                .is_err(),
            "LocalIntake root returned before its accepted RPC completed"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.next())
                .await
                .is_err(),
            "client stream completed before the submission was released"
        );
        release_tx.send(()).unwrap();
        scope.wait_drain().await;
        let mut exit = None;
        while let Some(event) = stream.next().await {
            if let Some(Event::Exit(status)) = event.unwrap().event {
                exit = Some(status.exit_code);
            }
        }
        drop((stream, client));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("graceful LocalIntake root did not join")
            .unwrap();
        assert_eq!(exit, Some(0));

        registry.shutdown_sessions().await;
        let cleanup_registry = Arc::clone(&registry);
        tokio::task::spawn_blocking(move || cleanup_registry.shutdown_cleanup_blocking())
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn verified_tool_profile_matches_compilers_only() {
        // COR-004: bare / absolute / extension / case forms of the verified-
        // deterministic compilers match; an arbitrary tool does NOT (→ distributed
        // but never recorded, so its un-keyed vectors can't serve a stale hit).
        assert!(is_verified_tool("cl"));
        assert!(is_verified_tool("clang-cl"));
        assert!(is_verified_tool("dxc"));
        assert!(is_verified_tool(
            "C:\\Program Files\\LLVM\\bin\\clang-cl.exe"
        ));
        assert!(is_verified_tool("CLANG++"), "case-insensitive");
        assert!(
            !is_verified_tool("python"),
            "arbitrary tool is not verified"
        );
        assert!(!is_verified_tool("my-custom-codegen.exe"));
        assert!(!is_verified_tool(""));
    }

    #[test]
    fn verified_tool_honors_operator_opt_in() {
        // An operator verifies their own known-good tool via the env var (COR-004).
        let key = "SEMBAZURU_VERIFIED_TOOLS";
        assert!(!is_verified_tool("my-codegen"));
        // SAFETY: a uniquely-named var not touched by other tests; set, assert, clear.
        unsafe { std::env::set_var(key, "my-codegen, other-tool") };
        let opted = is_verified_tool("my-codegen") && is_verified_tool("C:\\x\\OTHER-TOOL.exe");
        unsafe { std::env::remove_var(key) };
        assert!(
            opted,
            "SEMBAZURU_VERIFIED_TOOLS opts a tool into the cache profile"
        );
        assert!(
            !is_verified_tool("my-codegen"),
            "removed → no longer verified"
        );
    }

    #[test]
    fn path_corpus_declared_output_specs_keep_short_alias_root_prefix() {
        let root = crate::fileserver::normalize_root(
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root",
        )
        .expect("root");
        let declared_outputs = vec![
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\obj\\out.obj".to_string(),
            "C:\\Users\\<user>\\AppData\\Local\\Temp\\sbz-dp-root\\PROGRA~1\\tool.obj"
                .to_string(),
        ];

        let specs = declared_output_specs(&declared_outputs, Some(&root));

        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].final_path,
            std::path::PathBuf::from(
                "c:\\users\\kingka~1\\appdata\\local\\temp\\sbz-dp-root\\obj\\out.obj"
            )
        );
    }

    #[test]
    fn worker_tool_match_requires_reported_digest() {
        let expected = sembazuru_cas::Digest::of(b"agent-tool");
        assert!(worker_tool_matches(&expected.to_string(), &expected));
        assert!(!worker_tool_matches(
            &sembazuru_cas::Digest::of(b"worker-tool").to_string(),
            &expected
        ));
        assert!(!worker_tool_matches("", &expected));

        let metrics = Metrics::default();
        if !worker_tool_matches("", &expected) {
            metrics.record_compiler_digest_mismatch();
        }
        assert_eq!(metrics.compiler_digest_mismatch.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn verified_tool_unresolved_is_not_recorded() {
        let d = sembazuru_cas::Digest::of(b"toolchain-name:cl");
        let identity = ToolchainIdentity::NameOnly {
            digest: d.clone(),
            argv0: "cl".into(),
        };

        assert!(!should_record_cache(true, &identity, &d.to_string()));
    }

    #[test]
    fn verified_tool_resolved_file_is_recorded() {
        let d = sembazuru_cas::Digest::of(b"real-cl-bytes");
        let identity = ToolchainIdentity::Content {
            digest: d.clone(),
            path: "C:/x/cl.exe".into(),
        };

        assert!(should_record_cache(true, &identity, &d.to_string()));
    }

    #[test]
    fn worker_nameonly_identity_skips_record() {
        let agent = sembazuru_cas::Digest::of(b"agent-content-tool");
        let worker = sembazuru_cas::Digest::of(b"toolchain-name:cl");
        let identity = ToolchainIdentity::Content {
            digest: agent,
            path: "C:/x/cl.exe".into(),
        };

        assert!(!should_record_cache(true, &identity, &worker.to_string()));
    }

    #[test]
    fn agent_worker_tool_identity_mismatch_skips_record() {
        let agent = sembazuru_cas::Digest::of(b"agent-content-tool");
        let worker = sembazuru_cas::Digest::of(b"worker-content-tool");
        let identity = ToolchainIdentity::Content {
            digest: agent,
            path: "C:/x/cl.exe".into(),
        };

        assert!(!should_record_cache(true, &identity, &worker.to_string()));
    }

    #[test]
    fn unverified_resolved_file_is_not_recorded() {
        let d = sembazuru_cas::Digest::of(b"real-cl-bytes");
        let identity = ToolchainIdentity::Content {
            digest: d.clone(),
            path: "C:/x/cl.exe".into(),
        };

        assert!(!should_record_cache(false, &identity, &d.to_string()));
    }

    #[test]
    fn session_id_is_unpredictable_128_bit_hex() {
        // ADR 0013 / PROTO-001: a session id must be 32 lowercase hex chars (128
        // random bits) and must NOT be the old guessable `intake-{n}` form. Two
        // mints differing is a (probabilistic) proxy for "drawn from the CSPRNG,
        // not a counter" — equality would be a 1-in-2^128 event.
        let a = mint_session_id();
        let b = mint_session_id();
        assert_eq!(
            a.len(),
            32,
            "session id must be 32 hex chars (128 bits): {a:?}"
        );
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "session id must be lowercase hex: {a:?}"
        );
        assert!(
            !a.starts_with("intake-"),
            "session id must not be the guessable counter form"
        );
        assert_ne!(
            a, b,
            "two minted session ids must differ (drawn from the CSPRNG)"
        );
    }

    #[test]
    fn loopback_addresses_are_accepted() {
        assert!(resolve_loopback_intake("127.0.0.1:50071").is_ok());
        assert!(resolve_loopback_intake("127.0.0.1:0").is_ok());
        // IPv6 loopback.
        assert!(resolve_loopback_intake("[::1]:50071").is_ok());
    }

    #[test]
    fn non_loopback_addresses_are_refused() {
        // The wildcard bind is the dangerous one: it would expose unauthenticated
        // command execution to the whole network.
        assert!(resolve_loopback_intake("0.0.0.0:50071").is_err());
        assert!(resolve_loopback_intake("[::]:50071").is_err());
        // A specific routable address is also refused.
        assert!(resolve_loopback_intake("10.0.0.5:50071").is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn transport_from_endpoint_parses_loopback() {
        for endpoint in ["http://127.0.0.1:50071", "127.0.0.1:50071"] {
            let transport = LocalIntakeTransport::from_endpoint(endpoint)
                .expect("loopback endpoint should parse");
            match transport {
                LocalIntakeTransport::LoopbackTcp(addr) => {
                    assert_eq!(addr, "127.0.0.1:50071".parse().unwrap());
                }
            }
        }

        assert!(LocalIntakeTransport::from_endpoint("http://10.0.0.5:50071").is_err());
        assert!(LocalIntakeTransport::loopback_tcp("127.0.0.1:0").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_production_server_rejects_legacy_tcp_config() {
        let error = LocalIntakeTransport::production_server("127.0.0.1:50071")
            .expect_err("Windows production must not retain a TCP LocalIntake escape hatch");
        assert!(error.contains("npipe://Sembazuru.LocalIntake.v1"));
        assert!(
            LocalIntakeTransport::production_server("npipe://Sembazuru.LocalIntake.v1").is_ok()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_connector_propagates_authentication_failure() {
        let error = connect_named_pipe_with_opener(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "test rejected server SID",
            ))
        })
        .await
        .expect_err("connector must fail closed when server authentication fails");
        assert!(
            matches!(error, crate::ExecuteError::Transport(_)),
            "authentication refusal must surface as a transport error: {error:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_service_hardening_promotes_trusted_authority() {
        let service = IntakeService::new(Scheduler::new(WorkerTable::new(Duration::from_secs(60))));
        assert!(matches!(
            service.authority,
            super::IntakeAuthority::TrustedCurrentProcess
        ));

        let service = super::harden_named_pipe_service(service);
        assert!(matches!(
            service.authority,
            super::IntakeAuthority::AuthenticatedCaller
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_exposes_local_intake_but_not_status_or_admin() {
        use sembazuru_proto::v0::GetStatusRequest;
        use sembazuru_proto::v0::status_client::StatusClient;

        static PIPE_SEQ: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            r"\\.\pipe\Sembazuru.LocalIntake.v1.service-only.{}.{}",
            std::process::id(),
            PIPE_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let (incoming, server_sid) = crate::intake_pipe::test_incoming_at(name.clone()).unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let service = IntakeService::new(Scheduler::new(WorkerTable::new(Duration::from_secs(60))));
        let server = tokio::spawn(async move {
            serve_named_pipe_incoming_with_shutdown(incoming, service, server_shutdown)
                .await
                .unwrap();
        });

        let channel = connect_named_pipe_with_opener(move || {
            crate::intake_pipe::open_test_client_at(&name, &server_sid)
        })
        .await
        .unwrap();
        let error = StatusClient::new(channel)
            .get_status(GetStatusRequest {})
            .await
            .expect_err("Status/Admin must not be routed over LocalIntake pipe");
        assert_eq!(error.code(), tonic::Code::Unimplemented);

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("named-pipe LocalIntake server did not stop")
            .unwrap();
    }

    #[tokio::test]
    async fn transport_serve_and_connect_round_trips() {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = reserved.local_addr().unwrap();
        drop(reserved);

        let transport = LocalIntakeTransport::loopback_tcp(&addr.to_string()).unwrap();
        let scheduler = Scheduler::new(WorkerTable::new(Duration::from_secs(60)));
        let service = IntakeService::new(scheduler);
        let server_transport = transport.clone();
        let server = tokio::spawn(async move {
            server_transport.serve(service).await.unwrap();
        });

        let command = Command {
            argv: vec!["cmd".into(), "/c".into(), "exit".into(), "0".into()],
            env: Default::default(),
            cwd: String::new(),
        };
        let endpoint = format!("http://{addr}");
        let mut result = None;
        for _ in 0..20 {
            match submit_to_loopback_fixture(
                endpoint.clone(),
                command.clone(),
                SubmitOptions::default(),
            )
            .await
            {
                Ok(ok) => {
                    result = Some(ok);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
        server.abort();

        let (code, note) = result.expect("transport-backed intake should accept a submission");
        assert_eq!(code, 0);
        assert!(
            note.starts_with("local fallback:"),
            "empty worker table should dispatch via local fallback, got {note:?}"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn path_corpus_publish_failure_runs_local_fallback() {
        let reg = SessionRegistry::new().unwrap();
        let cap = reg
            .create("intake-publish-fallback".into(), None, Vec::new())
            .await;
        let root = std::env::temp_dir().join(format!(
            "sbz-intake-publish-fallback-{}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "sbz-intake-publish-fallback-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        let final_path = root.join("out.txt");
        let external_peer = outside.join("peer.txt");
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
        std::fs::hard_link(&external_peer, &staging_path)
            .expect("hardlink path-corpus evidence is required for intake publish fallback");

        let fallback_cmd = Command {
            argv: vec![
                "cmd".into(),
                "/C".into(),
                format!("echo fallback>{}", final_path.display()),
            ],
            env: Default::default(),
            cwd: String::new(),
        };
        let tracker = ActionTracker::default();
        let remote = tracker
            .begin_attempt(
                "publish-fallback",
                0,
                "w1",
                ExecutionKind::Remote,
                "main.cpp",
            )
            .unwrap();
        tracker.finish(&remote, ActivityState::Completed);
        let outcome = publish_remote_or_fallback(
            Execution::Remote(crate::ActionOutcome {
                states: vec![ActionState::Completed as i32],
                exit_code: Some(0),
                ..Default::default()
            }),
            &cap,
            &fallback_cmd,
            &LocalExecutionContext::CurrentProcess,
            &tracker,
            "publish-fallback",
            1,
            "main.cpp",
        )
        .await;

        match outcome {
            Execution::LocalFallback { reason, .. } => assert!(
                reason
                    .to_string()
                    .contains("remote writeback publish failed"),
                "publish failure must become a remote-exhausted local fallback, got {reason}"
            ),
            other => panic!("publish failure must replace remote success with fallback: {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&final_path).unwrap().trim(),
            "fallback"
        );
        let mut attempts = tracker.snapshot();
        attempts.sort_by_key(|attempt| attempt.key.attempt_no);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].execution_kind, ExecutionKind::Remote);
        assert_eq!(attempts[1].execution_kind, ExecutionKind::Fallback);
        assert_eq!(attempts[0].display_name, "main.cpp");
        assert_eq!(attempts[1].display_name, "main.cpp");
        assert!(attempts.iter().all(|attempt| attempt.state.is_terminal()));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
