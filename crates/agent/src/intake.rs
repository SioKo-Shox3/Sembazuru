//! LocalIntake (M6): the build-system launcher's entry into the agent daemon.
//!
//! A compiler launcher (`sembazuru <compiler> <args...>`, set as
//! `CMAKE_<LANG>_COMPILER_LAUNCHER` or an MSBuild `CLToolExe` shim) is a
//! short-lived process. It hands its one action to the long-lived daemon over
//! loopback; the daemon schedules it across workers (or runs it locally on
//! fallback) and streams the result back so the launcher exits exactly as the
//! compiler would have (`docs/protocol/v0.md` §3.2; see `LocalIntake` in
//! `control.proto`).
//!
//! This plane is loopback-only. Carrying the full command (not just an input
//! root) is safe here precisely because it never leaves the machine — the
//! launcher already has the command on its argv.

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
use crate::scheduler::Scheduler;
use crate::session_registry::{
    DEFAULT_OUTPUT_MAX_BYTES, OutputSpec, SessionCapability, SessionRegistry,
};
use crate::status::Metrics;
use crate::{ExecOptions, ExecuteError, Execution, LocalFallbackReason, run_local};

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
        }
    }

    /// Intake that runs submissions under the read-VFS (and the action cache when
    /// `ctx.cache` is set) — the production daemon's compile front door (M6.1).
    pub fn with_vfs(scheduler: Scheduler, ctx: IntakeVfsContext) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
            vfs: Some(Arc::new(ctx)),
            metrics: Arc::new(Metrics::default()),
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
        tokio::spawn(run_submission(
            self.scheduler.clone(),
            self.vfs.clone(),
            self.metrics.clone(),
            command,
            req.declared_outputs,
            req.non_deterministic,
            req.strict_vfs,
            req.input_root,
            action_id,
            session_id,
            n,
            tx,
        ));
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

async fn publish_remote_or_fallback(
    outcome: Execution,
    cap: &SessionCapability,
    fallback_command: &Command,
) -> Execution {
    if let Execution::Remote(o) = &outcome
        && o.exit_code == Some(0)
        && let Err(e) = cap.publish_staged().await
    {
        eprintln!("sembazuru-agent: publishing staged outputs failed: {e}");
        let detail = format!("remote writeback publish failed: {e}");
        let exit_code = run_local(fallback_command).await.unwrap_or(-1);
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

    let Some(ctx) = vfs else {
        // Plain dispatch (M6.0 / tests): no VFS config, no cache.
        let outcome = scheduler
            .dispatch(command, action_id, session_id, ExecOptions::default())
            .await;
        metrics.record_outcome(&outcome);
        emit_outcome(&tx, outcome).await;
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

    // Prior build's inputs to warm ahead of process I/O (M5.4 prefetch).
    let predicted_paths = match (&ctx.cache, &weak) {
        (Some(cache), Some(weak)) => {
            let cache = cache.clone();
            let weak = weak.clone();
            tokio::task::spawn_blocking(move || cache.predicted_paths(&weak))
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

    let opts = ExecOptions {
        predicted_paths,
        vfs: Some(VfsExecution {
            agent_fileserver: ctx.agent_fileserver.clone(),
            vfs_root: vfs_root.clone(),
            trace_dir: trace_dir.clone(),
            strict: strict_vfs,
        }),
    };

    // Open the agent-authoritative session BEFORE dispatch (ADR 0013), so the
    // worker's Hello — carrying this session_id — finds it and binds to the
    // agent's scope root + per-session pin partition + allowed-digest ACL +
    // normalized output-id authority. Trace-discovered outputs are cache record
    // inputs only; they do not grant WriteBack authority (SEC-003).
    let outputs: Vec<OutputSpec> = declared_outputs
        .iter()
        .filter_map(|p| crate::fileserver::normalize_requested(p))
        .enumerate()
        .map(|(id, normalized)| OutputSpec {
            id: id as u32,
            final_path: PathBuf::from(normalized),
            max_size: DEFAULT_OUTPUT_MAX_BYTES,
        })
        .collect();
    let cap = ctx
        .registry
        .create(
            session_id.clone(),
            crate::fileserver::normalize_root(&vfs_root),
            outputs,
        )
        .await;

    let fallback_command = command.clone();
    let outcome = scheduler
        .dispatch(command, action_id, session_id.clone(), opts)
        .await;

    // dispatch() returns only after the worker's terminal Execute event (after
    // the child exits): the action is done and no legitimate data-plane op
    // remains. Finish before cache record/publish so lingering/detached
    // connections cannot run late post-processing ops, future 2-machine
    // WriteBack cannot race cache record/publish, the ADD-001 closed gate
    // rejects any late detached read, and the idle sweeper stays a crash backstop.
    ctx.registry.finish(&session_id).await;
    let outcome = publish_remote_or_fallback(outcome, &cap, &fallback_command).await;
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
                    && let Ok(manifest) = cache.manifest_from_trace_dir(&td, root)
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

/// LocalIntake transport.
///
/// A Windows named-pipe variant with a caller-SID DACL lands in 4.3; this
/// preparatory abstraction keeps the M6 default TCP behavior unchanged.
#[derive(Clone, Debug)]
pub enum LocalIntakeTransport {
    /// Loopback TCP (the M6 default).
    LoopbackTcp(SocketAddr),
}

impl LocalIntakeTransport {
    /// Server-side loopback TCP transport from config such as `127.0.0.1:50071`.
    pub fn loopback_tcp(addr: &str) -> Result<Self, String> {
        Ok(Self::LoopbackTcp(require_loopback(addr, "LocalIntake")?))
    }

    /// Client-side LocalIntake transport from the launcher's endpoint string.
    pub fn from_endpoint(endpoint: &str) -> Result<Self, String> {
        let addr = endpoint.strip_prefix("http://").unwrap_or(endpoint);
        Ok(Self::LoopbackTcp(require_loopback(addr, "LocalIntake")?))
    }

    /// Serve LocalIntake over this transport.
    pub async fn serve(
        self,
        service: IntakeService,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::LoopbackTcp(addr) => {
                let listener = TcpListener::bind(addr).await?;
                serve_intake_service(listener, service).await
            }
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
        }
    }
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
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::{
        IntakeService, LocalIntakeTransport, SubmitOptions, is_verified_tool, mint_session_id,
        publish_remote_or_fallback, resolve_loopback_intake, should_record_cache, submit_to_daemon,
        worker_tool_matches,
    };
    use crate::Execution;
    use crate::coordination::WorkerTable;
    use crate::scheduler::Scheduler;
    use crate::session_registry::{SessionRegistry, StagingTemp, create_staging_temp};
    use crate::status::Metrics;
    use sembazuru_cas::Digest;
    use sembazuru_cas::toolchain::ToolchainIdentity;
    use sembazuru_proto::v0::{ActionState, Command};
    use tokio::net::TcpListener;

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
            match submit_to_daemon(endpoint.clone(), command.clone(), SubmitOptions::default())
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
        let outcome = publish_remote_or_fallback(
            Execution::Remote(crate::ActionOutcome {
                states: vec![ActionState::Completed as i32],
                exit_code: Some(0),
                ..Default::default()
            }),
            &cap,
            &fallback_cmd,
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

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
