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

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_proto::v0::{
    ActionState, Command, ExitStatus, OutputChunk, StateChange, SubmitActionEvent,
    SubmitActionRequest, VfsExecution, local_intake_client::LocalIntakeClient,
    local_intake_server::LocalIntake, submit_action_event::Event,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

use crate::action_cache::{AgentCache, CacheLookup};
use crate::scheduler::Scheduler;
use crate::session_registry::SessionRegistry;
use crate::status::Metrics;
use crate::{ExecOptions, ExecuteError, Execution};

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

/// Drives one submission to completion and mirrors its terminal events. Without
/// a VFS context this is a plain dispatch (M6.0). With one, the compile runs
/// under the read-VFS; with a cache it is resolved first (a hit skips the worker)
/// and recorded after a successful run so the next identical build hits.
#[allow(clippy::too_many_arguments)]
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

    // The weak key keys resolve, predicted_paths, and record. Computed off the
    // async runtime: weak_key hashes the toolchain binary from disk.
    let weak = match &ctx.cache {
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
            tokio::task::spawn_blocking(move || cache.weak_key(&argv, &env, &cwd))
                .await
                .ok()
        }
        None => None,
    };

    // Cache resolve: a hit republishes the outputs and skips the worker entirely.
    if let (Some(cache), Some(weak)) = (&ctx.cache, &weak) {
        let cache = cache.clone();
        let weak = weak.clone();
        let br = build_root.clone();
        match tokio::task::spawn_blocking(move || cache.resolve(&weak, &br)).await {
            Ok(Ok(CacheLookup::Hit { exit_code })) => {
                metrics.record_cache_hit();
                let _ = tx
                    .send(Ok(state_ev(ActionState::Completed, "cache hit")))
                    .await;
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
    // agent's scope root + per-session pin partition + allowed-digest ACL.
    // Declared outputs are not yet wired into the capability (deferred with
    // 2-machine WriteBack); the file server's within-root output scoping is still
    // strictly tighter than the pre-0013 any-path behaviour.
    ctx.registry
        .create(
            session_id.clone(),
            crate::fileserver::normalize_root(&vfs_root),
            Default::default(),
        )
        .await;

    let outcome = scheduler
        .dispatch(command, action_id, session_id.clone(), opts)
        .await;

    // Record a successful remote run so the next identical build hits. Needs the
    // trace (from the DLL); the outputs come from the launcher's declaration when
    // it had one, else they are discovered from the trace itself (ADR 0007 §b —
    // the compiler-independent path, so dxc and other non-clang-cl tools cache
    // too). A non-deterministic action is distributed but never recorded (ADR
    // 0007 §c): a later byte-identical-input hit would serve a stale result.
    // Without a trace or any discoverable output, recording is skipped (the build
    // is still correct, just uncached).
    if let (Some(cache), Some(weak)) = (&ctx.cache, &weak)
        && matches!(&outcome, Execution::Remote(o) if o.exit_code == Some(0))
        && !trace_dir.is_empty()
        && !non_deterministic
    {
        let cache = cache.clone();
        let weak = weak.clone();
        let br = build_root.clone();
        let declared = declared_outputs.clone();
        let td = trace_dir.clone();
        let rd = root_decl.clone();
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
                let _ = cache.record(&weak, &manifest, &br, &outs, 0);
            }
        })
        .await;
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

    // The action is done: drop the agent-authoritative session (ADR 0013) — its
    // pin partition, allowed-digest ACL, and writeback table. A worker connection
    // that lingers briefly holds a ConnGuard, so the entry's capability stays
    // alive until that closes; the idle sweeper is only a backstop for a crash.
    ctx.registry.finish(&session_id).await;
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
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .map_err(ExecuteError::Transport)?
        .connect_timeout(Duration::from_millis(500))
        .connect()
        .await?;
    let mut client = LocalIntakeClient::new(channel);
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
    use super::{mint_session_id, resolve_loopback_intake};

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
}
