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
    ActionState, Command, ExitStatus, StateChange, SubmitActionEvent, SubmitActionRequest,
    VfsExecution, local_intake_client::LocalIntakeClient, local_intake_server::LocalIntake,
    submit_action_event::Event,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

use crate::action_cache::{AgentCache, CacheLookup};
use crate::scheduler::Scheduler;
use crate::{ExecOptions, ExecuteError, Execution};

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
}

/// The LocalIntake gRPC service. Wraps the daemon's [`Scheduler`]; every
/// submitted action is dispatched (affinity → least-loaded → local fallback)
/// and its terminal outcome is mirrored back as a [`SubmitActionEvent`] stream.
#[derive(Clone)]
pub struct IntakeService {
    scheduler: Scheduler,
    /// Per-daemon action counter, so each submission gets a unique action_id /
    /// session_id without a clock or RNG (keeps the daemon reproducible).
    seq: Arc<AtomicU64>,
    /// Read-VFS + cache context; `None` → plain dispatch (M6.0/tests).
    vfs: Option<Arc<IntakeVfsContext>>,
}

impl IntakeService {
    /// Plain intake: submissions are dispatched directly (no VFS, no cache).
    pub fn new(scheduler: Scheduler) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
            vfs: None,
        }
    }

    /// Intake that runs submissions under the read-VFS (and the action cache when
    /// `ctx.cache` is set) — the production daemon's compile front door (M6.1).
    pub fn with_vfs(scheduler: Scheduler, ctx: IntakeVfsContext) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
            vfs: Some(Arc::new(ctx)),
        }
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

        // A unique id per submission; session_id binds the data-plane file
        // session and `n` names the per-action trace dir.
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let action_id = format!("intake-{n}");
        let session_id = action_id.clone();

        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(run_submission(
            self.scheduler.clone(),
            self.vfs.clone(),
            command,
            req.declared_outputs,
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
    command: Command,
    declared_outputs: Vec<String>,
    action_id: String,
    session_id: String,
    n: u64,
    tx: mpsc::Sender<Result<SubmitActionEvent, Status>>,
) {
    let Some(ctx) = vfs else {
        // Plain dispatch (M6.0 / tests): no VFS config, no cache.
        let outcome = scheduler
            .dispatch(command, action_id, session_id, ExecOptions::default())
            .await;
        emit_outcome(&tx, outcome).await;
        return;
    };

    let build_root = PathBuf::from(&command.cwd);

    // The weak key keys resolve, predicted_paths, and record. Computed off the
    // async runtime: weak_key hashes the toolchain binary from disk.
    let weak = match &ctx.cache {
        Some(cache) => {
            let cache = cache.clone();
            let argv = command.argv.clone();
            let mut env: Vec<(String, String)> = command
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            env.sort();
            tokio::task::spawn_blocking(move || cache.weak_key(&argv, &env))
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
        if let Ok(Ok(CacheLookup::Hit { exit_code })) =
            tokio::task::spawn_blocking(move || cache.resolve(&weak, &br)).await
        {
            let _ = tx
                .send(Ok(state_ev(ActionState::Completed, "cache hit")))
                .await;
            let _ = tx.send(Ok(exit_ev(exit_code, 0))).await;
            return;
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

    let opts = ExecOptions {
        predicted_paths,
        vfs: Some(VfsExecution {
            agent_fileserver: ctx.agent_fileserver.clone(),
            // Single-machine: reads under the build dir redirect through the VFS;
            // anything outside resolves to the same local bytes (correct either
            // way). A 2-machine split would scope this to the project source root.
            vfs_root: command.cwd.clone(),
            trace_dir: trace_dir.clone(),
        }),
    };

    let outcome = scheduler
        .dispatch(command, action_id, session_id, opts)
        .await;

    // Record a successful remote run so the next identical build hits. Needs the
    // trace (from the DLL) and the declared outputs (from the launcher); without
    // either, recording is skipped (the build is still correct, just uncached).
    if let (Some(cache), Some(weak)) = (&ctx.cache, &weak)
        && matches!(&outcome, Execution::Remote(o) if o.exit_code == Some(0))
        && !trace_dir.is_empty()
        && !declared_outputs.is_empty()
    {
        let cache = cache.clone();
        let weak = weak.clone();
        let br = build_root.clone();
        let outs = declared_outputs.clone();
        let td = trace_dir.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(manifest) = cache.manifest_from_trace_dir(&td) {
                let _ = cache.record(&weak, &manifest, &br, &outs, 0);
            }
        })
        .await;
    }

    emit_outcome(&tx, outcome).await;
}

/// Mirrors a dispatch outcome as the terminal `state` + `exit` events. dispatch
/// always completes (remote or local fallback), so there is always an exit code.
async fn emit_outcome(tx: &mpsc::Sender<Result<SubmitActionEvent, Status>>, outcome: Execution) {
    let (code, wall, note) = match outcome {
        Execution::Remote(o) => (
            o.exit_code.unwrap_or(-1),
            o.wall_time_us,
            "remote".to_string(),
        ),
        Execution::LocalFallback { exit_code, reason } => {
            (exit_code, 0, format!("local fallback: {reason}"))
        }
    };
    let _ = tx.send(Ok(state_ev(ActionState::Completed, &note))).await;
    let _ = tx.send(Ok(exit_ev(code, wall))).await;
}

/// Resolves `addr` for the LocalIntake listener, **refusing any non-loopback
/// address**. Intake executes arbitrary submitted commands and is unauthenticated
/// until M7, so it must never be reachable off-box: the launcher only ever dials
/// `127.0.0.1` (see `sembazuru_launcher.rs`), so loopback-only costs nothing.
/// Without this guard, `SEMBAZURU_INTAKE=0.0.0.0:50071` would expose
/// unauthenticated remote command execution (security-reviewer M6.0, MEDIUM).
/// Coordination and the file server are deliberately *not* guarded — they
/// legitimately need LAN reach for workers; intake does not.
pub fn resolve_loopback_intake(addr: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("invalid intake address {addr:?}: {e}"))?
        .collect();
    let first = resolved
        .first()
        .copied()
        .ok_or_else(|| format!("intake address {addr:?} resolved to no socket address"))?;
    // Refuse if *any* resolved address is non-loopback (a hostname could resolve
    // to both; binding the loopback one while a routable one exists would still
    // be surprising, so fail closed).
    if let Some(bad) = resolved.iter().find(|a| !a.ip().is_loopback()) {
        return Err(format!(
            "refusing to bind LocalIntake to non-loopback address {bad}: intake executes \
             arbitrary commands and is unauthenticated (M7). Use a loopback address such as \
             127.0.0.1:<port>; the launcher only ever dials loopback."
        ));
    }
    Ok(first)
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
    declared_outputs: Vec<String>,
) -> Result<(i32, String), ExecuteError> {
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .map_err(ExecuteError::Transport)?
        .connect_timeout(Duration::from_millis(500))
        .connect()
        .await?;
    let mut client = LocalIntakeClient::new(channel);
    let request = SubmitActionRequest {
        command: Some(command),
        declared_outputs,
    };
    let mut stream = client.submit_action(request).await?.into_inner();
    let mut exit_code: Option<i32> = None;
    let mut note = String::new();
    while let Some(ev) = stream.message().await? {
        match ev.event {
            Some(Event::Exit(e)) => exit_code = Some(e.exit_code),
            Some(Event::State(s)) if !s.detail.is_empty() => note = s.detail,
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
    use super::resolve_loopback_intake;

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
