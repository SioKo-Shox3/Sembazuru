//! Sembazuru worker: a control-plane server that executes actions and streams
//! their lifecycle back to the agent (see `docs/protocol/v0.md` §3.2).
//!
//! **M3.1 scope — loopback Execute.** The worker hosts the `Execution` service:
//! it runs the commanded process and streams `StateChange` + `ExitStatus` back.
//! It does NOT yet touch the filesystem itself — on a loopback worker the input
//! files are physically present, so there is no redirection. The on-demand VFS
//! (M3.2), write-back/atomic publish (M3.3), and abort/fallback (M3.4) come
//! later; keeping the worker filesystem-agnostic here avoids baking in an
//! assumption that M3.2 would have to tear out.

pub mod config;
pub mod coordination;
mod cpu_monitor;
pub mod fileclient;
mod job;
pub mod run;
#[cfg(windows)]
pub mod service;
pub mod vfs_pipe;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use job::JobObject;

use sembazuru_proto::v0::{
    AbortRequest, AbortResponse, ActionState, Command, ExecuteEvent, ExecuteRequest, ExitStatus,
    OutputChunk, StateChange, VfsExecution, execute_event::Event, execution_server::Execution,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

use crate::vfs_pipe::serve_vfs_with_prefetch_ready;

/// Disambiguates per-action VFS pipe/scratch names within a worker process.
static EXEC_SEQ: AtomicU64 = AtomicU64::new(0);

/// Worker-local install config for read-VFS execution (M6.1). Set from the
/// worker daemon's environment; absent on a plain (M5 scale) worker. The agent
/// fileserver address is NOT here — it rides per-action in `VfsExecution` so one
/// worker can serve many agents (forward-compatible with the LAN split).
#[derive(Clone)]
pub struct WorkerVfsConfig {
    /// `launcher.exe` — injects the hook DLL via DetourCreateProcessWithDllExW.
    pub launcher: PathBuf,
    /// `sbz_interceptor64.dll` — the injected hook that redirects reads.
    pub dll: PathBuf,
    /// Root under which per-action scratch (hydrated input) trees are created.
    pub scratch_root: PathBuf,
    /// Worker-local content store, persisted across builds (M4 worker cache).
    pub cas_root: PathBuf,
}

/// Default admission capacity when none is given: the machine's parallelism.
fn default_capacity() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// How many actions may be *accepted* (queued + running) per running slot before
/// the worker sheds load. Bounds the memory a flood of `Execute`s can pin in
/// queued tasks (security: admission caps running processes, this caps the
/// waiting backlog so the worker cannot be memory-flooded).
const QUEUE_FACTOR: u32 = 8;

/// Marker the injected DLL drops in the per-action scratch dir when, under strict
/// VFS (ADR 0007 §a②), a read-only open under `vfs_root` could not be supplied by
/// the agent and was therefore failed instead of opened locally. Its presence
/// after the child exits means the process saw a wrong/missing input, so the
/// worker reports the action as not-completed and the agent re-runs it locally.
/// Must match `kUnvirtMarker` in `hooks/src/interceptor.cpp`.
const UNVIRT_MARKER: &str = ".sbz-unvirtualized";

/// Hard ceiling on a single action's wall time when none is configured. This is
/// a runaway/hung-child backstop (a process the agent never reaps still frees
/// its slot), NOT the latency budget — it is generous so it never kills a real
/// compile. Override with `SEMBAZURU_ACTION_TIMEOUT_SECS`.
const DEFAULT_ACTION_CEILING_SECS: u64 = 3600;

fn default_action_ceiling() -> std::time::Duration {
    let secs = std::env::var("SEMBAZURU_ACTION_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_ACTION_CEILING_SECS);
    std::time::Duration::from_secs(secs)
}

/// The worker's gRPC service. Bounds concurrent actions with an admission
/// `Semaphore` (a single un-virtualized worker must not fork-bomb under a flood
/// of `Execute`s — the DoS fix), sheds excess accepted work past `QUEUE_FACTOR ×
/// capacity` (so the queued backlog cannot memory-flood the worker), and tracks
/// the in-flight count so the Coordination heartbeat pushes real capacity to the
/// agent (ADR 0004).
#[derive(Clone)]
pub struct WorkerService {
    running: Arc<AtomicU32>,
    served: Arc<std::sync::atomic::AtomicU64>,
    limit: Arc<Semaphore>,
    accept: Arc<Semaphore>,
    capacity: u32,
    ceiling: std::time::Duration,
    /// Read-VFS install config; `None` → the worker only plain-spawns and
    /// rejects VFS-mode requests (M5 scale worker). Set via [`with_vfs`].
    vfs: Option<Arc<WorkerVfsConfig>>,
    /// Per-action Job Objects for in-flight VFS actions, so `Abort` can kill the
    /// whole process tree (launcher + the real compiler grandchild). Keyed by
    /// action_id; entry removed when the action ends (M6.1e).
    aborts: Arc<Mutex<HashMap<String, Arc<JobObject>>>>,
}

impl Default for WorkerService {
    fn default() -> Self {
        Self::with_capacity(default_capacity())
    }
}

impl WorkerService {
    /// A worker admitting up to `available_parallelism()` concurrent actions.
    pub fn new() -> Self {
        Self::default()
    }

    /// A worker admitting up to `capacity` concurrent actions; up to
    /// `QUEUE_FACTOR × capacity` more may queue (reported as `QUEUED`), beyond
    /// which `Execute` is rejected with `RESOURCE_EXHAUSTED`. `capacity` ≥ 1.
    pub fn with_capacity(capacity: u32) -> Self {
        let capacity = capacity.max(1);
        Self {
            running: Arc::new(AtomicU32::new(0)),
            served: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            limit: Arc::new(Semaphore::new(capacity as usize)),
            accept: Arc::new(Semaphore::new((capacity * QUEUE_FACTOR) as usize)),
            capacity,
            ceiling: default_action_ceiling(),
            vfs: None,
            aborts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enables read-VFS execution (M6.1): VFS-mode `Execute` requests inject the
    /// hook DLL and supply inputs on demand. Without it, a VFS-mode request is
    /// rejected (it would otherwise plain-spawn the compiler with no inputs).
    pub fn with_vfs(mut self, cfg: WorkerVfsConfig) -> Self {
        self.vfs = Some(Arc::new(cfg));
        self
    }

    /// Overrides the per-action wall-clock ceiling from configuration (M9.3c). A
    /// service has no per-shell environment, so the timeout must be settable from
    /// `worker.toml`, not only `SEMBAZURU_ACTION_TIMEOUT_SECS`. `None` (or a zero
    /// value) keeps the default resolved at construction by [`default_action_ceiling`]
    /// — so the env path is unchanged and the file path now works too.
    pub fn with_action_timeout_secs(mut self, secs: Option<u64>) -> Self {
        if let Some(s) = secs.filter(|&s| s > 0) {
            self.ceiling = std::time::Duration::from_secs(s);
        }
        self
    }

    /// A handle to the in-flight-action counter, shared with every clone of the
    /// service (tonic clones the service per connection). The heartbeat task
    /// reads this to report `running_actions` / `idle_slots`.
    pub fn running_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.running)
    }

    /// A handle to the cumulative count of actions this worker has admitted
    /// (run), for telemetry and for tests that assert work actually spread here.
    pub fn served_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.served)
    }

    /// The admission capacity (max concurrent actions).
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

/// Decrements the in-flight counter when an action's task ends, however it ends
/// (normal completion, early return, or a panic unwinding the spawned task).
struct RunningGuard(Arc<AtomicU32>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn state_event(state: ActionState, detail: &str) -> Result<ExecuteEvent, Status> {
    Ok(ExecuteEvent {
        event: Some(Event::State(StateChange {
            state: state as i32,
            detail: detail.to_string(),
        })),
    })
}

/// Sanitizes a worker-side error (setup or run) for the wire (M7.1,
/// `docs/deferred.md` M7 "エラー詳細の情報漏洩"). The detailed cause — which can contain worker-side
/// filesystem paths and raw OS error text — is logged to the worker's OWN stderr
/// (safe; the worker operator sees it), while only the coarse, path-free
/// `category` crosses the trust boundary to the agent (and onward to the
/// developer's console). The developer still gets the real compiler error: a
/// FAILED action falls back to a local build, whose output they see directly.
fn setup_err(category: &'static str, detail: impl std::fmt::Display) -> String {
    eprintln!("sembazuru-worker: {category}: {detail}");
    category.to_string()
}

fn exit_event(code: i32, wall_us: u64) -> Result<ExecuteEvent, Status> {
    Ok(ExecuteEvent {
        event: Some(Event::Exit(ExitStatus {
            exit_code: code,
            wall_time_us: wall_us,
            user_time_us: 0,
            kernel_time_us: 0,
        })),
    })
}

/// Streams a child's stdout/stderr to the agent as `OutputChunk` events so the
/// developer driving the build via the launcher sees the compiler's diagnostics
/// (M6.1). Reads continuously, which also prevents the child from blocking on a
/// full pipe buffer. Ends on EOF (child exit) or when the receiver is gone.
fn spawn_stdio_reader<R>(
    mut reader: R,
    is_stderr: bool,
    tx: mpsc::Sender<Result<ExecuteEvent, Status>>,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let ev = Ok(ExecuteEvent {
                        event: Some(Event::Stdio(OutputChunk {
                            is_stderr,
                            data: buf[..n].to_vec(),
                        })),
                    });
                    if tx.send(ev).await.is_err() {
                        break; // agent went away
                    }
                }
            }
        }
    })
}

/// Drives one action to completion, emitting lifecycle events into `tx`.
///
/// Admission: the action is `QUEUED` until it acquires a permit from `limit`,
/// bounding concurrency to the worker's capacity. Once admitted it counts toward
/// `running` (the capacity the heartbeat reports) for exactly the run's duration.
///
/// A nonzero exit code is a normal result (a compiler legitimately fails a
/// compile) and is reported via `ExitStatus` under a `COMPLETED` state. `FAILED`
/// is reserved for the worker being unable to run the process at all — that
/// distinction is what lets the agent decide whether to fall back (§3.2).
#[allow(clippy::too_many_arguments)]
async fn run_action(
    cmd: Command,
    action_id: String,
    // The agent-minted data-plane session id (ADR 0013), forwarded onto the VFS
    // handshake so the agent binds file supply to the authoritative session.
    session_id: String,
    vfs_req: Option<VfsExecution>,
    predicted_paths: Vec<String>,
    vfs_cfg: Option<Arc<WorkerVfsConfig>>,
    aborts: Arc<Mutex<HashMap<String, Arc<JobObject>>>>,
    tx: mpsc::Sender<Result<ExecuteEvent, Status>>,
    limit: Arc<Semaphore>,
    running: Arc<AtomicU32>,
    served: Arc<std::sync::atomic::AtomicU64>,
    ceiling: std::time::Duration,
    // Held for the whole task (queued + running) so the accepted-work backlog
    // stays bounded; released on drop when the action leaves the worker.
    _accept: tokio::sync::OwnedSemaphorePermit,
) {
    let _ = tx.send(state_event(ActionState::Queued, "")).await;

    // Admission control: wait for a free slot. The owned permit is held for the
    // whole run and released on drop (normal end, early return, or panic).
    let _permit = match limit.acquire_owned().await {
        Ok(p) => p,
        // Only happens if the semaphore is closed (worker shutting down).
        Err(_) => {
            let _ = tx
                .send(state_event(ActionState::Failed, "worker shutting down"))
                .await;
            return;
        }
    };
    // Now genuinely running: count it for capacity reporting until the guard
    // drops. Queued (un-admitted) actions are deliberately not counted.
    running.fetch_add(1, Ordering::SeqCst);
    served.fetch_add(1, Ordering::SeqCst);
    let _guard = RunningGuard(running);

    let _ = tx.send(state_event(ActionState::Preparing, "")).await;

    // Self-guard the invariant the indexing below relies on, rather than trust a
    // distant caller: an empty argv is a worker-side inability to run (FAILED),
    // not a panic.
    if cmd.argv.is_empty() {
        let _ = tx
            .send(state_event(ActionState::Failed, "command.argv is empty"))
            .await;
        return;
    }

    // Decide execution mode. VFS mode (M6.1) injects the hook DLL and supplies
    // inputs on demand; plain mode (M5 scale) spawns the process directly. A
    // VFS-mode request on a worker that lacks VFS config is a hard FAILED, not a
    // plain spawn — plain-spawning would run the compiler with no inputs and
    // produce a wrong result the agent would then trust.
    let vfs_plan = match (vfs_req, vfs_cfg) {
        (Some(v), Some(cfg)) => Some((v, cfg)),
        (Some(_), None) => {
            let _ = tx
                .send(state_event(
                    ActionState::Failed,
                    "worker is not configured for VFS execution",
                ))
                .await;
            return;
        }
        (None, _) => None,
    };

    let start = Instant::now();
    // For VFS mode, `pipe_task` keeps the per-action pipe server alive for the
    // run; `job` is the process-tree kill handle; `scratch_dir` is the hydrated
    // input tree to remove after the run (deferred #8 / M9.2). All are cleaned up
    // after the child exits.
    let (mut child, pipe_task, job, unvirt_marker, scratch_dir) =
        match build_child(&cmd, vfs_plan, predicted_paths, session_id).await {
            Ok(parts) => parts,
            Err(detail) => {
                let _ = tx.send(state_event(ActionState::Failed, &detail)).await;
                return;
            }
        };

    // Register the job so `Abort` (or a reassign that drops the stream) kills the
    // whole tree. Both the map and this scope hold an Arc; the action's processes
    // die only once BOTH are gone, so the entry is removed at the end below.
    if let Some(j) = job {
        aborts
            .lock()
            .expect("aborts map poisoned")
            .insert(action_id.clone(), Arc::new(j));
    }

    // Stream the child's console output to the agent. Reading continuously also
    // stops the child from blocking on a full pipe buffer (M6.1).
    let mut stdout_reader = child
        .stdout
        .take()
        .map(|s| spawn_stdio_reader(s, false, tx.clone()));
    let mut stderr_reader = child
        .stderr
        .take()
        .map(|s| spawn_stdio_reader(s, true, tx.clone()));

    let _ = tx.send(state_event(ActionState::Running, "")).await;

    tokio::select! {
        // The agent cancelled or disconnected: the receiver is gone, so nobody
        // will read further events. Return; `child` drops here and `kill_on_drop`
        // terminates it rather than leaving an orphan.
        _ = tx.closed() => {}
        // Runaway/hung-process backstop: a process the agent never reaps (no
        // budget on the direct-Execute path) must not pin its slot forever.
        // `child` drops on return and `kill_on_drop` terminates it.
        _ = tokio::time::sleep(ceiling) => {
            let _ = tx
                .send(state_event(ActionState::Failed, "exceeded execution ceiling"))
                .await;
        }
        result = child.wait() => match result {
            Ok(status) => {
                // Flush all console output BEFORE the exit event, so the launcher
                // has the full diagnostics in hand when it sees the exit code.
                if let Some(h) = stdout_reader.take() { let _ = h.await; }
                if let Some(h) = stderr_reader.take() { let _ = h.await; }
                // Fail-closed (M8.2 ②): under strict VFS, if the DLL marked an
                // unvirtualized access (a read under vfs_root the agent could not
                // supply), the process ran against a wrong/missing input — its
                // exit code is untrustworthy. Report NOT-completed (Failed, no
                // exit) so the agent re-runs the whole action locally. This is the
                // sanctioned fallback channel: the agent treats "no exit status"
                // as a fallback trigger (a nonzero exit would NOT fall back).
                if unvirt_marker.as_ref().is_some_and(|m| m.exists()) {
                    let _ = tx
                        .send(state_event(
                            ActionState::Failed,
                            "unvirtualized access under vfs_root (strict): re-run locally",
                        ))
                        .await;
                } else {
                    // On Windows a process always has an exit code; unwrap_or
                    // guards the signal-terminated case that does not occur here.
                    let code = status.code().unwrap_or(-1);
                    // Saturate explicitly rather than let `as u64` wrap; this is
                    // the pattern that will be copied for user/kernel time
                    // accounting later, where the values are not bounded by a wall
                    // clock.
                    let wall = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                    let _ = tx.send(exit_event(code, wall)).await;
                    let _ = tx.send(state_event(ActionState::Completed, "")).await;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(state_event(ActionState::Failed, &setup_err("wait failed", e)))
                    .await;
            }
        }
    }

    // Abort any stdio readers still running (the non-wait exits: cancel/ceiling).
    // On the normal wait path they were already awaited and taken.
    if let Some(h) = stdout_reader.take() {
        h.abort();
    }
    if let Some(h) = stderr_reader.take() {
        h.abort();
    }
    // Stop the per-action VFS pipe server (if any). The serve loop runs forever
    // by design, so it must be aborted once the action is done or it leaks one
    // task (and one listening pipe instance) per action.
    if let Some(t) = pipe_task {
        t.abort();
    }
    // Drop the Job Object handle (removing the last Arc): closing it kills any
    // process still in the job — so a normal completion reaps stragglers and a
    // cancelled action (stream dropped / Abort) kills the whole compiler tree.
    aborts
        .lock()
        .expect("aborts map poisoned")
        .remove(&action_id);
    // Make sure the action's process tree is fully gone before removing its
    // scratch. On the normal path the child already exited; on the cancel/ceiling
    // paths closing the Job Object above kills the tree, and the launcher (which
    // WaitForSingleObject's the compiler) exits once the compiler dies — so
    // awaiting the launcher here means no surviving process still holds a scratch
    // file open. This makes the cleanup reliable on EVERY path, not just normal
    // exit. A second wait on an already-exited child returns immediately, and a
    // killed tree exits promptly, so this never hangs.
    let _ = child.wait().await;
    // Remove the per-action hydrated scratch tree (deferred #8 / M9.2). Best-effort:
    // a residual lock just leaves one tree behind (a later run with the same suffix
    // cannot occur — EXEC_SEQ is monotonic), never a wrong result, so a failure is
    // logged, not fatal. This is what bounds a long-lived worker's disk: previously
    // every action's scratch was left forever ("left for now").
    if let Some(dir) = scratch_dir
        && let Err(e) = tokio::fs::remove_dir_all(&dir).await
        && dir.exists()
    {
        eprintln!(
            "sembazuru-worker: failed to remove scratch {}: {e}",
            dir.display()
        );
    }
}

/// Builds the child process for an action. Plain mode spawns the command
/// directly (M5 scale path) and returns `(child, None)`. VFS mode (M6.1) starts
/// a per-action pipe server, waits for it to be dialable, then spawns the
/// compiler through `launcher.exe` (DLL injection) with an explicit environment;
/// it returns the pipe-server task so the caller can abort it after the run. On
/// any setup failure it returns a human-readable detail for a FAILED event.
async fn build_child(
    cmd: &Command,
    vfs_plan: Option<(VfsExecution, Arc<WorkerVfsConfig>)>,
    predicted_paths: Vec<String>,
    // The agent-minted session id (ADR 0013); moved onto the VFS data-plane
    // handshake. Empty/unused on the plain path (it has no data plane).
    session_id: String,
) -> Result<
    (
        tokio::process::Child,
        Option<tokio::task::JoinHandle<std::io::Result<()>>>,
        Option<JobObject>,
        // Strict-VFS unvirtualized-access marker path to check after exit (M8.2
        // ②); `None` in plain mode or when strict VFS is off.
        Option<std::path::PathBuf>,
        // Per-action hydrated scratch dir to remove after the run (deferred #8 /
        // M9.2); `None` in plain mode, where no scratch tree is created.
        Option<std::path::PathBuf>,
    ),
    String,
> {
    let Some((v, cfg)) = vfs_plan else {
        // Plain spawn (M5 scale path): the child inherits the worker service env
        // (it needs OS basics like SystemRoot/PATH/ComSpec that the action's own
        // env may not carry — a full `env_clear` here breaks bare commands such as
        // `cmd /c ping`), with the action's `cmd.env` overlaid on top.
        //
        // But the worker service process holds its own secrets — above all
        // SEMBAZURU_CLUSTER_TOKEN (config.rs reads it from the env), plus
        // SEMBAZURU_AGENT/_CAPACITY and other SEMBAZURU_* internals — and the
        // child's stdout/stderr are streamed straight back to the requesting agent.
        // So strip every inherited SEMBAZURU_* var before overlaying `cmd.env`,
        // otherwise an Execute of e.g. `cmd /c set` would exfiltrate the cluster
        // token (SEC-002). The VFS branch below `env_clear`s instead because it
        // runs through launcher.exe with a fully curated compiler env.
        //
        // LOAD-BEARING INVARIANT (else this leaks): the worker service env must
        // carry secrets ONLY under the `SEMBAZURU_*` prefix. This is a denylist,
        // not an allowlist — every non-`SEMBAZURU_` var (PATH, SystemRoot, …) is
        // inherited so the bare command can run, so any non-`SEMBAZURU_` secret
        // placed in the service env (an `AWS_*`/proxy cred, …) WOULD reach the
        // child. The worker runs as a minimal-env service account, so today this
        // holds; a future deployment that injects other secrets must extend this.
        let mut command = tokio::process::Command::new(&cmd.argv[0]);
        command.args(&cmd.argv[1..]);
        if !cmd.cwd.is_empty() {
            command.current_dir(&cmd.cwd);
        }
        for (key, _) in std::env::vars_os() {
            if key
                .to_string_lossy()
                .to_ascii_uppercase()
                .starts_with("SEMBAZURU_")
            {
                command.env_remove(&key);
            }
        }
        for (k, val) in &cmd.env {
            command.env(k, val);
        }
        command.stdin(Stdio::null());
        // Capture stdout/stderr so they can be streamed to the agent (M6.1).
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // Kill the child if its task is dropped (agent gave up / fallback), so
        // the worker never leaks an orphan holding an admission slot.
        command.kill_on_drop(true);
        let child = command.spawn().map_err(|e| setup_err("spawn failed", e))?;
        // Sandbox this child too (M7.4, security HIGH-1): the plain path has no
        // grandchild to orphan, but the Job Object's UI restrictions and
        // die-on-unhandled-exception still apply, so whatever the agent asked us
        // to run is sandboxed UNIFORMLY with the VFS path — not left bare. (The
        // small spawn->assign window is the same documented residual as the VFS
        // path; kill_on_drop covers the direct child meanwhile.)
        let job = JobObject::new_kill_on_close()
            .and_then(|j| match child.raw_handle() {
                Some(h) => j.assign(h).map(|()| j),
                None => Ok(j), // already exited; nothing to assign
            })
            .map_err(|e| setup_err("job object setup failed", e))?;
        return Ok((child, None, Some(job), None, None));
    };

    // VFS mode. Per-action unique pipe + scratch so concurrent actions never
    // collide (their traces/scratch must not cross-contaminate).
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        EXEC_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let pipe_name = format!("sbz-exec-{suffix}");
    let scratch = cfg.scratch_root.join(&suffix);
    // Keep a copy of the scratch path so the action removes the hydrated input
    // tree after the run (deferred #8 / M9.2); `scratch` itself is moved into the
    // per-action pipe server task below.
    let scratch_for_cleanup = scratch.clone();
    let agent_addr: SocketAddr = v
        .agent_fileserver
        .parse()
        .map_err(|e| setup_err("invalid agent fileserver address", e))?;
    tokio::fs::create_dir_all(&scratch)
        .await
        .map_err(|e| setup_err("create scratch dir failed", e))?;
    if !v.trace_dir.is_empty() {
        tokio::fs::create_dir_all(&v.trace_dir)
            .await
            .map_err(|e| setup_err("create trace dir failed", e))?;
    }
    let scratch_str = scratch.to_string_lossy().into_owned();

    // Start the pipe server and WAIT for readiness before launching, so the
    // compiler cannot dial the pipe before it exists (Plan risk 1). A create
    // failure drops `ready_tx`, so `ready_rx.await` errors and we fail closed.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let cas = cfg.cas_root.clone();
    let pipe_for_task = pipe_name.clone();
    // Declare the action's input root so the agent scopes file supply to it
    // (M7.1): the worker only legitimately reads under vfs_root (the hook
    // redirects exactly that subtree), so a request outside it is illegitimate.
    let vfs_root = v.vfs_root.clone();
    let pipe_task = tokio::spawn(async move {
        serve_vfs_with_prefetch_ready(
            &pipe_for_task,
            agent_addr,
            scratch,
            cas,
            Duration::ZERO,
            predicted_paths,
            ready_tx,
            vfs_root,
            session_id,
        )
        .await
    });
    if ready_rx.await.is_err() {
        pipe_task.abort();
        return Err("VFS pipe server failed to start".to_string());
    }

    // Inject the DLL via launcher.exe. Env is set EXPLICITLY (env_clear first):
    // launcher.cpp passes no env block, so the compiler inherits the launcher's
    // environment — which is what we set here. Clearing first stops worker-
    // internal vars (SEMBAZURU_AGENT/CAPACITY) and any stale SEMBAZURU_VFS_* from
    // a prior action from leaking into the compiler and perturbing its output.
    let mut command = tokio::process::Command::new(&cfg.launcher);
    command.arg(&cfg.dll);
    command.args(&cmd.argv);
    if !cmd.cwd.is_empty() {
        command.current_dir(&cmd.cwd);
    }
    command.env_clear();
    for (k, val) in &cmd.env {
        command.env(k, val);
    }
    command.env("SEMBAZURU_MODE", "vfs");
    command.env("SEMBAZURU_VFS_ROOT", &v.vfs_root);
    command.env("SEMBAZURU_VFS_PIPE", &pipe_name);
    command.env("SEMBAZURU_VFS_SCRATCH", &scratch_str);
    if !v.trace_dir.is_empty() {
        command.env("SEMBAZURU_TRACE_DIR", &v.trace_dir);
    }
    // Strict virtualization (M8.2 ②): tell the DLL to FAIL an unsuppliable
    // read under vfs_root (and drop UNVIRT_MARKER) instead of opening the local
    // file. Default off keeps the compiler fail-open behavior (all M3-M7 gates).
    // Set it AUTHORITATIVELY ("1"/"0") like SEMBAZURU_MODE/_ROOT/_PIPE, so the
    // action's cmd.env cannot smuggle strict on and desync the DLL from this
    // worker's marker check (security M8.2 MEDIUM-1).
    command.env("SEMBAZURU_VFS_STRICT", if v.strict { "1" } else { "0" });
    let unvirt_marker = if v.strict {
        Some(std::path::PathBuf::from(&scratch_str).join(UNVIRT_MARKER))
    } else {
        None
    };
    command.stdin(Stdio::null());
    // Capture the launcher's stdout/stderr — which are the injected compiler's,
    // since launcher.exe forwards its std handles — to stream to the agent (M6.1).
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            pipe_task.abort();
            let _ = tokio::fs::remove_dir_all(&scratch_for_cleanup).await;
            return Err(setup_err("launcher spawn failed", e));
        }
    };

    // Assign the launcher to a kill-on-close Job Object so the grandchild (the
    // real compiler the launcher injects into) dies with it — kill_on_drop alone
    // would orphan it (M6.1e). The grandchild auto-joins the job. A small window
    // exists between spawn and assign; the launcher resolves the DLL path before
    // it spawns the compiler, so assignment normally wins.
    let job = match JobObject::new_kill_on_close().and_then(|j| {
        match child.raw_handle() {
            Some(h) => j.assign(h).map(|()| j),
            None => Ok(j), // child already exited; nothing to assign
        }
    }) {
        Ok(j) => j,
        Err(e) => {
            pipe_task.abort();
            let _ = tokio::fs::remove_dir_all(&scratch_for_cleanup).await;
            // `child` drops here; kill_on_drop terminates at least the launcher.
            return Err(setup_err("job object setup failed", e));
        }
    };
    Ok((
        child,
        Some(pipe_task),
        Some(job),
        unvirt_marker,
        Some(scratch_for_cleanup),
    ))
}

#[tonic::async_trait]
impl Execution for WorkerService {
    type ExecuteStream = ReceiverStream<Result<ExecuteEvent, Status>>;

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let req = request.into_inner();
        let cmd = req
            .command
            .ok_or_else(|| Status::invalid_argument("ExecuteRequest.command is required"))?;
        if cmd.argv.is_empty() {
            return Err(Status::invalid_argument("command.argv must be non-empty"));
        }
        // M6.1: VFS config and prefetch hint ride the request; the worker's own
        // install config decides whether VFS mode is even possible.
        let action_id = req.action_id;
        // ADR 0013: the agent-minted data-plane session id. Previously decoded
        // and dropped here; now forwarded onto the VFS handshake so the agent can
        // bind file supply to the authoritative session (root/pins/outputs).
        let session_id = req.session_id;
        let vfs_req = req.vfs;
        let predicted_paths = req.predicted_paths;
        let vfs_cfg = self.vfs.clone();
        let aborts = Arc::clone(&self.aborts);

        // Shed load before spawning anything: if the accepted-work backlog is
        // already at QUEUE_FACTOR × capacity, reject rather than pin more memory
        // in a queued task (DoS hardening). The permit is held by the task for
        // its whole lifetime.
        let accept = match Arc::clone(&self.accept).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return Err(Status::resource_exhausted(
                    "worker accepted-work backlog is full",
                ));
            }
        };

        // Bounded channel: the lifecycle producer is slow relative to gRPC, so a
        // small buffer is plenty and bounds memory if the client stalls.
        let (tx, rx) = mpsc::channel(16);
        // Admission + capacity accounting happen inside the task (an action is
        // QUEUED until it acquires a permit), so the gRPC call returns its stream
        // immediately and queued actions are visible as QUEUED events.
        tokio::spawn(run_action(
            cmd,
            action_id,
            session_id,
            vfs_req,
            predicted_paths,
            vfs_cfg,
            aborts,
            tx,
            Arc::clone(&self.limit),
            Arc::clone(&self.running),
            Arc::clone(&self.served),
            self.ceiling,
            accept,
        ));
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn abort(
        &self,
        request: Request<AbortRequest>,
    ) -> Result<Response<AbortResponse>, Status> {
        // M6.1e: real cancellation. Terminate the action's Job Object, killing
        // the whole process tree (launcher + the injected compiler grandchild).
        // The run_action select then observes the child exit and cleans up. A
        // plain (non-VFS) action has no job; its stream-drop + kill_on_drop still
        // covers it, and the reassign path drops the stream rather than calling
        // Abort, so this acknowledges either way.
        let action_id = request.into_inner().action_id;
        if let Some(job) = self
            .aborts
            .lock()
            .expect("aborts map poisoned")
            .get(&action_id)
        {
            job.terminate();
        }
        Ok(Response::new(AbortResponse { acknowledged: true }))
    }
}

/// Serves the `Execution` service on an already-bound listener. Taking the
/// listener (rather than an address) lets callers bind an ephemeral port and
/// learn it before serving — used by both the binary and the integration test.
pub async fn serve_on_listener(
    listener: TcpListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_on_listener_with(listener, WorkerService::new()).await
}

/// Like [`serve_on_listener`], but with a caller-provided service so the worker
/// daemon can share the service's in-flight counter with a Coordination
/// heartbeat task (the binary registers and heartbeats; tests do not need to).
pub async fn serve_on_listener_with(
    listener: TcpListener,
    service: WorkerService,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::execution_server::ExecutionServer;

    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(20)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
        .add_service(ExecutionServer::new(service))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}
