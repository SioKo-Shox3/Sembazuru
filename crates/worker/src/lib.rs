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
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use job::JobObject;

use sembazuru_proto::{
    capability,
    quotas::MAX_PREDICTED_PATHS,
    v0::{
        AbortRequest, AbortResponse, ActionState, Command, ExecuteEvent, ExecuteRequest,
        ExitStatus, OutputChunk, StateChange, VfsExecution, execute_event::Event,
        execution_server::Execution,
    },
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

use crate::vfs_pipe::serve_vfs_with_prefetch_ready;

/// Disambiguates per-action VFS pipe/scratch names within a worker process.
static EXEC_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
enum VfsChildCwd {
    None,
    Original(PathBuf),
    Scratch(PathBuf),
}

impl VfsChildCwd {
    fn path(&self) -> Option<&Path> {
        match self {
            VfsChildCwd::None => None,
            VfsChildCwd::Original(path) | VfsChildCwd::Scratch(path) => Some(path),
        }
    }
}

fn vfs_child_cwd(cmd_cwd: &str, vfs_root: &str, scratch: &Path) -> VfsChildCwd {
    if cmd_cwd.is_empty() {
        return VfsChildCwd::None;
    }
    if vfs_root.is_empty() {
        return VfsChildCwd::Original(PathBuf::from(cmd_cwd));
    }

    let cwd = Path::new(cmd_cwd);
    let root = Path::new(vfs_root);
    match strip_prefix_case_insensitive(cwd, root) {
        Some(rel) if rel.as_os_str().is_empty() => VfsChildCwd::Scratch(scratch.to_path_buf()),
        Some(rel) if is_safe_relative_child_cwd(&rel) => VfsChildCwd::Scratch(scratch.join(rel)),
        Some(_) => VfsChildCwd::Original(cwd.to_path_buf()),
        None => VfsChildCwd::Original(cwd.to_path_buf()),
    }
}

fn is_safe_relative_child_cwd(rel: &Path) -> bool {
    rel.components().all(|c| {
        !matches!(
            c,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    })
}

fn strip_prefix_case_insensitive(path: &Path, base: &Path) -> Option<PathBuf> {
    let mut path_components = path.components();
    for base_component in base.components() {
        let path_component = path_components.next()?;
        let path_text = path_component.as_os_str().to_string_lossy();
        let base_text = base_component.as_os_str().to_string_lossy();
        if !path_text.eq_ignore_ascii_case(base_text.as_ref()) {
            return None;
        }
    }

    let mut rel = PathBuf::new();
    for component in path_components {
        rel.push(component.as_os_str());
    }
    Some(rel)
}

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
    /// Shared cluster token presented on the data-plane handshake, threaded from
    /// the resolved WorkerConfig so a token set only in worker.toml reaches the
    /// data plane; None/empty = no auth.
    pub cluster_token: Option<String>,
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

/// Upper bound on a worker's admission capacity (RES-001). No real host has
/// hundreds of cores, and — crucially — `capacity * QUEUE_FACTOR` must not
/// overflow `u32` (a misconfigured `u32::MAX` would otherwise panic in debug /
/// wrap in release when sizing the accept-backlog semaphore). Matches the agent's
/// `MAX_TRUSTED_CPU` clamp, so a worker over-reporting capacity is bounded on both
/// sides.
const MAX_CAPACITY: u32 = 256;

/// Marker the injected DLL drops in the per-action scratch dir when a VFS remote
/// attempt must be abandoned and re-run locally. Strict unsupplied reads and
/// unsupported VFS-root wildcard enumeration both use it.
/// Must match `kUnvirtMarker` in `hooks/src/interceptor.cpp`.
const UNVIRT_MARKER: &str = ".sbz-unvirtualized";
/// Marker the injected DLL drops when a scratch-cwd action mutates a logical-root
/// path. Until output WriteBack is wired end-to-end, those outputs would be
/// stranded in scratch, so the worker must force local fallback instead.
/// Must match `kUnsafeOutputMarker` in `hooks/src/interceptor.cpp`.
const UNSAFE_OUTPUT_MARKER: &str = ".sbz-unsafe-output";

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
    cluster_token: Option<String>,
    worker_id: String,
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
        // Clamp to [1, MAX_CAPACITY]: a 0 would admit nothing, and a misconfigured
        // huge value (e.g. u32::MAX) would overflow `capacity * QUEUE_FACTOR` below
        // (panic in debug / wrap in release) — RES-001.
        let capacity = capacity.clamp(1, MAX_CAPACITY);
        Self {
            running: Arc::new(AtomicU32::new(0)),
            served: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            limit: Arc::new(Semaphore::new(capacity as usize)),
            accept: Arc::new(Semaphore::new((capacity * QUEUE_FACTOR) as usize)),
            capacity,
            ceiling: default_action_ceiling(),
            vfs: None,
            aborts: Arc::new(Mutex::new(HashMap::new())),
            cluster_token: None,
            worker_id: crate::coordination::default_worker_id(),
        }
    }

    /// Enables signed action capability enforcement when a cluster token is configured.
    pub fn with_action_capability_auth(
        mut self,
        cluster_token: Option<String>,
        worker_id: String,
    ) -> Self {
        self.cluster_token = cluster_token.filter(|token| !token.is_empty());
        self.worker_id = worker_id;
        self
    }

    fn now_unix_secs() -> Result<u64, Status> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| Status::permission_denied("capability time unavailable"))
    }

    fn verify_execute_capability(
        &self,
        action_capability: &[u8],
        action_id: &str,
        session_id: &str,
        cmd: &Command,
        vfs: Option<&VfsExecution>,
    ) -> Result<(), Status> {
        let Some(token) = &self.cluster_token else {
            return Ok(());
        };
        if action_capability.is_empty() {
            return Err(Status::permission_denied("missing action capability"));
        }

        let key = capability::cap_key(token);
        let cap = capability::decode_and_verify(action_capability, &key, Self::now_unix_secs()?)
            .map_err(|e| Status::permission_denied(e.reason()))?;
        if cap.worker_id != self.worker_id {
            return Err(Status::permission_denied("capability not for this worker"));
        }
        if cap.action_id != action_id {
            return Err(Status::permission_denied("action id mismatch"));
        }
        if cap.session_id != session_id {
            return Err(Status::permission_denied("session id mismatch"));
        }
        let expected_digest = capability::command_digest(&cmd.argv, &cmd.env, &cmd.cwd);
        if cap.command_digest != expected_digest {
            return Err(Status::permission_denied("command mismatch"));
        }
        if cap.vfs_digest != capability::vfs_digest(vfs) {
            return Err(Status::permission_denied("vfs mismatch"));
        }
        Ok(())
    }
    fn verify_abort_capability(
        &self,
        action_capability: &[u8],
        action_id: &str,
    ) -> Result<(), Status> {
        let Some(token) = &self.cluster_token else {
            return Ok(());
        };
        if action_capability.is_empty() {
            return Err(Status::permission_denied("missing action capability"));
        }
        let key = capability::cap_key(token);
        let cap = capability::decode_and_verify(action_capability, &key, Self::now_unix_secs()?)
            .map_err(|e| Status::permission_denied(e.reason()))?;
        if cap.worker_id != self.worker_id {
            return Err(Status::permission_denied("capability not for this worker"));
        }
        if cap.action_id != action_id {
            return Err(Status::permission_denied("action id mismatch"));
        }
        Ok(())
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

fn resolved_tool_digest(cmd: &Command) -> String {
    // Extract PATH the SAME way the agent does for the weak key, so the two sides
    // can never resolve a different binary from an equivalent env and spuriously
    // mismatch (COR-005 symmetry; a mismatch is always safe — a lost cache record,
    // never a false hit). The agent sorts the env before reading PATH
    // (`intake.rs` → `weak_key_and_tool`); a proto `map` can carry distinct
    // case-variant keys ("PATH" vs "Path") with different values, so without the
    // sort the worker would pick by HashMap iteration order. Sorting makes both
    // sides deterministic and identical.
    let mut env: Vec<(String, String)> = cmd
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    env.sort();
    let path_env = env
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.as_str());
    sembazuru_cas::toolchain::toolchain_digest(
        cmd.argv.first().map(String::as_str).unwrap_or(""),
        path_env,
        &cmd.cwd,
    )
    .to_string()
}

fn cap_predicted_paths(mut predicted_paths: Vec<String>) -> Vec<String> {
    predicted_paths.truncate(MAX_PREDICTED_PATHS);
    predicted_paths
}

fn exit_event(
    code: i32,
    wall_us: u64,
    resolved_tool_digest: String,
) -> Result<ExecuteEvent, Status> {
    Ok(ExecuteEvent {
        event: Some(Event::Exit(ExitStatus {
            exit_code: code,
            wall_time_us: wall_us,
            user_time_us: 0,
            kernel_time_us: 0,
            resolved_tool_digest,
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
    let (mut child, pipe_task, job, unvirt_marker, unsafe_output_marker, scratch_dir) =
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
                // Fail-closed: if the DLL marked an unsupported VFS access, the
                // process did not complete against a trustworthy remote view.
                // Report NOT-completed (Failed, no exit) so the agent re-runs the
                // whole action locally. This is the sanctioned fallback channel:
                // the agent treats "no exit status" as a fallback trigger (a
                // nonzero exit would NOT fall back).
                if unvirt_marker.as_ref().is_some_and(|m| m.exists()) {
                    let _ = tx
                        .send(state_event(
                            ActionState::Failed,
                            "unsupported VFS access under vfs_root: re-run locally",
                        ))
                        .await;
                } else if unsafe_output_marker.as_ref().is_some_and(|m| m.exists()) {
                    let _ = tx
                        .send(state_event(
                            ActionState::Failed,
                            "output under virtual cwd requires WriteBack: re-run locally",
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
                    let tool_digest = resolved_tool_digest(&cmd);
                    let _ = tx.send(exit_event(code, wall, tool_digest)).await;
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
        stop_vfs_pipe_task(t).await;
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

async fn stop_vfs_pipe_task(task: tokio::task::JoinHandle<std::io::Result<()>>) {
    task.abort();
    let _ = task.await;
}

/// Builds the child process for an action. Plain mode spawns the command
/// directly (M5 scale path) and returns `(child, None)`. VFS mode (M6.1) starts
/// a per-action pipe server, waits for it to be dialable, then spawns the
/// compiler through `launcher.exe` (DLL injection) with an explicit environment;
/// it returns the pipe-server task so the caller can stop it after the run. On
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
        // VFS local-rerun marker path to check after exit; `None` in plain mode.
        Option<std::path::PathBuf>,
        // Scratch-cwd output-mutation marker path to check after exit; `None`
        // when the child ran in its submitted cwd or in plain mode.
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
        return Ok((child, None, Some(job), None, None, None));
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
    let child_cwd = vfs_child_cwd(&cmd.cwd, &v.vfs_root, &scratch);
    if let VfsChildCwd::Scratch(path) = &child_cwd {
        match tokio::fs::create_dir_all(path).await {
            Ok(()) => {}
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&scratch_for_cleanup).await;
                return Err(setup_err("create child cwd failed", e));
            }
        }
    }
    let scratch_str = scratch.to_string_lossy().into_owned();

    // Start the pipe server and WAIT for readiness before launching, so the
    // compiler cannot dial the pipe before it exists (Plan risk 1). A create
    // failure drops `ready_tx`, so `ready_rx.await` errors and we fail closed.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let cas = cfg.cas_root.clone();
    let auth_token = cfg.cluster_token.clone().unwrap_or_default();
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
            auth_token,
        )
        .await
    });
    if ready_rx.await.is_err() {
        stop_vfs_pipe_task(pipe_task).await;
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
    if let Some(cwd) = child_cwd.path() {
        command.current_dir(cwd);
    }
    command.env_clear();
    for (k, val) in &cmd.env {
        command.env(k, val);
    }
    // Authoritative VFS cwd: cmd.env must not smuggle fake logical cwd remaps
    // when this action is not intentionally running from scratch.
    command.env_remove("SEMBAZURU_VFS_CWD");
    // Authoritative trace destination: only the worker-selected trace dir may
    // collect hook traces for this action.
    command.env_remove("SEMBAZURU_TRACE_DIR");
    command.env("SEMBAZURU_MODE", "vfs");
    command.env("SEMBAZURU_VFS_ROOT", &v.vfs_root);
    if let VfsChildCwd::Scratch(_) = &child_cwd {
        command.env("SEMBAZURU_VFS_CWD", &cmd.cwd);
    }
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
    let unvirt_marker = Some(std::path::PathBuf::from(&scratch_str).join(UNVIRT_MARKER));
    let unsafe_output_marker = if matches!(&child_cwd, VfsChildCwd::Scratch(_)) {
        Some(std::path::PathBuf::from(&scratch_str).join(UNSAFE_OUTPUT_MARKER))
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
            stop_vfs_pipe_task(pipe_task).await;
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
            stop_vfs_pipe_task(pipe_task).await;
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
        unsafe_output_marker,
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
        self.verify_execute_capability(
            &req.action_capability,
            &req.action_id,
            &req.session_id,
            &cmd,
            req.vfs.as_ref(),
        )?;
        // M6.1: VFS config and prefetch hint ride the request; the worker's own
        // install config decides whether VFS mode is even possible.
        let action_id = req.action_id;
        // ADR 0013: the agent-minted data-plane session id. Previously decoded
        // and dropped here; now forwarded onto the VFS handshake so the agent can
        // bind file supply to the authoritative session (root/pins/outputs).
        let session_id = req.session_id;
        let vfs_req = req.vfs;
        let predicted_paths = cap_predicted_paths(req.predicted_paths);
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
        let req = request.into_inner();
        self.verify_abort_capability(&req.action_capability, &req.action_id)?;
        let action_id = req.action_id;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_capacity_clamps_and_does_not_overflow() {
        // RES-001: a misconfigured huge capacity must not panic — pre-fix
        // `capacity * QUEUE_FACTOR` overflowed u32 (panic in debug) for u32::MAX —
        // and must clamp to the safe maximum.
        let w = WorkerService::with_capacity(u32::MAX);
        assert_eq!(
            w.capacity(),
            MAX_CAPACITY,
            "a huge capacity clamps to the safe max"
        );
        // Zero clamps up to 1 (admit at least one action); a normal value passes.
        assert_eq!(WorkerService::with_capacity(0).capacity(), 1);
        assert_eq!(WorkerService::with_capacity(4).capacity(), 4);
    }

    #[test]
    fn resolved_tool_digest_wiring_reports_non_empty_digest() {
        let current_exe = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let cmd = Command {
            argv: vec![current_exe.to_string_lossy().into_owned()],
            env: Default::default(),
            cwd: cwd.to_string_lossy().into_owned(),
        };

        assert!(
            !resolved_tool_digest(&cmd).is_empty(),
            "worker tool digest wiring should report a non-empty digest"
        );
    }

    #[test]
    fn execute_truncates_predicted_paths_before_prefetch() {
        let paths = (0..(MAX_PREDICTED_PATHS + 1))
            .map(|i| format!("c:\\src\\h{i}.h"))
            .collect::<Vec<_>>();

        let capped = cap_predicted_paths(paths);

        assert_eq!(capped.len(), MAX_PREDICTED_PATHS);
        assert_eq!(
            capped[MAX_PREDICTED_PATHS - 1],
            format!("c:\\src\\h{}.h", MAX_PREDICTED_PATHS - 1)
        );
    }

    #[test]
    fn vfs_child_cwd_maps_vfs_root_to_scratch() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd(r"C:\src\proj", r"C:\src\proj", scratch),
            VfsChildCwd::Scratch(scratch.to_path_buf())
        );
    }

    #[test]
    fn vfs_child_cwd_preserves_relative_subdir_under_scratch() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd(r"C:\src\proj\sub\dir", r"C:\src\proj", scratch),
            VfsChildCwd::Scratch(scratch.join(r"sub\dir"))
        );
    }

    #[test]
    fn vfs_child_cwd_matches_windows_paths_case_insensitively() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd(r"C:\SRC\proj\sub", r"c:\src\PROJ", scratch),
            VfsChildCwd::Scratch(scratch.join("sub"))
        );
    }

    #[test]
    fn vfs_child_cwd_rejects_parent_dir_suffix_under_root() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd(r"C:\src\proj\..\outside", r"C:\src\proj", scratch),
            VfsChildCwd::Original(PathBuf::from(r"C:\src\proj\..\outside"))
        );
    }

    #[test]
    fn vfs_child_cwd_leaves_outside_root_unchanged() {
        assert_eq!(
            vfs_child_cwd(
                r"D:\other",
                r"C:\src\proj",
                std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run")
            ),
            VfsChildCwd::Original(PathBuf::from(r"D:\other"))
        );
    }

    #[test]
    fn vfs_child_cwd_omits_empty_cwd() {
        assert_eq!(
            vfs_child_cwd("", r"C:\src\proj", std::path::Path::new(r"C:\scratch")),
            VfsChildCwd::None
        );
    }

    #[tokio::test]
    async fn stopping_vfs_pipe_waits_until_the_task_is_dropped() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ActiveGuard(Arc<AtomicUsize>);

        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let active = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let active_for_task = Arc::clone(&active);
        let writes_for_task = Arc::clone(&writes);
        let task = tokio::spawn(async move {
            active_for_task.fetch_add(1, Ordering::SeqCst);
            let _active_guard = ActiveGuard(active_for_task);
            let _ = started_tx.send(());
            let _ = release_rx.await;
            writes_for_task.fetch_add(1, Ordering::SeqCst);
            std::io::Result::Ok(())
        });
        started_rx.await.expect("pipe task should start");

        stop_vfs_pipe_task(task).await;

        assert_eq!(active.load(Ordering::SeqCst), 0);
        let _ = release_tx.send(());
        tokio::task::yield_now().await;
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}
