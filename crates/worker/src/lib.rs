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
mod sandbox;
#[cfg(windows)]
pub mod service;
pub mod vfs_pipe;

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
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
use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

use crate::sandbox::{
    ActionPipeSecurity, ActionToken, PrivateRuntime, PrivateScratch, RestrictedCommand,
    RestrictedProcess, secure_random_hex,
};
use crate::vfs_pipe::{ActionVfsServer, start_secured_action_vfs};

/// Disambiguates per-action VFS pipe/scratch names within a worker process.
#[cfg(test)]
static EXEC_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

fn vfs_child_cwd(
    cmd_cwd: &str,
    vfs_root: &str,
    scratch: &Path,
    allow_original_cwd: bool,
) -> VfsChildCwd {
    vfs_child_cwd_with_access(cmd_cwd, vfs_root, scratch, allow_original_cwd, |cwd| {
        std::fs::metadata(cwd).map(|m| m.is_dir()).unwrap_or(false)
    })
}

fn vfs_child_cwd_with_access(
    cmd_cwd: &str,
    vfs_root: &str,
    scratch: &Path,
    allow_original_cwd: bool,
    can_enter_cwd: impl Fn(&Path) -> bool,
) -> VfsChildCwd {
    if cmd_cwd.is_empty() {
        return VfsChildCwd::None;
    }
    if vfs_root.is_empty() {
        return VfsChildCwd::Original(PathBuf::from(cmd_cwd));
    }

    let cwd = Path::new(cmd_cwd);
    let root = Path::new(vfs_root);
    match strip_prefix_case_insensitive(cwd, root) {
        Some(_) if allow_original_cwd && can_enter_cwd(cwd) => {
            VfsChildCwd::Original(cwd.to_path_buf())
        }
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
/// Dedicated action exit for every VFS child-injection failure, regardless of
/// whether the hook can create `UNVIRT_MARKER`. Must match the hook constant.
const VFS_INJECTION_FAIL_CLOSED_EXIT_CODE: u32 = 0x0053_4249;
const VFS_INJECTION_FAIL_CLOSED_DETAIL: &str = "VFS child injection failed: re-run locally";
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
    scratch_root: Arc<PathBuf>,
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
            scratch_root: Arc::new(std::env::temp_dir()),
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

    /// Selects an already-provisioned parent for per-action private scratch leaves.
    pub fn with_scratch_root(mut self, root: PathBuf) -> Self {
        self.scratch_root = Arc::new(root);
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

fn vfs_injection_fail_closed_detail(code: u32) -> Option<&'static str> {
    (code == VFS_INJECTION_FAIL_CLOSED_EXIT_CODE).then_some(VFS_INJECTION_FAIL_CLOSED_DETAIL)
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

const BASELINE_ENV: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "ComSpec",
    "WINDIR",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "NUMBER_OF_PROCESSORS",
];

const VFS_RESERVED_ENV: &[&str] = &[
    "SEMBAZURU_MODE",
    "SEMBAZURU_VFS_ROOT",
    "SEMBAZURU_VFS_CWD",
    "SEMBAZURU_VFS_PIPE",
    "SEMBAZURU_VFS_SCRATCH",
    "SEMBAZURU_VFS_STRICT",
    "SEMBAZURU_TRACE_DIR",
];

struct VfsEnvironment<'a> {
    root: &'a str,
    logical_cwd: Option<&'a str>,
    pipe: &'a str,
    scratch: &'a Path,
    strict: bool,
    trace: Option<&'a Path>,
}

fn effective_environment(
    cmd: &Command,
    scratch: &Path,
    vfs: Option<VfsEnvironment<'_>>,
) -> Result<Vec<(OsString, OsString)>, String> {
    let mut values: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    if vfs.is_none() {
        for &name in BASELINE_ENV {
            if let Some(value) = std::env::var_os(name) {
                values.insert(name.to_ascii_lowercase(), (OsString::from(name), value));
            }
        }
    }
    let mut submitted = BTreeMap::new();
    for (name, value) in &cmd.env {
        let folded = name.to_lowercase();
        if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
            return Err("invalid command environment".into());
        }
        if submitted.insert(folded.clone(), ()).is_some() {
            return Err("duplicate command environment key".into());
        }
        if vfs.is_some()
            && VFS_RESERVED_ENV
                .iter()
                .any(|reserved| reserved.eq_ignore_ascii_case(name))
        {
            continue;
        }
        values.insert(folded, (OsString::from(name), OsString::from(value)));
    }
    for name in ["TEMP", "TMP"] {
        values.insert(
            name.to_ascii_lowercase(),
            (OsString::from(name), scratch.as_os_str().to_os_string()),
        );
    }
    if let Some(vfs) = vfs {
        let mut authoritative = vec![
            ("SEMBAZURU_MODE", OsString::from("vfs")),
            ("SEMBAZURU_VFS_ROOT", OsString::from(vfs.root)),
            ("SEMBAZURU_VFS_PIPE", OsString::from(vfs.pipe)),
            (
                "SEMBAZURU_VFS_SCRATCH",
                vfs.scratch.as_os_str().to_os_string(),
            ),
            (
                "SEMBAZURU_VFS_STRICT",
                OsString::from(if vfs.strict { "1" } else { "0" }),
            ),
        ];
        if let Some(cwd) = vfs.logical_cwd {
            authoritative.push(("SEMBAZURU_VFS_CWD", OsString::from(cwd)));
        }
        if let Some(trace) = vfs.trace {
            authoritative.push(("SEMBAZURU_TRACE_DIR", trace.as_os_str().to_os_string()));
        }
        for (name, value) in authoritative {
            values.insert(name.to_ascii_lowercase(), (OsString::from(name), value));
        }
    }
    Ok(values.into_values().collect())
}

fn environment_value<'a>(environment: &'a [(OsString, OsString)], name: &str) -> Option<&'a str> {
    environment
        .iter()
        .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.to_str())
}

struct ObservedTool {
    application: Option<PathBuf>,
    digest: String,
}

fn observe_tool(
    token: &ActionToken,
    cmd: &Command,
    environment: &[(OsString, OsString)],
    cwd: &Path,
    require_content: bool,
) -> Result<ObservedTool, String> {
    let cwd = cwd
        .to_str()
        .ok_or_else(|| setup_err("command cwd is not Unicode", cwd.display()))?;
    let path = environment_value(environment, "PATH");
    let identity = token
        .impersonated(|| {
            Ok(sembazuru_cas::toolchain::toolchain_identity(
                &cmd.argv[0],
                path,
                cwd,
            ))
        })
        .map_err(|error| setup_err("command executable observation failed", error))?;
    match identity {
        sembazuru_cas::toolchain::ToolchainIdentity::Content { digest, path } => Ok(ObservedTool {
            application: Some(path),
            digest: digest.to_string(),
        }),
        sembazuru_cas::toolchain::ToolchainIdentity::NameOnly { digest, .. }
            if !require_content =>
        {
            Ok(ObservedTool {
                application: None,
                digest: digest.to_string(),
            })
        }
        sembazuru_cas::toolchain::ToolchainIdentity::NameOnly { .. } => Err(setup_err(
            "command executable could not be resolved",
            &cmd.argv[0],
        )),
    }
}

struct TracePublish {
    stage: PathBuf,
    destination: PathBuf,
}

struct BuiltChild {
    process: RestrictedProcess,
    stdout: tokio::fs::File,
    stderr: tokio::fs::File,
    vfs_server: Option<ActionVfsServer>,
    scratch: PrivateScratch,
    unvirt_marker: Option<PathBuf>,
    unsafe_output_marker: Option<PathBuf>,
    trace: Option<TracePublish>,
    resolved_tool_digest: String,
}

fn move_file_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both paths are NUL-terminated and live. Zero flags intentionally
    // omit MOVEFILE_REPLACE_EXISTING, so a racing destination wins unchanged.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(80 | 183) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "trace destination already exists",
            )),
            _ => Err(error),
        };
    }
    Ok(())
}

fn publish_trace_file(
    source: &Path,
    final_path: &Path,
    before_move: impl FnOnce(&Path),
) -> io::Result<()> {
    if std::fs::symlink_metadata(final_path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "trace destination already exists",
        ));
    }
    let destination = final_path
        .parent()
        .ok_or_else(|| io::Error::other("trace destination has no parent"))?;
    let temp = destination.join(format!(".sbz-publish-{}.tmp", secure_random_hex()?));
    let result = (|| {
        let mut input = std::fs::File::open(source)?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        io::copy(&mut input, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        drop(output);
        before_move(&temp);
        move_file_no_replace(&temp, final_path)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

fn publish_trace_directory(source: &Path, destination: &Path) -> io::Result<()> {
    const REPARSE: u32 = windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    let source_meta = std::fs::symlink_metadata(source)?;
    if !source_meta.is_dir() || source_meta.file_attributes() & REPARSE != 0 {
        return Err(io::Error::other(
            "trace staging directory is not a regular directory",
        ));
    }
    std::fs::create_dir_all(destination)?;
    let destination_meta = std::fs::symlink_metadata(destination)?;
    if !destination_meta.is_dir() || destination_meta.file_attributes() & REPARSE != 0 {
        return Err(io::Error::other(
            "trace destination is not a regular directory",
        ));
    }
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sbzt"))
        {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_attributes() & REPARSE != 0 {
            return Err(io::Error::other("trace source is not a regular file"));
        }
        publish_trace_file(&path, &destination.join(entry.file_name()), |_| {})?;
    }
    Ok(())
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
    scratch_root: Arc<PathBuf>,
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
    let BuiltChild {
        mut process,
        stdout,
        stderr,
        vfs_server,
        scratch,
        unvirt_marker,
        unsafe_output_marker,
        trace,
        resolved_tool_digest,
    } = match build_child(&cmd, vfs_plan, predicted_paths, session_id, &scratch_root).await {
        Ok(parts) => parts,
        Err(detail) => {
            let _ = tx.send(state_event(ActionState::Failed, &detail)).await;
            return;
        }
    };

    // Every production process is already suspended-assigned-resumed by this
    // point. Abort keeps only another reference to that same kill-on-close Job.
    aborts
        .lock()
        .expect("aborts map poisoned")
        .insert(action_id.clone(), process.job());

    // Drain both pipes continuously. Waiting first can deadlock once either pipe
    // exceeds the Windows pipe buffer, so readers start before RUNNING is sent.
    let stdout_reader = spawn_stdio_reader(stdout, false, tx.clone());
    let stderr_reader = spawn_stdio_reader(stderr, true, tx.clone());

    let _ = tx.send(state_event(ActionState::Running, "")).await;

    enum Finish {
        Exited(io::Result<u32>),
        Cancelled,
        Ceiling,
    }
    let finish = tokio::select! {
        _ = tx.closed() => {
            process.terminate();
            let _ = process.wait().await;
            Finish::Cancelled
        }
        _ = tokio::time::sleep(ceiling) => {
            process.terminate();
            let _ = process.wait().await;
            Finish::Ceiling
        }
        result = process.wait() => Finish::Exited(result),
    };

    if matches!(&finish, Finish::Exited(Err(_))) {
        process.terminate();
        let _ = process.wait().await;
    }

    // `wait` has observed the direct process and terminated the complete Job.
    // Only then can EOF prove that descendants no longer own either stdio pipe.
    let _ = stdout_reader.await;
    let _ = stderr_reader.await;

    // The VFS broker owns CAS and cluster-token access. Stop it before consulting
    // or publishing action-controlled files from private scratch.
    if let Some(server) = vfs_server {
        server.shutdown().await;
    }
    aborts
        .lock()
        .expect("aborts map poisoned")
        .remove(&action_id);

    match finish {
        Finish::Exited(Ok(code)) => {
            if let Some(detail) = vfs_injection_fail_closed_detail(code) {
                let _ = tx.send(state_event(ActionState::Failed, detail)).await;
            } else {
                let publish = if let Some(trace) = trace {
                    tokio::task::spawn_blocking(move || {
                        publish_trace_directory(&trace.stage, &trace.destination)
                    })
                    .await
                    .map_err(|_| io::Error::other("trace publisher failed"))
                    .and_then(|result| result)
                } else {
                    Ok(())
                };
                if let Err(error) = publish {
                    let detail = setup_err("trace publish failed", error);
                    let _ = tx.send(state_event(ActionState::Failed, &detail)).await;
                } else if unvirt_marker.as_ref().is_some_and(|marker| marker.exists()) {
                    let _ = tx
                        .send(state_event(
                            ActionState::Failed,
                            "unsupported VFS access under vfs_root: re-run locally",
                        ))
                        .await;
                } else if unsafe_output_marker
                    .as_ref()
                    .is_some_and(|marker| marker.exists())
                {
                    let _ = tx
                        .send(state_event(
                            ActionState::Failed,
                            "output under virtual cwd requires WriteBack: re-run locally",
                        ))
                        .await;
                } else {
                    let wall = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                    let _ = tx
                        .send(exit_event(code as i32, wall, resolved_tool_digest))
                        .await;
                    let _ = tx.send(state_event(ActionState::Completed, "")).await;
                }
            }
        }
        Finish::Exited(Err(error)) => {
            let detail = setup_err("wait failed", error);
            let _ = tx.send(state_event(ActionState::Failed, &detail)).await;
        }
        Finish::Ceiling => {
            let _ = tx
                .send(state_event(
                    ActionState::Failed,
                    "exceeded execution ceiling",
                ))
                .await;
        }
        Finish::Cancelled => {}
    }

    let scratch = scratch.into_path();
    if let Err(error) = tokio::fs::remove_dir_all(&scratch).await
        && scratch.exists()
    {
        eprintln!(
            "sembazuru-worker: failed to remove scratch {}: {e}",
            scratch.display(),
            e = error,
        );
    }
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
    scratch_root: &Path,
) -> Result<BuiltChild, String> {
    if !scratch_root.is_absolute() {
        return Err(setup_err(
            "private scratch root is not absolute",
            scratch_root.display(),
        ));
    }
    let token =
        ActionToken::create().map_err(|error| setup_err("action token setup failed", error))?;
    let leaf = format!(
        "action-{}",
        secure_random_hex().map_err(|error| setup_err("scratch identity failed", error))?
    );
    let scratch = PrivateScratch::create(scratch_root, &leaf, &token)
        .map_err(|error| setup_err("private scratch setup failed", error))?;

    let finish_process = |mut process: RestrictedProcess,
                          vfs_server: Option<ActionVfsServer>,
                          scratch: PrivateScratch,
                          unvirt_marker: Option<PathBuf>,
                          unsafe_output_marker: Option<PathBuf>,
                          trace: Option<TracePublish>,
                          resolved_tool_digest: String| async move {
        let output = process.take_output();
        match output {
            Ok((stdout, stderr)) => Ok(BuiltChild {
                process,
                stdout,
                stderr,
                vfs_server,
                scratch,
                unvirt_marker,
                unsafe_output_marker,
                trace,
                resolved_tool_digest,
            }),
            Err(error) => {
                process.terminate();
                let _ = process.wait().await;
                if let Some(server) = vfs_server {
                    server.shutdown().await;
                }
                Err(setup_err("stdio setup failed", error))
            }
        }
    };

    let Some((v, cfg)) = vfs_plan else {
        let environment = effective_environment(cmd, scratch.path(), None)?;
        let cwd = if cmd.cwd.is_empty() {
            scratch.path().to_path_buf()
        } else {
            PathBuf::from(&cmd.cwd)
        };
        if !cwd.is_absolute() {
            return Err(setup_err("command cwd is not absolute", &cmd.cwd));
        }
        let observed = observe_tool(&token, cmd, &environment, &cwd, true)?;
        let application = observed
            .application
            .expect("content-required observation has an application path");
        let mut command = RestrictedCommand::new(application, cwd);
        for argument in &cmd.argv[1..] {
            command = command.arg(argument);
        }
        for (name, value) in environment {
            command = command.env(name, value);
        }
        let process = RestrictedProcess::spawn(&token, &command)
            .map_err(|error| setup_err("spawn failed", error))?;
        return finish_process(process, None, scratch, None, None, None, observed.digest).await;
    };

    let agent_addr: SocketAddr = v
        .agent_fileserver
        .parse()
        .map_err(|e| setup_err("invalid agent fileserver address", e))?;
    let runtime = PrivateRuntime::stage(&scratch, &cfg.launcher, &cfg.dll, &token)
        .map_err(|error| setup_err("private runtime staging failed", error))?;
    let suffix = secure_random_hex().map_err(|error| setup_err("pipe identity failed", error))?;
    let pipe_name = format!("sbz-exec-{suffix}");
    let child_cwd = vfs_child_cwd(&cmd.cwd, &v.vfs_root, scratch.path(), v.allow_original_cwd);
    if let VfsChildCwd::Scratch(path) = &child_cwd {
        tokio::fs::create_dir_all(path)
            .await
            .map_err(|error| setup_err("create child cwd failed", error))?;
    }
    let trace = if v.trace_dir.is_empty() {
        None
    } else {
        let stage = scratch.path().join(".trace");
        std::fs::create_dir(&stage)
            .map_err(|error| setup_err("create trace stage failed", error))?;
        Some(TracePublish {
            stage,
            destination: PathBuf::from(&v.trace_dir),
        })
    };
    let security = ActionPipeSecurity::new(&token)
        .map_err(|error| setup_err("VFS pipe security failed", error))?;
    let vfs_server = start_secured_action_vfs(
        pipe_name.clone(),
        agent_addr,
        scratch.path().to_path_buf(),
        cfg.cas_root.clone(),
        Duration::ZERO,
        predicted_paths,
        v.vfs_root.clone(),
        session_id,
        cfg.cluster_token.clone().unwrap_or_default(),
        security,
    )
    .await
    .map_err(|error| setup_err("VFS pipe server failed to start", error))?;

    let trace_stage = trace.as_ref().map(|publish| publish.stage.as_path());
    let logical_cwd = matches!(child_cwd, VfsChildCwd::Scratch(_)).then_some(cmd.cwd.as_str());
    let environment = match effective_environment(
        cmd,
        scratch.path(),
        Some(VfsEnvironment {
            root: &v.vfs_root,
            logical_cwd,
            pipe: &pipe_name,
            scratch: scratch.path(),
            strict: v.strict,
            trace: trace_stage,
        }),
    ) {
        Ok(environment) => environment,
        Err(error) => {
            vfs_server.shutdown().await;
            return Err(error);
        }
    };
    let cwd = child_cwd
        .path()
        .unwrap_or_else(|| scratch.path())
        .to_path_buf();
    if !cwd.is_absolute() {
        vfs_server.shutdown().await;
        return Err(setup_err("command cwd is not absolute", cwd.display()));
    }
    let observed = match observe_tool(&token, cmd, &environment, &cwd, false) {
        Ok(observed) => observed,
        Err(error) => {
            vfs_server.shutdown().await;
            return Err(error);
        }
    };
    let mut command = RestrictedCommand::new(runtime.launcher(), cwd).arg(runtime.interceptor64());
    for argument in &cmd.argv {
        command = command.arg(argument);
    }
    for (name, value) in environment {
        command = command.env(name, value);
    }
    let unvirt_marker = Some(scratch.path().join(UNVIRT_MARKER));
    let unsafe_output_marker = if matches!(&child_cwd, VfsChildCwd::Scratch(_)) {
        Some(scratch.path().join(UNSAFE_OUTPUT_MARKER))
    } else {
        None
    };
    let process = match RestrictedProcess::spawn(&token, &command) {
        Ok(process) => process,
        Err(error) => {
            vfs_server.shutdown().await;
            return Err(setup_err("launcher spawn failed", error));
        }
    };
    finish_process(
        process,
        Some(vfs_server),
        scratch,
        unvirt_marker,
        unsafe_output_marker,
        trace,
        observed.digest,
    )
    .await
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
            Arc::clone(&self.scratch_root),
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
        // Both plain and VFS actions register the restricted process's Job; the
        // reassign path can also cancel by dropping the execution stream.
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
    fn vfs_injection_fail_closed_exit_maps_to_failed_detail() {
        assert_eq!(
            vfs_injection_fail_closed_detail(0x534249),
            Some("VFS child injection failed: re-run locally")
        );
        assert_eq!(vfs_injection_fail_closed_detail(0), None);
    }

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
            vfs_child_cwd_with_access(r"C:\src\proj", r"C:\src\proj", scratch, false, |_| false),
            VfsChildCwd::Scratch(scratch.to_path_buf())
        );
    }

    #[test]
    fn vfs_child_cwd_preserves_relative_subdir_under_scratch() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd_with_access(
                r"C:\src\proj\sub\dir",
                r"C:\src\proj",
                scratch,
                false,
                |_| false
            ),
            VfsChildCwd::Scratch(scratch.join(r"sub\dir"))
        );
    }

    #[test]
    fn vfs_child_cwd_keeps_accessible_original_cwd_under_vfs_root() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd_with_access(
                r"C:\src\proj\project",
                r"C:\src\proj",
                scratch,
                true,
                |_| true
            ),
            VfsChildCwd::Original(PathBuf::from(r"C:\src\proj\project"))
        );
    }

    #[test]
    fn vfs_child_cwd_uses_scratch_for_remote_run_when_original_cwd_disallowed() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd_with_access(
                r"C:\src\proj\project",
                r"C:\src\proj",
                scratch,
                false,
                |_| true
            ),
            VfsChildCwd::Scratch(scratch.join("project"))
        );
    }

    #[test]
    fn vfs_child_cwd_keeps_accessible_vfs_root_as_original() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd_with_access(r"C:\src\proj", r"C:\src\proj", scratch, true, |_| true),
            VfsChildCwd::Original(PathBuf::from(r"C:\src\proj"))
        );
    }

    #[test]
    fn vfs_child_cwd_matches_windows_paths_case_insensitively() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd_with_access(r"C:\SRC\proj\sub", r"c:\src\PROJ", scratch, false, |_| {
                false
            }),
            VfsChildCwd::Scratch(scratch.join("sub"))
        );
    }

    #[test]
    fn vfs_child_cwd_rejects_parent_dir_suffix_under_root() {
        let scratch = std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run");

        assert_eq!(
            vfs_child_cwd_with_access(
                r"C:\src\proj\..\outside",
                r"C:\src\proj",
                scratch,
                false,
                |_| false
            ),
            VfsChildCwd::Original(PathBuf::from(r"C:\src\proj\..\outside"))
        );
    }

    #[test]
    fn vfs_child_cwd_leaves_outside_root_unchanged() {
        assert_eq!(
            vfs_child_cwd_with_access(
                r"D:\other",
                r"C:\src\proj",
                std::path::Path::new(r"C:\ProgramData\Sembazuru\scratch\run"),
                false,
                |_| false
            ),
            VfsChildCwd::Original(PathBuf::from(r"D:\other"))
        );
    }

    #[test]
    fn vfs_child_cwd_omits_empty_cwd() {
        assert_eq!(
            vfs_child_cwd_with_access(
                "",
                r"C:\src\proj",
                std::path::Path::new(r"C:\scratch"),
                false,
                |_| false
            ),
            VfsChildCwd::None
        );
    }

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sembazuru-worker-{label}-{}-{}",
            std::process::id(),
            EXEC_SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn effective_environment_is_case_insensitive_and_authoritative() {
        let scratch = Path::new(r"C:\private\action");
        let cmd = Command {
            argv: vec!["tool.exe".into()],
            env: [
                ("Path".into(), r"C:\submitted\bin".into()),
                ("temp".into(), r"C:\escape".into()),
                ("sembazuru_vfs_pipe".into(), "attacker".into()),
            ]
            .into_iter()
            .collect(),
            cwd: String::new(),
        };
        let plain = effective_environment(&cmd, scratch, None).unwrap();
        assert_eq!(environment_value(&plain, "PATH"), Some(r"C:\submitted\bin"));
        assert_eq!(
            environment_value(&plain, "TEMP"),
            Some(r"C:\private\action")
        );
        assert_eq!(environment_value(&plain, "TMP"), Some(r"C:\private\action"));

        let vfs = effective_environment(
            &cmd,
            scratch,
            Some(VfsEnvironment {
                root: r"C:\src",
                logical_cwd: Some(r"C:\src\project"),
                pipe: "private-pipe",
                scratch,
                strict: true,
                trace: Some(Path::new(r"C:\private\action\.trace")),
            }),
        )
        .unwrap();
        assert_eq!(
            environment_value(&vfs, "SEMBAZURU_VFS_PIPE"),
            Some("private-pipe")
        );
        assert_eq!(environment_value(&vfs, "SEMBAZURU_VFS_STRICT"), Some("1"));
        assert_eq!(environment_value(&vfs, "TEMP"), Some(r"C:\private\action"));
        assert_eq!(
            environment_value(&vfs, "NUMBER_OF_PROCESSORS"),
            None,
            "VFS must not inherit an unsubmitted broker baseline variable"
        );

        let mut submitted_vfs = cmd.clone();
        submitted_vfs
            .env
            .insert("NUMBER_OF_PROCESSORS".into(), "submitted-value".into());
        let submitted = effective_environment(
            &submitted_vfs,
            scratch,
            Some(VfsEnvironment {
                root: r"C:\src",
                logical_cwd: None,
                pipe: "private-pipe",
                scratch,
                strict: false,
                trace: None,
            }),
        )
        .unwrap();
        assert_eq!(
            environment_value(&submitted, "NUMBER_OF_PROCESSORS"),
            Some("submitted-value")
        );

        let duplicate = Command {
            argv: vec!["tool.exe".into()],
            env: [("Key".into(), "one".into()), ("KEY".into(), "two".into())]
                .into_iter()
                .collect(),
            cwd: String::new(),
        };
        assert!(effective_environment(&duplicate, scratch, None).is_err());
    }

    #[test]
    fn trace_publish_accepts_only_regular_sbzt_files_and_leaves_no_temp() {
        let root = test_path("trace-publish");
        let source = root.join("source");
        let destination = root.join("destination");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("read.sbzt"), b"trace").unwrap();
        std::fs::write(source.join("ignored.txt"), b"ignore").unwrap();

        publish_trace_directory(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("read.sbzt")).unwrap(),
            b"trace"
        );
        assert!(!destination.join("ignored.txt").exists());
        assert!(std::fs::read_dir(&destination).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sbz-publish-")
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trace_publish_rejects_reparse_source_directory() {
        let root = test_path("trace-reparse");
        let real = root.join("real");
        let source = root.join("source-junction");
        let destination = root.join("destination");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("read.sbzt"), b"trace").unwrap();
        let status = std::process::Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                &format!(r#"mklink /J {} {} >nul"#, source.display(), real.display()),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "junction fixture must be available");

        assert!(publish_trace_directory(&source, &destination).is_err());
        assert!(!destination.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trace_publish_race_never_replaces_existing_target_and_cleans_temp() {
        let root = test_path("trace-no-replace");
        let source = root.join("source.sbzt");
        let destination = root.join("destination");
        let target = destination.join("source.sbzt");
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(&source, b"new trace").unwrap();

        let error = publish_trace_file(&source, &target, |_| {
            std::fs::write(&target, b"existing trace").unwrap();
        })
        .expect_err("a target created after the pre-check must win");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"existing trace");
        assert!(std::fs::read_dir(&destination).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sbz-publish-")
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tool_observation_uses_the_restricted_action_token() {
        let root = test_path("tool-observation");
        std::fs::create_dir_all(&root).unwrap();
        let owner = ActionToken::create().unwrap();
        let caller = ActionToken::create().unwrap();
        let protected = PrivateScratch::create(&root, "protected", &owner).unwrap();
        let protected_tool = protected.path().join("broker-only.exe");
        std::fs::write(&protected_tool, b"not executable, but hashable by broker").unwrap();
        let cmd = Command {
            argv: vec![protected_tool.to_string_lossy().into_owned()],
            env: Default::default(),
            cwd: protected.path().to_string_lossy().into_owned(),
        };
        let environment = effective_environment(&cmd, protected.path(), None).unwrap();
        assert!(
            observe_tool(&caller, &cmd, &environment, protected.path(), true).is_err(),
            "a broker-readable but action-inaccessible executable must not resolve as Content"
        );

        let caller_scratch = PrivateScratch::create(&root, "caller", &caller).unwrap();
        let system = Command {
            argv: vec!["cmd.exe".into()],
            env: Default::default(),
            cwd: String::new(),
        };
        let environment = effective_environment(&system, caller_scratch.path(), None).unwrap();
        let observed = observe_tool(&caller, &system, &environment, caller_scratch.path(), true)
            .expect("the restricted action can execute and hash the system command processor");
        assert!(observed.application.is_some());
        assert!(!observed.digest.is_empty());
        drop((caller_scratch, protected));
        std::fs::remove_dir(root).unwrap();
    }
}
