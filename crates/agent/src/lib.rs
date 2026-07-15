//! Sembazuru local agent: owns the build session — schedules actions, will serve
//! the local filesystem to workers (M3.2), receives outputs (M3.3), and falls
//! back to local execution when remote fails (M3.4).
//!
//! **M3.1 scope — loopback Execute client.** This drives one remote action over
//! the `Execution` control plane (`docs/protocol/v0.md` §3.2): connect, send
//! `ExecuteRequest`, consume the `ExecuteEvent` stream, and report the outcome.

use std::sync::Arc;
use std::time::Duration;

use sembazuru_proto::v0::{
    ActionState, Command, ExecuteRequest, VfsExecution, execute_event::Event,
    execution_client::ExecutionClient,
};

use crate::action_tracker::{ActionTracker, ActivityState, AttemptKey};

pub mod action_cache;
pub mod action_tracker;
pub mod config;
pub mod coordination;
pub mod env_filter;
pub mod fileserver;
pub mod intake;
#[cfg(windows)]
#[allow(dead_code)] // Task 4 wires these authenticated transport primitives into the daemon.
mod intake_pipe;
pub mod rootdir;
pub mod run;
pub mod scheduler;
#[cfg(windows)]
pub mod service;
pub mod session_registry;
pub mod status;

#[cfg(all(test, windows))]
pub(crate) static LOCAL_JOB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(all(test, windows))]
pub(crate) struct LocalJobFixturePeer {
    pub(crate) role: u8,
    pub(crate) pid: u32,
    process: usize,
    pub(crate) socket: std::net::TcpStream,
}

#[cfg(all(test, windows))]
impl LocalJobFixturePeer {
    pub(crate) fn is_signaled(&self) -> bool {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        unsafe { WaitForSingleObject(self.process as _, 0) == WAIT_OBJECT_0 }
    }

    pub(crate) fn assert_signaled(&self) {
        assert!(
            self.is_signaled(),
            "fixture role {} process {} is still running",
            self.role,
            self.pid
        );
    }

    pub(crate) fn is_in_job(&self, job: usize) -> std::io::Result<bool> {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;

        let mut contained = 0;
        let ok = unsafe { IsProcessInJob(self.process as _, job as _, &mut contained) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(contained != 0)
        }
    }
}

#[cfg(all(test, windows))]
impl Drop for LocalJobFixturePeer {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        unsafe {
            let _ = CloseHandle(self.process as _);
        }
    }
}

#[cfg(all(test, windows))]
pub(crate) async fn accept_local_job_fixture(
    listener: std::net::TcpListener,
) -> Vec<LocalJobFixturePeer> {
    accept_local_job_fixture_count(listener, 2).await
}

#[cfg(all(test, windows))]
pub(crate) async fn accept_local_job_fixture_count(
    listener: std::net::TcpListener,
    count: usize,
) -> Vec<LocalJobFixturePeer> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };

        let mut peers = Vec::new();
        for _ in 0..count {
            let (mut socket, _) = listener.accept().unwrap();
            let mut hello = [0_u8; 5];
            socket.read_exact(&mut hello).unwrap();
            let pid = u32::from_be_bytes(hello[1..].try_into().unwrap());
            let process = unsafe {
                OpenProcess(
                    PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                )
            };
            assert!(
                !process.is_null(),
                "could not acquire a live synchronization handle for fixture process {pid}: {}",
                std::io::Error::last_os_error()
            );
            peers.push(LocalJobFixturePeer {
                role: hello[0],
                pid,
                process: process as usize,
                socket,
            });
        }
        peers
    })
    .await
    .unwrap()
}

tokio::task_local! {
    static SUBMISSION_DEADLINE: Arc<session_registry::SubmissionDeadline>;
}

pub(crate) async fn with_submission_deadline<F>(
    deadline: Arc<session_registry::SubmissionDeadline>,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    SUBMISSION_DEADLINE.scope(deadline, future).await
}

pub(crate) fn current_submission_deadline() -> Option<Arc<session_registry::SubmissionDeadline>> {
    SUBMISSION_DEADLINE.try_with(Arc::clone).ok()
}

/// Per-action execution extras carried alongside the command into `Execute`
/// (M6.1). Empty by default — the M5 scale path and the single-shot CLI send
/// neither, so the worker plain-spawns. The daemon fills these in: the prefetch
/// hint from the action cache, and the read-VFS config for a real compile.
#[derive(Debug, Default, Clone)]
pub struct ExecOptions {
    /// Prior build's input paths to warm ahead of process I/O (M5.4).
    pub predicted_paths: Vec<String>,
    /// Read-VFS execution config; `None` means plain spawn (back-compat).
    pub vfs: Option<VfsExecution>,
}

/// What a remote action reported back: the lifecycle states it passed through
/// (raw `ActionState` discriminants, in order) and, if it ran to completion,
/// the process exit code and worker-measured wall time.
#[derive(Debug, Default, Clone)]
pub struct ActionOutcome {
    pub states: Vec<i32>,
    pub exit_code: Option<i32>,
    pub wall_time_us: u64,
    pub resolved_tool_digest: String,
    /// The remote process's console output, collected for replay to the
    /// developer (M6.1): the compiler ran on the worker, so its diagnostics must
    /// be streamed back or they are invisible.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Errors the agent surfaces to its caller. A `Transport` or `Rpc` error is
/// exactly the kind of remote failure that M3.4 will turn into a local fallback.
#[derive(Debug)]
pub enum ExecuteError {
    Transport(tonic::transport::Error),
    Rpc(tonic::Status),
}

const MAX_ERROR_CHAIN_DEPTH: usize = 16;

struct ErrorChain<'a>(&'a (dyn std::error::Error + 'static));

impl std::fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut current = Some(self.0);
        let mut previous = None;
        let mut wrote = false;
        for _ in 0..MAX_ERROR_CHAIN_DEPTH {
            let Some(error) = current else {
                return Ok(());
            };
            let message = error.to_string();
            if previous.as_deref() != Some(message.as_str()) {
                if wrote {
                    f.write_str(": ")?;
                }
                f.write_str(&message)?;
                wrote = true;
            }
            previous = Some(message);
            current = error.source();
        }
        if current.is_some() {
            if wrote {
                f.write_str(": ")?;
            }
            f.write_str("[source chain truncated]")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecuteError::Transport(e) => write!(f, "transport: {}", ErrorChain(e)),
            ExecuteError::Rpc(s) => write!(f, "rpc: {s}"),
        }
    }
}

impl std::error::Error for ExecuteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExecuteError::Transport(error) => Some(error),
            ExecuteError::Rpc(status) => Some(status),
        }
    }
}

impl From<tonic::transport::Error> for ExecuteError {
    fn from(e: tonic::transport::Error) -> Self {
        ExecuteError::Transport(e)
    }
}

impl From<tonic::Status> for ExecuteError {
    fn from(s: tonic::Status) -> Self {
        ExecuteError::Rpc(s)
    }
}

/// How hard to try to connect to a worker's `Execution` endpoint before giving
/// up. Two callers want very different behaviour: a just-spawned loopback worker
/// needs patient retries to win the startup race, while the scheduler dispatches
/// to *already-registered* workers — a connect failure there means the worker is
/// gone and the action should be reassigned fast, not after seconds of retries.
#[derive(Clone, Copy)]
pub struct ConnectPolicy {
    pub attempts: u32,
    pub per_attempt_timeout: Duration,
    pub retry_sleep: Duration,
}

impl ConnectPolicy {
    /// Patient: tolerate a worker that is still starting its listener (loopback,
    /// the bin, tests). Up to ~5 s of retries.
    pub const PATIENT: ConnectPolicy = ConnectPolicy {
        attempts: 20,
        per_attempt_timeout: Duration::from_millis(200),
        retry_sleep: Duration::from_millis(50),
    };

    /// Fast: a registered worker that does not answer promptly is treated as
    /// dead so the scheduler reassigns within a fraction of a second instead of
    /// burning seconds per dead candidate.
    pub const FAST: ConnectPolicy = ConnectPolicy {
        attempts: 2,
        per_attempt_timeout: Duration::from_millis(250),
        retry_sleep: Duration::from_millis(25),
    };
}

/// Connects to a worker's `Execution` endpoint under `policy`. Readiness is
/// established by a successful connect rather than a separate probe.
async fn connect_with_policy(
    endpoint: String,
    policy: ConnectPolicy,
) -> Result<ExecutionClient<tonic::transport::Channel>, ExecuteError> {
    let ep = tonic::transport::Endpoint::from_shared(endpoint)
        .map_err(ExecuteError::Transport)?
        .connect_timeout(policy.per_attempt_timeout);
    let mut last: Option<tonic::transport::Error> = None;
    for i in 0..policy.attempts.max(1) {
        match ep.connect().await {
            Ok(channel) => return Ok(ExecutionClient::new(channel)),
            Err(e) => {
                last = Some(e);
                if i + 1 < policy.attempts {
                    tokio::time::sleep(policy.retry_sleep).await;
                }
            }
        }
    }
    Err(ExecuteError::Transport(last.expect("at least one attempt")))
}

/// Runs `command` on the worker at `endpoint` (e.g. `"http://127.0.0.1:50061"`)
/// and returns its outcome once the event stream closes. Uses patient connect
/// retries; the scheduler uses [`execute_remote_with`] with [`ConnectPolicy::FAST`].
pub async fn execute_remote(
    endpoint: String,
    command: Command,
    action_id: String,
    session_id: String,
) -> Result<ActionOutcome, ExecuteError> {
    execute_remote_with(
        endpoint,
        command,
        action_id,
        session_id,
        ConnectPolicy::PATIENT,
    )
    .await
}

/// Like [`execute_remote`], but with an explicit [`ConnectPolicy`].
pub async fn execute_remote_with(
    endpoint: String,
    command: Command,
    action_id: String,
    session_id: String,
    connect: ConnectPolicy,
) -> Result<ActionOutcome, ExecuteError> {
    let client = connect_with_policy(endpoint, connect).await?;
    drive_execute(
        client,
        command,
        action_id,
        session_id,
        ExecOptions::default(),
        Vec::new(),
        None,
    )
    .await
}

/// Runs an action on an already-connected channel with no execution extras
/// (plain spawn). The scheduler caches one channel per worker and calls this per
/// action, so the control plane pays no per-action connection handshake —
/// actions multiplex over the worker's one HTTP/2 connection (the control-plane
/// analogue of the M5.3 data-plane pool).
pub async fn execute_on_channel(
    channel: tonic::transport::Channel,
    command: Command,
    action_id: String,
    session_id: String,
) -> Result<ActionOutcome, ExecuteError> {
    execute_on_channel_with(
        channel,
        command,
        action_id,
        session_id,
        ExecOptions::default(),
        Vec::new(),
    )
    .await
}

/// Like [`execute_on_channel`], but carries [`ExecOptions`] (prefetch hint +
/// read-VFS config) into the `ExecuteRequest`. The daemon's compile path uses
/// this; the M5 scale path uses the plain [`execute_on_channel`].
pub async fn execute_on_channel_with(
    channel: tonic::transport::Channel,
    command: Command,
    action_id: String,
    session_id: String,
    opts: ExecOptions,
    action_capability: Vec<u8>,
) -> Result<ActionOutcome, ExecuteError> {
    execute_on_channel_with_observer(
        channel,
        command,
        action_id,
        session_id,
        opts,
        action_capability,
        None,
    )
    .await
}

pub async fn execute_on_channel_with_observer(
    channel: tonic::transport::Channel,
    command: Command,
    action_id: String,
    session_id: String,
    opts: ExecOptions,
    action_capability: Vec<u8>,
    observer: Option<ActionObserver>,
) -> Result<ActionOutcome, ExecuteError> {
    drive_execute(
        ExecutionClient::new(channel),
        command,
        action_id,
        session_id,
        opts,
        action_capability,
        observer,
    )
    .await
}

#[derive(Clone)]
pub struct ActionObserver {
    tracker: ActionTracker,
    key: AttemptKey,
}

impl ActionObserver {
    pub fn new(tracker: ActionTracker, key: AttemptKey) -> Self {
        Self { tracker, key }
    }

    fn worker_state(&self, state: i32) {
        let mapped = match ActionState::try_from(state).ok() {
            Some(ActionState::Queued) => Some(ActivityState::Queued),
            Some(ActionState::Preparing) => Some(ActivityState::Preparing),
            Some(ActionState::Running) => Some(ActivityState::Running),
            _ => None,
        };
        if let Some(next) = mapped {
            self.tracker.transition(&self.key, next);
        }
    }
}

/// Max console bytes buffered per stream (stdout/stderr) per action — a RES-001 DoS
/// cap. The agent buffers the worker's streamed console output whole (to replay it,
/// M6.1, and to record it, COR-007); a runaway or hostile worker streaming endless
/// `OutputChunk`s would otherwise grow this buffer without bound and OOM the agent
/// (and bloat the CAS). 8 MiB dwarfs any real compiler's per-TU diagnostics; beyond
/// it, further bytes are dropped with a one-time in-band notice.
const MAX_CONSOLE_BYTES: usize = 8 * 1024 * 1024;
const CONSOLE_TRUNCATION_NOTICE: &[u8] = b"\n[sembazuru: console output capped at 8 MiB]\n";

/// Appends `data` to `buf` but never grows `buf` past [`MAX_CONSOLE_BYTES`] (plus the
/// one-time [`CONSOLE_TRUNCATION_NOTICE`] emitted on the chunk that first overflows).
/// Bounds the agent's per-action console buffer regardless of how much the worker
/// streams (RES-001).
fn append_console_capped(buf: &mut Vec<u8>, data: &[u8]) {
    if buf.len() >= MAX_CONSOLE_BYTES {
        return; // already capped (the notice was appended on the overflowing chunk)
    }
    let room = MAX_CONSOLE_BYTES - buf.len();
    let take = data.len().min(room);
    buf.extend_from_slice(&data[..take]);
    if take < data.len() {
        buf.extend_from_slice(CONSOLE_TRUNCATION_NOTICE);
    }
}

/// Sends the `ExecuteRequest` and folds its event stream into an [`ActionOutcome`].
async fn drive_execute(
    mut client: ExecutionClient<tonic::transport::Channel>,
    command: Command,
    action_id: String,
    session_id: String,
    opts: ExecOptions,
    action_capability: Vec<u8>,
    observer: Option<ActionObserver>,
) -> Result<ActionOutcome, ExecuteError> {
    let request = ExecuteRequest {
        action_id,
        command: Some(command),
        session_id,
        predicted_inputs: None,
        predicted_paths: opts.predicted_paths,
        vfs: opts.vfs,
        action_capability,
    };

    let mut stream = client.execute(request).await?.into_inner();
    let mut outcome = ActionOutcome::default();
    while let Some(event) = stream.message().await? {
        match event.event {
            Some(Event::State(s)) => {
                if let Some(observer) = &observer {
                    observer.worker_state(s.state);
                }
                outcome.states.push(s.state);
            }
            Some(Event::Exit(e)) => {
                outcome.exit_code = Some(e.exit_code);
                outcome.wall_time_us = e.wall_time_us;
                outcome.resolved_tool_digest = e.resolved_tool_digest;
            }
            Some(Event::Stdio(c)) => {
                // Collect the compiler's console output to replay to the developer
                // (M6.1) and record it (COR-007). Buffered here, re-streamed to the
                // launcher. CAPPED (RES-001): a runaway/hostile worker streaming
                // endless chunks cannot grow this buffer without bound.
                let buf = if c.is_stderr {
                    &mut outcome.stderr
                } else {
                    &mut outcome.stdout
                };
                append_console_capped(buf, &c.data);
            }
            Some(Event::Output(_)) => { /* write-back is M3.3 */ }
            None => {}
        }
    }
    Ok(outcome)
}

/// How an action ultimately ran.
#[derive(Debug)]
pub enum Execution {
    /// The worker ran it and reported an exit status.
    Remote(ActionOutcome),
    /// The remote path failed (or didn't complete) and the agent ran it locally.
    /// Local fallback is the hard requirement of `docs/DESIGN.md` §2 — a build
    /// must complete even if the network or a worker dies.
    LocalFallback {
        exit_code: i32,
        reason: LocalFallbackReason,
    },
}

/// Why an action ran locally instead of remotely (MAINT-001). A typed reason
/// replaces the previous `reason: String`, whose `"route-away"` prefix had become
/// the implementation contract for the status breakdown (`status::record_outcome`
/// matched `reason.starts_with("route-away")`). [`Display`](std::fmt::Display)
/// reproduces the previous human-readable strings for telemetry; [`is_route_away`]
/// is the typed replacement for that prefix match.
///
/// [`is_route_away`]: LocalFallbackReason::is_route_away
#[derive(Debug, Clone)]
pub enum LocalFallbackReason {
    /// The process bypasses the user-mode hooks (msys2/Cygwin direct NT syscalls, or
    /// on the denylist) so it cannot be virtualized — it ran locally from the START.
    /// A DELIBERATE, correct local run by policy (ADR 0007 §a①), NOT a remote
    /// failure, so the status breakdown counts it as a local (not fallback) run.
    /// Carries the human-readable trigger.
    RouteAway(String),
    /// No live worker was available to attempt the action.
    NoWorker,
    /// Every worker tried was exhausted (unreachable / failed / did-not-complete /
    /// over the latency budget) — carries the last attempt's detail.
    RemoteExhausted(String),
}

impl LocalFallbackReason {
    /// Whether this was a deliberate policy route-away (a correct local run), as
    /// opposed to a remote-failure fallback — the distinction the status breakdown
    /// draws. Replaces the fragile `reason.starts_with("route-away")`.
    pub fn is_route_away(&self) -> bool {
        matches!(self, LocalFallbackReason::RouteAway(_))
    }
}

impl std::fmt::Display for LocalFallbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalFallbackReason::RouteAway(why) => write!(f, "route-away ({why})"),
            LocalFallbackReason::NoWorker => f.write_str("no live workers"),
            LocalFallbackReason::RemoteExhausted(detail) => f.write_str(detail),
        }
    }
}

/// The security context under which a daemon-side local execution must run.
///
/// Authenticated intake must carry the captured caller token all the way to
/// the execution boundary. It must never silently fall back to the daemon's
/// ambient token when caller-token process creation fails.
#[derive(Clone, Debug)]
pub(crate) enum LocalExecutionContext {
    /// Compatibility context for trusted in-process callers and test fixtures.
    CurrentProcess,
    /// Caller established by the authenticated Windows LocalIntake transport.
    #[cfg(windows)]
    AuthenticatedCaller(crate::intake_pipe::CallerIdentity),
}

/// Runs a local fallback under its explicitly selected security context.
///
/// Authenticated callers always use their captured restricted primary token;
/// process creation failures fail closed without an ambient-token retry.
pub(crate) async fn run_local_with_context(
    command: &Command,
    context: &LocalExecutionContext,
) -> std::io::Result<i32> {
    match context {
        LocalExecutionContext::CurrentProcess => run_local(command).await,
        #[cfg(windows)]
        LocalExecutionContext::AuthenticatedCaller(identity) => {
            #[cfg(test)]
            let test_control = local_job::resolve_test_control(command)?;
            let deadline = current_submission_deadline().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authenticated caller execution requires a submission deadline",
                )
            })?;
            #[cfg(test)]
            if let Some(state) = &test_control {
                state.record_run_local_deadline(true);
            }
            local_job::run_as_caller(
                command,
                identity,
                deadline,
                #[cfg(test)]
                test_control,
            )
            .await
        }
    }
}

/// Runs `command` on the local machine, returning its exit code. This is the
/// fallback path; outputs land where the command writes them (a self-contained
/// local build), so no write-back is involved.
pub async fn run_local(command: &Command) -> std::io::Result<i32> {
    #[cfg(all(test, windows))]
    let test_control = local_job::resolve_test_control(command)?;
    let submission_deadline = current_submission_deadline();
    #[cfg(all(test, windows))]
    if let Some(state) = &test_control {
        state.record_run_local_deadline(submission_deadline.is_some());
        if submission_deadline.is_none() {
            return Err(std::io::Error::other(
                "test guardian control requires a submission deadline",
            ));
        }
    }
    if command.argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "command.argv is empty",
        ));
    }
    #[cfg(windows)]
    if let Some(deadline) = submission_deadline {
        #[cfg(test)]
        return local_job::run(command, deadline, test_control).await;
        #[cfg(not(test))]
        return local_job::run(command, deadline).await;
    }

    let mut cmd = tokio::process::Command::new(&command.argv[0]);
    cmd.args(&command.argv[1..]);
    if !command.cwd.is_empty() {
        cmd.current_dir(&command.cwd);
    }
    for (k, v) in &command.env {
        cmd.env(k, v);
    }
    let status = cmd.status().await?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(windows)]
mod local_job {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use sembazuru_proto::v0::Command;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INVALID_PARAMETER, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::GetFullPathNameW;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Environment::{
        CreateEnvironmentBlock, DestroyEnvironmentBlock,
    };
    use windows_sys::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::SystemServices::{
        JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO,
        JOB_OBJECT_MSG_EXIT_PROCESS, JOB_OBJECT_MSG_NEW_PROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
        GetExitCodeProcess, INFINITE, OpenProcess, OpenThread, PROCESS_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ResumeThread, STARTUPINFOW,
        THREAD_SUSPEND_RESUME, TerminateProcess, WaitForSingleObject,
    };

    use crate::session_registry::{SubmissionDeadline, SubmissionPhase};

    static QUARANTINE_COUNT: AtomicU64 = AtomicU64::new(0);

    #[cfg(test)]
    pub(super) const TEST_CONTROL_MARKER: &str = "SEMBAZURU_INTERNAL_TEST_LOCAL_JOB_CONTROL";

    #[cfg(test)]
    pub(super) struct TestGuardianState {
        failpoint: std::sync::atomic::AtomicU8,
        delayed_new: Mutex<bool>,
        delayed_new_changed: Condvar,
        terminate_pause: Mutex<(bool, bool)>,
        terminate_pause_changed: Condvar,
        observe_job: AtomicBool,
        observed_job_handle: AtomicUsize,
        last_child_handle: AtomicUsize,
        last_audit_raw: AtomicU64,
        last_audit_unique: AtomicU64,
        last_audit_total: AtomicU64,
        job_owner_close_count: AtomicU64,
        natural_publish_branch: std::sync::atomic::AtomicU8,
        run_local_deadline_state: std::sync::atomic::AtomicU8,
        last_consumed_failpoint: std::sync::atomic::AtomicU8,
    }

    #[cfg(test)]
    impl TestGuardianState {
        fn new() -> Self {
            Self {
                failpoint: std::sync::atomic::AtomicU8::new(0),
                delayed_new: Mutex::new(false),
                delayed_new_changed: Condvar::new(),
                terminate_pause: Mutex::new((false, false)),
                terminate_pause_changed: Condvar::new(),
                observe_job: AtomicBool::new(false),
                observed_job_handle: AtomicUsize::new(0),
                last_child_handle: AtomicUsize::new(0),
                last_audit_raw: AtomicU64::new(0),
                last_audit_unique: AtomicU64::new(0),
                last_audit_total: AtomicU64::new(0),
                job_owner_close_count: AtomicU64::new(0),
                natural_publish_branch: std::sync::atomic::AtomicU8::new(0),
                run_local_deadline_state: std::sync::atomic::AtomicU8::new(0),
                last_consumed_failpoint: std::sync::atomic::AtomicU8::new(0),
            }
        }

        pub(super) fn record_run_local_deadline(&self, present: bool) {
            self.run_local_deadline_state
                .store(if present { 2 } else { 1 }, Ordering::SeqCst);
        }

        fn is_armed(&self, point: u8) -> bool {
            self.failpoint.load(Ordering::SeqCst) == point
        }

        fn take_failpoint(&self, point: u8) -> bool {
            let consumed = self
                .failpoint
                .compare_exchange(point, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();
            if consumed {
                self.last_consumed_failpoint.store(point, Ordering::SeqCst);
            }
            consumed
        }
    }

    #[cfg(test)]
    pub(crate) struct TestGuardianControl {
        id: u64,
        state: Arc<TestGuardianState>,
    }

    #[cfg(test)]
    static NEXT_TEST_CONTROL_ID: AtomicU64 = AtomicU64::new(1);

    #[cfg(test)]
    static TEST_CONTROLS: std::sync::LazyLock<
        Mutex<std::collections::HashMap<u64, std::sync::Weak<TestGuardianState>>>,
    > = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

    #[cfg(test)]
    impl TestGuardianControl {
        pub(crate) fn bind(command: &mut Command) -> std::io::Result<Self> {
            if command
                .env
                .keys()
                .any(|key| key.eq_ignore_ascii_case(TEST_CONTROL_MARKER))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "test guardian control marker already exists",
                ));
            }
            let id = NEXT_TEST_CONTROL_ID
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_add(1).filter(|next| *next != 0)
                })
                .map_err(|_| std::io::Error::other("test guardian control ID exhausted"))?;
            if id == 0 {
                return Err(std::io::Error::other(
                    "test guardian control ID cannot be zero",
                ));
            }
            let state = Arc::new(TestGuardianState::new());
            TEST_CONTROLS
                .lock()
                .unwrap()
                .insert(id, Arc::downgrade(&state));
            command
                .env
                .insert(TEST_CONTROL_MARKER.to_owned(), id.to_string());
            Ok(Self { id, state })
        }

        pub(crate) fn install(&self, point: u8) {
            if point == 11 {
                *self.state.delayed_new.lock().unwrap() = true;
            }
            if point == 20 {
                *self.state.terminate_pause.lock().unwrap() = (true, false);
            }
            self.state.failpoint.store(point, Ordering::SeqCst);
        }

        pub(crate) fn observe_job(&self) {
            self.state.observe_job.store(true, Ordering::SeqCst);
        }

        pub(crate) fn release_delayed_new(&self) {
            let mut delayed = self.state.delayed_new.lock().unwrap();
            *delayed = false;
            self.state.delayed_new_changed.notify_all();
        }

        pub(crate) async fn wait_before_terminate_reached(&self) {
            let state = Arc::clone(&self.state);
            tokio::task::spawn_blocking(move || {
                let mut pause = state.terminate_pause.lock().unwrap();
                while !pause.1 {
                    pause = state.terminate_pause_changed.wait(pause).unwrap();
                }
            })
            .await
            .unwrap();
        }

        pub(crate) fn release_before_terminate(&self) {
            let mut pause = self.state.terminate_pause.lock().unwrap();
            pause.0 = false;
            self.state.terminate_pause_changed.notify_all();
        }

        pub(crate) fn take_observed_job_handle(&self) -> usize {
            self.state.observed_job_handle.swap(0, Ordering::SeqCst)
        }

        pub(crate) fn take_last_child_handle(&self) -> usize {
            self.state.last_child_handle.swap(0, Ordering::SeqCst)
        }

        pub(crate) fn take_last_audit_counts(&self) -> (u64, u64, u64) {
            (
                self.state.last_audit_raw.swap(0, Ordering::SeqCst),
                self.state.last_audit_unique.swap(0, Ordering::SeqCst),
                self.state.last_audit_total.swap(0, Ordering::SeqCst),
            )
        }

        pub(crate) fn job_owner_close_count(&self) -> u64 {
            self.state.job_owner_close_count.load(Ordering::SeqCst)
        }

        pub(crate) fn take_natural_publish_branch(&self) -> u8 {
            self.state.natural_publish_branch.swap(0, Ordering::SeqCst)
        }

        pub(crate) fn take_run_local_deadline_state(&self) -> u8 {
            self.state
                .run_local_deadline_state
                .swap(0, Ordering::SeqCst)
        }

        pub(crate) fn take_last_consumed_failpoint(&self) -> u8 {
            self.state.last_consumed_failpoint.swap(0, Ordering::SeqCst)
        }
    }

    #[cfg(test)]
    impl Drop for TestGuardianControl {
        fn drop(&mut self) {
            let mut controls = TEST_CONTROLS.lock().unwrap();
            let own = Arc::downgrade(&self.state);
            if controls
                .get(&self.id)
                .is_some_and(|registered| std::sync::Weak::ptr_eq(registered, &own))
            {
                controls.remove(&self.id);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn resolve_test_control(
        command: &Command,
    ) -> std::io::Result<Option<Arc<TestGuardianState>>> {
        let values = command
            .env
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(TEST_CONTROL_MARKER))
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        if values.is_empty() {
            return Ok(None);
        }
        if values.len() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "test guardian control marker must appear exactly once",
            ));
        }
        let id = values[0].parse::<u64>().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "test guardian control marker is not a decimal ID",
            )
        })?;
        if id == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "test guardian control marker cannot be zero",
            ));
        }
        let state = TEST_CONTROLS
            .lock()
            .unwrap()
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test guardian control marker is stale or unknown",
                )
            })?;
        Ok(Some(state))
    }

    const JOB_COMPLETION_KEY: usize = 1;
    const OWNER_COMPLETION_KEY: usize = 2;
    const OWNER_BARRIER: u32 = 1;
    const OWNER_STOP: u32 = 2;
    #[cfg(not(test))]
    const AUDIT_DEADLINE: Duration = Duration::from_secs(5);
    #[cfg(test)]
    const AUDIT_DEADLINE: Duration = Duration::from_millis(500);

    #[cfg(test)]
    pub(super) fn quarantine_count() -> u64 {
        QUARANTINE_COUNT.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn classify_gone_and_foreign_packets() -> std::io::Result<(u64, u64)> {
        let job = create_job(None)?;
        let shared = MonitorShared::new(None);
        {
            let mut state = shared.state.lock().unwrap();
            state.seed_ready = true;
        }
        monitor_new_process(job.raw(), std::process::id(), &shared)?;
        monitor_new_process(job.raw(), u32::MAX, &shared)?;
        let state = shared.state.lock().unwrap();
        let gone = state
            .occurrences
            .iter()
            .filter(|occurrence| matches!(occurrence.state, OccurrenceState::ConfirmedGone))
            .count() as u64;
        Ok((state.unique_occurrences, gone))
    }

    #[cfg(test)]
    pub(super) fn classify_duplicate_gone_packets() -> std::io::Result<(u64, u64, u64)> {
        let job = create_job(None)?;

        let seeded_top = MonitorShared::new(None);
        {
            let mut state = seeded_top.state.lock().unwrap();
            state.seed_ready = true;
            push_occurrence(
                &mut state,
                ProcessOccurrence {
                    pid: u32::MAX,
                    state: OccurrenceState::ConfirmedGone,
                    top: true,
                },
            )?;
            state.top_new_pending = Some(u32::MAX);
        }
        monitor_new_process(job.raw(), u32::MAX, &seeded_top)?;
        let seeded_top_unique = seeded_top.state.lock().unwrap().unique_occurrences;

        let repeated_non_top = MonitorShared::new(None);
        repeated_non_top.state.lock().unwrap().seed_ready = true;
        monitor_new_process(job.raw(), u32::MAX, &repeated_non_top)?;
        monitor_new_process(job.raw(), u32::MAX, &repeated_non_top)?;
        let repeated_non_top_unique = repeated_non_top.state.lock().unwrap().unique_occurrences;

        let repeated_foreign = MonitorShared::new(None);
        repeated_foreign.state.lock().unwrap().seed_ready = true;
        monitor_new_process(job.raw(), std::process::id(), &repeated_foreign)?;
        monitor_new_process(job.raw(), std::process::id(), &repeated_foreign)?;
        let repeated_foreign_unique = repeated_foreign.state.lock().unwrap().unique_occurrences;

        Ok((
            seeded_top_unique,
            repeated_non_top_unique,
            repeated_foreign_unique,
        ))
    }

    struct OwnedHandle {
        raw: usize,
        job_owner: bool,
        #[cfg(test)]
        test_control: Option<Arc<TestGuardianState>>,
    }

    impl OwnedHandle {
        fn new(handle: HANDLE) -> std::io::Result<Self> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                Err(last_error("acquiring kernel handle failed"))
            } else {
                Ok(Self {
                    raw: handle as usize,
                    job_owner: false,
                    #[cfg(test)]
                    test_control: None,
                })
            }
        }

        fn new_job(
            handle: HANDLE,
            #[cfg(test)] test_control: Option<Arc<TestGuardianState>>,
        ) -> std::io::Result<Self> {
            let mut owned = Self::new(handle)?;
            owned.job_owner = true;
            #[cfg(test)]
            {
                owned.test_control = test_control;
            }
            Ok(owned)
        }

        fn raw(&self) -> HANDLE {
            self.raw as HANDLE
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            #[cfg(test)]
            if self.job_owner
                && let Some(control) = &self.test_control
            {
                control.job_owner_close_count.fetch_add(1, Ordering::SeqCst);
            }
            unsafe { close_handle(self.raw()) };
        }
    }

    enum OccurrenceState {
        Retained(OwnedHandle),
        ConfirmedGone,
    }

    struct ProcessOccurrence {
        pid: u32,
        state: OccurrenceState,
        top: bool,
    }

    struct MonitorState {
        raw_packets: u64,
        unique_occurrences: u64,
        occurrences: Vec<ProcessOccurrence>,
        top_new_pending: Option<u32>,
        seed_ready: bool,
        seed_aborted: bool,
        first_error: Option<String>,
        last_ack: usize,
        terminal: bool,
    }

    struct MonitorShared {
        state: Mutex<MonitorState>,
        changed: Condvar,
        next_barrier: AtomicUsize,
        #[cfg(test)]
        test_control: Option<Arc<TestGuardianState>>,
    }

    impl MonitorShared {
        fn new(#[cfg(test)] test_control: Option<Arc<TestGuardianState>>) -> Self {
            Self {
                state: Mutex::new(MonitorState {
                    raw_packets: 0,
                    unique_occurrences: 0,
                    occurrences: Vec::new(),
                    top_new_pending: None,
                    seed_ready: false,
                    seed_aborted: false,
                    first_error: None,
                    last_ack: 0,
                    terminal: false,
                }),
                changed: Condvar::new(),
                next_barrier: AtomicUsize::new(1),
                #[cfg(test)]
                test_control,
            }
        }

        fn record_error(&self, error: impl Into<String>) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state.first_error.is_none() {
                state.first_error = Some(error.into());
            }
            self.changed.notify_all();
        }

        fn abort_seed(&self, error: impl Into<String>) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state.first_error.is_none() {
                state.first_error = Some(error.into());
            }
            state.seed_aborted = true;
            self.changed.notify_all();
        }

        fn mark_terminal(&self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.terminal = true;
            self.changed.notify_all();
        }
    }

    struct Handles {
        job: Option<OwnedHandle>,
        port: Option<OwnedHandle>,
        top_before_seed: Option<OwnedHandle>,
        monitor: Option<std::thread::JoinHandle<()>>,
        shared: Arc<MonitorShared>,
    }

    impl Handles {
        fn job(&self) -> HANDLE {
            self.job.as_ref().expect("guardian Job missing").raw()
        }

        fn port(&self) -> HANDLE {
            self.port.as_ref().expect("guardian IOCP missing").raw()
        }

        fn top_handle(&self) -> Option<HANDLE> {
            if let Some(top) = &self.top_before_seed {
                return Some(top.raw());
            }
            let state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.occurrences.iter().find_map(|occurrence| {
                if occurrence.top {
                    match &occurrence.state {
                        OccurrenceState::Retained(handle) => Some(handle.raw()),
                        OccurrenceState::ConfirmedGone => None,
                    }
                } else {
                    None
                }
            })
        }

        fn close_after_monitor(&mut self) {
            self.top_before_seed.take();
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.occurrences.clear();
            drop(state);
            self.port.take();
            self.job.take();
        }
    }

    struct GuardianInner {
        handles: Mutex<Option<Handles>>,
        deadline: Arc<SubmissionDeadline>,
        cleanup_started: AtomicBool,
    }

    #[derive(Clone)]
    struct ProcessGuardian(Arc<GuardianInner>);

    enum FinishOutcome {
        Natural,
        Forced,
    }

    impl ProcessGuardian {
        fn new(handles: Handles, deadline: Arc<SubmissionDeadline>) -> Self {
            Self(Arc::new(GuardianInner {
                handles: Mutex::new(Some(handles)),
                deadline,
                cleanup_started: AtomicBool::new(false),
            }))
        }

        fn job_raw(&self) -> HANDLE {
            self.0
                .handles
                .lock()
                .expect("process guardian poisoned")
                .as_ref()
                .expect("process guardian handles missing")
                .job()
        }

        fn seed_top(&self, pid: u32) -> std::io::Result<()> {
            let mut handles = self.0.handles.lock().expect("process guardian poisoned");
            let handles = handles
                .as_mut()
                .ok_or_else(|| std::io::Error::other("process guardian handles missing"))?;
            if let Err(error) = seed_top_occurrence(handles, pid) {
                handles.shared.abort_seed(error.to_string());
                return Err(error);
            }
            Ok(())
        }

        async fn force_reap(&self, setup_rollback: bool) -> std::io::Result<()> {
            let guardian = self.clone();
            tokio::task::spawn_blocking(move || guardian.cleanup_blocking(setup_rollback))
                .await
                .map_err(|error| {
                    std::io::Error::other(format!("process reaper panicked: {error}"))
                })?
        }

        fn cleanup_blocking(&self, setup_rollback: bool) -> std::io::Result<()> {
            if self.0.cleanup_started.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            let handles = self
                .0
                .handles
                .lock()
                .expect("process guardian poisoned")
                .take();
            let Some(handles) = handles else {
                return Ok(());
            };
            let _ = self.0.deadline.try_begin_terminating();
            let result = cleanup_with_quarantine(handles, terminate_wait_audit_and_close);
            if result.is_ok() {
                if setup_rollback {
                    let _ = self.0.deadline.publish_retry_safe_reaped();
                } else {
                    let _ = self.0.deadline.publish_forced_reaped();
                }
            } else {
                let _ = self.0.deadline.publish_force_failed();
            }
            result
        }

        async fn finish_natural(&self) -> std::io::Result<FinishOutcome> {
            let guardian = self.clone();
            tokio::task::spawn_blocking(move || guardian.finish_natural_blocking())
                .await
                .map_err(|error| std::io::Error::other(format!("job disarm panicked: {error}")))?
        }

        fn finish_natural_blocking(&self) -> std::io::Result<FinishOutcome> {
            if self.0.cleanup_started.swap(true, Ordering::SeqCst) {
                return Err(std::io::Error::other("process guardian already consumed"));
            }
            let handles = self
                .0
                .handles
                .lock()
                .expect("process guardian poisoned")
                .take()
                .ok_or_else(|| std::io::Error::other("process guardian handles missing"))?;
            #[cfg(test)]
            let inject_disarm_failure = {
                handles
                    .shared
                    .test_control
                    .as_deref()
                    .is_some_and(|control| control.take_failpoint(4) || control.is_armed(22))
            };
            #[cfg(not(test))]
            let inject_disarm_failure = false;
            let result =
                finish_after_top_exit(handles, inject_disarm_failure, Arc::clone(&self.0.deadline));
            if result.is_err() {
                let _ = self.0.deadline.publish_force_failed();
            }
            result
        }
    }

    impl Drop for GuardianInner {
        fn drop(&mut self) {
            if self.cleanup_started.swap(true, Ordering::SeqCst) {
                return;
            }
            let handles = self
                .handles
                .get_mut()
                .expect("process guardian poisoned")
                .take();
            let Some(handles) = handles else {
                return;
            };
            let deadline = Arc::clone(&self.deadline);
            std::thread::spawn(move || {
                let setup = deadline.phase() == SubmissionPhase::SettingUp;
                let _ = deadline.try_begin_terminating();
                if cleanup_with_quarantine(handles, |handles| {
                    terminate_wait_audit_and_close(handles)
                })
                .is_ok()
                {
                    if setup {
                        let _ = deadline.publish_retry_safe_reaped();
                    } else {
                        let _ = deadline.publish_forced_reaped();
                    }
                } else {
                    let _ = deadline.publish_force_failed();
                }
            });
        }
    }

    fn last_error(context: &str) -> std::io::Error {
        let error = std::io::Error::last_os_error();
        std::io::Error::new(error.kind(), format!("{context}: {error}"))
    }

    unsafe fn close_handle(handle: HANDLE) {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(handle) };
        }
    }

    fn create_job(
        #[cfg(test)] test_control: Option<Arc<TestGuardianState>>,
    ) -> std::io::Result<OwnedHandle> {
        unsafe {
            let job = windows_sys::Win32::System::JobObjects::CreateJobObjectW(null(), null());
            if job.is_null() {
                return Err(last_error("CreateJobObjectW failed"));
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            #[cfg(test)]
            if test_control
                .as_deref()
                .is_some_and(|control| control.take_failpoint(5))
            {
                close_handle(job);
                return Err(std::io::Error::other(
                    "injected KILL_ON_JOB_CLOSE setup failure",
                ));
            }
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let error = last_error("setting JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE failed");
                close_handle(job);
                return Err(error);
            }
            OwnedHandle::new_job(
                job,
                #[cfg(test)]
                test_control,
            )
        }
    }

    fn create_port_and_associate(
        job: HANDLE,
        #[cfg(test)] test_control: Option<&TestGuardianState>,
    ) -> std::io::Result<OwnedHandle> {
        unsafe {
            #[cfg(test)]
            if test_control.is_some_and(|control| control.take_failpoint(6)) {
                return Err(std::io::Error::other("injected IOCP creation failure"));
            }
            let port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1);
            let port = OwnedHandle::new(port)?;
            let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
                CompletionKey: JOB_COMPLETION_KEY as *mut c_void,
                CompletionPort: port.raw(),
            };
            #[cfg(test)]
            if test_control.is_some_and(|control| control.take_failpoint(7)) {
                return Err(std::io::Error::other("injected IOCP association failure"));
            }
            if SetInformationJobObject(
                job,
                JobObjectAssociateCompletionPortInformation,
                &association as *const _ as *const c_void,
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            ) == 0
            {
                return Err(last_error("associating Job with IOCP failed"));
            }
            Ok(port)
        }
    }

    fn start_monitor(
        job: HANDLE,
        port: HANDLE,
        shared: Arc<MonitorShared>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        #[cfg(test)]
        if shared
            .test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(8))
        {
            return Err(std::io::Error::other("injected monitor start failure"));
        }
        let job = job as usize;
        let port = port as usize;
        std::thread::Builder::new()
            .name("sembazuru-job-iocp".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    monitor_loop(job as HANDLE, port as HANDLE, &shared)
                }));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => shared.record_error(error.to_string()),
                    Err(_) => shared.record_error("IOCP monitor panicked"),
                }
                shared.mark_terminal();
            })
    }

    fn monitor_loop(job: HANDLE, port: HANDLE, shared: &MonitorShared) -> std::io::Result<()> {
        loop {
            let mut message = 0_u32;
            let mut key = 0_usize;
            let mut overlapped = null_mut();
            let ok = unsafe {
                GetQueuedCompletionStatus(port, &mut message, &mut key, &mut overlapped, INFINITE)
            };
            if ok == 0 {
                return Err(last_error("GetQueuedCompletionStatus failed"));
            }
            #[cfg(test)]
            if shared
                .test_control
                .as_deref()
                .is_some_and(|control| control.take_failpoint(17))
            {
                return Err(std::io::Error::other("injected GQCS monitor failure"));
            }
            match key {
                JOB_COMPLETION_KEY => match message {
                    JOB_OBJECT_MSG_NEW_PROCESS => {
                        let pid = u32::try_from(overlapped as usize).map_err(|_| {
                            std::io::Error::other("NEW_PROCESS PID did not fit in u32")
                        })?;
                        if let Err(error) = monitor_new_process(job, pid, shared) {
                            shared.record_error(error.to_string());
                        }
                        #[cfg(test)]
                        {
                            let top_pid = shared
                                .state
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .occurrences
                                .iter()
                                .find(|occurrence| occurrence.top)
                                .map(|occurrence| occurrence.pid);
                            if top_pid != Some(pid)
                                && shared
                                    .test_control
                                    .as_deref()
                                    .is_some_and(|control| control.take_failpoint(21))
                                && let Err(error) = monitor_new_process(job, pid, shared)
                            {
                                shared.record_error(error.to_string());
                            }
                        }
                    }
                    JOB_OBJECT_MSG_EXIT_PROCESS
                    | JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS
                    | JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => {}
                    unexpected => shared
                        .record_error(format!("unexpected Job completion packet {unexpected}")),
                },
                OWNER_COMPLETION_KEY => match message {
                    OWNER_BARRIER => {
                        #[cfg(test)]
                        if shared
                            .test_control
                            .as_deref()
                            .is_some_and(|control| control.take_failpoint(18))
                        {
                            continue;
                        }
                        let token = overlapped as usize;
                        let mut state = shared
                            .state
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        state.last_ack = state.last_ack.max(token);
                        shared.changed.notify_all();
                    }
                    OWNER_STOP => return Ok(()),
                    unexpected => shared
                        .record_error(format!("unexpected IOCP owner control packet {unexpected}")),
                },
                unexpected => {
                    shared.record_error(format!("unexpected IOCP completion key {unexpected}"));
                }
            }
        }
    }

    fn wait_for_top_seed(shared: &MonitorShared) -> std::io::Result<()> {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while !state.seed_ready && !state.seed_aborted {
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        if state.seed_ready {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "top occurrence seeding aborted before NEW_PROCESS processing",
            ))
        }
    }

    fn push_occurrence(
        state: &mut MonitorState,
        occurrence: ProcessOccurrence,
    ) -> std::io::Result<()> {
        state.unique_occurrences = state
            .unique_occurrences
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("unique process occurrence counter overflow"))?;
        state.occurrences.push(occurrence);
        Ok(())
    }

    fn monitor_new_process(job: HANDLE, pid: u32, shared: &MonitorShared) -> std::io::Result<()> {
        {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.raw_packets = state
                .raw_packets
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("raw NEW_PROCESS counter overflow"))?;
        }
        wait_for_top_seed(shared)?;

        #[cfg(test)]
        {
            let is_top = shared
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .top_new_pending
                == Some(pid);
            if is_top
                && shared
                    .test_control
                    .as_deref()
                    .is_some_and(|control| control.take_failpoint(9))
            {
                return Ok(());
            }
            if !is_top
                && shared
                    .test_control
                    .as_deref()
                    .is_some_and(|control| control.take_failpoint(10))
            {
                return Ok(());
            }
            if !is_top
                && shared
                    .test_control
                    .as_deref()
                    .is_some_and(|control| control.take_failpoint(11))
            {
                let control = shared.test_control.as_deref().unwrap();
                let mut delayed = control.delayed_new.lock().unwrap();
                while *delayed {
                    delayed = control.delayed_new_changed.wait(delayed).unwrap();
                }
            }
            if !is_top
                && shared
                    .test_control
                    .as_deref()
                    .is_some_and(|control| control.take_failpoint(12))
            {
                panic!("injected IOCP monitor panic");
            }
            if !is_top
                && shared
                    .test_control
                    .as_deref()
                    .is_some_and(|control| control.take_failpoint(19))
            {
                return Err(std::io::Error::other(
                    "injected process membership ambiguity",
                ));
            }
        }

        {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state.top_new_pending == Some(pid) {
                state.top_new_pending = None;
                return Ok(());
            }
        }

        let process = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if process.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                let mut state = shared
                    .state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if state.occurrences.iter().any(|entry| entry.pid == pid) {
                    return Ok(());
                }
                return push_occurrence(
                    &mut state,
                    ProcessOccurrence {
                        pid,
                        state: OccurrenceState::ConfirmedGone,
                        top: false,
                    },
                );
            }
            return Err(std::io::Error::new(
                error.kind(),
                format!("OpenProcess({pid}) for NEW_PROCESS failed: {error}"),
            ));
        }
        let process = OwnedHandle::new(process)?;
        let mut contained = 0;
        if unsafe { IsProcessInJob(process.raw(), job, &mut contained) } == 0 {
            return Err(last_error("IsProcessInJob for NEW_PROCESS failed"));
        }

        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if contained == 0 {
            if state.occurrences.iter().any(|entry| entry.pid == pid) {
                return Ok(());
            }
            return push_occurrence(
                &mut state,
                ProcessOccurrence {
                    pid,
                    state: OccurrenceState::ConfirmedGone,
                    top: false,
                },
            );
        }

        for occurrence in state.occurrences.iter().filter(|entry| entry.pid == pid) {
            let OccurrenceState::Retained(handle) = &occurrence.state else {
                continue;
            };
            match unsafe { WaitForSingleObject(handle.raw(), 0) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Ok(()),
                WAIT_FAILED => return Err(last_error("checking retained process handle failed")),
                unexpected => {
                    return Err(std::io::Error::other(format!(
                        "unexpected process wait result {unexpected}"
                    )));
                }
            }
        }
        push_occurrence(
            &mut state,
            ProcessOccurrence {
                pid,
                state: OccurrenceState::Retained(process),
                top: false,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn process_is_in_job_for_test(pid: u32, job: usize) -> std::io::Result<bool> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        let process = OwnedHandle::new(process)?;
        let mut contained = 0;
        if unsafe { IsProcessInJob(process.raw(), job as HANDLE, &mut contained) } == 0 {
            return Err(last_error("IsProcessInJob(test child) failed"));
        }
        Ok(contained != 0)
    }

    fn resume_initial_thread(pid: u32) -> std::io::Result<()> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(last_error("CreateToolhelp32Snapshot failed"));
            }
            let mut entry: THREADENTRY32 = zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            let mut found = Vec::new();
            if Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        found.push(entry.th32ThreadID);
                    }
                    if Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            close_handle(snapshot);
            if found.len() != 1 {
                return Err(std::io::Error::other(format!(
                    "suspended child {pid} has {} initial threads; refusing ambiguous resume",
                    found.len()
                )));
            }
            let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, found[0]);
            if thread.is_null() {
                return Err(last_error("OpenThread(initial thread) failed"));
            }
            let previous = ResumeThread(thread);
            close_handle(thread);
            if previous == u32::MAX {
                return Err(last_error("ResumeThread failed"));
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct Accounting {
        total: u64,
        active: u32,
    }

    fn query_accounting(
        job: HANDLE,
        #[cfg(test)] test_control: Option<&TestGuardianState>,
    ) -> std::io::Result<Accounting> {
        #[cfg(test)]
        if test_control
            .is_some_and(|control| control.take_failpoint(14) || control.take_failpoint(22))
        {
            return Err(std::io::Error::other(
                "injected Job accounting query failure",
            ));
        }
        unsafe {
            let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
            if QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                &mut accounting as *mut _ as *mut c_void,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            ) == 0
            {
                return Err(last_error("QueryInformationJobObject failed"));
            }
            Ok(Accounting {
                total: u64::from(accounting.TotalProcesses),
                active: accounting.ActiveProcesses,
            })
        }
    }

    struct MonitorSnapshot {
        raw: u64,
        unique: u64,
        all_retained_signaled: bool,
    }

    enum AuditOutcome {
        Stable,
        ForceRequested,
    }

    fn post_barrier(handles: &Handles, deadline: Instant) -> std::io::Result<()> {
        #[cfg(test)]
        if handles
            .shared
            .test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(13))
        {
            return Err(std::io::Error::other("injected IOCP barrier post failure"));
        }
        let token = handles.shared.next_barrier.fetch_add(1, Ordering::SeqCst);
        if token == 0 || token == usize::MAX {
            return Err(std::io::Error::other("IOCP barrier token overflow"));
        }
        if unsafe {
            PostQueuedCompletionStatus(
                handles.port(),
                OWNER_BARRIER,
                OWNER_COMPLETION_KEY,
                token as *const _,
            )
        } == 0
        {
            return Err(last_error("posting IOCP barrier failed"));
        }

        let mut state = handles
            .shared
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        loop {
            if state.last_ack >= token {
                return Ok(());
            }
            if state.terminal {
                return Err(std::io::Error::other(
                    "IOCP monitor terminated before barrier acknowledgement",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "IOCP barrier acknowledgement timed out",
                ));
            }
            let (next, timeout) = handles
                .shared
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poison| poison.into_inner());
            state = next;
            if timeout.timed_out() && state.last_ack < token {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "IOCP barrier acknowledgement timed out",
                ));
            }
        }
    }

    fn monitor_snapshot(handles: &Handles) -> std::io::Result<MonitorSnapshot> {
        #[cfg(test)]
        if handles
            .shared
            .test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(15))
        {
            return Err(std::io::Error::other(
                "injected retained process wait failure",
            ));
        }
        let state = handles
            .shared
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(error) = &state.first_error {
            return Err(std::io::Error::other(format!(
                "IOCP monitor failed closed: {error}"
            )));
        }
        let mut all_retained_signaled = true;
        for occurrence in &state.occurrences {
            let OccurrenceState::Retained(handle) = &occurrence.state else {
                continue;
            };
            match unsafe { WaitForSingleObject(handle.raw(), 0) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => all_retained_signaled = false,
                WAIT_FAILED => return Err(last_error("auditing retained process handle failed")),
                unexpected => {
                    return Err(std::io::Error::other(format!(
                        "unexpected retained process wait result {unexpected}"
                    )));
                }
            }
        }
        Ok(MonitorSnapshot {
            raw: state.raw_packets,
            unique: state.unique_occurrences,
            all_retained_signaled,
        })
    }

    fn audit_until_stable(
        handles: &Handles,
        force: Option<&tokio_util::sync::CancellationToken>,
    ) -> std::io::Result<AuditOutcome> {
        let deadline = Instant::now() + AUDIT_DEADLINE;
        let mut previous_total = None;
        let mut previous_candidate = None;
        let mut previous_observation = None;
        let mut backoff = Duration::from_millis(1);
        loop {
            if force.is_some_and(tokio_util::sync::CancellationToken::is_cancelled) {
                return Ok(AuditOutcome::ForceRequested);
            }
            post_barrier(handles, deadline)?;
            let snapshot = monitor_snapshot(handles)?;
            let accounting = query_accounting(
                handles.job(),
                #[cfg(test)]
                handles.shared.test_control.as_deref(),
            )?;
            if previous_total.is_some_and(|total| accounting.total < total) {
                return Err(std::io::Error::other(format!(
                    "Job TotalProcesses decreased from {} to {}",
                    previous_total.unwrap(),
                    accounting.total
                )));
            }
            previous_total = Some(accounting.total);

            let candidate = accounting.active == 0
                && snapshot.unique == accounting.total
                && snapshot.all_retained_signaled;
            let counts = (accounting.total, snapshot.unique);
            if candidate && previous_candidate == Some(counts) {
                #[cfg(test)]
                if let Some(control) = &handles.shared.test_control {
                    control.last_audit_raw.store(snapshot.raw, Ordering::SeqCst);
                    control
                        .last_audit_unique
                        .store(snapshot.unique, Ordering::SeqCst);
                    control
                        .last_audit_total
                        .store(accounting.total, Ordering::SeqCst);
                }
                return Ok(AuditOutcome::Stable);
            }
            previous_candidate = candidate.then_some(counts);
            let observation = (
                accounting.active,
                accounting.total,
                snapshot.raw,
                snapshot.unique,
                snapshot.all_retained_signaled,
            );
            if previous_observation.is_some_and(|previous| previous != observation) {
                backoff = Duration::from_millis(1);
            }
            previous_observation = Some(observation);
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "Job audit did not stabilize: active={}, total={}, unique={}, raw={}, all_signaled={}",
                        accounting.active,
                        accounting.total,
                        snapshot.unique,
                        snapshot.raw,
                        snapshot.all_retained_signaled
                    ),
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(backoff.min(remaining));
            backoff = (backoff + backoff).min(Duration::from_millis(10));
        }
    }

    fn stop_monitor(handles: &mut Handles) -> std::io::Result<()> {
        if unsafe {
            PostQueuedCompletionStatus(handles.port(), OWNER_STOP, OWNER_COMPLETION_KEY, null())
        } == 0
        {
            return Err(last_error("posting IOCP monitor stop failed"));
        }
        let monitor = handles
            .monitor
            .take()
            .ok_or_else(|| std::io::Error::other("IOCP monitor owner missing"))?;
        monitor
            .join()
            .map_err(|_| std::io::Error::other("IOCP monitor join observed panic"))?;
        #[cfg(test)]
        if handles
            .shared
            .test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(16))
        {
            return Err(std::io::Error::other("injected IOCP monitor join failure"));
        }
        Ok(())
    }

    fn seed_top_occurrence(handles: &mut Handles, pid: u32) -> std::io::Result<()> {
        let top = handles
            .top_before_seed
            .take()
            .ok_or_else(|| std::io::Error::other("top process handle missing before seed"))?;
        let mut contained = 0;
        if unsafe { IsProcessInJob(top.raw(), handles.job(), &mut contained) } == 0 {
            handles.top_before_seed = Some(top);
            return Err(last_error("IsProcessInJob for top process failed"));
        }
        if contained == 0 {
            handles.top_before_seed = Some(top);
            return Err(std::io::Error::other(
                "top process was not contained in the exact guardian Job",
            ));
        }
        let accounting = match query_accounting(
            handles.job(),
            #[cfg(test)]
            handles.shared.test_control.as_deref(),
        ) {
            Ok(accounting) => accounting,
            Err(error) => {
                handles.top_before_seed = Some(top);
                return Err(error);
            }
        };
        if accounting.total < 1 {
            handles.top_before_seed = Some(top);
            return Err(std::io::Error::other(
                "Job accounting did not observe the assigned top process",
            ));
        }

        let mut state = handles
            .shared
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        push_occurrence(
            &mut state,
            ProcessOccurrence {
                pid,
                state: OccurrenceState::Retained(top),
                top: true,
            },
        )?;
        state.top_new_pending = Some(pid);
        state.seed_ready = true;
        handles.shared.changed.notify_all();
        Ok(())
    }

    fn terminate_wait_audit_and_close(handles: &mut Handles) -> std::io::Result<()> {
        let top = handles
            .top_handle()
            .ok_or_else(|| std::io::Error::other("top process handle missing during force"))?;
        #[cfg(test)]
        if handles
            .shared
            .test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(20))
        {
            let control = handles.shared.test_control.as_deref().unwrap();
            let mut pause = control.terminate_pause.lock().unwrap();
            pause.1 = true;
            control.terminate_pause_changed.notify_all();
            while pause.0 {
                pause = control.terminate_pause_changed.wait(pause).unwrap();
            }
        }
        let job_result = unsafe { TerminateJobObject(handles.job(), 1) };
        let process_result = unsafe { TerminateProcess(top, 1) };
        if job_result == 0 && process_result == 0 {
            return Err(last_error("terminating process and Job both failed"));
        }
        if unsafe { WaitForSingleObject(top, INFINITE) } != WAIT_OBJECT_0 {
            return Err(last_error("waiting for top process failed"));
        }
        match audit_until_stable(handles, None)? {
            AuditOutcome::Stable => {}
            AuditOutcome::ForceRequested => unreachable!("forced audit has no force observer"),
        }
        stop_monitor(handles)?;
        handles.close_after_monitor();
        Ok(())
    }

    fn record_quarantine(handles: &Handles, error: &std::io::Error) {
        use std::io::Write;

        handles.shared.record_error(error.to_string());
        let quarantine_id = QUARANTINE_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        let _ = writeln!(
            stderr,
            "Sembazuru local process guardian quarantine {quarantine_id}: {error}"
        );
    }

    fn quarantine<T>(handles: Handles, error: std::io::Error) -> std::io::Result<T> {
        record_quarantine(&handles, &error);
        std::mem::forget(handles);
        Err(error)
    }

    fn quarantine_natural(
        handles: Handles,
        error: std::io::Error,
        deadline: &SubmissionDeadline,
    ) -> std::io::Result<FinishOutcome> {
        record_quarantine(&handles, &error);
        #[cfg(test)]
        if let Some(control) = &handles.shared.test_control {
            control.natural_publish_branch.store(2, Ordering::SeqCst);
        }
        std::mem::forget(handles);
        if deadline.publish_natural_reaped() {
            Ok(FinishOutcome::Natural)
        } else {
            Err(std::io::Error::other(
                "committed natural completion lost its phase transition",
            ))
        }
    }

    fn cleanup_with_quarantine(
        mut handles: Handles,
        operation: impl FnOnce(&mut Handles) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        match catch_unwind(AssertUnwindSafe(|| operation(&mut handles))) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => quarantine(handles, error),
            Err(_) => quarantine(
                handles,
                std::io::Error::other("guardian audit owner panicked"),
            ),
        }
    }

    fn finish_after_top_exit(
        mut handles: Handles,
        inject_disarm_failure: bool,
        deadline: Arc<SubmissionDeadline>,
    ) -> std::io::Result<FinishOutcome> {
        unsafe {
            if deadline.force_token().is_cancelled() && deadline.try_begin_terminating() {
                cleanup_with_quarantine(handles, terminate_wait_audit_and_close)?;
                let _ = deadline.publish_forced_reaped();
                return Ok(FinishOutcome::Forced);
            }
            let limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            if !inject_disarm_failure
                && SetInformationJobObject(
                    handles.job(),
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const c_void,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ) != 0
            {
                if let Err(error) = stop_monitor(&mut handles) {
                    return quarantine_natural(handles, error, &deadline);
                }
                handles.close_after_monitor();
                #[cfg(test)]
                if let Some(control) = &handles.shared.test_control {
                    control.natural_publish_branch.store(2, Ordering::SeqCst);
                }
                if deadline.publish_natural_reaped() {
                    return Ok(FinishOutcome::Natural);
                }
                return Err(std::io::Error::other(
                    "natural completion lost its phase transition",
                ));
            }

            let force = deadline.force_token();
            loop {
                if force.is_cancelled() && deadline.try_begin_terminating() {
                    let result = cleanup_with_quarantine(handles, terminate_wait_audit_and_close);
                    if result.is_ok() {
                        let _ = deadline.publish_forced_reaped();
                        return Ok(FinishOutcome::Forced);
                    }
                    let _ = deadline.publish_force_failed();
                    return result.map(|()| FinishOutcome::Forced);
                }
                let audit = match audit_until_stable(&handles, Some(&force)) {
                    Ok(audit) => audit,
                    Err(error) => return quarantine(handles, error),
                };
                match audit {
                    AuditOutcome::ForceRequested => continue,
                    AuditOutcome::Stable => {
                        if let Err(error) = stop_monitor(&mut handles) {
                            return quarantine(handles, error);
                        }
                        handles.close_after_monitor();
                        #[cfg(test)]
                        if let Some(control) = &handles.shared.test_control {
                            control.natural_publish_branch.store(3, Ordering::SeqCst);
                        }
                        if deadline.publish_natural_reaped() {
                            return Ok(FinishOutcome::Natural);
                        }
                        return Err(std::io::Error::other(
                            "natural-empty audit lost its phase transition",
                        ));
                    }
                }
            }
        }
    }

    pub(super) struct CallerLaunch {
        pub(super) application: String,
        command_line: String,
        cwd: String,
        environment: Vec<(String, String)>,
    }

    fn validate_environment_entry(key: &str, value: &str) -> std::io::Result<()> {
        if key.is_empty() || key.contains('\0') || value.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "environment keys and values must be nonempty NUL-free UTF-16 strings",
            ));
        }
        if key.contains('=') && !key.starts_with('=') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("environment key contains '=': {key}"),
            ));
        }
        Ok(())
    }

    pub(super) fn overlay_environment(
        mut base: Vec<(String, String)>,
        overlay: &std::collections::HashMap<String, String>,
    ) -> std::io::Result<Vec<(String, String)>> {
        for (key, value) in overlay {
            #[cfg(test)]
            if key.eq_ignore_ascii_case(TEST_CONTROL_MARKER) {
                continue;
            }
            validate_environment_entry(key, value)?;
            base.retain(|(existing, _)| !existing.eq_ignore_ascii_case(key));
            base.push((key.clone(), value.clone()));
        }
        #[cfg(test)]
        base.retain(|(key, _)| !key.eq_ignore_ascii_case(TEST_CONTROL_MARKER));
        base.sort_by(|left, right| {
            left.0
                .to_ascii_lowercase()
                .cmp(&right.0.to_ascii_lowercase())
                .then_with(|| left.0.cmp(&right.0))
        });
        Ok(base)
    }

    fn environment_from_token(token: HANDLE) -> std::io::Result<Vec<(String, String)>> {
        let mut raw = null_mut();
        if unsafe { CreateEnvironmentBlock(&mut raw, token, 0) } == 0 {
            return Err(last_error("CreateEnvironmentBlock failed"));
        }
        struct EnvironmentBlock(*mut c_void);
        impl Drop for EnvironmentBlock {
            fn drop(&mut self) {
                unsafe {
                    let _ = DestroyEnvironmentBlock(self.0);
                }
            }
        }
        let block = EnvironmentBlock(raw);
        let mut entries = Vec::new();
        let mut offset = 0usize;
        const MAX_ENVIRONMENT_UNITS: usize = 16 * 1024 * 1024;
        loop {
            if offset >= MAX_ENVIRONMENT_UNITS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "caller environment block is not terminated",
                ));
            }
            let start = unsafe { (block.0 as *const u16).add(offset) };
            if unsafe { *start } == 0 {
                break;
            }
            let mut length = 0usize;
            while unsafe { *start.add(length) } != 0 {
                length += 1;
                if offset + length >= MAX_ENVIRONMENT_UNITS {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "caller environment entry is not terminated",
                    ));
                }
            }
            let entry = String::from_utf16(unsafe { std::slice::from_raw_parts(start, length) })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "caller environment contains invalid UTF-16",
                    )
                })?;
            let delimiter = if let Some(entry_without_prefix) = entry.strip_prefix('=') {
                entry_without_prefix.find('=').map(|index| index + 1)
            } else {
                entry.find('=')
            }
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "caller environment entry has no '=' delimiter",
                )
            })?;
            let (key, value) = entry.split_at(delimiter);
            let value = &value[1..];
            validate_environment_entry(key, value)?;
            entries.push((key.to_owned(), value.to_owned()));
            offset += length + 1;
        }
        Ok(entries)
    }

    fn environment_value<'a>(environment: &'a [(String, String)], key: &str) -> Option<&'a str> {
        environment
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    fn resolve_caller_program(
        program: &str,
        cwd: &Path,
        environment: &[(String, String)],
    ) -> std::io::Result<PathBuf> {
        if program.is_empty() || program.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command argv[0] must be a nonempty NUL-free string",
            ));
        }
        let program_path = Path::new(program);
        let explicit_path = program_path.is_absolute()
            || program.contains('\\')
            || program.contains('/')
            || program_path.components().count() > 1;
        let mut directories = Vec::new();
        if explicit_path {
            let candidate = if program_path.is_absolute() {
                program_path.to_path_buf()
            } else {
                cwd.join(program_path)
            };
            if let Some(parent) = candidate.parent() {
                directories.push((
                    parent.to_path_buf(),
                    candidate.file_name().unwrap().to_owned(),
                ));
            }
        } else {
            if let Some(path) = environment_value(environment, "PATH") {
                directories.extend(
                    std::env::split_paths(path)
                        .filter(|directory| !directory.as_os_str().is_empty())
                        .map(|directory| {
                            let directory = if directory.is_absolute() {
                                directory
                            } else {
                                cwd.join(directory)
                            };
                            (directory, program_path.as_os_str().to_owned())
                        }),
                );
            }
        }
        for (directory, file_name) in directories {
            let candidate = directory.join(&file_name);
            let candidates = if candidate.extension().is_none() {
                vec![candidate.with_extension("exe")]
            } else {
                vec![candidate]
            };
            for candidate in candidates {
                if candidate.is_file() {
                    return candidate.canonicalize();
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("caller program was not found using caller cwd/PATH: {program}"),
        ))
    }

    fn quote_windows_arg(argument: &str) -> String {
        if !argument.is_empty()
            && !argument
                .chars()
                .any(|character| character == ' ' || character == '\t' || character == '"')
        {
            return argument.to_owned();
        }
        let mut quoted = String::from("\"");
        let mut backslashes = 0usize;
        for character in argument.chars() {
            match character {
                '\\' => backslashes += 1,
                '"' => {
                    quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                    quoted.push('"');
                    backslashes = 0;
                }
                _ => {
                    quoted.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    quoted.push(character);
                }
            }
        }
        quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
        quoted.push('"');
        quoted
    }

    pub(super) fn quote_windows_argv(argv: &[String]) -> String {
        argv.iter()
            .map(|argument| quote_windows_arg(argument))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn append_batch_argument(command_line: &mut Vec<u16>, argument: &str) -> std::io::Result<()> {
        if argument.contains(['\0', '\r', '\n']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "batch file arguments must not contain NUL, CR, or LF",
            ));
        }
        let mut quote = argument.is_empty() || argument.ends_with('\\');
        const UNQUOTED: &str = r"#$*+-./:?@\_";
        for character in argument.chars() {
            let ascii_needs_quotes = character.is_ascii()
                && !(character.is_ascii_alphanumeric() || UNQUOTED.contains(character));
            if ascii_needs_quotes || character.is_control() {
                quote = true;
            }
        }
        if quote {
            command_line.push('"' as u16);
        }
        let mut backslashes = 0usize;
        for unit in std::ffi::OsStr::new(argument).encode_wide() {
            if unit == '\\' as u16 {
                backslashes += 1;
            } else {
                if unit == '"' as u16 {
                    command_line.extend(std::iter::repeat_n('\\' as u16, backslashes));
                    command_line.push('"' as u16);
                } else if unit == '%' as u16 {
                    command_line.extend("%%cd:~,".encode_utf16());
                }
                backslashes = 0;
            }
            command_line.push(unit);
        }
        if quote {
            command_line.extend(std::iter::repeat_n('\\' as u16, backslashes));
            command_line.push('"' as u16);
        }
        Ok(())
    }

    fn verified_batch_user_path(path: &Path) -> std::io::Result<Vec<u16>> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        const LEGACY_MAX_PATH: usize = 260;
        if wide.len() > LEGACY_MAX_PATH {
            return Ok(wide);
        }
        let candidate = match wide.as_slice() {
            [sep1, sep2, query, sep3, _, colon, sep4, ..]
                if *sep1 == '\\' as u16
                    && *sep2 == '\\' as u16
                    && *query == '?' as u16
                    && *sep3 == '\\' as u16
                    && *colon == ':' as u16
                    && *sep4 == '\\' as u16 =>
            {
                wide[4..].to_vec()
            }
            [sep1, sep2, query, sep3, u, n, c, sep4, ..]
                if *sep1 == '\\' as u16
                    && *sep2 == '\\' as u16
                    && *query == '?' as u16
                    && *sep3 == '\\' as u16
                    && *u == 'U' as u16
                    && *n == 'N' as u16
                    && *c == 'C' as u16
                    && *sep4 == '\\' as u16 =>
            {
                let mut candidate = vec!['\\' as u16, '\\' as u16];
                candidate.extend_from_slice(&wide[8..]);
                candidate
            }
            _ => return Ok(wide),
        };
        let required = unsafe { GetFullPathNameW(candidate.as_ptr(), 0, null_mut(), null_mut()) };
        if required == 0 {
            return Err(last_error("GetFullPathNameW(batch path length) failed"));
        }
        let mut full = vec![0u16; required as usize];
        let written = unsafe {
            GetFullPathNameW(
                candidate.as_ptr(),
                full.len() as u32,
                full.as_mut_ptr(),
                null_mut(),
            )
        };
        if written == 0 || written as usize >= full.len() {
            return Err(last_error("GetFullPathNameW(batch path) failed"));
        }
        full.truncate(written as usize);
        if full.as_slice() != &candidate[..candidate.len() - 1] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "batch path cannot be safely converted from verbatim form",
            ));
        }
        full.push(0);
        Ok(full)
    }

    pub(super) fn make_batch_command_line(
        script: &Path,
        args: &[String],
    ) -> std::io::Result<String> {
        let script = verified_batch_user_path(script)?;
        if script.starts_with(&['\\' as u16, '\\' as u16, '?' as u16, '\\' as u16]) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cmd.exe does not support verbatim batch paths",
            ));
        }
        let script = script.strip_suffix(&[0]).unwrap_or(&script);
        if script.contains(&('"' as u16)) || script.last() == Some(&('\\' as u16)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows batch paths must not contain quotes or end with backslash",
            ));
        }
        let mut command_line = "cmd.exe /e:ON /v:OFF /d /c \""
            .encode_utf16()
            .collect::<Vec<_>>();
        command_line.push('"' as u16);
        command_line.extend_from_slice(script);
        command_line.push('"' as u16);
        for argument in args {
            command_line.push(' ' as u16);
            append_batch_argument(&mut command_line, argument)?;
        }
        command_line.push('"' as u16);
        String::from_utf16(&command_line).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "batch command line contains invalid UTF-16",
            )
        })
    }

    pub(super) fn prepare_caller_launch(
        command: &Command,
        environment: Vec<(String, String)>,
    ) -> std::io::Result<CallerLaunch> {
        if command.argv.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command.argv is empty",
            ));
        }
        if command.argv.iter().any(|argument| argument.contains('\0')) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command arguments must not contain NUL",
            ));
        }
        if command.cwd.is_empty() || command.cwd.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "authenticated caller command requires a nonempty NUL-free cwd",
            ));
        }
        let cwd = PathBuf::from(&command.cwd);
        if !cwd.is_absolute() || !cwd.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "authenticated caller cwd is not an absolute directory: {}",
                    command.cwd
                ),
            ));
        }
        let application = resolve_caller_program(&command.argv[0], &cwd, &environment)?;
        let is_batch = application
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat")
            });
        let (application, command_line) = if is_batch {
            let comspec = environment_value(&environment, "ComSpec").ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "caller environment has no ComSpec for batch execution",
                )
            })?;
            let comspec = resolve_caller_program(comspec, &cwd, &environment)?;
            let command_line = make_batch_command_line(&application, &command.argv[1..])?;
            (comspec, command_line)
        } else {
            let mut argv = command.argv.clone();
            argv[0] = application.to_string_lossy().into_owned();
            let command_line = quote_windows_argv(&argv);
            (application, command_line)
        };
        Ok(CallerLaunch {
            application: application.to_string_lossy().into_owned(),
            command_line,
            cwd: cwd.to_string_lossy().into_owned(),
            environment,
        })
    }

    fn encode_environment_block(environment: &[(String, String)]) -> std::io::Result<Vec<u16>> {
        let mut block = Vec::new();
        for (key, value) in environment {
            validate_environment_entry(key, value)?;
            block.extend(std::ffi::OsStr::new(key).encode_wide());
            block.push('=' as u16);
            block.extend(std::ffi::OsStr::new(value).encode_wide());
            block.push(0);
        }
        block.push(0);
        if block.len() == 1 {
            block.push(0);
        }
        Ok(block)
    }

    struct CallerChild {
        process: OwnedHandle,
        initial_thread: Option<OwnedHandle>,
        pid: u32,
    }

    enum LocalChild {
        Ambient(Box<tokio::process::Child>),
        Caller(CallerChild),
    }

    impl LocalChild {
        fn pid(&self) -> std::io::Result<u32> {
            match self {
                Self::Ambient(child) => child
                    .id()
                    .ok_or_else(|| std::io::Error::other("suspended child has no process id")),
                Self::Caller(child) => Ok(child.pid),
            }
        }

        fn process_raw(&self) -> std::io::Result<HANDLE> {
            match self {
                Self::Ambient(child) => child
                    .raw_handle()
                    .map(|handle| handle as HANDLE)
                    .ok_or_else(|| std::io::Error::other("child process handle is unavailable")),
                Self::Caller(child) => Ok(child.process.raw()),
            }
        }

        fn duplicate_process(&self) -> std::io::Result<OwnedHandle> {
            duplicate_raw_process_handle(self.process_raw()?)
        }

        fn resume(&mut self) -> std::io::Result<()> {
            match self {
                Self::Ambient(child) => {
                    resume_initial_thread(child.id().ok_or_else(|| {
                        std::io::Error::other("suspended child has no process id")
                    })?)
                }
                Self::Caller(child) => {
                    let thread = child.initial_thread.take().ok_or_else(|| {
                        std::io::Error::other("caller child initial thread is unavailable")
                    })?;
                    let previous = unsafe { ResumeThread(thread.raw()) };
                    if previous == u32::MAX {
                        return Err(last_error("ResumeThread(caller child) failed"));
                    }
                    Ok(())
                }
            }
        }

        async fn terminate_and_wait(&mut self) -> std::io::Result<()> {
            match self {
                Self::Ambient(child) => {
                    let _ = child.start_kill();
                    child.wait().await.map(|_| ())
                }
                Self::Caller(child) => {
                    if unsafe { TerminateProcess(child.process.raw(), 1) } == 0 {
                        let wait = unsafe { WaitForSingleObject(child.process.raw(), 0) };
                        if wait != WAIT_OBJECT_0 {
                            return Err(last_error("TerminateProcess(caller child) failed"));
                        }
                    }
                    match unsafe { WaitForSingleObject(child.process.raw(), INFINITE) } {
                        WAIT_OBJECT_0 => Ok(()),
                        WAIT_FAILED => Err(last_error("WaitForSingleObject(caller child) failed")),
                        unexpected => Err(std::io::Error::other(format!(
                            "unexpected caller child wait result {unexpected}"
                        ))),
                    }
                }
            }
        }

        async fn wait(&mut self) -> std::io::Result<i32> {
            match self {
                Self::Ambient(child) => {
                    let status = child.wait().await?;
                    Ok(status.code().unwrap_or(-1))
                }
                Self::Caller(child) => {
                    let process = duplicate_raw_process_handle(child.process.raw())?;
                    tokio::task::spawn_blocking(move || {
                        match unsafe { WaitForSingleObject(process.raw(), INFINITE) } {
                            WAIT_OBJECT_0 => {
                                let mut exit_code = 0;
                                if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == 0
                                {
                                    Err(last_error("GetExitCodeProcess(caller child) failed"))
                                } else {
                                    Ok(exit_code as i32)
                                }
                            }
                            WAIT_FAILED => {
                                Err(last_error("WaitForSingleObject(caller child) failed"))
                            }
                            unexpected => Err(std::io::Error::other(format!(
                                "unexpected caller child wait result {unexpected}"
                            ))),
                        }
                    })
                    .await
                    .map_err(|error| {
                        std::io::Error::other(format!("caller child waiter panicked: {error}"))
                    })?
                }
            }
        }
    }

    fn duplicate_raw_process_handle(process: HANDLE) -> std::io::Result<OwnedHandle> {
        unsafe {
            let current = GetCurrentProcess();
            let mut duplicate = null_mut();
            if DuplicateHandle(
                current,
                process,
                current,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            ) == 0
            {
                return Err(last_error("DuplicateHandle(process) failed"));
            }
            OwnedHandle::new(duplicate)
        }
    }

    fn spawn_ambient(command: &Command) -> std::io::Result<LocalChild> {
        let mut cmd = tokio::process::Command::new(&command.argv[0]);
        cmd.args(&command.argv[1..]);
        if !command.cwd.is_empty() {
            cmd.current_dir(&command.cwd);
        }
        #[cfg(test)]
        cmd.env_remove(TEST_CONTROL_MARKER);
        for (key, value) in &command.env {
            #[cfg(test)]
            if key.eq_ignore_ascii_case(TEST_CONTROL_MARKER) {
                continue;
            }
            cmd.env(key, value);
        }
        cmd.kill_on_drop(true);
        cmd.as_std_mut().creation_flags(CREATE_SUSPENDED);
        cmd.spawn().map(Box::new).map(LocalChild::Ambient)
    }

    fn spawn_as_caller(
        command: &Command,
        identity: &crate::intake_pipe::CallerIdentity,
        #[cfg(test)] test_control: Option<&TestGuardianState>,
    ) -> std::io::Result<LocalChild> {
        let base = environment_from_token(identity.primary_token.as_raw_handle() as HANDLE)?;
        let environment = overlay_environment(base, &command.env)?;
        let launch = prepare_caller_launch(command, environment)?;
        let mut application = std::ffi::OsStr::new(&launch.application)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut command_line = std::ffi::OsStr::new(&launch.command_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let cwd = std::ffi::OsStr::new(&launch.cwd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let environment = encode_environment_block(&launch.environment)?;
        #[cfg(test)]
        if test_control.is_some_and(|control| control.take_failpoint(23)) {
            return Err(std::io::Error::other(
                "injected failure before CreateProcessAsUserW",
            ));
        }
        let mut startup: STARTUPINFOW = unsafe { zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
        let created = unsafe {
            CreateProcessAsUserW(
                identity.primary_token.as_raw_handle() as HANDLE,
                application.as_mut_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                cwd.as_ptr(),
                &startup,
                &mut process,
            )
        };
        if created == 0 {
            return Err(last_error("CreateProcessAsUserW failed"));
        }
        let process_handle = OwnedHandle::new(process.hProcess);
        let thread_handle = OwnedHandle::new(process.hThread);
        match (process_handle, thread_handle) {
            (Ok(process_handle), Ok(thread_handle)) => Ok(LocalChild::Caller(CallerChild {
                process: process_handle,
                initial_thread: Some(thread_handle),
                pid: process.dwProcessId,
            })),
            (process_result, thread_result) => {
                unsafe {
                    if let Ok(process_handle) = &process_result {
                        let _ = TerminateProcess(process_handle.raw(), 1);
                        let _ = WaitForSingleObject(process_handle.raw(), INFINITE);
                    } else if !process.hProcess.is_null() {
                        let _ = TerminateProcess(process.hProcess, 1);
                        let _ = WaitForSingleObject(process.hProcess, INFINITE);
                        close_handle(process.hProcess);
                    }
                    if thread_result.is_err() && !process.hThread.is_null() {
                        close_handle(process.hThread);
                    }
                }
                process_result.and(thread_result).map(|_| unreachable!())
            }
        }
    }

    enum SpawnContext<'a> {
        Ambient,
        Caller(&'a crate::intake_pipe::CallerIdentity),
    }

    pub(super) async fn run_as_caller(
        command: &Command,
        identity: &crate::intake_pipe::CallerIdentity,
        deadline: Arc<SubmissionDeadline>,
        #[cfg(test)] test_control: Option<Arc<TestGuardianState>>,
    ) -> std::io::Result<i32> {
        run_inner(
            command,
            deadline,
            SpawnContext::Caller(identity),
            #[cfg(test)]
            test_control,
        )
        .await
    }

    pub(super) async fn run(
        command: &Command,
        deadline: Arc<SubmissionDeadline>,
        #[cfg(test)] test_control: Option<Arc<TestGuardianState>>,
    ) -> std::io::Result<i32> {
        run_inner(
            command,
            deadline,
            SpawnContext::Ambient,
            #[cfg(test)]
            test_control,
        )
        .await
    }

    async fn run_inner(
        command: &Command,
        deadline: Arc<SubmissionDeadline>,
        spawn_context: SpawnContext<'_>,
        #[cfg(test)] test_control: Option<Arc<TestGuardianState>>,
    ) -> std::io::Result<i32> {
        if !deadline.try_begin_setup() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "submission was stopped before local process setup",
            ));
        }
        let job = match create_job(
            #[cfg(test)]
            test_control.clone(),
        ) {
            Ok(job) => job,
            Err(error) => {
                let _ = deadline.publish_retry_safe_reaped();
                return Err(error);
            }
        };
        let port = match create_port_and_associate(
            job.raw(),
            #[cfg(test)]
            test_control.as_deref(),
        ) {
            Ok(port) => port,
            Err(error) => {
                drop(job);
                let _ = deadline.publish_retry_safe_reaped();
                return Err(error);
            }
        };
        let shared = Arc::new(MonitorShared::new(
            #[cfg(test)]
            test_control.clone(),
        ));
        let monitor = match start_monitor(job.raw(), port.raw(), Arc::clone(&shared)) {
            Ok(monitor) => monitor,
            Err(error) => {
                drop(port);
                drop(job);
                let _ = deadline.publish_retry_safe_reaped();
                return Err(error);
            }
        };
        let mut handles = Handles {
            job: Some(job),
            port: Some(port),
            top_before_seed: None,
            monitor: Some(monitor),
            shared,
        };

        let spawn_result = match spawn_context {
            SpawnContext::Ambient => spawn_ambient(command),
            SpawnContext::Caller(identity) => spawn_as_caller(
                command,
                identity,
                #[cfg(test)]
                test_control.as_deref(),
            ),
        };
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(error) => {
                let _ = stop_monitor(&mut handles);
                handles.close_after_monitor();
                let _ = deadline.publish_retry_safe_reaped();
                return Err(error);
            }
        };
        let process = match child.duplicate_process() {
            Ok(process) => process,
            Err(error) => {
                let waited = child.terminate_and_wait().await;
                let _ = stop_monitor(&mut handles);
                handles.close_after_monitor();
                if waited.is_ok() {
                    let _ = deadline.publish_retry_safe_reaped();
                } else {
                    let _ = deadline.publish_force_failed();
                }
                return Err(error);
            }
        };
        handles.top_before_seed = Some(process);
        let guardian = ProcessGuardian::new(handles, Arc::clone(&deadline));
        #[cfg(test)]
        if test_control
            .as_deref()
            .is_some_and(|control| control.observe_job.swap(false, Ordering::SeqCst))
        {
            unsafe {
                let current = GetCurrentProcess();
                let mut duplicate = null_mut();
                assert_ne!(
                    DuplicateHandle(
                        current,
                        guardian.job_raw(),
                        current,
                        &mut duplicate,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    ),
                    0,
                    "could not duplicate observed Job handle: {}",
                    std::io::Error::last_os_error()
                );
                assert_eq!(
                    test_control
                        .as_ref()
                        .unwrap()
                        .observed_job_handle
                        .swap(duplicate as usize, Ordering::SeqCst),
                    0,
                    "previous observed Job handle was not consumed"
                );
            }
        }
        #[cfg(test)]
        if test_control
            .as_deref()
            .is_some_and(|control| (1..=3).any(|point| control.is_armed(point)))
        {
            use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};

            let pid = child.pid().unwrap_or(0);
            let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(
                !process.is_null(),
                "could not retain suspended child {pid}: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                test_control
                    .as_ref()
                    .unwrap()
                    .last_child_handle
                    .swap(process as usize, Ordering::SeqCst),
                0,
                "previous setup observation handle was not consumed"
            );
        }
        #[cfg(test)]
        if test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(1))
        {
            guardian.force_reap(true).await?;
            return Err(std::io::Error::other(
                "injected failure after suspended spawn",
            ));
        }
        let assigned =
            unsafe { AssignProcessToJobObject(guardian.job_raw(), child.process_raw()?) };
        if assigned == 0 {
            let error = last_error("AssignProcessToJobObject failed");
            guardian.force_reap(true).await?;
            return Err(error);
        }
        let pid = child.pid()?;
        if let Err(error) = guardian.seed_top(pid) {
            let _ = guardian.force_reap(true).await;
            return Err(error);
        }
        #[cfg(test)]
        if test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(2))
        {
            guardian.force_reap(true).await?;
            return Err(std::io::Error::other(
                "injected failure after job assignment",
            ));
        }
        #[cfg(test)]
        if test_control
            .as_deref()
            .is_some_and(|control| control.take_failpoint(3))
        {
            guardian.force_reap(true).await?;
            return Err(std::io::Error::other("injected failure before resume"));
        }
        if let Err(error) = child.resume() {
            guardian.force_reap(true).await?;
            return Err(error);
        }
        if !deadline.publish_active() {
            guardian.force_reap(true).await?;
            return Err(std::io::Error::other(
                "submission phase changed before child became active",
            ));
        }

        let force = deadline.force_token();
        tokio::select! {
            biased;
            _ = force.cancelled() => {
                guardian.force_reap(false).await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "local process was stopped for daemon shutdown",
                ))
            }
            exit_code = child.wait() => {
                let exit_code = exit_code?;
                match guardian.finish_natural().await? {
                    FinishOutcome::Natural => Ok(exit_code),
                    FinishOutcome::Forced => Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "local process tree was stopped during post-exit drain",
                    )),
                }
            }
        }
    }
}

/// Tries the action on the worker; on any remote failure — transport/RPC error,
/// or the action not completing (worker reported FAILED, no exit) — re-runs it
/// locally. This is the "safety half" of M3.4: the build always completes. The
/// latency-budget timer and the detect-unvirtualizable-access trigger are the
/// tuning half (M3.5 / later); this guarantees correctness first.
pub async fn execute_with_fallback(
    endpoint: String,
    command: Command,
    action_id: String,
    session_id: String,
) -> Execution {
    let reason = match execute_remote(endpoint, command.clone(), action_id, session_id).await {
        Ok(outcome) if outcome.exit_code.is_some() => return Execution::Remote(outcome),
        Ok(_) => LocalFallbackReason::RemoteExhausted(
            "remote action did not complete (no exit status)".to_string(),
        ),
        Err(e) => LocalFallbackReason::RemoteExhausted(format!("remote execution failed: {e}")),
    };
    let exit_code = run_local(&command).await.unwrap_or(-1);
    Execution::LocalFallback { exit_code, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct SourceError(&'static str, bool);

    impl std::fmt::Display for SourceError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for SourceError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.then_some(self)
        }
    }

    #[test]
    fn execute_error_rpc_display_does_not_expand_status_source() {
        let status = tonic::Status::from_error(Box::new(SourceError("rpc-source", false)));
        let expected = format!("rpc: {status}");
        let error = ExecuteError::Rpc(status);
        assert_eq!(error.to_string(), expected);
        let source = std::error::Error::source(&error).unwrap();
        assert!(source.is::<tonic::Status>());
    }

    #[test]
    fn error_chain_display_bounds_cycles() {
        let displayed = ErrorChain(&SourceError("cycle-source", true)).to_string();
        assert_eq!(displayed, "cycle-source: [source chain truncated]");
    }

    #[cfg(windows)]
    #[test]
    fn caller_launch_quotes_windows_argv_and_overlays_environment() {
        let base = [
            ("Path".to_string(), r"C:\caller\bin".to_string()),
            ("KEEP".to_string(), "base".to_string()),
            ("replace".to_string(), "old".to_string()),
        ]
        .into_iter()
        .collect();
        let overlay = [
            ("PATH".to_string(), r"C:\override\bin".to_string()),
            ("REPLACE".to_string(), "new".to_string()),
            ("Unicode".to_string(), "鶴".to_string()),
        ]
        .into_iter()
        .collect();

        let merged = local_job::overlay_environment(base, &overlay).unwrap();
        assert_eq!(
            merged
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("path"))
                .unwrap()
                .1,
            r"C:\override\bin"
        );
        assert_eq!(
            merged
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("replace"))
                .count(),
            1
        );
        assert_eq!(
            merged
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("replace"))
                .unwrap()
                .1,
            "new"
        );
        assert_eq!(
            local_job::quote_windows_argv(&[
                r"C:\space dir\tool.exe".into(),
                "".into(),
                r#"a\"b"#.into(),
                r"ends\\".into(),
                "鶴".into(),
            ]),
            r#""C:\space dir\tool.exe" "" "a\\\"b" ends\\ 鶴"#
        );
    }

    #[cfg(windows)]
    #[test]
    fn caller_bare_program_resolves_only_from_caller_path() {
        let root = std::env::temp_dir().join(format!(
            "sembazuru-caller-resolve-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cwd = root.join("cwd");
        let path = root.join("path");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(cwd.join("same-name.exe"), b"cwd impostor").unwrap();
        std::fs::write(path.join("same-name.exe"), b"caller path target").unwrap();
        let command = Command {
            argv: vec!["same-name.exe".into()],
            env: Default::default(),
            cwd: cwd.to_string_lossy().into_owned(),
        };
        let environment = vec![("Path".into(), path.to_string_lossy().into_owned())];

        let launch = local_job::prepare_caller_launch(&command, environment).unwrap();
        assert_eq!(
            std::path::Path::new(&launch.application),
            path.join("same-name.exe").canonicalize().unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn caller_path_search_ignores_empty_entries_and_cwd_impostor() {
        let root = std::env::temp_dir().join(format!(
            "sembazuru-caller-empty-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cwd = root.join("cwd");
        let path = root.join("path");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(cwd.join("cl.exe"), b"cwd impostor").unwrap();
        std::fs::write(path.join("cl.exe"), b"caller path target").unwrap();
        let command = Command {
            argv: vec!["cl".into()],
            env: Default::default(),
            cwd: cwd.to_string_lossy().into_owned(),
        };
        let environment = vec![("Path".into(), format!(";{};;", path.to_string_lossy()))];

        let launch = local_job::prepare_caller_launch(&command, environment).unwrap();
        assert_eq!(
            std::path::Path::new(&launch.application),
            path.join("cl.exe").canonicalize().unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn caller_extensionless_program_never_resolves_plain_file() {
        let root = std::env::temp_dir().join(format!(
            "sembazuru-caller-extensionless-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cwd = root.join("cwd");
        let path = root.join("path");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("bare"), b"not an exe candidate").unwrap();
        std::fs::write(cwd.join("explicit"), b"not an exe candidate").unwrap();

        let bare = Command {
            argv: vec!["bare".into()],
            env: Default::default(),
            cwd: cwd.to_string_lossy().into_owned(),
        };
        let path_environment = vec![("Path".into(), path.to_string_lossy().into_owned())];
        assert_eq!(
            local_job::prepare_caller_launch(&bare, path_environment)
                .err()
                .expect("bare extensionless file unexpectedly resolved")
                .kind(),
            std::io::ErrorKind::NotFound
        );

        let explicit = Command {
            argv: vec![r".\explicit".into()],
            env: Default::default(),
            cwd: cwd.to_string_lossy().into_owned(),
        };
        assert_eq!(
            local_job::prepare_caller_launch(&explicit, Vec::new())
                .err()
                .expect("explicit extensionless file unexpectedly resolved")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn caller_normal_launch_rejects_embedded_nul() {
        let executable = std::env::current_exe().unwrap();
        let command = Command {
            argv: vec![
                executable.to_string_lossy().into_owned(),
                "before\0after".into(),
            ],
            env: Default::default(),
            cwd: executable.parent().unwrap().to_string_lossy().into_owned(),
        };

        assert_eq!(
            local_job::prepare_caller_launch(&command, Vec::new())
                .err()
                .expect("embedded NUL argument was accepted")
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[cfg(windows)]
    #[test]
    fn caller_batch_command_line_matches_rust_std_golden() {
        let script = std::path::Path::new(r"C:\test.cmd");
        let prefix = r#"cmd.exe /e:ON /v:OFF /d /c ""C:\test.cmd" "#;
        assert_eq!(
            local_job::make_batch_command_line(script, &[]).unwrap(),
            r#"cmd.exe /e:ON /v:OFF /d /c ""C:\test.cmd"""#
        );
        assert_eq!(
            local_job::make_batch_command_line(script, &[String::new()]).unwrap(),
            format!("{prefix}\"\"\"")
        );
        assert_eq!(
            local_job::make_batch_command_line(script, &["a&b".into()]).unwrap(),
            format!("{prefix}\"a&b\"\"")
        );
        assert_eq!(
            local_job::make_batch_command_line(script, &["%PATH%".into()]).unwrap(),
            format!("{prefix}\"%%cd:~,%PATH%%cd:~,%\"\"")
        );
        assert_eq!(
            local_job::make_batch_command_line(script, &["a\"b".into()]).unwrap(),
            format!("{prefix}\"a\"\"b\"\"")
        );
        assert_eq!(
            local_job::make_batch_command_line(script, &["ends\\".into()]).unwrap(),
            format!("{prefix}\"ends\\\\\"\"")
        );
        for invalid in ["line\rbreak", "line\nbreak", "nul\0inside"] {
            assert_eq!(
                local_job::make_batch_command_line(script, &[invalid.into()])
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        let long_nonverbatim =
            std::path::PathBuf::from(format!(r"C:\{}\test.cmd", "a".repeat(270)));
        assert!(local_job::make_batch_command_line(&long_nonverbatim, &[]).is_ok());
        let long_verbatim =
            std::path::PathBuf::from(format!(r"\\?\C:\{}\test.cmd", "a".repeat(270)));
        assert_eq!(
            local_job::make_batch_command_line(&long_verbatim, &[])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn caller_batch_launch_matches_std_argv() {
        use std::os::windows::ffi::OsStrExt;

        fn expected_binary(arguments: &[String]) -> Vec<u8> {
            let mut output = Vec::new();
            output.extend_from_slice(&(arguments.len() as u32).to_le_bytes());
            for argument in arguments {
                let wide = std::ffi::OsStr::new(argument)
                    .encode_wide()
                    .collect::<Vec<_>>();
                output.extend_from_slice(&(wide.len() as u32).to_le_bytes());
                for unit in wide {
                    output.extend_from_slice(&unit.to_le_bytes());
                }
            }
            output
        }

        let cwd = std::env::temp_dir().join(format!(
            "sembazuru-caller-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&cwd).unwrap();
        let helper_source = cwd.join("helper.rs");
        let helper = cwd.join("helper.exe");
        let script = cwd.join("oracle.cmd");
        let std_output = cwd.join("std-argv.bin");
        let caller_output = cwd.join("caller-argv.bin");
        let sentinel = cwd.join("injected.txt");
        std::fs::write(
            &helper_source,
            r#"use std::os::windows::ffi::OsStrExt;
fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut output = Vec::new();
    output.extend_from_slice(&(arguments.len() as u32).to_le_bytes());
    for argument in arguments {
        let wide = argument.encode_wide().collect::<Vec<_>>();
        output.extend_from_slice(&(wide.len() as u32).to_le_bytes());
        for unit in wide { output.extend_from_slice(&unit.to_le_bytes()); }
    }
    std::fs::write(std::env::var_os("SEMBAZURU_ARGV_OUTPUT").unwrap(), output).unwrap();
}
"#,
        )
        .unwrap();
        let build = std::process::Command::new("rustc")
            .arg(&helper_source)
            .arg("-o")
            .arg(&helper)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "helper build failed: stdout={}; stderr={}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        std::fs::write(&script, "@echo off\r\n\"%~dp0helper.exe\" %*\r\n").unwrap();
        let arguments = vec![
            "".into(),
            "space value".into(),
            format!("a&echo PWNED>{}", sentinel.display()),
            format!("left|echo PWNED>{}", sentinel.display()),
            "angle>value<input".into(),
            "(parentheses)".into(),
            "%PATH%".into(),
            "!PATH!".into(),
            format!("x\" & echo PWNED > {} & \"y", sentinel.display()),
            "ends\\".into(),
            "caret^value".into(),
            "鶴".into(),
        ];
        let std_run = std::process::Command::new(&script)
            .args(&arguments)
            .current_dir(&cwd)
            .env("SEMBAZURU_ARGV_OUTPUT", &std_output)
            .output()
            .unwrap();
        assert!(
            std_run.status.success(),
            "std batch oracle failed: stdout={}; stderr={}",
            String::from_utf8_lossy(&std_run.stdout),
            String::from_utf8_lossy(&std_run.stderr)
        );
        let mut environment = std::collections::HashMap::new();
        environment.insert(
            "SEMBAZURU_ARGV_OUTPUT".into(),
            caller_output.to_string_lossy().into_owned(),
        );
        let command = Command {
            argv: std::iter::once(script.to_string_lossy().into_owned())
                .chain(arguments.iter().cloned())
                .collect(),
            env: environment,
            cwd: cwd.to_string_lossy().into_owned(),
        };
        let identity = crate::intake_pipe::CallerIdentity::restricted_current_for_test().unwrap();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let exit_code = with_submission_deadline(Arc::clone(&deadline), async {
            run_local_with_context(
                &command,
                &LocalExecutionContext::AuthenticatedCaller(identity),
            )
            .await
        })
        .await
        .unwrap();
        assert_eq!(exit_code, 0);
        let expected = expected_binary(&arguments);
        let std_actual = std::fs::read(&std_output).unwrap();
        let caller_actual = std::fs::read(&caller_output).unwrap();
        assert_eq!(std_actual, expected, "std batch argv did not round-trip");
        assert_eq!(
            caller_actual, expected,
            "caller batch argv did not round-trip"
        );
        assert_eq!(caller_actual, std_actual);
        assert!(
            !sentinel.exists(),
            "cmd metacharacters escaped the argument"
        );
        std::fs::remove_dir_all(cwd).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn caller_token_spawn_failure_never_retries_with_daemon_token() {
        let output = unique_job_output("caller-spawn-failure");
        let mut command = Command {
            argv: vec![
                "cmd.exe".into(),
                "/D".into(),
                "/C".into(),
                format!("echo retry>{}", output.display()),
            ],
            env: Default::default(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        };
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.install(23);
        let identity = crate::intake_pipe::CallerIdentity::restricted_current_for_test().unwrap();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let result = with_submission_deadline(Arc::clone(&deadline), async {
            run_local_with_context(
                &command,
                &LocalExecutionContext::AuthenticatedCaller(identity),
            )
            .await
        })
        .await;

        assert!(result.is_err());
        assert!(
            !output.exists(),
            "ambient-token retry executed the sentinel"
        );
        assert_eq!(control.take_last_consumed_failpoint(), 23);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::RetrySafeReaped
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_as_caller_is_assigned_before_resume() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = unique_job_output("authenticated-caller");
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.observe_job();
        let identity = crate::intake_pipe::CallerIdentity::restricted_current_for_test().unwrap();
        let expected_sid = identity.sid.clone();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local_with_context(
                &command,
                &LocalExecutionContext::AuthenticatedCaller(identity),
            )
            .await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        let job = control.take_observed_job_handle();
        assert_ne!(job, 0);
        for peer in &peers {
            assert_eq!(
                crate::intake_pipe::process_sid_for_test(peer.pid).unwrap(),
                expected_sid
            );
            assert!(local_job::process_is_in_job_for_test(peer.pid, job).unwrap());
        }
        for peer in &mut peers {
            use std::io::Write;
            peer.socket.write_all(&[1]).unwrap();
        }
        assert_eq!(run.await.unwrap().unwrap(), 0);
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(job as _);
        }
        let _ = std::fs::remove_file(output);
    }

    #[cfg(windows)]
    fn break_process_stderr() {
        use std::ffi::c_void;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

        const STD_ERROR_HANDLE: u32 = -12_i32 as u32;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreatePipe(
                read_pipe: *mut HANDLE,
                write_pipe: *mut HANDLE,
                pipe_attributes: *const c_void,
                size: u32,
            ) -> i32;
            fn GetStdHandle(n_std_handle: u32) -> HANDLE;
            fn SetStdHandle(n_std_handle: u32, handle: HANDLE) -> i32;
        }

        unsafe {
            let previous = GetStdHandle(STD_ERROR_HANDLE);
            let mut read_pipe = std::ptr::null_mut();
            let mut write_pipe = std::ptr::null_mut();
            assert_ne!(
                CreatePipe(&mut read_pipe, &mut write_pipe, std::ptr::null(), 0),
                0,
                "could not create broken stderr pipe"
            );
            assert_ne!(CloseHandle(read_pipe), 0, "could not break stderr pipe");
            assert_ne!(
                SetStdHandle(STD_ERROR_HANDLE, write_pipe),
                0,
                "could not install broken child-process stderr"
            );
            if !previous.is_null() && previous != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(previous);
            }
        }
    }

    #[cfg(windows)]
    fn assert_observed_job_kill_on_close(control: &local_job::TestGuardianControl, expected: bool) {
        use std::ffi::c_void;
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
        };

        let job = control.take_observed_job_handle();
        assert_ne!(job, 0, "observed Job handle was zero; expected nonzero");
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        let queried = unsafe {
            QueryInformationJobObject(
                job as _,
                JobObjectExtendedLimitInformation,
                &mut limits as *mut _ as *mut c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            queried, 0,
            "broken-stderr quarantine closed its retained Job owner"
        );
        let actual =
            limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0;
        assert_eq!(actual, expected);
        unsafe {
            let _ = CloseHandle(job as _);
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore]
    async fn local_job_broken_stderr_fixture() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let scenario = std::env::var("SEMBAZURU_BROKEN_STDERR_SCENARIO").unwrap();
        match scenario.as_str() {
            "forced" => {
                let quarantines_before = local_job::quarantine_count();
                break_process_stderr();
                let (result, phase, peers, control) =
                    force_fixture_with_failpoint(12, true, &[]).await;
                assert!(
                    result.is_err(),
                    "forced result was {result:?}; expected Err"
                );
                assert_eq!(
                    phase,
                    session_registry::SubmissionPhase::ForceFailed,
                    "forced phase mismatch"
                );
                let quarantine_actual = local_job::quarantine_count();
                let quarantine_expected = quarantines_before + 1;
                assert_eq!(quarantine_actual, quarantine_expected);
                assert_eq!(control.job_owner_close_count(), 0);
                assert_observed_job_kill_on_close(&control, true);
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !peers.iter().all(LocalJobFixturePeer::is_signaled) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("forced peer processes did not become signaled");
                let peer_signals = peers
                    .iter()
                    .map(|peer| (peer.role, peer.pid, peer.is_signaled()))
                    .collect::<Vec<_>>();
                assert!(
                    peer_signals.iter().all(|(_, _, signaled)| *signaled),
                    "forced peer signals were {peer_signals:?}; expected all true"
                );
            }
            "natural" => {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let output = std::env::temp_dir().join(format!(
                    "sembazuru-job-broken-stderr-natural-{}-{}.txt",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                let mut command = fixture_command(listener.local_addr().unwrap(), &output);
                command
                    .env
                    .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
                let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
                control.observe_job();
                let deadline = Arc::new(session_registry::SubmissionDeadline::new());
                let run_deadline = Arc::clone(&deadline);
                let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
                    run_local(&command).await
                }));
                let mut peers = accept_local_job_fixture(listener).await;
                let quarantines_before = local_job::quarantine_count();
                break_process_stderr();
                control.install(16);
                peers
                    .iter_mut()
                    .find(|peer| peer.role == 1)
                    .unwrap()
                    .socket
                    .write_all(&[1])
                    .unwrap();

                assert_eq!(run.await.unwrap().unwrap(), 0);
                assert_eq!(
                    deadline.phase(),
                    session_registry::SubmissionPhase::NaturalReaped
                );
                assert_eq!(local_job::quarantine_count(), quarantines_before + 1);
                assert_eq!(control.job_owner_close_count(), 0);
                assert_observed_job_kill_on_close(&control, false);
                let child = peers.iter_mut().find(|peer| peer.role == 0).unwrap();
                assert!(!child.is_signaled());
                child.socket.write_all(&[1]).unwrap();
                tokio::time::timeout(Duration::from_secs(1), async {
                    while !child.is_signaled() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                let _ = std::fs::remove_file(output);
            }
            other => panic!("unexpected broken-stderr scenario {other}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn local_job_broken_stderr_cannot_interrupt_quarantine() {
        for scenario in ["forced", "natural"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "tests::local_job_broken_stderr_fixture",
                    "--nocapture",
                ])
                .env("SEMBAZURU_BROKEN_STDERR_SCENARIO", scenario)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "broken-stderr {scenario} fixture failed with {status}: stdout={stdout}; stderr={stderr}",
                status = output.status,
                stdout = String::from_utf8_lossy(&output.stdout),
                stderr = String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore]
    fn local_job_child_fixture() {
        use std::io::{Read, Write};

        let Ok(mode) = std::env::var("SEMBAZURU_JOB_FIXTURE_MODE") else {
            return;
        };
        assert!(
            std::env::vars_os().all(|(key, _)| !key
                .to_string_lossy()
                .eq_ignore_ascii_case(local_job::TEST_CONTROL_MARKER)),
            "test guardian control marker leaked into fixture child"
        );
        let addr = std::env::var("SEMBAZURU_JOB_FIXTURE_ADDR").unwrap();
        let mut grandchild = if mode == "parent" {
            Some(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "tests::local_job_child_fixture",
                        "--nocapture",
                    ])
                    .env("SEMBAZURU_JOB_FIXTURE_MODE", "child")
                    .env("SEMBAZURU_JOB_FIXTURE_ADDR", &addr)
                    .env(
                        "SEMBAZURU_JOB_FIXTURE_OUTPUT",
                        std::env::var("SEMBAZURU_JOB_FIXTURE_OUTPUT").unwrap(),
                    )
                    .spawn()
                    .unwrap(),
            )
        } else {
            None
        };
        if mode == "parent" && std::env::var_os("SEMBAZURU_JOB_FIXTURE_STRESS").is_some() {
            for _ in 0..32 {
                assert!(
                    std::process::Command::new("cmd.exe")
                        .args(["/D", "/C", "exit", "0"])
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
        let nested_job = if mode == "parent"
            && std::env::var_os("SEMBAZURU_JOB_FIXTURE_NESTED").is_some()
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW,
            };

            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            assert!(!job.is_null(), "nested CreateJobObjectW failed");
            assert_ne!(
                unsafe {
                    AssignProcessToJobObject(job, grandchild.as_ref().unwrap().as_raw_handle() as _)
                },
                0,
                "nested AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            );
            Some(job)
        } else {
            None
        };
        let mut socket = std::net::TcpStream::connect(&addr).unwrap();
        let role = u8::from(mode == "parent");
        let mut hello = [0_u8; 5];
        hello[0] = role;
        hello[1..].copy_from_slice(&std::process::id().to_be_bytes());
        socket.write_all(&hello).unwrap();
        let mut release = [0_u8; 1];
        socket.read_exact(&mut release).unwrap();
        let mut late_child = None;
        if mode == "parent" && release[0] == 2 {
            late_child = Some(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "tests::local_job_child_fixture",
                        "--nocapture",
                    ])
                    .env("SEMBAZURU_JOB_FIXTURE_MODE", "child")
                    .env("SEMBAZURU_JOB_FIXTURE_ADDR", &addr)
                    .env(
                        "SEMBAZURU_JOB_FIXTURE_OUTPUT",
                        std::env::var("SEMBAZURU_JOB_FIXTURE_OUTPUT").unwrap(),
                    )
                    .spawn()
                    .unwrap(),
            );
            socket.read_exact(&mut release).unwrap();
        }
        if let Some(child) = &mut grandchild {
            let detached = std::env::var_os("SEMBAZURU_JOB_FIXTURE_DETACH").is_some();
            if !detached {
                child.wait().unwrap();
                if let Some(late_child) = &mut late_child {
                    late_child.wait().unwrap();
                }
            }
            std::fs::write(
                std::env::var("SEMBAZURU_JOB_FIXTURE_OUTPUT").unwrap(),
                b"completed\n",
            )
            .unwrap();
        }
        if let Some(job) = nested_job {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(job);
            }
        }
    }

    #[cfg(windows)]
    fn fixture_command(addr: std::net::SocketAddr, output: &std::path::Path) -> Command {
        Command {
            argv: vec![
                std::env::current_exe()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                "--ignored".into(),
                "--exact".into(),
                "tests::local_job_child_fixture".into(),
                "--nocapture".into(),
            ],
            env: [
                ("SEMBAZURU_JOB_FIXTURE_MODE".into(), "parent".into()),
                ("SEMBAZURU_JOB_FIXTURE_ADDR".into(), addr.to_string()),
                (
                    "SEMBAZURU_JOB_FIXTURE_OUTPUT".into(),
                    output.to_string_lossy().into_owned(),
                ),
            ]
            .into_iter()
            .collect(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        }
    }

    #[cfg(windows)]
    fn unique_job_output(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sembazuru-job-{label}-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(windows)]
    #[test]
    fn local_job_test_control_rejects_invalid_markers() {
        fn command_with_marker(key: &str, value: &str) -> Command {
            Command {
                argv: vec!["cmd".into(), "/D".into(), "/C".into(), "exit 0".into()],
                env: [(key.to_owned(), value.to_owned())].into_iter().collect(),
                cwd: std::env::temp_dir().to_string_lossy().into_owned(),
            }
        }

        for value in ["0", "not-decimal"] {
            let command = command_with_marker(local_job::TEST_CONTROL_MARKER, value);
            assert!(local_job::resolve_test_control(&command).is_err());
        }

        let mut duplicate = command_with_marker(local_job::TEST_CONTROL_MARKER, "1");
        duplicate.env.insert(
            local_job::TEST_CONTROL_MARKER.to_ascii_lowercase(),
            "2".into(),
        );
        assert!(local_job::resolve_test_control(&duplicate).is_err());

        let mut collision =
            command_with_marker(&local_job::TEST_CONTROL_MARKER.to_ascii_lowercase(), "1");
        assert!(local_job::TestGuardianControl::bind(&mut collision).is_err());

        let mut stale = Command {
            argv: vec!["cmd".into(), "/D".into(), "/C".into(), "exit 0".into()],
            env: Default::default(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        };
        let control = local_job::TestGuardianControl::bind(&mut stale).unwrap();
        drop(control);
        assert!(local_job::resolve_test_control(&stale).is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_test_control_requires_submission_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let output = unique_job_output("missing-deadline");
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();

        let error = run_local(&command).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(control.take_run_local_deadline_state(), 1);
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(!output.exists());
    }

    #[cfg(windows)]
    async fn force_fixture_with_failpoint(
        point: u8,
        install_before_run: bool,
        extra_env: &[(&str, &str)],
    ) -> (
        std::io::Result<i32>,
        session_registry::SubmissionPhase,
        Vec<LocalJobFixturePeer>,
        local_job::TestGuardianControl,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-iocp-{point}-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        for (key, value) in extra_env {
            command.env.insert((*key).into(), (*value).into());
        }
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.observe_job();
        if install_before_run {
            control.install(point);
        }
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let peers = accept_local_job_fixture(listener).await;
        if !install_before_run {
            control.install(point);
        }
        if install_before_run && point == 12 {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match control.take_last_consumed_failpoint() {
                        0 => tokio::task::yield_now().await,
                        12 => break,
                        unexpected => panic!(
                            "monitor consumed unexpected failpoint {unexpected}; expected 12"
                        ),
                    }
                }
            })
            .await
            .expect("monitor did not consume failpoint 12 before force");
        }
        deadline.request_force();
        let result = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("forced fixture did not reach a terminal")
            .unwrap();
        (result, deadline.phase(), peers, control)
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_top_new_drop_is_covered_by_verified_seed() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (result, phase, peers, control) = force_fixture_with_failpoint(9, true, &[]).await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(phase, session_registry::SubmissionPhase::ForcedReaped);
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
        let (_, unique, total) = control.take_last_audit_counts();
        assert_eq!(unique, total);
        assert_eq!(total, 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_dropped_descendant_new_fails_closed() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (result, phase, peers, _control) = force_fixture_with_failpoint(10, true, &[]).await;
        assert!(result.is_err());
        assert_eq!(phase, session_registry::SubmissionPhase::ForceFailed);
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_delayed_descendant_new_blocks_terminal_until_caught_up() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-delay-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.install(11);
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let mut run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let peers = accept_local_job_fixture(listener).await;
        deadline.request_force();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut run)
                .await
                .is_err(),
            "terminal escaped while a NEW_PROCESS packet was delayed"
        );
        control.release_delayed_new();
        assert_eq!(
            run.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::ForcedReaped
        );
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_late_grandchild_before_terminate_is_retained_and_waited() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let late_listener = listener.try_clone().unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-late-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        control.install(20);
        deadline.request_force();
        control.wait_before_terminate_reached().await;
        peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[2])
            .unwrap();
        let mut late = accept_local_job_fixture_count(late_listener, 1).await;
        control.release_before_terminate();
        assert_eq!(
            run.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        peers.append(&mut late);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::ForcedReaped
        );
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
        let (_, unique, total) = control.take_last_audit_counts();
        assert_eq!(unique, total);
        assert_eq!(total, 3);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_monitor_and_audit_failures_are_fail_closed() {
        use std::ffi::c_void;
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
        };

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        for (point, before) in [
            (12, true),
            (13, false),
            (14, false),
            (15, false),
            (16, false),
            (17, true),
            (18, false),
            (19, true),
        ] {
            let quarantines_before = local_job::quarantine_count();
            let (result, phase, peers, control) =
                force_fixture_with_failpoint(point, before, &[]).await;
            assert!(result.is_err(), "failpoint {point} unexpectedly succeeded");
            assert_eq!(
                phase,
                session_registry::SubmissionPhase::ForceFailed,
                "failpoint {point} did not fail closed"
            );
            assert_eq!(
                local_job::quarantine_count(),
                quarantines_before + 1,
                "failpoint {point} did not quarantine exactly one owner bundle"
            );
            assert_eq!(
                control.job_owner_close_count(),
                0,
                "failpoint {point} closed the quarantined Job owner"
            );
            let job = control.take_observed_job_handle();
            assert_ne!(job, 0, "failpoint {point} did not expose its Job");
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            assert_ne!(
                unsafe {
                    QueryInformationJobObject(
                        job as _,
                        JobObjectExtendedLimitInformation,
                        &mut limits as *mut _ as *mut c_void,
                        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                        std::ptr::null_mut(),
                    )
                },
                0,
                "failpoint {point} closed the quarantined Job handle"
            );
            assert_ne!(
                limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                0,
                "failpoint {point} disarmed KILL_ON_JOB_CLOSE before quarantine"
            );
            unsafe {
                let _ = CloseHandle(job as _);
            }
            drop(peers);
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_natural_empty_failure_quarantines_live_detached_descendant() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-natural-empty-failed-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.observe_job();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let quarantines_before = local_job::quarantine_count();
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        control.install(22);
        peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[1])
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("natural-empty failure remained unobservably Terminating")
            .unwrap();
        assert!(result.is_err());
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::ForceFailed
        );
        assert_eq!(local_job::quarantine_count(), quarantines_before + 1);
        assert_eq!(control.job_owner_close_count(), 0);
        assert!(
            peers
                .iter()
                .find(|peer| peer.role == 1)
                .unwrap()
                .is_signaled()
        );
        let child = peers.iter_mut().find(|peer| peer.role == 0).unwrap();
        assert!(
            !child.is_signaled(),
            "natural-empty ForceFailed waited for the detached descendant"
        );
        child.socket.write_all(&[1]).unwrap();
        let job = control.take_observed_job_handle();
        assert_ne!(job, 0);
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(job as _);
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_gone_and_foreign_pid_packets_are_confirmed_gone() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (unique, gone) = local_job::classify_gone_and_foreign_packets().unwrap();
        assert_eq!(unique, 2);
        assert_eq!(gone, 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_gone_duplicate_packets_do_not_overcount_unique_occurrences() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (seeded_top_unique, repeated_non_top_unique, repeated_foreign_unique) =
            local_job::classify_duplicate_gone_packets().unwrap();
        assert_eq!(seeded_top_unique, 1);
        assert_eq!(repeated_non_top_unique, 1);
        assert_eq!(repeated_foreign_unique, 1);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_short_lived_child_stress_preserves_complete_count() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (result, phase, peers, control) =
            force_fixture_with_failpoint(0, false, &[("SEMBAZURU_JOB_FIXTURE_STRESS", "1")]).await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(phase, session_registry::SubmissionPhase::ForcedReaped);
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
        let (raw, unique, total) = control.take_last_audit_counts();
        assert_eq!(unique, total);
        assert!(total >= 34, "stress Job only accounted {total} processes");
        assert!(raw >= unique.saturating_sub(1));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_nested_member_is_seen_by_parent_iocp_and_accounting() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (result, phase, peers, control) =
            force_fixture_with_failpoint(0, false, &[("SEMBAZURU_JOB_FIXTURE_NESTED", "1")]).await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(phase, session_registry::SubmissionPhase::ForcedReaped);
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
        let (raw, unique, total) = control.take_last_audit_counts();
        assert_eq!(unique, total);
        assert_eq!(total, 2);
        assert!(
            raw >= unique,
            "parent IOCP did not receive nested NEW packets"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_nested_duplicate_packet_changes_raw_not_unique_count() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let (result, phase, peers, control) =
            force_fixture_with_failpoint(21, true, &[("SEMBAZURU_JOB_FIXTURE_NESTED", "1")]).await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(phase, session_registry::SubmissionPhase::ForcedReaped);
        assert!(peers.iter().all(LocalJobFixturePeer::is_signaled));
        let (raw, unique, total) = control.take_last_audit_counts();
        assert_eq!(unique, total);
        assert_eq!(total, 2);
        assert!(
            raw > unique,
            "duplicate packet incorrectly changed unique count"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_pre_spawn_iocp_setup_failures_are_retry_safe() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        for failpoint in 5..=8 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let output = std::env::temp_dir().join(format!(
                "sembazuru-job-pre-spawn-{failpoint}-{}.txt",
                std::process::id()
            ));
            let mut command = fixture_command(listener.local_addr().unwrap(), &output);
            let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
            let deadline = Arc::new(session_registry::SubmissionDeadline::new());
            control.install(failpoint);
            let result = with_submission_deadline(Arc::clone(&deadline), async {
                run_local(&command).await
            })
            .await;
            assert!(result.is_err());
            assert_eq!(
                deadline.phase(),
                session_registry::SubmissionPhase::RetrySafeReaped
            );
            assert!(matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_force_reaps_parent_and_grandchild_before_return() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-force-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = fixture_command(listener.local_addr().unwrap(), &output);
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let peers = accept_local_job_fixture(listener).await;
        deadline.request_force();
        let result = run.await.unwrap();

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::ForcedReaped
        );
        for peer in &peers {
            peer.assert_signaled();
        }
        assert!(!output.exists(), "forced tree wrote output before release");
        drop(peers);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_fixture_members_are_in_the_guardian_job() {
        use std::ffi::c_void;
        use std::mem::{size_of, zeroed};
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetHandleInformation, HANDLE_FLAG_INHERIT,
        };
        use windows_sys::Win32::System::JobObjects::{
            IsProcessInJob, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            QueryInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let mut runner_in_job = 0;
        assert_ne!(
            unsafe { IsProcessInJob(GetCurrentProcess(), null_mut(), &mut runner_in_job) },
            0
        );
        let runner_limits = if runner_in_job != 0 {
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            let ok = unsafe {
                QueryInformationJobObject(
                    null_mut(),
                    JobObjectExtendedLimitInformation,
                    &mut limits as *mut _ as *mut c_void,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    null_mut(),
                )
            };
            assert_ne!(ok, 0, "could not query test runner Job limits");
            Some(limits.BasicLimitInformation.LimitFlags)
        } else {
            None
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-membership-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.observe_job();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let peers = accept_local_job_fixture(listener).await;
        let job = control.take_observed_job_handle();
        assert_ne!(job, 0, "guardian Job handle was not observed");
        drop(control);
        let mut handle_flags = 0_u32;
        assert_ne!(
            unsafe { GetHandleInformation(job as _, &mut handle_flags) },
            0,
            "could not query guardian Job handle flags"
        );
        assert_eq!(
            handle_flags & HANDLE_FLAG_INHERIT,
            0,
            "guardian Job handle was inheritable"
        );
        let membership: Vec<_> = peers
            .iter()
            .map(|peer| (peer.role, peer.pid, peer.is_in_job(job).unwrap()))
            .collect();
        deadline.request_force();
        let result = run.await.unwrap();
        unsafe {
            let _ = CloseHandle(job as _);
        }

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert!(
            runner_limits.is_none_or(|flags| flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK == 0),
            "test runner ancestor Job enables SILENT_BREAKAWAY_OK: {runner_limits:?}"
        );
        assert!(
            membership.iter().all(|(_, _, contained)| *contained),
            "fixture membership in guardian Job: {membership:?}; runner limits: {runner_limits:?}"
        );
        drop(peers);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_natural_completion_preserves_exit_and_output() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-natural-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = fixture_command(listener.local_addr().unwrap(), &output);
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        for peer in &mut peers {
            peer.socket.write_all(&[1]).unwrap();
        }
        let exit = run.await.unwrap().unwrap();

        assert_eq!(exit, 0);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::NaturalReaped
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"completed\n");
        for peer in &peers {
            peer.assert_signaled();
        }
        let _ = std::fs::remove_file(output);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_successful_disarm_preserves_live_detached_descendant() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-detached-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[1])
            .unwrap();
        assert_eq!(run.await.unwrap().unwrap(), 0);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::NaturalReaped
        );
        assert!(
            peers
                .iter()
                .find(|peer| peer.role == 1)
                .unwrap()
                .is_signaled()
        );
        let child = peers.iter_mut().find(|peer| peer.role == 0).unwrap();
        assert!(
            !child.is_signaled(),
            "successful disarm killed the detached descendant"
        );
        child.socket.write_all(&[1]).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !child.is_signaled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached descendant did not exit after release");
        let _ = std::fs::remove_file(output);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_disarm_commits_natural_exit_before_monitor_stop_failure() {
        use std::ffi::c_void;
        use std::io::Write;
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
        };

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-disarm-quarantine-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.observe_job();
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let quarantines_before = local_job::quarantine_count();
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        control.install(16);
        peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[1])
            .unwrap();

        assert_eq!(run.await.unwrap().unwrap(), 0);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::NaturalReaped
        );
        assert_eq!(local_job::quarantine_count(), quarantines_before + 1);
        assert_eq!(control.job_owner_close_count(), 0);
        assert_eq!(std::fs::read(&output).unwrap(), b"completed\n");
        assert!(
            peers
                .iter()
                .find(|peer| peer.role == 1)
                .unwrap()
                .is_signaled()
        );
        let child = peers.iter_mut().find(|peer| peer.role == 0).unwrap();
        assert!(
            !child.is_signaled(),
            "committed natural completion killed the detached descendant"
        );

        let job = control.take_observed_job_handle();
        assert_ne!(job, 0);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        assert_ne!(
            unsafe {
                QueryInformationJobObject(
                    job as _,
                    JobObjectExtendedLimitInformation,
                    &mut limits as *mut _ as *mut c_void,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            0,
            "natural cleanup failure re-armed KILL_ON_JOB_CLOSE"
        );

        child.socket.write_all(&[1]).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !child.is_signaled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached descendant did not exit after release");
        unsafe {
            let _ = CloseHandle(job as _);
        }
        let _ = std::fs::remove_file(output);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_future_abort_reaps_tree_before_retry_safe_terminal() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-abort-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = fixture_command(listener.local_addr().unwrap(), &output);
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let peers = accept_local_job_fixture(listener).await;
        run.abort();
        assert!(run.await.unwrap_err().is_cancelled());
        assert_eq!(
            deadline.wait_terminal().await,
            session_registry::SubmissionPhase::ForcedReaped
        );
        for peer in &peers {
            peer.assert_signaled();
        }
        assert!(!output.exists(), "aborted tree wrote output before release");
        drop(peers);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_setup_failpoints_reap_suspended_child_without_starting_it() {
        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        for failpoint in 1..=3 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let output = std::env::temp_dir().join(format!(
                "sembazuru-job-setup-{failpoint}-{}-{}.txt",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut command = fixture_command(listener.local_addr().unwrap(), &output);
            let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
            let deadline = Arc::new(session_registry::SubmissionDeadline::new());
            control.install(failpoint);
            let result = with_submission_deadline(Arc::clone(&deadline), async {
                run_local(&command).await
            })
            .await;

            assert!(result.is_err(), "failpoint {failpoint} unexpectedly ran");
            assert_eq!(
                deadline.phase(),
                session_registry::SubmissionPhase::RetrySafeReaped
            );
            let process = control.take_last_child_handle();
            assert_ne!(process, 0, "setup failpoint did not retain a live handle");
            unsafe {
                use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
                use windows_sys::Win32::System::Threading::WaitForSingleObject;

                assert_eq!(WaitForSingleObject(process as _, 0), WAIT_OBJECT_0);
                let _ = CloseHandle(process as _);
            }
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "suspended child reached user code at failpoint {failpoint}"
            );
            assert!(!output.exists());
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_failpoint_is_bound_to_target_guardian() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let target_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target_output = unique_job_output("failpoint-target");
        let mut target_command =
            fixture_command(target_listener.local_addr().unwrap(), &target_output);
        target_command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let target_control = local_job::TestGuardianControl::bind(&mut target_command).unwrap();
        target_control.install(4);
        target_control.observe_job();
        let target_deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let target_run_deadline = Arc::clone(&target_deadline);
        let mut target_run =
            tokio::spawn(with_submission_deadline(target_run_deadline, async move {
                run_local(&target_command).await
            }));
        let mut target_peers = accept_local_job_fixture(target_listener).await;

        let decoy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let decoy_output = unique_job_output("failpoint-decoy");
        let decoy_command = fixture_command(decoy_listener.local_addr().unwrap(), &decoy_output);
        let decoy_deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let decoy_run_deadline = Arc::clone(&decoy_deadline);
        let decoy_run = tokio::spawn(with_submission_deadline(decoy_run_deadline, async move {
            run_local(&decoy_command).await
        }));
        let mut decoy_peers = accept_local_job_fixture(decoy_listener).await;
        for peer in &mut decoy_peers {
            peer.socket.write_all(&[1]).unwrap();
        }
        assert_eq!(decoy_run.await.unwrap().unwrap(), 0);
        assert_eq!(
            decoy_deadline.phase(),
            session_registry::SubmissionPhase::NaturalReaped
        );

        target_peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[1])
            .unwrap();
        if let Ok(joined) = tokio::time::timeout(Duration::from_millis(100), &mut target_run).await
        {
            target_peers
                .iter_mut()
                .find(|peer| peer.role == 0)
                .unwrap()
                .socket
                .write_all(&[1])
                .unwrap();
            panic!("unrelated guardian consumed the targeted disarm failpoint: {joined:?}");
        }
        assert!(
            !target_peers
                .iter()
                .find(|peer| peer.role == 0)
                .unwrap()
                .is_signaled()
        );

        target_deadline.request_force();
        assert_eq!(
            target_run.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        assert_eq!(
            target_deadline.phase(),
            session_registry::SubmissionPhase::ForcedReaped
        );
        assert!(target_peers.iter().all(LocalJobFixturePeer::is_signaled));
        assert_eq!(target_control.take_last_consumed_failpoint(), 4);
        assert_eq!(target_control.take_run_local_deadline_state(), 2);
        let (_, unique, total) = target_control.take_last_audit_counts();
        assert_eq!((unique, total), (2, 2));
        assert_eq!(target_control.take_natural_publish_branch(), 0);
        let observed_job = target_control.take_observed_job_handle();
        assert_ne!(observed_job, 0);
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(observed_job as _);
        }
        let _ = std::fs::remove_file(target_output);
        let _ = std::fs::remove_file(decoy_output);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_disarm_failure_holds_exit_until_detached_descendant_exits() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-disarm-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.install(4);
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let mut run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        let parent = peers.iter_mut().find(|peer| peer.role == 1).unwrap();
        parent.socket.write_all(&[1]).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut run)
                .await
                .is_err(),
            "real Exit escaped while a detached Job descendant was active"
        );
        assert!(parent.is_signaled());
        let child = peers.iter_mut().find(|peer| peer.role == 0).unwrap();
        assert!(!child.is_signaled());
        child.socket.write_all(&[1]).unwrap();

        assert_eq!(run.await.unwrap().unwrap(), 0);
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::NaturalReaped
        );
        for peer in &peers {
            peer.assert_signaled();
        }
        assert_eq!(std::fs::read(&output).unwrap(), b"completed\n");
        let _ = std::fs::remove_file(output);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn local_job_disarm_wait_observes_force_and_reaps_detached_descendant() {
        use std::io::Write;

        let _guard = LOCAL_JOB_TEST_LOCK.lock().await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-job-disarm-force-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = fixture_command(listener.local_addr().unwrap(), &output);
        command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let control = local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.install(4);
        let deadline = Arc::new(session_registry::SubmissionDeadline::new());
        let run_deadline = Arc::clone(&deadline);
        let mut run = tokio::spawn(with_submission_deadline(run_deadline, async move {
            run_local(&command).await
        }));
        let mut peers = accept_local_job_fixture(listener).await;
        peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[1])
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut run)
                .await
                .is_err(),
            "disarm failure did not hold while the descendant was active"
        );
        deadline.request_force();
        let forced = tokio::time::timeout(Duration::from_millis(250), &mut run).await;
        let joined = match forced {
            Ok(joined) => joined,
            Err(_) => {
                peers
                    .iter_mut()
                    .find(|peer| peer.role == 0)
                    .unwrap()
                    .socket
                    .write_all(&[1])
                    .unwrap();
                let _ = run.await;
                panic!("sticky force was not observed during disarm-failure wait");
            }
        };

        assert_eq!(
            joined.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        assert_eq!(
            deadline.phase(),
            session_registry::SubmissionPhase::ForcedReaped
        );
        for peer in &peers {
            peer.assert_signaled();
        }
        drop(peers);
        let _ = std::fs::remove_file(output);
    }

    #[test]
    fn console_buffer_is_capped_at_the_limit() {
        // RES-001: a flood far exceeding the cap is bounded (no unbounded growth),
        // and a one-time truncation notice is appended.
        let mut buf = Vec::new();
        let flood = vec![b'x'; MAX_CONSOLE_BYTES * 2];
        append_console_capped(&mut buf, &flood);
        assert!(
            buf.len() <= MAX_CONSOLE_BYTES + CONSOLE_TRUNCATION_NOTICE.len(),
            "buffer is bounded by the cap (+ the notice): {}",
            buf.len()
        );
        assert!(
            buf.ends_with(CONSOLE_TRUNCATION_NOTICE),
            "an overflowing chunk appends the truncation notice"
        );
        // An already-capped buffer never grows further (further chunks dropped).
        let after_cap = buf.len();
        append_console_capped(&mut buf, b"more output");
        assert_eq!(buf.len(), after_cap, "a capped buffer does not grow");
    }

    #[test]
    fn console_buffer_keeps_small_output_verbatim() {
        // Normal-sized output is kept exactly, with no notice (the common case).
        let mut buf = Vec::new();
        append_console_capped(&mut buf, b"a.cpp(1): warning C4101\n");
        append_console_capped(&mut buf, b"a.cpp(2): note\n");
        assert_eq!(buf, b"a.cpp(1): warning C4101\na.cpp(2): note\n");
        assert!(!buf.ends_with(CONSOLE_TRUNCATION_NOTICE));
    }
}
