//! Sembazuru local agent: owns the build session — schedules actions, will serve
//! the local filesystem to workers (M3.2), receives outputs (M3.3), and falls
//! back to local execution when remote fails (M3.4).
//!
//! **M3.1 scope — loopback Execute client.** This drives one remote action over
//! the `Execution` control plane (`docs/protocol/v0.md` §3.2): connect, send
//! `ExecuteRequest`, consume the `ExecuteEvent` stream, and report the outcome.

use std::time::Duration;

use sembazuru_proto::v0::{
    Command, ExecuteRequest, VfsExecution, execute_event::Event, execution_client::ExecutionClient,
};

pub mod action_cache;
pub mod coordination;
pub mod env_filter;
pub mod fileserver;
pub mod intake;
pub mod scheduler;

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

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecuteError::Transport(e) => write!(f, "transport: {e}"),
            ExecuteError::Rpc(s) => write!(f, "rpc: {s}"),
        }
    }
}

impl std::error::Error for ExecuteError {}

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
) -> Result<ActionOutcome, ExecuteError> {
    drive_execute(
        ExecutionClient::new(channel),
        command,
        action_id,
        session_id,
        opts,
    )
    .await
}

/// Sends the `ExecuteRequest` and folds its event stream into an [`ActionOutcome`].
async fn drive_execute(
    mut client: ExecutionClient<tonic::transport::Channel>,
    command: Command,
    action_id: String,
    session_id: String,
    opts: ExecOptions,
) -> Result<ActionOutcome, ExecuteError> {
    let request = ExecuteRequest {
        action_id,
        command: Some(command),
        session_id,
        predicted_inputs: None,
        predicted_paths: opts.predicted_paths,
        vfs: opts.vfs,
    };

    let mut stream = client.execute(request).await?.into_inner();
    let mut outcome = ActionOutcome::default();
    while let Some(event) = stream.message().await? {
        match event.event {
            Some(Event::State(s)) => outcome.states.push(s.state),
            Some(Event::Exit(e)) => {
                outcome.exit_code = Some(e.exit_code);
                outcome.wall_time_us = e.wall_time_us;
            }
            Some(Event::Stdio(c)) => {
                // Collect the compiler's console output to replay to the
                // developer (M6.1). Buffered here, re-streamed to the launcher.
                if c.is_stderr {
                    outcome.stderr.extend_from_slice(&c.data);
                } else {
                    outcome.stdout.extend_from_slice(&c.data);
                }
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
    LocalFallback { exit_code: i32, reason: String },
}

/// Runs `command` on the local machine, returning its exit code. This is the
/// fallback path; outputs land where the command writes them (a self-contained
/// local build), so no write-back is involved.
pub async fn run_local(command: &Command) -> std::io::Result<i32> {
    if command.argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "command.argv is empty",
        ));
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
        Ok(_) => "remote action did not complete (no exit status)".to_string(),
        Err(e) => format!("remote execution failed: {e}"),
    };
    let exit_code = run_local(&command).await.unwrap_or(-1);
    Execution::LocalFallback { exit_code, reason }
}
