//! Sembazuru local agent: owns the build session — schedules actions, will serve
//! the local filesystem to workers (M3.2), receives outputs (M3.3), and falls
//! back to local execution when remote fails (M3.4).
//!
//! **M3.1 scope — loopback Execute client.** This drives one remote action over
//! the `Execution` control plane (`docs/protocol/v0.md` §3.2): connect, send
//! `ExecuteRequest`, consume the `ExecuteEvent` stream, and report the outcome.

use std::time::Duration;

use sembazuru_proto::v0::{
    Command, ExecuteRequest, execute_event::Event, execution_client::ExecutionClient,
};

pub mod action_cache;
pub mod fileserver;

/// What a remote action reported back: the lifecycle states it passed through
/// (raw `ActionState` discriminants, in order) and, if it ran to completion,
/// the process exit code and worker-measured wall time.
#[derive(Debug, Default, Clone)]
pub struct ActionOutcome {
    pub states: Vec<i32>,
    pub exit_code: Option<i32>,
    pub wall_time_us: u64,
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

/// Connects to a worker's `Execution` endpoint, retrying briefly so a
/// just-spawned worker (loopback) has time to start listening. Readiness is
/// established by a successful connect rather than a separate probe — M3.1 has
/// no discovery/registration yet (that is the agent-hosted `Coordination`
/// service, implemented later).
async fn connect_with_retry(
    endpoint: String,
) -> Result<ExecutionClient<tonic::transport::Channel>, ExecuteError> {
    // A bounded per-attempt connect timeout so a dead endpoint fails the whole
    // budget in ~1s (fast fallback) instead of hanging on the OS connect.
    let ep = tonic::transport::Endpoint::from_shared(endpoint)
        .map_err(ExecuteError::Transport)?
        .connect_timeout(Duration::from_millis(200));
    let mut last: Option<tonic::transport::Error> = None;
    for _ in 0..20 {
        match ep.connect().await {
            Ok(channel) => return Ok(ExecutionClient::new(channel)),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    Err(ExecuteError::Transport(last.expect("at least one attempt")))
}

/// Runs `command` on the worker at `endpoint` (e.g. `"http://127.0.0.1:50061"`)
/// and returns its outcome once the event stream closes.
pub async fn execute_remote(
    endpoint: String,
    command: Command,
    action_id: String,
    session_id: String,
) -> Result<ActionOutcome, ExecuteError> {
    let mut client = connect_with_retry(endpoint).await?;

    let request = ExecuteRequest {
        action_id,
        command: Some(command),
        session_id,
        predicted_inputs: None, // prefetch manifest is M5
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
