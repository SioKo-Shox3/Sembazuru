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
    let mut last: Option<tonic::transport::Error> = None;
    for _ in 0..20 {
        match ExecutionClient::connect(endpoint.clone()).await {
            Ok(c) => return Ok(c),
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
