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

use std::process::Stdio;
use std::time::Instant;

use sembazuru_proto::v0::{
    AbortRequest, AbortResponse, ActionState, Command, ExecuteEvent, ExecuteRequest, ExitStatus,
    StateChange, execute_event::Event, execution_server::Execution,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

/// The worker's gRPC service. Stateless in M3.1.
#[derive(Clone, Default)]
pub struct WorkerService;

fn state_event(state: ActionState, detail: &str) -> Result<ExecuteEvent, Status> {
    Ok(ExecuteEvent {
        event: Some(Event::State(StateChange {
            state: state as i32,
            detail: detail.to_string(),
        })),
    })
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

/// Drives one action to completion, emitting lifecycle events into `tx`.
///
/// A nonzero exit code is a normal result (a compiler legitimately fails a
/// compile) and is reported via `ExitStatus` under a `COMPLETED` state. `FAILED`
/// is reserved for the worker being unable to run the process at all — that
/// distinction is what lets the agent decide whether to fall back (§3.2).
async fn run_action(cmd: Command, tx: mpsc::Sender<Result<ExecuteEvent, Status>>) {
    let _ = tx.send(state_event(ActionState::Queued, "")).await;
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

    let mut command = tokio::process::Command::new(&cmd.argv[0]);
    command.args(&cmd.argv[1..]);
    if !cmd.cwd.is_empty() {
        command.current_dir(&cmd.cwd);
    }
    // Provided env is layered on top of the worker's inherited environment.
    // M3.2+ will make the env exact for remote correctness; loopback inherits.
    for (k, v) in &cmd.env {
        command.env(k, v);
    }
    command.stdin(Stdio::null());

    let start = Instant::now();
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx
                .send(state_event(
                    ActionState::Failed,
                    &format!("spawn failed: {e}"),
                ))
                .await;
            return;
        }
    };
    let _ = tx.send(state_event(ActionState::Running, "")).await;

    match child.wait().await {
        Ok(status) => {
            // On Windows a process always has an exit code; unwrap_or guards the
            // signal-terminated case that does not occur here.
            let code = status.code().unwrap_or(-1);
            // Saturate explicitly rather than let `as u64` wrap; this is the
            // pattern that will be copied for user/kernel time accounting later,
            // where the values are not bounded by a wall clock.
            let wall = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            let _ = tx.send(exit_event(code, wall)).await;
            let _ = tx.send(state_event(ActionState::Completed, "")).await;
        }
        Err(e) => {
            let _ = tx
                .send(state_event(
                    ActionState::Failed,
                    &format!("wait failed: {e}"),
                ))
                .await;
        }
    }
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

        // Bounded channel: the lifecycle producer is slow relative to gRPC, so a
        // small buffer is plenty and bounds memory if the client stalls.
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(run_action(cmd, tx));
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn abort(
        &self,
        _request: Request<AbortRequest>,
    ) -> Result<Response<AbortResponse>, Status> {
        // M3.1: acknowledge only. Real cancellation (kill the child, guarantee
        // no torn output) lands with the fallback work in M3.4.
        Ok(Response::new(AbortResponse { acknowledged: true }))
    }
}

/// Serves the `Execution` service on an already-bound listener. Taking the
/// listener (rather than an address) lets callers bind an ephemeral port and
/// learn it before serving — used by both the binary and the integration test.
pub async fn serve_on_listener(
    listener: TcpListener,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::execution_server::ExecutionServer;

    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(ExecutionServer::new(WorkerService))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}
