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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_proto::v0::{
    ActionState, Command, ExitStatus, StateChange, SubmitActionEvent, SubmitActionRequest,
    local_intake_client::LocalIntakeClient, local_intake_server::LocalIntake,
    submit_action_event::Event,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

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

/// The LocalIntake gRPC service. Wraps the daemon's [`Scheduler`]; every
/// submitted action is dispatched (affinity → least-loaded → local fallback)
/// and its terminal outcome is mirrored back as a [`SubmitActionEvent`] stream.
#[derive(Clone)]
pub struct IntakeService {
    scheduler: Scheduler,
    /// Per-daemon action counter, so each submission gets a unique action_id /
    /// session_id without a clock or RNG (keeps the daemon reproducible).
    seq: Arc<AtomicU64>,
}

impl IntakeService {
    pub fn new(scheduler: Scheduler) -> Self {
        Self {
            scheduler,
            seq: Arc::new(AtomicU64::new(0)),
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

        // A unique id per submission. session_id binds the (future, M6.1) file
        // session; for M6.0 the trivial action needs no file supply, but the id
        // is still distinct so it is ready to key a session.
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let action_id = format!("intake-{n}");
        let session_id = format!("intake-{n}");

        let scheduler = self.scheduler.clone();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            // M6.0: plain dispatch. The action-cache resolve/record and the
            // read-VFS config (ExecOptions) are wired in M6.1c.
            let outcome = scheduler
                .dispatch(command, action_id, session_id, ExecOptions::default())
                .await;
            // dispatch already guarantees completion (remote or local fallback),
            // so we always have an exit code to mirror. The launcher only needs
            // the exit; the state event is for observability / a fallback note.
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
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
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

/// Serves LocalIntake on an already-bound listener (the daemon binds an explicit
/// loopback port; tests bind an ephemeral one and learn it before serving).
pub async fn serve_intake(
    listener: TcpListener,
    scheduler: Scheduler,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sembazuru_proto::v0::local_intake_server::LocalIntakeServer;

    let incoming = TcpListenerStream::new(listener);
    tonic::transport::Server::builder()
        .add_service(LocalIntakeServer::new(IntakeService::new(scheduler)))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

/// Launcher side: submit `command` to the daemon at `endpoint` and return the
/// exit code once the stream closes. A transport/RPC error here is exactly the
/// signal the launcher turns into a local fallback (the daemon may be down) —
/// the build must still complete (DESIGN.md §2).
pub async fn submit_to_daemon(
    endpoint: String,
    command: Command,
    declared_outputs: Vec<String>,
) -> Result<i32, ExecuteError> {
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
    while let Some(ev) = stream.message().await? {
        if let Some(Event::Exit(e)) = ev.event {
            exit_code = Some(e.exit_code);
        }
    }
    exit_code.ok_or_else(|| {
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
