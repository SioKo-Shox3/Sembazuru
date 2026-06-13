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

pub mod coordination;
pub mod fileclient;
pub mod vfs_pipe;

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use sembazuru_proto::v0::{
    AbortRequest, AbortResponse, ActionState, Command, ExecuteEvent, ExecuteRequest, ExitStatus,
    StateChange, execute_event::Event, execution_server::Execution,
};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

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
        }
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
    // Kill the child if its task is dropped. Combined with the `tx.closed()` arm
    // below, this guarantees that when the agent gives up on an action (drops the
    // Execute stream — the fallback path) the worker does not leak an orphaned
    // process holding an admission slot (DoS hardening).
    command.kill_on_drop(true);

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
                // On Windows a process always has an exit code; unwrap_or guards
                // the signal-terminated case that does not occur here.
                let code = status.code().unwrap_or(-1);
                // Saturate explicitly rather than let `as u64` wrap; this is the
                // pattern that will be copied for user/kernel time accounting
                // later, where the values are not bounded by a wall clock.
                let wall = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                let _ = tx.send(exit_event(code, wall)).await;
                let _ = tx.send(state_event(ActionState::Completed, "")).await;
            }
            Err(e) => {
                let _ = tx
                    .send(state_event(ActionState::Failed, &format!("wait failed: {e}")))
                    .await;
            }
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
