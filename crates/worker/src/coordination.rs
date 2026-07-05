//! Worker side of the Coordination control plane (`docs/protocol/v0.md` §3.1,
//! ADR 0004). The worker is the *client* here: it dials the agent, `Register`s
//! its capabilities and Execution endpoint, then keeps a `Heartbeat` stream open
//! pushing live capacity. This is the "worker -> agent push" topology the proto
//! fixes — the agent learns workers from registration, not a static list, so
//! moving to mDNS later only changes how the worker finds the agent address.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sembazuru_proto::v0::{
    Capabilities, HeartbeatPing, PROTOCOL_VERSION, RegisterRequest,
    coordination_client::CoordinationClient,
};

use crate::config::{ParticipationMode, ParticipationSettings};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::IntervalStream;
use tokio_util::sync::CancellationToken;
use tonic::Code;

/// Worker-wide coordination shutdown flag.
///
/// This is intentionally distinct from [`AttemptStop`]: cancelling one failed
/// register/heartbeat attempt must stop that attempt's sampler and outbound stream
/// without stopping the reconnect loop.
#[derive(Clone, Debug)]
pub struct GlobalShutdownStop {
    inner: Arc<AtomicBool>,
}

impl GlobalShutdownStop {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

impl Default for GlobalShutdownStop {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Arc<AtomicBool>> for GlobalShutdownStop {
    fn from(inner: Arc<AtomicBool>) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Debug)]
struct AttemptStop {
    inner: Arc<AtomicBool>,
}

impl AttemptStop {
    fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    fn stop(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    fn is_stopped(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

struct AttemptStopGuard {
    stop: AttemptStop,
}

impl AttemptStopGuard {
    fn new(stop: AttemptStop) -> Self {
        Self { stop }
    }
}

impl Drop for AttemptStopGuard {
    fn drop(&mut self) {
        self.stop.stop();
    }
}

#[derive(Debug)]
pub enum CoordinationError {
    InvalidEndpoint(String),
    AuthRejected(String),
    RegisterRejected(String),
    ProtocolMismatch {
        expected: u32,
        actual: u32,
    },
    RetryableTransport {
        message: String,
        heartbeat_alive: Option<Duration>,
    },
}

impl CoordinationError {
    fn retryable(message: impl Into<String>, heartbeat_alive: Option<Duration>) -> Self {
        Self::RetryableTransport {
            message: message.into(),
            heartbeat_alive,
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::RetryableTransport { .. })
    }

    fn heartbeat_alive(&self) -> Option<Duration> {
        match self {
            Self::RetryableTransport {
                heartbeat_alive, ..
            } => *heartbeat_alive,
            _ => None,
        }
    }
}

impl fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(message) => write!(f, "invalid coordination endpoint: {message}"),
            Self::AuthRejected(message) => write!(f, "coordination auth rejected: {message}"),
            Self::RegisterRejected(message) => {
                write!(f, "coordination register rejected: {message}")
            }
            Self::ProtocolMismatch { expected, actual } => write!(
                f,
                "coordination protocol mismatch: expected {expected}, got {actual}"
            ),
            Self::RetryableTransport { message, .. } => {
                write!(f, "retryable coordination transport failure: {message}")
            }
        }
    }
}

impl Error for CoordinationError {}

#[derive(Debug, Clone, Copy)]
pub struct ReconnectBackoffPolicy {
    pub base: Duration,
    pub max: Duration,
    pub stable_window: Duration,
}

impl ReconnectBackoffPolicy {
    pub fn production_default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(30),
            stable_window: Duration::from_secs(60),
        }
    }

    #[cfg(test)]
    fn test_default() -> Self {
        Self {
            base: Duration::from_millis(10),
            max: Duration::from_millis(100),
            stable_window: Duration::from_secs(60),
        }
    }

    fn next_after(self, current: Duration) -> Duration {
        current.saturating_mul(2).min(self.max)
    }
}

fn classify_register_status(status: tonic::Status) -> CoordinationError {
    match status.code() {
        Code::Unauthenticated | Code::PermissionDenied => {
            CoordinationError::AuthRejected(status.to_string())
        }
        Code::InvalidArgument | Code::FailedPrecondition => {
            CoordinationError::RegisterRejected(status.to_string())
        }
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::Cancelled
        | Code::Unknown
        | Code::Internal
        | Code::ResourceExhausted
        | Code::Aborted => CoordinationError::retryable(status.to_string(), None),
        _ => CoordinationError::RegisterRejected(status.to_string()),
    }
}

fn classify_rejected_register_detail(detail: String) -> CoordinationError {
    match detail.as_str() {
        "missing cluster auth token" | "invalid cluster auth token" => {
            CoordinationError::AuthRejected(detail)
        }
        _ => CoordinationError::RegisterRejected(detail),
    }
}

/// Best-effort local capabilities for `Register`. `cpu_count` MUST be the
/// worker's real admission capacity (its concurrent-action limit), NOT the raw
/// machine parallelism: the agent schedules against this number, so advertising
/// more than the worker will actually admit makes the scheduler over-dispatch
/// and the excess bounce off the backlog into slow local fallback (ADR 0004).
pub fn local_capabilities(capacity: u32, mode: ParticipationMode) -> Capabilities {
    Capabilities {
        protocol_version: PROTOCOL_VERSION,
        os_build: std::env::var("OS").unwrap_or_default(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: capacity.max(1),
        memory_bytes: 0, // best-effort; not load-bearing for scheduling yet
        data_plane_transports: vec!["tcp-framed".to_string()],
        // This build speaks the M7 shared-token handshake (ADR 0006). An agent
        // with a cluster token configured uses this to tell M7 workers from
        // pre-M7 ones; an agent without a token ignores it.
        supports_auth: true,
        // This worker's build version (the workspace version) for version-gated
        // admission (ADR 0011): the agent schedules to this worker only when this
        // matches its own version, keeping the cluster on one build so distributed
        // output stays byte-identical to local. Manual updates (ADR 0009 withdrawal)
        // realign the cluster to a single version.
        worker_version: env!("CARGO_PKG_VERSION").to_string(),
        // How this worker participates (ADR 0012): the agent excludes it from
        // scheduling when this is "off", and an "always" worker reports no CPU
        // signal (full static capacity) while "adaptive" rides idle CPU (ADR 0010).
        participation_mode: mode.as_str().to_string(),
        // This build presents the agent-minted session_id on the data-plane Hello
        // so the agent binds file supply to the authoritative session (ADR 0013).
        // Advertised for visibility; the operative signal is the non-empty
        // session_id the worker forwards — an agent tolerates old workers that
        // send none (legacy per-connection scoping).
        supports_session_capability: true,
    }
}

/// A stable-enough worker identity for a static deployment: machine name + pid.
/// A restart gets a new pid (and so a new entry), which is the conservative
/// choice — the agent treats it as a fresh worker rather than silently merging.
pub fn default_worker_id() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "worker".to_string());
    format!("{host}#{}", std::process::id())
}

/// Registers with the agent and then heartbeats forever (until the connection
/// drops or the agent closes the pong stream). Returns `Err` if the initial
/// connect/register fails; a worker that cannot reach the agent simply runs
/// un-registered (the agent never schedules to it) rather than crashing.
#[allow(clippy::too_many_arguments)]
pub async fn register_and_heartbeat(
    agent_endpoint: String,
    worker_id: String,
    execution_endpoint: String,
    capacity: u32,
    running: Arc<AtomicU32>,
    heartbeat_interval: Duration,
    global_stop: impl Into<GlobalShutdownStop>,
    // Shared cluster token to present on Register (ADR 0006). Empty when the
    // cluster runs without auth; the agent then accepts unconditionally.
    auth_token: String,
    // Participation policy (ADR 0012, generalizing ADR 0010). `Adaptive` runs a
    // background idle-CPU sampler and every heartbeat carries the smoothed value so
    // the agent scales scheduling to host load. `Always` runs no sampler and sends
    // no CPU signal (full static capacity). `Off` also sends no signal; the agent
    // excludes it from scheduling by mode (its capability advertises "off").
    participation: ParticipationSettings,
) -> Result<(), CoordinationError> {
    let global_stop = global_stop.into();
    let caps = local_capabilities(capacity, participation.mode);
    let cpu_count = caps.cpu_count;

    // Match the agent's keepalive so a half-open TCP is noticed at the transport
    // layer too (ADR 0004's two-layer liveness); the app-layer ping below is the
    // process-liveness/capacity layer.
    let endpoint = tonic::transport::Endpoint::from_shared(agent_endpoint)
        .map_err(|e| CoordinationError::InvalidEndpoint(e.to_string()))?
        .http2_keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(10));
    let mut client = CoordinationClient::new(
        endpoint
            .connect()
            .await
            .map_err(|e| CoordinationError::retryable(e.to_string(), None))?,
    );

    let resp = client
        .register(RegisterRequest {
            worker_id: worker_id.clone(),
            caps: Some(caps),
            execution_endpoint,
            auth_token: auth_token.clone(),
        })
        .await
        .map_err(classify_register_status)?
        .into_inner();
    if resp.protocol_version != PROTOCOL_VERSION {
        return Err(CoordinationError::ProtocolMismatch {
            expected: PROTOCOL_VERSION,
            actual: resp.protocol_version,
        });
    }
    if !resp.accepted {
        return Err(classify_rejected_register_detail(resp.detail));
    }

    let attempt_stop = AttemptStop::new();
    let _attempt_stop_guard = AttemptStopGuard::new(attempt_stop.clone());

    // Start the idle-CPU sampler only in Adaptive mode (ADR 0012); it publishes the
    // latest smoothed reading into `cpu_signal`, which the heartbeat closure reads
    // each tick. The sentinel keeps heartbeats sending `None` (no CPU signal) until
    // the first real reading exists, and the sampler stops with the attempt-local
    // flag. In `Always` and `Off` no sampler runs and the heartbeat sends `None`:
    // `Always` then gets full static capacity from the agent, and `Off` is excluded
    // by its mode.
    let cpu_signal = if participation.mode == ParticipationMode::Adaptive {
        let sig = Arc::new(AtomicU32::new(crate::cpu_monitor::NOT_READY));
        crate::cpu_monitor::spawn_idle_cpu_sampler(
            Arc::clone(&sig),
            participation.idle,
            Arc::clone(&attempt_stop.inner),
        );
        Some(sig)
    } else {
        None
    };

    // Outbound ping stream: one ping per interval tick carrying current capacity,
    // ending when global shutdown or this attempt's local stop is set. `take_while`
    // terminates the stream — the gRPC body lives in tonic's connection task, so
    // ending the stream, not dropping this future, is what actually stops the
    // pings and lets the agent age the worker out.
    let start = Instant::now();
    let outbound_global_stop = global_stop.clone();
    let outbound_attempt_stop = attempt_stop.clone();
    let outbound = IntervalStream::new(tokio::time::interval(heartbeat_interval))
        .take_while(move |_| {
            !outbound_global_stop.is_stopped() && !outbound_attempt_stop.is_stopped()
        })
        .map(move |_| {
            let in_flight = running.load(Ordering::SeqCst);
            // Latest smoothed idle CPU, or None until the sampler is ready / when
            // the feature is off — the agent reads None as "no CPU signal" and
            // schedules this worker by slots alone (ADR 0010).
            let idle_cpu_pct = cpu_signal.as_ref().and_then(|s| {
                let v = s.load(Ordering::Relaxed);
                (v <= 100).then_some(v)
            });
            HeartbeatPing {
                worker_id: worker_id.clone(),
                monotonic_qpc: u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
                running_actions: in_flight,
                idle_slots: cpu_count.saturating_sub(in_flight),
                idle_cpu_pct,
                auth_token: auth_token.clone(),
            }
        });

    let mut pongs = client
        .heartbeat(tonic::Request::new(outbound))
        .await
        .map_err(|e| CoordinationError::retryable(e.to_string(), None))?
        .into_inner();
    let heartbeat_started = Instant::now();
    // Drain pongs until the stream ends; the agent uses ping arrival times, so we
    // do not need the pong content, only to keep the stream live.
    loop {
        match pongs.message().await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return if global_stop.is_stopped() || attempt_stop.is_stopped() {
                    Ok(())
                } else {
                    Err(CoordinationError::retryable(
                        "heartbeat pong stream closed before stop",
                        Some(heartbeat_started.elapsed()),
                    ))
                };
            }
            Err(e) => {
                return if global_stop.is_stopped() || attempt_stop.is_stopped() {
                    Ok(())
                } else {
                    Err(CoordinationError::retryable(
                        e.to_string(),
                        Some(heartbeat_started.elapsed()),
                    ))
                };
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn register_and_heartbeat_reconnect_loop(
    agent_endpoint: String,
    worker_id: String,
    execution_endpoint: String,
    capacity: u32,
    running: Arc<AtomicU32>,
    heartbeat_interval: Duration,
    global_stop: GlobalShutdownStop,
    auth_token: String,
    participation: ParticipationSettings,
    shutdown: CancellationToken,
) -> Result<(), CoordinationError> {
    register_and_heartbeat_reconnect_loop_with_backoff(
        agent_endpoint,
        worker_id,
        execution_endpoint,
        capacity,
        running,
        heartbeat_interval,
        global_stop,
        auth_token,
        participation,
        shutdown,
        ReconnectBackoffPolicy::production_default(),
        cancellable_sleep,
    )
    .await
}

async fn cancellable_sleep(duration: Duration, shutdown: CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => true,
        _ = shutdown.cancelled() => false,
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_and_heartbeat_reconnect_loop_with_backoff<F, Fut>(
    agent_endpoint: String,
    worker_id: String,
    execution_endpoint: String,
    capacity: u32,
    running: Arc<AtomicU32>,
    heartbeat_interval: Duration,
    global_stop: GlobalShutdownStop,
    auth_token: String,
    participation: ParticipationSettings,
    shutdown: CancellationToken,
    policy: ReconnectBackoffPolicy,
    mut sleep: F,
) -> Result<(), CoordinationError>
where
    F: FnMut(Duration, CancellationToken) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut next_backoff = policy.base;
    loop {
        if shutdown.is_cancelled() || global_stop.is_stopped() {
            global_stop.stop();
            return Ok(());
        }

        let attempt = register_and_heartbeat(
            agent_endpoint.clone(),
            worker_id.clone(),
            execution_endpoint.clone(),
            capacity,
            Arc::clone(&running),
            heartbeat_interval,
            global_stop.clone(),
            auth_token.clone(),
            participation,
        );
        let result = tokio::select! {
            _ = shutdown.cancelled() => {
                global_stop.stop();
                return Ok(());
            }
            result = attempt => result,
        };

        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.is_retryable() => {
                let stable = error
                    .heartbeat_alive()
                    .is_some_and(|alive| alive >= policy.stable_window);
                let delay = if stable { policy.base } else { next_backoff };
                next_backoff = policy.next_after(delay);
                let completed = sleep(delay, shutdown.clone()).await;
                if !completed {
                    global_stop.stop();
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sembazuru_proto::v0::{
        HeartbeatPing, HeartbeatPong, RegisterResponse,
        coordination_server::{Coordination, CoordinationServer},
    };
    use tokio::sync::{Mutex, Notify, mpsc};
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::transport::Server;
    use tonic::{Code, Request, Response, Status, Streaming};

    use super::*;
    #[derive(Clone)]
    struct ScriptedCoordination {
        state: Arc<ScriptedState>,
    }

    struct ScriptedState {
        registers: Mutex<VecDeque<RegisterBehavior>>,
        heartbeats: Mutex<VecDeque<HeartbeatBehavior>>,
        register_count: AtomicUsize,
        heartbeat_count: AtomicUsize,
        register_notify: Notify,
        heartbeat_notify: Notify,
    }

    enum RegisterBehavior {
        Response(RegisterResponse),
        ResponseAfter(Duration, RegisterResponse),
        Status(Code),
    }

    enum HeartbeatBehavior {
        StayOpen,
        StayOpenFor(Duration),
        EndImmediately,
    }

    impl ScriptedCoordination {
        fn new(registers: Vec<RegisterBehavior>, heartbeats: Vec<HeartbeatBehavior>) -> Self {
            Self {
                state: Arc::new(ScriptedState {
                    registers: Mutex::new(registers.into()),
                    heartbeats: Mutex::new(heartbeats.into()),
                    register_count: AtomicUsize::new(0),
                    heartbeat_count: AtomicUsize::new(0),
                    register_notify: Notify::new(),
                    heartbeat_notify: Notify::new(),
                }),
            }
        }

        async fn wait_for_registers(&self, count: usize) {
            loop {
                let notified = self.state.register_notify.notified();
                if self.state.register_count.load(Ordering::SeqCst) >= count {
                    return;
                }
                notified.await;
            }
        }

        async fn wait_for_heartbeats(&self, count: usize) {
            loop {
                let notified = self.state.heartbeat_notify.notified();
                if self.state.heartbeat_count.load(Ordering::SeqCst) >= count {
                    return;
                }
                notified.await;
            }
        }

        fn register_count(&self) -> usize {
            self.state.register_count.load(Ordering::SeqCst)
        }
    }

    #[tonic::async_trait]
    impl Coordination for ScriptedCoordination {
        type HeartbeatStream = ReceiverStream<Result<HeartbeatPong, Status>>;

        async fn register(
            &self,
            _request: Request<RegisterRequest>,
        ) -> Result<Response<RegisterResponse>, Status> {
            self.state.register_count.fetch_add(1, Ordering::SeqCst);
            self.state.register_notify.notify_one();

            let behavior = self
                .state
                .registers
                .lock()
                .await
                .pop_front()
                .expect("missing scripted register behavior");
            match behavior {
                RegisterBehavior::Response(resp) => Ok(Response::new(resp)),
                RegisterBehavior::ResponseAfter(delay, resp) => {
                    tokio::time::sleep(delay).await;
                    Ok(Response::new(resp))
                }
                RegisterBehavior::Status(code) => Err(Status::new(code, "scripted register error")),
            }
        }

        async fn heartbeat(
            &self,
            request: Request<Streaming<HeartbeatPing>>,
        ) -> Result<Response<Self::HeartbeatStream>, Status> {
            self.state.heartbeat_count.fetch_add(1, Ordering::SeqCst);
            self.state.heartbeat_notify.notify_one();
            let behavior = self
                .state
                .heartbeats
                .lock()
                .await
                .pop_front()
                .unwrap_or(HeartbeatBehavior::StayOpen);
            let mut inbound = request.into_inner();
            let (tx, rx) = mpsc::channel(4);
            match behavior {
                HeartbeatBehavior::StayOpen => {
                    tokio::spawn(async move {
                        while matches!(inbound.message().await, Ok(Some(_))) {
                            let _ = tx
                                .send(Ok(HeartbeatPong {
                                    agent_monotonic_us: 0,
                                }))
                                .await;
                        }
                    });
                }
                HeartbeatBehavior::StayOpenFor(duration) => {
                    tokio::spawn(async move {
                        let deadline = tokio::time::sleep(duration);
                        tokio::pin!(deadline);
                        loop {
                            tokio::select! {
                                _ = &mut deadline => break,
                                message = inbound.message() => {
                                    if !matches!(message, Ok(Some(_))) {
                                        break;
                                    }
                                    if tx.send(Ok(HeartbeatPong {
                                        agent_monotonic_us: 0,
                                    }))
                                    .await
                                    .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                HeartbeatBehavior::EndImmediately => drop(tx),
            }
            Ok(Response::new(ReceiverStream::new(rx)))
        }
    }

    fn accepted(protocol_version: u32) -> RegisterBehavior {
        RegisterBehavior::Response(RegisterResponse {
            protocol_version,
            accepted: true,
            detail: String::new(),
        })
    }

    fn accepted_after(delay: Duration, protocol_version: u32) -> RegisterBehavior {
        RegisterBehavior::ResponseAfter(
            delay,
            RegisterResponse {
                protocol_version,
                accepted: true,
                detail: String::new(),
            },
        )
    }

    fn rejected(detail: &str) -> RegisterBehavior {
        RegisterBehavior::Response(RegisterResponse {
            protocol_version: PROTOCOL_VERSION,
            accepted: false,
            detail: detail.to_string(),
        })
    }

    fn test_participation() -> ParticipationSettings {
        ParticipationSettings::always()
    }

    async fn serve_scripted_coordination(service: ScriptedCoordination) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind scripted coordination listener");
        let addr = listener.local_addr().expect("scripted listener local addr");
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinationServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("scripted coordination server exited");
        });
        format!("http://{addr}")
    }

    async fn run_loop_with_recorded_sleeps<F, Fut>(
        agent_endpoint: String,
        shutdown: tokio_util::sync::CancellationToken,
        global_stop: GlobalShutdownStop,
        policy: ReconnectBackoffPolicy,
        sleep: F,
    ) -> Result<(), CoordinationError>
    where
        F: FnMut(Duration, tokio_util::sync::CancellationToken) -> Fut,
        Fut: Future<Output = bool>,
    {
        register_and_heartbeat_reconnect_loop_with_backoff(
            agent_endpoint,
            "worker-1".to_string(),
            "http://127.0.0.1:50061".to_string(),
            4,
            Arc::new(AtomicU32::new(0)),
            Duration::from_millis(10),
            global_stop,
            String::new(),
            test_participation(),
            shutdown,
            policy,
            sleep,
        )
        .await
    }

    mod coordination_reconnect {
        use super::*;

        #[tokio::test]
        async fn retries_transient_network_failures_with_exponential_backoff() {
            let service = ScriptedCoordination::new(
                vec![
                    RegisterBehavior::Status(Code::Unavailable),
                    RegisterBehavior::Status(Code::Unavailable),
                    accepted(PROTOCOL_VERSION),
                ],
                vec![HeartbeatBehavior::StayOpen],
            );
            let endpoint = serve_scripted_coordination(service.clone()).await;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let global_stop = GlobalShutdownStop::new();
            let sleeps = Arc::new(Mutex::new(Vec::new()));
            let sleeps_for_loop = Arc::clone(&sleeps);
            let policy = ReconnectBackoffPolicy {
                base: Duration::from_millis(10),
                max: Duration::from_millis(100),
                stable_window: Duration::from_secs(60),
            };
            let loop_shutdown = shutdown.clone();
            let handle = tokio::spawn(run_loop_with_recorded_sleeps(
                endpoint,
                shutdown.clone(),
                global_stop,
                policy,
                move |duration, _shutdown| {
                    let sleeps = Arc::clone(&sleeps_for_loop);
                    async move {
                        sleeps.lock().await.push(duration);
                        true
                    }
                },
            ));

            service.wait_for_registers(3).await;
            service.wait_for_heartbeats(1).await;
            loop_shutdown.cancel();
            let result = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("reconnect loop did not return")
                .expect("reconnect loop task panicked");

            assert!(
                result.is_ok(),
                "shutdown should end loop cleanly: {result:?}"
            );
            assert_eq!(
                *sleeps.lock().await,
                vec![Duration::from_millis(10), Duration::from_millis(20)]
            );
            assert_eq!(service.register_count(), 3);
        }

        #[tokio::test]
        async fn shutdown_interrupts_backoff_sleep() {
            let service = ScriptedCoordination::new(
                vec![RegisterBehavior::Status(Code::Unavailable)],
                vec![],
            );
            let endpoint = serve_scripted_coordination(service).await;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let global_stop = GlobalShutdownStop::new();
            let sleep_entered = Arc::new(Notify::new());
            let sleep_entered_for_loop = Arc::clone(&sleep_entered);
            let policy = ReconnectBackoffPolicy {
                base: Duration::from_secs(30),
                max: Duration::from_secs(30),
                stable_window: Duration::from_secs(60),
            };
            let handle = tokio::spawn(run_loop_with_recorded_sleeps(
                endpoint,
                shutdown.clone(),
                global_stop.clone(),
                policy,
                move |_duration, shutdown| {
                    let sleep_entered = Arc::clone(&sleep_entered_for_loop);
                    async move {
                        sleep_entered.notify_one();
                        shutdown.cancelled().await;
                        false
                    }
                },
            ));

            sleep_entered.notified().await;
            shutdown.cancel();
            let result = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("reconnect loop did not return after shutdown")
                .expect("reconnect loop task panicked");

            assert!(
                result.is_ok(),
                "cancelled backoff should return Ok: {result:?}"
            );
            assert!(global_stop.is_stopped());
        }

        #[tokio::test]
        async fn delayed_register_with_immediate_heartbeat_end_does_not_reset_backoff() {
            let service = ScriptedCoordination::new(
                vec![
                    RegisterBehavior::Status(Code::Unavailable),
                    accepted_after(Duration::from_millis(80), PROTOCOL_VERSION),
                    accepted(PROTOCOL_VERSION),
                ],
                vec![
                    HeartbeatBehavior::EndImmediately,
                    HeartbeatBehavior::StayOpen,
                ],
            );
            let endpoint = serve_scripted_coordination(service.clone()).await;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let sleeps = Arc::new(Mutex::new(Vec::new()));
            let sleeps_for_loop = Arc::clone(&sleeps);
            let policy = ReconnectBackoffPolicy {
                base: Duration::from_millis(10),
                max: Duration::from_millis(100),
                stable_window: Duration::from_millis(50),
            };
            let loop_shutdown = shutdown.clone();
            let handle = tokio::spawn(run_loop_with_recorded_sleeps(
                endpoint,
                shutdown.clone(),
                GlobalShutdownStop::new(),
                policy,
                move |duration, _shutdown| {
                    let sleeps = Arc::clone(&sleeps_for_loop);
                    async move {
                        sleeps.lock().await.push(duration);
                        true
                    }
                },
            ));

            service.wait_for_registers(3).await;
            service.wait_for_heartbeats(2).await;
            loop_shutdown.cancel();
            let result = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("reconnect loop did not return")
                .expect("reconnect loop task panicked");

            assert!(
                result.is_ok(),
                "shutdown should end loop cleanly: {result:?}"
            );
            assert_eq!(
                *sleeps.lock().await,
                vec![Duration::from_millis(10), Duration::from_millis(20)]
            );
        }

        #[tokio::test]
        async fn caps_backoff_and_resets_after_stable_heartbeat() {
            let service = ScriptedCoordination::new(
                vec![
                    RegisterBehavior::Status(Code::Unavailable),
                    RegisterBehavior::Status(Code::Unavailable),
                    RegisterBehavior::Status(Code::Unavailable),
                    RegisterBehavior::Status(Code::Unavailable),
                    accepted(PROTOCOL_VERSION),
                    accepted(PROTOCOL_VERSION),
                ],
                vec![
                    HeartbeatBehavior::StayOpenFor(Duration::from_millis(250)),
                    HeartbeatBehavior::StayOpen,
                ],
            );
            let endpoint = serve_scripted_coordination(service.clone()).await;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let sleeps = Arc::new(Mutex::new(Vec::new()));
            let sleeps_for_loop = Arc::clone(&sleeps);
            let policy = ReconnectBackoffPolicy {
                base: Duration::from_millis(10),
                max: Duration::from_millis(40),
                stable_window: Duration::from_millis(50),
            };
            let loop_shutdown = shutdown.clone();
            let handle = tokio::spawn(run_loop_with_recorded_sleeps(
                endpoint,
                shutdown.clone(),
                GlobalShutdownStop::new(),
                policy,
                move |duration, _shutdown| {
                    let sleeps = Arc::clone(&sleeps_for_loop);
                    async move {
                        sleeps.lock().await.push(duration);
                        true
                    }
                },
            ));

            service.wait_for_registers(6).await;
            service.wait_for_heartbeats(2).await;
            loop_shutdown.cancel();
            let result = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("reconnect loop did not return")
                .expect("reconnect loop task panicked");

            assert!(
                result.is_ok(),
                "shutdown should end loop cleanly: {result:?}"
            );
            assert_eq!(
                *sleeps.lock().await,
                vec![
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                    Duration::from_millis(40),
                    Duration::from_millis(40),
                    Duration::from_millis(10),
                ]
            );
        }
    }

    mod coordination_failure_classification {
        use super::*;

        #[tokio::test]
        async fn auth_rejection_is_terminal_and_not_retried() {
            let service =
                ScriptedCoordination::new(vec![rejected("missing cluster auth token")], vec![]);
            let endpoint = serve_scripted_coordination(service.clone()).await;
            let sleeps = Arc::new(Mutex::new(Vec::new()));
            let sleeps_for_loop = Arc::clone(&sleeps);
            let err = run_loop_with_recorded_sleeps(
                endpoint,
                tokio_util::sync::CancellationToken::new(),
                GlobalShutdownStop::new(),
                ReconnectBackoffPolicy::test_default(),
                move |duration, _shutdown| {
                    let sleeps = Arc::clone(&sleeps_for_loop);
                    async move {
                        sleeps.lock().await.push(duration);
                        true
                    }
                },
            )
            .await
            .expect_err("auth rejection must be terminal");

            assert!(matches!(err, CoordinationError::AuthRejected(_)), "{err:?}");
            assert_eq!(service.register_count(), 1);
            assert!(sleeps.lock().await.is_empty());
        }

        #[tokio::test]
        async fn protocol_mismatch_is_terminal() {
            let service = ScriptedCoordination::new(vec![accepted(PROTOCOL_VERSION + 1)], vec![]);
            let endpoint = serve_scripted_coordination(service.clone()).await;
            let sleeps = Arc::new(Mutex::new(Vec::new()));
            let sleeps_for_loop = Arc::clone(&sleeps);
            let err = run_loop_with_recorded_sleeps(
                endpoint,
                tokio_util::sync::CancellationToken::new(),
                GlobalShutdownStop::new(),
                ReconnectBackoffPolicy::test_default(),
                move |duration, _shutdown| {
                    let sleeps = Arc::clone(&sleeps_for_loop);
                    async move {
                        sleeps.lock().await.push(duration);
                        true
                    }
                },
            )
            .await
            .expect_err("protocol mismatch must be terminal");

            assert!(
                matches!(
                    err,
                    CoordinationError::ProtocolMismatch {
                        expected: PROTOCOL_VERSION,
                        actual
                    } if actual == PROTOCOL_VERSION + 1
                ),
                "{err:?}"
            );
            assert_eq!(service.register_count(), 1);
            assert!(sleeps.lock().await.is_empty());
        }
    }
}
