//! Worker side of the Coordination control plane (`docs/protocol/v0.md` §3.1,
//! ADR 0004). The worker is the *client* here: it dials the agent, `Register`s
//! its capabilities and Execution endpoint, then keeps a `Heartbeat` stream open
//! pushing live capacity. This is the "worker -> agent push" topology the proto
//! fixes — the agent learns workers from registration, not a static list, so
//! moving to mDNS later only changes how the worker finds the agent address.

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sembazuru_proto::v0::{
    Capabilities, HeartbeatPing, PROTOCOL_VERSION, RegisterRequest,
    coordination_client::CoordinationClient,
};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::IntervalStream;

/// Best-effort local capabilities for `Register`. `cpu_count` MUST be the
/// worker's real admission capacity (its concurrent-action limit), NOT the raw
/// machine parallelism: the agent schedules against this number, so advertising
/// more than the worker will actually admit makes the scheduler over-dispatch
/// and the excess bounce off the backlog into slow local fallback (ADR 0004).
pub fn local_capabilities(capacity: u32) -> Capabilities {
    Capabilities {
        protocol_version: PROTOCOL_VERSION,
        os_build: std::env::var("OS").unwrap_or_default(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: capacity.max(1),
        memory_bytes: 0, // best-effort; not load-bearing for scheduling yet
        data_plane_transports: vec!["tcp-framed".to_string()],
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
    stop: Arc<AtomicBool>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let caps = local_capabilities(capacity);
    let cpu_count = caps.cpu_count;

    // Match the agent's keepalive so a half-open TCP is noticed at the transport
    // layer too (ADR 0004's two-layer liveness); the app-layer ping below is the
    // process-liveness/capacity layer.
    let endpoint = tonic::transport::Endpoint::from_shared(agent_endpoint)?
        .http2_keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(10));
    let mut client = CoordinationClient::new(endpoint.connect().await?);

    let resp = client
        .register(RegisterRequest {
            worker_id: worker_id.clone(),
            caps: Some(caps),
            execution_endpoint,
        })
        .await?
        .into_inner();
    if !resp.accepted {
        return Err(format!("agent rejected registration: {}", resp.detail).into());
    }

    // Outbound ping stream: one ping per interval tick carrying current
    // capacity, ending when `stop` is set (graceful worker drain). `take_while`
    // terminates the stream — the gRPC body lives in tonic's connection task, so
    // ending the stream, not dropping this future, is what actually stops the
    // pings and lets the agent age the worker out.
    let start = Instant::now();
    let outbound = IntervalStream::new(tokio::time::interval(heartbeat_interval))
        .take_while(move |_| !stop.load(Ordering::SeqCst))
        .map(move |_| {
            let in_flight = running.load(Ordering::SeqCst);
            HeartbeatPing {
                worker_id: worker_id.clone(),
                monotonic_qpc: u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
                running_actions: in_flight,
                idle_slots: cpu_count.saturating_sub(in_flight),
            }
        });

    let mut pongs = client
        .heartbeat(tonic::Request::new(outbound))
        .await?
        .into_inner();
    // Drain pongs until the stream ends; the agent uses ping arrival times, so we
    // do not need the pong content, only to keep the stream live.
    while pongs.message().await?.is_some() {}
    Ok(())
}
