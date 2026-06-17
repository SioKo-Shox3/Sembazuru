//! Async Status client for the resident GUI (M9.4).
//!
//! The GUI dials the daemon's loopback-only, unauthenticated Status service
//! (ADR 0008 §4) at `http://127.0.0.1:50073` (override with `SEMBAZURU_STATUS`).
//! Everything here is a plain `async fn` over a fresh per-call connection: at a
//! ~1.5s cadence over loopback the connect cost is negligible, and it keeps the
//! whole client headless-testable (point it at an in-process `serve_status_service`,
//! exactly as `crates/agent/tests/status.rs` does) with no client state machine.
//!
//! The GUI only ever dials loopback; it never binds a listener and never speaks
//! the cluster-facing Coordination plane.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

use sembazuru_proto::v0::status_client::StatusClient;
use sembazuru_proto::v0::{GetConfigRequest, GetStatusRequest, TriggerEvictionRequest};

use crate::model::{
    ConfigEdit, ConfigModel, ConnectionState, EvictionOutcome, SetConfigOutcome, map_config,
    map_dashboard, map_eviction, map_set_config,
};

/// Default loopback Status address (mirrors the daemon's `DEFAULT_STATUS`). The
/// GUI hardcodes it rather than pull the agent crate into its production deps.
pub const DEFAULT_STATUS_ADDR: &str = "127.0.0.1:50073";
/// Env override for the Status address (the same var the daemon reads).
pub const STATUS_ADDR_ENV: &str = "SEMBAZURU_STATUS";
/// How often the dashboard refreshes.
pub const POLL_INTERVAL: Duration = Duration::from_millis(1500);
/// Bounds a TCP connect so a half-open daemon does not stall the poll task.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Backstop deadline per RPC so a daemon that accepts the connection then stalls
/// cannot wedge a request forever. Generous (a `GetStatus` walks the CAS to size
/// it); the point is only to bound a true hang, not to clip a slow-but-live call.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolves the Status address from the environment and verifies it is loopback,
/// returning the loopback `SocketAddr` to dial. The GUI dials loopback only
/// (ADR 0008 §4): a non-loopback `SEMBAZURU_STATUS` is refused rather than
/// reaching out over the network. Returning the *resolved* address (not the raw
/// string) means the address we checked is the address we dial — there is no
/// second, unchecked resolution inside the transport. Defense in depth: the
/// daemon already binds the Status plane loopback-only (`intake::require_loopback`).
pub fn status_endpoint() -> Result<String, String> {
    let resolved = resolve_loopback(&status_addr())?;
    Ok(format!("http://{resolved}"))
}

fn status_addr() -> String {
    std::env::var(STATUS_ADDR_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_STATUS_ADDR.to_string())
}

/// Resolves `addr` and returns a loopback `SocketAddr`, failing closed unless
/// every address it resolves to is loopback. Mirrors the daemon's `require_loopback`.
fn resolve_loopback(addr: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| format!("invalid Status address {addr:?}: {e}"))?
        .collect();
    let Some(first) = resolved.first().copied() else {
        return Err(format!(
            "Status address {addr:?} resolved to no socket address"
        ));
    };
    if resolved.iter().all(|s| s.ip().is_loopback()) {
        Ok(first)
    } else {
        Err(format!(
            "refusing to dial non-loopback Status address {addr:?}: the GUI talks to \
             the local daemon over loopback only (set SEMBAZURU_STATUS to a \
             127.0.0.0/8 or ::1 address)"
        ))
    }
}

/// A connection or RPC failure reduced to a message safe to display. Carries no
/// secret material (the Status surface never echoes the cluster token).
#[derive(Clone, Debug)]
pub struct ClientError(pub String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ClientError {}

/// The latest dashboard snapshot, shared between the background poll task and the
/// UI thread. Single slot, last-writer-wins: the poller overwrites, the UI reads.
#[derive(Clone)]
pub struct SharedState {
    conn: Arc<Mutex<ConnectionState>>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            conn: Arc::new(Mutex::new(ConnectionState::Connecting)),
        }
    }

    /// A clone of the current connection state for rendering one frame.
    pub fn snapshot(&self) -> ConnectionState {
        self.conn.lock().expect("status mutex poisoned").clone()
    }

    fn set(&self, state: ConnectionState) {
        *self.conn.lock().expect("status mutex poisoned") = state;
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

/// A wake callback the poll loop fires after each refresh so the UI repaints. In
/// the GUI this calls `egui::Context::request_repaint`; in tests it is a no-op.
pub type Waker = Arc<dyn Fn() + Send + Sync>;

/// User-initiated, occasional operations routed to the background runtime so they
/// never block the UI thread. Each carries a `oneshot` for the reply.
pub enum UiCommand {
    GetConfig(oneshot::Sender<Result<ConfigModel, ClientError>>),
    SetConfig(
        ConfigEdit,
        oneshot::Sender<Result<SetConfigOutcome, ClientError>>,
    ),
    TriggerEviction(oneshot::Sender<Result<EvictionOutcome, ClientError>>),
}

/// Connects, fetches one status snapshot, and maps it. Connection-refused is a
/// [`ConnectionState::DaemonDown`], not an error — the daemon is simply not up.
pub async fn fetch_status(endpoint: &str) -> ConnectionState {
    let mut client = match connect(endpoint).await {
        Ok(client) => client,
        Err(_) => return ConnectionState::DaemonDown,
    };
    match client.get_status(GetStatusRequest {}).await {
        Ok(resp) => ConnectionState::Connected(Box::new(map_dashboard(resp.into_inner()))),
        Err(status) => classify(&status),
    }
}

/// Reads the persisted daemon config (presence-only token).
pub async fn fetch_config(endpoint: &str) -> Result<ConfigModel, ClientError> {
    let mut client = connect(endpoint).await?;
    let resp = client
        .get_config(GetConfigRequest {})
        .await
        .map_err(rpc_err)?;
    Ok(map_config(resp.into_inner()))
}

/// Persists a config edit (applies on the next daemon restart, not live).
pub async fn apply_config(
    endpoint: &str,
    edit: ConfigEdit,
) -> Result<SetConfigOutcome, ClientError> {
    let mut client = connect(endpoint).await?;
    let resp = client
        .set_config(edit.into_request())
        .await
        .map_err(rpc_err)?;
    Ok(map_set_config(resp.into_inner()))
}

/// Evicts the cache down to the configured cap.
pub async fn trigger_eviction(endpoint: &str) -> Result<EvictionOutcome, ClientError> {
    let mut client = connect(endpoint).await?;
    let resp = client
        .trigger_eviction(TriggerEvictionRequest {})
        .await
        .map_err(rpc_err)?;
    Ok(map_eviction(resp.into_inner()))
}

async fn connect(endpoint: &str) -> Result<StatusClient<tonic::transport::Channel>, ClientError> {
    let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| ClientError(format!("invalid Status endpoint: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(RPC_TIMEOUT)
        .connect()
        .await
        .map_err(|e| ClientError(format!("cannot reach the daemon: {e}")))?;
    Ok(StatusClient::new(channel))
}

fn classify(status: &tonic::Status) -> ConnectionState {
    if status.code() == tonic::Code::Unavailable {
        ConnectionState::DaemonDown
    } else {
        ConnectionState::Error(status.message().to_string())
    }
}

fn rpc_err(status: tonic::Status) -> ClientError {
    ClientError(status.message().to_string())
}

/// The background poll loop: refresh status every [`POLL_INTERVAL`] and serve
/// user commands, all off the UI thread. The first `interval` tick fires
/// immediately, so the dashboard paints without a 1.5s blank. Returns when the
/// command channel closes (every sender dropped — i.e. the app is exiting).
pub async fn run_client(
    endpoint: String,
    shared: SharedState,
    mut commands: mpsc::Receiver<UiCommand>,
    wake: Waker,
) {
    let endpoint: Arc<str> = Arc::from(endpoint);
    let mut tick = tokio::time::interval(POLL_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Poll off the select path so a slow GetStatus never starves command
                // servicing (last-writer-wins on SharedState if two ever overlap).
                let endpoint = endpoint.clone();
                let shared = shared.clone();
                let wake = wake.clone();
                tokio::spawn(async move {
                    shared.set(fetch_status(&endpoint).await);
                    wake();
                });
            }
            command = commands.recv() => match command {
                Some(command) => spawn_command(endpoint.clone(), command),
                None => break,
            }
        }
    }
}

/// Runs one user command on its own task so a slow RPC never blocks the loop or
/// other commands. The reply `oneshot` is dropped (the caller sees `Err`) if the
/// UI dropped its receiver.
fn spawn_command(endpoint: Arc<str>, command: UiCommand) {
    tokio::spawn(async move {
        match command {
            UiCommand::GetConfig(reply) => {
                let _ = reply.send(fetch_config(&endpoint).await);
            }
            UiCommand::SetConfig(edit, reply) => {
                let _ = reply.send(apply_config(&endpoint, edit).await);
            }
            UiCommand::TriggerEviction(reply) => {
                let _ = reply.send(trigger_eviction(&endpoint).await);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::resolve_loopback;

    #[test]
    fn loopback_addresses_are_accepted() {
        assert!(
            resolve_loopback("127.0.0.1:50073")
                .unwrap()
                .ip()
                .is_loopback()
        );
        assert!(resolve_loopback("[::1]:50073").unwrap().ip().is_loopback());
        assert!(
            resolve_loopback("localhost:50073")
                .unwrap()
                .ip()
                .is_loopback()
        );
    }

    #[test]
    fn routable_addresses_are_refused() {
        assert!(resolve_loopback("0.0.0.0:50073").is_err());
        assert!(resolve_loopback("10.0.0.5:50073").is_err());
        assert!(resolve_loopback("not a socket addr").is_err());
    }
}
