//! Pure logic for the "join a cluster" flow (M11): turn wizard input into a validated
//! worker.toml. No egui, no I/O — unit-tested. Only the subset of worker fields the
//! wizard sets is emitted; the rest fall back to WorkerConfig defaults on the worker side.
use serde::Serialize;

#[derive(Clone, Debug, Default)]
pub struct JoinInput {
    pub agent: String,
    pub cluster_token: String,
    pub listen_addr: String,
    pub advertise: String, // empty = auto-fill
    pub detected_lan_ip: Option<String>,
    pub participation_mode: String, // "always" | "adaptive" | "off"
    pub allow_insecure_lan: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinError {
    AgentUrl,
    TokenRequired,
    ListenAddr,
    AdvertiseUnresolved,
    ParticipationMode,
}

/// The validated, ready-to-serialize subset of worker.toml.
#[derive(Clone, Debug, Serialize)]
pub struct WorkerJoin {
    pub agent: String,
    pub cluster_token: String,
    pub listen_addr: String,
    pub advertise: String,
    pub participation_mode: String,
    pub unsafe_allow_insecure_execution_lan: bool,
}

fn parse_socket(addr: &str) -> Option<(std::net::IpAddr, u16)> {
    addr.parse::<std::net::SocketAddr>()
        .ok()
        .map(|s| (s.ip(), s.port()))
}

pub fn validate(i: JoinInput) -> Result<WorkerJoin, JoinError> {
    if !(i.agent.starts_with("http://") || i.agent.starts_with("https://")) {
        return Err(JoinError::AgentUrl);
    }
    if i.cluster_token.trim().is_empty() {
        return Err(JoinError::TokenRequired);
    }
    let (ip, port) = parse_socket(&i.listen_addr).ok_or(JoinError::ListenAddr)?;
    if !matches!(i.participation_mode.as_str(), "always" | "adaptive" | "off") {
        return Err(JoinError::ParticipationMode);
    }
    // Advertise: explicit wins; else if listen is 0.0.0.0/unspecified, derive from detected LAN IP.
    let advertise = if !i.advertise.trim().is_empty() {
        i.advertise.trim().to_string()
    } else if ip.is_unspecified() {
        let lan = i
            .detected_lan_ip
            .as_deref()
            .ok_or(JoinError::AdvertiseUnresolved)?;
        format!("http://{lan}:{port}")
    } else {
        format!("http://{ip}:{port}")
    };
    Ok(WorkerJoin {
        agent: i.agent.trim().to_string(),
        cluster_token: i.cluster_token.clone(),
        listen_addr: i.listen_addr.trim().to_string(),
        advertise,
        participation_mode: i.participation_mode,
        unsafe_allow_insecure_execution_lan: i.allow_insecure_lan,
    })
}

/// Serialize to TOML text (via `toml`), the exact bytes the writer persists.
pub fn render_worker_toml(w: &WorkerJoin) -> String {
    toml::to_string_pretty(w).expect("WorkerJoin is a fixed, always-serializable struct")
}
