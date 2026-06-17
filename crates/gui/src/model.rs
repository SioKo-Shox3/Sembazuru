//! Pure proto → view-model mapping for the resident GUI (M9.4).
//!
//! This module has no I/O and no egui: it turns the wire types the daemon's
//! loopback Status service returns (`sembazuru.v0`, see `control.proto`) into the
//! plain structs the dashboard renders, and turns a config edit back into a
//! `SetConfigRequest`. Keeping it side-effect-free is what lets the whole mapping
//! — including the security-critical cluster-token handling — be unit-tested
//! without standing up egui or a tokio runtime.
//!
//! Secret discipline (ADR 0008 §4): the cluster token is never read back. The
//! read path ([`ConfigModel`]) carries only a `cluster_token_set` presence flag —
//! there is no field that could hold the secret — and the write path
//! ([`TokenAction`]) is the only channel a token value travels through.

use sembazuru_proto::v0::{
    CacheStatus, ExecBreakdown, FileServerStatus, GetConfigResponse, GetStatusResponse,
    SetConfigRequest, SetConfigResponse, TriggerEvictionResponse, WorkerStatus,
};

/// What the dashboard knows about the daemon connection at a given moment. The
/// poll loop replaces this wholesale each tick; the UI renders whatever it finds.
#[derive(Clone, Debug)]
pub enum ConnectionState {
    /// No snapshot yet (the first poll is in flight).
    Connecting,
    /// A fresh snapshot from a reachable daemon.
    Connected(Box<DashboardModel>),
    /// The daemon is not listening on the loopback Status port (connection
    /// refused / transport unavailable). Not an error — the daemon is just down,
    /// which drives the "start the daemon" affordance.
    DaemonDown,
    /// The daemon answered but the RPC failed; the (sanitized) message to show.
    Error(String),
}

/// The whole dashboard, mapped from one `GetStatusResponse`.
#[derive(Clone, Debug, Default)]
pub struct DashboardModel {
    pub workers: Vec<WorkerRow>,
    pub cache: CacheModel,
    pub exec: ExecModel,
    pub fileserver: FileServerModel,
    pub in_flight: u32,
    pub auth_enabled: bool,
}

/// One connected worker as a table row.
#[derive(Clone, Debug, Default)]
pub struct WorkerRow {
    pub id: String,
    pub endpoint: String,
    pub cpu: u32,
    pub os_build: String,
    pub arch: String,
    pub running: u32,
    pub idle: u32,
    /// Heartbeat age rendered as a short human string (e.g. "1.5s ago").
    pub last_ping: String,
    pub healthy: bool,
}

/// Action-cache state, with the hit rate computed GUI-side (no float on the wire).
#[derive(Clone, Debug, Default)]
pub struct CacheModel {
    pub enabled: bool,
    pub size_bytes: u64,
    pub max_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    /// hits / (hits + misses) as a percentage; `None` when nothing has been
    /// looked up yet (so the UI shows "—" rather than a misleading 0%).
    pub hit_rate_pct: Option<f64>,
}

/// Where completed actions ran (remote / kept-local / fell-back).
#[derive(Clone, Debug, Default)]
pub struct ExecModel {
    pub remote: u64,
    pub local: u64,
    pub fallback: u64,
}

/// File-supply data-plane counters.
#[derive(Clone, Debug, Default)]
pub struct FileServerModel {
    pub read_ops: u64,
    pub read_bytes: u64,
    pub inline_bytes: u64,
}

/// The persisted daemon config, mapped from `GetConfigResponse`. Mirrors the
/// daemon's settings the GUI lets the user edit, hiding the `SEMBAZURU_*` env.
#[derive(Clone, Debug, Default)]
pub struct ConfigModel {
    pub config_path: String,
    pub file_exists: bool,
    pub coord_addr: String,
    pub intake_addr: String,
    pub fileserver_addr: String,
    pub status_addr: String,
    pub cache_root: String,
    pub trace_root: String,
    pub cache_max_bytes: u64,
    /// Presence only — the secret itself is never read back (ADR 0008 §4). There
    /// is deliberately no field here that could carry the token value.
    pub cluster_token_set: bool,
}

/// The outcome of a `SetConfig` (the daemon's "saved; restart to apply" reply).
#[derive(Clone, Debug)]
pub struct SetConfigOutcome {
    pub ok: bool,
    pub detail: String,
}

/// The outcome of a cache eviction pass.
#[derive(Clone, Debug)]
pub struct EvictionOutcome {
    pub freed_bytes: u64,
    pub size_bytes_after: u64,
    pub cap_configured: bool,
}

/// A write-only secret (the cluster token). It redacts itself in `Debug`, refuses
/// to be `Clone`d, and zeroizes its buffer on drop, so the plaintext does not
/// linger in freed heap memory or get copied around the UI by accident.
///
/// This bounds the *GUI-side* exposure, which is where the config text box will
/// hold the value. Once lowered to the wire ([`ConfigEdit::into_request`]) the
/// value transiently exists in tonic's serialization buffer, which is outside the
/// GUI's control — that residual copy is unavoidable for a write that must send
/// the token, and is acknowledged rather than zeroized here.
pub struct SecretString(String);

impl SecretString {
    /// Moves the inner plaintext out for lowering to the wire, without letting the
    /// zeroizing `Drop` wipe the buffer we are handing on.
    fn into_inner(self) -> String {
        let mut held = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut held.0)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// How a config save should treat the cluster token. The GUI's token text box is
/// write-only; this enum is the only channel a token value travels through, and
/// it maps 1:1 onto the `optional string cluster_token` wire semantics. It is
/// deliberately neither `Clone` nor value-printing in `Debug`.
#[derive(Default)]
pub enum TokenAction {
    /// Leave the stored token unchanged (the box was untouched) → absent.
    #[default]
    Keep,
    /// Clear the token, disabling auth → present-and-empty.
    Clear,
    /// Set the token to this value → present-and-nonempty.
    Set(SecretString),
}

impl std::fmt::Debug for TokenAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keep => f.write_str("Keep"),
            Self::Clear => f.write_str("Clear"),
            Self::Set(_) => f.write_str("Set(<redacted>)"),
        }
    }
}

/// A config edit from the GUI, before it becomes a wire request. Empty addresses
/// mean "keep the existing value" (matching `SetConfigRequest` semantics); the
/// token follows [`TokenAction`]. Not `Clone` — the secret it may carry must not
/// be copied; the edit is built once and moved to the runtime.
#[derive(Debug, Default)]
pub struct ConfigEdit {
    pub coord_addr: String,
    pub intake_addr: String,
    pub fileserver_addr: String,
    pub status_addr: String,
    pub cache_root: String,
    pub trace_root: String,
    pub cache_max_bytes: u64,
    pub token: TokenAction,
}

impl ConfigEdit {
    /// Lowers the edit to a wire `SetConfigRequest`. The token mapping here is the
    /// security-critical part: it is the sole place a token value reaches the wire.
    pub fn into_request(self) -> SetConfigRequest {
        SetConfigRequest {
            coord_addr: self.coord_addr,
            intake_addr: self.intake_addr,
            fileserver_addr: self.fileserver_addr,
            status_addr: self.status_addr,
            cache_root: self.cache_root,
            trace_root: self.trace_root,
            cache_max_bytes: self.cache_max_bytes,
            cluster_token: match self.token {
                TokenAction::Keep => None,
                TokenAction::Clear => Some(String::new()),
                TokenAction::Set(secret) => Some(secret.into_inner()),
            },
        }
    }
}

/// Maps a `GetStatusResponse` into the dashboard model.
pub fn map_dashboard(resp: GetStatusResponse) -> DashboardModel {
    DashboardModel {
        workers: resp.workers.into_iter().map(map_worker).collect(),
        cache: map_cache(resp.cache),
        exec: map_exec(resp.exec),
        fileserver: map_fileserver(resp.fileserver),
        in_flight: resp.in_flight,
        auth_enabled: resp.auth_enabled,
    }
}

fn map_worker(w: WorkerStatus) -> WorkerRow {
    WorkerRow {
        id: w.worker_id,
        endpoint: w.execution_endpoint,
        cpu: w.cpu_count,
        os_build: w.os_build,
        arch: w.arch,
        running: w.running_actions,
        idle: w.idle_slots,
        last_ping: humanize_age(w.last_ping_age_ms),
        healthy: w.healthy,
    }
}

// The nested messages arrive as `Option<T>` in prost; an absent one folds to a
// sane default (caching disabled, all counters zero) rather than panicking.
fn map_cache(cache: Option<CacheStatus>) -> CacheModel {
    let c = cache.unwrap_or_default();
    CacheModel {
        enabled: c.enabled,
        size_bytes: c.size_bytes,
        max_bytes: c.max_bytes,
        hits: c.hits,
        misses: c.misses,
        hit_rate_pct: hit_rate(c.hits, c.misses),
    }
}

fn map_exec(exec: Option<ExecBreakdown>) -> ExecModel {
    let e = exec.unwrap_or_default();
    ExecModel {
        remote: e.remote,
        local: e.local,
        fallback: e.fallback,
    }
}

fn map_fileserver(fs: Option<FileServerStatus>) -> FileServerModel {
    let f = fs.unwrap_or_default();
    FileServerModel {
        read_ops: f.read_ops,
        read_bytes: f.read_bytes,
        inline_bytes: f.inline_bytes,
    }
}

/// Maps a `GetConfigResponse` into the config model (presence-only token).
pub fn map_config(resp: GetConfigResponse) -> ConfigModel {
    ConfigModel {
        config_path: resp.config_path,
        file_exists: resp.file_exists,
        coord_addr: resp.coord_addr,
        intake_addr: resp.intake_addr,
        fileserver_addr: resp.fileserver_addr,
        status_addr: resp.status_addr,
        cache_root: resp.cache_root,
        trace_root: resp.trace_root,
        cache_max_bytes: resp.cache_max_bytes,
        cluster_token_set: resp.cluster_token_set,
    }
}

/// Maps a `SetConfigResponse` into the save outcome.
pub fn map_set_config(resp: SetConfigResponse) -> SetConfigOutcome {
    SetConfigOutcome {
        ok: resp.ok,
        detail: resp.detail,
    }
}

/// Maps a `TriggerEvictionResponse` into the eviction outcome.
pub fn map_eviction(resp: TriggerEvictionResponse) -> EvictionOutcome {
    EvictionOutcome {
        freed_bytes: resp.freed_bytes,
        size_bytes_after: resp.size_bytes_after,
        cap_configured: resp.cap_configured,
    }
}

/// hits / (hits + misses) as a percent, or `None` when there have been no lookups
/// (avoids a 0/0 that would render as a misleading 0%).
pub fn hit_rate(hits: u64, misses: u64) -> Option<f64> {
    let total = hits + misses;
    (total > 0).then(|| hits as f64 / total as f64 * 100.0)
}

/// A heartbeat age in milliseconds as a short human string for the worker table.
pub fn humanize_age(ms: u64) -> String {
    if ms < 1_000 {
        "just now".to_string()
    } else if ms < 60_000 {
        // Truncate to tenths so 59_999ms reads "59.9s ago" — never rounding up to a
        // "60.0s" that should have rolled into the minutes bucket.
        let tenths = ms / 100;
        format!("{}.{}s ago", tenths / 10, tenths % 10)
    } else {
        let secs = ms / 1000;
        format!("{}m {:02}s ago", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_rate_guards_divide_by_zero() {
        assert_eq!(hit_rate(0, 0), None, "no lookups → no rate (not 0%)");
        assert_eq!(hit_rate(1, 0), Some(100.0));
        assert_eq!(hit_rate(0, 1), Some(0.0));
        assert_eq!(hit_rate(1, 3), Some(25.0));
    }

    #[test]
    fn humanize_age_buckets() {
        assert_eq!(humanize_age(0), "just now");
        assert_eq!(humanize_age(999), "just now");
        assert_eq!(humanize_age(1_500), "1.5s ago");
        // Just under a minute must not round up into a bogus "60.0s ago".
        assert_eq!(humanize_age(59_999), "59.9s ago");
        assert_eq!(humanize_age(65_000), "1m 05s ago");
        assert_eq!(humanize_age(3_661_000), "61m 01s ago");
    }

    #[test]
    fn token_action_maps_to_wire_semantics() {
        // Keep → absent (leave the stored token unchanged).
        let req = ConfigEdit {
            token: TokenAction::Keep,
            ..Default::default()
        }
        .into_request();
        assert_eq!(req.cluster_token, None);

        // Clear → present-and-empty (disable auth).
        let req = ConfigEdit {
            token: TokenAction::Clear,
            ..Default::default()
        }
        .into_request();
        assert_eq!(req.cluster_token, Some(String::new()));

        // Set → present-and-nonempty.
        let req = ConfigEdit {
            token: TokenAction::Set("s3cret".into()),
            ..Default::default()
        }
        .into_request();
        assert_eq!(req.cluster_token.as_deref(), Some("s3cret"));
    }

    #[test]
    fn secret_token_is_redacted_in_debug() {
        // A `{:?}` on an edit carrying a token must never print the plaintext —
        // the only way the value reaches the wire is `into_request`.
        let edit = ConfigEdit {
            token: TokenAction::Set("s3cret".into()),
            ..Default::default()
        };
        let dbg = format!("{edit:?}");
        assert!(!dbg.contains("s3cret"), "token leaked into Debug: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "token field should be redacted: {dbg}"
        );
    }

    #[test]
    fn empty_addresses_are_kept_not_cleared() {
        // Default edit (all addresses empty) lowers to empty strings, which the
        // daemon reads as "keep existing" — the GUI never has to re-send addrs.
        let req = ConfigEdit::default().into_request();
        assert!(req.coord_addr.is_empty());
        assert!(req.status_addr.is_empty());
    }

    #[test]
    fn config_model_reports_presence_only() {
        // The mapped model exposes the presence flag and structurally cannot hold
        // the secret (no token-value field exists on ConfigModel).
        let resp = GetConfigResponse {
            cluster_token_set: true,
            ..Default::default()
        };
        let model = map_config(resp);
        assert!(model.cluster_token_set);
    }

    #[test]
    fn absent_nested_messages_fold_to_defaults() {
        // A response with cache/exec/fileserver all None must not panic.
        let model = map_dashboard(GetStatusResponse::default());
        assert!(!model.cache.enabled);
        assert_eq!(model.cache.hit_rate_pct, None);
        assert_eq!(
            (model.exec.remote, model.exec.local, model.exec.fallback),
            (0, 0, 0)
        );
        assert_eq!(model.fileserver.read_ops, 0);
    }
}
