//! Worker configuration source (M9.3c, ADR 0008 §3).
//!
//! The mirror of `sembazuru_agent::config::DaemonConfig` for the worker. A Windows
//! Service (M9.3c) has no per-shell environment, so the worker needs a *persisted*
//! config source: settings load from a TOML file
//! (`%ProgramData%\Sembazuru\worker.toml`), then the `SEMBAZURU_*` environment
//! variables override individual fields (**env > file**). This keeps the dev/CLI
//! workflow — exporting env vars — working unchanged, while giving the service a
//! file to read so a second PC joins the cluster with the installer + a config file
//! and no manual environment setup (M9 Done-when / M10 precondition).
//!
//! No live reload: the worker reads the effective config once at startup.
//!
//! The cluster token is read with exactly the daemon's semantics (`empty == unset`,
//! taken **verbatim** otherwise — see [`empty_to_none`]) so the daemon and the
//! worker can never disagree on whether auth is on (ADR 0006). M9.3a shipped a bug
//! where trimming made the two readers disagree and silently disabled auth; this
//! module must not reintroduce it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::WorkerVfsConfig;

/// The worker's default Execution listen address — its historical hard-coded
/// default, now in one place so the file, the env override, and
/// [`WorkerConfig::default`] agree.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:50061";

/// Environment variable naming an explicit config-file path; overrides the default
/// `%ProgramData%\Sembazuru\worker.toml` location (used by the service installer
/// and by tests). Distinct from the daemon's `SEMBAZURU_CONFIG` so the two services
/// read separate files on the same host.
pub const CONFIG_PATH_ENV: &str = "SEMBAZURU_WORKER_CONFIG";

/// Default idle headroom kept for the local user, in percent of the machine
/// (ADR 0010). A gentle "good neighbour" default; tunable on real LAN data (M10).
pub const DEFAULT_IDLE_CPU_RESERVE_PCT: u32 = 10;
/// Default hysteresis band (percent) above the reserve required to *resume*
/// participating after dropping out — stops the worker flapping at the threshold.
pub const DEFAULT_IDLE_CPU_HYSTERESIS_PCT: u32 = 10;
/// Default EMA weight (percent) for the newest idle sample; ~3-4 sample memory.
pub const DEFAULT_IDLE_CPU_EMA_ALPHA_PCT: u32 = 30;
/// Default minimum schedulable idle the worker offers while participating (ADR
/// 0012). 0 = pure good-neighbour (offer only what is idle above the reserve); an
/// operator raises it to guarantee a baseline contribution even under some load.
pub const DEFAULT_PARTICIPATION_FLOOR_PCT: u32 = 0;

/// How a worker participates in the cluster (ADR 0012, generalizing the ADR 0010
/// CPU-aware admission). The agent admits a worker to scheduling only when its mode
/// is not [`Off`](ParticipationMode::Off) (and its version matches, ADR 0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipationMode {
    /// Always contribute up to the static admission capacity, regardless of host
    /// load: the worker reports no CPU signal, so the agent uses its full capacity.
    /// (This is the behaviour of the pre-0012 `idle_cpu_enabled = false`.)
    Always,
    /// Contribute dynamically, scaled by smoothed idle CPU — the "good neighbour"
    /// default (ADR 0010): back off while the local user is busy, recover when idle.
    #[default]
    Adaptive,
    /// Do not participate. The worker stays registered and heartbeating, but the
    /// agent excludes it from scheduling entirely (shown as "off" on the dashboard).
    Off,
}

impl ParticipationMode {
    /// The wire string carried in `Capabilities.participation_mode` / shown on the
    /// dashboard. Matches the serde `snake_case` rename so TOML, the wire, and the
    /// agent's `!= "off"` check all agree.
    pub fn as_str(self) -> &'static str {
        match self {
            ParticipationMode::Always => "always",
            ParticipationMode::Adaptive => "adaptive",
            ParticipationMode::Off => "off",
        }
    }
}

/// Resolved participation policy (ADR 0012): the worker's [`ParticipationMode`] plus
/// the idle-CPU tuning [`IdleCpuSettings`] used when the mode is `Adaptive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParticipationSettings {
    pub mode: ParticipationMode,
    /// Adaptive-mode CPU thresholds; ignored when the mode is `Always`/`Off` (no
    /// CPU sampling happens in those modes).
    pub idle: IdleCpuSettings,
}

impl ParticipationSettings {
    /// `Always` participation with default idle tuning: the worker contributes its
    /// full static capacity regardless of host load (no CPU sampling). The
    /// no-CPU-signal behaviour callers that opt out of the good neighbour want
    /// (e.g. coordination tests). The idle tuning is unused in this mode.
    pub fn always() -> Self {
        Self {
            mode: ParticipationMode::Always,
            idle: WorkerConfig::default().idle_cpu(),
        }
    }
}

/// Idle-CPU tuning for `Adaptive` participation (ADR 0010): the optional
/// [`WorkerConfig`] knobs with their defaults applied. The percentages are tuning
/// constants; only consulted when [`ParticipationMode::Adaptive`] is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleCpuSettings {
    pub reserve_pct: u32,
    pub hysteresis_pct: u32,
    pub ema_alpha_pct: u32,
    /// Minimum schedulable idle offered while participating (ADR 0012). 0 = pure
    /// good neighbour; a higher value guarantees a baseline contribution.
    pub participation_floor_pct: u32,
}

/// The worker's persisted configuration. Field names are the TOML keys; every field
/// has a default (via [`Default`]) so a partial or absent file still yields a
/// complete config. Optional fields are "unset" when `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkerConfig {
    /// Execution listen address (the agent dials this for scheduling).
    pub listen_addr: String,
    /// Agent Coordination endpoint to register + heartbeat with; `None` → the
    /// worker only serves Execution and is driven directly (legacy loopback mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The address the agent should dial for Execution (the worker's routable
    /// endpoint). Required when the bind is unspecified (`0.0.0.0`); otherwise
    /// derived from the bind address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise: Option<String>,
    /// Shared cluster auth token (ADR 0006); `None` disables auth (presented empty).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_token: Option<String>,
    /// Admission capacity (max concurrent actions); `None` = machine parallelism.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u32>,
    /// Per-action wall-clock ceiling in seconds (runaway-child backstop); `None` =
    /// the 3600s default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_timeout_secs: Option<u64>,
    /// `launcher.exe` for read-VFS execution (M6.1); VFS is enabled only when all
    /// four VFS paths are set (see [`WorkerConfig::vfs`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launcher: Option<String>,
    /// `sbz_interceptor64.dll` (the injected hook).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dll: Option<String>,
    /// Root for per-action hydrated-input scratch trees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scratch_root: Option<String>,
    /// Worker-local content store, persisted across builds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_root: Option<String>,
    /// How the worker participates (ADR 0012): `always` / `adaptive` / `off`.
    /// `None` → `adaptive` (the good-neighbour default). Replaces the pre-0012
    /// `idle_cpu_enabled` bool (`false` is now `always`; `true` is `adaptive`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participation_mode: Option<ParticipationMode>,
    /// Idle headroom kept for the local user, percent; `None` → the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_cpu_reserve_pct: Option<u32>,
    /// Hysteresis band above the reserve, percent; `None` → the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_cpu_hysteresis_pct: Option<u32>,
    /// EMA smoothing weight for the newest idle sample, percent; `None` → default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_cpu_ema_alpha_pct: Option<u32>,
    /// Minimum schedulable idle offered while participating, percent (ADR 0012);
    /// `None` → the default (0 = pure good neighbour).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_cpu_floor_pct: Option<u32>,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            listen_addr: DEFAULT_LISTEN.to_string(),
            agent: None,
            advertise: None,
            cluster_token: None,
            capacity: None,
            action_timeout_secs: None,
            launcher: None,
            dll: None,
            scratch_root: None,
            cas_root: None,
            participation_mode: None,
            idle_cpu_reserve_pct: None,
            idle_cpu_hysteresis_pct: None,
            idle_cpu_ema_alpha_pct: None,
            idle_cpu_floor_pct: None,
        }
    }
}

/// Maps an empty value to `None`, keeping a non-empty value **verbatim** (no
/// trimming). This deliberately matches `sembazuru_proto::auth::cluster_token_from_env`
/// (`empty == unset`, exact bytes otherwise): the worker and the daemon must read
/// the cluster token identically or a padded/whitespace token would make them
/// disagree on whether auth is on (ADR 0006 "they cannot disagree"). The same rule
/// is applied to the path fields so config values are never silently normalized out
/// from under the operator.
fn empty_to_none(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// Parses `SEMBAZURU_PARTICIPATION_MODE` (case-insensitive): `always` / `adaptive` /
/// `off`; anything else → `None` (the caller then leaves the field unchanged rather
/// than guessing). Matches the serde `snake_case` spelling used in the TOML file.
fn parse_participation_mode(s: &str) -> Option<ParticipationMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "always" => Some(ParticipationMode::Always),
        "adaptive" => Some(ParticipationMode::Adaptive),
        "off" => Some(ParticipationMode::Off),
        _ => None,
    }
}

impl WorkerConfig {
    /// The default config file path: `%ProgramData%\Sembazuru\worker.toml`. Falls
    /// back to the temp dir when `ProgramData` is unset (non-service / CI
    /// contexts), so the path is always resolvable.
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join("Sembazuru").join("worker.toml")
    }

    /// The config file path to use: `$SEMBAZURU_WORKER_CONFIG` if set, else
    /// [`default_path`](Self::default_path).
    pub fn path_from_env() -> PathBuf {
        std::env::var_os(CONFIG_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(Self::default_path)
    }

    /// Loads the config from `path`, or returns defaults when the file is absent
    /// (the common dev case) or unreadable/invalid (logging a warning) — a missing
    /// or corrupt file must never stop the worker from starting.
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => match toml::from_str(&s) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!(
                        "sembazuru-worker: config {} is invalid ({e}); using defaults",
                        path.display()
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Overlays `SEMBAZURU_*` environment variables on top of the loaded values
    /// (env wins). A var that is *present* controls its field even if empty: an
    /// empty `SEMBAZURU_CLUSTER_TOKEN` clears it (empty == unset, ADR 0006). An
    /// absent var leaves the file/default value untouched. The cluster token is
    /// taken **verbatim** when non-empty (no trimming), so the worker presents the
    /// exact same token the daemon expects — see [`empty_to_none`].
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SEMBAZURU_WORKER_LISTEN") {
            self.listen_addr = v;
        }
        if let Ok(v) = std::env::var("SEMBAZURU_AGENT") {
            self.agent = empty_to_none(v);
        }
        if let Ok(v) = std::env::var("SEMBAZURU_WORKER_ADVERTISE") {
            self.advertise = empty_to_none(v);
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_CLUSTER_TOKEN") {
            self.cluster_token = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Ok(v) = std::env::var("SEMBAZURU_CAPACITY") {
            // Present-but-invalid (or zero) clears it → machine parallelism, matching
            // the worker's historical parse. Present-but-invalid still overrides the
            // file (the operator's intent was to set it from the environment).
            self.capacity = v.trim().parse::<u32>().ok().filter(|&n| n > 0);
        }
        if let Ok(v) = std::env::var("SEMBAZURU_ACTION_TIMEOUT_SECS") {
            self.action_timeout_secs = v.trim().parse::<u64>().ok().filter(|&n| n > 0);
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_LAUNCHER") {
            self.launcher = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_DLL") {
            self.dll = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_SCRATCH_ROOT") {
            self.scratch_root = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_CAS_ROOT") {
            self.cas_root = empty_to_none(v.to_string_lossy().into_owned());
        }
        // Participation / CPU-aware admission knobs (ADR 0012 / 0010). A present-but-
        // unparseable percent keeps the existing file/default for that knob (`.or`
        // below) — unlike SEMBAZURU_CAPACITY which clears, because these are gentle
        // tuning knobs where preserving an operator's file setting over a typo'd env
        // is the safer default. A recognized SEMBAZURU_PARTICIPATION_MODE sets it.
        if let Ok(v) = std::env::var("SEMBAZURU_PARTICIPATION_MODE") {
            self.participation_mode = parse_participation_mode(&v).or(self.participation_mode);
        }
        if let Ok(v) = std::env::var("SEMBAZURU_IDLE_CPU_RESERVE_PCT") {
            self.idle_cpu_reserve_pct = v
                .trim()
                .parse::<u32>()
                .ok()
                .map(|n| n.min(100))
                .or(self.idle_cpu_reserve_pct);
        }
        if let Ok(v) = std::env::var("SEMBAZURU_IDLE_CPU_HYSTERESIS_PCT") {
            self.idle_cpu_hysteresis_pct = v
                .trim()
                .parse::<u32>()
                .ok()
                .map(|n| n.min(100))
                .or(self.idle_cpu_hysteresis_pct);
        }
        if let Ok(v) = std::env::var("SEMBAZURU_IDLE_CPU_EMA_ALPHA_PCT") {
            self.idle_cpu_ema_alpha_pct = v
                .trim()
                .parse::<u32>()
                .ok()
                .map(|n| n.clamp(1, 100))
                .or(self.idle_cpu_ema_alpha_pct);
        }
        if let Ok(v) = std::env::var("SEMBAZURU_IDLE_CPU_FLOOR_PCT") {
            self.idle_cpu_floor_pct = v
                .trim()
                .parse::<u32>()
                .ok()
                .map(|n| n.min(100))
                .or(self.idle_cpu_floor_pct);
        }
    }

    /// Loads from `path` then applies the env overrides. The **lenient** variant: a
    /// present-but-invalid file silently falls back to defaults (used off the startup
    /// path, e.g. tooling). Startup must use [`load_effective_checked`] instead.
    pub fn load_effective(path: &Path) -> Self {
        let mut cfg = Self::load_from(path);
        cfg.apply_env_overrides();
        cfg
    }

    /// Loads from `path`, distinguishing an ABSENT file (→ defaults, the common dev
    /// case) from one that is PRESENT but unreadable / not UTF-8 / invalid TOML (→
    /// `Err`). Mirrors the daemon's CFG-001 `load_or_refuse`: a present-but-bad worker
    /// config must NOT silently fall back to defaults, because the defaults carry no
    /// `agent`, no `cluster_token`, and no VFS paths — the worker would then silently
    /// fail to register, present no auth token, and disable read-VFS while the
    /// operator believes their file took effect. Refuse instead so the
    /// misconfiguration is loud. Env overrides are applied by [`load_effective_checked`].
    pub fn load_or_refuse(path: &Path) -> Result<Self, String> {
        // `try_exists() == Ok(false)` is the only "definitely not there" signal; a
        // permission error on the file itself returns `Err`, which falls through to
        // the read+refuse below (a present-but-unreadable file must not be defaulted).
        if matches!(path.try_exists(), Ok(false)) {
            return Ok(Self::default());
        }
        match std::fs::read(path) {
            // Raced away between the existence check and the read → treat as absent.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!(
                "worker config {} exists but is unreadable ({e}); refusing to start on \
                 defaults (no agent/token/VFS). Fix its permissions or remove it.",
                path.display()
            )),
            Ok(bytes) => {
                let s = String::from_utf8(bytes).map_err(|_| {
                    format!(
                        "worker config {} is not valid UTF-8; refusing to start.",
                        path.display()
                    )
                })?;
                toml::from_str(&s).map_err(|e| {
                    format!(
                        "worker config {} is invalid TOML ({e}); refusing to start on \
                         defaults (no agent/token/VFS). Fix or remove it.",
                        path.display()
                    )
                })
            }
        }
    }

    /// The worker's effective STARTUP config: [`load_or_refuse`] then env overrides.
    /// Returns `Err` (so the CLI exits non-zero / the service reports Stopped) on a
    /// present-but-bad config rather than silently running on defaults (CFG-001).
    pub fn load_effective_checked(path: &Path) -> Result<Self, String> {
        let mut cfg = Self::load_or_refuse(path)?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    /// Writes the config to `path` as TOML, creating the parent directory. The MSI
    /// installer (M9.5) and a future Status SetConfig path persist settings here;
    /// they take effect on the next worker start (no live reload, ADR 0008).
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        // Atomic write (CFG-001, mirroring the daemon): a crash mid-write must never
        // leave a TRUNCATED config — under [`load_effective_checked`] that truncation
        // would refuse the worker's start, and under the lenient [`load_from`] it
        // would silently load as defaults. Write a temp sibling on the same volume,
        // then rename onto the final path; a rename is atomic within a volume, so a
        // reader always sees the old or the new file whole, never a half-written one.
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "worker.toml".into());
        let mut tmp = path.to_path_buf();
        tmp.set_file_name(format!(".{name}.tmp.{}", std::process::id()));
        std::fs::write(&tmp, s)?;
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    /// The resolved idle-CPU tuning (ADR 0010): the optional knobs with their
    /// defaults applied. Only consulted in `Adaptive` participation (see
    /// [`participation`](Self::participation)).
    pub fn idle_cpu(&self) -> IdleCpuSettings {
        IdleCpuSettings {
            reserve_pct: self
                .idle_cpu_reserve_pct
                .unwrap_or(DEFAULT_IDLE_CPU_RESERVE_PCT),
            hysteresis_pct: self
                .idle_cpu_hysteresis_pct
                .unwrap_or(DEFAULT_IDLE_CPU_HYSTERESIS_PCT),
            ema_alpha_pct: self
                .idle_cpu_ema_alpha_pct
                .unwrap_or(DEFAULT_IDLE_CPU_EMA_ALPHA_PCT),
            participation_floor_pct: self
                .idle_cpu_floor_pct
                .unwrap_or(DEFAULT_PARTICIPATION_FLOOR_PCT),
        }
    }

    /// The resolved participation policy (ADR 0012): the mode (defaulting to
    /// `Adaptive`, the good neighbour) plus the idle-CPU tuning used in that mode.
    /// This is what the worker hands to coordination to decide how it reports
    /// capacity and whether it samples CPU at all.
    pub fn participation(&self) -> ParticipationSettings {
        ParticipationSettings {
            mode: self.participation_mode.unwrap_or_default(),
            idle: self.idle_cpu(),
        }
    }

    /// The read-VFS install config (M6.1), present only when **all four** VFS paths
    /// are set; any missing one yields `None` (a plain M5-scale worker). This
    /// preserves the all-or-nothing rule the worker's `worker_vfs_config()` used.
    pub fn vfs(&self) -> Option<WorkerVfsConfig> {
        Some(WorkerVfsConfig {
            launcher: PathBuf::from(self.launcher.as_ref()?),
            dll: PathBuf::from(self.dll.as_ref()?),
            scratch_root: PathBuf::from(self.scratch_root.as_ref()?),
            cas_root: PathBuf::from(self.cas_root.as_ref()?),
        })
    }

    /// Builds the installer's default `worker.toml` (M9.5d): a VFS-ready config wired
    /// to the hook binaries the MSI lays beside the worker exe (`install_dir`) and to
    /// the per-machine runtime roots under `data_dir` (`%ProgramData%\Sembazuru`). It
    /// also points the worker at the local daemon so a single-machine install
    /// distributes out of the box; a second worker host repoints `agent` (and sets
    /// the token) via the GUI.
    ///
    /// The cluster token is deliberately NOT seeded: a per-deployment secret must
    /// never be written into a file the installer generates (it would otherwise leak
    /// into installer logs / golden images). The operator supplies it via the GUI.
    pub fn installer_seed(install_dir: &Path, data_dir: &Path) -> Self {
        let at = |dir: &Path, name: &str| dir.join(name).to_string_lossy().into_owned();
        Self {
            // Register with the local daemon's default loopback Coordination address
            // (mirrors sembazuru_agent::config::DEFAULT_COORD). A second host changes
            // this to the daemon host's LAN address via the GUI.
            agent: Some("http://127.0.0.1:50070".to_string()),
            // Read-VFS wired to the installed hook binaries + per-machine data roots,
            // so the worker supplies inputs on demand with no manual setup.
            launcher: Some(at(install_dir, "launcher.exe")),
            dll: Some(at(install_dir, "sbz_interceptor64.dll")),
            scratch_root: Some(at(data_dir, "scratch")),
            cas_root: Some(at(data_dir, "cas")),
            ..Self::default()
        }
    }

    /// Writes `self` to `path` as the seed config, but only if no file exists there
    /// yet — re-running the installer (repair/upgrade) must never clobber an
    /// operator-edited config. Returns whether a file was written.
    pub fn seed_if_absent(&self, path: &Path) -> std::io::Result<bool> {
        if path.exists() {
            return Ok(false);
        }
        self.save_to(path)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    /// Serializes the env-mutating tests: cargo runs tests as threads in one
    /// process, and `SEMBAZURU_*` env vars are process-global, so two tests setting
    /// the same var concurrently would race. Poison-tolerant (a panicking test must
    /// not wedge the others).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp_file() -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("sbz-wcfg-{}-{seq}", std::process::id()))
            .join("worker.toml")
    }

    #[test]
    fn defaults_when_file_absent() {
        let cfg = WorkerConfig::load_from(&tmp_file());
        assert_eq!(cfg, WorkerConfig::default());
        assert_eq!(cfg.listen_addr, DEFAULT_LISTEN);
        assert!(cfg.agent.is_none());
        assert!(cfg.cluster_token.is_none());
        assert!(cfg.capacity.is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = tmp_file();
        let cfg = WorkerConfig {
            listen_addr: "0.0.0.0:50061".into(),
            agent: Some("http://10.0.0.1:50070".into()),
            advertise: Some("http://10.0.0.2:50061".into()),
            cluster_token: Some("s3cret".into()),
            capacity: Some(8),
            action_timeout_secs: Some(1800),
            launcher: Some("C:\\sbz\\launcher.exe".into()),
            dll: Some("C:\\sbz\\sbz_interceptor64.dll".into()),
            scratch_root: Some("C:\\sbz\\scratch".into()),
            cas_root: Some("C:\\sbz\\cas".into()),
            participation_mode: Some(ParticipationMode::Always),
            idle_cpu_reserve_pct: Some(15),
            idle_cpu_hysteresis_pct: Some(5),
            idle_cpu_ema_alpha_pct: Some(40),
            idle_cpu_floor_pct: Some(20),
        };
        cfg.save_to(&path).unwrap();
        assert_eq!(WorkerConfig::load_from(&path), cfg);
    }

    #[test]
    fn partial_file_fills_missing_fields_from_defaults() {
        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Only the agent is set; everything else must default.
        std::fs::write(&path, "agent = \"http://host:50070\"\n").unwrap();
        let cfg = WorkerConfig::load_from(&path);
        assert_eq!(cfg.agent.as_deref(), Some("http://host:50070"));
        assert_eq!(cfg.listen_addr, DEFAULT_LISTEN, "missing addr defaults");
        assert!(cfg.capacity.is_none());
    }

    #[test]
    fn invalid_file_falls_back_to_defaults() {
        // The LENIENT loader (`load_from`) still defaults on a corrupt file — used off
        // the startup path. Startup uses the checked loader (see the CFG-001 test).
        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "this is = = not valid toml [[[").unwrap();
        assert_eq!(WorkerConfig::load_from(&path), WorkerConfig::default());
    }

    #[test]
    fn load_or_refuse_defaults_when_absent_but_refuses_a_corrupt_present_file() {
        // CFG-001 (worker mirror): an ABSENT config → defaults (common dev case, OK).
        // A PRESENT but invalid config → Err, so the worker refuses to start rather
        // than silently running on defaults (no agent/token/VFS) while the operator
        // believes their wired file took effect.
        let absent = tmp_file();
        assert_eq!(
            WorkerConfig::load_or_refuse(&absent).unwrap(),
            WorkerConfig::default(),
            "an absent config loads defaults"
        );

        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "this is = = not valid toml ][").unwrap();
        let err = WorkerConfig::load_or_refuse(&path)
            .expect_err("a present-but-invalid config must be refused, not defaulted");
        assert!(err.contains("invalid"), "the error explains why: {err}");

        // A present-but-non-UTF-8 file is also refused (not silently defaulted) — the
        // arm the daemon's tests leave uncovered.
        let bin_path = tmp_file();
        std::fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
        std::fs::write(&bin_path, [0xff, 0xfe, 0x00, 0x80, 0x81]).unwrap();
        let err = WorkerConfig::load_or_refuse(&bin_path)
            .expect_err("a present-but-non-UTF-8 config must be refused");
        assert!(err.contains("UTF-8"), "the error names the cause: {err}");
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_sibling() {
        // CFG-001 (worker mirror): the save writes a temp sibling then renames
        // (atomic), so a reader never sees a truncated config; after a successful save
        // no `.worker.toml.tmp.*` residue remains and the result round-trips.
        let path = tmp_file();
        let cfg = WorkerConfig {
            agent: Some("http://10.0.0.1:50070".into()),
            cluster_token: Some("keep-this-token".into()),
            ..WorkerConfig::default()
        };
        cfg.save_to(&path).unwrap();
        assert_eq!(WorkerConfig::load_from(&path), cfg, "round-trips");
        let dir = path.parent().unwrap();
        let leftover: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".worker.toml.tmp")
            })
            .collect();
        assert!(leftover.is_empty(), "no temp residue after an atomic save");
    }

    #[test]
    fn vfs_requires_all_four_paths() {
        // None set → no VFS.
        assert!(WorkerConfig::default().vfs().is_none());
        // Three of four set → still no VFS (all-or-nothing).
        let partial = WorkerConfig {
            launcher: Some("l".into()),
            dll: Some("d".into()),
            scratch_root: Some("s".into()),
            ..WorkerConfig::default()
        };
        assert!(partial.vfs().is_none(), "a missing cas_root disables VFS");
        // All four → VFS configured with the exact paths.
        let full = WorkerConfig {
            cas_root: Some("c".into()),
            ..partial
        };
        let vfs = full.vfs().expect("all four paths set");
        assert_eq!(vfs.launcher, PathBuf::from("l"));
        assert_eq!(vfs.cas_root, PathBuf::from("c"));
    }

    #[test]
    fn installer_seed_wires_vfs_without_token() {
        let install = PathBuf::from("C:\\Program Files\\Sembazuru");
        let data = PathBuf::from("C:\\ProgramData\\Sembazuru");
        let cfg = WorkerConfig::installer_seed(&install, &data);
        // All four VFS paths set → the worker is read-VFS-capable out of the box.
        let vfs = cfg.vfs().expect("the seed must enable VFS");
        assert_eq!(vfs.launcher, install.join("launcher.exe"));
        assert_eq!(vfs.dll, install.join("sbz_interceptor64.dll"));
        assert_eq!(vfs.scratch_root, data.join("scratch"));
        assert_eq!(vfs.cas_root, data.join("cas"));
        // Registers with the local daemon, but the per-deployment token is never seeded.
        assert_eq!(cfg.agent.as_deref(), Some("http://127.0.0.1:50070"));
        assert!(
            cfg.cluster_token.is_none(),
            "the installer must not seed a cluster token (per-deployment secret)"
        );
    }

    #[test]
    fn seed_if_absent_is_idempotent() {
        let path = tmp_file();
        let seed =
            WorkerConfig::installer_seed(&PathBuf::from("C:\\inst"), &PathBuf::from("C:\\data"));
        assert!(
            seed.seed_if_absent(&path).unwrap(),
            "first seed writes the file"
        );
        // An operator edit must survive a re-seed (installer repair / upgrade).
        let edited = WorkerConfig {
            capacity: Some(99),
            ..seed.clone()
        };
        edited.save_to(&path).unwrap();
        assert!(
            !seed.seed_if_absent(&path).unwrap(),
            "a second seed is a no-op when the file exists"
        );
        assert_eq!(
            WorkerConfig::load_from(&path).capacity,
            Some(99),
            "the operator's edit is preserved"
        );
    }

    // Env-override tests mutate process-global env, so they take ENV_LOCK to avoid
    // cross-test races (cargo runs tests in the same process concurrently).
    #[test]
    fn env_overrides_win_over_file() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = tmp_file();
        WorkerConfig {
            listen_addr: "127.0.0.1:1111".into(),
            cluster_token: Some("file-token".into()),
            capacity: Some(2),
            ..WorkerConfig::default()
        }
        .save_to(&path)
        .unwrap();

        // SAFETY: serialized by ENV_LOCK; set, load, then clear.
        unsafe {
            std::env::set_var("SEMBAZURU_WORKER_LISTEN", "127.0.0.1:2222");
            std::env::set_var("SEMBAZURU_CAPACITY", "16");
            // A padded token must be taken VERBATIM (no trimming) so the worker and
            // the daemon (which reads cluster_token_from_env) agree (ADR 0006).
            std::env::set_var("SEMBAZURU_CLUSTER_TOKEN", "  pad  ");
        }
        let cfg = WorkerConfig::load_effective(&path);
        unsafe {
            std::env::remove_var("SEMBAZURU_WORKER_LISTEN");
            std::env::remove_var("SEMBAZURU_CAPACITY");
            std::env::remove_var("SEMBAZURU_CLUSTER_TOKEN");
        }

        assert_eq!(cfg.listen_addr, "127.0.0.1:2222", "env addr wins");
        assert_eq!(cfg.capacity, Some(16), "env capacity wins");
        assert_eq!(
            cfg.cluster_token.as_deref(),
            Some("  pad  "),
            "the cluster token is taken verbatim (no trim), matching the daemon's reader"
        );
    }

    #[test]
    fn participation_defaults_to_adaptive_with_gentle_constants() {
        // An absent file / no knobs → adaptive (good neighbour) with the defaults.
        let p = WorkerConfig::default().participation();
        assert_eq!(
            p.mode,
            ParticipationMode::Adaptive,
            "participation defaults to adaptive (good neighbour)"
        );
        assert_eq!(p.idle.reserve_pct, DEFAULT_IDLE_CPU_RESERVE_PCT);
        assert_eq!(p.idle.hysteresis_pct, DEFAULT_IDLE_CPU_HYSTERESIS_PCT);
        assert_eq!(p.idle.ema_alpha_pct, DEFAULT_IDLE_CPU_EMA_ALPHA_PCT);
        assert_eq!(
            p.idle.participation_floor_pct,
            DEFAULT_PARTICIPATION_FLOOR_PCT
        );
        // Explicit knobs are passed through.
        let cfg = WorkerConfig {
            participation_mode: Some(ParticipationMode::Off),
            idle_cpu_reserve_pct: Some(25),
            idle_cpu_floor_pct: Some(30),
            ..WorkerConfig::default()
        };
        let p = cfg.participation();
        assert_eq!(p.mode, ParticipationMode::Off);
        assert_eq!(p.idle.reserve_pct, 25);
        assert_eq!(p.idle.participation_floor_pct, 30);
    }

    #[test]
    fn participation_mode_round_trips_through_toml() {
        // The serde snake_case spelling matches ParticipationMode::as_str / the
        // agent's "off" check, so the TOML, the wire, and the gate all agree.
        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "participation_mode = \"off\"\n").unwrap();
        let cfg = WorkerConfig::load_from(&path);
        assert_eq!(cfg.participation_mode, Some(ParticipationMode::Off));
        assert_eq!(cfg.participation().mode.as_str(), "off");
    }

    #[test]
    fn participation_and_idle_env_overrides_win() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let absent = tmp_file(); // no file → values come purely from env
        // SAFETY: serialized by ENV_LOCK; set, load, clear.
        unsafe {
            std::env::set_var("SEMBAZURU_PARTICIPATION_MODE", "always");
            std::env::set_var("SEMBAZURU_IDLE_CPU_RESERVE_PCT", "20");
            std::env::set_var("SEMBAZURU_IDLE_CPU_EMA_ALPHA_PCT", "50");
            std::env::set_var("SEMBAZURU_IDLE_CPU_FLOOR_PCT", "35");
        }
        let p = WorkerConfig::load_effective(&absent).participation();
        unsafe {
            std::env::remove_var("SEMBAZURU_PARTICIPATION_MODE");
            std::env::remove_var("SEMBAZURU_IDLE_CPU_RESERVE_PCT");
            std::env::remove_var("SEMBAZURU_IDLE_CPU_EMA_ALPHA_PCT");
            std::env::remove_var("SEMBAZURU_IDLE_CPU_FLOOR_PCT");
        }
        assert_eq!(
            p.mode,
            ParticipationMode::Always,
            "SEMBAZURU_PARTICIPATION_MODE=always wins"
        );
        assert_eq!(p.idle.reserve_pct, 20, "env reserve wins");
        assert_eq!(p.idle.ema_alpha_pct, 50, "env alpha wins");
        assert_eq!(p.idle.participation_floor_pct, 35, "env floor wins");
    }

    #[test]
    fn idle_cpu_unparseable_env_keeps_the_file_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = tmp_file();
        WorkerConfig {
            idle_cpu_reserve_pct: Some(33),
            ..WorkerConfig::default()
        }
        .save_to(&path)
        .unwrap();
        // SAFETY: serialized by ENV_LOCK; set, load, clear.
        unsafe {
            std::env::set_var("SEMBAZURU_IDLE_CPU_RESERVE_PCT", "not-a-number");
        }
        let s = WorkerConfig::load_effective(&path).idle_cpu();
        unsafe {
            std::env::remove_var("SEMBAZURU_IDLE_CPU_RESERVE_PCT");
        }
        assert_eq!(
            s.reserve_pct, 33,
            "an unparseable env percent keeps the file value (documented contract)"
        );
    }

    #[test]
    fn unparseable_participation_mode_env_keeps_the_file_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = tmp_file();
        WorkerConfig {
            participation_mode: Some(ParticipationMode::Off),
            ..WorkerConfig::default()
        }
        .save_to(&path)
        .unwrap();
        // SAFETY: serialized by ENV_LOCK; set, load, clear.
        unsafe {
            std::env::set_var("SEMBAZURU_PARTICIPATION_MODE", "bogus");
        }
        let cfg = WorkerConfig::load_effective(&path);
        unsafe {
            std::env::remove_var("SEMBAZURU_PARTICIPATION_MODE");
        }
        assert_eq!(
            cfg.participation_mode,
            Some(ParticipationMode::Off),
            "an unrecognized SEMBAZURU_PARTICIPATION_MODE keeps the file value (no guessing, no panic)"
        );
    }

    #[test]
    fn empty_env_token_clears_the_file_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = tmp_file();
        WorkerConfig {
            cluster_token: Some("file-token".into()),
            ..WorkerConfig::default()
        }
        .save_to(&path)
        .unwrap();
        // SAFETY: serialized by ENV_LOCK; set, load, clear.
        unsafe {
            std::env::set_var("SEMBAZURU_CLUSTER_TOKEN", "");
        }
        let cfg = WorkerConfig::load_effective(&path);
        unsafe {
            std::env::remove_var("SEMBAZURU_CLUSTER_TOKEN");
        }
        assert_eq!(
            cfg.cluster_token, None,
            "a present-but-empty SEMBAZURU_CLUSTER_TOKEN clears the file token (empty == unset)"
        );
    }

    /// The load-bearing invariant: the worker's `cluster_token` (via this config)
    /// must resolve to exactly what `sembazuru_proto::auth::cluster_token_from_env`
    /// returns for the same `SEMBAZURU_CLUSTER_TOKEN` — same bytes, same empty-is-None
    /// rule, no trimming. If these ever diverge, auth silently disagrees (the M9.3a
    /// bug). Checked for a padded value (verbatim) and the empty value (None).
    #[test]
    fn cluster_token_matches_proto_reader() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let absent = tmp_file(); // no file → cluster_token comes purely from env

        for value in ["  spaced token  ", "plain", ""] {
            // SAFETY: serialized by ENV_LOCK; set, read both readers, clear.
            unsafe {
                std::env::set_var("SEMBAZURU_CLUSTER_TOKEN", value);
            }
            let from_config = WorkerConfig::load_effective(&absent).cluster_token;
            let from_proto = sembazuru_proto::auth::cluster_token_from_env();
            unsafe {
                std::env::remove_var("SEMBAZURU_CLUSTER_TOKEN");
            }
            assert_eq!(
                from_config, from_proto,
                "config and proto cluster-token readers must agree for {value:?}"
            );
        }
    }
}
