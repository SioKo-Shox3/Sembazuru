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
    }

    /// Loads from `path` then applies the env overrides — the worker's effective
    /// startup config.
    pub fn load_effective(path: &Path) -> Self {
        let mut cfg = Self::load_from(path);
        cfg.apply_env_overrides();
        cfg
    }

    /// Writes the config to `path` as TOML, creating the parent directory. The MSI
    /// installer (M9.5) and a future Status SetConfig path persist settings here;
    /// they take effect on the next worker start (no live reload, ADR 0008).
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, s)
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
        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "this is = = not valid toml [[[").unwrap();
        assert_eq!(WorkerConfig::load_from(&path), WorkerConfig::default());
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
