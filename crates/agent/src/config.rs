//! Daemon configuration source (M9.3a, ADR 0008 §3).
//!
//! A Windows Service has no per-shell environment, so the daemon needs a
//! *persisted* config source. Settings load from a TOML file
//! (`%ProgramData%\Sembazuru\daemon.toml`); then the `SEMBAZURU_*` environment
//! variables override individual fields (**env > file**). This keeps the dev/CLI
//! workflow — exporting env vars — working unchanged, while giving the service
//! (M9.3b) a file to read and the GUI (M9.4, via the Status GetConfig/SetConfig
//! RPC) a file to manage.
//!
//! No live reload: the daemon reads the effective config once at startup. The GUI
//! persists changes here and they take effect on the next daemon start (ADR 0008).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default listen addresses — the daemon's historical hard-coded defaults, now in
/// one place so the file, the env override, and [`DaemonConfig::default`] agree.
pub const DEFAULT_COORD: &str = "127.0.0.1:50070";
pub const DEFAULT_INTAKE: &str = "127.0.0.1:50071";
pub const DEFAULT_FILESERVER: &str = "127.0.0.1:50072";
pub const DEFAULT_STATUS: &str = "127.0.0.1:50073";

/// Environment variable naming an explicit config-file path; overrides the default
/// `%ProgramData%\Sembazuru\daemon.toml` location (used by the service installer
/// and by tests).
pub const CONFIG_PATH_ENV: &str = "SEMBAZURU_CONFIG";

/// The daemon's persisted configuration. Field names are the TOML keys; every
/// field has a default (via [`Default`]) so a partial or absent file still yields
/// a complete config. Optional fields are "unset" when `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// Coordination listen address (workers register + heartbeat here).
    pub coord_addr: String,
    /// LocalIntake listen address (launchers submit actions; loopback-only).
    pub intake_addr: String,
    /// File-supply (data-plane) listen address (workers pull inputs).
    pub fileserver_addr: String,
    /// Status listen address (the resident GUI reads it; loopback-only).
    pub status_addr: String,
    /// Persistent action-cache root; `None` disables caching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_root: Option<String>,
    /// Per-action trace dir root; `None` uses a temp dir.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_root: Option<String>,
    /// Shared cluster auth token (ADR 0006); `None` disables worker auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_token: Option<String>,
    /// CAS size cap in bytes (M9.2); `None` = uncapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_max_bytes: Option<u64>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            coord_addr: DEFAULT_COORD.to_string(),
            intake_addr: DEFAULT_INTAKE.to_string(),
            fileserver_addr: DEFAULT_FILESERVER.to_string(),
            status_addr: DEFAULT_STATUS.to_string(),
            cache_root: None,
            trace_root: None,
            cluster_token: None,
            cache_max_bytes: None,
        }
    }
}

/// Maps an empty value to `None`, keeping a non-empty value **verbatim** (no
/// trimming). This deliberately matches `sembazuru_proto::auth::cluster_token_from_env`
/// (`empty == unset`, exact bytes otherwise): the daemon and the worker must read
/// the cluster token identically or a padded/whitespace token would make them
/// disagree on whether auth is on (ADR 0006 "they cannot disagree"). The same
/// rule is applied to the path fields so config values are never silently
/// normalized out from under the operator.
fn empty_to_none(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

impl DaemonConfig {
    /// The default config file path: `%ProgramData%\Sembazuru\daemon.toml`. Falls
    /// back to the temp dir when `ProgramData` is unset (non-service / CI
    /// contexts), so the path is always resolvable.
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        base.join("Sembazuru").join("daemon.toml")
    }

    /// The config file path to use: `$SEMBAZURU_CONFIG` if set, else
    /// [`default_path`](Self::default_path).
    pub fn path_from_env() -> PathBuf {
        std::env::var_os(CONFIG_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(Self::default_path)
    }

    /// Loads the config from `path`, or returns defaults when the file is absent
    /// (the common dev case) or unreadable/invalid (logging a warning) — a
    /// missing or corrupt file must never stop the daemon from starting.
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => match toml::from_str(&s) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!(
                        "sembazuru-daemon: config {} is invalid ({e}); using defaults",
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
    /// empty `SEMBAZURU_CLUSTER_TOKEN`/`SEMBAZURU_CACHE_ROOT` clears it (empty ==
    /// unset, ADR 0006). An absent var leaves the file/default value untouched.
    /// The cluster token is taken **verbatim** when non-empty (no trimming), so
    /// the daemon reads the exact same token the worker presents via
    /// `cluster_token_from_env` — see [`empty_to_none`].
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SEMBAZURU_COORD") {
            self.coord_addr = v;
        }
        if let Ok(v) = std::env::var("SEMBAZURU_INTAKE") {
            self.intake_addr = v;
        }
        if let Ok(v) = std::env::var("SEMBAZURU_FILESERVER") {
            self.fileserver_addr = v;
        }
        if let Ok(v) = std::env::var("SEMBAZURU_STATUS") {
            self.status_addr = v;
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_CACHE_ROOT") {
            self.cache_root = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_TRACE_ROOT") {
            self.trace_root = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Some(v) = std::env::var_os("SEMBAZURU_CLUSTER_TOKEN") {
            self.cluster_token = empty_to_none(v.to_string_lossy().into_owned());
        }
        if let Ok(v) = std::env::var("SEMBAZURU_CACHE_MAX_BYTES") {
            // A non-numeric or zero value disables the cap (matches the daemon's
            // historical parse). Present-but-invalid still overrides the file.
            self.cache_max_bytes = v.trim().parse::<u64>().ok().filter(|&n| n > 0);
        }
    }

    /// Loads from `path` then applies the env overrides — the daemon's effective
    /// startup config.
    pub fn load_effective(path: &Path) -> Self {
        let mut cfg = Self::load_from(path);
        cfg.apply_env_overrides();
        cfg
    }

    /// Writes the config to `path` as TOML, creating the parent directory. Used by
    /// the Status `SetConfig` RPC: the GUI persists settings here and they take
    /// effect on the next daemon start (no live reload, ADR 0008).
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, s)
    }

    /// Builds the installer's default `daemon.toml` (M9.5d) — just the defaults. The
    /// daemon needs no wiring to be useful (it binds its loopback + LAN listeners
    /// from the built-in defaults); the file is seeded only so it exists for
    /// discovery and GUI editing. No cluster token is seeded (a per-deployment
    /// secret; the operator sets it via the GUI).
    pub fn installer_seed() -> Self {
        Self::default()
    }

    /// Writes `self` to `path` only if no file exists there yet — idempotent
    /// installer seeding that never clobbers an operator-edited config. Returns
    /// whether a file was written.
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
    /// the same var concurrently would race. Poison-tolerant (a panicking test
    /// must not wedge the others).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp_file() -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("sbz-cfg-{}-{seq}", std::process::id()))
            .join("daemon.toml")
    }

    #[test]
    fn defaults_when_file_absent() {
        let cfg = DaemonConfig::load_from(&tmp_file());
        assert_eq!(cfg, DaemonConfig::default());
        assert_eq!(cfg.coord_addr, DEFAULT_COORD);
        assert!(cfg.cache_root.is_none());
        assert!(cfg.cluster_token.is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = tmp_file();
        let cfg = DaemonConfig {
            coord_addr: "127.0.0.1:6000".into(),
            cache_root: Some("C:\\cache".into()),
            cluster_token: Some("s3cret".into()),
            cache_max_bytes: Some(4096),
            ..DaemonConfig::default()
        };
        cfg.save_to(&path).unwrap();
        assert_eq!(DaemonConfig::load_from(&path), cfg);
    }

    #[test]
    fn partial_file_fills_missing_fields_from_defaults() {
        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Only one key set; everything else must default.
        std::fs::write(&path, "cache_root = \"C:\\\\only\"\n").unwrap();
        let cfg = DaemonConfig::load_from(&path);
        assert_eq!(cfg.cache_root.as_deref(), Some("C:\\only"));
        assert_eq!(cfg.coord_addr, DEFAULT_COORD, "missing addr defaults");
        assert_eq!(cfg.status_addr, DEFAULT_STATUS);
    }

    #[test]
    fn invalid_file_falls_back_to_defaults() {
        let path = tmp_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "this is = = not valid toml [[[").unwrap();
        assert_eq!(DaemonConfig::load_from(&path), DaemonConfig::default());
    }

    // Env-override tests mutate process-global env, so they share one test to
    // avoid cross-test races (cargo runs tests in the same process concurrently).
    #[test]
    fn env_overrides_win_over_file() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = tmp_file();
        DaemonConfig {
            coord_addr: "127.0.0.1:1111".into(),
            cache_root: Some("C:\\from-file".into()),
            cluster_token: Some("file-token".into()),
            cache_max_bytes: Some(10),
            ..DaemonConfig::default()
        }
        .save_to(&path)
        .unwrap();

        // SAFETY: single-threaded within this test; we set, load, then clear.
        unsafe {
            std::env::set_var("SEMBAZURU_COORD", "127.0.0.1:2222");
            std::env::set_var("SEMBAZURU_CACHE_MAX_BYTES", "999");
            // A padded token must be taken VERBATIM (no trimming) so the daemon
            // and the worker (which reads cluster_token_from_env) agree (ADR 0006).
            std::env::set_var("SEMBAZURU_CLUSTER_TOKEN", "  pad  ");
        }
        let cfg = DaemonConfig::load_effective(&path);
        unsafe {
            std::env::remove_var("SEMBAZURU_COORD");
            std::env::remove_var("SEMBAZURU_CACHE_MAX_BYTES");
            std::env::remove_var("SEMBAZURU_CLUSTER_TOKEN");
        }

        assert_eq!(cfg.coord_addr, "127.0.0.1:2222", "env addr wins");
        assert_eq!(cfg.cache_max_bytes, Some(999), "env cap wins");
        assert_eq!(
            cfg.cluster_token.as_deref(),
            Some("  pad  "),
            "the cluster token is taken verbatim (no trim), matching the worker's reader"
        );
        assert_eq!(
            cfg.cache_root.as_deref(),
            Some("C:\\from-file"),
            "a field with no env var keeps the file value"
        );
    }

    #[test]
    fn seed_if_absent_writes_then_preserves() {
        let path = tmp_file();
        assert!(
            DaemonConfig::installer_seed()
                .seed_if_absent(&path)
                .unwrap(),
            "first seed writes the file"
        );
        // The seed carries defaults and never a token.
        assert!(DaemonConfig::load_from(&path).cluster_token.is_none());
        // A re-seed never clobbers an operator-edited file.
        DaemonConfig {
            cache_max_bytes: Some(123),
            ..DaemonConfig::default()
        }
        .save_to(&path)
        .unwrap();
        assert!(
            !DaemonConfig::installer_seed()
                .seed_if_absent(&path)
                .unwrap(),
            "a second seed is a no-op when the file exists"
        );
        assert_eq!(DaemonConfig::load_from(&path).cache_max_bytes, Some(123));
    }

    #[test]
    fn empty_env_token_clears_the_file_token() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = tmp_file();
        DaemonConfig {
            cluster_token: Some("file-token".into()),
            ..DaemonConfig::default()
        }
        .save_to(&path)
        .unwrap();
        // SAFETY: serialized by ENV_LOCK; set, load, clear.
        unsafe {
            std::env::set_var("SEMBAZURU_CLUSTER_TOKEN", "");
        }
        let cfg = DaemonConfig::load_effective(&path);
        unsafe {
            std::env::remove_var("SEMBAZURU_CLUSTER_TOKEN");
        }
        assert_eq!(
            cfg.cluster_token, None,
            "a present-but-empty SEMBAZURU_CLUSTER_TOKEN clears the file token (empty == unset)"
        );
    }
}
