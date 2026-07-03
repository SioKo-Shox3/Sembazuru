//! Config-write abstraction (M11). The privileged write of daemon.toml/worker.toml is
//! blocked by design (SetConfig admin-gated OFF; %ProgramData% ACL) — see roadmap §2.0.
//! Everything upstream (wizard, validation, restart orchestration) builds against this
//! trait; the CONCRETE backend (enable status_admin / installer ACL grant / elevated
//! helper) is the owner's external security decision and lands as a real impl later.
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTarget {
    WorkerToml,
    DaemonToml,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// No config-write backend has been chosen/installed yet (roadmap §2.0).
    MechanismUnconfigured,
    /// The chosen backend failed at runtime (permission denied, path, elevation declined…).
    Backend(String),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::MechanismUnconfigured => write!(
                f,
                "config-write mechanism not configured (roadmap §2.0, owner-managed); \
                 cannot persist config from the GUI yet"
            ),
            WriteError::Backend(m) => write!(f, "config write failed: {m}"),
        }
    }
}
impl std::error::Error for WriteError {}

pub trait ConfigWriter: Send + Sync {
    /// Persist `contents` to the given config target, atomically. Returns after the bytes
    /// are on disk (the caller then restarts the service to apply).
    fn write(&self, target: WriteTarget, contents: &str) -> Result<(), WriteError>;
}

/// Default backend until §2.0 is decided: refuses, with a clear message.
pub struct StubConfigWriter;
impl ConfigWriter for StubConfigWriter {
    fn write(&self, _t: WriteTarget, _c: &str) -> Result<(), WriteError> {
        Err(WriteError::MechanismUnconfigured)
    }
}
