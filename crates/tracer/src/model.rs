//! In-memory model of one process's trace and the events within it. These
//! mirror the on-disk record types in `docs/trace-format.md` §5 but are
//! decoupled from the byte layout (that lives in `format`).

/// Record type tags (`docs/trace-format.md` §5.1).
pub mod record_type {
    pub const FILE: u8 = 1;
    pub const PROCESS: u8 = 2;
    pub const REGISTRY: u8 = 3;
    pub const ENV: u8 = 4;
}

/// File operation within a `FILE` record (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    OpenRead,
    OpenWrite,
    OpenReadWrite,
    Probe,
    Enumerate,
    Delete,
    Move,
    CreateDir,
    RemoveDir,
}

impl FileOp {
    pub fn from_u8(v: u8) -> Option<FileOp> {
        Some(match v {
            1 => FileOp::OpenRead,
            2 => FileOp::OpenWrite,
            3 => FileOp::OpenReadWrite,
            4 => FileOp::Probe,
            5 => FileOp::Enumerate,
            6 => FileOp::Delete,
            7 => FileOp::Move,
            8 => FileOp::CreateDir,
            9 => FileOp::RemoveDir,
            _ => return None,
        })
    }
}

/// Process operation within a `PROCESS` record (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOp {
    ChildCreated,
}

impl ProcessOp {
    pub fn from_u8(v: u8) -> Option<ProcessOp> {
        match v {
            1 => Some(ProcessOp::ChildCreated),
            _ => None,
        }
    }
}

/// Registry operation within a `REGISTRY` record (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOp {
    OpenKey,
    QueryValue,
}

impl RegistryOp {
    pub fn from_u8(v: u8) -> Option<RegistryOp> {
        match v {
            1 => Some(RegistryOp::OpenKey),
            2 => Some(RegistryOp::QueryValue),
            _ => None,
        }
    }
}

/// Environment operation within an `ENV` record (§5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvOp {
    Read,
    BlockRead,
}

impl EnvOp {
    pub fn from_u8(v: u8) -> Option<EnvOp> {
        match v {
            1 => Some(EnvOp::Read),
            2 => Some(EnvOp::BlockRead),
            _ => None,
        }
    }
}

/// A decoded event, one per on-disk record.
#[derive(Debug, Clone)]
pub enum EventKind {
    File {
        op: FileOp,
        extra: u64,
    },
    Process {
        op: ProcessOp,
        child_pid: u32,
    },
    Registry {
        op: RegistryOp,
        value_type: u32,
    },
    Env {
        op: EnvOp,
    },
    /// A record whose type/op tags were not recognized. Preserved rather than
    /// dropped so an unknown future record never silently shrinks a graph.
    Unknown {
        record_type: u8,
        op: u8,
    },
}

/// One decoded trace record.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
    /// Win32/NTSTATUS status; `0` means success.
    pub status: u32,
    pub tid: u32,
    pub qpc: u64,
    /// Primary subject: path, registry key, or variable name.
    pub path: String,
    /// Secondary string: move destination, registry value name, or env value.
    pub aux: String,
}

impl Event {
    pub fn succeeded(&self) -> bool {
        self.status == 0
    }
}

/// Access kind attributed to a path in the dependency graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessKind {
    Read,
    Write,
    /// Existence/attribute query that succeeded, or a read open that found
    /// the file — the build depends on the file being present.
    Probe,
    /// Probe or read that failed: the build's behavior depends on the file
    /// being *absent* (e.g. an include-path miss). Real dependency info.
    ProbeMiss,
    Enumerate,
    Delete,
    Move,
}

impl AccessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessKind::Read => "read",
            AccessKind::Write => "write",
            AccessKind::Probe => "probe",
            AccessKind::ProbeMiss => "probe-miss",
            AccessKind::Enumerate => "enumerate",
            AccessKind::Delete => "delete",
            AccessKind::Move => "move",
        }
    }
}

/// One process's full trace: header metadata plus its decoded events.
#[derive(Debug, Clone)]
pub struct Trace {
    pub version: u32,
    pub pid: u32,
    pub parent_pid: u32,
    pub qpc_frequency: u64,
    pub start_qpc: u64,
    pub start_filetime: u64,
    pub exe_path: String,
    pub command_line: String,
    /// Working directory sampled by the interceptor at DLL attach
    /// (`docs/trace-format.md` §4). Empty if the writer could not record it;
    /// the graph builder then leaves relative paths verbatim.
    pub cwd: String,
    pub events: Vec<Event>,
    /// True if parsing stopped early on a truncated final record (the writing
    /// process was likely killed mid-write). Not an error; surfaced as a
    /// warning by the graph builder.
    pub truncated: bool,
}

impl Trace {
    /// Last path component of `exe_path`, lowercased — used for telemetry
    /// tagging (e.g. `vctip.exe`).
    pub fn exe_name(&self) -> String {
        self.exe_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.exe_path)
            .to_ascii_lowercase()
    }
}
