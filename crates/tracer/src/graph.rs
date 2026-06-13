//! Dependency-graph construction: the semantics that define M1's "Done when"
//! (`docs/DESIGN.md` §7) and `docs/trace-format.md` §6.
//!
//! Given the set of per-process traces from one run, this links them into a
//! process tree and folds their events into normalized input/output sets,
//! registry reads, and environment reads. Normalization rules (case folding,
//! relative-path resolution, intermediate/telemetry tagging) live here and
//! nowhere else.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{AccessKind, EnvOp, EventKind, FileOp, RegistryOp, Trace};

/// Telemetry processes whose accesses are tagged and excluded from the
/// comparison sets by default (`docs/trace-format.md` §6).
const TELEMETRY_EXES: &[&str] = &["vctip.exe"];

/// Synthetic env-entry name for a whole-environment-block read
/// (`GetEnvironmentStringsW`). `=` cannot appear in a real variable name, so
/// this never collides with a genuine variable.
const ENV_BLOCK_NAME: &str = "<environment-block>";

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe: String,
    pub command_line: String,
    pub children: Vec<u32>,
    pub tags: Vec<String>,
}

/// A path with the union of access kinds observed for it and the pids that
/// touched it.
#[derive(Debug, Clone)]
pub struct PathAccess {
    pub path: String,
    pub kinds: BTreeSet<AccessKind>,
    pub pids: BTreeSet<u32>,
}

#[derive(Debug, Clone)]
pub struct RegistryAccess {
    pub key: String,
    pub value: String,
    pub pids: BTreeSet<u32>,
}

#[derive(Debug, Clone)]
pub struct EnvAccess {
    pub name: String,
    pub found: bool,
    pub pids: BTreeSet<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub root_pid: u32,
    pub processes: Vec<ProcessNode>,
    /// Files the build read or depended on the presence/absence of.
    pub inputs: Vec<PathAccess>,
    /// Files the build produced and left behind (write opens, move
    /// destinations, created directories). These survive the build, so they
    /// are the outputs that matter for reproducibility and distribution.
    pub outputs: Vec<PathAccess>,
    /// Files the build deleted or removed without otherwise producing them —
    /// transients (compiler temp files, stale-output cleanup). Dependency
    /// information, but not surviving outputs, so kept separate: a transient
    /// with a run-varying name must not break output-set comparison.
    pub deletions: Vec<PathAccess>,
    pub registry: Vec<RegistryAccess>,
    pub env: Vec<EnvAccess>,
    pub warnings: Vec<String>,
}

/// Normalizes a path for set comparison. Folds `/`→`\`, strips a `\\?\`
/// long-path prefix (and rewrites `\\?\UNC\` back to `\\`), case-folds (Windows
/// file systems are case-insensitive), and — for a drive-absolute path or a
/// relative path resolved against `cwd` — collapses repeated separators and
/// resolves `.`/`..` lexically so that, e.g., a relative open of `main.c` and
/// its absolute form fold to one entry.
///
/// `cwd` is the recording process's working directory at attach
/// (`Trace::cwd`); pass `""` when it is unknown, in which case a relative path
/// is left verbatim (still separator-collapsed) — stable run-to-run for a fixed
/// working directory, which is the pre-CWD behavior. Resolution is purely
/// lexical: the filesystem is never touched (the trace may be analyzed on
/// another machine). UNC/device paths and the rare drive-relative (`c:foo`) or
/// current-drive-rooted (`\foo`) forms are not `.`/`..`-resolved — guessing
/// their base would be worse than a verbatim entry.
fn normalize_path(raw: &str, cwd: &str) -> String {
    let u = unify(raw);
    match classify(&u) {
        PathKind::DriveAbsolute => canonicalize(&u),
        PathKind::Relative if !cwd.is_empty() => {
            let base = unify(cwd);
            let joined = format!("{}\\{}", base.trim_end_matches('\\'), u);
            match classify(&base) {
                // Only a drive-absolute base is safe to `.`/`..`-resolve.
                PathKind::DriveAbsolute => canonicalize(&joined),
                _ => collapse_separators(&joined),
            }
        }
        // UNC/device, drive-relative, current-drive-rooted, or relative with no
        // known cwd: collapse separators but do not resolve dot segments.
        _ => collapse_separators(&u),
    }
}

/// Path shape, used to decide how (and whether) to resolve a path.
enum PathKind {
    /// `\\server\share\…` or `\\.\device` — leading double separator.
    UncOrDevice,
    /// `c:\…` — drive letter plus a rooted separator.
    DriveAbsolute,
    /// `c:foo` (drive-relative) or `\foo` (current-drive-rooted): rooted but
    /// against a base we don't record.
    Verbatim,
    /// No root at all: resolve against the recording process's cwd.
    Relative,
}

fn classify(p: &str) -> PathKind {
    if p.starts_with("\\\\") {
        return PathKind::UncOrDevice;
    }
    let b = p.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return if b.get(2) == Some(&b'\\') {
            PathKind::DriveAbsolute
        } else {
            PathKind::Verbatim // c:foo — drive-relative
        };
    }
    if b.first() == Some(&b'\\') {
        return PathKind::Verbatim; // \foo — current-drive-rooted
    }
    PathKind::Relative
}

/// Folds `/`→`\`, case-folds, and strips a long-path prefix (`\\?\`, `\??\`,
/// and `\\?\UNC\` → `\\`). Does not collapse separators or resolve dots.
fn unify(raw: &str) -> String {
    let lower = raw.replace('/', "\\").to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("\\\\?\\unc\\") {
        return format!("\\\\{rest}");
    }
    if let Some(rest) = lower.strip_prefix("\\\\?\\") {
        return rest.to_string();
    }
    if let Some(rest) = lower.strip_prefix("\\??\\") {
        return rest.to_string();
    }
    lower
}

/// Lexically canonicalizes a drive-absolute path: collapses separators and
/// resolves `.`/`..` while keeping the `c:` root. `c:\a\..\b` → `c:\b`.
fn canonicalize(p: &str) -> String {
    let (root, rest) = p.split_at(2); // "c:" + the remainder
    let mut comps: Vec<&str> = Vec::new();
    for seg in rest.split('\\') {
        match seg {
            "" | "." => {} // collapsed separator or current-dir: drop
            ".." => {
                comps.pop(); // at the root, `..` has nowhere to go: ignore
            }
            other => comps.push(other),
        }
    }
    let mut out = String::with_capacity(p.len());
    out.push_str(root);
    for c in comps {
        out.push('\\');
        out.push_str(c);
    }
    out
}

/// Collapses runs of `\` into a single separator so that, e.g., `C:\\a\\\b`
/// and `C:\a\b` fold to one entry. A leading `\\` is preserved: UNC
/// (`\\server\share`) and device (`\\.\…`) paths legitimately begin with two,
/// and `is_device` keys on that prefix.
fn collapse_separators(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut chars = p.chars();

    // Preserve exactly one leading `\\`, consuming any further run.
    let leading_unc = p.starts_with("\\\\");
    if leading_unc {
        out.push('\\');
        out.push('\\');
        for c in chars.by_ref() {
            if c != '\\' {
                out.push(c);
                break;
            }
        }
    }

    let mut prev_sep = false;
    for c in chars {
        if c == '\\' {
            if !prev_sep {
                out.push('\\');
            }
            prev_sep = true;
        } else {
            out.push(c);
            prev_sep = false;
        }
    }
    out
}

/// Is this path under the session temp area, i.e. an intermediate artifact to
/// exclude from run-to-run comparison? Uses %TMP%/%TEMP% captured from the
/// root process's environment reads when available; falls back to common temp
/// markers.
fn is_intermediate(norm_path: &str, temp_dirs: &BTreeSet<String>) -> bool {
    if temp_dirs.iter().any(|t| norm_path.starts_with(t.as_str())) {
        return true;
    }
    // Fallback markers for when the env block wasn't captured.
    norm_path.contains("\\temp\\") || norm_path.contains("\\appdata\\local\\temp\\")
}

/// Which comparison set a file access folds into.
#[derive(Clone, Copy)]
enum Bucket {
    Input,
    Output,
    Deletion,
}

struct Accumulator {
    inputs: BTreeMap<String, PathAccess>,
    outputs: BTreeMap<String, PathAccess>,
    deletions: BTreeMap<String, PathAccess>,
    registry: BTreeMap<(String, String), RegistryAccess>,
    env: BTreeMap<String, EnvAccess>,
}

impl Accumulator {
    fn new() -> Self {
        Accumulator {
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            deletions: BTreeMap::new(),
            registry: BTreeMap::new(),
            env: BTreeMap::new(),
        }
    }

    fn add_path(&mut self, bucket: Bucket, norm: &str, kind: AccessKind, pid: u32) {
        let map = match bucket {
            Bucket::Input => &mut self.inputs,
            Bucket::Output => &mut self.outputs,
            Bucket::Deletion => &mut self.deletions,
        };
        let entry = map.entry(norm.to_string()).or_insert_with(|| PathAccess {
            path: norm.to_string(),
            kinds: BTreeSet::new(),
            pids: BTreeSet::new(),
        });
        entry.kinds.insert(kind);
        entry.pids.insert(pid);
    }
}

/// Device/pipe paths (`\\.\pipe\...`, `\\.\PhysicalDrive0`, console handles)
/// are not files; they must never enter the file input/output sets. The
/// `\\?\` long-path prefix has already been stripped by `normalize_path`, so
/// only the `\\.\` device namespace and an explicit `\pipe\` segment remain to
/// catch here.
fn is_device(norm: &str) -> bool {
    norm.starts_with("\\\\.\\") || norm.contains("\\pipe\\")
}

/// Collects %TMP%/%TEMP% values seen in env reads, normalized, so intermediate
/// detection can use the run's real temp dirs.
fn collect_temp_dirs(traces: &[Trace]) -> BTreeSet<String> {
    let mut dirs = BTreeSet::new();
    for t in traces {
        for ev in &t.events {
            if let EventKind::Env { op: EnvOp::Read } = ev.kind {
                let name = ev.path.to_ascii_uppercase();
                if (name == "TMP" || name == "TEMP") && !ev.aux.is_empty() {
                    let mut d = normalize_path(&ev.aux, &t.cwd);
                    if !d.ends_with('\\') {
                        d.push('\\');
                    }
                    dirs.insert(d);
                }
            }
        }
    }
    dirs
}

/// Builds the dependency graph from a set of traces gathered in one run.
///
/// `root_pid` is the launched process (the one whose parent is outside the
/// trace set). If several look like roots, the lowest start time wins and the
/// rest are attached as orphans with a warning.
pub fn build_graph(traces: &[Trace]) -> DependencyGraph {
    let mut graph = DependencyGraph::default();
    if traces.is_empty() {
        graph.warnings.push("no traces provided".to_string());
        return graph;
    }

    let pids: BTreeSet<u32> = traces.iter().map(|t| t.pid).collect();
    let temp_dirs = collect_temp_dirs(traces);

    // --- Process tree -----------------------------------------------------
    let mut nodes: BTreeMap<u32, ProcessNode> = BTreeMap::new();
    for t in traces {
        let mut tags = Vec::new();
        if TELEMETRY_EXES.contains(&t.exe_name().as_str()) {
            tags.push("telemetry".to_string());
        }
        if t.truncated {
            tags.push("truncated".to_string());
            graph.warnings.push(format!(
                "trace for pid {} is truncated (process killed mid-write?)",
                t.pid
            ));
        }
        nodes.insert(
            t.pid,
            ProcessNode {
                pid: t.pid,
                parent_pid: t.parent_pid,
                exe: t.exe_path.clone(),
                command_line: t.command_line.clone(),
                children: Vec::new(),
                tags,
            },
        );
    }

    // Link children to parents that exist in the set.
    let child_pids: Vec<(u32, u32)> = nodes.values().map(|n| (n.pid, n.parent_pid)).collect();
    for (pid, parent_pid) in child_pids {
        if parent_pid != pid
            && let Some(parent) = nodes.get_mut(&parent_pid)
        {
            parent.children.push(pid);
        }
    }

    // Spawn records pointing at a child with no trace = injection gap.
    for t in traces {
        for ev in &t.events {
            if let EventKind::Process {
                op: crate::model::ProcessOp::ChildCreated,
                child_pid,
            } = ev.kind
                && child_pid != 0
                && ev.succeeded()
                && !pids.contains(&child_pid)
            {
                graph.warnings.push(format!(
                    "pid {} spawned child {} but no trace file exists \
                         (injection into the child failed?)",
                    t.pid, child_pid
                ));
            }
        }
    }

    // Root = a process whose parent is not in the set.
    let mut roots: Vec<u32> = nodes
        .values()
        .filter(|n| !pids.contains(&n.parent_pid) || n.parent_pid == n.pid)
        .map(|n| n.pid)
        .collect();
    roots.sort_by_key(|pid| {
        traces
            .iter()
            .find(|t| t.pid == *pid)
            .map(|t| t.start_filetime)
            .unwrap_or(u64::MAX)
    });
    graph.root_pid = roots.first().copied().unwrap_or(traces[0].pid);
    if roots.len() > 1 {
        graph.warnings.push(format!(
            "{} root processes found; using earliest-started pid {} as root",
            roots.len(),
            graph.root_pid
        ));
    }

    // --- Fold events into access sets ------------------------------------
    let mut acc = Accumulator::new();
    for t in traces {
        // Telemetry processes are tagged in the tree but contribute nothing to
        // the comparison sets; skip folding their accesses entirely.
        if TELEMETRY_EXES.contains(&t.exe_name().as_str()) {
            continue;
        }
        for ev in &t.events {
            match &ev.kind {
                EventKind::File { op, .. } => {
                    fold_file(&mut acc, t.pid, *op, ev, &temp_dirs, &t.cwd);
                }
                EventKind::Registry {
                    op: RegistryOp::QueryValue,
                    ..
                } => {
                    let key = (ev.path.clone(), ev.aux.clone());
                    let entry = acc.registry.entry(key).or_insert_with(|| RegistryAccess {
                        key: ev.path.clone(),
                        value: ev.aux.clone(),
                        pids: BTreeSet::new(),
                    });
                    entry.pids.insert(t.pid);
                }
                EventKind::Env { op: EnvOp::Read } => {
                    let entry = acc.env.entry(ev.path.clone()).or_insert_with(|| EnvAccess {
                        name: ev.path.clone(),
                        found: false,
                        pids: BTreeSet::new(),
                    });
                    entry.found |= ev.succeeded();
                    entry.pids.insert(t.pid);
                }
                EventKind::Env {
                    op: EnvOp::BlockRead,
                } => {
                    // A CRT that snapshots the whole environment block depends
                    // on *all* of it. Surface that as one synthetic entry under
                    // a reserved name (env var names cannot contain '='), so
                    // the signal reaches the graph rather than being dropped.
                    let entry = acc
                        .env
                        .entry(ENV_BLOCK_NAME.to_string())
                        .or_insert_with(|| EnvAccess {
                            name: ENV_BLOCK_NAME.to_string(),
                            found: true,
                            pids: BTreeSet::new(),
                        });
                    entry.pids.insert(t.pid);
                }
                _ => {}
            }
        }
    }

    graph.processes = nodes.into_values().collect();
    graph.inputs = acc.inputs.into_values().collect();
    graph.outputs = acc.outputs.into_values().collect();
    graph.deletions = acc.deletions.into_values().collect();
    graph.registry = acc.registry.into_values().collect();
    graph.env = acc.env.into_values().collect();
    graph
}

fn fold_file(
    acc: &mut Accumulator,
    pid: u32,
    op: FileOp,
    ev: &crate::model::Event,
    temp_dirs: &BTreeSet<String>,
    cwd: &str,
) {
    let norm = normalize_path(&ev.path, cwd);
    if is_device(&norm) {
        return; // named pipe / device, not a file
    }
    if is_intermediate(&norm, temp_dirs) {
        return; // intermediate artifact, excluded from comparison sets
    }
    let ok = ev.succeeded();
    match op {
        FileOp::OpenRead => {
            // A successful read is an input; a failed read open is a probe of
            // an absent file — still a dependency (the build behaves
            // differently because it's missing).
            let kind = if ok {
                AccessKind::Read
            } else {
                AccessKind::ProbeMiss
            };
            acc.add_path(Bucket::Input, &norm, kind, pid);
        }
        FileOp::OpenReadWrite => {
            acc.add_path(Bucket::Input, &norm, AccessKind::Read, pid);
            acc.add_path(Bucket::Output, &norm, AccessKind::Write, pid);
        }
        FileOp::OpenWrite => {
            acc.add_path(Bucket::Output, &norm, AccessKind::Write, pid);
        }
        FileOp::Probe => {
            let kind = if ok {
                AccessKind::Probe
            } else {
                AccessKind::ProbeMiss
            };
            acc.add_path(Bucket::Input, &norm, kind, pid);
        }
        FileOp::Enumerate => {
            acc.add_path(Bucket::Input, &norm, AccessKind::Enumerate, pid);
        }
        FileOp::Delete => {
            // A deleted file does not survive the build: a transient, not a
            // surviving output. Kept in the separate deletions set.
            acc.add_path(Bucket::Deletion, &norm, AccessKind::Delete, pid);
        }
        FileOp::Move => {
            // Source is consumed (input-ish), destination is produced.
            acc.add_path(Bucket::Input, &norm, AccessKind::Move, pid);
            if !ev.aux.is_empty() {
                let dst = normalize_path(&ev.aux, cwd);
                if !is_device(&dst) && !is_intermediate(&dst, temp_dirs) {
                    acc.add_path(Bucket::Output, &dst, AccessKind::Write, pid);
                }
            }
        }
        FileOp::CreateDir => {
            acc.add_path(Bucket::Output, &norm, AccessKind::Write, pid);
        }
        FileOp::RemoveDir => {
            acc.add_path(Bucket::Deletion, &norm, AccessKind::Delete, pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, EventKind, ProcessOp};

    fn trace(pid: u32, parent: u32, exe: &str) -> Trace {
        Trace {
            version: 0,
            pid,
            parent_pid: parent,
            qpc_frequency: 1,
            start_qpc: 0,
            start_filetime: pid as u64, // deterministic ordering in tests
            exe_path: exe.to_string(),
            command_line: String::new(),
            cwd: String::new(),
            events: Vec::new(),
            truncated: false,
        }
    }

    fn file_event(op: FileOp, path: &str, status: u32) -> Event {
        Event {
            kind: EventKind::File { op, extra: 0 },
            status,
            tid: 1,
            qpc: 0,
            path: path.to_string(),
            aux: String::new(),
        }
    }

    #[test]
    fn read_is_input_write_is_output() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::OpenRead, "C:\\src\\a.c", 0));
        t.events
            .push(file_event(FileOp::OpenWrite, "C:\\src\\a.obj", 0));
        let g = build_graph(&[t]);
        assert_eq!(g.inputs.len(), 1);
        assert_eq!(g.inputs[0].path, "c:\\src\\a.c");
        assert_eq!(g.outputs.len(), 1);
        assert_eq!(g.outputs[0].path, "c:\\src\\a.obj");
    }

    #[test]
    fn failed_probe_is_kept_as_probe_miss() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        // include search miss: the build depends on this file being absent
        t.events
            .push(file_event(FileOp::Probe, "C:\\inc1\\stdio.h", 2));
        let g = build_graph(&[t]);
        assert_eq!(g.inputs.len(), 1);
        assert!(g.inputs[0].kinds.contains(&AccessKind::ProbeMiss));
    }

    #[test]
    fn child_tree_links_parent_to_child() {
        let parent = trace(10, 1, "C:\\cl.exe");
        let child = trace(20, 10, "C:\\link.exe");
        let g = build_graph(&[parent, child]);
        let p = g.processes.iter().find(|n| n.pid == 10).unwrap();
        assert_eq!(p.children, vec![20]);
        assert_eq!(g.root_pid, 10);
    }

    #[test]
    fn missing_child_trace_warns() {
        let mut parent = trace(10, 1, "C:\\cl.exe");
        parent.events.push(Event {
            kind: EventKind::Process {
                op: ProcessOp::ChildCreated,
                child_pid: 999,
            },
            status: 0,
            tid: 1,
            qpc: 0,
            path: "C:\\link.exe".to_string(),
            aux: String::new(),
        });
        let g = build_graph(&[parent]);
        assert!(g.warnings.iter().any(|w| w.contains("999")));
    }

    #[test]
    fn deleted_file_is_a_transient_not_an_output() {
        // A compiler temp file: deleted, never produced as a surviving output.
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::Delete, "C:\\build\\_cl_12345.tmp", 0));
        let g = build_graph(&[t]);
        assert!(g.outputs.is_empty(), "transient must not be an output");
        assert_eq!(g.deletions.len(), 1);
        assert_eq!(g.deletions[0].path, "c:\\build\\_cl_12345.tmp");
    }

    #[test]
    fn named_pipe_is_not_a_file() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(
            FileOp::OpenWrite,
            "\\\\.\\pipe\\vctip_1.2.3_pipe",
            0,
        ));
        let g = build_graph(&[t]);
        assert!(g.outputs.is_empty(), "a pipe is not a file output");
        assert!(g.inputs.is_empty());
    }

    #[test]
    fn env_block_read_surfaces_as_synthetic_entry() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(Event {
            kind: EventKind::Env {
                op: EnvOp::BlockRead,
            },
            status: 0,
            tid: 1,
            qpc: 0,
            path: String::new(),
            aux: String::new(),
        });
        let g = build_graph(&[t]);
        assert_eq!(g.env.len(), 1);
        assert_eq!(g.env[0].name, ENV_BLOCK_NAME);
        assert!(g.env[0].found);
        assert!(g.env[0].pids.contains(&10));
    }

    #[test]
    fn repeated_separators_collapse_to_one_entry() {
        // The same file reached via a doubled separator must fold to one input,
        // not two: a duplicate entry would make the input set (and its hash)
        // depend on incidental separator noise.
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::OpenRead, "C:\\src\\\\a.c", 0));
        t.events
            .push(file_event(FileOp::OpenRead, "C:\\src\\a.c", 0));
        let g = build_graph(&[t]);
        assert_eq!(
            g.inputs.len(),
            1,
            "doubled separator must not split entries"
        );
        assert_eq!(g.inputs[0].path, "c:\\src\\a.c");
    }

    #[test]
    fn unc_leading_double_separator_is_preserved() {
        assert_eq!(
            collapse_separators("\\\\srv\\\\share\\x"),
            "\\\\srv\\share\\x"
        );
        assert_eq!(collapse_separators("c:\\\\a\\\\\\b"), "c:\\a\\b");
        // A device path keeps its `\\.\` prefix so `is_device` still matches.
        assert!(is_device(&normalize_path("\\\\.\\pipe\\foo", "")));
    }

    #[test]
    fn relative_path_resolves_against_cwd() {
        // A relative open (`main.c`) and the absolute form a sibling process
        // sees must fold to one input — otherwise the same file is counted
        // twice and the input hash depends on which form the app happened to
        // pass.
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.cwd = "C:\\work\\proj".to_string();
        t.events.push(file_event(FileOp::OpenRead, "main.c", 0));
        t.events
            .push(file_event(FileOp::OpenRead, "C:\\work\\proj\\main.c", 0));
        // A `..` in a relative include is resolved lexically.
        t.events
            .push(file_event(FileOp::Probe, "..\\inc\\dep.h", 0));
        let g = build_graph(&[t]);
        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\work\\proj\\main.c"),
            "relative and absolute forms must fold to one entry: {inputs:?}"
        );
        assert_eq!(
            inputs.iter().filter(|p| p.ends_with("main.c")).count(),
            1,
            "main.c must appear exactly once: {inputs:?}"
        );
        assert!(
            inputs.contains(&"c:\\work\\inc\\dep.h"),
            "`..` must resolve lexically against cwd: {inputs:?}"
        );
    }

    #[test]
    fn relative_path_without_cwd_stays_verbatim() {
        // Pre-CWD behavior preserved when the writer couldn't record a cwd:
        // relative paths compare verbatim (stable for a fixed working dir).
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(FileOp::OpenRead, "main.c", 0));
        let g = build_graph(&[t]);
        assert_eq!(g.inputs.len(), 1);
        assert_eq!(g.inputs[0].path, "main.c");
    }

    #[test]
    fn telemetry_process_is_tagged_and_excluded() {
        let mut t = trace(10, 1, "C:\\vctip.exe");
        t.events
            .push(file_event(FileOp::OpenWrite, "C:\\telemetry.dat", 0));
        let g = build_graph(&[t]);
        let n = g.processes.iter().find(|n| n.pid == 10).unwrap();
        assert!(n.tags.iter().any(|x| x == "telemetry"));
        assert!(g.outputs.is_empty()); // its accesses don't pollute the sets
    }
}
