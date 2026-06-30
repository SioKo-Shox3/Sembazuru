//! Dependency-graph construction: the semantics that define M1's "Done when"
//! (`docs/DESIGN.md` §7) and `docs/trace-format.md` §6.
//!
//! Given the set of per-process traces from one run, this links them into a
//! process tree and folds their events into normalized input/output sets,
//! registry reads, and environment reads. Normalization rules (case folding,
//! relative-path resolution, telemetry tagging) live here and nowhere else.
//!
//! Transients are detected from event sequences, never from path location. A
//! path is non-surviving only when one trace shows it was created in that
//! process and then deleted, or written and then renamed away by that same
//! process. Reads are kept as inputs even when they live under %TMP%/%TEMP% or
//! a directory named `temp`; dropping a real read by location could omit it from
//! the action key and allow a stale cache hit. Cross-process deletes are
//! conservatively not applied to another process's outputs: this keeps a real
//! delete-then-write survivor, at the cost of rare write-then-delete false
//! outputs. False outputs can cause misses, but not stale hits or incomplete
//! republishes.

use std::collections::{BTreeMap, BTreeSet, HashSet};

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
    /// Surviving outputs are not filtered by temp-looking directories: a temp
    /// file that remains on disk is conservative output evidence.
    pub outputs: Vec<PathAccess>,
    /// Files the build deleted or renamed away. Delete removes only an output
    /// produced earlier by the same trace from the surviving output set but
    /// leaves any prior input intact, so a read of a pre-existing file remains
    /// an input even when the file is later deleted. Cross-process deletes do
    /// not remove another trace's output. This survival-based model replaces
    /// the old temp-path substring heuristic and is cache-correct because it
    /// never drops a read merely because of where the file lived.
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
/// Exposed for `action_key`: anchoring a traced input to a re-readable absolute
/// path on a later build uses these exact rules, so the anchored path folds to
/// the same logical entry the graph emits.
pub fn normalize_path(raw: &str, cwd: &str) -> String {
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

/// Canonicalizes an already-absolute path the same way the graph normalizes
/// the paths in its input/output sets, so a caller (e.g. the determinism gate)
/// can derive a work-root prefix that actually matches those entries. Equivalent
/// to normalizing with no cwd: a relative path would be left verbatim, which is
/// not what a work root should be.
pub fn normalize_for_compare(path: &str) -> String {
    normalize_path(path, "")
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

    fn remove_path_for_pid(&mut self, bucket: Bucket, norm: &str, pid: u32) {
        let map = match bucket {
            Bucket::Input => &mut self.inputs,
            Bucket::Output => &mut self.outputs,
            Bucket::Deletion => &mut self.deletions,
        };
        let should_remove = map
            .get_mut(norm)
            .map(|entry| {
                entry.pids.remove(&pid);
                entry.pids.is_empty()
            })
            .unwrap_or(false);
        if should_remove {
            map.remove(norm);
        }
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
        let mut produced: HashSet<String> = HashSet::new();
        for ev in &t.events {
            match &ev.kind {
                EventKind::File { op, .. } => {
                    fold_file(&mut acc, t.pid, *op, ev, &t.cwd, &mut produced);
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

/// Folds one file event into the graph's comparison buckets.
///
/// Transient classification here is survival-based rather than location-based:
/// a successful delete removes only a same-process output from the surviving
/// output set, while preserving any prior input read; a successful move removes
/// the renamed-away source from input/output buckets only when this trace
/// produced that source, then records the destination as an output when it is a
/// real file path. Cross-process deletes never drop another process's output,
/// so trace fold order cannot turn a real delete-then-write survivor into a
/// missing republished output. The intentionally conservative opposite case, a
/// cross-process write-then-delete, may leave a false output and cause a miss.
/// A failed delete or rename leaves any surviving output in place. No
/// temp-directory or substring heuristic is consulted, so a content read under
/// %TMP%/%TEMP% remains an input and is not dropped by location.
fn fold_file(
    acc: &mut Accumulator,
    pid: u32,
    op: FileOp,
    ev: &crate::model::Event,
    cwd: &str,
    produced: &mut HashSet<String>,
) {
    let norm = normalize_path(&ev.path, cwd);
    if is_device(&norm) {
        return; // named pipe / device, not a file
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
            produced.insert(norm.clone());
        }
        FileOp::OpenWrite => {
            acc.add_path(Bucket::Output, &norm, AccessKind::Write, pid);
            produced.insert(norm.clone());
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
            // Only a SUCCESSFUL delete proves the path did not survive the
            // build. A failed delete (sharing violation, EDR/AV lock,
            // incremental-link lock) leaves a genuinely-produced output in
            // place; the hook still emits the event with a non-zero status, so
            // an unconditional removal would drop a real output -> a later
            // cache hit would republish an incomplete result. Keep the deletion
            // record unconditional (matches prior behavior; the deletions set
            // is informational).
            if ok && produced.contains(&norm) {
                acc.remove_path_for_pid(Bucket::Output, &norm, pid);
            }
            acc.add_path(Bucket::Deletion, &norm, AccessKind::Delete, pid);
        }
        FileOp::Move => {
            // Only a SUCCESSFUL rename removes the source and produces the
            // destination. A failed rename leaves the source surviving (do not
            // drop it from outputs) and produces no destination (do not invent
            // a phantom output). Same survival rule as Delete.
            //
            // After a successful rename, the source does not survive the build.
            // If a prior write in this process produced it — the compiler's
            // write-temp-then-rename-onto-the-final-name pattern, e.g. lld via
            // NtSetInformationFile(FileRenameInformation) — drop it from the
            // outputs so a run-varying temp name cannot break output-set
            // comparison, and record it in the separate deletions set. It is
            // deliberately NOT added to inputs: a self-produced transient with a
            // run-varying name must not perturb the input hash (which excludes
            // generated outputs, not arbitrary inputs). lld opens its temp
            // read+write (it memory-maps the output buffer), so the temp was
            // also added to INPUTS by the read side of that open — drop it from
            // both sets, not just outputs, or the run-varying name pollutes the
            // input hash whenever the temp lives outside the build root.
            if ok && produced.contains(&norm) {
                // A successful rename removes the source. Drop it from outputs
                // (it does not survive under its temp name). Only drop it from
                // INPUTS if it was this-process-PRODUCED -- i.e. a prior write
                // in this trace created it (lld
                // OpenReadWrite's its temp and memory-maps the output buffer,
                // so its read side is reading our own output, not a real
                // dependency). A move of a PRE-EXISTING file that was only READ
                // is a real input and MUST stay in the cache key, or a later
                // content change would stale-hit.
                acc.remove_path_for_pid(Bucket::Output, &norm, pid);
                acc.remove_path_for_pid(Bucket::Input, &norm, pid);
            }
            acc.add_path(Bucket::Deletion, &norm, AccessKind::Move, pid);
            if ok && !ev.aux.is_empty() {
                let dst = normalize_path(&ev.aux, cwd);
                if !is_device(&dst) {
                    acc.add_path(Bucket::Output, &dst, AccessKind::Write, pid);
                    produced.insert(dst);
                }
            }
        }
        FileOp::CreateDir => {
            acc.add_path(Bucket::Output, &norm, AccessKind::Write, pid);
            produced.insert(norm.clone());
        }
        FileOp::RemoveDir => {
            // A directory created and then removed by the same process did not
            // survive -- drop it from outputs, mirroring the Delete arm. A
            // FAILED RemoveDir (non-zero status) leaves the directory in place,
            // so gate the removal on success. Deletion record stays
            // unconditional.
            if ok && produced.contains(&norm) {
                acc.remove_path_for_pid(Bucket::Output, &norm, pid);
            }
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
    fn cross_process_delete_then_write_keeps_the_output() {
        let mut driver = trace(10, 1, "C:\\driver.exe");
        driver
            .events
            .push(file_event(FileOp::Delete, "C:\\proj\\bin\\out.dll", 0));

        let mut linker = trace(20, 1, "C:\\link.exe");
        linker
            .events
            .push(file_event(FileOp::OpenWrite, "C:\\proj\\bin\\out.dll", 0));

        let g = build_graph(&[driver.clone(), linker.clone()]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            outs.contains(&"c:\\proj\\bin\\out.dll"),
            "delete-then-write survivor must remain an output: {outs:?}"
        );

        let g = build_graph(&[linker, driver]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            outs.contains(&"c:\\proj\\bin\\out.dll"),
            "trace order must not drop the surviving output: {outs:?}"
        );
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
        // A compiler temp file created and deleted in the same run never
        // survives as an output.
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::OpenWrite, "C:\\build\\_cl_12345.tmp", 0));
        t.events
            .push(file_event(FileOp::Delete, "C:\\build\\_cl_12345.tmp", 0));
        let g = build_graph(&[t]);
        assert!(g.outputs.is_empty(), "transient must not be an output");
        assert_eq!(g.deletions.len(), 1);
        assert_eq!(g.deletions[0].path, "c:\\build\\_cl_12345.tmp");

        // A pre-existing file read before deletion is still a real input. If
        // this were removed from inputs, a later content change could stale-hit.
        let mut t = trace(20, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::OpenRead, "C:\\src\\config.h", 0));
        t.events
            .push(file_event(FileOp::Delete, "C:\\src\\config.h", 0));
        let g = build_graph(&[t]);
        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\src\\config.h"),
            "read-then-delete must stay an input: {inputs:?}"
        );
        assert!(
            g.deletions.iter().any(|d| d.path == "c:\\src\\config.h"),
            "read-then-delete must also record the deletion"
        );
    }

    #[test]
    fn failed_delete_keeps_a_surviving_output() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::OpenWrite, "C:\\proj\\out.o", 0));
        t.events
            .push(file_event(FileOp::Delete, "C:\\proj\\out.o", 5));

        let g = build_graph(&[t]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            outs.contains(&"c:\\proj\\out.o"),
            "stale-hit regression: failed delete must not drop a surviving output: {outs:?}"
        );
    }

    #[test]
    fn created_then_removed_dir_is_not_a_surviving_output() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::CreateDir, "C:\\build\\objs", 0));
        t.events
            .push(file_event(FileOp::RemoveDir, "C:\\build\\objs", 0));

        let g = build_graph(&[t]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            !outs.contains(&"c:\\build\\objs"),
            "created-then-removed directory must not survive as an output: {outs:?}"
        );
        assert!(
            g.deletions.iter().any(|d| d.path == "c:\\build\\objs"),
            "removed directory must be recorded as a deletion"
        );
    }

    #[test]
    fn failed_removedir_keeps_the_directory_output() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::CreateDir, "C:\\build\\objs", 0));
        t.events
            .push(file_event(FileOp::RemoveDir, "C:\\build\\objs", 5));

        let g = build_graph(&[t]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            outs.contains(&"c:\\build\\objs"),
            "failed RemoveDir must keep the surviving directory output: {outs:?}"
        );
    }

    #[test]
    fn failed_move_keeps_source_and_adds_no_phantom_output() {
        let mut t = trace(10, 1, "C:\\link.exe");
        t.events
            .push(file_event(FileOp::OpenWrite, "C:\\work\\a.obj", 0));
        let mut rename = file_event(FileOp::Move, "C:\\work\\a.obj", 5);
        rename.aux = "C:\\work\\final.obj".to_string();
        t.events.push(rename);

        let g = build_graph(&[t]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            outs.contains(&"c:\\work\\a.obj"),
            "failed move must keep the surviving source output: {outs:?}"
        );
        assert!(
            !outs.contains(&"c:\\work\\final.obj"),
            "failed move must not invent a phantom destination output: {outs:?}"
        );
    }

    #[test]
    fn read_then_move_of_preexisting_file_keeps_the_input() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events
            .push(file_event(FileOp::OpenRead, "C:\\src\\config.h", 0));
        let mut rename = file_event(FileOp::Move, "C:\\src\\config.h", 0);
        rename.aux = "C:\\archive\\config.h".to_string();
        t.events.push(rename);

        let g = build_graph(&[t]);
        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\src\\config.h"),
            "read-then-move of a pre-existing file must stay an input: {inputs:?}"
        );
        assert!(
            outs.contains(&"c:\\archive\\config.h"),
            "successful move must record the destination output: {outs:?}"
        );
    }

    #[test]
    fn write_temp_then_rename_yields_only_the_final_output() {
        // The lld / clang-cl pattern, now observable via the NtSetInformationFile
        // hook (M3.1.5): write a run-varying temp, then rename it onto the final
        // name. The surviving output must be ONLY the final artifact; the temp
        // must be neither an output (it is gone) nor an input (it is a
        // self-produced transient that would poison the run-to-run input hash).
        let mut t = trace(10, 1, "C:\\clang-cl.exe");
        t.cwd = "C:\\work".to_string();
        // lld opens its temp READ+WRITE (it memory-maps the output buffer), so
        // the temp lands in BOTH inputs and outputs at the open; the rename must
        // then clear it from both. (OpenWrite alone would make `inputs.is_empty`
        // pass vacuously and hide the input-hash-pollution regression.)
        t.events.push(file_event(
            FileOp::OpenReadWrite,
            "C:\\work\\a-915f50da.obj.tmp",
            0,
        ));
        // Move records source in `path`, destination in `aux`. The hook emits
        // the destination as the NT-form path the buffer carries (\??\C:\...);
        // the reader must normalize it to the same key as the Win32 records.
        let mut rename = file_event(FileOp::Move, "C:\\work\\a-915f50da.obj.tmp", 0);
        rename.aux = "\\??\\C:\\work\\a.obj".to_string();
        t.events.push(rename);

        let g = build_graph(&[t]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(outs, vec!["c:\\work\\a.obj"], "only the final survives");
        assert!(
            g.inputs.is_empty(),
            "the run-varying temp must not become an input: {:?}",
            g.inputs.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        assert!(
            g.deletions
                .iter()
                .any(|d| d.path == "c:\\work\\a-915f50da.obj.tmp"),
            "the renamed-away temp is recorded as a (non-surviving) deletion"
        );
    }

    #[test]
    fn temp_located_reads_are_inputs_transients_are_dropped_by_event_sequence() {
        // COR-006: temp-looking locations are not transients by themselves. A
        // read from any of these locations is a real input; only a create then
        // delete event sequence proves a non-surviving compiler temp.
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(
            FileOp::OpenRead,
            "C:\\temp\\proj\\src\\a.cpp",
            0,
        ));
        t.events.push(file_event(
            FileOp::OpenRead,
            "D:\\work\\temp\\fixtures\\input.dat",
            0,
        ));
        t.events.push(file_event(
            FileOp::OpenRead,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\real_input.h",
            0,
        ));
        t.events.push(file_event(
            FileOp::OpenWrite,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\_cl_abc.tmp",
            0,
        ));
        t.events.push(file_event(
            FileOp::Delete,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\_cl_abc.tmp",
            0,
        ));
        let g = build_graph(&[t]);

        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\temp\\proj\\src\\a.cpp"),
            "a source under C:\\temp must stay an input (COR-006): {inputs:?}"
        );
        assert!(
            inputs.contains(&"d:\\work\\temp\\fixtures\\input.dat"),
            "a source under a \\temp\\ segment must stay an input (COR-006): {inputs:?}"
        );
        assert!(
            inputs.contains(&"c:\\users\\dev\\appdata\\local\\temp\\real_input.h"),
            "a read under the real temp dir must stay an input: {inputs:?}"
        );
        assert!(
            g.outputs.is_empty(),
            "created-then-deleted temp must not be a surviving output: {:?}",
            g.outputs.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn project_root_under_c_temp_is_an_input() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(
            FileOp::OpenRead,
            "C:\\temp\\project\\src\\main.cpp",
            0,
        ));
        let g = build_graph(&[t]);
        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\temp\\project\\src\\main.cpp"),
            "project source under C:\\temp must be an input: {inputs:?}"
        );
    }

    #[test]
    fn source_read_under_percent_temp_is_an_input() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(
            FileOp::OpenRead,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\src\\main.cpp",
            0,
        ));
        let g = build_graph(&[t]);
        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\users\\dev\\appdata\\local\\temp\\src\\main.cpp"),
            "source read under %TEMP% must be an input: {inputs:?}"
        );
    }

    #[test]
    fn compiler_temp_create_write_delete_is_a_transient() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(
            FileOp::OpenWrite,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\_cl_abc.tmp",
            0,
        ));
        t.events.push(file_event(
            FileOp::Delete,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\_cl_abc.tmp",
            0,
        ));
        let g = build_graph(&[t]);
        assert!(
            g.outputs.is_empty(),
            "created-then-deleted temp must not be an output: {:?}",
            g.outputs.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        assert!(
            g.deletions
                .iter()
                .any(|d| d.path == "c:\\users\\dev\\appdata\\local\\temp\\_cl_abc.tmp"),
            "created-then-deleted temp must be recorded as a deletion"
        );
    }

    #[test]
    fn compiler_temp_create_write_rename_is_a_transient() {
        let mut t = trace(10, 1, "C:\\clang-cl.exe");
        t.events.push(file_event(
            FileOp::OpenReadWrite,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\a-915f50da.obj.tmp",
            0,
        ));
        let mut rename = file_event(
            FileOp::Move,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\a-915f50da.obj.tmp",
            0,
        );
        rename.aux = "C:\\work\\a.obj".to_string();
        t.events.push(rename);

        let g = build_graph(&[t]);
        let outs: Vec<&str> = g.outputs.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(outs, vec!["c:\\work\\a.obj"], "only final output survives");
        assert!(
            g.inputs.is_empty(),
            "renamed-away temp must not remain an input: {:?}",
            g.inputs.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn read_temp_file_is_included_as_input() {
        let mut t = trace(10, 1, "C:\\cl.exe");
        t.events.push(file_event(
            FileOp::OpenRead,
            "C:\\Users\\dev\\AppData\\Local\\Temp\\settings.props",
            0,
        ));
        let g = build_graph(&[t]);
        let inputs: Vec<&str> = g.inputs.iter().map(|p| p.path.as_str()).collect();
        assert!(
            inputs.contains(&"c:\\users\\dev\\appdata\\local\\temp\\settings.props"),
            "read-only temp-located file must be an input: {inputs:?}"
        );
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
