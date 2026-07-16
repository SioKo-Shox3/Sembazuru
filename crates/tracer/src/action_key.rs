//! The observed-input fingerprint of a traced action — the foundation of the
//! action cache (M4) and the `verify-determinism` input-hash check (M2).
//!
//! Our actions discover their inputs *on demand* (the whole point of the VFS),
//! so an action's true input set is not known until it has run and been traced.
//! These functions turn a trace's [`DependencyGraph`] into the canonical, sorted
//! input set and a stable hash over it. M2 uses the hash to assert two runs saw
//! the same inputs; M4 uses it as the *strong* half of a two-phase action key:
//! the **weak** key (command + env + toolchain, known before running) maps to
//! the observed input *paths*, and re-hashing those paths' current content
//! yields the **strong** key that selects a cached result.
//!
//! The hash here is SHA-256 (`crate::determinism::sha256_hex`), the same content
//! hash M2 has always used — it is an internal *key*, independent of the CAS
//! content digest (ADR 0003: BLAKE3). Keeping it stable avoids rehashing every
//! input and preserves the `verify-determinism --json` mapping byte-for-byte.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io;
use std::path::Path;

use crate::determinism;
use crate::graph::{ENV_BLOCK_NAME, PathAccess, normalize_path};
use crate::model::AccessKind;
use crate::{DependencyGraph, Trace, build_graph, format, normalize_for_compare};

/// Loads every `*.sbzt` trace in `dir`, builds the dependency graph, and returns
/// it with the root process's normalized working directory (the build root used
/// to relativize logical paths). Parse failures on individual files are skipped
/// with a warning; a `read_dir` error is fatal.
pub fn load_run_from_dir(dir: &str) -> Result<(DependencyGraph, String), String> {
    let (traces, skipped) = load_traces_from_dir(dir)?;
    let mut graph = build_graph(&traces);
    // A trace file that could not be read or parsed means a process's observed I/O
    // is missing from the run — its inputs are absent from the graph, so a later
    // edit to one of them would not move the strong key (a stale hit). Surface it
    // as a (cache-blocking) graph warning so `input_manifest` declines to cache the
    // action (COR-003).
    graph.warnings.extend(skipped);
    let cwd = traces
        .iter()
        .find(|t| t.pid == graph.root_pid)
        .map(|t| normalize_for_compare(&t.cwd))
        .unwrap_or_default();
    Ok((graph, cwd))
}

/// Loads every `*.sbzt` trace in `dir`. Returns the parsed traces and a list of
/// human-readable warnings for files that could not be read or parsed (each a
/// dropped process trace — cache-blocking, see [`load_run_from_dir`]). A
/// `read_dir` error is fatal.
fn load_traces_from_dir(dir: &str) -> Result<(Vec<Trace>, Vec<String>), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read directory '{dir}': {e}"))?;

    let mut traces = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("error iterating '{dir}': {e}"))?;
        let path = entry.path();
        if !is_sbzt(&path) {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                skipped.push(format!(
                    "trace file unreadable, dropped from the run: {} ({e})",
                    path.display()
                ));
                continue;
            }
        };
        match format::parse(&bytes) {
            Ok(t) => traces.push(t),
            Err(e) => skipped.push(format!(
                "trace file failed to parse, dropped from the run: {} ({e})",
                path.display()
            )),
        }
    }
    Ok((traces, skipped))
}

/// Returns `true` if `path` has a `.sbzt` extension (case-insensitive).
fn is_sbzt(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| ext.eq_ignore_ascii_case("sbzt"))
        .unwrap_or(false)
}

/// The set of output logical paths (relative to the run's build root `cwd`).
pub fn logical_outputs(graph: &DependencyGraph, cwd: &str) -> BTreeSet<String> {
    graph
        .outputs
        .iter()
        .map(|o| determinism::relativize(&o.path, cwd))
        .collect()
}

/// True only for a pure relative path that stays *strictly under* the build
/// root. Self-contained: it rejects every shape that could name a file outside
/// the root, so callers can use it both to decide cacheability and to gate a
/// `build_root.join(logical)` write.
///
/// Rejected (returns `false`):
///   * drive-absolute `c:\…` or drive-relative `c:foo` (a `:` in position 2);
///   * UNC/device `\\…` or current-drive-rooted `\foo` (a leading `\`);
///   * any path containing a `..` component, which can climb out of the root
///     even from an otherwise-relative path.
///
/// A `/` is treated the same as `\` (some traces keep forward slashes), so a
/// `../x` cannot slip past by spelling. This is the input-side and output-side
/// scope guard for the action cache (BLOCK-B, ADR 0007 §b.3 / M7.1 BLOCK-1).
pub fn is_under_build_root(logical: &str) -> bool {
    let u = logical.replace('/', "\\");
    let b = u.as_bytes();
    // Drive-absolute (`c:\…`) or drive-relative (`c:foo`): a `:` as the second
    // byte means the path is rooted against a drive, not the build root.
    if b.len() >= 2 && b[1] == b':' {
        return false;
    }
    // UNC/device (`\\…`) or current-drive-rooted (`\foo`).
    if u.starts_with('\\') {
        return false;
    }
    // A `..` component escapes upward.
    if u.split('\\').any(|c| c == "..") {
        return false;
    }
    if u.split('\\').any(is_ambiguous_windows_component) {
        return false;
    }
    true
}

fn is_ambiguous_windows_component(component: &str) -> bool {
    if component.is_empty() || component == "." {
        return false;
    }
    if component.contains(':') || component.ends_with('.') || component.ends_with(' ') {
        return true;
    }

    let stem = component.split('.').next().unwrap_or(component);
    let stem_upper = stem.to_ascii_uppercase();
    let reserved = matches!(
        stem_upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || {
        let bytes = stem_upper.as_bytes();
        bytes.len() == 4
            && matches!(&bytes[..3], b"COM" | b"LPT")
            && (b'1'..=b'9').contains(&bytes[3])
    };
    if reserved {
        return true;
    }

    let (name, ext) = component
        .split_once('.')
        .map_or((component, None), |(name, ext)| (name, Some(ext)));
    let Some((prefix, generation)) = name.split_once('~') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.len() <= 6
        && !generation.is_empty()
        && generation
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit())
        && ext.is_none_or(|ext| !ext.is_empty() && ext.len() <= 3 && !ext.contains('.'))
}

/// Anchors a traced input path to a re-readable, drive-absolute form under
/// `root`, reusing the graph's exact normalization so the result folds to the
/// same logical entry. Returns `None` when the path cannot be tied to a stable
/// drive-absolute path — a relative path with no usable (drive-absolute) root,
/// or a UNC/device/drive-relative form. Such an input's *content* cannot be
/// reliably re-hashed on a later build, so a real read of it makes the whole
/// action fail closed (uncacheable) rather than being silently dropped.
fn anchor(root: &str, path: &str) -> Option<String> {
    let normalized = normalize_path(path, root);
    is_drive_absolute(&normalized).then_some(normalized)
}

/// `c:\…` — a drive letter, a colon, and a rooted separator.
fn is_drive_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// Whether a traced access actually *read file content* (so its bytes are a
/// strong-key dependency). A bare metadata probe, an enumerate, or an
/// absent-file miss is not a content read.
fn is_content_read(inp: &PathAccess) -> bool {
    inp.kinds.contains(&AccessKind::Read)
}

/// The sorted, hashable components of a run's input key: one
/// `"logical\0content-hash"` line per source input, then a `--cmd--` marker,
/// then the build-root-relativized command lines. Returned as a list so two
/// runs can be diffed on mismatch rather than just compared by hash.
///
/// Exclusions keep the key stable: generated outputs (`outputs`, trace-derived,
/// including run-varying temps) never count as inputs; and an *unreadable*
/// input under the build root is a build transient (e.g. a temp file probed
/// then renamed away by clang) whose run-varying name would wreck the key — it
/// is dropped, whereas an absent input *outside* the root (a real
/// include-search miss) keeps its `absent` marker.
pub fn input_components(
    graph: &DependencyGraph,
    cwd: &str,
    outputs: &BTreeSet<String>,
) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    for inp in &graph.inputs {
        let logical = determinism::relativize(&inp.path, cwd);
        if outputs.contains(&logical) {
            continue; // a generated artifact, not a source input
        }
        let content = match std::fs::read(&inp.path) {
            Ok(bytes) => determinism::sha256_hex(&bytes),
            Err(_) => {
                if is_under_build_root(&logical) {
                    continue; // build transient with a run-varying name
                }
                "absent".to_string()
            }
        };
        entries.push(format!("{logical}\u{0}{content}"));
    }
    entries.sort();

    let mut cmds: Vec<String> = graph
        .processes
        .iter()
        .map(|p| p.command_line.to_ascii_lowercase().replace(cwd, "."))
        .collect();
    cmds.sort();

    entries.push("--cmd--".to_string());
    entries.extend(cmds);
    entries
}

/// Hashes the input components into the stable input hash.
pub fn hash_components(components: &[String]) -> String {
    let mut blob = String::new();
    for c in components {
        blob.push_str(c);
        blob.push('\n');
    }
    determinism::sha256_hex(blob.as_bytes())
}

/// Convenience: the input hash of a traced run — the sorted observed-input set
/// (excluding generated outputs) plus relativized command lines, hashed. This
/// is the strong-fingerprint material for the action cache and the value
/// `verify-determinism --json` reports.
pub fn input_hash(graph: &DependencyGraph, cwd: &str) -> String {
    let outputs = logical_outputs(graph, cwd);
    hash_components(&input_components(graph, cwd, &outputs))
}

// ---------------------------------------------------------------------------
// Two-phase action-cache material.
// ---------------------------------------------------------------------------
//
// On-demand input discovery means a fresh run's inputs aren't known until it has
// run. The action cache resolves this in two phases (BuildXL's design): the
// *weak* key (command+env+toolchain, known up front) selects an `InputManifest`
// observed by a prior run; re-reading those exact paths' *current* content and
// hashing them ([`manifest_hash`]) yields the *strong* key. If the strong key
// still resolves to a result, nothing changed and the result is reused.

/// How a manifest input contributes to the strong key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// A content dependency: re-read `absolute` and fold its hash. If it has
    /// gone unreadable on a later build, that is a meaningful change — the key
    /// moves and the lookup misses. Its content is *never* dropped from the key.
    Content,
    /// A stable absent dependency (an observed include-search miss): folds an
    /// `absent` marker. If the file later appears, the key moves.
    Absent,
}

/// One observed input: its build-root-relative logical name (for diagnostics and
/// stability across roots), the absolute path to re-read on the next build, and
/// how it keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputEntry {
    pub logical: String,
    pub absolute: String,
    pub kind: InputKind,
}

/// The paths a traced run actually read, plus its relativized command lines —
/// everything needed to recompute the strong fingerprint on a later build
/// *without* re-running the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputManifest {
    pub inputs: Vec<InputEntry>,
    /// Relativized, lowercased command lines, sorted — the command half of the
    /// fingerprint (also folded into the weak key, but kept here so the strong
    /// hash is self-contained and matches `verify-determinism`'s shape).
    pub cmds: Vec<String>,
    /// `false` when a real content read could not be anchored to a stable
    /// drive-absolute path, so the strong key cannot be guaranteed to cover it.
    /// The action must then *not* be cached (input-side fail-closed, ADR 0007
    /// §b.3) — caching it would risk serving a stale result for a changed input
    /// the key never observed.
    pub cacheable: bool,
}

pub struct SideEffectPolicy {
    /// Whether a whole environment block read is known cache-safe.
    pub allow_env_block: bool,
    /// Exact normalized registry key/value pairs known cache-safe.
    pub allowed_registry: Vec<(String, String)>,
    /// Exact normalized dir paths whose enumeration is known cache-safe.
    pub allowed_enumerate: Vec<String>,
}

impl SideEffectPolicy {
    pub fn conservative() -> Self {
        Self {
            allow_env_block: false,
            allowed_registry: Vec::new(),
            allowed_enumerate: Vec::new(),
        }
    }

    fn allows_registry(&self, key: &str, value: &str) -> bool {
        self.allowed_registry
            .iter()
            .any(|(allowed_key, allowed_value)| allowed_key == key && allowed_value == value)
    }

    fn allows_enumerate(&self, dir: &str) -> bool {
        self.allowed_enumerate.iter().any(|s| s == dir)
    }
}

/// Whether a `build_graph` / `load_run_from_dir` warning means a process's reads
/// were genuinely **unobserved** — so the input set is incomplete and the action
/// must not be cached (COR-003). Lost-input signals block: a truncated per-process
/// trace, a spawned child with no trace (an injection gap), an unreadable or
/// unparseable trace file, and "no traces" at all.
///
/// A `"N root processes found"` warning does NOT block. It is a root-ATTRIBUTION
/// ambiguity, not lost I/O — every process's reads are still in the graph — and it
/// legitimately occurs for a multi-process toolchain like clang-cl (driver →
/// `-cc1` frontend), whose input set the M2 determinism gate confirms is complete.
/// Blocking on it would wrongly make every such build uncacheable (the M4 gate
/// regression that surfaced this). Match on the stable substring the warning
/// carries (see `graph.rs`).
fn is_cache_blocking_warning(w: &str) -> bool {
    !w.contains("root processes found")
}

/// Extracts the manifest from a traced run: every input that is not a generated
/// output, anchored to a re-readable absolute path under `root`, plus the
/// relativized command lines.
///
/// `root` is the action's *effective* build root — the declared input root, or
/// the run's working directory. Inputs are anchored against it (so a source the
/// compiler opened by a bare relative name, e.g. via a response file, becomes a
/// real absolute path readable on a later build — the BLOCK-A fix) and their
/// logical names are relativized against it.
///
/// Classification (using the trace's access kinds, `graph.rs`):
///   * anchors and is readable now → [`InputKind::Content`] (its bytes key);
///   * anchors but is unreadable and was a failed probe → [`InputKind::Absent`]
///     (a stable include-search miss), regardless of its root-relative location;
///   * anchors but is unreadable without failed-probe evidence → the action is
///     marked uncacheable, because an observed content read may have vanished;
///   * does **not** anchor *and was a real content read* → the action is marked
///     uncacheable (`cacheable = false`), because the strong key cannot be
///     guaranteed to cover that source's content (input-side fail-closed).
///
/// Content is read here only to classify; [`manifest_hash`] re-reads it on the
/// later build, so the same manifest re-hashes against changed files.
pub fn input_manifest(graph: &DependencyGraph, root: &str) -> InputManifest {
    let policy = SideEffectPolicy::conservative();
    input_manifest_with_policy(graph, root, &policy)
}

pub fn input_manifest_with_policy(
    graph: &DependencyGraph,
    root: &str,
    policy: &SideEffectPolicy,
) -> InputManifest {
    let outputs = logical_outputs(graph, root);
    let mut inputs = Vec::new();
    // COR-003: a trace that failed to OBSERVE some process's reads makes the whole
    // action uncacheable (input-side fail-closed) — a later edit to an unobserved
    // input would not move the strong key, serving a stale result. The action still
    // distributes and runs; it is only not RECORDED (ADR 0007 §c). Only *lost-input*
    // warnings block (see [`is_cache_blocking_warning`]); a benign one — e.g. a
    // root-attribution ambiguity for a multi-process toolchain like clang-cl, whose
    // input set the determinism gate confirms is complete — must NOT, or it would
    // wrongly make those actions uncacheable.
    let blocking: Vec<&str> = graph
        .warnings
        .iter()
        .map(String::as_str)
        .filter(|w| is_cache_blocking_warning(w))
        .collect();
    let mut cacheable = blocking.is_empty();
    if !cacheable {
        eprintln!("sembazuru: action not cached — incomplete trace: {blocking:?}");
    }
    for inp in &graph.inputs {
        let logical = determinism::relativize(&inp.path, root);
        if outputs.contains(&logical) {
            continue; // a generated artifact, not a source input
        }
        match anchor(root, &inp.path) {
            Some(absolute) => match std::fs::read(&absolute) {
                Ok(_) => inputs.push(InputEntry {
                    logical,
                    absolute,
                    kind: InputKind::Content,
                }),
                Err(_) => {
                    // A directory the toolchain probed for existence (an include-
                    // search path — clang-cl and cl `stat`/open every candidate
                    // directory) is NOT a content dependency: the headers resolved
                    // *within* it are tracked as their own Content/Absent inputs, so
                    // a header appearing is still caught (COR-002). Recording the
                    // directory as `Absent` would break every resolve — `std::fs::read`
                    // on a directory errors with PermissionDenied (not NotFound), so
                    // `manifest_hash` re-reads it, hits the non-NotFound arm, and
                    // returns `Err`, which `resolve` treats as a permanent miss (the
                    // clang-cl M4-gate regression). Drop it.
                    if std::fs::metadata(&absolute)
                        .map(|m| m.is_dir())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if inp.kinds.contains(&AccessKind::ProbeMiss) {
                        inputs.push(InputEntry {
                            logical,
                            absolute,
                            kind: InputKind::Absent,
                        });
                    } else {
                        // Location is not proof that an unreadable input was a
                        // self-produced transient. graph.rs removes those from
                        // the surviving input set using their event sequence.
                        cacheable = false;
                    }
                }
            },
            None => {
                // Could not tie this input to a stable absolute path. If it was a
                // real content read, the strong key cannot cover it → fail closed.
                // (A bare probe with no anchor is not a content dependency and
                // does not poison the action.)
                if is_content_read(inp) {
                    cacheable = false;
                }
            }
        }
    }
    // ADR 0014 §3 — fail-closed side-effect policy.
    // Registry value DATA is not recorded by the tracer (only key+name are
    // captured), so a registry QueryValue read can make build output depend on
    // state the action key does not capture -> stale hit. Similarly, directory
    // enumeration MEMBERSHIP is not recorded, and a whole-environment block read
    // pulls in unkeyed/volatile vars. Fail closed: any such read not on the
    // allow-list makes the action uncacheable. The allow-list is empirically
    // populated per ADR 0014 §3 (env-gated) — see docs/deferred.md. Default is
    // empty (maximally safe).
    if cacheable {
        if graph
            .registry
            .iter()
            .any(|r| !policy.allows_registry(&r.key, &r.value))
        {
            cacheable = false;
        }
        if cacheable
            && !policy.allow_env_block
            && graph.env.iter().any(|e| e.name == ENV_BLOCK_NAME)
        {
            cacheable = false;
        }
        if cacheable {
            for entry in &graph.inputs {
                if entry.kinds.contains(&AccessKind::Enumerate)
                    && !policy.allows_enumerate(&entry.path)
                {
                    cacheable = false;
                    break;
                }
            }
        }
    }
    let mut cmds: Vec<String> = graph
        .processes
        .iter()
        .map(|p| p.command_line.to_ascii_lowercase().replace(root, "."))
        .collect();
    cmds.sort();
    InputManifest {
        inputs,
        cmds,
        cacheable,
    }
}

/// Recomputes the strong-fingerprint hash by reading each manifest input's
/// *current* content. Both kinds are **re-evaluated against the filesystem on
/// every build** — neither is ever folded to a constant — so any semantic change
/// (edit, deletion, or a previously-absent file appearing) moves the hash and the
/// lookup misses. Each entry keys per its [`InputKind`]:
///   * [`InputKind::Content`] folds the current content hash. If the file has
///     been deleted/moved (`NotFound`), it folds a `<missing>` marker instead —
///     moving the hash so the lookup *misses* and the action re-runs. A content
///     dependency is **never** silently dropped: dropping it is what let a stale
///     result be served (BLOCK-A).
///   * [`InputKind::Absent`] is re-checked: if the file is *still* absent it
///     folds the stable `absent` marker (keeping the action cacheable); if it has
///     since **appeared** it folds `appeared:<hash>`, moving the key so the stale
///     result is no longer served (COR-002 — the previous code returned a
///     constant `"absent"` and never noticed the file appearing).
///
/// A read error other than `NotFound` (permission denied, sharing violation, the
/// path became a directory) cannot be folded to a fixed token without risking a
/// stale hit, so it is returned as an `Err` — callers treat that as a cache miss
/// (re-run / decline to store), never a hit (input-side fail-closed).
pub fn manifest_hash(manifest: &InputManifest) -> io::Result<String> {
    let mut entries: Vec<String> = Vec::new();
    for inp in &manifest.inputs {
        let token = match inp.kind {
            InputKind::Content => match std::fs::read(&inp.absolute) {
                Ok(bytes) => determinism::sha256_hex(&bytes),
                Err(e) if e.kind() == io::ErrorKind::NotFound => "<missing>".to_string(),
                Err(e) => return Err(e),
            },
            InputKind::Absent => match std::fs::read(&inp.absolute) {
                Ok(bytes) => format!("appeared:{}", determinism::sha256_hex(&bytes)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => "absent".to_string(),
                Err(e) => return Err(e),
            },
        };
        entries.push(format!("{}\u{0}{token}", inp.logical));
    }
    entries.sort();
    entries.push("--cmd--".to_string());
    entries.extend(manifest.cmds.iter().cloned());
    Ok(hash_components(&entries))
}

#[cfg(test)]
mod action_cache_tests {
    use super::*;
    use crate::graph::{EnvAccess, PathAccess, RegistryAccess};
    use crate::model::{EnvOp, Event, EventKind};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn tmp_dir(tag: &str) -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("sbz-actionkey-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn read_access(path: &str) -> PathAccess {
        PathAccess {
            path: path.to_string(),
            kinds: BTreeSet::from([AccessKind::Read]),
            pids: BTreeSet::from([1]),
        }
    }
    fn enumerate_access(path: &str) -> PathAccess {
        PathAccess {
            path: path.to_string(),
            kinds: BTreeSet::from([AccessKind::Enumerate]),
            pids: BTreeSet::from([1]),
        }
    }
    fn probe_access(path: &str) -> PathAccess {
        PathAccess {
            path: path.to_string(),
            kinds: BTreeSet::from([AccessKind::Probe]),
            pids: BTreeSet::from([1]),
        }
    }
    fn probe_miss_access(path: &str) -> PathAccess {
        PathAccess {
            path: path.to_string(),
            kinds: BTreeSet::from([AccessKind::ProbeMiss]),
            pids: BTreeSet::from([1]),
        }
    }
    fn graph_with(inputs: Vec<PathAccess>) -> DependencyGraph {
        DependencyGraph {
            root_pid: 1,
            inputs,
            ..Default::default()
        }
    }
    fn root_str(p: &Path) -> String {
        normalize_for_compare(&p.to_string_lossy())
    }
    fn trace(pid: u32, parent: u32, exe: &str, cwd: &str) -> Trace {
        Trace {
            version: 0,
            pid,
            parent_pid: parent,
            qpc_frequency: 1,
            start_qpc: 0,
            start_filetime: pid as u64,
            exe_path: exe.to_string(),
            command_line: String::new(),
            cwd: cwd.to_string(),
            events: Vec::new(),
            truncated: false,
        }
    }
    fn env_block_event() -> Event {
        Event {
            kind: EventKind::Env {
                op: EnvOp::BlockRead,
            },
            status: 0,
            tid: 1,
            qpc: 0,
            path: String::new(),
            aux: String::new(),
        }
    }
    fn registry_access(key: &str, value: &str) -> RegistryAccess {
        RegistryAccess {
            key: key.to_string(),
            value: value.to_string(),
            pids: BTreeSet::from([1]),
        }
    }
    fn env_access(name: &str) -> EnvAccess {
        EnvAccess {
            name: name.to_string(),
            found: true,
            pids: BTreeSet::from([1]),
        }
    }

    #[test]
    fn a_registry_read_makes_the_action_uncacheable() {
        let root = tmp_dir("registry-blocks");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        g.registry
            .push(registry_access("hklm\\software\\tool", "setting"));

        assert!(!input_manifest(&g, &rs).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_enumeration_makes_the_action_uncacheable() {
        let root = tmp_dir("enumerate-blocks");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        std::fs::create_dir_all(root.join("incdir")).unwrap();
        let rs = root_str(&root);
        let g = graph_with(vec![read_access("a.cpp"), enumerate_access("incdir")]);

        assert!(!input_manifest(&g, &rs).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_whole_environment_block_read_makes_the_action_uncacheable() {
        let root = tmp_dir("env-block");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        g.env.push(env_access(crate::graph::ENV_BLOCK_NAME));

        assert!(!input_manifest(&g, &rs).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_policy_can_allow_env_block_and_exact_directory_enumeration() {
        let root = tmp_dir("env-block-enumerate-allow");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        std::fs::create_dir_all(root.join("incdir")).unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp"), enumerate_access("incdir")]);
        g.env.push(env_access(crate::graph::ENV_BLOCK_NAME));

        assert!(!input_manifest_with_policy(&g, &rs, &SideEffectPolicy::conservative()).cacheable);

        let policy = SideEffectPolicy {
            allow_env_block: true,
            allowed_registry: Vec::new(),
            allowed_enumerate: vec!["incdir".to_string()],
        };

        assert!(input_manifest_with_policy(&g, &rs, &policy).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn env_block_read_through_build_graph_makes_action_uncacheable() {
        let root = tmp_dir("env-block-real-path");
        let rs = root_str(&root);
        let mut t = trace(10, 1, "C:\\cl.exe", &rs);
        t.events.push(env_block_event());
        let g = build_graph(&[t]);

        assert!(g.env.iter().any(|e| e.name == crate::graph::ENV_BLOCK_NAME));
        assert!(!input_manifest(&g, &rs).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_clean_file_only_action_stays_cacheable() {
        let root = tmp_dir("clean-file");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let g = graph_with(vec![read_access("a.cpp")]);

        assert!(input_manifest(&g, &rs).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_single_var_env_read_does_not_block() {
        let root = tmp_dir("env-var");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        g.env.push(env_access("INCLUDE"));

        assert!(input_manifest(&g, &rs).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_allowlisted_registry_read_stays_cacheable() {
        let root = tmp_dir("registry-allow");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        g.registry
            .push(registry_access("hklm\\software\\tool", "setting"));
        let policy = SideEffectPolicy {
            allow_env_block: false,
            allowed_registry: vec![("hklm\\software\\tool".to_string(), "setting".to_string())],
            allowed_enumerate: Vec::new(),
        };

        assert!(input_manifest_with_policy(&g, &rs, &policy).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn registry_allowlist_does_not_match_joined_needle_collision() {
        let root = tmp_dir("registry-allow-collision");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        g.registry
            .push(registry_access("hklm\\software", "tool\\setting"));
        let policy = SideEffectPolicy {
            allow_env_block: false,
            allowed_registry: vec![("hklm\\software\\tool".to_string(), "setting".to_string())],
            allowed_enumerate: Vec::new(),
        };

        assert!(!input_manifest_with_policy(&g, &rs, &policy).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_allowlisted_enumeration_stays_cacheable() {
        let root = tmp_dir("enumerate-allow");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        std::fs::create_dir_all(root.join("incdir")).unwrap();
        let rs = root_str(&root);
        let g = graph_with(vec![read_access("a.cpp"), enumerate_access("incdir")]);
        let policy = SideEffectPolicy {
            allow_env_block: false,
            allowed_registry: Vec::new(),
            allowed_enumerate: vec!["incdir".to_string()],
        };

        assert!(input_manifest_with_policy(&g, &rs, &policy).cacheable);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn is_under_build_root_rejects_every_escape_shape() {
        // Pure relative paths under the root are accepted.
        assert!(is_under_build_root("a.cpp"));
        assert!(is_under_build_root("obj\\a.obj"));
        assert!(is_under_build_root("sub/dir/x")); // forward slashes
        // Rooted-against-a-drive / UNC / device / rooted: rejected.
        assert!(!is_under_build_root("c:\\x"));
        assert!(!is_under_build_root("c:foo")); // drive-relative
        assert!(!is_under_build_root("\\\\srv\\share\\x")); // UNC
        assert!(!is_under_build_root("\\\\.\\pipe\\x")); // device
        assert!(!is_under_build_root("\\foo")); // current-drive-rooted
        // `..` cannot climb out — including spelled with forward slashes.
        assert!(!is_under_build_root("..\\secret"));
        assert!(!is_under_build_root("obj\\..\\..\\secret"));
        assert!(!is_under_build_root("a/../../b"));
    }

    #[test]
    fn path_corpus_is_under_build_root_rejects_ambiguous_relative_components() {
        for logical in [
            "obj\\out.obj:ads",
            "out.",
            "out ",
            "obj\\con",
            "obj\\nul.txt",
            "obj\\com1.obj",
            "obj\\lpt9.log",
            "PROGRA~1\\tool.exe",
            "obj\\LONGFI~12.TXT",
        ] {
            assert!(
                !is_under_build_root(logical),
                "{logical:?} must fail closed"
            );
        }

        assert!(is_under_build_root("obj\\file~backup.obj"));
        assert!(is_under_build_root("temp\\probe.obj"));
    }

    #[test]
    fn bare_relative_source_anchors_to_the_root_and_keys_its_content() {
        // The MSBuild/response-file case: the trace recorded a *bare relative*
        // source name. Anchoring it to the build root must make it a Content
        // dependency whose edit moves the strong key (BLOCK-A: no stale hit).
        let root = tmp_dir("anchor");
        std::fs::write(root.join("a.cpp"), b"v1").unwrap();
        let rs = root_str(&root);

        let g = graph_with(vec![read_access("a.cpp")]);
        let m = input_manifest(&g, &rs);
        assert!(m.cacheable);
        assert_eq!(m.inputs.len(), 1);
        assert_eq!(m.inputs[0].logical, "a.cpp");
        assert_eq!(m.inputs[0].kind, InputKind::Content);
        assert!(is_drive_absolute(&m.inputs[0].absolute));

        let before = manifest_hash(&m).unwrap();
        std::fs::write(root.join("a.cpp"), b"v2-different-bytes").unwrap();
        assert_ne!(
            before,
            manifest_hash(&m).unwrap(),
            "an edited source MUST move the strong key (no stale hit)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn uncoverable_real_read_fails_closed() {
        // A real content read that cannot be anchored to a stable path (no usable
        // build root) makes the whole action uncacheable — never silently key
        // without the source's content.
        let g = graph_with(vec![read_access("a.cpp")]);
        let m = input_manifest(&g, ""); // build root unknown → cannot anchor
        assert!(!m.cacheable, "an uncoverable source must fail closed");
    }

    #[test]
    fn an_incomplete_trace_is_uncacheable() {
        // COR-003: a graph carrying a LOST-INPUT warning (a truncated trace, a
        // child whose injection failed so its I/O is unobserved, a trace file that
        // would not parse, or no traces) means inputs are missing — a later edit to
        // one would not move the strong key. Such an action must be distributed but
        // NEVER recorded (no stale hit), so its manifest is uncacheable regardless
        // of how cleanly its observed inputs anchor.
        let root = tmp_dir("incomplete");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        // With a clean trace this exact action IS cacheable...
        assert!(input_manifest(&g, &rs).cacheable);
        // ...but a single lost-input warning (here: a child-injection gap) blocks it.
        g.warnings
            .push("pid 10 spawned child 99 but no trace file exists".into());
        assert!(
            !input_manifest(&g, &rs).cacheable,
            "an incomplete trace (lost input) must be uncacheable (COR-003)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_root_attribution_warning_does_not_block_caching() {
        // COR-003 refinement: a "N root processes found" warning is a root-
        // ATTRIBUTION ambiguity, not lost I/O (the clang-cl driver→frontend case,
        // which the M4 cache gate caches and the M2 determinism gate proves
        // complete). It must NOT make the action uncacheable — only genuinely
        // lost-input warnings do. (This is the regression that failed CI.)
        let root = tmp_dir("multiroot");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let mut g = graph_with(vec![read_access("a.cpp")]);
        g.warnings
            .push("2 root processes found; using earliest-started pid 10 as root".into());
        assert!(
            input_manifest(&g, &rs).cacheable,
            "a root-attribution warning must not block caching (clang-cl)"
        );
        // ...but a real lost-input warning alongside it still does.
        g.warnings
            .push("trace for pid 10 is truncated (process killed mid-write?)".into());
        assert!(
            !input_manifest(&g, &rs).cacheable,
            "a truncated trace still blocks even with a benign root warning present"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_probed_directory_is_dropped_from_the_inputs() {
        // clang-cl/cl probe include-search DIRECTORIES for existence. A directory is
        // not a content dependency (headers within it are tracked as their own
        // inputs), and `std::fs::read` on a directory errors with PermissionDenied
        // (not NotFound) — recording it as an `Absent` input made `manifest_hash`
        // return `Err` on every resolve, a PERMANENT cache miss (the clang-cl M4
        // regression). The directory must be dropped, the action stay cacheable, and
        // the strong hash be stable (re-readable) across resolves.
        let root = tmp_dir("dirinput");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        std::fs::create_dir_all(root.join("incdir")).unwrap();
        let rs = root_str(&root);
        // A real file read + a probe of an existing directory.
        let g = graph_with(vec![read_access("a.cpp"), probe_access("incdir")]);
        let m = input_manifest(&g, &rs);
        assert!(
            m.cacheable,
            "a directory probe must not make the action uncacheable"
        );
        assert!(
            m.inputs
                .iter()
                .all(|e| !e.absolute.to_ascii_lowercase().contains("incdir")),
            "the probed directory must be dropped from the inputs: {:?}",
            m.inputs.iter().map(|e| &e.absolute).collect::<Vec<_>>()
        );
        assert!(
            m.inputs
                .iter()
                .any(|e| e.absolute.to_ascii_lowercase().contains("a.cpp")),
            "the real file input must remain"
        );
        // The strong hash must recompute without an Err (the bug) and be stable.
        let h1 = manifest_hash(&m).expect("manifest_hash must not Err on a dir-free manifest");
        let h2 = manifest_hash(&m).expect("stable");
        assert_eq!(h1, h2, "strong hash must be stable across resolves");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_run_from_dir_flags_an_unparseable_trace_file() {
        // COR-003 wiring (end-to-end): a `.sbzt` file that fails to parse must
        // surface as a cache-blocking graph warning via load_run_from_dir, not be
        // silently swallowed — so the action it belongs to is not recorded. This
        // exercises the real load_traces_from_dir → load_run_from_dir path (a test
        // that only pushes a synthetic warning would not catch a dropped wiring).
        let root = tmp_dir("badtrace");
        std::fs::write(root.join("garbage.sbzt"), b"this is not a valid sbzt trace").unwrap();
        let dir = root.to_string_lossy().into_owned();
        let (graph, _cwd) = load_run_from_dir(&dir).unwrap();
        assert!(
            graph.warnings.iter().any(|w| w.contains("failed to parse")),
            "an unparseable .sbzt must become a cache-blocking warning: {:?}",
            graph.warnings
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vanished_content_forces_a_miss_rather_than_a_drop() {
        let root = tmp_dir("vanish");
        std::fs::write(root.join("a.cpp"), b"v1").unwrap();
        let rs = root_str(&root);
        let g = graph_with(vec![read_access("a.cpp")]);
        let m = input_manifest(&g, &rs);
        let present = manifest_hash(&m).unwrap();
        // The source disappears (deleted/moved). The key must MOVE (miss), not
        // stay the same by dropping the entry.
        std::fs::remove_file(root.join("a.cpp")).unwrap();
        assert_ne!(
            present,
            manifest_hash(&m).unwrap(),
            "a vanished content input must move the key, not be dropped"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_that_later_appears_moves_the_key() {
        // COR-002 regression: an Absent input (an include-search miss outside the
        // build root) must be RE-CHECKED on every strong-key recompute. If the
        // file later appears — a generated header, a newly-created optional
        // config — the key must MOVE so the prior cached result is not served.
        // The pre-fix code folded a constant `"absent"` and never noticed.
        let root = tmp_dir("appears");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        // The missing header lives *outside* the build root (a real SDK-search
        // miss) so it classifies as Absent rather than a dropped build transient.
        let missing = std::env::temp_dir().join(format!(
            "sbz-appears-hdr-{}-{}.h",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let missing_s = normalize_for_compare(&missing.to_string_lossy());
        let _ = std::fs::remove_file(&missing); // ensure absent at first

        let g = graph_with(vec![read_access("a.cpp"), probe_miss_access(&missing_s)]);
        let m = input_manifest(&g, &rs);
        assert!(m.cacheable);
        assert!(
            m.inputs.iter().any(|e| e.kind == InputKind::Absent),
            "the outside-root miss must be an Absent entry"
        );

        let while_absent = manifest_hash(&m).unwrap();
        // Still absent → stable key (an Absent input must not flap build to build).
        assert_eq!(
            while_absent,
            manifest_hash(&m).unwrap(),
            "a still-absent input keeps a stable key"
        );
        // The file appears. The strong key MUST move (cache miss), not stay put.
        std::fs::write(&missing, b"#pragma once\nnow I exist").unwrap();
        assert_ne!(
            while_absent,
            manifest_hash(&m).unwrap(),
            "an absent input that APPEARS must move the strong key (no stale hit)"
        );

        let _ = std::fs::remove_file(&missing);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_probe_under_build_root_is_keyed_until_it_appears() {
        let root = tmp_dir("root-absent-appears");
        let rs = root_str(&root);
        let missing = root.join("generated\\missing.h");
        let g = graph_with(vec![probe_miss_access("generated\\missing.h")]);

        let m = input_manifest(&g, &rs);
        assert!(m.cacheable);
        assert_eq!(m.inputs.len(), 1, "the in-root miss must remain keyed");
        assert_eq!(m.inputs[0].kind, InputKind::Absent);

        let while_absent = manifest_hash(&m).unwrap();
        std::fs::create_dir_all(missing.parent().unwrap()).unwrap();
        std::fs::write(&missing, b"#pragma once\n").unwrap();
        assert_ne!(
            while_absent,
            manifest_hash(&m).unwrap(),
            "creating an in-root missing header must move the key"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vanished_non_probe_read_fails_closed() {
        let root = tmp_dir("vanished-non-probe");
        let rs = root_str(&root);
        let g = graph_with(vec![read_access("vanished.h")]);

        let m = input_manifest(&g, &rs);
        assert!(
            !m.cacheable,
            "an unreadable content read must not be mistaken for an absent probe"
        );
        assert!(
            m.inputs.is_empty(),
            "a non-probe read must not be recorded as an Absent dependency"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_outside_root_keeps_a_stable_marker() {
        // A failed include-search probe outside the root is a stable `absent`
        // dependency — kept (not poisoning), so the action is still cacheable.
        let root = tmp_dir("absent");
        std::fs::write(root.join("a.cpp"), b"src").unwrap();
        let rs = root_str(&root);
        let g = graph_with(vec![
            read_access("a.cpp"),
            probe_miss_access("c:\\sdk\\missing.h"),
        ]);
        let m = input_manifest(&g, &rs);
        assert!(m.cacheable);
        let absent: Vec<_> = m
            .inputs
            .iter()
            .filter(|e| e.kind == InputKind::Absent)
            .collect();
        assert_eq!(absent.len(), 1, "the outside-root miss is an Absent marker");
        let _ = std::fs::remove_dir_all(&root);
    }
}
