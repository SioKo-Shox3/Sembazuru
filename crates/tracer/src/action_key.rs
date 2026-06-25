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
use crate::graph::{PathAccess, normalize_path};
use crate::model::AccessKind;
use crate::{DependencyGraph, Trace, build_graph, format, normalize_for_compare};

/// Loads every `*.sbzt` trace in `dir`, builds the dependency graph, and returns
/// it with the root process's normalized working directory (the build root used
/// to relativize logical paths). Parse failures on individual files are skipped
/// with a warning; a `read_dir` error is fatal.
pub fn load_run_from_dir(dir: &str) -> Result<(DependencyGraph, String), String> {
    let traces = load_traces_from_dir(dir)?;
    let graph = build_graph(&traces);
    let cwd = traces
        .iter()
        .find(|t| t.pid == graph.root_pid)
        .map(|t| normalize_for_compare(&t.cwd))
        .unwrap_or_default();
    Ok((graph, cwd))
}

fn load_traces_from_dir(dir: &str) -> Result<Vec<Trace>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read directory '{dir}': {e}"))?;

    let mut traces = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("error iterating '{dir}': {e}"))?;
        let path = entry.path();
        if !is_sbzt(&path) {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: could not read '{}': {e}", path.display());
                continue;
            }
        };
        match format::parse(&bytes) {
            Ok(t) => traces.push(t),
            Err(e) => eprintln!("warning: skipping '{}': {e}", path.display()),
        }
    }
    Ok(traces)
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
    true
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
    /// A stable absent dependency (an include-search miss outside the root):
    /// folds an `absent` marker. If the file later appears, the key moves.
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
///   * anchors but is unreadable and *outside* the root → [`InputKind::Absent`]
///     (a stable include-search miss);
///   * anchors but is unreadable and *under* the root → a build transient
///     (a renamed-away temp) → dropped, as before;
///   * does **not** anchor *and was a real content read* → the action is marked
///     uncacheable (`cacheable = false`), because the strong key cannot be
///     guaranteed to cover that source's content (input-side fail-closed).
///
/// Content is read here only to classify; [`manifest_hash`] re-reads it on the
/// later build, so the same manifest re-hashes against changed files.
pub fn input_manifest(graph: &DependencyGraph, root: &str) -> InputManifest {
    let outputs = logical_outputs(graph, root);
    let mut inputs = Vec::new();
    let mut cacheable = true;
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
                    if is_under_build_root(&logical) {
                        continue; // build transient with a run-varying name
                    }
                    inputs.push(InputEntry {
                        logical,
                        absolute,
                        kind: InputKind::Absent,
                    });
                }
            },
            None => {
                // Could not tie this input to a stable absolute path. If it was a
                // real content read, the strong key cannot cover it → fail closed.
                // (A bare probe/enumerate with no anchor is not a content
                // dependency and does not poison the action.)
                if is_content_read(inp) {
                    cacheable = false;
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
    use crate::graph::PathAccess;
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
