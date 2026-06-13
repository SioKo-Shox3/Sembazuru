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
use std::path::Path;

use crate::determinism;
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

/// A logical path that `relativize` left relative (no drive, no UNC) lives
/// under the build root; an absolute path lives outside it.
pub fn is_under_build_root(logical: &str) -> bool {
    let b = logical.as_bytes();
    let drive = b.len() >= 2 && b[1] == b':';
    !drive && !logical.starts_with("\\\\")
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

/// One observed input: its build-root-relative logical name (for diagnostics and
/// stability across roots) and the absolute path to re-read on the next build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputEntry {
    pub logical: String,
    pub absolute: String,
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
}

/// Extracts the manifest from a traced run: every input that is not a generated
/// output, as `(logical, absolute)`, plus the relativized command lines. Content
/// is *not* read here — that happens in [`manifest_hash`], so the same manifest
/// can be re-hashed against changed files on a later build.
pub fn input_manifest(graph: &DependencyGraph, cwd: &str) -> InputManifest {
    let outputs = logical_outputs(graph, cwd);
    let mut inputs = Vec::new();
    for inp in &graph.inputs {
        let logical = determinism::relativize(&inp.path, cwd);
        if outputs.contains(&logical) {
            continue; // generated artifact, not a source input
        }
        inputs.push(InputEntry {
            logical,
            absolute: inp.path.clone(),
        });
    }
    let mut cmds: Vec<String> = graph
        .processes
        .iter()
        .map(|p| p.command_line.to_ascii_lowercase().replace(cwd, "."))
        .collect();
    cmds.sort();
    InputManifest { inputs, cmds }
}

/// Recomputes the strong-fingerprint hash by reading each manifest input's
/// *current* content. Same shape as [`input_components`] + [`hash_components`],
/// so it follows the same rules: a build-root-relative input that has gone
/// unreadable is a run-varying transient and is dropped; an absent input outside
/// the root keeps an `absent` marker (a real, stable include-search miss). Thus
/// a meaningful content change moves the hash (cache miss), while build noise
/// does not.
pub fn manifest_hash(manifest: &InputManifest) -> String {
    let mut entries: Vec<String> = Vec::new();
    for inp in &manifest.inputs {
        let content = match std::fs::read(&inp.absolute) {
            Ok(bytes) => determinism::sha256_hex(&bytes),
            Err(_) => {
                if is_under_build_root(&inp.logical) {
                    continue;
                }
                "absent".to_string()
            }
        };
        entries.push(format!("{}\u{0}{content}", inp.logical));
    }
    entries.sort();
    entries.push("--cmd--".to_string());
    entries.extend(manifest.cmds.iter().cloned());
    hash_components(&entries)
}
