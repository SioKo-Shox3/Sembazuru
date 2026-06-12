//! JSON export of a [`DependencyGraph`] in the shape defined by
//! `docs/trace-format.md` §7.
//!
//! Ordering is intentionally stable: the graph's Vecs were already built from
//! BTreeMaps (and BTreeSets for `kinds`/`pids`) so iteration order is sorted.
//! This module preserves that order and never re-sorts.

use serde::Serialize;

use crate::graph::{DependencyGraph, EnvAccess, PathAccess, ProcessNode, RegistryAccess};

// ---------------------------------------------------------------------------
// Serde mirror structs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct JsonGraph<'a> {
    schema: &'static str,
    root_pid: u32,
    processes: Vec<JsonProcess<'a>>,
    inputs: Vec<JsonPathAccess<'a>>,
    outputs: Vec<JsonPathAccess<'a>>,
    deletions: Vec<JsonPathAccess<'a>>,
    registry: Vec<JsonRegistry<'a>>,
    env: Vec<JsonEnv<'a>>,
    warnings: &'a [String],
}

#[derive(Serialize)]
struct JsonProcess<'a> {
    pid: u32,
    parent_pid: u32,
    exe: &'a str,
    command_line: &'a str,
    children: &'a [u32],
    tags: &'a [String],
}

#[derive(Serialize)]
struct JsonPathAccess<'a> {
    path: &'a str,
    /// Sorted by AccessKind's Ord (which matches alphabetical for these
    /// variants), then rendered as `&'static str` via `as_str()`.
    kinds: Vec<&'static str>,
    pids: Vec<u32>,
}

#[derive(Serialize)]
struct JsonRegistry<'a> {
    key: &'a str,
    value: &'a str,
    pids: Vec<u32>,
}

#[derive(Serialize)]
struct JsonEnv<'a> {
    name: &'a str,
    found: bool,
    pids: Vec<u32>,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn convert_process(n: &ProcessNode) -> JsonProcess<'_> {
    JsonProcess {
        pid: n.pid,
        parent_pid: n.parent_pid,
        exe: &n.exe,
        command_line: &n.command_line,
        children: &n.children,
        tags: &n.tags,
    }
}

fn convert_path(pa: &PathAccess) -> JsonPathAccess<'_> {
    JsonPathAccess {
        path: &pa.path,
        // BTreeSet iterates in sorted order; map to the canonical string form.
        kinds: pa.kinds.iter().map(|k| k.as_str()).collect(),
        pids: pa.pids.iter().copied().collect(),
    }
}

fn convert_registry(ra: &RegistryAccess) -> JsonRegistry<'_> {
    JsonRegistry {
        key: &ra.key,
        value: &ra.value,
        pids: ra.pids.iter().copied().collect(),
    }
}

fn convert_env(ea: &EnvAccess) -> JsonEnv<'_> {
    JsonEnv {
        name: &ea.name,
        found: ea.found,
        pids: ea.pids.iter().copied().collect(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Converts a `DependencyGraph` into a `serde_json::Value` matching §7.
///
/// Ordering is stable: graph Vecs are already BTreeMap-ordered; BTreeSet
/// fields (`kinds`, `pids`) iterate sorted.
pub fn to_json(graph: &DependencyGraph) -> serde_json::Value {
    let jg = JsonGraph {
        schema: "sembazuru-trace/v0",
        root_pid: graph.root_pid,
        processes: graph.processes.iter().map(convert_process).collect(),
        inputs: graph.inputs.iter().map(convert_path).collect(),
        outputs: graph.outputs.iter().map(convert_path).collect(),
        deletions: graph.deletions.iter().map(convert_path).collect(),
        registry: graph.registry.iter().map(convert_registry).collect(),
        env: graph.env.iter().map(convert_env).collect(),
        warnings: &graph.warnings,
    };
    serde_json::to_value(jg).expect("DependencyGraph JSON serialization is infallible")
}

/// Returns the graph as indented JSON (2-space indent, trailing newline).
pub fn to_string_pretty(graph: &DependencyGraph) -> String {
    let v = to_json(graph);
    let mut s =
        serde_json::to_string_pretty(&v).expect("DependencyGraph JSON serialization is infallible");
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::graph::{DependencyGraph, EnvAccess, PathAccess, ProcessNode, RegistryAccess};
    use crate::model::AccessKind;

    fn small_graph() -> DependencyGraph {
        let mut g = DependencyGraph {
            root_pid: 10,
            ..DependencyGraph::default()
        };

        g.processes.push(ProcessNode {
            pid: 10,
            parent_pid: 1,
            exe: "C:\\cl.exe".to_string(),
            command_line: "cl /c hello.c".to_string(),
            children: vec![20],
            tags: vec![],
        });
        g.processes.push(ProcessNode {
            pid: 20,
            parent_pid: 10,
            exe: "C:\\link.exe".to_string(),
            command_line: "link hello.obj".to_string(),
            children: vec![],
            tags: vec!["telemetry".to_string()],
        });

        let mut input_kinds = BTreeSet::new();
        input_kinds.insert(AccessKind::Read);
        input_kinds.insert(AccessKind::Probe);
        let mut input_pids = BTreeSet::new();
        input_pids.insert(10u32);
        g.inputs.push(PathAccess {
            path: "c:\\src\\hello.c".to_string(),
            kinds: input_kinds,
            pids: input_pids,
        });

        let mut output_kinds = BTreeSet::new();
        output_kinds.insert(AccessKind::Write);
        let mut output_pids = BTreeSet::new();
        output_pids.insert(20u32);
        g.outputs.push(PathAccess {
            path: "c:\\src\\hello.obj".to_string(),
            kinds: output_kinds,
            pids: output_pids,
        });

        let mut reg_pids = BTreeSet::new();
        reg_pids.insert(10u32);
        g.registry.push(RegistryAccess {
            key: "HKLM\\SOFTWARE\\Test".to_string(),
            value: "Version".to_string(),
            pids: reg_pids,
        });

        let mut env_pids = BTreeSet::new();
        env_pids.insert(10u32);
        g.env.push(EnvAccess {
            name: "INCLUDE".to_string(),
            found: true,
            pids: env_pids,
        });

        g.warnings.push("test warning".to_string());
        g
    }

    #[test]
    fn schema_string_is_correct() {
        let g = small_graph();
        let v = to_json(&g);
        assert_eq!(v["schema"], "sembazuru-trace/v0");
    }

    #[test]
    fn root_pid_matches() {
        let g = small_graph();
        let v = to_json(&g);
        assert_eq!(v["root_pid"], 10);
    }

    #[test]
    fn input_path_appears_with_correct_kinds() {
        let g = small_graph();
        let v = to_json(&g);
        let inputs = v["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 1);
        let entry = &inputs[0];
        assert_eq!(entry["path"], "c:\\src\\hello.c");
        // AccessKind::Ord: Probe < ProbeMiss < Read ... (alphabetical by Ord)
        // actual Ord is: Read=0, Write=1, Probe=2, ProbeMiss=3, Enumerate=4, Delete=5, Move=6
        // So sorted order: Read, Probe — but BTreeSet sorts by Ord, so Read < Probe
        let kinds = entry["kinds"].as_array().unwrap();
        // Both "read" and "probe" must be present (order stable by Ord)
        let kind_strs: Vec<&str> = kinds.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(kind_strs.contains(&"read"), "expected 'read' in kinds");
        assert!(kind_strs.contains(&"probe"), "expected 'probe' in kinds");
        // Order must be stable: Read comes before Probe in AccessKind Ord
        let read_pos = kind_strs.iter().position(|&s| s == "read").unwrap();
        let probe_pos = kind_strs.iter().position(|&s| s == "probe").unwrap();
        assert!(
            read_pos < probe_pos,
            "Read should sort before Probe per AccessKind Ord"
        );
    }

    #[test]
    fn output_kinds_contain_write() {
        let g = small_graph();
        let v = to_json(&g);
        let outputs = v["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["path"], "c:\\src\\hello.obj");
        let kinds = outputs[0]["kinds"].as_array().unwrap();
        assert_eq!(kinds.len(), 1);
        assert_eq!(kinds[0], "write");
    }

    #[test]
    fn registry_entry_present() {
        let g = small_graph();
        let v = to_json(&g);
        let reg = v["registry"].as_array().unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0]["key"], "HKLM\\SOFTWARE\\Test");
        assert_eq!(reg[0]["value"], "Version");
    }

    #[test]
    fn env_entry_present() {
        let g = small_graph();
        let v = to_json(&g);
        let env = v["env"].as_array().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0]["name"], "INCLUDE");
        assert_eq!(env[0]["found"], true);
    }

    #[test]
    fn warnings_propagated() {
        let g = small_graph();
        let v = to_json(&g);
        let warnings = v["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], "test warning");
    }

    #[test]
    fn to_string_pretty_ends_with_newline() {
        let g = small_graph();
        let s = to_string_pretty(&g);
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn process_children_and_tags() {
        let g = small_graph();
        let v = to_json(&g);
        let procs = v["processes"].as_array().unwrap();
        // processes come from BTreeMap-ordered nodes
        let p10 = procs.iter().find(|p| p["pid"] == 10).unwrap();
        assert_eq!(p10["children"].as_array().unwrap()[0], 20);
        assert_eq!(p10["tags"].as_array().unwrap().len(), 0);
        let p20 = procs.iter().find(|p| p["pid"] == 20).unwrap();
        assert_eq!(p20["tags"].as_array().unwrap()[0], "telemetry");
    }
}
