//! Sembazuru tracer: reads the binary trace files written by the interceptor
//! DLL (`hooks/`, format in `docs/trace-format.md`), reconstructs the process
//! tree, and derives a compiler dependency graph (input/output file sets).
//!
//! The C++ side only appends raw events; every interpretation rule — access
//! classification, path normalization, intermediate/telemetry tagging — lives
//! here so it can be changed without touching the hook layer.

pub mod determinism;
pub mod format;
pub mod graph;
pub mod json;
pub mod model;

pub use graph::{DependencyGraph, build_graph, normalize_for_compare};
pub use json::to_string_pretty;
pub use model::{AccessKind, EnvOp, Event, EventKind, FileOp, ProcessOp, RegistryOp, Trace};

/// Crate version, surfaced by the `sembazuru-trace` CLI.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
