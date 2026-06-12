//! `sembazuru-trace` CLI -- export and diff dependency graphs from binary trace
//! files (`*.sbzt`).
//!
//! Subcommands:
//!   export   Parse a trace directory and print the dependency graph as JSON.
//!   diff     Compare the input/output sets of two trace directories.
//!
//! No third-party argument-parsing crates are used; arguments are handled by
//! hand with `std::env::args`.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;

use sembazuru_tracer::format;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // args[0] is the binary name; look at args[1..].
    match args.get(1).map(String::as_str) {
        Some("export") => cmd_export(&args[2..]),
        Some("diff") => cmd_diff(&args[2..]),
        Some("--version") | Some("-V") => {
            println!("sembazuru-trace {}", sembazuru_tracer::version());
            ExitCode::SUCCESS
        }
        Some("--help") | Some("-h") => {
            print!("{}", top_help());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown subcommand '{other}'");
            eprintln!();
            eprint!("{}", top_help());
            ExitCode::from(2)
        }
        None => {
            eprint!("{}", top_help());
            ExitCode::from(2)
        }
    }
}

fn top_help() -> String {
    format!(
        concat!(
            "sembazuru-trace {}\n",
            "\n",
            "Usage: sembazuru-trace <SUBCOMMAND> [OPTIONS]\n",
            "\n",
            "Subcommands:\n",
            "  export   Parse trace files and print the dependency graph as JSON\n",
            "  diff     Compare input/output sets of two trace directories\n",
            "\n",
            "Flags:\n",
            "  --version   Print version and exit\n",
            "  --help      Print this help and exit\n",
            "\n",
            "Run 'sembazuru-trace <SUBCOMMAND> --help' for subcommand options.\n"
        ),
        sembazuru_tracer::version()
    )
}

// ---------------------------------------------------------------------------
// `export` subcommand
// ---------------------------------------------------------------------------

fn cmd_export(args: &[String]) -> ExitCode {
    let mut trace_dir: Option<String> = None;
    // --json is accepted for forward-compatibility; JSON is the only output
    // format today regardless of whether the flag is present.
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--trace-dir" => {
                i += 1;
                match args.get(i) {
                    Some(v) => trace_dir = Some(v.clone()),
                    None => {
                        eprintln!("error: --trace-dir requires a value");
                        return ExitCode::from(2);
                    }
                }
            }
            "--json" => { /* accepted, currently the only mode */ }
            "--help" | "-h" => {
                print!("{}", export_help());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unrecognized option '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let dir = match trace_dir {
        Some(d) => d,
        None => {
            eprintln!("error: --trace-dir is required");
            return ExitCode::from(2);
        }
    };

    match load_traces_from_dir(&dir) {
        Ok(traces) => {
            let graph = sembazuru_tracer::build_graph(&traces);
            print!("{}", sembazuru_tracer::to_string_pretty(&graph));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn export_help() -> &'static str {
    concat!(
        "Usage: sembazuru-trace export --trace-dir <DIR> [--json]\n",
        "\n",
        "Parse all *.sbzt files in DIR, build a dependency graph, and\n",
        "print it as pretty JSON to stdout.\n",
        "\n",
        "Options:\n",
        "  --trace-dir <DIR>  Directory containing *.sbzt trace files\n",
        "  --json             Select JSON output (default; accepted for\n",
        "                     forward compatibility)\n",
        "  --help             Print this help\n",
    )
}

// ---------------------------------------------------------------------------
// `diff` subcommand
// ---------------------------------------------------------------------------

fn cmd_diff(args: &[String]) -> ExitCode {
    let mut dirs: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--trace-dir" => {
                i += 1;
                match args.get(i) {
                    Some(v) => dirs.push(v.clone()),
                    None => {
                        eprintln!("error: --trace-dir requires a value");
                        return ExitCode::from(2);
                    }
                }
            }
            "--help" | "-h" => {
                print!("{}", diff_help());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unrecognized option '{other}'");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    if dirs.len() != 2 {
        eprintln!(
            "error: diff requires exactly two --trace-dir arguments, got {}",
            dirs.len()
        );
        return ExitCode::from(2);
    }

    let graph_a = match load_traces_from_dir(&dirs[0]) {
        Ok(t) => sembazuru_tracer::build_graph(&t),
        Err(e) => {
            eprintln!("error reading '{}': {e}", dirs[0]);
            return ExitCode::FAILURE;
        }
    };
    let graph_b = match load_traces_from_dir(&dirs[1]) {
        Ok(t) => sembazuru_tracer::build_graph(&t),
        Err(e) => {
            eprintln!("error reading '{}': {e}", dirs[1]);
            return ExitCode::FAILURE;
        }
    };

    let inputs_a: BTreeSet<&str> = graph_a.inputs.iter().map(|p| p.path.as_str()).collect();
    let inputs_b: BTreeSet<&str> = graph_b.inputs.iter().map(|p| p.path.as_str()).collect();
    let outputs_a: BTreeSet<&str> = graph_a.outputs.iter().map(|p| p.path.as_str()).collect();
    let outputs_b: BTreeSet<&str> = graph_b.outputs.iter().map(|p| p.path.as_str()).collect();

    let mut changed = false;

    // Print added/removed inputs.
    for path in inputs_a.difference(&inputs_b) {
        println!("input  - {path}");
        changed = true;
    }
    for path in inputs_b.difference(&inputs_a) {
        println!("input  + {path}");
        changed = true;
    }

    // Print added/removed outputs.
    for path in outputs_a.difference(&outputs_b) {
        println!("output - {path}");
        changed = true;
    }
    for path in outputs_b.difference(&outputs_a) {
        println!("output + {path}");
        changed = true;
    }

    if changed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn diff_help() -> &'static str {
    concat!(
        "Usage: sembazuru-trace diff --trace-dir <DIR_A> --trace-dir <DIR_B>\n",
        "\n",
        "Build a dependency graph from each directory and compare the\n",
        "normalized input and output path sets.\n",
        "\n",
        "Exit codes:\n",
        "  0   Input set AND output set are identical\n",
        "  1   At least one set differs\n",
        "  2   Usage error\n",
        "\n",
        "Options:\n",
        "  --trace-dir <DIR>  Provide a trace directory (pass twice)\n",
        "  --help             Print this help\n",
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reads all `*.sbzt` files in `dir` (case-insensitive extension match),
/// parses each, and returns the successful traces. Parse failures are written
/// to stderr and skipped; `read_dir` errors are fatal.
fn load_traces_from_dir(dir: &str) -> Result<Vec<sembazuru_tracer::Trace>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read directory '{dir}': {e}"))?;

    let mut traces = Vec::new();
    for entry in entries {
        let entry: std::fs::DirEntry =
            entry.map_err(|e| format!("error iterating '{dir}': {e}"))?;
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
            Err(e) => {
                eprintln!("warning: skipping '{}': {e}", path.display());
            }
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
