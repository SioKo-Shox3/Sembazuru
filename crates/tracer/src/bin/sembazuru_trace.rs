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
use sembazuru_tracer::{EventKind, FileOp, Trace};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // args[0] is the binary name; look at args[1..].
    match args.get(1).map(String::as_str) {
        Some("export") => cmd_export(&args[2..]),
        Some("diff") => cmd_diff(&args[2..]),
        Some("verify-determinism") => cmd_verify_determinism(&args[2..]),
        Some("diagnose-createfile") => cmd_diagnose_createfile(&args[2..]),
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
            "  verify-determinism\n",
            "           Compare output *bytes* of two runs (M2 determinism gate)\n",
            "  diagnose-createfile\n",
            "           Safely summarize failed CreateFile opens under scratch\n",
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
// `verify-determinism` subcommand
// ---------------------------------------------------------------------------

use sembazuru_tracer::action_key;
use sembazuru_tracer::determinism::{self, Verdict};

/// One run: where its trace files are and where its output files live on disk.
struct Run {
    trace_dir: String,
    work_root: String,
}

fn cmd_verify_determinism(args: &[String]) -> ExitCode {
    let mut trace_a: Option<String> = None;
    let mut root_a: Option<String> = None;
    let mut trace_b: Option<String> = None;
    let mut root_b: Option<String> = None;
    let mut json = false;
    // Explicit output artifacts to compare (work-root-relative), repeatable.
    // When given, these replace trace-derived output discovery — necessary for
    // toolchains (clang/lld) that write to a run-varying temp file and rename
    // it via an NT-level call our Win32 hooks don't see, so the trace only
    // records the transient temp name, never the final artifact.
    let mut outputs: Vec<String> = Vec::new();

    // Path arguments take a value; Windows paths contain ':' and '\', so a
    // packed "dir:root" form would be ambiguous — keep four plain flags.
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let dst = match flag {
            "--trace-a" => Some(&mut trace_a),
            "--root-a" => Some(&mut root_a),
            "--trace-b" => Some(&mut trace_b),
            "--root-b" => Some(&mut root_b),
            "--output" => match args.get(i + 1) {
                Some(v) => {
                    outputs.push(v.clone());
                    i += 2;
                    continue;
                }
                None => {
                    eprintln!("error: --output requires a value");
                    return ExitCode::from(2);
                }
            },
            "--json" => {
                json = true;
                i += 1;
                continue;
            }
            "--help" | "-h" => {
                print!("{}", verify_help());
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("error: unrecognized option '{other}'");
                return ExitCode::from(2);
            }
        };
        // Value-taking flag: consume the next argument.
        match args.get(i + 1) {
            Some(v) => *dst.unwrap() = Some(v.clone()),
            None => {
                eprintln!("error: {flag} requires a value");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }

    let (Some(ta), Some(ra), Some(tb), Some(rb)) = (trace_a, root_a, trace_b, root_b) else {
        eprintln!("error: --trace-a/--root-a and --trace-b/--root-b are all required");
        return ExitCode::from(2);
    };
    let run_a = Run {
        trace_dir: ta,
        work_root: ra,
    };
    let run_b = Run {
        trace_dir: tb,
        work_root: rb,
    };

    let (graph_a, cwd_a) = match action_key::load_run_from_dir(&run_a.trace_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (graph_b, cwd_b) = match action_key::load_run_from_dir(&run_b.trace_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Trace-derived outputs, keyed by logical path relative to the *build*
    // root (the run's recorded cwd). Used to exclude generated artifacts —
    // including run-varying temp files — from the input hash.
    let trace_out_a = action_key::logical_outputs(&graph_a, &cwd_a);
    let trace_out_b = action_key::logical_outputs(&graph_b, &cwd_b);

    // The comparison set: explicit --output artifacts when given (both runs are
    // expected to have each), else the trace-derived outputs per run.
    let (outs_a, outs_b) = if outputs.is_empty() {
        (trace_out_a.clone(), trace_out_b.clone())
    } else {
        let s: BTreeSet<String> = outputs.iter().cloned().collect();
        (s.clone(), s)
    };

    // Input-hash stability: the same logical inputs should hash the same in
    // both runs. Generated outputs (trace-derived, including temp artifacts)
    // are excluded — only true sources count. Kept as component lists so a
    // mismatch can be diffed for the operator.
    let comp_a = action_key::input_components(&graph_a, &cwd_a, &trace_out_a);
    let comp_b = action_key::input_components(&graph_b, &cwd_b, &trace_out_b);
    let in_a = action_key::hash_components(&comp_a);
    let in_b = action_key::hash_components(&comp_b);
    let input_match = in_a == in_b;

    // Compare each logical output present in both runs; flag set mismatches.
    let mut results: Vec<OutResult> = Vec::new();
    let mut all_logical: BTreeSet<&str> = BTreeSet::new();
    all_logical.extend(outs_a.iter().map(String::as_str));
    all_logical.extend(outs_b.iter().map(String::as_str));

    for logical in &all_logical {
        // An output outside the build root keeps an absolute logical path; the
        // two runs can't be matched by relative correspondence, and reading an
        // absolute path would read the same physical file twice (a false
        // Identical). Surface it as a failure rather than a silent pass.
        if logical.len() >= 2 && logical.as_bytes()[1] == b':' {
            results.push(OutResult {
                path: (*logical).to_string(),
                verdict: "outside-build-root".to_string(),
                reasons: Vec::new(),
                output_hash: String::new(),
                unexplained: true,
            });
            continue;
        }
        let in_a = outs_a.contains(*logical);
        let in_b = outs_b.contains(*logical);
        if in_a && in_b {
            let pa = join_root(&run_a.work_root, logical);
            let pb = join_root(&run_b.work_root, logical);
            match (std::fs::read(&pa), std::fs::read(&pb)) {
                (Ok(ba), Ok(bb)) => {
                    let verdict = determinism::compare(&ba, &bb);
                    let out_hash = determinism::sha256_hex(&determinism::normalize(&ba).bytes);
                    results.push(OutResult {
                        path: (*logical).to_string(),
                        verdict: verdict_label(&verdict).to_string(),
                        reasons: verdict_reasons(&verdict),
                        output_hash: out_hash,
                        unexplained: matches!(verdict, Verdict::Differs),
                    });
                }
                _ => results.push(OutResult {
                    path: (*logical).to_string(),
                    verdict: "read-error".to_string(),
                    reasons: Vec::new(),
                    output_hash: String::new(),
                    unexplained: true,
                }),
            }
        } else {
            // Present in one run but not the other: a structural mismatch.
            let label = if in_a { "missing-in-b" } else { "missing-in-a" };
            results.push(OutResult {
                path: (*logical).to_string(),
                verdict: label.to_string(),
                reasons: Vec::new(),
                output_hash: String::new(),
                unexplained: true,
            });
        }
    }

    let unexplained = results.iter().filter(|r| r.unexplained).count();
    let compared = compared_count(&results);
    // The gate keys on OUTPUT byte reproduction (the M2 "Done when") plus the
    // guard that we actually compared something. An input-hash mismatch is a
    // *warning*, not a failure: the tracer can capture run-varying build
    // transients (e.g. clang's temp-file probes) that perturb the input key
    // without the outputs differing — and the outputs are what must reproduce.
    let ok = unexplained == 0 && compared > 0;

    if json {
        print_json_report(&in_a, &in_b, input_match, ok, &results);
    } else {
        if !input_match {
            print_input_diff(&comp_a, &comp_b);
        }
        print_text_report(&in_a, &in_b, input_match, &results);
    }

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

struct OutResult {
    path: String,
    verdict: String,
    reasons: Vec<String>,
    output_hash: String,
    unexplained: bool,
}

fn verdict_label(v: &Verdict) -> &'static str {
    match v {
        Verdict::Identical => "identical",
        Verdict::NormalizedEqual(_) => "normalized-equal",
        Verdict::Differs => "differs",
    }
}

fn verdict_reasons(v: &Verdict) -> Vec<String> {
    match v {
        Verdict::NormalizedEqual(rs) => rs.iter().map(|s| s.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// Number of outputs that were actually byte-compared (not structurally
/// missing, unreadable, or outside the build root). Zero means the gate
/// verified nothing.
fn compared_count(results: &[OutResult]) -> usize {
    results
        .iter()
        .filter(|r| {
            matches!(
                r.verdict.as_str(),
                "identical" | "normalized-equal" | "differs"
            )
        })
        .count()
}

/// Joins a read root and a logical (relative) path into an on-disk path. If the
/// logical path is still absolute (an output outside the build root, which
/// can't be located by relative key), it is returned as-is.
fn join_root(read_root: &str, logical: &str) -> String {
    if logical.len() >= 2 && logical.as_bytes()[1] == b':' {
        return logical.to_string(); // absolute drive path; not under a root
    }
    format!("{}\\{}", read_root.trim_end_matches(['\\', '/']), logical)
}

/// Prints which input components differ between the two runs, so an input-hash
/// mismatch (a warning, not a failure) is diagnosable.
fn print_input_diff(comp_a: &[String], comp_b: &[String]) {
    let sa: BTreeSet<&String> = comp_a.iter().collect();
    let sb: BTreeSet<&String> = comp_b.iter().collect();
    println!("input-set differs (warning — the gate keys on output bytes):");
    for e in sa.difference(&sb) {
        println!("  only in A: {e}");
    }
    for e in sb.difference(&sa) {
        println!("  only in B: {e}");
    }
}

fn print_text_report(in_a: &str, in_b: &str, input_match: bool, results: &[OutResult]) {
    println!("input-hash A: {in_a}");
    println!("input-hash B: {in_b}");
    println!(
        "input-hash match: {}",
        if input_match { "yes" } else { "NO (warning)" }
    );
    println!("outputs:");
    for r in results {
        let reasons = if r.reasons.is_empty() {
            String::new()
        } else {
            format!(" [{}]", r.reasons.join(", "))
        };
        println!("  {:<16} {}{}", r.verdict, r.path, reasons);
        if !r.output_hash.is_empty() {
            println!("      output-hash: {}", r.output_hash);
        }
    }
    let unexplained = results.iter().filter(|r| r.unexplained).count();
    let compared = compared_count(results);
    if compared == 0 {
        println!(
            "\nDETERMINISM FAIL: no outputs were compared (none produced under the build root)"
        );
    } else if unexplained == 0 {
        let note = if input_match {
            ""
        } else {
            " (input-set differed — see warning above)"
        };
        println!(
            "\nDETERMINISM OK: {compared} output(s) reproduce (no unexplained differences){note}"
        );
    } else {
        println!("\nDETERMINISM FAIL: {unexplained} unexplained output difference(s)");
    }
}

fn print_json_report(in_a: &str, in_b: &str, input_match: bool, ok: bool, results: &[OutResult]) {
    // Hand-rolled JSON (the export path uses serde; this keeps the gate output
    // dependency-light and stable). Values here are hashes, fixed labels, and
    // normalized relative paths — none contain characters needing escaping
    // beyond the backslash in paths, which we escape explicitly.
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let compared = compared_count(results);
    println!("{{");
    println!("  \"schema\": \"sembazuru-determinism/v0\",");
    println!("  \"ok\": {ok},");
    println!("  \"compared\": {compared},");
    println!("  \"input_hash\": {{");
    println!("    \"a\": \"{in_a}\",");
    println!("    \"b\": \"{in_b}\",");
    println!("    \"match\": {input_match}");
    println!("  }},");
    println!("  \"outputs\": [");
    for (idx, r) in results.iter().enumerate() {
        let comma = if idx + 1 < results.len() { "," } else { "" };
        let reasons = r
            .reasons
            .iter()
            .map(|s| format!("\"{}\"", esc(s)))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    {{");
        println!("      \"path\": \"{}\",", esc(&r.path));
        println!("      \"verdict\": \"{}\",", r.verdict);
        println!("      \"reasons\": [{reasons}],");
        println!("      \"output_hash\": \"{}\"", r.output_hash);
        println!("    }}{comma}");
    }
    println!("  ]");
    println!("}}");
}

fn verify_help() -> &'static str {
    concat!(
        "Usage: sembazuru-trace verify-determinism \\\n",
        "         --trace-a <DIR> --root-a <DIR> \\\n",
        "         --trace-b <DIR> --root-b <DIR> [--json]\n",
        "\n",
        "Compare the output *bytes* of two runs of the same build (M2). For\n",
        "each surviving output, compare raw bytes; on a difference, mask the\n",
        "documented non-deterministic regions (timestamps, PE Rich header) and\n",
        "compare again. Also checks that the two runs' logical input sets hash\n",
        "identically.\n",
        "\n",
        "Run the same source in two *different* work roots so a byte match\n",
        "proves determinism despite differing absolute paths.\n",
        "\n",
        "Exit codes:\n",
        "  0   Every output is identical or normalized-equal, input hashes match\n",
        "  1   An unexplained output difference, a set mismatch, or input drift\n",
        "  2   Usage error\n",
        "\n",
        "Options:\n",
        "  --trace-a <DIR>  Trace dir for run A (*.sbzt)\n",
        "  --root-a  <DIR>  Work root for run A (where its outputs live)\n",
        "  --trace-b <DIR>  Trace dir for run B\n",
        "  --root-b  <DIR>  Work root for run B\n",
        "  --output  <REL>  Compare this work-root-relative artifact explicitly\n",
        "                   (repeatable). Use when the compiler writes via a\n",
        "                   run-varying temp file + rename the tracer can't see\n",
        "                   (clang/lld); replaces trace-derived output discovery.\n",
        "  --json           Emit a machine-readable report\n",
        "  --help           Print this help\n",
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

// ---------------------------------------------------------------------------
// `diagnose-createfile` subcommand
// ---------------------------------------------------------------------------

const DIAGNOSTIC_SCHEMA: &str = "sembazuru.createfile-diagnostic.v1";
const MAX_DIAGNOSTIC_FAILURES: usize = 32;
const MAX_DIAGNOSTIC_PATH_BYTES: usize = 512;
const ERROR_ACCESS_DENIED: u32 = 5;

struct DiagnoseArgs {
    trace_dir: String,
    exe_name: String,
    scratch_root: String,
}

#[derive(Clone)]
struct WindowsPath {
    volume: String,
    components: Vec<String>,
    normalized: String,
}

struct RawWindowsPath {
    volume: String,
    components: Vec<String>,
}

enum WindowsPathError {
    NotAbsolute,
    Ambiguous,
}

enum ScratchContainment {
    Under,
    Root,
    Outside,
}

#[derive(Serialize)]
struct CreateFileDiagnostic {
    schema: &'static str,
    complete: bool,
    result: &'static str,
    process: String,
    target_traces: usize,
    total_failed: usize,
    emitted: usize,
    omitted: usize,
    reason: &'static str,
    failures: Vec<CreateFileFailure>,
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq)]
struct CreateFileFailure {
    path: String,
    status: u32,
    access: u32,
    disposition: u32,
}

fn cmd_diagnose_createfile(args: &[String]) -> ExitCode {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        print!("{}", diagnose_createfile_help());
        return ExitCode::SUCCESS;
    }
    let parsed = match parse_diagnose_createfile_args(args) {
        Ok(parsed) => parsed,
        Err(()) => {
            eprintln!("error: invalid diagnose-createfile arguments");
            return ExitCode::from(2);
        }
    };
    let report = diagnose_createfile(&parsed);
    println!(
        "{}",
        serde_json::to_string(&report).expect("diagnostic report must serialize")
    );
    diagnostic_exit(&report)
}

fn diagnose_createfile_help() -> &'static str {
    concat!(
        "Usage: sembazuru-trace diagnose-createfile --trace-dir <DIR> --exe-name <BASENAME> --under <ABS_SCRATCH_ROOT>\n",
        "\n",
        "Safely summarize failed CreateFile opens for one process under a private scratch root.\n",
    )
}

fn parse_diagnose_createfile_args(args: &[String]) -> Result<DiagnoseArgs, ()> {
    let mut trace_dir = None;
    let mut exe_name = None;
    let mut scratch_root = None;
    let mut i = 0;
    while i < args.len() {
        let destination = match args[i].as_str() {
            "--trace-dir" => &mut trace_dir,
            "--exe-name" => &mut exe_name,
            "--under" => &mut scratch_root,
            _ => return Err(()),
        };
        let Some(value) = args.get(i + 1) else {
            return Err(());
        };
        if destination.replace(value.clone()).is_some() {
            return Err(());
        }
        i += 2;
    }
    let (Some(trace_dir), Some(exe_name), Some(scratch_root)) = (trace_dir, exe_name, scratch_root)
    else {
        return Err(());
    };
    let scratch_root = match normalize_absolute_windows_path(&scratch_root) {
        Ok(path) => path,
        Err(_) => return Err(()),
    };
    if !is_basename(&exe_name) {
        return Err(());
    }
    Ok(DiagnoseArgs {
        trace_dir,
        exe_name: exe_name.to_ascii_lowercase(),
        scratch_root: scratch_root.normalized,
    })
}

fn is_basename(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['\\', '/'])
        && !value.contains(':')
}

fn normalize_absolute_windows_path(value: &str) -> Result<WindowsPath, WindowsPathError> {
    let raw = parse_absolute_windows_path(value)?;
    let mut components = Vec::new();
    for component in raw.components {
        match component.as_str() {
            "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(WindowsPathError::Ambiguous);
                }
            }
            _ if component.contains(':') || component.contains('\0') => {
                return Err(WindowsPathError::Ambiguous);
            }
            _ => components.push(component),
        }
    }
    let normalized = if raw.volume.starts_with("\\\\") {
        if components.is_empty() {
            raw.volume.clone()
        } else {
            format!("{}\\{}", raw.volume, components.join("\\"))
        }
    } else if components.is_empty() {
        format!("{}\\", raw.volume)
    } else {
        format!("{}\\{}", raw.volume, components.join("\\"))
    };
    Ok(WindowsPath {
        volume: raw.volume,
        components,
        normalized,
    })
}

fn parse_absolute_windows_path(value: &str) -> Result<RawWindowsPath, WindowsPathError> {
    if value.contains('\0') {
        return Err(WindowsPathError::Ambiguous);
    }
    let mut value = value.replace('/', "\\");
    if let Some(remainder) = value.strip_prefix("\\\\?\\") {
        if remainder
            .as_bytes()
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"UNC\\"))
        {
            value = format!("\\\\{}", &remainder[4..]);
        } else {
            value = remainder.to_string();
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return Ok(RawWindowsPath {
            volume: value[..2].to_ascii_uppercase(),
            components: value[3..]
                .split('\\')
                .filter(|component| !component.is_empty())
                .map(str::to_string)
                .collect(),
        });
    }
    let Some(remainder) = value.strip_prefix("\\\\") else {
        return Err(WindowsPathError::NotAbsolute);
    };
    let mut components = remainder
        .split('\\')
        .filter(|component| !component.is_empty());
    let (Some(server), Some(share)) = (components.next(), components.next()) else {
        return Err(WindowsPathError::NotAbsolute);
    };
    if matches!(server, "." | "..") || matches!(share, "." | "..") {
        return Err(WindowsPathError::Ambiguous);
    }
    Ok(RawWindowsPath {
        volume: format!("\\\\{server}\\{share}"),
        components: components.map(str::to_string).collect(),
    })
}

fn escapes_scratch_root(value: &str, root: &WindowsPath) -> Result<bool, WindowsPathError> {
    let raw = parse_absolute_windows_path(value)?;
    if !raw.volume.eq_ignore_ascii_case(&root.volume) {
        return Ok(false);
    }
    let mut components: Vec<String> = Vec::new();
    for component in raw.components {
        match component.as_str() {
            "." => {}
            ".." => {
                if has_root_prefix(&components, &root.components)
                    && components.len() == root.components.len()
                {
                    return Ok(true);
                }
                if components.pop().is_none() {
                    return Err(WindowsPathError::Ambiguous);
                }
            }
            _ => components.push(component),
        }
    }
    Ok(false)
}

fn has_root_prefix(components: &[String], root: &[String]) -> bool {
    components.len() >= root.len()
        && components
            .iter()
            .zip(root)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn diagnose_createfile(args: &DiagnoseArgs) -> CreateFileDiagnostic {
    let entries = match std::fs::read_dir(&args.trace_dir) {
        Ok(entries) => entries,
        Err(_) => return incomplete_report(&args.exe_name, "trace-load-incomplete"),
    };
    let mut traces = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return incomplete_report(&args.exe_name, "trace-load-incomplete");
        };
        let path = entry.path();
        if !is_sbzt(&path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return incomplete_report(&args.exe_name, "trace-load-incomplete");
        };
        let Ok(trace) = format::parse(&bytes) else {
            return incomplete_report(&args.exe_name, "trace-load-incomplete");
        };
        traces.push(trace);
    }
    diagnose_loaded_traces(&args.exe_name, &args.scratch_root, &traces)
}

fn diagnose_loaded_traces(
    exe_name: &str,
    scratch_root: &str,
    traces: &[Trace],
) -> CreateFileDiagnostic {
    let targets: Vec<&Trace> = traces
        .iter()
        .filter(|trace| trace.exe_name() == exe_name)
        .collect();
    if targets.is_empty() {
        return incomplete_report(exe_name, "target-trace-missing");
    }
    if targets.iter().any(|trace| trace.truncated) {
        return incomplete_report_with_targets(exe_name, "target-trace-truncated", targets.len());
    }

    let root = match normalize_absolute_windows_path(scratch_root) {
        Ok(root) => root,
        Err(_) => return incomplete_report(exe_name, "diagnostic-root-invalid"),
    };
    let mut failures = Vec::new();
    let mut outside_failed = 0usize;
    for trace in targets.iter().copied() {
        for event in &trace.events {
            let (op, extra) = match event.kind {
                EventKind::File { op, extra } => (op, extra),
                EventKind::Unknown { .. } if !event.succeeded() => {
                    return incomplete_report_with_targets(
                        exe_name,
                        "target-unknown-failed-event",
                        targets.len(),
                    );
                }
                _ => continue,
            };
            if event.succeeded() {
                continue;
            }
            if op == FileOp::Probe {
                return incomplete_report_with_targets(
                    exe_name,
                    "target-failed-probe-ambiguous",
                    targets.len(),
                );
            }
            if !matches!(
                op,
                FileOp::OpenRead | FileOp::OpenWrite | FileOp::OpenReadWrite
            ) {
                continue;
            }
            let path = match normalize_absolute_windows_path(&event.path) {
                Ok(path) => path,
                Err(WindowsPathError::NotAbsolute) => {
                    return incomplete_report_with_targets(
                        exe_name,
                        "target-failed-open-path-not-absolute",
                        targets.len(),
                    );
                }
                Err(WindowsPathError::Ambiguous) => {
                    return incomplete_report_with_targets(
                        exe_name,
                        "target-failed-open-path-ambiguous",
                        targets.len(),
                    );
                }
            };
            match escapes_scratch_root(&event.path, &root) {
                Ok(true) | Err(_) => {
                    return incomplete_report_with_targets(
                        exe_name,
                        "target-failed-open-path-ambiguous",
                        targets.len(),
                    );
                }
                Ok(false) => {}
            }
            match scratch_containment(&path, &root) {
                ScratchContainment::Root => {
                    return incomplete_report_with_targets(
                        exe_name,
                        "target-failed-open-path-ambiguous",
                        targets.len(),
                    );
                }
                ScratchContainment::Outside => {
                    outside_failed += 1;
                    continue;
                }
                ScratchContainment::Under => {}
            }
            if path.normalized.len() > MAX_DIAGNOSTIC_PATH_BYTES {
                return incomplete_report_with_targets(
                    exe_name,
                    "diagnostic-path-too-long",
                    targets.len(),
                );
            }
            failures.push(CreateFileFailure {
                path: redact_scratch_path(&path, &root),
                status: event.status,
                access: extra as u32,
                disposition: (extra >> 32) as u32,
            });
        }
    }
    failures.sort_by(|left, right| {
        let left_denied = left.status == ERROR_ACCESS_DENIED;
        let right_denied = right.status == ERROR_ACCESS_DENIED;
        right_denied
            .cmp(&left_denied)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.status.cmp(&right.status))
            .then_with(|| left.access.cmp(&right.access))
            .then_with(|| left.disposition.cmp(&right.disposition))
    });
    let total_failed = failures.len() + outside_failed;
    let emitted = failures.len().min(MAX_DIAGNOSTIC_FAILURES);
    failures.truncate(emitted);
    let omitted = total_failed - emitted;
    let result = if total_failed == 0 { "clean" } else { "failed" };
    let reason = if outside_failed > 0 {
        "target-failed-open-outside-scratch"
    } else if total_failed == 0 {
        "no-failed-target-opens"
    } else {
        "failed-target-opens-under-scratch"
    };
    CreateFileDiagnostic {
        schema: DIAGNOSTIC_SCHEMA,
        complete: true,
        result,
        process: exe_name.to_string(),
        target_traces: targets.len(),
        total_failed,
        emitted,
        omitted,
        reason,
        failures,
    }
}

fn scratch_containment(path: &WindowsPath, root: &WindowsPath) -> ScratchContainment {
    if !path.volume.eq_ignore_ascii_case(&root.volume)
        || !has_root_prefix(&path.components, &root.components)
    {
        return ScratchContainment::Outside;
    }
    if path.components.len() == root.components.len() {
        ScratchContainment::Root
    } else {
        ScratchContainment::Under
    }
}

fn redact_scratch_path(path: &WindowsPath, root: &WindowsPath) -> String {
    let suffix = &path.components[root.components.len()..];
    format!("<scratch>\\{}", suffix.join("\\"))
}

fn incomplete_report(exe_name: &str, reason: &'static str) -> CreateFileDiagnostic {
    incomplete_report_with_targets(exe_name, reason, 0)
}

fn incomplete_report_with_targets(
    exe_name: &str,
    reason: &'static str,
    target_traces: usize,
) -> CreateFileDiagnostic {
    CreateFileDiagnostic {
        schema: DIAGNOSTIC_SCHEMA,
        complete: false,
        result: "incomplete",
        process: exe_name.to_string(),
        target_traces,
        total_failed: 0,
        emitted: 0,
        omitted: 0,
        reason,
        failures: Vec::new(),
    }
}

fn diagnostic_exit(report: &CreateFileDiagnostic) -> ExitCode {
    if !report.complete {
        ExitCode::from(3)
    } else if report.result == "clean" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sembazuru_tracer::Event;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    fn trace(exe: &str, events: Vec<Event>) -> Trace {
        Trace {
            version: 0,
            pid: 1,
            parent_pid: 0,
            qpc_frequency: 1,
            start_qpc: 0,
            start_filetime: 0,
            exe_path: exe.to_string(),
            command_line: "secret command line".to_string(),
            cwd: "C:\\private\\cwd".to_string(),
            events,
            truncated: false,
        }
    }

    fn failed_open(op: FileOp, path: &str, status: u32, access: u32, disposition: u32) -> Event {
        Event {
            kind: EventKind::File {
                op,
                extra: u64::from(access) | (u64::from(disposition) << 32),
            },
            status,
            tid: 1,
            qpc: 1,
            path: path.to_string(),
            aux: "secret aux".to_string(),
        }
    }

    fn successful_open(path: &str) -> Event {
        failed_open(FileOp::OpenRead, path, 0, 0, 0)
    }

    fn report_for(traces: &[Trace]) -> CreateFileDiagnostic {
        diagnose_loaded_traces("cl.exe", "C:\\scratch", traces)
    }

    fn temp_dir() -> std::path::PathBuf {
        let suffix = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "sembazuru-trace-diagnostic-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn push_string(bytes: &mut Vec<u8>, value: &str) {
        let units: Vec<u16> = value.encode_utf16().collect();
        bytes.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for unit in units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }

    fn empty_trace_bytes(exe: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SBZT");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        push_string(&mut bytes, exe);
        push_string(&mut bytes, "secret command line");
        push_string(&mut bytes, "C:\\private\\cwd");
        bytes
    }

    #[test]
    fn scratch_open_diagnostic_is_advertised_as_a_cli_subcommand() {
        assert!(top_help().contains("diagnose-createfile"));
    }

    #[test]
    fn scratch_open_diagnostic_decodes_extra_and_filters_unrelated_events() {
        let trace = trace(
            "C:\\tools\\CL.EXE",
            vec![
                failed_open(FileOp::OpenWrite, "C:\\scratch\\denied.tmp", 5, 0x12, 7),
                successful_open("C:\\scratch\\success.tmp"),
                failed_open(FileOp::Delete, "C:\\scratch\\delete.tmp", 5, 1, 1),
                failed_open(FileOp::OpenRead, "C:\\outside\\secret.tmp", 5, 1, 1),
            ],
        );
        let report = report_for(&[trace]);
        assert!(report.complete);
        assert_eq!(report.result, "failed");
        assert_eq!(report.reason, "target-failed-open-outside-scratch");
        assert_eq!(report.total_failed, 2);
        assert_eq!(report.emitted, 1);
        assert_eq!(report.omitted, 1);
        assert_eq!(
            report.failures,
            vec![CreateFileFailure {
                path: "<scratch>\\denied.tmp".to_string(),
                status: 5,
                access: 0x12,
                disposition: 7,
            }]
        );
    }

    #[test]
    fn scratch_open_diagnostic_marks_failed_probe_under_scratch_incomplete() {
        let report = report_for(&[trace(
            "cl.exe",
            vec![failed_open(
                FileOp::Probe,
                "C:\\scratch\\_cl_probe.tmp",
                5,
                0x8000_0000,
                3,
            )],
        )]);
        assert!(!report.complete);
        assert_eq!(report.reason, "target-failed-probe-ambiguous");
        assert_eq!(diagnostic_exit(&report), ExitCode::from(3));
    }

    #[test]
    fn scratch_open_diagnostic_normalizes_components_before_containment() {
        let escaped = report_for(&[trace(
            "cl.exe",
            vec![failed_open(
                FileOp::OpenRead,
                "C:\\scratch\\..\\outside\\secret.tmp",
                5,
                0,
                0,
            )],
        )]);
        assert!(!escaped.complete);
        assert_eq!(escaped.reason, "target-failed-open-path-ambiguous");

        let repeated = report_for(&[trace(
            "cl.exe",
            vec![failed_open(
                FileOp::OpenRead,
                "C:\\scratch\\\\nested\\.\\file.tmp",
                5,
                0,
                0,
            )],
        )]);
        assert!(repeated.complete);
        assert_eq!(repeated.failures[0].path, "<scratch>\\nested\\file.tmp");

        let root = report_for(&[trace(
            "cl.exe",
            vec![failed_open(FileOp::OpenRead, "C:\\scratch", 5, 0, 0)],
        )]);
        assert!(!root.complete);
        assert_eq!(root.reason, "target-failed-open-path-ambiguous");
    }

    #[test]
    fn scratch_open_diagnostic_normalizes_verbatim_drive_and_unc_paths() {
        let verbatim = report_for(&[trace(
            "cl.exe",
            vec![failed_open(
                FileOp::OpenRead,
                "\\\\?\\C:\\scratch\\file.tmp",
                5,
                0,
                0,
            )],
        )]);
        assert!(verbatim.complete);
        assert_eq!(verbatim.failures[0].path, "<scratch>\\file.tmp");

        let unc = diagnose_loaded_traces(
            "cl.exe",
            "\\\\server\\share\\scratch",
            &[trace(
                "cl.exe",
                vec![failed_open(
                    FileOp::OpenRead,
                    "\\\\?\\UNC\\server\\share\\scratch\\file.tmp",
                    5,
                    0,
                    0,
                )],
            )],
        );
        assert!(unc.complete);
        assert_eq!(unc.failures[0].path, "<scratch>\\file.tmp");
    }

    #[test]
    fn scratch_open_diagnostic_marks_failed_unknown_events_incomplete() {
        let unknown = Event {
            kind: EventKind::Unknown {
                record_type: 1,
                op: 99,
            },
            status: 5,
            tid: 1,
            qpc: 1,
            path: "C:\\outside\\secret.tmp".to_string(),
            aux: "secret aux".to_string(),
        };
        let report = report_for(&[trace("cl.exe", vec![unknown])]);
        assert!(!report.complete);
        assert_eq!(report.reason, "target-unknown-failed-event");
        assert_eq!(diagnostic_exit(&report), ExitCode::from(3));
    }

    #[test]
    fn scratch_open_diagnostic_rejects_relative_drive_relative_and_rooted_target_paths() {
        for path in ["relative.tmp", "C:relative.tmp", "\\rooted.tmp"] {
            let report = report_for(&[trace(
                "cl.exe",
                vec![failed_open(FileOp::OpenRead, path, 5, 0, 0)],
            )]);
            assert!(!report.complete, "{path}");
            assert_eq!(report.reason, "target-failed-open-path-not-absolute");
            assert_eq!(diagnostic_exit(&report), ExitCode::from(3));
        }
    }

    #[test]
    fn scratch_open_diagnostic_requires_a_nontruncated_target_trace() {
        let missing = report_for(&[trace("link.exe", Vec::new())]);
        assert!(!missing.complete);
        assert_eq!(missing.reason, "target-trace-missing");

        let mut truncated = trace("cl.exe", Vec::new());
        truncated.truncated = true;
        let report = report_for(&[truncated]);
        assert!(!report.complete);
        assert_eq!(report.reason, "target-trace-truncated");
    }

    #[test]
    fn scratch_open_diagnostic_refuses_a_corrupt_trace_even_with_a_valid_target() {
        let dir = temp_dir();
        std::fs::write(dir.join("good.sbzt"), empty_trace_bytes("cl.exe")).unwrap();
        std::fs::write(dir.join("bad.sbzt"), b"not a trace").unwrap();
        let report = diagnose_createfile(&DiagnoseArgs {
            trace_dir: dir.to_string_lossy().into_owned(),
            exe_name: "cl.exe".to_string(),
            scratch_root: "C:\\scratch".to_string(),
        });
        std::fs::remove_dir_all(dir).unwrap();
        assert!(!report.complete);
        assert_eq!(report.reason, "trace-load-incomplete");
        assert_eq!(report.target_traces, 0);
    }

    #[test]
    fn scratch_open_diagnostic_bounds_and_escapes_paths_without_leaking_scratch_root() {
        let long = format!("C:\\scratch\\{}", "x".repeat(MAX_DIAGNOSTIC_PATH_BYTES));
        let incomplete = report_for(&[trace(
            "cl.exe",
            vec![failed_open(FileOp::OpenRead, &long, 5, 0, 0)],
        )]);
        assert!(!incomplete.complete);
        assert_eq!(incomplete.reason, "diagnostic-path-too-long");

        let report = report_for(&[trace(
            "cl.exe",
            vec![failed_open(
                FileOp::OpenRead,
                "C:\\scratch\\quote\n.tmp",
                5,
                0,
                0,
            )],
        )]);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("<scratch>\\\\quote\\n.tmp"));
        assert!(!json.contains("C:\\\\scratch"));
        assert!(!json.contains('\n'));
    }

    #[test]
    fn scratch_open_diagnostic_sorts_denied_first_and_caps_at_32_records() {
        let mut events = Vec::new();
        for index in (0..34).rev() {
            events.push(failed_open(
                FileOp::OpenRead,
                &format!("C:\\scratch\\{index:02}.tmp"),
                if index == 33 { 5 } else { 3 },
                index,
                index + 100,
            ));
        }
        let report = report_for(&[trace("cl.exe", events)]);
        assert!(report.complete);
        assert_eq!(report.total_failed, 34);
        assert_eq!(report.emitted, 32);
        assert_eq!(report.omitted, 2);
        assert_eq!(report.failures[0].path, "<scratch>\\33.tmp");
        assert_eq!(report.failures[1].path, "<scratch>\\00.tmp");
        assert_eq!(report.failures.last().unwrap().path, "<scratch>\\30.tmp");
    }

    #[test]
    fn scratch_open_diagnostic_reports_clean_when_target_has_no_failed_opens() {
        let report = report_for(&[trace(
            "cl.exe",
            vec![successful_open("C:\\scratch\\ok.tmp")],
        )]);
        assert!(report.complete);
        assert_eq!(report.result, "clean");
        assert_eq!(report.reason, "no-failed-target-opens");
        assert_eq!(diagnostic_exit(&report), ExitCode::SUCCESS);
    }

    #[test]
    fn scratch_open_diagnostic_cli_args_are_strict_and_help_is_available() {
        assert!(diagnose_createfile_help().contains("--under <ABS_SCRATCH_ROOT>"));
        let good = vec![
            "--trace-dir".to_string(),
            "C:\\trace".to_string(),
            "--exe-name".to_string(),
            "cl.exe".to_string(),
            "--under".to_string(),
            "C:\\scratch".to_string(),
        ];
        assert!(parse_diagnose_createfile_args(&good).is_ok());
        for bad in [
            vec!["--trace-dir".to_string()],
            vec!["--trace-dir".to_string(), "C:\\trace".to_string()],
            vec![
                "--trace-dir".to_string(),
                "C:\\trace".to_string(),
                "--exe-name".to_string(),
                "C:\\tools\\cl.exe".to_string(),
                "--under".to_string(),
                "C:\\scratch".to_string(),
            ],
            vec![
                "--trace-dir".to_string(),
                "C:\\trace".to_string(),
                "--exe-name".to_string(),
                "cl.exe".to_string(),
                "--under".to_string(),
                "scratch".to_string(),
            ],
        ] {
            assert!(parse_diagnose_createfile_args(&bad).is_err());
        }
    }
}
