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
        Some("verify-determinism") => cmd_verify_determinism(&args[2..]),
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
