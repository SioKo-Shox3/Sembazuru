//! Thin CLI over the agent action cache (M4.6), driven by the rebuild gate
//! `hooks/test/m4_cache_rebuild.ps1`. It exposes the two phases so a real traced
//! compile can be cached and a second build resolved against it.
//!
//! ```text
//! cache_cli record  --cache <dir> --trace-dir <dir> --build-root <dir>
//!                   --output <rel> [--output <rel>...] [--exit <n>] -- <argv...>
//! cache_cli resolve --cache <dir> --build-root <dir> -- <argv...>
//! ```
//!
//! `record` derives the weak key from `<argv>` + the current environment,
//! extracts the observed-input manifest from the trace, ingests the named
//! outputs into the CAS, and stores the result. `resolve` recomputes the key,
//! and on a hit republishes the cached outputs under `--build-root` and prints
//! `HIT <exit>` (process exit 0); on a miss it prints `MISS` (process exit 3),
//! so the gate can branch on "compile skipped" vs "must run".

use std::path::PathBuf;
use std::process::ExitCode;

use sembazuru_agent::action_cache::{AgentCache, CacheLookup};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sep = args.iter().position(|a| a == "--");
    let (head, argv) = match sep {
        Some(i) => (&args[..i], args[i + 1..].to_vec()),
        None => {
            eprintln!("cache_cli: missing `--` separator before argv");
            return ExitCode::from(2);
        }
    };
    if head.is_empty() || argv.is_empty() {
        eprintln!("usage: cache_cli <record|resolve> --cache <dir> ... -- <argv...>");
        return ExitCode::from(2);
    }
    let mode = head[0].as_str();

    // Simple --flag value parsing (repeatable --output).
    let mut cache = None;
    let mut trace_dir = None;
    let mut build_root = None;
    let mut outputs: Vec<String> = Vec::new();
    let mut exit_code: i32 = 0;
    let mut i = 1;
    while i < head.len() {
        let flag = head[i].as_str();
        let val = head.get(i + 1).cloned();
        match flag {
            "--cache" => cache = val,
            "--trace-dir" => trace_dir = val,
            "--build-root" => build_root = val,
            "--output" => {
                if let Some(v) = val {
                    outputs.push(v)
                }
            }
            "--exit" => exit_code = val.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
            other => {
                eprintln!("cache_cli: unknown flag {other}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }

    let Some(cache_dir) = cache else {
        eprintln!("cache_cli: --cache is required");
        return ExitCode::from(2);
    };
    let Some(build_root) = build_root else {
        eprintln!("cache_cli: --build-root is required");
        return ExitCode::from(2);
    };
    let agent = match AgentCache::open(&cache_dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("cache_cli: open cache: {e}");
            return ExitCode::FAILURE;
        }
    };
    let env: Vec<(String, String)> = std::env::vars().collect();
    let weak = agent.weak_key(&argv, &env);
    let build_root = PathBuf::from(build_root);

    match mode {
        "record" => {
            let Some(trace_dir) = trace_dir else {
                eprintln!("cache_cli record: --trace-dir is required");
                return ExitCode::from(2);
            };
            let manifest = match agent.manifest_from_trace_dir(&trace_dir) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("cache_cli record: load trace: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match agent.record(&weak, &manifest, &build_root, &outputs, exit_code) {
                Ok(()) => {
                    println!(
                        "RECORDED inputs={} outputs={}",
                        manifest.inputs.len(),
                        outputs.len()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("cache_cli record: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "resolve" => match agent.resolve(&weak, &build_root) {
            Ok(CacheLookup::Hit { exit_code }) => {
                println!("HIT {exit_code}");
                ExitCode::SUCCESS
            }
            Ok(CacheLookup::Miss) => {
                println!("MISS");
                ExitCode::from(3)
            }
            Err(e) => {
                eprintln!("cache_cli resolve: {e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("cache_cli: unknown mode {other}");
            ExitCode::from(2)
        }
    }
}
