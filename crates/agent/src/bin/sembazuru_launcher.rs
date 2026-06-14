//! `sembazuru` — the compiler launcher (M6.0). The build system invokes it as
//! `sembazuru <compiler> <args...>` (e.g. via `CMAKE_<LANG>_COMPILER_LAUNCHER`,
//! which prepends the launcher to the compiler command line). It hands the
//! action to the agent daemon over loopback and exits with the compiler's exit
//! code.
//!
//! **Local fallback is mandatory (DESIGN.md §2).** If the daemon is unreachable
//! or the remote path errors, the launcher runs the compiler locally so the
//! build still completes. A *nonzero* exit from a remote run is NOT a fallback
//! trigger — a compiler that legitimately fails (a syntax error) must surface
//! its own exit code, not be silently re-run.
//!
//!   SEMBAZURU_DAEMON  daemon LocalIntake endpoint (default http://127.0.0.1:50071)

use std::collections::HashMap;

use sembazuru_agent::intake::{SubmitOptions, submit_to_daemon};
use sembazuru_agent::run_local;
use sembazuru_proto::v0::Command;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// The action's declared output files, in ADR 0007 §b priority order:
///   1. external declaration via `SEMBAZURU_OUTPUTS` (`;`-separated paths
///      relative to cwd) — the build-system / arbitrary-process escape hatch;
///   2. else the clang-cl/cl `/Fo` fast-path inference below.
///
/// Empty result = "let the daemon discover outputs from the action trace" (the
/// compiler-independent path, e.g. dxc). A wrong or empty guess only disables
/// caching for that action — never a wrong build.
fn declared_outputs(compiler_argv: &[String]) -> Vec<String> {
    if let Ok(spec) = std::env::var("SEMBAZURU_OUTPUTS") {
        let outs: Vec<String> = spec
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !outs.is_empty() {
            return outs;
        }
    }
    infer_outputs(compiler_argv)
}

/// Best-effort inference of the action's output files from a clang-cl/cl command
/// line — a fast-path for the common compiler case; the general case is
/// trace-based discovery on the daemon (ADR 0007 §b). Recognizes `/Fo<path>`
/// (the object output); a `/Fo<dir>\` form names the object after the `/c`
/// source. Only emits a *glued* `/Fo<path>`: a bare `-Fo` (the space-separated
/// form some tools like dxc use) is left for trace discovery rather than guessed
/// wrong. Returns paths as written (relative to cwd = the cache's build root).
fn infer_outputs(compiler_argv: &[String]) -> Vec<String> {
    let mut source: Option<String> = None;
    let mut fo: Option<String> = None;
    for a in &compiler_argv[1..] {
        if let Some(rest) = a.strip_prefix("/Fo").or_else(|| a.strip_prefix("-Fo")) {
            let p = rest.trim_start_matches(':');
            if !p.is_empty() {
                fo = Some(p.to_string());
            }
        } else if !a.starts_with('/') && !a.starts_with('-') {
            let lower = a.to_ascii_lowercase();
            if lower.ends_with(".cpp")
                || lower.ends_with(".cc")
                || lower.ends_with(".cxx")
                || lower.ends_with(".c")
            {
                source = Some(a.clone());
            }
        }
    }
    let obj_from_source = || {
        source.as_ref().map(|s| {
            let stem = std::path::Path::new(s)
                .file_stem()
                .map(|x| x.to_string_lossy().into_owned())
                .unwrap_or_else(|| "out".into());
            format!("{stem}.obj")
        })
    };
    match fo {
        Some(p) if p.ends_with('\\') || p.ends_with('/') => match obj_from_source() {
            Some(obj) => vec![format!("{p}{obj}")],
            None => Vec::new(),
        },
        Some(p) => vec![p],
        None => obj_from_source().into_iter().collect(),
    }
}

/// A boolean env flag: set and not one of the falsey spellings ("", "0", "false").
fn env_flag(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() {
    // argv[0] is `sembazuru` itself; argv[1..] is the real compiler command.
    let mut argv: Vec<String> = std::env::args().skip(1).collect();

    // MSBuild/VS shim mode (M6.2). CMake/Ninja prepend the launcher to the
    // compiler (`sembazuru cl /c a.cpp`), so argv[0] is already the compiler.
    // MSBuild's CL task instead runs `<CLToolPath>\<CLToolExe> <CL-args>`; pointing
    // CLToolExe at this launcher gives it only the CL args, with no compiler. When
    // SEMBAZURU_SHIM_CC names the real compiler, prepend it so the action is the
    // same `<compiler> <args>` shape the CMake path produces. A Directory.Build.props
    // drop-in sets CLToolExe + this env var (docs/integrations/msbuild).
    if let Ok(cc) = std::env::var("SEMBAZURU_SHIM_CC")
        && !cc.is_empty()
    {
        argv.insert(0, cc);
    }

    if argv.is_empty() {
        eprintln!("usage: sembazuru <compiler> <args...>  (or set SEMBAZURU_SHIM_CC)");
        std::process::exit(2);
    }

    // The launcher's working directory and environment are what the compiler
    // would have seen — carry them so local fallback and remote execution match.
    // The environment is reduced to compiler-relevant variables (M7.1): the full
    // environment can reach a remote worker over the LAN, so forwarding the
    // developer's secrets would leak them off-box (ADR 0006 is LAN-trusted, not
    // "leak everything"). A local fallback re-applies these same variables, so
    // the dropped ones (secrets, worker-internal SEMBAZURU_*) were never needed
    // to compile. Builds with unusual env deps can re-add names via
    // SEMBAZURU_ENV_PASSTHROUGH.
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let full_env: HashMap<String, String> = std::env::vars().collect();
    let env = sembazuru_agent::env_filter::filter_compiler_env(&full_env);
    let command = Command { argv, env, cwd };

    let endpoint = env_or("SEMBAZURU_DAEMON", "http://127.0.0.1:50071");
    let opts = SubmitOptions {
        declared_outputs: declared_outputs(&command.argv),
        // Mark non-byte-reproducible actions (e.g. tests) so the daemon
        // distributes but never caches them (ADR 0007 §c).
        non_deterministic: env_flag("SEMBAZURU_NONDETERMINISTIC"),
        // Strict virtualization for arbitrary processes whose inputs are not
        // co-located on the worker: an unsuppliable input fails the action →
        // local fallback rather than a silent wrong local read (ADR 0007 §a②).
        strict_vfs: env_flag("SEMBAZURU_VFS_STRICT"),
        // Declared input root for processes that read above their cwd (ADR
        // 0007 / M8.3); empty = use cwd (the compiler default).
        input_root: std::env::var("SEMBAZURU_INPUT_ROOT").unwrap_or_default(),
    };

    let code = match submit_to_daemon(endpoint, command.clone(), opts).await {
        Ok((code, note)) => {
            if !note.is_empty() {
                eprintln!("sembazuru: {note}");
            }
            code
        }
        Err(e) => {
            eprintln!("sembazuru: daemon unavailable, running locally ({e})");
            run_local(&command).await.unwrap_or(-1)
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::infer_outputs;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn cl_glued_fo_is_inferred() {
        // The clang-cl/cl fast-path: a glued /Fo<path> is the object output.
        assert_eq!(
            infer_outputs(&argv(&["clang-cl", "/c", "a.cpp", "/Foout\\a.obj"])),
            vec!["out\\a.obj".to_string()]
        );
        // Inferred from the /c source when no /Fo is given.
        assert_eq!(
            infer_outputs(&argv(&["clang-cl", "/c", "a.cpp"])),
            vec!["a.obj".to_string()]
        );
    }

    #[test]
    fn dxc_separated_fo_is_left_for_trace_discovery() {
        // dxc writes `-Fo out.dxil` (space-separated). The old code set fo=Some("")
        // — a bogus empty output that broke recording. Now a bare -Fo emits
        // nothing, so the daemon discovers the real output from the trace.
        assert!(
            infer_outputs(&argv(&[
                "dxc", "-T", "ps_6_0", "-E", "main", "-Fo", "out.dxil", "tri.hlsl"
            ]))
            .is_empty(),
            "a bare -Fo must not be guessed; trace discovery handles it"
        );
        // A glued -Fo<path> form is still honored.
        assert_eq!(
            infer_outputs(&argv(&["dxc", "-Foout.dxil", "tri.hlsl"])),
            vec!["out.dxil".to_string()]
        );
    }

    #[test]
    fn unknown_tool_with_no_recognizable_output_infers_nothing() {
        // An arbitrary process: nothing inferable → empty → trace discovery.
        assert!(infer_outputs(&argv(&["my-tool", "--in", "x", "--out", "y"])).is_empty());
    }
}
