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

use sembazuru_agent::intake::submit_to_daemon;
use sembazuru_agent::run_local;
use sembazuru_proto::v0::Command;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Best-effort inference of the action's output files from a clang-cl/cl command
/// line, so the daemon can record them in the action cache (a 2nd identical build
/// then republishes them and skips the compile). Recognizes `/Fo<path>` (the
/// object output); a `/Fo<dir>\` form names the object after the `/c` source.
/// Returns paths as written (relative to cwd = the cache's build root). A wrong
/// or empty guess only disables caching for that action — never a wrong build.
fn infer_outputs(compiler_argv: &[String]) -> Vec<String> {
    let mut source: Option<String> = None;
    let mut fo: Option<String> = None;
    for a in &compiler_argv[1..] {
        if let Some(rest) = a.strip_prefix("/Fo").or_else(|| a.strip_prefix("-Fo")) {
            fo = Some(rest.trim_start_matches(':').to_string());
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
    let declared_outputs = infer_outputs(&command.argv);

    let code = match submit_to_daemon(endpoint, command.clone(), declared_outputs).await {
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
