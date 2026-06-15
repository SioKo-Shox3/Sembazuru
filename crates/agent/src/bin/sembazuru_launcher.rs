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

/// Rewrites each `@<path>` response-file argument in `argv` to a
/// content-addressed stable path under `root`. See the call site for why: it
/// makes the action's weak key reproducible across builds. Each rewrite is best
/// effort — a failure leaves the original argument untouched.
fn stabilize_response_files(argv: &mut [String], root: &str) {
    for arg in argv.iter_mut() {
        let Some(path) = arg.strip_prefix('@') else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        if let Some(stable) = stabilize_one(path, root) {
            *arg = format!("@{stable}");
        }
    }
}

/// Materializes the response file at `path` as `<root>\.sembazuru\sbz-rsp-<digest>.rsp`
/// and returns that stable path, or `None` if it cannot be done safely.
///
/// Hardening: the bytes are written to a unique temp sibling and **atomically
/// renamed** into place, then the on-disk file is re-read and its digest
/// re-verified before the path is returned (TOCTOU: only rewrite the argument if
/// the stable file truly holds these exact bytes). Content addressing makes it
/// idempotent — a correct existing copy is reused, and concurrent launchers
/// writing the same digest converge on identical content.
fn stabilize_one(path: &str, root: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let digest: String = sembazuru_cas::Digest::of(&bytes).hex().to_owned();
    let dir = std::path::Path::new(root).join(".sembazuru");
    std::fs::create_dir_all(&dir).ok()?;
    let stable = dir.join(format!("sbz-rsp-{digest}.rsp"));

    // Reuse a correct existing copy (idempotent across builds and launchers).
    // Refuse to trust a pre-placed *symlink* even if its target's bytes hash
    // correctly: on a shared build root an attacker could point it elsewhere and
    // swap the target after the digest check (TOCTOU). Treating a symlink as
    // "not correct" forces the atomic rename below, replacing it with our own
    // regular file before the compiler ever opens it.
    let is_regular = std::fs::symlink_metadata(&stable)
        .map(|m| !m.file_type().is_symlink())
        .unwrap_or(false);
    let already_correct = is_regular
        && std::fs::read(&stable)
            .map(|b| digest == sembazuru_cas::Digest::of(&b).hex())
            .unwrap_or(false);
    if !already_correct {
        let tmp = dir.join(format!("sbz-rsp-{digest}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, &bytes).ok()?;
        if std::fs::rename(&tmp, &stable).is_err() {
            // A racing launcher may have published it first; clean up our temp.
            let _ = std::fs::remove_file(&tmp);
        }
    }

    // Re-verify the on-disk content before trusting the path (TOCTOU).
    let on_disk = std::fs::read(&stable).ok()?;
    (digest == sembazuru_cas::Digest::of(&on_disk).hex())
        .then(|| stable.to_string_lossy().into_owned())
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

    // Declared input root for processes that read above their cwd (ADR 0007 /
    // M8.3); empty = use cwd (the compiler default).
    let input_root = std::env::var("SEMBAZURU_INPUT_ROOT").unwrap_or_default();

    // Stabilize any `@<response-file>` argument before submitting. MSBuild's CL
    // task names the response file with a per-invocation random temp path, so the
    // weak key (an argv hash) would change every build and never cache. Rewriting
    // it to a content-addressed stable path under the build root makes the key
    // reproducible and puts the file where the read-VFS can supply it. On any
    // failure the original argument is kept — the build stays correct, just
    // uncached.
    let rsp_root = if input_root.is_empty() {
        cwd.as_str()
    } else {
        input_root.as_str()
    };
    stabilize_response_files(&mut argv, rsp_root);

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
        input_root,
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
    use super::{infer_outputs, stabilize_response_files};

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

    #[test]
    fn response_file_arg_is_rewritten_to_a_stable_content_addressed_path() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sbz-rsp-test-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Two response files with identical content but different (random) names —
        // the MSBuild case. Both must rewrite to the SAME stable path so the weak
        // key is reproducible across builds.
        let rsp_a = root.join("tmpAAAA.rsp");
        let rsp_b = root.join("tmpBBBB.rsp");
        std::fs::write(&rsp_a, b"/c\na.cpp\nb.cpp\n").unwrap();
        std::fs::write(&rsp_b, b"/c\na.cpp\nb.cpp\n").unwrap();

        let root_s = root.to_string_lossy().into_owned();
        let mut argv_a = vec!["cl".to_string(), format!("@{}", rsp_a.display())];
        let mut argv_b = vec!["cl".to_string(), format!("@{}", rsp_b.display())];
        stabilize_response_files(&mut argv_a, &root_s);
        stabilize_response_files(&mut argv_b, &root_s);

        assert_eq!(
            argv_a[1], argv_b[1],
            "identical content → identical key arg"
        );
        let stable = argv_a[1].strip_prefix('@').unwrap();
        assert!(
            std::path::Path::new(stable).exists(),
            "stable rsp must exist on disk"
        );
        assert_eq!(
            std::fs::read(stable).unwrap(),
            b"/c\na.cpp\nb.cpp\n",
            "stable rsp content matches the original"
        );

        // Different content → different stable path (a changed action must not
        // collide onto the prior key).
        let rsp_c = root.join("tmpCCCC.rsp");
        std::fs::write(&rsp_c, b"/c\na.cpp\nb.cpp\nc.cpp\n").unwrap();
        let mut argv_c = vec!["cl".to_string(), format!("@{}", rsp_c.display())];
        stabilize_response_files(&mut argv_c, &root_s);
        assert_ne!(argv_a[1], argv_c[1], "changed content → changed key arg");

        // A non-response argument is left untouched.
        let mut plain = vec!["cl".to_string(), "/c".to_string(), "a.cpp".to_string()];
        stabilize_response_files(&mut plain, &root_s);
        assert_eq!(plain, vec!["cl", "/c", "a.cpp"]);

        let _ = std::fs::remove_dir_all(&root);
    }
}
