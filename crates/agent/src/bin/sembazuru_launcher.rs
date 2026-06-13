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

#[tokio::main]
async fn main() {
    // argv[0] is `sembazuru` itself; argv[1..] is the real compiler command.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("usage: sembazuru <compiler> <args...>");
        std::process::exit(2);
    }

    // The launcher's working directory and environment are what the compiler
    // would have seen — carry them so local fallback and remote execution match.
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let env: HashMap<String, String> = std::env::vars().collect();
    let command = Command { argv, env, cwd };

    let endpoint = env_or("SEMBAZURU_DAEMON", "http://127.0.0.1:50071");

    let code = match submit_to_daemon(endpoint, command.clone(), Vec::new()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sembazuru: daemon unavailable, running locally ({e})");
            run_local(&command).await.unwrap_or(-1)
        }
    };
    std::process::exit(code);
}
