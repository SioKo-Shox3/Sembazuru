//! Dev driver (not shipped): sends ONE `Execute` with a `VfsExecution` to a
//! worker and exits with the action's code. This drives the worker's read-VFS
//! execution path directly (bypassing the daemon's LocalIntake, which wires the
//! VFS config itself in M6.1c), so the M6.1b gate
//! (hooks/test/m6_worker_vfs_redirect.ps1) can prove the worker injects the hook
//! DLL and supplies inputs on demand.
//!
//! Usage:
//!   exec_vfs <worker_endpoint> <agent_fileserver> <vfs_root> <trace_dir|--empty-trace-dir> -- <argv...>
//! e.g.
//!   exec_vfs http://127.0.0.1:50061 127.0.0.1:50072 C:\src C:\trace -- probe.exe C:\src\a.txt

use std::collections::HashMap;

use sembazuru_agent::{ExecOptions, execute_on_channel_with};
use sembazuru_proto::v0::{Command, VfsExecution};

const EMPTY_TRACE_DIR_SENTINEL: &str = "--empty-trace-dir";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("missing `--` before the command argv")?;
    if sep < 4 {
        return Err(
            "usage: exec_vfs <worker> <agent_fileserver> <vfs_root> <trace_dir|--empty-trace-dir> -- <argv...>"
                .into(),
        );
    }
    let worker_endpoint = args[0].clone();
    let agent_fileserver = args[1].clone();
    let vfs_root = args[2].clone();
    let trace_dir = if args[3] == EMPTY_TRACE_DIR_SENTINEL {
        String::new()
    } else {
        args[3].clone()
    };
    let argv: Vec<String> = args[sep + 1..].to_vec();
    if argv.is_empty() {
        return Err("empty command argv".into());
    }

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Full env so the injected launcher/compiler has PATH etc. (the worker sets
    // the child env explicitly from this, plus the VFS vars).
    let env: HashMap<String, String> = std::env::vars().collect();
    let command = Command { argv, env, cwd };

    let opts = ExecOptions {
        predicted_paths: Vec::new(),
        vfs: Some(VfsExecution {
            agent_fileserver,
            vfs_root,
            trace_dir,
            strict: false,
            allow_original_cwd: false,
        }),
    };

    let channel = tonic::transport::Endpoint::from_shared(worker_endpoint)?
        .connect()
        .await?;
    let outcome = execute_on_channel_with(
        channel,
        command,
        "exec-vfs".into(),
        // This dev harness bypasses the daemon, so no agent-side session
        // registry entry exists. Use the legacy empty session id accepted by
        // fileserver_host; production intake still mints a bound session id.
        String::new(),
        opts,
        Vec::new(),
    )
    .await?;
    let code = outcome.exit_code.unwrap_or(-1);
    println!("exec_vfs: states={:?} exit={code}", outcome.states);
    std::process::exit(code);
}
