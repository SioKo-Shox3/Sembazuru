//! Dev driver (not shipped): sends ONE `Execute` with a `VfsExecution` to a
//! worker and exits with the action's code. This drives the worker's read-VFS
//! execution path directly (bypassing the daemon's LocalIntake, which wires the
//! VFS config itself in M6.1c), so the M6.1b gate
//! (hooks/test/m6_worker_vfs_redirect.ps1) can prove the worker injects the hook
//! DLL and supplies inputs on demand.
//!
//! Usage:
//!   exec_vfs <worker_endpoint> <agent_fileserver> <vfs_root> <trace_dir> -- <argv...>
//! e.g.
//!   exec_vfs http://127.0.0.1:50061 127.0.0.1:50072 C:\src C:\trace -- probe.exe C:\src\a.txt

use std::collections::HashMap;

use sembazuru_agent::{ExecOptions, execute_on_channel_with};
use sembazuru_proto::v0::{Command, VfsExecution};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("missing `--` before the command argv")?;
    if sep < 4 {
        return Err(
            "usage: exec_vfs <worker> <agent_fileserver> <vfs_root> <trace_dir> -- <argv...>"
                .into(),
        );
    }
    let worker_endpoint = args[0].clone();
    let agent_fileserver = args[1].clone();
    let vfs_root = args[2].clone();
    let trace_dir = args[3].clone();
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
        }),
    };

    let channel = tonic::transport::Endpoint::from_shared(worker_endpoint)?
        .connect()
        .await?;
    let outcome =
        execute_on_channel_with(channel, command, "exec-vfs".into(), "exec-vfs".into(), opts)
            .await?;
    let code = outcome.exit_code.unwrap_or(-1);
    eprintln!("exec_vfs: states={:?} exit={code}", outcome.states);
    std::process::exit(code);
}
