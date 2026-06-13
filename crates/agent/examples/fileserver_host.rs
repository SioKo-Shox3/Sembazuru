//! Dev harness (not shipped): runs the agent data-plane file server on a fixed
//! address so a worker-daemon VFS gate (hooks/test/m6_worker_vfs_redirect.ps1)
//! can point a real worker's `Execute` at it. Identity mode serves the agent's
//! filesystem as-is; remap mode serves bytes from `backing_root` for paths under
//! `logical_root`, so the gate can prove a redirect pulled the AGENT's bytes (not
//! a stale local copy at the logical path).
//!
//! Usage: fileserver_host <addr> [logical_root backing_root]

use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = args
        .first()
        .cloned()
        .ok_or("usage: fileserver_host <addr> [logical_root backing_root]")?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("fileserver_host: file server on {}", listener.local_addr()?);
    if args.len() >= 3 {
        sembazuru_agent::fileserver::serve_files_remap(listener, &args[1], PathBuf::from(&args[2]))
            .await?;
    } else {
        sembazuru_agent::fileserver::serve_files(listener).await?;
    }
    Ok(())
}
