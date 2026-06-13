//! Dev harness (not shipped): co-locates the agent file server and the worker
//! VFS pipe in one process, so an end-to-end read-VFS redirect can be exercised
//! locally (hooks/test/vfs_redirect.ps1) without a real two-machine split. The
//! file server serves the agent's filesystem identity-mapped; the pipe hydrates
//! requested reads into the scratch dir.
//!
//! Usage: vfs_host <pipe_name> <scratch_dir> [logical_root backing_root]
//!
//! With the optional logical/backing pair, the file server remaps reads under
//! logical_root to backing_root, so the bytes the agent supplies differ from
//! whatever sits at the logical path locally (used by the redirect gate to prove
//! content provenance). Without it, the server serves identity-mapped.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: vfs_host <pipe_name> <scratch_dir> [logical_root backing_root]");
        std::process::exit(2);
    }
    let pipe_name = args[0].clone();
    let scratch = PathBuf::from(&args[1]);
    let remap = if args.len() >= 4 {
        Some((args[2].clone(), PathBuf::from(&args[3])))
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let r = match remap {
            Some((logical, backing)) => {
                sembazuru_agent::fileserver::serve_files_remap(listener, &logical, backing).await
            }
            None => sembazuru_agent::fileserver::serve_files(listener).await,
        };
        let _ = r;
    });
    eprintln!("vfs_host: file server on {addr}, pipe {pipe_name}");
    sembazuru_worker::vfs_pipe::serve_vfs(&pipe_name, addr, scratch).await?;
    Ok(())
}
