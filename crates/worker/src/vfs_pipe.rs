//! Worker-side VFS named-pipe server (M3.2b). The injected hook DLL, when in
//! VFS mode, asks this server to *hydrate* a path it is about to open for read:
//! the server fetches the bytes from the agent over the data plane
//! ([`crate::fileclient`]), materializes them into a per-session scratch tree,
//! and replies with the local scratch path the DLL should open instead
//! (hydrate-on-open, `docs/decisions/0001-vfs-approach.md`). Keeping the DLL on
//! a local pipe (never the network transport) keeps its re-entrancy-safe surface
//! tiny — the three-layer split is DLL -> worker(pipe) -> agent(data plane).
//!
//! **Wire (byte-mode pipe, matches the C++ client):** each message is a `u32`
//! little-endian length prefix followed by the payload.
//!   * request payload  = the UTF-8 path to hydrate.
//!   * response payload = 1 status byte (0=ok, 1=not-found, 2=error) followed by
//!     the UTF-8 local path to open (empty unless status==0).
//!
//! **M3.2 scope.** A fresh agent connection is made per hydrate (pooling is M3.5
//! latency work); the scratch tree persists for the session and is not yet
//! scrubbed (M3.3 owns output fencing/cleanup).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Mutex;

use crate::fileclient::FileClient;

const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_ERROR: u8 = 2;
const MAX_MSG: u32 = 64 * 1024; // a path message; generous bound

/// Maps an agent-side logical path to its location in the scratch tree by
/// flattening the drive letter: `C:\work\a.cpp` -> `<scratch>\C\work\a.cpp`. The
/// exact scratch layout is invisible to the compiler (it opens the handle we
/// return but records the logical path it asked for), so any stable, collision-
/// free mapping is fine here.
fn scratch_mirror(scratch_root: &Path, logical: &str) -> PathBuf {
    let mut rel = String::with_capacity(logical.len());
    for ch in logical.chars() {
        match ch {
            ':' => {}              // drop the drive colon
            '/' => rel.push('\\'), // normalize separators
            c => rel.push(c),
        }
    }
    let rel = rel.trim_start_matches('\\');
    scratch_root.join(rel)
}

/// Serves the VFS pipe until an unrecoverable error. `pipe_name` is the bare
/// name (the `\\.\pipe\` prefix is added here). Each hydrated path is cached for
/// the session so a re-open is a pipe round-trip with no re-fetch.
pub async fn serve_vfs(
    pipe_name: &str,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    rtt: Duration,
) -> io::Result<()> {
    let full = format!(r"\\.\pipe\{pipe_name}");
    let cache: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&full)?;
    loop {
        server.connect().await?;
        let connected = server;
        // Pre-create the next instance so a client never races a missing pipe.
        server = ServerOptions::new().create(&full)?;

        let cache = cache.clone();
        let scratch = scratch_root.clone();
        tokio::spawn(async move {
            let _ = handle_client(connected, agent_addr, scratch, cache, rtt).await;
        });
    }
}

async fn handle_client(
    mut pipe: NamedPipeServer,
    agent_addr: SocketAddr,
    scratch_root: PathBuf,
    cache: Arc<Mutex<HashMap<String, String>>>,
    rtt: Duration,
) -> io::Result<()> {
    loop {
        let path = match read_msg(&mut pipe).await {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(p) => p,
                Err(_) => {
                    write_response(&mut pipe, STATUS_ERROR, "").await?;
                    continue;
                }
            },
            Ok(None) => return Ok(()), // client closed
            Err(e) => return Err(e),
        };

        let (status, local) = hydrate(&path, agent_addr, &scratch_root, &cache, rtt).await;
        write_response(&mut pipe, status, &local).await?;
    }
}

async fn hydrate(
    path: &str,
    agent_addr: SocketAddr,
    scratch_root: &Path,
    cache: &Arc<Mutex<HashMap<String, String>>>,
    rtt: Duration,
) -> (u8, String) {
    if let Some(local) = cache.lock().await.get(path) {
        return (STATUS_OK, local.clone());
    }

    let mut client = match FileClient::connect_with_rtt(agent_addr, rtt).await {
        Ok(c) => c,
        Err(_) => return (STATUS_ERROR, String::new()),
    };
    match client.fetch(path).await {
        Ok(Some((bytes, _digest))) => {
            let local = scratch_mirror(scratch_root, path);
            if let Some(parent) = local.parent()
                && let Err(_) = tokio::fs::create_dir_all(parent).await
            {
                return (STATUS_ERROR, String::new());
            }
            if tokio::fs::write(&local, &bytes).await.is_err() {
                return (STATUS_ERROR, String::new());
            }
            let local_str = local.to_string_lossy().into_owned();
            cache
                .lock()
                .await
                .insert(path.to_string(), local_str.clone());
            (STATUS_OK, local_str)
        }
        Ok(None) => (STATUS_NOT_FOUND, String::new()),
        Err(_) => (STATUS_ERROR, String::new()),
    }
}

/// Reads one length-prefixed message. Returns `None` on a clean EOF before any
/// bytes (client disconnected between requests).
async fn read_msg(pipe: &mut NamedPipeServer) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match pipe.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vfs pipe message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    pipe.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_response(pipe: &mut NamedPipeServer, status: u8, local: &str) -> io::Result<()> {
    let mut payload = Vec::with_capacity(1 + local.len());
    payload.push(status);
    payload.extend_from_slice(local.as_bytes());
    pipe.write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    pipe.write_all(&payload).await?;
    pipe.flush().await
}
