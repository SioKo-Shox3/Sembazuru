//! Measures production file-server fetch I/O after the session snapshot and CAS
//! are warm.
//! Run with `cargo run -p sembazuru-agent --example fileserver_range_bench --release`.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sembazuru_agent::fileserver::{ServerStats, serve_files_with_stats_token};
use sembazuru_agent::session_registry::SessionRegistry;
use sembazuru_cas::Digest;
use sembazuru_worker::fileclient::FileClient;

const MIB: usize = 1024 * 1024;
const SIZE_MIB: usize = 64;

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("fileserver_range_bench: {error}");
        std::process::exit(1);
    }
}

async fn run() -> io::Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = TempRoot(std::env::temp_dir().join(format!(
        "sembazuru-fileserver-range-bench.{}.{}",
        std::process::id(),
        nonce
    )));
    std::fs::create_dir_all(&root.0)?;
    let source_path = root.0.join("source.bin");
    let source: Vec<u8> = (0..SIZE_MIB * MIB)
        .map(|index| (index % 251) as u8)
        .collect();
    let expected_digest = Digest::of(&source);
    std::fs::write(&source_path, &source)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let registry = Arc::new(SessionRegistry::new()?);
    let session_id = "fileserver-range-bench".to_string();
    registry
        .create(session_id.clone(), None, Default::default())
        .await;
    let stats = Arc::new(ServerStats::default());
    let server_stats = Arc::clone(&stats);
    let server = tokio::spawn(async move {
        serve_files_with_stats_token(listener, server_stats, None, registry, false).await
    });
    let client = FileClient::connect_with_rtt_session(
        addr,
        Duration::ZERO,
        String::new(),
        String::new(),
        session_id,
    )
    .await?;
    let path = source_path.to_string_lossy().into_owned();

    let (warm_bytes, warm_digest) = client
        .fetch(&path)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "benchmark source"))?;
    verify_fetch(&warm_bytes, &warm_digest, &source, &expected_digest)?;

    let read_before = process_read_transfer_bytes()?;
    let started = Instant::now();
    let (bytes, digest) = client
        .fetch(&path)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "benchmark source"))?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let read_transfer_bytes = process_read_transfer_bytes()?.saturating_sub(read_before);
    verify_fetch(&bytes, &digest, &source, &expected_digest)?;
    let peak_working_set_bytes = process_peak_working_set_bytes()?;

    #[cfg(windows)]
    if read_transfer_bytes > (source.len() as u64) * 2 {
        return Err(io::Error::other(format!(
            "read transfer amplification: {read_transfer_bytes} bytes exceeds {}",
            source.len() * 2
        )));
    }
    #[cfg(not(windows))]
    eprintln!("fileserver_range_bench: skipping Windows ReadTransferCount threshold");

    println!(
        "size_mib={SIZE_MIB} mode=fileserver-fetch median_ms={elapsed_ms:.2} read_transfer_bytes={read_transfer_bytes} peak_working_set_bytes={peak_working_set_bytes}"
    );
    server.abort();
    Ok(())
}

fn verify_fetch(
    bytes: &[u8],
    digest: &Digest,
    expected_bytes: &[u8],
    expected_digest: &Digest,
) -> io::Result<()> {
    if bytes != expected_bytes || digest != expected_digest || Digest::of(bytes) != *digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-server fetch bytes or digest did not match source",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn process_read_transfer_bytes() -> io::Result<u64> {
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessIoCounters, IO_COUNTERS,
    };

    let mut counters: IO_COUNTERS = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetProcessIoCounters(GetCurrentProcess(), &mut counters) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(counters.ReadTransferCount)
}

#[cfg(not(windows))]
fn process_read_transfer_bytes() -> io::Result<u64> {
    Ok(0)
}

#[cfg(windows)]
fn process_peak_working_set_bytes() -> io::Result<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(counters.PeakWorkingSetSize as u64)
}

#[cfg(not(windows))]
fn process_peak_working_set_bytes() -> io::Result<u64> {
    Ok(0)
}
