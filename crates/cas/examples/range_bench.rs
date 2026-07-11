//! Measures the I/O and peak-memory amplification avoided by CAS range reads.
//!
//! Run the controller; it creates the corpus and launches one fresh child per
//! mode so process-lifetime peak working-set values never cross-contaminate:
//!
//! ```text
//! cargo run -p sembazuru-cas --example range_bench --release
//! ```

use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sembazuru_cas::{BlobStore, Digest};

const MIB: usize = 1024 * 1024;
const CHUNK_SIZE: usize = 256 * 1024;
const ITERATIONS: usize = 5;
const SIZES_MIB: [usize; 3] = [1, 16, 64];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    WholePerChunk,
    Range,
}

impl Mode {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "whole-per-chunk" => Ok(Self::WholePerChunk),
            "range" => Ok(Self::Range),
            _ => Err(invalid_data(format!("unknown mode: {value}"))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::WholePerChunk => "whole-per-chunk",
            Self::Range => "range",
        }
    }
}

#[derive(Debug)]
struct MeasurementLine {
    size_mib: usize,
    mode: Mode,
    median_ms: f64,
    read_transfer_bytes: u64,
    peak_working_set_bytes: u64,
}

struct TempStoreRoot(PathBuf);

impl Drop for TempStoreRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("range_bench: {error}");
        process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        run_controller()
    } else {
        let (mode, root, digests) = parse_child_args(&args)?;
        run_child(mode, &root, &digests)
    }
}

fn run_controller() -> io::Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = TempStoreRoot(std::env::temp_dir().join(format!(
        "sembazuru-range-bench.{}.{}",
        process::id(),
        nonce
    )));
    let store = BlobStore::open(&root.0)?;
    let mut blobs = Vec::with_capacity(SIZES_MIB.len());

    for size_mib in SIZES_MIB {
        let bytes = vec![size_mib as u8; size_mib * MIB];
        let digest = store.put(&bytes)?;
        blobs.push((size_mib, digest));
    }
    drop(store);

    let executable = std::env::current_exe()?;
    for mode in [Mode::WholePerChunk, Mode::Range] {
        let mut command = Command::new(&executable);
        command
            .arg("--child-mode")
            .arg(mode.as_str())
            .arg("--root")
            .arg(&root.0);
        for (_, digest) in &blobs {
            command.arg("--digest").arg(digest.canonical());
        }

        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{} child failed with {}: {}",
                mode.as_str(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|error| invalid_data(format!("child stdout is not UTF-8: {error}")))?;
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() != blobs.len() {
            return Err(invalid_data(format!(
                "{} child emitted {} lines, expected {}",
                mode.as_str(),
                lines.len(),
                blobs.len()
            )));
        }

        for (line, (expected_size_mib, _)) in lines.into_iter().zip(&blobs) {
            let parsed = parse_measurement_line(line)?;
            if parsed.mode != mode || parsed.size_mib != *expected_size_mib {
                return Err(invalid_data(format!(
                    "unexpected child result: mode={} size_mib={}",
                    parsed.mode.as_str(),
                    parsed.size_mib
                )));
            }
            println!("{line}");
        }
    }

    Ok(())
}

fn parse_child_args(args: &[String]) -> io::Result<(Mode, PathBuf, Vec<Digest>)> {
    if args.len() != 10
        || args[0] != "--child-mode"
        || args[2] != "--root"
        || args[4] != "--digest"
        || args[6] != "--digest"
        || args[8] != "--digest"
    {
        return Err(invalid_data(
            "expected --child-mode MODE --root PATH and three --digest values",
        ));
    }

    let mode = Mode::parse(&args[1])?;
    let digests = [&args[5], &args[7], &args[9]]
        .into_iter()
        .map(|value| {
            Digest::parse(value)
                .map_err(|error| invalid_data(format!("invalid digest {value}: {error}")))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok((mode, PathBuf::from(&args[3]), digests))
}

fn run_child(mode: Mode, root: &Path, digests: &[Digest]) -> io::Result<()> {
    if digests.len() != SIZES_MIB.len() {
        return Err(invalid_data("child digest count does not match size count"));
    }
    let store = BlobStore::open(root)?;
    for (size_mib, digest) in SIZES_MIB.into_iter().zip(digests) {
        let measurement = bench_one(&store, digest, size_mib, mode)?;
        println!(
            "size_mib={} mode={} median_ms={:.2} read_transfer_bytes={} peak_working_set_bytes={}",
            measurement.size_mib,
            measurement.mode.as_str(),
            measurement.median_ms,
            measurement.read_transfer_bytes,
            measurement.peak_working_set_bytes
        );
    }
    Ok(())
}

fn bench_one(
    store: &BlobStore,
    digest: &Digest,
    size_mib: usize,
    mode: Mode,
) -> io::Result<MeasurementLine> {
    let size = size_mib * MIB;
    let mut elapsed_ms = Vec::with_capacity(ITERATIONS);
    let mut transfer_bytes = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let transfer_before = process_read_transfer_bytes()?;
        let started = Instant::now();
        read_blob_in_chunks(store, digest, size, mode)?;
        elapsed_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        let transfer_after = process_read_transfer_bytes()?;
        transfer_bytes.push(transfer_after.saturating_sub(transfer_before));
    }

    elapsed_ms.sort_by(f64::total_cmp);
    transfer_bytes.sort_unstable();
    Ok(MeasurementLine {
        size_mib,
        mode,
        median_ms: elapsed_ms[ITERATIONS / 2],
        read_transfer_bytes: transfer_bytes[ITERATIONS / 2],
        peak_working_set_bytes: process_peak_working_set_bytes()?,
    })
}

fn read_blob_in_chunks(
    store: &BlobStore,
    digest: &Digest,
    size: usize,
    mode: Mode,
) -> io::Result<()> {
    for offset in (0..size).step_by(CHUNK_SIZE) {
        let chunk_len = CHUNK_SIZE.min(size - offset);
        match mode {
            Mode::WholePerChunk => {
                let bytes = store
                    .get(digest)?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "benchmark blob"))?;
                if bytes.len() != size {
                    return Err(invalid_data(format!(
                        "blob length {}, expected {size}",
                        bytes.len()
                    )));
                }
                std::hint::black_box(&bytes[offset..offset + chunk_len]);
            }
            Mode::Range => {
                let bytes = store
                    .get_range(digest, offset as u64, chunk_len)?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "benchmark blob"))?;
                if bytes.len() != chunk_len {
                    return Err(invalid_data(format!(
                        "range length {}, expected {chunk_len}",
                        bytes.len()
                    )));
                }
                std::hint::black_box(bytes);
            }
        }
    }
    Ok(())
}

fn parse_measurement_line(line: &str) -> io::Result<MeasurementLine> {
    let mut fields = line.split_ascii_whitespace();
    let size_mib = parse_field(&mut fields, "size_mib")?;
    let mode = parse_field(&mut fields, "mode")?;
    let median_ms = parse_field(&mut fields, "median_ms")?;
    let read_transfer_bytes = parse_field(&mut fields, "read_transfer_bytes")?;
    let peak_working_set_bytes = parse_field(&mut fields, "peak_working_set_bytes")?;
    if fields.next().is_some() {
        return Err(invalid_data("measurement line has extra fields"));
    }

    let median_ms = median_ms
        .parse::<f64>()
        .map_err(|error| invalid_data(format!("invalid median_ms: {error}")))?;
    if !median_ms.is_finite() || median_ms < 0.0 {
        return Err(invalid_data("median_ms must be finite and non-negative"));
    }
    Ok(MeasurementLine {
        size_mib: parse_number(size_mib, "size_mib")?,
        mode: Mode::parse(mode)?,
        median_ms,
        read_transfer_bytes: parse_number(read_transfer_bytes, "read_transfer_bytes")?,
        peak_working_set_bytes: parse_number(peak_working_set_bytes, "peak_working_set_bytes")?,
    })
}

fn parse_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    expected_name: &str,
) -> io::Result<&'a str> {
    let field = fields
        .next()
        .ok_or_else(|| invalid_data(format!("missing {expected_name}")))?;
    let (name, value) = field
        .split_once('=')
        .ok_or_else(|| invalid_data(format!("invalid {expected_name} field")))?;
    if name != expected_name || value.is_empty() {
        return Err(invalid_data(format!("expected {expected_name}=VALUE")));
    }
    Ok(value)
}

fn parse_number<T: std::str::FromStr>(value: &str, name: &str) -> io::Result<T>
where
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| invalid_data(format!("invalid {name}: {error}")))
}

#[cfg(windows)]
fn process_read_transfer_bytes() -> io::Result<u64> {
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessIoCounters, IO_COUNTERS,
    };

    let mut counters: IO_COUNTERS = unsafe { std::mem::zeroed() };
    let succeeded = unsafe { GetProcessIoCounters(GetCurrentProcess(), &mut counters) };
    if succeeded == 0 {
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
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let succeeded = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::try_from(counters.PeakWorkingSetSize).unwrap_or(u64::MAX))
}

#[cfg(not(windows))]
fn process_peak_working_set_bytes() -> io::Result<u64> {
    Ok(0)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_line_parser_accepts_the_fixed_format() {
        let parsed = parse_measurement_line(
            "size_mib=7 mode=range median_ms=3.25 read_transfer_bytes=123 peak_working_set_bytes=456",
        )
        .unwrap();

        assert_eq!(parsed.size_mib, 7);
        assert_eq!(parsed.mode, Mode::Range);
        assert_eq!(parsed.median_ms, 3.25);
        assert_eq!(parsed.read_transfer_bytes, 123);
        assert_eq!(parsed.peak_working_set_bytes, 456);
    }

    #[test]
    fn measurement_line_parser_rejects_extra_or_invalid_fields() {
        assert!(parse_measurement_line("size_mib=1 mode=range").is_err());
        assert!(
            parse_measurement_line(
                "size_mib=1 mode=range median_ms=NaN read_transfer_bytes=1 peak_working_set_bytes=2"
            )
            .is_err()
        );
        assert!(parse_measurement_line(
            "size_mib=1 mode=range median_ms=1.0 read_transfer_bytes=1 peak_working_set_bytes=2 extra=3"
        )
        .is_err());
    }
}
