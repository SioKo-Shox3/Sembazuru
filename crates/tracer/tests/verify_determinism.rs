//! Integration tests for the `verify-determinism` subcommand — the gate's
//! orchestration (logical mapping, the PASS/FAIL decision, the
//! "compared nothing" guard), which the library unit tests don't reach.
//!
//! Windows-only: the gate is inherently a Windows/PE-COFF concern and the
//! tests synthesize Windows-style absolute paths and read them back from disk.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static CTR: AtomicU32 = AtomicU32::new(0);

fn unique_dir(tag: &str) -> PathBuf {
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    // Use Cargo's per-test scratch dir (under `target/`), NOT the system temp:
    // the reader drops paths under %TEMP% as intermediates, which would erase
    // the very outputs these tests compare.
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let p = base.join(format!("sbz-vd-{}-{}-{}", std::process::id(), tag, n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn push_string(b: &mut Vec<u8>, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    b.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for u in units {
        b.extend_from_slice(&u.to_le_bytes());
    }
}

/// Appends one FILE record (`docs/trace-format.md` §5).
fn write_file_record(b: &mut Vec<u8>, op: u8, path: &str) {
    b.push(1); // record_type = FILE
    b.push(op);
    b.extend_from_slice(&0u16.to_le_bytes()); // reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // status = success
    b.extend_from_slice(&1u32.to_le_bytes()); // tid
    b.extend_from_slice(&0u64.to_le_bytes()); // qpc
    b.extend_from_slice(&0u64.to_le_bytes()); // extra
    push_string(b, path);
    push_string(b, ""); // aux
}

/// Builds a single-process trace: header (with cwd) + write/read records.
fn trace_bytes(cwd: &str, cmd: &str, writes: &[&str], reads: &[&str]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"SBZT");
    b.extend_from_slice(&0u32.to_le_bytes()); // version
    b.extend_from_slice(&100u32.to_le_bytes()); // pid
    b.extend_from_slice(&1u32.to_le_bytes()); // parent_pid (not in set => root)
    b.extend_from_slice(&1u64.to_le_bytes()); // qpc_frequency
    b.extend_from_slice(&0u64.to_le_bytes()); // start_qpc
    b.extend_from_slice(&0u64.to_le_bytes()); // start_filetime
    push_string(&mut b, "C:\\cl.exe"); // exe_path
    push_string(&mut b, cmd); // command_line
    push_string(&mut b, cwd); // cwd
    for w in writes {
        write_file_record(&mut b, 2, w); // OpenWrite
    }
    for r in reads {
        write_file_record(&mut b, 1, r); // OpenRead
    }
    b
}

fn write_trace(dir: &Path, bytes: &[u8]) {
    std::fs::write(dir.join("p100.sbzt"), bytes).unwrap();
}

/// A minimal AMD64 COFF object: machine at 0, TimeDateStamp at +4, one content
/// byte at +20 so callers can introduce a genuine (non-timestamp) difference.
fn coff(timestamp: u32, content: u8) -> Vec<u8> {
    let mut b = vec![0u8; 24];
    b[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
    b[2..4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    b[4..8].copy_from_slice(&timestamp.to_le_bytes());
    b[20] = content;
    b
}

/// Sets up one run: a build root holding `a.obj`, and a trace dir whose trace
/// records that obj as a write under the root's cwd. Returns (trace_dir, root).
fn setup_run(tag: &str, cmd: &str, obj: &[u8]) -> (PathBuf, PathBuf) {
    let root = unique_dir(&format!("{tag}-root"));
    std::fs::write(root.join("a.obj"), obj).unwrap();
    let tdir = unique_dir(&format!("{tag}-trace"));
    let cwd = root.to_str().unwrap();
    let outpath = format!("{cwd}\\a.obj");
    write_trace(&tdir, &trace_bytes(cwd, cmd, &[&outpath], &[]));
    (tdir, root)
}

fn verify(ta: &Path, ra: &Path, tb: &Path, rb: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sembazuru-trace"))
        .args([
            "verify-determinism",
            "--trace-a",
            ta.to_str().unwrap(),
            "--root-a",
            ra.to_str().unwrap(),
            "--trace-b",
            tb.to_str().unwrap(),
            "--root-b",
            rb.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

#[test]
fn identical_outputs_pass() {
    // Same command (no embedded path) so input hashes match; identical obj
    // bytes built in two different roots must verify clean.
    let (ta, ra) = setup_run("idA", "cc a.cpp", &coff(5, 0xab));
    let (tb, rb) = setup_run("idB", "cc a.cpp", &coff(5, 0xab));
    let out = verify(&ta, &ra, &tb, &rb);
    assert!(
        out.status.success(),
        "expected PASS; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("identical"));
}

#[test]
fn timestamp_only_difference_is_normalized_equal() {
    // Objs differ solely in the COFF TimeDateStamp -> masked -> PASS.
    let (ta, ra) = setup_run("neA", "cc a.cpp", &coff(111, 0xab));
    let (tb, rb) = setup_run("neB", "cc a.cpp", &coff(222, 0xab));
    let out = verify(&ta, &ra, &tb, &rb);
    assert!(
        out.status.success(),
        "expected PASS (normalized-equal); stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("normalized-equal"));
}

#[test]
fn real_content_difference_fails() {
    // A genuine content byte differs -> normalization can't explain it -> FAIL.
    let (ta, ra) = setup_run("rdA", "cc a.cpp", &coff(5, 0xab));
    let (tb, rb) = setup_run("rdB", "cc a.cpp", &coff(5, 0xcd));
    let out = verify(&ta, &ra, &tb, &rb);
    assert!(
        !out.status.success(),
        "expected FAIL on a real byte difference; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("differs"));
}

#[test]
fn no_outputs_is_a_failure_not_a_vacuous_pass() {
    // Both runs produced no outputs under the build root. The gate must NOT
    // report success for having compared nothing (verifier finding H1).
    let root_a = unique_dir("emptyA-root");
    let root_b = unique_dir("emptyB-root");
    let ta = unique_dir("emptyA-trace");
    let tb = unique_dir("emptyB-trace");
    write_trace(
        &ta,
        &trace_bytes(root_a.to_str().unwrap(), "cc a.cpp", &[], &[]),
    );
    write_trace(
        &tb,
        &trace_bytes(root_b.to_str().unwrap(), "cc a.cpp", &[], &[]),
    );
    let out = verify(&ta, &root_a, &tb, &root_b);
    assert!(
        !out.status.success(),
        "comparing zero outputs must fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("no outputs were compared"));
}

#[test]
fn output_outside_build_root_is_flagged() {
    // An output written outside the build root can't be mapped by relative
    // correspondence; reading it would read the same file twice. It must be
    // surfaced as a failure, not a silent Identical (verifier finding M3).
    let root_a = unique_dir("orA-root");
    let root_b = unique_dir("orB-root");
    let other = unique_dir("orother");
    std::fs::write(other.join("x.obj"), coff(5, 0xab)).unwrap();
    let outside = format!("{}\\x.obj", other.to_str().unwrap());
    let ta = unique_dir("orA-trace");
    let tb = unique_dir("orB-trace");
    write_trace(
        &ta,
        &trace_bytes(root_a.to_str().unwrap(), "cc a.cpp", &[&outside], &[]),
    );
    write_trace(
        &tb,
        &trace_bytes(root_b.to_str().unwrap(), "cc a.cpp", &[&outside], &[]),
    );
    let out = verify(&ta, &root_a, &tb, &root_b);
    assert!(
        !out.status.success(),
        "an output outside the build root must fail; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("outside-build-root"));
}
