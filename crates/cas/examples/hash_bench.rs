//! M4.0 measurement harness for ADR 0003 (CAS hash + chunking).
//!
//! The hash and chunking decisions are made with real data, not asserted. This
//! example measures the two quantities the ADR turns on:
//!
//!   1. **Hash throughput** across representative file sizes, for three
//!      implementations: the tracer's std-only hand-rolled SHA-256 (today's
//!      digest-as-identity), `sha2` with the SHA-NI asm backend, and `blake3`.
//!      C++ build I/O is a mix of small headers (KBs) and large objects/images
//!      (MBs), so the sweep spans 1 KiB … 16 MiB.
//!
//!   2. **Cross-build chunk-dedup potential.** Given two byte streams (two
//!      builds of the same artifact), it reports the fixed-64-KiB-chunk match
//!      ratio — an upper bound on what content-defined chunking could save.
//!      Build artifacts regenerate wholesale, so this is expected to be low,
//!      which is the evidence for "whole-file dedup, CDC deferred".
//!
//! Usage:
//!   cargo run -p sembazuru-cas --example hash_bench --release
//!   cargo run -p sembazuru-cas --example hash_bench --release -- <fileA> <fileB>
//!
//! With two file arguments it additionally prints the chunk-dedup measurement
//! for that pair (e.g. a.obj from two builds with a one-line source change).

use std::time::Instant;

use sembazuru_tracer::determinism::sha256_hex;
use sha2::{Digest, Sha256};

/// Representative sizes spanning the header-vs-object/image split.
const SIZES: &[(&str, usize)] = &[
    ("1 KiB", 1 << 10),
    ("4 KiB", 1 << 12),
    ("8 KiB", 1 << 13),
    ("64 KiB", 1 << 16),
    ("256 KiB", 1 << 18),
    ("1 MiB", 1 << 20),
    ("4 MiB", 1 << 22),
    ("16 MiB", 1 << 24),
];

/// Total bytes to push through each implementation at every size, so small
/// sizes run enough iterations to dwarf timer noise without the big sizes
/// taking forever. ~256 MiB per (impl, size) cell.
const BYTES_PER_CELL: usize = 256 << 20;

/// Deterministic pseudo-random fill (xorshift64*), so the corpus is identical
/// run to run and the numbers are comparable. Incompressible enough that no
/// implementation gets an unfair memcpy-of-zeros advantage.
fn fill_pseudo_random(buf: &mut [u8]) {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for chunk in buf.chunks_mut(8) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

fn mibps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

fn bench_sizes() {
    println!("=== Hash throughput (MiB/s, higher is better) ===");
    println!(
        "{:<10} {:>14} {:>14} {:>14}",
        "size", "sha256(hand)", "sha256(sha-ni)", "blake3"
    );

    for (label, size) in SIZES {
        let mut buf = vec![0u8; *size];
        fill_pseudo_random(&mut buf);
        let iters = (BYTES_PER_CELL / size).max(1);
        let total = iters * size;

        // Hand-rolled std-only SHA-256 (crates/tracer determinism.rs).
        let t = Instant::now();
        let mut sink = 0u8;
        for _ in 0..iters {
            let h = sha256_hex(&buf);
            sink ^= h.as_bytes()[0];
        }
        let hand = mibps(total, t.elapsed().as_secs_f64());

        // RustCrypto sha2 with the SHA-NI asm backend.
        let t = Instant::now();
        for _ in 0..iters {
            let mut hasher = Sha256::new();
            hasher.update(&buf);
            let d = hasher.finalize();
            sink ^= d[0];
        }
        let shani = mibps(total, t.elapsed().as_secs_f64());

        // BLAKE3 (single-threaded; SIMD auto-detected at runtime).
        let t = Instant::now();
        for _ in 0..iters {
            let d = blake3::hash(&buf);
            sink ^= d.as_bytes()[0];
        }
        let b3 = mibps(total, t.elapsed().as_secs_f64());

        println!(
            "{:<10} {:>14.0} {:>14.0} {:>14.0}   (sink={sink})",
            label, hand, shani, b3
        );
    }
    println!();
}

/// Fixed-size-chunk dedup ratio between two byte streams at chunk size `chunk`:
/// the fraction of B's chunks whose content also appears anywhere in A. This is
/// the optimistic ceiling for fixed-chunk reuse; finer chunks can only raise it,
/// so a low ratio at a small chunk size is strong evidence that build artifacts
/// rewrite rather than shift.
fn chunk_match_ratio(a: &[u8], b: &[u8], chunk: usize) -> (usize, usize) {
    use std::collections::HashSet;
    let mut a_chunks: HashSet<[u8; 32]> = HashSet::new();
    for c in a.chunks(chunk) {
        a_chunks.insert(*blake3::hash(c).as_bytes());
    }
    let mut matched = 0usize;
    let mut total = 0usize;
    for c in b.chunks(chunk) {
        total += 1;
        if a_chunks.contains(blake3::hash(c).as_bytes()) {
            matched += 1;
        }
    }
    (matched, total)
}

fn bench_pair(path_a: &str, path_b: &str) {
    let a = std::fs::read(path_a).expect("read fileA");
    let b = std::fs::read(path_b).expect("read fileB");
    println!("=== Cross-build chunk dedup (64 KiB fixed chunks) ===");
    println!("A: {path_a} ({} bytes)", a.len());
    println!("B: {path_b} ({} bytes)", b.len());
    println!(
        "whole-file identical: {}",
        if a == b { "yes" } else { "no" }
    );
    for chunk in [4 << 10, 16 << 10, 64 << 10] {
        let (matched, total) = chunk_match_ratio(&a, &b, chunk);
        let pct = if total == 0 {
            0.0
        } else {
            100.0 * matched as f64 / total as f64
        };
        println!(
            "  {:>3} KiB chunks: B reusable from A {matched}/{total} ({pct:.1}%)",
            chunk >> 10
        );
    }
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    bench_sizes();
    if args.len() >= 2 {
        bench_pair(&args[0], &args[1]);
    } else {
        println!("(pass two file paths to also measure cross-build chunk dedup)");
    }
}
