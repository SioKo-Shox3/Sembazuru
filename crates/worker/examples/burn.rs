//! A deterministic CPU-bound workload standing in for a compile in the M5.5
//! parallel-efficiency harness. Each invocation does a fixed number of integer
//! iterations — so its *work* is machine-independent (its wall time scales with
//! CPU speed, which cancels in the efficiency ratio E(W) = T(1)/(W·T(W))). It
//! has no inputs/outputs, isolating the scheduler's distribution efficiency from
//! data-plane file supply. Exits 0.
//!
//! Usage: `burn [iterations]` (default 20,000,000).

fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000);

    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..iters {
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3) ^ i;
        acc = acc.rotate_left(13);
    }
    // Keep the optimizer from eliding the loop; the value is otherwise unused.
    std::hint::black_box(acc);
}
