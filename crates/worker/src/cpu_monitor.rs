//! Host idle-CPU sampling for the "good neighbour" admission policy (ADR 0010).
//!
//! A worker is often a developer's own machine. To avoid making that machine feel
//! sluggish while its user works, the worker samples how idle its CPU is and
//! reports it on every heartbeat; the *agent* then scales how many actions it
//! schedules onto this worker (`scheduler::effective_capacity`). The worker's
//! static admission semaphore stays an absolute ceiling — this only ever offers
//! *less* than that, never more.
//!
//! The signal is shaped here, not in the scheduler, so the policy (smoothing,
//! reserve, hysteresis) lives next to the host it protects and the wire stays a
//! single number. Two concerns are kept separate and independently testable:
//!
//!   * [`idle_pct_from_deltas`] / [`SystemTimesSampler`] — turn two `GetSystemTimes`
//!     readings into a raw idle percent over the interval.
//!   * [`IdleCpuPolicy`] — smooth that raw signal (EMA), hold back a reserve for
//!     the user, and apply hysteresis so the worker does not flap in and out of
//!     scheduling around the participation threshold.
//!
//! The exact constants are deliberately gentle defaults and are tuning knobs
//! (worker config / `SEMBAZURU_IDLE_CPU_*`), expected to be calibrated on real LAN
//! data (M10). Only the *shape* is fixed here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::config::IdleCpuSettings;

/// Sentinel stored in the published atomic before the sampler has a smoothed
/// reading (it needs two `GetSystemTimes` points to form a delta). Any value above
/// 100 means "no reading yet"; the heartbeat then sends `None` (no CPU signal),
/// which the agent treats as legacy slot-based scheduling.
pub(crate) const NOT_READY: u32 = u32::MAX;

/// How often the background sampler reads the system times. Smoothing is expressed
/// as an EMA weight over these ticks (see [`IdleCpuSettings::ema_alpha_pct`]), so
/// the "window" is `~ 1 / alpha` ticks. Kept short relative to the 5 s heartbeat so
/// the reported value reacts within a heartbeat or two of a load change, which
/// shortens the burst-overshoot window the scheduler has to absorb.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Raw idle percent (0-100) over an interval, from the per-interval deltas of the
/// idle / kernel / user system times. `kernel` already *includes* idle on Windows,
/// so total busy+idle time is `kernel + user`. Returns `None` when no time elapsed
/// (a zero denominator), so the caller keeps its previous reading rather than
/// dividing by zero. Pure and integer-only — no platform calls, no floats — so the
/// scheduler-facing number is reproducible and this is unit-testable anywhere.
pub(crate) fn idle_pct_from_deltas(idle_d: u64, kernel_d: u64, user_d: u64) -> Option<u32> {
    let total = kernel_d.checked_add(user_d)?;
    if total == 0 {
        return None;
    }
    // idle is a subset of kernel; clamp defensively so a racy sample can never
    // report > 100%.
    let idle = idle_d.min(total);
    Some(((idle * 100) / total) as u32)
}

/// Smooths and shapes the raw idle signal into the schedulable idle percent the
/// worker advertises. Stateful (EMA memory + a hysteresis latch); fed one raw
/// sample per tick.
#[derive(Debug)]
pub(crate) struct IdleCpuPolicy {
    /// EMA weight for the newest sample, in percent (e.g. 30 = 0.3).
    alpha_pct: u32,
    /// Idle headroom kept for the local user, in percent of the machine.
    reserve_pct: u32,
    /// Extra idle (above the reserve) required to *resume* participating after
    /// dropping out — the hysteresis band that stops flapping at the threshold.
    hysteresis_pct: u32,
    /// Minimum schedulable idle to offer while participating (ADR 0012). Raises the
    /// reported value up to this floor so an operator can guarantee a baseline
    /// contribution; 0 leaves the pure good-neighbour behaviour unchanged. Does NOT
    /// apply while latched out (a dropped-out worker still offers 0).
    participation_floor_pct: u32,
    /// Smoothed raw idle percent; `None` until the first sample seeds it.
    ema: Option<u32>,
    /// Whether the worker currently offers itself to the cluster. Starts `true`
    /// (an idle worker participates immediately); the latch only drops it out when
    /// idle falls below the reserve, and only restores it above reserve+hysteresis.
    participating: bool,
}

impl IdleCpuPolicy {
    pub(crate) fn new(settings: &IdleCpuSettings) -> Self {
        Self {
            // Clamp alpha into (0, 100]: a 0 weight would freeze the EMA forever.
            alpha_pct: settings.ema_alpha_pct.clamp(1, 100),
            reserve_pct: settings.reserve_pct.min(100),
            hysteresis_pct: settings.hysteresis_pct.min(100),
            participation_floor_pct: settings.participation_floor_pct.min(100),
            ema: None,
            participating: true,
        }
    }

    /// Feed one raw idle sample (0-100); returns the schedulable idle percent to
    /// report this tick: the smoothed idle minus the reserve (raised to the
    /// participation floor, ADR 0012) while participating, or 0 while the latch
    /// holds the worker out.
    pub(crate) fn observe(&mut self, raw_idle_pct: u32) -> u32 {
        let raw = raw_idle_pct.min(100);
        let ema = match self.ema {
            None => raw,
            // Integer EMA: alpha*raw + (1-alpha)*prev, rounded. A convex
            // combination of values <= 100 stays <= 100. Deterministic.
            Some(prev) => {
                let a = self.alpha_pct;
                (a * raw + (100 - a) * prev + 50) / 100
            }
        };
        self.ema = Some(ema);

        let resume_at = (self.reserve_pct + self.hysteresis_pct).min(100);
        if self.participating {
            if ema < self.reserve_pct {
                self.participating = false;
            }
        } else if ema >= resume_at {
            self.participating = true;
        }

        if self.participating {
            // Offer idle above the reserve, but never below the operator's floor
            // (ADR 0012). The floor only applies while participating; a latched-out
            // worker still offers nothing.
            ema.saturating_sub(self.reserve_pct)
                .max(self.participation_floor_pct)
        } else {
            0
        }
    }
}

/// Reads the system-wide idle / kernel / user times and turns successive readings
/// into a raw idle percent. Holds the previous reading so each `sample` covers the
/// interval since the last call. The first call (and any failed read) returns
/// `None`.
pub(crate) struct SystemTimesSampler {
    prev: Option<(u64, u64, u64)>,
}

impl SystemTimesSampler {
    pub(crate) fn new() -> Self {
        Self { prev: None }
    }

    /// Raw idle percent since the previous call, or `None` on the first call / an
    /// API failure / a zero-length interval.
    pub(crate) fn sample(&mut self) -> Option<u32> {
        let cur = read_system_times()?;
        let raw = match self.prev {
            None => None,
            Some(prev) => idle_pct_from_deltas(
                cur.0.saturating_sub(prev.0),
                cur.1.saturating_sub(prev.1),
                cur.2.saturating_sub(prev.2),
            ),
        };
        self.prev = Some(cur);
        raw
    }
}

/// Reads `(idle, kernel, user)` system times as 100 ns ticks, or `None` if the OS
/// call fails. `kernel` includes idle (Windows semantics), as relied on by
/// [`idle_pct_from_deltas`].
#[cfg(windows)]
fn read_system_times() -> Option<(u64, u64, u64)> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetSystemTimes;

    let mut idle = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = idle;
    let mut user = idle;
    // SAFETY: three valid, distinct out-params; GetSystemTimes only writes them.
    let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
    if ok == 0 {
        return None;
    }
    let as_u64 = |t: FILETIME| ((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64;
    Some((as_u64(idle), as_u64(kernel), as_u64(user)))
}

/// Non-Windows stub so the crate still type-checks off-Windows (the worker only
/// runs on Windows; this keeps `cargo check` portable). Always reports "no signal".
#[cfg(not(windows))]
fn read_system_times() -> Option<(u64, u64, u64)> {
    None
}

/// Spawns the background sampler: every [`SAMPLE_INTERVAL`] it reads the system
/// times, feeds the policy, and publishes the schedulable idle percent into `out`
/// (which the heartbeat loop reads). Stops when `stop` is set (worker drain). Until
/// the first smoothed reading, `out` holds [`NOT_READY`] so the heartbeat sends
/// `None`.
pub(crate) fn spawn_idle_cpu_sampler(
    out: Arc<AtomicU32>,
    settings: IdleCpuSettings,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        let mut sampler = SystemTimesSampler::new();
        let mut policy = IdleCpuPolicy::new(&settings);
        let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
        loop {
            tick.tick().await;
            if stop.load(Ordering::SeqCst) {
                break;
            }
            if let Some(raw) = sampler.sample() {
                out.store(policy.observe(raw), Ordering::Relaxed);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(reserve: u32, hysteresis: u32, alpha: u32) -> IdleCpuSettings {
        IdleCpuSettings {
            reserve_pct: reserve,
            hysteresis_pct: hysteresis,
            ema_alpha_pct: alpha,
            participation_floor_pct: 0,
        }
    }

    fn settings_with_floor(
        reserve: u32,
        hysteresis: u32,
        alpha: u32,
        floor: u32,
    ) -> IdleCpuSettings {
        IdleCpuSettings {
            participation_floor_pct: floor,
            ..settings(reserve, hysteresis, alpha)
        }
    }

    #[test]
    fn idle_pct_is_the_idle_fraction_of_busy_plus_idle() {
        // kernel includes idle, so total = kernel + user. Half idle.
        assert_eq!(idle_pct_from_deltas(50, 60, 40), Some(50));
        // Fully idle.
        assert_eq!(idle_pct_from_deltas(100, 100, 0), Some(100));
        // Fully busy.
        assert_eq!(idle_pct_from_deltas(0, 70, 30), Some(0));
        // Zero elapsed → no reading (no divide-by-zero).
        assert_eq!(idle_pct_from_deltas(0, 0, 0), None);
        // A racy idle > total is clamped, never > 100%.
        assert_eq!(idle_pct_from_deltas(200, 100, 0), Some(100));
    }

    #[test]
    fn policy_with_alpha_100_tracks_the_raw_signal_minus_reserve() {
        // alpha 100 = no smoothing; reserve 10, no hysteresis.
        let mut p = IdleCpuPolicy::new(&settings(10, 0, 100));
        assert_eq!(p.observe(100), 90, "100% idle, 10% reserved → offer 90%");
        assert_eq!(p.observe(50), 40);
        assert_eq!(p.observe(10), 0, "at the reserve, nothing schedulable");
        assert_eq!(p.observe(5), 0, "below the reserve → 0 and dropped out");
    }

    #[test]
    fn ema_smooths_a_transient_spike() {
        // alpha 30: a single busy sample only partially pulls the average down,
        // so one transient does not yank the worker out of scheduling.
        let mut p = IdleCpuPolicy::new(&settings(0, 0, 30));
        assert_eq!(p.observe(100), 100, "first sample seeds the EMA");
        // 0.3*0 + 0.7*100 = 70 (rounded).
        assert_eq!(p.observe(0), 70, "one busy tick is smoothed, not obeyed");
    }

    #[test]
    fn hysteresis_prevents_flapping_at_the_threshold() {
        // reserve 20, hysteresis 10 → drop out below 20, resume only at/above 30.
        // alpha 100 so the EMA equals the raw sample and we test the latch alone.
        let mut p = IdleCpuPolicy::new(&settings(20, 10, 100));
        assert_eq!(p.observe(50), 30, "participating: 50 - 20 reserve");
        assert_eq!(p.observe(15), 0, "below reserve → drops out");
        // 25 is above the reserve (20) but below resume (30): stays out (no flap).
        assert_eq!(p.observe(25), 0, "in the hysteresis band → stays out");
        assert_eq!(p.observe(30), 10, "at resume threshold → rejoins, 30 - 20");
    }

    #[test]
    fn participation_floor_raises_the_offer_while_participating() {
        // reserve 10, floor 30, alpha 100 (no smoothing). While participating, the
        // offer is max(idle - reserve, floor): at 50% idle that is max(40,30)=40,
        // but at 25% idle the floor lifts max(15,30) to 30.
        let mut p = IdleCpuPolicy::new(&settings_with_floor(10, 0, 100, 30));
        assert_eq!(p.observe(50), 40, "above the floor: idle - reserve wins");
        assert_eq!(p.observe(25), 30, "below the floor: lifted to the floor");
    }

    #[test]
    fn participation_floor_does_not_apply_once_latched_out() {
        // reserve 20, floor 50, hysteresis 0, alpha 100. Dropping below the reserve
        // latches the worker out, and a latched-out worker offers 0 regardless of
        // the floor (the floor is a participating-only baseline, ADR 0012).
        let mut p = IdleCpuPolicy::new(&settings_with_floor(20, 0, 100, 50));
        assert_eq!(p.observe(60), 50, "participating: max(40, 50 floor) = 50");
        assert_eq!(
            p.observe(10),
            0,
            "below reserve → latched out → 0, floor ignored"
        );
    }

    #[cfg(windows)]
    #[test]
    fn system_times_sampler_yields_a_percent_after_two_reads() {
        let mut s = SystemTimesSampler::new();
        assert_eq!(s.sample(), None, "first read has no delta");
        // Let some wall-clock pass so the second read has a non-zero interval.
        std::thread::sleep(Duration::from_millis(50));
        let pct = s
            .sample()
            .expect("a second read over a real interval yields a percent");
        assert!(pct <= 100, "idle percent is bounded, got {pct}");
    }
}
