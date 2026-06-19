//! Agent-side scheduler (M5.2, ADR 0004). v0 keeps scheduling in the agent: the
//! agent owns the build session, so it is the single authority on which worker
//! runs each action. This module turns the live [`WorkerTable`] into placement
//! decisions and drives one action to completion with reassignment + local
//! fallback.
//!
//! **Placement = soft affinity + least-loaded.** Each action has a stable
//! `affinity_key` (a hash of its argv = the translation unit's identity). A
//! consistent-hash ring maps that key to a *preferred* worker, so the same
//! action returns to the same worker across rebuilds — its headers are already
//! warm in that worker's local cache (M4), cutting data-plane round-trips. When
//! the preferred worker is full the action spills to the least-loaded worker;
//! pure affinity (which would hot-spot) is never used.
//!
//! **Load is agent-tracked, not heartbeat-derived.** The heartbeat's
//! `idle_slots` lags by one interval (≈5 s); under a burst of dispatches every
//! action would see the same stale value and pile onto one worker. Because the
//! agent is the *only* scheduler (v0), it instead counts its own in-flight
//! assignments per worker and schedules against `cpu_count - in_flight`. The
//! heartbeat is used for liveness and the initial capacity (`cpu_count`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sembazuru_proto::v0::Command;

use crate::coordination::{WorkerEntry, WorkerTable};
use crate::{ExecOptions, ExecuteError, Execution, execute_on_channel_with, run_local};

/// Upper bound on a worker's self-reported `cpu_count` when used for load
/// math. A worker is untrusted until M7 (ADR 0004 §6); clamping stops a single
/// (mis)configured or hostile worker from advertising a huge capacity and
/// black-holing every action by always looking the least loaded.
const MAX_TRUSTED_CPU: u32 = 256;

/// Default per-attempt remote latency budget. Exceeding it on one worker is
/// treated as a failure and the action is reassigned (then locally). The value
/// is a scaffold tuned against the M5.5 efficiency measurement (ADR 0004 §5).
pub const DEFAULT_REMOTE_BUDGET: Duration = Duration::from_secs(120);

/// SplitMix64 finalizer — avalanches every input bit into every output bit.
fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Stable 64-bit hash: FNV-1a accumulation, then [`mix64`]. Deterministic across
/// processes and builds, so affinity placement is stable. (What actually keeps
/// prefix-sharing worker ids from collapsing onto one worker is the *joint* mix
/// in [`preferred_index`], not this finalizer alone; the finalizer just makes
/// the key value itself well-distributed.)
fn stable_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    mix64(h)
}

/// The affinity key of an action: a stable hash of its argv (the TU identity).
/// Same command line → same key → same preferred worker across rebuilds.
pub fn affinity_key(argv: &[String]) -> u64 {
    let mut buf = Vec::new();
    for a in argv {
        buf.extend_from_slice(a.as_bytes());
        buf.push(0); // length-independent separator
    }
    stable_hash(&buf)
}

/// Rendezvous (highest-random-weight) hashing: the preferred worker is the one
/// scoring highest for this key. Chosen over a one-point-per-worker ring because
/// the ring's arc lengths have high variance at small worker counts (3 points
/// can split the keyspace ~85/10/5), whereas HRW gives each key an independent
/// uniform pick — even distribution at any N — while keeping the same minimal-
/// disruption property: removing a worker only remaps the ~1/N keys it owned.
fn preferred_index(workers: &[WorkerEntry], key: u64) -> usize {
    let mut best = 0usize;
    let mut best_score = 0u64;
    for (i, w) in workers.iter().enumerate() {
        // Joint hash of (worker, key): mixing the precomputable id hash with the
        // key avalanches their combination so scores are independent per worker.
        let score = mix64(stable_hash(w.worker_id.as_bytes()) ^ key);
        if score > best_score {
            best_score = score;
            best = i;
        }
    }
    best
}

/// One unit of work for [`Scheduler::run_build`]: a command plus the identity
/// the worker reports it under and the data-plane file session it binds to.
#[derive(Clone, Debug)]
pub struct BuildAction {
    pub command: Command,
    pub action_id: String,
    pub session_id: String,
}

/// The agent-side scheduler over a shared worker table.
#[derive(Clone)]
pub struct Scheduler {
    table: WorkerTable,
    /// Agent's own in-flight assignment count per worker_id (authoritative load).
    in_flight: Arc<Mutex<HashMap<String, u32>>>,
    /// One lazily-connected gRPC channel per worker Execution endpoint, reused
    /// across actions so the control plane pays no per-action handshake.
    channels: Arc<Mutex<HashMap<String, tonic::transport::Channel>>>,
    remote_budget: Duration,
}

/// Increments a worker's in-flight count for the lifetime of a remote attempt,
/// decrementing on drop (success, failure, or panic) so the accounting cannot
/// leak a slot.
struct AssignGuard {
    map: Arc<Mutex<HashMap<String, u32>>>,
    worker_id: String,
}

impl Drop for AssignGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock().expect("in_flight poisoned");
        if let Some(c) = m.get_mut(&self.worker_id) {
            *c = c.saturating_sub(1);
            // Drop the entry at zero so the map cannot grow without bound as
            // workers come and go (verifier M2). Live load is re-inserted on the
            // next assignment.
            if *c == 0 {
                m.remove(&self.worker_id);
            }
        }
    }
}

impl Scheduler {
    pub fn new(table: WorkerTable) -> Self {
        Self::with_remote_budget(table, DEFAULT_REMOTE_BUDGET)
    }

    pub fn with_remote_budget(table: WorkerTable, remote_budget: Duration) -> Self {
        Self {
            table,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            channels: Arc::new(Mutex::new(HashMap::new())),
            remote_budget,
        }
    }

    /// A cached, lazily-connected channel to `endpoint`. `connect_lazy` never
    /// fails here (it connects on first use); a dead worker surfaces as an error
    /// on the Execute call, which dispatch then reassigns past.
    fn channel_for(&self, endpoint: &str) -> Result<tonic::transport::Channel, ExecuteError> {
        let mut chans = self.channels.lock().expect("channels poisoned");
        if let Some(c) = chans.get(endpoint) {
            return Ok(c.clone());
        }
        let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
            .map_err(ExecuteError::Transport)?
            .connect_timeout(Duration::from_millis(250))
            .connect_lazy();
        chans.insert(endpoint.to_string(), channel.clone());
        Ok(channel)
    }

    /// Drops cached channels whose worker is no longer live, bounding the cache
    /// to the current cluster. A worker that restarts on the same endpoint just
    /// re-inserts (and tonic reconnects) on the next dispatch.
    fn prune_channels(&self) {
        let live: std::collections::HashSet<String> = self
            .table
            .live_snapshot()
            .into_iter()
            .map(|w| w.execution_endpoint)
            .collect();
        let mut chans = self.channels.lock().expect("channels poisoned");
        chans.retain(|ep, _| live.contains(ep));
    }

    /// How many concurrent actions a worker is *willing* to run right now: its
    /// advertised admission capacity (clamped, as the worker is untrusted), scaled
    /// down by its smoothed idle CPU when it reports one (ADR 0010 "good
    /// neighbour"). A worker with no CPU signal (`None` — pre-0010 or feature off)
    /// keeps its full capacity, so the scheduler behaves exactly as before for it.
    ///
    /// Integer math only: the scheduler is float-free so identical inputs schedule
    /// identically (determinism). `base * pct` never overflows (`base <= 256`,
    /// `pct <= 100`). The exact `f()` (here a linear scale; reserve/floor live in
    /// the worker's reported value) is tunable on real LAN data (M10) without
    /// touching this shape.
    fn effective_capacity(w: &WorkerEntry) -> u32 {
        let base = w.caps.cpu_count.clamp(1, MAX_TRUSTED_CPU);
        match w.idle_cpu_pct {
            None => base,
            Some(pct) => base.saturating_mul(pct.min(100)) / 100,
        }
    }

    /// Effective free slots on a worker = its CPU-aware effective capacity
    /// ([`effective_capacity`]) minus the actions this agent currently has
    /// assigned to it. Subtracting `used` from the *scaled* capacity is what
    /// controls bursts: a freshly reserved slot drops this immediately, before the
    /// worker's (EMA-lagged) idle CPU has caught up, so concurrent dispatchers
    /// spread instead of piling onto one worker.
    fn effective_idle(&self, w: &WorkerEntry, in_flight: &HashMap<String, u32>) -> u32 {
        let used = in_flight.get(&w.worker_id).copied().unwrap_or(0);
        Self::effective_capacity(w).saturating_sub(used)
    }

    /// Atomically choose the best live worker for `key` (excluding `tried`) AND
    /// reserve a slot on it — pick and increment under the *same* `in_flight`
    /// lock. This is load-bearing for fan-out: if the pick and the reservation
    /// were separate (read load, release, then increment), the many dispatch
    /// tasks `run_build` spawns at once would all read the same stale "all idle"
    /// load and herd onto one affinity-preferred worker, leaving the rest idle
    /// (measured: ~half the cluster running). Reserving under the lock makes each
    /// dispatcher see the others' reservations and spread.
    ///
    /// Returns the chosen worker and a guard that frees the reservation on drop,
    /// or `None` when no live, untried, CPU-eligible worker remains.
    ///
    /// A worker whose CPU-aware [`effective_capacity`] is 0 (its host is too busy,
    /// ADR 0010) is *ineligible* — filtered out here so it is never tried, not even
    /// as a last resort. When every live worker is busy, this returns `None` and
    /// `dispatch` falls back to local, the same path as "no live workers". This is
    /// distinct from a worker whose `effective_idle` is 0 only because this agent
    /// has already reserved its capacity (`used >= effective_capacity`): such a
    /// worker stays eligible so the fan-out pipeline keeps its next action queued.
    fn pick_and_reserve(
        &self,
        key: u64,
        tried: &std::collections::HashSet<String>,
    ) -> Option<(WorkerEntry, AssignGuard)> {
        let snapshot = self.table.live_snapshot();
        let live: Vec<WorkerEntry> = snapshot
            .into_iter()
            .filter(|w| !tried.contains(&w.worker_id) && Self::effective_capacity(w) > 0)
            .collect();
        if live.is_empty() {
            return None;
        }

        let mut m = self.in_flight.lock().expect("in_flight poisoned");

        // Affinity-preferred worker, used if it still has a free slot; otherwise
        // the least-loaded (most effective-idle, stable by id) worker.
        let preferred = preferred_index(&live, key);
        let chosen_idx = if self.effective_idle(&live[preferred], &m) > 0 {
            preferred
        } else {
            (0..live.len())
                .max_by(|&a, &b| {
                    self.effective_idle(&live[a], &m)
                        .cmp(&self.effective_idle(&live[b], &m))
                        .then_with(|| live[b].worker_id.cmp(&live[a].worker_id))
                })
                .unwrap_or(preferred)
        };
        let chosen = live[chosen_idx].clone();

        *m.entry(chosen.worker_id.clone()).or_insert(0) += 1;
        let guard = AssignGuard {
            map: Arc::clone(&self.in_flight),
            worker_id: chosen.worker_id.clone(),
        };
        Some((chosen, guard))
    }

    /// Runs a whole build phase: every action is dispatched concurrently across
    /// the live workers (each with reassignment + local fallback), and the
    /// outcomes are returned once all complete. Fan-out is bounded per worker by
    /// the agent's in-flight accounting and the worker's admission semaphore, so
    /// a thousand actions do not stampede a four-core worker. This is the M5.5
    /// scheduler entry point; `run_build`'s wall time over `actions.len()` actions
    /// against W workers is what the parallel-efficiency measurement divides.
    pub async fn run_build(&self, actions: Vec<BuildAction>) -> Vec<Execution> {
        // Drop channels to workers that are no longer live so the cache cannot
        // grow without bound across a long-lived agent's worker churn
        // (security-reviewer / verifier B2).
        self.prune_channels();

        // Throttle fan-out to roughly the cluster's capacity (×2 so a worker
        // finishing one action always has the next already queued, never idling
        // between dispatches). Excess actions wait HERE, on the agent, instead of
        // being flung at workers that reject past their backlog and bounce to
        // slow local fallback — which would wreck parallel efficiency. The floor
        // is the local core count, so an all-local fallback (no live workers)
        // still runs in parallel rather than one TU at a time (verifier B1).
        let local_floor = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let cap = (self.cluster_capacity() * 2).max(local_floor);
        let gate = Arc::new(tokio::sync::Semaphore::new(cap));

        let mut tasks = Vec::with_capacity(actions.len());
        for a in actions {
            let permit = Arc::clone(&gate)
                .acquire_owned()
                .await
                .expect("build gate semaphore is never closed");
            let s = self.clone();
            tasks.push(tokio::spawn(async move {
                // The scale path plain-spawns: no prefetch hint, no VFS config.
                let outcome = s
                    .dispatch(a.command, a.action_id, a.session_id, ExecOptions::default())
                    .await;
                drop(permit); // free a slot for the next queued action
                outcome
            }));
        }
        let mut outcomes = Vec::with_capacity(tasks.len());
        for t in tasks {
            // A panicked dispatch task is a bug, not a build outcome; surface it.
            outcomes.push(t.await.expect("dispatch task panicked"));
        }
        outcomes
    }

    /// Total admission capacity across the live workers (clamped cpu_count sum) —
    /// how many actions the cluster can run at once, the basis for `run_build`'s
    /// fan-out throttle.
    fn cluster_capacity(&self) -> usize {
        self.table
            .live_snapshot()
            .iter()
            .map(|w| w.caps.cpu_count.clamp(1, MAX_TRUSTED_CPU) as usize)
            .sum()
    }

    /// Dispatches one action: try the affinity-preferred worker, then other live
    /// workers in least-loaded order (reassignment), then local execution. The
    /// build always completes (DESIGN.md §2): if every remote attempt fails or no
    /// worker is live, the action runs locally.
    pub async fn dispatch(
        &self,
        command: Command,
        action_id: String,
        session_id: String,
        opts: ExecOptions,
    ) -> Execution {
        // Route-away screen (M8.2, ADR 0007 §a①). A process that bypasses the
        // user-mode hooks — the msys2/Cygwin runtime issues direct NT syscalls
        // (BuildXL #680), or an operator put it on the denylist — cannot be
        // virtualized: on a worker it would silently read unvirtualized files and
        // produce a wrong result. user-mode hooks cannot observe what they never
        // intercepted, so the only safe move is to run it locally from the start
        // (non-negotiable #2). Correctness over the lost distribution.
        if let Some(why) = route_away_reason(&command) {
            let exit_code = run_local(&command).await.unwrap_or(-1);
            return Execution::LocalFallback {
                exit_code,
                reason: format!("route-away ({why})"),
            };
        }

        let key = affinity_key(&command.argv);
        let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut reason = "no live workers".to_string();

        // Try workers one at a time (reassignment), reserving each atomically so
        // concurrent dispatchers balance. The guard holds the reservation for the
        // duration of the attempt and frees it on the next iteration / on return.
        while let Some((w, guard)) = self.pick_and_reserve(key, &tried) {
            tried.insert(w.worker_id.clone());
            let channel = match self.channel_for(&w.execution_endpoint) {
                Ok(c) => c,
                Err(e) => {
                    reason = format!("worker {} unreachable: {e}", w.worker_id);
                    drop(guard);
                    continue;
                }
            };
            let attempt = tokio::time::timeout(
                self.remote_budget,
                execute_on_channel_with(
                    channel,
                    command.clone(),
                    action_id.clone(),
                    session_id.clone(),
                    opts.clone(),
                ),
            )
            .await;
            match attempt {
                Ok(Ok(outcome)) if outcome.exit_code.is_some() => {
                    return Execution::Remote(outcome);
                }
                Ok(Ok(_)) => {
                    reason = format!("worker {} did not complete the action", w.worker_id);
                }
                Ok(Err(e)) => {
                    reason = format!("worker {} failed: {e}", w.worker_id);
                }
                Err(_) => {
                    reason = format!("worker {} exceeded latency budget", w.worker_id);
                }
            }
            drop(guard); // release the reservation before trying the next worker
        }

        // Every remote path is exhausted: run locally so the build still finishes.
        let exit_code = run_local(&command).await.unwrap_or(-1);
        Execution::LocalFallback { exit_code, reason }
    }
}

/// User-mode-hook-bypassing runtimes: a binary linked against one of these issues
/// direct NT syscalls that our Detours hooks never see, so its file I/O cannot be
/// virtualized (ADR 0001 §110-113, BuildXL #680). Matched as a substring of the
/// binary's bytes — the import directory stores the DLL name as a plain ASCII
/// C-string, so a scan needs no PE parser and a normal exe does not contain these
/// names unless it actually imports them.
const BYPASS_RUNTIMES: &[&str] = &["msys-2.0.dll", "cygwin1.dll"];

/// Why this action must run locally rather than be virtualized on a worker, or
/// `None` if it is safe to distribute (ADR 0007 §a①). Two screens:
///
///   1. the `SEMBAZURU_LOCAL_ONLY` denylist (operator escape hatch; `;`-separated
///      exe basenames, case-insensitive);
///   2. a binary linked against a hook-bypassing runtime ([`BYPASS_RUNTIMES`]).
///
/// Fail-open by design: an unreadable / bare-name `argv[0]` is *not* forced local
/// (the worker-side fail-closed redirect is the backstop, M8.2 ②) — this screen
/// only catches what it can positively identify, conservatively.
fn route_away_reason(command: &Command) -> Option<String> {
    let argv0 = command.argv.first()?;
    let base = std::path::Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0)
        .to_ascii_lowercase();

    if let Ok(list) = std::env::var("SEMBAZURU_LOCAL_ONLY")
        && list
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|e| e.eq_ignore_ascii_case(&base))
    {
        return Some(format!("{base} on SEMBAZURU_LOCAL_ONLY"));
    }

    if let Some(rt) = bypass_runtime_of(argv0) {
        return Some(format!("{base} links {rt} (bypasses user-mode hooks)"));
    }
    None
}

/// Memoized verdicts, keyed by (path, len, mtime-secs), so the full-binary scan
/// runs once per distinct toolchain binary rather than once per dispatch (a build
/// has thousands of TUs through the same compiler — security M8.2 MEDIUM-2). A
/// toolchain upgrade (changed len/mtime) re-scans. The scan is NOT bounded to a
/// prefix: route-away is the *only* safety net for an msys2/Cygwin binary (its
/// direct syscalls bypass the hook, so strict-VFS can't catch it), so a missed
/// import name would let it run remotely and read unvirtualized files.
type RuntimeVerdictCache = Mutex<HashMap<(String, u64, u64), Option<&'static str>>>;
static RUNTIME_VERDICTS: std::sync::LazyLock<RuntimeVerdictCache> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// The hook-bypassing runtime DLL `path` is linked against, if any (memoized).
/// Returns `None` if the file cannot be read (bare PATH-resolved name,
/// permissions) — the caller treats that as "let it try remote; the worker
/// fail-closes if needed".
fn bypass_runtime_of(path: &str) -> Option<&'static str> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    let key = (path.to_string(), meta.len(), mtime);
    if let Some(v) = RUNTIME_VERDICTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
    {
        return *v;
    }
    let verdict = std::fs::read(path).ok().and_then(|bytes| {
        BYPASS_RUNTIMES
            .iter()
            .copied()
            .find(|rt| contains_ascii_ci(&bytes, rt.as_bytes()))
    });
    RUNTIME_VERDICTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, verdict);
    verdict
}

/// Case-insensitive ASCII substring search of `haystack` for `needle` (no
/// allocation of a lowercased copy of the whole binary).
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sembazuru_proto::v0::Capabilities;

    fn entry(id: &str, endpoint: &str, cpu: u32) -> WorkerEntry {
        // Build a WorkerEntry via the table so the private fields are set.
        let table = WorkerTable::new(Duration::from_secs(60));
        table.upsert_register(
            id.to_string(),
            endpoint.to_string(),
            Capabilities {
                cpu_count: cpu,
                ..Default::default()
            },
        );
        table
            .live_snapshot()
            .into_iter()
            .find(|w| w.worker_id == id)
            .unwrap()
    }

    fn tmp_file(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "sbz-routeaway-{}-{tag}-{seq}.bin",
            std::process::id()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn cmd1(argv0: &str) -> Command {
        Command {
            argv: vec![argv0.to_string()],
            env: Default::default(),
            cwd: String::new(),
        }
    }

    #[test]
    fn contains_ascii_ci_matches_case_insensitively() {
        assert!(contains_ascii_ci(b"....MSYS-2.0.DLL\0..", b"msys-2.0.dll"));
        assert!(contains_ascii_ci(b"x\0cygwin1.dll\0", b"cygwin1.dll"));
        assert!(!contains_ascii_ci(b"kernel32.dll\0", b"msys-2.0.dll"));
        assert!(!contains_ascii_ci(b"ab", b"abc")); // needle longer than haystack
    }

    #[test]
    fn bypass_runtime_is_detected_from_the_binary_bytes() {
        // A binary whose import directory names the msys2 runtime is detected.
        let msys = tmp_file("msys", b"MZ\x90...imports...\0msys-2.0.dll\0...");
        assert_eq!(
            bypass_runtime_of(msys.to_str().unwrap()),
            Some("msys-2.0.dll")
        );
        // A clean binary is not.
        let clean = tmp_file("clean", b"MZ\x90...kernel32.dll\0ntdll.dll\0");
        assert_eq!(bypass_runtime_of(clean.to_str().unwrap()), None);
        // An unreadable path fails open (None) — the worker fail-close is the backstop.
        assert_eq!(bypass_runtime_of("c:\\nope\\missing-xyz.exe"), None);
        let _ = std::fs::remove_file(&msys);
        let _ = std::fs::remove_file(&clean);
    }

    #[test]
    fn route_away_screens_msys_binaries_but_not_clean_ones() {
        let msys = tmp_file("ra-msys", b"MZ\0cygwin1.dll\0");
        let why = route_away_reason(&cmd1(msys.to_str().unwrap()));
        assert!(
            why.is_some_and(|w| w.contains("cygwin1.dll")),
            "a cygwin-linked binary must route away to local"
        );
        let clean = tmp_file("ra-clean", b"MZ\0kernel32.dll\0");
        assert!(
            route_away_reason(&cmd1(clean.to_str().unwrap())).is_none(),
            "a clean binary is safe to distribute"
        );
        // Empty argv → nothing to screen.
        assert!(
            route_away_reason(&cmd1("")).is_none()
                || route_away_reason(&Command::default()).is_none()
        );
        let _ = std::fs::remove_file(&msys);
        let _ = std::fs::remove_file(&clean);
    }

    #[test]
    fn affinity_key_is_stable_and_command_sensitive() {
        let a = affinity_key(&["clang-cl".into(), "/c".into(), "a.cpp".into()]);
        let a2 = affinity_key(&["clang-cl".into(), "/c".into(), "a.cpp".into()]);
        let b = affinity_key(&["clang-cl".into(), "/c".into(), "b.cpp".into()]);
        assert_eq!(a, a2, "same argv hashes the same (rebuild affinity)");
        assert_ne!(a, b, "different TUs get different keys");
    }

    #[test]
    fn preferred_is_consistent_for_a_key() {
        let ws = vec![
            entry("w1", "http://1", 4),
            entry("w2", "http://2", 4),
            entry("w3", "http://3", 4),
        ];
        let key = affinity_key(&["cc".into(), "x.cpp".into()]);
        let p1 = preferred_index(&ws, key);
        let p2 = preferred_index(&ws, key);
        assert_eq!(p1, p2, "ring pick is deterministic for a key");
    }

    #[test]
    fn ring_spreads_keys_across_similar_worker_ids() {
        // Regression for the ring-collapse bug: prefix-sharing ids ("w1".."w3",
        // "worker-N") must NOT all hash to the same ring point. Map many TU keys
        // and require every worker to get a fair share (no starvation / no single
        // worker taking everything).
        for ids in [
            vec!["w1", "w2", "w3"],
            vec!["worker-0", "worker-1", "worker-2", "worker-3"],
            vec![
                "build-rig-01",
                "build-rig-02",
                "build-rig-03",
                "build-rig-04",
            ],
        ] {
            let ws: Vec<_> = ids
                .iter()
                .map(|id| entry(id, &format!("http://{id}"), 4))
                .collect();
            let n = ws.len();
            let total = 6000;
            let mut counts = vec![0usize; n];
            for i in 0..total {
                let key = affinity_key(&["clang-cl".into(), format!("tu{i}.cpp")]);
                counts[preferred_index(&ws, key)] += 1;
            }
            let expected = total / n;
            for (j, &c) in counts.iter().enumerate() {
                // HRW spreads to within a few % of fair; require ≥ 2/3 of the
                // fair share so the test also catches *moderate* skew (e.g. one
                // worker taking ~50%), not just the total single-point collapse.
                assert!(
                    c >= expected * 2 / 3,
                    "worker {} ({}) got {c} of {total} keys (expected ~{expected}); \
                     distribution is skewed — counts={counts:?}",
                    j,
                    ids[j]
                );
            }
        }
    }

    #[test]
    fn churn_remaps_only_the_removed_workers_keys() {
        // HRW's minimal-disruption property: dropping one of N workers must only
        // move the keys that pointed at it; every other key keeps its worker.
        let full: Vec<_> = ["w1", "w2", "w3", "w4"]
            .iter()
            .map(|id| entry(id, &format!("http://{id}"), 4))
            .collect();
        let reduced: Vec<_> = full
            .iter()
            .filter(|w| w.worker_id != "w2")
            .cloned()
            .collect();

        let total = 4000;
        let mut moved = 0;
        let mut moved_from_removed = 0;
        for i in 0..total {
            let key = affinity_key(&["cc".into(), format!("tu{i}.cpp")]);
            let before = full[preferred_index(&full, key)].worker_id.clone();
            let after = reduced[preferred_index(&reduced, key)].worker_id.clone();
            if before != after {
                moved += 1;
                assert_eq!(
                    before, "w2",
                    "only keys owned by the removed worker may move"
                );
                moved_from_removed += 1;
            }
        }
        // Everything that moved was on w2; nothing else was disturbed.
        assert_eq!(moved, moved_from_removed);
        assert!(moved > 0, "removing a worker should remap its own keys");
    }

    #[test]
    fn pick_prefers_affinity_then_spills_when_full() {
        use std::collections::HashSet;
        let table = WorkerTable::new(Duration::from_secs(60));
        for id in ["w1", "w2", "w3"] {
            table.upsert_register(
                id.to_string(),
                format!("http://{id}"),
                Capabilities {
                    cpu_count: 2,
                    ..Default::default()
                },
            );
        }
        let sched = Scheduler::new(table);
        let key = affinity_key(&["cc".into(), "x.cpp".into()]);
        let snap = sched.table.live_snapshot();
        let pref = snap[preferred_index(&snap, key)].worker_id.clone();
        let none = HashSet::new();

        // Reserving (and holding) consecutively: the affinity-preferred worker is
        // chosen until it fills to capacity (2), then the pick spills elsewhere.
        let (w0, g0) = sched.pick_and_reserve(key, &none).unwrap();
        assert_eq!(w0.worker_id, pref, "affinity-preferred is chosen first");
        let (w1, g1) = sched.pick_and_reserve(key, &none).unwrap();
        assert_eq!(
            w1.worker_id, pref,
            "second slot still fits on preferred (cap 2)"
        );
        let (w2, _g2) = sched.pick_and_reserve(key, &none).unwrap();
        assert_ne!(
            w2.worker_id, pref,
            "a full preferred worker spills to a least-loaded peer"
        );
        drop((g0, g1));

        // Excluding a worker via `tried` never returns it (reassignment honors it).
        let mut tried = HashSet::new();
        tried.insert(pref.clone());
        let (w, _g) = sched.pick_and_reserve(key, &tried).unwrap();
        assert_ne!(w.worker_id, pref, "a tried worker is skipped");
    }

    // ---- ADR 0010: CPU-aware effective capacity -------------------------------

    #[test]
    fn effective_capacity_scales_with_reported_idle_cpu() {
        let mut w = entry("w", "http://w", 8);
        // No CPU signal → full advertised capacity (legacy behaviour).
        assert_eq!(Scheduler::effective_capacity(&w), 8);
        w.idle_cpu_pct = Some(100);
        assert_eq!(Scheduler::effective_capacity(&w), 8);
        w.idle_cpu_pct = Some(50);
        assert_eq!(Scheduler::effective_capacity(&w), 4);
        // Integer floor: just under one core's worth of idle reads as busy (0).
        w.idle_cpu_pct = Some(13); // 8*13/100 = 1
        assert_eq!(Scheduler::effective_capacity(&w), 1);
        w.idle_cpu_pct = Some(12); // 8*12/100 = 0
        assert_eq!(Scheduler::effective_capacity(&w), 0);
        w.idle_cpu_pct = Some(0);
        assert_eq!(Scheduler::effective_capacity(&w), 0);
        // pct is clamped at 100 so a misreporting worker cannot inflate capacity.
        w.idle_cpu_pct = Some(250);
        assert_eq!(Scheduler::effective_capacity(&w), 8);

        // base = 4 boundary: 25% → 1 core, 24% → 0 (busy).
        let mut s = entry("s", "http://s", 4);
        s.idle_cpu_pct = Some(25);
        assert_eq!(Scheduler::effective_capacity(&s), 1);
        s.idle_cpu_pct = Some(24);
        assert_eq!(Scheduler::effective_capacity(&s), 0);
    }

    #[test]
    fn effective_idle_subtracts_reservations_from_scaled_capacity() {
        let sched = Scheduler::new(WorkerTable::new(Duration::from_secs(60)));
        let mut w = entry("w", "http://w", 8);
        w.idle_cpu_pct = Some(50); // scaled capacity = 4
        let mut m = HashMap::new();
        assert_eq!(
            sched.effective_idle(&w, &m),
            4,
            "no reservations → full scaled capacity"
        );
        m.insert("w".to_string(), 3);
        assert_eq!(
            sched.effective_idle(&w, &m),
            1,
            "reservations cut the scaled capacity (burst control)"
        );
        m.insert("w".to_string(), 9);
        assert_eq!(
            sched.effective_idle(&w, &m),
            0,
            "over-reserved saturates at 0, never underflows"
        );
    }

    #[test]
    fn pick_skips_a_cpu_busy_worker_even_when_it_is_affinity_preferred() {
        use std::collections::HashSet;
        let table = WorkerTable::new(Duration::from_secs(60));
        for id in ["w1", "w2", "w3"] {
            table.upsert_register(
                id.to_string(),
                format!("http://{id}"),
                Capabilities {
                    cpu_count: 4,
                    ..Default::default()
                },
            );
        }
        let snap = table.live_snapshot();
        let key = affinity_key(&["cc".into(), "busy.cpp".into()]);
        let pref = snap[preferred_index(&snap, key)].worker_id.clone();
        // The affinity-preferred worker is fully busy; its peers are fully idle.
        for w in &snap {
            let pct = if w.worker_id == pref { 0 } else { 100 };
            table.on_ping(&w.worker_id, 0, 0, Some(pct));
        }
        let sched = Scheduler::new(table);
        let (chosen, _g) = sched.pick_and_reserve(key, &HashSet::new()).unwrap();
        assert_ne!(
            chosen.worker_id, pref,
            "a CPU-busy affinity-preferred worker is skipped for an idle peer"
        );
    }

    #[test]
    fn pick_returns_none_when_every_live_worker_is_cpu_busy() {
        use std::collections::HashSet;
        let table = WorkerTable::new(Duration::from_secs(60));
        for id in ["w1", "w2"] {
            table.upsert_register(
                id.to_string(),
                format!("http://{id}"),
                Capabilities {
                    cpu_count: 4,
                    ..Default::default()
                },
            );
            table.on_ping(id, 0, 0, Some(0)); // host busy → effective_capacity 0
        }
        let sched = Scheduler::new(table);
        let key = affinity_key(&["cc".into(), "x.cpp".into()]);
        assert!(
            sched.pick_and_reserve(key, &HashSet::new()).is_none(),
            "all workers CPU-busy → no eligible worker → dispatch falls back to local"
        );
    }

    #[test]
    fn an_in_flight_saturated_but_cpu_idle_worker_stays_eligible() {
        use std::collections::HashSet;
        let table = WorkerTable::new(Duration::from_secs(60));
        table.upsert_register(
            "w1".into(),
            "http://w1".into(),
            Capabilities {
                cpu_count: 2,
                ..Default::default()
            },
        );
        table.on_ping("w1", 0, 0, Some(100)); // fully idle host, scaled capacity 2
        let sched = Scheduler::new(table);
        let none = HashSet::new();
        // Reserve past capacity (2): the worker is in_flight-saturated
        // (effective_idle 0) but NOT CPU-busy, so the pipeline keeps choosing it
        // to stay full rather than starving — the two zeros are distinct.
        let (_w, _g1) = sched
            .pick_and_reserve(affinity_key(&["a".into()]), &none)
            .unwrap();
        let (_w, _g2) = sched
            .pick_and_reserve(affinity_key(&["b".into()]), &none)
            .unwrap();
        assert!(
            sched
                .pick_and_reserve(affinity_key(&["c".into()]), &none)
                .is_some(),
            "an in_flight-saturated but CPU-idle worker still accepts queued work"
        );
    }
}
