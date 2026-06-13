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
use crate::{ConnectPolicy, Execution, execute_remote_with, run_local};

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

/// The agent-side scheduler over a shared worker table.
#[derive(Clone)]
pub struct Scheduler {
    table: WorkerTable,
    /// Agent's own in-flight assignment count per worker_id (authoritative load).
    in_flight: Arc<Mutex<HashMap<String, u32>>>,
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
        Self {
            table,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            remote_budget: DEFAULT_REMOTE_BUDGET,
        }
    }

    pub fn with_remote_budget(table: WorkerTable, remote_budget: Duration) -> Self {
        Self {
            table,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            remote_budget,
        }
    }

    /// Effective free slots on a worker = its advertised capacity (clamped, as
    /// the worker is untrusted) minus the actions this agent currently has
    /// assigned to it.
    fn effective_idle(&self, w: &WorkerEntry, in_flight: &HashMap<String, u32>) -> u32 {
        let used = in_flight.get(&w.worker_id).copied().unwrap_or(0);
        w.caps
            .cpu_count
            .clamp(1, MAX_TRUSTED_CPU)
            .saturating_sub(used)
    }

    /// Orders the live workers for an action: the affinity-preferred worker
    /// first (if it has a free slot), then the rest by most-free-first. This is
    /// the reassignment order — each is tried until one accepts the action.
    fn order_candidates(&self, key: u64) -> Vec<WorkerEntry> {
        let snapshot = self.table.live_snapshot();
        if snapshot.is_empty() {
            return Vec::new();
        }
        let m = self.in_flight.lock().expect("in_flight poisoned");

        let preferred = preferred_index(&snapshot, key);
        let preferred_free = self.effective_idle(&snapshot[preferred], &m) > 0;

        // Sort all workers by most-effective-idle first (stable by worker_id for
        // determinism). Then, if the affinity-preferred worker still has a slot,
        // float it to the front so affinity wins over a marginally-freer peer.
        let mut ordered = snapshot.clone();
        ordered.sort_by(|a, b| {
            self.effective_idle(b, &m)
                .cmp(&self.effective_idle(a, &m))
                .then_with(|| a.worker_id.cmp(&b.worker_id))
        });
        if preferred_free {
            let pid = &snapshot[preferred].worker_id;
            if let Some(pos) = ordered.iter().position(|w| &w.worker_id == pid) {
                let p = ordered.remove(pos);
                ordered.insert(0, p);
            }
        }
        ordered
    }

    fn assign(&self, worker_id: &str) -> AssignGuard {
        {
            let mut m = self.in_flight.lock().expect("in_flight poisoned");
            *m.entry(worker_id.to_string()).or_insert(0) += 1;
        }
        AssignGuard {
            map: Arc::clone(&self.in_flight),
            worker_id: worker_id.to_string(),
        }
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
    ) -> Execution {
        let key = affinity_key(&command.argv);
        let candidates = self.order_candidates(key);

        let mut reason = if candidates.is_empty() {
            "no live workers".to_string()
        } else {
            String::new()
        };

        for w in &candidates {
            let _guard = self.assign(&w.worker_id);
            let attempt = tokio::time::timeout(
                self.remote_budget,
                execute_remote_with(
                    w.execution_endpoint.clone(),
                    command.clone(),
                    action_id.clone(),
                    session_id.clone(),
                    // Registered workers should answer at once; a slow connect
                    // means dead → reassign fast (verifier 欠陥2).
                    ConnectPolicy::FAST,
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
            // Fall through to the next candidate (reassignment).
        }

        // Every remote path is exhausted: run locally so the build still finishes.
        let exit_code = run_local(&command).await.unwrap_or(-1);
        Execution::LocalFallback { exit_code, reason }
    }
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
    fn order_floats_preferred_then_spreads_by_load() {
        let table = WorkerTable::new(Duration::from_secs(60));
        for (id, cpu) in [("w1", 2u32), ("w2", 2), ("w3", 2)] {
            table.upsert_register(
                id.to_string(),
                format!("http://{id}"),
                Capabilities {
                    cpu_count: cpu,
                    ..Default::default()
                },
            );
        }
        let sched = Scheduler::new(table);

        // With no load, the preferred worker for a key leads the candidate order.
        let key = affinity_key(&["cc".into(), "x.cpp".into()]);
        let snap = sched.table.live_snapshot();
        let pref = snap[preferred_index(&snap, key)].worker_id.clone();
        let ordered = sched.order_candidates(key);
        assert_eq!(ordered[0].worker_id, pref, "affinity-preferred leads");

        // Saturate the preferred worker (cpu_count assignments): it must drop out
        // of the lead, and a different (least-loaded) worker takes first. Hold the
        // guards alive so the in-flight count stays raised for the assertion.
        let _guards: Vec<_> = (0..2).map(|_| sched.assign(&pref)).collect();
        let ordered2 = sched.order_candidates(key);
        assert_ne!(
            ordered2[0].worker_id, pref,
            "a full preferred worker spills to least-loaded"
        );
    }
}
