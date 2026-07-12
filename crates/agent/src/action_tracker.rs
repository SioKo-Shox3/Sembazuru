use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sembazuru_proto::v0::Command;

pub const ACTIVITY_TTL: Duration = Duration::from_secs(60);
pub const MAX_ACTIVITY_ATTEMPTS: usize = 4096;
pub const MAX_DISPLAY_CHARS: usize = 128;
pub const MAX_ID_CHARS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttemptKey {
    pub action_id: String,
    pub attempt_no: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionKind {
    Remote,
    Local,
    Fallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityState {
    Created,
    Queued,
    Preparing,
    Running,
    Completed,
    Failed,
    Interrupted,
}

impl ActivityState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Interrupted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivitySnapshot {
    pub key: AttemptKey,
    pub worker_id: String,
    pub execution_kind: ExecutionKind,
    pub display_name: String,
    pub state: ActivityState,
    pub lane_index: u32,
    pub started_age: Duration,
    pub finished_age: Option<Duration>,
    pub duration: Duration,
}

pub trait TrackerClock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl TrackerClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
pub struct ActionTracker {
    inner: Arc<Mutex<TrackerState>>,
    clock: Arc<dyn TrackerClock>,
}

pub struct AttemptLease {
    tracker: ActionTracker,
    key: AttemptKey,
    finished: bool,
}

impl AttemptLease {
    pub fn key(&self) -> &AttemptKey {
        &self.key
    }

    pub fn transition(&self, next: ActivityState) {
        self.tracker.transition(&self.key, next);
    }

    pub fn finish(&mut self, terminal: ActivityState) {
        self.tracker.finish(&self.key, terminal);
        if terminal.is_terminal() {
            self.finished = true;
        }
    }
}

impl Drop for AttemptLease {
    fn drop(&mut self) {
        if !self.finished {
            self.tracker.finish(&self.key, ActivityState::Interrupted);
        }
    }
}

#[derive(Default)]
struct TrackerState {
    attempts: HashMap<AttemptKey, AttemptRecord>,
    terminal_order: VecDeque<AttemptKey>,
    worker_lanes: HashMap<String, LaneAllocator>,
    rejected_transitions: u64,
}

struct LaneAllocator {
    next_lane: u32,
    free_lanes: BinaryHeap<Reverse<u32>>,
    active: usize,
}

impl Default for LaneAllocator {
    fn default() -> Self {
        Self {
            next_lane: 1,
            free_lanes: BinaryHeap::new(),
            active: 0,
        }
    }
}

struct AttemptRecord {
    worker_id: String,
    execution_kind: ExecutionKind,
    display_name: String,
    state: ActivityState,
    lane_index: u32,
    started_at: Instant,
    finished_at: Option<Instant>,
}

impl Default for ActionTracker {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl ActionTracker {
    pub fn with_clock(clock: Arc<dyn TrackerClock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerState::default())),
            clock,
        }
    }

    pub fn begin_attempt(
        &self,
        action_id: &str,
        attempt_no: u32,
        worker_id: &str,
        execution_kind: ExecutionKind,
        display_name: &str,
    ) -> Option<AttemptKey> {
        let now = self.clock.now();
        let mut state = self.lock();
        prune_locked(&mut state, now);

        let key = AttemptKey {
            action_id: bounded_id(action_id),
            attempt_no,
        };
        if state.attempts.contains_key(&key) {
            return None;
        }
        while state.attempts.len() >= MAX_ACTIVITY_ATTEMPTS {
            if !evict_oldest_terminal(&mut state) {
                return None;
            }
        }

        state.attempts.insert(
            key.clone(),
            AttemptRecord {
                worker_id: bounded_id(worker_id),
                execution_kind,
                display_name: truncate_chars(display_name, MAX_DISPLAY_CHARS),
                state: ActivityState::Created,
                lane_index: 0,
                started_at: now,
                finished_at: None,
            },
        );
        Some(key)
    }

    pub fn begin_attempt_lease(
        &self,
        action_id: &str,
        attempt_no: u32,
        worker_id: &str,
        execution_kind: ExecutionKind,
        display_name: &str,
    ) -> Option<AttemptLease> {
        self.begin_attempt(
            action_id,
            attempt_no,
            worker_id,
            execution_kind,
            display_name,
        )
        .map(|key| AttemptLease {
            tracker: self.clone(),
            key,
            finished: false,
        })
    }

    pub fn transition(&self, key: &AttemptKey, next: ActivityState) {
        self.transition_at(key, next, self.clock.now());
    }

    pub fn finish(&self, key: &AttemptKey, terminal: ActivityState) {
        let now = self.clock.now();
        let mut state = self.lock();
        if !terminal.is_terminal() {
            state.rejected_transitions = state.rejected_transitions.saturating_add(1);
            return;
        }
        transition_locked(&mut state, key, terminal, now);
    }

    pub fn snapshot(&self) -> Vec<ActivitySnapshot> {
        self.snapshot_at(self.clock.now())
    }

    fn transition_at(&self, key: &AttemptKey, next: ActivityState, now: Instant) {
        let mut state = self.lock();
        transition_locked(&mut state, key, next, now);
    }

    fn snapshot_at(&self, now: Instant) -> Vec<ActivitySnapshot> {
        let mut state = self.lock();
        prune_locked(&mut state, now);
        let mut snapshots = state
            .attempts
            .iter()
            .map(|(key, record)| {
                let end = record.finished_at.unwrap_or(now);
                ActivitySnapshot {
                    key: key.clone(),
                    worker_id: record.worker_id.clone(),
                    execution_kind: record.execution_kind,
                    display_name: record.display_name.clone(),
                    state: record.state,
                    lane_index: record.lane_index,
                    started_age: age(now, record.started_at),
                    finished_age: record.finished_at.map(|finished| age(now, finished)),
                    duration: age(end, record.started_at),
                }
            })
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| {
            let left_started = state.attempts[&left.key].started_at;
            let right_started = state.attempts[&right.key].started_at;
            left_started
                .cmp(&right_started)
                .then_with(|| left.key.action_id.cmp(&right.key.action_id))
                .then_with(|| left.key.attempt_no.cmp(&right.key.attempt_no))
        });
        snapshots
    }

    #[cfg(test)]
    fn prune_at(&self, now: Instant) {
        prune_locked(&mut self.lock(), now);
    }

    fn lock(&self) -> MutexGuard<'_, TrackerState> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    #[cfg(test)]
    fn rejected_transitions(&self) -> u64 {
        self.lock().rejected_transitions
    }
}

fn transition_locked(
    state: &mut TrackerState,
    key: &AttemptKey,
    next: ActivityState,
    now: Instant,
) {
    let Some(current) = state.attempts.get(key).map(|record| record.state) else {
        state.rejected_transitions = state.rejected_transitions.saturating_add(1);
        return;
    };
    if current.is_terminal() {
        if current != next {
            state.rejected_transitions = state.rejected_transitions.saturating_add(1);
        }
        return;
    }
    if next == current {
        return;
    }
    if !next.is_terminal() && state_rank(next) < state_rank(current) {
        state.rejected_transitions = state.rejected_transitions.saturating_add(1);
        return;
    }

    let lane_index = if next == ActivityState::Running {
        let worker_id = state.attempts[key].worker_id.clone();
        allocate_lane(&mut state.worker_lanes, worker_id)
    } else {
        state.attempts[key].lane_index
    };

    let record = state.attempts.get_mut(key).expect("attempt disappeared");
    let released_lane = if next.is_terminal() && record.lane_index != 0 {
        Some((record.worker_id.clone(), record.lane_index))
    } else {
        None
    };
    record.state = next;
    if next == ActivityState::Running {
        record.lane_index = lane_index;
    }
    if next.is_terminal() {
        record.finished_at = Some(now);
        state.terminal_order.push_back(key.clone());
        if let Some((worker_id, lane_index)) = released_lane {
            release_lane(&mut state.worker_lanes, &worker_id, lane_index);
        }
    }
}

fn allocate_lane(worker_lanes: &mut HashMap<String, LaneAllocator>, worker_id: String) -> u32 {
    let allocator = worker_lanes.entry(worker_id).or_default();
    let lane = allocator.free_lanes.pop().map_or_else(
        || {
            let lane = allocator.next_lane;
            allocator.next_lane = allocator.next_lane.saturating_add(1);
            lane
        },
        |Reverse(lane)| lane,
    );
    allocator.active = allocator.active.saturating_add(1);
    lane
}

fn release_lane(
    worker_lanes: &mut HashMap<String, LaneAllocator>,
    worker_id: &str,
    lane_index: u32,
) {
    let remove_allocator = if let Some(allocator) = worker_lanes.get_mut(worker_id) {
        allocator.active = allocator.active.saturating_sub(1);
        allocator.free_lanes.push(Reverse(lane_index));
        allocator.active == 0
    } else {
        false
    };
    if remove_allocator {
        worker_lanes.remove(worker_id);
    }
}

fn state_rank(state: ActivityState) -> u8 {
    match state {
        ActivityState::Created => 0,
        ActivityState::Queued => 1,
        ActivityState::Preparing => 2,
        ActivityState::Running => 3,
        ActivityState::Completed | ActivityState::Failed | ActivityState::Interrupted => 4,
    }
}

fn prune_locked(state: &mut TrackerState, now: Instant) {
    while let Some(key) = state.terminal_order.front() {
        let expired = state
            .attempts
            .get(key)
            .and_then(|record| record.finished_at)
            .is_none_or(|finished| age(now, finished) >= ACTIVITY_TTL);
        if !expired {
            break;
        }
        let key = state
            .terminal_order
            .pop_front()
            .expect("terminal queue front disappeared");
        state.attempts.remove(&key);
    }
}

fn evict_oldest_terminal(state: &mut TrackerState) -> bool {
    while let Some(key) = state.terminal_order.pop_front() {
        if state.attempts.remove(&key).is_some() {
            return true;
        }
    }
    false
}

fn age(later: Instant, earlier: Instant) -> Duration {
    later.checked_duration_since(earlier).unwrap_or_default()
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn bounded_id(value: &str) -> String {
    if value.chars().count() <= MAX_ID_CHARS {
        return value.to_owned();
    }
    let prefix = truncate_chars(value, 96);
    let digest = sembazuru_cas::Digest::of(value.as_bytes());
    format!("{prefix}#{}", &digest.hex()[..16])
}

pub fn display_name(command: &Command) -> String {
    const SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "m", "mm", "rs"];
    let mut sources = command.argv.iter().filter_map(|argument| {
        let basename = argument.rsplit(['\\', '/']).next()?;
        let path = std::path::Path::new(basename);
        let extension = path.extension()?.to_str()?;
        if SOURCE_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
        {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        } else {
            None
        }
    });
    let first = sources
        .next()
        .or_else(|| {
            command
                .argv
                .first()
                .and_then(|argument| argument.rsplit(['\\', '/']).next().map(str::to_owned))
        })
        .unwrap_or_else(|| "process".to_owned());
    let extra = sources.count();
    let label = if extra == 0 {
        first
    } else {
        format!("{first} +{extra}")
    };
    truncate_chars(&label, MAX_DISPLAY_CHARS)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use sembazuru_proto::v0::Command;

    use super::*;

    struct ManualClock(Mutex<Instant>);

    impl ManualClock {
        fn new(now: Instant) -> Self {
            Self(Mutex::new(now))
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.0.lock().unwrap();
            *now += duration;
        }
    }

    impl TrackerClock for ManualClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    #[test]
    fn tracker_reuses_lane_only_after_terminal() {
        let tracker = ActionTracker::default();
        let a = tracker
            .begin_attempt("a", 0, "w1", ExecutionKind::Remote, "a.cpp")
            .unwrap();
        let b = tracker
            .begin_attempt("b", 0, "w1", ExecutionKind::Remote, "b.cpp")
            .unwrap();
        tracker.transition(&a, ActivityState::Running);
        tracker.transition(&b, ActivityState::Running);
        assert_eq!(
            tracker
                .snapshot()
                .iter()
                .find(|entry| entry.key == a)
                .unwrap()
                .lane_index,
            1
        );
        assert_eq!(
            tracker
                .snapshot()
                .iter()
                .find(|entry| entry.key == b)
                .unwrap()
                .lane_index,
            2
        );
        tracker.finish(&a, ActivityState::Completed);
        assert_eq!(
            tracker
                .snapshot()
                .iter()
                .find(|entry| entry.key == a)
                .unwrap()
                .lane_index,
            1,
            "terminal history must retain its display lane"
        );
        let c = tracker
            .begin_attempt("c", 0, "w1", ExecutionKind::Remote, "c.cpp")
            .unwrap();
        tracker.transition(&c, ActivityState::Running);
        assert_eq!(
            tracker
                .snapshot()
                .iter()
                .find(|entry| entry.key == c)
                .unwrap()
                .lane_index,
            1
        );
    }

    #[test]
    fn retry_gets_distinct_attempt_key() {
        let tracker = ActionTracker::default();
        let first = tracker
            .begin_attempt("compile", 0, "w1", ExecutionKind::Remote, "a.cpp")
            .unwrap();
        tracker.finish(&first, ActivityState::Failed);
        let retry = tracker
            .begin_attempt("compile", 1, "w2", ExecutionKind::Remote, "a.cpp")
            .unwrap();
        assert_ne!(first, retry);
        assert_eq!(tracker.snapshot().len(), 2);
    }

    #[test]
    fn display_name_never_contains_parent_path() {
        let command = Command {
            argv: vec![
                "clang-cl.exe".into(),
                "/c".into(),
                "C:\\secret\\src\\main.cpp".into(),
            ],
            env: [("TOKEN".into(), "secret".into())].into_iter().collect(),
            cwd: "C:\\secret".into(),
        };
        assert_eq!(display_name(&command), "main.cpp");
        let unix = Command {
            argv: vec!["clang".into(), "-c".into(), "/secret/src/unix.cc".into()],
            ..Default::default()
        };
        assert_eq!(display_name(&unix), "unix.cc");
    }

    #[test]
    fn tracker_prunes_expired_terminal_and_never_evicts_active_attempts() {
        let start = Instant::now();
        let clock = Arc::new(ManualClock::new(start));
        let tracker = ActionTracker::with_clock(clock.clone());
        let done = tracker
            .begin_attempt("done", 0, "w1", ExecutionKind::Remote, "done.cpp")
            .unwrap();
        tracker.finish(&done, ActivityState::Completed);
        clock.advance(ACTIVITY_TTL + Duration::from_millis(1));
        tracker.prune_at(clock.now());
        assert!(tracker.snapshot().is_empty());
        assert!(tracker.lock().terminal_order.is_empty());

        for index in 0..MAX_ACTIVITY_ATTEMPTS {
            assert!(
                tracker
                    .begin_attempt(
                        &format!("active-{index}"),
                        0,
                        "w1",
                        ExecutionKind::Remote,
                        "active.cpp",
                    )
                    .is_some()
            );
        }
        assert!(
            tracker
                .begin_attempt("overflow", 0, "w1", ExecutionKind::Remote, "overflow.cpp")
                .is_none()
        );
        assert_eq!(tracker.snapshot().len(), MAX_ACTIVITY_ATTEMPTS);
    }

    #[test]
    fn dropped_attempt_lease_interrupts_and_becomes_ttl_prunable() {
        let start = Instant::now();
        let clock = Arc::new(ManualClock::new(start));
        let tracker = ActionTracker::with_clock(clock.clone());
        {
            let lease = tracker
                .begin_attempt_lease("cancelled", 0, "w1", ExecutionKind::Remote, "cancelled.cpp")
                .unwrap();
            lease.transition(ActivityState::Running);
        }
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].state, ActivityState::Interrupted);
        assert_eq!(snapshot[0].lane_index, 1);

        clock.advance(ACTIVITY_TTL + Duration::from_millis(1));
        tracker.prune_at(clock.now());
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn tracker_bounds_8192_terminal_attempts_and_auxiliary_state() {
        let tracker = ActionTracker::default();
        for index in 0..(MAX_ACTIVITY_ATTEMPTS * 2) {
            let key = tracker
                .begin_attempt(
                    &format!("action-{index}"),
                    0,
                    "w1",
                    ExecutionKind::Remote,
                    "unit.cpp",
                )
                .unwrap();
            tracker.finish(&key, ActivityState::Completed);
        }
        tracker.prune_at(Instant::now());
        let state = tracker.lock();
        assert_eq!(state.attempts.len(), MAX_ACTIVITY_ATTEMPTS);
        assert_eq!(state.terminal_order.len(), state.attempts.len());
        assert!(state.worker_lanes.is_empty());
    }

    #[test]
    fn tracker_rejects_regression_and_terminal_overwrite() {
        let tracker = ActionTracker::default();
        let key = tracker
            .begin_attempt("a", 0, "w1", ExecutionKind::Remote, "a.cpp")
            .unwrap();
        tracker.transition(&key, ActivityState::Running);
        tracker.transition(&key, ActivityState::Queued);
        assert_eq!(tracker.snapshot()[0].state, ActivityState::Running);
        tracker.finish(&key, ActivityState::Failed);
        tracker.finish(&key, ActivityState::Completed);
        assert_eq!(tracker.snapshot()[0].state, ActivityState::Failed);
        assert_eq!(tracker.rejected_transitions(), 2);
    }

    #[test]
    fn long_ids_are_bounded_without_colliding() {
        let tracker = ActionTracker::default();
        let common = "x".repeat(MAX_ID_CHARS + 32);
        let first = tracker
            .begin_attempt(
                &(common.clone() + "a"),
                0,
                &(common.clone() + "worker-a"),
                ExecutionKind::Remote,
                &"d".repeat(MAX_DISPLAY_CHARS + 32),
            )
            .unwrap();
        let second = tracker
            .begin_attempt(&(common + "b"), 0, "w2", ExecutionKind::Remote, "b.cpp")
            .unwrap();
        assert_ne!(first, second);
        assert!(first.action_id.chars().count() <= MAX_ID_CHARS);
        let snapshot = tracker.snapshot();
        assert!(snapshot[0].worker_id.chars().count() <= MAX_ID_CHARS);
        assert!(snapshot[0].display_name.chars().count() <= MAX_DISPLAY_CHARS);
    }

    #[test]
    fn poisoned_mutex_does_not_break_observation() {
        let tracker = ActionTracker::default();
        let poison = tracker.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.inner.lock().unwrap();
            panic!("poison tracker mutex");
        })
        .join();

        let key = tracker
            .begin_attempt("a", 0, "w1", ExecutionKind::Remote, "a.cpp")
            .unwrap();
        tracker.transition(&key, ActivityState::Running);
        assert_eq!(tracker.snapshot().len(), 1);
    }
}
