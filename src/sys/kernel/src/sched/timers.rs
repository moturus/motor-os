use alloc::collections::{BTreeMap, BTreeSet};

use super::{scheduler::Job, SchedulerJobFn};
use crate::{arch::time::Instant, config::uCpus, uspace::process::Thread, util::SpinLock};
use core::sync::atomic::*;

pub struct Timer {
    when: Instant,
    id: u64, // Need unique ids for Eq trait and to cancel in thread.
    job: Job,
    cpu: uCpus,
}

unsafe impl Send for Timer {}
unsafe impl Sync for Timer {}

impl Timer {
    pub fn new(job_fn: SchedulerJobFn, thread: &Thread, when: Instant, cpu: uCpus) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        debug_assert!(!when.is_nan());

        let mut job = Job::new(job_fn, thread.get_weak(), 0, cpu);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        job.arg = id;

        Self { when, job, id, cpu }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn cpu(&self) -> uCpus {
        self.cpu
    }

    pub fn job(self) -> Job {
        self.job
    }

    pub fn when(&self) -> Instant {
        self.when
    }
}

impl PartialEq for Timer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Timer {}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // BinaryHeap is max-heap, so we need to reverse.
        let when_cmp = self.when.cmp(&other.when);
        if when_cmp == core::cmp::Ordering::Equal {
            self.id.cmp(&other.id).reverse()
        } else {
            when_cmp.reverse()
        }
    }
}

struct TimersInner {
    time_queue: BTreeMap<Instant, BTreeSet<u64>>,
    timers: BTreeMap<u64, Timer>,
}

impl TimersInner {
    fn new() -> Self {
        Self {
            time_queue: BTreeMap::new(),
            timers: BTreeMap::new(),
        }
    }

    fn add_timer(&mut self, timer: Timer) {
        if let Some(set) = self.time_queue.get_mut(&timer.when) {
            set.insert(timer.id);
        } else {
            let mut set = BTreeSet::new();
            set.insert(timer.id);
            self.time_queue.insert(timer.when, set);
        }

        self.timers.insert(timer.id, timer);
    }

    fn remove_timer(&mut self, timer_id: u64) {
        if let Some(timer) = self.timers.remove(&timer_id) {
            let set = self.time_queue.get_mut(&timer.when).unwrap();
            assert!(set.remove(&timer.id));
            if set.is_empty() {
                self.time_queue.remove(&timer.when);
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.time_queue.first_key_value().map(|(when, _)| *when)
    }

    // Returns Ok(timer) if there is a timer <= cutoff;
    // returns Err(earliest) otherwise.
    fn pop(&mut self, cutoff: Instant) -> Result<Timer, Instant> {
        match self.time_queue.first_entry() {
            Some(mut entry) => {
                if *entry.key() > cutoff {
                    return Err(*entry.key());
                }

                let set = entry.get_mut();

                let id = set.pop_first().unwrap();
                if set.is_empty() {
                    self.time_queue.pop_first();
                }

                Ok(self.timers.remove(&id).unwrap())
            }
            None => Err(Instant::nan()),
        }
    }
}

pub(super) struct Timers {
    inner: SpinLock<TimersInner>,

    // Raw-TSC mirror of next_deadline() (u64::MAX when there are no timers),
    // maintained under the lock on every mutation. The timer-IRQ fast-return
    // path reads it from IRQ context, where taking `inner` could deadlock
    // against a holder on this CPU running with interrupts enabled.
    next_deadline_tsc: core::sync::atomic::AtomicU64,
}

impl Timers {
    pub fn new() -> Self {
        Self {
            inner: SpinLock::new(TimersInner::new()),
            next_deadline_tsc: core::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    fn update_deadline_mirror(&self, inner: &TimersInner) {
        self.next_deadline_tsc.store(
            inner.next_deadline().map_or(u64::MAX, |when| when.as_u64()),
            core::sync::atomic::Ordering::Release,
        );
    }

    pub fn add_timer(&self, timer: Timer) {
        let mut inner = self.inner.lock(line!());
        inner.add_timer(timer);
        self.update_deadline_mirror(&inner);
    }

    pub fn remove_timer(&self, timer_id: u64) {
        let mut inner = self.inner.lock(line!());
        inner.remove_timer(timer_id);
        self.update_deadline_mirror(&inner);
    }

    // The earliest pending deadline, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.inner.lock(line!()).next_deadline()
    }

    // The earliest pending deadline as raw TSC, u64::MAX if none. Lock-free;
    // safe to call from IRQ context.
    pub fn next_deadline_tsc(&self) -> u64 {
        self.next_deadline_tsc
            .load(core::sync::atomic::Ordering::Acquire)
    }

    // Returns Ok(timer) if there is a timer <= cutoff;
    // returns Err(earliest) otherwise.
    pub fn pop(&self, cutoff: Instant) -> Result<Timer, Instant> {
        let mut inner = self.inner.lock(line!());
        let result = inner.pop(cutoff);
        self.update_deadline_mirror(&inner);
        result
    }
}
