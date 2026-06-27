//! A queue of timers, i.e. a map of Instant -> FnOnce().
//!
//! Uses alloc::BinaryHeap.
use alloc::collections::binary_heap::BinaryHeap;
use alloc::rc::Rc;
use core::cell::Cell;
use moto_rt::time::Instant;

extern crate alloc;

#[cfg(not(target_os = "motor"))]
compile_error!("Only Motor OS targets supported.");

/// Handle to a queued timer.
///
/// Futures such as [`crate::Sleep`] register a timer when first polled but are
/// very often dropped before they fire — e.g. the losing branch of a `select!`.
/// Such a future cancels its timer via this handle on drop; a cancelled timer is
/// silently discarded instead of firing. Without this, dropped-but-uncancelled
/// timers accumulate in the queue without bound and fire spurious wakeups that
/// pile up in the run queue and starve the runtime.
#[derive(Clone)]
pub(crate) struct Timer {
    alive: Rc<Cell<bool>>,
}

impl Timer {
    /// Cancel the timer so it is skipped (does not fire) once its deadline passes.
    pub(crate) fn cancel(&self) {
        self.alive.set(false);
    }
}

struct QueueEntry<T> {
    at: Instant,
    what: T,
    // Cleared when the timer is cancelled; such entries are discarded rather than
    // fired. Not part of the ordering below.
    alive: Rc<Cell<bool>>,
}

impl<T: PartialEq> PartialEq for QueueEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.what == other.what
    }
}

impl<T: Eq> Eq for QueueEntry<T> {}

impl<T: Ord> PartialOrd for QueueEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Ord> Ord for QueueEntry<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if self.at < other.at {
            return core::cmp::Ordering::Less;
        }

        if self.at > other.at {
            return core::cmp::Ordering::Greater;
        }

        self.what.cmp(&other.what)
    }
}

pub struct TimeQ<T: Eq + Ord> {
    // BinaryHeap is a max heap, we need a min heap.
    inner: BinaryHeap<core::cmp::Reverse<QueueEntry<T>>>,
}

impl<T: Eq + Ord> Default for TimeQ<T> {
    fn default() -> Self {
        Self {
            inner: BinaryHeap::new(),
        }
    }
}

impl<T: Eq + Ord> TimeQ<T> {
    /// Queue a timer firing at `at`, returning a handle to cancel it (e.g. from
    /// the registering future's `Drop`).
    pub fn add_at(&mut self, at: Instant, what: T) -> Timer {
        let alive = Rc::new(Cell::new(true));
        self.inner.push(core::cmp::Reverse(QueueEntry {
            at,
            what,
            alive: alive.clone(),
        }));
        Timer { alive }
    }

    /// Deadline of the earliest still-live timer. Cancelled timers at the front
    /// are purged first so we never sleep waiting for one.
    pub fn next(&mut self) -> Option<Instant> {
        self.purge_cancelled();
        self.inner.peek().map(|e| e.0.at)
    }

    /// Pop the earliest live timer whose deadline is `<= at`, discarding any
    /// cancelled timers encountered along the way.
    pub fn pop_at(&mut self, at: Instant) -> Option<T> {
        loop {
            let next_at = self.inner.peek().map(|e| e.0.at)?;
            if next_at > at {
                return None;
            }
            let entry = self.inner.pop().unwrap().0;
            if entry.alive.get() {
                return Some(entry.what);
            }
            // Cancelled and due: drop it and keep looking.
        }
    }

    /// Drop cancelled timers from the front of the queue.
    fn purge_cancelled(&mut self) {
        while let Some(top) = self.inner.peek() {
            if top.0.alive.get() {
                break;
            }
            self.inner.pop();
        }
    }
}

#[test]
fn simple_ord() {
    let e1 = QueueEntry {
        at: Instant::now(),
        what: 1,
    };
    let e2 = QueueEntry {
        at: Instant::now() + core::time::Duration::from_secs(1),
        what: 2,
    };
    assert!(e1 < e2);
}

#[test]
fn basic_timeq() {
    let at = Instant::now();
    let mut timeq = TimeQ::default();

    let at_1 = at + core::time::Duration::from_secs(1);
    let at_2 = at + core::time::Duration::from_secs(2);
    let at_3 = at + core::time::Duration::from_secs(3);

    assert!(timeq.next().is_none());

    timeq.add_at(at_3, 3);
    timeq.add_at(at_2, 2);
    timeq.add_at(at_1, 1);

    assert_eq!(timeq.next(), Some(at_1));
    assert_eq!(1, timeq.pop_at(at_1).unwrap());

    assert!(timeq.pop_at(at_1).is_none());
    assert_eq!(timeq.next(), Some(at_2));
    assert!(
        timeq
            .pop_at(at_1 + core::time::Duration::from_millis(500))
            .is_none()
    );

    assert_eq!(
        2,
        timeq
            .pop_at(at_2 + core::time::Duration::from_millis(1))
            .unwrap()
    );
    assert!(timeq.pop_at(at_2).is_none());

    assert_eq!(
        3,
        timeq
            .pop_at(at_3 + core::time::Duration::from_secs(100))
            .unwrap()
    );
    assert!(timeq.next().is_none());
}
