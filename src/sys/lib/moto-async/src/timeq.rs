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
    // Shared with the owning queue: cancelling bumps it so the queue knows how
    // much of itself is garbage and when to compact.
    cancelled: Rc<Cell<usize>>,
}

impl Timer {
    /// Cancel the timer so it is skipped (does not fire) once its deadline passes.
    pub(crate) fn cancel(&self) {
        if self.alive.replace(false) {
            self.cancelled.set(self.cancelled.get() + 1);
        }
    }
}

struct QueueEntry<T> {
    at: Instant,
    // Insertion order, the ordering tie-break: the payload (a waker) has
    // no useful order of its own.
    seq: u64,
    what: T,
    // Cleared when the timer is cancelled; such entries are discarded rather than
    // fired. Not part of the ordering below.
    alive: Rc<Cell<bool>>,
}

impl<T> PartialEq for QueueEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.seq == other.seq
    }
}

impl<T> Eq for QueueEntry<T> {}

impl<T> PartialOrd for QueueEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for QueueEntry<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.at, self.seq).cmp(&(other.at, other.seq))
    }
}

pub struct TimeQ<T> {
    // BinaryHeap is a max heap, we need a min heap.
    inner: BinaryHeap<core::cmp::Reverse<QueueEntry<T>>>,
    next_seq: u64,
    // Queued entries already cancelled. Only the front of a heap can be
    // purged cheaply, so cancelled entries behind it stay until their
    // deadline surfaces them; see [`Self::compact`].
    cancelled: Rc<Cell<usize>>,
}

impl<T> Default for TimeQ<T> {
    fn default() -> Self {
        Self {
            inner: BinaryHeap::new(),
            next_seq: 0,
            cancelled: Rc::new(Cell::new(0)),
        }
    }
}

impl<T> TimeQ<T> {
    /// Compact once garbage dominates: a timer cancelled deep in the heap is
    /// only reached when its deadline comes due, and typical deadlines are
    /// seconds away, so without this a hot `select!` loop (the sys-io device
    /// task creates ~90K cancelled timers/sec) grows the heap into the
    /// hundreds of thousands. That cost is not the wasted memory but the
    /// cache behavior: every push and pop then sifts through a multi-megabyte
    /// array, and draining the backlog burned most of a core in sys-io.
    /// Rebuilding is O(n) but happens at most once per n/2 cancellations.
    fn compact(&mut self) {
        const MIN_ENTRIES: usize = 64;
        if self.inner.len() < MIN_ENTRIES || self.cancelled.get() * 2 < self.inner.len() {
            return;
        }
        self.inner.retain(|entry| entry.0.alive.get());
        self.cancelled.set(0);
    }

    /// Queue a timer firing at `at`, returning a handle to cancel it (e.g. from
    /// the registering future's `Drop`).
    pub fn add_at(&mut self, at: Instant, what: T) -> Timer {
        self.compact();
        let alive = Rc::new(Cell::new(true));
        let seq = self.next_seq;
        self.next_seq += 1;
        self.inner.push(core::cmp::Reverse(QueueEntry {
            at,
            seq,
            what,
            alive: alive.clone(),
        }));
        Timer {
            alive,
            cancelled: self.cancelled.clone(),
        }
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
            self.uncount_cancelled();
        }
    }

    /// Queued entries, cancelled-but-not-yet-compacted ones included.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Drop cancelled timers from the front of the queue.
    fn purge_cancelled(&mut self) {
        while let Some(top) = self.inner.peek() {
            if top.0.alive.get() {
                break;
            }
            self.inner.pop();
            self.uncount_cancelled();
        }
    }

    /// A cancelled entry just left the queue, so it is no longer garbage the
    /// compaction pass would remove.
    fn uncount_cancelled(&mut self) {
        self.cancelled.set(self.cancelled.get().saturating_sub(1));
    }
}

#[test]
fn simple_ord() {
    let e1 = QueueEntry {
        at: Instant::now(),
        seq: 0,
        what: 1,
        alive: Rc::new(Cell::new(true)),
    };
    let e2 = QueueEntry {
        at: Instant::now() + core::time::Duration::from_secs(1),
        seq: 1,
        what: 2,
        alive: Rc::new(Cell::new(true)),
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
