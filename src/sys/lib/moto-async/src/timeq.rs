//! A queue of timers, i.e. a map of Instant -> FnOnce().
//!
//! Uses alloc::BinaryHeap.
use alloc::collections::binary_heap::BinaryHeap;
use moto_rt::time::Instant;

extern crate alloc;

struct QueueEntry<T> {
    at: Instant,
    what: T,
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
    pub fn add_at(&mut self, at: Instant, what: T) {
        self.inner.push(core::cmp::Reverse(QueueEntry { at, what }))
    }

    pub fn add_after(&mut self, after: core::time::Duration, what: T) {
        self.add_at(Instant::now() + after, what)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn next(&self) -> Option<Instant> {
        self.inner.peek().map(|e| e.0.at)
    }

    pub fn pop_at(&mut self, at: Instant) -> Option<T> {
        if let Some(next_at) = self.next() {
            if next_at > at {
                return None;
            }
        }

        self.inner.pop().map(|e| e.0.what)
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

    assert!(timeq.next_at().is_none());

    timeq.add_after(core::time::Duration::from_secs(3), 3);
    timeq.add_at(at_2, 2);
    timeq.add_at(at_1, 1);

    assert_eq!(timeq.next_at(), Some(at_1));
    assert_eq!(1, timeq.pop_at(at_1).unwrap());

    assert!(timeq.pop_at(at_1).is_none());
    assert_eq!(timeq.next_at(), Some(at_2));
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
    assert!(timeq.next_at().is_none());
}
