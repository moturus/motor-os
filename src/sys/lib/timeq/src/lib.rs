#![feature(box_as_ptr)]

/// A queue of timers, i.e. a map of Instant -> FnOnce().
///
/// Uses alloc::BinaryHeap.
use alloc::collections::binary_heap::BinaryHeap;
use std::time::Instant;

extern crate alloc;

pub type Timer = Box<dyn FnOnce()>;

struct Entry {
    at: Instant,
    what: Timer,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
            && (Box::as_ptr(&self.what) as *const () as usize)
                == (Box::as_ptr(&other.what) as *const () as usize)
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.at < other.at {
            return Some(std::cmp::Ordering::Less);
        }

        if self.at > other.at {
            return Some(std::cmp::Ordering::Greater);
        }

        (Box::as_ptr(&self.what) as *const () as usize)
            .partial_cmp(&(Box::as_ptr(&other.what) as *const () as usize))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.at < other.at {
            return std::cmp::Ordering::Less;
        }

        if self.at > other.at {
            return std::cmp::Ordering::Greater;
        }

        (Box::as_ptr(&self.what) as *const () as usize)
            .cmp(&(Box::as_ptr(&other.what) as *const () as usize))
    }
}

#[derive(Default)]
pub struct TimeQ {
    // BinaryHeap is a max heap, we need a min heap.
    inner: BinaryHeap<core::cmp::Reverse<Entry>>,
}

impl TimeQ {
    pub fn add_at(&mut self, at: Instant, what: Timer) {
        self.inner.push(core::cmp::Reverse(Entry { at, what }))
    }

    pub fn add_after(&mut self, after: core::time::Duration, what: Timer) {
        self.add_at(Instant::now() + after, what)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn next_at(&self) -> Option<Instant> {
        self.inner.peek().map(|e| e.0.at)
    }

    pub fn pop_at(&mut self, at: Instant) -> Option<Timer> {
        if let Some(next_at) = self.next_at() {
            if next_at > at {
                return None;
            }
        }

        self.inner.pop().map(|e| e.0.what)
    }
}

#[test]
fn simple_ord() {
    let e1 = Entry {
        at: Instant::now(),
        what: Box::new(|| {}),
    };
    let e2 = Entry {
        at: Instant::now() + core::time::Duration::from_secs(1),
        what: Box::new(|| {}),
    };
    assert!(e1 < e2);
}

#[test]
fn basic_timeq() {
    let at = Instant::now();
    let mut timeq = TimeQ::default();

    static VAL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    let new_what =
        |val: u32| Box::new(move || VAL.store(val, std::sync::atomic::Ordering::Release));

    let at_1 = at + core::time::Duration::from_secs(1);
    let at_2 = at + core::time::Duration::from_secs(2);
    let at_3 = at + core::time::Duration::from_secs(3);

    let what_1 = new_what(1);
    let what_2 = new_what(2);
    let what_3 = new_what(3);

    assert!(timeq.next_at().is_none());

    timeq.add_after(core::time::Duration::from_secs(3), what_3);
    timeq.add_at(at_2, what_2);
    timeq.add_at(at_1, what_1);

    assert_eq!(timeq.next_at(), Some(at_1));
    timeq.pop_at(at_1).unwrap()();
    assert_eq!(1, VAL.load(std::sync::atomic::Ordering::Acquire));

    assert!(timeq.pop_at(at_1).is_none());
    assert_eq!(timeq.next_at(), Some(at_2));
    assert!(timeq
        .pop_at(at_1 + core::time::Duration::from_millis(500))
        .is_none());

    timeq
        .pop_at(at_2 + core::time::Duration::from_millis(1))
        .unwrap()();
    assert_eq!(2, VAL.load(std::sync::atomic::Ordering::Acquire));
    assert!(timeq.pop_at(at_2).is_none());

    timeq
        .pop_at(at_3 + core::time::Duration::from_secs(100))
        .unwrap()();
    assert_eq!(3, VAL.load(std::sync::atomic::Ordering::Acquire));
    assert!(timeq.next_at().is_none());
}
