//! An async read-write lock (single-threaded / local).
//!
//! Many concurrent readers XOR one writer. FIFO-fair, mirroring
//! [`crate::LocalMutex`]: a queued writer blocks readers that arrive after it
//! (no barging), and queued readers acquire in a wake chain once the lock
//! becomes readable.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use core::cell::{Cell, RefCell, UnsafeCell};
use core::ops::{Deref, DerefMut};
use core::task::LocalWaker;
use core::task::Poll;

extern crate alloc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaiterKind {
    Reader,
    Writer,
}

#[derive(Default)]
pub struct LocalRwLock<T> {
    // The number of live read guards.
    readers: Cell<usize>,
    // A live write guard exists. Mutually exclusive with readers > 0.
    writer: Cell<bool>,
    value: UnsafeCell<T>,

    // Waiters (same design as LocalMutex).
    next_waiter_id: Cell<u64>,
    // A VecDeque to maintain fairness.
    wait_queue: RefCell<VecDeque<u64>>,
    // Keeps track of (gone) waiters and their latest wakers.
    waiters: RefCell<BTreeMap<u64, (WaiterKind, LocalWaker)>>,
}

impl<T> LocalRwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            readers: Cell::new(0),
            writer: Cell::new(false),
            value: UnsafeCell::new(value),
            next_waiter_id: Cell::new(1),
            wait_queue: RefCell::new(VecDeque::new()),
            waiters: RefCell::new(BTreeMap::new()),
        }
    }

    /// Lock for reading. Multiple read guards may be alive concurrently.
    #[inline]
    pub fn read(&self) -> LocalRwLockReadWaiter<'_, T> {
        LocalRwLockReadWaiter {
            waiter: Waiter {
                lock: self,
                kind: WaiterKind::Reader,
                id: 0,
            },
        }
    }

    /// Lock for writing (exclusive).
    #[inline]
    pub fn write(&self) -> LocalRwLockWriteWaiter<'_, T> {
        LocalRwLockWriteWaiter {
            waiter: Waiter {
                lock: self,
                kind: WaiterKind::Writer,
                id: 0,
            },
        }
    }

    fn next_waiter_id(&self) -> u64 {
        let id = self.next_waiter_id.get();
        self.next_waiter_id.set(id + 1);
        id
    }

    /// Wake the front live waiter, dropping dead (cancelled) entries.
    fn wake_next_waiter(&self) {
        let mut wait_queue = self.wait_queue.borrow_mut();
        let waiters = self.waiters.borrow();
        loop {
            let Some(waiter_id) = wait_queue.front() else {
                return;
            };

            if let Some((_, waker)) = waiters.get(waiter_id) {
                waker.wake_by_ref();
                return;
            }

            wait_queue.pop_front();
        }
    }
}

struct Waiter<'a, T> {
    lock: &'a LocalRwLock<T>,
    kind: WaiterKind,
    id: u64, // zero => not registered.
}

impl<'a, T> Drop for Waiter<'a, T> {
    fn drop(&mut self) {
        if core::hint::unlikely(self.id != 0) {
            // This waiter was polled, but then dropped without acquiring
            // the lock (e.g. cancelled via select/timeout).
            assert!(self.lock.waiters.borrow_mut().remove(&self.id).is_some());
            if !self.lock.writer.get() {
                // Our removal may unblock the (new) front waiter; a spurious
                // wake is harmless.
                self.lock.wake_next_waiter();
            }
        }
    }
}

impl<'a, T> Waiter<'a, T> {
    /// Register in the wait queue, or update the stored waker.
    fn register(&mut self, cx: &mut core::task::Context<'_>) {
        let mut waiters = self.lock.waiters.borrow_mut();
        if self.id == 0 {
            self.id = self.lock.next_waiter_id();
            waiters.insert(self.id, (self.kind, cx.local_waker().clone()));
            self.lock.wait_queue.borrow_mut().push_back(self.id);
        } else {
            waiters.get_mut(&self.id).unwrap().1 = cx.local_waker().clone();
        }
    }

    /// The lock is in a state this waiter could acquire; enforce FIFO order.
    /// Returns true if this waiter is at the front of the queue (or the queue
    /// is empty), i.e. may acquire now; wakes the front waiter and registers
    /// otherwise.
    fn fifo_may_acquire(&mut self, cx: &mut core::task::Context<'_>) -> bool {
        let mut wait_queue = self.lock.wait_queue.borrow_mut();
        let mut waiters = self.lock.waiters.borrow_mut();

        loop {
            let Some(waiter_id) = wait_queue.front().copied() else {
                // No waiters.
                debug_assert!(waiters.is_empty());
                debug_assert_eq!(self.id, 0);
                return true;
            };

            if waiter_id == self.id {
                // Our turn.
                wait_queue.pop_front();
                assert!(waiters.remove(&self.id).is_some());
                self.id = 0; // Mark not registered so that Drop behaves correctly.

                // Readers acquire in a chain: if the next live waiter is also
                // a reader, wake it so it can acquire concurrently with us.
                if self.kind == WaiterKind::Reader {
                    while let Some(next_id) = wait_queue.front() {
                        match waiters.get(next_id) {
                            Some((WaiterKind::Reader, waker)) => {
                                waker.wake_by_ref();
                                break;
                            }
                            Some((WaiterKind::Writer, _)) => break,
                            None => {
                                // A dead waiter.
                                wait_queue.pop_front();
                            }
                        }
                    }
                }
                return true;
            }

            if waiters.contains_key(&waiter_id) {
                // Not our turn: wake the front waiter and wait.
                waiters.get(&waiter_id).unwrap().1.wake_by_ref();
                drop(waiters);
                drop(wait_queue);
                self.register(cx);
                return false;
            }

            // The front waiter is gone.
            wait_queue.pop_front();
        }
    }

    /// Try to acquire the lock (as reader or writer per self.kind),
    /// respecting FIFO fairness. Updates the lock state on success.
    fn poll_acquire(&mut self, cx: &mut core::task::Context<'_>) -> Poll<()> {
        let lock = self.lock;
        let acquirable = match self.kind {
            // Readers share the lock with other readers.
            WaiterKind::Reader => !lock.writer.get(),
            WaiterKind::Writer => !lock.writer.get() && (lock.readers.get() == 0),
        };

        if !acquirable {
            self.register(cx);
            return Poll::Pending;
        }

        if !self.fifo_may_acquire(cx) {
            return Poll::Pending;
        }

        match self.kind {
            WaiterKind::Reader => lock.readers.set(lock.readers.get() + 1),
            WaiterKind::Writer => {
                debug_assert_eq!(lock.readers.get(), 0);
                lock.writer.set(true);
            }
        }
        Poll::Ready(())
    }
}

pub struct LocalRwLockReadWaiter<'a, T> {
    waiter: Waiter<'a, T>,
}

impl<'a, T> Future for LocalRwLockReadWaiter<'a, T> {
    type Output = LocalRwLockReadGuard<'a, T>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let lock = self.waiter.lock;
        self.waiter
            .poll_acquire(cx)
            .map(|()| LocalRwLockReadGuard { lock })
    }
}

pub struct LocalRwLockWriteWaiter<'a, T> {
    waiter: Waiter<'a, T>,
}

impl<'a, T> Future for LocalRwLockWriteWaiter<'a, T> {
    type Output = LocalRwLockWriteGuard<'a, T>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let lock = self.waiter.lock;
        self.waiter
            .poll_acquire(cx)
            .map(|()| LocalRwLockWriteGuard { lock })
    }
}

pub struct LocalRwLockReadGuard<'a, T> {
    lock: &'a LocalRwLock<T>,
}

impl<T> Deref for LocalRwLockReadGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Safety: read guards coexist only with other read guards, so only
        // shared references to the value are live.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for LocalRwLockReadGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        let readers = self.lock.readers.get();
        debug_assert!(readers > 0);
        debug_assert!(!self.lock.writer.get());
        self.lock.readers.set(readers - 1);
        if readers == 1 {
            // The lock is now free; wake the front waiter (of either kind).
            self.lock.wake_next_waiter();
        }
    }
}

pub struct LocalRwLockWriteGuard<'a, T> {
    lock: &'a LocalRwLock<T>,
}

impl<T> Deref for LocalRwLockWriteGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Safety: the write guard is exclusive.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for LocalRwLockWriteGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // Safety: the write guard is exclusive.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for LocalRwLockWriteGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        debug_assert!(self.lock.writer.get());
        debug_assert_eq!(self.lock.readers.get(), 0);
        self.lock.writer.set(false);
        self.lock.wake_next_waiter();
    }
}
