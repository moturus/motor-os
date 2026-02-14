//! An async mutex.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use core::cell::{RefCell, UnsafeCell};
use core::ops::{Deref, DerefMut};
use core::task::LocalWaker;

extern crate alloc;

#[derive(Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Unlocked,
    Locked,
}

#[derive(Default)]
pub struct LocalMutex<T> {
    state: RefCell<State>,
    value: UnsafeCell<T>,

    // Waiters.
    next_waiter_id: RefCell<u64>,
    // Use a VecDeque to maintain mutex fairness.
    wait_queue: RefCell<VecDeque<u64>>,
    // Use a BTreeMap to keep track of (gone) waiters and their latest wakers.
    waiters: RefCell<BTreeMap<u64, LocalWaker>>,
}

pub struct LocalMutexGuard<'a, T> {
    mutex: &'a LocalMutex<T>,
}

pub struct LocalMutexWaiter<'a, T> {
    mutex: &'a LocalMutex<T>,
    id: u64, // zero => not registered.
}

impl<'a, T> Drop for LocalMutexWaiter<'a, T> {
    fn drop(&mut self) {
        if core::hint::unlikely(self.id != 0) {
            // This waiter was polled, but then dropped without acquiring
            // the mutex (e.g. cancelled via select/timeout).
            assert!(self.mutex.waiters.borrow_mut().remove(&self.id).is_some());
            let Some(next_waiter_id) = self.mutex.wait_queue.borrow().front().copied() else {
                return;
            };

            if self.id == next_waiter_id && (*self.mutex.state.borrow() == State::Unlocked) {
                self.mutex.wake_next_waiter();
            }
        }
    }
}

impl<'a, T> Future for LocalMutexWaiter<'a, T> {
    type Output = LocalMutexGuard<'a, T>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        let mut state = self.mutex.state.borrow_mut();
        let mut wait_queue = self.mutex.wait_queue.borrow_mut();
        let mut waiters = self.mutex.waiters.borrow_mut();

        if *state == State::Locked {
            if self.id == 0 {
                self.id = self.mutex.next_waiter_id();
                waiters.insert(self.id, cx.local_waker().clone());
                wait_queue.push_back(self.id);
            } else {
                // Update the waker.
                *waiters.get_mut(&self.id).unwrap() = cx.local_waker().clone();
            }

            return core::task::Poll::Pending;
        }

        // Unlocked.
        loop {
            let Some(waiter_id) = wait_queue.front() else {
                // No waiters.
                debug_assert!(waiters.is_empty());
                debug_assert_eq!(self.id, 0);
                *state = State::Locked;
                return core::task::Poll::Ready(LocalMutexGuard { mutex: self.mutex });
            };

            if *waiter_id == self.id {
                // Our turn: all is good.
                *state = State::Locked;
                assert!(waiters.remove(&self.id).is_some());
                self.id = 0; // Mark not registered so that Drop behaves correctly.
                return core::task::Poll::Ready(LocalMutexGuard { mutex: self.mutex });
            }

            if let Some(waker) = waiters.get(waiter_id) {
                // Not our turn.
                waker.wake_by_ref();
                if self.id == 0 {
                    self.id = self.mutex.next_waiter_id();
                    waiters.insert(self.id, cx.local_waker().clone());
                    wait_queue.push_back(self.id);
                } else {
                    // Update the waker.
                    *waiters.get_mut(&self.id).unwrap() = cx.local_waker().clone();
                }

                return core::task::Poll::Pending;
            }

            // The waiter is gone.
            wait_queue.pop_front();
        }
    }
}

impl<T> LocalMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: RefCell::new(State::Unlocked),
            value: UnsafeCell::new(value),
            next_waiter_id: RefCell::new(1),
            waiters: RefCell::new(BTreeMap::new()),
            wait_queue: RefCell::new(VecDeque::new()),
        }
    }

    fn next_waiter_id(&self) -> u64 {
        let mut id_ref = self.next_waiter_id.borrow_mut();
        let result = *id_ref;
        *id_ref += 1;
        result
    }

    fn wake_next_waiter(&self) {
        let mut wait_queue = self.wait_queue.borrow_mut();
        let waiters = self.waiters.borrow();
        loop {
            let Some(waiter_id) = wait_queue.front() else {
                return;
            };

            if let Some(waker) = waiters.get(waiter_id) {
                waker.wake_by_ref();
                return;
            }

            wait_queue.pop_front();
        }
    }

    #[inline]
    pub fn lock(&self) -> LocalMutexWaiter<'_, T> {
        LocalMutexWaiter { mutex: self, id: 0 }
    }
}

impl<T> Deref for LocalMutexGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Safety: safe by construction.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for LocalMutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // Safety: safe by construction.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for LocalMutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        let mut state = self.mutex.state.borrow_mut();
        assert_eq!(*state, State::Locked);
        *state = State::Unlocked;
        core::mem::drop(state);

        self.mutex.wake_next_waiter();
    }
}
