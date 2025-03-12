/// A futex-based mutex, to be used in no-std environments.
//
// A slightly modified version of
// https://github.com/m-ou-se/rust-atomics-and-locks/blob/main/src/ch9_locks/mutex_3.rs
//
// which has this LICENCE:
//
// You may use all code in this repository for any purpose.
//
// Attribution is appreciated, but not required.
// An attribution usually includes the book title, author,
// publisher, and ISBN. For example: "Rust Atomics and
// Locks by Mara Bos (O’Reilly). Copyright 2023 Mara Bos,
// 978-1-098-11944-7."
//
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

const UNLOCKED: u32 = 0;
const LOCKED_NO_WAITERS: u32 = 1;
const LOCKED_YES_WAITERS: u32 = 2;

pub struct Mutex<T> {
    state: AtomicU32,
    value: UnsafeCell<T>,
}

unsafe impl<T> Sync for Mutex<T> where T: Send {}

pub struct MutexGuard<'a, T> {
    pub(crate) mutex: &'a Mutex<T>,
}

unsafe impl<T> Sync for MutexGuard<'_, T> where T: Sync {}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(UNLOCKED),
            value: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn lock(&self) -> MutexGuard<T> {
        if self
            .state
            .compare_exchange(UNLOCKED, LOCKED_NO_WAITERS, Acquire, Relaxed)
            .is_err()
        {
            // The lock was already locked. :(
            lock_contended(&self.state);
        }
        MutexGuard { mutex: self }
    }
}

#[cold]
fn lock_contended(state: &AtomicU32) {
    let mut spin_count = 0;
    const MAX_BUSY_LOOP_ITERS: u32 = 100;

    while state.load(Relaxed) == LOCKED_NO_WAITERS && spin_count < MAX_BUSY_LOOP_ITERS {
        spin_count += 1;
        core::hint::spin_loop();
    }

    if state
        .compare_exchange(UNLOCKED, LOCKED_NO_WAITERS, Acquire, Relaxed)
        .is_ok()
    {
        return;
    }

    while state.swap(LOCKED_YES_WAITERS, Acquire) != UNLOCKED {
        crate::futex_wait(state, LOCKED_YES_WAITERS, None);
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        if self.mutex.state.swap(UNLOCKED, Release) == LOCKED_YES_WAITERS {
            crate::futex_wake(&self.mutex.state);
        }
    }
}
