/// A minimalistic SpinLock.
//
// A slightly modified version of
// https://github.com/m-ou-se/rust-atomics-and-locks/blob/main/src/ch4_spin_lock/s3_guard.rs
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
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::{AcqRel, Release};

#[derive(Default)]
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T> Sync for SpinLock<T> where T: Send {}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
}

unsafe impl<T> Sync for Guard<'_, T> where T: Sync {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn lock(&self) -> Guard<'_, T> {
        while self.locked.swap(true, AcqRel) {
            core::hint::spin_loop();
        }
        Guard { lock: self }
    }
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Safety: The very existence of this Guard
        // guarantees we've exclusively locked the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // Safety: The very existence of this Guard
        // guarantees we've exclusively locked the lock.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Release);
    }
}
