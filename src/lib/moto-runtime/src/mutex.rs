// A futex-based mutex, to be used in no-std environments.
// Inspired by spin::Mutex.

use core::cell::UnsafeCell;
use core::default::Default;
use core::marker::Sync;
use core::ops::{Deref, DerefMut, Drop};
use core::sync::atomic::{AtomicU32, Ordering};

pub struct Mutex<T: ?Sized> {
    lock: AtomicU32,
    data: UnsafeCell<T>,
}

#[derive(Debug)]
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a AtomicU32,
    data: &'a mut T,
}

unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;

impl<T> Mutex<T> {
    pub const fn new(user_data: T) -> Mutex<T> {
        Mutex {
            lock: AtomicU32::new(UNLOCKED),
            data: UnsafeCell::new(user_data),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    fn obtain_lock(&self) {
        while self
            .lock
            .compare_exchange_weak(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::futex_wait(&self.lock, LOCKED, None);
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.obtain_lock();
        MutexGuard {
            lock: &self.lock,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

impl<T: ?Sized + Default> Default for Mutex<T> {
    fn default() -> Mutex<T> {
        Mutex::new(Default::default())
    }
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
    type Target = T;
    fn deref<'b>(&'b self) -> &'b T {
        &*self.data
    }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
    fn deref_mut<'b>(&'b mut self) -> &'b mut T {
        &mut *self.data
    }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.store(UNLOCKED, Ordering::Release);
        crate::futex_wake(self.lock);
    }
}
