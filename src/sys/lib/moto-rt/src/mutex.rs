// A futex-based mutex, to be used in no-std environments.
// Inspired by spin::Mutex.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
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
        const BUSY_LOOP_ITERS: i32 = 128;
        let mut busy_loop_counter = 0;
        while self
            .lock
            .compare_exchange_weak(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if busy_loop_counter < BUSY_LOOP_ITERS {
                busy_loop_counter += 1;
                core::hint::spin_loop();
                continue;
            }
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

impl<T: Default> Default for Mutex<T> {
    fn default() -> Mutex<T> {
        Mutex::new(Default::default())
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &*self.data
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.data
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.store(UNLOCKED, Ordering::Release);
        crate::futex_wake(self.lock);
    }
}
