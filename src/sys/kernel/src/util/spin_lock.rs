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
use core::sync::atomic::Ordering::{AcqRel, Relaxed, Release};

pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T> Sync for SpinLock<T> where T: Send {}

pub struct LockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

unsafe impl<T> Sync for LockGuard<'_, T> where T: Sync {}

impl<T> Default for SpinLock<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: T::default().into(),
        }
    }
}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub fn lock(&self, lockword: u32) -> LockGuard<'_, T> {
        let mut iters = 0_u64;
        while self.locked.swap(true, AcqRel) {
            // Spin while the lock is already locked.
            while self.locked.load(Relaxed) {
                iters += 1;
                if iters > 100_000_000 {
                    panic!("spin_lock.rs: deadlock? {}", lockword);
                }
                core::hint::spin_loop();
            }
        }
        LockGuard { lock: self }
    }
}

impl<T> Deref for LockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Safety: The very existence of this Guard
        // guarantees we've exclusively locked the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for LockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // Safety: The very existence of this Guard
        // guarantees we've exclusively locked the lock.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for LockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Release);
    }
}

/*
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

pub struct SpinLock<T: ?Sized> {
    lock_word: AtomicU32, // Unlocked == 0.

    #[cfg(debug_assertions)]
    lock_cpu: AtomicU32,

    data: UnsafeCell<T>,
}

#[derive(Debug)]
pub struct LockGuard<'a, T: ?Sized> {
    lock_word: &'a AtomicU32,
    data: &'a mut T,
}

unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(user_data: T) -> SpinLock<T> {
        SpinLock {
            lock_word: AtomicU32::new(0),

            #[cfg(debug_assertions)]
            lock_cpu: AtomicU32::new(u32::MAX),

            data: UnsafeCell::new(user_data),
        }
    }
}

impl<T: ?Sized> SpinLock<T> {
    fn obtain_lock(&self, lockword: u32) {
        assert_ne!(0, lockword);
        let mut outer_iter = 0_u64;
        while self
            .lock_word
            .compare_exchange(0, lockword, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            outer_iter += 1;
            if outer_iter > 1_000 {
                #[cfg(debug_assertions)]
                log::error!(
                    "spinlock deadlock: {}:{}",
                    self.lock_cpu.load(Ordering::Acquire),
                    self.lock_word.load(Ordering::Acquire)
                );
                panic!(
                    "spinlock outer deadlock: {}",
                    self.lock_word.load(Ordering::Acquire)
                )
            }
            // Wait until the lock looks unlocked before retrying.
            let mut inner_iter = 0_u64;
            while self.lock_word.load(Ordering::Relaxed) != 0 {
                inner_iter += 1;
                if inner_iter > 100_000_000 {
                    #[cfg(debug_assertions)]
                    {
                        let cpu = self.lock_cpu.load(Ordering::Acquire) as crate::config::uCpus;
                        log::error!(
                            "spinlock deadlock: {}:{}",
                            cpu,
                            self.lock_word.load(Ordering::Acquire)
                        );
                        super::print_stack_trace_and_die(cpu);
                        #[allow(clippy::empty_loop)]
                        loop {}
                    }
                    #[cfg(not(debug_assertions))]
                    panic!(
                        "spinlock inner deadlock: {}",
                        self.lock_word.load(Ordering::Acquire)
                    )
                }
                core::hint::spin_loop();
            }
        }

        #[cfg(debug_assertions)]
        self.lock_cpu
            .store(crate::arch::current_cpu() as u32, Ordering::Release);
    }

    pub fn lock(&self, lockword: u32) -> LockGuard<'_, T> {
        self.obtain_lock(lockword);
        LockGuard {
            lock_word: &self.lock_word,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

impl<T: Default> Default for SpinLock<T> {
    fn default() -> SpinLock<T> {
        SpinLock::new(Default::default())
    }
}

impl<T: ?Sized> Deref for LockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &*self.data
    }
}

impl<T: ?Sized> DerefMut for LockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.data
    }
}

impl<T: ?Sized> Drop for LockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock_word.store(0, Ordering::SeqCst);
    }
}
*/
