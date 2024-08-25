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

impl<T: ?Sized + Default> Default for SpinLock<T> {
    fn default() -> SpinLock<T> {
        SpinLock::new(Default::default())
    }
}

impl<'a, T: ?Sized> Deref for LockGuard<'a, T> {
    type Target = T;
    fn deref<'b>(&'b self) -> &'b T {
        &*self.data
    }
}

impl<'a, T: ?Sized> DerefMut for LockGuard<'a, T> {
    fn deref_mut<'b>(&'b mut self) -> &'b mut T {
        &mut *self.data
    }
}

impl<'a, T: ?Sized> Drop for LockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock_word.store(0, Ordering::SeqCst);
    }
}
