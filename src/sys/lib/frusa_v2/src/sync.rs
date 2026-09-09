//! Locks. A slab has one read/write guard and one spinlock for its partial
//! stack. Readers are ordinary allocation and free; the writer is growth's
//! link step or reclaim, which then has the slab to itself. Neither lock is
//! ever held across a backend call.

use core::sync::atomic::{AtomicU32, Ordering};

const WRITER: u32 = 1;
const READER: u32 = 2;
// A reader that observes a count above this backs off: the writer bit or an
// absurd reader count means the word is not in a state to join.
const MAX_LOCK_VALUE: u32 = u32::MAX / 2;

/// Readers/writer guard. Readers spin while a writer holds it; a writer
/// waits for readers to drain.
pub(crate) struct RwLock(AtomicU32);

impl RwLock {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    pub fn try_read_lock(&self) -> bool {
        let val = self.0.fetch_add(READER, Ordering::SeqCst);
        if val > MAX_LOCK_VALUE || val & WRITER != 0 {
            self.0.fetch_sub(READER, Ordering::SeqCst);
            false
        } else {
            true
        }
    }

    pub fn read_lock(&self) {
        while !self.try_read_lock() {
            core::hint::spin_loop();
        }
    }

    pub fn read_unlock(&self) {
        self.0.fetch_sub(READER, Ordering::SeqCst);
    }

    /// Takes the writer role if nobody else holds it, then waits for the
    /// readers to drain. Returns false at once if another writer holds it.
    pub fn try_write_lock(&self) -> bool {
        let mut val = self.0.fetch_or(WRITER, Ordering::SeqCst);
        if val & WRITER != 0 {
            return false;
        }
        while val != WRITER {
            core::hint::spin_loop();
            val = self.0.load(Ordering::SeqCst);
        }
        true
    }

    pub fn write_lock(&self) {
        while !self.try_write_lock() {
            core::hint::spin_loop();
        }
    }

    pub fn write_unlock(&self) {
        let val = self.0.fetch_xor(WRITER, Ordering::SeqCst);
        assert_eq!(val & WRITER, WRITER);
    }

    #[cfg(test)]
    pub fn is_write_locked(&self) -> bool {
        self.0.load(Ordering::SeqCst) & WRITER != 0
    }
}

/// A plain spinlock. Critical sections under it are a few loads and one
/// compare-and-swap, so spinning is the right choice.
pub(crate) struct SpinLock(AtomicU32);

pub(crate) struct SpinGuard<'a>(&'a SpinLock);

impl SpinLock {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    pub fn lock(&self) -> SpinGuard<'_> {
        loop {
            if self
                .0
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return SpinGuard(self);
            }
            while self.0.load(Ordering::Relaxed) != 0 {
                core::hint::spin_loop();
            }
        }
    }

    #[cfg(test)]
    pub fn is_locked(&self) -> bool {
        self.0.load(Ordering::SeqCst) != 0
    }
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.0.0.store(0, Ordering::Release);
    }
}
