//! Locks. A slab has one readers/writer guard and one spinlock for its
//! partial stack. Readers are ordinary allocation and free; the writer is
//! growth's link step or reclaim, which then has the slab to itself. Neither
//! lock is ever held across a backend call.
//!
//! Reader counts are sharded: each shard is a cache line of its own, and a
//! thread counts itself in the shard of the CPU it runs on, so readers on
//! different CPUs never write the same line. The writer bit lives in the
//! slab and the writer waits for every shard to drain.

use core::sync::atomic::{AtomicU32, Ordering};

const WRITER: u32 = 1;

/// Reader shards per slab. Two threads sharing one only share a line.
pub(crate) const SHARDS: usize = 16;

/// One reader count on its own cache line.
#[repr(align(64))]
pub(crate) struct ReaderShard(AtomicU32);

impl ReaderShard {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
}

/// The writer side of a slab guard; readers are counted in `ReaderShard`s.
pub(crate) struct RwLock(AtomicU32);

impl RwLock {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    fn writer_pending(&self) -> bool {
        self.0.load(Ordering::SeqCst) & WRITER != 0
    }

    /// Joins as a reader in `shard` unless a writer holds or is taking the
    /// guard. The count is touched only when no writer is pending, so a
    /// draining writer sees it reach zero.
    pub fn try_read_lock(&self, shard: &ReaderShard) -> bool {
        if self.writer_pending() {
            return false;
        }
        shard.0.fetch_add(1, Ordering::SeqCst);
        if self.writer_pending() {
            shard.0.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        true
    }

    pub fn read_lock(&self, shard: &ReaderShard) {
        while !self.try_read_lock(shard) {
            core::hint::spin_loop();
        }
    }

    pub fn read_unlock(&self, shard: &ReaderShard) {
        shard.0.fetch_sub(1, Ordering::SeqCst);
    }

    /// Takes the writer role if nobody else holds it, then waits for every
    /// shard to drain. Returns false at once if another writer holds it.
    pub fn try_write_lock(&self, shards: &[ReaderShard]) -> bool {
        if self.0.fetch_or(WRITER, Ordering::SeqCst) & WRITER != 0 {
            return false;
        }
        for shard in shards {
            while shard.0.load(Ordering::SeqCst) != 0 {
                core::hint::spin_loop();
            }
        }
        true
    }

    pub fn write_lock(&self, shards: &[ReaderShard]) {
        loop {
            while self.writer_pending() {
                core::hint::spin_loop();
            }
            if self.try_write_lock(shards) {
                return;
            }
        }
    }

    pub fn write_unlock(&self) {
        let val = self.0.fetch_xor(WRITER, Ordering::SeqCst);
        assert_eq!(val & WRITER, WRITER);
    }

    #[cfg(test)]
    pub fn is_write_locked(&self) -> bool {
        self.writer_pending()
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
