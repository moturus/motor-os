//! Per-class free lists sharded by CPU. A free pushes the slot on the list
//! of the caller's shard and an allocation pops from it. A slot on a list
//! stays marked in use in its block, so listing changes no block state and
//! the slab paths are untouched. Each list has a spinlock that is only ever
//! tried, never spun on: a busy list is skipped and the caller uses its
//! next tier. Memory on a list is reachable from every thread -- an
//! allocation that would otherwise grow its slab first takes from the other
//! shards' lists, and reclaim drains them -- so the lists pin nothing the
//! way a private cache would.
//!
//! The list runs through the slots themselves: word 0 holds the next slot's
//! address XOR the slot's own address shifted right by 12, so a stale or
//! overwritten link is unlikely to decode to a usable pointer; word 1 holds
//! the list's key, which flags a double free. Slots are at least 16 bytes,
//! so both words fit.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::sync::SpinLock;

/// One list on its own cache line.
#[repr(align(64))]
pub(crate) struct ShardList {
    lock: SpinLock,
    /// Written under `lock`; read without it only as a hint.
    head: AtomicPtr<u8>,
    len: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<ShardList>() == 64);

impl ShardList {
    pub const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            head: AtomicPtr::new(core::ptr::null_mut()),
            len: AtomicU32::new(0),
        }
    }

    /// The word a listed slot carries to flag a double free.
    fn key(&self) -> usize {
        self as *const Self as usize ^ 0x5FEE_1157_0000_0000
    }

    fn next_of(slot: *mut u8) -> *mut u8 {
        (unsafe { *(slot as *const usize) } ^ (slot as usize >> 12)) as *mut u8
    }

    /// Takes the most recently pushed slot, or null when the list is empty
    /// or busy. A link that does not decode to a slot boundary of the
    /// class is corruption.
    #[inline(always)]
    pub fn pop(&self, entry_sz_log2: u32) -> *mut u8 {
        if self.head.load(Ordering::Relaxed).is_null() {
            return core::ptr::null_mut();
        }
        let Some(_guard) = self.lock.try_lock() else {
            return core::ptr::null_mut();
        };
        let slot = self.head.load(Ordering::Relaxed);
        if slot.is_null() {
            return slot;
        }
        let next = Self::next_of(slot);
        assert!(
            next as usize & ((1usize << entry_sz_log2) - 1) == 0,
            "FRUSA: corrupted free list"
        );
        unsafe { *(slot as *mut usize).add(1) = 0 };
        self.head.store(next, Ordering::Relaxed);
        self.len
            .store(self.len.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
        slot
    }

    /// Lists `slot` unless the list holds `limit` slots already or is
    /// busy. Returns whether it did.
    #[inline(always)]
    pub fn push(&self, slot: *mut u8, limit: u32) -> bool {
        if self.len.load(Ordering::Relaxed) >= limit {
            return false;
        }
        let Some(_guard) = self.lock.try_lock() else {
            return false;
        };
        let len = self.len.load(Ordering::Relaxed);
        if len >= limit {
            return false;
        }
        let words = slot as *mut usize;
        let key = self.key();
        if unsafe { *words.add(1) } == key {
            // The key can survive in a slot that was handed out and never
            // written; a slot that is still on the list is a double free.
            let mut cur = self.head.load(Ordering::Relaxed);
            while !cur.is_null() {
                assert!(cur != slot, "FRUSA: double free");
                cur = Self::next_of(cur);
            }
        }
        unsafe {
            *words = self.head.load(Ordering::Relaxed) as usize ^ (slot as usize >> 12);
            *words.add(1) = key;
        }
        self.head.store(slot, Ordering::Relaxed);
        self.len.store(len + 1, Ordering::Relaxed);
        true
    }

    #[cfg(test)]
    pub fn len(&self) -> u32 {
        self.len.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn hold_for_test(&self) -> crate::sync::SpinGuard<'_> {
        self.lock.lock()
    }
}
