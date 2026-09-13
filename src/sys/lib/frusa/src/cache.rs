//! A thread's private blocks: one per cached class, allocated from without
//! touching any shared structure. The caller owns the cache and passes it
//! to the cached entry points; the crate never looks up thread state.
//!
//! Ownership protocol (see `docs/frusa.md`, per-thread caches): a block's `owner`
//! word names the cache holding it. It is set under the partial lock when
//! the block is popped, and cleared by its owner before the block can be
//! pushed again. A block with an owner is off the stack, is allocated from
//! only by its owner, and is never reclaimed.

use core::cell::Cell;

use crate::block::Block;

pub struct ThreadCache<const SLABS: usize> {
    pub(crate) current: [Cell<*mut Block>; SLABS],
    /// The reader shard this thread uses for the slab guards.
    pub(crate) shard: Cell<u32>,
}

impl<const SLABS: usize> ThreadCache<SLABS> {
    pub const fn new() -> Self {
        Self {
            current: [const { Cell::new(core::ptr::null_mut()) }; SLABS],
            shard: Cell::new(0),
        }
    }

    /// Selects the guard shard, normally the thread's current CPU.
    pub fn set_shard(&self, shard: u32) {
        self.shard.set(shard);
    }

    /// The value stored in an owned block's `owner` word.
    pub(crate) fn id(&self) -> *mut () {
        self as *const Self as *mut ()
    }
}

impl<const SLABS: usize> Default for ThreadCache<SLABS> {
    fn default() -> Self {
        Self::new()
    }
}
