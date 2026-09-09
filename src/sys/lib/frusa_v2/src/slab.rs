//! A size class: its batch list, the partial stack of blocks that have a
//! free slot, and the address-sorted index that maps a pointer to its block.
//!
//! The index and the batch list change only under the slab's write guard
//! (growth's link step, reclaim). The partial stack changes under the
//! partial lock, or under the write guard, which excludes every holder of
//! the read guard and therefore of the partial lock.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use crate::block::Block;
use crate::sync::{RwLock, SpinLock};

/// Smallest index capacity, one 4 KiB page of pointers.
pub(crate) const INDEX_MIN_CAP: usize = 512;

#[repr(C)]
pub(crate) struct Slab {
    pub entry_sz_log2: u32,
    /// Position in the allocator's slab table; the metadata slab is last.
    pub table_idx: u32,
    pub guard: RwLock,
    pub partial_lock: SpinLock,
    /// Batch list: newest batch first, each batch contiguous in it.
    pub head: AtomicPtr<Block>,
    pub bytes_total: AtomicUsize,
    pub partial_head: AtomicPtr<Block>,
    /// Address-sorted block pointers; null until the first growth.
    pub index: AtomicPtr<*mut Block>,
    pub index_len: AtomicU32,
    pub index_cap: AtomicU32,
    _reserved: [u64; 1], // Keeps size_of::<Self>() at 64.
}

const _: () = assert!(core::mem::size_of::<Slab>() == 64);

/// The blocks of a batch list or a batch, following `next` links.
pub(crate) struct Blocks {
    cur: *mut Block,
    left: usize,
}

impl Iterator for Blocks {
    type Item = *mut Block;

    fn next(&mut self) -> Option<*mut Block> {
        if self.cur.is_null() || self.left == 0 {
            return None;
        }
        let block = self.cur;
        self.cur = unsafe { (*block).next.load(Ordering::Acquire) };
        self.left -= 1;
        Some(block)
    }
}

impl Slab {
    pub const fn new(entry_sz_log2: u32, table_idx: u32) -> Self {
        Self {
            entry_sz_log2,
            table_idx,
            guard: RwLock::new(),
            partial_lock: SpinLock::new(),
            head: AtomicPtr::new(core::ptr::null_mut()),
            bytes_total: AtomicUsize::new(0),
            partial_head: AtomicPtr::new(core::ptr::null_mut()),
            index: AtomicPtr::new(core::ptr::null_mut()),
            index_len: AtomicU32::new(0),
            index_cap: AtomicU32::new(0),
            _reserved: [0; 1],
        }
    }

    pub fn block_size(&self) -> usize {
        Block::ENTRIES << self.entry_sz_log2
    }

    // ---- batch list (write guard) ----

    /// Prepends a batch whose blocks are already chained by `next`.
    pub fn link_batch(&self, first: *mut Block, last: *mut Block) {
        unsafe {
            (*last)
                .next
                .store(self.head.load(Ordering::Acquire), Ordering::Release)
        };
        self.head.store(first, Ordering::Release);
    }

    /// Every block in the batch list. Stable under either guard.
    pub fn blocks(&self) -> Blocks {
        Blocks {
            cur: self.head.load(Ordering::Acquire),
            left: usize::MAX,
        }
    }

    /// The `len` blocks starting at `first`.
    pub fn batch(first: *mut Block, len: usize) -> Blocks {
        Blocks {
            cur: first,
            left: len,
        }
    }

    /// Bytes held by live slots, summed over the batch list.
    pub fn in_use_bytes(&self) -> usize {
        let mut slots = 0usize;
        for block in self.blocks() {
            slots += unsafe { (*block).used_bitmap.load(Ordering::Relaxed) }.count_ones() as usize;
        }
        slots << self.entry_sz_log2
    }

    // ---- partial stack (partial lock or write guard) ----

    /// Pushes a block unless it is already on the stack.
    pub fn stack_push(&self, block: *mut Block) {
        let b = unsafe { &*block };
        if b.on_stack() {
            return;
        }
        b.set_on_stack(true);
        b.partial_next
            .store(self.partial_head.load(Ordering::Relaxed), Ordering::Relaxed);
        self.partial_head.store(block, Ordering::Release);
    }

    pub fn stack_pop(&self) -> *mut Block {
        let top = self.partial_head.load(Ordering::Relaxed);
        if !top.is_null() {
            let b = unsafe { &*top };
            self.partial_head
                .store(b.partial_next.load(Ordering::Relaxed), Ordering::Release);
            b.set_on_stack(false);
        }
        top
    }

    /// Rebuilds the stack from the batch list: every non-full block without
    /// an owner. Write guard only.
    pub fn stack_rebuild(&self) {
        self.partial_head
            .store(core::ptr::null_mut(), Ordering::Release);
        for block in self.blocks() {
            let b = unsafe { &*block };
            b.set_on_stack(false);
            if !b.is_full() && b.owner.load(Ordering::Relaxed).is_null() {
                self.stack_push(block);
            }
        }
    }

    /// Claims a slot from the top of the partial stack, popping the block
    /// once it is full. Null means the slab has no free slot and must grow.
    pub fn alloc(&self) -> *mut u8 {
        if self.partial_head.load(Ordering::Acquire).is_null() {
            return core::ptr::null_mut();
        }
        let _lock = self.partial_lock.lock();
        loop {
            crate::stack_counted();
            let top = self.partial_head.load(Ordering::Relaxed);
            if top.is_null() {
                return core::ptr::null_mut();
            }
            match unsafe { (*top).alloc() } {
                Some((ptr, became_full)) => {
                    if became_full {
                        self.stack_pop();
                    }
                    return ptr;
                }
                None => {
                    // A full block never belongs on the stack.
                    debug_assert!(false, "FRUSA: full block on the partial stack");
                    self.stack_pop();
                }
            }
        }
    }

    // ---- sorted index (read under the read guard, written under the write guard) ----

    fn index_slice(&self) -> &[*mut Block] {
        let base = self.index.load(Ordering::Acquire);
        let len = self.index_len.load(Ordering::Acquire) as usize;
        if base.is_null() {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(base, len) }
        }
    }

    /// The block whose data starts at the greatest address not above `ptr`,
    /// or null. The caller validates the range with `Block::slot_of`.
    pub fn lookup(&self, ptr: *mut u8) -> *mut Block {
        let index = self.index_slice();
        let mut lo = 0usize;
        let mut hi = index.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            crate::probe_counted();
            if unsafe { (*index[mid]).data } as usize <= ptr as usize {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            core::ptr::null_mut()
        } else {
            index[lo - 1]
        }
    }

    /// The capacity a replacement array needs to hold `extra` more blocks,
    /// or `None` if the current one suffices.
    pub fn index_growth(&self, extra: usize) -> Option<usize> {
        let len = self.index_len.load(Ordering::Acquire) as usize;
        let cap = self.index_cap.load(Ordering::Acquire) as usize;
        if len + extra <= cap {
            return None;
        }
        let mut new_cap = cap.max(INDEX_MIN_CAP);
        while new_cap < len + extra {
            new_cap *= 2;
        }
        Some(new_cap)
    }

    /// Installs a larger array, copying the entries. Returns the old array
    /// and its capacity for the caller to free after releasing the guard.
    pub fn index_install(&self, array: *mut *mut Block, cap: usize) -> (*mut *mut Block, usize) {
        let old = self.index.load(Ordering::Acquire);
        let old_cap = self.index_cap.load(Ordering::Acquire) as usize;
        let len = self.index_len.load(Ordering::Acquire) as usize;
        assert!(cap >= len);
        if !old.is_null() {
            unsafe { core::ptr::copy_nonoverlapping(old, array, len) };
        }
        self.index.store(array, Ordering::Release);
        self.index_cap.store(cap as u32, Ordering::Release);
        (old, old_cap)
    }

    /// Inserts a batch of `num` blocks with consecutive data addresses,
    /// chained by `next` from `first`. Capacity must already suffice.
    pub fn index_insert_batch(&self, first: *mut Block, num: usize) {
        let len = self.index_len.load(Ordering::Acquire) as usize;
        assert!(len + num <= self.index_cap.load(Ordering::Acquire) as usize);
        let base = self.index.load(Ordering::Acquire);
        let index = unsafe { core::slice::from_raw_parts_mut(base, len + num) };
        let start = unsafe { (*first).data } as usize;
        let pos = index[..len].partition_point(|b| (unsafe { (**b).data } as usize) < start);
        index.copy_within(pos..len, pos + num);
        for (slot, block) in index[pos..pos + num]
            .iter_mut()
            .zip(Self::batch(first, num))
        {
            *slot = block;
        }
        self.index_len.store((len + num) as u32, Ordering::Release);
    }

    /// Rebuilds the index from the batch list. Write guard only.
    pub fn index_rebuild(&self) {
        let base = self.index.load(Ordering::Acquire);
        if base.is_null() {
            debug_assert!(self.head.load(Ordering::Acquire).is_null());
            return;
        }
        let cap = self.index_cap.load(Ordering::Acquire) as usize;
        let mut len = 0usize;
        for block in self.blocks() {
            assert!(len < cap);
            unsafe { base.add(len).write(block) };
            len += 1;
        }
        let index = unsafe { core::slice::from_raw_parts_mut(base, len) };
        index.sort_unstable_by_key(|b| unsafe { (**b).data } as usize);
        self.index_len.store(len as u32, Ordering::Release);
    }

    #[cfg(test)]
    pub fn check_index(&self) {
        let index = self.index_slice();
        for pair in index.windows(2) {
            assert!(unsafe { (*pair[0]).data } < unsafe { (*pair[1]).data });
        }
        let listed = self.blocks().count();
        assert_eq!(listed, index.len());
        for block in self.blocks() {
            assert!(index.contains(&block));
        }
    }

    #[cfg(test)]
    pub fn check_stack(&self) {
        let mut seen = 0usize;
        let mut cur = self.partial_head.load(Ordering::Relaxed);
        while !cur.is_null() {
            let b = unsafe { &*cur };
            assert!(b.on_stack());
            assert!(!b.is_full());
            assert!(b.owner.load(Ordering::Relaxed).is_null());
            seen += 1;
            assert!(seen <= self.blocks().count(), "cycle in the partial stack");
            cur = b.partial_next.load(Ordering::Relaxed);
        }
        let expected = self
            .blocks()
            .filter(|b| unsafe {
                !(**b).is_full() && (**b).owner.load(Ordering::Relaxed).is_null()
            })
            .count();
        assert_eq!(seen, expected);
    }
}
