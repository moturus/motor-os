//! A Global Allocator with dynamic memory expansion and on-demand reclaim.
//!
//! It uses a fallback (system) allocator as its "back-end" allocator.
//!
//! Memory is requested from the fallback allocator dynamically (when needed)
//! and is returned back via an explicit reclaim() call (if not in use).

#![no_std]
#![feature(test)]

mod rwlock;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::*;

/// Basic usage statistics.
#[derive(Default, Clone, Copy)]
pub struct FrusaStats {
    pub allocated_from_fallback: usize,
    pub in_use: usize,
    pub allocated_metadata: usize,
    pub in_use_metadata: usize,
}

/// An allocator that manages allocations below 4K and uses
/// the fallback allocator for the rest.
pub struct Frusa4K {
    inner: Frusa<8>,
}

unsafe impl Send for Frusa4K {}
unsafe impl Sync for Frusa4K {}

unsafe impl GlobalAlloc for Frusa4K {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout)
    }
}

impl Frusa4K {
    pub const fn new(fallback: &'static dyn GlobalAlloc) -> Self {
        Self {
            inner: Frusa::<8>::new(fallback),
        }
    }

    pub fn reclaim(&self) {
        self.inner.reclaim();
    }

    pub fn stats(&self) -> FrusaStats {
        self.inner.stats()
    }
}

/// An allocator that manages allocations below 2M and uses
/// the fallback allocator for the rest.
pub struct Frusa2M {
    inner: Frusa<17>,
}

unsafe impl Send for Frusa2M {}
unsafe impl Sync for Frusa2M {}

unsafe impl GlobalAlloc for Frusa2M {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout)
    }
}

impl Frusa2M {
    pub const fn new(fallback: &'static dyn GlobalAlloc) -> Self {
        Self {
            inner: Frusa::<17>::new(fallback),
        }
    }

    pub fn reclaim(&self) {
        self.inner.reclaim();
    }

    pub fn stats(&self) -> FrusaStats {
        self.inner.stats()
    }
}

// *********************************************************************
// ****************** Private structs below. ***************************
// *********************************************************************

#[repr(C)]
struct Block {
    entry_sz_log2: u32,
    // Blocks are often allocated in "batches", i.e. several blocks together.
    // This has to be tracked for reclaim, as partial batch reclaim
    // is not possible.
    batch_pos: u16,
    batch_sz: u16,

    used_bitmap: AtomicU64,
    data: *mut u8, // entry_sz * 64
    next: AtomicPtr<Self>,
    _reserved: [u64; 4], // Bump size_of::<Self>() to 64.
}

impl Block {
    const BLOCK_ENTRIES: usize = 64;

    fn init(&mut self, entry_sz_log2: u32, batch_pos: u16, batch_sz: u16, data: *mut u8) {
        self.entry_sz_log2 = entry_sz_log2;
        self.batch_pos = batch_pos;
        self.batch_sz = batch_sz;
        self.used_bitmap.store(0, Ordering::Release);
        self.data = data;
        self.next.store(core::ptr::null_mut(), Ordering::Release);
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_ENTRIES << self.entry_sz_log2
    }

    fn alloc(&self) -> *mut u8 {
        let bitmap = self.used_bitmap.load(Ordering::Relaxed);
        let ones = bitmap.trailing_ones();
        if ones == 64 {
            return core::ptr::null_mut();
        }

        let bit = 1u64 << ones;
        assert_eq!(0, bitmap & bit);
        if self
            .used_bitmap
            .compare_exchange_weak(bitmap, bitmap | bit, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // Contention: use another block.
            return core::ptr::null_mut();
        }

        return unsafe { self.data.add((ones as usize) << self.entry_sz_log2) };
    }

    fn dealloc(&self, ptr: *mut u8) -> Result<(), ()> {
        if (ptr as usize) < (self.data as usize) {
            Err(())
        } else {
            let bit = ((ptr as usize) - (self.data as usize)) >> self.entry_sz_log2;
            if bit >= 64 {
                Err(())
            } else {
                let bit = 1_u64 << bit;
                let prev = self.used_bitmap.fetch_xor(bit, Ordering::Relaxed);
                assert_eq!(bit, prev & bit);

                Ok(())
            }
        }
    }
}

#[repr(C)]
struct Slab {
    entry_sz_log2: u32,
    reclaim_lock: AtomicU32,
    head: AtomicPtr<Block>,

    bytes_total: AtomicUsize,
    bytes_in_use: AtomicUsize,

    _reserved: [u64; 4], // Bump size_of::<Self>() to 64.
}

impl Slab {
    unsafe fn alloc(&self) -> *mut u8 {
        if self.bytes_in_use.load(Ordering::Relaxed) == self.bytes_total.load(Ordering::Relaxed) {
            return core::ptr::null_mut();
        }

        let mut pblock = loop {
            let head = self.head.load(Ordering::Acquire);
            if head != LOCKED_MARKER as *mut _ {
                break head;
            }
            core::hint::spin_loop();
        };

        while !pblock.is_null() {
            let maybe_alloc = (*pblock).alloc();
            if !maybe_alloc.is_null() {
                self.bytes_in_use
                    .fetch_add(1 << self.entry_sz_log2, Ordering::Relaxed);
                return maybe_alloc;
            }

            pblock = (*pblock).next.load(Ordering::Acquire);
        }

        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8) {
        let mut pblock = loop {
            let head = self.head.load(Ordering::Acquire);
            if head != LOCKED_MARKER as *mut _ {
                break head;
            }
            core::hint::spin_loop();
        };

        while !pblock.is_null() {
            if (*pblock).dealloc(ptr).is_ok() {
                self.bytes_in_use
                    .fetch_sub(1 << self.entry_sz_log2, Ordering::Relaxed);
                return;
            }

            pblock = (*pblock).next.load(Ordering::Acquire);
        }

        panic!("FRUSA: bad ptr for dealloc.");
    }

    const fn new(entry_sz_log2: u32) -> Self {
        Self {
            entry_sz_log2,
            reclaim_lock: rwlock::rwlock_new(),
            bytes_total: AtomicUsize::new(0),
            bytes_in_use: AtomicUsize::new(0),
            head: AtomicPtr::new(core::ptr::null_mut()),
            _reserved: [0; 4],
        }
    }

    fn add_blocks(&self, blocks: *mut Block, num_blocks: usize) {
        self.bytes_total.fetch_add(
            (num_blocks * Block::BLOCK_ENTRIES) << self.entry_sz_log2,
            Ordering::Relaxed,
        );
        // Use SeqCst because block data (non-atomic)
        // is changed concurrently.
        core::sync::atomic::fence(Ordering::SeqCst);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        assert_eq!(
            self.head.swap(blocks, Ordering::SeqCst),
            LOCKED_MARKER as *mut _
        );
    }

    fn try_lock(&self) -> Option<*mut Block> {
        let prev = self.head.load(Ordering::Acquire);
        if prev == LOCKED_MARKER as *mut _ {
            return None;
        }
        if self
            .head
            .compare_exchange(
                prev,
                LOCKED_MARKER as *mut _,
                Ordering::SeqCst,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // Use SeqCst because block data (non-atomic)
            // is changed concurrently.
            core::sync::atomic::fence(Ordering::SeqCst);
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            Some(prev)
        } else {
            None
        }
    }

    fn unlock(&self, head: *mut Block) {
        assert_eq!(
            self.head.swap(head, Ordering::AcqRel),
            LOCKED_MARKER as *mut _
        );
    }
}

#[repr(C)]
struct Frusa<const SLABS: usize> {
    fallback_allocator: &'static dyn GlobalAlloc,
    metadata_slab: Slab,
    data_slabs: AtomicPtr<[Slab; SLABS]>,
}

unsafe impl<const SLABS: usize> Send for Frusa<SLABS> {}
unsafe impl<const SLABS: usize> Sync for Frusa<SLABS> {}

const LOCKED_MARKER: usize = 1;

impl<const SLABS: usize> Frusa<SLABS> {
    const MIN_SIZE: usize = 16;
    const MAX_SIZE: usize = 1 << (SLABS + 3);
    const METADATA_SZ: usize = 64; // Full cache line to avoid false sharing.
    const PAGE_4K: usize = 4096;
    const PAGE_2M: usize = 2 * 1024 * 1024;

    pub const fn new(fallback_allocator: &'static dyn GlobalAlloc) -> Self {
        assert!(core::mem::size_of::<Block>() == Self::METADATA_SZ);
        assert!(core::mem::size_of::<Slab>() == Self::METADATA_SZ);
        assert!(core::mem::size_of::<usize>() == 8);
        assert!(Self::MAX_SIZE <= (1 << 30));

        Self {
            fallback_allocator,
            metadata_slab: Slab::new(Self::METADATA_SZ.ilog2()),
            data_slabs: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    pub fn stats(&self) -> FrusaStats {
        let mut result = FrusaStats::default();

        result.allocated_metadata = self.metadata_slab.bytes_total.load(Ordering::Relaxed);
        result.allocated_from_fallback = result.allocated_metadata;
        for slab in self.slabs() {
            result.allocated_from_fallback += slab.bytes_total.load(Ordering::Relaxed);
        }

        result.in_use_metadata = self.metadata_slab.bytes_in_use.load(Ordering::Relaxed);
        result.in_use = result.in_use_metadata;
        for slab in self.slabs() {
            result.in_use += slab.bytes_in_use.load(Ordering::Relaxed);
        }

        result
    }

    fn init(&self) {
        let locked_marker = LOCKED_MARKER as *mut _;
        if self
            .data_slabs
            .compare_exchange(
                core::ptr::null_mut(),
                locked_marker,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.do_init();
            return;
        }

        while self.data_slabs.load(Ordering::Acquire) == locked_marker {
            core::hint::spin_loop()
        }
    }

    fn do_init(&self) {
        assert!(self.metadata_slab.try_lock() == Some(core::ptr::null_mut()));
        let (blocks, num) = self.alloc_metadata_blocks(core::ptr::null_mut());
        if num == 0 {
            panic!("Cannot initialize FRUSA: OOM");
        }
        self.metadata_slab.add_blocks(blocks, num);

        unsafe {
            let meta_block = &mut *blocks;
            assert_eq!(meta_block.used_bitmap.load(Ordering::Relaxed), 1);

            let pslabs: *mut [Slab; SLABS] = ((blocks as usize) + Self::METADATA_SZ) as *mut _;
            let slabs = &mut *pslabs;

            let mut curr_used_bit = 2_u64;

            let mut entry_sz_log2 = Self::MIN_SIZE.ilog2();
            for idx in 0..SLABS {
                let slab = &mut slabs[idx];
                slab.entry_sz_log2 = entry_sz_log2;
                slab.bytes_total.store(0, Ordering::Relaxed);
                slab.bytes_in_use.store(0, Ordering::Relaxed);
                slab.head.store(core::ptr::null_mut(), Ordering::Release);

                meta_block
                    .used_bitmap
                    .fetch_xor(curr_used_bit, Ordering::AcqRel);
                curr_used_bit <<= 1;

                entry_sz_log2 += 1;
            }

            self.data_slabs.store(pslabs, Ordering::Release);
        }
        self.metadata_slab
            .bytes_in_use
            .fetch_add(SLABS << self.metadata_slab.entry_sz_log2, Ordering::Relaxed);
    }

    fn alloc_metadata_blocks(&self, prev_head: *mut Block) -> (*mut Block, usize) {
        // Unlike data blocks, which have their data separate from their
        // metadata, metadata blocks have their metadata embedded inside.
        unsafe {
            let layout = Layout::from_size_align(Self::PAGE_4K, Self::PAGE_4K).unwrap();
            let blocks = self.fallback_allocator.alloc(layout) as *mut Block;
            if blocks.is_null() {
                return (blocks, 0);
            }

            let mut pblock = blocks;
            let end = (blocks as usize) + Self::PAGE_4K;

            while (pblock as usize) < end {
                let block = &mut *pblock;

                block.init(Self::METADATA_SZ.ilog2(), 0, 0, pblock as *mut u8);
                // The first entry is the block's metadata.
                block.used_bitmap.store(1, Ordering::Release);

                let next = ((pblock as usize) + block.block_size()) as *mut Block;
                if (next as usize) < end {
                    block.next.store(next, Ordering::Release);
                } else {
                    block.next.store(prev_head, Ordering::Release);
                }

                pblock = next;
            }

            let num_blocks = Self::PAGE_4K / (Self::METADATA_SZ * Block::BLOCK_ENTRIES);
            self.metadata_slab.bytes_in_use.fetch_add(
                num_blocks << self.metadata_slab.entry_sz_log2,
                Ordering::Relaxed,
            );
            (blocks, num_blocks)
        }
    }

    unsafe fn alloc_metadata(&self) -> *mut u8 {
        loop {
            let maybe_alloc = self.metadata_slab.alloc();
            if !maybe_alloc.is_null() {
                return maybe_alloc;
            }

            if let Some(head) = self.metadata_slab.try_lock() {
                let (blocks, num) = self.alloc_metadata_blocks(head);
                if num == 0 {
                    self.metadata_slab.unlock(head);
                    return core::ptr::null_mut();
                }
                self.metadata_slab.add_blocks(blocks, num);
            } else {
                core::hint::spin_loop();
            }
        }
    }

    fn slabs(&self) -> &[Slab; SLABS] {
        // First/fast path, do a relaxed load.
        let data_slabs = self.data_slabs.load(Ordering::Relaxed);
        let addr = data_slabs as usize;
        if addr != 0 && addr != LOCKED_MARKER {
            return unsafe { &*data_slabs };
        }

        // If failed, do it properly.
        loop {
            let data_slabs = self.data_slabs.load(Ordering::Acquire);
            let addr = data_slabs as usize;
            if addr != 0 && addr != LOCKED_MARKER {
                return unsafe { &*data_slabs };
            }

            self.init();
        }
    }

    fn slab_for_sz(&self, sz: usize) -> &Slab {
        debug_assert!(sz.is_power_of_two());
        let sz = sz.max(Self::MIN_SIZE);

        let order: usize = sz.ilog2() as usize - 4;
        debug_assert!(order < SLABS);

        &self.slabs()[order]
    }

    fn sz_from_layout(layout: &Layout) -> Option<usize> {
        let sz = layout.size().next_power_of_two().max(layout.align());
        if sz <= Self::MAX_SIZE {
            Some(sz)
        } else {
            None
        }
    }

    unsafe fn alloc_from_slab(&self, slab: &Slab) -> *mut u8 {
        rwlock::read_lock(&slab.reclaim_lock);
        loop {
            let ptr = slab.alloc();
            if !ptr.is_null() {
                rwlock::read_unlock(&slab.reclaim_lock);
                return ptr;
            }

            // The slab is full. Add blocks to it.
            if let Some(head) = slab.try_lock() {
                if self.add_blocks_to_locked_slab(slab, head).is_err() {
                    slab.unlock(head);
                    rwlock::read_unlock(&slab.reclaim_lock);
                    return core::ptr::null_mut();
                }
            } else {
                core::hint::spin_loop();
            }
        }
    }

    unsafe fn add_blocks_to_locked_slab(
        &self,
        slab: &Slab,
        prev_head: *mut Block,
    ) -> Result<(), ()> {
        let block_sz = Block::BLOCK_ENTRIES << slab.entry_sz_log2;
        let alloc_sz = {
            let alloc_sz = block_sz;
            if alloc_sz <= Self::PAGE_4K {
                if slab.bytes_total.load(Ordering::Relaxed) < (alloc_sz << 3) {
                    // Initially, allocate in small chunks.
                    Self::PAGE_4K
                } else {
                    // If this proves not enough, allocate in larger chunks.
                    Self::PAGE_4K * 8
                }
            } else if alloc_sz <= Self::PAGE_4K * 64 {
                alloc_sz
            } else {
                alloc_sz.max(Self::PAGE_2M)
            }
        };
        let alloc_align = if alloc_sz < Self::PAGE_2M {
            Self::PAGE_4K
        } else {
            Self::PAGE_2M
        };

        let layout = Layout::from_size_align(alloc_sz, alloc_align).unwrap();
        let block_data = self.fallback_allocator.alloc(layout);
        if block_data.is_null() {
            return Err(());
        }

        let num_blocks = alloc_sz / block_sz;
        assert!(num_blocks <= u16::MAX as usize);
        debug_assert_eq!(num_blocks * block_sz, alloc_sz);

        let mut prev_block: *mut Block = core::ptr::null_mut();
        let mut blocks: *mut Block = core::ptr::null_mut();
        let mut curr_block_data = block_data;
        for idx in 0..num_blocks {
            let pblock: *mut Block = self.alloc_metadata() as *mut Block;
            if pblock.is_null() {
                // Free and return Err.
                for _ in 0..idx {
                    let next = (*blocks).next.load(Ordering::Acquire);
                    self.metadata_slab.dealloc(blocks as *mut u8);
                    blocks = next;
                }
                self.fallback_allocator.dealloc(block_data, layout);
                return Err(());
            }

            let block = &mut *pblock;

            block.init(
                slab.entry_sz_log2,
                idx as u16,
                num_blocks as u16,
                curr_block_data,
            );

            if let Some(block) = prev_block.as_mut() {
                block.next.store(pblock, Ordering::Release);
            }
            prev_block = pblock;
            if idx == 0 {
                blocks = pblock;
            }

            curr_block_data = curr_block_data.add(block_sz);
        }

        (*prev_block).next.store(prev_head, Ordering::Release);

        slab.add_blocks(blocks, num_blocks);
        Ok(())
    }

    unsafe fn dealloc_to_slab(&self, slab: &Slab, ptr: *mut u8) {
        rwlock::read_lock(&slab.reclaim_lock);
        slab.dealloc(ptr);
        rwlock::read_unlock(&slab.reclaim_lock);
    }

    fn reclaim(&self) {
        unsafe {
            for slab in self.slabs() {
                self.reclaim_slab(slab);
            }

            // TODO: reclaim metadata? (Cannot use the normal reclaim_slab()).
        }
    }

    unsafe fn reclaim_slab(&self, slab: &Slab) {
        if (slab.bytes_total.load(Ordering::Relaxed) - slab.bytes_in_use.load(Ordering::Relaxed))
            < Self::PAGE_4K
        {
            return; // Not enough unused bytes.
        }
        if !rwlock::single_write_lock(&slab.reclaim_lock) {
            return; // Another reclaim running.
        }
        let maybe_head = slab.try_lock();
        if maybe_head.is_none() {
            // If the slab is locked, it is full and needs more data,
            // so nothing to reclaim.
            rwlock::write_unlock(&slab.reclaim_lock);
            return;
        }
        let mut head = maybe_head.unwrap_unchecked();

        if head.is_null() {
            slab.unlock(head);
            rwlock::write_unlock(&slab.reclaim_lock);
            return;
        }

        // Use SeqCst because block data (non-atomic)
        // is changed concurrently.
        core::sync::atomic::fence(Ordering::SeqCst);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        let mut prev_block: *mut Block = core::ptr::null_mut();
        let mut batch_start = head;
        while !batch_start.is_null() {
            assert!(
                prev_block.is_null() || (*prev_block).next.load(Ordering::Relaxed) == batch_start
            );
            let (freed, batch_end_or_next) = self.maybe_free_batch(batch_start);

            if freed > 0 {
                slab.bytes_total.fetch_sub(freed, Ordering::Relaxed);
                // batch_end_or_next is next.
                if prev_block.is_null() {
                    head = batch_end_or_next;
                } else {
                    (*prev_block)
                        .next
                        .store(batch_end_or_next, Ordering::Release);
                }
                batch_start = batch_end_or_next;
            } else {
                // batch_end_or_next is batch_end.
                prev_block = batch_end_or_next;
                batch_start = (*batch_end_or_next).next.load(Ordering::Acquire);
            }
        }

        slab.unlock(head);
        rwlock::write_unlock(&slab.reclaim_lock);
    }

    // If freed, returns (bytes_freed, next_batch), otherwise (0, batch_end).
    unsafe fn maybe_free_batch(&self, batch_start: *mut Block) -> (usize, *mut Block) {
        assert_eq!((*batch_start).batch_pos, 0);
        let batch_sz = (*batch_start).batch_sz;
        assert!(batch_sz > 0);

        let mut next = batch_start;
        let mut prev: *mut Block = core::ptr::null_mut();
        let mut in_use = false;
        for pos in 0..batch_sz {
            let block = &*next;
            assert_eq!(pos, block.batch_pos);
            prev = next;

            if in_use {
                next = block.next.load(Ordering::Acquire);
                continue;
            }

            // Mark the batch as fully used first, to avoid concurrent allocations.
            if block
                .used_bitmap
                .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                next = block.next.load(Ordering::Acquire);
            } else {
                in_use = true;
                // Unmark marked blocks.
                let mut marked_block = batch_start;
                for marked_pos in 0..pos {
                    let block = &*marked_block;
                    assert_eq!(marked_pos, block.batch_pos);
                    assert!(block
                        .used_bitmap
                        .compare_exchange(u64::MAX, 0, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok());
                    marked_block = block.next.load(Ordering::Acquire);
                }
                next = block.next.load(Ordering::Acquire);
            }
        }

        assert!(!prev.is_null());

        if in_use {
            return (0, prev);
        }

        // Now free.
        let block = &*batch_start;
        let alloc_sz = (block.batch_sz as usize) * block.block_size();
        let alloc_align = if alloc_sz < Self::PAGE_2M {
            Self::PAGE_4K
        } else {
            Self::PAGE_2M
        };

        next = batch_start;
        let data: *mut u8 = block.data;
        for pos in 0..batch_sz {
            let block = &*next;
            assert_eq!(pos, block.batch_pos);
            assert_eq!(
                block.data as usize,
                (data as usize) + ((pos as usize) * block.block_size())
            );

            let curr = next;
            next = block.next.load(Ordering::Acquire);
            self.metadata_slab.dealloc(curr as *mut u8);
        }

        let layout = Layout::from_size_align(alloc_sz, alloc_align).unwrap();
        self.fallback_allocator.dealloc(data, layout);

        (alloc_sz, next)
    }
}

unsafe impl<const SLABS: usize> GlobalAlloc for Frusa<SLABS> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match Self::sz_from_layout(&layout) {
            Some(sz) => self.alloc_from_slab(self.slab_for_sz(sz)),
            None => self.fallback_allocator.alloc(layout),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match Self::sz_from_layout(&layout) {
            Some(sz) => self.dealloc_to_slab(self.slab_for_sz(sz), ptr),
            None => self.fallback_allocator.dealloc(ptr, layout),
        }
    }
}
