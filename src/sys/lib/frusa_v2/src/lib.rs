//! A global allocator with dynamic memory expansion and on-demand reclaim.
//!
//! Memory is requested from a fallback (system) allocator when needed and
//! returned by an explicit `reclaim()` call. Compared to `frusa`, owner
//! lookup and free-slot search are bounded (a sorted block index and a
//! partial stack instead of list walks), no lock is held across a backend
//! call, and callers may hold a per-thread cache of private blocks.

#![no_std]

mod block;
mod slab;
mod sync;

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod tests;

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicPtr, Ordering};

use block::Block;
use slab::Slab;

/// Basic usage statistics. In-use figures are computed from the block
/// bitmaps when asked, so the hot paths keep no counters.
#[derive(Default, Clone, Copy, Debug)]
pub struct FrusaStats {
    pub allocated_from_fallback: usize,
    pub in_use: usize,
    pub allocated_metadata: usize,
    pub in_use_metadata: usize,
}

/// An allocator that manages allocations up to 4K and uses the fallback
/// allocator for the rest.
pub struct Frusa4K {
    inner: Frusa<9>,
}

unsafe impl Send for Frusa4K {}
unsafe impl Sync for Frusa4K {}

unsafe impl GlobalAlloc for Frusa4K {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.inner.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { self.inner.realloc(ptr, layout, new_size) }
    }
}

impl Frusa4K {
    pub const fn new(fallback: &'static dyn GlobalAlloc) -> Self {
        Self {
            inner: Frusa::<9>::new(fallback),
        }
    }

    /// Returns every batch whose blocks are all free to the fallback
    /// allocator.
    pub fn reclaim(&self) {
        self.inner.reclaim();
    }

    pub fn stats(&self) -> FrusaStats {
        self.inner.stats()
    }
}

/// An allocator that manages allocations up to 1M and uses the fallback
/// allocator for the rest.
pub struct Frusa2M {
    inner: Frusa<17>,
}

unsafe impl Send for Frusa2M {}
unsafe impl Sync for Frusa2M {}

unsafe impl GlobalAlloc for Frusa2M {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.inner.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { self.inner.realloc(ptr, layout, new_size) }
    }
}

impl Frusa2M {
    pub const fn new(fallback: &'static dyn GlobalAlloc) -> Self {
        Self {
            inner: Frusa::<17>::new(fallback),
        }
    }

    /// Returns every batch whose blocks are all free to the fallback
    /// allocator.
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
struct Frusa<const SLABS: usize> {
    fallback_allocator: &'static dyn GlobalAlloc,
    /// Descriptors live here: 64-byte entries in page-sized blocks whose
    /// descriptor is their own first entry.
    metadata_slab: Slab,
    /// The data slabs, in the first metadata page; null until first use,
    /// `LOCKED_MARKER` while one thread builds them.
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
        // The slab table and the first block's own descriptor share a page.
        assert!((SLABS + 1) * Self::METADATA_SZ <= Self::PAGE_4K);

        Self {
            fallback_allocator,
            metadata_slab: Slab::new(Self::METADATA_SZ.ilog2(), SLABS as u32),
            data_slabs: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    pub fn stats(&self) -> FrusaStats {
        let mut result = FrusaStats::default();
        let slabs = self.slabs(); // Forces initialization before reading metadata.
        let meta = &self.metadata_slab;
        meta.guard.read_lock();
        result.allocated_metadata = meta.bytes_total.load(Ordering::Relaxed);
        result.in_use_metadata = meta.in_use_bytes();
        meta.guard.read_unlock();

        let mut index_bytes = 0;
        for slab in slabs {
            slab.guard.read_lock();
            result.allocated_from_fallback += slab.bytes_total.load(Ordering::Relaxed);
            result.in_use += slab.in_use_bytes();
            index_bytes += slab.index_cap.load(Ordering::Relaxed) as usize * 8;
            slab.guard.read_unlock();
        }
        result.allocated_metadata += index_bytes;
        result.allocated_from_fallback += result.allocated_metadata;
        result.in_use += result.in_use_metadata;
        result
    }

    // ---- initialization ----

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
        let block = self.alloc_metadata_page();
        if block.is_null() {
            panic!("Cannot initialize FRUSA: OOM");
        }
        let pslabs: *mut [Slab; SLABS] = ((block as usize) + Self::METADATA_SZ) as *mut _;
        unsafe {
            let meta_block = &*block;
            // Entries 1..=SLABS hold the slab table.
            let mut used = 1u64;
            let first_log2 = Self::MIN_SIZE.ilog2();
            for (idx, slab) in (*pslabs).iter_mut().enumerate() {
                core::ptr::write(slab, Slab::new(first_log2 + idx as u32, idx as u32));
                used |= 1u64 << (idx + 1);
            }
            meta_block.used_bitmap.store(used, Ordering::Release);
        }
        self.link_metadata_page(block);
        self.data_slabs.store(pslabs, Ordering::Release);
    }

    // ---- metadata slab ----

    /// One page from the backend, set up as a metadata block whose first
    /// entry is its own descriptor. Not yet linked into the slab.
    fn alloc_metadata_page(&self) -> *mut Block {
        let layout = Layout::from_size_align(Self::PAGE_4K, Self::PAGE_4K).unwrap();
        let page = unsafe { self.fallback_allocator.alloc(layout) };
        if page.is_null() {
            return core::ptr::null_mut();
        }
        debug_assert_eq!(page as usize & (Self::PAGE_4K - 1), 0, "backend alignment");
        let block = page as *mut Block;
        unsafe {
            (*block).init(Self::METADATA_SZ.ilog2(), 0, 1, page);
            (*block).used_bitmap.store(1, Ordering::Release);
        }
        block
    }

    fn link_metadata_page(&self, block: *mut Block) {
        let meta = &self.metadata_slab;
        meta.guard.write_lock();
        meta.link_batch(block, block);
        meta.stack_push(block);
        meta.bytes_total.fetch_add(Self::PAGE_4K, Ordering::Relaxed);
        meta.guard.write_unlock();
    }

    fn alloc_metadata(&self) -> *mut u8 {
        let meta = &self.metadata_slab;
        loop {
            meta.guard.read_lock();
            let ptr = meta.alloc();
            meta.guard.read_unlock();
            if !ptr.is_null() {
                return ptr;
            }
            let block = self.alloc_metadata_page();
            if block.is_null() {
                return core::ptr::null_mut();
            }
            self.link_metadata_page(block);
        }
    }

    /// The owner of a descriptor is the page it lives in.
    fn dealloc_metadata(&self, ptr: *mut u8) {
        let meta = &self.metadata_slab;
        let block = ((ptr as usize) & !(Self::PAGE_4K - 1)) as *mut Block;
        meta.guard.read_lock();
        unsafe {
            assert!((*block).data == block as *mut u8, "FRUSA: bad metadata ptr");
            if (*block).dealloc(ptr) {
                let _lock = meta.partial_lock.lock();
                meta.stack_push(block);
            }
        }
        meta.guard.read_unlock();
    }

    // ---- data slabs ----

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
        if sz <= Self::MAX_SIZE { Some(sz) } else { None }
    }

    fn alloc_from_slab(&self, slab: &Slab) -> *mut u8 {
        loop {
            slab.guard.read_lock();
            let ptr = slab.alloc();
            slab.guard.read_unlock();
            if !ptr.is_null() {
                return ptr;
            }
            if self.grow(slab).is_err() {
                return core::ptr::null_mut();
            }
        }
    }

    fn dealloc_to_slab(&self, slab: &Slab, ptr: *mut u8) {
        slab.guard.read_lock();
        let block = slab.lookup(ptr);
        if block.is_null() {
            panic!("FRUSA: bad ptr for dealloc");
        }
        if unsafe { (*block).dealloc(ptr) } {
            let _lock = slab.partial_lock.lock();
            slab.stack_push(block);
        }
        slab.guard.read_unlock();
    }

    /// Bytes to request for the next batch of `slab`: small classes start
    /// with single pages and move to larger batches as they grow, so a big
    /// heap needs few backend calls while a small one returns memory in
    /// small pieces.
    fn batch_bytes(slab: &Slab) -> usize {
        let block = slab.block_size();
        if block > Self::PAGE_4K * 64 {
            return block.max(Self::PAGE_2M);
        }
        let total = slab.bytes_total.load(Ordering::Relaxed);
        let tier = if total < 8 * Self::PAGE_4K {
            Self::PAGE_4K
        } else if total < 256 * Self::PAGE_4K {
            8 * Self::PAGE_4K
        } else {
            64 * Self::PAGE_4K
        };
        block.max(tier)
    }

    fn batch_layout(bytes: usize) -> Layout {
        let align = if bytes < Self::PAGE_2M {
            Self::PAGE_4K
        } else {
            Self::PAGE_2M
        };
        Layout::from_size_align(bytes, align).unwrap()
    }

    fn index_layout(cap: usize) -> Layout {
        Layout::from_size_align(cap * 8, Self::PAGE_4K).unwrap()
    }

    /// Adds a batch to `slab`. Everything is allocated with no lock held;
    /// the write guard covers only linking, indexing, and pushing.
    fn grow(&self, slab: &Slab) -> Result<(), ()> {
        let batch_bytes = Self::batch_bytes(slab);
        let block_sz = slab.block_size();
        let num_blocks = batch_bytes / block_sz;
        assert!(num_blocks * block_sz == batch_bytes);
        assert!(num_blocks <= u16::MAX as usize);
        let layout = Self::batch_layout(batch_bytes);
        let data = unsafe { self.fallback_allocator.alloc(layout) };
        if data.is_null() {
            return Err(());
        }
        debug_assert_eq!(data as usize & (Self::PAGE_4K - 1), 0, "backend alignment");

        let mut first: *mut Block = core::ptr::null_mut();
        let mut last: *mut Block = core::ptr::null_mut();
        for idx in 0..num_blocks {
            let block = self.alloc_metadata() as *mut Block;
            if block.is_null() {
                for taken in Slab::batch(first, idx) {
                    self.dealloc_metadata(taken as *mut u8);
                }
                unsafe { self.fallback_allocator.dealloc(data, layout) };
                return Err(());
            }
            unsafe {
                (*block).init(
                    slab.entry_sz_log2,
                    idx as u16,
                    num_blocks as u16,
                    data.add(idx * block_sz),
                );
                if last.is_null() {
                    first = block;
                } else {
                    (*last).next.store(block, Ordering::Release);
                }
            }
            last = block;
        }

        // The index may need a larger array. It is allocated with no lock
        // held, so by the time the guard is taken another grower may have
        // installed one (ours goes unused) or inserted a batch (ours may
        // be too small: release, get a larger one, and try again).
        let mut array: *mut *mut Block = core::ptr::null_mut();
        let mut array_cap = 0;
        let retired = loop {
            if let Some(cap) = slab.index_growth(num_blocks)
                && cap > array_cap
            {
                if !array.is_null() {
                    unsafe {
                        self.fallback_allocator
                            .dealloc(array as *mut u8, Self::index_layout(array_cap))
                    };
                }
                array = unsafe { self.fallback_allocator.alloc(Self::index_layout(cap)) } as *mut _;
                if array.is_null() {
                    for taken in Slab::batch(first, num_blocks) {
                        self.dealloc_metadata(taken as *mut u8);
                    }
                    unsafe { self.fallback_allocator.dealloc(data, layout) };
                    return Err(());
                }
                array_cap = cap;
            }
            slab.guard.write_lock();
            match slab.index_growth(num_blocks) {
                Some(cap) if cap > array_cap => slab.guard.write_unlock(),
                Some(_) => break slab.index_install(array, array_cap),
                None => break (array, array_cap),
            }
        };
        slab.index_insert_batch(first, num_blocks);
        slab.link_batch(first, last);
        {
            // The write guard already excludes every reader; the lock is
            // taken for uniformity with the stack's documented rule.
            let _lock = slab.partial_lock.lock();
            for block in Slab::batch(first, num_blocks) {
                slab.stack_push(block);
            }
        }
        slab.bytes_total.fetch_add(batch_bytes, Ordering::Relaxed);
        slab.guard.write_unlock();

        if !retired.0.is_null() {
            unsafe {
                self.fallback_allocator
                    .dealloc(retired.0 as *mut u8, Self::index_layout(retired.1))
            };
        }
        Ok(())
    }

    // ---- reclaim ----

    fn reclaim(&self) {
        for slab in self.slabs() {
            self.reclaim_slab(slab);
        }
        // Metadata pages are never returned.
    }

    /// Two phases: under the write guard, detach every batch whose blocks
    /// are all free and rebuild the index and the stack; after releasing
    /// it, return the detached memory. No lock is held across a backend
    /// call, and a concurrent reclaim or growth link step makes this one
    /// skip the slab.
    fn reclaim_slab(&self, slab: &Slab) {
        slab.guard.read_lock();
        let slack = slab.bytes_total.load(Ordering::Relaxed) - slab.in_use_bytes();
        slab.guard.read_unlock();
        if slack < Self::PAGE_4K {
            return;
        }
        if !slab.guard.try_write_lock() {
            return;
        }

        let mut detached: *mut Block = core::ptr::null_mut();
        let mut freed = 0usize;
        let mut prev: *mut Block = core::ptr::null_mut();
        let mut batch_start = slab.head.load(Ordering::Acquire);
        while !batch_start.is_null() {
            let batch_sz = unsafe { (*batch_start).batch_sz } as usize;
            debug_assert_eq!(unsafe { (*batch_start).batch_pos }, 0);
            let mut batch_last = batch_start;
            let mut in_use = false;
            for block in Slab::batch(batch_start, batch_sz) {
                let b = unsafe { &*block };
                in_use |= !b.is_empty() || !b.owner.load(Ordering::Relaxed).is_null();
                batch_last = block;
            }
            let next_batch = unsafe { (*batch_last).next.load(Ordering::Acquire) };
            if in_use {
                prev = batch_last;
            } else {
                if prev.is_null() {
                    slab.head.store(next_batch, Ordering::Release);
                } else {
                    unsafe { (*prev).next.store(next_batch, Ordering::Release) };
                }
                unsafe { (*batch_last).next.store(detached, Ordering::Release) };
                detached = batch_start;
                freed += batch_sz * slab.block_size();
            }
            batch_start = next_batch;
        }
        if freed > 0 {
            slab.bytes_total.fetch_sub(freed, Ordering::Relaxed);
            slab.index_rebuild();
            slab.stack_rebuild();
        }
        slab.guard.write_unlock();

        while !detached.is_null() {
            let batch_sz = unsafe { (*detached).batch_sz } as usize;
            let bytes = batch_sz * slab.block_size();
            let data = unsafe { (*detached).data };
            let mut next_batch = core::ptr::null_mut();
            for block in Slab::batch(detached, batch_sz) {
                next_batch = unsafe { (*block).next.load(Ordering::Acquire) };
                self.dealloc_metadata(block as *mut u8);
            }
            unsafe {
                self.fallback_allocator
                    .dealloc(data, Self::batch_layout(bytes))
            };
            detached = next_batch;
        }
    }

    /// Every slab's index and stack invariants, checked with the slab to
    /// itself. Test builds only.
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) {
        for slab in self.slabs() {
            slab.guard.write_lock();
            slab.check_index();
            slab.check_stack();
            slab.guard.write_unlock();
        }
        self.metadata_slab.guard.write_lock();
        self.metadata_slab.check_stack();
        self.metadata_slab.guard.write_unlock();
    }
}

unsafe impl<const SLABS: usize> GlobalAlloc for Frusa<SLABS> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match Self::sz_from_layout(&layout) {
            Some(sz) => self.alloc_from_slab(self.slab_for_sz(sz)),
            None => unsafe { self.fallback_allocator.alloc(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match Self::sz_from_layout(&layout) {
            Some(sz) => self.dealloc_to_slab(self.slab_for_sz(sz), ptr),
            None => unsafe { self.fallback_allocator.dealloc(ptr, layout) },
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        if let (Some(old), Some(new)) = (
            Self::sz_from_layout(&layout),
            Self::sz_from_layout(&new_layout),
        ) && old == new
        {
            // Same class: the slot already fits.
            return ptr;
        }
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}

/// Test-only work counter: one index probe. Compiles to nothing otherwise.
#[cfg(test)]
pub(crate) fn index_probes() -> usize {
    INDEX_PROBES.with(|p| p.get())
}

// Per thread, so tests running in parallel do not count each other's work.
#[cfg(test)]
std::thread_local! {
    static INDEX_PROBES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[inline(always)]
pub(crate) fn probe_counted() {
    #[cfg(test)]
    INDEX_PROBES.with(|p| p.set(p.get() + 1));
}
