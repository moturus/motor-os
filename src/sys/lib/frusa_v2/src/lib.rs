//! A global allocator with dynamic memory expansion and on-demand reclaim.
//!
//! Memory is requested from a fallback (system) allocator when needed and
//! returned by an explicit `reclaim()` call. Compared to `frusa`, owner
//! lookup and free-slot search are bounded (a sorted block index and a
//! partial stack instead of list walks), no lock is held across a backend
//! call, and callers may hold a per-thread cache of private blocks.

#![no_std]

mod block;
mod cache;
mod lists;
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
pub use cache::ThreadCache;
use lists::ShardList;
use slab::Slab;
use sync::{ReaderShard, SHARDS};

/// The per-thread cache type for [`Frusa4K`].
pub type Cache4K = ThreadCache<9>;
/// The per-thread cache type for [`Frusa2M`].
pub type Cache2M = ThreadCache<17>;

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

    /// Allocation served from the free list of the caller's shard, then the
    /// thread's private block when the class is cached, then the shared
    /// path; other shards' lists are used before the slab grows.
    ///
    /// # Safety
    ///
    /// As for `GlobalAlloc::alloc`. `cache` must be used by one thread at a
    /// time and only with this allocator.
    pub unsafe fn alloc_cached(&self, cache: &Cache4K, layout: Layout) -> *mut u8 {
        self.inner.alloc_cached(cache, layout)
    }

    /// # Safety
    ///
    /// As for `GlobalAlloc::dealloc`, with the `cache` rule of `alloc_cached`.
    pub unsafe fn dealloc_cached(&self, cache: &Cache4K, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc_cached(cache, ptr, layout) }
    }

    /// # Safety
    ///
    /// As for `GlobalAlloc::realloc`, with the `cache` rule of `alloc_cached`.
    pub unsafe fn realloc_cached(
        &self,
        cache: &Cache4K,
        ptr: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        unsafe { self.inner.realloc_cached(cache, ptr, layout, new_size) }
    }

    /// Gives the cache's private blocks back to their slabs. Call before a
    /// thread exits; the cache may be used again afterwards.
    pub fn release_cache(&self, cache: &Cache4K) {
        self.inner.release_cache(cache)
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

    /// See [`Frusa4K::alloc_cached`].
    ///
    /// # Safety
    ///
    /// As for [`Frusa4K::alloc_cached`].
    pub unsafe fn alloc_cached(&self, cache: &Cache2M, layout: Layout) -> *mut u8 {
        self.inner.alloc_cached(cache, layout)
    }

    /// # Safety
    ///
    /// As for [`Frusa4K::dealloc_cached`].
    pub unsafe fn dealloc_cached(&self, cache: &Cache2M, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc_cached(cache, ptr, layout) }
    }

    /// # Safety
    ///
    /// As for [`Frusa4K::realloc_cached`].
    pub unsafe fn realloc_cached(
        &self,
        cache: &Cache2M,
        ptr: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        unsafe { self.inner.realloc_cached(cache, ptr, layout, new_size) }
    }

    /// See [`Frusa4K::release_cache`].
    pub fn release_cache(&self, cache: &Cache2M) {
        self.inner.release_cache(cache)
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
    /// `SHARDS` reader counts per slab, the metadata slab's last, allocated
    /// at initialization.
    shards: AtomicPtr<ReaderShard>,
    /// `SHARDS` free lists per data slab, allocated at initialization.
    lists: AtomicPtr<ShardList>,
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
            shards: AtomicPtr::new(core::ptr::null_mut()),
            lists: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    pub fn stats(&self) -> FrusaStats {
        let mut result = FrusaStats::default();
        let slabs = self.slabs(); // Forces initialization before reading metadata.
        let meta = &self.metadata_slab;
        self.read_lock(meta, 0);
        result.allocated_metadata = meta.bytes_total.load(Ordering::Relaxed);
        result.in_use_metadata = meta.in_use_bytes();
        self.read_unlock(meta, 0);

        let mut index_bytes = 0;
        for slab in slabs {
            self.read_lock(slab, 0);
            result.allocated_from_fallback += slab.bytes_total.load(Ordering::Relaxed);
            result.in_use += slab.in_use_bytes();
            index_bytes +=
                slab.index_cap.load(Ordering::Relaxed) as usize * slab::INDEX_ENTRY_BYTES;
            self.read_unlock(slab, 0);
        }
        result.allocated_metadata +=
            index_bytes + Self::shards_layout().size() + Self::lists_layout().size();
        result.allocated_from_fallback += result.allocated_metadata;
        result.in_use += result.in_use_metadata;
        result
    }

    // ---- guards ----

    fn shards_layout() -> Layout {
        let bytes = ((SLABS + 1) * SHARDS * core::mem::size_of::<ReaderShard>())
            .next_multiple_of(Self::PAGE_4K);
        Layout::from_size_align(bytes, Self::PAGE_4K).unwrap()
    }

    fn shards_of(&self, slab: &Slab) -> &[ReaderShard] {
        let base = self.shards.load(Ordering::Relaxed);
        debug_assert!(!base.is_null());
        unsafe { core::slice::from_raw_parts(base.add(slab.table_idx as usize * SHARDS), SHARDS) }
    }

    // ---- free lists ----

    fn lists_layout() -> Layout {
        let bytes =
            (SLABS * SHARDS * core::mem::size_of::<ShardList>()).next_multiple_of(Self::PAGE_4K);
        Layout::from_size_align(bytes, Self::PAGE_4K).unwrap()
    }

    /// The free list of `slab`'s class for `shard`. Data slabs only.
    fn list(&self, slab: &Slab, shard: u32) -> &ShardList {
        let base = self.lists.load(Ordering::Relaxed);
        debug_assert!(!base.is_null());
        debug_assert!((slab.table_idx as usize) < SLABS);
        unsafe { &*base.add(slab.table_idx as usize * SHARDS + shard as usize % SHARDS) }
    }

    /// Bytes one list of one class may hold; a list is also capped at 64
    /// slots, and classes above 16 KiB keep none.
    const FREE_LIST_BYTES: usize = 16 * 1024;

    fn free_list_limit(entry_sz_log2: u32) -> u32 {
        ((Self::FREE_LIST_BYTES >> entry_sz_log2) as u32).min(64)
    }

    /// A slot from any other shard's list, or null. The tier before
    /// growth: what another CPU freed is used before the backend is asked.
    fn steal(&self, slab: &Slab, shard: u32) -> *mut u8 {
        for offset in 1..SHARDS as u32 {
            let slot = self
                .list(slab, shard.wrapping_add(offset))
                .pop(slab.entry_sz_log2);
            if !slot.is_null() {
                return slot;
            }
        }
        core::ptr::null_mut()
    }

    /// Returns every listed slot of `slab`'s class to its block.
    fn drain_lists(&self, slab: &Slab) {
        for shard in 0..SHARDS as u32 {
            let list = self.list(slab, shard);
            loop {
                let slot = list.pop(slab.entry_sz_log2);
                if slot.is_null() {
                    break;
                }
                self.dealloc_to_slab(slab, slot, shard);
            }
        }
    }

    fn read_lock(&self, slab: &Slab, shard: u32) {
        guard_counted();
        slab.guard
            .read_lock(&self.shards_of(slab)[shard as usize % SHARDS]);
    }

    fn read_unlock(&self, slab: &Slab, shard: u32) {
        slab.guard
            .read_unlock(&self.shards_of(slab)[shard as usize % SHARDS]);
    }

    fn try_write_lock(&self, slab: &Slab) -> bool {
        slab.guard.try_write_lock(self.shards_of(slab))
    }

    fn write_lock(&self, slab: &Slab) {
        slab.guard.write_lock(self.shards_of(slab));
    }

    fn write_unlock(&self, slab: &Slab) {
        slab.guard.write_unlock();
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
        // Reader shards first: linking the first metadata page takes a guard.
        let shards =
            unsafe { self.fallback_allocator.alloc(Self::shards_layout()) } as *mut ReaderShard;
        if shards.is_null() {
            panic!("Cannot initialize FRUSA: OOM");
        }
        for idx in 0..(SLABS + 1) * SHARDS {
            unsafe { shards.add(idx).write(ReaderShard::new()) };
        }
        self.shards.store(shards, Ordering::Release);
        let lists =
            unsafe { self.fallback_allocator.alloc(Self::lists_layout()) } as *mut ShardList;
        if lists.is_null() {
            panic!("Cannot initialize FRUSA: OOM");
        }
        for idx in 0..SLABS * SHARDS {
            unsafe { lists.add(idx).write(ShardList::new()) };
        }
        self.lists.store(lists, Ordering::Release);
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

    /// Links a new metadata page, or gives it back if another thread has
    /// refilled the metadata stack meanwhile (the same rule as `grow`).
    fn link_metadata_page(&self, block: *mut Block) {
        let meta = &self.metadata_slab;
        self.write_lock(meta);
        if !meta.partial_head.load(Ordering::Acquire).is_null() {
            self.write_unlock(meta);
            let layout = Layout::from_size_align(Self::PAGE_4K, Self::PAGE_4K).unwrap();
            unsafe { self.fallback_allocator.dealloc(block as *mut u8, layout) };
            return;
        }
        meta.link_batch(block, block);
        meta.stack_push(block);
        meta.bytes_total.fetch_add(Self::PAGE_4K, Ordering::Relaxed);
        self.write_unlock(meta);
    }

    fn alloc_metadata(&self) -> *mut u8 {
        let meta = &self.metadata_slab;
        loop {
            self.read_lock(meta, 0);
            let ptr = meta.alloc();
            self.read_unlock(meta, 0);
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
        self.read_lock(meta, 0);
        unsafe {
            assert!((*block).data == block as *mut u8, "FRUSA: bad metadata ptr");
            if (*block).dealloc(ptr) {
                let _lock = meta.partial_lock.lock();
                meta.stack_push(block);
            }
        }
        self.read_unlock(meta, 0);
    }

    // ---- data slabs ----

    /// One relaxed load on every allocation and free; initialization is
    /// kept out of line so this inlines into the hot paths.
    #[inline(always)]
    fn slabs(&self) -> &[Slab; SLABS] {
        let data_slabs = self.data_slabs.load(Ordering::Relaxed);
        let addr = data_slabs as usize;
        if addr != 0 && addr != LOCKED_MARKER {
            return unsafe { &*data_slabs };
        }
        self.slabs_slow()
    }

    #[cold]
    #[inline(never)]
    fn slabs_slow(&self) -> &[Slab; SLABS] {
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

    fn alloc_from_slab(&self, slab: &Slab, shard: u32) -> *mut u8 {
        loop {
            self.read_lock(slab, shard);
            let ptr = slab.alloc();
            self.read_unlock(slab, shard);
            if !ptr.is_null() {
                return ptr;
            }
            let stolen = self.steal(slab, shard);
            if !stolen.is_null() {
                return stolen;
            }
            if self.grow(slab).is_err() {
                return core::ptr::null_mut();
            }
        }
    }

    fn dealloc_to_slab(&self, slab: &Slab, ptr: *mut u8, shard: u32) {
        self.read_lock(slab, shard);
        let block = slab.lookup(ptr);
        if block.is_null() {
            panic!("FRUSA: bad ptr for dealloc");
        }
        if unsafe { (*block).dealloc(ptr) } {
            self.push_unowned(slab, block);
        }
        self.read_unlock(slab, shard);
    }

    /// A block that just went from full to non-full rejoins the stack unless
    /// a cache owns it: the owner sees the free slot itself, and if it is
    /// giving the block up, its own re-check pushes it (§5.2 of the plan).
    fn push_unowned(&self, slab: &Slab, block: *mut Block) {
        let _lock = slab.partial_lock.lock();
        if unsafe { (*block).owner.load(Ordering::SeqCst) }.is_null() {
            slab.stack_push(block);
        }
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
        Layout::from_size_align(cap * slab::INDEX_ENTRY_BYTES, Self::PAGE_4K).unwrap()
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
            self.write_lock(slab);
            match slab.index_growth(num_blocks) {
                Some(cap) if cap > array_cap => self.write_unlock(slab),
                Some(_) => break slab.index_install(array, array_cap),
                None => break (array, array_cap),
            }
        };
        // Another grower may have refilled the stack meanwhile. Linking a
        // second batch on top of it would let a stampede of growers multiply
        // the slab's memory; give this one back instead, and let the caller
        // retry against the refilled stack.
        if !slab.partial_head.load(Ordering::Acquire).is_null() {
            self.write_unlock(slab);
            for taken in Slab::batch(first, num_blocks) {
                self.dealloc_metadata(taken as *mut u8);
            }
            unsafe { self.fallback_allocator.dealloc(data, layout) };
            if !retired.0.is_null() {
                unsafe {
                    self.fallback_allocator
                        .dealloc(retired.0 as *mut u8, Self::index_layout(retired.1))
                };
            }
            return Ok(());
        }
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
        self.write_unlock(slab);

        if !retired.0.is_null() {
            unsafe {
                self.fallback_allocator
                    .dealloc(retired.0 as *mut u8, Self::index_layout(retired.1))
            };
        }
        Ok(())
    }

    // ---- per-thread private blocks ----

    /// Entries up to this size are served from private blocks. An idle
    /// thread holds at most one block per cached class; at 2 KiB that is
    /// classes 16 B..2 KiB, up to 255 KiB in all. Larger classes stay on
    /// the shared path, where their few, large blocks cost little to reach.
    const CACHED_MAX_LOG2: u32 = 11;

    fn alloc_cached(&self, cache: &ThreadCache<SLABS>, layout: Layout) -> *mut u8 {
        let Some(sz) = Self::sz_from_layout(&layout) else {
            return unsafe { self.fallback_allocator.alloc(layout) };
        };
        let slab = self.slab_for_sz(sz);
        let shard = cache.shard.get();
        let class = slab.table_idx as usize;
        // The private block first: it is ours, so reclaim never touches it,
        // and its descriptor never leaves the metadata slab. No guard.
        if slab.entry_sz_log2 <= Self::CACHED_MAX_LOG2 {
            let block = cache.current[class].get();
            if !block.is_null()
                && let Some((ptr, became_full)) = unsafe { (*block).alloc() }
            {
                if became_full {
                    self.read_lock(slab, shard);
                    self.release_private(slab, cache, class);
                    self.read_unlock(slab, shard);
                }
                return ptr;
            }
        }
        // Then this CPU's list. Every slot of the class is aligned to its
        // size, so a listed slot fits any layout that maps to the class.
        let slot = self.list(slab, shard).pop(slab.entry_sz_log2);
        if !slot.is_null() {
            return slot;
        }
        if slab.entry_sz_log2 > Self::CACHED_MAX_LOG2 {
            return self.alloc_from_slab(slab, shard);
        }
        loop {
            self.read_lock(slab, cache.shard.get());
            let block = cache.current[class].get();
            if !block.is_null() {
                match unsafe { (*block).alloc() } {
                    Some((ptr, became_full)) => {
                        if became_full {
                            self.release_private(slab, cache, class);
                        }
                        self.read_unlock(slab, cache.shard.get());
                        return ptr;
                    }
                    None => self.release_private(slab, cache, class),
                }
            }
            let taken = {
                let _lock = slab.partial_lock.lock();
                let taken = slab.stack_pop();
                if !taken.is_null() {
                    unsafe { (*taken).owner.store(cache.id(), Ordering::SeqCst) };
                }
                taken
            };
            if !taken.is_null() {
                cache.current[class].set(taken);
                self.read_unlock(slab, cache.shard.get());
                continue;
            }
            self.read_unlock(slab, cache.shard.get());
            let stolen = self.steal(slab, shard);
            if !stolen.is_null() {
                return stolen;
            }
            if self.grow(slab).is_err() {
                return core::ptr::null_mut();
            }
        }
    }

    /// Gives up the private block of `class`. Ownership is cleared first;
    /// then, if a remote free landed while the block looked full to its
    /// owner, that free saw an owner and did not push, so the re-check here
    /// does. Both sides use sequentially consistent operations, so one of
    /// them always observes the other. Read guard held by the caller.
    fn release_private(&self, slab: &Slab, cache: &ThreadCache<SLABS>, class: usize) {
        let block = cache.current[class].replace(core::ptr::null_mut());
        if block.is_null() {
            return;
        }
        let b = unsafe { &*block };
        let previous = b.owner.swap(core::ptr::null_mut(), Ordering::SeqCst);
        debug_assert_eq!(previous, cache.id());
        if !b.is_full() {
            let _lock = slab.partial_lock.lock();
            slab.stack_push(block);
        }
    }

    unsafe fn dealloc_cached(&self, cache: &ThreadCache<SLABS>, ptr: *mut u8, layout: Layout) {
        let Some(sz) = Self::sz_from_layout(&layout) else {
            return unsafe { self.fallback_allocator.dealloc(ptr, layout) };
        };
        let slab = self.slab_for_sz(sz);
        // The block this thread still holds first: one locked bit flip, and
        // the slot is reused by this thread's next allocation. The block is
        // ours (`owner` names this cache), so reclaim never touches it, and
        // its descriptor is stable; `slot_of` is a pure range check, so no
        // read guard is needed. It is always non-full here (a fill nulls
        // the slot in `alloc_cached`), so the free never fills a gap that
        // would rejoin the partial stack.
        if slab.entry_sz_log2 <= Self::CACHED_MAX_LOG2 {
            let block = cache.current[slab.table_idx as usize].get();
            if !block.is_null() && unsafe { (*block).slot_of(ptr).is_some() } {
                let was_full = unsafe { (*block).dealloc(ptr) };
                debug_assert!(!was_full, "cached current block was full");
                return;
            }
        }
        // Then this CPU's list, whichever block and thread the slot came
        // from: the slot stays marked in use, so nothing shared changes.
        let limit = Self::free_list_limit(slab.entry_sz_log2);
        if limit != 0 && self.list(slab, cache.shard.get()).push(ptr, limit) {
            return;
        }
        self.dealloc_to_slab(slab, ptr, cache.shard.get());
    }

    unsafe fn realloc_cached(
        &self,
        cache: &ThreadCache<SLABS>,
        ptr: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        if let (Some(old), Some(new)) = (
            Self::sz_from_layout(&layout),
            Self::sz_from_layout(&new_layout),
        ) && old == new
        {
            return ptr;
        }
        let new_ptr = self.alloc_cached(cache, new_layout);
        if !new_ptr.is_null() {
            unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size)) };
            unsafe { self.dealloc_cached(cache, ptr, layout) };
        }
        new_ptr
    }

    fn release_cache(&self, cache: &ThreadCache<SLABS>) {
        for (class, slab) in self.slabs().iter().enumerate() {
            if cache.current[class].get().is_null() {
                continue;
            }
            self.read_lock(slab, cache.shard.get());
            self.release_private(slab, cache, class);
            self.read_unlock(slab, cache.shard.get());
        }
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
        // Listed slots count as in use; give them back first so that the
        // batches they sit in can be returned.
        self.drain_lists(slab);
        self.read_lock(slab, 0);
        let slack = slab.bytes_total.load(Ordering::Relaxed) - slab.in_use_bytes();
        self.read_unlock(slab, 0);
        if slack < Self::PAGE_4K {
            return;
        }
        if !self.try_write_lock(slab) {
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
        self.write_unlock(slab);

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
            self.write_lock(slab);
            slab.check_index();
            slab.check_stack();
            self.write_unlock(slab);
        }
        self.write_lock(&self.metadata_slab);
        self.metadata_slab.check_stack();
        self.write_unlock(&self.metadata_slab);
    }
}

unsafe impl<const SLABS: usize> GlobalAlloc for Frusa<SLABS> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match Self::sz_from_layout(&layout) {
            Some(sz) => self.alloc_from_slab(self.slab_for_sz(sz), 0),
            None => unsafe { self.fallback_allocator.alloc(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match Self::sz_from_layout(&layout) {
            Some(sz) => self.dealloc_to_slab(self.slab_for_sz(sz), ptr, 0),
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

#[cfg(test)]
pub(crate) fn stack_examined() -> usize {
    STACK_EXAMINED.with(|p| p.get())
}

#[cfg(test)]
pub(crate) fn guards_taken() -> usize {
    GUARDS_TAKEN.with(|p| p.get())
}

// Per thread, so tests running in parallel do not count each other's work.
#[cfg(test)]
std::thread_local! {
    static INDEX_PROBES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static STACK_EXAMINED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static GUARDS_TAKEN: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Test-only work counter: one read guard taken.
#[inline(always)]
fn guard_counted() {
    #[cfg(test)]
    GUARDS_TAKEN.with(|p| p.set(p.get() + 1));
}

#[inline(always)]
pub(crate) fn probe_counted() {
    #[cfg(test)]
    INDEX_PROBES.with(|p| p.set(p.get() + 1));
}

/// Test-only work counter: one partial-stack entry examined by an allocation.
#[inline(always)]
pub(crate) fn stack_counted() {
    #[cfg(test)]
    STACK_EXAMINED.with(|p| p.set(p.get() + 1));
}
