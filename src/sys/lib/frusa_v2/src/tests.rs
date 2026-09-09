use core::sync::atomic::{AtomicUsize, Ordering};
use std::boxed::Box;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use crate::block::Block;
use crate::sync::{RwLock, SpinLock};

#[test]
fn rwlock_readers_share_and_exclude_writers() {
    let lock = RwLock::new();
    lock.read_lock();
    assert!(lock.try_read_lock());
    assert!(!lock.is_write_locked());
    lock.read_unlock();
    lock.read_unlock();

    assert!(lock.try_write_lock());
    assert!(!lock.try_read_lock());
    assert!(!lock.try_write_lock());
    lock.write_unlock();
    assert!(lock.try_read_lock());
    lock.read_unlock();
}

#[test]
fn rwlock_writer_waits_for_readers_to_drain() {
    let lock = Arc::new(RwLock::new());
    lock.read_lock();
    let writer = {
        let lock = lock.clone();
        std::thread::spawn(move || {
            lock.write_lock();
            let held = lock.is_write_locked();
            lock.write_unlock();
            held
        })
    };
    // The writer has taken its bit but cannot proceed; new readers back off.
    std::thread::sleep(Duration::from_millis(20));
    assert!(!lock.try_read_lock());
    lock.read_unlock();
    assert!(writer.join().unwrap());
    lock.read_lock();
    lock.read_unlock();
}

#[test]
fn spinlock_excludes() {
    static LOCK: SpinLock = SpinLock::new();
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..10_000 {
                    let _guard = LOCK.lock();
                    let v = COUNT.load(Ordering::Relaxed);
                    COUNT.store(v + 1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(COUNT.load(Ordering::Relaxed), 80_000);
    assert!(!LOCK.is_locked());
}

fn synthetic_block(entry_sz_log2: u32) -> (Box<Block>, Vec<u8>) {
    let mut data = vec![0u8; Block::ENTRIES << entry_sz_log2];
    let mut block: Box<Block> = unsafe { Box::new(core::mem::zeroed()) };
    block.init(entry_sz_log2, 0, 1, data.as_mut_ptr());
    (block, data)
}

#[test]
fn block_alloc_fills_in_order_and_reports_transitions() {
    let (block, data) = synthetic_block(5);
    assert!(block.is_empty());
    let mut expected = data.as_ptr() as usize;
    for slot in 0..Block::ENTRIES {
        let (ptr, became_full) = block.alloc().unwrap();
        assert_eq!(ptr as usize, expected);
        assert_eq!(became_full, slot == Block::ENTRIES - 1);
        expected += 32;
    }
    assert!(block.is_full());
    assert!(block.alloc().is_none());

    let ptr = unsafe { data.as_ptr().add(32 * 13) } as *mut u8;
    assert!(block.dealloc(ptr));
    assert!(!block.is_full());
    assert_eq!(block.alloc().unwrap(), (ptr, true));
    assert!(block.dealloc(ptr));
    assert!(!block.dealloc(unsafe { data.as_ptr().add(32 * 7) } as *mut u8));
    drop(data);
}

#[test]
fn block_rejects_foreign_and_misaligned_pointers() {
    let (block, data) = synthetic_block(4);
    let base = data.as_ptr() as *mut u8;
    assert_eq!(block.slot_of(base), Some(0));
    assert_eq!(block.slot_of(unsafe { base.add(16 * 63) }), Some(63));
    assert_eq!(block.slot_of(unsafe { base.add(16 * 64) }), None);
    assert_eq!(block.slot_of(unsafe { base.add(8) }), None);
    assert_eq!(block.slot_of(unsafe { base.sub(16) }), None);
    drop(data);
}

#[test]
#[should_panic(expected = "double free")]
fn block_double_free_panics() {
    let (block, data) = synthetic_block(4);
    let (ptr, _) = block.alloc().unwrap();
    block.dealloc(ptr);
    block.dealloc(ptr);
    drop(data);
}

#[test]
#[should_panic(expected = "bad ptr")]
fn block_foreign_free_panics() {
    let (block, data) = synthetic_block(4);
    block.dealloc(unsafe { (data.as_ptr() as *mut u8).add(8) });
    drop(data);
}

#[test]
fn block_flags_and_links_start_clear() {
    let (block, data) = synthetic_block(4);
    assert!(!block.on_stack());
    assert!(block.owner.load(Ordering::Relaxed).is_null());
    assert!(block.partial_next.load(Ordering::Relaxed).is_null());
    block.set_on_stack(true);
    assert!(block.on_stack());
    assert_eq!(block.entry_size(), 16);
    assert_eq!(block.block_size(), 1024);
    drop(data);
}

// ---- slab ----

use crate::slab::{INDEX_MIN_CAP, Slab};

/// Blocks for a synthetic slab: `batches` batches of `per_batch` contiguous
/// 1 KiB blocks (16-byte entries), each batch its own buffer, descriptors
/// kept alive by the returned vectors.
struct SyntheticSlab {
    slab: Box<Slab>,
    descriptors: Vec<Box<[Block]>>,
    buffers: Vec<Vec<u8>>,
    index: Vec<*mut Block>,
}

impl SyntheticSlab {
    fn new(batches: usize, per_batch: usize) -> Self {
        let slab = Box::new(Slab::new(4, 0));
        let mut index = Vec::with_capacity(INDEX_MIN_CAP);
        index.resize(INDEX_MIN_CAP, core::ptr::null_mut());
        slab.index_install(index.as_mut_ptr(), INDEX_MIN_CAP);
        let mut this = Self {
            slab,
            descriptors: Vec::new(),
            buffers: Vec::new(),
            index,
        };
        for _ in 0..batches {
            this.add_batch(per_batch);
        }
        this
    }

    /// Links and indexes one batch, and pushes its blocks on the stack.
    fn add_batch(&mut self, per_batch: usize) {
        let mut buffer = vec![0u8; per_batch * 1024];
        let mut descriptors: Box<[Block]> =
            unsafe { Box::new_zeroed_slice(per_batch).assume_init() };
        for (pos, block) in descriptors.iter_mut().enumerate() {
            block.init(4, pos as u16, per_batch as u16, unsafe {
                buffer.as_mut_ptr().add(pos * 1024)
            });
        }
        for pos in 0..per_batch - 1 {
            let next = &mut descriptors[pos + 1] as *mut Block;
            descriptors[pos].next.store(next, Ordering::Release);
        }
        let first = &mut descriptors[0] as *mut Block;
        let last = &mut descriptors[per_batch - 1] as *mut Block;
        self.slab.link_batch(first, last);
        self.slab.index_insert_batch(first, per_batch);
        for block in Slab::batch(first, per_batch) {
            self.slab.stack_push(block);
        }
        self.slab
            .bytes_total
            .fetch_add(per_batch * 1024, Ordering::Relaxed);
        self.descriptors.push(descriptors);
        self.buffers.push(buffer);
    }

    fn block(&self, batch: usize, pos: usize) -> *mut Block {
        &self.descriptors[batch][pos] as *const Block as *mut Block
    }
}

#[test]
fn slab_stack_push_is_idempotent_and_pop_clears() {
    let s = SyntheticSlab::new(1, 3);
    s.slab.check_stack();
    let top = s.slab.partial_head.load(Ordering::Relaxed);
    s.slab.stack_push(top);
    s.slab.stack_push(s.block(0, 1));
    s.slab.check_stack();
    assert_eq!(s.slab.stack_pop(), top);
    assert!(!unsafe { (*top).on_stack() });
    assert_eq!(s.slab.stack_pop(), s.block(0, 1));
    assert_eq!(s.slab.stack_pop(), s.block(0, 0));
    assert!(s.slab.stack_pop().is_null());
    assert!(s.slab.alloc().is_null());
}

#[test]
fn slab_alloc_drains_the_top_block_then_pops_it() {
    let s = SyntheticSlab::new(1, 2);
    let top = s.slab.partial_head.load(Ordering::Relaxed);
    let mut ptrs = Vec::new();
    for _ in 0..Block::ENTRIES {
        let p = s.slab.alloc();
        assert!(!p.is_null());
        assert_eq!(s.slab.lookup(p), top);
        ptrs.push(p);
    }
    assert!(unsafe { (*top).is_full() });
    assert!(!unsafe { (*top).on_stack() });
    s.slab.check_stack();
    let p = s.slab.alloc();
    assert_ne!(s.slab.lookup(p), top);
    // A free that makes the full block non-full is what pushes it back.
    assert!(unsafe { (*top).dealloc(ptrs[5]) });
    {
        let _lock = s.slab.partial_lock.lock();
        s.slab.stack_push(top);
    }
    s.slab.check_stack();
    assert_eq!(s.slab.alloc(), ptrs[5]);
    assert_eq!(s.slab.in_use_bytes(), (Block::ENTRIES + 1) * 16);
}

#[test]
fn slab_index_finds_every_block_boundary() {
    let s = SyntheticSlab::new(4, 3);
    s.slab.check_index();
    for batch in 0..4 {
        for pos in 0..3 {
            let block = s.block(batch, pos);
            let data = unsafe { (*block).data };
            assert_eq!(s.slab.lookup(data), block);
            assert_eq!(s.slab.lookup(unsafe { data.add(1023) }), block);
            assert_eq!(unsafe { (*block).slot_of(data.add(1023)) }, None);
            assert_eq!(unsafe { (*block).slot_of(data.add(1008)) }, Some(63));
        }
    }
    let lowest = s
        .slab
        .blocks()
        .map(|b| unsafe { (*b).data } as usize)
        .min()
        .unwrap();
    assert!(s.slab.lookup((lowest - 1) as *mut u8).is_null());
    assert!(s.slab.lookup(core::ptr::null_mut()).is_null());
}

#[test]
fn slab_index_probes_are_logarithmic() {
    let s = SyntheticSlab::new(16, 8);
    let blocks: Vec<*mut Block> = s.slab.blocks().collect();
    let before = crate::INDEX_PROBES.load(Ordering::Relaxed);
    for block in &blocks {
        assert_eq!(s.slab.lookup(unsafe { (**block).data }), *block);
    }
    let probes = crate::INDEX_PROBES.load(Ordering::Relaxed) - before;
    let bound = (128usize.ilog2() as usize + 1) * blocks.len();
    assert!(
        probes <= bound,
        "{probes} probes for {} lookups",
        blocks.len()
    );
}

#[test]
fn slab_index_growth_and_replacement_keep_entries() {
    let mut s = SyntheticSlab::new(1, 4);
    assert_eq!(s.slab.index_growth(INDEX_MIN_CAP - 4), None);
    assert_eq!(
        s.slab.index_growth(INDEX_MIN_CAP - 3),
        Some(2 * INDEX_MIN_CAP)
    );
    let mut bigger = vec![core::ptr::null_mut(); 2 * INDEX_MIN_CAP];
    let (old, old_cap) = s.slab.index_install(bigger.as_mut_ptr(), 2 * INDEX_MIN_CAP);
    assert_eq!(old, s.index.as_mut_ptr());
    assert_eq!(old_cap, INDEX_MIN_CAP);
    s.index = bigger;
    s.add_batch(2);
    s.slab.check_index();
    assert_eq!(s.slab.index_len.load(Ordering::Relaxed), 6);
}

#[test]
fn slab_rebuild_matches_incremental_state() {
    let mut s = SyntheticSlab::new(3, 2);
    // Take a few slots so the stack has full and non-full blocks.
    for _ in 0..Block::ENTRIES {
        assert!(!s.slab.alloc().is_null());
    }
    let full = s
        .slab
        .blocks()
        .filter(|b| unsafe { (**b).is_full() })
        .count();
    assert_eq!(full, 1);
    let stacked_before: Vec<*mut Block> = {
        let mut v = Vec::new();
        let mut cur = s.slab.partial_head.load(Ordering::Relaxed);
        while !cur.is_null() {
            v.push(cur);
            cur = unsafe { (*cur).partial_next.load(Ordering::Relaxed) };
        }
        v
    };
    // Drop the middle batch from the list as reclaim would, then rebuild.
    let first = s.block(1, 0);
    let after = unsafe { (*s.block(1, 1)).next.load(Ordering::Relaxed) };
    let mut prev = core::ptr::null_mut::<Block>();
    for block in s.slab.blocks() {
        if block == first {
            break;
        }
        prev = block;
    }
    unsafe { (*prev).next.store(after, Ordering::Release) };
    s.slab.index_rebuild();
    s.slab.stack_rebuild();
    s.slab.check_index();
    s.slab.check_stack();
    assert_eq!(s.slab.index_len.load(Ordering::Relaxed), 4);
    let mut stacked_after = 0;
    let mut cur = s.slab.partial_head.load(Ordering::Relaxed);
    while !cur.is_null() {
        assert!(stacked_before.contains(&cur));
        stacked_after += 1;
        cur = unsafe { (*cur).partial_next.load(Ordering::Relaxed) };
    }
    assert_eq!(stacked_after, 3);
    s.descriptors.remove(1);
    s.buffers.remove(1);
}

// ---- allocator ----

use core::alloc::{GlobalAlloc, Layout};
use std::time::Instant;

use crate::{Frusa, Frusa2M, Frusa4K};

/// How many data slabs `frusa` has.
fn num_slabs<const SLABS: usize>(_frusa: &Frusa<SLABS>) -> usize {
    SLABS
}

/// The largest allocation served inside rather than by the back end.
fn max_inside_size<const SLABS: usize>(_frusa: &Frusa<SLABS>) -> usize {
    Frusa::<SLABS>::MAX_SIZE
}

struct BackEndAllocator {}

unsafe impl Send for BackEndAllocator {}
unsafe impl Sync for BackEndAllocator {}

unsafe impl GlobalAlloc for BackEndAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static BACK_END: BackEndAllocator = BackEndAllocator {};

const PAGE: usize = 4096;

#[test]
fn test_init() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let slabs = num_slabs(&frusa.inner);
    // stats() forces the lazy init: one metadata page holding its own
    // descriptor and the slab table.
    let stats = frusa.stats();
    assert_eq!(PAGE, stats.allocated_from_fallback);
    assert_eq!(PAGE, stats.allocated_metadata);
    assert_eq!((slabs + 1) * 64, stats.in_use_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata);

    let layout = Layout::from_size_align(1, 1).unwrap();
    let ptr = unsafe { frusa.alloc(layout) };
    assert!(!ptr.is_null());

    // Plus one page for the smallest slab's first batch (four 1 KiB blocks,
    // hence four descriptors) and one page for its index.
    let blocks = PAGE / (16 * Block::ENTRIES);
    let stats = frusa.stats();
    assert_eq!(PAGE * 3, stats.allocated_from_fallback);
    assert_eq!(PAGE * 2, stats.allocated_metadata);
    assert_eq!((slabs + 1 + blocks) * 64, stats.in_use_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata + 16);

    unsafe { frusa.dealloc(ptr, layout) };
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
    assert_eq!(PAGE * 3, stats.allocated_from_fallback);
}

fn fill_and_check(ptr: *mut u8, size: usize) {
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
    for (idx, byte) in buf.iter_mut().enumerate() {
        *byte = (idx % 251) as u8;
    }
    for (idx, byte) in buf.iter().enumerate() {
        assert_eq!((idx % 251) as u8, *byte);
    }
}

fn basic_test_impl(frusa: &dyn GlobalAlloc, max_size: usize) {
    let mut live: Vec<(*mut u8, Layout)> = Vec::new();
    for size in (1..max_size).step_by(7) {
        for align_step in 0..8 {
            let align: usize = 1 << align_step;
            let layout = Layout::from_size_align(size, align).unwrap();
            let ptr = unsafe { frusa.alloc(layout) };
            assert!(!ptr.is_null());
            assert_eq!(0, (ptr as usize) & (align - 1));
            fill_and_check(ptr, size);
            live.push((ptr, layout));
        }
    }
    for (ptr, layout) in live {
        unsafe { frusa.dealloc(ptr, layout) };
    }
}

#[test]
fn basic_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    basic_test_impl(&frusa, 5000);
    assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata);
}

#[test]
fn basic_test_2m() {
    let frusa: Frusa2M = Frusa2M::new(&BACK_END);
    assert_eq!(max_inside_size(&frusa.inner), 1 << 20);
    basic_test_impl(&frusa, 3000);
    let big = Layout::from_size_align(1 << 20, 8).unwrap();
    let ptr = unsafe { frusa.alloc(big) };
    assert!(!ptr.is_null());
    fill_and_check(ptr, 1 << 20);
    unsafe { frusa.dealloc(ptr, big) };
}

#[test]
fn realloc_keeps_the_slot_within_a_class() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(40, 8).unwrap();
    let ptr = unsafe { frusa.alloc(layout) };
    fill_and_check(ptr, 40);
    let same = unsafe { frusa.realloc(ptr, layout, 64) };
    assert_eq!(same, ptr);
    let moved = unsafe { frusa.realloc(same, Layout::from_size_align(64, 8).unwrap(), 65) };
    assert_ne!(moved, ptr);
    let buf = unsafe { core::slice::from_raw_parts(moved, 40) };
    for (idx, byte) in buf.iter().enumerate() {
        assert_eq!((idx % 251) as u8, *byte);
    }
    unsafe { frusa.dealloc(moved, Layout::from_size_align(65, 8).unwrap()) };
    assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata);
}

/// Sorts the pointers and checks that no two live objects overlap.
fn assert_disjoint(ptrs: &[*mut u8], size: usize) {
    let mut sorted: Vec<usize> = ptrs.iter().map(|p| *p as usize).collect();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert!(pair[1] - pair[0] >= size, "overlapping allocations");
    }
}

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut rng = Xorshift(seed);
    for i in (1..items.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

#[cfg(debug_assertions)]
const RETAINED: usize = 16 * 1024;
#[cfg(not(debug_assertions))]
const RETAINED: usize = 64 * 1024;

/// The §1.1 reproduction: a retained population, churn on its oldest slot,
/// then whole-population frees in several orders. Correctness is asserted;
/// timings are printed for the baseline record, never asserted.
#[test]
fn retained_population_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(64, 8).unwrap();
    for order in ["insertion", "reverse", "random"] {
        let start = Instant::now();
        let mut ptrs = Vec::with_capacity(RETAINED);
        for i in 0..RETAINED {
            let ptr = unsafe { frusa.alloc(layout) };
            assert!(!ptr.is_null());
            unsafe { ptr.write(i as u8) };
            ptrs.push(ptr);
        }
        let populate = start.elapsed();
        assert_disjoint(&ptrs, 64);
        assert_eq!(
            frusa.stats().in_use - frusa.stats().in_use_metadata,
            RETAINED * 64
        );

        let start = Instant::now();
        for _ in 0..10_000 {
            unsafe { frusa.dealloc(ptrs[0], layout) };
            ptrs[0] = unsafe { frusa.alloc(layout) };
            assert!(!ptrs[0].is_null());
        }
        let churn = start.elapsed();
        assert_disjoint(&ptrs, 64);
        for (i, ptr) in ptrs.iter().enumerate().skip(1) {
            assert_eq!(unsafe { ptr.read() }, i as u8);
        }

        match order {
            "reverse" => ptrs.reverse(),
            "random" => shuffle(&mut ptrs, 0x9E3779B97F4A7C15),
            _ => {}
        }
        let start = Instant::now();
        for ptr in ptrs {
            unsafe { frusa.dealloc(ptr, layout) };
        }
        let free_all = start.elapsed();
        assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata);
        println!(
            "retained {RETAINED} x 64 B, {order} order: populate {populate:?}, churn {churn:?}, free-all {free_all:?}"
        );
    }
}

/// One slot freed in every block, then reallocated: allocation must find
/// the holes through the partial stack, not by scanning.
#[test]
fn sparse_holes_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(64, 8).unwrap();
    let mut ptrs: Vec<*mut u8> = (0..RETAINED)
        .map(|_| unsafe { frusa.alloc(layout) })
        .collect();
    let holes: Vec<*mut u8> = ptrs.iter().copied().step_by(Block::ENTRIES).collect();
    for hole in &holes {
        unsafe { frusa.dealloc(*hole, layout) };
    }
    let total_before = frusa.stats().allocated_from_fallback;
    let refilled: Vec<*mut u8> = holes
        .iter()
        .map(|_| unsafe { frusa.alloc(layout) })
        .collect();
    assert_eq!(
        total_before,
        frusa.stats().allocated_from_fallback,
        "holes not reused"
    );
    let mut hole_set = holes.clone();
    hole_set.sort_unstable();
    for ptr in &refilled {
        assert!(hole_set.binary_search(ptr).is_ok());
    }
    for (slot, hole) in holes.iter().enumerate() {
        let idx = ptrs.iter().position(|p| p == hole).unwrap();
        ptrs[idx] = refilled[slot];
    }
    assert_disjoint(&ptrs, 64);
    for ptr in ptrs {
        unsafe { frusa.dealloc(ptr, layout) };
    }
}

/// A backend that allocates from the allocator it backs, once per request,
/// as a logging or instrumented backend would. This deadlocks in `frusa`,
/// whose slab lock is held across the backend call.
struct NestingBackEnd;

static NESTED: Frusa4K = Frusa4K::new(&NestingBackEnd);

thread_local! {
    static NESTING: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

unsafe impl GlobalAlloc for NestingBackEnd {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !NESTING.with(|n| n.replace(true)) {
            let inner = Layout::from_size_align(layout.size().min(4096), 8).unwrap();
            let ptr = unsafe { NESTED.alloc(inner) };
            assert!(!ptr.is_null());
            unsafe { NESTED.dealloc(ptr, inner) };
            NESTING.with(|n| n.set(false));
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !NESTING.with(|n| n.replace(true)) {
            let inner = Layout::from_size_align(64, 8).unwrap();
            let p = unsafe { NESTED.alloc(inner) };
            unsafe { NESTED.dealloc(p, inner) };
            NESTING.with(|n| n.set(false));
        }
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

#[test]
fn backend_may_allocate_from_the_allocator_it_backs() {
    // Initialization itself must not re-enter: it holds the slab table
    // marker, so a nested request would spin on it. Run it with nesting
    // suppressed, as a real backend would be quiet until the runtime is up.
    NESTING.with(|n| n.set(true));
    NESTED.stats();
    NESTING.with(|n| n.set(false));
    let mut live = Vec::new();
    for size in [16usize, 64, 4096, 512, 32] {
        let layout = Layout::from_size_align(size, 8).unwrap();
        for _ in 0..200 {
            let ptr = unsafe { NESTED.alloc(layout) };
            assert!(!ptr.is_null());
            live.push((ptr, layout));
        }
    }
    for (ptr, layout) in live {
        unsafe { NESTED.dealloc(ptr, layout) };
    }
    assert_eq!(NESTED.stats().in_use, NESTED.stats().in_use_metadata);
}
