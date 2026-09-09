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
