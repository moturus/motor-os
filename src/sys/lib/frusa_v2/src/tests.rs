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
