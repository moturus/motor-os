use core::sync::atomic::*;

const READER: u32 = 2;
const WRITER: u32 = 1;

const MAX_LOCK_VALUE: u32 = u32::MAX / 2;

pub const fn rwlock_new() -> AtomicU32 {
    AtomicU32::new(0)
}

pub fn try_read_lock(lock: &AtomicU32) -> bool {
    let val = lock.fetch_add(READER, Ordering::Relaxed);
    if val > MAX_LOCK_VALUE {
        lock.fetch_sub(READER, Ordering::Relaxed);
        false
    } else if val & WRITER != 0 {
        lock.fetch_sub(READER, Ordering::Relaxed);
        false
    } else {
        true
    }
}

pub fn read_lock(lock: &AtomicU32) {
    loop {
        if try_read_lock(lock) {
            return;
        }
        core::hint::spin_loop();
    }
}

pub fn read_unlock(lock: &AtomicU32) {
    lock.fetch_sub(READER, Ordering::Relaxed);
}

pub fn single_write_lock(lock: &AtomicU32) -> bool {
    let mut val = lock.fetch_or(WRITER, Ordering::Acquire);
    if val & WRITER != 0 {
        return false;
    }

    while val != WRITER {
        core::hint::spin_loop();
        val = lock.load(Ordering::Relaxed);
    }

    true
}

pub fn write_unlock(lock: &AtomicU32) {
    let val = lock.fetch_xor(WRITER, Ordering::Release);
    assert_eq!(val & WRITER, WRITER);
}
