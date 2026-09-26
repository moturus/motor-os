//! Futexes that never allocate: while it sleeps, a waiter links a node on
//! its own stack into a fixed hash bucket. A process must be able to wait
//! even when its heap cannot grow, e.g. while the machine is at the user
//! memory floor.
//!
//! A waiter unlinks its node, or sees that a waker already did, under the
//! bucket lock before it returns. A thread dies only with its whole process,
//! so no dead thread's node stays linked.

use core::ptr::null_mut;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use moto_rt::spinlock::SpinLock;
use moto_sys::SysCpu;
use moto_sys::SysHandle;

struct Waiter {
    key: usize,
    thread: u64,
    prev: *mut Waiter,
    next: *mut Waiter,
    // Cleared by whoever unlinks the node.
    linked: bool,
}

// Waiters in arrival order: each futex wakes its waiters first in, first out.
struct Bucket {
    head: *mut Waiter,
    tail: *mut Waiter,
}

// SAFETY: the nodes are only accessed under their bucket's lock.
unsafe impl Send for Bucket {}

impl Bucket {
    // SAFETY: called under the lock, with `waiter` valid and not linked.
    unsafe fn push_back(&mut self, waiter: *mut Waiter) {
        unsafe {
            (*waiter).prev = self.tail;
            (*waiter).next = null_mut();
            if self.tail.is_null() {
                self.head = waiter;
            } else {
                (*self.tail).next = waiter;
            }
        }
        self.tail = waiter;
    }

    // SAFETY: called under the lock, with `waiter` linked into this bucket.
    unsafe fn unlink(&mut self, waiter: *mut Waiter) {
        unsafe {
            debug_assert!((*waiter).linked);
            let (prev, next) = ((*waiter).prev, (*waiter).next);
            if prev.is_null() {
                self.head = next;
            } else {
                (*prev).next = next;
            }
            if next.is_null() {
                self.tail = prev;
            } else {
                (*next).prev = prev;
            }
            (*waiter).linked = false;
        }
    }

    // Unlinks the longest waiting waiter on `key` and returns its thread.
    fn pop(&mut self, key: usize) -> Option<u64> {
        let mut waiter = self.head;
        // SAFETY: linked nodes stay valid while the lock is held.
        unsafe {
            while !waiter.is_null() {
                if (*waiter).key == key {
                    self.unlink(waiter);
                    return Some((*waiter).thread);
                }
                waiter = (*waiter).next;
            }
        }
        None
    }

    fn count(&self, key: usize) -> usize {
        let mut count = 0;
        let mut waiter = self.head;
        // SAFETY: linked nodes stay valid while the lock is held.
        unsafe {
            while !waiter.is_null() {
                if (*waiter).key == key {
                    count += 1;
                }
                waiter = (*waiter).next;
            }
        }
        count
    }
}

const NUM_BUCKETS: usize = 64;

static BUCKETS: [SpinLock<Bucket>; NUM_BUCKETS] = [const {
    SpinLock::new(Bucket {
        head: null_mut(),
        tail: null_mut(),
    })
}; NUM_BUCKETS];

fn bucket(key: usize) -> &'static SpinLock<Bucket> {
    // Fibonacci hashing of the futex word's address.
    let hash = ((key as u64) >> 2).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    &BUCKETS[(hash >> (u64::BITS - NUM_BUCKETS.ilog2())) as usize]
}

// Returns false on timeout.
fn futex_wait_impl(
    futex: *const AtomicU32,
    expected: u32,
    timeout: Option<core::time::Duration>,
) -> bool {
    // Create abs timeout before anything else, otherwise it will be not as precise, due
    // to time passage.
    let timeout = timeout.map(|dur| moto_rt::time::Instant::now() + dur);

    let key = futex as *const _ as usize;
    let futex_ref = unsafe { futex.as_ref().unwrap() };
    if futex_ref.load(Ordering::Acquire) != expected {
        return true;
    }

    let mut waiter = Waiter {
        key,
        thread: moto_sys::current_thread().as_u64(),
        prev: null_mut(),
        next: null_mut(),
        linked: true,
    };
    let node = &raw mut waiter;
    let bucket = bucket(key);
    // SAFETY: `waiter` does not move until it is unlinked below.
    unsafe { bucket.lock().push_back(node) };

    // Wakers change the value before they look for waiters, so a change made
    // after the node is linked is either seen here or followed by a wake.
    let awake = if futex_ref.load(Ordering::Acquire) != expected {
        true
    } else if timeout.is_some_and(|timo| timo <= moto_rt::time::Instant::now()) {
        false
    } else {
        match SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, timeout) {
            Ok(()) => true,
            Err(err) => {
                assert_eq!(err, moto_rt::E_TIMED_OUT);
                false
            }
        }
    };

    let mut bucket = bucket.lock();
    // SAFETY: the node is only accessed under the bucket lock.
    let woken = unsafe {
        let woken = !(*node).linked;
        if !woken {
            bucket.unlink(node);
        }
        woken
    };
    drop(bucket);

    // Note: we DO NOT check futex value again and loop if expected,
    // because a tokio test will hang. It seems that tokio expects
    // a wake/wake_all to kick a waiter (all waiters) unconditionally.

    // A wake that raced with the timeout was consumed here, so report it.
    awake || woken
}

fn futex_wake_impl(key: usize) -> bool {
    let Some(thread) = bucket(key).lock().pop(key) else {
        return false;
    };
    let _ = SysCpu::wake(SysHandle::from_u64(thread)); // Ignore errors: the wake could have raced with wait.
    true
}

// Returns 0 on timeout.
pub extern "C" fn futex_wait(futex: *const AtomicU32, expected: u32, timeout: u64) -> u32 {
    let timo = match timeout {
        u64::MAX => None,
        val => Some(core::time::Duration::from_nanos(val)),
    };

    if futex_wait_impl(futex, expected, timo) {
        1
    } else {
        0
    }
}

pub extern "C" fn futex_wake(futex: *const AtomicU32) -> u32 {
    if futex_wake_impl(futex as usize) {
        1
    } else {
        0
    }
}

pub extern "C" fn futex_wake_all(futex: *const AtomicU32) {
    let key = futex as usize;
    // Only the waiters present now: one that is woken and waits again must
    // not keep this loop going.
    let waiters = bucket(key).lock().count(key);
    for _ in 0..waiters {
        if !futex_wake_impl(key) {
            break;
        }
    }
}
