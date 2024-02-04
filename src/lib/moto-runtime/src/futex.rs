use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::clone::Clone;
use core::marker::PhantomPinned;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use crate::external::spin;
use moto_sys::syscalls::SysCpu;
use moto_sys::syscalls::SysHandle;
use moto_sys::ErrorCode;

// We need to be able to remove from the middle of the list, and Rust's
// standard List does not have this functionality.
struct WaitQueueEntry {
    wake_handle: u64,
    prev: AtomicUsize,
    next: AtomicUsize,
    _pin: PhantomPinned,
}

unsafe impl Sync for WaitQueueEntry {}
unsafe impl Send for WaitQueueEntry {}

impl WaitQueueEntry {
    // Lives on stack.
    fn new() -> Self {
        Self {
            wake_handle: 0,
            prev: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
            _pin: PhantomPinned::default(),
        }
    }

    unsafe fn insert_before(&mut self, next: &mut WaitQueueEntry) {
        let prev = (next.prev.load(Ordering::Relaxed) as *mut Self)
            .as_mut()
            .unwrap();

        prev.next
            .store(self as *const _ as usize, Ordering::Relaxed);
        next.prev
            .store(self as *const _ as usize, Ordering::Relaxed);

        self.prev
            .store(prev as *const _ as usize, Ordering::Relaxed);
        self.next
            .store(next as *const _ as usize, Ordering::Relaxed);
    }

    unsafe fn remove(&mut self) {
        let prev = (self.prev.load(Ordering::Relaxed) as *mut Self)
            .as_mut()
            .unwrap();
        let next = (self.next.load(Ordering::Relaxed) as *mut Self)
            .as_mut()
            .unwrap();

        prev.next
            .store(next as *const _ as usize, Ordering::Relaxed);
        next.prev
            .store(prev as *const _ as usize, Ordering::Relaxed);

        self.prev.store(0, Ordering::Relaxed);
        self.next.store(0, Ordering::Relaxed);
    }
}

struct WaitQueue {
    entries: spin::Mutex<WaitQueueEntry>,
    num_waiters: AtomicU64,
    p_head: usize,
}

unsafe impl Sync for WaitQueue {}
unsafe impl Send for WaitQueue {}

impl WaitQueue {
    fn new() -> Arc<Self> {
        let mut self_ = Arc::new(Self {
            entries: spin::Mutex::new(WaitQueueEntry::new()),
            num_waiters: AtomicU64::new(0),
            p_head: 0,
        });

        unsafe {
            let self_ref: &mut WaitQueue = Arc::get_mut(&mut self_).unwrap_unchecked();
            let mut head_lock = self_ref.entries.lock();
            let head: &mut WaitQueueEntry = &mut *head_lock;
            self_ref.p_head = head as *const _ as usize;
            head.prev.store(self_ref.p_head, Ordering::Relaxed);
            head.next.store(self_ref.p_head, Ordering::Relaxed);
        }

        self_
    }

    // Returns true if timed out.
    fn wait(&self, timeout: &Option<moto_sys::time::Instant>) -> bool {
        let mut entry = WaitQueueEntry::new();

        let tcb = moto_sys::UserThreadControlBlock::get();
        entry.wake_handle = tcb.self_handle;

        {
            let mut head_lock = self.entries.lock();

            // Safe because under the mutex lock.
            unsafe {
                entry.insert_before(&mut *head_lock);
            }
        }

        let timed_out = match SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, *timeout) {
            Ok(()) => false,
            Err(err) => {
                assert_eq!(err, ErrorCode::TimedOut);
                true
            }
        };

        {
            let _entries = self.entries.lock();
            // Safe because under the mutex lock.
            unsafe {
                // Entries are removed from the list in wake_one().
                if entry.next.load(Ordering::Relaxed) != 0 {
                    entry.remove(); // Timed out.
                }
            }
        }
        timed_out
    }

    fn wake_one(&self) -> bool {
        let wake_handle = {
            let head = self.entries.lock();
            let p_first = head.next.load(Ordering::Relaxed);
            if p_first == self.p_head {
                return false;
            }

            // Safe because under the mutex lock.
            unsafe {
                let first = (p_first as *mut WaitQueueEntry).as_mut().unwrap();
                first.remove();
                first.wake_handle
            }
        };

        SysCpu::wake(moto_sys::SysHandle::from_u64(wake_handle)).ok(); // Ignore errors: the wake could have raced with wait.
        true
    }

    fn wake_all(&self) {
        while self.wake_one() {}
    }
}

static FUTEX_WAIT_QUEUES: spin::Mutex<BTreeMap<usize, Arc<WaitQueue>>> =
    spin::Mutex::new(BTreeMap::new());

// Returns false on timeout.
pub fn futex_wait(futex: &AtomicU32, expected: u32, timeout: Option<moto_sys::time::Instant>) -> bool {
    let key = futex as *const _ as usize;
    loop {
        if futex.load(Ordering::Relaxed) != expected {
            return true;
        }
        if let Some(timo) = timeout {
            if timo <= moto_sys::time::Instant::now() {
                return false;
            }
        }

        let queue = {
            let mut lock = FUTEX_WAIT_QUEUES.lock();
            match lock.get(&key) {
                Some(q) => q.clone(),
                None => {
                    let q = WaitQueue::new();
                    lock.insert(key, q.clone());
                    q
                }
            }
        };

        queue.num_waiters.fetch_add(1, Ordering::Relaxed);
        let timed_out = if futex.load(Ordering::Relaxed) == expected {
            queue.wait(&timeout)
        } else {
            false
        };

        {
            let mut lock = FUTEX_WAIT_QUEUES.lock();
            if 1 == queue.num_waiters.fetch_sub(1, Ordering::Relaxed) {
                if let Some(q) = lock.get(&key) {
                    // It is really hard to get a pointer out of Pin<Arc<_>>.
                    let ref1: &WaitQueue = &*q;
                    let ref2: &WaitQueue = &*queue;
                    let ptr1 = ref1 as *const WaitQueue;
                    let ptr2 = ref2 as *const WaitQueue;
                    if ptr1 == ptr2 {
                        lock.remove(&key);
                    }
                }
            }
        }

        if timed_out {
            return false;
        }
    }
}

pub fn futex_wake(futex: &AtomicU32) -> bool {
    let key = futex as *const _ as usize;
    let queue = {
        let lock = FUTEX_WAIT_QUEUES.lock();
        match lock.get(&key) {
            Some(q) => q.clone(),
            None => return false,
        }
    };

    queue.wake_one()
}

pub fn futex_wake_all(futex: &AtomicU32) {
    let key = futex as *const _ as usize;
    let queue = {
        let mut lock = FUTEX_WAIT_QUEUES.lock();
        if let Some(q) = lock.remove(&key) {
            q
        } else {
            return;
        }
    };

    queue.wake_all()
}
