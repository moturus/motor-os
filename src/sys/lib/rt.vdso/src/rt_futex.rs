use alloc::collections::btree_set::BTreeSet;
use alloc::collections::vec_deque::VecDeque;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use moto_rt::spinlock::SpinLock;
use moto_sys::SysCpu;
use moto_sys::SysHandle;

// The challenge here is that we want to keep first-in, first-out,
// which calls for VecDeque, and fast access by value. We maintain
// this by having both a VecDeque and a BTreeSet.
struct WaitQueue {
    id: u64, // Needed to differentiate individual queues.
    entries: SpinLock<(VecDeque<u64>, BTreeSet<u64>)>,
}

impl WaitQueue {
    fn new() -> Arc<Self> {
        static ID: AtomicU64 = AtomicU64::new(0);
        Arc::new(Self {
            id: ID.fetch_add(1, Ordering::Relaxed),
            entries: SpinLock::new((VecDeque::new(), BTreeSet::new())),
        })
    }

    fn add_waiter(&self) {
        let tcb = moto_sys::UserThreadControlBlock::get();
        let wake_handle = tcb.self_handle;

        let mut entries = self.entries.lock();
        entries.0.push_back(wake_handle);
        assert!(entries.1.insert(wake_handle));
    }

    // Returns true if the queue is empty.
    fn remove_waiter(&self) -> bool {
        let tcb = moto_sys::UserThreadControlBlock::get();
        let wake_handle = tcb.self_handle;

        let mut entries = self.entries.lock();
        assert!(entries.1.remove(&wake_handle));

        // Don't search for _this_ entry, it will be cleared during wake.
        if entries.1.is_empty() {
            entries.0.clear();
            true
        } else {
            false
        }
    }

    // Returns true if timed out.
    fn wait(&self, timeout: &Option<moto_rt::time::Instant>) -> bool {
        match SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, *timeout) {
            Ok(()) => false,
            Err(err) => {
                assert_eq!(err, moto_rt::E_TIMED_OUT);
                true
            }
        }
    }

    fn wake_one(&self) -> bool {
        let wake_handle: u64 = {
            let mut entries = self.entries.lock();
            loop {
                let Some(handle) = entries.0.pop_front() else {
                    return false;
                };

                if entries.1.contains(&handle) {
                    break handle;
                }
            }
        };

        let _ = SysCpu::wake(moto_sys::SysHandle::from_u64(wake_handle)); // Ignore errors: the wake could have raced with wait.
        true
    }

    fn wake_all(&self) {
        while self.wake_one() {}
    }
}

static FUTEX_WAIT_QUEUES: SpinLock<BTreeMap<usize, Arc<WaitQueue>>> =
    SpinLock::new(BTreeMap::new());

fn add_waiter_to_queue(key: usize) -> Arc<WaitQueue> {
    let mut queues_lock = FUTEX_WAIT_QUEUES.lock();
    let queue = match queues_lock.get(&key) {
        Some(q) => q.clone(),
        None => {
            let q = WaitQueue::new();
            assert!(queues_lock.insert(key, q.clone()).is_none());
            q
        }
    };
    queue.add_waiter(); // Must happen under the global lock.
    queue
}

fn remove_waiter_from_queue(key: usize, queue: Arc<WaitQueue>) {
    let mut queues_lock = FUTEX_WAIT_QUEUES.lock();
    let empty = queue.remove_waiter(); // Must happen under the global lock.
    if empty {
        let removed = queues_lock.remove(&key).unwrap();
        assert_eq!(removed.id, queue.id);
    }
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

    // Get/create the queue.
    let queue = add_waiter_to_queue(key);

    if futex_ref.load(Ordering::Acquire) != expected {
        remove_waiter_from_queue(key, queue);
        return false;
    }

    if let Some(timo) = timeout {
        if timo <= moto_rt::time::Instant::now() {
            remove_waiter_from_queue(key, queue);
            return true;
        }
    }

    let timedout = queue.wait(&timeout);
    remove_waiter_from_queue(key, queue);

    // Note: we DO NOT check futex value again and loop if expected,
    // because a tokio test will hang. It seems that tokio expects
    // a wake/wake_all to kick a waiter (all waiters) unconditionally.

    !timedout
}

fn futex_wake_impl(futex: *const AtomicU32) -> bool {
    let key = futex as usize;
    let queue = {
        let lock = FUTEX_WAIT_QUEUES.lock();
        match lock.get(&key) {
            Some(q) => q.clone(),
            None => return false,
        }
    };

    queue.wake_one()
}

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
    if futex_wake_impl(futex) {
        1
    } else {
        0
    }
}

pub extern "C" fn futex_wake_all(futex: *const AtomicU32) {
    let key = futex as usize;
    let queue = {
        let lock = FUTEX_WAIT_QUEUES.lock();
        match lock.get(&key) {
            Some(q) => q.clone(),
            None => return,
        }
    };

    queue.wake_all()
}
