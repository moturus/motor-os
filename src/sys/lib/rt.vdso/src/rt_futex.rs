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
    entries: SpinLock<(VecDeque<u64>, BTreeSet<u64>)>,
    num_waiters: AtomicU64,
}

impl WaitQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: SpinLock::new((VecDeque::new(), BTreeSet::new())),
            num_waiters: AtomicU64::new(0),
        })
    }

    // Returns true if timed out.
    fn wait(&self, timeout: &Option<moto_rt::time::Instant>) -> bool {
        let tcb = moto_sys::UserThreadControlBlock::get();
        let wake_handle = tcb.self_handle;

        {
            let mut entries = self.entries.lock();
            entries.0.push_back(wake_handle);
            entries.1.insert(wake_handle);
        }

        let timed_out = match SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, *timeout) {
            Ok(()) => false,
            Err(err) => {
                assert_eq!(err, moto_rt::E_TIMED_OUT);
                true
            }
        };

        {
            let mut entries = self.entries.lock();
            entries.1.remove(&wake_handle);
            // Note: we don't search VecDeque.
        }
        timed_out
    }

    fn wake_one(&self) -> bool {
        let wake_handle: u64 = {
            let mut entries = self.entries.lock();
            loop {
                let Some(handle) = entries.0.pop_front() else {
                    return false;
                };

                if entries.1.remove(&handle) {
                    break handle;
                }
            }
        };

        SysCpu::wake(moto_sys::SysHandle::from_u64(wake_handle)).ok(); // Ignore errors: the wake could have raced with wait.
        true
    }

    fn wake_all(&self) {
        while self.wake_one() {}
    }
}

static FUTEX_WAIT_QUEUES: SpinLock<BTreeMap<usize, Arc<WaitQueue>>> =
    SpinLock::new(BTreeMap::new());

// Returns false on timeout.
fn futex_wait_impl(
    futex: &AtomicU32,
    expected: u32,
    timeout: Option<core::time::Duration>,
) -> bool {
    let timeout = timeout.map(|dur| moto_rt::time::Instant::now() + dur);

    let key = futex as *const _ as usize;
    loop {
        if futex.load(Ordering::Acquire) != expected {
            return true;
        }
        if let Some(timo) = timeout {
            if timo <= moto_rt::time::Instant::now() {
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

        queue.num_waiters.fetch_add(1, Ordering::SeqCst);
        let timed_out = if futex.load(Ordering::Acquire) == expected {
            queue.wait(&timeout)
        } else {
            false
        };

        {
            let mut lock = FUTEX_WAIT_QUEUES.lock();
            if 1 == queue.num_waiters.fetch_sub(1, Ordering::SeqCst) {
                if let Some(q) = lock.get(&key) {
                    // It is really hard to get a pointer out of Pin<Arc<_>>.
                    let ref1: &WaitQueue = q;
                    let ref2: &WaitQueue = &queue;
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

fn futex_wake_impl(futex: &AtomicU32) -> bool {
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

fn futex_wake_all_impl(futex: &AtomicU32) {
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

pub extern "C" fn futex_wait(futex: *const AtomicU32, expected: u32, timeout: u64) -> u32 {
    let timo = match timeout {
        u64::MAX => None,
        val => Some(core::time::Duration::from_nanos(val)),
    };

    if futex_wait_impl(unsafe { futex.as_ref().unwrap() }, expected, timo) {
        1
    } else {
        0
    }
}

pub extern "C" fn futex_wake(futex: *const AtomicU32) -> u32 {
    if futex_wake_impl(unsafe { futex.as_ref().unwrap() }) {
        1
    } else {
        0
    }
}

pub extern "C" fn futex_wake_all(futex: *const AtomicU32) {
    futex_wake_all_impl(unsafe { futex.as_ref().unwrap() })
}
