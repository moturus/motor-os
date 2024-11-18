use core::any::Any;
use core::sync::atomic::*;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::{collections::BTreeMap, sync::Weak};
use moto_sys::syscalls::*;

use crate::util::SpinLock;

use super::process::{Thread, ThreadId};
use super::Process;

// Represents a system object that SysHandle points to.
#[repr(align(8))]
pub struct SysObject {
    // Upon a wake event, SysObject adds itself to the global list
    // of woken objects. As this is often done in the IRQ context,
    // we can't do mutexes/memory allocations/etc., so we we work
    // with a lock-free intrusive singly-linked-list. See Self::wake()
    next_woken: AtomicU64,
    wake_event_lock: AtomicBool,

    waiting_threads: SpinLock<BTreeMap<ThreadId, (Weak<Thread>, SysHandle)>>,

    url: Arc<String>,
    owner: Arc<dyn Any + Sync + Send>,
    process_owner: Weak<Process>,

    // A unique ID, otherwise it is hard to figure out if two refs point at the same obj:
    // Rust does not have equality by reference.
    id: u64,

    // Each wake increments the counter; each waiter stores the last delivered wake counter
    // value, thus ensuring that wake events are not lost.
    wake_counter: AtomicU64,

    // Shared objects in shared.rs have two children; when one dies, another
    // gets sibling_dropped set.
    sibling_dropped: AtomicBool,

    // Some objects wake once and then always stay "woken", e.g. process completions.
    done: AtomicBool,
}

impl PartialEq for SysObject {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Drop for SysObject {
    fn drop(&mut self) {
        // Woken objects are stored as raw pointers on the global
        // woken list, so they should never be dropped.
        assert!(!self.is_woken());

        if !self.sibling_dropped.load(Ordering::Relaxed) {
            super::shared::on_drop(self);
        }
    }
}

impl SysObject {
    pub fn new_owned(
        url: Arc<String>,
        owner: Arc<dyn Any + Sync + Send>,
        process_owner: Weak<Process>,
    ) -> Arc<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        Arc::new(Self {
            waiting_threads: SpinLock::new(BTreeMap::new()),
            next_woken: AtomicU64::new(0),
            wake_event_lock: AtomicBool::new(false),
            url,
            owner,
            process_owner,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            wake_counter: AtomicU64::new(0),
            sibling_dropped: AtomicBool::new(false),
            done: AtomicBool::new(false),
        })
    }

    pub fn new(url: Arc<String>) -> Arc<Self> {
        Self::new_owned(url, Arc::<()>::new(()), Weak::new())
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn owner(&self) -> &Arc<dyn Any + Sync + Send> {
        &self.owner
    }

    pub fn process_owner(&self) -> &Weak<Process> {
        &self.process_owner
    }

    pub fn on_sibling_dropped(&self) {
        self.sibling_dropped.store(true, Ordering::Release);
        self.wake(false); // Important to wake after setting sibling_dropped.
    }

    pub fn sibling_dropped(&self) -> bool {
        self.sibling_dropped.load(Ordering::Acquire)
    }

    pub fn mark_done(&self) {
        assert!(!self.done.swap(true, Ordering::Release));
    }

    pub fn done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn is_woken(&self) -> bool {
        self.next_woken.load(Ordering::Relaxed) != 0
    }

    #[inline(always)]
    pub fn set_next_woken(&self, next: u64) {
        debug_assert!(self.wake_event_lock.load(Ordering::Relaxed));
        // Use +1 to indicate self is woken even if next is zero.
        self.next_woken.store(next + 1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add_waiting_thread(&self, thread: &Thread, handle: SysHandle) {
        self.waiting_threads
            .lock(line!())
            .insert(thread.tid(), (thread.get_weak(), handle));
    }

    pub fn remove_waiting_thread(&self, thread: &Thread) {
        self.waiting_threads.lock(line!()).remove(&thread.tid());
    }

    pub fn take_woken(&self) -> (u64, BTreeMap<ThreadId, (Weak<Thread>, SysHandle)>) {
        loop {
            let prev = self.wake_event_lock.swap(true, Ordering::Acquire);
            if !prev {
                break;
            }
        }
        // Use -1 because we did a +1 in set_next_woken.
        let next = self.next_woken.swap(0, Ordering::Relaxed) - 1;
        let threads = core::mem::take(&mut *self.waiting_threads.lock(line!()));
        self.wake_event_lock.store(false, Ordering::Release);

        (next, threads)
    }

    pub fn get_single_waiter(&self) -> Option<Arc<Thread>> {
        let waiters = self.waiting_threads.lock(line!());
        if let Some((_, (t, _))) = waiters.iter().next() {
            t.upgrade()
        } else {
            None
        }
    }

    // May be called from IRQ.
    #[inline]
    pub fn wake_irq(self_: &Arc<Self>) {
        self_.wake_counter.fetch_add(1, Ordering::Release);
        // Protect against concurrent attempts to add this object to the woken list.
        let prev = self_.wake_event_lock.swap(true, Ordering::Acquire);
        if prev {
            return;
        }

        if !self_.is_woken() {
            on_object_woke(self_);
        }

        self_.wake_event_lock.store(false, Ordering::Release);
    }

    #[allow(clippy::result_unit_err)]
    pub fn wake_thread(&self, wakee_thread: SysHandle, this_cpu: bool) -> Result<(), ()> {
        if let Some(process) = self.process_owner().upgrade() {
            if let Some(thread) = super::sysobject::object_from_handle::<super::process::Thread>(
                &process,
                wakee_thread,
            ) {
                thread.post_wake(this_cpu);
                return Ok(());
            }
        }
        Err(())
    }

    // NOT called from IRQ.
    pub fn wake(&self, this_cpu: bool) {
        self.wake_counter.fetch_add(1, Ordering::Release);
        // Protect against concurrent attempts to add this object to the woken list.
        let prev = self.wake_event_lock.swap(true, Ordering::Acquire);
        if prev {
            return;
        }

        if self.is_woken() {
            self.wake_event_lock.store(false, Ordering::Release);
            return;
        }

        self.set_next_woken(0); // Mark woken.
        self.wake_event_lock.store(false, Ordering::Release);

        // See process_wake_events.
        let (next, threads_and_handles) = self.take_woken();
        assert_eq!(next, 0);
        for (_, (thread, handle)) in threads_and_handles {
            if let Some(thread) = thread.upgrade() {
                thread.wake_by_object(handle, this_cpu);
            }
        }
    }

    pub fn wake_count(&self) -> u64 {
        self.wake_counter.load(Ordering::Acquire)
    }
}

pub fn object_from_handle<T: Any + Send + Sync>(
    process: &super::Process,
    handle: SysHandle,
) -> Option<Arc<T>> {
    match process.get_object(&handle) {
        None => None,
        Some(obj) => object_from_sysobject(&obj.sys_object),
    }
}

pub fn object_from_sysobject<T: Any + Send + Sync>(sys_object: &Arc<SysObject>) -> Option<Arc<T>> {
    Arc::downcast::<T>(sys_object.owner.clone()).ok()
}

static WOKEN_OBJECTS: AtomicU64 = AtomicU64::new(0);

fn on_object_woke(woken: &Arc<SysObject>) {
    // NOTE: this is often called from an IRQ, be very careful what you do here:
    // no taking of locks, no memory allocations.
    debug_assert!(!woken.is_woken());

    loop {
        let prev_head = WOKEN_OBJECTS.load(Ordering::Relaxed);
        woken.set_next_woken(prev_head);

        // Do Arc::into_raw + clone to keep the refcount up.
        let next_head = Arc::into_raw(woken.clone()) as usize as u64;

        if WOKEN_OBJECTS
            .compare_exchange_weak(prev_head, next_head, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
}

pub fn process_wake_events() {
    let mut next = WOKEN_OBJECTS.swap(0, Ordering::AcqRel);

    while next != 0 {
        let obj = unsafe { Arc::from_raw(next as usize as *const SysObject) };
        // See SysObject::wake().
        let (next_, threads_and_handles) = obj.take_woken();
        next = next_;
        for (_, (thread, handle)) in threads_and_handles {
            if let Some(thread) = thread.upgrade() {
                thread.wake_by_object(handle, false);
            }
        }
    }
}
