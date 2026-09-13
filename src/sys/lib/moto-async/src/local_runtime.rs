//! LocalExecutor runtime for Motor OS.
//!
//! We need our own runtime because runtimes depend on low-level system services which are not
//! portable across operating systems without abstraction layers like tokio::mio or Rust stdlib.
//! Yes, tokio has been ported to Motor OS, but it cannot be used at the lowest level (rt.vdso).
//!
//! Inspired by futures::executor::LocalPool.
//!
//! From tokio::runtime docs:
//!
//! Unlike other Rust programs, asynchronous applications require runtime
//! support. In particular, the following runtime services are necessary:
//!
//! * An **I/O event loop**, called the driver, which drives I/O resources and
//!   dispatches I/O events to tasks that depend on them.
//! * A **scheduler** to execute [tasks] that use these I/O resources.
//! * A **timer** for scheduling work to run after a set period of time.
//!
//! Motor OS Runtime bundles all of these services as a single type, allowing them to be started,
//! shut down, and configured together.

use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::vec_deque::VecDeque;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::OnceCell;
use core::cell::RefCell;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::Context;
use core::task::ContextBuilder;
use core::task::LocalWaker;
use core::task::Poll;
use core::task::RawWaker;
use core::task::RawWakerVTable;
use core::task::Waker;
use moto_rt::Result;
use moto_rt::time::Instant;
use moto_sys::SysHandle;

use crate::oneshot;

mod wake_queue;
use wake_queue::{Link, LocalQueue, WakeQueue};

extern crate alloc;

static RUNTIME_TLS_KEY: AtomicUsize = AtomicUsize::new(0);

fn get_runtime_tls_key() -> moto_rt::tls::Key {
    let key = RUNTIME_TLS_KEY.load(Ordering::Relaxed);
    if key != 0 {
        return key;
    }

    let key = moto_rt::tls::create(None);
    assert_ne!(key, 0);
    if let Err(prev) = RUNTIME_TLS_KEY.compare_exchange(0, key, Ordering::AcqRel, Ordering::Relaxed)
    {
        // Safety: we just created the key, so it is safe.
        unsafe { moto_rt::tls::destroy(key) };
        prev
    } else {
        key
    }
}

pub(crate) fn on_runtime_thread() -> bool {
    !get_local_runtime_context().is_null()
}

fn get_local_runtime_context() -> *const LocalRuntimeInner {
    // Safety: safe by construction.
    unsafe { moto_rt::tls::get(get_runtime_tls_key()) as usize as *const _ }
}

fn set_local_runtime_context(runtime: &LocalRuntime) {
    // Safety: safe by construction.
    unsafe {
        moto_rt::tls::set(
            get_runtime_tls_key(),
            Box::as_ptr(&runtime.inner) as usize as *mut u8,
        )
    }
}

fn clear_local_runtime_context() {
    // Safety: safe by construction.
    unsafe { moto_rt::tls::set(get_runtime_tls_key(), core::ptr::null_mut()) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TaskId(u64);

impl TaskId {
    fn default_root() -> Self {
        Self(0)
    }

    fn is_root(&self) -> bool {
        self.0 == 0
    }
}

// Executor run-state, for wake elision (design 3.4): a cross-thread wake
// enqueues its task (or coalesces into the pending entry), and pays the
// wake syscall only when the runtime is parked or committing to park.
const RUN_STATE_POLLING: u32 = 0;
const RUN_STATE_COMMITTING: u32 = 1;
const RUN_STATE_PARKED: u32 = 2;

// Cross-thread wakes that enqueued: issued (syscall) vs elided (runtime
// awake), process-wide. Coalesced wakes are not counted.
static WAKES_ISSUED: AtomicU64 = AtomicU64::new(0);
static WAKES_ELIDED: AtomicU64 = AtomicU64::new(0);

pub fn wake_counters() -> (u64, u64) {
    (
        WAKES_ISSUED.load(Ordering::Relaxed),
        WAKES_ELIDED.load(Ordering::Relaxed),
    )
}

/// Entries queued in the current runtime's timer queue, cancelled-but-not-yet-
/// compacted ones included. Diagnostic: lets a caller assert that a hot
/// register/cancel loop does not grow the queue without bound.
/// Must be called within a LocalRuntime context.
pub fn timer_queue_len() -> usize {
    LocalRuntimeInner::current().timeq.borrow().len()
}

/// A readiness check the executor polls instead of parking.
///
/// A task that goes Pending on a recently active source registers one (see
/// [`register_spin_source`]). While the registration lives the executor
/// checks the source on every scheduling turn, spins on it for a bounded
/// time when it has nothing else to run, and wakes the task without a
/// syscall or an IPI when it becomes ready. Between `begin` and `end` the
/// peer need not send wakes, so `end` runs exactly once per registration:
/// when readiness is observed, when the registration is replaced or expires,
/// or before the executor parks or leaves `block_on`.
pub trait SpinSource {
    fn ready(&self) -> bool;
    /// The executor now watches the source (e.g. clear the channel's
    /// "waiting" flag so the peer skips its wake syscall).
    fn begin(&self) {}
    /// The executor stops watching: ask the peer for wakes again, then
    /// report whether the source became ready meanwhile.
    fn end(&self) -> bool {
        self.ready()
    }
}

struct SpinEntry {
    source: Box<dyn SpinSource>,
    waker: core::task::LocalWaker,
    expires: u64, // TSC
}

/// How long an idle executor spins on its sources before parking.
const SPIN_BEFORE_PARK_NS: u64 = 20_000;
/// Registrations beyond this keep the normal wake path: a pass over more
/// sources would eat the spin window.
const MAX_SPIN_SOURCES: usize = 8;

fn tsc_now() -> u64 {
    moto_rt::time::Instant::now().as_u64()
}

fn ns_to_tsc(ns: u64) -> u64 {
    moto_sys::KernelStaticPage::get().tsc_in_sec * ns / 1_000_000_000
}

/// Register `source` for the current task for `active_for_ns` from now. A
/// no-op outside a LocalRuntime context or when the table is full.
pub fn register_spin_source(source: Box<dyn SpinSource>, cx: &mut Context<'_>, active_for_ns: u64) {
    let Some(inner) = LocalRuntimeInner::try_current() else {
        return;
    };
    let waker = cx.local_waker().clone();
    let mut sources = inner.spin_sources.borrow_mut();
    // One registration per task: a re-poll replaces the previous one.
    if let Some(idx) = sources
        .iter()
        .position(|entry| entry.waker.data() == waker.data())
    {
        let old = sources.swap_remove(idx);
        if old.source.end() {
            old.waker.wake_by_ref();
        }
    }
    if sources.len() >= MAX_SPIN_SOURCES {
        return;
    }
    source.begin();
    sources.push(SpinEntry {
        source,
        waker,
        expires: tsc_now() + ns_to_tsc(active_for_ns),
    });
}

const WAKE_IDLE: u8 = 0;
const WAKE_QUEUED: u8 = 1;
const WAKE_COMPLETE: u8 = 2;
// wake() claims with fetch_max, so the numeric order is load-bearing.
const _: () = assert!(WAKE_IDLE < WAKE_QUEUED && WAKE_QUEUED < WAKE_COMPLETE);

// Only this header is shared across threads; the future stays executor-local.
// Link must remain first so the intrusive queues can recover the Arc pointer.
#[repr(C)]
struct MotoWaker {
    link: Link,
    state: AtomicU8,
    runqueue: alloc::sync::Weak<WakeQueue>,
    run_state: Arc<AtomicU32>,
    task_id: TaskId,
    wake_handle: SysHandle, // The handle to call wake() on.
}

impl MotoWaker {
    fn new(queue: &Arc<WakeQueue>, run_state: &Arc<AtomicU32>, task_id: TaskId) -> Self {
        Self {
            link: Link::new(),
            state: AtomicU8::new(WAKE_IDLE),
            runqueue: Arc::downgrade(queue),
            run_state: run_state.clone(),
            task_id,
            wake_handle: moto_sys::current_thread(),
        }
    }

    // True if this wake must enqueue the header; false if the task is already
    // queued (the wake coalesces) or complete. Even a coalesced wake publishes
    // its prior writes to the acquire that clears WAKE_QUEUED before the poll.
    fn claim(&self) -> bool {
        self.state.fetch_max(WAKE_QUEUED, Ordering::AcqRel) == WAKE_IDLE
    }

    fn wake(self: &Arc<Self>, local: bool) {
        // A wake on the owning executor's own thread goes straight to its
        // local queue: no shared-queue traffic and nothing to notify.
        if local
            && let Some(inner) = LocalRuntimeInner::try_current()
            && core::ptr::eq(self.runqueue.as_ptr(), Arc::as_ptr(&inner.nonlocal_wakes))
        {
            if self.claim() {
                // Safety: the claim gives this wake exclusive use of the link.
                unsafe { inner.runqueue.borrow_mut().push(self.clone()) };
            }
            return;
        }

        // Keep the queue alive through both halves of publication and notification.
        let Some(queue) = self.runqueue.upgrade() else {
            return;
        };
        if !self.claim() {
            return;
        }
        // Safety: as above.
        unsafe { queue.push(self.clone()) };
        // SC fence pairs with the one in LocalRuntime::wait(): either our
        // link is visible to its recheck, or we see its COMMITTING store.
        core::sync::atomic::fence(Ordering::SeqCst);
        if self.run_state.load(Ordering::Relaxed) == RUN_STATE_POLLING {
            WAKES_ELIDED.fetch_add(1, Ordering::Relaxed);
        } else {
            WAKES_ISSUED.fetch_add(1, Ordering::Relaxed);
            let _ = moto_sys::SysCpu::wake(self.wake_handle);
        }
    }

    fn complete(&self) {
        self.state.store(WAKE_COMPLETE, Ordering::Release);
    }
}

// The vtables below receive `data` from Arc::into_raw or Arc::as_ptr, so it
// carries the allocation's provenance and may be turned back into an Arc.

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    unsafe { Arc::increment_strong_count(data.cast::<MotoWaker>()) };
    RawWaker::new(data, &RAW_WAKER_VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    unsafe { Arc::from_raw(data.cast::<MotoWaker>()) }.wake(false);
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    let header = unsafe { ManuallyDrop::new(Arc::from_raw(data.cast::<MotoWaker>())) };
    header.wake(false);
}

unsafe fn waker_drop(data: *const ()) {
    unsafe { Arc::decrement_strong_count(data.cast::<MotoWaker>()) };
}

static RAW_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

unsafe fn local_waker_clone(data: *const ()) -> RawWaker {
    unsafe { Arc::increment_strong_count(data.cast::<MotoWaker>()) };
    RawWaker::new(data, &RAW_LOCAL_WAKER_VTABLE)
}

unsafe fn local_waker_wake(data: *const ()) {
    unsafe { Arc::from_raw(data.cast::<MotoWaker>()) }.wake(true);
}

unsafe fn local_waker_wake_by_ref(data: *const ()) {
    let header = unsafe { ManuallyDrop::new(Arc::from_raw(data.cast::<MotoWaker>())) };
    header.wake(true);
}

static RAW_LOCAL_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    local_waker_clone,
    local_waker_wake,
    local_waker_wake_by_ref,
    waker_drop,
);

// The Waker and LocalWaker a future is polled with. They borrow the header
// instead of owning a reference to it, so a poll costs no reference-count
// traffic; a clone taken through either owns its own reference.
struct PollWakers<'a> {
    waker: ManuallyDrop<Waker>,
    local_waker: ManuallyDrop<LocalWaker>,
    _header: PhantomData<&'a Arc<MotoWaker>>,
}

impl<'a> PollWakers<'a> {
    fn new(header: &'a Arc<MotoWaker>) -> Self {
        let data = Arc::as_ptr(header).cast::<()>();
        // Safety: the vtables only touch the header, which `header` keeps
        // alive for 'a; the views are never dropped, so they release nothing.
        unsafe {
            Self {
                waker: ManuallyDrop::new(Waker::from_raw(RawWaker::new(data, &RAW_WAKER_VTABLE))),
                local_waker: ManuallyDrop::new(LocalWaker::from_raw(RawWaker::new(
                    data,
                    &RAW_LOCAL_WAKER_VTABLE,
                ))),
                _header: PhantomData,
            }
        }
    }

    fn context(&self) -> Context<'_> {
        ContextBuilder::from_waker(&self.waker)
            .local_waker(&self.local_waker)
            .build()
    }
}

struct Task {
    fut: Pin<Box<dyn Future<Output = ()>>>,
    header: Arc<MotoWaker>,

    #[cfg(debug_assertions)]
    debug_log: bool,
}

impl Drop for Task {
    fn drop(&mut self) {
        // Retire before the future's destructor can invoke any stale wakers.
        self.header.complete();
    }
}

// When a task is polled, it should be pinned, therefore borrowed.
// So its container gets borrowed. So LocalRuntimeInner gets borrowed.
//
// While LocalRuntimeInner::tasks::<task> are pinned/borrowed,
// the running code may add timers, spawn other tasks, etc., so
// we need interior mutability at runtime (=> RefCell).
struct LocalRuntimeInner {
    // The main (local) runqueue. Runnable tasks live there.
    runqueue: RefCell<LocalQueue>,

    // SysHandle futures.
    sys_handle_futures: RefCell<BTreeMap<SysHandle, VecDeque<Rc<RefCell<SysHandleFutureInner>>>>>,

    // Timers. Can be added to at runtime. Hold wakers, not task IDs:
    // a timer registered under a nested combinator (FuturesUnordered)
    // must fire the combinator's waker, or the child is never re-polled.
    timeq: RefCell<crate::timeq::TimeQ<core::task::LocalWaker>>,

    // New tasks (from spawn()). As they are added "at runtime",
    // when Self::tasks is borrowed, we need to temporarily
    // store them into Self::incoming for later processing.
    incoming: RefCell<VecDeque<Task>>,

    // All tasks present in this runtime (at most one can be running).
    tasks: RefCell<BTreeMap<TaskId, Task>>,
    next_task_id: RefCell<u64>,

    // Intrusive headers of wakes coming from wakers (!= LocalWaker).
    nonlocal_wakes: Arc<WakeQueue>,

    // The header every block_on future is polled with, created on the first
    // block_on. One per runtime, so a LocalWaker stored under an earlier
    // block_on (a Sleep keeps its timer's) still wakes the current one; a
    // stale root wake costs one spurious poll.
    root: OnceCell<Arc<MotoWaker>>,

    run_state: Arc<AtomicU32>,

    // Deferred peer wake (design 3.3): delivered exactly once, folded
    // into the next sleep syscall or issued if we resume polling.
    wake_on_sleep: core::cell::Cell<Option<SysHandle>>,

    currently_running_task: core::cell::Cell<Option<TaskId>>,

    // Set only by the task currently being polled. The scheduler consumes it
    // at the safe point after releasing that task's borrow.
    io_turn_requested: core::cell::Cell<bool>,

    // See SpinSource.
    spin_sources: RefCell<Vec<SpinEntry>>,
}

impl LocalRuntimeInner {
    fn try_new() -> Result<Self> {
        let timeq = crate::timeq::TimeQ::try_new()?;
        let nonlocal_wakes = WakeQueue::try_new()?;
        let run_state = Arc::try_new(AtomicU32::new(RUN_STATE_POLLING))
            .map_err(|_| moto_rt::Error::OutOfMemory)?;
        Ok(Self {
            runqueue: Default::default(),
            sys_handle_futures: Default::default(),
            timeq: RefCell::new(timeq),
            incoming: Default::default(),
            tasks: Default::default(),
            next_task_id: RefCell::new(1),
            nonlocal_wakes,
            root: OnceCell::new(),
            run_state,
            wake_on_sleep: core::cell::Cell::new(None),
            currently_running_task: Default::default(),
            io_turn_requested: Default::default(),
            spin_sources: Default::default(),
        })
    }

    // About to park: nobody will watch the sources, so end every
    // registration. True if one turned ready.
    fn park_spin_sources(&self) -> bool {
        let entries = core::mem::take(&mut *self.spin_sources.borrow_mut());
        let mut woke = false;
        for entry in entries {
            if entry.source.end() {
                entry.waker.wake_by_ref();
                woke = true;
            }
        }
        woke
    }

    // A pass over the registered sources on every scheduling turn: a ready
    // one wakes its task, an expired one is dropped; both end the
    // registration.
    fn check_spin_sources(&self) {
        let mut sources = self.spin_sources.borrow_mut();
        if sources.is_empty() {
            return;
        }
        let now = tsc_now();
        sources.retain(|entry| {
            if entry.expires > now && !entry.source.ready() {
                return true;
            }
            if entry.source.end() {
                entry.waker.wake_by_ref();
            }
            false
        });
    }

    // Spin on the registered sources for a bounded time. True if a task
    // was woken or cross-thread work arrived, i.e. do not park yet.
    fn spin_for_sources(&self) -> bool {
        let mut entries = core::mem::take(&mut *self.spin_sources.borrow_mut());
        if entries.is_empty() {
            return false;
        }
        let now = tsc_now();
        let mut resume = false;
        entries.retain(|entry| {
            if entry.expires > now {
                return true;
            }
            if entry.source.end() {
                entry.waker.wake_by_ref();
                resume = true;
            }
            false
        });
        let deadline = now + ns_to_tsc(SPIN_BEFORE_PARK_NS);
        while !resume && !entries.is_empty() {
            if entries.iter().any(|entry| entry.source.ready()) {
                break;
            }
            self.merge_wakes();
            if !self.runqueue.borrow().is_empty() || !self.incoming.borrow().is_empty() {
                resume = true;
                break;
            }
            if tsc_now() >= deadline {
                break;
            }
            core::hint::spin_loop();
        }
        // A ready source ends its registration and wakes its task; the
        // rest stay registered (check_spin_sources watches them while tasks
        // run, park_spin_sources ends them before a park).
        entries.retain(|entry| {
            if !entry.source.ready() {
                return true;
            }
            entry.source.end();
            entry.waker.wake_by_ref();
            resume = true;
            false
        });
        let mut sources = self.spin_sources.borrow_mut();
        debug_assert!(sources.is_empty());
        *sources = entries;
        resume
    }

    fn new_header(&self, task_id: TaskId) -> Arc<MotoWaker> {
        Arc::new(MotoWaker::new(
            &self.nonlocal_wakes,
            &self.run_state,
            task_id,
        ))
    }

    fn next_task_id(&self) -> TaskId {
        let mut id_ref = self.next_task_id.borrow_mut();
        let result = *id_ref;
        (*id_ref) += 1;
        TaskId(result)
    }

    fn add_sys_handle_future(&self, future: Rc<RefCell<SysHandleFutureInner>>) {
        let sys_handle = future.borrow().handle;

        self.sys_handle_futures
            .borrow_mut()
            .entry(sys_handle)
            .or_default()
            .push_back(future);
    }

    fn try_current<'a>() -> Option<&'a Self> {
        // Safety: the context guard sets the pointer and clears it before the
        // runtime can move or drop.
        unsafe { get_local_runtime_context().as_ref() }
    }

    fn current<'a>() -> &'a Self {
        Self::try_current().expect("No runtime.")
    }

    fn merge_wakes(&self) {
        let mut runqueue = self.runqueue.borrow_mut();
        // Only this runtime thread consumes the shared queue. A popped node
        // is fully unlinked, and remains claimed until removed for polling.
        while let Some(waker) = unsafe { self.nonlocal_wakes.pop() } {
            unsafe { runqueue.push(waker) };
        }
    }

    fn merge_incoming(&self) {
        self.merge_wakes();

        let mut incoming = VecDeque::new();
        core::mem::swap(&mut incoming, &mut self.incoming.borrow_mut());

        let mut tasks = self.tasks.borrow_mut();
        for task in incoming {
            assert!(tasks.insert(task.header.task_id, task).is_none());
        }
    }

    fn next_runnable(&self) -> Option<Arc<MotoWaker>> {
        loop {
            let header = self.runqueue.borrow_mut().pop()?;
            match header.state.compare_exchange(
                WAKE_QUEUED,
                WAKE_IDLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(header),
                // The task completed while queued; drop the stale entry.
                Err(actual) => debug_assert_eq!(actual, WAKE_COMPLETE),
            }
        }
    }

    fn request_io_turn(&self) {
        let already_requested = self.io_turn_requested.replace(true);
        debug_assert!(!already_requested);
    }

    fn take_io_turn_request(&self) -> bool {
        self.io_turn_requested.replace(false)
    }

    /// Poll timers and registered system handles once without blocking.
    ///
    /// This runs only between task polls, when the scheduler holds no task-map
    /// borrow: timer wakers may run arbitrary code and newly spawned tasks must
    /// be free to enter the map.
    fn poll_io_nonblocking(&self) {
        // The peer of a registered source sends no wakes (SpinSource::begin),
        // so a busy executor must check the sources on every IO turn too.
        self.check_spin_sources();

        // A deferred peer wake normally rides the executor's sleep syscall.
        // An explicitly requested I/O turn does not sleep, so deliver it the
        // same way LocalRuntime::wait does when runnable work reappears.
        if let Some(handle) = self.wake_on_sleep.take() {
            let _ = moto_sys::SysCpu::wake(handle);
        }

        self.enqueue_expired_timers();
        self.merge_incoming();

        // System-handle wakes are latched in the kernel until SysCpu::wait
        // reports them. A deadline of now makes this a poll, never a sleep.
        self.wait(Some(Instant::now()), SysHandle::NONE);

        // The syscall and its wakers may have made more work ready.
        self.enqueue_expired_timers();
        self.merge_incoming();
    }

    fn wait(&self, timeo: Option<Instant>, wake_target: SysHandle) {
        let sys_waiters = self.sys_handle_futures.borrow();
        if sys_waiters.is_empty() {
            core::mem::drop(sys_waiters);
            let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, wake_target, timeo);
            return;
        }

        // Prepare wait handles.
        let mut wait_handles = Vec::with_capacity(sys_waiters.len());
        for sw in sys_waiters.keys() {
            wait_handles.push(*sw);
        }
        core::mem::drop(sys_waiters);

        let result = moto_sys::SysCpu::wait(
            wait_handles.as_mut_slice(),
            SysHandle::NONE,
            wake_target,
            timeo,
        );

        match result {
            Ok(()) | Err(moto_rt::E_TIMED_OUT) => {
                for handle in wait_handles {
                    if handle.is_none() {
                        break;
                    }
                    // The kernel queues wakers for signals arriving while
                    // this thread is awake, so a wait may report a handle
                    // no future waits on anymore. The signal stays latched
                    // on the object; there is nothing to deliver.
                    let Some(done_futures) = self.sys_handle_futures.borrow_mut().remove(&handle)
                    else {
                        continue;
                    };
                    let mut to_wake = Vec::new();
                    for future in done_futures {
                        let mut inner_future = future.borrow_mut();
                        if inner_future.dropped {
                            continue;
                        }
                        #[cfg(debug_assertions)]
                        {
                            if inner_future.debug_log {
                                log::debug!("{}: woke ok", inner_future.name());
                            }
                        }
                        inner_future.result = Some(Ok(()));
                        to_wake.extend(inner_future.waker.take());
                    }
                    for waker in to_wake {
                        waker.wake();
                    }
                }
            }
            Err(moto_rt::E_BAD_HANDLE) => {
                for handle in wait_handles {
                    if handle.is_none() {
                        break;
                    }

                    // See above: a stale queued waker may name a handle
                    // with no remaining waiters.
                    let Some(done_futures) = self.sys_handle_futures.borrow_mut().remove(&handle)
                    else {
                        continue;
                    };
                    let mut to_wake = Vec::new();
                    for future in done_futures {
                        let mut inner_future = future.borrow_mut();
                        if inner_future.dropped {
                            continue;
                        }
                        #[cfg(debug_assertions)]
                        {
                            if inner_future.debug_log {
                                log::debug!("{}: woke BAD_HANDLE", inner_future.name());
                            }
                        }
                        inner_future.result = Some(Err(moto_rt::Error::BadHandle));
                        to_wake.extend(inner_future.waker.take());
                    }
                    for waker in to_wake {
                        waker.wake();
                    }
                }
            }
            Err(moto_rt::E_STORAGE_FULL) => {
                panic!("SysCpu::wait(): too many handles: {}", wait_handles.len());
            }
            Err(err) => panic!("Unexpected error {err} from SysCpu::wait()."),
        }
    }

    fn enqueue_expired_timers(&self) {
        let now = Instant::now();
        // Wake with no borrows held: a foreign (combinator) waker runs
        // arbitrary code, which may add timers or wake tasks.
        loop {
            let Some(waker) = self.timeq.borrow_mut().pop_at(now) else {
                return;
            };
            waker.wake();
        }
    }
}

/// Local-thread async runtime, similar to futures::LocalPool and tokio::Runtime, but simpler.
pub struct LocalRuntime {
    // Need an indirection, to put a pointer to an "active" runtime into TLS,
    // while keeping the "outer" runtime movable.
    inner: Box<LocalRuntimeInner>,
}

pub struct LocalRuntimeContextGuard {
    context: usize,
}

impl Drop for LocalRuntimeContextGuard {
    fn drop(&mut self) {
        assert_eq!(self.context, get_local_runtime_context() as usize);
        // No source is watched outside block_on, even if the runtime is kept.
        // End it while callback wakers still have their runtime context.
        LocalRuntimeInner::current().park_spin_sources();
        clear_local_runtime_context();
    }
}

impl LocalRuntimeContextGuard {
    fn new(rt: &LocalRuntime) -> Self {
        assert!(
            get_local_runtime_context().is_null(),
            "Nesting runtime contexts are not allowed."
        );
        set_local_runtime_context(rt);
        Self {
            context: Box::as_ptr(&rt.inner) as usize,
        }
    }
}

impl Default for LocalRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalRuntime {
    pub fn new() -> Self {
        Self::try_new().expect("failed to allocate local runtime")
    }

    /// Construct a runtime without invoking the allocation-error handler.
    pub fn try_new() -> Result<Self> {
        let inner = LocalRuntimeInner::try_new()?;
        Ok(Self {
            inner: Box::try_new(inner).map_err(|_| moto_rt::Error::OutOfMemory)?,
        })
    }

    fn enter(&mut self) -> LocalRuntimeContextGuard {
        LocalRuntimeContextGuard::new(self)
    }

    pub(crate) fn add_timer(when: Instant, cx: &mut Context<'_>) -> crate::timeq::Timer {
        LocalRuntimeInner::current()
            .timeq
            .borrow_mut()
            .add_at(when, cx.local_waker().clone())
    }

    /// Defer a peer wake to the executor (design 3.3): delivered exactly
    /// once, folded as the wake target of the next sleep syscall, or issued
    /// explicitly if the executor resumes polling instead of sleeping.
    /// The handle is only ever a wake target, never a swap target.
    /// Must be called within a LocalRuntime context.
    pub fn set_wake_on_sleep(handle: SysHandle) {
        let prev = LocalRuntimeInner::current()
            .wake_on_sleep
            .replace(Some(handle));
        // Same-handle sets coalesce; a second distinct handle would lose
        // the first wake.
        debug_assert!(prev.is_none() || prev == Some(handle));
    }

    /// Spawn a new asynchronous task. Must be called within a LocalRuntime context.
    pub fn spawn<F: Future + 'static>(f: F) -> JoinHandle<F::Output> {
        let inner = LocalRuntimeInner::current();
        let (tx, rx) = oneshot::oneshot::<F::Output>();

        // Box `f` before capturing it in the wrapper block: the wrapper's
        // generator layout stores the captured future AND its awaitee copy
        // without overlapping them, so capturing `f` inline would make the
        // task allocation ~2x the future size. Big tasks fall out of the
        // global allocator's slabs (> 2048 bytes) into per-alloc SysMem
        // map/unmap - a broadcast TLB shootdown on every free.
        let f = Box::pin(f);
        let task = Task {
            fut: Box::pin(async move {
                let _ = tx.send(f.await);
            }),
            header: inner.new_header(inner.next_task_id()),

            #[cfg(debug_assertions)]
            debug_log: false,
        };

        task.header.wake(true);
        inner.incoming.borrow_mut().push_back(task);

        JoinHandle { rx }
    }

    // Wait until a wakeup or next timeout.
    fn wait() {
        let inner = LocalRuntimeInner::current();

        loop {
            inner.enqueue_expired_timers();
            inner.merge_incoming();
            if !inner.runqueue.borrow().is_empty() {
                // Resuming polling instead of sleeping: the deferred
                // wake cannot be folded, so issue it (exactly once).
                if let Some(handle) = inner.wake_on_sleep.take() {
                    let _ = moto_sys::SysCpu::wake(handle);
                }
                return; // Always entered and left in POLLING.
            }

            // Nothing runnable: poll the active sources before parking.
            if inner.spin_for_sources() {
                continue;
            }
            // A parked executor watches nothing: end the registrations
            // (one that turned ready meanwhile makes us resume).
            if inner.park_spin_sources() {
                continue;
            }

            // Commit to park, then recheck: a waker that pushed before
            // seeing COMMITTING skipped its wake syscall (see the SC
            // fence pairing in MotoWaker::wake). A wake that lands
            // after this check is sticky in the kernel and makes the
            // wait below return immediately.
            inner
                .run_state
                .store(RUN_STATE_COMMITTING, Ordering::Relaxed);
            core::sync::atomic::fence(Ordering::SeqCst);
            // A producer paused between its head exchange and link store
            // will notify after publication. Recheck consumable nodes, not
            // just the head, so that gap cannot make us spin indefinitely.
            inner.merge_wakes();
            if !inner.runqueue.borrow().is_empty() {
                inner.run_state.store(RUN_STATE_POLLING, Ordering::Relaxed);
                continue;
            }

            let timeo = inner.timeq.borrow_mut().next();
            let wake_target = inner.wake_on_sleep.take().unwrap_or(SysHandle::NONE);
            inner.run_state.store(RUN_STATE_PARKED, Ordering::Relaxed);
            inner.wait(timeo, wake_target);
            inner.run_state.store(RUN_STATE_POLLING, Ordering::Relaxed);
        }
    }

    /// Run a future to completion. Similar to futures::LocalPool::run_until().
    pub fn block_on<F: Future>(&mut self, f: F) -> F::Output {
        let mut f = core::pin::pin!(f);
        let _guard = self.enter();
        let runtime = LocalRuntimeInner::current();
        let root = runtime
            .root
            .get_or_init(|| runtime.new_header(TaskId::default_root()));
        let wakers = PollWakers::new(root);
        loop {
            let mut cx = wakers.context();

            runtime
                .currently_running_task
                .set(Some(TaskId::default_root()));
            let result = f.as_mut().poll(&mut cx);
            runtime.currently_running_task.set(None);

            let io_turn_requested = runtime.take_io_turn_request();
            if let Poll::Ready(output) = result {
                debug_assert!(!io_turn_requested);
                // The runtime exits instead of sleeping: still owes
                // the deferred wake, if one is pending.
                if let Some(handle) = runtime.wake_on_sleep.take() {
                    let _ = moto_sys::SysCpu::wake(handle);
                }
                return output;
            }

            if io_turn_requested {
                runtime.poll_io_nonblocking();
                // The hot root future runs behind the I/O and timer work
                // queued above, unless a wake during its poll already
                // queued it ahead of them.
                root.wake(true);
            }

            loop {
                if Self::poll_loop().is_ready() {
                    break;
                } else {
                    Self::wait();
                }
            }
        }
    }

    // Poll the runnable queue until there's nothing to do.
    // It is safe to sleep when poll_pool() returns.
    // Kinda like futures::LocalPool::poll_pool(), but much simpler.
    fn poll_loop() -> Poll<()> {
        loop {
            let inner = LocalRuntimeInner::current();

            // Spin-source callbacks run user code that may spawn, so merge
            // after them: every queued task is then in the map when dequeued.
            inner.check_spin_sources();
            inner.merge_incoming();

            let Some(header) = inner.next_runnable() else {
                return Poll::Pending;
            };
            let task_id = header.task_id;
            if task_id.is_root() {
                return Poll::Ready(());
            }

            let mut tasks_ref = inner.tasks.borrow_mut();
            let Some(task) = tasks_ref.get_mut(&task_id) else {
                // spawn() queues the header and the task together, the merge
                // above precedes the dequeue, and a completed task retires
                // its header before it is removed.
                unreachable!("runnable task {} is not in the task map", task_id.0);
            };
            let wakers = PollWakers::new(&header);
            let mut inner_cx = wakers.context();
            #[cfg(debug_assertions)]
            {
                if task.debug_log {
                    log::debug!("Running task {}", task_id.0);
                }
            }

            // This may call spawn, or add a timer, which borrows inner.
            inner.currently_running_task.set(Some(task_id));
            let poll_result = {
                let pinned = task.fut.as_mut();
                // --------- RUN A TASK ------------------
                pinned.poll(&mut inner_cx)
                // --------- DONE RUNNING THE TASK -------
            };
            inner.currently_running_task.set(None);
            #[cfg(debug_assertions)]
            {
                if task.debug_log {
                    log::debug!("task {} stopped running", task_id.0);
                }
            }

            let io_turn_requested = inner.take_io_turn_request();
            if poll_result.is_pending() {
                // Timer wakers may run arbitrary code and merge_incoming()
                // borrows the task map, so release this poll's borrow first.
                drop(tasks_ref);
                if io_turn_requested {
                    inner.poll_io_nonblocking();
                    // This hot task runs behind the ready work found above,
                    // unless a wake during its poll already queued it.
                    header.wake(true);
                }
                continue;
            }
            debug_assert!(!io_turn_requested);

            // The task has completed: its oneshot sender already woke the
            // JoinHandle, and dropping the task retires the header.
            let task = tasks_ref.remove(&task_id).unwrap();
            drop(tasks_ref);
            drop(task);
        }
    }
}

pub struct JoinHandle<T> {
    rx: oneshot::Receiver<T>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.rx)
            .poll(cx)
            .map(|result| result.expect("task dropped before completion"))
    }
}

/// Same as std::IntoFuture. Had to copy it here so that
/// it can be implemented for SysHandle.
pub trait AsFuture {
    /// The output that the future will produce on completion.
    type Output;

    /// Which kind of future are we turning this into?
    type AsFuture: Future<Output = Self::Output>;

    /// Creates a future from a value.
    fn as_future(&self) -> Self::AsFuture;
}

struct SysHandleFutureInner {
    handle: SysHandle,
    // The latest poll's waker, taken when the handle completes. None before
    // the first poll: a completion then waits to be polled.
    waker: Option<LocalWaker>,
    result: Option<Result<()>>,
    dropped: bool,

    #[cfg(debug_assertions)]
    debug_ready_done: bool,

    #[cfg(debug_assertions)]
    debug_log: bool,
}

#[cfg(debug_assertions)]
impl SysHandleFutureInner {
    fn name(&self) -> alloc::string::String {
        alloc::format!(
            "\n\tSysHandleFuture: [handle: 0x{:x}]",
            self.handle.as_u64()
        )
    }
}

// #[derive(Clone)]
pub struct SysHandleFuture {
    inner: Rc<RefCell<SysHandleFutureInner>>,
}

impl Drop for SysHandleFuture {
    fn drop(&mut self) {
        let mut inner = self.inner.borrow_mut();
        #[cfg(debug_assertions)]
        {
            if inner.debug_log && !inner.debug_ready_done {
                log::debug!(
                    "{}: dropping pending: woke: {}",
                    inner.name(),
                    inner.result.is_some()
                );
            } else if inner.debug_log {
                log::debug!("{}: dropping done", inner.name());
            }
        }
        inner.dropped = true;
        // The registration lingers until the kernel reports the handle; do
        // not keep the task header alive with it.
        inner.waker = None;
    }
}

impl AsFuture for SysHandle {
    type Output = Result<()>;

    type AsFuture = SysHandleFuture;

    fn as_future(&self) -> Self::AsFuture {
        let inner = Rc::new(RefCell::new(SysHandleFutureInner {
            handle: *self,
            waker: None,
            result: None,
            dropped: false,

            #[cfg(debug_assertions)]
            debug_ready_done: false,

            #[cfg(debug_assertions)]
            debug_log: false,
        }));

        LocalRuntimeInner::current().add_sys_handle_future(inner.clone());
        SysHandleFuture { inner }
    }
}

impl SysHandleFuture {
    #[cfg(debug_assertions)]
    pub fn set_debug_log(&self, debug_log: bool) {
        self.inner.borrow_mut().debug_log = debug_log;
        log::debug!("debugging future {}", self.inner.borrow().name());
    }

    pub fn do_poll(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        #[cfg(debug_assertions)]
        if self.inner.borrow_mut().debug_ready_done {
            panic!("SysHandleFuture polled after Poll::Ready() was returned.");
        }

        let mut inner = self.inner.borrow_mut();

        if let Some(result) = inner.result.take() {
            #[cfg(debug_assertions)]
            {
                inner.debug_ready_done = true;
                if inner.debug_log {
                    log::debug!("{}: done", inner.name());
                }
            }

            return Poll::Ready(result);
        }

        // Re-register only if the waker changed (e.g. a nested combinator).
        let waker = &mut inner.waker;
        match waker {
            Some(waker) => waker.clone_from(cx.local_waker()),
            None => *waker = Some(cx.local_waker().clone()),
        }
        #[cfg(debug_assertions)]
        if inner.debug_log {
            log::debug!("{}: pending", inner.name());
        }
        Poll::Pending
    }
}

impl Future for SysHandleFuture {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.do_poll(cx)
    }
}

/// Yields execution back to the `LocalRuntime`.
///
/// This function returns a future that completes after yielding once,
/// allowing other tasks multiplexed on the current thread to progress.
pub async fn yield_now() {
    struct YieldNow {
        yielded: bool,
    }

    impl Future for YieldNow {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yielded {
                return Poll::Ready(());
            }

            self.yielded = true;

            // Wake the current task immediately.
            // This ensures the `LocalRuntime` puts the task back into its run queue.
            cx.local_waker().wake_by_ref();

            Poll::Pending
        }
    }

    YieldNow { yielded: false }.await
}

/// Yields execution after asking the runtime to poll I/O and timers once.
///
/// Unlike [yield_now], this makes kernel-latched system-handle wakes and
/// expired timers runnable even when the caller keeps the run queue non-empty.
/// The poll never sleeps, and the caller is requeued behind the work it
/// discovers, unless another wake queued it during its poll.
///
/// This is more expensive than [yield_now]; use it as the bounded fairness
/// edge in a hot loop, not on every iteration.
pub async fn yield_to_io() {
    struct YieldToIo {
        yielded: bool,
    }

    impl Future for YieldToIo {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yielded {
                return Poll::Ready(());
            }

            self.yielded = true;
            LocalRuntimeInner::current().request_io_turn();
            Poll::Pending
        }
    }

    YieldToIo { yielded: false }.await
}

#[cfg(debug_assertions)]
pub fn task_id(cx: &mut Context<'_>) -> u64 {
    let waker = cx.waker();
    let local_waker = cx.local_waker();
    // A combinator's context carries its own wakers, not the runtime's.
    assert!(core::ptr::eq(waker.vtable(), &RAW_WAKER_VTABLE));
    assert!(core::ptr::eq(local_waker.vtable(), &RAW_LOCAL_WAKER_VTABLE));
    assert!(core::ptr::eq(waker.data(), local_waker.data()));
    // Safety: the vtable check proves `data` is a header this context keeps alive.
    unsafe { &*waker.data().cast::<MotoWaker>() }.task_id.0
}

#[cfg(debug_assertions)]
pub fn current_task_id() -> u64 {
    LocalRuntimeInner::current()
        .currently_running_task
        .get()
        .as_ref()
        .unwrap()
        .0
}

#[cfg(debug_assertions)]
pub fn debug_current_task(debug: bool) {
    let current_task_id = TaskId(current_task_id());

    let runtime = LocalRuntimeInner::current();

    // TODO: refactor runtime so that runtime.tasks() is not borrowed
    // and the unsafe {} below can be removed.
    //
    // SAFETY: runtime.tasks() is borrowed at the moment. But it is
    // obviously safe to flip a bookean flag.
    unsafe {
        runtime
            .tasks
            .as_ptr()
            .as_mut_unchecked()
            .get_mut(&current_task_id)
            .unwrap()
            .debug_log = debug;
    }
}
