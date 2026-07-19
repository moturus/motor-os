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
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::Context;
use core::task::Poll;
use core::task::RawWaker;
use core::task::RawWakerVTable;
use core::task::Waker;
use futures::channel::oneshot;
use futures::task::LocalFutureObj;
use moto_rt::Result;
use moto_rt::time::Instant;
use moto_sys::SysHandle;

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

// Executor run-state, for wake elision (design 3.4): cross-thread wakes
// always enqueue, but pay the wake syscall only when the runtime is
// parked or committing to park.
const RUN_STATE_POLLING: u32 = 0;
const RUN_STATE_COMMITTING: u32 = 1;
const RUN_STATE_PARKED: u32 = 2;

// Wakes issued (syscall) vs elided (runtime awake), process-wide.
static WAKES_ISSUED: AtomicU64 = AtomicU64::new(0);
static WAKES_ELIDED: AtomicU64 = AtomicU64::new(0);

pub fn wake_counters() -> (u64, u64) {
    (
        WAKES_ISSUED.load(Ordering::Relaxed),
        WAKES_ELIDED.load(Ordering::Relaxed),
    )
}

// This is the waker to use cross-threads.
// The local waker is just a pointer to TaskId.
struct MotoWaker {
    // The queue to add task_id upon wake.
    runqueue: Arc<crossbeam::queue::SegQueue<TaskId>>,
    run_state: Arc<AtomicU32>,
    task_id: TaskId,
    wake_handle: SysHandle, // The handle to call wake() on.
}

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    unsafe {
        Arc::increment_strong_count(data as usize as *const MotoWaker);
    }
    RawWaker::new(data, &RAW_WAKER_VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    unsafe {
        waker_wake_by_ref(data);
        waker_drop(data);
    }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    let waker = unsafe {
        (data as usize as *const MotoWaker)
            .as_ref()
            .unwrap_unchecked()
    };

    waker.runqueue.push(waker.task_id);
    // SC fence pairs with the one in LocalRuntime::wait(): either our
    // push is visible to the executor's recheck-after-commit, or its
    // COMMITTING store is visible to the load below and we wake.
    core::sync::atomic::fence(Ordering::SeqCst);
    if waker.run_state.load(Ordering::Relaxed) == RUN_STATE_POLLING {
        WAKES_ELIDED.fetch_add(1, Ordering::Relaxed);
    } else {
        WAKES_ISSUED.fetch_add(1, Ordering::Relaxed);
        let _ = moto_sys::SysCpu::wake(waker.wake_handle);
    }
}

unsafe fn waker_drop(data: *const ()) {
    unsafe {
        Arc::decrement_strong_count(data as usize as *const MotoWaker);
    }
}

const RAW_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

unsafe fn local_waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &RAW_LOCAL_WAKER_VTABLE)
}

unsafe fn local_waker_wake(data: *const ()) {
    let task_id = TaskId(data as usize as u64);
    LocalRuntimeInner::current()
        .runqueue
        .borrow_mut()
        .push_back(task_id);
}

unsafe fn local_waker_wake_by_ref(data: *const ()) {
    unsafe { local_waker_wake(data) }
}

unsafe fn local_waker_drop(_data: *const ()) {}

const RAW_LOCAL_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    local_waker_clone,
    local_waker_wake,
    local_waker_wake_by_ref,
    local_waker_drop,
);

fn new_local_waker(task_id: TaskId) -> core::task::LocalWaker {
    unsafe {
        core::task::LocalWaker::from_raw(core::task::RawWaker::new(
            task_id.0 as usize as *const (),
            &RAW_LOCAL_WAKER_VTABLE,
        ))
    }
}

struct Task {
    id: TaskId,
    fut: LocalFutureObj<'static, ()>,
    join_handle_waker: alloc::rc::Weak<RefCell<Option<Waker>>>,

    #[cfg(debug_assertions)]
    debug_log: bool,
}

// When a task is polled, it should be pinned, therefore borrowed.
// So its container gets borrowed. So LocalRuntimeInner gets borrowed.
//
// While LocalRuntimeInner::tasks::<task> are pinned/borrowed,
// the running code may add timers, spawn other tasks, etc., so
// we need interior mutability at runtime (=> RefCell).
struct LocalRuntimeInner {
    // The main (local) runqueue. Runnable tasks live there.
    runqueue: RefCell<VecDeque<TaskId>>,

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

    // Task IDs of wakes coming from wakers (!= LocalWaker).
    nonlocal_wakes: Arc<crossbeam::queue::SegQueue<TaskId>>,

    run_state: Arc<AtomicU32>,

    // Deferred peer wake (design 3.3): delivered exactly once, folded
    // into the next sleep syscall or issued if we resume polling.
    wake_on_sleep: core::cell::Cell<Option<SysHandle>>,

    currently_running_task: core::cell::Cell<Option<TaskId>>,
}

impl LocalRuntimeInner {
    fn new() -> Self {
        Self {
            runqueue: Default::default(),
            sys_handle_futures: Default::default(),
            timeq: Default::default(),
            incoming: Default::default(),
            tasks: Default::default(),
            next_task_id: RefCell::new(1),
            nonlocal_wakes: Default::default(),
            run_state: Arc::new(AtomicU32::new(RUN_STATE_POLLING)),
            wake_on_sleep: core::cell::Cell::new(None),
            currently_running_task: Default::default(),
        }
    }

    fn new_waker(&self, task_id: TaskId) -> Waker {
        let moto_waker = Arc::new(MotoWaker {
            runqueue: self.nonlocal_wakes.clone(),
            run_state: self.run_state.clone(),
            task_id,
            wake_handle: moto_sys::current_thread(),
        });

        let waker_data = Arc::into_raw(moto_waker) as usize as *const ();

        // Safety: safe by construction.
        unsafe { Waker::from_raw(RawWaker::new(waker_data, &RAW_WAKER_VTABLE)) }
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

    fn current<'a>() -> &'a Self {
        if let Some(this) = unsafe { get_local_runtime_context().as_ref() } {
            this
        } else {
            panic!("No runtime.");
        }
    }

    fn merge_incoming(&self) {
        let mut runqueue = self.runqueue.borrow_mut();
        while let Some(task_id) = self.nonlocal_wakes.pop() {
            runqueue.push_back(task_id);
        }

        let mut incoming = VecDeque::new();
        core::mem::swap(&mut incoming, &mut self.incoming.borrow_mut());

        let mut tasks = self.tasks.borrow_mut();
        for task in incoming {
            assert!(tasks.insert(task.id, task).is_none());
        }
    }

    fn next_runnable(&self) -> Option<TaskId> {
        self.runqueue.borrow_mut().pop_front()
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
                    let done_futures = self
                        .sys_handle_futures
                        .borrow_mut()
                        .remove(&handle)
                        .unwrap();
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
                        to_wake.push(inner_future.waker.clone());
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

                    let done_futures = self
                        .sys_handle_futures
                        .borrow_mut()
                        .remove(&handle)
                        .unwrap();
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
                        to_wake.push(inner_future.waker.clone());
                    }
                    for waker in to_wake {
                        waker.wake();
                    }
                }
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
        Self {
            inner: Box::new(LocalRuntimeInner::new()),
        }
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
        let prev = LocalRuntimeInner::current().wake_on_sleep.replace(Some(handle));
        // Same-handle sets coalesce; a second distinct handle would lose
        // the first wake.
        debug_assert!(prev.is_none() || prev == Some(handle));
    }

    /// Spawn a new asynchronous task. Must be called within a LocalRuntime context.
    pub fn spawn<F: Future + 'static>(f: F) -> JoinHandle<F::Output> {
        use futures::channel::oneshot;

        let inner = LocalRuntimeInner::current();
        let (tx, rx) = oneshot::channel::<F::Output>();

        let waker = Rc::new(RefCell::new(None));
        let task_id = inner.next_task_id();

        // Box `f` before capturing it in the wrapper block: the wrapper's
        // generator layout stores the captured future AND its awaitee copy
        // without overlapping them, so capturing `f` inline would make the
        // task allocation ~2x the future size. Big tasks fall out of the
        // global allocator's slabs (> 2048 bytes) into per-alloc SysMem
        // map/unmap - a broadcast TLB shootdown on every free.
        let f = Box::pin(f);
        let task = Task {
            id: task_id,
            fut: Box::pin(async move {
                let _ = tx.send(f.await);
            })
            .into(),
            join_handle_waker: Rc::downgrade(&waker),

            #[cfg(debug_assertions)]
            debug_log: false,
        };

        inner.runqueue.borrow_mut().push_back(task_id);
        inner.incoming.borrow_mut().push_back(task);

        JoinHandle { rx, waker }
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

            // Commit to park, then recheck: a waker that pushed before
            // seeing COMMITTING skipped its wake syscall (see the SC
            // fence pairing in waker_wake_by_ref). A wake that lands
            // after this check is sticky in the kernel and makes the
            // wait below return immediately.
            inner
                .run_state
                .store(RUN_STATE_COMMITTING, Ordering::Relaxed);
            core::sync::atomic::fence(Ordering::SeqCst);
            if !inner.nonlocal_wakes.is_empty() {
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
        futures::pin_mut!(f);
        let _guard = self.enter();
        loop {
            let runtime = LocalRuntimeInner::current();
            let waker = runtime.new_waker(TaskId::default_root());
            let local_waker = new_local_waker(TaskId::default_root());
            let mut cx = core::task::ContextBuilder::from_waker(&waker)
                .local_waker(&local_waker)
                .build();

            {
                runtime
                    .currently_running_task
                    .set(Some(TaskId::default_root()));
                let result = f.as_mut().poll(&mut cx);
                runtime.currently_running_task.set(None);

                if let Poll::Ready(output) = result {
                    // The runtime exits instead of sleeping: still owes
                    // the deferred wake, if one is pending.
                    if let Some(handle) = runtime.wake_on_sleep.take() {
                        let _ = moto_sys::SysCpu::wake(handle);
                    }
                    return output;
                }
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

            inner.merge_incoming();
            let next_runnable = inner.next_runnable();

            let Some(next_runnable) = next_runnable else {
                return Poll::Pending;
            };

            if next_runnable.is_root() {
                return Poll::Ready(());
            }

            let task_waker = inner.new_waker(next_runnable);
            let local_waker = new_local_waker(next_runnable);
            let mut inner_cx = core::task::ContextBuilder::from_waker(&task_waker)
                .local_waker(&local_waker)
                .build();

            let mut tasks_ref = inner.tasks.borrow_mut();
            let Some(task) = tasks_ref.get_mut(&next_runnable) else {
                // This could happen if the local waker gets cloned and woken
                // multiple times; this will enqueue it multiple times into
                // the runnable queue.
                log::trace!("unknown task: {}", next_runnable.0);
                continue;
            };
            let current_task_id = task.id;
            #[cfg(debug_assertions)]
            {
                if task.debug_log {
                    log::debug!("Running task {}", current_task_id.0);
                }
            }

            // This may call spawn, or add a timer, which borrows inner.
            inner.currently_running_task.set(Some(current_task_id));
            let poll_result = {
                let pinned = Pin::new(&mut task.fut);
                // --------- RUN A TASK ------------------
                pinned.poll(&mut inner_cx)
                // --------- DONE RUNNING THE TASK -------
            };
            inner.currently_running_task.set(None);
            #[cfg(debug_assertions)]
            {
                if task.debug_log {
                    log::debug!("task {} stopped running", current_task_id.0);
                }
            }

            if poll_result.is_pending() {
                inner.currently_running_task.set(None);
                continue;
            }

            // The task has completed.
            if let Some(waker_cell) = task.join_handle_waker.upgrade()
                && let Some(waker) = waker_cell.borrow_mut().take()
            {
                waker.wake();
            }

            let task = tasks_ref.remove(&next_runnable).unwrap();
            assert_eq!(next_runnable, task.id);
        }
    }
}

pub struct JoinHandle<T> {
    rx: oneshot::Receiver<T>,
    waker: Rc<RefCell<Option<Waker>>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rx.try_recv() {
            Ok(Some(res)) => Poll::Ready(res),
            Ok(None) => {
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(err) => panic!("{err:?}"),
        }
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
    // Woken on completion. Set at creation to the owning task's waker,
    // refreshed on every poll so nested combinators wake correctly.
    waker: core::task::LocalWaker,
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
        alloc::format!("\n\tSysHandleFuture: [handle: 0x{:x}]", self.handle.as_u64())
    }
}

// #[derive(Clone)]
pub struct SysHandleFuture {
    inner: Rc<RefCell<SysHandleFutureInner>>,
}

impl Drop for SysHandleFuture {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let inner = self.inner.borrow();
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
        self.inner.borrow_mut().dropped = true;
    }
}

impl AsFuture for SysHandle {
    type Output = Result<()>;

    type AsFuture = SysHandleFuture;

    fn as_future(&self) -> Self::AsFuture {
        let inner = Rc::new(RefCell::new(SysHandleFutureInner {
            handle: *self,
            waker: new_local_waker(
                LocalRuntimeInner::current()
                    .currently_running_task
                    .get()
                    .unwrap(),
            ),
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

        inner.waker = cx.local_waker().clone();
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

#[cfg(debug_assertions)]
pub fn task_id(cx: &mut Context<'_>) -> u64 {
    let waker = unsafe {
        (cx.waker().data() as usize as *const MotoWaker)
            .as_ref()
            .unwrap_unchecked()
    };
    let task_id_global = waker.task_id.0;
    let task_id_local = cx.local_waker().data() as usize as u64;
    assert_eq!(task_id_global, task_id_local);

    task_id_local
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
