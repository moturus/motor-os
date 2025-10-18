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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use core::task::Context;
use core::task::Poll;
use core::task::RawWaker;
use core::task::RawWakerVTable;
use core::task::Waker;
use futures::channel::oneshot;
use futures::task::LocalFutureObj;
use moto_rt::spinlock::SpinLock;
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
    if let Err(prev) = RUNTIME_TLS_KEY.compare_exchange(key, 0, Ordering::AcqRel, Ordering::Relaxed)
    {
        // Safety: we just created the key, so it is safe.
        unsafe { moto_rt::tls::destroy(key) };
        prev
    } else {
        key
    }
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

struct MotoWaker {
    runqueue: alloc::sync::Weak<SpinLock<VecDeque<TaskId>>>,
    task_id: TaskId,
    wake_handle: SysHandle,
}

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    unsafe {
        Arc::increment_strong_count(data as usize as *const MotoWaker);
    }
    RawWaker::new(data, &RAW_WAKER_VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    let waker = unsafe { (data as usize as *const MotoWaker).as_ref().unwrap() };

    if let Some(runqueue) = waker.runqueue.upgrade() {
        runqueue.lock().push_back(waker.task_id);
        if let Err(err) = moto_sys::SysCpu::wake(waker.wake_handle) {
            log::warn!("Error {err} while waking {}.", waker.wake_handle.as_u64());
        }
    }
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    unsafe { waker_wake(data) }
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

    // Tasks waiting on specific sys handles.
    sys_waiters: RefCell<BTreeMap<SysHandle, TaskId>>,

    // Timers. Can be added to at runtime.
    timeq: RefCell<crate::timeq::TimeQ<TaskId>>,

    // New tasks (from spawn()). As they are added "at runtime",
    // when Self::tasks is borrowed, we need to temporarily
    // store them into Self::incoming for later processing.
    incoming: RefCell<VecDeque<Task>>,

    // All tasks present in this runtime (at most one can be running).
    tasks: RefCell<BTreeMap<TaskId, Task>>,
    next_task_id: RefCell<u64>,

    // Wakes from wait_handles are stored here.
    sys_wakes: RefCell<BTreeMap<SysHandle, moto_rt::ErrorCode>>,

    // Task IDs of wakes coming from wakers (!= LocalWaker).
    nonlocal_wakes: Arc<SpinLock<VecDeque<TaskId>>>,
}

impl LocalRuntimeInner {
    fn new() -> Self {
        Self {
            runqueue: Default::default(),
            sys_waiters: Default::default(),
            timeq: Default::default(),
            incoming: Default::default(),
            tasks: Default::default(),
            next_task_id: RefCell::new(1),
            sys_wakes: Default::default(),
            nonlocal_wakes: Default::default(),
        }
    }

    fn new_waker(&self, task_id: TaskId) -> Waker {
        let moto_waker = Arc::new(MotoWaker {
            runqueue: Arc::downgrade(&self.nonlocal_wakes),
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

    fn current<'a>() -> &'a Self {
        if let Some(this) = unsafe { get_local_runtime_context().as_ref() } {
            this
        } else {
            panic!("No runtime.");
        }
    }

    fn add_sys_waiter(&self, handle: SysHandle, task_id: TaskId) {
        self.sys_waiters.borrow_mut().insert(handle, task_id);
    }

    fn merge_incoming(&self) {
        let mut incoming = VecDeque::new();
        core::mem::swap(&mut incoming, &mut *self.nonlocal_wakes.lock());

        let mut runqueue = self.runqueue.borrow_mut();
        for task_id in incoming {
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

    fn wait(&self, timeo: Option<Instant>) {
        self.sys_wakes.borrow_mut().clear(); // Cancelled futures can leave residue here.

        let sys_waiters = self.sys_waiters.borrow();
        if sys_waiters.is_empty() {
            core::mem::drop(sys_waiters);
            log::info!("empty wait");
            let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, timeo);
            return;
        }

        // Prepare wait handles.
        let mut wait_handles = Vec::with_capacity(sys_waiters.len());
        for sw in sys_waiters.keys() {
            wait_handles.push(*sw);
        }
        core::mem::drop(sys_waiters);

        log::info!("full wait");
        let result = moto_sys::SysCpu::wait(
            wait_handles.as_mut_slice(),
            SysHandle::NONE,
            SysHandle::NONE,
            timeo,
        );

        match result {
            Ok(()) => {
                for handle in wait_handles {
                    if handle.is_none() {
                        break;
                    }
                    let task_id = self.sys_waiters.borrow_mut().remove(&handle).unwrap();
                    self.runqueue.borrow_mut().push_back(task_id);
                    self.sys_wakes.borrow_mut().insert(handle, moto_rt::E_OK);
                }
            }
            Err(moto_rt::E_TIMED_OUT) => {}
            Err(moto_rt::E_BAD_HANDLE) => {
                for handle in wait_handles {
                    if handle.is_none() {
                        break;
                    }

                    let task_id = self.sys_waiters.borrow_mut().remove(&handle).unwrap();
                    self.runqueue.borrow_mut().push_back(task_id);
                    self.sys_wakes
                        .borrow_mut()
                        .insert(handle, moto_rt::E_BAD_HANDLE);
                }
            }
            Err(err) => panic!("Unexpected error {err} from SysCpu::wait()."),
        }
    }

    fn enqueue_expired_timers(&self) {
        let now = Instant::now();
        let mut timeq = self.timeq.borrow_mut();
        let mut runqueue = self.runqueue.borrow_mut();

        while let Some(task_id) = timeq.pop_at(now) {
            runqueue.push_back(task_id)
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

    pub(crate) fn add_timer(when: Instant, cx: &mut Context<'_>) {
        let task_id = TaskId(cx.local_waker().data() as usize as u64);

        LocalRuntimeInner::current()
            .timeq
            .borrow_mut()
            .add_at(when, task_id);
    }

    /// Spawn a new asynchronous task. Must be called within a LocalRuntime context.
    pub fn spawn<F: Future + 'static>(f: F) -> JoinHandle<F::Output> {
        use futures::channel::oneshot;

        let inner = LocalRuntimeInner::current();
        let (tx, rx) = oneshot::channel::<F::Output>();

        let waker = alloc::rc::Rc::new(RefCell::new(None));
        let task_id = inner.next_task_id();

        let task = Task {
            id: task_id,
            fut: Box::pin(async move {
                let _ = tx.send(f.await);
            })
            .into(),
            join_handle_waker: alloc::rc::Rc::downgrade(&waker),
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
            if !inner.runqueue.borrow().is_empty() {
                return;
            }

            let timeo = inner.timeq.borrow().next();
            inner.wait(timeo);
        }
    }

    /// Run a future to completion. Similar to futures::LocalPool::run_until().
    pub fn block_on<F: Future>(&mut self, f: F) -> F::Output {
        futures::pin_mut!(f);
        let _guard = self.enter();
        loop {
            let waker = LocalRuntimeInner::current().new_waker(TaskId::default_root());
            let local_waker = new_local_waker(TaskId::default_root());
            let mut cx = core::task::ContextBuilder::from_waker(&waker)
                .local_waker(&local_waker)
                .build();

            {
                let result = f.as_mut().poll(&mut cx);
                if let Poll::Ready(output) = result {
                    return output;
                }
            }

            loop {
                if Self::poll_pool().is_ready() {
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
    fn poll_pool() -> Poll<()> {
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
            let task = tasks_ref.get_mut(&next_runnable).unwrap();
            let pinned = Pin::new(&mut task.fut);

            // This may call spawn, or add a timer, which borrows inner.
            if pinned.poll(&mut inner_cx).is_pending() {
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
    waker: alloc::rc::Rc<RefCell<Option<Waker>>>,
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

pub struct SysHandleFuture {
    handle: SysHandle,
    task_id: Option<TaskId>,
}

impl AsFuture for SysHandle {
    type Output = Result<(), moto_rt::ErrorCode>;

    type AsFuture = SysHandleFuture;

    fn as_future(&self) -> Self::AsFuture {
        SysHandleFuture {
            handle: *self,
            task_id: None,
        }
    }
}

impl Future for SysHandleFuture {
    type Output = Result<(), moto_rt::ErrorCode>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = LocalRuntimeInner::current();

        let Some(task_id) = self.task_id.as_ref() else {
            let task_id = TaskId(cx.local_waker().data() as usize as u64);
            self.task_id = Some(task_id);
            inner.add_sys_waiter(self.handle, task_id);
            return Poll::Pending;
        };

        if let Some(wait_result) = inner.sys_wakes.borrow_mut().remove(&self.handle) {
            Poll::Ready(if wait_result == moto_rt::E_OK {
                Ok(())
            } else {
                Err(wait_result)
            })
        } else {
            inner.add_sys_waiter(self.handle, *task_id);
            Poll::Pending
        }
    }
}
