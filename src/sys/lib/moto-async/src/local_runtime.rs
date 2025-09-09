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
use alloc::collections::btree_set::BTreeSet;
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
struct TaskId(u64);

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
        log::trace!("Waking {:?}", waker.task_id);
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

struct Task {
    id: TaskId,
    fut: LocalFutureObj<'static, ()>,
    event_stream_handle: SysHandle,
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

    // Tasks attached to wait handles.
    attached_tasks: RefCell<BTreeMap<SysHandle, TaskId>>,

    // Denormalized wait handles.
    wait_handles: RefCell<Vec<SysHandle>>,

    // Timers. Can be added to at runtime.
    timeq: RefCell<crate::timeq::TimeQ<TaskId>>,

    // New tasks (from spawn()). As they are added "at runtime",
    // when Self::tasks is borrowed, we need to temporarily
    // store them into Self::incoming for later processing.
    incoming: RefCell<VecDeque<Task>>,

    // All tasks present in this runtime (at most one running).
    tasks: RefCell<BTreeMap<TaskId, Task>>,
    next_task_id: RefCell<u64>,

    // Wakes from wait_handles are stored here.
    sys_events: RefCell<BTreeSet<TaskId>>,

    // Task IDs of wakes coming from other threads.
    nonlocal_wakes: Arc<SpinLock<VecDeque<TaskId>>>,
}

impl LocalRuntimeInner {
    fn new() -> Self {
        Self {
            runqueue: Default::default(),
            attached_tasks: Default::default(),
            wait_handles: Default::default(),
            timeq: Default::default(),
            incoming: Default::default(),
            tasks: Default::default(),
            next_task_id: RefCell::new(1),
            sys_events: Default::default(),
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
            let task_wait_handle = task.event_stream_handle;
            if !task_wait_handle.is_none() {
                assert!(
                    self.attached_tasks
                        .borrow_mut()
                        .insert(task_wait_handle, task.id)
                        .is_none()
                );
                self.wait_handles.borrow_mut().push(task_wait_handle);
            }
            assert!(tasks.insert(task.id, task).is_none());
        }
    }

    fn next_runnable(&self) -> Option<TaskId> {
        self.runqueue.borrow_mut().pop_front()
    }

    fn wait(&self, timeo: Option<Instant>) {
        let mut wait_handles = self.wait_handles.borrow().clone();
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
                    let task_id = *self.attached_tasks.borrow().get(&handle).unwrap();
                    self.runqueue.borrow_mut().push_back(task_id);
                    self.sys_events.borrow_mut().insert(task_id);
                }
            }
            Err(moto_rt::E_TIMED_OUT) => {}
            Err(moto_rt::E_BAD_HANDLE) => {
                for handle in wait_handles {
                    if handle.is_none() {
                        break;
                    }
                    let task_id = self.attached_tasks.borrow_mut().remove(&handle).unwrap();
                    let task = self.tasks.borrow_mut().remove(&task_id).unwrap();
                    assert_eq!(task.id, task_id);
                    assert_eq!(handle, task.event_stream_handle);
                    log::debug!("Task {task_id:?} with {handle:?} is gone.");
                }

                self.rebuild_wait_handles();
            }
            Err(err) => panic!("Unexpected error {err} from SysCpu::wait()."),
        }
    }

    fn enqueue_expired_timers(&self) {
        let now = Instant::now();
        let mut timeq = self.timeq.borrow_mut();
        let mut runqueue = self.runqueue.borrow_mut();

        while let Some(task_id) = timeq.pop_at(now) {
            log::trace!("Timer expired for {task_id:?}.");
            runqueue.push_back(task_id)
        }
    }

    fn rebuild_wait_handles(&self) {
        let attached_tasks = self.attached_tasks.borrow();
        let mut wait_handles = self.wait_handles.borrow_mut();
        wait_handles.clear();
        for h in attached_tasks.keys() {
            wait_handles.push(*h);
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
        log::trace!("add_timer");

        /*
                let local_waker = cx.local_waker().data() as usize as *const MotoWaker;

                log::error!("todo: validate cx/local_waker by comparing pointers");
                let task_id = unsafe { local_waker.as_ref().unwrap().task_id };
        */
        let waker = cx.waker().data() as usize as *const MotoWaker;

        log::error!("todo: validate cx/local_waker by comparing pointers");
        let task_id = unsafe { waker.as_ref().unwrap().task_id };
        log::trace!("adding timer to task {task_id:?}");

        LocalRuntimeInner::current()
            .timeq
            .borrow_mut()
            .add_at(when, task_id);
    }

    fn next_task_id_for_spawn() -> TaskId {
        let ctx = get_local_runtime_context();
        if ctx.is_null() {
            panic!("spawn() must be called from within a runtime context.");
        }

        let inner = LocalRuntimeInner::current();
        inner.next_task_id()
    }

    /// Spawn a new asynchronous task. Must be called within a LocalRuntime context.
    pub fn spawn<F: Future + 'static>(f: F) -> JoinHandle<F::Output> {
        Self::spawn_inner(Self::next_task_id_for_spawn(), SysHandle::NONE, f)
    }

    /// Spawn a new asynchronous task that can wait for events on the provided wait_handle.
    /// Must be called within a LocalRuntime context.
    ///
    /// # Example
    ///
    /// ```
    /// fn test_event_listener() {
    ///     // Test a ping-pong across threads.
    ///     const ITERS: u32 = 10;
    ///     let (handle_here, handle_there) =
    ///         moto_sys::SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();
    ///
    ///     let channel_here = Arc::new(AtomicU32::new(0));
    ///     let channel_there = channel_here.clone();
    ///
    ///     let runtime_thread = std::thread::spawn(move || {
    ///         moto_async::LocalRuntime::new().block_on(async move {
    ///             let _ = moto_async::LocalRuntime::spawn_event_listener(
    ///                 handle_there,
    ///                 async move |event_stream| {
    ///                     for step in 0..ITERS {
    ///                         assert_eq!(step * 2, channel_there.fetch_add(1, Ordering::AcqRel));
    ///                         moto_sys::SysCpu::wake(handle_there).unwrap();
    ///                         event_stream.next().await;
    ///                     }
    ///                 },
    ///             )
    ///             .await;
    ///         });
    ///     });
    ///
    ///     for step in 0..ITERS {
    ///         let mut handles = [handle_here];
    ///         moto_sys::SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None).unwrap();
    ///         assert_eq!(step * 2 + 1, channel_here.fetch_add(1, Ordering::AcqRel));
    ///         moto_sys::SysCpu::wake(handle_here).unwrap();
    ///     }
    ///
    ///     runtime_thread.join().unwrap();
    ///     println!("PASS");
    /// }
    /// ```

    pub fn spawn_event_listener<TaskFn, Fut, T>(
        wait_handle: SysHandle,
        task_fn: TaskFn,
    ) -> JoinHandle<T>
    where
        TaskFn: FnOnce(EventStream) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
    {
        let task_id = Self::next_task_id_for_spawn();

        Self::spawn_inner(task_id, wait_handle, async move {
            task_fn(EventStream { task_id }).await
        })
    }

    fn spawn_inner<F: Future + 'static>(
        task_id: TaskId,
        wait_handle: SysHandle,
        f: F,
    ) -> JoinHandle<F::Output> {
        use futures::channel::oneshot;

        let inner = LocalRuntimeInner::current();
        let (tx, rx) = oneshot::channel::<F::Output>();

        let waker = alloc::rc::Rc::new(RefCell::new(None));

        let task = Task {
            id: task_id,
            event_stream_handle: wait_handle,
            fut: Box::pin(async move {
                let _ = tx.send(f.await);
                log::trace!("Task {:?} almost ready.", task_id);
            })
            .into(),
            join_handle_waker: alloc::rc::Rc::downgrade(&waker),
        };

        inner.runqueue.borrow_mut().push_back(task_id);
        inner.incoming.borrow_mut().push_back(task);
        log::trace!("spawned task {task_id:?}");

        JoinHandle { task_id, rx, waker }
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
            let mut cx = core::task::Context::from_waker(&waker);

            {
                log::trace!("Polling the root task/future.");
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
                log::trace!("root wakeup");
                return Poll::Ready(());
            }

            let task_waker = inner.new_waker(next_runnable);
            let mut inner_cx = core::task::Context::from_waker(&task_waker);

            let mut tasks_ref = inner.tasks.borrow_mut();
            let task = tasks_ref.get_mut(&next_runnable).unwrap();
            let pinned = Pin::new(&mut task.fut);

            // This may call spawn, or add a timer, which borrows inner.
            if let Poll::Pending = pinned.poll(&mut inner_cx) {
                continue;
            }

            // The task has completed.
            if let Some(waker_cell) = task.join_handle_waker.upgrade() {
                if let Some(waker) = waker_cell.borrow_mut().take() {
                    log::trace!("Waking the join handle for {:?}.", next_runnable);
                    waker.wake();
                }
            }
            let task = tasks_ref.remove(&next_runnable).unwrap();
            assert_eq!(next_runnable, task.id);
            if !task.event_stream_handle.is_none() {
                assert_eq!(
                    next_runnable,
                    inner
                        .attached_tasks
                        .borrow_mut()
                        .remove(&task.event_stream_handle)
                        .unwrap()
                );
                inner.rebuild_wait_handles();
            }
        }
    }
}

pub struct JoinHandle<T> {
    task_id: TaskId,
    rx: oneshot::Receiver<T>,

    waker: alloc::rc::Rc<RefCell<Option<Waker>>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rx.try_recv() {
            Ok(Some(res)) => {
                log::trace!("Task {:?} is ready.", self.task_id);
                Poll::Ready(res)
            }
            Ok(None) => {
                log::trace!("JoinHandle::Poll: Pending");
                *self.waker.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(err) => panic!("{err:?}"),
        }
    }
}

pub struct EventStream {
    task_id: TaskId,
}

pub struct EventStreamWaiter {
    task_id: TaskId,
}

impl EventStream {
    pub fn next(&self) -> EventStreamWaiter {
        EventStreamWaiter {
            task_id: self.task_id,
        }
    }
}

impl Future for EventStreamWaiter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = LocalRuntimeInner::current();
        if inner.sys_events.borrow_mut().remove(&self.task_id) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
