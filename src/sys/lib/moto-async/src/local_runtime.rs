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

fn get_local_runtime_context() -> *const RefCell<LocalRuntimeInner> {
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
    join_handle_waker: alloc::rc::Weak<RefCell<Option<Waker>>>,
}

struct LocalRuntimeInner {
    timeq: RefCell<crate::timeq::TimeQ<TaskId>>,
    global_runqueue: Arc<SpinLock<VecDeque<TaskId>>>,
    local_runqueue: VecDeque<TaskId>,

    tasks: RefCell<BTreeMap<TaskId, Task>>,
    incoming: VecDeque<Task>,

    next_task_id: u64,
}

impl LocalRuntimeInner {
    fn new() -> Self {
        Self {
            timeq: Default::default(),
            global_runqueue: Default::default(),
            local_runqueue: Default::default(),
            tasks: Default::default(),
            incoming: Default::default(),
            next_task_id: 1,
        }
    }

    fn new_waker(&mut self, task_id: TaskId) -> Waker {
        let moto_waker = Arc::new(MotoWaker {
            runqueue: Arc::downgrade(&self.global_runqueue),
            task_id,
            wake_handle: moto_sys::current_thread(),
        });

        let waker_data = Arc::into_raw(moto_waker) as usize as *const ();

        // Safety: safe by construction.
        unsafe { Waker::from_raw(RawWaker::new(waker_data, &RAW_WAKER_VTABLE)) }
    }

    fn next_task_id(&mut self) -> TaskId {
        let next_task_id = self.next_task_id;
        self.next_task_id += 1;
        TaskId(next_task_id)
    }

    fn current<'a>() -> &'a RefCell<Self> {
        if let Some(this) = unsafe { get_local_runtime_context().as_ref() } {
            this
        } else {
            panic!("No runtime.");
        }
    }

    fn merge_incoming(&mut self) {
        let mut global_queue = VecDeque::new();
        core::mem::swap(&mut global_queue, &mut *self.global_runqueue.lock());
        for task_id in global_queue {
            self.local_runqueue.push_back(task_id);
        }

        let mut incoming = VecDeque::new();
        core::mem::swap(&mut incoming, &mut self.incoming);

        let mut tasks = self.tasks.borrow_mut();
        for task in incoming {
            assert!(tasks.insert(task.id, task).is_none());
        }
    }

    fn next_runnable(&mut self) -> Option<TaskId> {
        self.local_runqueue.pop_front()
    }

    fn wait(&self, timeo: Option<Instant>) {
        let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, timeo);
    }

    fn enqueue_expired_timers(&mut self) {
        let now = Instant::now();
        let mut timeq = self.timeq.borrow_mut();
        while let Some(task_id) = timeq.pop_at(now) {
            log::trace!("Timer expired for {task_id:?}.");
            self.local_runqueue.push_back(task_id)
        }
    }
}

/// Local-thread async runtime, similar to futures::LocalPool and tokio::Runtime, but simpler.
pub struct LocalRuntime {
    inner: Box<RefCell<LocalRuntimeInner>>,
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
            inner: Box::new(RefCell::new(LocalRuntimeInner::new())),
        }
    }

    pub fn enter(&mut self) -> LocalRuntimeContextGuard {
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

        let inner = LocalRuntimeInner::current();
        inner.borrow().timeq.borrow_mut().add_at(when, task_id);
    }

    /// Spawn a new asynchronous task. Must be called within a LocalRuntime context.
    pub fn spawn<F: Future + 'static>(f: F) -> JoinHandle<F::Output> {
        use futures::channel::oneshot;

        let ctx = get_local_runtime_context();
        if ctx.is_null() {
            panic!("spawn() must be called from within a runtime context.");
        }

        // Safety: we just checked that ctx is not null.
        let mut inner = unsafe { ctx.as_ref().unwrap().borrow_mut() };
        let (tx, rx) = oneshot::channel::<F::Output>();

        let task_id = inner.next_task_id();

        let waker = alloc::rc::Rc::new(RefCell::new(None));

        let task = Task {
            id: task_id,
            fut: Box::pin(async move {
                let _ = tx.send(f.await);
                log::trace!("Task {:?} almost ready.", task_id);
            })
            .into(),
            join_handle_waker: alloc::rc::Rc::downgrade(&waker),
        };

        inner.local_runqueue.push_back(task_id);
        inner.incoming.push_back(task);
        log::trace!("spawned task {task_id:?}");

        JoinHandle { task_id, rx, waker }
    }

    // See futures::local_pool::run_executor().
    fn run_executor<T, F: FnMut(&mut Context<'_>) -> Poll<T>>(mut f: F) -> T {
        let waker = LocalRuntimeInner::current()
            .borrow_mut()
            .new_waker(TaskId::default_root());
        let mut cx = core::task::Context::from_waker(&waker);

        loop {
            if let Poll::Ready(t) = f(&mut cx) {
                return t;
            }

            Self::wait();
        }
    }

    // Wait until a wakeup or next timeout.
    fn wait() {
        let inner = LocalRuntimeInner::current();

        loop {
            inner.borrow_mut().enqueue_expired_timers();
            if !inner.borrow().local_runqueue.is_empty() {
                return;
            }

            let timeo = inner.borrow().timeq.borrow().next();
            inner.borrow().wait(timeo);
        }
    }

    /// Run a future to completion. Similar to futures::LocalPool::run_until().
    pub fn block_on<F: Future>(&mut self, f: F) -> F::Output {
        futures::pin_mut!(f);
        let _guard = self.enter();
        Self::run_executor(|cx| {
            loop {
                {
                    log::trace!("Polling the root task/future.");
                    let result = f.as_mut().poll(cx);
                    if let Poll::Ready(output) = result {
                        return Poll::Ready(output);
                    }
                }

                if Self::poll_pool(cx).is_ready() {
                    continue;
                } else {
                    return Poll::Pending; // Will sleep/wait.
                }
            }
        })
    }

    // Poll the runnable queue until there's nothing to do.
    // It is safe to sleep when poll_pool() returns.
    // Kinda like futures::LocalPool::poll_pool(), but much simpler.
    fn poll_pool(_cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let inner = LocalRuntimeInner::current();

            inner.borrow_mut().merge_incoming();
            let next_runnable = inner.borrow_mut().next_runnable();

            let Some(next_runnable) = next_runnable else {
                return Poll::Pending;
            };

            if next_runnable.is_root() {
                log::trace!("root wakeup");
                return Poll::Ready(());
            }

            let task_waker = LocalRuntimeInner::current()
                .borrow_mut()
                .new_waker(next_runnable);
            let mut inner_cx = core::task::Context::from_waker(&task_waker);

            let inner_ref = inner.borrow();
            let mut tasks_ref = inner_ref.tasks.borrow_mut();
            let task = tasks_ref.get_mut(&next_runnable).unwrap();
            let pinned = Pin::new(&mut task.fut);

            log::trace!("polling task {next_runnable:?}");
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
            core::mem::drop(tasks_ref);
            core::mem::drop(inner_ref);
            inner.borrow_mut().tasks.borrow_mut().remove(&next_runnable);
        }

        /*
        loop {
            self.drain_incoming();

            let pool_ret = self.pool.poll_next_unpin(cx);

            // We queued up some new tasks; add them and poll again.
            if !self.incoming.borrow().is_empty() {
                continue;
            }

            match pool_ret {
                Poll::Ready(Some(())) => continue,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
        */
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

impl<T> JoinHandle<T> {
    pub fn join(self) -> T {
        todo!()
    }
}
