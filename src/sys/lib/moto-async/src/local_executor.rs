//! LocalExecutor for Motor OS.
//!
//! Closely follows (and reuses a lot of code/infra) futures::executor::LocalPool.
//!
//! Because all semi-popular local executors from crates.io require stdlib.

use alloc::boxed::Box;
use core::future::Future;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use core::task::Context;
use core::task::Poll;
use core::task::RawWaker;
use core::task::RawWakerVTable;
use core::task::Waker;
use moto_rt::time::Instant;
use moto_sys::SysHandle;

extern crate alloc;
/*

pub struct Task {
    wait_handle: SysHandle,

    // Tasks don't return Result<()> because the runtime won't know what to do about it.
    future: core::pin::Pin<Box<dyn Future<Output = ()>>>,

    #[cfg(debug_assertions)]
    debug_name: String,
}

impl Task {
    pub fn new(
        wait_handle: SysHandle,
        future: impl Future<Output = ()> + 'static,
        #[cfg(debug_assertions)] debug_name: String,
    ) -> Task {
        Task {
            wait_handle,
            future: Box::pin(future),

            #[cfg(debug_assertions)]
            debug_name,
        }
    }

    fn poll(&mut self, context: &mut core::task::Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}

struct LocalExecutor {
    tasks: alloc::collections::BTreeMap<SysHandle, Task>,
}

impl LocalExecutor {
    fn new() -> LocalExecutor {
        LocalExecutor {
            tasks: alloc::collections::BTreeMap::new(),
        }
    }

    fn wait_handles(&mut self) -> Vec<SysHandle> {
        let mut new_tasks = Vec::new();

        POSTED_TASKS.with(|t| {
            let mut t = t.borrow_mut();
            let tasks = &mut *t;

            core::mem::swap(&mut new_tasks, tasks);
        });

        LOCAL_EXECUTOR.with(|ex| {
            let mut exe = ex.borrow_mut();
            let tasks = &mut exe.as_mut().unwrap().tasks;

            for t in new_tasks {
                assert!(!t.wait_handle.is_none());
                assert!(tasks.insert(t.wait_handle, t).is_none());
            }

            let mut result = Vec::with_capacity(tasks.len());
            for k in tasks.keys() {
                result.push(*k);
            }

            result
        })
    }

    fn process_errors(bad_handles: Vec<SysHandle>) {
        LOCAL_EXECUTOR.with(|ex| {
            let mut exe = ex.borrow_mut();
            let tasks = &mut exe.as_mut().unwrap().tasks;
            for h in bad_handles {
                if h.is_none() {
                    break;
                }
                let _bad_task = tasks.remove(&h).unwrap();

                #[cfg(debug_assertions)]
                log::debug!(
                    "{:?}: LocalExecutor: removing bad task {}.",
                    std::thread::current().name(),
                    _bad_task.debug_name
                );
            }
        });
    }

    fn process_wakeups(handles: Vec<SysHandle>) {
        LOCAL_EXECUTOR.with(|ex| {
            let mut exe = ex.borrow_mut();
            let tasks = &mut exe.as_mut().unwrap().tasks;

            let local_waker = core::task::LocalWaker::noop();
            let waker = core::task::Waker::noop();

            let mut cx = core::task::ContextBuilder::from_waker(&waker)
                .local_waker(&local_waker)
                .build();

            for h in handles {
                if h.is_none() {
                    break;
                }
                log::debug!("wakeup on 0x{:x}", h.as_u64());
                let task = tasks.get_mut(&h).unwrap();
                match task.poll(&mut cx) {
                    Poll::Ready(()) => {
                        // The task has completed.
                        tasks.remove(&h);
                    }
                    Poll::Pending => {}
                }
            }
        });
    }

    fn run() {
        loop {
            let mut wait_handles = Self::wait_handles();
            if wait_handles.is_empty() {
                break;
            }

            match moto_sys::SysCpu::wait(
                &mut wait_handles,
                SysHandle::NONE,
                SysHandle::NONE,
                Some(moto_rt::time::Instant::nan()),
            ) {
                Ok(()) => {
                    if wait_handles.is_empty() {
                        continue;
                    }
                }
                Err(_) => {
                    Self::process_errors(wait_handles);
                    continue;
                }
            }

            Self::process_wakeups(wait_handles);
        }

        log::debug!("{:?}: LocalExecutor done.", std::thread::current().name());
        LOCAL_EXECUTOR.with(|ex| {
            let _ = ex.borrow_mut().take();
        })
    }
}

thread_local! {
    static LOCAL_EXECUTOR: core::cell::RefCell<Option<LocalExecutor>> = core::cell::RefCell::new(None);

    // While the executor is polling its tasks, new tasks may be added. To keep the borrow
    // checker happy, we add new tasks here, to consume later.
    static POSTED_TASKS: core::cell::RefCell<Vec<Task>> = core::cell::RefCell::new(vec![]);
}

pub fn run_local() {
    LOCAL_EXECUTOR.with(|ex| {
        let mut exe = ex.borrow_mut();
        assert!(exe.is_none());
        *exe = Some(LocalExecutor::new());
    });

    LocalExecutor::run();
}

pub fn add_task(task: Task) {
    POSTED_TASKS.with(|t| {
        t.borrow_mut().push(task);
    });
}

*/

static TLS_KEY: AtomicUsize = AtomicUsize::new(0);

fn get_tls_key() -> moto_rt::tls::Key {
    let key = TLS_KEY.load(Ordering::Relaxed);
    if key != 0 {
        return key;
    }

    let key = moto_rt::tls::create(Some(tls_dtor));
    assert_ne!(key, 0);
    if let Err(prev) = TLS_KEY.compare_exchange(key, 0, Ordering::AcqRel, Ordering::Relaxed) {
        // Safety: we just created the key, so it is safe.
        unsafe { moto_rt::tls::destroy(key) };
        prev
    } else {
        key
    }
}

unsafe extern "C" fn tls_dtor(data: *mut u8) {
    let _ = unsafe { Box::from_raw(data as usize as *mut LocalExecutor) };
}

pub(crate) fn get_local_executor() -> *mut LocalExecutor {
    // Safety: safe by construction.
    unsafe { moto_rt::tls::get(get_tls_key()) as usize as *mut _ }
}

fn set_local_executor(ptr: Box<LocalExecutor>) {
    // Safety: safe by construction.
    unsafe { moto_rt::tls::set(get_tls_key(), Box::into_raw(ptr) as usize as *mut u8) }
}

fn clear_local_executor() {
    // Safety: safe by construction.
    unsafe { moto_rt::tls::set(get_tls_key(), core::ptr::null_mut()) }
}

struct MotoWaker {}

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &WAKER_VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    todo!()
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    todo!()
}

unsafe fn waker_drop(data: *const ()) {
    // todo!()
}

const WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

pub(crate) struct LocalExecutor {
    timeq: crate::timeq::TimeQ<()>,
    // pool: futures::stream::FuturesUnordered<futures::task::LocalFutureObj<'static, ()>>,
}

impl LocalExecutor {
    pub(crate) fn add_timer(&mut self, when: Instant) {
        self.timeq.add_at(when, ());
    }
}

fn run_executor<T, F: FnMut(&mut Context<'_>) -> Poll<T>>(mut f: F) -> T {
    let executor = Box::new(LocalExecutor {
        timeq: Default::default(),
    });
    set_local_executor(executor);

    // let moto_waker = MotoWaker {};
    let raw_waker = RawWaker::new(get_local_executor() as usize as *const (), &WAKER_VTABLE);

    let local_waker = unsafe { core::task::LocalWaker::from_raw(raw_waker) };
    let mut cx = core::task::ContextBuilder::from_waker(Waker::noop())
        .local_waker(&local_waker)
        .build();

    loop {
        if let Poll::Ready(t) = f(&mut cx) {
            clear_local_executor();
            return t;
        }

        let now = Instant::now();
        let Some(next) = (unsafe { get_local_executor().as_mut().unwrap().timeq.next() }) else {
            panic!("Executor with nothing to do");
        };
        moto_rt::thread::sleep_until(next);
    }
}

/// Run a future to completion on the current thread.
///
/// This function will block the caller until the given future has completed.
pub fn block_on<F: Future>(f: F) -> F::Output {
    if !get_local_executor().is_null() {
        panic!("block_on() called from within an existing execution context.");
    }
    futures::pin_mut!(f);
    run_executor(|cx| f.as_mut().poll(cx))
}
