use core::future::Future;
use core::task::Poll;

use moto_sys::SysHandle;

pub struct Task {
    wait_handle: SysHandle,
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

    fn wait_handles() -> Vec<SysHandle> {
        let mut new_tasks = vec![];

        POSTED_TASKS.with(|t| {
            let mut t = t.borrow_mut();
            let tasks = &mut *t;

            core::mem::swap(&mut new_tasks, tasks);
        });

        LOCAL_EXECUTOR.with(|ex| {
            let mut exe = ex.borrow_mut();
            let tasks = &mut exe.as_mut().unwrap().tasks;

            for t in new_tasks {
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
                    Poll::Ready(_) => {
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
