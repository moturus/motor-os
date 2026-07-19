//! The core IO runtime: one lazily created LocalRuntime thread per
//! process (design section 4). The FS client's dispatch loop is its
//! first resident; unmanaged-source readiness tasks and other
//! residents follow.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use moto_sys::SysHandle;

type LocalBoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

// Task constructors cross threads, the futures they build do not:
// resident state (Rc and friends) stays on the runtime thread.
type TaskConstructor = Box<dyn FnOnce() -> LocalBoxFuture + Send + 'static>;

struct Spawner {
    tasks_tx: moto_async::channel::Sender<TaskConstructor>,
}

static SPAWNER: AtomicUsize = AtomicUsize::new(SPAWNER_NONE);

const SPAWNER_NONE: usize = 0;
const SPAWNER_PENDING: usize = 1;

/// Spawn the future `make_task` builds onto the core IO runtime,
/// creating the runtime thread on first use. Must not be called from
/// the runtime thread itself: residents spawn siblings directly via
/// `LocalRuntime::spawn`.
pub fn spawn<C, F>(make_task: C)
where
    C: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + 'static,
{
    let ctor: TaskConstructor = Box::new(move || Box::pin(make_task()));
    let spawner = get_spawner();
    moto_async::block_on_sync(async {
        let _ = spawner.tasks_tx.send(ctor).await;
    });
}

fn get_spawner() -> &'static Spawner {
    let addr = SPAWNER.load(Ordering::Acquire);
    if addr > SPAWNER_PENDING {
        return unsafe { &*(addr as *const Spawner) };
    }

    if addr == SPAWNER_NONE
        && SPAWNER
            .compare_exchange(
                SPAWNER_NONE,
                SPAWNER_PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    {
        return create_spawner();
    }

    // Wait out a concurrent initialization.
    loop {
        let addr = SPAWNER.load(Ordering::Acquire);
        if addr > SPAWNER_PENDING {
            return unsafe { &*(addr as *const Spawner) };
        }
        moto_sys::SysCpu::sched_yield();
    }
}

fn create_spawner() -> &'static Spawner {
    let (tasks_tx, tasks_rx) = moto_async::channel(8);
    let spawner: &'static Spawner = Box::leak(Box::new(Spawner { tasks_tx }));

    let thread_param = Box::into_raw(Box::new(tasks_rx));
    moto_sys::SysCpu::spawn(
        SysHandle::SELF,
        4096 * 16,
        runtime_thread as *const () as usize as u64,
        thread_param as u64,
    )
    .expect("Error spawning the IO runtime thread.");

    SPAWNER.store(spawner as *const Spawner as usize, Ordering::Release);
    spawner
}

extern "C" fn runtime_thread(param: u64) {
    // Safety: uniquely owned; see create_spawner().
    let mut tasks_rx = *unsafe {
        Box::from_raw(param as usize as *mut moto_async::channel::Receiver<TaskConstructor>)
    };
    moto_sys::set_current_thread_name("rt::io_runtime").unwrap();

    moto_async::LocalRuntime::new().block_on(async move {
        loop {
            let ctor = tasks_rx.recv().await.unwrap();
            // Residents run detached; dropping the JoinHandle does not
            // cancel the task.
            core::mem::drop(moto_async::LocalRuntime::spawn(ctor()));
        }
    });
}
