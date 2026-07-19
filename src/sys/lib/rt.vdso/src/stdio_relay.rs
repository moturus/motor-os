//! The stdio relay runtime (design sections 4, 7.2): a dedicated
//! sibling of the core IO runtime, so a child's interactive output
//! never queues behind FS work. At most one thread per process,
//! created when an inherited-stdio child appears; it exits with the
//! last relay task and is recreated on demand.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use moto_async::SyncWaiter;
use moto_rt::spinlock::SpinLock;
use moto_sys::SysHandle;

type LocalBoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;
type TaskConstructor = Box<dyn FnOnce() -> LocalBoxFuture + Send + 'static>;

enum RelayMsg {
    Spawn(TaskConstructor),
    // Sent by the last finishing relay; the dispatcher re-checks
    // under the lock and exits.
    ExitCheck,
}

struct RelayState {
    tasks_tx: Option<moto_async::channel::Sender<RelayMsg>>,
    // Relay tasks alive or queued. A queued Spawn is always counted
    // before it is sent, so live == 0 implies an empty queue: the
    // dispatcher may exit, and the next spawn() starts a new thread.
    live: usize,
}

static STATE: SpinLock<RelayState> = SpinLock::new(RelayState {
    tasks_tx: None,
    live: 0,
});

/// Spawn the future `make_task` builds onto the relay runtime,
/// creating the runtime thread if none is running. Returns only after
/// the task's first poll: a relay must have its pipe-handle future
/// registered before the child process spawns, or output written just
/// before an early child exit can die unread (the old relay threads
/// won this race by going straight into a blocking read).
pub fn spawn<C, F>(make_task: C)
where
    C: FnOnce() -> F + Send + 'static,
    F: Future<Output = ()> + 'static,
{
    let tasks_tx = {
        let mut state = STATE.lock();
        state.live += 1;
        match &state.tasks_tx {
            Some(tasks_tx) => tasks_tx.clone(),
            None => {
                let (tasks_tx, tasks_rx) = moto_async::channel(8);
                let thread_param = Box::into_raw(Box::new((tasks_rx, tasks_tx.clone())));
                moto_sys::SysCpu::spawn(
                    SysHandle::SELF,
                    4096 * 16,
                    runtime_thread as *const () as usize as u64,
                    thread_param as u64,
                )
                .expect("Error spawning the stdio relay thread.");
                state.tasks_tx = Some(tasks_tx.clone());
                tasks_tx
            }
        }
    };

    let started = Arc::new((AtomicBool::new(false), SyncWaiter::new()));
    let started_task = started.clone();
    let ctor: TaskConstructor = Box::new(move || {
        let fut = make_task();
        Box::pin(async move {
            // The first poll continues into the task body right after
            // this; a pipe signal racing the last microseconds of
            // handle registration is latched by the kernel.
            started_task.0.store(true, Ordering::Release);
            started_task.1.signal();
            fut.await
        })
    });
    moto_async::block_on_sync(async move {
        let _ = tasks_tx.send(RelayMsg::Spawn(ctor)).await;
    });
    while !started.0.load(Ordering::Acquire) {
        started.1.wait(None);
    }
}

/// Give live relays a bounded window to finish before process exit;
/// they exit only after draining a dead child's pipe, so this restores
/// the ordering the per-child relay threads got from their write
/// yields (child output drained before the parent's exit is visible).
/// A relay of a still-running child just eats the timeout, as before.
pub fn drain_for_exit() {
    let deadline = moto_rt::time::Instant::now() + core::time::Duration::from_millis(10);
    while STATE.lock().live > 0 && moto_rt::time::Instant::now() < deadline {
        moto_sys::SysCpu::sched_yield();
    }
}

extern "C" fn runtime_thread(param: u64) {
    type Channel = (
        moto_async::channel::Receiver<RelayMsg>,
        moto_async::channel::Sender<RelayMsg>,
    );
    // Safety: uniquely owned; see spawn().
    let (mut tasks_rx, tasks_tx) = *unsafe { Box::from_raw(param as usize as *mut Channel) };
    moto_sys::set_current_thread_name("rt::stdio_relay").unwrap();

    moto_async::LocalRuntime::new().block_on(async move {
        loop {
            match tasks_rx.recv().await.unwrap() {
                RelayMsg::Spawn(ctor) => {
                    let tasks_tx = tasks_tx.clone();
                    core::mem::drop(moto_async::LocalRuntime::spawn(async move {
                        ctor().await;
                        let last = {
                            let mut state = STATE.lock();
                            state.live -= 1;
                            state.live == 0
                        };
                        if last {
                            let _ = tasks_tx.send(RelayMsg::ExitCheck).await;
                        }
                    }));
                }
                RelayMsg::ExitCheck => {
                    let mut state = STATE.lock();
                    if state.live == 0 {
                        // A racing spawn() either saw tasks_tx and made
                        // live nonzero (we would not be here), or sees
                        // None and starts a fresh thread.
                        state.tasks_tx = None;
                        return;
                    }
                }
            }
        }
    });

    let _ = moto_sys::SysObj::put(SysHandle::SELF);
    unreachable!()
}
