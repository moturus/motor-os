//! The stdio relay runtime (design sections 4, 7.2): a dedicated
//! sibling of the core IO runtime, so a child's interactive output
//! never queues behind FS work. At most one thread per process,
//! created when an inherited-stdio child appears; it exits with the
//! last relay task and is recreated on demand.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicBool, AtomicU32};
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

/// File relays, tracked apart from `STATE` because process exit treats them
/// differently: their sink is the filesystem, so pending bytes cannot be
/// dropped on a deadline the way bytes headed for another live process can.
struct FileRelays {
    shutdown: AtomicBool,
    live: AtomicU32,
    /// One signal per live relay. A relay parks on its *peer's* handle, which
    /// only the peer can signal, so exit needs an in-process wakeup; this is
    /// the same cross-thread wake into the relay runtime that `spawn()` uses.
    /// Firing before the relay parks is safe: the receiver resolves on its
    /// first poll, so the wakeup cannot be lost.
    signals: SpinLock<Vec<(SysHandle, moto_async::oneshot::Sender<()>)>>,
}

static FILE_RELAYS: FileRelays = FileRelays {
    shutdown: AtomicBool::new(false),
    live: AtomicU32::new(0),
    signals: SpinLock::new(Vec::new()),
};

pub(crate) fn register_file_relay(handle: SysHandle) -> moto_async::oneshot::Receiver<()> {
    let (tx, rx) = moto_async::oneshot();
    FILE_RELAYS.live.fetch_add(1, Ordering::Relaxed);
    FILE_RELAYS.signals.lock().push((handle, tx));
    rx
}

pub(crate) fn unregister_file_relay(handle: SysHandle) {
    {
        // Dropping the sender closes the channel, which would look like a
        // shutdown signal -- harmless here, because the relay is done with its
        // receiver by the time it unregisters.
        let mut signals = FILE_RELAYS.signals.lock();
        if let Some(idx) = signals.iter().position(|(entry, _)| *entry == handle) {
            signals.swap_remove(idx);
        }
    }
    if FILE_RELAYS.live.fetch_sub(1, Ordering::AcqRel) == 1 {
        moto_rt::futex_wake_all(&FILE_RELAYS.live);
    }
}

/// Whether this process is exiting and file relays should close their pipes
/// and flush what the ring already holds.
pub(crate) fn shutting_down() -> bool {
    FILE_RELAYS.shutdown.load(Ordering::Acquire)
}

pub(crate) struct CompletionGroup {
    child: u64,
    pending: AtomicU32,
}

static COMPLETION_GROUPS: SpinLock<BTreeMap<u64, Arc<CompletionGroup>>> =
    SpinLock::new(BTreeMap::new());

pub(crate) fn install_completion_group(child: u64, pending: usize) -> Arc<CompletionGroup> {
    assert!(pending > 0 && pending <= u32::MAX as usize);
    let group = Arc::new(CompletionGroup {
        child,
        pending: AtomicU32::new(pending as u32),
    });
    // The kernel reuses a process handle number once the parent releases it,
    // so an entry still here belongs to a child that was dropped unwaited: no
    // one can ask about it any more. Evict it rather than treating the
    // collision as a bug. Its relays own their own `Arc` and still finish;
    // `complete_one()` already declines to remove an entry it does not own.
    COMPLETION_GROUPS.lock().insert(child, group.clone());
    group
}

impl CompletionGroup {
    pub(crate) fn complete_one(self: &Arc<Self>) {
        let previous = self.pending.fetch_sub(1, Ordering::AcqRel);
        assert!(previous != 0);
        if previous != 1 {
            return;
        }

        moto_rt::futex_wake_all(&self.pending);
        let mut groups = COMPLETION_GROUPS.lock();
        if groups
            .get(&self.child)
            .is_some_and(|group| Arc::ptr_eq(group, self))
        {
            groups.remove(&self.child);
        }
    }

    pub(crate) fn wait(&self) {
        loop {
            let pending = self.pending.load(Ordering::Acquire);
            if pending == 0 {
                return;
            }
            moto_rt::futex_wait(&self.pending, pending, None);
        }
    }
}

/// The relay-completion group of `child`, if it has one. Callers that are
/// about to release the child's handle must take this *before* releasing it:
/// the number can be handed to a new process immediately afterwards.
pub(crate) fn completion_group(child: u64) -> Option<Arc<CompletionGroup>> {
    COMPLETION_GROUPS.lock().get(&child).cloned()
}

pub(crate) fn wait_for_child(child: u64) {
    if let Some(group) = completion_group(child) {
        group.wait();
    }
}

pub(crate) fn child_is_finalized(child: u64) -> bool {
    COMPLETION_GROUPS
        .lock()
        .get(&child)
        .is_none_or(|group| group.pending.load(Ordering::Acquire) == 0)
}

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

/// Finish relaying before the process exits.
///
/// File relays are waited for without a deadline. Each one first tells its
/// peer the reader is closing, after which no child can add bytes, so what
/// remains is at most one ring and the wait cannot be extended by a child, a
/// grandchild, or a slow writer. It is bounded in work rather than in
/// wall-clock time -- a filesystem request has no wall-clock bound -- which is
/// the same guarantee `wait()` already makes for relay finalization. Dropping
/// those bytes on a timer would silently truncate a redirected file.
///
/// Ordinary pipe relays hand bytes to another live process, so they keep the
/// bounded window that restores the ordering the per-child relay threads got
/// from their write yields (child output drained before the parent's exit is
/// visible). A relay of a still-running child just eats the timeout, as before.
pub fn drain_for_exit() {
    FILE_RELAYS.shutdown.store(true, Ordering::Release);
    // Take the signals out first: waking runs relay code, and a relay
    // finishing meanwhile needs this lock to unregister.
    let signals = core::mem::take(&mut *FILE_RELAYS.signals.lock());
    for (_, signal) in signals {
        let _ = signal.send(());
    }
    loop {
        let live = FILE_RELAYS.live.load(Ordering::Acquire);
        if live == 0 {
            break;
        }
        moto_rt::futex_wait(&FILE_RELAYS.live, live, None);
    }

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
