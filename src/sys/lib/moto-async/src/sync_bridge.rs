//! Sync/async boundary primitives (vdso-rewrite-design.md, sections 3.1-3.2).
//!
//! One parking protocol for the whole codebase: a three-state atomic plus
//! the waiter's thread handle. `SyncWaiter` exposes it to sync threads
//! waiting on a task-maintained condition; `block_on_sync` builds its
//! future-polling parker on the same state machine.

extern crate alloc;

use alloc::sync::Arc;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{ContextBuilder, LocalWaker, Poll, RawWaker, RawWakerVTable, Waker};
use moto_rt::time::Instant;
use moto_sys::SysHandle;

const EMPTY: u32 = 0;
const WAITING: u32 = 1;
const NOTIFIED: u32 = 2;

/// The core state machine. At most one thread may park at a time;
/// unpark may be called from any thread, including runtime tasks.
///
/// Relies on kernel wakes being sticky: a wake delivered between our
/// state transition and the wait syscall makes that wait return
/// immediately instead of being lost. The flip side: a wake that loses
/// the race with a timed-out park stays queued in the kernel and makes
/// some later, unrelated wait return early. Every user of this protocol
/// must therefore tolerate spurious returns and re-check its condition.
pub(crate) struct Parker {
    state: AtomicU32,
    waiter: AtomicU64,
}

impl Parker {
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU32::new(EMPTY),
            waiter: AtomicU64::new(0),
        }
    }

    /// Park the calling thread until unpark, the deadline, or a spurious
    /// wake. Returns immediately (no syscall) if an unpark is pending.
    pub(crate) fn park(&self, deadline: Option<Instant>) {
        self.waiter
            .store(moto_sys::current_thread().as_u64(), Ordering::Relaxed);

        // Release publishes the waiter handle to unpark(); Acquire on
        // failure pairs with unpark()'s Release swap to NOTIFIED.
        match self
            .state
            .compare_exchange(EMPTY, WAITING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(prev) => {
                debug_assert_eq!(prev, NOTIFIED, "concurrent park() calls");
                self.state.store(EMPTY, Ordering::Release);
                return;
            }
        }

        let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, deadline);

        // Either woken (NOTIFIED) or timed out (still WAITING); an unpark
        // racing with the timeout is consumed here or left for the next
        // park -- both fold into the spurious-return contract.
        self.state.swap(EMPTY, Ordering::AcqRel);
    }

    /// Wake the parked thread, or make the next park return immediately.
    /// Signals coalesce; only the EMPTY->parked transition pays a syscall.
    pub(crate) fn unpark(&self) {
        if self.state.swap(NOTIFIED, Ordering::AcqRel) == WAITING {
            let _ =
                moto_sys::SysCpu::wake(SysHandle::from_u64(self.waiter.load(Ordering::Relaxed)));
        }
    }
}

/// A sync thread's wait-for-a-condition primitive: the condition itself
/// lives outside (e.g. "the send queue has room"), maintained by tasks.
/// The waiter re-checks it after every wait(); spurious wakeups are
/// allowed and harmless by contract. Replaces the per-site futex dances
/// (EventSourceManaged and friends).
pub struct SyncWaiter {
    parker: Parker,
}

impl Default for SyncWaiter {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncWaiter {
    pub const fn new() -> Self {
        Self {
            parker: Parker::new(),
        }
    }

    /// Block until signal(), the deadline, or a spurious wake. At most
    /// one thread may wait at a time.
    pub fn wait(&self, deadline: Option<Instant>) {
        self.parker.park(deadline);
    }

    /// Callable from any thread or task. A signal with no waiter is
    /// remembered and consumed by the next wait().
    pub fn signal(&self) {
        self.parker.unpark();
    }
}

// The calling thread's parker, created once and cached in TLS; waker
// clones handed to futures keep it alive past thread exit if needed.
static PARKER_TLS_KEY: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn drop_thread_parker(ptr: *mut u8) {
    unsafe { Arc::decrement_strong_count(ptr as *const Parker) };
}

fn parker_tls_key() -> moto_rt::tls::Key {
    let key = PARKER_TLS_KEY.load(Ordering::Relaxed);
    if key != 0 {
        return key;
    }

    let key = moto_rt::tls::create(Some(drop_thread_parker));
    assert_ne!(key, 0);
    if let Err(prev) = PARKER_TLS_KEY.compare_exchange(0, key, Ordering::AcqRel, Ordering::Relaxed)
    {
        // Safety: we just created the key; nobody else saw it.
        unsafe { moto_rt::tls::destroy(key) };
        prev
    } else {
        key
    }
}

fn thread_parker() -> Arc<Parker> {
    let key = parker_tls_key();
    // Safety: the key is valid; the slot holds null or an Arc'd Parker.
    let ptr = unsafe { moto_rt::tls::get(key) } as *const Parker;
    if ptr.is_null() {
        let parker = Arc::new(Parker::new());
        // Safety: the raw count is owned by the TLS slot until thread exit.
        unsafe { moto_rt::tls::set(key, Arc::into_raw(parker.clone()) as *mut u8) };
        parker
    } else {
        // Safety: the slot's strong count keeps ptr alive.
        unsafe {
            Arc::increment_strong_count(ptr);
            Arc::from_raw(ptr)
        }
    }
}

unsafe fn bridge_waker_clone(data: *const ()) -> RawWaker {
    unsafe { Arc::increment_strong_count(data as *const Parker) };
    RawWaker::new(data, &BRIDGE_WAKER_VTABLE)
}

unsafe fn bridge_waker_wake(data: *const ()) {
    unsafe {
        bridge_waker_wake_by_ref(data);
        bridge_waker_drop(data);
    }
}

unsafe fn bridge_waker_wake_by_ref(data: *const ()) {
    unsafe { (data as *const Parker).as_ref().unwrap_unchecked() }.unpark();
}

unsafe fn bridge_waker_drop(data: *const ()) {
    unsafe { Arc::decrement_strong_count(data as *const Parker) };
}

static BRIDGE_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    bridge_waker_clone,
    bridge_waker_wake,
    bridge_waker_wake_by_ref,
    bridge_waker_drop,
);

/// Poll `fut` to completion on the calling thread, parking between polls.
///
/// The sync half of the sync/async boundary (design 3.1): sync callers
/// drive bridge futures (channel sends, oneshot receives) with this; the
/// async half runs on some LocalRuntime elsewhere. A ready future
/// completes in one poll with no syscall and no allocation (the waker
/// state is cached per thread).
///
/// Must not be called on a LocalRuntime thread: parking there would
/// deadlock the executor. Futures that need a runtime (SysHandleFuture,
/// timers) cannot be driven by this either -- they panic on "No runtime".
pub fn block_on_sync<F: Future>(fut: F) -> F::Output {
    debug_assert!(
        !crate::local_runtime::on_runtime_thread(),
        "block_on_sync on a LocalRuntime thread"
    );

    let mut fut = pin!(fut);
    let parker = thread_parker();
    let data = Arc::as_ptr(&parker) as *const ();
    // Safety: both wakers own a strong count via bridge_waker_clone.
    let waker = unsafe { Waker::from_raw(bridge_waker_clone(data)) };
    let local_waker = unsafe { LocalWaker::from_raw(bridge_waker_clone(data)) };
    let mut cx = ContextBuilder::from_waker(&waker)
        .local_waker(&local_waker)
        .build();

    loop {
        if let Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
            return val;
        }
        // A leftover signal from a prior call costs one spurious re-poll.
        parker.park(None);
    }
}

/// `block_on_sync` with a deadline. On timeout the future is handed
/// back so the caller can extract partial progress (design rule 7:
/// a blocking write that timed out mid-way returns Ok(written)) and
/// cancel by dropping it.
///
/// `F: Unpin` because the future is returned by value; the intended
/// consumers are hand-rolled progress-tracking structs, which are.
pub fn block_on_sync_deadline<F: Future + Unpin>(
    mut fut: F,
    deadline: Instant,
) -> Result<F::Output, F> {
    debug_assert!(
        !crate::local_runtime::on_runtime_thread(),
        "block_on_sync_deadline on a LocalRuntime thread"
    );

    let parker = thread_parker();
    let data = Arc::as_ptr(&parker) as *const ();
    // Safety: both wakers own a strong count via bridge_waker_clone.
    let waker = unsafe { Waker::from_raw(bridge_waker_clone(data)) };
    let local_waker = unsafe { LocalWaker::from_raw(bridge_waker_clone(data)) };
    let mut cx = ContextBuilder::from_waker(&waker)
        .local_waker(&local_waker)
        .build();

    loop {
        // Progress racing the deadline: always one final poll first.
        if let Poll::Ready(val) = core::pin::Pin::new(&mut fut).poll(&mut cx) {
            return Ok(val);
        }
        if Instant::now() >= deadline {
            return Err(fut);
        }
        parker.park(Some(deadline));
    }
}
