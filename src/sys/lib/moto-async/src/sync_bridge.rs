//! Sync/async boundary primitives (vdso-rewrite-design.md, sections 3.1-3.2).
//!
//! One parking protocol for the whole codebase: a three-state atomic plus
//! the waiter's thread handle. `SyncWaiter` exposes it to sync threads
//! waiting on a task-maintained condition; `block_on_sync` builds its
//! future-polling parker on the same state machine.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
            let _ = moto_sys::SysCpu::wake(SysHandle::from_u64(self.waiter.load(Ordering::Relaxed)));
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
