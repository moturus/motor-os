//! Thread-local context used in select.

use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use moto_rt::time::Instant;
use moto_sys::SysHandle;

use crossbeam_utils::Backoff;

use crate::select::Selected;

/// Thread-local context used in select.
// This is a private API that is used by the select macro.
#[derive(Debug, Clone)]
pub struct Context {
    inner: Arc<Inner>,
}

/// Inner representation of `Context`.
#[derive(Debug)]
struct Inner {
    /// Selected operation.
    select: AtomicUsize,

    /// A slot into which another thread may store a pointer to its `Packet`.
    packet: AtomicPtr<()>,

    /// Thread id.
    thread_id: SysHandle,
}

impl Context {
    /// Creates a new context for the duration of the closure.
    #[inline]
    pub fn with<F, R>(f: F) -> R
    where
        F: FnOnce(&Self) -> R,
    {
        // thread_local! {
        //     /// Cached thread-local context.
        //     static CONTEXT: Cell<Option<Context>> = Cell::new(Some(Context::new()));
        // }

        // let mut f = Some(f);
        // let mut f = |cx: &Self| -> R {
        //     let f = f.take().unwrap();
        //     f(cx)
        // };

        // CONTEXT
        //     .try_with(|cell| match cell.take() {
        //         None => f(&Self::new()),
        //         Some(cx) => {
        //             cx.reset();
        //             let res = f(&cx);
        //             cell.set(Some(cx));
        //             res
        //         }
        //     })
        //     .unwrap_or_else(|_| f(&Self::new()))
        f(&Self::new())
    }

    /// Creates a new `Context`.
    // #[cold]
    fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                select: AtomicUsize::new(Selected::Waiting.into()),
                packet: AtomicPtr::new(ptr::null_mut()),
                thread_id: crate::utils::current_thread_id(),
            }),
        }
    }

    /// Resets `select` and `packet`.
    #[inline]
    fn _reset(&self) {
        self.inner
            .select
            .store(Selected::Waiting.into(), Ordering::Release);
        self.inner.packet.store(ptr::null_mut(), Ordering::Release);
    }

    /// Attempts to select an operation.
    ///
    /// On failure, the previously selected operation is returned.
    #[inline]
    pub fn try_select(&self, select: Selected) -> Result<(), Selected> {
        self.inner
            .select
            .compare_exchange(
                Selected::Waiting.into(),
                select.into(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|e| e.into())
    }

    /// Returns the selected operation.
    #[inline]
    pub fn selected(&self) -> Selected {
        Selected::from(self.inner.select.load(Ordering::Acquire))
    }

    /// Stores a packet.
    ///
    /// This method must be called after `try_select` succeeds and there is a packet to provide.
    #[inline]
    pub fn store_packet(&self, packet: *mut ()) {
        if !packet.is_null() {
            self.inner.packet.store(packet, Ordering::Release);
        }
    }

    /// Waits until a packet is provided and returns it.
    #[inline]
    pub fn wait_packet(&self) -> *mut () {
        let backoff = Backoff::new();
        loop {
            let packet = self.inner.packet.load(Ordering::Acquire);
            if !packet.is_null() {
                return packet;
            }
            backoff.snooze();
        }
    }

    /// Waits until an operation is selected and returns it.
    ///
    /// If the deadline is reached, `Selected::Aborted` will be selected.
    #[inline]
    pub fn wait_until(&self, deadline: Option<Instant>) -> Selected {
        // Spin for a short time, waiting until an operation is selected.
        let backoff = Backoff::new();
        loop {
            let sel = Selected::from(self.inner.select.load(Ordering::Acquire));
            if sel != Selected::Waiting {
                return sel;
            }

            if backoff.is_completed() {
                break;
            } else {
                backoff.snooze();
            }
        }

        loop {
            // Check whether an operation has been selected.
            let sel = Selected::from(self.inner.select.load(Ordering::Acquire));
            if sel != Selected::Waiting {
                return sel;
            }

            // If there's a deadline, park the current thread until the deadline is reached.
            if let Some(end) = deadline {
                let now = Instant::now();

                if now < end {
                    crate::utils::sleep_until(deadline);
                } else {
                    // The deadline has been reached. Try aborting select.
                    return match self.try_select(Selected::Aborted) {
                        Ok(()) => Selected::Aborted,
                        Err(s) => s,
                    };
                }
            } else {
                crate::utils::sleep_until(None);
            }
        }
    }

    /// Unparks the thread this context belongs to.
    #[inline]
    pub fn unpark(&self) {
        let _ = moto_sys::SysCpu::wake(self.thread_id());
    }

    /// Returns the id of the thread this context belongs to.
    #[inline]
    pub fn thread_id(&self) -> SysHandle {
        self.inner.thread_id
    }
}
