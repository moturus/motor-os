//! The vDSO listener's accept pump (design 6.5).
//!
//! Wiring: `run` is spawned onto the IO runtime at bind, the
//! `RtTcpListener` wrapper pokes it, and `stop` (or the native
//! listener's death) ends it.
//!
//! The pump reproduces the pool path's arming discipline on donations:
//! one posted request stands while the ready queue is below the vDSO
//! backlog, so held reservations scale with connections actually queued,
//! never with the backlog number. It is a level-driven policy loop --
//! every wake recomputes `TcpListener::accept_load` from ground truth and
//! acts on it, so coalesced or spurious pokes are harmless. Its pokes:
//! a completion queued (the wrapper's readiness observer -- the standing
//! request was consumed), a connection claimed (the accept shims -- queue
//! room reopened), a backlog change, and stop.

use alloc::sync::{Arc, Weak};
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Poll;
use moto_io::net::tcp::TcpListener;
use moto_rt::mutex::Mutex;

/// The pump's cross-thread wakeup: an epoch counter and a single parked
/// waker. Raisers run on the channel runtime thread (completion dispatch)
/// and on caller threads (the accept shims), so unlike
/// `moto_async::LocalNotify` this must be `Sync`; it carries no permit
/// because the pump re-reads its level after every wake.
struct PumpSignal {
    epoch: AtomicU64,
    waker: Mutex<Option<core::task::Waker>>,
}

impl PumpSignal {
    const fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            waker: Mutex::new(None),
        }
    }

    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    fn raise(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Completes once the epoch differs from `seen`. Single-waiter: only
    /// the pump task parks here.
    async fn changed(&self, seen: u64) {
        core::future::poll_fn(|cx| {
            if self.epoch() != seen {
                return Poll::Ready(());
            }
            *self.waker.lock() = Some(cx.waker().clone());
            // Re-check after publishing the waker: a raise in between took
            // the previous slot content, not this one. The waker left
            // behind on this path goes stale; the next raise or park
            // replaces it, and a spurious pump wake only recomputes.
            if self.epoch() != seen {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await
    }

    /// Race `fut` against this signal: `Some` if `fut` completed, `None`
    /// if the signal fired first -- the caller re-reads its level. Lets a
    /// stop (or any poke) interrupt a pool reserve parked on provisioning;
    /// the dropped reserve future deregisters its pool waiter.
    async fn race<F: Future>(&self, seen: u64, fut: F) -> Option<F::Output> {
        let mut fut = core::pin::pin!(fut);
        core::future::poll_fn(|cx| {
            if let Poll::Ready(out) = fut.as_mut().poll(cx) {
                return Poll::Ready(Some(out));
            }
            if self.epoch() != seen {
                return Poll::Ready(None);
            }
            *self.waker.lock() = Some(cx.waker().clone());
            if self.epoch() != seen {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await
    }
}

pub struct AcceptPump {
    pool: &'static super::pool::NetPool,
    /// `Weak`: the wrapper owns the native listener's lifetime; the pump
    /// exits when it is gone (or on [`stop`](Self::stop), which is eager).
    listener: Weak<TcpListener>,
    /// The vDSO backlog (design 6.5): the ready-queue depth the pump keeps
    /// fed. Zero -- the initial state -- means unarmed: nothing is donated
    /// until `listen()` or the nonblocking arming sets a depth.
    backlog: AtomicU32,
    stopped: AtomicBool,
    signal: PumpSignal,
}

impl AcceptPump {
    pub fn new(pool: &'static super::pool::NetPool, listener: Weak<TcpListener>) -> Arc<Self> {
        Arc::new(Self {
            pool,
            listener,
            backlog: AtomicU32::new(0),
            stopped: AtomicBool::new(false),
            signal: PumpSignal::new(),
        })
    }

    /// The level may have changed; wake the pump to recompute.
    pub fn poke(&self) {
        self.signal.raise();
    }

    /// A host-owned listener never calls native `listen()`; the pump's
    /// backlog is the vDSO backlog the `listen()` ABI configures.
    pub fn set_backlog(&self, backlog: u32) {
        self.backlog.store(backlog, Ordering::Release);
        self.signal.raise();
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.signal.raise();
    }

    /// The pump task (design 6.5): keep one donation standing while the
    /// ready queue is below the backlog, park otherwise. Reservations
    /// obtained after a stop are simply dropped -- releasing a never-posted
    /// slot is free.
    pub async fn run(self: Arc<Self>) {
        loop {
            // The epoch is read before the level: a poke landing during
            // the computation re-runs the loop instead of being lost.
            let seen = self.signal.epoch();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            let Some(listener) = self.listener.upgrade() else {
                return;
            };

            let (requests, ready) = listener.accept_load();
            let backlog = self.backlog.load(Ordering::Acquire) as usize;
            if requests == 0 && ready < backlog {
                match self.signal.race(seen, self.pool.reserve()).await {
                    None => continue, // Poked mid-reserve; recompute.
                    Some(Ok(reservation)) => {
                        if self.stopped.load(Ordering::Acquire) {
                            return;
                        }
                        listener.post_accept(reservation);
                        continue;
                    }
                    Some(Err(err)) => {
                        // Park until the next poke rather than dying or
                        // spinning -- the connect budget inside reserve()
                        // already spent ~10s (sys-io-unavailable coverage:
                        // net_driver::test_sys_io_unavailable_fails_all).
                        crate::moto_log!("rt_net: accept pump reservation failed: {err:?}");
                    }
                }
            }

            // Do not hold the native listener across the park.
            drop(listener);
            self.signal.changed(seen).await;
        }
    }
}
