//! The vDSO listener's accept pump (design 6.5).
//!
//! Stage 4 preparation, landed additively with [`super::pool`]: no listener
//! constructs a pump until the Stage 5 flip, which wires `run` onto the IO
//! runtime and `poke`/`stop` into the `RtTcpListener` wrapper -- its
//! readiness observer (a completion reached the ready queue) and its accept
//! shims (a caller claimed one).
//!
//! The pump is a level-driven policy loop: every wake it recomputes the
//! native listener's accept load from ground truth
//! (`TcpListener::outstanding_accepts`) and donates reservations while the
//! backlog has room. Nothing counts edges -- a completion handed straight
//! to a parked `accept()` caller raises no READABLE edge, so edge counters
//! would drift; a coalesced or spurious wake just recomputes.

use alloc::sync::{Arc, Weak};
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
}

pub struct AcceptPump {
    pool: &'static super::pool::NetPool,
    /// `Weak`: the wrapper owns the native listener's lifetime; the pump
    /// exits when it is gone (or on [`stop`](Self::stop), which is eager).
    listener: Weak<TcpListener>,
    backlog: AtomicU32,
    stopped: AtomicBool,
    signal: PumpSignal,
}

impl AcceptPump {
    pub fn new(
        pool: &'static super::pool::NetPool,
        listener: Weak<TcpListener>,
        backlog: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool,
            listener,
            backlog: AtomicU32::new(backlog),
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

    /// The pump task (design 6.5): donate while the backlog has room, park
    /// until poked. Reservations obtained after a stop are simply dropped
    /// -- releasing a never-posted slot is free.
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

            while listener.outstanding_accepts() < self.backlog.load(Ordering::Acquire) as usize {
                match self.pool.reserve().await {
                    Ok(reservation) => {
                        if self.stopped.load(Ordering::Acquire) {
                            return;
                        }
                        listener.post_accept(reservation);
                    }
                    Err(err) => {
                        // Provisional, flagged for Stage 5's
                        // sys-io-unavailable work: park until the next poke
                        // rather than dying or spinning -- the connect
                        // budget inside reserve() already spent ~10s.
                        crate::moto_log!("rt_net: accept pump reservation failed: {err:?}");
                        break;
                    }
                }
            }

            // Do not hold the native listener across the park.
            drop(listener);
            self.signal.changed(seen).await;
        }
    }
}
