//! Memory pressure mode: while the kernel's `memory_pressure` flag (in
//! `KernelStaticPage`) is raised, sys-io refuses new memory-growing work --
//! new clients, new sockets -- so its demand stops before the kernel starts
//! refusing it, which would abort sys-io (a failed global-allocator call
//! cannot be reported).
//!
//! The kernel owns the watermarks and the hysteresis; every check here is one
//! shared-page load. The recovery task exists only to re-arm parked
//! listening-pool replenishments once the flag clears.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::task::{Poll, Waker};

use super::backlog::PoolKey;
use super::stats::NetStats;
use super::tcp_listener::TcpListener;

/// How often the recovery task re-reads the flag while an observed episode
/// lasts. Bounds how long a cleared flag can keep replenishment parked.
const RECOVERY_POLL: core::time::Duration = core::time::Duration::from_millis(500);

/// One shared-page load: the kernel's current verdict.
pub(super) fn active() -> bool {
    moto_sys::memory_pressure()
}

/// What a parked listening-pool replenishment needs to resume; see
/// [`super::socket::tcp::replenish_pool`].
struct ParkedReplenish {
    listener: Weak<RefCell<TcpListener>>,
    device_idx: usize,
    socket_addr: SocketAddr,
}

pub(super) struct Pressure {
    /// Whether sys-io has noticed the current episode: the edge on which the
    /// entries metric counts and the recovery task wakes.
    observed: Cell<bool>,

    /// Keyed by pool, so what pressure mode holds is bounded by the number of
    /// listening pools, not by how many departures happened while it was on.
    parked: RefCell<BTreeMap<PoolKey, ParkedReplenish>>,

    /// The recovery task parks here between observed episodes.
    recovery_waker: Cell<Option<Waker>>,

    stats: Rc<NetStats>,
}

impl Pressure {
    pub(super) fn new(stats: Rc<NetStats>) -> Self {
        // The watermarks are kernel policy; queried once, for metrics only.
        let adm = moto_sys::stats::AdmissionStats::get()
            .expect("the admission-stats query cannot fail on a live kernel");
        stats.pressure_low_pages.set(adm.pressure_low_pages);
        stats.pressure_high_pages.set(adm.pressure_high_pages);

        Self {
            observed: Cell::new(false),
            parked: RefCell::new(BTreeMap::new()),
            recovery_waker: Cell::new(None),
            stats,
        }
    }

    /// The synchronous check before a memory-growing request. Refusal must
    /// not allocate; the caller sends the error on the existing channel.
    pub(super) fn admit(&self) -> std::io::Result<()> {
        if !active() {
            return Ok(());
        }

        self.note_observed();
        self.stats
            .pressure_refused
            .set(self.stats.pressure_refused.get() + 1);
        Err(ErrorKind::OutOfMemory.into())
    }

    /// A new client connection arrived under pressure and is being dropped.
    pub(super) fn client_refused(&self) {
        self.note_observed();
        self.stats
            .pressure_refused_clients
            .set(self.stats.pressure_refused_clients.get() + 1);
    }

    /// Under pressure a departing listening socket is not replaced; the
    /// pool's replenishment parks here until the flag clears.
    pub(super) fn defer_replenish(
        &self,
        key: PoolKey,
        listener: &Weak<RefCell<TcpListener>>,
        device_idx: usize,
        socket_addr: SocketAddr,
    ) -> bool {
        if !active() {
            return false;
        }

        self.note_observed();
        self.stats
            .pressure_deferred_replenish
            .set(self.stats.pressure_deferred_replenish.get() + 1);
        self.parked
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| ParkedReplenish {
                listener: listener.clone(),
                device_idx,
                socket_addr,
            });
        true
    }

    /// The first observation of an episode counts it and wakes the recovery
    /// task. Must not allocate: it runs on refusal paths.
    fn note_observed(&self) {
        if self.observed.replace(true) {
            return;
        }
        self.stats
            .pressure_entries
            .set(self.stats.pressure_entries.get() + 1);
        if let Some(waker) = self.recovery_waker.take() {
            waker.wake();
        }
    }

    fn rearm(&self, runtime: &super::NetRuntime) {
        let parked = core::mem::take(&mut *self.parked.borrow_mut());
        for (key, p) in parked {
            super::socket::tcp::replenish_pool(
                runtime.clone(),
                p.listener,
                p.device_idx,
                p.socket_addr,
                key,
            );
        }
    }
}

/// Parked until sys-io observes a pressure episode. It then re-reads the flag
/// every [`RECOVERY_POLL`] until the kernel clears it, re-arms what was
/// parked, and parks itself again.
pub(super) fn spawn_recovery(runtime: super::NetRuntime) {
    moto_async::LocalRuntime::spawn(async move {
        let pressure = runtime.pressure.clone();
        loop {
            core::future::poll_fn(|cx| {
                if pressure.observed.get() {
                    Poll::Ready(())
                } else {
                    pressure.recovery_waker.set(Some(cx.waker().clone()));
                    Poll::Pending
                }
            })
            .await;

            while active() {
                moto_async::sleep(RECOVERY_POLL).await;
            }

            // Reset the edge before re-arming: an episode starting mid-rearm
            // must find it clear, or its parks would wait on a spent waker.
            pressure.observed.set(false);
            pressure.rearm(&runtime);
            log::info!(
                "sys-io: memory pressure cleared; refusals so far: {} requests, {} clients",
                pressure.stats.pressure_refused.get(),
                pressure.stats.pressure_refused_clients.get()
            );
        }
    });
}
