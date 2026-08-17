//! How large a listening-socket pool may grow under demand.
//!
//! A listener pre-creates `DEFAULT_NUM_LISTENING_SOCKETS` sockets per address it
//! binds, and a socket that takes a SYN is replaced one for one. Between the
//! netstack taking a SYN and the executor running that replacement lies a whole
//! `poll()`, so a burst arriving together can only ever be as deep as the pool.
//! Measured against the default pool of 4, half of sixteen simultaneous connects
//! found no socket in `Listen`; each of them was reset, and an RST is terminal
//! for the peer. Such a request is now dropped instead, so the peer retransmits
//! into whatever the pool has grown to by then -- a port nothing listens on
//! keeps its reset.
//!
//! Sizing the pool for bursts up front is what costs: the rings are committed
//! when the socket is created, so a pool of 32 is 8 MiB standing idle on a
//! listener that never sees a second connection. Instead the pool starts at what
//! the client asked for and doubles whenever a burst drains it, up to a cap --
//! demand pays for the memory, and only the first burst of a given depth is
//! refused.
//!
//! Growth is bounded twice. Per pool, so one listener cannot commit more than it
//! could have requested at bind; and globally over the *extra* sockets growth
//! added, so many listeners cannot each grow to their own cap. The base pools
//! are never charged against the global bound: a bind must not fail because
//! somebody else's listener grew.
//!
//! Growth is also returned. A sweep every [`SWEEP_INTERVAL`] takes back the
//! sockets that sat in `Listen` through a whole window, down to what the client
//! asked for at bind, so one burst -- or a scan of a few dozen ports -- does not
//! pin the memory for the listener's life. The sweep exists only while there is
//! growth to reclaim: the first growth arms it and the sweep that finds the
//! global bound empty again ends it, so a VM that never meets a burst never runs
//! a timer, and boot arms nothing.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::time::Duration;

use super::stats::NetStats;

/// How long a socket must sit unused before a sweep may take it back. Two
/// windows pass between a burst and the return of what it added: the window the
/// burst is in saw the pool drained, so it returns nothing. Long enough that the
/// bursts of one page load keep the depth they paid for; short enough that the
/// memory does not outlast the traffic by much.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// At 256 KiB per listening socket, 32 MiB of growth across all listeners.
/// `max_backlog_global` in `/system/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_BACKLOG_GLOBAL: NonZeroUsize = NonZeroUsize::new(128).unwrap();

/// Growth stops where an explicit request would have been refused: this matches
/// `MAX_NUM_LISTENING_SOCKETS`, 8 MiB per address. `max_backlog_per_listener` in
/// `/system/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_BACKLOG_PER_LISTENER: NonZeroUsize = NonZeroUsize::new(32).unwrap();

/// A listener binds one pool per address, so the address is part of the key.
pub(super) type PoolKey = (u64, SocketAddr);

struct Pool {
    /// What the client asked for at bind. Never charged globally, and the floor
    /// a shrink may return to.
    base: usize,
    /// How many sockets replenishment currently aims to keep in `Listen`.
    target: usize,
    /// How many are in `Listen` right now.
    listening: usize,
    /// The smallest `listening` demand drove this pool to since the last sweep.
    /// Sockets that sat above it through the whole window are what a sweep
    /// returns: they were never needed.
    low_water: usize,
    /// Sockets a sweep dropped whose departures have not arrived yet. They
    /// reach [`BacklogBudget::left_listen`] like any other, and must be read as
    /// neither demand nor exhaustion -- a pool shrunk to what it uses would
    /// otherwise take its own reclamation for a burst and double straight back.
    reclaiming: usize,
}

/// Per-pool targets and the global bound on what growth added.
pub(super) struct BacklogBudget {
    /// Growth beyond the base, summed over pools, stops here. The type excludes
    /// zero, which would be a config that reads as "no global room" -- every
    /// pool pinned to its base, which is the behavior this module exists to fix.
    max_global_extra: NonZeroUsize,
    max_per_pool: NonZeroUsize,

    extra: Cell<usize>,
    pools: RefCell<HashMap<PoolKey, Pool>>,

    /// Where [`Self::extra`] is published, so what the global bound holds is
    /// visible without a debug build.
    stats: Rc<NetStats>,

    /// Whether a sweep task is running. It is spawned by the growth that first
    /// makes `extra` nonzero and ends when a sweep leaves it zero again.
    sweeping: Cell<bool>,
}

impl BacklogBudget {
    pub(super) fn new(
        stats: Rc<NetStats>,
        max_global_extra: NonZeroUsize,
        max_per_pool: NonZeroUsize,
    ) -> Self {
        Self {
            max_global_extra,
            max_per_pool,
            extra: Cell::new(0),
            pools: RefCell::new(HashMap::new()),
            stats,
            sweeping: Cell::new(false),
        }
    }

    fn set_extra(&self, extra: usize) {
        self.extra.set(extra);
        self.stats.tcp_backlog_extra.set(extra as u64);
    }

    /// Register a pool at bind, with the size the client asked for.
    pub(super) fn open(&self, key: PoolKey, base: usize) {
        self.pools.borrow_mut().insert(
            key,
            Pool {
                base,
                target: base,
                listening: 0,
                low_water: 0,
                reclaiming: 0,
            },
        );
    }

    /// Drop a pool and return what it held globally. Called once the listener
    /// can no longer replenish, or its growth is charged for the process's life.
    pub(super) fn close(&self, key: PoolKey) {
        if let Some(pool) = self.pools.borrow_mut().remove(&key) {
            self.set_extra(self.extra.get().saturating_sub(pool.target - pool.base));
        }
    }

    /// A socket of `key` entered `Listen`.
    pub(super) fn entered_listen(&self, key: PoolKey) {
        if let Some(pool) = self.pools.borrow_mut().get_mut(&key) {
            pool.listening += 1;
        }
    }

    /// A socket of `key` left `Listen`, having taken a SYN or died trying.
    ///
    /// A pool that hits zero doubles: emptying is the last warning before a
    /// request is refused, and growing now costs a connection less than
    /// growing after. Exhaustion rather than a rate is the trigger, so a pool
    /// that never empties never grows, however busy -- but it is only half the
    /// signal, and [`Self::refused`] is the other half.
    pub(super) fn left_listen(&self, key: PoolKey) {
        let mut pools = self.pools.borrow_mut();
        let Some(pool) = pools.get_mut(&key) else {
            return;
        };
        pool.listening = pool.listening.saturating_sub(1);

        // A socket a sweep dropped, leaving the way one that took a SYN does.
        // It is this pool's own reclamation: neither demand for the window's
        // low-water mark nor evidence that the pool was too shallow.
        if pool.reclaiming > 0 {
            pool.reclaiming -= 1;
            return;
        }

        pool.low_water = pool.low_water.min(pool.listening);
        if pool.listening == 0 {
            self.grow(pool);
        }
    }

    /// A connection request for `addr` found no socket in `Listen`.
    ///
    /// This is the exhaustion [`Self::left_listen`] can miss, and the reason it
    /// cannot be the only trigger: the netstack hands out and refuses SYNs
    /// inside one poll, while the departures it caused are counted afterwards,
    /// interleaved with the replenishment each one spawns. A pool that was
    /// empty for the netstack can therefore never read zero here. A refused
    /// request is the unambiguous evidence, and it also says the pool used
    /// everything it had, so the window's low-water mark goes with it.
    pub(super) fn refused(&self, addr: SocketAddr) {
        let mut pools = self.pools.borrow_mut();
        let Some((_, pool)) = pools
            .iter_mut()
            .find(|((_, pool_addr), _)| *pool_addr == addr)
        else {
            // The netstack reports only endpoints a listener owns, so this is
            // the listener going away between that poll and this: there is no
            // pool left to deepen.
            return;
        };
        pool.low_water = 0;
        self.grow(pool);
    }

    /// Double a pool that demand has outrun, within both bounds.
    fn grow(&self, pool: &mut Pool) {
        // A client may bind a pool deeper than the configured growth cap, so the
        // cap is a ceiling on growth, never a reason to aim below the base.
        let room = self.max_global_extra.get().saturating_sub(self.extra.get());
        let target = pool
            .target
            .saturating_mul(2)
            .min(self.max_per_pool.get().max(pool.base))
            .min(pool.target + room);
        self.set_extra(self.extra.get() + (target - pool.target));
        pool.target = target;
    }

    /// Whether the caller must start a sweep task: there is growth to return
    /// and nothing is returning it. Claims the task, so two callers racing
    /// cannot both start one.
    pub(super) fn needs_sweeper(&self) -> bool {
        if self.extra.get() == 0 || self.sweeping.get() {
            return false;
        }
        self.sweeping.set(true);
        true
    }

    /// Take back the growth no burst used in the last window.
    ///
    /// Returns how many sockets each pool must drop, and whether any growth is
    /// left to sweep. Lowering the target alone frees the global bound at once
    /// and stops replacement, so a busy pool's surplus drains as connections
    /// arrive -- but a pool that grew and then went quiet holds its sockets
    /// until something takes them, and that pool is why this exists.
    pub(super) fn sweep(&self) -> (Vec<(PoolKey, usize)>, bool) {
        let mut drops = Vec::new();
        let mut extra = self.extra.get();

        for (key, pool) in self.pools.borrow_mut().iter_mut() {
            // Down to what was actually used, never below what was asked for,
            // and never more sockets than are there to drop.
            let unused = pool
                .low_water
                .min(pool.target - pool.base)
                .min(pool.listening);
            pool.target -= unused;
            pool.low_water = pool.listening - unused;
            extra = extra.saturating_sub(unused);
            if unused > 0 {
                pool.reclaiming += unused;
                drops.push((*key, unused));
            }
        }

        self.set_extra(extra);
        self.sweeping.set(extra > 0);
        (drops, extra > 0)
    }

    /// How many sockets replenishment should create for `key` right now.
    ///
    /// Replenishment is driven by departures, and every departure asks: the
    /// first to run covers the whole deficit and the rest find none, so a burst
    /// costs one refill rather than one per socket.
    pub(super) fn deficit(&self, key: PoolKey) -> usize {
        self.pools
            .borrow()
            .get(&key)
            .map_or(0, |pool| pool.target.saturating_sub(pool.listening))
    }
}

/// Return unused growth every [`SWEEP_INTERVAL`] until there is none left.
///
/// Started by the growth that first charges the global bound (see
/// [`BacklogBudget::left_listen`]), so an idle VM arms no timer.
pub(super) fn spawn_sweeper(runtime: super::NetRuntime) {
    moto_async::LocalRuntime::spawn(async move {
        loop {
            moto_async::sleep(SWEEP_INTERVAL).await;
            let (drops, more) = runtime.backlog.sweep();
            for (key, count) in drops {
                super::tcp_listener::TcpListener::shrink_pool(&runtime, key, count);
            }
            if !more {
                return;
            }
        }
    });
}

/// The full-OS side of this is a burst of simultaneous connects, which moves the
/// pool but cannot construct a window's worth of quiet around it. See
/// [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        ("net::backlog::refills_to_the_base", refills_to_the_base),
        ("net::backlog::doubles_on_exhaustion", doubles_on_exhaustion),
        (
            "net::backlog::stops_at_the_per_pool_cap",
            stops_at_the_per_pool_cap,
        ),
        (
            "net::backlog::stops_at_the_global_cap",
            stops_at_the_global_cap,
        ),
        ("net::backlog::keeps_pools_apart", keeps_pools_apart),
        (
            "net::backlog::returns_growth_on_close",
            returns_growth_on_close,
        ),
        (
            "net::backlog::ignores_an_unknown_pool",
            ignores_an_unknown_pool,
        ),
        ("net::backlog::sweeps_unused_growth", sweeps_unused_growth),
        (
            "net::backlog::keeps_the_growth_a_burst_used",
            keeps_the_growth_a_burst_used,
        ),
        (
            "net::backlog::does_not_regrow_on_its_own_sweep",
            does_not_regrow_on_its_own_sweep,
        ),
        (
            "net::backlog::sweeps_only_while_growth_stands",
            sweeps_only_while_growth_stands,
        ),
        (
            "net::backlog::grows_on_a_refused_request",
            grows_on_a_refused_request,
        ),
        (
            "net::backlog::ignores_a_refusal_it_owns_no_pool_for",
            ignores_a_refusal_it_owns_no_pool_for,
        ),
    ];

    const BASE: usize = 4;

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(std::net::Ipv4Addr::new(10, 0, 0, last).into(), 80)
    }

    fn key(id: u64) -> PoolKey {
        (id, addr(1))
    }

    fn budget() -> BacklogBudget {
        BacklogBudget::new(
            Rc::new(NetStats::default()),
            DEFAULT_MAX_BACKLOG_GLOBAL,
            DEFAULT_MAX_BACKLOG_PER_LISTENER,
        )
    }

    /// Fill a pool to its target, then drain `count` sockets out of `Listen`.
    fn cycle(budget: &BacklogBudget, key: PoolKey, count: usize) {
        for _ in 0..budget.deficit(key) {
            budget.entered_listen(key);
        }
        for _ in 0..count {
            budget.left_listen(key);
        }
    }

    fn refills_to_the_base() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);

        // A fresh pool owes its whole base, and owes nothing once created.
        st_assert_eq!(budget.deficit(key(1)), BASE);
        cycle(&budget, key(1), 0);
        st_assert_eq!(budget.deficit(key(1)), 0);

        // One connection taken, one socket owed back -- no growth, because the
        // pool still has sockets left for the next SYN.
        budget.left_listen(key(1));
        st_assert_eq!(budget.deficit(key(1)), 1);
        Ok(())
    }

    fn doubles_on_exhaustion() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);

        // A burst that empties the pool leaves it owing twice its base.
        cycle(&budget, key(1), BASE);
        st_assert_eq!(budget.deficit(key(1)), BASE * 2);

        // And again, once the deeper pool is itself drained.
        cycle(&budget, key(1), BASE * 2);
        st_assert_eq!(budget.deficit(key(1)), BASE * 4);
        Ok(())
    }

    fn stops_at_the_per_pool_cap() -> Result<(), String> {
        let budget = budget();
        let cap = DEFAULT_MAX_BACKLOG_PER_LISTENER.get();
        budget.open(key(1), BASE);

        for _ in 0..10 {
            let depth = budget.deficit(key(1));
            cycle(&budget, key(1), depth.max(1));
        }
        st_assert_eq!(budget.deficit(key(1)), cap);

        // A client that asked for the maximum has nowhere to grow, and must not
        // charge the global bound for growth it did not get.
        budget.open(key(2), cap);
        cycle(&budget, key(2), cap);
        st_assert_eq!(budget.deficit(key(2)), cap);
        st_assert_eq!(budget.extra.get(), cap - BASE);
        Ok(())
    }

    fn stops_at_the_global_cap() -> Result<(), String> {
        let nz = |n| NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN);
        let budget = BacklogBudget::new(Rc::new(NetStats::default()), nz(5), nz(32));
        budget.open(key(1), BASE);
        budget.open(key(2), BASE);

        // The first pool doubles, spending 4 of the 5 extra sockets available.
        cycle(&budget, key(1), BASE);
        st_assert_eq!(budget.deficit(key(1)), BASE * 2);
        st_assert_eq!(budget.extra.get(), 4);

        // The second gets the one that is left rather than its full double, and
        // then nothing: the bound holds across pools, not per pool.
        cycle(&budget, key(2), BASE);
        st_assert_eq!(budget.deficit(key(2)), BASE + 1);
        cycle(&budget, key(2), BASE + 1);
        st_assert_eq!(budget.deficit(key(2)), BASE + 1);
        st_assert_eq!(budget.extra.get(), 5);
        Ok(())
    }

    fn keeps_pools_apart() -> Result<(), String> {
        let budget = budget();
        let other = (1u64, addr(2));
        budget.open(key(1), BASE);
        budget.open(other, BASE);

        // Same listener, two addresses: draining one leaves the other's pool
        // untouched, since each address takes its own SYNs.
        cycle(&budget, key(1), BASE);
        st_assert_eq!(budget.deficit(key(1)), BASE * 2);
        st_assert_eq!(budget.deficit(other), BASE);
        Ok(())
    }

    fn returns_growth_on_close() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        cycle(&budget, key(1), BASE);
        st_assert!(budget.extra.get() > 0);

        // A listener that goes away must hand its growth back, or the global
        // bound ratchets closed as listeners come and go.
        budget.close(key(1));
        st_assert_eq!(budget.extra.get(), 0);
        st_assert!(budget.pools.borrow().is_empty());

        // Closing twice is not a client-triggerable underflow.
        budget.close(key(1));
        st_assert_eq!(budget.extra.get(), 0);
        Ok(())
    }

    fn ignores_an_unknown_pool() -> Result<(), String> {
        let budget = budget();

        // Teardown races the listen tasks: a socket can leave `Listen` after
        // its listener closed the pool. That owes nothing and must not
        // resurrect an entry, which would leak for the process's life.
        budget.entered_listen(key(9));
        budget.left_listen(key(9));
        budget.refused(addr(1));
        st_assert_eq!(budget.deficit(key(9)), 0);
        st_assert!(budget.pools.borrow().is_empty());
        Ok(())
    }

    fn sweeps_unused_growth() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        cycle(&budget, key(1), BASE);
        cycle(&budget, key(1), 0);
        st_assert_eq!(budget.extra.get(), BASE);

        // The window the burst is in returns nothing: the pool was drained in
        // it, so every socket it holds was wanted.
        let (drops, more) = budget.sweep();
        st_assert!(drops.is_empty());
        st_assert!(more);

        // A quiet window returns the growth, down to what was asked for at
        // bind and no further.
        let (drops, more) = budget.sweep();
        st_assert_eq!(drops, vec![(key(1), BASE)]);
        st_assert!(!more);
        st_assert_eq!(budget.extra.get(), 0);

        // The target fell with it, so nothing replaces what the sweep drops.
        for _ in 0..BASE {
            budget.left_listen(key(1));
        }
        st_assert_eq!(budget.deficit(key(1)), 0);
        Ok(())
    }

    fn keeps_the_growth_a_burst_used() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        cycle(&budget, key(1), BASE);
        cycle(&budget, key(1), 0);
        let (drops, _) = budget.sweep();
        st_assert!(drops.is_empty());

        // Six of the eight taken in this window, all replaced: a sweep returns
        // what sat unused, not what demand was using.
        cycle(&budget, key(1), 6);
        cycle(&budget, key(1), 0);
        let (drops, more) = budget.sweep();
        st_assert_eq!(drops, vec![(key(1), 2)]);
        st_assert!(more);
        st_assert_eq!(budget.extra.get(), 2);
        Ok(())
    }

    fn does_not_regrow_on_its_own_sweep() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        cycle(&budget, key(1), BASE);

        // Only half the deficit is created -- which is what the half-open cap
        // does to a pool -- so a sweep can drop every socket it has.
        for _ in 0..BASE {
            budget.entered_listen(key(1));
        }
        let (drops, _) = budget.sweep();
        st_assert!(drops.is_empty());
        let (drops, more) = budget.sweep();
        st_assert_eq!(drops, vec![(key(1), BASE)]);
        st_assert!(!more);

        // The departures the sweep asked for arrive and empty the pool. A pool
        // must not read its own reclamation as a burst it was too shallow for.
        for _ in 0..BASE {
            budget.left_listen(key(1));
        }
        st_assert_eq!(budget.extra.get(), 0);
        st_assert_eq!(budget.deficit(key(1)), BASE);
        Ok(())
    }

    fn grows_on_a_refused_request() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        cycle(&budget, key(1), 0);
        // A quiet window, so the pool has a low-water mark to lose below.
        let (drops, _) = budget.sweep();
        st_assert!(drops.is_empty());

        // The pool is full as far as its own accounting knows -- the netstack
        // took and refused SYNs inside a poll that has not been accounted for
        // yet -- so nothing but the refusal itself can deepen it.
        st_assert_eq!(budget.deficit(key(1)), 0);
        budget.refused(addr(1));
        st_assert_eq!(budget.deficit(key(1)), BASE);
        st_assert_eq!(budget.extra.get(), BASE);
        st_assert!(budget.needs_sweeper());

        // A pool that lost a request used everything it had, so the window it
        // was in holds nothing back for the sweep to take: growth answering a
        // refusal must survive the sweep that follows it.
        cycle(&budget, key(1), 0);
        let (drops, _) = budget.sweep();
        st_assert!(drops.is_empty());
        st_assert_eq!(budget.extra.get(), BASE);
        Ok(())
    }

    fn ignores_a_refusal_it_owns_no_pool_for() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        cycle(&budget, key(1), 0);

        // A listener that went away between the poll that lost the request and
        // the drain that reports it owns no pool any more, and must not deepen
        // somebody else's.
        budget.refused(addr(2));
        st_assert_eq!(budget.deficit(key(1)), 0);
        st_assert_eq!(budget.extra.get(), 0);
        st_assert!(!budget.needs_sweeper());
        Ok(())
    }

    fn sweeps_only_while_growth_stands() -> Result<(), String> {
        let budget = budget();
        budget.open(key(1), BASE);
        for _ in 0..BASE {
            budget.entered_listen(key(1));
        }

        // A departure that leaves sockets behind grows nothing, and an idle VM
        // must not be given a timer for nothing.
        for _ in 0..(BASE - 1) {
            budget.left_listen(key(1));
            st_assert!(!budget.needs_sweeper());
        }
        budget.left_listen(key(1));
        st_assert!(budget.needs_sweeper());

        // Further growth joins the running sweep rather than starting a second.
        for _ in 0..budget.deficit(key(1)) {
            budget.entered_listen(key(1));
        }
        for _ in 0..(BASE * 2) {
            budget.left_listen(key(1));
        }
        st_assert!(budget.extra.get() > BASE);
        st_assert!(!budget.needs_sweeper());

        // The sweep that leaves nothing charged ends, and the next growth after
        // that starts a fresh one.
        cycle(&budget, key(1), 0);
        let (_, more) = budget.sweep();
        st_assert!(more);
        let (drops, more) = budget.sweep();
        st_assert!(!more);
        st_assert!(!budget.sweeping.get());

        for _ in 0..drops[0].1 {
            budget.left_listen(key(1));
        }
        cycle(&budget, key(1), BASE - 1);
        st_assert!(!budget.needs_sweeper());
        budget.left_listen(key(1));
        st_assert!(budget.needs_sweeper());
        Ok(())
    }
}
