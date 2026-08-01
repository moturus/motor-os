//! How large a listening-socket pool may grow under demand.
//!
//! A listener pre-creates `DEFAULT_NUM_LISTENING_SOCKETS` sockets per address it
//! binds, and a socket that takes a SYN is replaced one for one. Between the
//! netstack taking a SYN and the executor running that replacement lies a whole
//! `poll()`, so a burst arriving together can only ever be as deep as the pool:
//! the SYN that finds no socket in `Listen` is reset, and an RST is terminal for
//! the peer. Measured against the default pool of 4, half of sixteen
//! simultaneous connects were refused.
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

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;

/// At 256 KiB per listening socket, 32 MiB of growth across all listeners.
/// `max_backlog_global` in `/sys/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_BACKLOG_GLOBAL: NonZeroUsize = NonZeroUsize::new(128).unwrap();

/// Growth stops where an explicit request would have been refused: this matches
/// `MAX_NUM_LISTENING_SOCKETS`, 8 MiB per address. `max_backlog_per_listener` in
/// `/sys/cfg/sys-net.toml` overrides it.
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
}

impl BacklogBudget {
    pub(super) fn new(max_global_extra: NonZeroUsize, max_per_pool: NonZeroUsize) -> Self {
        Self {
            max_global_extra,
            max_per_pool,
            extra: Cell::new(0),
            pools: RefCell::new(HashMap::new()),
        }
    }

    /// Register a pool at bind, with the size the client asked for.
    pub(super) fn open(&self, key: PoolKey, base: usize) {
        self.pools.borrow_mut().insert(
            key,
            Pool {
                base,
                target: base,
                listening: 0,
            },
        );
    }

    /// Drop a pool and return what it held globally. Called once the listener
    /// can no longer replenish, or its growth is charged for the process's life.
    pub(super) fn close(&self, key: PoolKey) {
        if let Some(pool) = self.pools.borrow_mut().remove(&key) {
            self.extra
                .set(self.extra.get().saturating_sub(pool.target - pool.base));
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
    /// A pool that hits zero was too shallow for the burst it just met, so it
    /// doubles. Growth is measured at the moment of exhaustion rather than
    /// against a rate: the pool that never empties never grows, however busy.
    pub(super) fn left_listen(&self, key: PoolKey) {
        let mut pools = self.pools.borrow_mut();
        let Some(pool) = pools.get_mut(&key) else {
            return;
        };
        pool.listening = pool.listening.saturating_sub(1);
        if pool.listening > 0 {
            return;
        }

        // A client may bind a pool deeper than the configured growth cap, so the
        // cap is a ceiling on growth, never a reason to aim below the base.
        let room = self.max_global_extra.get().saturating_sub(self.extra.get());
        let target = pool
            .target
            .saturating_mul(2)
            .min(self.max_per_pool.get().max(pool.base))
            .min(pool.target + room);
        self.extra.set(self.extra.get() + (target - pool.target));
        pool.target = target;
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

/// The full-OS side of this is a burst of simultaneous connects, which measures
/// the pool but cannot see the target it grew to. See [`crate::self_test`].
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
    ];

    const BASE: usize = 4;

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(std::net::Ipv4Addr::new(10, 0, 0, last).into(), 80)
    }

    fn key(id: u64) -> PoolKey {
        (id, addr(1))
    }

    fn budget() -> BacklogBudget {
        BacklogBudget::new(DEFAULT_MAX_BACKLOG_GLOBAL, DEFAULT_MAX_BACKLOG_PER_LISTENER)
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
        let budget = BacklogBudget::new(nz(5), nz(32));
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
        st_assert_eq!(budget.deficit(key(9)), 0);
        st_assert!(budget.pools.borrow().is_empty());
        Ok(())
    }
}
