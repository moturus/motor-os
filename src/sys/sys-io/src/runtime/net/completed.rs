//! Bounds established sockets waiting for an application to accept them.

use super::stats::NetStats;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    num::NonZeroUsize,
    rc::Rc,
};

/// 128 sockets at 256 KiB of default-sized rings: 32 MiB globally. Guests
/// below 256 MiB of RAM get a quarter (see [`super::config::ram_scaled`]).
pub(super) const DEFAULT_MAX_GLOBAL: NonZeroUsize = NonZeroUsize::new(128).unwrap();
/// One listener may hold at most 8 MiB of default-sized completed sockets.
pub(super) const DEFAULT_MAX_PER_LISTENER: NonZeroUsize = NonZeroUsize::new(32).unwrap();

pub(super) struct CompletedBacklog {
    stats: Rc<NetStats>,
    max_global: usize,
    max_per_listener: usize,
    global: Cell<usize>,
    per_listener: RefCell<HashMap<u64, usize>>,
}

impl CompletedBacklog {
    pub(super) fn new(
        stats: Rc<NetStats>,
        max_global: NonZeroUsize,
        max_per_listener: NonZeroUsize,
    ) -> Self {
        Self {
            stats,
            max_global: max_global.get(),
            max_per_listener: max_per_listener.get(),
            global: Cell::new(0),
            per_listener: RefCell::new(HashMap::new()),
        }
    }

    /// Reserve space for one completed connection, or count its refusal.
    pub(super) fn try_admit(&self, listener_id: u64) -> bool {
        let per_listener = self
            .per_listener
            .borrow()
            .get(&listener_id)
            .copied()
            .unwrap_or(0);
        if self.global.get() >= self.max_global || per_listener >= self.max_per_listener {
            self.stats
                .tcp_accept_overflow
                .set(self.stats.tcp_accept_overflow.get() + 1);
            return false;
        }

        let global = self.global.get() + 1;
        self.global.set(global);
        self.stats.tcp_accept_backlog.set(global as u64);
        *self
            .per_listener
            .borrow_mut()
            .entry(listener_id)
            .or_insert(0) += 1;
        true
    }

    pub(super) fn release(&self, listener_id: u64) {
        let global = self.global.get().checked_sub(1).unwrap();
        self.global.set(global);
        self.stats.tcp_accept_backlog.set(global as u64);

        let mut per_listener = self.per_listener.borrow_mut();
        let count = per_listener.get_mut(&listener_id).unwrap();
        *count -= 1;
        if *count == 0 {
            per_listener.remove(&listener_id);
        }
    }
}

#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        ("net::completed::caps_globally", caps_globally),
        ("net::completed::caps_each_listener", caps_each_listener),
        (
            "net::completed::release_restores_capacity",
            release_restores_capacity,
        ),
    ];

    const MAX_GLOBAL: usize = DEFAULT_MAX_GLOBAL.get();
    const MAX_PER_LISTENER: usize = DEFAULT_MAX_PER_LISTENER.get();

    fn budget() -> (Rc<NetStats>, CompletedBacklog) {
        let stats = Rc::new(NetStats::default());
        let budget =
            CompletedBacklog::new(stats.clone(), DEFAULT_MAX_GLOBAL, DEFAULT_MAX_PER_LISTENER);
        (stats, budget)
    }

    fn caps_globally() -> Result<(), String> {
        let (stats, budget) = budget();
        for listener_id in 0..(MAX_GLOBAL / MAX_PER_LISTENER) as u64 {
            for _ in 0..MAX_PER_LISTENER {
                st_assert!(budget.try_admit(listener_id));
            }
        }
        st_assert!(!budget.try_admit(99));
        st_assert_eq!(stats.tcp_accept_backlog.get(), MAX_GLOBAL as u64);
        st_assert_eq!(stats.tcp_accept_overflow.get(), 1);
        Ok(())
    }

    fn caps_each_listener() -> Result<(), String> {
        let (stats, budget) = budget();
        for _ in 0..MAX_PER_LISTENER {
            st_assert!(budget.try_admit(1));
        }
        st_assert!(!budget.try_admit(1));
        st_assert!(budget.try_admit(2));
        st_assert_eq!(
            stats.tcp_accept_backlog.get(),
            (MAX_PER_LISTENER + 1) as u64
        );
        Ok(())
    }

    fn release_restores_capacity() -> Result<(), String> {
        let (stats, budget) = budget();
        for _ in 0..MAX_PER_LISTENER {
            st_assert!(budget.try_admit(1));
        }
        budget.release(1);
        st_assert!(budget.try_admit(1));
        st_assert_eq!(stats.tcp_accept_backlog.get(), MAX_PER_LISTENER as u64);
        Ok(())
    }
}
