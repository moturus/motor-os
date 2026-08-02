//! How many listening sockets may sit in SYN-RECEIVED at once.
//!
//! A listening socket that has taken a peer's SYN holds its full 128 KiB
//! receive and transmit rings until the handshake finishes or the 15-second
//! timeout fires, and sys-io refills the listening pool as soon as a socket
//! leaves `Listen`. Unbounded, that is `SYN_rate * 15 s * 256 KiB` of memory
//! that unanswered SYNs command.
//!
//! What is capped is replenishment, not the SYN: by the time sys-io observes
//! `SynReceived` the netstack has already taken the segment. At the cap the
//! pool stops being refilled, so it drains, and further SYNs match no socket
//! and are reset by the netstack -- the same answer an honest client gets when
//! nothing is listening. Half-open sockets are therefore bounded by the cap
//! plus whatever was still listening when the cap was reached, not by the cap
//! alone.
//!
//! This is the seam SYN cookies engage on when they land: "cap hit -> cookie
//! mode" replaces "cap hit -> let the pool drain". Cookies need TCP timestamps
//! (window scale and SACK survive only in the timestamp option) and the keyed
//! hash from the RFC 6528 ISN work, so they come later. See
//! `docs/plans/core-safety-hardening.md`, item 6.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

/// At 256 KiB per half-open socket, 32 MiB. `max_half_open_global` in
/// `/sys/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_HALF_OPEN_GLOBAL: NonZeroUsize = NonZeroUsize::new(128).unwrap();

/// One listener cannot hold more sockets half-open than it may keep listening:
/// this matches `MAX_NUM_LISTENING_SOCKETS`, 8 MiB. `max_half_open_per_listener`
/// in `/sys/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_HALF_OPEN_PER_LISTENER: NonZeroUsize = NonZeroUsize::new(32).unwrap();

/// Half-open slots in use, and the replenishments the cap is holding back.
///
/// `T` is what a deferred replenishment needs to resume; sys-io parks the
/// oneshot that wakes a listening socket's replacement task. It is a type
/// parameter so this accounting can be tested without an executor.
pub(super) struct HalfOpenBudget<T> {
    /// Half-open sockets at which the listening pool stops being refilled.
    /// The type excludes zero, which would leave [`Self::release`] unable to
    /// ever resume a deferred replenishment: the pool would stay closed.
    max_global: NonZeroUsize,
    max_per_listener: NonZeroUsize,

    global: Cell<usize>,

    /// Per-listener counts. An entry is dropped when it reaches zero, so this
    /// cannot grow across a long-lived process as listener ids advance.
    per_listener: RefCell<HashMap<u64, usize>>,

    /// Replenishments held back at the cap, oldest first.
    deferred: RefCell<VecDeque<(u64, T)>>,
}

impl<T> HalfOpenBudget<T> {
    /// Build a budget with the configured caps. There is deliberately no
    /// `Default`: the caps come from `/sys/cfg/sys-net.toml`, and a
    /// zero-argument constructor is how one silently starts ignoring it.
    pub(super) fn new(max_global: NonZeroUsize, max_per_listener: NonZeroUsize) -> Self {
        Self {
            max_global,
            max_per_listener,
            global: Cell::new(0),
            per_listener: RefCell::new(HashMap::new()),
            deferred: RefCell::new(VecDeque::new()),
        }
    }

    /// Count one socket of `listener_id` into the budget.
    ///
    /// Returns whether the listening pool may be refilled right away. `false`
    /// means a cap is reached and the caller must hand its replenishment to
    /// [`Self::defer`], which resumes it once a slot frees.
    pub(super) fn admit(&self, listener_id: u64) -> bool {
        let global = self.global.get() + 1;
        self.global.set(global);

        let mut per_listener = self.per_listener.borrow_mut();
        let count = per_listener.entry(listener_id).or_insert(0);
        *count += 1;

        global < self.max_global.get() && *count < self.max_per_listener.get()
    }

    /// Park a replenishment that [`Self::admit`] refused to let through.
    pub(super) fn defer(&self, listener_id: u64, replenish: T) {
        self.deferred
            .borrow_mut()
            .push_back((listener_id, replenish));
    }

    /// Give back one slot, and return a replenishment to resume if the cap was
    /// holding one back. The caller resumes it, so no borrow of this struct is
    /// live while a parked task is woken.
    #[must_use]
    pub(super) fn release(&self, listener_id: u64) -> Option<T> {
        self.global.set(self.global.get().saturating_sub(1));

        let mut per_listener = self.per_listener.borrow_mut();
        if let Some(count) = per_listener.get_mut(&listener_id) {
            *count -= 1;
            if *count == 0 {
                per_listener.remove(&listener_id);
            }
        }

        if self.global.get() >= self.max_global.get() {
            return None;
        }

        // Oldest first, but skip listeners still at their own cap: a busy
        // listener must not hold the queue closed against the others.
        let max_per_listener = self.max_per_listener.get();
        let mut deferred = self.deferred.borrow_mut();
        let position = deferred
            .iter()
            .position(|(id, _)| per_listener.get(id).copied().unwrap_or(0) < max_per_listener)?;
        deferred.remove(position).map(|(_, replenish)| replenish)
    }

    #[cfg(debug_assertions)]
    fn deferred_len(&self) -> usize {
        self.deferred.borrow().len()
    }
}

/// These exercise the cap that patch 9's specified full-OS regression cannot:
/// nothing in the gate can hold a handshake in SYN-RECEIVED. See
/// [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        (
            "net::half_open::admits_up_to_the_global_cap",
            admits_up_to_the_global_cap,
        ),
        (
            "net::half_open::defers_beyond_the_global_cap",
            defers_beyond_the_global_cap,
        ),
        (
            "net::half_open::resumes_deferred_in_fifo_order",
            resumes_deferred_in_fifo_order,
        ),
        (
            "net::half_open::caps_each_listener_separately",
            caps_each_listener_separately,
        ),
        (
            "net::half_open::skips_a_listener_still_at_its_cap",
            skips_a_listener_still_at_its_cap,
        ),
        (
            "net::half_open::forgets_a_drained_listener",
            forgets_a_drained_listener,
        ),
        (
            "net::half_open::honors_configured_caps",
            honors_configured_caps,
        ),
    ];

    /// The compiled-in defaults, which most of these tests run against.
    const GLOBAL: usize = DEFAULT_MAX_HALF_OPEN_GLOBAL.get();
    const PER_LISTENER: usize = DEFAULT_MAX_HALF_OPEN_PER_LISTENER.get();

    fn budget() -> HalfOpenBudget<u32> {
        HalfOpenBudget::new(
            DEFAULT_MAX_HALF_OPEN_GLOBAL,
            DEFAULT_MAX_HALF_OPEN_PER_LISTENER,
        )
    }

    /// Spread admissions across enough listeners that only the global cap can
    /// be the one that bites.
    fn admit_globally(budget: &HalfOpenBudget<u32>, count: usize) -> usize {
        let per_listener = PER_LISTENER - 1;
        let mut replenished = 0;
        for i in 0..count {
            if budget.admit((i / per_listener) as u64) {
                replenished += 1;
            }
        }
        replenished
    }

    fn admits_up_to_the_global_cap() -> Result<(), String> {
        let budget = budget();

        // Every admission short of the cap leaves room for another, so the
        // pool keeps refilling and nothing is held back.
        let replenished = admit_globally(&budget, GLOBAL - 1);
        st_assert_eq!(replenished, GLOBAL - 1);
        st_assert_eq!(budget.deferred_len(), 0);
        Ok(())
    }

    fn defers_beyond_the_global_cap() -> Result<(), String> {
        let budget = budget();

        // The admission that reaches the cap is the first one refused: it is
        // admitted, but the pool it came from is not refilled.
        let replenished = admit_globally(&budget, GLOBAL + 8);
        st_assert_eq!(replenished, GLOBAL - 1);
        Ok(())
    }

    fn resumes_deferred_in_fifo_order() -> Result<(), String> {
        let budget = budget();
        st_assert!(admit_globally(&budget, GLOBAL) < GLOBAL);

        budget.defer(0, 10);
        budget.defer(0, 11);
        budget.defer(0, 12);

        // One slot back, one replenishment resumed, oldest first.
        st_assert_eq!(budget.release(0), Some(10));
        st_assert_eq!(budget.deferred_len(), 2);
        st_assert_eq!(budget.release(0), Some(11));
        st_assert_eq!(budget.release(0), Some(12));

        // Nothing parked, nothing to resume.
        st_assert_eq!(budget.release(0), None);
        Ok(())
    }

    fn caps_each_listener_separately() -> Result<(), String> {
        let budget = budget();

        // One listener runs itself out of per-listener slots...
        let mut replenished = 0;
        for _ in 0..PER_LISTENER {
            if budget.admit(1) {
                replenished += 1;
            }
        }
        st_assert_eq!(replenished, PER_LISTENER - 1);

        // ...without spending another listener's, well short of the global cap.
        st_assert!(budget.admit(2));
        st_assert!(budget.admit(2));
        Ok(())
    }

    fn skips_a_listener_still_at_its_cap() -> Result<(), String> {
        let budget = budget();
        for _ in 0..PER_LISTENER {
            let _ = budget.admit(1);
        }
        let _ = budget.admit(2);

        // Listener 1 parked first, but is still at its own cap after listener
        // 2 hands a slot back, so listener 2 resumes instead of waiting behind
        // a listener that cannot use the slot.
        budget.defer(1, 10);
        budget.defer(2, 20);
        st_assert_eq!(budget.release(2), Some(20));

        // Once listener 1 drops below its cap it resumes too.
        st_assert_eq!(budget.release(1), Some(10));
        Ok(())
    }

    fn forgets_a_drained_listener() -> Result<(), String> {
        let budget = budget();
        st_assert!(budget.admit(7));
        st_assert_eq!(budget.release(7), None);

        // A listener that gave everything back leaves nothing behind: ids only
        // ever advance, so a retained entry would leak for the process's life.
        st_assert!(budget.per_listener.borrow().is_empty());

        // Releasing more than was taken must not underflow into a huge count,
        // which would wedge the cap closed forever.
        st_assert_eq!(budget.release(7), None);
        st_assert_eq!(budget.global.get(), 0);
        st_assert!(budget.admit(7));
        Ok(())
    }

    /// Both caps come from `/sys/cfg/sys-net.toml`, so a budget must enforce
    /// the numbers it was built with. These are small enough that the
    /// compiled-in defaults would let every admission through.
    fn honors_configured_caps() -> Result<(), String> {
        let nz = |n| NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN);
        let budget = HalfOpenBudget::<u32>::new(nz(3), nz(2));

        st_assert!(budget.admit(1));
        st_assert!(!budget.admit(1)); // Listener 1 took its second and last.
        st_assert!(!budget.admit(2)); // Third slot globally, on a fresh listener.

        // Resuming measures against the configured caps too.
        budget.defer(2, 20);
        st_assert_eq!(budget.release(1), Some(20));
        Ok(())
    }
}
