//! Physical page accounting and the rules for accepting an allocation.
//!
//! `phys_blocks::Pool` (defined in the parent `mod.rs`) allocates physical RAM
//! pages for the kernel and all processes. It stores its used-page count and
//! OOM control state together in `Counters::state: AtomicU64`. `StateSnapshot`
//! decodes a copy of that word and calculates proposed changes; the `Pool`
//! methods below commit them with compare-and-swap (CAS).
//! Keeping count and control state in the same CAS prevents an allocation from
//! passing a gate/floor check against state that changed before its charge.

use super::*;

const USED_MASK: u64 = (1 << 25) - 1;
const PHASE_MASK: u64 = 3 << 25;
const IDLE: u64 = 0;
const KILLING: u64 = 1 << 25;
const LATCHED: u64 = 2 << 25;
const SYSTEM_BLOCKED: u64 = 1 << 27;
const ARMED: u64 = 1 << 28;
const GENERATION_ONE: u64 = 1 << 29;

const _: () = assert!((MAX_BLOCKS as u64) * (PAGES as u64) <= USED_MASK);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationClass {
    Kernel,
    System,
    User,
}

impl From<moto_sys::caps::ProcessRole> for AllocationClass {
    fn from(role: moto_sys::caps::ProcessRole) -> Self {
        match role {
            moto_sys::caps::ProcessRole::System => Self::System,
            moto_sys::caps::ProcessRole::None | moto_sys::caps::ProcessRole::Interactive => {
                Self::User
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefusalKind {
    /// OOM state currently blocks allocations for this class.
    Gate,
    /// The charge would leave fewer free pages than this class's floor.
    Floor,
    /// The pool has fewer free pages than the requested charge.
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationError {
    Corruption(Corruption),
    Refused {
        class: AllocationClass,
        kind: RefusalKind,
        state: StateSnapshot,
    },
}

impl From<Corruption> for AllocationError {
    fn from(err: Corruption) -> Self {
        Self::Corruption(err)
    }
}

/// A snapshot of accounting and OOM state for the physical RAM page allocator,
/// `phys_blocks::Pool`, defined in the parent `mod.rs`.
///
/// The OS has one such allocator: `PhysicalMemory::blocks` in `mm/phys.rs`,
/// whose type `BlockPool` is an alias for `Pool`. Its counters cover managed
/// physical RAM shared by the kernel and all processes. That allocator owns
/// the authoritative `Counters::state: AtomicU64`; this `StateSnapshot(u64)` is a
/// plain copy used to calculate an allocation decision before committing it.
///
/// Bit layout (all page counts use 4 KiB pages):
///
/// ```text
///  0..=24  used pages
/// 25..=26  phase: 0 = Idle, 1 = Killing, 2 = Latched; 3 is invalid
///      27  System allocations blocked until the current run ends
///      28  OOM policy armed
/// 29..=63  generation; advances without wrapping
/// ```
/// The 64 GiB pool cap includes a count of 2^24 pages, requiring 25 count bits.
/// Total pages are immutable and stored separately; free pages = total - used.
///
/// When armed, System must leave 128 free pages (512 KiB), User must leave
/// 512 (2 MiB), and Kernel has no floor. Idle opens all allocation gates.
/// Killing blocks User allocations while reclamation runs. Latched means
/// reclamation ended below recovery: User stays blocked, but System may
/// allocate again. Recovery at 768 free pages (3 MiB) returns to Idle and
/// clears the System block. Run starts and recovery advance the generation,
/// preserving their history even between scheduler visits; later OOM jobs can
/// use it to reject work from an obsolete run.
///
/// Unarmed state disables floors, gates and OOM transitions while retaining
/// accounting. The OS allocator remains unarmed during step 5a. Debug guest
/// tests construct private `Pool` instances and exercise armed states there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StateSnapshot(pub(super) u64);

impl StateSnapshot {
    /// Initial accounting only: Idle, unarmed, generation zero, System open.
    pub(super) fn new(used: u64) -> Self {
        assert!(used <= USED_MASK);
        Self(used)
    }

    pub(super) fn used(self) -> u64 {
        self.0 & USED_MASK
    }

    fn phase(self) -> u64 {
        self.0 & PHASE_MASK
    }

    fn next_generation(self) -> Option<Self> {
        self.0.checked_add(GENERATION_ONE).map(Self)
    }

    /// Propose a new word and an optional refusal without modifying the pool.
    /// A refusal leaves usage unchanged but can start Killing or block System;
    /// the caller must commit that state change even when returning a refusal.
    fn charge(self, total: u64, count: u16, class: AllocationClass) -> (Self, Option<RefusalKind>) {
        let free = total
            .checked_sub(self.used())
            .expect("phys: used exceeds total");
        let armed = self.0 & ARMED != 0;
        let floor = match class {
            _ if !armed => 0,
            AllocationClass::Kernel => 0,
            AllocationClass::System => 128,
            AllocationClass::User => 512,
        };
        let refusal = if armed
            && ((class == AllocationClass::User && self.phase() != IDLE)
                || (class == AllocationClass::System && self.0 & SYSTEM_BLOCKED != 0))
        {
            Some(RefusalKind::Gate)
        } else if free < u64::from(count) {
            Some(RefusalKind::Capacity)
        } else if free - u64::from(count) < floor {
            Some(RefusalKind::Floor)
        } else {
            None
        };
        let mut next = self;
        if refusal.is_none() {
            let used = self.used() + u64::from(count);
            assert!(used <= USED_MASK);
            next.0 = (self.0 & !USED_MASK) | used;
        }
        if armed {
            let free_after = total - next.used();
            if (refusal.is_none() && free_after < 512 && matches!(self.phase(), IDLE | LATCHED))
                || (refusal == Some(RefusalKind::Floor) && free < 768 && self.phase() == IDLE)
            {
                next.0 = (next.0 & !PHASE_MASK) | KILLING;
                next = next
                    .next_generation()
                    .expect("phys: OOM generation exhausted");
            }
            if next.phase() == KILLING
                && ((class == AllocationClass::System && refusal == Some(RefusalKind::Floor))
                    || (class == AllocationClass::Kernel && refusal.is_none() && free_after < 128))
            {
                next.0 |= SYSTEM_BLOCKED;
            }
        }
        (next, refusal)
    }

    fn release(self, total: u64, count: u16) -> Self {
        let used = self
            .used()
            .checked_sub(u64::from(count))
            .expect("phys: release underflow");
        let mut next = Self((self.0 & !USED_MASK) | used);
        if self.0 & ARMED != 0 && self.phase() != IDLE && total - used >= 768 {
            next.0 &= !(PHASE_MASK | SYSTEM_BLOCKED);
            next = next
                .next_generation()
                .expect("phys: OOM generation exhausted");
        }
        next
    }
}

impl<L: PageLinks> Pool<'_, L> {
    /// Read one consistent snapshot; another CPU may immediately supersede it.
    pub(super) fn state_snapshot(&self) -> StateSnapshot {
        StateSnapshot(self.counters.state.load(Ordering::Acquire))
    }

    pub(super) fn charge(&self, count: u16, class: AllocationClass) -> Result<(), AllocationError> {
        let mut old = self.state_snapshot();
        loop {
            // Recompute the whole decision after a failed CAS: either the
            // available count or the class's gate may have changed.
            let (next, refusal) = old.charge(self.counters.total, count, class);
            match self.counters.state.compare_exchange_weak(
                old.0,
                next.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if let Some(kind) = refusal {
                        return Err(AllocationError::Refused {
                            class,
                            kind,
                            state: next,
                        });
                    }
                    self.counters
                        .high_water
                        .fetch_max(next.used(), Ordering::Relaxed);
                    if let Some(published) = self.counters.published.get() {
                        published.fetch_sub(u64::from(count), Ordering::Relaxed);
                    }
                    #[cfg(debug_assertions)]
                    if let Some(trace) = self.trace {
                        trace.record(Publication::Charge(count));
                    }
                    return Ok(());
                }
                Err(current) => old = StateSnapshot(current),
            }
        }
    }

    pub(super) fn release(&self, count: u16) {
        let mut old = self.state_snapshot();
        loop {
            let next = old.release(self.counters.total, count);
            match self.counters.state.compare_exchange_weak(
                old.0,
                next.0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => old = StateSnapshot(current),
            }
        }
        if let Some(published) = self.counters.published.get() {
            published.fetch_add(u64::from(count), Ordering::Relaxed);
        }
        #[cfg(debug_assertions)]
        if let Some(trace) = self.trace {
            trace.record(Publication::Release(count));
        }
    }
}

#[cfg(debug_assertions)]
#[path = "policy_tests.rs"]
pub(super) mod tests;
