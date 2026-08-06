//! The mio-agnostic seam between the net socket state machines and the poll
//! registry (design 5.1). A socket emits clean readiness edges through an
//! installed `NetEventListener`; the vdso veneer's listener translates them
//! into poll-registry events. A native `moto_io::net` consumer installs none
//! and reads the readiness futures instead -- the edge vocabulary here never
//! mentions the poll ABI, so the state machine carries no poll dependency.

/// A set of readiness edges in mio-free terms. The five edges map one-to-one
/// onto the poll ABI's event bits, but the vocabulary is kept independent so
/// the veneer -- not the state machine -- owns the translation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Readiness(u8);

impl Readiness {
    pub const EMPTY: Self = Self(0);
    pub const READABLE: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const READ_CLOSED: Self = Self(1 << 2);
    pub const WRITE_CLOSED: Self = Self(1 << 3);
    pub const ERROR: Self = Self(1 << 4);

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for Readiness {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Readiness {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A per-socket sink for readiness edges, optionally installed by a host that
/// wants push delivery -- the vdso veneer installs one at FD creation.
/// `on_readiness` runs inline on the channel runtime thread, so the crate
/// boundary costs one indirect call, not a scheduling hop.
///
/// There is no `as_any`: a host that wants its concrete observer back keeps
/// the `Arc` it constructed, rather than recovering it from the socket. That
/// leaves this the only handle a socket stores, so the state machine holds no
/// poll-registry type and no observer at all unless a host asked for one.
pub trait NetEventListener: Send + Sync {
    fn on_readiness(&self, edges: Readiness);
}
