use alloc::vec::Vec;

use crate::time::{Duration, Instant};
use crate::wire::{IpAddress, IpCidr};
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Cidr};

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Route {
    pub cidr: IpCidr,
    pub via_router: IpAddress,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}

#[cfg(feature = "proto-ipv4")]
const IPV4_DEFAULT: IpCidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0));
#[cfg(feature = "proto-ipv6")]
const IPV6_DEFAULT: IpCidr =
    IpCidr::Ipv6(Ipv6Cidr::new(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0), 0));

// The following PMTU integration commits consume this component in production.
#[cfg_attr(not(test), allow(dead_code))]
const PMTU_CACHE_CAPACITY: usize = 64;
#[cfg_attr(not(test), allow(dead_code))]
const PMTU_LIFETIME: Duration = Duration::from_secs(10 * 60);
#[cfg(feature = "proto-ipv4")]
#[cfg_attr(not(test), allow(dead_code))]
const IPV4_MIN_PMTU: usize = 68;
#[cfg(feature = "proto-ipv4")]
#[cfg_attr(not(test), allow(dead_code))]
const IPV4_PMTU_PLATEAUS: &[usize] = &[
    65_535, 32_000, 17_914, 8_166, 4_352, 2_002, 1_492, 1_006, 508, 296, 68,
];

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct PmtuEntry {
    destination: IpAddress,
    mtu: usize,
    expires_at: Instant,
    updated_at: Instant,
}

#[derive(Debug)]
struct PmtuCache {
    entries: Vec<PmtuEntry>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PmtuCache {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn expire(&mut self, timestamp: Instant) {
        self.entries.retain(|entry| timestamp < entry.expires_at);
    }

    fn effective_mtu(
        &mut self,
        destination: IpAddress,
        interface_mtu: usize,
        timestamp: Instant,
    ) -> usize {
        self.expire(timestamp);
        self.entries
            .iter()
            .find(|entry| entry.destination == destination)
            .map_or(interface_mtu, |entry| entry.mtu)
    }

    fn update(
        &mut self,
        destination: IpAddress,
        advertised_mtu: usize,
        quoted_packet_len: usize,
        interface_mtu: usize,
        timestamp: Instant,
    ) -> bool {
        self.expire(timestamp);

        let candidate = match destination {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) if advertised_mtu == 0 => IPV4_PMTU_PLATEAUS
                .iter()
                .copied()
                .find(|mtu| *mtu < quoted_packet_len),
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) => Some(advertised_mtu.max(IPV4_MIN_PMTU)),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => Some(advertised_mtu.max(crate::wire::ipv6::MIN_MTU)),
        };
        let Some(candidate) = candidate else {
            return false;
        };

        let current = self
            .entries
            .iter()
            .find(|entry| entry.destination == destination)
            .map_or(interface_mtu, |entry| entry.mtu);
        if candidate >= current || candidate >= quoted_packet_len {
            return false;
        }

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.destination == destination)
        {
            entry.mtu = candidate;
            entry.expires_at = timestamp + PMTU_LIFETIME;
            entry.updated_at = timestamp;
            return true;
        }

        if self.entries.len() == PMTU_CACHE_CAPACITY {
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.updated_at)
                .map(|(index, _)| index)
                .unwrap();
            self.entries.swap_remove(oldest);
        }
        self.entries.push(PmtuEntry {
            destination,
            mtu: candidate,
            expires_at: timestamp + PMTU_LIFETIME,
            updated_at: timestamp,
        });
        true
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            cidr: IPV4_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            cidr: IPV6_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns `true` if the route is a default route for IPv6.
    #[cfg(feature = "proto-ipv6")]
    pub fn is_ipv6_gateway(&self) -> bool {
        self.cidr == IPV6_DEFAULT
    }

    /// Returns `true` if the route is a default route for IPv4.
    #[cfg(feature = "proto-ipv4")]
    pub fn is_ipv4_gateway(&self) -> bool {
        self.cidr == IPV4_DEFAULT
    }
}

/// A routing table. Grows to hold whatever its owner writes: entries come
/// from the operator's configuration (and, under SLAAC, from a merge that is
/// bounded on its own side), never straight off the network.
///
/// The entries are held most-specific-first -- reordered after every
/// mutation, on the cold path -- so the per-packet lookup takes the first
/// live match and stops instead of scoring the whole table.
#[derive(Debug)]
pub struct Routes {
    storage: Vec<Route>,
    pmtu: PmtuCache,
    #[cfg(feature = "proto-ipv6")]
    ipv6_eligible: bool,
}

impl Routes {
    /// Creates a new empty routing table.
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
            pmtu: PmtuCache::new(),
            #[cfg(feature = "proto-ipv6")]
            ipv6_eligible: true,
        }
    }

    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn disable_ipv6(&mut self) {
        self.ipv6_eligible = false;
        self.pmtu.clear();
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut Vec<Route>)>(&mut self, f: F) {
        self.mutate(f);
    }

    fn mutate<R>(&mut self, f: impl FnOnce(&mut Vec<Route>) -> R) -> R {
        let result = f(&mut self.storage);
        #[cfg(feature = "proto-ipv6")]
        let invalid_ipv6 = !self.ipv6_eligible
            && self.storage.iter().any(|route| {
                matches!(route.cidr, IpCidr::Ipv6(_))
                    || matches!(route.via_router, IpAddress::Ipv6(_))
            });
        #[cfg(feature = "proto-ipv6")]
        if invalid_ipv6 {
            self.storage.retain(|route| {
                !matches!(route.cidr, IpCidr::Ipv6(_))
                    && !matches!(route.via_router, IpAddress::Ipv6(_))
            });
        }
        self.reorder();
        self.pmtu.clear();
        #[cfg(feature = "proto-ipv6")]
        if invalid_ipv6 {
            panic!("IPv6 routes require an interface MTU of at least 1280");
        }
        result
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_pmtu(
        &mut self,
        destination: IpAddress,
        interface_mtu: usize,
        timestamp: Instant,
    ) -> usize {
        assert!(destination.is_unicast());
        self.pmtu
            .effective_mtu(destination, interface_mtu, timestamp)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn update_pmtu(
        &mut self,
        destination: IpAddress,
        advertised_mtu: usize,
        quoted_packet_len: usize,
        interface_mtu: usize,
        timestamp: Instant,
    ) -> bool {
        assert!(destination.is_unicast());
        self.pmtu.update(
            destination,
            advertised_mtu,
            quoted_packet_len,
            interface_mtu,
            timestamp,
        )
    }

    /// Restore the most-specific-first order `lookup` walks. Stable, so
    /// routes of equal prefix length keep their insertion order.
    fn reorder(&mut self) {
        self.storage
            .sort_by_key(|route| core::cmp::Reverse(route.cidr.prefix_len()));
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway`").
    ///
    /// Returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn add_default_ipv4_route(&mut self, gateway: Ipv4Address) -> Option<Route> {
        self.mutate(|storage| {
            let old = storage
                .iter()
                .position(Route::is_ipv4_gateway)
                .map(|index| storage.remove(index));
            storage.push(Route::new_ipv4_gateway(gateway));
            old
        })
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway`").
    ///
    /// Returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn add_default_ipv6_route(&mut self, gateway: Ipv6Address) -> Option<Route> {
        assert!(
            self.ipv6_eligible,
            "IPv6 routes require an interface MTU of at least 1280"
        );
        self.mutate(|storage| {
            let old = storage
                .iter()
                .position(Route::is_ipv6_gateway)
                .map(|index| storage.remove(index));
            storage.push(Route::new_ipv6_gateway(gateway));
            old
        })
    }

    /// Returns the ipv4 default route if there is one in the route table.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_default_ipv4_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv4_gateway()).copied()
    }

    /// Returns the ipv6 default route if there is one in the route table.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_default_ipv6_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv6_gateway()).copied()
    }

    /// Remove the default ipv4 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn remove_default_ipv4_route(&mut self) -> Option<Route> {
        self.mutate(|storage| {
            storage
                .iter()
                .position(Route::is_ipv4_gateway)
                .map(|index| storage.remove(index))
        })
    }

    /// Remove the default ipv6 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        self.mutate(|storage| {
            storage
                .iter()
                .position(Route::is_ipv6_gateway)
                .map(|index| storage.remove(index))
        })
    }

    /// Whether `addr` is the router of a route that has not expired. Every
    /// destination such a route serves depends on the neighbor entry for it.
    pub(crate) fn is_active_router(&self, addr: &IpAddress, timestamp: Instant) -> bool {
        self.storage.iter().any(|route| {
            if let Some(expires_at) = route.expires_at
                && timestamp > expires_at
            {
                return false;
            }
            route.via_router == *addr
        })
    }

    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        assert!(addr.is_unicast());

        #[cfg(feature = "proto-ipv6")]
        if matches!(addr, IpAddress::Ipv6(_)) && !self.ipv6_eligible {
            return None;
        }

        // Most-specific-first order: the first live match wins, except that
        // among routes of equal prefix length the last matching one is kept,
        // which is what `max_by_key` over the unordered table returned.
        let mut best: Option<&Route> = None;
        for route in &self.storage {
            if let Some(found) = best
                && route.cidr.prefix_len() < found.cidr.prefix_len()
            {
                break;
            }
            if let Some(expires_at) = route.expires_at
                && timestamp > expires_at
            {
                continue;
            }
            if route.cidr.contains_addr(addr) {
                best = Some(route);
            }
        }
        best.map(|route| route.via_router)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "proto-ipv6")]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 1);
        pub const ADDR_1B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 13);
        pub const ADDR_1C: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 42);
        pub fn cidr_1() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 0), 64)
        }

        pub const ADDR_2A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 1);
        pub const ADDR_2B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 21);
        pub fn cidr_2() -> Ipv6Cidr {
            Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 0), 64)
        }
    }

    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    mod mock {
        use super::super::*;
        pub const ADDR_1A: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
        pub const ADDR_1B: Ipv4Address = Ipv4Address::new(192, 0, 2, 13);
        pub const ADDR_1C: Ipv4Address = Ipv4Address::new(192, 0, 2, 42);
        pub fn cidr_1() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address::new(192, 0, 2, 0), 24)
        }

        pub const ADDR_2A: Ipv4Address = Ipv4Address::new(198, 51, 100, 1);
        pub const ADDR_2B: Ipv4Address = Ipv4Address::new(198, 51, 100, 21);
        pub fn cidr_2() -> Ipv4Cidr {
            Ipv4Cidr::new(Ipv4Address::new(198, 51, 100, 0), 24)
        }
    }

    use self::mock::*;

    /// The table grows far past the fixed capacity it used to have, and the
    /// lookup semantics hold at size: of sixty-four nested prefixes that all
    /// contain the address, the most specific one wins.
    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn the_table_grows_with_demand() {
        let mut routes = Routes::new();
        routes.update(|storage| {
            for len in 1..=64u8 {
                storage.push(Route {
                    cidr: Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 0), len).into(),
                    via_router: Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 1, len as u16).into(),
                    preferred_until: None,
                    expires_at: None,
                });
            }
            assert_eq!(storage.len(), 64);
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 1, 64).into())
        );
    }

    /// The most specific route wins whatever order the table was written
    /// in, and the default route serves only what nothing else covers.
    #[test]
    fn a_default_route_is_the_last_resort() {
        let mut routes = Routes::new();
        let default_router = ADDR_2A;
        // Deliberately widest-first: the lookup order is the table's own.
        routes.update(|storage| {
            storage.push(Route {
                cidr: cidr_1().into(),
                via_router: ADDR_1A.into(),
                preferred_until: None,
                expires_at: None,
            });
        });
        #[cfg(feature = "proto-ipv6")]
        routes.add_default_ipv6_route(default_router);
        #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
        routes.add_default_ipv4_route(default_router);

        // Inside the covered prefix: the specific route, not the default.
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        // Outside it: the default.
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            Some(default_router.into())
        );
    }

    #[test]
    fn test_is_active_router() {
        let mut routes = Routes::new();
        assert!(!routes.is_active_router(&ADDR_1A.into(), Instant::from_millis(0)));

        routes.update(|storage| {
            storage.push(Route {
                cidr: cidr_1().into(),
                via_router: ADDR_1A.into(),
                preferred_until: None,
                expires_at: Some(Instant::from_millis(10)),
            });
        });

        assert!(routes.is_active_router(&ADDR_1A.into(), Instant::from_millis(10)));
        assert!(!routes.is_active_router(&ADDR_1B.into(), Instant::from_millis(10)));

        // An expired route carries nothing, so its router needs no protection.
        assert!(!routes.is_active_router(&ADDR_1A.into(), Instant::from_millis(11)));
    }

    #[test]
    fn test_fill() {
        let mut routes = Routes::new();

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            None
        );

        let route = Route {
            cidr: cidr_1().into(),
            via_router: ADDR_1A.into(),
            preferred_until: None,
            expires_at: None,
        };
        routes.update(|storage| {
            storage.push(route);
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            None
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            None
        );

        let route2 = Route {
            cidr: cidr_2().into(),
            via_router: ADDR_2A.into(),
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        routes.update(|storage| {
            storage.push(route2);
        });

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)),
            Some(ADDR_2A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)),
            Some(ADDR_2A.into())
        );

        assert_eq!(
            routes.lookup(&ADDR_1A.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1B.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_1C.into(), Instant::from_millis(10)),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2A.into(), Instant::from_millis(10)),
            Some(ADDR_2A.into())
        );
        assert_eq!(
            routes.lookup(&ADDR_2B.into(), Instant::from_millis(10)),
            Some(ADDR_2A.into())
        );
    }

    #[cfg(feature = "proto-ipv4")]
    fn pmtu_v4(index: u8) -> IpAddress {
        Ipv4Address::new(192, 0, 2, index + 1).into()
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn pmtu_decreases_are_bounded_and_expire() {
        let mut routes = Routes::new();
        let start = Instant::from_secs(10);
        let destination = pmtu_v4(0);

        assert!(routes.update_pmtu(destination, 1_200, 1_400, 1_500, start));
        assert_eq!(routes.effective_pmtu(destination, 1_500, start), 1_200);
        assert!(!routes.update_pmtu(
            destination,
            1_300,
            1_400,
            1_500,
            start + Duration::from_secs(300)
        ));
        assert_eq!(
            routes.effective_pmtu(destination, 1_500, start + PMTU_LIFETIME),
            1_500
        );

        let floored = pmtu_v4(1);
        assert!(routes.update_pmtu(floored, 1, 1_400, 1_500, start));
        assert_eq!(routes.effective_pmtu(floored, 1_500, start), 68);
        assert!(!routes.update_pmtu(pmtu_v4(2), 1_400, 1_300, 1_500, start));
        assert!(!routes.update_pmtu(pmtu_v4(3), 1_500, 1_600, 1_500, start));
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn legacy_ipv4_pmtu_uses_the_next_lower_plateau() {
        let mut routes = Routes::new();
        let now = Instant::ZERO;
        assert!(routes.update_pmtu(pmtu_v4(0), 0, 1_500, 2_000, now));
        assert_eq!(routes.effective_pmtu(pmtu_v4(0), 2_000, now), 1_492);
        assert!(routes.update_pmtu(pmtu_v4(1), 0, 1_492, 2_000, now));
        assert_eq!(routes.effective_pmtu(pmtu_v4(1), 2_000, now), 1_006);
        assert!(!routes.update_pmtu(pmtu_v4(2), 0, 68, 2_000, now));
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn ipv6_pmtu_is_floored_at_1280() {
        let mut routes = Routes::new();
        let destination = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
        assert!(routes.update_pmtu(destination, 1, 1_500, 1_500, Instant::ZERO));
        assert_eq!(
            routes.effective_pmtu(destination, 1_500, Instant::ZERO),
            1_280
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn pmtu_capacity_evicts_the_least_recently_updated() {
        let mut routes = Routes::new();
        for index in 0..PMTU_CACHE_CAPACITY as u8 {
            assert!(routes.update_pmtu(
                pmtu_v4(index),
                1_400,
                1_500,
                1_500,
                Instant::from_secs(index)
            ));
        }
        assert!(routes.update_pmtu(pmtu_v4(0), 1_300, 1_500, 1_500, Instant::from_secs(100)));
        assert!(routes.update_pmtu(pmtu_v4(64), 1_400, 1_500, 1_500, Instant::from_secs(101)));

        assert_eq!(routes.pmtu.entries.len(), PMTU_CACHE_CAPACITY);
        assert_eq!(
            routes.effective_pmtu(pmtu_v4(0), 1_500, Instant::from_secs(101)),
            1_300
        );
        assert_eq!(
            routes.effective_pmtu(pmtu_v4(1), 1_500, Instant::from_secs(101)),
            1_500
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv4")]
    fn route_mutation_flushes_pmtu() {
        let mut routes = Routes::new();
        let destination = pmtu_v4(0);
        let cache = |routes: &mut Routes| {
            assert!(routes.update_pmtu(destination, 1_200, 1_400, 1_500, Instant::ZERO));
        };

        cache(&mut routes);
        routes.update(|_| {});
        assert_eq!(
            routes.effective_pmtu(destination, 1_500, Instant::ZERO),
            1_500
        );
        cache(&mut routes);
        routes.add_default_ipv4_route(Ipv4Address::new(192, 0, 2, 254));
        assert_eq!(
            routes.effective_pmtu(destination, 1_500, Instant::ZERO),
            1_500
        );
        cache(&mut routes);
        routes.remove_default_ipv4_route();
        assert_eq!(
            routes.effective_pmtu(destination, 1_500, Instant::ZERO),
            1_500
        );
    }
}
