use alloc::vec::Vec;

use crate::time::Instant;
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
    #[cfg(feature = "proto-ipv6")]
    ipv6_eligible: bool,
}

impl Routes {
    /// Creates a new empty routing table.
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
            #[cfg(feature = "proto-ipv6")]
            ipv6_eligible: true,
        }
    }

    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn disable_ipv6(&mut self) {
        self.ipv6_eligible = false;
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut Vec<Route>)>(&mut self, f: F) {
        f(&mut self.storage);
        #[cfg(feature = "proto-ipv6")]
        if !self.ipv6_eligible
            && self.storage.iter().any(|route| {
                matches!(route.cidr, IpCidr::Ipv6(_))
                    || matches!(route.via_router, IpAddress::Ipv6(_))
            })
        {
            self.storage.retain(|route| {
                !matches!(route.cidr, IpCidr::Ipv6(_))
                    && !matches!(route.via_router, IpAddress::Ipv6(_))
            });
            panic!("IPv6 routes require an interface MTU of at least 1280");
        }
        self.reorder();
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
        let old = self.remove_default_ipv4_route();
        // A /0 belongs at the very end the order wants; push keeps it there.
        self.storage.push(Route::new_ipv4_gateway(gateway));
        old
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
        let old = self.remove_default_ipv6_route();
        // A /0 belongs at the very end the order wants; push keeps it there.
        self.storage.push(Route::new_ipv6_gateway(gateway));
        old
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
        if let Some((i, _)) = self
            .storage
            .iter()
            .enumerate()
            .find(|(_, r)| r.is_ipv4_gateway())
        {
            Some(self.storage.remove(i))
        } else {
            None
        }
    }

    /// Remove the default ipv6 gateway
    ///
    /// On success, returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        if let Some((i, _)) = self
            .storage
            .iter()
            .enumerate()
            .find(|(_, r)| r.is_ipv6_gateway())
        {
            Some(self.storage.remove(i))
        } else {
            None
        }
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
}
