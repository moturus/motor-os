// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use heapless::LinearMap;

use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;
use crate::time::{Duration, Instant};
use crate::wire::{HardwareAddress, IpAddress};

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbor {
    hardware_addr: HardwareAddress,
    expires_at: Instant,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(HardwareAddress),
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

/// A neighbor cache backed by a map.
#[derive(Debug)]
pub struct Cache {
    storage: LinearMap<IpAddress, Neighbor, IFACE_NEIGHBOR_CACHE_COUNT>,
    silent_until: Instant,
}

impl Cache {
    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    pub fn new() -> Self {
        Self {
            storage: LinearMap::new(),
            silent_until: Instant::from_millis(0),
        }
    }

    pub fn reset_expiry_if_existing(
        &mut self,
        protocol_addr: IpAddress,
        source_hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if let Some(Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get_mut(&protocol_addr)
            && source_hardware_addr == *hardware_addr
        {
            *expires_at = timestamp + Self::ENTRY_LIFETIME;
        }
    }

    /// Fill with nothing protected from eviction. Test setup only: a test that
    /// wants a populated cache has no route table to protect entries with.
    #[cfg(test)]
    pub fn fill(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        self.fill_solicited(protocol_addr, hardware_addr, timestamp, |_| false);
    }

    /// Fill from a reply to a request of our own -- an ARP reply or a neighbor
    /// advertisement. Our own egress asked for the mapping, so it may displace
    /// a cached one, but never one `protected` claims: the entry a route's
    /// gateway resolves to is what every destination behind that route needs,
    /// and a peer answering with a stream of addresses would otherwise aim its
    /// evictions straight at it.
    pub(crate) fn fill_solicited(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
        protected: impl Fn(&IpAddress) -> bool,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        let neighbor = Neighbor {
            expires_at,
            hardware_addr,
        };
        match self.storage.insert(protocol_addr, neighbor) {
            Ok(Some(old_neighbor)) => {
                if old_neighbor.hardware_addr != hardware_addr {
                    net_trace!(
                        "replaced {} => {} (was {})",
                        protocol_addr,
                        hardware_addr,
                        old_neighbor.hardware_addr
                    );
                }
            }
            Ok(None) => {
                net_trace!("filled {} => {} (was empty)", protocol_addr, hardware_addr);
            }
            Err((protocol_addr, neighbor)) => {
                // If we're going down this branch, it means the cache is full, and we need to evict an entry:
                // the one closest to expiry that is not protected. Protecting every entry is possible only
                // with fewer cache slots than routes, and there the entry closest to expiry goes anyway,
                // since a cache that can evict nothing can never learn anything again.
                let old_protocol_addr = *self
                    .storage
                    .iter()
                    .filter(|&(addr, _)| !protected(addr))
                    .min_by_key(|(_, neighbor)| neighbor.expires_at)
                    .or_else(|| {
                        self.storage
                            .iter()
                            .min_by_key(|(_, neighbor)| neighbor.expires_at)
                    })
                    .expect("empty neighbor cache storage")
                    .0;

                let _old_neighbor = self.storage.remove(&old_protocol_addr).unwrap();
                match self.storage.insert(protocol_addr, neighbor) {
                    Ok(None) => {
                        net_trace!(
                            "filled {} => {} (evicted {} => {})",
                            protocol_addr,
                            hardware_addr,
                            old_protocol_addr,
                            _old_neighbor.hardware_addr
                        );
                    }
                    // We've covered everything else above.
                    _ => unreachable!(),
                }
            }
        }
    }

    /// Fill from an unsolicited packet -- an ARP request or a neighbor
    /// solicitation, either of which any peer on the segment may emit at any
    /// time. Such a packet may refresh or replace a mapping that is already
    /// cached, and may take a free slot, but it may never displace another
    /// entry: with eviction available, a handful of forged requests would
    /// otherwise flush every legitimate mapping, the gateway included.
    ///
    /// Returns whether the mapping was admitted. A reply to a request of our
    /// own keeps [`Cache::fill_solicited`], whose eviction serves an address
    /// our own egress asked to resolve.
    #[must_use]
    pub(crate) fn fill_unsolicited(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> bool {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let neighbor = Neighbor {
            expires_at: timestamp + Self::ENTRY_LIFETIME,
            hardware_addr,
        };

        // `insert` fails only when the cache is full *and* this address is not
        // already in it, which is exactly the case that would need an eviction.
        match self.storage.insert(protocol_addr, neighbor) {
            Ok(_) => true,
            Err(_) => {
                net_debug!(
                    "refused {} => {}: neighbor cache full",
                    protocol_addr,
                    hardware_addr
                );
                false
            }
        }
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        assert!(protocol_addr.is_unicast());

        if let Some(&Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get(protocol_addr)
            && timestamp < expires_at
        {
            return Answer::Found(hardware_addr);
        }

        if timestamp < self.silent_until {
            Answer::RateLimited
        } else {
            Answer::NotFound
        }
    }

    pub(crate) fn limit_rate(&mut self, timestamp: Instant, delay: Duration) {
        self.silent_until = timestamp + delay;
    }

    pub(crate) fn flush(&mut self) {
        self.storage.clear()
    }
}

#[cfg(feature = "medium-ethernet")]
#[cfg(test)]
mod test {
    use super::*;
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    use crate::wire::ipv4::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::ipv6::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};

    use crate::wire::EthernetAddress;

    const HADDR_A: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 1]));
    const HADDR_B: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 2]));
    const HADDR_C: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 3]));
    const HADDR_D: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 4]));

    #[test]
    fn test_fill() {
        let mut cache = Cache::new();

        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
    }

    #[test]
    fn test_expire() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );
    }

    #[test]
    fn test_replace() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(50));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(200));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(300));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000))
                .found()
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_unsolicited_never_evicts() {
        let mut cache = Cache::new();

        // A free slot still fills.
        assert!(cache.fill_unsolicited(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100)));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_A)
        );

        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(200));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(300));

        // The cache is now full, so a fourth address arriving unsolicited is
        // refused and every cached mapping survives.
        assert!(!cache.fill_unsolicited(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(400)));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000))
                .found()
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_A)
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_3.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_C)
        );

        // A reply answers a request of our own, so it still evicts the entry
        // closest to expiry.
        cache.fill(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(400));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(1000))
                .found()
        );
    }

    #[test]
    fn test_unsolicited_refreshes_cached_entry() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(200));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(300));

        // The cache is full, but this address is already in it, so nothing has
        // to make way and the mapping is admitted.
        assert!(cache.fill_unsolicited(
            MOCK_IP_ADDR_1.into(),
            HADDR_A,
            Instant::from_millis(30_000)
        ));

        // Past the expiry the entry had, within the one it was given.
        let past_original = Instant::from_millis(100) + Cache::ENTRY_LIFETIME;
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), past_original),
            Answer::Found(HADDR_A)
        );
    }

    #[test]
    fn test_protected_entry_is_not_evicted() {
        let mut cache = Cache::new();
        let gateway: IpAddress = MOCK_IP_ADDR_1.into();

        cache.fill(gateway, HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(200));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(300));

        // The gateway is closest to expiry, so an unprotected fill would take
        // it. Protected, the next-closest goes instead.
        cache.fill_solicited(
            MOCK_IP_ADDR_4.into(),
            HADDR_D,
            Instant::from_millis(400),
            |addr| *addr == gateway,
        );
        assert_eq!(
            cache.lookup(&gateway, Instant::from_millis(1000)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000))
                .found()
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_all_protected_still_fills() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(200));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(300));

        // With no unprotected entry to prefer, the one closest to expiry goes
        // anyway: a cache that can evict nothing never learns anything again.
        cache.fill_solicited(
            MOCK_IP_ADDR_4.into(),
            HADDR_D,
            Instant::from_millis(400),
            |_| true,
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(1000))
                .found()
        );
    }

    #[test]
    fn test_hush() {
        let mut cache = Cache::new();

        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::NotFound
        );

        cache.limit_rate(Instant::from_millis(0), Duration::from_millis(1000));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(100)),
            Answer::RateLimited
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(2000)),
            Answer::NotFound
        );
    }

    #[test]
    fn test_flush() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.flush();
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
    }
}
