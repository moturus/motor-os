// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

#[cfg(test)]
mod tests;

#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "medium-ieee802154")]
mod ieee802154;

#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
mod pmtu;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[cfg(feature = "multicast")]
pub(crate) mod multicast;
#[cfg(feature = "socket-tcp")]
mod rate_limit;
#[cfg(feature = "socket-tcp")]
mod syn_cookies;
#[cfg(feature = "socket-tcp")]
mod tcp;
#[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
mod udp;

use super::packet::*;

use core::result::Result;
use heapless::Vec;

#[cfg(feature = "proto-ipv4-fragmentation")]
use super::fragmentation::Ipv4ReassemblyContext;
#[cfg(feature = "proto-ipv6-fragmentation")]
use super::fragmentation::Ipv6FragKey;
#[cfg(any(
    feature = "proto-ipv4-fragmentation",
    feature = "proto-ipv6-fragmentation"
))]
use super::fragmentation::{AssemblerError, AssemblerOutcome};
#[cfg(feature = "_proto-fragmentation")]
use super::fragmentation::{FragKey, PacketAssemblerSet};
use super::fragmentation::{Fragmenter, FragmentsBuffer};

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use super::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache};
use super::socket_set::SocketSet;
#[cfg(feature = "proto-ipv6-slaac")]
use crate::config::IFACE_MAX_PREFIX_COUNT;
#[cfg(feature = "proto-sixlowpan")]
use crate::config::IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT;
use crate::iface::Routes;
#[cfg(feature = "proto-ipv6-slaac")]
use crate::iface::Slaac;
#[cfg(feature = "proto-ipv4-fragmentation")]
use crate::phy::IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
use crate::phy::PacketMeta;
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
#[cfg(any(feature = "socket-tcp", feature = "proto-ipv4-fragmentation"))]
use crate::siphash::SipHasher24;
use crate::socket::*;
use crate::time::{Duration, Instant};

use crate::wire::*;

#[cfg(feature = "proto-ipv6")]
fn ipv6_device_eligible(caps: &DeviceCapabilities) -> bool {
    caps.ip_mtu() >= IPV6_MIN_MTU || {
        #[cfg(feature = "medium-ieee802154")]
        {
            caps.medium == Medium::Ieee802154
        }
        #[cfg(not(feature = "medium-ieee802154"))]
        {
            false
        }
    }
}

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}
use check;

/// Result returned by [`Interface::poll`].
///
/// This contains information on whether socket states might have changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollResult {
    /// Socket state is guaranteed to not have changed.
    None,
    /// You should check the state of sockets again for received data or completion of operations.
    SocketStateChanged,
}

/// Drain-on-read IP fragmentation, reassembly, and PMTU counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IpPacketStats {
    pub ipv4_fragments_rx: u64,
    pub ipv6_fragments_rx: u64,
    pub ipv4_fragments_tx: u64,
    pub ipv6_fragments_tx: u64,
    pub reassemblies_completed: u64,
    pub reassembly_malformed_drops: u64,
    pub reassembly_no_slot_drops: u64,
    pub reassembly_allocation_drops: u64,
    pub reassembly_expiry_drops: u64,
    pub reassembly_duplicates: u64,
    pub reassembly_range_limit_drops: u64,
    pub egress_fragment_stage_busy_drops: u64,
    pub pmtu_updates_accepted: u64,
    pub icmp_pmtu_messages_rejected: u64,
}

/// Result returned by [`Interface::poll_ingress_single`].
///
/// This contains information on whether a packet was processed or not,
/// and whether it might've affected socket states.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollIngressSingleResult {
    /// No packet was processed. You don't need to call [`Interface::poll_ingress_single`]
    /// again, until more packets arrive.
    ///
    /// Socket state is guaranteed to not have changed.
    None,
    /// A packet was processed.
    ///
    /// There may be more packets in the device's RX queue, so you should call [`Interface::poll_ingress_single`] again.
    ///
    /// Socket state is guaranteed to not have changed.
    PacketProcessed,
    /// A packet was processed, which might have caused socket state to change.
    ///
    /// There may be more packets in the device's RX queue, so you should call [`Interface::poll_ingress_single`] again.
    ///
    /// You should check the state of sockets again for received data or completion of operations.
    SocketStateChanged,
}

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface {
    pub(crate) inner: InterfaceInner,
    fragments: FragmentsBuffer,
    fragmenter: Fragmenter,
    /// Where the next egress pass starts; see [`Interface::socket_egress`].
    egress_cursor: u64,
    /// The pass's iteration order, kept to reuse its allocation.
    egress_order: alloc::vec::Vec<u64>,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner {
    caps: DeviceCapabilities,
    now: Instant,
    rand: Rand,

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: NeighborCache,
    /// A neighbor was learned this poll; sockets silenced waiting on one
    /// must have their poll caches recomputed.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_learned: bool,
    hardware_addr: HardwareAddress,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_fragment_ids: ipv4::Ipv4FragmentIds,
    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context:
        Vec<SixlowpanAddressContext, IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    tag: u16,
    /// Grows to hold whatever the owner configures; the owner's own config
    /// bounds it, not this crate. SLAAC's inflow is bounded on its side.
    ip_addrs: alloc::vec::Vec<IpCidr>,
    any_ip: bool,
    #[cfg(feature = "proto-ipv6-slaac")]
    slaac_enabled: bool,
    #[cfg(feature = "proto-ipv6-slaac")]
    slaac: Slaac,
    #[cfg(feature = "proto-ipv6-slaac")]
    slaac_updated: Instant,
    routes: Routes,
    #[cfg(feature = "multicast")]
    multicast: multicast::State,

    auto_icmp_echo_reply: bool,
    discovery_silent_time: Duration,

    /// Received TCP and UDP segments dropped because their checksum did not
    /// verify, since the last [`Interface::take_rx_csum_failed`]. Frames the
    /// device vouched for are not verified, so they cannot land here.
    rx_csum_failed: u64,

    /// Fragmentation, reassembly, and PMTU events since the last stats drain.
    ip_packet_stats: IpPacketStats,

    /// Neighbor mappings an unsolicited packet offered while the cache was
    /// full, since the last [`Interface::take_neighbor_admission_refused`].
    /// Such a packet may not displace an entry, so the mapping is not learned.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_admission_refused: u64,

    /// Connection requests that drew the reset path because nothing was
    /// listening for them, since the last
    /// [`Interface::take_tcp_syn_rst_unmatched`]. When the reflector's bucket
    /// is dry the reset itself is suppressed and counted again under
    /// [`InterfaceInner::tcp_rst_suppressed`].
    #[cfg(feature = "socket-tcp")]
    tcp_syn_rst_unmatched: u64,

    /// Limits the resets sent for segments no socket owns, from
    /// [`Config::tcp_rst_rate_limit`].
    #[cfg(feature = "socket-tcp")]
    tcp_rst_limiter: rate_limit::TokenBucket,

    /// Reflector resets the bucket above suppressed, since the last
    /// [`Interface::take_tcp_rst_suppressed`].
    #[cfg(feature = "socket-tcp")]
    tcp_rst_suppressed: u64,

    /// Limits the cookie SYN|ACKs, from [`Config::tcp_cookie_rate_limit`].
    #[cfg(feature = "socket-tcp")]
    tcp_cookie_limiter: rate_limit::TokenBucket,

    /// Cookie SYN|ACKs the bucket above suppressed, since the last
    /// [`Interface::take_tcp_syn_cookies_suppressed`].
    #[cfg(feature = "socket-tcp")]
    tcp_syn_cookies_suppressed: u64,

    /// Connection requests dropped because a listener owned the endpoint but
    /// had no socket left to take them, since the last
    /// [`Interface::take_tcp_syn_backlog_dropped`].
    #[cfg(feature = "socket-tcp")]
    tcp_syn_backlog_dropped: u64,

    /// Which local endpoints those dropped requests were for, deduplicated.
    /// This is the only unambiguous evidence that an accept backlog ran out: a
    /// socket leaving `Listen` is ordinary, but a request nobody could take is
    /// not. Bounded because the addresses come from the network -- a machine
    /// with more listeners than this loses the surplus for one poll rather than
    /// turning it into an unbounded list.
    #[cfg(feature = "socket-tcp")]
    tcp_backlog_endpoints: Vec<IpEndpoint, MAX_BACKLOG_ENDPOINTS>,

    /// Keys [`InterfaceInner::tcp_isn`], from [`Config::tcp_isn_key`].
    #[cfg(feature = "socket-tcp")]
    tcp_isn_key: SipHasher24,

    /// Keys the SYN cookies minted for the endpoints below, from
    /// [`Config::tcp_cookie_key`].
    #[cfg(feature = "socket-tcp")]
    tcp_cookie_key: SipHasher24,

    /// The RFC 7323 timestamp clock for segments no socket sends -- today
    /// only the cookie SYN|ACK. `None` leaves those segments without
    /// timestamps, and their eventual restorations degraded.
    #[cfg(feature = "socket-tcp")]
    tsval_generator: Option<TcpTimestampGenerator>,

    /// Listening endpoints whose admission is at its half-open cap: a
    /// connection request one of these owns but nothing can take is answered
    /// with a cookie SYN|ACK instead of being dropped, and an unmatched ACK
    /// arriving for one is checked as a possible cookie echo.
    #[cfg(feature = "socket-tcp")]
    syn_cookie_listeners:
        Vec<(IpEndpoint, syn_cookies::SynCookieListener), MAX_SYN_COOKIE_LISTENERS>,

    /// Connections verified cookie ACKs proved, waiting for the owner to
    /// build sockets for them; drained by
    /// [`Interface::take_tcp_cookie_restores`] after every poll.
    #[cfg(feature = "socket-tcp")]
    tcp_cookie_restores: Vec<crate::socket::tcp::TcpCookieRestore, MAX_COOKIE_RESTORES>,

    /// Cookie SYN|ACKs sent, since the last
    /// [`Interface::take_tcp_syn_cookies_sent`].
    #[cfg(feature = "socket-tcp")]
    tcp_syn_cookies_sent: u64,

    /// Unmatched ACKs at cookie-verifying endpoints that failed validation,
    /// since the last [`Interface::take_tcp_syn_cookies_rejected`].
    #[cfg(feature = "socket-tcp")]
    tcp_syn_cookies_rejected: u64,

    /// Verified restorations lost to a full queue, since the last
    /// [`Interface::take_tcp_cookie_restores_dropped`].
    #[cfg(feature = "socket-tcp")]
    tcp_cookie_restores_dropped: u64,

    /// From [`Config::loopback`].
    #[cfg(feature = "proto-ipv4")]
    loopback: bool,

    /// Frames dropped because a loopback address arrived on an interface that
    /// is not [`Config::loopback`], since the last
    /// [`Interface::take_rx_loopback_dropped`].
    #[cfg(feature = "proto-ipv4")]
    rx_loopback_dropped: u64,
}

/// How many distinct local endpoints one poll reports as out of listening
/// sockets. Only endpoints a listener owns are recorded, so a scan of closed
/// ports cannot crowd out the listener that really ran out.
#[cfg(feature = "socket-tcp")]
pub const MAX_BACKLOG_ENDPOINTS: usize = 8;

/// How many listening endpoints may run in SYN-cookie mode at once. A
/// listener refused a slot here keeps the old behavior -- requests it cannot
/// admit are dropped for the peer to retransmit.
#[cfg(feature = "socket-tcp")]
pub const MAX_SYN_COOKIE_LISTENERS: usize = 8;

/// How many verified cookie restorations one poll may hold for the owner.
/// The queue is drained every poll; a valid ACK lost to a full queue costs
/// the peer a retransmission, not the connection.
#[cfg(feature = "socket-tcp")]
pub const MAX_COOKIE_RESTORES: usize = 16;

#[cfg(feature = "socket-tcp")]
pub use syn_cookies::TcpSynCookieConfig;

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,

    /// Key for assigning IPv4 fragment identifiers to tuple buckets.
    ///
    /// Draw this independently from the platform entropy source for every
    /// interface. Tests may use a fixed value for deterministic identifiers.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub ipv4_fragment_id_key: [u8; 16],

    /// Key for the TCP initial sequence number hash (RFC 6528).
    ///
    /// Unlike [`Config::random_seed`], this one does have to be unpredictable
    /// and must not be derived from that seed: a peer who learns it can compute
    /// the sequence numbers of connections between two other machines, which is
    /// the whole of what the hash defends against. Draw it from the platform's
    /// entropy source, once per interface.
    #[cfg(feature = "socket-tcp")]
    pub tcp_isn_key: [u8; 16],

    /// Key for the SYN-cookie hash. As unpredictable as
    /// [`Config::tcp_isn_key`] and drawn independently of it: a peer must
    /// not learn one keyed hash from outputs of the other.
    #[cfg(feature = "socket-tcp")]
    pub tcp_cookie_key: [u8; 16],

    /// Token-bucket rate, per second, for the resets answering segments no
    /// socket owns; zero (the default) leaves them unlimited. Every such
    /// reset is one reply per unsolicited segment, so without a bound a peer
    /// spraying segments from spoofed sources turns this interface into a
    /// reset reflector aimed at whoever the sources name. A suppressed reset
    /// costs a real peer one retransmission round, not the connection.
    #[cfg(feature = "socket-tcp")]
    pub tcp_rst_rate_limit: u32,

    /// The same bound for cookie SYN|ACKs, separate because the two answer
    /// opposite populations: resets go where nothing listens, cookies where a
    /// flooded listener does -- and a flood must not spend the resets'
    /// budget, nor the reverse. Zero (the default) is unlimited.
    #[cfg(feature = "socket-tcp")]
    pub tcp_cookie_rate_limit: u32,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub hardware_addr: HardwareAddress,

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub pan_id: Option<Ieee802154Pan>,

    /// Enable stateless address autoconfiguration on the interface.
    #[cfg(feature = "proto-ipv6")]
    pub slaac: bool,

    /// This interface is a loopback interface: everything it carries stays on
    /// this machine.
    ///
    /// A 127/8 address means "this machine" and nothing else, so on any other
    /// interface such an address is either spoofed or misrouted, and ingress
    /// drops it. The default is `false`, which is the checked direction: an
    /// interface that never says what it is gets the check, not the exemption.
    #[cfg(feature = "proto-ipv4")]
    pub loopback: bool,

    /// Reply to ICMP echo requests addressed to this interface.
    pub auto_icmp_echo_reply: bool,

    /// Minimum delay between neighbor discovery requests for one destination.
    /// A destination that never answers therefore costs one request per delay
    /// and does not delay discovery of any other address.
    pub discovery_silent_time: Duration,
}

impl Config {
    pub(crate) const DEFAULT_DISCOVERY_SILENT_TIME: Duration = Duration::from_millis(1_000);

    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config {
            random_seed: 0,
            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_fragment_id_key: [0; 16],
            #[cfg(feature = "socket-tcp")]
            tcp_isn_key: [0; 16],
            #[cfg(feature = "socket-tcp")]
            tcp_cookie_key: [0; 16],
            #[cfg(feature = "socket-tcp")]
            tcp_rst_rate_limit: 0,
            #[cfg(feature = "socket-tcp")]
            tcp_cookie_rate_limit: 0,
            hardware_addr,
            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,
            #[cfg(feature = "proto-ipv6")]
            slaac: false,
            #[cfg(feature = "proto-ipv4")]
            loopback: false,
            auto_icmp_echo_reply: false,
            discovery_silent_time: Self::DEFAULT_DISCOVERY_SILENT_TIME,
        }
    }
}

impl Interface {
    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// This function panics if the [`Config::hardware_address`] does not match
    /// the medium of the device.
    pub fn new(config: Config, device: &mut (impl Device + ?Sized), now: Instant) -> Self {
        let caps = device.capabilities();
        assert_eq!(
            config.hardware_addr.medium(),
            caps.medium,
            "The hardware address does not match the medium of the interface."
        );

        #[allow(unused_mut)]
        let mut rand = Rand::new(config.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-sixlowpan")]
        let mut tag;

        #[cfg(feature = "proto-sixlowpan")]
        loop {
            tag = rand.rand_u16();
            if tag != 0 {
                break;
            }
        }

        #[allow(unused_mut)]
        let mut routes = Routes::new();
        #[cfg(feature = "proto-ipv6")]
        if !ipv6_device_eligible(&caps) {
            routes.disable_ipv6();
        }

        Interface {
            fragments: FragmentsBuffer {
                #[cfg(feature = "proto-sixlowpan")]
                decompress_buf: [0u8; sixlowpan::MAX_DECOMPRESSED_LEN],

                #[cfg(feature = "_proto-fragmentation")]
                assembler: PacketAssemblerSet::new(),
                #[cfg(feature = "_proto-fragmentation")]
                reassembly_timeout: Duration::from_secs(60),
            },
            fragmenter: Fragmenter::new(),
            egress_cursor: 0,
            egress_order: alloc::vec::Vec::new(),
            inner: InterfaceInner {
                now,
                caps,
                hardware_addr: config.hardware_addr,
                ip_addrs: alloc::vec::Vec::new(),
                any_ip: false,
                routes,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache: NeighborCache::new(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_learned: false,
                #[cfg(feature = "multicast")]
                multicast: multicast::State::new(),
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: config.pan_id,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_fragment_ids: ipv4::Ipv4FragmentIds::new(config.ipv4_fragment_id_key),
                #[cfg(feature = "proto-sixlowpan")]
                sixlowpan_address_context: Vec::new(),
                #[cfg(feature = "proto-ipv6-slaac")]
                slaac_enabled: config.slaac,
                #[cfg(feature = "proto-ipv6-slaac")]
                slaac: Slaac::new(),
                #[cfg(feature = "proto-ipv6-slaac")]
                slaac_updated: Instant::from_millis(0),
                rand,
                auto_icmp_echo_reply: config.auto_icmp_echo_reply,
                discovery_silent_time: config.discovery_silent_time,
                rx_csum_failed: 0,
                ip_packet_stats: IpPacketStats::default(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_admission_refused: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_syn_rst_unmatched: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_rst_limiter: rate_limit::TokenBucket::new(config.tcp_rst_rate_limit, now),
                #[cfg(feature = "socket-tcp")]
                tcp_rst_suppressed: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_cookie_limiter: rate_limit::TokenBucket::new(config.tcp_cookie_rate_limit, now),
                #[cfg(feature = "socket-tcp")]
                tcp_syn_cookies_suppressed: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_syn_backlog_dropped: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_backlog_endpoints: Vec::new(),
                #[cfg(feature = "socket-tcp")]
                tcp_isn_key: SipHasher24::new(config.tcp_isn_key),
                #[cfg(feature = "socket-tcp")]
                tcp_cookie_key: SipHasher24::new(config.tcp_cookie_key),
                #[cfg(feature = "socket-tcp")]
                tsval_generator: None,
                #[cfg(feature = "socket-tcp")]
                syn_cookie_listeners: Vec::new(),
                #[cfg(feature = "socket-tcp")]
                tcp_cookie_restores: Vec::new(),
                #[cfg(feature = "socket-tcp")]
                tcp_syn_cookies_sent: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_syn_cookies_rejected: 0,
                #[cfg(feature = "socket-tcp")]
                tcp_cookie_restores_dropped: 0,
                #[cfg(feature = "proto-ipv4")]
                loopback: config.loopback,
                #[cfg(feature = "proto-ipv4")]
                rx_loopback_dropped: 0,
            },
        }
    }

    /// Received TCP and UDP segments dropped because their checksum did not
    /// verify. Reading the count clears it, so the caller accumulates.
    pub fn take_rx_csum_failed(&mut self) -> u64 {
        core::mem::take(&mut self.inner.rx_csum_failed)
    }

    /// Fragmentation, reassembly, and PMTU events. Reading clears the counters.
    pub fn take_ip_packet_stats(&mut self) -> IpPacketStats {
        core::mem::take(&mut self.inner.ip_packet_stats)
    }

    /// Frames dropped because a loopback address arrived on an interface that
    /// is not [`Config::loopback`]. Reading the count clears it, so the caller
    /// accumulates.
    #[cfg(feature = "proto-ipv4")]
    pub fn take_rx_loopback_dropped(&mut self) -> u64 {
        core::mem::take(&mut self.inner.rx_loopback_dropped)
    }

    /// Neighbor mappings refused because an unsolicited packet -- an ARP
    /// request or a neighbor solicitation -- offered one while the cache was
    /// full. Reading the count clears it, so the caller accumulates.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn take_neighbor_admission_refused(&mut self) -> u64 {
        core::mem::take(&mut self.inner.neighbor_admission_refused)
    }

    /// Connection requests reset because nothing was listening for them.
    /// Reading the count clears it, so the caller accumulates.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_syn_rst_unmatched(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_syn_rst_unmatched)
    }

    /// Resets [`Config::tcp_rst_rate_limit`] suppressed: the offending
    /// segment was dropped unanswered instead. Reading the count clears it.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_rst_suppressed(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_rst_suppressed)
    }

    /// Cookie SYN|ACKs [`Config::tcp_cookie_rate_limit`] suppressed: the
    /// request was dropped for the peer to retransmit, exactly as if the
    /// endpoint had not been in cookie mode. Reading the count clears it.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_syn_cookies_suppressed(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_syn_cookies_suppressed)
    }

    /// Connection requests dropped because the listener that owns their
    /// endpoint had no socket left to take them. Reading the count clears it.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_syn_backlog_dropped(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_syn_backlog_dropped)
    }

    /// The local endpoints those dropped requests were for, at most
    /// [`MAX_BACKLOG_ENDPOINTS`] of them. Each one is a listener that had no
    /// socket left to take a connection. Reading them clears the list.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_backlog_endpoints(&mut self) -> Vec<IpEndpoint, MAX_BACKLOG_ENDPOINTS> {
        core::mem::take(&mut self.inner.tcp_backlog_endpoints)
    }

    /// Install the TCP timestamp clock used where no socket supplies one:
    /// the cookie SYN|ACK. Without it those segments carry no timestamps and
    /// their restorations degrade to no scaling and no SACK.
    #[cfg(feature = "socket-tcp")]
    pub fn set_tsval_generator(&mut self, generator: Option<TcpTimestampGenerator>) {
        self.inner.tsval_generator = generator;
    }

    /// Put `endpoint` in SYN-cookie mode: a request it owns that nothing can
    /// take is answered statelessly instead of dropped. Re-engaging replaces
    /// the advertised numbers. `false` means the table is full
    /// ([`MAX_SYN_COOKIE_LISTENERS`]) and the endpoint keeps drop behavior.
    #[cfg(feature = "socket-tcp")]
    pub fn engage_tcp_syn_cookies(
        &mut self,
        endpoint: IpEndpoint,
        config: TcpSynCookieConfig,
    ) -> bool {
        let now = self.inner.now;
        let listeners = &mut self.inner.syn_cookie_listeners;
        if let Some((_, entry)) = listeners.iter_mut().find(|(e, _)| *e == endpoint) {
            entry.config = config;
            entry.draining_until = None;
            return true;
        }
        // A drained entry no longer verifies anything; reclaim its slot
        // rather than refuse a live listener.
        if listeners.is_full()
            && let Some(i) = listeners
                .iter()
                .position(|(_, entry)| entry.draining_until.is_some_and(|until| until < now))
        {
            listeners.swap_remove(i);
        }
        listeners
            .push((
                endpoint,
                syn_cookies::SynCookieListener {
                    config,
                    draining_until: None,
                },
            ))
            .is_ok()
    }

    /// Take `endpoint` out of SYN-cookie mode: no more cookies are minted
    /// for it. Its table entry keeps verifying completing ACKs for one
    /// cookie validity window, so handshakes already on the wire land; a
    /// listener being torn down entirely should still call this, and the
    /// entry ages out on its own.
    #[cfg(feature = "socket-tcp")]
    pub fn disengage_tcp_syn_cookies(&mut self, endpoint: IpEndpoint) {
        let until = self.inner.now + syn_cookies::DRAIN_WINDOW;
        if let Some((_, entry)) = self
            .inner
            .syn_cookie_listeners
            .iter_mut()
            .find(|(e, _)| *e == endpoint)
            && entry.draining_until.is_none()
        {
            entry.draining_until = Some(until);
        }
    }

    /// Cookie SYN|ACKs sent. Reading the count clears it, so the caller
    /// accumulates.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_syn_cookies_sent(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_syn_cookies_sent)
    }

    /// Unmatched ACKs at cookie-verifying endpoints that failed validation
    /// -- a forged or expired cookie, or a timestamp echo that did not
    /// decode -- and were reset. Reading the count clears it.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_syn_cookies_rejected(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_syn_cookies_rejected)
    }

    /// Whether [`Interface::take_tcp_cookie_restores`] has anything to
    /// take: cheap enough for a hot poll loop, unlike the take itself, whose
    /// inline storage is copied out whole.
    #[cfg(feature = "socket-tcp")]
    pub fn tcp_cookie_restores_pending(&self) -> bool {
        !self.inner.tcp_cookie_restores.is_empty()
    }

    /// The connections verified cookie ACKs proved since the last take, at
    /// most [`MAX_COOKIE_RESTORES`]. The owner builds a socket for each and
    /// restores it with [`crate::socket::tcp::Socket::restore_from_cookie`].
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_cookie_restores(
        &mut self,
    ) -> Vec<crate::socket::tcp::TcpCookieRestore, MAX_COOKIE_RESTORES> {
        core::mem::take(&mut self.inner.tcp_cookie_restores)
    }

    /// Verified restorations lost to a full queue; each cost the peer a
    /// retransmission. Reading the count clears it.
    #[cfg(feature = "socket-tcp")]
    pub fn take_tcp_cookie_restores_dropped(&mut self) -> u64 {
        core::mem::take(&mut self.inner.tcp_cookie_restores_dropped)
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        self.inner.hardware_addr
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = addr;
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_addr()
    }

    /// Get the first IPv6 address if present.
    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.inner.ipv6_addr()
    }

    /// Get an address from the interface that could be used as source address.
    /// For IPv4, this function tries to find a registered IPv4 address in the same
    /// subnet as the destination, falling back to the first IPv4 address if none is
    /// found. For IPv6, the selection is based on RFC6724.
    pub fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        self.inner.get_source_address(dst_addr)
    }

    /// Get an IPv4 source address based on a destination address. This function tries
    /// to find the first IPv4 address from the interface that is in the same subnet as
    /// the destination address. If no such address is found, the first IPv4 address
    /// from the interface is returned.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        self.inner.get_source_address_ipv4(dst_addr)
    }

    /// Get an address from the interface that could be used as source address. The selection is
    /// based on RFC6724.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address) -> Ipv6Address {
        self.inner.get_source_address_ipv6(dst_addr)
    }

    /// Update the IP addresses of the interface. The table grows to hold
    /// whatever the closure pushes.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut alloc::vec::Vec<IpCidr>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_neighbor_cache(&mut self.inner);
        #[cfg(feature = "proto-ipv6")]
        if !ipv6_device_eligible(&self.inner.caps)
            && self
                .inner
                .ip_addrs
                .iter()
                .any(|cidr| matches!(cidr, IpCidr::Ipv6(_)))
        {
            self.inner
                .ip_addrs
                .retain(|cidr| !matches!(cidr, IpCidr::Ipv6(_)));
            panic!("IPv6 addresses require an interface MTU of at least 1280");
        }
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs);

        #[cfg(all(
            feature = "proto-ipv6",
            feature = "multicast",
            feature = "medium-ethernet"
        ))]
        if self.inner.caps.medium == Medium::Ethernet {
            self.update_solicited_node_groups();
        }
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    /// Enable or disable the AnyIP capability.
    ///
    /// AnyIP allowins packets to be received
    /// locally on IP addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [`routes`](Self::routes) specifies one of
    /// the interface's [`ip_addrs`](Self::ip_addrs) as its gateway, the interface will accept
    /// packets addressed to that prefix.
    pub fn set_any_ip(&mut self, any_ip: bool) {
        self.inner.any_ip = any_ip;
    }

    /// Get whether AnyIP is enabled.
    ///
    /// See [`set_any_ip`](Self::set_any_ip) for details on AnyIP
    pub fn any_ip(&self) -> bool {
        self.inner.any_ip
    }

    /// Get the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn reassembly_timeout(&self) -> Duration {
        self.fragments.reassembly_timeout
    }

    /// Set the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn set_reassembly_timeout(&mut self, timeout: Duration) {
        if timeout > Duration::from_secs(60) {
            net_debug!(
                "RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds"
            );
        }
        self.fragments.reassembly_timeout = timeout;
    }

    /// Transmit packets queued in the sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a value indicating whether the state of any socket
    /// might have changed.
    ///
    /// ## DoS warning
    ///
    /// This function processes all packets in the device's queue. This can
    /// be an unbounded amount of work if packets arrive faster than they're
    /// processed.
    ///
    /// If this is a concern for your application (i.e. your environment doesn't
    /// have preemptive scheduling, or `poll()` is called from a main loop where
    /// other important things are processed), you may use the lower-level methods
    /// [`poll_egress()`](Self::poll_egress), [`poll_maintenance()`](Self::poll_maintenance)
    /// and [`poll_ingress_single()`](Self::poll_ingress_single).
    /// This allows you to insert yields or process other events between processing
    /// individual ingress packets.
    pub fn poll(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;

        let mut res = PollResult::None;

        self.poll_maintenance(timestamp);

        // The poll edge: sockets mutated since the last poll recompute
        // their cached poll obligation, and in debug builds the whole
        // index is verified against a from-scratch recomputation.
        self.refresh_stale_poll_at(sockets);
        #[cfg(debug_assertions)]
        self.assert_poll_index_coherent(sockets);

        // Process ingress while there's packets available.
        loop {
            match self.socket_ingress(device, sockets) {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => res = PollResult::SocketStateChanged,
            }
        }

        // A neighbor learned during ingress unsilences whoever waited on
        // it; no single mark covers that, so everything is recomputed.
        if self.inner.take_neighbor_learned() {
            sockets.mark_all_poll_stale();
        }
        self.refresh_stale_poll_at(sockets);

        // Process egress.
        loop {
            match self.poll_egress(timestamp, device, sockets) {
                PollResult::None => break,
                PollResult::SocketStateChanged => res = PollResult::SocketStateChanged,
            }
        }

        res
    }

    /// Recompute the cached poll obligation of every socket marked stale.
    fn refresh_stale_poll_at(&mut self, sockets: &mut SocketSet<'_>) {
        let (items, _demux, poll_index) = sockets.parts_mut();
        for id in poll_index.take_stale() {
            // A stale mark may outlive its socket.
            if let Some(item) = items.get_mut(&id) {
                refresh_poll_at(&mut self.inner, poll_index, item);
            }
        }
    }

    /// The poll index oracle: every socket's cached obligation, recomputed
    /// from scratch, may never promise a later wake than the truth -- a
    /// too-early cache costs one empty visit, a too-late one is a socket
    /// that never transmits again. Runs at the poll edge in debug builds.
    #[cfg(debug_assertions)]
    fn assert_poll_index_coherent(&mut self, sockets: &mut SocketSet<'_>) {
        let now = self.inner.now;
        let (items, _demux, poll_index) = sockets.parts_mut();
        assert!(poll_index.stale_is_empty());
        for item in items.values_mut() {
            let socket_poll_at = item.socket.poll_at(&mut self.inner);
            let truth =
                item.meta
                    .poll_at(socket_poll_at, |addr| self.inner.has_neighbor(&addr), now);
            let cached = item.meta.poll_at_cache;
            let wake = |value: PollAt| match value {
                PollAt::Now => Some(now),
                PollAt::Time(t) => Some(t),
                PollAt::Ingress => None,
            };
            let coherent = match (wake(cached), wake(truth)) {
                (_, None) => true,
                (Some(promised), Some(true_at)) => promised <= true_at.max(now),
                (None, Some(_)) => false,
            };
            assert!(
                coherent,
                "poll cache incoherent for {}: cached {:?}, true {:?}, now {}",
                item.meta.handle, cached, truth, now
            );
            assert!(
                poll_index.entry_matches(&item.meta),
                "poll index entry mismatch for {}: cached {:?}",
                item.meta.handle,
                cached
            );
        }
    }

    #[cfg(any(
        feature = "proto-ipv4-fragmentation",
        feature = "proto-ipv6-fragmentation"
    ))]
    fn ip_fragment_egress(&mut self, device: &mut (impl Device + ?Sized)) -> bool {
        #[cfg(feature = "proto-ipv4-fragmentation")]
        if self.fragmenter.ip_version == Some(IpVersion::Ipv4) {
            return self.ipv4_egress(device);
        }
        #[cfg(feature = "proto-ipv6-fragmentation")]
        if self.fragmenter.ip_version == Some(IpVersion::Ipv6) {
            return self.ipv6_egress(device);
        }
        false
    }

    /// Transmit packets queued in the sockets.
    ///
    /// This function returns a value indicating whether the state of any socket
    /// might have changed.
    ///
    /// This is guaranteed to always perform a bounded amount of work.
    pub fn poll_egress(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;

        // A direct caller may arrive with mutations the poll edge has not
        // seen; the due set is complete only after they are refreshed.
        // Free inside `poll()`'s own loop, where the edge already drained.
        self.refresh_stale_poll_at(sockets);

        #[cfg(feature = "_proto-fragmentation")]
        let fragment_emitted = match self.inner.caps.medium {
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                {
                    self.sixlowpan_egress(device)
                }
                #[cfg(not(feature = "proto-sixlowpan-fragmentation"))]
                {
                    false
                }
            }
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ip"))]
            _ => {
                #[cfg(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-ipv6-fragmentation"
                ))]
                {
                    self.ip_fragment_egress(device)
                }
                #[cfg(not(any(
                    feature = "proto-ipv4-fragmentation",
                    feature = "proto-ipv6-fragmentation"
                )))]
                {
                    false
                }
            }
        };

        #[cfg(feature = "_proto-fragmentation")]
        if !self.fragmenter.is_empty() {
            return if fragment_emitted {
                PollResult::SocketStateChanged
            } else {
                PollResult::None
            };
        }

        #[cfg(feature = "proto-ipv6-slaac")]
        if self.inner.slaac_enabled {
            self.ndisc_rs_egress(device);
        }

        #[cfg(feature = "multicast")]
        self.multicast_egress(device);

        self.socket_egress(device, sockets)
    }

    /// Process one incoming packet queued in the device.
    ///
    /// Returns a value indicating:
    /// - whether a packet was processed, in which case you have to call this method again in case there's more packets queued.
    /// - whether the state of any socket might have changed.
    ///
    /// Since it processes at most one packet, this is guaranteed to always perform a bounded amount of work.
    pub fn poll_ingress_single(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollIngressSingleResult {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        self.remove_expired_fragments(timestamp);

        self.socket_ingress(device, sockets)
    }

    /// Maintain stateful processing on the device.
    ///
    /// This is guaranteed to always perform a bounded amount of work.
    pub fn poll_maintenance(&mut self, timestamp: Instant) {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        self.remove_expired_fragments(timestamp);

        #[cfg(feature = "proto-ipv6-slaac")]
        if self.inner.slaac.sync_required(timestamp) {
            self.sync_slaac_state(timestamp)
        }
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        if !self.fragmenter.is_empty() {
            return Some(Instant::from_millis(0));
        }

        #[allow(unused_mut)]
        let mut res = if sockets.poll_stale_is_empty() {
            // The index answers for every socket at once; `poll()` drained
            // the stale marks, so it is current.
            match sockets.poll_index_min() {
                PollAt::Ingress => None,
                PollAt::Time(instant) => Some(instant),
                PollAt::Now => Some(Instant::from_millis(0)),
            }
        } else {
            // Mutations since the last poll edge: the index cannot answer
            // yet, so this caller pays the recomputation the edge would.
            sockets
                .items()
                .filter_map(|item| {
                    let socket_poll_at = item.socket.poll_at(&mut self.inner);
                    match item.meta.poll_at(
                        socket_poll_at,
                        |ip_addr| self.inner.has_neighbor(&ip_addr),
                        timestamp,
                    ) {
                        PollAt::Ingress => None,
                        PollAt::Time(instant) => Some(instant),
                        PollAt::Now => Some(Instant::from_millis(0)),
                    }
                })
                .min()
        };

        #[cfg(feature = "proto-ipv6-slaac")]
        if self.inner.slaac_enabled {
            res = res.min(self.inner.slaac.poll_at(timestamp));
        }

        // The retired scan lives on as the oracle: the index may never
        // promise a later wake than a from-scratch recomputation.
        #[cfg(debug_assertions)]
        if sockets.poll_stale_is_empty() {
            let promised = res.map(|instant| instant.max(timestamp));
            let socket_wake = sockets
                .items()
                .filter_map(|item| {
                    let socket_poll_at = item.socket.poll_at(&mut self.inner);
                    match item.meta.poll_at(
                        socket_poll_at,
                        |ip_addr| self.inner.has_neighbor(&ip_addr),
                        timestamp,
                    ) {
                        PollAt::Ingress => None,
                        PollAt::Time(instant) => Some(instant.max(timestamp)),
                        PollAt::Now => Some(timestamp),
                    }
                })
                .min();
            if let Some(true_at) = socket_wake {
                assert!(
                    promised.is_some_and(|at| at <= true_at),
                    "poll_at promises {promised:?} against a true wake of {true_at:?}"
                );
            }
        }

        res
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    #[cfg(feature = "_proto-fragmentation")]
    fn remove_expired_fragments(&mut self, timestamp: Instant) {
        let expired = self.fragments.assembler.remove_expired(timestamp);
        self.inner.ip_packet_stats.reassembly_expiry_drops = self
            .inner
            .ip_packet_stats
            .reassembly_expiry_drops
            .wrapping_add(expired.incomplete as u64);
    }

    fn record_socketless_dispatch_error(_stats: &mut IpPacketStats, error: DispatchError) {
        #[cfg(any(
            feature = "proto-ipv4-fragmentation",
            feature = "proto-ipv6-fragmentation"
        ))]
        if error == DispatchError::FragmenterBusy {
            let counter = &mut _stats.egress_fragment_stage_busy_drops;
            *counter = counter.wrapping_add(1);
        }
        net_debug!("Failed to send response: {:?}", error);
    }

    fn socket_ingress(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollIngressSingleResult {
        let Some((rx_token, tx_token)) = device.receive(self.inner.now) else {
            return PollIngressSingleResult::None;
        };

        let rx_meta = rx_token.meta();
        rx_token.consume(|frame| {
            if frame.is_empty() {
                return PollIngressSingleResult::PacketProcessed;
            }

            match self.inner.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => {
                    if let Some(packet) =
                        self.inner
                            .process_ethernet(sockets, rx_meta, frame, &mut self.fragments)
                        && let Err(err) =
                            self.inner.dispatch(tx_token, packet, &mut self.fragmenter)
                    {
                        Self::record_socketless_dispatch_error(
                            &mut self.inner.ip_packet_stats,
                            err,
                        );
                    }
                }
                #[cfg(feature = "medium-ip")]
                Medium::Ip => {
                    if let Some(packet) =
                        self.inner
                            .process_ip(sockets, rx_meta, frame, &mut self.fragments)
                        && let Err(err) = self.inner.dispatch_ip(
                            tx_token,
                            PacketMeta::default(),
                            packet,
                            &mut self.fragmenter,
                        )
                    {
                        Self::record_socketless_dispatch_error(
                            &mut self.inner.ip_packet_stats,
                            err,
                        );
                    }
                }
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => {
                    if let Some(packet) =
                        self.inner
                            .process_ieee802154(sockets, rx_meta, frame, &mut self.fragments)
                        && let Err(err) = self.inner.dispatch_ip(
                            tx_token,
                            PacketMeta::default(),
                            packet,
                            &mut self.fragmenter,
                        )
                    {
                        Self::record_socketless_dispatch_error(
                            &mut self.inner.ip_packet_stats,
                            err,
                        );
                    }
                }
            }

            // TODO: Propagate the PollIngressSingleResult from deeper.
            // There's many received packets that we process but can't cause sockets
            // to change state. For example IP fragments, multicast stuff, ICMP pings
            // if they dont't match any raw socket...
            // We should return `PacketProcessed` for these to save the user from
            // doing useless socket polls.
            PollIngressSingleResult::SocketStateChanged
        })
    }

    fn socket_egress(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        let _caps = device.capabilities();

        enum EgressError {
            Exhausted,
            Dispatch,
        }

        let mut result = PollResult::None;
        let (items, demux, poll_index) = sockets.parts_mut();

        // The pass visits only the sockets due right now -- the poll
        // index's ready set plus its expired timers -- so egress work
        // follows the ready population, not the socket count. It rotates:
        // it starts at the cursor, not at the lowest id. Ids are
        // allocation-ordered and never reused, so a pass that always
        // started at the beginning handed the oldest sockets first claim on
        // the TX ring every time -- under device exhaustion the youngest
        // starved in tiers.
        let mut order = core::mem::take(&mut self.egress_order);
        order.clear();
        poll_index.extend_with_due(self.inner.now, self.egress_cursor, &mut order);

        let mut first_served = None;
        let mut refused = false;
        for &id in &order {
            let Some(item) = items.get_mut(&id) else {
                continue;
            };
            if !item
                .meta
                .egress_permitted(self.inner.now, |ip_addr| self.inner.has_neighbor(&ip_addr))
            {
                // `egress_permitted` can unsilence; the cache follows.
                refresh_poll_at(&mut self.inner, poll_index, item);
                continue;
            }

            let mut neighbor_addr = None;
            let mut served = false;
            let mut respond = |inner: &mut InterfaceInner, meta: PacketMeta, response: Packet| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                let t = device.transmit(inner.now).ok_or_else(|| {
                    net_debug!("failed to transmit IP: device exhausted");
                    EgressError::Exhausted
                })?;

                inner
                    .dispatch_ip(t, meta, response, &mut self.fragmenter)
                    .map_err(|_| EgressError::Dispatch)?;

                result = PollResult::SocketStateChanged;
                served = true;

                Ok(())
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(&mut self.inner, |inner, (ip, raw)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Raw(raw)),
                    )
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, response| match response {
                        #[cfg(feature = "proto-ipv4")]
                        (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ipv4_repr, IpPayload::Icmpv4(icmpv4_repr)),
                        ),
                        #[cfg(feature = "proto-ipv6")]
                        (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmpv6_repr)),
                        ),
                        #[allow(unreachable_patterns)]
                        _ => unreachable!(),
                    })
                }
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, meta, (ip, udp, payload)| {
                        respond(inner, meta, Packet::new(ip, IpPayload::Udp(udp, payload)))
                    })
                }
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, meta, (ip, tcp)| {
                        respond(inner, meta, Packet::new(ip, IpPayload::Tcp(tcp)))
                    })
                }
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => {
                    socket.dispatch(&mut self.inner, |inner, (ip, udp, dhcp)| {
                        respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ip, IpPayload::Dhcpv4(udp, dhcp)),
                        )
                    })
                }
                #[cfg(feature = "socket-dns")]
                Socket::Dns(socket) => socket.dispatch(&mut self.inner, |inner, (ip, udp, dns)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Udp(udp, dns)),
                    )
                }),
            };

            // `dispatch` runs the timers: TimeWait expiry, the timeout abort,
            // the post-abort RST emission, the lost-source-address reset all
            // change the socket's demux identity in here; the poll cache
            // follows the same rule -- except that a socket which just
            // emitted while already marked ready stays ready unexamined.
            // Bulk transfer then pays no recomputation per segment; if the
            // emission was the socket's last, the next visit emits nothing
            // and parks it then. A too-ready cache costs one empty visit,
            // which is the safe side of the oracle's invariant.
            demux.resync(item);
            if !(served && item.meta.poll_at_cache == PollAt::Now) {
                refresh_poll_at(&mut self.inner, poll_index, item);
            }

            if served && first_served.is_none() {
                first_served = Some(id);
            }

            match result {
                Err(EgressError::Exhausted) => {
                    // Device buffer full. The refused socket goes first next
                    // pass.
                    self.egress_cursor = id;
                    refused = true;
                    break;
                }
                Err(EgressError::Dispatch) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    item.meta.neighbor_missing(
                        self.inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                        self.inner.discovery_silent_time,
                    );
                }
                Ok(()) => {}
            }
        }
        if !refused && let Some(id) = first_served {
            // One past the completed pass's lead, so the ring's early slots
            // move around the set even when every pass completes.
            self.egress_cursor = id + 1;
        }
        self.egress_order = order;
        result
    }
}

/// Recompute `item`'s poll obligation and move its index entry to match.
/// Called wherever the interface's own loops may have changed what the
/// socket would transmit -- the counterpart of the stale marks the
/// [`SocketSet`]'s mutable accessors leave for everyone else.
fn refresh_poll_at(
    inner: &mut InterfaceInner,
    poll_index: &mut crate::iface::socket_set::PollIndex,
    item: &mut crate::iface::socket_set::Item<'_>,
) {
    let socket_poll_at = item.socket.poll_at(inner);
    let value = item
        .meta
        .poll_at(socket_poll_at, |addr| inner.has_neighbor(&addr), inner.now);
    poll_index.set(&mut item.meta, value);
}

impl InterfaceInner {
    fn take_neighbor_learned(&mut self) -> bool {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        {
            core::mem::take(&mut self.neighbor_learned)
        }
        #[cfg(not(any(feature = "medium-ethernet", feature = "medium-ieee802154")))]
        {
            false
        }
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        self.hardware_addr
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum.clone()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        self.caps.ip_mtu()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu_for(&mut self, destination: IpAddress) -> usize {
        let interface_mtu = self.caps.ip_mtu();
        if destination.is_unicast() {
            self.routes
                .effective_pmtu(destination, interface_mtu, self.now)
        } else {
            interface_mtu
        }
    }

    /// See [`DeviceCapabilities::max_tso_size`]. 0 = the device does not
    /// support TCP segmentation offload.
    #[allow(unused)]
    pub(crate) fn max_tso_size(&self) -> usize {
        self.caps.max_tso_size
    }

    #[allow(unused)] // unused depending on which sockets are enabled, and in tests
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(|a| a.into()),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) if ipv6_device_eligible(&self.caps) => {
                Some(self.get_source_address_ipv6(addr).into())
            }
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => None,
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_ip_addrs(&mut self, addrs: alloc::vec::Vec<IpCidr>) {
        self.ip_addrs = addrs;
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Check whether the interface has the given IP address assigned.
    ///
    /// Always returns true if [`InterfaceInner::any_ip`].
    pub(crate) fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        // If any IP is set to true, we don't bother about checking the IP.
        if self.any_ip {
            return true;
        }

        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Check whether the interface listens to given destination multicast IP address.
    fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();

        #[cfg(feature = "multicast")]
        if self.multicast.has_multicast_group(addr) {
            return true;
        }

        match addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(key) => key == IPV4_MULTICAST_ALL_SYSTEMS,
            #[cfg(feature = "proto-rpl")]
            IpAddress::Ipv6(IPV6_LINK_LOCAL_ALL_RPL_NODES) => true,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(key) => {
                key == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(key)
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ip_payload: &'frame [u8],
        frag: &'frame mut FragmentsBuffer,
    ) -> Option<Packet<'frame>> {
        match IpVersion::of_packet(ip_payload) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(ip_payload));
                self.process_ipv4(sockets, meta, HardwareAddress::Ip, &ipv4_packet, frag)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(ip_payload));
                self.process_ipv6(sockets, meta, HardwareAddress::Ip, &ipv6_packet, Some(frag))
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &[u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .items_mut()
            .filter_map(|i| raw::Socket::downcast_mut(&mut i.socket))
        {
            if raw_socket.accepts(ip_repr) {
                raw_socket.process(self, ip_repr, ip_payload);
                handled_by_raw_socket = true;
            }
        }
        handled_by_raw_socket
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        packet: EthernetPacket,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => {
                self.dispatch_ip(tx_token, PacketMeta::default(), packet, frag)
            }
        }
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        #[cfg(feature = "proto-ipv6")]
        if matches!(addr, IpAddress::Ipv6(_)) && !ipv6_device_eligible(&self.caps) {
            return None;
        }

        // Send directly.
        // note: no need to use `self.is_broadcast()` to check for subnet-local broadcast addrs
        //       here because `in_same_network` will already return true.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Some(*addr);
        }

        // Route via a router.
        self.routes.lookup(addr, timestamp)
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Some(_routed_addr) => match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            None => false,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        dst_addr: &IpAddress,
        fragmenter: &mut Fragmenter,
    ) -> Result<(HardwareAddress, Tx), DispatchError>
    where
        Tx: TxToken,
    {
        if self.is_broadcast(dst_addr) {
            let hardware_addr = match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match *dst_addr {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let b = addr.octets();
                        HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                            0x01,
                            0x00,
                            0x5e,
                            b[1] & 0x7F,
                            b[2],
                            b[3],
                        ]))
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => unreachable!(),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let b = addr.octets();
                        HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                            0x33, 0x33, b[12], b[13], b[14], b[15],
                        ]))
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        // Not sure if this is correct
                        HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST)
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self
            .route(dst_addr, self.now)
            .ok_or(DispatchError::NoRoute)?;

        match self.neighbor_cache.lookup(&dst_addr, self.now) {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(DispatchError::NeighborPending),
            _ => (), // XXX
        }

        match dst_addr {
            #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
            IpAddress::Ipv4(dst_addr) if matches!(self.caps.medium, Medium::Ethernet) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                let src_hardware_addr = self.hardware_addr.ethernet_or_panic();

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: src_hardware_addr,
                    source_protocol_addr: self
                        .get_source_address_ipv4(&dst_addr)
                        .ok_or(DispatchError::NoRoute)?,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                if let Err(e) =
                    self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                        frame.set_dst_addr(EthernetAddress::BROADCAST);
                        frame.set_ethertype(EthernetProtocol::Arp);

                        arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                    })
                {
                    net_debug!("Failed to dispatch ARP request: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(dst_addr) => {
                net_debug!(
                    "address {} not in neighbor cache, sending Neighbor Solicitation",
                    dst_addr
                );

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.hardware_addr.into()),
                });

                let packet = Packet::new_ipv6(
                    Ipv6Repr {
                        src_addr: self.get_source_address_ipv6(&dst_addr),
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff,
                    },
                    IpPayload::Icmpv6(solicit),
                );

                if let Err(e) =
                    self.dispatch_ip(tx_token, PacketMeta::default(), packet, fragmenter)
                {
                    net_debug!("Failed to dispatch NDISC solicit: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[allow(unreachable_patterns)]
            _ => (),
        }

        // The request got dispatched; hold back further requests for this
        // destination, and for this destination only.
        self.neighbor_cache
            .limit_rate(dst_addr, self.now, self.discovery_silent_time);
        Err(DispatchError::NeighborPending)
    }

    fn flush_neighbor_cache(&mut self) {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        self.neighbor_cache.flush()
    }

    /// Cache a neighbor learned from an unsolicited packet -- an ARP request or
    /// a neighbor solicitation -- counting the mapping when a full cache
    /// refuses it. See [`NeighborCache::fill_unsolicited`].
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn fill_neighbor_unsolicited(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if !self
            .neighbor_cache
            .fill_unsolicited(protocol_addr, hardware_addr, timestamp)
        {
            self.neighbor_admission_refused = self.neighbor_admission_refused.wrapping_add(1);
        } else {
            self.neighbor_learned = true;
        }
    }

    /// Cache a neighbor learned from a reply to a request of our own -- an ARP
    /// reply or a neighbor advertisement -- which may evict, but never a router
    /// we route through. See [`NeighborCache::fill_solicited`].
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn fill_neighbor_solicited(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        let routes = &self.routes;
        self.neighbor_cache
            .fill_solicited(protocol_addr, hardware_addr, timestamp, |addr| {
                routes.is_active_router(addr, timestamp)
            });
        self.neighbor_learned = true;
    }

    #[cfg(any(
        feature = "proto-ipv4-fragmentation",
        feature = "proto-ipv6-fragmentation"
    ))]
    fn count_reassembly_error(&mut self, error: AssemblerError) {
        let counter = match error {
            AssemblerError::Invalid
            | AssemblerError::SizeLimit
            | AssemblerError::FinalSize
            | AssemblerError::Overlap => &mut self.ip_packet_stats.reassembly_malformed_drops,
            AssemblerError::RangeLimit => &mut self.ip_packet_stats.reassembly_range_limit_drops,
            AssemblerError::Allocation => &mut self.ip_packet_stats.reassembly_allocation_drops,
            AssemblerError::Poisoned => return,
        };
        *counter = counter.wrapping_add(1);
    }

    fn count_pmtu_message(&mut self, accepted: bool) {
        let counter = if accepted {
            &mut self.ip_packet_stats.pmtu_updates_accepted
        } else {
            &mut self.ip_packet_stats.icmp_pmtu_messages_rejected
        };
        *counter = counter.wrapping_add(1);
    }

    fn dispatch_ip<Tx: TxToken>(
        &mut self,
        // NOTE(unused_mut): tx_token isn't always mutated, depending on
        // the feature set that is used.
        #[allow(unused_mut)] mut tx_token: Tx,
        meta: PacketMeta,
        packet: Packet,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError> {
        #[cfg(feature = "_proto-fragmentation")]
        if !frag.is_empty() && frag.finished() {
            frag.reset();
        }
        #[cfg(feature = "_proto-fragmentation")]
        if !frag.is_empty() {
            return Err(DispatchError::FragmenterBusy);
        }
        let mut ip_repr = packet.ip_repr();
        assert!(!ip_repr.dst_addr().is_unspecified());
        let path_mtu = self.ip_mtu_for(ip_repr.dst_addr());

        // Dispatch IEEE802.15.4:

        #[cfg(feature = "medium-ieee802154")]
        if matches!(self.caps.medium, Medium::Ieee802154) {
            let (addr, tx_token) =
                self.lookup_hardware_addr(tx_token, &ip_repr.dst_addr(), frag)?;
            let addr = addr.ieee802154_or_panic();

            self.dispatch_ieee802154(addr, tx_token, meta, packet, frag);
            return Ok(());
        }

        // Dispatch IP/Ethernet:

        let caps = self.caps.clone();

        // First we calculate the total length that we will have to emit.
        let mut total_len = ip_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(self.caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // If the medium is Ethernet, then we need to retrieve the destination hardware address.
        #[cfg(feature = "medium-ethernet")]
        let (dst_hardware_addr, mut tx_token) = match self.caps.medium {
            Medium::Ethernet => {
                let (hardware_addr, tx_token) =
                    self.lookup_hardware_addr(tx_token, &ip_repr.dst_addr(), frag)?;
                (hardware_addr.ethernet_or_panic(), tx_token)
            }
            #[cfg(any(feature = "medium-ip", feature = "medium-ieee802154"))]
            _ => (EthernetAddress([0; 6]), tx_token),
        };

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            repr.emit(&mut *tx_buffer, &self.caps.checksum);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        let total_ip_len = ip_repr.buffer_len();

        match &mut ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_repr) => {
                // If we have an IPv4 packet, then we need to check if we need to fragment it.
                // TSO super-segments (meta.tso_seg_size != 0) exceed the wire
                // MTU by design — the device segments them — so they always
                // take the direct-emit path below.
                if meta.tso_seg_size == 0 && total_ip_len > path_mtu {
                    #[cfg(feature = "proto-ipv4-fragmentation")]
                    {
                        net_debug!("start fragmentation");

                        // Calculate how much we will send now (including the Ethernet header).

                        let ip_header_len = _repr.buffer_len();
                        let payload_mtu = path_mtu - ip_header_len;
                        let first_frag_data_len =
                            payload_mtu - payload_mtu % IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
                        let first_frag_ip_len = first_frag_data_len + ip_header_len;
                        let mut tx_len = first_frag_ip_len;
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(caps.medium, Medium::Ethernet) {
                            tx_len += EthernetFrame::<&[u8]>::header_len();
                        }

                        if frag.buffer.len() < _repr.payload_len {
                            net_debug!(
                                "Fragmentation buffer is too small, at least {} needed. Dropping",
                                _repr.payload_len
                            );
                            return Ok(());
                        }

                        let ipv4_id = self.ipv4_fragment_ids.next(
                            _repr.src_addr,
                            _repr.dst_addr,
                            _repr.next_header,
                        );

                        #[cfg(feature = "medium-ethernet")]
                        {
                            frag.ipv4.dst_hardware_addr = dst_hardware_addr;
                        }

                        // Stage only the fragmentable payload; each fragment
                        // receives a freshly emitted IP header.
                        frag.packet_len = _repr.payload_len;
                        frag.ip_version = Some(IpVersion::Ipv4);
                        frag.ipv4.repr = *_repr;
                        frag.ipv4.path_mtu = path_mtu;
                        packet.emit_payload(
                            &IpRepr::Ipv4(*_repr),
                            &mut frag.buffer[.._repr.payload_len],
                            &caps,
                        );

                        _repr.payload_len = first_frag_data_len;
                        let first_repr = *_repr;
                        frag.sent_bytes = first_frag_data_len;
                        frag.ipv4.ident = ipv4_id;

                        // Transmit the first packet.
                        tx_token.consume(tx_len, |mut tx_buffer| {
                            #[cfg(feature = "medium-ethernet")]
                            if matches!(self.caps.medium, Medium::Ethernet) {
                                emit_ethernet(&IpRepr::Ipv4(first_repr), tx_buffer);
                                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                            }

                            let mut ipv4_packet =
                                Ipv4Packet::new_unchecked(&mut tx_buffer[..ip_header_len]);
                            first_repr.emit(&mut ipv4_packet, &caps.checksum);
                            ipv4_packet.set_ident(ipv4_id);
                            ipv4_packet.set_more_frags(true);
                            ipv4_packet.set_dont_frag(false);
                            ipv4_packet.set_frag_offset(0);
                            if caps.checksum.ipv4.tx() {
                                ipv4_packet.fill_checksum();
                            }
                            tx_buffer[ip_header_len..first_frag_ip_len]
                                .copy_from_slice(&frag.buffer[..first_frag_data_len]);
                            frag.ipv4.frag_offset = first_frag_data_len as u16;
                        });
                        self.ip_packet_stats.ipv4_fragments_tx =
                            self.ip_packet_stats.ipv4_fragments_tx.wrapping_add(1);

                        Ok(())
                    }

                    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                    {
                        net_debug!(
                            "Enable the `proto-ipv4-fragmentation` feature for fragmentation support."
                        );
                        Ok(())
                    }
                } else {
                    tx_token.set_meta(meta);

                    // No fragmentation is required.
                    tx_token.consume(total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.caps.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer);
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                    });

                    Ok(())
                }
            }
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_repr) => {
                // TSO super-segments are segmented by the device, never here.
                if meta.tso_seg_size == 0 && total_ip_len > path_mtu {
                    #[cfg(feature = "proto-ipv6-fragmentation")]
                    {
                        if _repr.next_header != IpProtocol::Udp {
                            net_debug!("IPv6 source fragmentation is supported only for UDP.");
                            return Ok(());
                        }
                        if frag.buffer.len() < _repr.payload_len {
                            return Ok(());
                        }

                        packet.emit_payload(
                            &IpRepr::Ipv6(*_repr),
                            &mut frag.buffer[.._repr.payload_len],
                            &caps,
                        );
                        frag.ipv6.repr = *_repr;
                        frag.ipv6.path_mtu = path_mtu;
                        #[cfg(feature = "medium-ethernet")]
                        {
                            frag.ipv6.dst_hardware_addr = dst_hardware_addr;
                        }
                        let ident = self.rand.rand_u32();
                        frag.ipv6.ident = if ident == 0 { 1 } else { ident };
                        frag.sent_bytes = 0;
                        frag.ip_version = Some(IpVersion::Ipv6);
                        frag.packet_len = _repr.payload_len;
                        self.dispatch_ipv6_frag(tx_token, frag);
                        Ok(())
                    }
                    #[cfg(not(feature = "proto-ipv6-fragmentation"))]
                    {
                        net_debug!(
                            "Enable the proto-ipv6-fragmentation feature for fragmentation support."
                        );
                        Ok(())
                    }
                } else {
                    tx_token.set_meta(meta);

                    tx_token.consume(total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.caps.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer);
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                    });
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DispatchError {
    #[cfg(feature = "_proto-fragmentation")]
    /// Another fragmented datagram owns the single bounded staging slot.
    FragmenterBusy,
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
