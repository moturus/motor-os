//! Destination ordering for lookup answers -- RFC 6724 rule 1 in spirit:
//! avoid unusable destinations. A global IPv6 answer is a dead end when
//! this node's own IPv6 source toward the internet is not global (a test
//! tap's documentation-prefix address is the canonical case), so such
//! answers rank after every address the node can use. sys-io's source
//! selection is the authority: a bind-for-remote reports the local
//! address that would carry the packet, and sends nothing.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::OnceLock;

use moto_dns::{Address, AddressFamily};

/// Global unicast as far as reachability goes: everything but the scopes
/// and special-purpose prefixes that never route on the public internet.
fn is_global_v6(addr: &Ipv6Addr) -> bool {
    let seg = addr.segments();
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.to_ipv4_mapped().is_some()
        || (seg[0] & 0xffc0) == 0xfe80 // link-local
        || (seg[0] & 0xfe00) == 0xfc00 // unique-local
        || (seg[0] & 0xffc0) == 0xfec0 // site-local
        || (seg[0] == 0x2001 && seg[1] == 0xdb8) // documentation, RFC 3849
        || (seg[0] == 0x3fff && seg[1] & 0xf000 == 0)) // documentation, RFC 9637
}

pub fn is_global_v6_destination(address: &Address) -> bool {
    address.family == AddressFamily::V6 as u8 && is_global_v6(&Ipv6Addr::from(address.bytes))
}

/// The IPv6 source sys-io would pick toward the global internet: the
/// bound socket exists only to ask, carries no traffic, and closes here.
fn probed_v6_source() -> Option<Ipv6Addr> {
    // A representative global destination; only route selection sees it.
    let remote = SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        53,
        0,
        0,
    );
    let rt_fd = moto_rt::net::udp_bind_for_remote(&SocketAddr::V6(remote).into()).ok()?;
    let local = moto_rt::net::socket_addr(rt_fd);
    let _ = moto_rt::fs::close(rt_fd);
    match SocketAddr::from(local.ok()?) {
        SocketAddr::V6(v6) => Some(*v6.ip()),
        SocketAddr::V4(_) => None,
    }
}

/// Whether global IPv6 answers rank after everything else here. The
/// address configuration changes only with a sys-io restart, and that
/// takes this daemon down with it, so one completed probe settles the
/// answer. A probe that fails (no v6 route, or the stack still coming
/// up) reads as "nothing to prefer v6 with" for the current lookup
/// without pinning the verdict.
pub fn v6_ranks_last() -> bool {
    static VERDICT: OnceLock<bool> = OnceLock::new();
    if let Some(verdict) = VERDICT.get() {
        return *verdict;
    }
    match probed_v6_source() {
        Some(source) => *VERDICT.get_or_init(|| !is_global_v6(&source)),
        None => true,
    }
}

/// Stable partition: every address the node can use keeps its position
/// ahead of the global IPv6 answers it cannot.
fn demote_global_v6(addresses: &mut [Address]) {
    let mut ordered = Vec::with_capacity(addresses.len());
    ordered.extend(
        addresses
            .iter()
            .copied()
            .filter(|address| !is_global_v6_destination(address)),
    );
    ordered.extend(addresses.iter().copied().filter(is_global_v6_destination));
    addresses.copy_from_slice(&ordered);
}

pub fn order_destinations(addresses: &mut [Address]) {
    if v6_ranks_last() {
        demote_global_v6(addresses);
    }
}

/// True when a non-empty answer consists solely of addresses rule 1
/// demotes -- the shape the v4 re-ask in `resolve` exists for.
pub fn only_unusable_answers(addresses: &[Address]) -> bool {
    !addresses.is_empty() && addresses.iter().all(is_global_v6_destination)
}

pub fn v4_address(octets: [u8; 4]) -> Address {
    let mut address = Address::zeroed();
    address.family = AddressFamily::V4 as u8;
    address.bytes[..4].copy_from_slice(&octets);
    address
}

pub fn v6_address(text: &str) -> Address {
    let parsed: Ipv6Addr = text.parse().unwrap();
    let mut address = Address::zeroed();
    address.family = AddressFamily::V6 as u8;
    address.bytes = parsed.octets();
    address
}

pub fn self_test() {
    for global in ["2607:f8b0:4005:806::200e", "2001:4860:4860::8888"] {
        assert!(is_global_v6(&global.parse().unwrap()), "{global}");
    }
    for non_global in [
        "2001:db8::2",
        "3fff::1",
        "fe80::1",
        "fd00::1",
        "fec0::1",
        "::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!is_global_v6(&non_global.parse().unwrap()), "{non_global}");
    }

    let mut answer = [
        v6_address("2607:f8b0::1"),
        v4_address([142, 250, 1, 1]),
        v6_address("2001:db8::7"),
        v6_address("2607:f8b0::2"),
    ];
    assert!(!only_unusable_answers(&answer));
    demote_global_v6(&mut answer);
    assert_eq!(answer[0].bytes[..4], [142, 250, 1, 1]);
    assert_eq!(answer[1].bytes, v6_address("2001:db8::7").bytes);
    assert_eq!(answer[2].bytes, v6_address("2607:f8b0::1").bytes);
    assert_eq!(answer[3].bytes, v6_address("2607:f8b0::2").bytes);

    assert!(only_unusable_answers(&[v6_address("2607:f8b0::1")]));
    assert!(!only_unusable_answers(&[]));
    assert!(!only_unusable_answers(&[v4_address([8, 8, 8, 8])]));

    // The probe must complete against the running sys-io; the verdict
    // itself belongs to the environment.
    println!(
        "dns-resolver: global IPv6 answers rank {}",
        if v6_ranks_last() {
            "last (no global IPv6 source)"
        } else {
            "normally"
        }
    );
}
