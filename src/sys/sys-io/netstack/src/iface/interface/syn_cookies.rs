//! SYN cookies: the stateless half of a listener under SYN flood.
//!
//! When admission would refuse a SYN, the SYN|ACK's sequence number is minted
//! here instead of a socket being built, and the connection state rides the
//! wire: the peer's completing ACK returns `cookie + 1`, and [`verify`]
//! decides whether that number could only have come from [`mint`]. What the
//! ISN cannot carry -- the peer's window scale and SACK offer, normally lost
//! with the unrecorded SYN -- rides the timestamp option: [`pack_tsval`] puts
//! it in the six low bits of TSval, and the peer's echo brings it home to
//! [`validate_tsecr`].
//!
//! Everything here is a pure function of its arguments; engagement policy and
//! socket restoration live with the callers.

// Callers arrive with the stateless reply path; until then only the tests
// call in.
#![cfg_attr(not(test), allow(dead_code))]

use crate::siphash::SipHasher24;
use crate::time::Instant;
use crate::wire::{IpEndpoint, TcpSeqNumber};

use super::tcp::{MAX_TUPLE_LEN, write_tuple};

/// The MSS values a cookie can carry, ascending. Three index bits leave room
/// for eight; these four cover the real world (RFC 1122's default, the IPv6
/// minimum-MTU path, tunneled Ethernet, plain Ethernet). A peer's advertised
/// MSS rounds down to one of them, so a restored connection never sends larger
/// segments than the peer asked for.
const MSS_TABLE: [u16; 4] = [536, 1220, 1440, 1460];

/// Bits 20..0 of the cookie hold the tag; bits 23..21 the MSS index; bits
/// 31..24 the counter's low byte.
const TAG_MASK: u32 = 0x1f_ffff;

/// The cookie counter: one period per 64 seconds. A cookie is honored for the
/// current and the previous period (128 seconds), Linux parity. Arithmetic
/// shift, like [`super::tcp`]'s ISN timer: `Instant` is signed and flooring
/// keeps the counter monotone either side of its origin.
pub(crate) fn counter(now: Instant) -> i64 {
    now.secs() >> 6
}

/// The ISN a cookie SYN|ACK carries, for a SYN from `remote` with the given
/// advertised MSS (`None` when the SYN carried no MSS option).
pub(crate) fn mint(
    key: &SipHasher24,
    local: IpEndpoint,
    remote: IpEndpoint,
    counter: i64,
    peer_mss: Option<u16>,
) -> TcpSeqNumber {
    let mss = peer_mss.unwrap_or(MSS_TABLE[0]);
    let mss_idx = MSS_TABLE.iter().rposition(|&v| v <= mss).unwrap_or(0);

    let isn = ((counter as u32) << 24)
        | ((mss_idx as u32) << 21)
        | (tag(key, local, remote, counter) & TAG_MASK);
    TcpSeqNumber(isn as i32)
}

/// Whether `isn` (the completing ACK's `ack - 1`) is a cookie this machine
/// minted for this 4-tuple within the validity window. `Some` carries the MSS
/// the mint recorded.
///
/// The counter byte and MSS index ride in the clear: the counter byte only
/// selects which full counter value the tag is recomputed under -- a
/// 256-period-old cookie shares the byte but not the tag -- and the index is
/// the peer's own MSS claim, every value of which is one it could have
/// advertised anyway.
pub(crate) fn verify(
    key: &SipHasher24,
    local: IpEndpoint,
    remote: IpEndpoint,
    counter_now: i64,
    isn: TcpSeqNumber,
) -> Option<u16> {
    let isn = isn.0 as u32;
    for t in [counter_now, counter_now - 1] {
        if t as u32 & 0xff == isn >> 24 && tag(key, local, remote, t) & TAG_MASK == isn & TAG_MASK {
            return MSS_TABLE.get((isn >> 21 & 0x7) as usize).copied();
        }
    }
    None
}

/// The keyed tag binding a cookie to its 4-tuple and full counter value.
fn tag(key: &SipHasher24, local: IpEndpoint, remote: IpEndpoint, counter: i64) -> u32 {
    let mut tuple = [0_u8; MAX_TUPLE_LEN];
    let len = write_tuple(&mut tuple, local, remote);

    let mut msg = [0_u8; MAX_TUPLE_LEN + 8];
    msg[..len].copy_from_slice(&tuple[..len]);
    msg[len..len + 8].copy_from_slice(&counter.to_le_bytes());
    key.hash(&msg[..len + 8]) as u32
}

/// What the peer's SYN offered, recovered from its timestamp echo.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TsEcho {
    /// `None` when the SYN carried no window-scale option: RFC 7323 then
    /// forbids scaling in either direction, which is not the same as scaling
    /// by zero.
    pub(crate) peer_wscale: Option<u8>,
    pub(crate) peer_sack: bool,
}

/// The wscale nibble value that stands for "no window-scale option".
const WSCALE_NONE: u32 = 0xf;

/// How stale a TSecr's clock may be: the cookie validity window (128 s) in
/// the 64 ms ticks that survive the six-bit shift.
const TS_FRESH_TICKS: u32 = 2000;

/// The shifted clock is 26 bits wide; its arithmetic wraps there.
const TS_CLOCK_MASK: u32 = (1 << 26) - 1;

/// The TSval a cookie SYN|ACK advertises: the timestamp clock's current value
/// with the six low bits repurposed to carry the peer's own offer back to us
/// -- wscale nibble, SACK bit, and a spare bit kept zero.
///
/// The 64 ms the repurposing costs is noise to the peer's RTT estimate, and
/// PAWS at the peer is per-connection, so the value only has to be plausible,
/// not exact.
pub(crate) fn pack_tsval(ts_now: u32, peer_wscale: Option<u8>, peer_sack: bool) -> u32 {
    // RFC 7323 caps the shift at 14; a larger advertisement means the peer is
    // broken and gets the cap, which is also all the nibble can hold.
    let wscale = match peer_wscale {
        Some(w) => (w as u32).min(14),
        None => WSCALE_NONE,
    };
    (ts_now & !0x3f) | (wscale << 2) | ((peer_sack as u32) << 1)
}

/// The second validation factor: whether `tsecr` is a TSval [`pack_tsval`]
/// could have produced within the validity window. `None` refuses the
/// restoration even when the cookie's tag verified.
///
/// Every wscale nibble decodes (fifteen stands for no option at all), so the
/// checks with teeth are the spare bit -- always minted zero -- and the
/// clock's freshness. An ACK without a timestamp option never reaches here;
/// degraded restoration is the caller's decision.
pub(crate) fn validate_tsecr(tsecr: u32, ts_now: u32) -> Option<TsEcho> {
    if tsecr & 1 != 0 {
        return None;
    }
    // Rejects the future as a special case of stale: a clock ahead of ours
    // wraps into an enormous age.
    let age = (ts_now >> 6).wrapping_sub(tsecr >> 6) & TS_CLOCK_MASK;
    if age > TS_FRESH_TICKS {
        return None;
    }

    let wscale = tsecr >> 2 & 0xf;
    Some(TsEcho {
        peer_wscale: (wscale != WSCALE_NONE).then_some(wscale as u8),
        peer_sack: tsecr & 0b10 != 0,
    })
}

#[cfg(all(test, feature = "proto-ipv4"))]
mod tests {
    use super::*;
    use crate::wire::IpAddress;

    const KEY: SipHasher24 = SipHasher24::new([0x5a; 16]);
    const T: i64 = 1_000;

    fn endpoint(host: u8, port: u16) -> IpEndpoint {
        IpEndpoint::new(IpAddress::v4(192, 0, 2, host), port)
    }

    fn tuple() -> (IpEndpoint, IpEndpoint) {
        (endpoint(1, 80), endpoint(2, 49152))
    }

    fn mint_here(counter: i64, peer_mss: Option<u16>) -> TcpSeqNumber {
        let (local, remote) = tuple();
        mint(&KEY, local, remote, counter, peer_mss)
    }

    fn verify_here(counter_now: i64, isn: TcpSeqNumber) -> Option<u16> {
        let (local, remote) = tuple();
        verify(&KEY, local, remote, counter_now, isn)
    }

    /// The advertised MSS comes back rounded down to a table value, and a SYN
    /// without the option gets the protocol default.
    #[test]
    fn the_mss_survives_the_roundtrip_rounded_down() {
        for (advertised, restored) in [
            (None, 536),
            (Some(400), 536),
            (Some(536), 536),
            (Some(1219), 536),
            (Some(1400), 1220),
            (Some(1452), 1440),
            (Some(1460), 1460),
            (Some(u16::MAX), 1460),
        ] {
            let cookie = mint_here(T, advertised);
            assert_eq!(verify_here(T, cookie), Some(restored), "{advertised:?}");
        }
    }

    /// A cookie is honored for its own period and the next, and no further:
    /// two periods is the whole validity window.
    #[test]
    fn the_window_is_two_periods() {
        let cookie = mint_here(T, None);

        assert_eq!(verify_here(T, cookie), Some(536));
        assert_eq!(verify_here(T + 1, cookie), Some(536));
        assert_eq!(verify_here(T + 2, cookie), None);
        // From the verifier's future, i.e. a guessed not-yet-minted counter.
        assert_eq!(verify_here(T - 1, cookie), None);
    }

    /// The tag covers the full counter, not the byte the cookie carries: a
    /// replay from 256 periods ago matches the byte and still dies.
    #[test]
    fn a_counter_byte_collision_does_not_replay() {
        let cookie = mint_here(T, None);
        assert_eq!(verify_here(T + 256, cookie), None);
    }

    /// Tampering with tag or counter bits kills the cookie. The MSS index
    /// bits are the recorded exception: they ride in the clear, so flipping
    /// one inside the table merely selects a different canonical MSS, and
    /// flipping the index out of the table refuses.
    #[test]
    fn a_flipped_bit_is_rejected() {
        let cookie = mint_here(T, None).0 as u32;

        for bit in (0..21).chain(24..32) {
            let bent = TcpSeqNumber((cookie ^ (1 << bit)) as i32);
            assert_eq!(verify_here(T, bent), None, "bit {bit}");
        }
        assert_eq!(
            verify_here(T, TcpSeqNumber((cookie ^ (1 << 21)) as i32)),
            Some(1220)
        );
        // Index 4, past the table's end.
        assert_eq!(
            verify_here(T, TcpSeqNumber((cookie ^ (1 << 23)) as i32)),
            None
        );
    }

    /// A cookie binds to its 4-tuple and its key.
    #[test]
    fn the_tuple_and_the_key_both_bind() {
        let (local, remote) = tuple();
        let cookie = mint_here(T, None);

        assert_eq!(verify(&KEY, local, endpoint(2, 49153), T, cookie), None);
        assert_eq!(verify(&KEY, endpoint(3, 80), remote, T, cookie), None);

        let mut other = [0x5a; 16];
        other[0] ^= 1;
        assert_eq!(
            verify(&SipHasher24::new(other), local, remote, T, cookie),
            None
        );
    }

    /// One counter period per 64 seconds, floored.
    #[test]
    fn the_counter_ticks_every_64_seconds() {
        assert_eq!(counter(Instant::from_secs(0)), 0);
        assert_eq!(counter(Instant::from_secs(63)), 0);
        assert_eq!(counter(Instant::from_secs(64)), 1);
        assert_eq!(counter(Instant::from_secs(-1)), -1);
    }

    /// What pack_tsval encodes, validate_tsecr returns -- for every wscale
    /// the nibble can carry, the no-wscale case, and both SACK answers.
    #[test]
    fn the_peer_offer_survives_the_echo() {
        const TS: u32 = 0xdead_beef;

        for wscale in (0..=14).map(Some).chain([None]) {
            for sack in [false, true] {
                let echo = validate_tsecr(pack_tsval(TS, wscale, sack), TS);
                assert_eq!(
                    echo,
                    Some(TsEcho {
                        peer_wscale: wscale,
                        peer_sack: sack
                    })
                );
            }
        }
        // A broken peer's oversized shift comes back capped at RFC 7323's 14.
        assert_eq!(
            validate_tsecr(pack_tsval(TS, Some(30), false), TS),
            Some(TsEcho {
                peer_wscale: Some(14),
                peer_sack: false
            })
        );
    }

    /// The clock check accepts the whole validity window, wrap included, and
    /// nothing outside it in either direction.
    #[test]
    fn the_echo_must_be_fresh() {
        const TS: u32 = 5_000_000;
        let minted = pack_tsval(TS, None, false);

        assert!(validate_tsecr(minted, TS).is_some());
        assert!(validate_tsecr(minted, TS + 128_000).is_some());
        assert!(validate_tsecr(minted, TS + 128_000 + 64).is_none());
        // A clock ahead of ours is stale by wraparound.
        assert!(validate_tsecr(minted, TS - 64).is_none());

        // The 32-bit clock wrapping between mint and echo is routine at
        // 49-day uptimes.
        let late = pack_tsval(u32::MAX & !0x3f, None, false);
        assert!(validate_tsecr(late, 64_000).is_some());
    }

    /// The spare bit is minted zero; set, it refuses the restoration.
    #[test]
    fn the_spare_bit_refuses() {
        const TS: u32 = 5_000_000;
        assert!(validate_tsecr(pack_tsval(TS, None, true) | 1, TS).is_none());
    }
}
