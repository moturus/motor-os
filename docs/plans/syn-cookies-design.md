# SYN cookies (step 4 design -- for review, nothing implemented)

2026-08-11. Step 4 of `networking-remaining-steps.md`, scheduled
2026-08-10 (Motor is expected to face untrusted networks as a server)
and queued behind the RACK-TLP series, which is now landed. This doc is
the design round; per the run scope ruling it stops at review.

## What already exists on purpose

- The half-open admission machinery (`sys-io/runtime/net/half_open.rs`):
  a global cap (128) and a per-listener cap (32) bound how many
  embryonic connections exist at once. Today, at the cap, further SYNs
  are simply not admitted -- flood damage is bounded, but so is
  legitimate admission during a flood. The cap is the natural
  engagement trigger: cookies are what admission does INSTEAD of
  refusing once the cap is hit.
- The RFC 6528 ISN (`Context::tcp_isn`, SipHash over the 4-tuple and a
  boot secret) is the cookie primitive: the same keyed-hash shape, so
  the cookie needs no new cryptography.
- RFC 7323 timestamps are landed with TS.Recent echo; TSopt is the
  side channel that carries the peer's advertised wscale and
  SACK-permitted through the stateless window (the classic Linux
  scheme), so cookie-restored connections keep both.
- The listener backlog pool builds sockets lazily with 16 KiB floor
  rings (step 2), so a cookie-validated ACK can be given a real socket
  cheaply at restoration time.
- Window accounting was normalized during the hardening knowing
  cookies would add a second writer of initial state.

## Design

**Engagement.** Cookies are off in normal operation (full state keeps
its RTT sample from the handshake and needs no encoding limits). When
a listener's half-open cap or the global cap would refuse a SYN, the
SYN is answered with a cookie SYN|ACK instead and NO state is created:
the half-open slot stays free, the flood holds nothing.

**The cookie (ISN).** Classic layout over the RFC 6528 primitive:

    ISN = t << 24 | mss_idx << 21 | H(secret, tuple, t) & 0x1fffff

with `t` a 64-second counter (low 8 bits), `mss_idx` one of eight
canonical MSS values (536, 1220, 1440, 1460 cover the real world; the
peer's advertised MSS rounds down), and H the SipHash the ISN already
uses, re-keyed with a cookie-specific secret derived at boot. The
SYN|ACK carries the usual options; our advertised wscale (from the
listener's configured buffer size, step 2) and SACK-permitted ride
TSval per the Linux scheme:

    TSval = ts_clock << 6 | our_wscale << 2 | sack_ok << 1 | ecn(0)

The peer echoes TSecr on its ACK, returning what we advertised; its
OWN wscale and SACK offer, normally lost with the SYN, are also
recovered from the echo -- we encode what the SYN offered, not what we
chose. (Precisely: the six low bits carry peer_wscale (4 bits),
peer_sack (1), spare (1); our own choices are recomputed from the
listener config at restoration, which is deterministic.)

**Validation and restoration.** An ACK that matches no socket and no
half-open entry, arriving at a listening port, is checked:
`ack - 1` must verify against H for `t` or `t - 1` (128 seconds of
validity, two counter periods). On success a backlog socket is built
exactly as the pool builds one today (floor rings, configured shift,
growth latched), forced straight to ESTABLISHED with the sequence
state reconstructed: RCV.NXT = seg.seq, SND.UNA = SND.NXT = ack,
remote MSS from mss_idx, peer wscale/SACK from TSecr if present.
Without a timestamp echo the connection degrades safely: wscale 0,
no SACK (RACK still works from cumulative ACKs; the dupack fallback
covers loss). The restored socket then flows through the normal accept
path -- sys-io's listener sees a completed connection exactly as if
the pool had carried it.

**What cookie mode costs, honestly.** No RTT sample from the
handshake (the first data exchange seeds rtte instead); MSS rounded
down to a canonical value; a stale ACK within the 128-second window
can conjure a connection the peer never completed (mitigated by the
hash width, 21 bits per counter period, and by counting restorations
in stats); no retransmission of the SYN|ACK (stateless -- a lost
cookie SYN|ACK relies on the peer's SYN retransmit drawing a fresh
one).

**Out of scope.** ECN negotiation through cookies (we do not negotiate
ECN at all yet); cookie mode for the no-listener RST path (unchanged);
IPv6 uses the same scheme (the hash input is the tuple either way).

## Patches (each 100-300 lines with tests, each 3+3 gated)

1. netstack: cookie mint/verify as pure functions beside `tcp_isn`
   (counter, MSS table, TSval pack/unpack), unit-tested including
   counter rollover and bad-cookie rejection.
2. netstack: stateless SYN|ACK reply path for a listening socket at
   cap ("answer without admitting"), and ACK-restoration
   (`Socket::restore_from_cookie`-shaped constructor into
   ESTABLISHED); packet tests for the full stateless handshake, the
   degraded no-TS peer, and stale/forged ACKs.
3. sys-io: wire the cap-refusal path to mint instead of drop, route
   unmatched ACKs at listening ports through verification, restored
   sockets into the accept queue; stats (`net.tcp.cookies_sent`,
   `cookies_accepted`, `cookies_rejected`). systest: flood a listener
   past the cap with raw SYNs while a legitimate connect completes.

## Decisions for review

- Engagement: at the cap only (proposed), or a config knob to force
  cookies always-on / always-off per listener?
- Validity window: two 64-second periods (proposed, Linux parity)?
- Degraded no-TS peers: accept with wscale 0 and no SACK (proposed,
  Linux parity), or refuse restoration without a timestamp echo?
- The stale-ACK exposure above: acceptable at 21 hash bits per period
  (proposed), or require TS echo as a second factor when present?
