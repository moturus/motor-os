# Per-socket buffer sizing (SO_RCVBUF / SO_SNDBUF): design

2026-08-10. The step 6(b) design round from
`networking-remaining-steps.md`, written for review before any code.
Reviewed and approved 2026-08-11 with one amendment, recorded in
place: `SO_RCVBUF` on an armed listener applies to later accepts
instead of erroring.
Decision context: WAN workloads are a product target (Question 7,
2026-08-10), so the 128 KiB per-direction default is a real throughput
cap (a 128 KiB window caps a 100 ms path at ~10 Mbit/s); the fixed
default raise (a) deliberately waits behind this design so listening
sockets do not pre-commit full-size buffers (Question 8).

## Facts this design rests on

- Buffers are built in sys-io at socket construction:
  `TCP_SOCKET_BUFFER_SIZE = 128 * 1024` per direction
  (`sys-io/src/runtime/net/socket/tcp.rs`), for outbound sockets and for
  the listener-owned sockets that serve accepts alike.
- The advertised window scale is derived from the receive capacity when
  the netstack socket is constructed (`remote_win_shift =
  rx_cap_log2.saturating_sub(16)`, `netstack/src/socket/tcp.rs`), and
  re-derived on the listen-time reset. It is announced in our SYN or
  SYN-ACK and is immutable for the connection thereafter (RFC 7323).
  Receive capacity is therefore a pre-SYN commitment; transmit capacity
  is purely local and is not.
- The io_channel `Msg` is 56 bytes with a 24-byte payload union. The
  connect request consumes the socket address (18 of 24 payload bytes in
  the IPv6 case), `args_8[23]` (subchannel), and `flags` (timeout); the
  bind request consumes the address and `flags` (backlog hint). Both
  leave at least 4 payload bytes free in the worst case.
- The vDSO ABI creates sockets in one shot (`tcp_connect(addr, timeout,
  nonblocking)`, `tcp_bind(addr)`): there is no descriptor that exists
  before setup begins, so a std caller cannot `setsockopt` before the
  SYN. Rust std has no pre-connect buffer API at all (only socket2
  does); mio on Motor likewise never sizes buffers pre-connect. The
  pre-SYN consumers are native `moto-io` users and any future
  builder-style ABI, not std.

## The shape: requested sizes ride construction; growth is the escape hatch

Two primitives, designed once, used by both this feature and the lazy
listening-socket buffers:

1. **Construct-with-shift.** The netstack socket gains
   `Socket::new_with_win_shift(rx, tx, shift)`: the announced window
   scale is taken from the argument, not from the rx ring actually
   allocated. The shift is computed from the *configured* receive
   capacity; the ring the socket starts with may be smaller. A small
   ring under a large shift is wire-legal (the window field simply reads
   small) and costs nothing: the shift only sets the ceiling the window
   can later express.
2. **Grow-an-empty-ring.** `SocketBuffer` gains `grow_to(bytes)`,
   callable only when the ring holds zero unconsumed bytes (assert), and
   the socket gains `grow_rx_capacity(bytes)` / `grow_tx_capacity(bytes)`
   that apply immediately if their ring is empty and otherwise latch and
   apply at the next empty point (rx: fully read out; tx: fully acked and
   drained). Growth never re-announces the shift; rx growth is capped at
   `65535 << shift`, the most the announced scale can express.

Shrinking is out of scope (declined, recorded): Linux also applies
shrinks lazily at best, the memory win is small against the
complexity of evicting queued data, and a workload that wants small
buffers asks for them at construction.

Implementation note (patch 2, 2026-08-11): "applies immediately if the
ring is empty" holds only once the connection is synchronized. In
Closed/Listen/SynSent/SynReceived a request latches even though the
rings are empty -- they are always empty there, and immediate
application would allocate at configure time, defeating lazy backlog
rings. Pending growth applies at the ESTABLISHED edge (inside
`set_state`, before any payload carried by the handshake-completing
segment can queue), at the `recv_slice`/ack drain points, and at
`dispatch` entry -- a growth latched behind a borrowing `recv` cannot
apply inside that call (the returned slice points into the ring), so it
applies on the next egress pass, before the window is computed.
`reset` clears latches, so sizes must be configured after listen/rearm.
rx re-clamps to `65535 << shift` at apply time (a peer without wscale
zeroes the shift).

## API surface

Native (`moto-io`): a `TcpSocketOptions { rx_buf: u32, tx_buf: u32 }`
(0 = default) parameter object, added as an `Option<&TcpSocketOptions>`
to `TcpStream::connect_reserved` and `TcpListener::bind_reserved`. No
builder type: the reservation-then-construct flow already is the
builder, and both calls already take option-shaped arguments
(timeout, observer).

vDSO ABI (`moto_rt::net`): two new option codes, `SO_RCVBUF = 13` and
`SO_SNDBUF = 14`, `u64` byte counts, plus one new ABI entry
`tcp_connect_with_options` / extension of the bind path (exact shim
shape at implementation time; the RT_VERSION bump rule applies). POSIX
semantics by state:

- Listener: applies to the listener's accepted-socket configuration
  (see inheritance below), at any time. Setting `SO_RCVBUF` after
  accepts are armed applies to later accepts (review ruling
  2026-08-11, replacing the first draft's `E_INVALID_ARGUMENT`):
  backlog sockets constructed after the change announce the new
  window scale and grow to the new size; a socket whose SYN-ACK
  commitment is already spent keeps the size whose scale it
  announced. `SO_SNDBUF` likewise applies to later accepts. Getters
  on the listener report the configured sizes; an accepted socket
  reports its own inherited effective sizes.
- Connected stream: `SO_SNDBUF` grows via the latch (always honest);
  `SO_RCVBUF` grows up to the announced-scale ceiling and clamps there.
- Getters always report the **effective** size: the ring capacity now,
  plus the latched target if one is pending (reported as the target,
  because it is committed and will apply without further caller
  action). A clamped request reads back clamped -- never the number the
  caller asked for. Silently reporting an unapplied size is not
  acceptable (standing rule).

std mapping: std exposes no buffer sizing, so nothing changes for std
users; they get defaults. The new codes serve native users, the mio
shim if it ever wants them, and tests.

## Wire encoding

Requested sizes travel in the existing connect and bind requests as two
spare payload bytes each: `ceil(log2(bytes / 16 KiB))` -- 0 means
default, values 1..=16 span 32 KiB..=1 GiB in power-of-two steps.
Power-of-two granularity is exactly what the ring allocator and the
window-scale math want, and two bytes always fit next to an IPv6
address. No new RPC, no second round trip, no ordering problem with the
SYN: the sizes arrive in the same message that causes it.

## Floors, caps, units, zero

- Unit: bytes on the API; rounded UP to the next power of two of 16 KiB
  or more internally. We do not double the caller's value (Linux's
  doubling is a bookkeeping artifact, not a contract worth copying);
  the rounding rule is documented at the option's declaration.
- Floor: 16 KiB per direction (below that, TSO/page interplay wastes
  more than it saves). Cap: 8 MiB per direction -- WAN-relevant
  (8 MiB / 100 ms ~= 670 Mbit/s), while `1 GiB` stays encodable for a
  future justified raise. Requests outside the range clamp and report
  the clamp (no error: matches POSIX practice and keeps portable code
  portable).
- Zero: reset to the build default (128 KiB today). `getsockopt` after
  a reset reports the default's effective value.

Memory accounting: buffer bytes stay inside sys-io's existing
per-process admission story; the cap bounds the per-socket worst case.
The 8 MiB cap was affirmed in review (2026-08-11).

## Listener timing, inheritance, and lazy listening-socket buffers

Accepted sockets inherit the listener's configured sizes (matches
Linux, and the SYN-ACK wscale is the listener's to announce anyway).
The listener's own demand-grown backlog sockets are where
construct-with-shift pays for itself:

- Today every backlog socket is built with full 128 KiB + 128 KiB.
- After: backlog sockets are built with the 16 KiB floor rings and the
  shift of the *configured* size, then grown to the configured size on
  reaching ESTABLISHED (both rings empty by definition at that point,
  so growth is immediate, before data can queue).
- 256 listeners with default sizing drop from 64 MiB of idle backlog
  buffers to 8 MiB, and the step 10 aggregate-exhaustion OOM item
  shrinks proportionally. A configured 8 MiB server socket costs its
  8 MiB only once a connection is real.

## Follow-ups riding on this design (recorded, unchanged)

- Ephemeral-port randomization unification: once a connect can pin its
  source port (the options struct is the natural carrier), the loopback
  exemption that keeps `test_simultaneous_open` deterministic can go.
- Receive autotuning stays deferred until fixed-plus-per-socket is shown
  insufficient on a real workload.

## Patch plan (each 100-300 loc, gated)

1. netstack: `SocketBuffer::grow_to` + construct-with-shift + unit
   tests (deterministic, harness-level).
2. netstack: grow latches on the socket + ESTABLISHED-edge growth +
   packet-level tests (window scale announced from config, window field
   from actual ring).
3. sys-io: wire decode, per-socket configured sizes, listener
   inheritance, lazy backlog rings.
4. moto-io + vdso ABI: options struct, SO codes, effective-size
   getters; systest coverage (pre-SYN request honored end to end:
   verify the announced wscale on a loopback capture via the packet
   harness; clamp reporting; latch semantics).
5. Optional after review: the default raise (a), now safe because
   listening sockets no longer pre-commit it.

Reviewed 2026-08-11, all three flagged items decided: the 8 MiB cap
stands; `SO_RCVBUF` on an armed listener applies to later accepts
instead of erroring (the listener-semantics bullet above is updated
accordingly); UDP sizing is declined for this series (the rx queue is
page-pool backed, so it is a different mechanism). The review also
approves deferring the fixed default raise until the lazy backlog
rings land.
