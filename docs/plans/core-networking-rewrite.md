# Core networking: smoltcp fork refactor/rewrite

2026-07-26. Plan only. No code changes accompany this document.

Fourth of the networking plans. `virtio-rx-coalescing.md` raises the receive
packet-rate ceiling, `tcp-receive-window.md` raises the single-stream window,
`vdso-rewrite.md` fixes the client-side async boundary. This one covers the
stack itself: the `moturus/smoltcp` fork and the sys-io code that drives it.
The authoritative cross-plan execution order and status are in
`docs/plans/networking-step-by-step.md`.

All findings below were verified against the tree at `d6bcf1de` and the fork
checkout at `d2ff65b`. Citations are `file:line`; `SM/` is the fork's `src/`,
`SI/` is `src/sys/sys-io/src/runtime/net/`. Step 0 moves `SM/` in-tree to
`src/sys/sys-io/netstack/src/`.

## Summary and headline recommendation

**Do not rewrite the stack. The largest safety and performance wins available
are not rewrites, and doing them first is worth more than the rewrite would
be.**

The single most valuable change is deleting code: sys-io depends on smoltcp
with **default features** (`sys-io/Cargo.toml:32`), compiling 6LoWPAN, DHCP,
DNS, mDNS, raw sockets, multicast, SLAAC, RPL wire, and IPv4 fragmentation --
roughly 55-65% of the fork's ~55.6k LOC that Motor never uses. One of those
features carries a trivial remote DoS that has nothing to do with any code we
wrote. `default-features = false` plus an explicit list is a one-line change
that removes ~30k LOC of attack surface.

Status: the Step 4 feature trim against the owned `moto-netstack` is fully
gated. Host and Motor checks, paired KVM performance measurements, and three
debug plus three release focused full-OS suites pass.

The second most valuable is a handful of one-line constant and flag changes
whose current values are actively hostile to a hypervisor guest: congestion
control was **entirely absent from Motor's build** (cwnd was `usize::MAX`) --
Cubic enabled and made load-bearing 2026-08-02, execution Step 10 item 1 -- the
minimum RTO was **1 second**, now 200 ms as of Step 10 item 2 part three -- and
the out-of-order assembler held **4 segments**, now 32 as of Step 10 item 3.

The third is fixing sys-io's own panic surface, which includes a **one-packet
remote kill** of all networking on the machine.

Only after those does architectural work pay: smoltcp's O(N)-per-packet
socket scans and its contiguous-buffer token contract are genuine structural
limits that no amount of tuning removes. Those are the parts worth
rewriting, and they should be scoped against measurements taken after the
cheap work lands.

## Correction to the other plan docs

`virtio-rx-coalescing.md` and this series elsewhere state the fork is "stock
v0.13.0 plus exactly one commit". That is wrong. `git log df66ffe..HEAD`
(v0.13.0 to fork HEAD) shows **four** commits, +202/-116 across 7 files:

| Commit | Author | Date | What |
|---|---|---|---|
| `25d4f7c` | Dario Nieuwenhuis | 2026-04-03 | upstream: tcp SACK sequence-number overflow fix |
| `faa1603` | Artem Kryvokrysenko | 2026-04-03 | upstream: IPv4 IHL >= 20 check |
| `44ecae4` | U. Lasiotus | 2026-04-07 | Motor: configurable neighbor-discovery silent time |
| `d2ff65b` | U. Lasiotus | 2026-07-12 | Motor: implement TSO |

Two upstream cherry-picks, two Motor commits. The divergence is still small
and cheap to rebase, which is the central fact this plan is built around.

Fix the claim in `virtio-rx-coalescing.md` when that plan is next touched.

## What we actually run

**Integration shape** (this part is good; see "What to preserve"). One
`moto_async::LocalRuntime` thread pinned to CPU 0 drives everything
(`sys-io/src/runtime/mod.rs:132-140`); all state is `Rc`/`RefCell`, no locks.
`Interface::poll` has exactly one call site (`SI/device.rs:501,504`), driven
by a per-device task (`sys-io/src/runtime/net.rs:120-182`) that selects
between a device notify and a `poll_delay()`-armed sleep. Readiness reaches
clients through smoltcp's own wakers -- `register_recv_waker`
(`SI/socket/tcp.rs:717`) and `register_send_waker` (`:840`) -- so sys-io
never scans sockets after a poll. Per-device `SocketSet`s partition all
state; sockets never cross devices (`SI/socket.rs:4-14`).

**Feature set compiled at the planning baseline** (from the build
fingerprint): `default`, i.e. `medium-ieee802154`,
`proto-sixlowpan{,-fragmentation}`,
`proto-dhcpv4`, `socket-dhcpv4`, `proto-dns`, `socket-dns`, `socket-mdns`,
`socket-raw`, `multicast`, `proto-ipv6-slaac`, `proto-ipv4-fragmentation`,
`auto-icmp-echo-reply`, `phy-raw_socket`, `phy-tuntap_interface`, plus the
parts Motor uses (`medium-ethernet`, `proto-ipv4`, `proto-ipv6`,
`socket-tcp`, `socket-udp`, `socket-icmp`, `async`, `std`).

Motor uses `medium-ethernet` for configured virtio devices, `medium-ip` for
logical loopback, static IP config (`SI/config.rs`), and TCP/UDP/ICMP sockets.
DNS lives in a separate `dns-resolver` crate. Nothing creates a DHCP, DNS,
mDNS, or raw socket.

Step 2 selects only `std`, `async`, `medium-ethernet`, `medium-ip`,
`proto-ipv4`, `proto-ipv6`, `socket-tcp`, `socket-udp`, and `socket-icmp`.
The compile-time echo-reply feature is replaced by the explicit
`auto_icmp_echo_reply` sys-io policy, enabled in the shipped configuration.

**Fixed-capacity tables in the compiled config** (`OUT_DIR/config.rs`), all
`heapless` regardless of `alloc` being on:

| Constant | Value | Consequence |
|---|---|---|
| `IFACE_NEIGHBOR_CACHE_COUNT` | 8 -> **64** | ARP entries per interface, linear-scan map; the scan is over occupancy, not capacity |
| `IFACE_MAX_ROUTE_COUNT` | 2 -> **8** | 2 was exactly v4+v6 defaults, and one more aborted sys-io at boot |
| `IFACE_MAX_ADDR_COUNT` | 2 -> **8** | scanned per `tcp::dispatch`; 2 was exactly one dual-stack device |
| `ASSEMBLER_MAX_SEGMENT_COUNT` | 4 | 3 out-of-order holes max |
| `REASSEMBLY_BUFFER_COUNT` | 1 | one IP reassembly in flight, machine-wide |

**Important:** turning on `alloc` did **not** relax any of these. They are
`heapless::Vec`/`LinearMap`/arrays sized by build-time constants
(`SM/iface/neighbor.rs:47`, `route.rs:81`, `storage/assembler.rs:99`,
`iface/fragmentation.rs:192`). The std/alloc opportunity is real but it is
not free: it requires replacing the data structures, not flipping a feature.

## Safety findings

### P0: one-packet remote kill

Status: the first Step 1 patch removed the connect-task `panic!` and
`todo!()` paths described below. Its compile-time check covers every smoltcp
TCP state; it treats `SynSent`/`SynReceived` as pending,
`Established`/`CloseWait` as connected, and all other states as failed. The
reachable-abort audit then found a separate client-disconnect race: the
connection loop can remove `ClientConnection` before an already spawned
resource-creation task is first polled, after which listener/socket
registration unwraps the missing client and aborts sys-io. The first staged
fix now rejects queued control tasks after client teardown and has a
synchronized raw-channel regression. Its exact source state passed three
consecutive debug and three consecutive release full suites. A separately
discovered monotonic `net.total_clients` accounting bug is now corrected and
covered by a sequential-client regression. Its exact source state also passed
three consecutive debug and three consecutive release full suites. The accept
path now discards requests from closed clients, validates a new owner before
removing the listener's ownership, and requeues an established socket if the
new owner disappears during handoff. A raw cross-connection regression passed
three consecutive debug and three consecutive release full suites. Shared
socket registration now rejects inactive clients and removes its smoltcp
socket; later TCP connect and UDP bind failures release all registered and
reserved resources. A deterministic failed-connect regression and the exact
source state passed three consecutive debug and three consecutive release
full suites. Listener binds now reject conflicts after wildcard resolution,
and ephemeral listener allocation skips ports held by fixed listeners on the
same concrete endpoint. Its raw regression and exact source state passed three
consecutive debug and three consecutive release full suites. Transactional
listener pool creation is now complete: creation failures are propagated
after shared unregister-first cleanup removes both ownership records and
tears down any partial socket pool. The current non-yielding creation loop
does not expose a deterministic public partial-failure trigger, so the shared
primitive is covered through existing cancelled-bind and listener-drop tests
rather than production failure injection. The exact rollback source state
passed focused debug/release builds and clippy plus three consecutive debug
and three consecutive release full suites without retries or tolerated
failures. Simultaneous open now has a deterministic self-connect regression,
whose exact source state passed the same focused checks and three consecutive
debug plus three consecutive release full suites. The batched `SYN|ACK + FIN`
case has no in-order peer that can produce it; guidance decided it gets no
harness now, since the state is handled and the classification is
compile-time locked, and it is carried as a final-verification obligation and
a Step 5 corpus seed. Step 1 is complete.

At audit time, `SI/socket/tcp.rs:544` panicked on
`State::Listen | State::SynReceived`, and `:553-558` plus `:576-588` contained
fourteen `todo!()`s covering every other TCP state.
`src/sys/Cargo.toml:62,65` sets `panic = "abort"` for both profiles, so any of
these took down sys-io and with it all networking on the machine.

These were reachable from the wire, not just theoretically:

- **Simultaneous open.** smoltcp implements RFC 9293 simultaneous open: a
  bare SYN (no ACK) received in `SynSent` moves the socket to `SynReceived`
  (`SM/socket/tcp.rs:1893-1928`, verified). sys-io's connect task then hit
  the former `panic!` at `SI/socket/tcp.rs:544`. **One packet from a peer we
  connected to, no handshake required.** It now remains pending. A TCP
  self-connect reaches this state through the ordinary API, and is the
  regression test: a socket dialing its own endpoint receives its own bare
  SYN. Verified directly against the fork, which reports
  `SynSent -> SynReceived -> Established` and then echoes payload to itself.
- **Batched SYN|ACK + FIN.** `Interface::poll` drains the entire RX queue
  before the executor runs again (`SM/iface/interface/mod.rs:490-496`), so a
  peer can drive `SynSent -> Established -> CloseWait` within one poll batch;
  the connect task observed `CloseWait` and hit `todo!()` at `:556`. It now
  reports the completed connection before normal close processing. No
  in-order peer produces the batch -- a correct FIN can only follow our own
  ACK -- so the regression needs crafted packets and waits for the Step 5
  harness. Receive coalescing makes the batch more likely, not less.

This is sys-io code, not smoltcp code, and it is fixable in isolation. It
should be fixed regardless of every other decision in this document.

Related, lower severity: `Err(_err) => todo!()` in the TX loop
(`SI/socket/tcp.rs:923`), `assert!` on every RX completion
(`SI/device.rs:155`), `.unwrap()` on `IoBuf` allocation (`SI/device.rs:50`),
the buffer-cache oversize `assert!` and the UDP-address and ICMP-identifier
removal asserts, and a live-in-release `assert!` whose
`#[cfg(debug_assertions)]` was commented out (`sys-io/src/runtime/net.rs:364`).
**All of these are fixed by Step 6 patch 4**: each logs and recovers locally,
with no change on the success path. Config parsing still panics on more than 2
CIDRs or 2 routes (`SI/device.rs:427,440`); those are boot-time configuration
errors, not packet- or client-reachable, and were left out of that patch.

### P1: remote resource exhaustion

**IPv4 fragment reassembly -- one packet, 60 seconds, machine-wide.** There
is exactly one reassembly slot (`REASSEMBLY_BUFFER_COUNT = 1`,
`SM/iface/fragmentation.rs:192`). A single crafted fragment with `MF=1` and
a high offset claims it, allocates ~128KB (`alloc` makes the buffer a `Vec`
that resizes with no bound, `fragmentation.rs:147-150`), and holds it for the
full 60-second timeout (`SM/iface/interface/mod.rs:265`), which is set at
claim time and never refreshed. **All fragmented IPv4 traffic for the whole
machine dies, at a cost of one packet per minute.** Compounding it,
`fragmentation.rs:1` is `#![allow(unused)]`, which suppresses
`unused_must_use`, so the `TooManyHolesError` from `add()` at `:131,161` is
silently discarded.

Motor does not need IPv4 fragmentation. Dropping `proto-ipv4-fragmentation`
deletes this entire class of bug.

**SYN flood -- unbounded 256KB per SYN.** Every listening socket is a full
TCP socket with 128KB rx + 128KB tx rings allocated at creation
(`SI/socket/tcp.rs:231-233`). A SYN consumes one and immediately spawns a
replacement (`:340-351`). Half-open sockets are reaped only by the 15-second
timeout (`:328`), and nothing caps their number: steady-state memory is
roughly `SYN_rate x 15s x 256KB`, i.e. ~384MB at 100 SYN/s and ~3.8GB at
1000 SYN/s. There are no SYN cookies, no accept-queue cap, and no
per-source limit anywhere.

It also interacts quadratically with the demux scan below: N half-open
sockets make each subsequent SYN cost an O(N) scan.

Measured by Step 6 patch 8 -- `net.tcp.half_open` (how many exist now),
`net.tcp.half_open_total` (how many there have been), and
`net.tcp.syn_rst_unmatched` (connection requests no socket took) -- and capped by
patch 9, at 128 globally and 32 per listener, both configurable in
`/sys/cfg/sys-net.toml`. At the cap the listening pool stops being refilled, so
the memory a flood commands is bounded by the cap plus whatever was still
listening when it was reached.

**Backlog is effectively 4 per poll batch, and overflow gets RST.**
`DEFAULT_NUM_LISTENING_SOCKETS = 4` (`SI/tcp_listener.rs:11`), and
replenishment is asynchronous -- it cannot run until the executor is
scheduled, which happens only after `poll()` has drained the whole RX queue.
So the 5th SYN in one batch matches no listening socket, and smoltcp replies
**RST** rather than dropping it (`SM/iface/interface/tcp.rs:44`). Five
concurrent honest connects are enough; the client sees `ECONNREFUSED` and
does not retry. That unmatched-SYN RST path is also unrate-limited, making it
a 1:1 reflector.

Fixed by Step 6 patches 10 and 10.1: a pool that a burst drains doubles, bounded
per listener and globally over what growth added, and a sweep returns the growth
once the bursts stop, so the depth is demand-driven in both directions. The
trigger is the refusal itself -- the netstack reports the local endpoint of every
connection request it resets -- because a pool the stack ran out of inside a poll
can never look empty to the accounting that runs after it. Measured
against the default pool of four, sixteen simultaneous connects lost 42 of 80
before and 2 of 80 after.

Patch 10.2 answers the rest: a connection request for an endpoint a listener
owns -- one it is merely out of sockets for -- is now dropped rather than reset,
so the peer retransmits into the deepened pool instead of failing. Guest-side
bursts of 24 against a four-deep pool lost 74 of 120 before and none of 120
after. A port no listener owns keeps its RST, so `ECONNREFUSED` still means what
it means; that path is still an unrate-limited 1:1 reflector, which is
unchanged, but a listening port no longer answers a flood at all.

**ARP cache thrash.** Was 8 entries, now 64 (Step 10 item 4), with earliest-expiry eviction
(`SM/iface/neighbor.rs:47,119-128`), fillable by any same-subnet ARP request
aimed at us (`SM/iface/interface/ipv4.rs:297`). Eight forged requests evict
every legitimate entry including the gateway. The rate limit is a single
global `silent_until` (`neighbor.rs:48,165-167`), which sys-io sets to
**5 ms** (`SI/device.rs:397` -- the fork's own `44ecae4` knob, 200x more
aggressive than upstream's 1s), so the flood also amplifies ARP requests.

Step 6 patch 11 closed the first half: an unsolicited packet -- an ARP request
or its IPv6 counterpart, a neighbor solicitation -- may refresh a cached
mapping or take a free slot but may never displace an entry, so forged requests
no longer evict anything. A reply to a request of our own keeps the evicting
fill, which is what still lets our own resolution through a cache someone has
filled. Patch 12 then took the routers out of that remaining path's reach: the
evicting fill picks its victim among the entries no unexpired route depends on,
so forged replies displace only entries nothing routes through, and no eviction
an off-path peer can aim reaches the gateway. Patch 13 closed the amplification
half: the global `silent_until` is now a per-destination map, so an address that
never answers holds back requests for itself alone instead of starving discovery
of every other destination for the interval. All three landed 2026-08-01.

### P2: protocol hardening gaps

**A drained socket was closed with RST, not FIN. Found 2026-08-02, fixed
2026-08-02.** Found while building the flow-completion benchmark for execution
Step 10 item 1c; not previously recorded, and reproduced on the first
connection of every attempt.

`close_tcp_socket_inner` (`SI/runtime/net/socket/tcp.rs`) decided between a
graceful close and an abort with

```rust
let drained = state.tx_queue.is_empty() && netstack_socket.send_queue() == 0;
drained || Some(0) == state.linger_secs
```

and `abort` sent `linger_secs = 0`, which goes straight to `drop_tcp_socket()`
and `netstack_socket.abort()` -- an RST. So a socket that had *nothing left to
send* was reset rather than finished. The graceful path existed and worked, but
only won when there was still unsent data. The comment at the condition shows
the intent was the reverse worry -- do not abort while data is pending -- and
the drained case simply inherited the abort.

The shape that hits it is a server that finishes writing, waits, and then
closes: by then the peer has acknowledged everything, so `send_queue()` is zero.
`write` immediately followed by `close` usually escaped, because the data was
still unacknowledged at that moment. Confirmed empirically rather than inferred:
a host client that read a complete response from an in-Motor server and then
half-closed got `ECONNRESET`, which Linux reports only on a received RST. Every
attempt failed on flow 1, at both a 1KB and a 64KB buffer size, so it was not a
resource or accumulation effect.

The fix replaces the boolean with an explicit `CloseAction`:

- **`Abort`** on `SO_LINGER(0)`, and on a close that still has *unread* data in
  the receive queue. The second is Linux's rule and is required here rather than
  merely conventional: the close stops draining the receive half, so a FIN would
  leave the peer waiting on a window that never reopens.
- **`Finish`** otherwise, when nothing of ours is left to hand over --
  `netstack_socket.close()` is called in the close path itself, and
  moto-netstack puts whatever is still in its own send buffer ahead of the FIN.
  Calling it there also makes `may_send()` false, which is what stops
  `tcp_write_task` from re-registering the send waker the linger task takes
  over.
- **`DrainThenFinish`** when the TX queue still holds client writes; the TX task
  closes when it has handed them over, as before, and signals the lingerer.

Two further changes were needed to make that safe rather than merely correct.
`tcp_linger_task` now waits for the close handshake on the netstack's send waker
instead of polling `is_open()` once a second -- with FIN on the common path,
that poll would have added ~1s of held buffers to *every* close (systest's
`test_simultaneous_open` measured exactly that: "1.008s vs 0 with SO_LINGER").
And it waits for the lingerer only in the `DrainThenFinish` case: that signal is
sent once, when the TX task ends, so a socket whose TX task had already finished
-- a `shutdown(WRITE)` then `close`, say -- would otherwise have waited out the
whole linger. `drop_tcp_socket` also no longer aborts a socket that is already
past its close handshake, which would have put an RST on the wire after a clean
FIN exchange (moto-netstack sends one for any CLOSED socket that still knows its
peer, which is what TIME-WAIT is).

Verified by the tool that found it: 50 fresh flows at 8KB and 50 at 64KB against
an in-Motor server, all ending in a clean EOF, where before every single one
ended in `ECONNRESET`.

Two behaviours this deliberately does not change, both worth recording. A peer
that half-closes and then holds its side open leaves the local socket in
FIN-WAIT-2 for up to `DEFAULT_LINGER_SECS` (60, matching Linux's
`tcp_fin_timeout`) -- correct, but a Motor socket holds its whole 128KiB of
buffers for that time, where Linux keeps only an orphan structure. And data
arriving *after* our FIN is not drained and does not trigger a reset, where
Linux resets an orphaned socket that receives new data; the receive window
simply stays shut until the linger expires.

**Predictable ISNs and ports.** Initial sequence numbers come from a
non-cryptographic PCG32 (`SM/rand.rs:14-25`) shared per-interface
(`SM/socket/tcp.rs:1061`), seeded from wall-clock nanoseconds at boot
(`SI/device.rs:393-396`). Consecutive connections are consecutive PRNG
outputs, so a peer that opens a few connections can recover the state and
predict all future ISNs on that interface. There is no RFC 6528 per-connection
hashing. sys-io compounds this by allocating ephemeral ports linearly from
49152 (`SI/device.rs:548,581`), making outbound source ports predictable too.
The seed half landed 2026-08-01 as Step 6 patch 17: each device now draws its
seed from the CPU's hardware RNG, so the state is no longer searchable offline
from an approximate boot time. The ISNs themselves landed the same day as patch
18, which replaced the shared generator with RFC 6528's `M + F(4-tuple, key)` --
SipHash-2-4 under a per-interface key drawn from the same hardware entropy, plus
a four-microsecond timer -- so recovering the PCG32 no longer says anything
about sequence numbers. The PCG32 remains for IPv4 identifiers and DNS
transaction ids, which are not secrets. The linear ports landed the same day as
patch 19: on a device that carries external traffic the allocator now starts its
scan at a uniform point in the ephemeral range (RFC 6056), drawn from the
hardware RNG rather than a generator, so no field of an outbound connection's
4-tuple is guessable any more. The logical loopback device keeps lowest-free
allocation, since a local process can already enumerate those ports through the
socket-stats service; patch 19 enforces that premise by dropping 127/8 addresses
arriving on external ingress. ICMP echo identifiers are still allocated
linearly, which is recorded in `core-safety-hardening.md` as a decision rather
than an oversight.

**RFC 5961 is not implemented.** RST acceptance skips the ACK check entirely
(`SM/socket/tcp.rs:1593`) and any in-window RST closes the connection
(`:1835-1840`). RFC 5961 requires `SEG.SEQ == RCV.NXT` exactly. With the
128KB window, blind off-path reset needs ~32768 guesses instead of 2^32 --
and combined with predictable ports above, that is practical rather than
theoretical. Section 3 landed 2026-08-01 as Step 6 patch 14: past SYN-SENT a
reset is acted on only at exactly `RCV.NXT`, one elsewhere in the window draws a
rate-limited challenge ACK, and one outside it is dropped unanswered, so the
blind reset is back to costing 2^32. Section 4 landed the same day as patch 15:
a SYN on a synchronized connection draws the same rate-limited challenge ACK
irrespective of its sequence number, so a rebooted peer redialling the tuple is
no longer stranded behind our stale socket.

**PAWS landed 2026-08-03 as Step 10 item 2, together with the timestamps it
needs.** Before it, timestamps were parsed and echoed but `last_remote_tsval`
was never compared, and sys-io installed no `tsval_generator`, so the option was
off end to end and PAWS had nothing to compare even if it had existed. Now
sys-io offers RFC 7323 timestamps and the netstack applies section 5.3's check
R1: past LISTEN and SYN-SENT, a segment whose timestamp predates TS.Recent is an
old duplicate that wrapped the sequence space, and is dropped with a
rate-limited acknowledgement rather than accepted on the strength of a plausible
sequence number. On this link that is not a hypothetical -- 4 GiB of sequence
space goes by in a few seconds, and nothing else can tell the wrapped copy from
the real thing. Resets are exempt, per section 5.2.

Check R3 had to change with it. TS.Recent used to take the timestamp of any
accepted segment; it now advances only for one starting at or before the next
byte expected. The unconditional form is not merely unfaithful -- a segment
arriving while a hole ahead of it is still open would push TS.Recent past the
timestamp of the retransmission that fills the hole, R1 would reject the repair,
and the connection would stall on exactly the loss it was recovering from.

The full account, including what enabling the option cost and the segment-sizing
defect it exposed, is in `networking-step-by-step.md` under Step 10 item 2.

**Checksum-offload trust gap.** When virtio negotiates `GUEST_CSUM`, sys-io
disables RX checksum verification for every frame. `VIRTIO_NET_F_GUEST_CSUM`
only means the host *may* deliver frames flagged `DATA_VALID`; unflagged frames
still carry a real checksum that should be verified. As written, a segment
corrupted in transit with valid ports and sequence is accepted and delivered to
the application.

Re-verified at `8e2b31a7`: the capability is now keyed on both negotiated
features rather than set to `None` unconditionally
(`SI/device.rs:342-352`), but the RX half of the finding stands unchanged, and
the per-packet metadata never even reaches sys-io -- `post_read` zeroes a
`NetHeader`, and the device-written flags are dropped when the descriptor is
released (`V/virtio_net.rs:419-451`). `DATA_VALID` has no constant in the tree.
ICMP is unaffected: sys-io leaves the ICMP checksum capabilities at `Both`.
Scheduled as item 2 of `docs/plans/core-safety-hardening.md`.

Updated 2026-07-30 by that item's patch 5: the metadata now survives. The RX
completion reads the device-written header before its descriptor chain is
released and resolves to the frame plus an `RxMeta` whose `l4_csum_vouched`
records `NEEDS_CSUM`/`DATA_VALID` (both constants now exist), and completions
the negotiated feature set cannot produce are rejected and counted in
`net.device.rx_dropped`.

**Closed 2026-07-30 by patch 6.** sys-io advertises RX verification as on for
every frame -- `caps.checksum.tcp` is `Rx` with `VIRTIO_NET_F_CSUM` and `Both`
without it, `caps.checksum.udp` is `Both` -- and the `GUEST_CSUM` saving is
taken per frame instead: the verdict rides `PacketMeta::l4_csum_vouched` from
`VirtioRxToken::meta()` to the TCP and UDP ingress parse sites, which drop
software verification for that frame only. An unflagged frame is verified, so a
segment corrupted in transit with valid ports and sequence is dropped and
counted in `net.rx.csum_failed` rather than delivered. The driver refuses to
honor a vouch when `GUEST_CSUM` was not negotiated, so no configuration
verifies less than it did before. ICMP remains unaffected. Patch 7 landed the
deterministic per-verdict coverage on 2026-07-30 -- one TCP and one UDP
`Interface::poll` regression over every combination of verdict and
checksum-field content -- which the measurement recorded there makes mandatory:
this rig delivers no unvouched TCP or UDP frame at all, so the full-OS suite
alone never exercises the verification path. Item 2 is complete.

### P3: panic-shaped code reachable from crafted packets

smoltcp is `#![deny(unsafe_code)]` (`SM/lib.rs:2`) and **contains no unsafe
in any packet-facing path** -- all 18 `unsafe` blocks are libc wrappers in
`phy/sys/`, which Motor does not compile (no `target_family` on
`x86_64-unknown-motor`). That is a genuine strength and a reason not to
replace the stack with hand-written code.

The residual risk is panic-shaped, not memory-unsafety-shaped:

- `SM/socket/tcp.rs:1755` slices `repr.payload` using two `SeqNumber`
  subtractions, which panic on underflow (`SM/wire/tcp.rs:73`). The ordering
  invariant is checked only by `debug_assert!` at `:1750`, i.e. not in
  release. `SeqNumber: PartialOrd` is wrapping and therefore not a total
  order, and `window_start`/`window_end` are computed from different epochs
  (`:1679-1684`), so they can cross after a window shrink. **This is the
  first thing the deterministic crafted-packet harness should target.**
- Release-live `assert!`s on attacker-influenced lengths:
  `storage/ring_buffer.rs:345` (called from `socket/tcp.rs:2171`) and
  `:398` (called with `ack_len` at `socket/tcp.rs:2026`).
- `SM/socket/tcp.rs:2162` is a `debug_assert!` that the rx write was
  complete; in release a short write records bytes in the assembler anyway
  (`:2143-2153`) and later publishes them (`:2171`), **delivering stale
  ring-buffer contents to the application as stream data**.

Re-verified at `8e2b31a7`, and the residual risk was no longer only
panic-shaped. `dispatch` stored the deliberately unscaled SYN/SYN|ACK window
into `remote_last_win`, which the receive-window right edge and
`last_scaled_window` both shifted back up by the negotiated scale, so for one
round trip after either an active or a passive open the socket's acceptance
window was twice its 128 KiB ring. The acceptance test never consults the ring's
free space, so in-order payload beyond it reached `enqueue_unallocated` and
tripped that method's release-live `assert!`: a peer that ignores the window we
advertised aborted sys-io and took down all networking on the machine. An honest
peer could not reach it. This is defect D1 of
`docs/plans/core-safety-hardening.md`, which also records the three smaller
preexisting defects the same pass found and schedules the P3 sites above as its
item 1. **Fixed by Step 6 patch 1**: `remote_last_win` now records the
advertised window in bytes, no consumer shifts it, and direct fail-first
regressions cover the overrun in both roles.

**The P3 sites above are fixed by Step 6 patch 2.** The receive-window right
edge is bounded by the left edge and by the receive ring's free space; the
payload slice and its ring offset come from a checked helper that drops the
segment instead of panicking; the write site rejects a short write before the
assembler records it, so stale ring contents can no longer be published; and
both ring-buffer `assert!`s are debug assertions that clamp in release, with
their callers bounding the counts first.

**The assembler's unbounded offset (D4) is closed by Step 6 patch 3.** That
same write-site check is the caller-side bound D4 wanted, since the assembler's
offsets and the ring's unallocated region share an origin, so patch 3 found the
numeric protection already in place and delivered the invariant enforcement its
entry predicted: the bound now names the unfillable-hole invariant alongside the
short-write one, a caller-side `debug_assert!` catches a later change to the
acceptance arithmetic that upholds it, and a direct regression proves an
out-of-order offset past the ring never reaches the assembler. The assembler is
unchanged.

### Packet-facing regression coverage is incomplete

The stack has extensive scenario tests, but no compact crafted-packet suite
for the sequence and receive-window boundaries above. Step 1 added a
simultaneous-open regression through sys-io's public API. A deterministic
packet harness is still needed for transitions that an ordinary in-order peer
cannot emit, especially batched `SYN|ACK + FIN`.

## Performance findings

### Structural: O(N) scans everywhere

There is no connection table, no ready list, and no timer wheel. Per received
TCP segment, smoltcp linearly scans every socket calling `accepts()`
(`SM/iface/interface/tcp.rs:22-31`), after a separate full scan for raw
sockets (`iface/interface/ipv4.rs:151`). Per egress pass it iterates every
socket calling `dispatch` (`iface/interface/mod.rs:722`), and `poll()` repeats
that until a pass produces nothing (`:499-504`). `poll_at` again queries every
socket and takes a `min` (`:591-622`), and TCP's `poll_at` is not cheap -- it
recomputes MSS and window state (`socket/tcp.rs:2723,2726`).

`SocketSet::items_mut` walks the whole backing slice including `None` holes
left by `remove()` (`iface/socket_set.rs:124-150`), so cost tracks the
high-water socket count, not the live one. Sockets are also `dispatch`ed at
most once per pass (`FnOnce`, `socket/tcp.rs:2355`), so sending K packets
from one socket costs `(K+1) x N` socket visits.

For a server with many connections this is the dominant scalability cliff,
and it is the multiplier that turns the SYN flood above into a CPU DoS.

### Structural: two copies each way, mandated by the token contract

`RxToken::consume` hands out `&[u8]` and `TxToken::consume` hands out
`&mut [u8]` (`SM/phy/mod.rs:411-431`) -- contiguous single buffers, no
scatter-gather anywhere in the tree. Consequently:

- **RX:** DMA into a pooled `IoBuf` (no copy) -> copy #1 into the socket rx
  ring (`SM/socket/tcp.rs:2161`) -> copy #2 into the io_channel page
  (`SI/socket/tcp.rs:753`) -> client copies out (`moto-io/src/net/tcp.rs:1250`).
- **TX:** client copies in -> copy #1 into the tx ring
  (`SI/socket/tcp.rs:907`) -> copy #2 into the device buffer
  (`SM/wire/tcp.rs:1053`, inside `VirtioTxToken::consume`) -> DMA.

Two copies each way inside sys-io. Both are avoidable in principle: virtio
`IoBuf`s and io_channel pages are both pooled, 4K-based, and phys-addr-cached
(`moto-tooling/src/iobuf.rs:61-87`), so page-flipping is structurally
plausible. But it requires changing the token contract, which is the deepest
fork divergence this plan contemplates.

### Tunable: values that are simply wrong for a VM guest

These need no architecture change and are the best value in the document.

**No congestion control at all.** `CongestionControl::{Reno, Cubic}` are
feature-gated (`socket-tcp-reno`, `socket-tcp-cubic`) and **neither is in
`default`**, so Motor gets `AnyController::None`, whose `window()` returns
`usize::MAX` (`SM/socket/tcp/congestion/no_control.rs:8-10`, verified). No
slow start, no AIMD, no loss response beyond RTO. `set_congestion_control` is
never called in sys-io. Note Cubic uses `f64` (`congestion/cubic.rs:90-104`),
which is a real consideration for a system process -- Reno is the safer
default.

  **The `f64` half of that is wrong, corrected 2026-08-02.** Motor's kloader
  enables `OSFXSR`, `OSXSAVE`, and AVX/SSE (`x64.kloader/src/util.rs:24-40`) and
  the kernel `xsave`/`xrstor`s around context switches
  (`arch/x64/syscall.rs:472,522`), so floats are ordinary in a Motor userspace
  process. The objection was imported from smoltcp's own Cargo.toml, whose
  stated reasons -- FPU-less Cortex-M parts, interrupt handlers, kernel-mode
  code -- describe none of sys-io. Cubic's `cube_root` is hand-rolled
  Newton-Raphson, so it pulls in no math library either.

  With that objection withdrawn, **Cubic is the choice** (guidance
  2026-08-02): it is what a general-purpose host is expected to run, and the
  remaining argument for Reno was about this implementation rather than the
  algorithm.

  **The implementation had three defects; fixed 2026-08-02** in
  `SM/socket/tcp/congestion/cubic.rs`, on guidance, as part of item 1a.

  1. **No TCP-friendly region.** RFC 8312 section 4.2 requires Cubic to track
     the window Reno would have reached, `W_est`, and use the larger of that and
     the curve. This implementation had none, which is the real reason it
     underperforms on a short-RTT path: the cubic curve alone climbs far slower
     than Reno on a low-BDP link, so Cubic was strictly the worse of the two
     here. `W_est` now grows per ACK in congestion avoidance, by one MSS per
     window acknowledged, and `pre_transmit` takes the maximum.
  2. **Congestion avoidance advanced only on a 100ms timer**, at millisecond
     granularity, while `on_ack` returned early once past slow start -- so there
     was no per-ACK growth to fall back on and the window sat still for ~2,170
     round trips at a time. The floor is gone and the curve is evaluated in
     microseconds, which `Instant` stores natively.
  3. **`cube_root` converged on an absolute, per-decade tolerance** -- 5.0 on a
     root near 90 -- leaving K about 0.16% high. That starts the curve *below*
     `w_max * beta`, where it should meet `W_est` exactly at t = 0, and it took
     roughly 150ms of curve growth to climb back. It now converges on a relative
     tolerance. Affordable because K is cached per congestion epoch rather than
     recomputed per transmit, which is what forced the update floor to exist.

  4. **Slow start was undone periodically.** `pre_transmit` applied the recovery
     curve unconditionally, including before any loss had ever happened, while
     `w_max` was still its initial 2048 -- where the curve evaluates below
     `min_cwnd`. Each update therefore dropped the window to a single segment
     and discarded what slow start had built. The 100ms floor bounded this to
     once per 100ms rather than continuously, so the real shape was a sawtooth
     on a link that had never lost a packet. `pre_transmit` now returns early
     while `cwnd < ssthresh`: the curve describes recovery, and there is nothing
     to recover from before the first congestion event.

  Two of these were found by tests rather than by reading, and one of the tests
  had to be rewritten before it found anything.

  The 0.16% in item 3 surfaced when the TCP-friendly-region test failed against
  the *fixed* code: the curve was demonstrably advancing and the window still
  would not move, because `W_est` masked it. Item 4 was found by re-deriving the
  arithmetic, and its first test was wrong -- it passed against the original,
  because the 100ms floor happens to protect slow start after the first clobber.
  Rewriting it around the invariant that actually holds (with no loss the window
  must never shrink) makes it fail at 1ms, where the window drops 2048 -> 1460.

  All four regressions are pinned by tests verified to fail against a faithful
  restoration of the original `pre_transmit`, floor included, rather than
  against a paraphrase of it. The first paraphrase was misleading twice.

  `on_duplicate_ack` reacting to *every* duplicate ACK was deferred to the cwnd
  fix and is **fixed 2026-08-02** with it; see below.

  **Cubic enabled 2026-08-02** (execution Step 10 item 1a). sys-io takes the
  `socket-tcp-cubic` feature and names `CongestionControl::Cubic` at its one
  socket-creation site, which makes the feature a compile-time requirement --
  the variant does not exist without it -- so a build that dropped it fails
  there rather than quietly returning to the uncontrolled `usize::MAX` window.
  Landed as Reno first and switched on guidance; see the `f64` correction
  below for why the original Reno argument did not hold.

  **But enabling it was inert, and that was a second defect; fixed 2026-08-02**
  as Step 10 item 1b. The congestion
  window was read in exactly one place in the whole netstack:
  `seq_to_transmit()` did `max_send.min(cwnd)`, where `max_send` is *unsent
  octets still inside the offered window* rather than octets in flight.
  `dispatch()` then sized the segment at `win_limit.min(max_seg)` with **no cwnd
  term at all**, where `win_limit` is the remote window less what is already in
  flight. So cwnd gated whether to transmit and never how much, and in-flight
  data grew to the peer's advertised window whatever cwnd said.

  It could not gate even that. Reno's floor `min_cwnd` becomes the peer's MSS on
  SYN, so `max_send.min(cwnd)` reached zero only when it was already
  zero, and `can_send_full` -- the one other consumer, feeding Nagle -- was
  never falsified either, since `effective_mss <= min_cwnd` by construction.
  With TSO a socket could emit a 60KB super-segment while cwnd read 2048.

  Scheduled as its own patch under Step 10 item 1, by guidance, because it is a
  preexisting defect found while enabling Reno rather than one this work
  introduced. Both call sites now go through one helper,
  `congestion_window_headroom()`, which is `cwnd` less `SND.NXT - SND.UNA`;
  `dispatch()` applies it *before* the zero-window-probe fixup, which stays
  exempt because a probe is what reopens a peer's zero window. They had to move
  together: `poll_at()` asks `seq_to_transmit()` whether to schedule, so a
  predicate that says yes while the sizer emits nothing is a busy loop.

  The upstream smoltcp checkout on this rig
  (`~/.cargo/git/checkouts/smoltcp-*`) carries the same two gaps, so they are
  not fork drift -- though that copy already has Motor's TSO changes and is not
  a pristine baseline.

  Fixed with it, and previously deferred here: `on_duplicate_ack` fired on
  *every* duplicate ACK. RFC 5681 section 3.2 reduces once per loss event, on
  the third -- the same signal that arms the fast retransmit -- because the
  first two are as likely to be reordering. On Cubic, whose reduction is
  multiplicative, reacting to all of them was `beta` raised to the size of the
  flight: a measured 65536 to 7709 across six duplicates, against 65536 to
  45875 for one event.

  **Still owed.** A loss event now reaches Cubic exactly twice: once from the
  third duplicate ACK and once from the fast retransmit it arms, since
  `dispatch()` reports both through `on_retransmit`. Cubic's two hooks are the
  same `on_congestion`, so a loss costs `beta` squared, 0.49, rather than 0.7.
  Closing it needs a loss-epoch notion this fork does not have -- the controller
  cannot distinguish an RTO from a fast retransmit, and Reno genuinely wants
  both hooks, since they are section 3.2's separate `ssthresh` and `cwnd`
  halves. Also unchanged: `on_congestion` sets `ssthresh = cwnd >> 1` where RFC
  8312 specifies `cwnd * beta`.

  **The initial window is now RFC 6928's. Raised 2026-08-02, on decision.**
  Both controllers used to start at `cwnd: 1024 * 2` with `min_cwnd: 1024 * 2`,
  and `set_mss` set `min_cwnd = mss` without touching `cwnd`, so a normal
  handshake left the initial window at **2048 bytes against a 1460-byte MSS --
  1.4 segments**, below every RFC's floor of two. `set_mss` now also sets `cwnd
  = initial_window(mss)`, `min(10*MSS, max(2*MSS, 14600))`
  (`SM/socket/tcp/congestion.rs`), which is 14600 at that MSS and what Linux has
  shipped since 2.6.39.

  The handshake is the only place this can happen, because it is the only place
  an MSS arrives; it is also the only place it is meaningful, since nothing has
  been sent or acknowledged yet and `cwnd` is still the constructor's
  placeholder. `set_mss` *assigns* rather than taking the larger of the two on
  purpose: for a small enough MSS the placeholder is the bigger number, and
  keeping it would be many segments in flight before a single ACK -- at a
  100-byte MSS, twenty of them. Cubic also carries `w_est` and `w_max`, and the
  constructor starts all three equal; `w_est` has to follow, because slow start's
  `on_ack` holds it equal to `cwnd` and leaving it behind would put the
  TCP-friendly floor under the window it tracks. `w_max` follows for consistency
  only -- it is a congestion event's memory and is rewritten before it is read.

  A larger initial window cannot put anything extra on the wire against a peer
  that advertised a small one: `dispatch()` derives `win_limit` from the remote
  window first and only then takes `min` with the congestion headroom.

  Measured with the flow-completion mode built for it (Step 10 item 1c), which
  is where the numbers and the counterbalanced block design live: **13% to 38%
  off p50 flow completion** across 4 KiB to 256 KiB, the largest single win this
  work has produced. What that measurement cannot say is what IW10 costs, and
  the limit is the rig, not the method: this host loses no packets, so a
  ten-segment burst into a cold path has no downside to show here, and Motor's
  TSO path can emit that burst as a single super-segment, so a real NIC's pacing
  is absent too. The decision to take RFC 6928 over RFC 5681's 4380 was made on
  that understanding -- IW3 was measured in the same sitting and captured about a
  third of the win.

  Related, noticed and deliberately not changed: `set_remote_window` in both
  controllers only ratchets *upward* (`if self.rwnd < remote_window`), so
  `rwnd` -- the cap on `cwnd` -- holds the largest window the peer ever
  advertised rather than its current one. Benign, because `dispatch()` enforces
  the real remote window separately through `win_limit`.

**Minimum RTO was 1000 ms; it is now 200 ms.** RFC 6298 recommends a second for
the Internet, and on a VM-to-host path with ~59 usec RTT that meant any loss
cost a full second. `RTTE_MIN_RTO` is 200 ms as of Step 10 item 2 part three,
matching Linux's `TCP_RTO_MIN` (`HZ / 5`, and `net.ipv4.tcp_rto_min_us` =
200000, both verified on the build host) under the same clause of RFC 6298 (2.4)
that recommends the second: "a lower minimum SHOULD be used when it is known
that a path has a shorter RTT."

`RTTE_INITIAL_RTO` stays at a second -- it governs a connection that has no
measurement, which is RFC 6298 (2.1) and Linux's `TCP_TIMEOUT_INIT` -- so the
*first* retransmission of a fresh connection is unchanged. The floor still binds
on this path: the estimate under it is about 5 ms, essentially all of it
`RTTE_MIN_MARGIN`. Note that `TCP_DELACK_MAX` is also `HZ / 5`, so a Linux peer
may delay an ACK for as long as this timer waits; what keeps that from being a
spurious retransmit is that the delay is inside the RTT sample that sets `srtt`.

The sampling half of the finding was fixed first, and had to be. RTT *was*
sampled at millisecond
granularity, so every sub-millisecond RTT sampled as zero and `srtt`/`rttvar`
were permanently zero -- the estimator ran and measured nothing. Step 10 item 2
part two moved the estimator to microseconds, which is the resolution `Instant`
always had. It changes nothing on the wire while the floor stands, by design:
the clamp rounds a 60-usec estimate up to a second exactly as it rounded up a
zero. What it changes is that there is now something real under the clamp, so
lowering the floor becomes a decision about a measured path rather than a
change from one constant to another.

Two things the conversion had to settle that milliseconds hid. `u32`
microseconds run out at 71 minutes and the smoothing multiplies `srtt` by
seven, so a sample is capped at `RTTE_MAX_RTO` -- an uncapped `u32::MAX` sample
overflows `rttvar * K`, which aborts a `panic = "abort"` process in debug and
silently wraps in release. And the old table's plateau at 2012 ms for a
2-second path was an artifact of the unit: `rttvar` cannot fall below 1 under
`div_ceil`, and 1 ms of variance times K is 4 ms. In microseconds that term
vanishes and the plateau is `RTTE_MIN_MARGIN` above `srtt`, where RFC 6298 puts
it.

`RTTE_MIN_MARGIN` keeps its 5 ms. It is RFC 6298 (2.4)'s `G`, the clock
granularity, which 5 ms has never been for this clock -- it is really a floor
under how tight an RTO the variance alone may ask for, and microsecond sampling
is what makes it reachable at all. Its value therefore belongs to whoever
decides the floor, not to a change of units.

**Retransmission is go-back-N.** On RTO or fast retransmit, the send pointer
is rewound to `SND.UNA` -- `self.remote_last_seq = self.local_seq_no`
(`SM/socket/tcp.rs:2401`) -- resending the entire unacknowledged window, one
MSS per egress pass. There is no recovery point, no partial-ACK handling, no
NewReno.

**Received SACK is parsed and discarded.** `TcpRepr::parse` fills
`sack_ranges` (`SM/wire/tcp.rs:935,948`) but `process()` never reads it.
`remote_has_sack` means only "the peer permits *us* to send SACK blocks". Our
own SACK generation fills just one block of three
(`SM/socket/tcp.rs:1477-1503`, with a comment admitting it).

**Out-of-order assembler held 4 contigs; it now holds 32.** Past capacity the
segment is dropped **and no ACK is generated** (`SM/socket/tcp.rs`, the
`add_then_remove_front` failure returns `None`), so the sender loses the
duplicate ACKs a fast retransmit is built from and waits out its RTO -- at least
200 ms since Step 10 item 2 part three, and a full second before that. That is
still true at 32; what changed is how far a loss burst has to go to reach it.
Four contigs against a 128KB window -- about ninety segments -- was reachable at
a few percent loss, a self-inflicted throughput collapse on any lossy path and
not only an attack surface. Raised in Step 10 item 3 via
`assembler-max-segment-count-32`, at 16 bytes per hole per socket.

Note what that item found on the way: `lib.rs` compiles `cfg(test)` against a
hardcoded `config` module, so **no capacity constant in this crate is tested at
the value it deploys** unless someone has edited both by hand.
`ASSEMBLER_MAX_SEGMENT_COUNT`, `IFACE_MAX_ADDR_COUNT` and
`IFACE_MAX_ROUTE_COUNT` now are, each held by a `const` assertion in sys-io.
`REASSEMBLY_BUFFER_COUNT` (4 under test against 1 deployed) and
`FRAGMENTATION_BUFFER_SIZE` (4096 against 1500) are not.

`IFACE_NEIGHBOR_CACHE_COUNT` is a third case and not a defect: it is 3 under
test against 64 deployed *deliberately*, because eviction is only reachable in a
test that can fill the cache. What those tests cover is the eviction policy,
which does not depend on the number; see Step 10 item 4.

Together these four are why loss recovery on a real Internet path will be
poor even after the window and coalescing plans land.

### Smaller, cheap

- **A segment's own options were not subtracted from its payload. Found and
  fixed 2026-08-03.** `dispatch()` sized what it sent against the constant
  `TCP_HEADER_LEN`, twenty bytes, while `TcpRepr::header_len()` -- which is what
  actually gets emitted -- counts the options too. Every option we send is
  therefore MTU the packet does not have. Latent for as long as we sent none,
  and instant once RFC 7323 timestamps were switched on: twelve bytes over on
  every full-sized segment, which took the VM's networking down entirely. Three
  sites, all sizing our own packet: the payload, the TSO cap against 65535, and
  `tso_seg_size` -- that last one worst, since the device stamps the header onto
  every wire segment it splits out, so one super-segment becomes a burst of
  oversized frames. The MSS we advertise in our SYN deliberately keeps the
  constant: RFC 6691 defines an advertised MSS as payload alone, each sender
  accounting for its own options, and that asymmetry is what makes the bug easy
  to write. The upstream smoltcp checkout has the same shape, latent for the
  same reason. Under Step 10 item 2.
- **TSO super-segments are silently truncated at the ring wrap.**
  `get_allocated` returns only the largest contiguous slice
  (`SM/storage/ring_buffer.rs:363-367`), so a 60KB TSO burst straddling the
  128KB tx ring is clipped. Likely halves effective TSO size at steady state;
  worth measuring before anything else in this section.
- **MTU off-by-14.** sys-io passes the virtio MTU as
  `max_transmission_unit` (`SI/device.rs:326`), but smoltcp treats that as the
  *link* MTU and subtracts the Ethernet header for `ip_mtu()`
  (`SM/phy/mod.rs:307-318`), yielding MSS 1446 instead of 1460.

  **Fixed 2026-08-01** (execution Step 7), after measurement showed it was not
  cheap in the other direction. The sign depends on whether `VIRTIO_NET_F_MTU`
  is negotiated, and on the current rig it is not: QEMU is launched without
  `host_mtu=`, so it never offers the bit, and `VirtioDevice::new` fell back to
  `unwrap_or(1536)`. That made `ip_mtu()` 1522 and the advertised MSS 1482 on a
  tap that carries 1460 -- too large by 22, not too small by 14. Advertising
  more than the path holds is a different class of bug from advertising less: a
  peer that honored it would make Motor emit a 1536-byte frame into a 1500-byte
  link, and the fork has no PMTU discovery to recover. It was latent because
  peers clamp to their own path MSS, which `ss` confirmed live
  (`mss:1460 advmss:1460 pmtu:1500`).

  A named `frame_mtu()` now converts the virtio MTU (an IP MTU) to the frame
  size `max_transmission_unit` means, defaulting to `DEFAULT_IP_MTU = 1500`
  when the device reports none. Both directions of the error close together,
  since the same conversion applies whether or not the bit is negotiated. A
  self-test round-trips each candidate through the netstack's own `ip_mtu()`.

  **Two further holes in the same code, fixed 2026-08-02.** The 2026-08-01 fix
  corrected the units but still believed whatever the device said.

  - **The receive path cannot honor an arbitrary MTU.** `rx_task` posts
    `SMALL_BUF_SIZE` (2048-byte) buffers unconditionally, and without
    `VIRTIO_NET_F_MRG_RXBUF` -- which Motor does not negotiate, and which Cloud
    Hypervisor does not even offer -- the device cannot continue a frame into a
    second buffer. Any reported MTU above 2034 therefore advertised an MSS that
    could not be received. Reachable without a malicious VMM: CHV takes its
    reported MTU from the tap, so a jumbo tap is enough. Now capped at
    `SMALL_BUF_SIZE - ETHERNET_HEADER_LEN`, with the self-test tying the cap to
    the buffer size so a later buffer change cannot silently break it.
  - **A tiny reported MTU underflowed the MSS arithmetic.**
    `ip_mtu() - ip_header_len - TCP_HEADER_LEN` is `usize`, so a device
    reporting below 40 (IPv4) or 60 (IPv6) wrapped it -- a panic in debug, a
    nonsense MSS in release, in a `panic = "abort"` process. Values below 576,
    IPv4's minimum reassembly buffer, are now treated as a broken device and
    replaced by the default rather than clamped upward; clamping upward would
    recreate the advertise-more-than-the-path-holds failure that has no PMTU
    discovery to recover from.

  Neither changes behavior on any current rig: QEMU and Firecracker report no
  MTU, and Cloud Hypervisor reports 1500.

  **This entry's own 1446 confirmed live, 2026-08-02**, while gathering the
  evidence for execution Step 8. Cloud Hypervisor v52.0 is the one VMM of the
  three the repository ships scripts for that offers `VIRTIO_NET_F_MTU`, and it
  reports 1500 -- so CHV is exactly where this defect took the sign written
  above, and the QEMU rig was the wrong place to look. Booting a build with only
  the old line restored gives the host `mss:1446 pmtu:1500`; HEAD gives
  `mss:1460`. Nothing clamped this direction, because 1446 is below the path MSS
  rather than above it, so it cost 1% of every segment's payload on that VMM for
  as long as it existed.
  See `virtio-rx-coalescing.md`, Step 0 result.
- **Checksum is a 16-bit-at-a-time loop** (`SM/wire/ip.rs:773-802`), roughly
  an order of magnitude slower than a u64-accumulator version. Matters for
  UDP TX, which stays in software deliberately (`SI/device.rs:348-352`).
- `DeviceCapabilities` is cloned on **every transmitted packet**
  (`SM/iface/interface/mod.rs:1233`).
- smoltcp is built with `log` on, so `net_trace!` calls sit in the per-packet
  path; sys-io's logger has no `enabled()` filter (`sys-io/src/logger.rs:7-9`)
  and debug builds log per packet.

## What to preserve

A rewrite that discards these would be a regression:

- **No unsafe in packet-facing code.** smoltcp's `#![deny(unsafe_code)]` is
  worth more than any performance delta. Any replacement subsystem should
  hold the same line.
- **The waker-driven integration.** One recv waker and one send waker per
  socket, with sys-io tasks parked on them, is a good design and is why
  sys-io does no post-poll scanning. smoltcp allows exactly one registration
  per direction; any replacement must either keep that contract or provide
  its own registry.
- **Per-device partitioning.** Separate `SocketSet` per device with no
  cross-device sockets (`SI/socket.rs:4-14`) is the natural shard boundary if
  the runtime ever goes multi-threaded.
- **The tuned lifecycle invariants**, each of which was measured: RX drain
  must poke `device_notify` or a zero-window stall recovers only via persist
  probes, 0.78 vs 16+ MiB/s (`SI/socket/tcp.rs:770-781`); close must not
  `abort()` mid-drain or acknowledged writes are truncated (`:1065-1076`);
  sockets linger after their client is gone (`:1097-1130`); the timer re-arm
  heuristic avoids ~80k timers/sec (`net.rs:130-165`); TX is multi-page and
  RX single-page for measured reasons (`:266-273`, `SI/socket/tcp.rs:681-687`).
- **The ability to take upstream fixes.** Four commits of divergence means
  upstream patches still apply cleanly. We will not send changes the other
  way (see "Upstreaming policy: none"), but cherry-picking upstream fixes in
  keeps real value, and it stays cheap only while the fork's changes avoid
  the code paths upstream touches.

## Options

**Option A: harden and tune in place, stay close to upstream.** Feature trim,
constants, flags, sys-io panic fixes, protocol fixes. Removes
every P0/P1 finding and the four worst performance defaults. Does not touch
O(N) demux or the copy count. Small, low-risk, mostly a few hundred loc.

**Option B: Option A plus targeted architectural surgery in the fork.**
Replace the demux scan with a hashed connection table, add a ready-list for
egress and a timer wheel for `poll_at`, replace the 4-contig assembler with
an allocating interval list, and swap the heapless tables for real ones.
These are inherently divergent -- upstream will not take them, because they
depend on `alloc` and change the no-std contract that is smoltcp's reason to
exist. Meaningful fork maintenance cost; large payoff for connection scale.

**Option C: Option B plus a scatter-gather token contract for zero-copy.**
The deepest change: `RxToken`/`TxToken` grow descriptor lists, every ingress
parse site and `emit` path learns non-contiguous buffers. Collapses sys-io's
2 copies each way toward 1 or 0. Very invasive, touches the entire wire
layer, and forecloses easy rebasing permanently.

**Option D: write a Motor-native TCP/IP stack.** Full control, std and alloc
from the start, exactly the features Motor needs. Also: re-litigating twenty
years of TCP edge cases, in a component whose panic takes down the machine,
with incomplete packet-facing regression coverage. smoltcp's
9000-line TCP state machine plus 6600 lines of tests is a real asset. **Not
recommended, and this document should be read as an argument against it.**

## Recommendation

**A now, B when measurements justify it, C only behind a proven bottleneck,
D never.**

The ordering matters more than the option choice: everything in A is cheaper,
safer, and higher-value than everything in B, and A changes the measurements
that B should be scoped against. Enabling congestion control and fixing the
RTO floor will change throughput numbers substantially; scoping a connection
table before that lands means scoping against the wrong profile.

### Upstreaming policy: none

**We will not try to upstream any changes to smoltcp.** This was tried and
is settled: some of this work was offered upstream and the maintainer was
not interested, and most of what this plan proposes depends on `alloc`,
breaking the no-alloc contract that is smoltcp's reason to exist -- it would
not be accepted even with a willing reviewer. All fork changes -- plain bug
fixes (the `SeqNumber` underflow, the discarded `TooManyHolesError`, the
`async` cfg bug), RFC compliance (5961, 6528, PAWS), the packet harness, and
everything in Option B -- are permanent divergence and ours to carry.

Cherry-picking in the other direction, upstream fixes into the fork, stays
on the table. It is cheapest where we have not modified the code -- in
particular, components sitting behind features we have turned off carry no
local changes and take upstream patches verbatim. That, not upstreamability,
is the reason to keep the divergent surface small and identifiable: the less
we perturb files upstream also touches, the longer cherry-picking stays
cheap.

## Proposed work

Steps are independently reviewable and each leaves a runnable tree.

**Step 0 -- bring the fork in-tree.** With upstreaming ruled out, the fork is
a Motor component with external ancestry, not a vendored dependency. Four
sub-steps: (a) and (b) are decided, (c) and (d) are open.

**(a) Import the fork at `src/sys/sys-io/netstack/`.** A sub-crate in
sys-io's own directory, added to the workspace `members` list, renamed off
`smoltcp` -- `moto-netstack` as the package name, though a bare `netstack` is
equally fine since it is private to sys-io and will never be published. Land
it `cargo +nightly fmt`-clean and with the clippy gate satisfied.

Import scope was narrowed by guidance to the production crate: retain the
license, manifest, build script, production `src/` tree, and a small Motor
README; omit upstream CI, repository documentation, examples, benches,
integration tests, non-production test tooling, utilities, generator script,
and the unused packet-mutation support module. Prune only the manifest entries
and module exports made invalid by those omissions. Step 5 will add a
Motor-owned deterministic packet-facing harness.

Why not the alternatives considered: `src/third_party/` holds
externally-authored code consumed as-is, whereas this crate will be reworked
substantially and may grow dependencies on `src/sys/lib` crates, which a
`third_party/` crate must not have. `src/sys/lib/` reads as shared libraries,
and this one will have exactly one consumer forever. A sub-crate under sys-io
says what it actually is: sys-io's private stack implementation. Placement is
a source-layout question only -- the crate is statically linked into the
sys-io binary either way, so it is inside the net driver at runtime
regardless.

Keeping it a crate rather than a module of sys-io is deliberate: as a module,
every sys-io edit would recompile ~55.6k LOC (`codegen-units = 1`,
`lto = "fat"`, `src/sys/Cargo.toml:66-68`), which works directly against
iteration speed; Step 2's feature trim depends on the fork's own `[features]`
and `build.rs`, which as a module would need ~30 pass-through features
declared on sys-io plus an absorbed build script; and `git am --directory=`
cherry-picks stay workable. None of that obstructs (d) -- see the note there.

Sequence as three commits -- curated production import, rename, then fmt plus
clippy -- so the source blobs retain a clean base for `git am -3` upstream
cherry-picks. The import commit changes only the manifest metadata and targets
required by the approved pruning. The rename commit changes the package and
source self-references to `moto-netstack`/`moto_netstack`, registers the
workspace member, and changes `build.rs`'s config-env prefix to
`MOTO_NETSTACK_*`. There is no in-tree user of the old `SMOLTCP_*` prefix, so
the later assembler configuration must use
`MOTO_NETSTACK_ASSEMBLER_MAX_SEGMENT_COUNT`. Registration also requires
removing the imported package-local release profile: Cargo ignores member
profiles and warns about it. The first
`cargo +nightly fmt` may mass-reformat the whole tree if Motor's rustfmt
config differs from upstream's -- that is what the dedicated third commit is
for. The clippy pass over foreign code should use one visible, commented
crate-level `#![allow]` block rather than scattered suppressions.

**(b) Copy smoltcp's `tcp::State` into `moto-sys-io`; repoint both
dependents.** `TcpSocketStatsV1` is a `#[repr(C)]` IPC wire struct that
embeds `smoltcp::socket::tcp::State` directly
(`lib/moto-sys-io/src/stats.rs:25`), so a foreign enum's layout is currently
part of Motor's IPC ABI -- a variant reorder during the rework would change
the wire format with no compile error on either side. `moto-sys-io` is also a
published crate (0.2.4) and so cannot depend on a path-only crate. Copy the
11-variant enum in under an interim name -- it cannot be `TcpState`, which is
taken by `api_net::TcpState`; (c) resolves that collision -- convert at the
sys-io boundary, which already matches on this state
(`SI/socket/tcp.rs:1611-1619`), and drop `moto-sys-io`'s netstack dependency
entirely. Then repoint sys-io's 202 `smoltcp` references across 8 files, and
delete `[patch.crates-io] smoltcp` (`src/sys/Cargo.toml:59`). Verified
against `Cargo.lock`: `moto-sys-io` and `sys-io` are the only dependents and
both are direct, so the patch is pure git-fork redirection that a path
dependency replaces. This also subsumes the old plan to pin the fork by
`rev`; a path dependency cannot drift under `cargo update`.

**(c) Consolidate the `TcpState` enums. Open -- design TBD.** Two enums
should not survive, but they currently model different layers, so the merge
is not mechanical:

- `moto_sys_io::api_net::TcpState` (`api_net.rs:132-142`) is a 7-variant
  client-facing API state -- `Closed`, `Listening`, `PendingAccept`,
  `Connecting`, `ReadWrite`, `ReadOnly`, `WriteOnly` -- with explicit
  discriminants, a `_Max` sentinel, and a `TryFrom<u32>` that `transmute`s
  (`:144-152`). It is part of the client ABI.
- smoltcp's `tcp::State` is the 11-variant RFC 9293 protocol state machine.

They overlap rather than duplicate. `ReadOnly`/`WriteOnly` encode half-close,
which is derivable from the protocol state (`FinWait*` means we sent FIN,
`CloseWait` means the peer did), while `PendingAccept` and `Connecting` are
Motor lifecycle concepts with no protocol equivalent. The design question is
whether the API enum becomes a projection of the protocol state plus shutdown
flags, or whether the two stay distinct under clearer names. Either way it
changes a client-visible ABI read through a transmuting `TryFrom`, so it
needs its own compatibility story. Scope properly when reached.

**(d) Deeper integration -- open, details TBD.** The candidate identified so
far is the duplicated socket bookkeeping. `SocketBase` carries both
`socket_id: u64` and `smoltcp_handle: SocketHandle` (`SI/socket.rs:48-62`),
so every operation traverses sys-io's socket map to reach `MotoSocket` and
then `SocketSet` (`SI/device.rs:376`) to reach the `tcp::Socket` -- two maps,
two identities, two allocations per connection. Collapsing it means
reworking the fork's socket ownership: either `Interface::poll` iterates a
caller-supplied socket store, or the socket carries a user-data payload
holding `SocketBase` so `SocketSet` becomes the only map. Both keep the
dependency one-directional -- the netstack defines the trait or type
parameter, sys-io supplies the concrete type -- so neither requires merging
the crates, and the abstraction is the same one Step 5's packet harness wants.
Overlaps Option B's connection table; scope the two together.

Sub-steps (a) and (b) should precede Steps 2 and 3, so the feature trim, the
`async` cfg fix, and the constant changes all have in-repo history from the
start. Step 1 is independent and need not wait. Note that (a) moves the `SM/`
paths cited throughout this document into `src/sys/sys-io/netstack/src/`.

**Step 1 -- sys-io panic surface (P0).** Replace the `panic!` and fourteen
`todo!()`s in the connect task (`SI/socket/tcp.rs:544,553-558,576-588`) with
"close the socket and notify the client". Audit every `todo!`/`unreachable!`/
bare `panic!` in `SI/` reachable from a smoltcp state read or a client
message; convert to errors. Add the first sys-io test that drives
`MotoSocket` through unusual state sequences, including simultaneous open.
Do this first and independently of everything else. ~150-250 loc. Status: the
connect-task state classification is complete; the broader audit found the
client-disconnect/control-task race described above. Its narrow dispatch guard
and regression are complete. The monotonic stats correction, stale-accept
handoff, fallible socket registration/setup rollback, and resolved listener
conflict correction are also complete; transactional listener pool creation
is also complete, using the explicit-drop cleanup primitive for rollback. The
exact source state passed three consecutive debug and three consecutive
release full suites. Simultaneous open is now covered by a self-connect
regression. The batched `SYN|ACK + FIN` case is carried to Step 5, where
crafted packets become available, and to the final verification. Step 1 is
complete.

**Step 2 -- feature trim (P1).** `default-features = false` in
`sys-io/Cargo.toml:32` plus an explicit list: `medium-ethernet`, `medium-ip`,
`proto-ipv4`, `proto-ipv6`, `socket-tcp`, `socket-udp`, `socket-icmp`,
`async`, and `std`. Deletes the fragmentation DoS outright, removes ~30k LOC
of attack surface, drops the `libc` dependency, and speeds up every poll.
Verify ICMP echo reply is either still wanted or deliberately dropped with
runtime policy. ~10 loc, large blast radius -- gate it carefully. Once Step
0(b) has landed, the fork is a path dependency and needs no version pinning;
give it a Motor version number distinct from upstream's 0.13.0 so it is never
mistaken for stock smoltcp.

Status: implemented as `moto-netstack` version `0.13.0-motor.1`. The exact Motor
feature closure above removes the fragmentation and host-`libc` edges;
`medium-ip` is retained only for logical loopback. Per-interface runtime
configuration preserves shipped IPv4 and IPv6 echo replies while allowing
them to be disabled. The inherited reduced-feature `rstest` conditions are
repaired, and the final production closure passes 518 unit tests plus 7
doctests with warnings denied. Broad tests/clippy, Motor builds/clippy, and
paired code-size checks pass.

Logical loopback now uses the IP medium and hardware address. This fixes the
IPv6 `::1` regression exposed when multicast removal left an Ethernet-mode
loopback dependent on neighbor discovery. The stripped sys-io binary falls
from 2,151,752 to 1,955,144 bytes (9.1%), with text down 8.9%.

Paired same-host release KVM medians pass the established gate. Default
RR/RX/TX changes from 55.285 usec/164.04/326.00 MiB/s to
59.401/163.87/319.90; 64 KiB changes from
54.357/668.12/1401.33 to 58.506/712.24/1408.26. All samples are retained.
By user guidance, synthetic host-qdisc delay/loss testing is not required for
the integrated OS stack. Three debug and three release runs of the
user-approved `full-test-networking.sh`, which omits all rmux/tmux tests,
reach both systest `PASS` and the final marker. Step 2 is fully gated.

**Step 3 -- constants and flags.** Enable a controller and call
`set_congestion_control` at socket creation -- done 2026-08-02 as execution Step
10 item 1, with Cubic rather than Reno, and with the congestion window made to
bind what is sent. Lower `RTTE_MIN_RTO` -- done 2026-08-03 as execution Step 10
item 2 part three, to Linux's 200 ms, over an estimator converted to
microseconds in part two because it had been measuring zero (a fork change;
consider making it configurable, as `44ecae4` did for silent time). Raise
the assembler's capacity from 4 -- done 2026-08-03 as execution Step 10 item 3,
and via the `assembler-max-segment-count-32` cargo feature rather than
`MOTO_NETSTACK_ASSEMBLER_MAX_SEGMENT_COUNT`, since a feature travels with the
dependency declaration and an env var has to be set by whoever invokes the
build.
Consider the neighbor cache and route counts -- done 2026-08-03 as execution
Step 10 item 4, which found the route and address counts were not a performance
question at all but a boot-time abort on any config with one entry too many.
Measure each small change separately, because congestion control in particular
can legitimately *lower* a benchmark number while improving real-path
behavior. Re-check the 5 ms
`discovery_silent_time` (`SI/device.rs:397`) against its original motivation.

This step also owns TCP timestamps and PAWS, moved out of the safety-hardening
work by `docs/plans/core-safety-hardening.md`: offering TSopt costs 12 bytes on
every segment, and the RTT sampling this step needs before it can lower the RTO
floor is the benefit that pays for it, so both land and are measured together.
The 5 ms silent-time re-check now follows that plan's item 5, which replaces the
single global rate limit with a per-destination one.

**Step 4 -- listen-path hardening.** Cap concurrent half-open sockets; make
the backlog independent of the pre-created socket pool so it is not 4 per
poll batch; lazily allocate socket buffers, or start rx small and grow, so a
SYN does not commit 256KB. Decide whether unmatched SYNs should RST or drop
under load. Coordinate with `tcp-receive-window.md` Step 2, which changes the
same buffer sizing. 2-4 patches.

Split by `docs/plans/core-safety-hardening.md`: the half-open cap, the
pool-independent backlog, and their counters are that plan's item 6 and land in
Step 6 of the execution order; the lazy or growable buffers move to Step 12,
where per-socket sizing must define the same construct-with-shift and
grow-an-empty-ring netstack surface. The half-open cap landed as patch 9 and the
pool's growth and its return as patches 10 and 10.1. The RST-versus-drop
question this step asked was decided in patch 10.2, which by user decision ran
immediately after the shrink rather than waiting on receive coalescing: a
request for an endpoint a listener owns is dropped and counted in
`net.tcp.syn_backlog_dropped`, and one for an endpoint no listener owns keeps
the RST that `net.tcp.syn_rst_unmatched` has counted since patch 8. That
completes item 6 and this step's hardening half.

**Step 5 -- deterministic packet tests.** Add a small harness around
`tcp::process()` and target the `socket/tcp.rs:1755` slice first. Build a
reviewed set of crafted segments covering sequence wrapping, receive-window
changes, RST handling, overlaps, duplicates, and batched transitions. Add a
sys-io harness that drives `MotoSocket` state transitions. This coverage gates
later architectural work.

Status: the existing `TestSocket`/`send` support already drives
`tcp::process()` directly, so Step 5 reuses it. A new interface-level
regression queues `SYN|ACK` and `FIN` together and proves one poll leaves the
connecting socket in `CloseWait`; sys-io's exhaustive compile-time state map
then classifies the connection as successful. Direct-process regressions also
cover receive overlap across the signed sequence-number boundary and
out-of-order assembler exhaustion without state corruption. The focused gate
now runs the 521-test Motor feature closure before every VM boot. A full-OS
sys-io harness observes `Listen`, both established endpoints, and the
`FinWait2`/`CloseWait` half-closed pair through public socket stats while
proving data still flows in the open direction. Three debug and three release
focused full suites pass with the deterministic regressions and final marker
in every run; the broad default closure passes 660 unit tests plus 7 doctests.
Step 5 is complete.

**Missing safety steps -- required before Step 6.** The P2/P3 and ARP
findings above need explicit implementation patches; regression bullets alone
do not schedule them. `docs/plans/networking-step-by-step.md` Step 6 orders
packet-facing arithmetic and short-write fixes, per-packet virtio checksum
metadata, ISN/port generation, RFC 5961 and PAWS, ARP hardening, and listen
hardening. Move the deterministic packet harness ahead of those fork behavior
changes.

Those patches are now planned in `docs/plans/core-safety-hardening.md`, whose
findings were re-verified after the in-tree import and the feature trim. It
records what RFC 5961 already has (the section 5 ACK range and the rate-limited
challenge ACK are in place; section 3's RST sequence check is not), that PAWS
requires enabling timestamps and therefore belongs with Step 3's RTT work, and
that the listen path's lazy or growable buffers cannot be designed separately
from per-socket sizing.

**Step 6 -- measure, then re-scope.** With Steps 1-5 landed and the other
three networking plans' work in place, re-run the full-OS benchmark set and
profile a many-connection server. Only then decide whether Option B's
connection table and timer wheel are worth their divergence cost, and in
what order. The expected answer is yes for the connection table if Motor
targets server workloads, and no for zero-copy until a profile shows the
copies dominating.

**Step 7 -- Option B, if Step 6 supports it.** Hashed 4-tuple demux; egress
ready-list; timer wheel for `poll_at`; allocating interval-list assembler;
real neighbor cache and route table. Each is separable and separately
measurable. Scope properly when reached; the bullets here are not an estimate.

**Deferred: Option C (zero-copy tokens).** Reopen only behind a profile.

## Regression coverage

Beyond each step's own tests:

- crafted-packet corpus: SYN|ACK+FIN in one batch, RST in every state, window
  shrink, zero-window probes, out-of-order storms exceeding the assembler,
  overlapping and duplicate segments (simultaneous open needs no crafted
  packet: a self-connect reaches it through the ordinary API);
- fragment reassembly abuse (before Step 2 removes it) as a regression guard
  that it is really gone;
- SYN flood: bounded memory, legitimate connects still succeed, no quadratic
  CPU;
- ARP cache flood: gateway entry survives, no request amplification;
- congestion control on/off A/B in the full OS, with deterministic protocol
  tests covering its loss-recovery state transitions;
- the preserved invariants listed above, especially the zero-window/notify
  interaction and close-during-drain.

## Risks and open questions

- **Step 2 is a large blast radius for a small diff.** Removing features can
  change behavior in non-obvious ways (ICMP auto-reply, IPv6 SLAAC paths,
  multicast). It deserves the full gate even though it is ten lines.
- **Congestion control will change benchmark numbers, possibly downward.**
  `NoControl` is "infinite cwnd", which flatters a clean local rig. Treat its
  performance and protocol-correctness evidence separately and record the
  expected local cost explicitly.
- **Lowering `RTTE_MIN_RTO` risks spurious retransmits** if RTT estimation is
  poor. The sampling half of that risk was closed first, and deliberately in a
  separate patch -- the estimator reads microseconds as of Step 10 item 2 part
  two, and holds a real `srtt` and `rttvar` on a 60-usec path -- and the floor
  came down to Linux's 200 ms in part three. **The residual risk is that the
  floor cannot be validated here:** it only ever shows itself on loss, and this
  rig produces none, so the change is argued from Linux's default and RFC 6298
  (2.4) rather than measured. Enabling timestamps for RTTM would not help and
  would hurt: RFC 7323
  section 5.4 bounds a timestamp tick at a millisecond or coarser, so sampling
  from the option reintroduces the truncation microseconds just removed. The
  option's remaining RTT value is a sample per ACK instead of one per window,
  and one that survives a retransmission.
- **Whether Motor targets server workloads at all** determines whether Option
  B is worth doing. The O(N) scans are irrelevant for a handful of
  connections and dominant for thousands. This is a product question, not a
  technical one, and it should be answered before Step 7 is scoped.
- **Upstream drift.** Steps 2-3 keep the fork small; Step 7 makes it large.
  Once B lands, cherry-picking upstream TCP fixes becomes real work. Budget
  for it or decide explicitly to pin.
- **The `async` cfg bug** (`SM/socket/tcp.rs:10-12`, from the TSO commit)
  makes the fork unbuildable without the `async` feature. Latent for Motor,
  but it must be fixed before Step 2 changes the feature set, or Step 2 will
  fail confusingly. Fixed in `14310975`.

## Sequencing against the other plans

Independent of `vdso-rewrite.md` -- different crates entirely.

Steps 0, 1 and 2 are self-contained and can land at any time; Step 1 should
land soon on its own merits, since it is a remote kill switch. Step 0(a) and
0(b) are pure plumbing -- no behavior change -- but should precede Steps 2
and 3 so their fork edits are ordinary in-tree commits. Step 0(c) touches a
client-visible ABI and 0(d) overlaps Option B, so both are scoped separately
and neither blocks Steps 1-5.

Step 3's congestion control and RTO changes interact with
`virtio-rx-coalescing.md` and `tcp-receive-window.md`: all three change what
the throughput benchmarks measure. Recommended order is coalescing and window
first (they raise ceilings), then Step 3 (it changes behavior under loss),
so each is attributable. Step 4 overlaps `tcp-receive-window.md` Step 2
directly -- both change socket buffer allocation -- and they should be done
together or in a deliberate order, not concurrently.

Step 6's measurement should be the same sitting that re-baselines the other
plans, using the benchmark manifest in
`docs/plans/networking-step-by-step.md`.

## Gates

Per AGENTS.md: `full-test.sh` three times debug and three times release, no
new compiler or clippy warnings, `cargo +nightly fmt`. Additionally:

- By explicit user guidance, this networking work uses
  `src/tests/full-test-networking.sh` for its three debug and three release
  passes. That focused copy omits all rmux/tmux tests and retains the full OS
  networking, systest, SFTP, mio, and tokio coverage. The standard harness and
  `AGENTS.md` are unchanged.
- Steps 2, 3, 4, 7 are data-path or behavior changes and need the paired
  same-host release rnetbench A/B from `vdso-rewrite.md` Section 10. Protocol
  behavior changes also need deterministic stack tests and full-OS coverage.
- Step 5's crafted-packet suite must pass before Step 7 begins.
- Every fork change is permanent divergence by policy (see "Upstreaming
  policy: none"); the fork's commit count should be recorded here as it
  grows.

The imported fork contains four divergence commits. `14310975` is the fifth
logical stack patch; the feature/policy trim is the sixth.
