# Core safety hardening: Step 6 patch plan

2026-07-29. Plan only. No code changes accompany this document.

This is the design-sized patch plan that `docs/plans/networking-step-by-step.md`
Step 6 requires before any of its six items may be implemented. That document
remains the authoritative execution order and status ledger;
`docs/plans/core-networking-rewrite.md` remains the finding-level reference.

Every claim below was re-verified against the working tree at `8e2b31a7`, after
the in-tree netstack import (`4a99ee18`), the feature trim (`e64273b6`), and the
Step 5 coverage. Citations are `file:line` with these prefixes:

- `N/` = `src/sys/sys-io/netstack/src/`
- `SI/` = `src/sys/sys-io/src/runtime/net/`
- `V/` = `src/sys/lib/virtio-async/src/`

## Summary

Item 1 is no longer only "panic-shaped code": the re-verification found a
concrete release-mode abort that a non-conforming remote peer can trigger on any
TCP connection, in either role. It is the same class as the Step 1 P0 (one peer
kills all networking on the machine, because `panic = "abort"`), it survived
Step 1 because it lives in the netstack rather than in sys-io, and Step 5's
direct `tcp::process()` support is exactly what proves it. Item 1 therefore
leads, and its first patch is that fix, landed with the regression that aborts
without it.

Nothing in Step 6 changes the poll structure, the socket store, or the token
contract; all of that stays in Steps 8, 10, and 14.

## Sequencing

This is the execution order of record. Items keep their Step 6 numbers; patches
are numbered within their item and executed in this order across items. Each
patch is separately gated and leaves a runnable tree, so a later patch can be
resequenced without re-planning, but the item order below is what the rest of
this document and the Step 6 ledger entry assume.

| Order | Patch | Why here |
|---|---|---|
| 1 | 1.1 D1's fix + its fail-first test | Remotely reachable release abort; the Step 5 harness already proves it. **Landed 2026-07-29; all gates passed** (result note in Item 1) |
| 2 | 1.2 reject instead of assert | Removes the remaining attacker-influenced panics on the same path. **Landed 2026-07-29; all gates passed** (result note in Item 1) |
| 3 | 1.3 bound the assembler offset (D4) | Same receive path, smaller blast radius |
| 4 | 1.4 sys-io abort-shaped sites | The audit Step 1 deferred; no netstack coupling |
| 5 | 2.1 surface the virtio RX header (D2) | First half of the Step 8 prerequisite |
| 6 | 2.2 per-packet checksum policy | Closes the trust gap |
| 7 | 2.3 RX checksum coverage | Completes item 2, which unblocks Step 8 |
| 8 | 6.1 half-open observability | Measure before choosing a cap |
| 9 | 6.2 cap half-open sockets | Bounds the SYN-flood memory |
| 10 | 6.3 backlog independent of the pool | Completes item 6, which unblocks Step 9 and `tcp-receive-window.md` Step 1 |
| 11 | 5.1 ARP admission | Removes the eviction primitive outright |
| 12 | 5.2 gateway protection | Protects the entry whose loss stalls all egress |
| 13 | 5.3 per-destination request rate | Stops one black hole from starving resolution |
| 14 | 4.1 RFC 5961 section 3 | Raises blind-reset cost from ~32768 guesses to 2^32 |
| 15 | 4.2 RFC 5961 section 4 | Small, additive, same code |
| 16 | 3.0 D3's fix in `rt.vdso` | 3.1's only prerequisite: it must not import a panic |
| 17 | 3.1 seed from hardware entropy | The seed stops being the boot clock |
| 18 | 3.2 RFC 6528 ISNs | Per-connection hashing |
| 19 | 3.3 randomized ephemeral ports | Last: touches an existing regression's determinism |

Item 1 leads because it is the only remotely reachable abort in the list and
because Step 5 built exactly the harness that proves it. Items 2 and 6 follow
because they gate later steps -- item 2 gates Step 8's receive-offload
expansion, item 6 gates Step 9 and the receive-window plan's default raise -- so
delaying them stalls other work. Items 5, 4, and 3 are all off-path-attacker
work that blocks nothing else; item 3 is last because RFC 5961's exact-sequence
RST check (item 4) already removes the cheapest blind attack that predictable
ISNs and ports enable, and because item 3 is the only item that costs an
existing regression's determinism.

Sequencing decided outside Step 6, recorded in the affected plans:

- Timestamps and PAWS move from item 4 into Step 10 item 2, where the
  RTT-sampling benefit pays for the 12-bytes-per-segment cost and both are
  measured together (`core-networking-rewrite.md` Step 3).
- Lazy or growable socket buffers move from item 6 into Step 12, which must
  define per-socket sizing over the same fork surface
  (`tcp-receive-window.md` Step 2). Item 6 delivers bounding only.
- Neighbor-cache capacity stays in Step 10 item 4, measured with the route
  table; item 5 hardens admission and eviction at the current eight entries.
- D3 (`fill_random_bytes` panics on RDRAND failure) is an `rt.vdso` patch, not a
  networking one. It lands immediately before 3.1, which is its only consumer
  here.

Decided in review, 2026-07-29: the three design choices are resolved -- item 2
lands as shape A, 4.2 stays in scope, item 3 randomizes external devices only --
and each of D1-D4 is approved for fixing at its scheduled place. The sections
below record each decision inline.

One roadmap input from that review shapes several choices here: **SYN cookies
are planned after this step.** They slot in after Step 10 item 2, because
cookies without timestamps lose window scaling (classic cookies encode MSS in
the ISN bits; wscale and SACK survive only in the timestamp option). Three
consequences inside Step 6: cookies reconstruct a socket from a stateless
SYN|ACK at ACK time, making them a second writer of `remote_last_win` and a
second computer of the receive-window right edge -- the reason D1's fix both
normalizes the field (1.1) and clamps acceptance (1.2); a cookie *is* an ISN,
so 3.2's SipHash and its key handling are direct prerequisites, not parallel
machinery; and 6.2's cap is the engagement trigger a future cookie mode plugs
into ("cap hit -> cookie mode" replaces "cap hit -> drop").

## Newly discovered preexisting defects -- approved 2026-07-29

AGENTS.md requires stopping on each of these before it is fixed. All four were
reviewed and approved on 2026-07-29; the fix shapes decided in that review are
recorded below. Where each one lands in the order: D1 is patch 1.1, D4 is patch
1.3, D2 is folded into patch 2.1, and D3 is an `rt.vdso` patch immediately
before 3.1.

**D1. `remote_last_win` records an unscaled SYN window into a scaled field.**
`dispatch` sets `remote_last_win = repr.window_len` unconditionally
(`N/socket/tcp.rs:2679`), but the SYN and SYN|ACK paths deliberately write an
*unscaled* window into that field (`:2494-2506`, with the comment "window len
must NOT be scaled in SYNs"). Every consumer shifts it back up by
`remote_win_shift`: the receive-window right edge (`:1681`) and
`last_scaled_window` (`:766`). With the shipped 128 KiB receive buffer,
`rx_cap_log2` is 18 and the shift is 2 (`:573`, `:594`), so for one round trip
after either an active or a passive open the socket computes a right edge of
`65535 << 2 = 262140` bytes while the receive buffer holds 131072 and while the
peer was correctly told 65535.

Consequences, in order of severity:

- The acceptance test (`:1693-1743`) admits in-order payload that the receive
  ring has no room for, because it clamps to `window_end` and never consults
  `rx_buffer.window()`. For in-order data the assembler returns the full length
  (`storage/assembler.rs:300-315` with an empty assembler), so
  `enqueue_unallocated(contig_len)` runs with `contig_len > window()` and trips
  the release-live `assert!(count <= self.window())` at
  `N/storage/ring_buffer.rs:345`. sys-io aborts; all networking on the machine
  dies. The preceding `write_unallocated` short write already trips
  `debug_assert!(len_written == payload_len)` (`:2162`) in debug builds.
- `Interface::poll` drains the entire receive queue before any egress
  (`N/iface/interface/mod.rs:495-508`), so no ACK is emitted mid-batch and the
  stale right edge governs the whole batch. Once an ordinary ACK does go out,
  `remote_last_win` becomes correctly scaled and the excess is truncated
  instead, so the window of exposure is one round trip per connection -- which
  is also exactly when a peer's first burst arrives.
- An honest peer cannot reach it: it sends at most the 65535 we advertised in
  the SYN, and our first ordinary ACK then publishes a correctly scaled window.
  A peer that ignores the advertised window reaches it with ~90 ordinary
  1460-byte segments to an application that is not draining. Motor is exposed in
  both roles -- as a server accepting the connection, and as a client connecting
  to a hostile server.
- It also mis-sizes `last_scaled_window`, i.e. the window-update ACK heuristic,
  for that same round trip.

Approved; fixed as patch 1.1, the first patch of Step 6: the field gets one
meaning -- the last window we advertised, in bytes -- so no consumer shifts it.
`dispatch` stores `repr.window_len` for SYN/SYN|ACK and
`repr.window_len << remote_win_shift` otherwise; `:1681` and `:766` use the value
directly. Its fail-first regression lands with it, because a test that aborts
cannot pass its own gate alone. Nothing else in Step 6 precedes it. The 1.2
acceptance clamp is part of the same decision, not merely defence in depth: the
planned syncookie path will initialize this field and recompute this right edge
in a second place, and a single-unit field plus a ring-bounded acceptance test
are what make that second writer safe to add.

**D2. The virtio RX size adjustor can underflow.**
`RX_SIZE_ADJUSTOR` is `|val| val - NET_HEADER_LEN as u32` (`V/virtio_net.rs:441`)
and its result is passed straight to `IoBuf::set_len` (`V/virtio_queue.rs:847`).
A device-reported used length below 12 wraps to ~4 GiB. The device is the host,
which Motor must trust for availability, but this is a one-line check on a path
item 2 already edits. Approved; fixed inside patch 2.1: reject the completion
(count it, re-post the buffer) when the used length is under `NET_HEADER_LEN`.
Reviewed against the threat model and kept: the host is trusted for
availability, but a hypervisor bug should surface as a counter, not as a wild
`set_len`.

**D3. `fill_random_bytes` panics when RDRAND fails.**
`rt.vdso`'s helper ignores the RDRAND carry flag and panics if the value is zero
(`src/sys/lib/rt.vdso/src/main.rs:444-463`). Two defects in one: a failed draw
(CF=0) that leaves garbage in `val` is silently accepted, and a legitimate zero
(CF=1, probability 2^-64 per 8-byte chunk) kills the calling process. Item 3
wants exactly one call per device at initialization, which inherits that panic.
Approved; fixed as its own `rt.vdso` patch immediately before 3.1, since it
belongs to a different subsystem: check the carry flag, accept zero when CF=1,
retry up to ten times per the Intel SDM's guidance for transient DRNG
underflow, and panic with a clear message only when all ten draws fail -- which
on real hardware means a broken DRNG. No entropy fallback: a generic randomness
primitive must not silently return weak bytes a later caller may use as key
material. The ten-draw retry is the AGENTS.md-sanctioned kind -- a documented
transient external failure -- and the 2026-07-29 review is the prior user
approval that rule requires.

**D4. The assembler accepts an unbounded offset.**
`Assembler::add` writes `Contig::hole_and_data(offset, size)` for any offset when
the first contig is unused (`N/storage/assembler.rs:206-215`), with no relation
to the receive ring's capacity. Recording a hole larger than the window can never
be filled, permanently keeps `assembler.is_empty()` false, and emits a phantom
SACK block (`N/socket/tcp.rs:1498-1503`). Approved; fixed as patch 1.3, bounded
in the caller, where the receive window is known, rather than in the assembler
(which has no capacity notion, and giving it one is the largest fork divergence
for the same protection). Reachability, stated honestly: the only known network
path to an out-of-window offset runs through D1's inflated right edge, so after
1.1 and 1.2 this is invariant enforcement, not a live bug. Kept because Step
12's growable rings and the planned syncookie path both touch the acceptance
arithmetic the invariant silently depends on, and a caller-side `debug_assert`
is what catches the next mistake there.

## Item 1 -- sequence arithmetic, assertions, short RX writes

### Verified state

Panicking primitives, all live in release:

- `SeqNumber - SeqNumber` panics when the wrapped difference is negative
  (`N/wire/tcp.rs:67-77`); `SeqNumber ± usize` panics above `i32::MAX`
  (`:39-59`).
- `PartialOrd` is a wrapping comparison (`:79-83`) and therefore not transitive:
  `a < b` means only that `b - a` lands in `(0, 2^31)`. `SeqNumber::max`/`min`
  (`:17-23`) inherit that. Two comparisons that each look satisfied can imply a
  third that is false -- which is how a crossed window survives the acceptance
  test.
- `assert!(count <= self.window())` in `enqueue_unallocated`
  (`N/storage/ring_buffer.rs:345`) and `assert!(count <= self.len())` in
  `dequeue_allocated` (`:398`).

Attacker-influenced call sites:

- `N/socket/tcp.rs:1746-1757`: `overlap_start`/`overlap_end` are derived from
  `window_start` and `window_end`, which are computed from different epochs
  (`:1679-1684`); the ordering invariant is only `debug_assert!`ed (`:1750`); the
  payload slice and the ring offset are three `SeqNumber` subtractions.
- `N/socket/tcp.rs:2161-2171`: `write_unallocated` silently clamps to the ring's
  free space (`N/storage/ring_buffer.rs:297-315`), the equality is only
  `debug_assert!`ed (`:2162`), and `enqueue_unallocated(contig_len)` then
  publishes a length the assembler computed rather than the length actually
  written.
- `N/socket/tcp.rs:2018-2026`: `dequeue_allocated(ack_len)` is guarded, several
  hundred lines earlier, by the acceptable-ACK range test (`:1644-1675`) -- and
  item 4 edits that test.

Reachability today is D1 above. The remaining sites are guarded only by
invariants that no code enforces.

### Patches

**1.1 -- D1's fix, proved by a fail-first test (~160 lines).** The fix and its
regression land together: the test aborts the process against the current
source, so it cannot be committed on its own without failing its own gate. It is
verified the way the Step 2 staging fence was -- run it against the unfixed
source once, record that it aborts, then run it against the fix. Test first in
the patch's own development order, fix second.

The fix gives `remote_last_win` one meaning -- the last window we advertised, in
bytes -- so no consumer shifts it. `dispatch` (`N/socket/tcp.rs:2679`) stores
`repr.window_len` for SYN and SYN|ACK and `repr.window_len << remote_win_shift`
otherwise; the right-edge computation (`:1681`) and `last_scaled_window`
(`:766`) then use the value directly.

The regressions are direct `tcp::process()` cases in `N/socket/tcp.rs`'s test
module, using the existing `TestSocket`/`send!` support that Step 5 established.
Two properties of that support decide how they must be written, and explain why
6600 lines of existing TCP tests never caught D1:

- `socket_established_with_buffer_sizes` hand-sets
  `remote_last_win = s.scaled_window()` (`:3081`), i.e. the correctly scaled
  value. The defect is in what `dispatch` records, so the test must drive the
  handshake through `dispatch` rather than start from that helper.
- The default 64-byte test buffers give `remote_win_shift == 0` (`:573`,
  `:594`), which hides any scaling defect. The test needs a receive buffer of at
  least 65536, the smallest capacity with a nonzero shift; at exactly 65536 the
  recorded right edge is twice the ring and about 45 ordinary segments reach it.

The cases:

- passive and active open, each driven through `dispatch` so the SYN|ACK path
  records the window, then an in-order stream exceeding the advertised window
  inside one batch: the socket must reject the excess, stay usable, and deliver
  exactly the bytes it accepted. This is the fail-first case.
- the same two opens, asserting directly that the recorded window equals what
  the peer was told, so a future scaling change cannot silently reintroduce D1.

**1.1 result, landed 2026-07-29.** The fail-first record matches the analysis:
against the unfixed source both overrun regressions abort in release on the
release-live `assert!(count <= self.window())` at
`N/storage/ring_buffer.rs:345`, in debug on the short-write `debug_assert!` at
`N/socket/tcp.rs:2162`, and the recorded-window regressions show the halved
consumer values directly. The fix stores the field in bytes (now `u32`):
`dispatch` records SYN/SYN|ACK window fields verbatim and every other
segment's shifted up by `remote_win_shift`; the right edge,
`last_scaled_window`, and the ACK-reply site use the value directly.

One interaction surfaced during implementation and was resolved in the patch:
with the field honest, `window_to_update` -- whose input the D1 entry above
already called mis-sized -- began emitting its corrective window update while
still in SYN-RECEIVED, because a scaled socket's SYN|ACK can announce at most
65535 bytes. That is a second reply to every SYN, i.e. amplification ahead of
item 6's half-open bounding, so by implementation decision the heuristic is
restricted to post-handshake states and the full-window advertisement goes
out on reaching ESTABLISHED. (SYN-SENT was dead in its state list:
`remote_last_ack` stays `None` for that whole state.)
`test_listen_full_window_advertised_after_establish` pins both halves --
nothing follows the SYN|ACK, and the update fires after the handshake ACK.
Reverting to the SYN-RECEIVED update is a one-line change if review prefers
it.

Five regressions landed: passive and active overrun-and-recover (46 ordinary
1460-byte segments against a 65536-byte ring in one batch; exactly the
advertised bytes delivered, one challenge ACK for the excess, tail retransmit
accepted after the window reopens), passive and active
recorded-window-in-bytes, and the establishment advertisement above. Gates:
the Motor closure passes 526 unit tests plus 7 doctests and the broad default
closure 665 plus 7, both with all-target clippy warnings denied; Motor-target
debug and release builds and clippy show only the pre-existing
`sys-io/src/runtime` warnings; three consecutive debug and three consecutive
release `full-test-networking.sh` runs passed with no retries and no
tolerated failures, all six containing the five new regressions.

Paired same-host release `rnetbench` with one unchanged host client: bulk is
RR +2.1 usec, RX -0.74%, TX -0.9% (medians of three). The initial default
block pair straddled a host performance-state shift -- rerunning the *clean*
tree afterwards reproduced the "regressed" numbers exactly -- so default was
re-measured as A/B/A blocks of five rounds each. Within the same regime the
prepared tree matches clean HEAD round-for-round, including the
first-round-after-boot spike: medians RR -4.4 usec (prepared faster), RX
-0.25%, TX +0.10%. All samples retained; the host rig shows two default-RX/TX
regimes (~166/325 fresh, ~141/301 MiB/s after sustained benching), which
future A/Bs should bracket with an A/B/A design.

**1.2 -- reject instead of assert (~140 lines).** With D1 fixed, the right edge
can no longer exceed the ring, so what remains is defence in depth for every
other epoch mismatch: this patch makes the arithmetic incapable of aborting
rather than merely currently-unreachable. Bound the accepted payload by
`rx_buffer.window()` as well as by `window_end`; normalize `window_end` to at
least `window_start` with a comment naming the epochs; replace the three
subtractions at `:1755-1756` with checked helpers that drop the segment (and
`net_debug!`) instead of panicking; make the short-write case drop the segment
before the assembler records it, so no ACK advances over data we did not store;
turn the two ring-buffer `assert!`s into debug assertions plus caller-side
rejection, keeping the documented panic contract on the public methods.

Its tests: a receive window whose recorded right edge precedes its left edge,
asserting every acceptance branch rejects instead of computing an overlap; and a
short in-order write against a nearly full ring, asserting nothing is enqueued
and no stale bytes are ever readable -- fill the ring with a known pattern
first, so a stale publication shows up as data, not just as a length. Both
construct the state directly, since after 1.1 no packet sequence produces it.

**1.2 result, landed 2026-07-29.** Implemented as planned, with one addition
and one clarification.

The right edge is now bounded on both sides in one place: it is raised to the
left edge and lowered to `window_start + rx_buffer.window()`, with the comment
naming the two epochs. The three subtractions became `Socket::receive_overlap`,
which derives the accepted slice and its ring offset through a new
`SeqNumber::checked_sub` and rejects -- `net_debug!` plus drop -- when the
bounds cross or the overlap does not fit the ring. The write site re-checks the
room before the assembler records anything, so a short write can never make us
acknowledge octets the ring did not store. Both ring-buffer `assert!`s are
debug assertions that clamp in release, with their panic contracts documented
as debug-build behavior; `dequeue_allocated`'s caller clamps `ack_len` to the
unacknowledged octets first, and its own `ack_number - tx_buffer_start_seq` is
now the checked subtraction that guards it.

The addition: `last_scaled_window` computed `last_ack + last_win - next_ack`,
a fourth panicking subtraction over the same two epochs, on the *dispatch*
path rather than the receive path. It now returns `None` there, which
`window_to_update` already treats as "no previous window".

Three regressions landed: `test_receive_overlap_bounds` drives the helper
directly over in-order, truncated, left-trimmed, out-of-order, crossed, and
past-the-ring cases; `test_established_recorded_window_beyond_ring` gives an
established socket a right edge 4 KiB past its ring (constructed directly,
since after 1.1 no packet sequence records one) and requires that exactly the
ring's worth is accepted from a 100-octet segment, that the socket stays
usable, and that the delivered octets are the peer's, not the pattern the ring
storage was filled with; `test_established_crossed_receive_window` crosses the
edges and sends a segment far enough ahead that the wrapping acceptance
comparisons admit it, requiring an empty assembler and a usable socket after.
`SeqNumber::checked_sub` has its own wrap-crossing unit test.

The fail-first record was captured against the unfixed source: in debug both
`process()`-level regressions abort on the short-write `debug_assert!`
(`N/socket/tcp.rs:2209`); in release the beyond-the-ring one aborts on the
release-live `assert!(count <= self.window())`
(`N/storage/ring_buffer.rs:349`) and the crossed one survives with a phantom
assembler hole -- D4's exact shape, which patch 1.3 bounds at the caller.

**1.3 -- bound the assembler offset (~60 lines).** D4's fix in the caller, with
a direct test that a far-offset out-of-order segment is rejected, leaves the
assembler untouched, and does not prevent later in-order recovery (the Step 5
overflow regression already covers the in-capacity case).

**1.4 -- sys-io abort-shaped sites (~120 lines).** The audit deferred by Step 1:
`SI/device.rs:41` (`assert!(len <= BIG_BUF_SIZE)`), `:50` (`IoBuf` allocation
unwrap), `:155` (`assert!(result.is_ok())` on every RX completion), `:591` and
`:633` (address/identifier removal asserts), `SI/socket/tcp.rs:949`
(`Err(_err) => todo!()` in the TX loop), and the live-in-release assert whose
`#[cfg(debug_assertions)]` is commented out at `src/sys/sys-io/src/runtime/net.rs:384-386`.
Each becomes a logged error plus a local recovery path. No behavior change on
the success path.

### Tests and gate

Direct `process()` tests run in the netstack closure that
`full-test-networking.sh` already builds (its `NETSTACK_FEATURES` line). 1.4 is
covered by the existing full-OS suites. Per patch: `cargo +nightly fmt`, the
Motor debug and release builds, debug and release clippy, the netstack feature
closure plus the broad default closure, and three debug plus three release
`full-test-networking.sh` runs. 1.1 and 1.2 touch the per-segment receive path,
so both also need the paired same-host release `rnetbench` A/B (default and
64 KiB).

## Item 2 -- per-packet virtio RX checksum metadata

### Verified state

The finding in `core-networking-rewrite.md` ("sys-io sets RX checksum
verification to `None` unconditionally") is stale in its detail and correct in
its substance. Current code keys the capability on both negotiated features:

```
caps.checksum.tcp = match (self.guest_csum, self.csum_offload) { ... }   SI/device.rs:342-347
caps.checksum.udp = if self.guest_csum { Checksum::Tx } else { Checksum::Both }  :348-352
```

So with `VIRTIO_NET_F_GUEST_CSUM` negotiated, TCP and UDP receive verification is
off for *every* frame. Per-packet metadata is not merely ignored -- it never
reaches sys-io:

- `post_read` zeroes a `NetHeader` and submits it as a separate descriptor; the
  completion returns only the data `IoBuf` and a length, so the device-written
  `flags` are dropped when the descriptor is released
  (`V/virtio_net.rs:419-451`, `V/virtio_queue.rs:827-853`).
- Only `VIRTIO_NET_HDR_F_NEEDS_CSUM` is even defined (`V/virtio_net.rs:54`);
  there is no `DATA_VALID` constant.
- ICMP is unaffected: sys-io leaves `caps.checksum.icmpv4`/`icmpv6` at `Both`,
  and the virtio L4 offload contract does not cover ICMP.

Enabling infrastructure already exists on the netstack side: `RxToken::meta()`
is a trait method with a default (`N/phy/mod.rs:402-415`), `socket_ingress`
already reads it and threads it into `process_ethernet`/`process_ip`
(`N/iface/interface/mod.rs:646-692`), and only two ingress sites consult the L4
checksum policy -- `N/iface/interface/tcp.rs:19` and `N/iface/interface/udp.rs:24`.
`caps` itself is captured once at `Interface::new` (`:221`, `:275`), so a
per-packet policy cannot come from `capabilities()`.

### Design decision (decided 2026-07-29: shape A)

Two implementable shapes were considered; A is decided and the patches below
implement it. Patch 2.1 would have been needed by either shape:

- **A (decided): carry the verdict in `PacketMeta` and honor it at the two
  ingress parse sites.** Add `l4_csum_vouched: bool` to `PacketMeta`
  (`N/phy/mod.rs:164-177`), return it from `VirtioRxToken::meta()`, store it on
  `InterfaceInner` while a frame is being processed, and select the effective
  checksum capability at `iface/interface/tcp.rs:19` and `udp.rs:24`. sys-io then
  advertises RX verification as *on* and lets vouched frames skip it. Keeps all
  checksum logic in the netstack, is ~80 lines of fork change, and preserves the
  GUEST_CSUM saving exactly where the host actually vouched.
- **B: verify in sys-io's `RxToken::consume` before handing the frame over.** No
  fork change, but it duplicates IP/TCP/UDP parsing and checksum code in sys-io
  and parses every unvouched frame twice.

B was rejected for that duplication, and because coalescing Step 1's host-built
super-segments arrive `NEEDS_CSUM` -- inherently per-packet state that B would
have to special-case outside the stack that owns the parsing.

A also decides the policy per flag, which needs confirming: `DATA_VALID` -> skip
(the device verified); `NEEDS_CSUM` -> skip (the field holds only a
pseudo-header sum, so verification would reject a valid host-originated frame --
this is Linux's `CHECKSUM_PARTIAL` on ingress); `flags == 0` -> verify. That last
case is the whole point: it is what QEMU delivers for frames the host did not
validate, and it is what is silently accepted today.

### Patches

**2.1 -- surface the header (~90 lines).** Read `NetHeader.flags`, `gso_type`,
and `num_buffers` when the RX completion resolves, before the descriptor chain is
released, and return them alongside the buffer. Define `DATA_VALID`. Reject and
count frames that are impossible for our negotiated feature set: a nonzero
`gso_type` without `GUEST_TSO`, or `num_buffers > 1` without `MRG_RXBUF`.
Includes D2's length check (approved above).

**2.2 -- per-packet policy (~110 lines).** Shape A above, plus sys-io's RX queue
carrying the per-packet verdict to `VirtioRxToken`, plus a new
`net.rx.csum_failed` counter (`SI/stats.rs`, next free metric id after
`NET_UDP_TX_DROPPED = 19`) for frames dropped by verification.

**2.3 -- coverage (~120 lines).** Netstack tests driving `Interface::poll` with
each verdict: an unflagged frame with a corrupt TCP checksum is dropped and
delivers nothing; the same frame flagged `DATA_VALID` is delivered; a
`NEEDS_CSUM` frame whose checksum field holds only a pseudo-header sum is
delivered; the same three for UDP. A full-OS check that ordinary traffic still
flows and that `net.rx.csum_failed` stays at zero across the suite.

### Tests and gate

Standard per-patch gate. 2.2 changes per-frame receive work, so paired release
`rnetbench` A/B is required; record whether the local rig's frames arrive
vouched (expected: host-originated traffic yes, so the steady-state cost should
be a flag test per frame). Item 2 is the gate on Step 8: do not expand the
receive-offload feature set until 2.1-2.3 have landed.

## Item 6 -- bounded half-open sockets and backlog (buffers deferred)

### Verified state

- Every socket, including every *listening* socket, eagerly allocates 128 KiB
  receive and 128 KiB transmit rings (`SI/socket/tcp.rs:272-281`).
- A listener pre-creates `DEFAULT_NUM_LISTENING_SOCKETS = 4`, and a client may
  request up to `MAX_NUM_LISTENING_SOCKETS = 32` through `msg.flags`
  (`SI/tcp_listener.rs:11-12`, `:340-347`) -- 8 MiB of listening rings per
  listener at the maximum.
- A replacement listening socket is spawned when the current one leaves `Listen`
  (`SI/socket/tcp.rs:390-401`), which cannot happen until the executor runs, i.e.
  after `poll()` has drained the whole receive queue. So the effective backlog
  per poll batch is the pool size.
- Half-open sockets are bounded only by the 15-second socket timeout
  (`:371-379`); nothing caps how many exist. Steady-state memory is
  `SYN_rate x 15 s x 256 KiB`.
- A SYN matching no socket gets an RST from the netstack
  (`N/iface/interface/tcp.rs:44`), so pool exhaustion presents to an honest
  client as `ECONNREFUSED` rather than as a retryable drop.

### Scope, decided

- **Item 6 delivers bounding only:** a half-open cap, a backlog independent of
  the pre-created pool, and the counters to see both. Lazy or growable buffers
  move into Step 12. They cannot be designed twice cheaply: `remote_win_shift`
  is fixed from the receive capacity at construction (`N/socket/tcp.rs:573`,
  `:594`) and window scale is negotiated in the SYN, so starting small and
  growing needs an explicit construct-with-shift API plus a grow-an-empty-ring
  API in the fork -- exactly the surface `tcp-receive-window.md` Step 2 and Step
  12 must define for per-socket sizing. Recorded in both plans; this narrows
  Step 6 item 6 rather than dropping work.
- **Overload behavior stays RST for now.** With a cap, excess SYNs match no
  socket and the netstack RSTs them. Dropping is better under flood but must not
  change the nothing-is-listening case, which existing tests and applications
  depend on, so 6.1 counts the unmatched RSTs and the choice is revisited with
  Step 8's batching evidence.

### Patches

**6.1 -- observe (~90 lines).** `net.tcp.half_open` (gauge) and
`net.tcp.syn_rst_unmatched` (counter) in `SI/stats.rs`, plus a full-OS test that
half-open count rises and falls across a deliberately stalled handshake.
Measurement first, so the cap in 6.2 is chosen against data.

**6.2 -- cap half-open sockets (~140 lines).** A per-listener and a global cap;
at the cap, replenishment is deferred rather than spawned, and resumes when a
half-open socket completes or times out. No change to the accept path. Test: a
raw-channel regression that opens more simultaneous half-open connections than
the cap, proves the gauge plateaus at the cap, and proves a legitimate connect
succeeds once earlier half-opens complete.

**6.3 -- backlog independent of the pool (~140 lines).** Decouple the accept
backlog from the pre-created socket count so the pool size stops being the
per-batch backlog. Exact mechanism to be settled inside 6.2's measurements; if
it cannot be done without the buffer work, it joins Step 12 with the same
recommendation as above, recorded explicitly rather than dropped.

### Tests and gate

Standard per-patch gate. 6.2 and 6.3 change the listen path, so paired release
`rnetbench` A/B plus a full-OS accept-rate check. Item 6 gates
`tcp-receive-window.md` Step 1 and Step 9: no default buffer raise before the
half-open count is bounded.

## Item 5 -- ARP cache admission, eviction, request rate

### Verified state

- Eight entries machine-wide in a linear map with earliest-expiry eviction
  (`N/iface/neighbor.rs:44-49`, `:105-144`); entry lifetime 60 s (`:53`).
- Any same-subnet ARP *request* aimed at one of our addresses fills the cache
  (`N/iface/interface/ipv4.rs:299-307`), so eight forged requests evict every
  legitimate entry, the gateway included. IPv6 fills only from neighbor
  advertisements carrying a link-layer address (`ipv6.rs:472`).
- The request rate limit is a single global `silent_until` (`neighbor.rs:48`,
  `:158-167`), armed after each dispatched request
  (`N/iface/interface/mod.rs:1204-1207`), which sys-io sets to 5 ms
  (`SI/device.rs:407`) -- the fork's own `44ecae4` knob, 200x more aggressive
  than upstream's 1 s. Because it is global, resolution of a legitimate address
  is starved by egress to unresolvable ones.
- An unresolved destination fails dispatch with `NeighborPending`
  (`mod.rs:1131-1135`), i.e. the packet is dropped and TCP waits out its RTO,
  which is at least 1 s (`N/socket/tcp.rs:159`).

### Patches

**5.1 -- admission (~110 lines).** An ARP request may refresh an existing entry
but may not evict one to create a new entry; replies to our own requests, and
requests when a slot is free, still fill. This is `arp_accept = 0` behavior and
removes the eviction primitive outright. Netstack tests: a request from an
unknown same-subnet address with a full cache leaves every entry intact; the
same request with a free slot fills it; a request from a known address refreshes
its expiry.

**5.2 -- gateway protection (~90 lines).** Never evict an entry that a
configured route's gateway resolves to. Test: a flood of distinct same-subnet
sources cannot displace the gateway entry, and egress through the gateway keeps
working across the flood.

**5.3 -- per-destination request rate (~120 lines).** Replace the global
`silent_until` with a per-destination silent time so one unresolvable address
cannot starve another, keeping sys-io's 5 ms value and re-recording its
motivation. Test: two destinations, one black-holed, and the other still
resolves within one silent interval.

Explicitly out of scope, with rationale: rate-limiting ARP *replies*. Replying
to a request aimed at us is required behavior and is 1:1, not amplifying.

Cache capacity (`iface-neighbor-cache-count-N`) stays in Step 10 item 4, decided:
it is a build-feature change with a linear-scan cost that belongs with the route
table it is measured against, and 5.1 removes the eviction primitive outright, so
the eight-entry limit stops being an attack surface and becomes only a
performance question. 5.1 is nonetheless strictly more effective with more slots,
so Step 10 item 4 must not be deferred indefinitely.

### Tests and gate

Netstack tests plus a full-OS check that ordinary external traffic is unaffected.
Standard per-patch gate; no data-path cost expected, but 5.3 touches egress
dispatch, so include the paired release `rnetbench` A/B.

## Item 4 -- RFC 5961 RST handling and PAWS policy

### Verified state

Partially present, which changes the shape of this item:

- Challenge-ACK infrastructure exists and is rate-limited to one per second
  (`N/socket/tcp.rs:1512-1526`), and is already used for an unacceptably high
  ACK (`:1674`), an out-of-window segment (`:1765`), and a duplicate ACK in
  `LastAck` (`:1990`). RFC 5961 section 5's ACK acceptance range is therefore
  effectively in place: too-old ACKs are dropped (`:1657-1665`), too-new ACKs get
  a challenge ACK.
- Section 3 is **not** in place. After the SYN-SENT special cases, any RST needs
  only a valid sequence number (`:1593`), and any in-window RST closes the
  connection (`:1835-1839`). RFC 5961 requires `SEG.SEQ == RCV.NXT` exactly, and
  a challenge ACK otherwise. With a 128 KiB window a blind off-path reset needs
  ~32768 guesses instead of 2^32.
- Section 4 is not in place either, but fails safe: a SYN in a synchronized
  state matches no arm of the state machine and is dropped with a `net_debug!`
  (`:1995-1998`) rather than resetting the connection. Compliance gap, not a
  vulnerability.
- PAWS is absent. Timestamps are parsed and echoed (`:2098-2100`, `:1452`,
  `:2473-2476`) but `last_remote_tsval` is never compared, and sys-io never
  installs a `tsval_generator` (`:537-541`, `:606-607`, `:621-627`), so
  timestamps are off entirely: we never offer TSopt, so no peer sends one, so
  PAWS has nothing to compare.

### Scope, decided

Item 4 lands RFC 5961 section 3 (and optionally section 4); **timestamps and PAWS
move to Step 10 item 2.** PAWS requires offering TSopt, which costs 12 bytes of
options on every segment and adds option processing to the per-packet path. The
same change is what Step 10 item 2 needs before it can lower the 1-second RTO
floor, so landing it there pays for the per-segment cost with the RTT-sampling
benefit and measures both in one sitting. Enabling timestamps here would mean
measuring the cost twice and attributing it to the wrong change. Recorded in
`core-networking-rewrite.md` Step 3 and in the Step 10 ledger entry.

4.2 reviewed and kept (2026-07-29). A blind in-window SYN is already dropped
rather than acted on, so section 4 adds no attack-surface defence -- what the
silent drop gets wrong is liveness. A rebooted peer reusing the same 4-tuple
sends a fresh SYN; dropping it silently strands that peer, because our stale
socket lingers until keepalive fires, and `keep_alive` is off by default, so
possibly forever. The challenge ACK is the recovery mechanism: the rebooted
peer answers it with a correctly-sequenced RST, the stale socket closes
legitimately, and the peer's SYN retry succeeds. This is also RFC 9293
3.10.7.4 conformance -- the same clause the fork already implements for
duplicate ACKs in LastAck (`:1990`).

### Patches

**4.1 -- RFC 5961 section 3 (~130 lines).** An RST is accepted only at exactly
`RCV.NXT`; an in-window RST elsewhere produces a rate-limited challenge ACK; an
out-of-window RST is dropped silently rather than answered. Preserve the two
SYN-SENT special cases (`:1582-1591`) and the SYN-RECEIVED-to-LISTEN return
(`:1827-1832`), which sys-io's listen task depends on
(`SI/socket/tcp.rs:474-480`). Netstack tests: an in-window RST off by one leaves
the connection established and emits at most one challenge ACK per second; an
exact-`RCV.NXT` RST still closes; an out-of-window RST is silent; the
SYN-RECEIVED case is unchanged.

**4.2 -- RFC 5961 section 4 (~70 lines).** A SYN in a synchronized state gets a
rate-limited challenge ACK instead of a silent drop: one match arm ahead of the
`_ =>` catch-all (`:1995-1998`), reusing `challenge_ack_reply`. Netstack tests:
a SYN in Established elicits at most one challenge ACK per second and changes
no state; the full rebooted-peer sequence (SYN, challenge ACK, correctly
sequenced RST, reconnect on the same tuple) recovers.

Step 5 deliberately did not lock in current RST behavior, so no existing
netstack test needs to change; 4.1 must confirm that while it lands.

### Tests and gate

Standard per-patch gate. Protocol behavior change, so also: the full-OS suites
must show unchanged connect-refused, close, and abort behavior, and the paired
release `rnetbench` A/B.

## Item 3 -- ISN and ephemeral-port generation

### Verified state

- ISNs come from one PCG32 per interface (`N/rand.rs:9-39`,
  `N/iface/interface/mod.rs:131`, `:228`, `:863-864`), consumed through
  `Socket::random_seq_no` (`N/socket/tcp.rs:1059-1062`). Consecutive connections
  are consecutive PRNG outputs, so a peer that opens a few connections can
  recover the state. No RFC 6528 per-connection hashing.
- The seed is boot wall-clock nanoseconds (`SI/device.rs:402-405`).
- Ephemeral ports are allocated as the lowest free port from 49152, for both TCP
  and UDP (`SI/device.rs:562-576`, `:595-613`).
- `random_seq_no` is a constant 10000 under `cfg(test)` (`N/socket/tcp.rs:1055-1057`),
  which the netstack's ~6600 lines of TCP tests depend on. Any change must keep a
  deterministic test path.

### The test interaction, stated up front

`test_simultaneous_open` (`src/sys/tests/systest/src/tcp.rs:1127-1163`) is
deterministic *because* allocation is lowest-free: it binds a port-zero listener,
releases it, and connects to the port the next allocation must return, producing
a self-connect. Randomizing ephemeral ports breaks the only regression covering
the RFC 9293 simultaneous-open transition that Step 1's P0 `panic!` guarded.

This is why item 3 is last in the order: it is the only Step 6 item whose cost
includes an existing regression, and everything else should be landed and gated
before that cost is paid.

Decided 2026-07-29: randomize on devices that carry external traffic and keep
lowest-free on the logical loopback device. Loopback ports are already
enumerable by any local process through the public socket-stats service
(`SI/stats.rs`), so randomizing them buys nothing against a local attacker,
while off-path port guessing is precisely an external-path threat. The
regression then keeps working unchanged, with no test-only hook in production
code. The alternative -- randomizing everywhere and rebuilding that regression
on bind-before-connect, a mechanism that does not exist yet -- would make item 3
wait for `networking-step-by-step.md` Step 12's local-port work. Two riders on
the decision: 3.3 also enforces the premise that loopback has no off-path
attacker by dropping 127/8 addresses arriving on external ingress, and once
Step 12 lands, the regression can pin its source port explicitly, at which
point unifying on randomization everywhere becomes a small revisit rather than
a lost test.

### Patches

**3.0 -- D3's fix in `rt.vdso` (~40 lines).** As decided under D3: check the
carry flag, accept a zero drawn with CF=1, retry up to ten times, panic clearly
on ten consecutive failures; no entropy fallback. The success path is exercised
constantly by every process (hasher seeds); the failure path is not testable
without a seam over the intrinsic, which a loop this small does not justify --
it is reviewed as written. Separate patch, separate subsystem, immediately
before 3.1.

**3.1 -- seed from hardware entropy (~50 lines).** Replace the wall-clock seed
with one `moto_rt::fill_random_bytes` call per device at initialization. One
RDRAND per device at boot; no per-packet or per-connection cost. Unit test that
two interfaces constructed in the same process do not share a seed.

**3.2 -- RFC 6528 ISNs (~180 lines, may split).** `ISN = M + F(4-tuple, key)`
with `M` a coarse monotonic timer and `F` a keyed PRF. Implement SipHash-2-4 in
the netstack with the reference test vectors so the primitive itself is
verifiable, key it from the interface's entropy, and keep the `cfg(test)`
determinism. Netstack tests: identical tuples with different keys differ;
different tuples with one key differ; a reconnect on the same tuple advances
monotonically; the published SipHash vectors pass.

**3.3 -- randomized ephemeral ports (~150 lines).** RFC 6056: a random starting
offset in the ephemeral range, then upward scan for a free port, preserving the
existing in-use and reserved-port checks (`SI/device.rs:595-613`, including the
listener-reservation predicate added in Step 1). Applied per the loopback
decision above, whose premise this patch also enforces: 127/8 source or
destination addresses arriving on external-device ingress are dropped at the
IPv4 ingress validation site and counted the way 2.2 counts checksum drops.
Tests: allocations do not form a monotone run on an external device; the
loopback device still returns lowest-free; a 127/8-source frame on the external
device is dropped and counted; the listener-conflict regression and
`test_simultaneous_open` are unchanged.

### Tests and gate

Standard per-patch gate. 3.2 touches connection setup, so include the paired
release `rnetbench` A/B (the request-response workload opens and closes
connections, so a per-connection hash shows up there if anywhere).

## What Step 6 deliberately does not do

- No congestion control, RTO floor, assembler capacity, or neighbor/route
  capacity change: Step 10, measured separately. Timestamps and PAWS join that
  step by the sequencing above.
- No receive-offload expansion, poll-batching change, or coalescing: Step 8,
  and gated on item 2. `virtio-rx-coalescing.md` Step 1 records the dependency
  and that it relaxes patch 2.1's `gso_type` check when it acks guest TSO.
- No buffer default raise, no per-socket sizing, and no lazy or growable socket
  buffers: Steps 9 and 12, per item 6's scope decision.
- No connection table, ready list, or timer wheel: Step 14.
- No SYN cookies. They need deep fork work and, with item 6's cap plus item 1's
  hardening, are not the next marginal gain. Recorded so the omission is a
  decision.

## Gates for every Step 6 patch

Per `networking-step-by-step.md`, this work uses
`src/tests/full-test-networking.sh` in place of the repository-wide harness:

1. `cargo +nightly fmt`.
2. Motor-target debug and release builds; debug and release clippy with no new
   warnings.
3. The Motor netstack feature closure and the broad default closure, both with
   warnings denied.
4. Three consecutive debug and three consecutive release
   `full-test-networking.sh` runs, with no retries and no tolerated failures.
5. Paired same-host release `rnetbench` A/B (default and 64 KiB) for every patch
   marked above as touching a data path or protocol behavior.
6. Every new test reachable from `full-test-networking.sh`, directly or
   transitively.

Patches needing the paired `rnetbench` A/B, from the sections above: 1.1, 1.2,
2.2, 5.3, 6.2, 6.3, 3.2, and 4.1.

Each patch updates this document's Sequencing table with its result and the Step
6 status in `networking-step-by-step.md` as it lands, and corrects
`core-networking-rewrite.md` where it changes one of that document's facts.
