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

This is the execution order of record.

**Numbering.** Step 6 has nineteen patches, numbered **1 to 19 in execution
order**. That number is a patch's only name: "Step 6 patch 8" is the eighth
patch to land, always. Items keep their Step 6 numbers, but an item is a topic,
not a position -- the items are worked in the order 1, 2, 6, 5, 4, 3, so the
patch number, not the item number, is what says when something happens. Each
patch is separately gated and leaves a runnable tree, so a later patch can be
resequenced; if one is, renumber the table rather than inserting a fraction.

Patches 1 to 7 were committed before this numbering existed, under item-local
labels (1.1 through 2.3). The `Committed as` column is the crosswalk from those
commit subjects to the numbers used everywhere else; no other document uses the
old labels any more.

| Patch | Item | What it does | Why here | Status |
|---|---|---|---|---|
| 1 | 1 | D1's fix + its fail-first test | Remotely reachable release abort; the Step 5 harness already proves it | **Landed 2026-07-29** as `b8d1c105` (`Step 6 patch 1.1, D1`); result note in Item 1 |
| 2 | 1 | Reject instead of assert | Removes the remaining attacker-influenced panics on the same path | **Landed 2026-07-29** as `89c076de` (`fix window size handling`); result note in Item 1 |
| 3 | 1 | Bound the assembler offset (D4) | Same receive path, smaller blast radius | **Landed 2026-07-30** as `a465b5b8` (`fix a potential tcp assembler issue`); result note in Item 1 |
| 4 | 1 | sys-io abort-shaped sites | The audit Step 1 deferred; no netstack coupling | **Landed 2026-07-30** as `bd864a88` (`hardening patch 1.4`); result note in Item 1 |
| 5 | 2 | Surface the virtio RX header (D2) | First half of the Step 8 prerequisite | **Landed 2026-07-30** as `ecd83483` (`hardening patch 2.1`); result note in Item 2 |
| 6 | 2 | Per-packet checksum policy | Closes the trust gap | **Landed 2026-07-30** as `6b187439` (`hardening patch 2.2`); result note in Item 2 |
| 7 | 2 | RX checksum coverage | Completes item 2, which unblocks Step 8 | **Landed 2026-07-30** as `610623ed` (`hardening patch 2.3`); result note in Item 2 |
| 8 | 6 | Half-open observability | Measure before choosing a cap | **Landed 2026-07-31**; result note in Item 6 |
| 9 | 6 | Cap half-open sockets | Bounds the SYN-flood memory | **Landed 2026-07-31**; result note in Item 6 |
| 10 | 6 | Backlog independent of the pool | Completes item 6, which unblocks Step 9 and `tcp-receive-window.md` Step 1 | **Next** |
| 11 | 5 | ARP admission | Removes the eviction primitive outright | |
| 12 | 5 | Gateway protection | Protects the entry whose loss stalls all egress | |
| 13 | 5 | Per-destination request rate | Stops one black hole from starving resolution | |
| 14 | 4 | RFC 5961 section 3 | Raises blind-reset cost from ~32768 guesses to 2^32 | |
| 15 | 4 | RFC 5961 section 4 | Small, additive, same code | |
| 16 | 3 | D3's fix in `rt.vdso` | Patch 17's only prerequisite: it must not import a panic | |
| 17 | 3 | Seed from hardware entropy | The seed stops being the boot clock | |
| 18 | 3 | RFC 6528 ISNs | Per-connection hashing | |
| 19 | 3 | Randomized ephemeral ports | Last: touches an existing regression's determinism | |

Future commit subjects use the number: `sys-io: net: hardening patch 8`.

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
  define per-socket sizing over the same fork surface (`tcp-receive-window.md`
  Step 2). Item 6 delivers bounding only.
- Neighbor-cache capacity stays in Step 10 item 4, measured with the route
  table; item 5 hardens admission and eviction at the current eight entries.
- D3 (`fill_random_bytes` panics on RDRAND failure) is an `rt.vdso` patch, not
  a networking one. It lands immediately before patch 17, which is its only
  consumer here.

Decided in review, 2026-07-29: the three design choices are resolved -- item 2
lands as shape A, patch 15 stays in scope, item 3 randomizes external devices
only -- and each of D1-D4 is approved for fixing at its scheduled place. The
sections below record each decision inline.

One roadmap input from that review shapes several choices here: **SYN cookies
are planned after this step.** They slot in after Step 10 item 2, because
cookies without timestamps lose window scaling (classic cookies encode MSS in
the ISN bits; wscale and SACK survive only in the timestamp option). Three
consequences inside Step 6: cookies reconstruct a socket from a stateless
SYN|ACK at ACK time, making them a second writer of `remote_last_win` and a
second computer of the receive-window right edge -- the reason D1's fix both
normalizes the field (patch 1) and clamps acceptance (patch 2); a cookie *is*
an ISN, so patch 18's SipHash and its key handling are direct prerequisites,
not parallel machinery; and patch 9's cap is the engagement trigger a future
cookie mode plugs into ("cap hit -> cookie mode" replaces "cap hit -> drop").

## Newly discovered preexisting defects -- approved 2026-07-29

AGENTS.md requires stopping on each of these before it is fixed. All four were
reviewed and approved on 2026-07-29; the fix shapes decided in that review are
recorded below. Where each one lands in the order: D1 is patch 1, D4 is
patch 3, D2 is folded into patch 5, and D3 is patch 16, an `rt.vdso` patch
immediately before patch 17.

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

Approved; fixed as patch 1, the first patch of Step 6: the field gets one
meaning -- the last window we advertised, in bytes -- so no consumer shifts it.
`dispatch` stores `repr.window_len` for SYN/SYN|ACK and
`repr.window_len << remote_win_shift` otherwise; `:1681` and `:766` use the value
directly. Its fail-first regression lands with it, because a test that aborts
cannot pass its own gate alone. Nothing else in Step 6 precedes it. Patch 2's
acceptance clamp is part of the same decision, not merely defence in depth: the
planned syncookie path will initialize this field and recompute this right edge
in a second place, and a single-unit field plus a ring-bounded acceptance test
are what make that second writer safe to add.

**D2. The virtio RX size adjustor can underflow.** *(Fixed in patch 5, with
one addition: see the result note in Item 2. The recorded consequence below is
understated -- `IoBuf::set_len` asserts against capacity in release too, so the
~4 GiB length aborts sys-io rather than producing a wild slice, and an
over-length used value aborts it the same way. Both are now rejected.)*
`RX_SIZE_ADJUSTOR` is `|val| val - NET_HEADER_LEN as u32` (`V/virtio_net.rs:441`)
and its result is passed straight to `IoBuf::set_len` (`V/virtio_queue.rs:847`).
A device-reported used length below 12 wraps to ~4 GiB. The device is the host,
which Motor must trust for availability, but this is a one-line check on a path
item 2 already edits. Approved; fixed inside patch 5: reject the completion
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
Approved; fixed as its own `rt.vdso` patch immediately before patch 17, since it
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
SACK block (`N/socket/tcp.rs:1498-1503`). Approved; fixed as patch 3, bounded
in the caller, where the receive window is known, rather than in the assembler
(which has no capacity notion, and giving it one is the largest fork divergence
for the same protection). Reachability, stated honestly: the only known network
path to an out-of-window offset runs through D1's inflated right edge, so after
patches 1 and 2 this is invariant enforcement, not a live bug. Kept because Step
12's growable rings and the planned syncookie path both touch the acceptance
arithmetic the invariant silently depends on, and a caller-side `debug_assert`
is what catches the next mistake there.

## Item 1 -- sequence arithmetic, assertions, short RX writes (patches 1-4)

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

**Patch 1 -- D1's fix, proved by a fail-first test (~160 lines).** The fix and
its regression land together: the test aborts the process against the current
source, so it cannot be committed on its own without failing its own gate. It
is verified the way the Step 2 staging fence was -- run it against the unfixed
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

**Patch 1 result, landed 2026-07-29.** The fail-first record matches the
analysis: against the unfixed source both overrun regressions abort in release
on the release-live `assert!(count <= self.window())` at
`N/storage/ring_buffer.rs:345`, in debug on the short-write `debug_assert!` at
`N/socket/tcp.rs:2162`, and the recorded-window regressions show the halved
consumer values directly. The fix stores the field in bytes (now `u32`):
`dispatch` records SYN/SYN|ACK window fields verbatim and every other segment's
shifted up by `remote_win_shift`; the right edge, `last_scaled_window`, and the
ACK-reply site use the value directly.

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

**Patch 2 -- reject instead of assert (~140 lines).** With D1 fixed, the right
edge can no longer exceed the ring, so what remains is defence in depth for
every other epoch mismatch: this patch makes the arithmetic incapable of
aborting rather than merely currently-unreachable. Bound the accepted payload
by `rx_buffer.window()` as well as by `window_end`; normalize `window_end` to
at least `window_start` with a comment naming the epochs; replace the three
subtractions at `:1755-1756` with checked helpers that drop the segment (and
`net_debug!`) instead of panicking; make the short-write case drop the segment
before the assembler records it, so no ACK advances over data we did not store;
turn the two ring-buffer `assert!`s into debug assertions plus caller-side
rejection, keeping the documented panic contract on the public methods.

Its tests: a receive window whose recorded right edge precedes its left edge,
asserting every acceptance branch rejects instead of computing an overlap; and
a short in-order write against a nearly full ring, asserting nothing is
enqueued and no stale bytes are ever readable -- fill the ring with a known
pattern first, so a stale publication shows up as data, not just as a length.
Both construct the state directly, since after patch 1 no packet sequence
produces it.

**Patch 2 result, landed 2026-07-29.** Implemented as planned, with one addition
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
since after patch 1 no packet sequence records one) and requires that exactly
the ring's worth is accepted from a 100-octet segment, that the socket stays
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
assembler hole -- D4's exact shape, which patch 3 bounds at the caller.

**Patch 3 -- bound the assembler offset (~60 lines).** D4's fix in the caller,
with a direct test that a far-offset out-of-order segment is rejected, leaves
the assembler untouched, and does not prevent later in-order recovery (the Step
5 overflow regression already covers the in-capacity case).

**Patch 3 result, landed 2026-07-30.** The numeric bound D4 asked for turned
out to be in place already: patch 2's write-site re-check, `payload_offset +
payload_len <= rx_buffer.window()`, *is* the caller-side bound, because the
assembler's offsets and the ring's unallocated region share an origin.
Confirmed by audit that it cannot be bypassed -- it is TCP's only path into
`Assembler::add`, and neither `payload`, `payload_offset`, nor `rx_buffer`
changes between the acceptance computation at `N/socket/tcp.rs:1797` and that
check. So patch 3 delivered exactly what D4's entry predicted it would be after
patches 1 and 2: invariant enforcement plus its regression, not a live fix.

The bound now names both invariants that rest on it -- the short write, and the
unfillable assembler hole with its permanent phantom SACK block -- and is
preceded by the caller-side `debug_assert!` D4 asked for. A later change to the
acceptance arithmetic, which is what upholds it, now fails loudly in debug
instead of silently dropping every segment in release; Step 12's growable rings
and the planned syncookie path are the changes it is there for. The assembler
itself is untouched, as decided. Its only other caller, IPv4/6LoWPAN fragment
reassembly, bounds its own offset by the reassembly buffer and is outside
Motor's feature closure.

One regression, `test_established_out_of_order_offset_bounded_by_ring`, gives
an established socket a recorded window far past its 64-byte ring --
constructed directly, since after patch 1 no packet sequence records one -- and
requires three things: an out-of-order segment 200 octets ahead is answered
with a challenge ACK and never reaches the assembler; a segment straddling the
ring's end is truncated so the recorded hole plus data ends exactly at the
ring's end; and the hole then fills, delivering the whole ring with the
truncated segment's four accepted octets and none of its discarded tail. The
fail-first record was taken with all three bounds removed -- `window_end`'s
`min(ring_end)` clamp, `receive_overlap`'s ring check, and the write-site
check: debug aborts on the pre-existing short-write `debug_assert!`
(`N/socket/tcp.rs:2241`), and release records D4's exact shape, a 200-octet
hole in a 64-byte ring, which the regression catches on its
`assembler.is_empty()` assertion.

No paired `rnetbench` A/B: `debug_assert!` compiles out in release and the
hoisted `rx_buffer.window()` is the same call the check already made, so the
release data path is unchanged.

**Patch 4 -- sys-io abort-shaped sites (~120 lines).** The audit deferred by
Step 1: `SI/device.rs:41` (`assert!(len <= BIG_BUF_SIZE)`), `:50` (`IoBuf`
allocation unwrap), `:155` (`assert!(result.is_ok())` on every RX completion),
`:591` and `:633` (address/identifier removal asserts), `SI/socket/tcp.rs:949`
(`Err(_err) => todo!()` in the TX loop), and the live-in-release assert whose
`#[cfg(debug_assertions)]` is commented out at
`src/sys/sys-io/src/runtime/net.rs:384-386`. Each becomes a logged error plus a
local recovery path. No behavior change on the success path.

**Patch 4 result, landed 2026-07-30.** All seven sites, each with the recovery
its own path allows and none with a behavior change on success:

- `BufCache::pop_buf` returns `Option<IoBuf>`; the oversize `assert!` and the
  allocation `unwrap()` are both a `None` for the caller to handle.
- The RX task no longer asserts its completion succeeded. A failed completion
  carries no data and its buffer still holds the length we posted it with, so
  that buffer is re-posted directly. An allocation failure after a *good*
  completion costs one in-flight buffer and logs; the queue keeps working. Only
  if every buffer is lost does the task log that RX is dead and return -- a
  logged-dead receive path on one device, rather than an abort that takes every
  other device and socket with it.
- `VirtioTxToken::consume` must hand the netstack its slice whatever happens, so
  with no pooled buffer it fills a plain heap scratch and drops it: the packet is
  lost, which TCP recovers from and UDP already permits. The pooled buffers are
  DMA-capable and page-aligned, a scarcer resource than that allocation.
- The UDP-address and ICMP-identifier removal asserts log an error instead.
- The TCP TX `todo!()` reports the error, drops that socket's queued bytes, and
  ends the TX task through the same path a normal TX close takes. It stays
  unreachable: the enclosing `can_send()` implies `may_send()`, the only state
  `send_slice` rejects. Returning the buffer and retrying was rejected -- the
  outer loop re-runs immediately on a non-empty queue, so it would busy-spin.
- The disconnect-path assert becomes a logged error per missing socket id. The
  loop it precedes already tolerates absence.

Audited on the same pass and deliberately left: `tx_task`'s
`completions.pop_front().unwrap()` is guarded by its own loop condition --
reaching it needs `txq_descs < MAX_TX_DESCS`, i.e. a TX virtqueue smaller than
one maximal packet's descriptor chain, which would break `post_write` outright.

No new tests: every recovery path here is unreachable through the public
protocol, so the existing full-OS suites are the coverage, as this section
planned. Gates: `cargo +nightly fmt`, Motor-target debug and release images,
and `make clippy` in both profiles with the warning counts unchanged from
before the patch (107 debug, 104 release, none in the changed files). Three
consecutive debug and three consecutive release `full-test-networking.sh` runs
passed with no retries and no tolerated failures. No paired `rnetbench` A/B: the
success path is instruction-for-instruction what it was.

### Tests and gate

Direct `process()` tests run in the netstack closure that
`full-test-networking.sh` already builds (its `NETSTACK_FEATURES` line). Patch
4 is covered by the existing full-OS suites. Per patch: `cargo +nightly fmt`,
the Motor debug and release builds, debug and release clippy, the netstack
feature closure plus the broad default closure, and three debug plus three
release `full-test-networking.sh` runs. Patches 1 and 2 touch the per-segment
receive path, so both also need the paired same-host release `rnetbench` A/B
(default and 64 KiB).

## Item 2 -- per-packet virtio RX checksum metadata (patches 5-7)

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
implement it. Patch 5 would have been needed by either shape:

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

**Patch 5 -- surface the header (~90 lines).** Read `NetHeader.flags`,
`gso_type`, and `num_buffers` when the RX completion resolves, before the
descriptor chain is released, and return them alongside the buffer. Define
`DATA_VALID`. Reject and count frames that are impossible for our negotiated
feature set: a nonzero `gso_type` without `GUEST_TSO`, or `num_buffers > 1`
without `MRG_RXBUF`. Includes D2's length check (approved above).

**Patch 6 -- per-packet policy (~110 lines).** Shape A above, plus sys-io's RX
queue carrying the per-packet verdict to `VirtioRxToken`, plus a new
`net.rx.csum_failed` counter (`SI/stats.rs`) for frames dropped by
verification. Metric id 21: patch 5 took the next free id, 20, for
`net.device.rx_dropped`. Landed; see the result note below, including where the
implementation departed from this sketch.

**Patch 7 -- coverage (~120 lines).** Netstack tests driving `Interface::poll`
with each verdict: an unflagged frame with a corrupt TCP checksum is dropped
and delivers nothing; the same frame flagged `DATA_VALID` is delivered; a
`NEEDS_CSUM` frame whose checksum field holds only a pseudo-header sum is
delivered; the same three for UDP. The full-OS half of this -- ordinary traffic
still flows and `net.rx.csum_failed` stays at zero -- landed with patch 6,
which is the patch whose risk it covers. Patch 7 is now the deterministic
per-verdict half, and patch 6's measurement makes it mandatory rather than
belt-and-braces: on this rig nothing the device delivers is unvouched, so the
full-OS suite exercises the verification path zero times.

### Tests and gate

Standard per-patch gate. Patch 6 changes per-frame receive work, so paired
release `rnetbench` A/B is required; record whether the local rig's frames
arrive vouched (expected: host-originated traffic yes, so the steady-state cost
should be a flag test per frame). Item 2 is the gate on Step 8: do not expand
the receive-offload feature set until patches 5-7 have landed.

### Patch 5 result, 2026-07-30

The RX header now reaches the driver. `post_read` returns a `NetReadCompletion`
that reads the chain head's header buffer while the completion still owns the
chain -- `VqCompletion::read_header` copies it before `Drop` releases the
descriptors -- and resolves to `(IoBuf, Result<RxMeta>)`. `RxMeta` carries the
one verdict decided above, `l4_csum_vouched` (`NEEDS_CSUM` or `DATA_VALID`;
`DATA_VALID` is now defined). sys-io drops the verdict for now: carrying it to
`VirtioRxToken` is patch 6's scope, and `capabilities()` is unchanged, so this
patch changes no packet-acceptance behavior.

Everything a completion cannot legitimately be is rejected, counted in the new
`net.device.rx_dropped` (metric id 20), and its buffer re-posted:

- a used length below `NET_HEADER_LEN` (D2, approved above);
- **added to D2's scope**: a used length whose payload exceeds the buffer we
  posted. `IoBuf::set_len` asserts `len <= capacity` in release as well as
  debug, so the over-length case aborts sys-io exactly like the underflow, and
  fixing one without the other would have left half the defect;
- a nonzero `gso_type` while no `GUEST_TSO4/6`, `GUEST_ECN`, or `GUEST_UFO` is
  negotiated (their bits now have constants, which coalescing Step 1 needs
  anyway when it relaxes this check);
- `num_buffers > 1` while `MRG_RXBUF` is not negotiated.

Nothing here is reachable from the network, so by the same provision patch 4
used, no packet-level test was added; the coverage is the full-OS suites plus
one new full-OS assertion, `test_device_rx_validation`, which requires that the
device delivered frames this boot and that the driver rejected none of them.
That is the check that matters for this patch: its risk is rejecting frames the
host legitimately sends, and systest arrives over ssh, so hundreds of ordinary
frames have crossed the new validation before it runs.

Evidence, taken on a debug run with temporary instrumentation that was removed
before the gate:

- The header read returns live device-written values, not the zeros `post_read`
  wrote: the first twenty frames arrive with lengths 42-1514, `gso_type 0` and
  `num_buffers 0` throughout, and `flags` 0x0 for the first two (ARP-shaped,
  no L4 checksum to vouch for) then 0x1 (`NEEDS_CSUM`) for every host-originated
  TCP frame after. This is patch 6's input datum: **on this rig ordinary traffic
  does arrive vouched, but not all of it does**, so the per-packet policy is
  not a no-op.
- Fail-first for the reject path: rejecting every 64th completion makes the
  suite fail at `test_device_rx_validation` ("the virtio driver rejected receive
  completions (502 frames delivered)"), and the VM survives boot, ssh, DNS,
  ping, and the whole non-network half of systest while dropping 1 frame in 64 --
  i.e. the rejection recovers locally by re-posting the buffer, as intended,
  rather than stalling the receive queue.

No paired `rnetbench` A/B: the sequencing table assigns item 2's measurement to
patch 6, which is where the per-frame policy lands and where the pair is
measured against a clean baseline. What patch 5 adds per received frame is one
12-byte volatile copy, two comparisons, and a `RefCell` borrow, replacing a
function pointer call.

Gate: the exact source state passed `cargo +nightly fmt`, Motor-target debug
and release image builds, and debug and release clippy with only the
repository's pre-existing warnings and none in the changed code. Both netstack
closures pass with warnings denied -- the Motor closure's 531 unit tests plus 7
doctests inside each harness run, and the broad default closure's 670 plus 7
separately. Three consecutive debug and three consecutive release
`full-test-networking.sh` runs then passed with no retries and no tolerated
failures; `test_device_rx_validation`, systest's `PASS` marker, and the tokio
suite are present in all six.

### Patch 6 result, 2026-07-30

The trust gap is closed. sys-io now advertises receive verification as *on* for
every frame -- `caps.checksum.tcp` is `Rx` with `VIRTIO_NET_F_CSUM` and `Both`
without it, and `caps.checksum.udp` is `Both` unconditionally -- and the
GUEST_CSUM saving is taken per frame instead: patch 5's `RxMeta` rides sys-io's
RX queue to `VirtioRxToken::meta()`, becomes `PacketMeta::l4_csum_vouched`, and
`ChecksumCapabilities::rx_vouched()` drops software receive verification for
that one frame at the two ingress parse sites. Only the receive half is
dropped, so a reply built from the result still computes its own checksums.

Implementation decisions, for review:

- **The verdict is a parameter, not interface state.** The plan sketched
  storing it on `InterfaceInner` for the duration of a frame. `process_udp`
  already took `PacketMeta`, so `process_tcp` takes it too and both call sites
  (`ipv4.rs`, `ipv6.rs`) already had it in scope. Threading cannot go stale; a
  stored field can, and `InterfaceInner` is handed to sockets through
  `context()`.
- **The driver gates the vouch on `VIRTIO_NET_F_GUEST_CSUM`.** Without that
  feature the device owes us fully checksummed frames, so honoring a flag it
  should not have set would verify strictly *less* than the driver did before
  the flag was ever read. Rejecting such a frame outright, the way patch 5
  rejects other feature-impossible headers, was considered and dropped:
  `DATA_VALID` is legitimate without GUEST_CSUM, and rejecting it would kill
  all traffic from an honest device. `NetDevice::guest_csum()` is deleted --
  the negotiated feature now decides only this verdict, inside the driver.
- **A reassembled IPv4 datagram drops the vouch.** It is not one frame, so no
  single frame's header vouches for its L4 checksum. Outside Motor's feature
  closure, but the fork has to be right.
- **DHCP's early UDP parse uses the same effective capabilities** as
  `process_udp`, so the two do not disagree about one datagram. Also outside
  Motor's closure.
- **`net.rx.csum_failed` (metric id 21) is attributed on the failure path.**
  The success path is byte-for-byte what it was; a parse that fails re-runs
  `verify_checksum` to decide whether the checksum was the reason, so a
  malformed segment is not miscounted as a corrupted one. sys-io drains the
  interface's count once per `poll()`, not per frame, and logs the batch.

Measurement of what the local rig actually delivers, taken with temporary
counters removed before the gate:

- Across a whole debug `full-test-networking.sh` run -- boot, ssh, DNS, ping,
  the whole of systest -- 556 frames were delivered and **software verification
  ran exactly zero times**: every TCP segment and UDP datagram arriving on the
  virtio interface was vouched for, and logical loopback keeps
  `ChecksumCapabilities::ignored()` so its traffic is exempt either way. The
  full-OS assertion added here is therefore a *no-regression* check on the
  vouch, not coverage of verification. Per-verdict coverage is patch 7's job,
  and this measurement is the reason it cannot be skipped.
- Fail-first, by sabotage: dropping the vouch on every 64th completion in the
  driver produced 7 verifications and 7 failures at 496 delivered frames, and
  `test_device_rx_validation` failed on the new counter ("the netstack dropped
  frames on checksum verification"). The VM kept running throughout -- TCP
  retransmitted the dropped segments -- which is the local recovery a dropped
  frame is supposed to have. That the failures equal the verifications is the
  point: ordinary host-originated frames really do carry only a pseudo-header
  sum, so honoring the vouch is load-bearing, and the verdict demonstrably
  reaches the parse site through the whole driver -> `PacketMeta` -> ingress
  chain.

Paired same-host release `rnetbench`, A/B/A blocks of five rounds with one
unchanged host client (medians; A = clean HEAD, B = prepared):

| Workload | Block | RR (usec) | Motor RX (MiB/s) | Motor TX (MiB/s) |
|---|---|---:|---:|---:|
| default | A1 (rounds 3-5) | 55.67 | 138.16 | 297.45 |
| default | B | 58.08 | 140.64 | 297.07 |
| default | A2 | 56.78 | 138.33 | 299.81 |
| 64 KiB | A1 (rounds 3-5) | 56.29 | 623.08 | 1203.93 |
| 64 KiB | B | 57.83 | 626.82 | 1199.30 |
| 64 KiB | A2 | 57.36 | 631.05 | 1205.97 |

Against the bracketing A2 block the prepared tree is RR +1.30 usec / RX +1.67%
/ TX -0.91% on the default workload and RR +0.47 usec / RX -0.67% / TX -0.55%
on bulk -- mixed sign, well inside the kill criteria (5% throughput, ~5 usec
RR). The A1 block's first two rounds landed in this host's known "fresh"
regime (~164 RX / ~330 TX default) before settling into the benched one
(~138 / ~298), which is why only its settled rounds are compared and why the
design is A/B/A; all samples are retained above. The result is what the
measurement above predicts: when every frame is vouched, the added per-frame
work is one bool test.

Gate: the exact source state passed `cargo +nightly fmt`, Motor-target debug
and release image builds, and debug and release clippy with only the
repository's pre-existing warnings and none in the changed code. Both netstack
closures pass with warnings denied -- the Motor closure's 531 unit tests plus 7
doctests, the broad default closure's 670 plus 7. Three consecutive debug and
three consecutive release `full-test-networking.sh` runs then passed with no
retries and no tolerated failures; `test_device_rx_validation` with its new
checksum assertion, systest's `PASS` marker, and the tokio suite are present in
all six.

### Patch 7 result, 2026-07-30

Item 2 is complete. The verifying path now has deterministic per-verdict
coverage, which patch 6's measurement made mandatory: on this rig the full-OS
suite exercises it zero times.

The netstack's `TestingDevice` carries a `PacketMeta` per queued frame, so its
`RxToken::meta()` returns a real verdict instead of the trait default; `push_rx`
queues an ordinary unvouched frame and `push_rx_vouched` states the verdict.
Two regressions in `N/iface/interface/tests/ipv4.rs` then drive `Interface::poll`
with each combination of verdict and checksum-field content -- one TCP, one UDP,
five cases each:

| Checksum field | Vouched | Expected |
|---|---|---|
| corrupt | no | dropped, `rx_csum_failed` +1, no reply |
| correct | no | delivered |
| corrupt | yes | delivered |
| pseudo-header sum only | yes | delivered |
| pseudo-header sum only | no | dropped, `rx_csum_failed` +1, no reply |

Notes on the shape:

- `NEEDS_CSUM` and `DATA_VALID` are one bool by the time a frame reaches the
  netstack -- the driver decides, as patch 6's `validate` shows -- so the two
  vouched cases differ in what the checksum field *holds*: a corrupted value,
  and a real pseudo-header sum (`!pseudo_header_v4(...)`, which is what a
  host's CHECKSUM_PARTIAL egress path leaves there). Both must be delivered
  unexamined.
- Two cases beyond the three this section planned. The correct-and-unvouched
  case makes the first drop attributable to the checksum and nothing else; the
  pseudo-header-and-unvouched case pins the converse of the vouch -- a partial
  sum is just a wrong checksum to a stack nobody vouched to.
- The signal is end-to-end, not a parse return value: the TCP frame is a SYN to
  a listening socket, so delivery is `Listen -> SynReceived` plus one emitted
  SYN|ACK, and a drop is the socket still in `Listen` with *no* reply at all --
  not even the RST an unmatched segment draws. The UDP frame's signal is the
  payload arriving in the bound socket's receive buffer.

Fail-first, by sabotage in both directions at `ChecksumCapabilities::rx_vouched`:

- Ignoring the verdict (`if false && vouched`), i.e. verifying every frame: both
  tests fail at the vouched-corrupt case (`(Listen, 1, 0)` instead of
  `(SynReceived, 0, 1)`; `(None, 1)` instead of the delivered payload). This is
  what would break if the verdict stopped reaching the parse sites.
- Waiving it always (`if true || vouched`), which is the pre-patch-6 behavior:
  both tests fail at the *first* case, accepting a corrupt segment. That is the
  trust gap patch 6 closed, and it is now caught by a test rather than by
  argument.

No production code changed: `N/tests.rs` is `#[cfg(test)]` and the regressions
are test-only, so the Motor images are unaffected and no paired `rnetbench` A/B
is required.

The first gate attempt stopped on a pre-existing defect outside this repository
and its runs were discarded: mlibc links and unlinks every FILE in one global
`frg::intrusive_list` without a lock, `getaddrinfo` opens `/etc/hosts` on every
lookup, and `dns-resolver` calls it from four worker threads, so two concurrent
lookups corrupt the list and frigg's assertion aborts the process through a bare
`ud2`. The full account -- five reproductions, the faulting-instruction evidence,
the fix, and its 250-cycle verification -- is in the Step 6 ledger entry of
`networking-step-by-step.md`. The gate recorded below is the rerun on the fixed
toolchain.

Gate: the exact source state passed `cargo +nightly fmt`, Motor-target debug and
release image builds, and debug and release clippy with the repository's
pre-existing warning counts unchanged (107 and 104, none in the changed files).
Both netstack closures pass with warnings denied -- the Motor closure's 533 unit
tests plus 7 doctests, the broad default closure's 672 plus 7. Three consecutive
debug and three consecutive release `full-test-networking.sh` runs then passed
with no retries and no tolerated failures. Both new regressions, all 533
production netstack tests, `test_device_rx_validation`, both DNS resolver
self-tests across the restart, systest's `PASS` marker, the tokio suite, and the
final full-suite marker are present in all six, and the negative DNS query
returned `NotFound` directly in all six.

## Item 6 -- half-open and backlog bounds, buffers deferred (patches 8-10)

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
  API in the fork -- exactly the surface `tcp-receive-window.md` Step 2 and
  Step 12 must define for per-socket sizing. Recorded in both plans; this
  narrows Step 6 item 6 rather than dropping work.
- **Overload behavior stays RST for now.** With a cap, excess SYNs match no
  socket and the netstack RSTs them. Dropping is better under flood but must
  not change the nothing-is-listening case, which existing tests and
  applications depend on, so patch 8 counts the unmatched RSTs and the choice
  is revisited with Step 8's batching evidence.

### Patches

**Patch 8 -- observe (~90 lines).** `net.tcp.half_open` (gauge) and
`net.tcp.syn_rst_unmatched` (counter) in `SI/stats.rs`, plus a full-OS test that
half-open count rises and falls across a deliberately stalled handshake.
Measurement first, so the cap in patch 9 is chosen against data. *(Landed with a
third metric and split coverage: the stalled handshake is not constructible in
the full-OS gate. See the result note below.)*

**Patch 9 -- cap half-open sockets (~140 lines).** A per-listener and a global
cap; at the cap, replenishment is deferred rather than spawned, and resumes
when a half-open socket completes or times out. No change to the accept path.
Test: a raw-channel regression that opens more simultaneous half-open
connections than the cap, proves the gauge plateaus at the cap, and proves a
legitimate connect succeeds once earlier half-opens complete. *(That regression
is not constructible either, for patch 8's reason: nothing in the gate can hold
a handshake half-open. By user direction the cap is instead covered by sys-io's
own `#[cfg(debug_assertions)]` self-tests, added between patches 8 and 9 and
triggered from systest -- see the step-by-step plan. The full-OS side keeps
proving that ordinary traffic is unaffected.)*

**Patch 10 -- backlog independent of the pool (~140 lines).** Decouple the
accept backlog from the pre-created socket count so the pool size stops being
the per-batch backlog. Exact mechanism to be settled inside patch 9's
measurements; if it cannot be done without the buffer work, it joins Step 12
with the same recommendation as above, recorded explicitly rather than dropped.

### Tests and gate

Standard per-patch gate. Patches 9 and 10 change the listen path, so paired
release `rnetbench` A/B plus a full-OS accept-rate check. Item 6 gates
`tcp-receive-window.md` Step 1 and Step 9: no default buffer raise before the
half-open count is bounded.

### Patch 8 result, 2026-07-31

Item 6 starts with the measurement its cap is to be chosen against. Three
metrics, not the two this section named:

- `net.tcp.half_open` (gauge) -- listening sockets that have taken a peer's SYN
  and are waiting for the handshake to finish. sys-io keeps it in the listen
  task, where that wait already lives: `tcp_listen_task`'s first wait ends when
  the socket leaves `Listen`, its second ends when the socket leaves
  `SynReceived`, and a `HalfOpenGuard` spans exactly the second one. A guard
  rather than a pair of updates because every exit must decrement, including the
  socket disappearing under the task.
- `net.tcp.half_open_total` (counter) -- entries into that state. Added to the
  plan; the deviation below is why.
- `net.tcp.syn_rst_unmatched` (counter) -- bare SYNs the netstack reset because
  no socket accepted them. Counted in the netstack at the reset site
  (`N/iface/interface/tcp.rs`) and drained per poll into sys-io's stats, the same
  shape as `rx_csum_failed`.

**Deviation, approved before implementation: the full-OS test this section
specified -- half-open rising and falling across a deliberately stalled
handshake -- is not constructible.** Holding a listening socket in SYN-RECEIVED
needs a peer that sends a SYN and withholds the ACK. Inside the guest there is no
packet injection: raw sockets are outside the Motor feature closure. On the host
it needs `CAP_NET_RAW`, and the gate runs unprivileged (`create-tap.sh` is a
one-time setup step, not part of a run). Every peer that answers completes the
handshake in the poll after the one that took its SYN -- `Interface::poll` drains
all ingress before any egress (`N/iface/interface/mod.rs:495-525`) and sys-io
yields to the executor on `SocketStateChanged`
(`src/sys/sys-io/src/runtime/net.rs:188-192`) -- so the state is genuinely
observable, but for a fraction of a round trip, while reading a metric is a
cross-thread round trip into the net runtime. Sampling it would need a
retry-until-nonzero loop, which is exactly the tolerated-flake pattern AGENTS.md
forbids. So the coverage splits, and the cumulative counter is what carries the
full-OS half:

- `test_half_open_accounting` (systest) proves the accounting over ordinary
  loopback handshakes: eight connect/accept pairs raise `half_open_total` by
  exactly eight and leave the gauge at its baseline. Exactly eight is
  deterministic rather than approximate -- `set_state` wakes the listen task, so
  it is queued ahead of the device task that then yields, and it always observes
  `SynReceived`. The test then connects to a closed port and requires
  `syn_rst_unmatched` to rise by exactly one.
- `tcp_half_open_stalls_and_unmatched_syn_is_reset` (netstack) is the stalled
  handshake, at the only layer that can construct one: a SYN arrives, the socket
  reaches `SynReceived`, and it is still there ten seconds later with its SYN|ACK
  being retransmitted. The same test pins the counter's scope -- a SYN for a port
  no socket holds counts one; an unmatched segment carrying an ACK is reset the
  same way and counts none.

Fail-first, by sabotage, before the gate:

- Guard never created: `half_open_total` moves 0 where the systest requires 8.
- Guard leaked (`mem::forget` instead of `drop`): the gauge ends 8 above its
  baseline (58 against 50) and the systest fails on the fall.
- Netstack increment removed: the unmatched-SYN case fails 0 against 1.
- Netstack increment taken for every unmatched reset: the unmatched-ACK case
  fails 1 against 0.

Live evidence, read through the ordinary stats path: `half_open_total` is 2 on a
freshly booted VM whose only traffic is two inbound ssh connections, and 107
after a full systest run, with the gauge at 0 both times. Inbound connections
over the virtio device pass through an observable half-open state, and so do
loopback ones.

No data-path change, which is why this patch is not on the `rnetbench` list: the
netstack increment sits on the unmatched-reset path, sys-io's drain is one
`mem::take` per poll beside the existing checksum drain, and the guard is one per
accepted connection in the listen task. Nothing on the success path of TCP RX or
TX is touched, so no paired A/B was run.

Gate: the exact source state passed `cargo +nightly fmt`, Motor-target debug and
release image builds, and debug and release `make clippy` whose output is
byte-identical to the same runs on clean `HEAD` -- 98 debug and 95 release
warning lines, none of them in the changed files. Both netstack closures pass
with warnings denied: the Motor closure's 534 unit tests plus 7 doctests, the
broad default closure's 673 plus 7. Three consecutive debug and three consecutive
release `full-test-networking.sh` runs then passed with no retries and no
tolerated failures. `test_half_open_accounting`,
`tcp_half_open_stalls_and_unmatched_syn_is_reset` inside the 534,
`test_device_rx_validation`, both DNS resolver self-tests across the restart,
systest's `PASS` marker, the tokio suite, and the final full-suite marker are
present in all six, and the negative DNS query returned `NotFound` directly in
all six.

### Patch 9 result, 2026-07-31

`MAX_HALF_OPEN_GLOBAL = 128` and `MAX_HALF_OPEN_PER_LISTENER = 32` -- 32 MiB and
8 MiB at 256 KiB a socket, with the per-listener cap matching
`MAX_NUM_LISTENING_SOCKETS` so a listener cannot hold more sockets half-open
than it may keep listening. Chosen by user decision, not by measurement: the
distribution patch 8 was to supply is exactly the one it recorded as not
constructible in the gate. The sizing that argued for it is legitimate
concurrent half-opens ~ `connect_rate x RTT`, so 128 absorbs ~1.3k conn/s at a
100 ms RTT and ~128k conn/s on a 1 ms LAN before it starts deferring.

**What the cap actually bounds.** Not the SYN: by the time sys-io observes
`SynReceived` the netstack has taken the segment. `HalfOpenBudget::admit` counts
every half-open socket, including the ones it refuses, and refusing means the
listening pool is not refilled. The pool then drains, further SYNs match no
socket, and the netstack resets them -- the pre-existing nothing-is-listening
answer. So the bound is the cap plus whatever was still listening when it was
reached, and the section heading's "bounds the SYN-flood memory" holds with that
qualifier. `HalfOpenGuard::drop` returns the slot and hands back one parked
replenishment, oldest first, skipping any listener still at its own cap so a
busy listener cannot hold the queue closed against the others.

Coverage, per the deviation approved above: six self-tests over
`HalfOpenBudget`, which is generic over what a deferred replenishment carries
precisely so the accounting is testable without an executor -- admits-to-cap,
defers-beyond, FIFO resume, per-listener isolation, skip-a-capped-listener, and
that a drained listener leaves no map entry behind (ids only advance, so a
retained entry would leak for the process's life) and that an extra release
cannot underflow the count into wedging the cap shut.

**The full-OS gate cannot reach the cap, so the production defer/resume path was
proved by forcing it.** With `MAX_HALF_OPEN_GLOBAL` temporarily set to 1, every
inbound connection defers and resumes: the VM booted, served ssh, ran the DNS
resolver restart sequence, and systest reached `PASS` across all TCP and UDP
tests after 27 deferrals. That run was not counted as a gate run -- at cap 1 the
accept path serialises hard and the later mio/tokio suites had not finished at a
ten-minute limit, and the self-tests were skipped for it because they assert
against the real constants. The shipped constants were restored and gated
normally, where the deferral never fires and ordinary traffic is unaffected.

Fail-first, by sabotage, each caught by exactly one self-test and none of them
reachable by the full-OS gate:

- `admit` always reports room (the cap silently stops capping):
  `defers_beyond_the_global_cap` fails 136 against 127. Every full-OS test still
  passes -- this is the case the seam exists for.
- Newest-first resume: `resumes_deferred_in_fifo_order` fails `Some(12)` against
  `Some(10)`.
- Resume ignores the per-listener cap: `skips_a_listener_still_at_its_cap` fails
  `Some(10)` against `Some(20)`.
- Drained listener's map entry retained: `forgets_a_drained_listener` fails on
  `is_empty()`.

Paired same-host release `rnetbench`, A/B/A blocks of five rounds with one
unchanged host client (medians; A = clean HEAD, B = prepared):

| Workload | Block | RR (usec) | Motor RX (MiB/s) | Motor TX (MiB/s) |
|---|---|---:|---:|---:|
| default | A1 | 52.30 | 164.94 | 324.40 |
| default | B | 52.81 | 162.64 | 318.48 |
| default | A2 | 56.45 | 161.42 | 314.47 |
| 64 KiB | A1 | 53.78 | 643.59 | 1234.03 |
| 64 KiB | B | 54.46 | 635.38 | 1208.58 |
| 64 KiB | A2 | 54.68 | 643.95 | 1246.51 |

Against A2 the prepared tree is RR -3.63 usec / RX +0.76% / TX +1.28% on the
default workload and RR -0.22 usec / RX -1.33% / TX -3.04% on bulk; against A1
it is RR +0.52 / RX -1.39% / TX -1.82% and RR +0.68 / RX -1.28% / TX -2.06%.
Mixed sign against the two bracketing blocks, largest excursion 3.04%, well
inside the kill criteria (5% throughput, ~5 usec RR). The A blocks differ from
each other by ~3% on default TX, which is this host's known drift and the reason
the protocol brackets.

The full-OS accept-rate check this section asks for alongside the A/B: 300
sequential connect-and-close cycles against a guest listener, three rounds per
block, every one of them walking the path the patch changed. Medians 5445/s
(A1), 6299/s (B), 6363/s (A2) -- B is within 1% of its bracketing block and
above the other, with zero connection failures in any block.

Gate: `cargo +nightly fmt`; Motor-target debug and release builds; debug and
release sys-io clippy byte-identical to clean `HEAD`; three debug and three
release `full-test.sh` runs, all six reaching the final marker with no retries
and no tolerated failures. All six report the netstack closure's 534 tests, the
debug three report 16 self-tests and the release three report none, and the
deferral log line appears zero times in all six -- the cap is never approached
by ordinary traffic.

## Item 5 -- ARP cache admission, eviction, request rate (patches 11-13)

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

**Patch 11 -- admission (~110 lines).** An ARP request may refresh an existing
entry but may not evict one to create a new entry; replies to our own requests,
and requests when a slot is free, still fill. This is `arp_accept = 0` behavior
and removes the eviction primitive outright. Netstack tests: a request from an
unknown same-subnet address with a full cache leaves every entry intact; the
same request with a free slot fills it; a request from a known address
refreshes its expiry.

**Patch 12 -- gateway protection (~90 lines).** Never evict an entry that a
configured route's gateway resolves to. Test: a flood of distinct same-subnet
sources cannot displace the gateway entry, and egress through the gateway keeps
working across the flood.

**Patch 13 -- per-destination request rate (~120 lines).** Replace the global
`silent_until` with a per-destination silent time so one unresolvable address
cannot starve another, keeping sys-io's 5 ms value and re-recording its
motivation. Test: two destinations, one black-holed, and the other still
resolves within one silent interval.

Explicitly out of scope, with rationale: rate-limiting ARP *replies*. Replying
to a request aimed at us is required behavior and is 1:1, not amplifying.

Cache capacity (`iface-neighbor-cache-count-N`) stays in Step 10 item 4,
decided: it is a build-feature change with a linear-scan cost that belongs with
the route table it is measured against, and patch 11 removes the eviction
primitive outright, so the eight-entry limit stops being an attack surface and
becomes only a performance question. Patch 11 is nonetheless strictly more
effective with more slots, so Step 10 item 4 must not be deferred indefinitely.

### Tests and gate

Netstack tests plus a full-OS check that ordinary external traffic is unaffected.
Standard per-patch gate; no data-path cost expected, but patch 13 touches egress
dispatch, so include the paired release `rnetbench` A/B.

## Item 4 -- RFC 5961 RST handling and PAWS policy (patches 14-15)

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

Patch 15 reviewed and kept (2026-07-29). A blind in-window SYN is already
dropped rather than acted on, so section 4 adds no attack-surface defence --
what the silent drop gets wrong is liveness. A rebooted peer reusing the same
4-tuple sends a fresh SYN; dropping it silently strands that peer, because our
stale socket lingers until keepalive fires, and `keep_alive` is off by default,
so possibly forever. The challenge ACK is the recovery mechanism: the rebooted
peer answers it with a correctly-sequenced RST, the stale socket closes
legitimately, and the peer's SYN retry succeeds. This is also RFC 9293 3.10.7.4
conformance -- the same clause the fork already implements for duplicate ACKs
in LastAck (`:1990`).

### Patches

**Patch 14 -- RFC 5961 section 3 (~130 lines).** An RST is accepted only at
exactly `RCV.NXT`; an in-window RST elsewhere produces a rate-limited challenge
ACK; an out-of-window RST is dropped silently rather than answered. Preserve
the two SYN-SENT special cases (`:1582-1591`) and the SYN-RECEIVED-to-LISTEN
return (`:1827-1832`), which sys-io's listen task depends on
(`SI/socket/tcp.rs:474-480`). Netstack tests: an in-window RST off by one
leaves the connection established and emits at most one challenge ACK per
second; an exact-`RCV.NXT` RST still closes; an out-of-window RST is silent;
the SYN-RECEIVED case is unchanged.

**Patch 15 -- RFC 5961 section 4 (~70 lines).** A SYN in a synchronized state
gets a rate-limited challenge ACK instead of a silent drop: one match arm ahead
of the `_ =>` catch-all (`:1995-1998`), reusing `challenge_ack_reply`. Netstack
tests: a SYN in Established elicits at most one challenge ACK per second and
changes no state; the full rebooted-peer sequence (SYN, challenge ACK,
correctly sequenced RST, reconnect on the same tuple) recovers.

Step 5 deliberately did not lock in current RST behavior, so no existing
netstack test needs to change; patch 14 must confirm that while it lands.

### Tests and gate

Standard per-patch gate. Protocol behavior change, so also: the full-OS suites
must show unchanged connect-refused, close, and abort behavior, and the paired
release `rnetbench` A/B.

## Item 3 -- ISN and ephemeral-port generation (patches 16-19)

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
the decision: patch 19 also enforces the premise that loopback has no off-path
attacker by dropping 127/8 addresses arriving on external ingress, and once
Step 12 lands, the regression can pin its source port explicitly, at which
point unifying on randomization everywhere becomes a small revisit rather than
a lost test.

### Patches

**Patch 16 -- D3's fix in `rt.vdso` (~40 lines).** As decided under D3: check
the carry flag, accept a zero drawn with CF=1, retry up to ten times, panic
clearly on ten consecutive failures; no entropy fallback. The success path is
exercised constantly by every process (hasher seeds); the failure path is not
testable without a seam over the intrinsic, which a loop this small does not
justify -- it is reviewed as written. Separate patch, separate subsystem,
immediately before patch 17.

**Patch 17 -- seed from hardware entropy (~50 lines).** Replace the wall-clock
seed with one `moto_rt::fill_random_bytes` call per device at initialization.
One RDRAND per device at boot; no per-packet or per-connection cost. Unit test
that two interfaces constructed in the same process do not share a seed.

**Patch 18 -- RFC 6528 ISNs (~180 lines, may split).** `ISN = M + F(4-tuple,
key)` with `M` a coarse monotonic timer and `F` a keyed PRF. Implement
SipHash-2-4 in the netstack with the reference test vectors so the primitive
itself is verifiable, key it from the interface's entropy, and keep the
`cfg(test)` determinism. Netstack tests: identical tuples with different keys
differ; different tuples with one key differ; a reconnect on the same tuple
advances monotonically; the published SipHash vectors pass.

**Patch 19 -- randomized ephemeral ports (~150 lines).** RFC 6056: a random
starting offset in the ephemeral range, then upward scan for a free port,
preserving the existing in-use and reserved-port checks
(`SI/device.rs:595-613`, including the listener-reservation predicate added in
Step 1). Applied per the loopback decision above, whose premise this patch also
enforces: 127/8 source or destination addresses arriving on external-device
ingress are dropped at the IPv4 ingress validation site and counted the way
patch 6 counts checksum drops. Tests: allocations do not form a monotone run on
an external device; the loopback device still returns lowest-free; a
127/8-source frame on the external device is dropped and counted; the
listener-conflict regression and `test_simultaneous_open` are unchanged.

### Tests and gate

Standard per-patch gate. Patch 18 touches connection setup, so include the
paired release `rnetbench` A/B (the request-response workload opens and closes
connections, so a per-connection hash shows up there if anywhere).

## What Step 6 deliberately does not do

- No congestion control, RTO floor, assembler capacity, or neighbor/route
  capacity change: Step 10, measured separately. Timestamps and PAWS join that
  step by the sequencing above.
- No receive-offload expansion, poll-batching change, or coalescing: Step 8,
  and gated on item 2. `virtio-rx-coalescing.md` Step 1 records the dependency
  and that it relaxes patch 5's `gso_type` check when it acks guest TSO.
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

Patches needing the paired `rnetbench` A/B, from the sections above: 1, 2, 6, 9,
10, 13, 14, and 18.

Each patch updates this document's Sequencing table with its result and the Step
6 status in `networking-step-by-step.md` as it lands, and corrects
`core-networking-rewrite.md` where it changes one of that document's facts.
