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
resequenced; if one is, renumber the table rather than inserting a fraction. A
patch that *splits* is the one exception: it keeps its number and its parts take
suffixes, as patch 10 did, so nothing after it moves.

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
| 10 | 6 | The pool grows into bursts | Four pre-created sockets are the whole backlog; a burst of sixteen loses half | **Landed 2026-07-31** as `24ae9cfd` (`glow listening pool under pressure`); result note in Item 6 |
| 10.1 | 6 | The growth is returned | Without it one burst pins the memory for the listener's life | **Landed 2026-07-31**; result note in Item 6 |
| 10.2 | 6 | Drop rather than reset | Completes item 6, which unblocks Step 9 and `tcp-receive-window.md` Step 1 | **Landed 2026-08-01**; result note in Item 6 |
| 11 | 5 | Neighbor admission | Removes the forgeable eviction primitive | **Landed 2026-08-01**; result note in Item 5 |
| 12 | 5 | Gateway protection | Protects the entry whose loss stalls all egress | **Landed 2026-08-01**; result note in Item 5 |
| 13 | 5 | Per-destination request rate | Stops one black hole from starving resolution | **Landed 2026-08-01**; result note in Item 5 |
| 14 | 4 | RFC 5961 section 3 | Raises blind-reset cost from ~32768 guesses to 2^32 | **Landed 2026-08-01**; result note in Item 4 |
| 15 | 4 | RFC 5961 section 4 | Small, additive, same code | **Landed 2026-08-01**; result note in Item 4 |
| 16 | 3 | D3's fix in `rt.vdso` | Patch 17's only prerequisite: it must not import a panic | **Landed 2026-08-01**; result note in Item 3 |
| 17 | 3 | Seed from hardware entropy | The seed stops being the boot clock | **Landed 2026-08-01**; result note in Item 3 |
| 18 | 3 | RFC 6528 ISNs | Per-connection hashing | **Landed 2026-08-01**; result note in Item 3 |
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
(CF=1, probability 2^-64 per 8-byte chunk) kills the calling process. *The first
of those is wrong -- RDRAND zeroes its destination whenever it clears CF, so the
`val == 0` test detected a failure correctly and the whole defect is the
response to it. Found while implementing patch 16, whose result note has the
detail; the fix shape below was unaffected.* Item 3
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
  client as `ECONNREFUSED` rather than as a retryable drop. *(Patch 10.2 changed
  this: exhaustion drops, a closed port still resets.)*

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
  is revisited with Step 8's batching evidence. *(Resolved earlier than that:
  patch 10's measurement made the cost plain -- an ordinary sixteen-connection
  burst lost half of itself terminally -- so the user moved the choice to patch
  10.2, which drops a request only for an endpoint a listener owns and leaves
  the closed-port reset alone. See that patch's result note below.)*

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

### Patch 9 follow-up: the caps are configurable, 2026-07-31

By user request. `max_half_open_global` and `max_half_open_per_listener` in
`/sys/cfg/sys-net.toml`, defaulting to the 128 and 32 above when either key is
absent, so a config written before this still loads. The constants became
`DEFAULT_MAX_HALF_OPEN_*` and `HalfOpenBudget` carries the caps it was built
with; it has no `Default`, because a zero-argument constructor is precisely how
one silently goes back to ignoring the config.

Zero is refused while parsing, by typing the fields `NonZeroUsize` rather than
by a check: at zero, `admit` refuses every replenishment and `release` can never
resume one, so the listening pool would close for the life of the process. One
is the smallest coherent setting and behaves -- see the cap-1 run below.

Three self-tests added, 19 in total: that a config without the keys takes the
documented defaults, that a config with them takes the configured values and
rejects a zero, and that a budget enforces the caps it was handed rather than
the compiled-in ones.

**The wiring the self-tests cannot reach.** Parsing and enforcement are tested
on either side of the seam, and nothing covers the one line in `net::init` that
joins them. So it was proved end to end: `max_half_open_global = 1` in the
shipped `sys-net.toml`, image rebuilt, and sys-io logged
`max_half_open_global: 1` and deferred 11 replenishments. The same run also
shows the numbers reach `NetConfig` from the file at all -- serde ignores an
unknown key, so a misspelled one would have defaulted to 128 in silence, and in
the six gate runs 128 is also what a typo would print. Only a non-default value
in the file distinguishes them.

That cap-1 run is stronger than patch 9's: systest exited 0, a full `PASS`, and
its 19 self-tests ran. Patch 9 had to skip the self-tests for the equivalent
experiment, because they asserted against the constants the experiment was
changing. Tests that build their own budgets are independent of the config, so
both can now be exercised at once.

Fail-first, each caught by exactly one of the three new tests, with sys-io still
serving after every one:

- `admit` consults the default instead of the configured cap -- the config is
  accepted and then ignored: `honors_configured_caps` fails on
  `` `!budget.admit(2)` is false ``.
- The serde default drifts from the documented 128:
  `defaults_the_half_open_caps` fails 64 against 128.
- `skip_deserializing` on the field, so the TOML is never read and the default
  silently stands in for a configured value: `parses_the_half_open_caps` fails
  128 against 64. This is the quiet one -- the system boots, networks, and
  passes every full-OS test while ignoring the config entirely.

Not sabotaged: that zero is rejected. It is a property of `NonZeroUsize`, so the
only way to regress it is to change the type -- a deliberate, visible act that
the same test then catches. The test earns its place as the guard on anyone
switching to a plain `usize` without adding the check back.

Gate: `cargo +nightly fmt --check`; Motor-target debug and release builds with no
new warnings; debug and release sys-io clippy byte-identical to the tree before
this change; three debug and three release `full-test.sh` runs, all six reaching
the final marker with no retries and no tolerated failures, all six reporting the
netstack closure's 534 tests, the debug three reporting 19 self-tests and the
release three none, and zero deferrals in all six.

The change moves two comparands from constants to fields on a struct already on
this path, so the accept path is the only thing it can cost and the full
`rnetbench` A/B/A patch 9 ran for this path stands. Accept-rate A/B/A instead,
five rounds of 300 sequential connect-and-close cycles per block, one image per
arm reused across both A blocks (the protocol brackets drift in the measurement,
not in the build):

| Block | Median (conn/s) | Rounds |
|---|---:|---|
| A1 | 6995.9 | 4879.0 6873.9 7096.6 7146.9 6995.9 |
| B | 6976.4 | 5340.1 6851.8 6976.4 7304.5 7146.5 |
| A2 | 7041.5 | 5415.0 6801.5 7223.2 7227.5 7041.5 |

B is -0.28% against A1 and -0.92% against A2, both far inside the 5% criterion,
with zero connection failures in all fifteen rounds. Every block's first round
is a cold-start outlier of the same size, which is why the median is over five.

### Patch 10 mechanism, decided 2026-07-31

Patch 10's entry above left its mechanism "to be settled inside patch 9's
measurements". It is settled here, against a measurement patch 9 did not make:
how deep a burst of simultaneous connections the listening pool actually serves.

A host client opens N sockets and issues every `connect` before collecting any
completion, so the guest meets them as one arrival burst. `rnetbench --server`
binds through `std`, which asks for no particular pool size and so gets
`DEFAULT_NUM_LISTENING_SOCKETS = 4`. Five bursts per row, release build:

| Burst | Accepted, burst by burst | Refused |
|---:|---|---:|
| 8 | 5 8 7 8 7 | 5 of 40 |
| 16 | 8 7 7 8 8 | 42 of 80 |
| 32 | 8 8 8 8 10 | 118 of 160 |
| 64 | 12 12 12 12 15 | 257 of 320 |

Half of sixteen simultaneous connects are refused, and what gets through does not
improve from one burst to the next: the pool *is* the backlog, about two poll
batches deep. Each refusal is an RST, which is terminal for the peer --
`ECONNREFUSED`, not a retry -- so it is a connection the application lost. This
is not a flood scenario; sixteen at once is an ordinary web page.

Deepening the pool fixes it and is exactly what must not be done up front: the
same bursts against a pool of 32 (measured, never committed) refuse nothing at 8,
16 or 32, but 32 pre-created sockets are 8 MiB of rings committed at bind by
every listener, including the ones that never see a second connection.

So the pool starts where the client asked and grows into the bursts it meets.
Decided with the user, in three patches:

- **Patch 10 -- growth.** A pool that a burst drains doubles, bounded per pool
  and globally over what growth added.
- **Patch 10.1 -- shrink.** Growth returns when demand falls, so a single burst
  does not pin the memory for the listener's life.
- **Patch 10.2 -- drop rather than reset.** The overload answer this item's
  scope note parked until Step 8's batching evidence. The user moved it here,
  directly after the shrink: growth cannot help the first burst of a new depth,
  and a dropped SYN is retransmitted where a reset one is not.

### Patch 10 result, 2026-07-31

`runtime/net/backlog.rs` holds one `Pool` per listening address -- what the
client asked for at bind, what replenishment currently aims at, and how many
sockets are in `Listen` right now. A pool whose last listening socket leaves
doubles its target; replenishment then creates the whole deficit instead of one
replacement. Exhaustion is the trigger rather than a rate, so a busy listener
that always has a socket free never grows, and only the burst that would have
been refused pays for the memory.

Two bounds, both `NonZeroUsize` and both configurable, as the half-open caps are:
`max_backlog_per_listener` (32, matching `MAX_NUM_LISTENING_SOCKETS`) stops a
pool where an explicit request would have been refused, and `max_backlog_global`
(128, 32 MiB) bounds the *extra* sockets growth added across all pools. Base
pools are never charged globally, so a bind cannot fail because another
listener grew. `close` returns a pool's share on teardown, which is what keeps
the global bound from ratcheting shut as listeners come and go.

Same bursts as the table above, this time against the patched release build:

| Burst | Accepted, burst by burst | Refused, before -> after |
|---:|---|---|
| 8 | 4 8 8 8 8 | 5 -> 4 of 40 |
| 16 | 14 16 16 16 16 | 42 -> 2 of 80 |
| 32 | 25 32 32 32 32 | 118 -> 7 of 160 |
| 64 | 40 60 60 53 52 | 257 -> 55 of 320 |

The shape is the point: the first burst of a given depth still loses part of its
tail, and every burst after it is served whole, up to the per-pool cap of 32.
Sixty-four is past that cap, and lands where the cap says it should.

The one line no self-test reaches is the same one patch 9's follow-up had to
prove separately: the configured caps arriving at the budget in `net::init`.
Shipping `max_backlog_per_listener = 8` in the image settles it -- the same
32-deep burst then plateaus at 12-13 accepted per round instead of 32, distinct
both from the default-cap run above and from the unpatched 8-10. The config was
restored byte-identically and the image rebuilt from it.

Nine self-tests, 28 in all: seven for the budget and two for the config keys.
Fail-first, by sabotage, each rebuilt and booted, with sys-io still serving every
time:

- `saturating_mul(2)` becomes `saturating_mul(1)` -- the config is read, the
  accounting is kept, and pools simply never deepen. Five of the seven fail,
  the first at `4 != 8`; this is the patch itself undone, so a single failing
  test would have meant the tests were measuring something narrower.
- Growth stops consulting the global bound: `stops_at_the_global_cap` alone,
  `8 != 5`.
- A closed pool keeps its share of that bound: `returns_growth_on_close` alone,
  `4 != 0`.
- The per-listener key is never read from the TOML:
  `net::config::parses_the_backlog_caps` alone, `32 != 8`.

Gate: `cargo +nightly fmt`; Motor-target debug and release builds with no new
warnings; debug and release sys-io clippy byte-identical to the tree before this
change, 107 and 104 warning lines, none in the changed files. Three debug and
three release `full-test.sh` runs, all six status 0 and reaching the final
marker with no retries and no tolerated failures, all six reporting the netstack
closure's 534, the debug three reporting 28 self-tests and the release three
none, and zero half-open deferrals in all six -- growth does not push ordinary
traffic into the cap patch 9 added.

The accept path gained one hash lookup where a listening socket is created and
one where it leaves `Listen`, so that is what was measured -- accept-rate A/B/A,
five rounds of 300 sequential connect-and-close per block, one image per arm
reused across both A blocks:

| Block | Median (conn/s) | Rounds |
|---|---:|---|
| A1 | 6779.0 | 5408.5 6779.0 6930.9 6072.9 7312.0 |
| B | 6899.2 | 5483.1 6899.2 6329.3 7380.9 7449.0 |
| A2 | 6713.5 | 4504.5 6417.1 6713.5 7307.2 7483.4 |

B is 1.8% above A1 and 2.8% above A2 -- inside the spread the two A blocks show
against each other, so no regression, and no gain claimed either. Zero connection
failures in all fifteen rounds, and every block's first round is a cold-start
outlier, which is why the median is over five.

**A consequence, stated rather than discovered later: this raises the half-open
ceiling patch 9 set.** That cap bounds sockets in SYN-RECEIVED, not sockets in
`Listen`, and its module note already puts the true bound at "the cap plus
whatever was still listening when the cap was reached". A flood drains pools, so
it also grows them, and that second term rises from 4 per pool to at most 32.
`max_backlog_global` is what keeps it finite: 128 extra sockets, so the worst
case moves from about 32 MiB of half-open rings to about 64 MiB. Patch 10.1
returns the growth once the flood ends.

### Patch 10 follow-up: growth triggers on a refused request, 2026-07-31

Found while gating patch 10.1, whose full-OS regression failed in two of three
debug runs. **Patch 10's trigger misses the exhaustion it exists to answer.** It
grows a pool when sys-io's own count of sockets in `Listen` reaches zero, but
that count is maintained by the listen task, which runs *after* the poll in which
the netstack already handed out and refused SYNs, and the replenishment each
departure spawns interleaves with the departures still to come. Traced during a
burst that drew 18 resets:

```
4 -> 3 -> 2 -> (replenish) 3 -> 4 -> 3 -> (replenish) 4 -> 3 -> 2 -> 1 -> (replenish) 2 -> 3 -> 4
```

The count bottoms out at 1 and the pool never doubles. Across six identical
bursts of 24 simultaneous connects, `net.tcp.syn_rst_unmatched` rose by 17 or 18
each time while `net.tcp.backlog_extra` stayed 0 in five of them: whether a pool
grows was decided by executor interleaving, not by demand. Patch 10's host-side
measurement is unaffected and stands -- the shape it drove does reach zero -- but
a guest-side burst on the same listener does not.

The fix is to trigger on the exhaustion itself. The netstack already counts a
connection request it reset because no socket took it (patch 8); it now also
records that request's **local endpoint**, deduplicated and capped at
`MAX_SYN_RST_ENDPOINTS` (8) per poll, because the addresses come from the network
and a port scan must not turn one poll into an unbounded list. sys-io drains the
endpoints where it already drains the counter and grows the pool that owns each
address; an address nothing listens on owns no pool and is ignored. A refusal
also zeroes that window's low-water mark, since a pool that lost a request was
using everything it had.

`left_listen`'s zero trigger is kept: emptying is the last warning before a
request is refused, and growing then costs a connection less. Arming the sweep
task moved into `BacklogBudget::needs_sweeper`, which both the listen task and
the device poll call, because growth now starts in two places.

Two implementation decisions for review: the bound drops the excess endpoints
rather than remembering an overflow flag, since an unattributable refusal cannot
grow anything; and growth is now driven by a signal an off-path attacker can
produce at will, which is deliberate -- it is bounded by the same two caps
(32 per listener, 128 extra globally) and returned by patch 10.1's sweep, and a
listener under a flood is precisely one that wants its pool deepened.

Netstack test: `unmatched_syn_reports_the_listening_endpoint` requires that one
listening socket meeting three requests reports its endpoint exactly once, that
reading clears the list, and that a scan of `MAX_SYN_RST_ENDPOINTS + 3` ports
reports the exact count but at most that many endpoints. Two self-tests, 34 in
all: a refused request deepens the pool its accounting believed full, and a
refusal for an address it owns no pool for deepens nothing.

The only always-on cost is two `Cell` reads per poll, from the sweeper check the
device loop now makes; the endpoint drain runs only when a request was refused,
and the netstack's record only at the reset site. Paired release `rnetbench`
A/B/A, five rounds per block, one image per arm reused across both A blocks:

| Workload | Block | RR (usec) | Motor RX (MiB/s) | Motor TX (MiB/s) |
|---|---|---:|---:|---:|
| default | A1 | 55.633 | 153.06 | 306.18 |
| default | B | 57.603 | 142.53 | 303.15 |
| default | A2 | 54.804 | 142.48 | 307.05 |
| 64 KiB | A1 | 55.443 | 648.33 | 1237.68 |
| 64 KiB | B | 56.511 | 647.91 | 1220.68 |
| 64 KiB | A2 | 54.570 | 651.09 | 1235.89 |

Against A2, which shares B's regime mix, B is RR +2.80 usec / RX +0.04% /
TX -1.27% on the default workload and RR +1.94 usec / RX -0.49% / TX -1.23% on
bulk -- inside the kill criteria, with the RR medians of the two *identical* A
blocks 0.8 usec apart and single samples ranging 52-64 usec in every block. A1's
default RX median is not comparable: its five samples walk straight through the
host's known regime shift (166.9, 165.1, 153.1, 142.3, 139.3) while B's and A2's
are one fresh sample plus four settled. All samples are retained above; an
earlier three-round A/B/A, where A1 fell entirely in the fresh regime, is
superseded by this one.

Fail-first, by sabotage, with sys-io still serving after both of the sys-io ones:

- The endpoint is never recorded: the netstack test fails at
  `[] != [Endpoint { addr: Ipv4(192.168.1.1), port: 49505 }]`.
- The deduplication is dropped, so a flood reports one entry per lost request
  and fills the bound with one listener: the same test fails at two identical
  endpoints against one.
- `refused` does nothing: `grows_on_a_refused_request` alone, `0 != 4` -- the
  pool that lost a request stays at its bind size.
- `refused` grows the pool but leaves the window's low-water mark alone: the
  same test alone, on the sweep that follows taking the growth straight back.
  This sabotage first found the test too weak to catch it -- a fresh pool's mark
  is already zero -- so the test now runs a quiet window before the refusal, and
  the mark it must clear is real.

### Patch 10.1 design -- returning the growth

Growth is demand-driven; without a way back, one burst pins a pool at its cap for
the listener's life, and a scan of a few dozen ports pins several. Two things
have to be right.

**What to return.** Each pool records `low_water`, the smallest `listening` seen
since the last sweep -- sockets that sat in `Listen` through the whole window and
were never needed. A sweep returns `min(low_water, target - base)`: down to what
was actually used, never below what the client asked for at bind. Lowering the
target alone frees the global bound immediately and stops replacement, so the
surplus drains as connections arrive; it does not free the memory of a pool that
grew and then went quiet, which is the case that motivates this patch, so the
sweep also drops that many of the pool's sockets that are still in `Listen`
(`SocketBase::local_addr` picks a pool's sockets out of the listener's set).

A sweep must not feed the growth rule it undoes. Dropping a listening socket ends
its listen task the same way a SYN does, so those departures reach `left_listen`,
and a pool shrunk to exactly what it uses would read its own reclamation as
exhaustion and double straight back. The count a sweep drops is therefore
recorded on the pool and spent by those departures before growth is considered.

**When to sweep.** A departure-counted window cannot see an idle pool, since an
idle pool has no departures -- so this needs a timer, and a timer is exactly what
must not run on an idle VM. It therefore exists only while there is growth to
reclaim: the first growth from `extra == 0` spawns the sweep task, and the sweep
that finds `extra == 0` ends it. A VM that never meets a burst never arms it,
and boot arms nothing.

Fail-first is the same seam as patch 10: the window arithmetic is self-testable
without an executor, and the full-OS side is a burst followed by quiet, with the
listening-socket gauge falling back toward the base.

### Patch 10.1 result, 2026-07-31

Built as designed. `Pool` gained `low_water` and `reclaiming`; `sweep()` returns
`min(low_water, target - base, listening)` per pool, lowers the target, charges
the drops to `reclaiming`, and resets `low_water` to what the pool will hold once
they land. `left_listen` spends `reclaiming` before it reads either demand or
exhaustion, and now returns whether the caller must start the sweep task, which
is the only thing that arms a timer -- `spawn_sweeper` sleeps
`SWEEP_INTERVAL` (5 s), sweeps, and returns as soon as a sweep leaves the global
bound empty.

Two implementation decisions are recorded here for review:

- **The sweep aborts a listening socket rather than tearing it down itself.**
  `Listen -> Closed` wakes the listen task that already owns that socket's
  teardown, so the gauge, the pool accounting, and the drop all run on the path
  a socket that took a SYN and lost it runs, with no second teardown ordering to
  get right. A `Listen` socket has no remote endpoint, so nothing is sent.
- **`net.tcp.backlog_extra` is new**, publishing what the global bound holds:
  patch 10 bounded a quantity nothing could observe. It is also what makes the
  full-OS test precise -- other listeners' *base* pools move
  `net.tcp_listening_sockets`, but only growth moves this.

**5 seconds, and why a burst pays for two windows.** The sweep returns what sat
unused for a whole window, so the window a burst falls in returns nothing: the
pool ran out inside it. A burst therefore keeps its depth for 5 to 10 seconds
after the last connection, and repeat bursts inside that window keep it for as
long as they keep arriving -- `low_water` returns only above the deepest dip.
Longer would suit a server whose visitors return in tens of seconds; the memory
is what argues the other way, and 32 MiB is the bound it argues against.

Four self-tests, 32 in all. Fail-first, by sabotage, each rebuilt and booted,
with sys-io still serving every time:

- The sweep returns nothing (`unused = 0`) -- the patch itself undone. All four
  fail, the first at `[] != [((1, 10.0.0.1:80), 4)]`, and the full-OS test fails
  with 4 grown sockets still held.
- The sweep ignores `low_water` and strips to the base every window: the same
  four fail, first at `sweeps_unused_growth`'s "the burst's own window returns
  nothing", which is the rule that keeps a pool through the burst that grew it.
- `left_listen` stops spending `reclaiming`:
  `does_not_regrow_on_its_own_sweep` alone, on the pool doubling back the moment
  its own reclamation empties it.
- Growth never arms a sweep: `sweeps_only_while_growth_stands` alone, plus the
  full-OS test.
- The target is lowered but no socket is dropped -- the accounting returned while
  the memory stays committed. No self-test can see this, and the full-OS test
  fails on `net.tcp_listening_sockets`: 20 listening against a bound of 16.

`test_backlog_growth_and_shrink` is the full-OS half: 24 threads released
together against a freshly bound listener must raise `backlog_extra`, and both it
and the listening gauge must return to their pre-burst values while the listener
is *still bound* -- dropping it would return the growth for reasons that have
nothing to do with a sweep. It takes about 10 seconds, which is the two windows.
It depends on the patch 10 follow-up above: before it, the burst deepened the
pool only when the executor happened to interleave the departures favorably, and
the test failed in two of three debug runs.

Gate, covering this patch and the patch 10 follow-up above as one tree -- the
full-OS regression here cannot pass without that fix, so gating them apart would
mean gating a test known to fail: `cargo +nightly fmt --check`; Motor-target
debug and release builds with no new warnings; debug and release sys-io clippy
byte-identical to clean `HEAD`; systest clippy with nothing in the changed code;
both netstack closures with warnings denied (535 plus 7 and 674 plus 7 tests);
the reduced no-`socket-tcp` netstack build with the same eight warnings as
before. Three debug and three release `full-test-networking.sh` runs, all six
status 0 and reaching the final marker with no retries and no tolerated
failures. All six report the netstack closure's 535 tests,
`test_backlog_growth_and_shrink`, a negative DNS query returning `NotFound`
directly, and `concurrent_flush_stress_test` completing 4 x 4,000 iterations;
the debug three report 34 self-tests and the release three none.

The sweep's own cost is nothing on a packet path -- it runs at most once every
five seconds and only while growth stands -- so the measurement this tree needed
is the follow-up's per-poll check, recorded above.

### Patch 10.2 result, 2026-08-01

The last of item 6, and the answer to the case growth cannot reach: a pool
cannot deepen before the burst that shows it is too shallow, so the first burst
of a new depth always loses its tail. Losing it to a reset is what made it
terminal -- an RST is a connection the application never gets -- while a dropped
SYN is retransmitted a second later, by which time the pool has been replenished
and deepened. `process_tcp` now drops such a request instead of resetting it,
counts it in the new `net.tcp.syn_backlog_dropped`, and records its endpoint;
a request for an endpoint no listener owns keeps its reset.

**The implementation decision this needed, recorded for review: how the netstack
tells a full backlog from a closed port.** sys-io holds that fact, and mirroring
it into the interface -- an endpoint set maintained at listener bind and close --
was the obvious shape and was rejected: it is duplicated state with two lockstep
call sites and nothing to catch them drifting, the failure that patch 6's
"a stored field can go stale" note already argued against. The netstack answers
it from what it already owns instead. `listen_endpoint` is set by
`Socket::listen`, survives into every state a socket that took a SYN moves
through, and is cleared by `Socket::connect`'s `reset()`, so a socket whose
listen endpoint would have accepted this request is proof that a listener is
there and out of sockets -- and an outbound connection's local port, which is
*not* a listener, can never answer for one. Its limit is stated rather than
hidden: a listener with no socket left anywhere, its pool empty and every
connection it accepted already gone, reads as a closed port and gets today's
reset. Replenishment is spawned by each departure, so that window is a poll or
two wide, and the degradation is the pre-patch behavior rather than a new
defect.

Two smaller decisions with it. The endpoint list moved from the reset site to
the drop site: after this patch a reset endpoint owns no pool by construction,
so recording one is dead weight, and worse, a scan of closed ports could fill
`MAX_BACKLOG_ENDPOINTS` and crowd out the listener that really ran out. The
field and its bound are renamed to `tcp_backlog_endpoints` /
`MAX_BACKLOG_ENDPOINTS` to match. And only bare SYNs are eligible: an unmatched
segment carrying an ACK is a stale connection, not a pending one, and keeps its
reset so the peer learns its connection is gone.

Measured, five bursts of 24 simultaneous guest-side connects against a
`std`-bound listener (four deep), each burst on a fresh listener with a quiet
window between:

| Tree | Connected, burst by burst | Lost | Dropped | Reset |
|---|---|---:|---:|---:|
| this patch reverted | 7 8 7 12 12 | 74 of 120 | 0 | 74 |
| patched | 24 24 24 24 24 | 0 of 120 | 18 typical | 0 |

Every burst arrives whole, and the resets are gone rather than converted: what
used to be a lost connection is now one that took a retransmit. The pool still
grows exactly as patch 10 left it.

Fail-first, by sabotage, each rebuilt and booted with sys-io still serving:

- The verdict is ignored, i.e. this patch undone. The netstack regression fails
  at `0 != 2` on the drop count, and `test_backlog_growth_and_shrink` fails with
  "a burst of 24 lost 16 connections" -- the table's first row.
- Every unmatched request is dropped, closed ports included. Both netstack
  regressions fail at `0 != 1` on the reset count, and the full-OS
  `test_half_open_accounting` fails on "expected exactly one reset connection
  request". That test's closed-port connect is now bounded by
  `connect_timeout`, because a request that is dropped rather than reset
  retransmits forever: without the bound this guard would hang instead of
  failing.
- The endpoint is recorded at the reset site instead of the drop site -- the
  "forgot to move it" defect, which after this patch means no endpoint is ever
  recorded. The netstack regression fails at `[] != [192.168.1.1:49505]`. The
  full-OS test does **not** fail, and that is worth recording: with dropping in
  place a burst arrives whether or not its pool is told to deepen, because
  `left_listen`'s zero trigger still fires across the several polls the
  retransmits now span. What the endpoint buys is depth. Over the same five
  bursts, `backlog_extra` reached 28 in four of five with it -- the pool at its
  32 per-listener cap -- and 12 in all five without it, so the pool stops at 16
  and the burst pays more retransmits to get in.

Gate: `cargo +nightly fmt`; Motor-target debug and release builds; debug and
release sys-io clippy identical to clean `HEAD` (35 and 32 warning lines, none
in the changed files, one line number shifted by this patch's own additions);
systest debug and release clippy identical to clean `HEAD`; both netstack
closures with warnings denied (535 plus 7 and 674 plus 7 tests -- the test count
is unchanged because this patch reworks the existing unmatched-SYN regression
rather than adding one); the reduced no-`socket-tcp` netstack build with no
warnings. Three debug and three release `full-test-networking.sh` runs, all six
status 0 with no retries and no tolerated failures. All six report the netstack
closure's 535 tests, `test_half_open_accounting`, `test_backlog_growth_and_shrink`,
a negative DNS query returning `NotFound` directly, and all four flush-stress
workers completing 4,000 iterations; the debug three report 34 self-tests and the
release three none.

One run is not counted: the first debug run built a tree that differed from the
final one by three comments in `backlog.rs`, written while it was in flight. The
binary is unaffected -- comments are not compiled -- but "the exact source state"
is the claim this record makes, so a fourth debug run was added and the recorded
debug three are runs 2, 3 and 4.

No paired `rnetbench` A/B: this patch's gate list does not ask for one, and
nothing on a packet success path changed. The one new cost is the socket-set
walk, and it is confined to a request no socket took -- a path that already
walks the whole set with the heavier `accepts()` predicate, so an unmatched SYN
costs two walks where it cost one, and ordinary traffic costs neither.

## Item 5 -- ARP cache admission, eviction, request rate (patches 11-13)

### Verified state

- Eight entries machine-wide in a linear map with earliest-expiry eviction
  (`N/iface/neighbor.rs:44-49`, `:105-144`); entry lifetime 60 s (`:53`).
- Any same-subnet ARP *request* aimed at one of our addresses fills the cache
  (`N/iface/interface/ipv4.rs:299-307`), so eight forged requests evict every
  legitimate entry, the gateway included. **Corrected while implementing patch
  11:** IPv6 does not fill only from neighbor advertisements (`ipv6.rs:472`).
  A neighbor *solicitation* carrying a link-layer address fills the same shared
  cache (`ipv6.rs:491`), which is the identical primitive under a different
  name. Both are fixed by patch 11.
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

*Wording corrected while implementing it.* "Removes the eviction primitive
outright" reads as though no fill may ever evict, which contradicts the same
sentence's "replies ... still fill" and is the wrong patch: with no eviction at
all, an attacker fills the cache with forged requests, refreshes them every
59 s, and the reply to our own ARP for the gateway can then never be admitted,
so all off-subnet egress dies permanently -- worse than what it replaces, and a
patch that does not leave a runnable tree. What patch 11 removes is the
*forgeable* eviction primitive: the one the P3 finding describes, where any
peer's request displaces an entry. A reply keeps the evicting fill, which is
what lets our own resolution through a cache someone has filled, and patch 12
is what protects the gateway on that remaining path. Decided with the
maintainer before implementation, 2026-08-01.

**Patch 12 -- gateway protection (~90 lines).** Never evict an entry that a
configured route's gateway resolves to. Test: a flood of distinct same-subnet
sources cannot displace the gateway entry, and egress through the gateway keeps
working across the flood.

*Read as written while implementing it,* with two readings made explicit.
"A configured route's gateway" is any route's `via_router`, not only a default
route's: a more specific route's router carries everything behind that prefix
and its entry is worth exactly as much. And a route that has expired carries
nothing, so its router is not protected -- the same expiry test `Routes::lookup`
already applies before it will use a route.

**Patch 13 -- per-destination request rate (~120 lines).** Replace the global
`silent_until` with a per-destination silent time so one unresolvable address
cannot starve another, keeping sys-io's 5 ms value and re-recording its
motivation. Test: two destinations, one black-holed, and the other still
resolves within one silent interval.

*Read as written while implementing it.* The 5 ms value is unchanged and its
motivation is recorded at the sys-io site where the value is set, next to what
per-destination now makes it cost.

Explicitly out of scope, with rationale: rate-limiting ARP *replies*. Replying
to a request aimed at us is required behavior and is 1:1, not amplifying.

Cache capacity (`iface-neighbor-cache-count-N`) stays in Step 10 item 4,
decided: it is a build-feature change with a linear-scan cost that belongs with
the route table it is measured against, and patches 11 and 12 together leave no
eviction an off-path peer can aim, so the eight-entry limit stops being an
attack surface and becomes mostly a performance question. Both are nonetheless
strictly more effective with more slots -- capacity is what decides how much
forged filling it takes before a legitimate mapping needs a reply to get back
in -- so Step 10 item 4 must not be deferred indefinitely.

### Tests and gate

Netstack tests plus a full-OS check that ordinary external traffic is unaffected.
Standard per-patch gate; no data-path cost expected, but patch 13 touches egress
dispatch, so include the paired release `rnetbench` A/B.

### Patch 11 result, 2026-08-01

`Cache::fill_unsolicited` is the admission path for a packet nobody asked for.
It may replace or refresh a mapping the cache already holds, and it may take a
free slot, but it may never displace another entry: `LinearMap::insert` fails
exactly when the cache is full *and* the address is absent, which is exactly the
case that would have needed an eviction, so the refusal is the failed insert
rather than a second capacity check that could disagree with it. `Cache::fill`
is untouched and still evicts the entry closest to expiry.

Two ingress sites use it, because a request and a solicitation are the same
primitive under two names -- see the verified-state correction above. The ARP
path splits on the operation: a request admits without evicting, a reply keeps
`fill`. The NDISC path gives `NeighborSolicit` the same treatment and leaves
`NeighborAdvert` on `fill`. Nothing else changed; a refused request is still
answered, because the reply is owed whether or not we chose to remember who
asked.

Three implementation decisions, recorded for review:

- **The split is by packet type, not by whether we actually solicited it.** The
  netstack keeps no record of which requests are outstanding, so "a reply to our
  own request" is not a question it can answer today; treating every reply as
  solicited is what the pre-patch code already did. This leaves forged *replies*
  as an eviction path, which is patch 12's subject and why patch 12 protects the
  gateway rather than being made redundant by this patch.
- **The counter lives on `InterfaceInner`, not on `Cache`.** It matches
  `rx_csum_failed` and `tcp_syn_backlog_dropped` -- drained per poll by
  `NetDev::poll`, accumulated into `NetStats` -- so sys-io has one shape for
  every netstack-side counter rather than a second one that reaches into the
  cache.
- **`net.neighbor.admission_refused` warns once per poll, not once per packet.**
  This is deliberately the same trade `net.rx.csum_failed` makes: the aggregate
  is what bounds the log a flood can produce, and per-packet logging on an
  attacker-reachable path would be the amplification the counter exists to
  report.

An unsolicited packet is not on a data path -- ARP and NDISC ingress is control
traffic that already parses and replies -- and the split costs one enum
comparison on it, so this patch is not on the `rnetbench` list and none was run.

Tests. Two cache-level (`neighbor.rs`): `test_unsolicited_never_evicts` proves
the free slot fills, that a full cache refuses a new address while every cached
mapping survives, and that a reply still evicts the entry closest to expiry;
`test_unsolicited_refreshes_cached_entry` proves a full cache still admits an
address it already holds and that the entry's expiry moves. Two at the
interface boundary: `test_arp_request_never_evicts` and
`test_ndisc_solicitation_never_evicts` fill the cache to
`IFACE_NEIGHBOR_CACHE_COUNT`, drive a real frame through `process_ethernet`, and
require that the reply still goes out, that no cached mapping moved, that the
sender was not learned, and that the counter reads exactly 1. The full-OS half
is systest's `test_neighbor_admission`: the counter must be 0 after a boot whose
traffic includes the ssh session systest itself arrives over, which the VM could
not have without resolving and using its gateway.

Fail-first, by sabotage in both directions. Routing `fill_unsolicited` back to
the evicting fill fails three of the four: both interface tests at the first
displaced mapping (`NotFound` against
`Found(Ethernet(Address([82, 84, 0, 0, 0, 10])))`) and the cache test at its
refusal assertion. `test_unsolicited_refreshes_cached_entry` correctly still
passes, because refreshing a cached address needs no eviction either way, which
is what makes it a test of the admitting branch rather than of the bound.
Dropping only the counter increment, leaving the refusal in place, fails both
interface tests at 0 against 1 -- so the counter the full-OS assertion reads is
load-bearing rather than incidentally zero.

The exact patch-11 source state passed formatting, Motor-target debug and
release builds, debug and release sys-io and systest clippy byte-identical to
clean `HEAD`, both netstack closures with warnings denied (539 plus 7 and 678
plus 7 tests, each four more than patch 10.2's), and three consecutive debug
plus three consecutive release `full-test-networking.sh` runs with no retries
and no tolerated failures. All six contain both new interface regressions, the
netstack closure's 539 tests, `test_neighbor_admission`,
`test_device_rx_validation`, both DNS resolver self-tests across the restart, a
negative DNS query returning `NotFound` directly, and all four flush-stress
workers completing 4,000 iterations; the debug three report 34 self-tests and
the release three none. `net.neighbor.admission_refused` stayed 0 in every run
-- the per-poll warning never fired once -- which is the "ordinary external
traffic is unaffected" evidence this item's gate asks for. Only the three plan
documents changed between the first debug run and the last release run, so all
six built one compiled tree.

### Patch 12 result, 2026-08-01

Patch 11 left one eviction an off-path peer can still aim: a forged *reply*.
Nothing in the netstack records which requests are outstanding, so every reply
is treated as solicited, and a stream of replies from distinct same-subnet
addresses evicts entry after entry -- the gateway among them, because nothing in
the victim choice treated it differently from any other mapping. Patch 12 takes
it out of that stream's reach. `Cache::fill_solicited` still evicts, but chooses the
entry closest to expiry *among the unprotected ones*, and `InterfaceInner`
supplies the protection: `Routes::is_active_router`, true for the `via_router`
of any route that has not expired. `fill_unsolicited` is untouched; it never
evicted.

Three implementation decisions, recorded for review:

- **The cache takes a predicate, not the route table.** `Cache` decides which
  entry to displace; it has no business knowing what a route is. The caller
  passes `impl Fn(&IpAddress) -> bool`, and the one production caller,
  `InterfaceInner::fill_neighbor_solicited`, closes over `self.routes`. This
  also makes the cache's own tests state their protection directly rather than
  building a route table to imply it.
- **When every entry is protected, the closest to expiry goes anyway.** The
  shipped configuration cannot reach this -- eight cache slots against two
  routes -- but the crate's test configuration can, with three slots and four
  routes. Refusing the fill there would be patch 11's rejected reading in
  miniature: a cache that can evict nothing can never learn anything again, and
  a machine whose cache is entirely routers would lose every other destination
  permanently. The fallback is exactly `HEAD`'s behavior, so protection is a
  strict improvement wherever it can be honored and costs nothing where it
  cannot.
- **`Cache::fill` is now `#[cfg(test)]`.** It is the unprotected fill, and after
  this patch no production path wants one. Gating it means a future caller
  cannot quietly bypass gateway protection by reaching for the shorter name --
  in a non-test build the function does not exist. Tests that merely want a
  populated cache keep using it.

Tests. Five, one per new behavior. `route.rs`: `test_is_active_router` covers
the address match, a non-router address, and the expiry boundary on both sides.
`neighbor.rs`: `test_protected_entry_is_not_evicted` makes the protected entry
the one closest to expiry -- the victim an unprotected fill would take -- and
requires the next-closest to go instead; `test_all_protected_still_fills`
requires the fallback, so the wedge described above stays impossible. At the
interface boundary, `test_arp_reply_never_evicts_gateway` and
`test_ndisc_advert_never_evicts_gateway` configure a default route, fill the
cache with the gateway as its earliest-expiring entry, drive
`IFACE_NEIGHBOR_CACHE_COUNT + 2` real forged replies through `process_ethernet`,
and require the gateway mapping to survive intact. The IPv4 one also calls
`lookup_hardware_addr` for an off-subnet destination afterwards and requires the
gateway's MAC back -- the plan's "egress through the gateway keeps working
across the flood", asserted at the point where egress actually resolves.

Fail-first, by three sabotages, each restored before the next. Dropping the
`protected` filter from the victim search fails exactly three: both interface
tests and `test_protected_entry_is_not_evicted`. `test_all_protected_still_fills`
correctly survives it, because the fallback is what that sabotage restores.
Removing the fallback fails exactly `test_all_protected_still_fills`, on the
`expect` that has nothing left to evict. Making `is_active_router` ignore route
expiry fails exactly `test_is_active_router`. No sabotage failed a test outside
its own subject, and none of the five passed under all three.

No paired `rnetbench` A/B. The item's gate list asks for one only on patch 13,
and this patch adds work to exactly one place: the eviction branch of a
solicited fill, which runs only when the cache is full and the reply's address
is not already in it. The added work is one linear pass over at most eight
entries, on a path that already made that pass.

The exact patch-12 source state passed formatting, Motor-target debug and
release builds, debug and release sys-io and systest clippy identical to clean
`HEAD`, both netstack closures with warnings denied (544 plus 7 and 683 plus 7
tests, each five more than patch 11's), and three consecutive debug plus three
consecutive release `full-test-networking.sh` runs with no retries and no
tolerated failures. All six contain the five new regressions by name, both of
patch 11's, the netstack closure's 544 tests, `test_neighbor_admission`,
`test_device_rx_validation`, both DNS resolver self-tests across the restart, a
negative DNS query returning `NotFound` directly, and all four flush-stress
workers completing 4,000 iterations; the debug three report 34 self-tests and
the release three none. The full-OS half of this item's gate -- ordinary
external traffic unaffected -- is that every run boots, resolves through its
gateway, and carries the ssh session systest arrives over, with
`net.neighbor.admission_refused` still 0 and the per-poll warning never fired.
Only the three plan documents changed between the first debug run and the last
release run, so all six built one compiled tree.

### Patch 13 result, 2026-08-01

The rate limit on neighbor discovery was one `silent_until` instant on the whole
cache: any dispatched request silenced discovery for *every* address, so a single
destination nobody answers for held back resolution of every other one for the
interval. It is now a second small map -- destination to the instant that
destination may be asked about again -- which `Cache::lookup` consults for the
address being resolved and `Cache::limit_rate` arms for the address just asked
about. `InterfaceInner::lookup_hardware_addr` passes the routed next hop, which
is the address the request was actually for.

Four implementation decisions, recorded for review:

- **A second map, not a field on the cached entry.** The addresses being rate
  limited are exactly the ones with no entry -- that is why a request went out --
  so a silence has nowhere to live on `Neighbor`. Folding pending destinations
  into `storage` as a second kind of entry was rejected: local egress toward
  unresolvable addresses would then evict resolved mappings, which is the
  eviction pressure patches 11 and 12 spent themselves removing.
- **`IFACE_NEIGHBOR_CACHE_COUNT` slots, not a new build knob.** The map holds
  neighbors under discovery, so the count of neighbors the interface tracks is
  the honest bound for it, and adding a fifteenth autogenerated config feature to
  size a 5 ms scratch map is not worth the build surface. The cost is one
  `IpAddress`/`Instant` pair per slot, about 200 bytes machine-wide.
- **A full map yields the silence with the least left to run.** Expired silences
  go first without a scan to find them, since any expired instant sorts below
  every live one. Refusing to record instead would leave the new destination with
  no limit at all, which is the opposite of what the map is for.
- **`flush` clears the silences.** Whatever made the interface forget its
  mappings -- an address change, today -- makes the requests those silences paid
  for stale, and re-resolution should not wait on them.

What the global instant was really bounding was the interface's whole ARP
request rate: one per interval, no matter how many destinations wanted one. That
bound is deliberately gone, and per-destination is what replaces it. The
machine-wide rate is still bounded, by the per-socket silence
`Meta::neighbor_missing` arms with the same 5 ms for the socket whose dispatch
failed, so a socket costs at most 200 requests/s whether or not its destination
holds a slot in the map.

Tests. Five, one per new behavior. `neighbor.rs`: `test_hush_is_per_destination`
requires a silenced address not to silence another and each to run out on its own
schedule; `test_hush_evicts_earliest` fills the map and requires the entry with
the least left to run to be the one that yields; `test_hush_refresh_keeps_slot`
re-arms an address already in a full map and requires the other silences to
survive; `test_flush_clears_hush` requires a flush to drop them. `test_hush`
keeps its original subject under the new signature. At the interface boundary,
`test_discovery_silence_is_per_destination` is the plan's test: it drives
`lookup_hardware_addr` through a real device token and reads the ARP requests off
the device's transmit queue, requiring the black-holed destination to produce one
request and then none, the second destination to produce its own request inside
that interval, and -- after a reply arrives for it -- to resolve with no further
request. All within one silent interval, since the clock never advances.

Fail-first, by four sabotages, each restored before the next. Making `lookup`
test any live silence rather than this address's fails exactly three:
`test_discovery_silence_is_per_destination`, `test_hush_is_per_destination`, and
`test_hush_evicts_earliest`, whose evicted address reads as rate limited again
under a global test. Dropping the slot-eviction branch fails exactly
`test_hush_evicts_earliest`. Leaving the silences behind on `flush` fails exactly
`test_flush_clears_hush`. Evicting whenever the map is full, even when the
address is already in it, fails exactly `test_hush_refresh_keeps_slot`. No
sabotage failed a test outside its own subject, and none of the five passed under
all four.

Paired same-host release `rnetbench`, A/B/A blocks of five rounds with one
unchanged host client (medians; A = clean `HEAD`, B = prepared):

| Workload | Block | RR (usec) | Motor RX (MiB/s) | Motor TX (MiB/s) |
|---|---|---:|---:|---:|
| default | A1 | 56.18 | 161.27 | 326.79 |
| default | B | 57.04 | 160.41 | 319.27 |
| default | A2 | 56.49 | 159.21 | 318.82 |
| 64 KiB | A1 | 59.05 | 633.10 | 1222.03 |
| 64 KiB | B | 57.22 | 627.20 | 1206.73 |
| 64 KiB | A2 | 56.91 | 642.05 | 1211.83 |

Against the bracketing A2 block the prepared tree is RR +0.55 usec / RX +0.75% /
TX +0.14% on the default workload and RR +0.31 usec / RX -2.31% / TX -0.42% on
bulk; against A1 it is RR +0.86 / RX -0.53% / TX -2.30% and RR -1.83 / RX -0.93%
/ TX -1.25%. Mixed sign against the two A blocks on every metric, largest
excursion 2.31%, well inside the kill criteria (5% throughput, ~5 usec RR). This
is the expected shape: the egress path this patch touches runs only when a
destination is *not* in the cache, and neither benchmark ever resolves more than
the peer it talks to.

The exact patch-13 source state passed formatting, Motor-target debug and
release builds, debug and release sys-io and systest clippy identical to clean
`HEAD`, both netstack closures with warnings denied (549 plus 7 and 688 plus 7
tests, each five more than patch 12's), and three consecutive debug plus three
consecutive release `full-test-networking.sh` runs with no retries and no
tolerated failures. All six contain the five new regressions by name, patch 12's
five and patch 11's two, the netstack closure's 549 tests,
`test_neighbor_admission`, `test_device_rx_validation`, both DNS resolver
self-tests across the restart, a negative DNS query returning `NotFound`
directly, and all four flush-stress workers completing 4,000 iterations; the
debug three report 34 self-tests and the release three none. The full-OS half of
this item's gate -- ordinary external traffic unaffected -- is that every run
boots, resolves through its gateway, and carries the ssh session systest arrives
over, with `net.neighbor.admission_refused` still 0 in all six. Only the three
plan documents changed between the first debug run and the last release run, so
all six built one compiled tree.

With patch 13, item 5 is complete: no eviction an off-path peer can aim reaches
a router, a full cache refuses unsolicited mappings instead of displacing
learned ones, and one unresolvable destination costs only its own request rate.
What remains for the ARP cache is capacity, which Step 10 item 4 measures
against the route table.

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

*The placement in that sentence is wrong, and the two halves of it contradict
each other: a rebooted peer's SYN carries no acknowledgement, so it never
reaches the state machine -- "every packet after the initial SYN must be an
acknowledgement" drops it several hundred lines earlier. A match arm there
would catch only a SYN bearing an acceptable ACK and an in-window sequence
number, which is not the case the patch exists for. Measured before deciding,
and the placement is now sabotage-tested. Details in the patch 15 result below.*

Step 5 deliberately did not lock in current RST behavior, so no existing
netstack test needs to change; patch 14 must confirm that while it lands.

*Read as written while implementing it. The claim above is wrong, and patch 14's
confirmation came back negative: three inherited netstack tests assert the RFC
793 behavior in passing and had to move. What Step 5 did not lock in was
sys-io's RST behavior; the fork's own suite predates it. The three, and why
moving them costs no coverage, are in the patch 14 result below.*

### Tests and gate

Standard per-patch gate. Protocol behavior change, so also: the full-OS suites
must show unchanged connect-refused, close, and abort behavior, and the paired
release `rnetbench` A/B.

### Patch 14 result, 2026-08-01

Past SYN-SENT, a reset is now acted on only at exactly `RCV.NXT`. One elsewhere
in the receive window draws a rate-limited challenge ACK and changes no state;
one outside the window is dropped with no reply at all. The whole change is one
block in `Socket::process`, placed between the receive-window computation and
the segment acceptability test, plus the correction of a comment in the
acknowledgement match that promised a sequence check the code did not make.

Four implementation decisions, recorded for review:

- **Ahead of the acceptability test, not inside it.** That test's verdict for a
  segment outside the window is a challenge ACK -- precisely what section 3
  forbids for a reset -- and its verdict for one inside is "acceptable", which is
  what closes the socket. Both of its answers are wrong for a reset, so the
  reset's own three-way decision is taken first, in one place, and the data path
  below is untouched: nothing but a reset can reach the new branch.
- **Every state past SYN-SENT, SYN-RECEIVED included.** RFC 9293 3.10.7.4 words
  the rule as applying in all states except SYN-SENT, and a half-open connection
  is worth the same protection as an established one -- an off-centre reset must
  not knock a pending accept back to LISTEN. The SYN-RECEIVED-to-LISTEN return
  the listen task depends on still fires, because a real peer's reset sits at
  `RCV.NXT`: the reset it generates for our SYN-ACK takes its sequence number
  from that segment's ACK field, which is our `RCV.NXT` exactly. LISTEN is
  excluded for a different reason -- `accepts` already refuses resets there, so
  the arm for it in the state machine is unreachable either way. The exclusion
  of SYN-SENT is load-bearing and inherited-tested: applying the check there
  fails `test_syn_sent_rst`, since the two SYN-SENT special cases validate the
  acknowledgement instead, before any receive window exists.
- **No new rate limiter.** The challenge ACK reuses `challenge_ack_timer`, which
  the unacceptable-ACK, out-of-window, and LastAck-duplicate sites already share,
  so the ceiling stays one challenge ACK per socket per second across all four --
  a reset flood cannot buy an extra reply by arriving on a path of its own.
- **A stray reset no longer restarts the TIME-WAIT timer.** It used to reach the
  acceptability test, which restarts the 2MSL close timer on its way to a
  challenge ACK. Dropping the out-of-window reset earlier means a stream of them
  can no longer hold a socket in TIME-WAIT; the restart still happens for the
  retransmitted FIN it was there for.

The cost is a round trip on one legitimate path. A peer that resets us after
data we never received -- its reset sits at its own `SND.NXT`, past the hole --
is now challenged rather than obeyed. The challenge ACK carries our `RCV.NXT`,
and the peer's answer to an ACK for a connection it no longer has is a reset at
that number, which we accept. So the connection still tears down, one exchange
later, and that convergence is the mechanism RFC 5961 relies on rather than an
accident of ours; `test_established_rst_in_window_is_challenged` walks it.

Three inherited tests moved, which is the plan's expectation coming back
negative. All three are upstream tests whose subject is something else and which
reach for a reset in passing, at a sequence number that RFC 793 accepted:
`test_established_rst_bad_seq` (smoltcp #338 -- the challenge ACK's ack number
must track received data even with no dispatch in between) aimed its reset one
octet *below* `RCV.NXT`, which is now dropped unanswered, so it moved to an
in-window number two past `RCV.NXT`, chosen so it stays wrong after the test
advances the sequence by one; `test_rx_close_rst_with_hole` and
`test_rx_close_fin_with_hole` (recv semantics when the socket is reset while the
assembler has a hole) aimed theirs past the hole, and moved to `RCV.NXT`, where
an accepted reset now has to sit, with the hole still above it. Each keeps its
own subject, and the acceptance behavior they had been asserting incidentally is
now asserted deliberately by the five tests below.

Tests. Five new, one per rule plus the two edges.
`test_established_rst_in_window_is_challenged` requires an off-centre reset to
leave the connection established and to answer with an ACK carrying `RCV.NXT`,
then requires the reset at that number to close it -- the convergence above.
`test_established_rst_challenge_ack_rate_limited` sends four resets across one
second and requires exactly two replies, at the start and at the second's end.
`test_established_rst_out_of_window_is_silent` takes both edges -- one octet
below the window and the first octet past it -- requires silence for each, and
then requires the last in-window octet to still draw its challenge ACK, so the
silence cannot be the rate limiter having fired.
`test_syn_received_rst_in_window_is_challenged` requires a half-open connection
to stay in SYN-RECEIVED, with its tuple, under an off-centre reset.
`test_time_wait_rst_out_of_window_is_silent` requires the close timer to be
untouched by one, and the reset at `RCV.NXT` to still close.

Fail-first, by six sabotages, each restored before the next, each failing
exactly its own subject. Removing the block entirely fails all five new tests
plus the moved `test_established_rst_bad_seq`. Challenging every reset that is
not at `RCV.NXT`, rather than only in-window ones, fails exactly the two
silence tests. Replying without the rate limiter fails exactly the rate-limit
test. Making the right window edge inclusive fails exactly the out-of-window
test. Extending the check to SYN-SENT fails exactly the inherited
`test_syn_sent_rst`; exempting SYN-RECEIVED fails exactly the SYN-RECEIVED test.

Paired release `rnetbench`, which this item's gate requires because the change
is protocol behavior. The first A/B/A came back with the default workload's
transmit median down 7% in B -- and down 6.5% in A2, which carries none of this
code, so the host had changed regimes partway through B and stayed there. That
is the bimodality this tree has hit before: the default workload's rounds land
in one of two modes, around 295-305 or around 320-334 MiB/s, and a block's
median is decided by how many of its five rounds land where. A second bracket
was taken, B2 then A3, and the arms pooled. Five blocks of five rounds per
workload, one unchanged host client throughout, medians:

| Workload | Metric | A1 | B | A2 | B2 | A3 |
|---|---|---:|---:|---:|---:|---:|
| default | RR usec | 56.48 | 57.83 | 58.66 | 55.35 | 58.30 |
| default | RX MiB/s | 164.22 | 159.01 | 160.40 | 161.21 | 160.61 |
| default | TX MiB/s | 325.30 | 302.01 | 304.09 | 328.68 | 300.74 |
| 64 KiB | RR usec | 57.75 | 56.98 | 58.28 | 58.57 | 58.39 |
| 64 KiB | RX MiB/s | 634.24 | 624.90 | 633.97 | 634.22 | 628.75 |
| 64 KiB | TX MiB/s | 1206.34 | 1202.86 | 1228.06 | 1234.89 | 1217.67 |

Pooled over all rounds -- A is 15, B is 10 -- B against A: default RR -1.89 usec,
RX -1.48%, TX +2.81%; 64 KiB RR -0.62 usec, RX +0.00%, TX -0.10%. Mixed sign,
largest excursion 2.81%, inside the 5% throughput and ~5 usec kill criteria, and
the round-level bimodality is split evenly between the arms: 8 of A's 15 default
transmit rounds land in the high mode against 6 of B's 10. Expected, and the
mechanism says why: the new branch is guarded on the control field being RST,
which no benchmark segment sets, and it sits after work `process` does for every
segment regardless, so a steady-state transfer pays one comparison on a field
already in hand.

Gate: three debug and three release `full-test-networking.sh` runs, all six exit
0 with no retries and nothing tolerated. Each carries the netstack's Motor
closure at 554 tests -- 549 plus this patch's five -- and each names all five
along with patch 13's five, patch 12's five, and patch 11's two. Before the
runs: `cargo +nightly fmt` clean, the Motor closure and the broad default
closure (693) both under `-D warnings`, and sys-io and systest clippy identical
to clean `HEAD` in debug and release. Item 4's own additions to the gate -- the
full-OS suites showing unchanged connect-refused, close, and abort behavior --
are `test_half_open_accounting`, whose reset half is the guard that a port
nothing listens on still answers `ECONNREFUSED`, together with
`test_tcp_socket_state_transitions`, `test_channel_teardown`,
`test_simultaneous_open`, and `test_tcp_linger`, which closes with a zero linger
and so tears down by reset; all five pass in all six runs, as they did in the
patch 13 logs this replaced. `test_backlog_growth_and_shrink`,
`test_device_rx_validation`, and `test_neighbor_admission` pass throughout, the
debug three report 34 sys-io self-tests and the release three none, and every
run boots, resolves through its gateway, and carries the ssh session systest
arrives over. Only the plan documents changed between the first debug run and
the last release run.

Item 4 is half landed. Patch 15 completes it with section 4, whose value is
liveness rather than defence -- a blind in-window SYN is already dropped -- and
which reuses the same `challenge_ack_reply` this patch just gave a fourth
caller.

### Patch 15 result, 2026-08-01

A SYN that arrives on a synchronized connection now draws a rate-limited
challenge ACK and changes nothing, irrespective of its sequence number. The
change is one block near the top of `Socket::process`, ahead of the
acknowledgement match; `challenge_ack_reply` gains a fifth caller and nothing
else moves.

**Where it had to go, which is not where the plan said.** The plan put it as a
match arm ahead of the state machine's `_ =>` catch-all. A probe test written
before the change showed why that is the one placement that cannot work: a
rebooted peer's SYN carries no acknowledgement, so `(_, _, None)` -- "every
packet after the initial SYN must be an acknowledgement" -- drops it in the
acknowledgement match, hundreds of lines above the state machine. Its sequence
number is a fresh ISN, so it would fail the window test too. Both are exactly
what RFC 5961 section 4 means by "irrespective of the sequence number", and both
have to be jumped. The plan's placement would have caught only a SYN carrying an
acceptable ACK *and* an in-window sequence number -- a duplicate SYN|ACK, not
the case the patch exists for. Sabotaged in place: moving the block down to sit
beside patch 14's fails the same four tests as deleting it outright.

Two further implementation decisions:

- **SYN-RECEIVED is left out**, which is where this patch and patch 14 part
  company. There a repeated SYN is the ordinary consequence of a lost SYN|ACK --
  the peer asking again -- and the reply it needs is that SYN|ACK, which our own
  retransmit timer already sends. A challenge ACK instead would be a bare ACK to
  a peer in SYN-SENT, which that peer ignores (`:1673-1683` after this patch,
  the arm that exists because Linux ignores it), so it buys nothing and spends
  the challenge budget of a socket that has yet to accept. RFC 9293 words the
  SYN-RECEIVED case as "return to LISTEN if the connection was initiated with a
  passive OPEN", not as a challenge; implementing *that* would hand an off-path
  SYN the power over a pending accept that patch 14 just took away from an
  off-path reset, so it is a deliberate divergence, not a rounding error.
- **A SYN no longer extends TIME-WAIT.** It used to reach the acceptability
  test, whose out-of-window path restarts the closing timer on the theory that
  the peer has not realized we closed. A peer redialling the tuple is the
  opposite situation -- it is the one case RFC 9293 names for this state -- so
  holding the tuple down longer is precisely wrong, and it also removes a way
  for a stranger to pin a TIME-WAIT socket indefinitely. Same shape as patch
  14's early return, and tested the same way.

What the patch buys is liveness, not defence: a blind in-window SYN was already
dropped rather than acted on. The peer it helps is one that rebooted and is
dialling the same 4-tuple again. Its SYN used to vanish in silence, leaving our
half of a connection it has forgotten to sit here until a keepalive noticed --
and `keep_alive` is off by default, so possibly forever. Now our challenge ACK
acknowledges the connection the peer lost; a peer in SYN-SENT answers an ACK it
cannot place with a reset seeded from that acknowledgement, which is our
`RCV.NXT` exactly, which is the one sequence number patch 14 accepts a reset at.
The two patches interlock: section 3 is what makes section 4's recovery land.
`test_established_syn_recovers_a_rebooted_peer` walks the whole loop, ending
with the peer's next SYN drawing our SYN|ACK on the same tuple. Motor is
that peer too, which closes the loop for Motor-to-Motor: the fork's own
SYN-SENT arm answers an unplaceable ACK with `rst_reply`, which seeds the
reset's sequence number from the ACK field it could not place.

Five netstack regressions, no existing test changed (554 to 559): the challenge
for a SYN with a fresh ISN and again for one that passes both checks; the
one-per-second limit; the rebooted-peer recovery end to end; the SYN-RECEIVED
exclusion; and the TIME-WAIT challenge with the timer asserted unmoved. Six
sabotages, each failing exactly its own subject -- deleting the block, dropping
the rate limit, extending it to SYN-RECEIVED, to SYN-SENT (thirteen inherited
handshake tests), to LISTEN (fifteen, plus this patch's recovery test, which
ends by listening again), and the plan's placement.

Paired release `rnetbench`, A/B/A, five rounds per workload per block, one
unchanged host client, medians:

| Workload | Metric | A1 | B | A2 |
|---|---|---:|---:|---:|
| default | RR usec | 53.77 | 52.84 | 54.37 |
| default | RX MiB/s | 160.61 | 162.41 | 162.15 |
| default | TX MiB/s | 328.40 | 323.79 | 317.06 |
| 64 KiB | RR usec | 55.90 | 54.06 | 57.08 |
| 64 KiB | RX MiB/s | 645.07 | 647.66 | 649.35 |
| 64 KiB | TX MiB/s | 1232.65 | 1238.54 | 1245.24 |

B is bracketed by the two A blocks on all six, so unlike patch 14 no second
bracket was needed. Pooled (A n=10, B n=5), B against A: default RR -1.50 usec,
RX +0.64%, TX -0.50%; 64 KiB RR -2.43 usec, RX -0.00%, TX -0.24%. The host's two
regimes show up within blocks as usual and split evenly between the arms -- 7 of
A's 10 default TX rounds in the high mode against 3 of B's 5. Expected: the new
branch reads a control field already in hand and no benchmark segment sets it.

Gate: three debug and three release `full-test-networking.sh` runs, all six exit
0 with no retries and nothing tolerated, on a `tcp.rs` whose md5 was checked
unchanged at the end. Each carries the Motor closure at 559 -- 554 plus this
patch's five -- and names all five along with patch 14's five, 13's five, 12's
five, and 11's two. Before the runs: `cargo +nightly fmt` clean, the Motor and
the default closures (698) both under `-D warnings`, and sys-io and systest
clippy identical to clean `HEAD` in debug and release. Item 4's own gate
addition -- the full-OS suites showing unchanged connect-refused, close, and
abort behavior -- is `test_half_open_accounting` with
`test_tcp_socket_state_transitions`, `test_channel_teardown`,
`test_simultaneous_open`, and `test_tcp_linger`; all five pass in all six runs,
as they did for patch 14. `test_backlog_growth_and_shrink`,
`test_device_rx_validation`, and `test_neighbor_admission` pass throughout, the
debug three report 34 sys-io self-tests and the release three none, and every
run boots, resolves through its gateway, and carries the ssh session systest
arrives over.

Item 4 is complete, and with it the RFC 5961 work: section 5's ACK range and
rate limiter were already in the fork, section 3 is patch 14, section 4 is this
one. PAWS is the remaining piece of that family and sits in Step 10 item 2,
where enabling timestamps pays for itself against the RTT work. Next is patch
16, which starts item 3 in `rt.vdso`.

## Item 3 -- ISN and ephemeral-port generation (patches 16-19)

### Verified state

- ISNs come from one PCG32 per interface (`N/rand.rs:9-39`,
  `N/iface/interface/mod.rs:131`, `:228`, `:863-864`), consumed through
  `Socket::random_seq_no` (`N/socket/tcp.rs:1059-1062`). Consecutive connections
  are consecutive PRNG outputs, so a peer that opens a few connections can
  recover the state. No RFC 6528 per-connection hashing. Corrected by patch 18:
  the ISN is now a SipHash-2-4 of the 4-tuple under a per-interface key plus a
  4-microsecond timer, in `N/iface/interface/tcp.rs`'s `tcp_isn`. The PCG32
  stays, and still generates IPv4 identifiers and DNS transaction ids.
- The seed is boot wall-clock nanoseconds (`SI/device.rs:402-405`). Corrected by
  patch 17: it is now one hardware draw per device, in `SI/device.rs`'s
  `random_seed`, since patch 18 `random_bytes`.
- Ephemeral ports are allocated as the lowest free port from 49152, for both TCP
  and UDP (`SI/device.rs:562-576`, `:595-613`).
- `random_seq_no` is a constant 10000 under `cfg(test)` (`N/socket/tcp.rs:1055-1057`),
  which the netstack's ~6600 lines of TCP tests depend on. Any change must keep a
  deterministic test path. Patch 18 kept it, renamed to `initial_seq_no`.

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

*Half of D3's diagnosis is wrong, found while implementing this. RDRAND writes
zero to its destination whenever it clears CF, and `_rdrand64_step` passes that
through, so `val == 0` was in fact a correct detector of a failed draw and no
garbage was ever accepted. What was wrong was the response: a transient DRNG
underflow killed the process instead of being retried, and the 2^-64 legitimate
zero was killed along with it. The fix shape is unchanged. Recorded in the patch
16 result below.*

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

Patch 16 gates on the repository-wide `src/tests/full-test.sh` rather than the
networking subset the rest of Step 6 uses. `rt.vdso` is linked into every Motor
process, and what the subset drops is exactly the rush and rmux coverage --
processes like any other, and ones whose hasher seeds call the function this
patch rewrites.

### Patch 16 result, 2026-08-01

`fill_random_bytes` now reads RDRAND's carry flag instead of discarding it,
retries a failed draw up to ten times, and panics with a clear message only
after ten consecutive failures. No fallback to a weaker source: callers key
hashes and ciphers with these bytes.

D3's diagnosis was half wrong, which is worth recording because the wrong half
is the scarier-sounding one. There was never any garbage: RDRAND writes zero to
its destination whenever it clears CF, and `_rdrand64_step` passes both through,
so the old `val == 0` test detected a failed draw correctly. The defect was
entirely in the response -- a transient DRNG underflow, which the Intel SDM says
to retry, killed the calling process instead, and so did the one-in-2^64
legitimate zero. The fix shape decided in review needed no change.

The retry is the AGENTS.md-sanctioned kind: a documented transient external
failure, with the 2026-07-29 review as the prior approval that rule requires.
Ten draws is the SDM's own figure.

Tests: `test_random_bytes` in systest, in the main suite. Per the plan, the
retry path itself needs a seam over the intrinsic to reach and is reviewed
rather than tested; the test targets what the patch actually restructured --
the tail copy at sizes that are not a multiple of eight, the byte past the
caller's buffer, a zero-length call, one fresh draw per chunk, and a fresh draw
per call, the last two established by comparing chunks within a call and buffers
across calls.

Three sabotages, each failing exactly its own assertion: writing two bytes where
one was asked for trips the guard byte, stopping a chunk short trips the
last-byte check, and drawing once before the loop instead of once per chunk
trips the chunk comparison. A fourth attempt survived and deserved to -- it
hoisted the `val` *declaration* out of the loop, which changes nothing, because
the retry loop still calls RDRAND once per chunk. Recorded because a survivor is
worth a second look at the sabotage before it is called a gap in the test.

Gate: three debug and three release `full-test.sh` runs, all six exit 0 with no
retries and nothing tolerated, on sources whose md5s were checked unchanged at
the end. Each names `test_random_bytes` and carries 22 host-side and in-VM
test-result lines -- among them the rmux and rush suites this harness has and
the networking one does not, and the netstack's 559 unchanged from patch 15.
Before the runs: `cargo +nightly fmt` clean, the Motor-target debug and release
builds, and `rt`, systest, and sys-io clippy identical to clean `HEAD` in debug
and release. Networking is unaffected as expected: `test_half_open_accounting`,
`test_tcp_socket_state_transitions`, `test_channel_teardown`,
`test_simultaneous_open`, and `test_tcp_linger` pass in all six, the debug three
report 34 sys-io self-tests, and DNS and the flush stress test pass throughout.
No `rnetbench` A/B: this touches no data path, only a call each process makes at
startup.

Patch 17 is next, and this is what unblocks it -- one `fill_random_bytes` per
device at initialization, which until now would have inherited the panic.

### Patch 17 result, 2026-08-01

Every interface's PRNG seed is now drawn from the CPU's hardware RNG instead of
the boot wall clock. `random_seed` takes eight bytes through
`moto_rt::fill_random_bytes` -- one RDRAND, per device, at initialization -- and
`NetDev::new`'s inline configuration moved into `iface_config` so that the seed
has exactly one source. Nothing on a packet or connection path changed.

What this closes, stated narrowly. The seed was `SystemTime::now()` nanoseconds,
so an off-path peer who knows roughly when the machine booted searched a small
range offline for the state behind every ISN and IPv4 identifier that interface
would ever emit; it also meant two interfaces initialized microseconds apart got
seeds differing only in their low bits. Both are gone. What is *not* gone is the
generator: consecutive connections remain consecutive PCG32 outputs, so a peer
that can open a few of them still recovers the state whatever it was seeded
with. Patch 18's per-connection hashing is what fixes that, and this patch is
what gives its key a source. The doc comment on `random_seed` says so, because a
reader who sees "hardware entropy" and stops there would draw the wrong
conclusion about the ISNs.

Test: `net::device::interfaces_do_not_share_a_seed`, a sys-io self-test, taking
eight configurations the way eight devices would and requiring their seeds to be
distinct. It checks the high 32 bits separately, because that is where a
clock-derived seed betrays itself: wall-clock nanoseconds advance through the
low bits, so draws moments apart share their top half for seconds at a time.
Both checks are probabilistic only in the sense that any test of an RNG is --
against a working source each fails with probability below 1e-8. The suite is 35
tests, up from 34.

The self-test is where the plan's "two interfaces constructed in the same
process" ends up, and the reason it tests configurations rather than
`Interface`s is that the netstack's PRNG is `pub(crate)`: a constructed
`Interface` will not tell sys-io what it was seeded with. `iface_config` is the
single call site of `random_seed`, so what two configurations show is exactly
what two devices get.

Fail-first, by sabotage in both directions, each rebuilt and booted with sys-io
still serving. Restoring the wall-clock seed fails on the high half --
`draws 0 and 1 share a seed's high half: 0x18c7d189`, and 0x18c7d189 times 2^32
is nanoseconds since the epoch, which is the defect naming itself. Caching one
draw and handing it to every interface fails on the seed itself,
`draws 0 and 1 share a seed: 0x361b92841199eb6d`. Each sabotage fails exactly
one of the two checks, so neither is redundant.

Live evidence through the production path, with the temporary log removed before
the gate: the two real devices took `0x4c2757041b259f58` (`loopback`) and
`0xe25c7455d54433a4` (`net0`), drawn at 606 ms and 613 ms into the boot, one
millisecond before each device's "Initializing net device" line. Distinct, and
neither is clock-shaped. Boot cost is below the log's millisecond resolution,
which is what one RDRAND per device should look like.

Gate: the exact patch-17 source state passed `cargo +nightly fmt`, Motor-target
debug and release builds, debug and release sys-io clippy identical to clean
`HEAD` -- the same 41 debug and 37 release diagnostics at the same sites, off by
the one line this patch adds to `net.rs` -- both netstack closures with warnings
denied (559 plus 7 and 698 plus 7 tests, unchanged because the netstack is
untouched), and three consecutive debug plus three consecutive release
`full-test-networking.sh` runs, all six exiting 0 with no retries and nothing
tolerated. The two sources' md5s were checked unchanged at the end. All six
contain the netstack closure's 559 tests, `test_random_bytes`,
`test_simultaneous_open`, `test_half_open_accounting`,
`test_backlog_growth_and_shrink`, `test_neighbor_admission`,
`test_device_rx_validation`, a negative DNS query returning `NotFound` directly,
and all four flush-stress workers completing 4,000 iterations; the debug three
report 35 sys-io self-tests with 0 failures and the release three none, which is
what a release sys-io with no self-test code in it should show.

No paired `rnetbench` A/B: the gate list does not ask for one, and nothing on a
packet or connection path changed -- the draw happens once per device, before
the interface exists.

### Patch 18 result, 2026-08-01

Initial sequence numbers are now RFC 6528's `ISN = M + F(4-tuple, key)`. `F` is
SipHash-2-4 in a new `N/siphash.rs`, keyed per interface from
`Config::tcp_isn_key`; `M` is the interface's own clock rounded to the RFC's
four microseconds. `Socket::random_seq_no` became `initial_seq_no` and takes the
two endpoints, since the number now depends on them; both of its call sites
already had the tuple in hand. sys-io draws the key from
`moto_rt::fill_random_bytes` in `iface_config`, alongside patch 17's seed.

What this closes. The netstack drew every ISN from one PCG32 per interface, and
that generator is linear: a peer that opens a handful of connections recovers
its state and can then predict the sequence numbers of connections it cannot
see, including ones between two other machines. Patch 17 gave that generator an
unguessable seed, which does nothing about this -- the state is recoverable from
the outputs whatever it was seeded with, which is why the two patches only
matter together. Now each number is a point of a keyed function of its own
4-tuple: connections a peer is allowed to see say nothing about the ones it is
not, and the key never leaves the process.

What it does not close: ephemeral ports are still allocated lowest-free, so the
local port of the next outbound connection remains guessable. That is patch 19,
and it is the last of item 3.

Two decisions worth recording.

The key is drawn separately rather than derived from `Config::random_seed`.
Deriving it would have been one fewer field and is exactly wrong: the seed's
generator is the one whose state a peer can recover, so a key derived from it
would be recoverable too, and the hash would be keyed by a value the attacker
holds. The seed is not a secret and the netstack does not treat it as one -- it
still drives IPv4 identifiers and DNS transaction ids. `Config::tcp_isn_key`
says so in its doc comment, next to `random_seed`, because the two fields look
alike and are not.

SipHash-2-4 rather than a hash from `core::hash`. `Hasher`'s output is not
specified to be any particular function, so it cannot be checked against
published vectors and can change under the crate on a compiler upgrade. A PRF
whose whole security argument is "the peer cannot invert it" needs to be the
function it claims to be, and SipHash is specified down to the byte. It is also
what Linux and the BSDs use for this. The primitive is about 120 lines and runs
eight SipRounds per IPv4 connection -- two per message block, two for the length
block, four to finish.

Tests. Five new netstack tests: `siphash::tests::reference_vectors` checks all
64 published vectors from the reference implementation's `vectors.h` -- every
message length from 0 to 63 under the paper's key -- and four in
`iface::interface::tcp::tests` cover the generator: the key changes the number,
every one of the 4-tuple's four fields changes the number, an interface hands
numbers out under the key it was configured with, and the same tuple advances by
exactly one tick per four microseconds. One new sys-io self-test,
`net::device::interfaces_do_not_share_an_isn_key`, takes eight configurations
the way eight devices would and requires distinct keys, which catches both a key
shared between interfaces and one left at the all-zero default; the suite is 36,
up from 35. `initial_seq_no` keeps its `cfg(test)` constant, so the netstack's
~6600 lines of TCP tests are untouched.

Fail-first, by sabotage, one at a time and each rebuilt:

| Sabotage | Fails |
|---|---|
| SipHash-2-4 absorbs with one round instead of two | `reference_vectors`, at the empty message |
| `tcp_isn` hashes under a fixed key | `the_key_changes_the_number` |
| the 4-tuple omits both ports | `every_tuple_field_changes_the_number` |
| the ISN drops the `M` term | `the_same_tuple_advances_with_time` |
| `Interface::new` ignores `config.tcp_isn_key` | `the_interface_uses_its_configured_key` |
| `iface_config` leaves the key at its default | `interfaces_do_not_share_an_isn_key`, live in a booted sys-io, naming the all-zero key |

Each fails exactly one test and none fails a test outside its own subject. The
last two are the reason both exist: keying `tcp_isn` and delivering the
configured key to the interface are separate failures, and a sabotage of either
leaves the other's test passing.

The implementation was also checked against an independent reimplementation of
SipHash-2-4 written from the specification, on the published vector and on the
tuple this patch actually hashes. That is what makes the 64-vector table
evidence about the code rather than about my recollection of the table.

Live evidence through the production path, with the temporary log removed before
the gate: `loopback` took key `ff8b8ae1b9a203e986df8933ff1ad657` at 590 ms into
the boot and `net0` took `1a16d47e7b24f7152e342462c284e696` at 597 ms, each two
milliseconds before its "Initializing net device" line. Distinct, neither zero.
Boot cost stays below the log's millisecond resolution: the patch adds two
RDRANDs per device to patch 17's one.

Paired same-host release `rnetbench`, four blocks of five rounds with one
unchanged host client (medians; A = clean `HEAD`, B = prepared). Four rather
than three because the host's default-workload bimodality showed up mid-run:

| Workload | A1 | B | A2 | B2 |
|---|---:|---:|---:|---:|
| default RR (usec) | 55.18 | 57.83 | 59.03 | 55.29 |
| default RX (MiB/s) | 161.33 | 139.55 | 141.54 | 158.83 |
| default TX (MiB/s) | 325.69 | 297.71 | 293.66 | 322.31 |
| 64 KiB RR (usec) | 58.29 | 58.07 | 57.71 | 57.42 |
| 64 KiB RX (MiB/s) | 639.05 | 634.90 | 627.71 | 631.42 |
| 64 KiB TX (MiB/s) | 1211.33 | 1231.08 | 1208.30 | 1208.03 |

The default workload visited both of this host's regimes, and both trees visited
both: A1 and B2 are fast, B and A2 are slow. The same-tree pairs are what settle
it -- A2 against A1 is RX -12.27% / TX -9.83% with no code difference at all,
and B2 against B is RX +13.82% / TX +8.26%, also with none. Any patched-versus-
clean number that straddles the regimes is measuring the host. Within a regime:
B against A2 is RR -1.20 usec / RX -1.41% / TX +1.38%, and B2 against A1 is RR
+0.11 usec / RX -1.55% / TX -1.04%. The 64 KiB workload is not bimodal and all
four blocks agree to within 1.9% with mixed sign. Every within-regime excursion
is under 2%, well inside the kill criteria of 5% throughput and ~5 usec RR. The
benchmarked block-B image was later reproduced byte-for-byte from the final
source, so this is a measurement of the shipped bits.

Read honestly, though, `rnetbench` says little about the cost this patch
actually adds. Its RR test opens one connection and loops on it for five
seconds, so a whole round exercises connection setup about three times: what the
A/B/A/B shows is that the data path is untouched, which is what the code says
too. The setup cost itself is eight SipRounds over twelve bytes, against a SYN
exchange that the RR number puts at tens of microseconds -- too small to appear
in any benchmark here, and one hash per SYN on the listen side, which patch 9's
half-open cap already bounds.

At 417 lines added over 32 removed this is past the 100-300 guideline,
deliberately. 66 of them are the published vector table and about 150 are tests,
which leaves roughly 200 lines of code. The natural split -- the
primitive, then its use -- would land a module nothing calls, and the only other
seam is between the netstack's hash and sys-io's key, which would leave an
all-zero key in the tree between the two patches. A larger patch is the better
of those.

Gate: the exact patch-18 source state passed `cargo +nightly fmt`, Motor-target
debug and release builds, debug and release sys-io clippy identical to clean
`HEAD` in both messages and sites -- 41 debug and 37 release diagnostics,
captured on both sides from a wiped target directory -- both netstack closures
with warnings denied (564 plus 7 and 703 plus 7 tests, each five more than patch
17's), and three consecutive debug plus three consecutive release
`full-test-networking.sh` runs with no retries and nothing tolerated. The six
sources' md5s were checked unchanged at the end.

The first attempt at those six runs failed in the first debug run, on
`the_interface_uses_its_configured_key`, and the cause was the fail-first
tooling rather than the patch: the sabotage script restored each file with `mv`,
which gave it an mtime older than the sabotaged build cargo had already
fingerprinted, so cargo kept serving the sabotaged object code. The tell was
that the failure's two numbers were byte-identical to the sabotage's, and an
independent computation of both ISNs confirmed the interface was using the
all-zero key that sabotage had installed. Everything captured after the
sabotages was re-established from forced-fresh compiles -- both netstack
closures, both clippy profiles from wiped target directories, and a full rebuild
of the release image that reproduced the benchmarked initrd byte-for-byte -- and
the recorded gate is the rerun. The script now touches what it restores.

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
