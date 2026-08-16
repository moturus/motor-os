# Netstack scalability: the egress path and the O(N) structures

Picked up 2026-08-16 on the user's go-ahead; the user runs the
benchmarks and owns every performance verdict (Method in
`networking-remaining-steps.md`). Input signal, recorded there: 64
parallel streams hold ~660 MiB/s aggregate each way with a 5x
per-stream fairness spread (tiers near 6 / 13 / 30 MiB/s) -- the
egress/subchannel-packing path.

## What the code does today

- `socket_egress` (`iface/interface/mod.rs`) walks every socket in
  ascending id order once per pass; each ready socket emits one packet
  per visit. `poll()` repeats passes until one emits nothing, so K
  packets from one socket among N sockets cost (K+1)xN dispatch calls.
- On device exhaustion the pass breaks -- and the next pass restarts
  at the lowest id. Ids are allocation-ordered and never reused, so
  earlier-created connections get first claim on the TX ring on every
  pass. This is the mechanical explanation on offer for the observed
  fairness tiers; the fix is worth landing regardless.
- `poll_at` recomputes over all sockets. sys-io calls it (via
  `poll_delay`) on every idle edge of the device loop
  (`runtime/net.rs`), so request/response workloads with many
  connections pay O(N) per quiescence.
- Neighbor lookups are a `heapless::LinearMap` scan -- consulted per
  socket per egress pass (`egress_permitted`) and per emitted packet;
  route lookup walks a `Vec` per emitted packet.
- The TCP assembler holds `ASSEMBLER_MAX_SEGMENT_COUNT = 4` contiguous
  runs; the overflow storm drops segments (behavior pinned by the
  crafted-packet tests 2026-08-16).

## Increments, in order

Each lands as its own 100-300 line gated commit (fmt, zero new
warnings, 3 debug + 3 release full-test-networking runs). The user
benchmarks after landing; nothing here gates on a number I produce.

1. **Egress round-robin cursor** (the fairness fix). The interface
   remembers where the next pass starts. A pass that breaks on device
   exhaustion at socket X resumes at X -- the socket that was refused
   goes first; a completed pass advances past the last socket that
   transmitted. Iteration becomes
   `range(cursor..).chain(range(..cursor))` over the same BTreeMap.
   No structure change, no behavior change beyond service order.
   Deterministic test: a bounded-TX device and three streams; assert
   service rotates instead of restarting at the lowest id.

2. **Cached per-socket `poll_at` + readiness/timer index** (the
   "egress ready-list" and "timer wheel" of the remaining-steps doc,
   one invariant). `Meta` gains the socket's `PollAt` as of its last
   resync; the `SocketSet` keeps two indexes over it: the ready set
   (`PollAt::Now`) and a timer order (`BTreeMap<(Instant, id)>` --
   a sorted map, not a literal wheel; O(log N) at our socket counts).
   The invariant mirrors the demux one and reuses its resync sites:
   every path that can change what a socket would transmit re-derives
   the cached value -- the SocketSet ops, process/dispatch in the
   interface loops, plus `get_mut` (the one door to every user-side
   mutation: send/recv/close/abort/options), which conservatively
   marks the socket stale for recomputation at the next poll entry.
   Neighbor-cache fills mark the sockets waiting on that neighbor
   stale (waiting set tracked alongside; discovery is rare and
   bounded). A debug oracle recomputes every socket's true `poll_at`
   per poll and asserts index agreement -- the retired O(N) scan
   lives on as the oracle, exactly like the demux series did it.

   Landing order inside the increment, each patch separable:
   a. the cache, the stale marking, and the oracle, dark -- the old
      O(N) loops stay authoritative while every debug gate verifies
      the index against them;
   b. `poll_at()` reads the index (min of ready/first timer);
   c. `socket_egress` iterates only the ready set (cursor fairness
      from increment 1 carried over); sockets whose timers expired
      join via the timer order's `<= now` prefix. Steady-state bulk
      keeps today's cost shape: a socket that just emitted stays
      ready without recomputation, and only the dispatch that emits
      nothing pays one `poll_at` to leave the set;
   d. delete the dark-launch scaffolding the oracle has replaced.

3. **Neighbor and route table structures.** Neighbor `LinearMap` to a
   keyed map with the same admission and eviction policy; routes from
   a per-packet `Vec` walk to a longest-prefix order computed at
   `update()` time. Both behavior-preserving; both small.

4. **Allocating interval-list assembler.** Replace the 4-run array
   with a growable interval list under an explicit bound sized to the
   receive ring (a few percent burst loss in a 128 KiB window already
   needs ~12 holes -- the multi-loss test documents it). The
   overflow-storm tests keep their scenarios; the assertions move to
   the new bound. WAN/loss work is in scope per the product rulings.

## Explicitly not in this series

- **The two TCP state enums** (7-variant client ABI vs 11-variant
  protocol enum): needs an ABI compatibility story -- a user
  decision, parked in the remaining-steps doc.
- **Zero-copy tokens** and the **per-page BTreeMap store swap**: both
  stay profile-gated fallbacks; nothing here forecloses them.

## Risks and their controls

- Single-stream throughput must not regress (performance only goes
  up). Control: increment 2c's rule above -- the hot bulk path gains
  no per-segment recomputation; the index is maintained at event
  edges, not per packet. The user's benchmarking is the verdict.
- A missed resync in increment 2 means a socket that never sends
  again -- the same failure class the wedge fix just closed. Control:
  the conservative `get_mut` stale door plus the per-poll debug
  oracle; every debug gate run exercises it across the whole suite.
- Service-order changes (increments 1, 2c) can shift test
  expectations that encoded id-order accidentally. Control: fix such
  tests to assert the contract (all sockets served) rather than the
  order, in the same patch, called out in the commit message.
