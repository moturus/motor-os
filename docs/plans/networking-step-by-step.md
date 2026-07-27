# Networking work: authoritative step-by-step plan

2026-07-26. This document is the execution order and status ledger for:

- `docs/plans/core-networking-rewrite.md`
- `docs/plans/tcp-receive-window.md`
- `docs/plans/virtio-rx-coalescing.md`
- `docs/plans/vdso-rewrite.md`

The companion documents remain the detailed design references. Where their
sequencing conflicts with this document, this document wins. Every networking
commit must update the status below and adjust a companion plan when the
commit changes one of its facts, decisions, measurements, or remaining work.

## Current status

Overall state: **in progress**.

Current step: **1 -- audit packet- and client-reachable aborts in the sys-io
network runtime**.

Completed:

- Reviewed the four companion plans together and checked their central claims
  against the current tree.
- Committed this authoritative execution order as `5e66e52a`.
- Corrected the companion plans' window-scale, socket-lifecycle,
  receive-checksum, flaky-gate, benchmark-script, and missing-safety-step
  statements.
- Audited the historical 8-of-10 debug `full-test.sh` record. Its Run 4
  tokio/network hang was the RX-task self-deadlock fixed by `812e7daf`. Its
  Run 7 DNS-negative-path/russhd empty-output failure was not root-caused or
  shown to be fixed.
- Found that `stress-soak.sh` explicitly tolerates a UDP `AlreadyInUse`
  port-reuse race in resilient mode. This is a tracked product defect, not an
  acceptable test-gate policy.
- Received guidance to prioritize the remotely triggerable packet panic while
  retaining both unresolved defects at their applicable gates.
- Investigated the `concurrent_flush_stress_test` stall. The failed run ended
  with a submitted virtio block flush for which no device completion was
  logged. It did not reproduce in 20 focused runs (640,000 explicit flush
  calls) or a fresh monitored ordinary debug suite. Those runs crossed the
  virtqueue index wrap repeatedly, so neither a deterministic flush defect nor
  an index-wrap defect is supported by the evidence.
- Corrected the independent `moto_async::Parker` ordering defect in
  `22045e38`. The NOTIFIED fast path now consumes a notification with an
  acquire/release RMW instead of a plain store that could erase a concurrent
  notification without acquiring its publication. The redundant-wake systest
  covers notification coalescing on that path.
- Added a focused systest subcommand for any future flush-stall investigation.
- Replaced the packet-triggered TCP connect-state aborts with exhaustive,
  deterministic pending, connected, and failed transitions. The state/action
  verification is a compile-time `const fn` check and adds no boot work.
- The exact source state containing the Parker fix and prepared Step 1 TCP
  patch passed focused debug/release builds and clippy, then three ordinary
  debug and three ordinary release `full-test.sh` runs without a tolerated
  failure. All six flush stress tests completed all 4,000 iterations per
  worker.

Unresolved investigation finding:

- The Parker defect is established from the atomic state machine, but is not
  proven to have caused the flush stall.
- The original stall was not captured live. Its final serial evidence is
  compatible with an unconsumed virtio request, a QEMU/host flush stall, or a
  stopped VM. The missing watchdog output traveled through the same QEMU
  network/stdio path and cannot distinguish those cases.
- No speculative virtio, timeout, retry, or test-relaxation change is
  proposed. On recurrence, capture the QEMU process state/stack, VM monitor
  CPU state, systest/sys-io stacks, and virtqueue indices before terminating
  the run.

## Rules for every step

1. Keep patches near 100-300 lines including tests. Split larger work unless a
   mechanical transition genuinely cannot build in smaller pieces.
2. Add each test to `src/tests/full-test.sh`, directly or through a suite that
   it already invokes.
3. Before every commit, run `cargo +nightly fmt`, the relevant build and
   clippy checks, and `src/tests/full-test.sh` three times each in debug and
   release. A documentation-only planning commit does not require rebuilding
   unchanged code.
4. Do not accept a pass percentage, retry away a failure, lengthen a timeout,
   or ignore a known signature. Diagnose the defect.
5. Use paired, same-host performance measurements around every data-path or
   protocol-behavior change. Rebaseline after an intentional ceiling change.
6. Stop for guidance on every decision gate below and on any newly discovered
   preexisting defect.
7. Do not begin a later step while an earlier step's required gate is open.

## Corrections that govern execution

These corrections must be reflected in the companion documents as their
affected steps are updated.

- Core networking Step 1, the remotely reachable sys-io panic, is the first
  production patch. It precedes the remaining vDSO Stage 2 work.
- The core plan needs explicit work items for its P2/P3 findings and ARP
  exhaustion. Regression bullets alone do not schedule fixes.
- The TCP per-socket option design is not implementable through the current
  outbound API: `tcp_connect(addr, timeout, nonblocking)` returns the FD only
  after connection setup has begun. That step requires a reviewed design
  before implementation.
- A 128 KiB smoltcp receive buffer selects window shift 2, not 1; 512 KiB
  selects shift 4.
- The TCP default must not be raised before the listen path caps half-open
  sockets and avoids eagerly committing the full buffers to each SYN.
- Receive coalescing depends on correct per-packet handling of the virtio-net
  RX header. `GUEST_CSUM` does not justify globally trusting unflagged frames.
- Coalescing Step 0 provides feature, queue-depth, and baseline evidence. It
  cannot by itself decide whether large frames reach the guest; Steps 0 and 1
  together answer that.
- `src/vm_scripts/run-qemu.sh` is tracked and copied into the ignored image
  directory by the build. Benchmark reproducibility instead needs a manifest
  of the host and VM environment.
- A Motor-owned TCP protocol-state enum copied into `moto-sys-io` needs an
  explicit representation and discriminants, compile-time layout assertions,
  and a wire-compatibility test.
- The two TCP state enums model different layers. Consolidating them and the
  deeper socket-store integration remain deferred, separately reviewed work.

## Step 0 -- audit trustworthy gates

Initial audit complete:

1. The historical Run 4 tokio/network hang was fixed by `812e7daf`.
2. Historical Run 7 remains an unresolved negative-DNS/russhd output-delivery
   failure: `expect_ping_error does-not-exist.motor.invalid NotFound` received
   empty output. Do not use an 8-in-10 rule. If this signature recurs in an
   ordinary gate, capture and diagnose it before committing the pending patch.
3. The UDP `AlreadyInUse` race belongs to Step 2 because teardown and address
   release ordering may be relevant. Resilient soak mode must not be used as a
   correctness gate while it tolerates that failure.
4. During the Step 1 gate, the third ordinary debug run stalled in
   `concurrent_flush_stress_test`. Its 45-second budget is checked only after
   each group of 64 completed iterations, so it cannot bound one blocked I/O.
   All four files opened; after hundreds of completed block-device flushes,
   the final `Motor FS: flushing the Block Device` had no matching
   `BD: flushed`. No panic or virtqueue-monitor warning was logged. The absent
   five-second watchdog output cannot show that the watchdog did not run
   because its output depended on the same VM-to-host path.
5. The stall did not recur in 20 focused runs on one VM or one fresh monitored
   ordinary debug suite. One earlier monitored-suite result was discarded
   because a monitor-port collision made its QEMU fail to start and the
   harness attached to a stale focused-test VM.
6. Source review found an independent Parker fast-path ordering defect. Its
   narrow fix is committed with this status update, but causality is
   deliberately not claimed. A virtio change would be speculative without a
   live recurrence.

The performance-record portion moves to measurement Step 7 so it does not
delay the remotely triggerable security fix. At Step 7, add or document a
benchmark manifest containing at least:

   - repository commit and dirty-tree exclusions;
   - debug/release build;
   - QEMU binary and version plus the complete command line;
   - host kernel, CPU model, governor, turbo state, and CPU affinity;
   - tap addresses, qdisc state, and offload state;
   - client/server command lines and binary identities.

Decision gate: a preexisting test-harness or product bug requires user
guidance before its fix is implemented. Guidance was received to investigate
the stall and prepare, but not commit, a fix; review then authorized committing
the Parker fix and continuing with Step 1. The unexplained stall remains
documented for live capture if it recurs.

## Step 1 -- remove the sys-io P0 panic surface

Execute core networking Step 1 as small state-group patches:

1. Replace the connect-state `panic!`/`todo!()` paths with deterministic
   socket closure and client notification.
2. Audit packet- and client-reachable panics in the sys-io network runtime.
3. Add simultaneous-open, batched close, and abnormal-state tests.

Do not combine this with moving the fork or tuning the data path.

Status: substep 1 is complete with this update. Substep 2 is next.

Gate: run the ordinary AGENTS.md checks without retries or tolerated failures.
The historical negative-DNS/russhd empty-output signature must not recur.
Current gate result: focused debug/release builds and clippy checks pass with
only preexisting warnings. The exact source state containing the Parker fix
and prepared TCP patch passed three ordinary debug and three ordinary release
full suites without retries or tolerated failures.

## Step 2 -- finish the vDSO async control plane

Finish vDSO Stage 2:

1. Reproduce and root-cause the UDP `AlreadyInUse` port-reuse race, then add a
   deterministic regression test and remove its resilient-soak exemption.
2. Convert UDP destruction to the teardown queue after confirming queued
   datagram disposition, address release, and ordering.
3. Convert orphan/late TCP connect and accept cleanup.
4. Remove the last `SyncWaiter`, synchronous send/RPC, condvar, and backoff
   machinery only after the last caller is gone.

Decision gate: stop if existing UDP teardown ordering is ambiguous.

## Step 3 -- take ownership of the netstack dependency

Execute only core Step 0(a) and 0(b):

1. Import the fork verbatim, then rename it, then format/lint it in distinct
   commits so ancestry remains reviewable.
2. Replace the foreign enum in `TcpSocketStatsV1` with a stable Motor wire
   enum and test its layout.
3. Repoint sys-io and remove the crates.io patch.

Defer core Step 0(c) and 0(d).

## Step 4 -- trim unused stack features

1. Fix the latent `async` feature configuration defect.
2. Disable default features and enable only Motor's required set.
3. Verify removed fragmentation behavior and all retained IPv4, IPv6, TCP,
   UDP, and ICMP behavior.

Decision gate: confirm whether automatic ICMP echo replies are required.

## Step 5 -- establish packet-facing test and fuzz coverage

Move core Step 5 ahead of further fork behavior changes:

1. Repair the TCP process fuzz target against the current API.
2. Add deterministic regression seeds for window wrapping, abnormal RSTs,
   out-of-order overflow, overlaps, and duplicates.
3. Add a sys-io socket-state harness.
4. Run deterministic coverage through `full-test.sh`; run the time-budgeted
   fuzzer separately as an additional gate.

## Step 6 -- complete core safety hardening

Add reviewed, separately gated core steps for:

1. P3 sequence arithmetic, attacker-influenced assertions, and short RX-ring
   writes that could expose stale contents.
2. Per-packet virtio RX checksum metadata, including unflagged,
   `NEEDS_CSUM`, and `DATA_VALID` cases.
3. ISN and ephemeral-port generation.
4. RFC 5961 RST handling and PAWS/timestamp policy.
5. ARP cache admission, eviction, and request-rate behavior.
6. Bounded half-open sockets, backlog behavior, and lazy/small initial socket
   buffers from core Step 4.

Each item needs a design-sized patch plan before implementation. In
particular, do not expand the receive-offload feature set until item 2 lands.

## Step 7 -- measure the two receive ceilings

Run measurement-only work from:

- TCP receive-window Step 0, including measured RTT and controlled loss; and
- virtio receive-coalescing Step 0, including features, queue depth, and RX
  packet-size/header distributions.

Record exact commands and the Step 0 benchmark manifest.

## Step 8 -- implement receive coalescing

1. Implement coalescing Option A atomically with correct feature negotiation,
   buffer sizing, descriptor accounting, and RX-header validation.
2. Tune queue population and record paired default/bulk RX/TX and RR results.
3. Rebaseline later vDSO work.

Decision gate: identify supported QEMU, Cloud Hypervisor, and Firecracker
versions. If portability requires mergeable buffers, write and review a
detailed Step 3 plan covering continuation-buffer headers, used-ring
completion ownership, gather lengths, malformed counts, and cleanup before
implementing Option B.

## Step 9 -- raise the fixed TCP window, if approved

After bounded/lazy listen allocation exists:

1. Review the measured RTT curve and choose whether a fixed default raise is
   justified.
2. Obtain approval for the established-socket memory budget.
3. Change RX and TX defaults separately if measurement benefits from
   separating their attribution.
4. Repeat clean-path, RTT, and loss measurements.

## Step 10 -- tune TCP loss behavior

Execute core Step 3 as separately measured patches:

1. Enable Reno.
2. Improve RTT sampling before lowering the minimum RTO, or justify a
   path-dependent floor.
3. Raise the out-of-order assembler capacity.
4. Revisit neighbor and route capacities separately from ARP security.

Do not classify a clean-LAN throughput reduction from congestion control as a
regression without the paired lossy-path result.

## Step 11 -- introduce the vDSO wrappers

Execute vDSO Stage 3. Once it lands, re-scope Stages 4 and 5 and update this
document before starting them.

## Step 12 -- redesign per-socket TCP buffer sizing

Before code, decide and review:

- how an outbound socket carries requested sizes before its SYN;
- whether this requires a new native builder, vDSO ABI, or growable rings;
- listener timing and accepted-socket inheritance;
- requested versus effective `getsockopt` values;
- post-connect behavior;
- independent RX/TX floor, cap, units, overflow, and zero semantics.

Then implement TCP receive-window Step 2 in small end-to-end slices.

## Step 13 -- finish the vDSO ownership work

1. Execute re-scoped Stages 4 and 5.
2. Execute Stage 6 only after the full-test flake baseline is clean; require
   the ordinary three passing debug and release runs.
3. Execute Stage 7 and record the final functional and performance gates.

## Step 14 -- measure and decide on architectural netstack work

Execute core Step 6 after all preceding ceiling and boundary changes. Profile
many-connection workloads and decide whether the connection table, ready
list, timer wheel, or allocating assembler is justified.

Decision gate: confirm that server workloads with enough concurrent
connections to justify core Option B are a Motor OS product target. Keep
zero-copy tokens deferred until a profile proves copies dominate.
