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

Current step: **1 -- complete the remaining unusual-state tests**.

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
- Audited the abort-shaped sites in the sys-io networking runtime. The TCP TX
  `todo!()` is unreachable under its current same-closure `can_send()` guard,
  and the UDP receive, TCP accept-state, and buffer-consumption unwraps/asserts
  likewise have local invariants. They should still be made non-fatal in later
  small patches, but are not the next client-triggerable abort.
- Hardened spawned control-task dispatch against the client-disconnect race.
  A queued task is rejected at entry when its client is missing or already
  `shutting_down`. The guard is only on the control-task path, adds no boot
  work, and adds no lookup to the inline TCP TX/RX-ack fast path.
- Added a raw-channel regression that waits for sys-io to account for its
  connection, queues a UDP bind, immediately disconnects, and verifies that
  both active-client and live-UDP-socket gauges return to their stable
  baselines.
- Hardened `full-test.sh` to track the launched QEMU PID, reject SSH success
  after that process exits, and wait for QEMU during cleanup. A negative run
  with an invalid QEMU argument now fails instead of attaching to a stale VM.
- Applied the approved bounded external-transient policy to negative DNS
  self-test queries. Only `TemporaryFailure`, `TimedOut`, and `Busy` are
  retried to the existing 30-second deadline; terminal results return
  immediately and must still be `NotFound`.
- The exact disconnect/harness/DNS source state passed formatting, focused
  debug and release builds, debug and release clippy, and three consecutive
  ordinary debug plus three consecutive ordinary release `full-test.sh` runs.
  There were no retries or tolerated failures; all six disconnect regressions
  passed, and all six flush stress tests completed 4,000 iterations per
  worker.
- Corrected `net.total_clients` to increment its own prior value instead of
  assigning `active_clients + 1`. A two-connection regression proves that the
  counter advances once per accepted client and never falls on disconnect.
- The exact client-counter source state passed formatting, focused debug and
  release builds, debug and release clippy, and three consecutive ordinary
  debug plus three consecutive ordinary release `full-test.sh` runs. There
  were no retries or tolerated failures; all six counter regressions and
  disconnect regressions passed, and all six flush stress tests completed
  4,000 iterations per worker.
- Corrected stale cross-connection TCP accepts. Accept requests from closed
  clients are discarded, ownership transfer validates the destination before
  removing the listener's ownership, and an established socket is returned to
  the pending queue if the accepting client closes during the handoff.
- Added a raw-channel regression with a FIFO control-task barrier. It proves
  that a connection matched to a stale accept remains available to a later
  live accept and that all three client connections are torn down.
- The exact stale-accept source state passed formatting, focused debug and
  release builds, debug and release clippy, and three consecutive ordinary
  debug plus three consecutive ordinary release `full-test.sh` runs. There
  were no retries or tolerated failures; all six stale-accept regressions
  passed, and all six flush stress tests completed 4,000 iterations per
  worker.
- Made shared TCP/UDP socket registration fallible. It now rejects a missing
  or shutting-down client and removes the already-created smoltcp socket
  without incrementing live or total socket counters.
- Made later setup failures transactional: a rejected smoltcp TCP connect
  tears down its registered socket and releases its ephemeral port, while UDP
  bind failures release both the address reservation and any allocated
  ephemeral port.
- Added a raw port-zero TCP connect regression. It proves the request reaches
  post-registration setup by observing one new total socket and proves the
  failure returns the live socket gauge to its exact baseline.
- The exact registration-rollback source state passed formatting,
  Motor-target debug and release builds, debug and release clippy, and three
  consecutive ordinary debug plus three consecutive ordinary release
  `full-test.sh` runs. There were no retries or tolerated failures; all six
  setup-rollback regressions passed, and all six flush stress tests completed
  4,000 iterations per worker.
- Found two listener address-conflict defects while auditing registration.
  Wildcard and specific binds were compared before wildcard expansion, and
  fixed listener ports were absent from ephemeral allocation, allowing a
  later `bind(addr:0)` to select an already-listening port.
- Listener conflict checks now compare the concrete `(address, device)` pairs
  produced by bind resolution in the same runtime borrow that registers the
  listener. Ephemeral listener allocation skips ports reserved by those
  concrete endpoints. This work runs only for listener bind requests and adds
  no boot or packet-path work.
- Added one raw-channel regression that proves a fixed `127.0.0.1:49152`
  listener forces a later port-zero bind to another port, a wildcard listener
  rejects an overlapping specific bind, and the owning client tears down to
  its exact active-client baseline.
- The exact listener-conflict source state passed formatting, Motor-target
  debug and release builds, debug and release clippy, and three consecutive
  ordinary debug plus three consecutive ordinary release `full-test.sh`
  runs. There were no retries or tolerated failures; all six conflict
  regressions passed, and all six flush stress tests completed 4,000
  iterations per worker.
- Made listener pool creation transactional. A creation error is now
  propagated after removing the listener from both runtime ownership maps,
  draining its pending and listening sockets, dropping the final strong
  listener reference, and asynchronously tearing down any partial pool.
- Factored that unregister-first ordering into the cleanup primitive also used
  by an explicit listener drop. This prevents a listening socket's replenish
  task from upgrading its weak reference and recreating a zombie listener.
  The change adds no boot work and no packet-path work.
- A direct partial-pool failure is not currently driveable through the public
  protocol: the single-threaded creation loop does not yield, and its only
  recoverable error requires the already-validated client to disappear.
  With maintainer approval, the existing deterministic cancelled-bind and
  listener-drop tests exercise the shared cleanup path; no production
  failure-injection hook or artificial yield was added.
- The exact listener-pool rollback source state passed formatting,
  Motor-target debug and release builds, debug and release clippy, and three
  consecutive ordinary debug plus three consecutive ordinary release
  `full-test.sh` runs. There were no retries or tolerated failures; both
  cancelled-bind cleanup tests passed in all six runs, and all six flush
  stress tests completed 4,000 iterations per worker.
- Added the simultaneous-open regression. A TCP self-connect drives the
  `SynSent -> SynReceived -> Established` sequence that the original P0
  `panic!` covered, and sys-io's lowest-free ephemeral allocation makes it
  deterministic: the test binds a port-zero listener, releases it, and
  connects to the port the next allocation must return. Confirmed against
  the fork on a standalone loopback interface before it was written.
- Found while gating that regression: closing the self-connected socket
  normally held it for a measured 1.008 seconds, because its own delayed ACK
  is still outstanding, so `close_tcp_socket_inner` lingers rather than
  aborts. The late drop decremented `net.tcp_sockets` under a later test's
  baseline. The regression now closes with `SO_LINGER(0)` and waits until
  sys-io reports no socket on the address, so it perturbs no global gauge.
  sys-io's behavior is correct and unchanged; global-gauge baselines in this
  suite are only valid while nothing else is draining.
- Established that the batched `SYN|ACK + FIN` case is not driveable through
  the public protocol. `CloseWait` during connect requires a peer that emits
  its FIN in the same poll batch as its SYN|ACK, which no in-order loopback
  or ordinary external peer produces: the FIN can only follow our own ACK,
  by which time the connect task has already run. Moving it to the Step 5
  crafted-packet corpus is proposed and awaits confirmation; no artificial
  peer or injection hook was added.
- The exact simultaneous-open source state passed formatting, Motor-target
  debug and release builds, debug and release clippy, and three consecutive
  ordinary debug plus three consecutive ordinary release `full-test.sh` runs.
  There were no retries or tolerated failures; all six simultaneous-open
  regressions passed, all six negative DNS queries returned `NotFound`
  directly, and all six flush stress tests completed 4,000 iterations per
  worker. An unrelated `rmux` pull landed in the working tree during the
  first attempt at this gate, so its six runs did not all build one tree and
  were discarded. The recorded gate is the rerun on committed `8a48bef6`.

Current work:

- Stop after committing the simultaneous-open regression, as requested.
- Confirm the batched-close deferral to Step 5 above before starting Step 2.
- Stop for review if the audit exposes ambiguous ownership or teardown
  ordering.

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
7. The disconnect-patch gate reproduced the stale-VM harness defect without a
   monitor: a previous VM still held `moto-tap`, the new QEMU exited, and
   `full-test.sh` connected to the old VM and ran its old `systest`. That run
   is discarded. Guidance approved fixing the harness by checking the
   launched process and waiting for it during cleanup before restarting the
   gate.
8. The next restarted gate received no upstream response for a negative DNS
   query, so the resolver correctly returned transient `TimedOut` while its
   self-test incorrectly required immediate `NotFound`. Guidance approved
   applying the self-test's existing bounded external-failure policy to these
   negative queries. That failed run is also discarded.

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
the Parker fix and continuing with Step 1. Later guidance authorized the
stale-VM harness and DNS self-test fixes above. The unexplained stall remains
documented for live capture if it recurs.

## Step 1 -- remove the sys-io P0 panic surface

Execute core networking Step 1 as small state-group patches:

1. Replace the connect-state `panic!`/`todo!()` paths with deterministic
   socket closure and client notification.
2. Audit packet- and client-reachable panics in the sys-io network runtime.
3. Add simultaneous-open, batched close, and abnormal-state tests.

Do not combine this with moving the fork or tuning the data path.

Status: substep 1, the first substep 2 hardening patches, and the independent
`net.total_clients` accounting correction are complete. The accept path now
also rejects stale destination clients without losing an established socket.
Socket registration and TCP/UDP setup rollback are also fallible and
transactional. Resolved listener endpoint conflicts and ephemeral listener
port collisions are corrected. Listener registration and partial pool
creation are transactional. Substep 3's simultaneous open is covered by a
deterministic self-connect regression; its batched `SYN|ACK + FIN` case
cannot be produced by any in-order peer, so moving it to the Step 5
crafted-packet corpus is proposed. The remaining connect-task terminals --
refused, timed out, and gracefully closed -- are already covered by existing
TCP tests, so substep 3 is complete once that move is confirmed.

Gate: run the ordinary AGENTS.md checks without retries or tolerated failures.
The historical negative-DNS/russhd empty-output signature must not recur.
Current gate result: formatting, focused debug/release builds, and
debug/release clippy pass with only preexisting warnings. After correcting the
approved harness and DNS self-test defects, the exact disconnect-patch source
state passed three consecutive ordinary debug and three consecutive ordinary
release full suites without retries or tolerated failures. All six
disconnect regressions passed, and all six `concurrent_flush_stress_test`
runs completed 4 x 4,000 operations. The subsequent client-counter patch also
passed focused debug/release builds and clippy plus three consecutive debug
and three consecutive release full suites. All six counter and disconnect
regressions passed, and all six flush stress tests completed 4 x 4,000
operations. The stale cross-connection accept patch passed the same focused
checks and three consecutive debug plus three consecutive release full
suites. All six stale-accept regressions passed, and all six flush stress
tests completed 4 x 4,000 operations. The socket-registration rollback patch
passed Motor-target debug/release builds and clippy plus three consecutive
debug and three consecutive release full suites. All six setup-rollback
regressions passed, and all six flush stress tests completed 4 x 4,000
operations. The listener-conflict patch passed the same focused checks and
three consecutive debug plus three consecutive release full suites. All six
resolved-conflict regressions passed, and all six flush stress tests completed
4 x 4,000 operations. The listener-pool rollback patch passed the same
focused checks and three consecutive debug plus three consecutive release
full suites. Both shared-cleanup regressions passed in all six runs, and all
six flush stress tests completed 4 x 4,000 operations. The simultaneous-open
regression passed the same focused checks and three consecutive debug plus
three consecutive release full suites. It passed in all six runs, all six
flush stress tests completed 4 x 4,000 operations, and the negative DNS query
returned `NotFound` directly in all six.

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
   out-of-order overflow, overlaps, duplicates, and, once its deferral is
   confirmed, the batched `SYN|ACK + FIN` from Step 1.
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
