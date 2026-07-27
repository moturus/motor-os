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

Overall state: **active, planning checkpoint**.

Current step: **0 -- restore trustworthy gates and benchmark records**.

Completed:

- Reviewed the four companion plans together and checked their central claims
  against the current tree.
- Committed this authoritative execution order as `5e66e52a`.
- Corrected the companion plans' window-scale, socket-lifecycle,
  receive-checksum, flaky-gate, benchmark-script, and missing-safety-step
  statements.

Next:

- Ask for guidance about the already-recorded `full-test.sh` flake baseline,
  as required by `AGENTS.md`, before changing production code.
- Once directed, diagnose and fix the underlying flake rather than accepting a
  statistical pass rate.
- Replace the stale "`run-qemu.sh` is untracked" premise with an auditable
  benchmark manifest.

No production implementation step has started.

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

## Step 0 -- restore trustworthy gates and benchmark records

1. Resolve the known `full-test.sh` debug flake instead of using the proposed
   8-in-10 acceptance rule.
2. Record the failing signatures and root cause in `vdso-rewrite.md`.
3. Add or document a benchmark manifest containing at least:
   - repository commit and dirty-tree exclusions;
   - debug/release build;
   - QEMU binary and version plus the complete command line;
   - host kernel, CPU model, governor, turbo state, and CPU affinity;
   - tap addresses, qdisc state, and offload state;
   - client/server command lines and binary identities.
4. Capture a clean functional and release-performance baseline after the gate
   is trustworthy.

Decision gate: a preexisting test-harness or product bug requires user
guidance before its fix is implemented.

## Step 1 -- remove the sys-io P0 panic surface

Execute core networking Step 1 as small state-group patches:

1. Replace the connect-state `panic!`/`todo!()` paths with deterministic
   socket closure and client notification.
2. Audit packet- and client-reachable panics in the sys-io network runtime.
3. Add simultaneous-open, batched close, and abnormal-state tests.

Do not combine this with moving the fork or tuning the data path.

## Step 2 -- finish the vDSO async control plane

Finish vDSO Stage 2:

1. Convert UDP destruction to the teardown queue after confirming queued
   datagram disposition and ordering.
2. Convert orphan/late TCP connect and accept cleanup.
3. Remove the last `SyncWaiter`, synchronous send/RPC, condvar, and backoff
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
