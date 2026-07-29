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

Current step: **3 -- take ownership of the netstack dependency**.

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
  acceptable test-gate policy. Root-caused and fixed under Step 2 below; the
  exemption and systest's `bind_retry` are both removed.
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
  by which time the connect task has already run.
- Guidance decided not to buy that evidence now. The state is already handled
  -- `CloseWait` classifies as connected -- and the classification cannot
  regress silently, because `connect_action` is a `const fn` whose match is
  exhaustive over smoltcp's `State` and whose eleven mappings are asserted at
  compile time. No packet-injection harness, artificial peer, or test-only
  hook was added for it. It is recorded as a final-verification obligation
  below and as a Step 5 corpus seed.
- The exact simultaneous-open source state passed formatting, Motor-target
  debug and release builds, debug and release clippy, and three consecutive
  ordinary debug plus three consecutive ordinary release `full-test.sh` runs.
  There were no retries or tolerated failures; all six simultaneous-open
  regressions passed, all six negative DNS queries returned `NotFound`
  directly, and all six flush stress tests completed 4,000 iterations per
  worker. An unrelated `rmux` pull landed in the working tree during the
  first attempt at this gate, so its six runs did not all build one tree and
  were discarded. The recorded gate is the rerun on committed `8a48bef6`.

- Reproduced and root-caused the UDP `AlreadyInUse` port-reuse race. Three
  independent measurements agree. At the failing bind, sys-io still had the
  old socket registered with strong count 1 on the same client connection, so
  no sys-io reference held it. sys-io's message-arrival log showed the normal
  `Drop, Bind, Drop, Bind` alternation broken by two consecutive binds, with
  the drop arriving after. A vdso-side probe fired at exactly the failing
  iterations, and the socket handle it named equalled the conflicting socket
  id every time.
- The defect was that `moto_io::net::udp::UdpSocket` posted its release from
  `Drop`. The channel IO thread briefly upgrades the weak reference it keeps
  to every live UDP socket on each pass, so a pass overlapping a close left
  the IO thread holding the last reference; `Drop` -- and the release message
  -- then ran there, after `close()` had returned and behind the caller's
  rebind. sys-io's rejection was correct for the order it saw.
- Fixed by splitting release out of `Drop` into an idempotent
  `UdpSocket::close()` that the closing descriptor invokes, so the release is
  queued before `close()` returns. `dup`ed descriptors keep working: the vdso
  calls it only when the last descriptor for the file closes.
- Removed both workarounds: systest's `bind_retry` (its binds are strict
  again, including the immediate rebind in `test_udp_double_bind`) and
  `stress-soak.sh`'s resilient-mode tolerance of suite failures.
- The exact UDP close source state passed formatting, Motor-target debug and
  release builds, debug and release clippy, and three consecutive ordinary
  debug plus three consecutive ordinary release `full-test.sh` runs. There
  were no retries or tolerated failures; the new regression passed in all six
  runs, all six flush stress tests completed 4,000 iterations per worker, and
  the negative DNS query returned `NotFound` directly in all six.

- Converted UDP destruction to the teardown queue. `close()` no longer posts
  its release through `send_msg_guaranteed`, which could park the closing
  thread on a full staging queue; it transfers the release and the socket's
  channel reservation to the driver and returns. It also empties the socket's
  own TX queue, and `try_tx` refuses to stage anything once `closed` is set,
  so no datagram can be handed to the channel behind the release.
- Established the teardown queue's ordering rule while doing it. Teardown
  outranks ordinary staging work, so a UDP close would have overtaken the
  datagrams its own socket had already staged. Each record now carries the
  staging queue's push count at the moment it was enqueued and waits until the
  driver has drained that many messages. The count is absolute, so a pop
  racing the capture cannot make the fence stale-high and let the caller's
  next bind overtake the release.
- Fixed two pre-existing defects on that path, with approval. `moto-io` read
  the staged datagram's size from `args_64()[1]` -- the TCP RX layout, which
  aliases the IPv6-mapped address -- so closing a socket holding a staged
  *empty* datagram freed io page 0, which it did not own, and an address whose
  middle eight bytes are zero leaked the page instead. sys-io reclaimed the io
  page of a UDP TX it could not deliver and then let the generic error path
  echo the request back holding that page index, so the client freed the same
  page again through its orphan handler. A fire-and-forget TX now answers
  nothing, and its page is reclaimed only when the size field says there is
  one.
- Added `net.udp.tx_dropped`, the count of UDP datagrams sys-io discarded
  because it no longer had the socket they name. It is the only client-visible
  trace of a close overtaking its own datagrams, and it gates the fence:
  `udp_close_does_not_overtake_tx_test` runs 200 send-then-close iterations
  and requires the counter not to move. Verified by sabotage -- with the fence
  disabled the same run discards exactly 200, one per iteration.
- Root-caused the DNS resolver restart failure. Shared IPC listener ownership
  was tied to the lifetime of the owner's `Process` allocation rather than its
  live status. A killed resolver entered `Exiting`, but the parent's retained
  process handle kept the allocation alive, so the replacement resolver's
  attempt to register `moto-dns-resolver` was rejected.
- Shared listener creation and lookup now discard entries owned by a process
  that is no longer alive. This changes no boot work and only adds the process
  status check while creating or discovering an IPC listener.
- Added a deterministic systest that kills a listener owner, intentionally
  retains its process handle, starts a replacement on the same URL, and
  connects to it. The test failed before the fix with the replacement's
  listener creation returning error 7 and passes after it.
- The exact DNS-listener source state passed formatting, a debug image build,
  debug and release systest clippy, and the kernel's debug and release clippy
  checks performed by the image builds. Three consecutive ordinary debug and
  three consecutive ordinary release `full-test.sh` runs then passed without
  retries or tolerated failures. Both DNS resolver self-tests and the new
  listener-restart regression passed in all six runs.

Current work:

- Step 2 is complete. TCP connect, accept re-posts, and late-success cleanup
  use the async driver-owned paths; the blocking channel-control machinery is
  removed; and the DNS resolver restart prerequisite and repeated final gate
  are closed.
- Step 3's first distinct slice is prepared from the locked fork revision
  `d2ff65b053bb1f7ea96e3df51857b53d2a751cba` at
  `src/sys/sys-io/netstack/`. By guidance, the import retains the production
  crate only: its license, manifest, build script, and complete `src/` tree.
  Upstream CI, repository documentation, examples, benches, integration
  tests, fuzz tree, utilities, and generator script are omitted. The manifest
  drops only the targets, readme entry, and dev dependencies made obsolete by
  those omissions.
- The package is intentionally still named `smoltcp`, is not a workspace
  member, and is not referenced by sys-io. Step 5 will add the planned
  packet-facing coverage as a Motor-owned harness rather than retaining the
  upstream cargo-fuzz project.
- After that isolated import is committed, rename the package and add it to
  the workspace as the second distinct Step 3 slice. Formatting and clippy
  remain a third slice as required by the fork-preservation sequence.

Scheduled defect, found while gating Step 2 substep 2:

- sys-io destroys a UDP socket's smoltcp state while its TX buffer still holds
  datagrams sys-io itself accepted. `udp_tx` writes into the buffer and
  notifies the device task; `UdpSocketDrop` is processed before that task
  polls, and `MotoSocket::drop` removes the smoltcp socket outright. So
  `send_to()` immediately followed by `close()` never delivers -- the ordinary
  fire-and-forget UDP idiom -- and `udp_rebind_after_close_test` has been
  losing all 2,000 of its datagrams unnoticed.
- This is pre-existing and independent of the client-side ordering above,
  which the sys-io log confirms is correct: the datagram reaches smoltcp
  (`UDP: socket 0x... sent 1 bytes`) before the drop, and sys-io then logs its
  own `Dropped UDP socket 0x... with unsent bytes.` next to the standing
  `// TODO: linger? UDP sockets don't linger, but we may?`.
- By decision it gets its own patch, not this one: the fix is a design choice
  between polling the device before removal (cheap, but a full interface poll
  from a destructor, and still best-effort for a peer whose ARP is pending)
  and deferring removal until the buffer drains (correct, but needs a
  draining list, a bound, and a rule for whether the address may be rebound
  meanwhile -- it interacts with the address release ordered above).
- Until it lands, no test may assert that a datagram sent immediately before a
  close is delivered.

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
3. The UDP `AlreadyInUse` race belonged to Step 2 because teardown and address
   release ordering were relevant: the release was posted from `Drop`, which
   could run on the channel IO thread after the caller's `close()` returned.
   Fixed in Step 2 substep 1; resilient soak mode no longer tolerates a suite
   failure.
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
deterministic self-connect regression. Its batched `SYN|ACK + FIN` case
cannot be produced by any in-order peer; by decision it gets no harness now
and is carried as a final-verification obligation and a Step 5 corpus seed.
The remaining connect-task terminals -- refused, timed out, and gracefully
closed -- are already covered by existing TCP tests. Step 1 is complete.

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

Status: complete. All four implementation substeps, the DNS resolver restart
prerequisite, and the repeated final gate are complete.

Substep 2's contract was confirmed before implementation and is unambiguous:
datagrams already handed to the channel must reach sys-io before the release;
datagrams still in the socket's own TX queue are discarded, and the one staged
message's io page is reclaimed locally; pending RX datagrams free their pages
when the socket drops. UDP is lossy by contract and the fragmenting queue
already drops datagrams when it is full, so a close waits for neither pages
nor staging room. Preserving the first half of that contract is what the
teardown record's staging fence is for -- without it the release outranks the
socket's own staged datagrams, which sys-io then discards.

Substep 1 status: release is no longer posted from
`UdpSocket::drop` but from an idempotent `UdpSocket::close()` that the
closing descriptor invokes, so sys-io has been told to free the address
before `close()` returns and a caller cannot lose a rebind to its own close.
`dup`ed descriptors are unaffected: the vdso invokes it only when the last
descriptor for the file closes, which it learns from the descriptor table.

`udp_rebind_after_close_test` covers it: 2,000 close/rebind cycles on a fixed
address with a background sender running, no retry anywhere. The background
sender is what makes the pre-fix failure reachable, so the test is
probabilistic against the old code -- it caught it in roughly two of three
release runs, and in six gate runs essentially always -- and deterministic
against the fixed code. By decision, no test-only hook was added to force the
IO thread to hold the reference across a close.

Substep 2 status: `close()` transfers the release and the socket's channel
reservation to the driver's teardown queue instead of posting the release
through `send_msg_guaranteed`, which could park the closing thread on a full
staging queue. The release is still queued by the closing thread before the
call returns, so substep 1's guarantee holds. `close()` also empties the
socket's TX queue, and `try_tx` reads `closed` under the same lock, so no
datagram is handed to the channel after the release is queued.

Teardown records are now ordered against the work staged before them (see the
contract above). Each carries the staging queue's absolute push count at
enqueue time and waits until the driver has drained that many messages; a pop
racing the capture therefore cannot make the fence stale-high and let the
caller's next bind overtake the release. The tx task's exit condition checks
the records explicitly, because one can be held back by its fence.

Two pre-existing defects on that path were fixed with approval, both about an
io page whose presence was decided from the wrong field: `moto-io` read the
staged datagram's size from the TCP RX offset, and sys-io echoed a reclaimed
page index back to the client in the error reply to a fire-and-forget TX. See
the status list above.

`udp_close_does_not_overtake_tx_test` gates the fence through the new
`net.udp.tx_dropped` counter, which is the only client-visible trace of the
reordering while Defect C above stands. Verified by sabotage: with the fence
disabled, its 200 send-then-close iterations discard exactly 200 datagrams.

Settled, as substep 2 owed: a *dead* client's addresses are still released
asynchronously, when sys-io observes the connection error. This work does not
change it and cannot: there is no client left to order anything from, so the
ordering lives entirely in sys-io's connection-error handling. No evidence
says the window is reachable -- a killed process's replacement must boot and
connect before it could matter -- so it stays out of scope rather than
unresolved.

Gate for substep 1: formatting, Motor-target debug and release builds, debug
and release clippy, and three consecutive ordinary debug plus three
consecutive ordinary release `full-test.sh` runs all passed with no retries
and no tolerated failures. The new regression passed in all six runs, all six
flush stress tests completed 4 x 4,000 operations, and the negative DNS query
returned `NotFound` directly in all six.

Gate for substep 2: the exact source state passed formatting, Motor-target
debug and release builds, and debug and release clippy with only preexisting
warnings, then three consecutive ordinary debug plus three consecutive
ordinary release `full-test.sh` runs. There were no retries and no tolerated
failures. `udp_close_does_not_overtake_tx_test` and
`udp_rebind_after_close_test` passed in all six runs, all six flush stress
tests completed 4 x 4,000 operations, and the negative DNS query returned
`NotFound` directly in all six.

Substeps 3 and 4 status: connect request staging is an async future with
insert-before-queue RPC registration. Its waiter keeps only a weak stream
reference, so cancellation releases the reservation; a successful late
response is closed by the driver if another reservation keeps the channel
alive, while sys-io reclaims it on channel disconnect otherwise. Accept
re-posts move directly to the driver queue. The listener retains each pending
accept reservation because sys-io clears those requests without replying when
the listener disappears. A delivered-but-unclaimed accepted stream transfers
its close and reservation together to the driver. These ownership paths remove
the last blocking send/RPC and guaranteed-send task machinery.

Gate for substeps 3 and 4: formatting, focused Motor-target debug/release
builds, and debug/release clippy passed with no new warnings. The first gate
attempt stopped on the DNS resolver restart defect and was not retried or
tolerated. After the IPC listener-ownership fix and deterministic regression,
the exact source state passed three consecutive ordinary debug and three
consecutive ordinary release full suites. All six runs included passing DNS
resolver restart/self-tests, listener-restart regressions, connect/accept
cancellation and drop-backpressure coverage, mio `close_on_drop`, UDP
ordering, and tokio tests.

## Step 3 -- take ownership of the netstack dependency

Execute only core Step 0(a) and 0(b):

1. Import the fork verbatim, then rename it, then format/lint it in distinct
   commits so ancestry remains reviewable.
2. Replace the foreign enum in `TcpSocketStatsV1` with a stable Motor wire
   enum and test its layout.
3. Repoint sys-io and remove the crates.io patch.

Defer core Step 0(c) and 0(d).

Status: the first of substep 1's three preservation commits is prepared. It
contains the locked fork's production crate subset plus this status update and
deliberately does not rename, format, register, or consume the imported crate.
Before the user-directed pruning, the full fork tree was compared byte-for-byte
with the clean cached checkout. The unchanged workspace passed
`cargo +nightly fmt -- --check` plus three consecutive ordinary debug and
three consecutive ordinary release `full-test.sh` runs without retries or
tolerated failures. The pruning changes no workspace member or compiled
source. Formatting and clippy for the imported crate remain deliberately
deferred to the third preservation commit.

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
   out-of-order overflow, overlaps, duplicates, and the batched
   `SYN|ACK + FIN` carried over from Step 1.
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

Note for the final verification below: coalescing exists to put more packets
into each `Interface::poll` batch, so every multi-packet-per-poll transition,
including the batched `SYN|ACK + FIN`, becomes more reachable after this step,
not less.

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

## Final verification

Behavior that is correct today but whose only evidence is source review, and
that later steps can silently break. Each must be proven, not re-argued,
before the networking work is called done.

1. A connect that observes `CloseWait` because the peer's SYN|ACK and FIN
   arrived in one `Interface::poll` batch must still report the established
   connection and then close normally. Deferred from Step 1: no in-order peer
   can produce the batch, so it needs the Step 5 harness. Steps 4, 8, and 10
   all change poll batching or stack behavior, and Step 8 makes the batch more
   likely, so verify after them.
