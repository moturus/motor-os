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

Current step: **6 -- complete core safety hardening (plan reviewed 2026-07-29;
D1-D4 approved, design choices resolved; patches 1.1, 1.2 and 1.3 landed, next
patch 1.4)**.

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
- Step 3's import slice landed as commit `4a99ee18` from the locked
  fork revision `d2ff65b053bb1f7ea96e3df51857b53d2a751cba` at
  `src/sys/sys-io/netstack/`. By guidance, the import retains the production
  crate only: its license, manifest, build script, complete `src/` tree, and a
  small Motor README. Upstream CI, repository documentation, examples,
  benches, integration tests, non-production test tooling, utilities, and
  generator script are omitted. The manifest drops only entries made obsolete
  by those omissions.
- The rename/register and formatting/lint preservation slices landed as
  `c66dfb30` and `16ad6a68`. The package is `moto-netstack`, its crate-name
  self-references are `moto_netstack`, it is a workspace member, and it uses
  the `MOTO_NETSTACK_*` configuration prefix. The unused packet-mutation
  middleware and ignored package-local release profile are removed.
- Step 3 substep 2 landed as `3825ac8e`. The public stats IPC now owns a stable
  Motor wire enum while preserving its V1 layout.
- Step 3 substep 3 landed as `03a59d71`. sys-io directly consumes the in-tree
  `moto-netstack`, and the temporary crates.io patch and old git package
  lockfile entry are gone. The dependency's default features remain enabled
  until Step 4's separately reviewed feature trim.
- Step 4 substep 1 landed as `14310975`. The in-tree stack now compiles
  without its `async` feature; Motor's enabled build and runtime behavior are
  unchanged.
- Step 4 substep 2 is complete. sys-io selects only the
  Motor feature closure, uses the IP medium for logical loopback, and makes
  automatic ICMP echo replies an explicit per-interface runtime policy. The
  inherited reduced-feature `rstest` cases are repaired. Host checks,
  Motor-target builds/clippy, code-size and paired KVM performance checks, and
  three debug plus three release focused full-OS suites pass.
- By maintainer guidance, Step 5 uses deterministic packet regressions only.
  The netstack's existing `TestSocket`/`send` unit-test support already calls
  `tcp::process()` directly and covers most planned sequence, window, RST,
  overlap, and duplicate cases.
- The first missing case is now covered at the interface boundary. A raw
  `SYN|ACK` followed by `FIN` in one receive queue is drained by one
  `Interface::poll`, leaving the connecting socket in `CloseWait`; sys-io's
  exhaustive compile-time mapping classifies that state as connected. This
  patch landed as `6c3f8f28`.
- Direct process regressions now cover a receive overlap whose old and new
  ranges cross the signed sequence-number boundary, and exhaustion of the
  out-of-order assembler. The overflow case proves rejection leaves the
  assembler and connection state intact and does not prevent later in-order
  recovery.
- The focused networking harness now runs the exact 521-test Motor feature
  closure in the matching debug or release profile before booting the VM.
  Three debug and three release runs pass, including the new regression and
  final full-suite marker in every run. The broad default closure passes 660
  unit tests plus 7 doctests.
- A full-OS sys-io state harness now observes listener, client, and accepted
  socket transitions through the public stats service. It checks
  `Listen/Listening`, both `Established/ReadWrite` endpoints, and the
  `FinWait2/ReadOnly` plus `CloseWait/WriteOnly` half-closed pair, then proves
  data still flows from the write-only peer.
- Step 5 is complete. Existing direct-process tests cover the remaining
  window-change, zero-window, reset, duplicate, and overlap cases, and all
  new coverage runs transitively through `full-test-networking.sh`.
- Step 6's required design plan is drafted as
  `docs/plans/core-safety-hardening.md`. Every finding in it was re-verified
  against `8e2b31a7`, i.e. after the in-tree import and the feature trim. It
  proposes a patch-sized breakdown for all six items, an execution order, the
  decision gates below, and the per-patch gate. No code changed.
- The re-verification found a remotely reachable release abort, recorded as
  defect D1 in that document. `dispatch` stores the deliberately unscaled
  SYN/SYN|ACK window into `remote_last_win`, which every consumer shifts back
  up by the negotiated scale, so for one round trip after either an active or
  a passive open the socket computes a receive-window right edge of 262140
  bytes while its ring holds 131072. The acceptance test clamps to that edge
  and never consults the ring's free space, so in-order payload beyond the
  ring reaches `enqueue_unallocated` and trips its release-live `assert!`;
  sys-io aborts and all networking on the machine dies. An honest peer cannot
  reach it -- it respects the 65535 we advertised -- but a peer that ignores
  the advertised window reaches it with about ninety ordinary segments to an
  application that is not draining, in either role. `Interface::poll` drains
  the whole receive queue before any egress, so no ACK corrects the stale edge
  mid-batch.
- Three smaller preexisting defects are recorded there as D2 (the virtio RX
  size adjustor can underflow below the 12-byte header), D3
  (`rt.vdso`'s `fill_random_bytes` panics when RDRAND fails, which item 3
  would inherit), and D4 (the assembler accepts an offset unrelated to the
  receive ring's capacity). Each needs guidance before its fix.
- Step 6 patch 1.1 is complete. `remote_last_win` now records the advertised
  window in bytes -- SYN/SYN|ACK fields verbatim, every other segment's
  scaled back up -- so no consumer shifts it and the first-round-trip
  receive-window right edge equals what the peer was told. The fail-first
  record was captured before the fix: both new overrun regressions abort the
  unfixed source on the release-live ring-buffer `assert!` in release and the
  short-write `debug_assert!` in debug, in both the passive and the active
  role.
- Fixing the field exposed that `window_to_update` would begin emitting its
  corrective window update while still in SYN-RECEIVED -- a second reply to
  every SYN on scaled sockets. By implementation decision, recorded for
  review in the patch plan, the heuristic is restricted to post-handshake
  states; the full-window advertisement goes out on reaching ESTABLISHED and
  is pinned by its own regression.
- The exact patch-1.1 source state passed formatting, Motor-target debug and
  release builds, debug and release clippy with only pre-existing warnings,
  both netstack closures with warnings denied (526 plus 7 and 665 plus 7
  tests), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries or tolerated failures. The
  paired release `rnetbench` A/B is within the kill criteria; the default
  workload was re-measured as A/B/A blocks after the first pair straddled a
  host performance-state shift that the clean tree reproduced exactly.
- Step 6 patch 1.2 is complete. The receive path can no longer abort on
  attacker-influenced arithmetic. The receive-window right edge is bounded by
  its left edge and by the receive ring's free space; the accepted slice and
  its ring offset come from a checked helper that drops the segment instead of
  panicking; the write site rejects a short write before the assembler records
  it, so no ACK can advance over octets the ring did not store; and both
  ring-buffer `assert!`s are debug assertions that clamp in release, with
  their callers bounding the counts first. A fourth panicking subtraction over
  the same two epochs, in `last_scaled_window` on the dispatch path, reports
  "no previous window" instead.
- The three new regressions construct their state directly, because after
  patch 1.1 no packet sequence produces it. The fail-first record was captured
  first: in debug both `process()`-level regressions abort the unfixed source
  on the short-write `debug_assert!`; in release the beyond-the-ring one
  aborts on the release-live ring-buffer `assert!` and the crossed-window one
  survives holding a phantom assembler hole, which is D4's shape and patch
  1.3's subject.
- Step 6 patch 1.3 is complete, and closes D4. The numeric bound it was to add
  was already there: patch 1.2's write-site re-check is the caller-side bound,
  because the assembler's offsets and the ring's unallocated region share an
  origin. It is TCP's only path into the assembler, and nothing it depends on
  changes between the acceptance computation and it. So 1.3 delivered the
  invariant enforcement D4's entry predicted would remain after 1.1 and 1.2:
  the bound now names both invariants it carries -- the short write and the
  unfillable assembler hole with its permanent phantom SACK block -- and a
  caller-side `debug_assert!` makes a later change to the acceptance
  arithmetic fail loudly in debug rather than silently drop every segment in
  release. The assembler is untouched, as decided; its only other caller,
  fragment reassembly, bounds its own offset and is outside Motor's feature
  closure.
- Its regression gives an established socket a recorded window far past its
  64-byte ring, constructed directly, and requires that an out-of-order
  segment 200 octets ahead draws a challenge ACK and never reaches the
  assembler, that a segment straddling the ring's end is truncated so the
  recorded hole plus data ends exactly at the ring's end, and that the hole
  then fills and delivers the whole ring. The fail-first record was taken with
  all three bounds removed: debug aborts on the pre-existing short-write
  `debug_assert!`, and release records D4's exact shape -- a 200-octet hole in
  a 64-byte ring -- which the regression catches.

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

For this networking work, user guidance replaces item 3's harness with
`src/tests/full-test-networking.sh`. It is a copy of the full suite with all
rmux/tmux host and guest tests removed, while retaining the build, networking
integration, systest, SFTP, mio, and tokio coverage. Each patch requires three
debug and three release passes through that focused harness. The
repository-wide `src/tests/full-test.sh` and `AGENTS.md` are unchanged.

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
  sockets and avoids eagerly committing the full buffers to each SYN. Step 6
  sequencing splits those two: the cap is Step 6 item 6, the eager commitment is
  Step 12, so Step 9 needs both or an explicit acceptance of the remaining
  per-listening-socket cost.
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

Status: the first of substep 1's three preservation commits landed as
`4a99ee18`. It contains the locked fork's curated production crate plus a
small Motor README and deliberately did not rename, format, register, or
consume the imported crate. Before the user-directed pruning, the full fork
tree was compared byte-for-byte with the clean cached checkout. The unchanged
workspace passed `cargo +nightly fmt -- --check` plus three consecutive
ordinary debug and three consecutive ordinary release `full-test.sh` runs
without retries or tolerated failures. The pruning changed no workspace
member or compiled source.

The second preservation slice landed as `c66dfb30`. It renames the package and
internal crate references to `moto-netstack`/`moto_netstack`, registers it as a
workspace member, changes the unused configuration prefix to
`MOTO_NETSTACK_*`, and removes the member-local release profile Cargo would
ignore with a warning. It also removes the unreferenced packet-mutation support
module. It does not yet repoint sys-io.

The third preservation slice landed as `16ad6a68`. `cargo +nightly fmt`
changes one expression in `iface/interface/mod.rs`. The six inherited clippy
exceptions are consolidated into one documented crate-level block, while
three new findings are fixed mechanically: TCP keep-alive late initialization,
DHCP address chunking, and an IEEE 802.15.4 `Option` unwrap. Host all-target
clippy and Motor-target debug and release clippy pass with warnings denied.
The 655 unit tests and 7 doctests pass. Three consecutive debug and two
consecutive release full suites pass. The third release suite reaches the DNS
restart gate with both resolver self-tests passing, then fails only because
`ping google.com` selects a returned IPv6 address on the intentionally
IPv4-only VM and reports `NotConnected`. By explicit direction, that known
unrelated failure did not block the formatting/lint preservation commit and
was handled by the immediate follow-up below.

Next step -- make `ping` select a routable resolved address:

- The VM's only non-loopback address is `192.168.4.2/24`; `moto-tap`, its
  default route, host forwarding, and NAT are all IPv4-only. The VM has IPv6
  loopback coverage but no external IPv6 route.
- Real external IPv6 would require an IPv6 address on both the VM interface and
  host TAP, a same-family VM default gateway, host IPv6 forwarding, and either
  a routed global prefix or NAT66. The current route selector also requires the
  gateway to be inside a configured same-family CIDR. That is a separate
  dual-stack project, not a prerequisite for DNS restart coverage.
- Before this follow-up, `sysbox ping` called `ToSocketAddrs` and discarded
  every result after `.next()`. Preserve all resolved candidates and use IPv4
  when an IPv6 candidate has no route. A numeric IPv6 destination must remain
  IPv6-only and continue to report the route error.
- Add deterministic address-selection/fallback tests and repeat the ordinary
  debug and release full-suite gate before returning to Step 3 substep 2.

Status: the `ping` follow-up landed as `4081252b`. Hostname resolution now
retains and deduplicates every returned address. An immediate `NotConnected`
advances to the next candidate without counting a second ping request. If
every returned candidate lacks a route and the resolver supplied only one
address family, `ping` makes one explicit lookup for the missing family
through the native `moto-dns` API. It does not repeat the original `Any`
lookup. Numeric destinations carry no hostname, so numeric IPv6 remains
IPv6-only and reports `NotConnected` on the current VM.

Three deterministic unit tests cover an existing next candidate, a missing
IPv4-family lookup after an unroutable IPv6-only result, and the numeric-IPv6
no-fallback rule. The Motor debug test target compiles, and debug plus release
all-target clippy passes with warnings denied. `full-test.sh` no longer
tolerates a hostname `NotConnected` when the host lacks external ICMP; only an
actual echo timeout remains an accepted environmental outcome. It also checks
the numeric `2001:db8::1` route failure directly.

The exact source state passes three consecutive ordinary debug and three
consecutive ordinary release full suites. In all six, the numeric IPv6 check
reports `NotConnected`, both pre- and post-restart `google.com` pings select
IPv4 and receive replies, and the suite reaches its final pass marker. One
log-captured debug invocation was discarded before VM boot because the
sandbox denied the host-only rnetbench performance-counter syscall; the same
command run with its normal host permission produced the recorded second
debug pass. No product or in-VM test failure was retried or tolerated.

Substep 2 landed as `3825ac8e`. `moto-sys-io` now owns the 11-variant
`TcpProtocolState` wire enum with `repr(u8)` and explicit discriminants. This
preserves the existing V1 IPC layout: the enum remains one byte,
`TcpSocketStatsV1` remains 72 bytes with alignment 8, and its two state fields
remain at offsets 60 and 64. Compile-time assertions pin those facts. The
crate's optional crates.io `smoltcp` dependency is removed, including its
lockfile edge.

sys-io performs an exhaustive conversion at the stats boundary. Compile-time
wire-compatibility assertions compare the Motor and current smoltcp enum sizes,
alignments, and every discriminant, so an upstream state addition or reorder
cannot silently change the mapping. Existing full-suite TCP tests now also
require both sides of a live accepted connection to report
`TcpProtocolState::Established` after crossing the real stats IPC path.

Formatting and focused Motor-target debug/release builds pass. Focused
debug/release clippy reports only the repository's pre-existing warnings and
none in the changed code. The exact code state passes three consecutive
ordinary debug and three consecutive ordinary release full suites; all six
include both IPC enum assertions and reach the final pass marker. One debug
invocation was discarded before VM boot because the sandbox denied all three
host rnetbench performance-counter tests with `EPERM`; the same command with
normal host permission supplied the recorded second debug pass. No product or
in-VM test was retried.

Substep 3 landed as `03a59d71`. sys-io now depends directly on the in-tree
`moto-netstack` path package. Its eight networking source files use the owned
crate name and neutral internal netstack identifiers. The public
`TcpSocketStatsV1::smoltcp_state` field name remains unchanged to avoid an
unnecessary source/API break; its value is still the stable Motor wire enum
introduced by substep 2. The crates.io patch and old git `smoltcp` package are
removed from the workspace manifest and authoritative lockfile. Cargo's
Motor-target dependency tree resolves only the in-tree `moto-netstack`.
Default features deliberately remain unchanged for Step 4.

Formatting and diff checks pass. The 655 host unit tests and 7 doctests pass,
as does host all-target clippy with warnings denied. Focused Motor-target
debug and release builds pass. Focused sys-io debug and release clippy report
only the repository's pre-existing warnings and none introduced by this
transition. The exact code state passes three consecutive ordinary debug and
three consecutive ordinary release full suites. Every run includes both
native-accept race regressions and reaches the final pass marker. No failed
product or in-VM test was retried or tolerated.

## Step 4 -- trim unused stack features

1. Fix the latent `async` feature configuration defect.
2. Disable default features and enable only Motor's required set.
3. Verify removed fragmentation behavior and all retained IPv4, IPv6, TCP,
   UDP, and ICMP behavior.

Decision: automatic ICMP echo replies will be controlled by a top-level
`auto_icmp_echo_reply` boolean in `/sys/cfg/sys-net.toml`. The shipped image
will explicitly enable the current behavior. sys-io will apply the value to
loopback and every configured device. This runtime policy replaces the
netstack's compile-time `auto-icmp-echo-reply` feature in substep 2.

Substep 1 landed as `14310975`. `PacketMeta`, which TCP dispatch uses with or
without the `async` feature, is now imported unconditionally.
`WakerRegistration`, which exists only with `async`, is imported under that
feature. This fixes the known no-async build failure without changing Motor's
enabled build or runtime behavior.

The reduced no-async feature set previously failed with three import/type
errors and now compiles. Its twelve existing feature-combination warnings are
outside the changed imports and remain work for substep 2; the normal
all-target host clippy gate passes with warnings denied. All 655 unit tests
and 7 doctests pass. Focused Motor-target debug and release builds pass, and
their clippy runs report only repository-pre-existing warnings.

The exact code state passes three consecutive ordinary debug and three
consecutive ordinary release full suites. Every run includes both
native-accept race regressions and reaches the final pass marker. No failed
product or in-VM test was retried or tolerated.

Substep 2 is complete. sys-io disables the netstack's default features and
enables exactly `std`, `async`, `medium-ethernet`, `medium-ip`, `proto-ipv4`,
`proto-ipv6`, `socket-tcp`, `socket-udp`, and `socket-icmp` (plus their
`alloc` and `socket` implications). `medium-ip` serves the logical loopback;
configured virtio devices remain Ethernet. The resolved dependency tree
contains no fragmentation, 6LoWPAN, DHCP, DNS, mDNS, raw-socket, multicast,
SLAAC, host-interface, packet-id, or logging feature and no netstack `libc`
edge. The owned package version is `0.13.0-motor.1`, distinct from stock
0.13.0.

The compile-time `auto-icmp-echo-reply` feature is removed. Interface
configuration now carries an `auto_icmp_echo_reply` boolean whose library
default is false. `/sys/cfg/sys-net.toml` requires and explicitly sets it to
true, and sys-io passes it to both loopback and every configured virtio
interface. Deterministic IPv4 and IPv6 stack tests prove both enabled replies
and disabled suppression; a sys-io unit test pins the TOML field.

The inherited reduced-feature `rstest` defect is fixed. Medium-specific cases
now use conditional case injection instead of accumulating item-level
`#[cfg]` attributes, and feature-specific helpers are gated by the feature
that owns them. The production closure passes 518 unit tests and 7 doctests
with warnings denied, including the intended IP and Ethernet cases. Its
all-target clippy gate also passes with warnings denied. The broad default
closure passes 657 unit tests, 7 doctests, and all-target clippy with warnings
denied. Focused Motor debug and release builds pass; Motor-target clippy
reports only repository-pre-existing warnings, none in the changed code.

The first debug full suite exposed a genuine integration regression at the
IPv6 loopback test: sys-io modeled logical loopback as Ethernet, so `::1`
traffic entered neighbor discovery after multicast support was removed.
Logical loopback now uses `Medium::Ip` with `HardwareAddress::Ip`; virtio
interfaces remain Ethernet. The focused `test-ipv6-loopback` command and the
final full-OS suites pass. The failed run was diagnosed and was not counted
or retried as a gate pass.

The clean-HEAD and prepared release binaries were built from isolated trees
on the same host. The stripped sys-io file falls from 2,151,752 to 1,955,144
bytes (-196,608, 9.1%); text falls from 2,095,457 to 1,908,377 bytes
(-187,080, 8.9%).

Paired release KVM `rnetbench` used one unchanged host client, three rounds
per workload, and all samples:

| Workload | Tree | RR (usec) | Motor RX (MiB/s) | Motor TX (MiB/s) |
|---|---|---:|---:|---:|
| default | clean HEAD | 55.285 | 164.04 | 326.00 |
| default | prepared | 59.401 | 163.87 | 319.90 |
| 64 KiB | clean HEAD | 54.357 | 668.12 | 1401.33 |
| 64 KiB | prepared | 58.506 | 712.24 | 1408.26 |

The prepared deltas are +4.116 usec/-0.10%/-1.87% for default and
+4.149 usec/+6.60%/+0.49% for bulk, within the established kill criteria.
Elevated-RR samples were retained rather than discarded or rerun. By user
guidance, synthetic host-qdisc delay/loss testing is not a gate for the
full-OS stack.

`src/tests/full-test-networking.sh` is the user-approved gate for this
substep. It is the standard suite with all rmux/tmux host and guest tests
removed. Three consecutive debug and three consecutive release runs each
reach both systest `PASS` and the final full-suite marker. No failed product
or in-VM test was retried or tolerated.

## Step 5 -- establish packet-facing regression coverage

Move core Step 5 ahead of further fork behavior changes:

1. Add a deterministic TCP process harness against the current API.
2. Add crafted regression cases for window wrapping, abnormal RSTs,
   out-of-order overflow, overlaps, duplicates, and the batched
   `SYN|ACK + FIN` carried over from Step 1.
3. Add a sys-io socket-state harness.
4. Run all deterministic coverage through `full-test-networking.sh`.

Status: substep 1 reuses the existing direct `tcp::process()` test support
rather than adding a parallel harness. The first new crafted-packet regression
queues `SYN|ACK` and `FIN` together and proves that one interface poll reaches
`CloseWait`. Together with sys-io's exhaustive `connect_action` mapping, this
closes the deferred batched-connect verification from Step 1; it landed as
`6c3f8f28`.

The next two direct-process regressions exercise receive overlap across the
signed sequence-number boundary and out-of-order assembler exhaustion. The
overflow case verifies that a rejected hole neither mutates the assembler nor
breaks later in-order recovery. Existing tests retain coverage of current RST
behavior; new RFC 5961 acceptance rules remain in Step 6 so Step 5 does not
lock in behavior that the next safety step intentionally changes.

The exact Motor feature closure passes 521 unit tests and 7 doctests, and the
broad default closure passes 660 unit tests and 7 doctests; both all-target
clippy runs pass with warnings denied. Motor debug and release clippy report
only repository-pre-existing warnings. Three debug and three release
`full-test-networking.sh` runs pass with both new tests, all 521 production
tests, and the final full-suite marker present in every run. No product or
in-VM failure was retried or tolerated.

Substep 3 adds a full-OS state-transition harness through sys-io's public
socket stats. It observes `Listen`, both established endpoints, and the
`FinWait2`/`CloseWait` half-closed pair with their Motor API states, then
transfers data across the surviving direction. Its first development run
passed the new test but failed the following global-gauge test: normal close
left this test's client teardown asynchronous, violating that test's
documented stable-baseline ordering. Moving the state test after the gauge
checks and adding the same explicit zero-linger cleanup barrier used by the
simultaneous-open regression corrected the harness isolation. That failed
development run is not counted.

The corrected source passes Motor debug and release clippy with only existing
repository warnings. Three debug and three release
`full-test-networking.sh` runs each contain the state-transition pass, all 521
production netstack tests, and the final full-suite marker. Step 5 is
complete.

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

Status: the required plan is `docs/plans/core-safety-hardening.md`, reviewed on
2026-07-29. It carries the verified state, the patch breakdown, the tests, and
the gate for each item, and its Sequencing section is the execution order of
record for Step 6. Patches 1.1 (D1), 1.2, and 1.3 (D4) are complete and gated;
their result notes, including the SYN-RECEIVED window-update decision, the
fourth panicking subtraction 1.2 added to its scope, and 1.3's finding that
1.2's write-site check was already D4's caller-side bound, are in that plan's
Item 1. The next patch is 1.4.

Item order: **1, 2, 6, 5, 4, 3.** Item 1 leads because it is the only remotely
reachable abort in the list and because Step 5 built exactly the harness that
proves it. Items 2 and 6 follow because they gate later steps -- item 2 gates
Step 8's receive-offload expansion, item 6 gates Step 9 and
`tcp-receive-window.md` Step 1 -- so delaying them stalls other work. Items 5, 4,
and 3 block nothing else; item 3 is last because item 4's exact-sequence RST
check already removes the cheapest blind attack that predictable ISNs and ports
enable, and because item 3 is the only item whose cost includes an existing
regression's determinism. Every patch is separately gated and leaves a runnable
tree, so a single patch can be resequenced without re-planning.

Patch order within that, nineteen patches: 1.1 (D1's fix with its fail-first
test), 1.2, 1.3 (D4), 1.4, 2.1 (D2), 2.2, 2.3, 6.1, 6.2, 6.3, 5.1, 5.2, 5.3,
4.1, 4.2, 3.0 (D3, an `rt.vdso` patch), 3.1, 3.2, 3.3.

Scope decided, and recorded in the affected plans:

- Item 4 lands RFC 5961 section 3; timestamps and PAWS move to Step 10 item 2,
  where the RTT-sampling benefit pays for the 12-bytes-per-segment cost and both
  are measured in one sitting.
- Item 6 delivers bounding only -- a half-open cap, a backlog independent of the
  pre-created pool, and the counters for both. Lazy or growable socket buffers
  move to Step 12, which must define the same construct-with-shift and
  grow-an-empty-ring fork surface for per-socket sizing; the window scale is
  fixed from the receive capacity at construction, so it cannot be designed twice
  cheaply.
- Item 5 hardens ARP admission and eviction at the current eight-entry capacity;
  cache capacity stays in Step 10 item 4, measured with the route table.
- Item 6 keeps the netstack's RST reply to an unmatched SYN, counts it, and
  revisits the drop-versus-RST choice with Step 8's batching evidence.
- D1-D4 keep their places in the order above. Each was reviewed and approved on
  2026-07-29; the fix shapes are recorded in the plan's defects section.

Design choices, resolved in the 2026-07-29 review (details in the plan):

- Item 2 lands as shape A: the per-packet verdict rides `PacketMeta` and is
  honored at the two netstack ingress parse sites. Verifying in sys-io's RX
  token was rejected for duplicating parsing on the hot path and dead-ending on
  coalescing's `NEEDS_CSUM` super-segments.
- Item 3 randomizes ephemeral ports on external devices only; the logical
  loopback keeps lowest-free allocation, so `test_simultaneous_open` keeps its
  determinism with no test-only hook. 3.3 also drops 127/8 addresses arriving
  on external ingress, enforcing the premise that loopback has no off-path
  attacker. Revisit unification once Step 12's local-port work lets the test
  pin its source port.
- Patch 4.2 is kept: the silent drop already defeats the blind-SYN attack, but
  it strands an honest rebooted peer reusing the tuple (keepalive is off by
  default); the challenge ACK is the RFC 9293 3.10.7.4 recovery path.

Roadmap note from the same review: **SYN cookies are planned** after this step.
They slot in after Step 10 item 2, because cookies without timestamps lose
window scaling. Step 6 already lays their groundwork: D1's dual fix makes the
cookie path's second `remote_last_win` writer safe, 3.2's SipHash and key
handling are reusable (a cookie is an ISN), and 6.2's half-open cap is the
trigger a cookie mode engages on.

## Step 7 -- measure the receive ceilings

Run measurement-only work from:

- TCP receive-window analysis against representative full-OS workloads when
  available; and
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

Prerequisites, as sequenced by Step 6: the half-open bound from Step 6 item 6 is
required, and the lazy or growable buffer work moved to Step 12, so a raise
before Step 12 lands still commits its full buffers to every listening socket.
Either take Step 12 first or approve that cost explicitly.

1. Review representative workload evidence and choose whether a fixed default
   raise is justified.
2. Obtain approval for the established-socket memory budget.
3. Change RX and TX defaults separately if measurement benefits from
   separating their attribution.
4. Repeat the paired full-OS performance and functional gates.

## Step 10 -- tune TCP loss behavior

Execute core Step 3 as separately measured patches:

1. Enable Reno.
2. Improve RTT sampling before lowering the minimum RTO, or justify a
   path-dependent floor. This item now also owns TCP timestamps and PAWS, moved
   here from Step 6 item 4: offering TSopt costs 12 bytes on every segment, and
   RTT sampling is the benefit that pays for it, so both land and are measured
   together. sys-io installs no `tsval_generator` today, so timestamps are off
   entirely and PAWS has nothing to compare. This item is also the gate for the
   planned SYN-cookie work (2026-07-29 review): cookies encode MSS in the ISN
   bits, but wscale and SACK survive only in the timestamp option, so cookies
   before TSopt would lose window scaling on every cookie-mode connection.
3. Raise the out-of-order assembler capacity.
4. Revisit neighbor and route capacities separately from ARP security. Step 6
   item 5 hardens ARP admission and eviction at the current eight entries, which
   makes capacity a performance question rather than an attack surface -- but its
   admission rule is strictly more effective with more slots, so do not defer
   this item indefinitely.

Keep congestion control's local performance cost separate from its
deterministic protocol-correctness evidence.

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
- independent RX/TX floor, cap, units, overflow, and zero semantics;
- lazy or growable listening-socket buffers, moved here from Step 6 item 6. A
  socket that starts small and grows needs the window scale it will eventually
  want to be advertised in its SYN, and the scale is derived from the receive
  capacity at construction, so this needs an explicit construct-with-shift API
  plus a grow-an-empty-ring API in the netstack -- the same fork surface
  per-socket sizing needs. Designing it twice is waste, which is why Step 6
  delivers only the half-open bound;
- whether the local port of an outbound connect becomes specifiable, which is
  what Step 6 item 3's alternative (randomizing loopback ephemeral ports too)
  would require before `test_simultaneous_open` could be rebuilt.

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
