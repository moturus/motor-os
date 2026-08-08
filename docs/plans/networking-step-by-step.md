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

Current step: **13 -- finish the vDSO ownership work**, executing re-scoped
vDSO Stage 4. Patches 1-3 -- the `NetClient`/`NetDriver` pair with the
async fallible `connect()`, the host-side reservation protocol, and the
explicit-reservation `UdpSocket::bind_reserved` /
`TcpStream::connect_reserved` -- landed 2026-08-07 (`ed59e765`,
`18b1889c`, `3b6976f3`). The six open design questions were decided in
review the same day (`facee970`), and the accept/listener work they
unblocked landed as patches 4-6: cancellation re-queues with atomic
dispatch (`d1325a69`), the host-owned listener's `bind_reserved` and
`post_accept` (`783160a4`), and the reserved cancellation siblings plus
the park regression (`dc2488de`). Decisions 1-5 are implemented and
pinned by regressions; decision 6 dissolved the notification-state
bullet. The records, their review-flagged decisions, and one open gate
anomaly are under Step 13 below.

**2026-08-08: the branch absorbed `main` (the kernel slab redesign) and
its history was rewritten in the process** (merge `bd0edc9b`). The hashes
above are the rebased branch's; the Step 13 records keep the pre-rebase
hashes they were gated on, and the two histories' patches are
content-identical (equal `git patch-id`): `c2137b85`->`ed59e765`,
`8f616fdc`->`18b1889c`, `71e7971e`->`3b6976f3`, `933db0e8`->`facee970`,
`6d213ec8`->`d1325a69`, `a1db0ab2`->`783160a4`, `8d49e910`->`dc2488de`.
One debug and one release `full-test-networking.sh` run were taken on the
merged tree before resuming; both passed rc=0 on the first attempt with
every Stage 4 marker present.

**Next steps, in order:**

1. Re-scoped Stage 5, the ownership flip -- provisioning coalescing before
   waiter work, the connection-storm soak owed when the async connect gains
   its production caller, and the deletion list including the compat host,
   the startup spin, and the thread handles.

Stage 4 completed 2026-08-08: the preparation bullet landed as patches 7
(the vDSO `NetPool` and channel-thread entry) and 8 (the accept-pump
type), both additive and unreachable until the Stage 5 flip.

Step 11 is complete and fully committed. Stage 3 landed as four patches, one
per socket type and then the shared listener work: `RtUdpSocket` 2026-08-04 as
`6ee7ba50` (the hash this document previously carried, `40df8637`, is not in
the tree), `RtTcpStream` as `f178dfbf`, `RtTcpListener` as `fdc24bb5`, and
patch 4, the optional readiness observer, 2026-08-05 as `39a0b9b4` (recorded
here as staged at the time; it is in the tree). The FD table stores a vdso
wrapper that owns `O_NONBLOCK`, the `SO_*TIMEO` deadlines and the raw option
dispatch; the native socket keeps only what sys-io must be told; `moto_io::net`
holds no POSIX state and no downcast crosses the crate boundary in either
direction. Patch 3.1, the accept-starvation fix taken on guidance, landed
2026-08-05 as `b571a5be`: a blocking `accept()` could be starved by an accept
request the listener already had outstanding, and the failure was a silent
hang. The full records are under Step 11 below.

**The re-scope of vDSO Stages 4 and 5 that Step 13 depends on is done**,
committed 2026-08-05 as `3fa997fe` into `vdso-rewrite.md` ("Stages 4 and 5
re-scoped against the tree Stage 3 left"). It struck three satisfied bullets,
enlarged two, split the accept-reservation work into its own patch, and moved
Stage 5's estimate from 5-8 to 7-9 patches.

**2026-08-07: the branch absorbed concurrent non-networking work** (kernel/
sys-io OOM handling, the TUI/is_terminal work, and the main/dev image split).
On instruction, one debug and one release `full-test.sh` run were taken on the
merged tree before resuming; both passed rc=0 on the first attempt.

**A close regression introduced by item 1b.1 is fixed as item 1b.2, on
instruction, 2026-08-05, committed as `cc4940f1`.** A socket its client
dropped without ever writing a byte was closed gracefully and then lingered,
absorbing the peer's writes into a buffer with no reader for the whole
60-second linger. mio's `tcp::test_write_error` took exactly that long, every
run, in both profiles. It resets now.

**The sys-io abort found while gating that fix is fixed, on instruction, as
Step 10 item 5, 2026-08-05, committed as `58622c82`** (recorded here as staged
at the time; it is in the tree). Two `get_pid` unwraps in
`runtime/net/tcp_listener.rs` took the machine's networking down when a client
died with a request still queued. Both records are under Step 10 below.

**Two findings from that work are reported and not fixed**: the kernel panics
with OOM when several processes each hold a few hundred TCP listeners, and the
abort has no in-suite regression because its window cannot be forced without a
sys-io test hook. Both are under Step 10 item 5.

**The branch was re-baselined at `e55c0223` first**, because it had merged
`main` and is now the same commit as it. Three debug `full-test.sh` runs passed;
of three release runs **one failed**, on a pre-existing host-side defect that is
recorded as open under Step 0 below and is not networking. On guidance, this
work gates on `full-test-networking.sh`, which does not contain it.

**Step 10 is complete** -- items 1a, 1a.1, 1b, 1b.1, 1b.2, 1c, 2 (in three
parts), 3, 4, 4a and 5, the last two of which the work turned up rather than
the plan. Its record follows.

Step 10 detail: **tune TCP loss behavior.** Item 1a, enabling Cubic, plus
the Cubic fixes, the MTU hardening, and the harness sync committed as
`6f003620`. Item 1b, making the congestion window actually bound what is sent,
committed as `712e4a18` -- it is what turned everything item 1a enabled from
advisory into load-bearing, and Motor now has working congestion control for
the first time. Steps 8 and 9 are both held on decisions rather than blocked on
work, and the execution order skips forward past them.

Item 1c, the initial congestion window, is done: RFC 6928's IW10 on decision
2026-08-02, and **the largest single win this work has produced** -- 13% to 38%
off p50 flow completion between 4 KiB and 256 KiB. It needed the flow-completion
tool built for it, and that tool first had to be unblocked by fixing the defect
it found, **Motor resetting a drained TCP connection instead of closing it**
(item 1b.1 below, and `core-networking-rewrite.md`, P2).

**Item 2 is done, in three parts, taken out of order on purpose.** TCP
timestamps and PAWS landed 2026-08-03, on decision, because they can be gated
here and the RTO floor cannot: this rig loses no packets and injecting loss
needs CAP_NET_ADMIN, which is not available to this work. Enabling the
option exposed a preexisting defect that took the VM's networking down entirely
-- **`dispatch()` did not subtract a segment's own options from its payload** --
fixed with it. TSopt also unblocks the planned SYN-cookie work, which loses
window scaling without it.

**RTT sampling landed 2026-08-03 as part two.** The finding that ordered it was
a measurement rather than a suspicion: on a path with a ~60 usec RTT every
sample truncated to zero, so `srtt` and `rttvar` were permanently zero and the
RTO was a constant at its floor. The estimator now reads the microseconds
`Instant` always carried. It is deliberately inert on the wire -- the 1-second
floor rounds a 60-usec estimate up exactly as it rounded up a zero -- and that
is the point: the floor is now the only thing between the estimator and the
path, so **part three is a decision about one constant and nothing else.**

**Part three, the floor, landed 2026-08-03 on decision: 200 ms, matching
Linux's `TCP_RTO_MIN`**, which was checked against this host's headers and
`net.ipv4.tcp_rto_min_us` rather than recalled. A single lost segment on a
60-usec path now costs 200 ms instead of a second. It is argued rather than
demonstrated -- loss recovery is the one thing this rig cannot produce -- so the
gate shows it breaks nothing, not that it helps.

Three defects are recorded as owed rather than fixed. Two are under item 1b: a
loss reaches Cubic twice (`beta` squared, 0.49, per loss) and `on_congestion`
uses `ssthresh = cwnd >> 1` rather than `cwnd * beta`. The third is under item 2:
the immediate-reply path echoes the incoming segment's timestamp rather than
TS.Recent, which understates a peer's RTT sample during loss recovery. All three
are unobservable on this rig for the same reason -- it does not lose packets.

A method correction came out of item 1a's benchmark and applies to every paired
gate from here: **A/B/A/B confounds the tree with block position.** Only the
first block of a sitting stays in the host's fast regime, and that block is
always the clean arm, so pooling all four blocks flatters clean by over 10% on
the default workload. Drop the first block from both arms, or counterbalance the
order.

**Extended by item 1c, 2026-08-02:** the position effect is not only the first
block. That sitting's default TX fell monotonically across all five blocks,
-8.3% end to end, straight through both arm boundaries, and its worst block was
a clean one -- a drift invisible in a pooled A-vs-B table and obvious in a
per-block one. Record per-block medians for every paired gate, not just the
pooled row, and read the same-tree pairs before believing the cross-tree one.

**Step 8 is held by decision, 2026-08-02**, with its gate measured. Booting the
same image under all three VMMs settled which option is portable: Cloud
Hypervisor v52.0 does not offer `MRG_RXBUF`, so Option A is the only scheme with
universal reach -- the reverse of the coalescing plan's standing recommendation,
which is corrected. Option A's costs are structural, not incidental: RX ring
depth falls to 14 slots on every VMM (only QEMU offers the indirect descriptors
that would restore it, and Firecracker cannot even resize the queue), and posted
receive memory goes from 262 KB to 918 KB per device. Neither option was taken.
Full gate record under Step 8 below; it resumes from that record.

**Step 9 is held on a negative finding.** The receive window is 3.9x from
binding on this rig and cannot be made to bind, so no local benchmark can
justify the raise; it needs a representative long-RTT workload, which does not
exist on this host, or an explicit decision on the Motivation table's arithmetic
plus an approved memory budget. Step 7 committed as `33df3c02`.

The defect Step 7 turned up is closed. `VIRTIO_NET_F_MTU` is not negotiated
here, sys-io fell back to a 1536-byte frame MTU, and Motor advertised TCP MSS
1482 on a path that carries 1460. Per AGENTS.md it was recorded rather than
fixed inside a measurement step, then fixed on guidance in the same commit.
Step 6 before it landed all nineteen patches and completed all six items (plan
reviewed 2026-07-29; D1-D4 approved, design choices resolved; patches 1-10,
10.1, 10.2 and 11-19 landed 2026-07-29 to 2026-08-01).

Patch 10 became three when its mechanism was settled against measurement: 10
grows the listening pool, 10.1 shrinks it again, and 10.2 answers overload by
dropping rather than resetting. Later numbers are unchanged, so item 5 is still
patches 11-13.

Step 6's patches are numbered 1 to 19 in execution order, and that number is
each patch's only name; a patch that splits keeps its number and takes a
suffix, as patch 10 did, so the numbers after it never move.
`docs/plans/core-safety-hardening.md`
Sequencing holds the table: what each patch does, which of Step 6's six topical
items it belongs to, and -- for patches 1-7, which were committed under the
earlier item-local labels 1.1 through 2.3 -- the commit it landed as.

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
- Step 6 patch 1 is complete. `remote_last_win` now records the advertised
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
- The exact patch-1 source state passed formatting, Motor-target debug and
  release builds, debug and release clippy with only pre-existing warnings,
  both netstack closures with warnings denied (526 plus 7 and 665 plus 7
  tests), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries or tolerated failures. The
  paired release `rnetbench` A/B is within the kill criteria; the default
  workload was re-measured as A/B/A blocks after the first pair straddled a
  host performance-state shift that the clean tree reproduced exactly.
- Step 6 patch 2 is complete. The receive path can no longer abort on
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
  patch 1 no packet sequence produces it. The fail-first record was captured
  first: in debug both `process()`-level regressions abort the unfixed source
  on the short-write `debug_assert!`; in release the beyond-the-ring one
  aborts on the release-live ring-buffer `assert!` and the crossed-window one
  survives holding a phantom assembler hole, which is D4's shape and
  patch 3's subject.
- Step 6 patch 3 is complete, and closes D4. The numeric bound it was to add
  was already there: patch 2's write-site re-check is the caller-side bound,
  because the assembler's offsets and the ring's unallocated region share an
  origin. It is TCP's only path into the assembler, and nothing it depends on
  changes between the acceptance computation and it. So patch 3 delivered the
  invariant enforcement D4's entry predicted would remain after patches 1 and 2:
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
- Step 6 patch 4 is complete, which completes item 1. The seven abort-shaped
  sys-io sites the Step 1 audit deferred now log and recover locally: the
  device buffer cache reports exhaustion instead of asserting, the RX task
  re-posts the buffer of a failed completion and degrades to fewer in-flight
  buffers rather than aborting, a TX token with no pooled buffer drops its
  packet through a heap scratch, the UDP-address and ICMP-identifier removals
  log, the TCP TX `todo!()` ends its task the way a normal TX close does, and
  the disconnect-path assert logs each missing socket id. Nothing changes on
  the success path.
- Every one of those paths is unreachable through the public protocol, so by
  the plan's own provision the existing full-OS suites are the coverage and no
  new test was added. `tx_task`'s remaining `pop_front().unwrap()` was audited
  and left: reaching it needs a TX virtqueue too small for one maximal
  packet's descriptor chain, which would break transmission outright.
- Step 6 patch 5 is complete, which starts item 2 and closes D2. The
  device-written virtio-net RX header used to be discarded when the descriptor
  chain was released; it is now read while the completion still owns the chain,
  and `post_read` resolves to the frame plus an `RxMeta` carrying the decided
  per-packet verdict, `l4_csum_vouched`. sys-io does not consume the verdict
  yet -- carrying it to the netstack is patch 6 -- so packet acceptance is
  unchanged.
- A completion that cannot be one we asked for is now rejected, counted in the
  new `net.device.rx_dropped`, and its buffer re-posted: a used length below
  the header length (D2), a used length whose payload overruns the buffer we
  posted, a nonzero `gso_type` with no guest GSO offload negotiated, or
  `num_buffers > 1` without `MRG_RXBUF`. The overrun bound was added to D2's
  scope on finding that `IoBuf::set_len` asserts against capacity in release
  too, so the over-length case aborts sys-io exactly as the underflow does.
- None of that is reachable from the network -- the device is the host -- so as
  in patch 4 no packet-level test was added. The new full-OS assertion instead
  covers this patch's actual risk, rejecting frames the host legitimately
  sends: `test_device_rx_validation` requires that the device delivered frames
  this boot and that the driver rejected none of them.
- Instrumented evidence, removed before the gate: the header read returns live
  values (lengths 42-1514, `gso_type 0`, `num_buffers 0`, and `flags` 0x1
  `NEEDS_CSUM` on host-originated TCP after two unflagged ARP-shaped frames),
  and rejecting every 64th completion fails the new assertion while the VM
  keeps running normally, which is the recovery the reject path is supposed to
  have. That flag distribution is also patch 6's input datum: ordinary
  traffic here does arrive vouched, but not all of it does.
- The exact patch-5 source state passed formatting, Motor-target debug and
  release builds, debug and release clippy with only pre-existing warnings,
  both netstack closures with warnings denied (531 plus 7 and 670 plus 7
  tests), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries or tolerated failures. The new
  device-RX assertion, systest's `PASS` marker, and the tokio suite are present
  in all six. No paired `rnetbench` A/B: the plan assigns item 2's measurement
  to patch 6, where the per-frame policy lands.
- Step 6 patch 6 is complete, and closes the checksum-offload trust gap.
  sys-io now advertises receive verification as on for every frame, and the
  `GUEST_CSUM` saving is taken per frame instead: patch 5's verdict rides the RX
  queue into `PacketMeta::l4_csum_vouched`, and the TCP and UDP ingress parse
  sites drop software receive verification for exactly the frames the device
  vouched for. Frames nobody vouched for -- what QEMU delivers for traffic the
  host did not validate -- are now verified rather than trusted, and a failure
  is counted in the new `net.rx.csum_failed`.
- Three implementation decisions are recorded for review in the patch plan: the
  verdict is threaded through `process_tcp` as a parameter rather than stored on
  `InterfaceInner`, because a stored field can go stale and `process_udp`
  already took one; the driver refuses to honor a vouch when
  `VIRTIO_NET_F_GUEST_CSUM` was not negotiated, so the change cannot verify less
  than before in any configuration; and the counter is attributed on the parse
  failure path, leaving the success path unchanged.
- Measured, with temporary counters removed before the gate: across a whole
  debug suite, 556 frames were delivered and software verification ran **zero**
  times -- every TCP and UDP frame on the virtio interface arrives vouched, and
  logical loopback ignores checksums entirely. So the full-OS assertion added
  here is a no-regression check on the vouch, and the deterministic per-verdict
  coverage in patch 7 is the only thing that will exercise verification.
- Fail-first, by sabotage: dropping the vouch on every 64th completion produced
  7 verifications and 7 failures at 496 frames and failed the new assertion,
  while the VM kept running on TCP retransmits. Equal counts prove that ordinary
  host-originated frames carry only a pseudo-header sum, so the vouch is
  load-bearing, and that the verdict reaches the parse site.
- The exact patch-6 source state passed formatting, Motor-target debug and
  release builds, debug and release clippy with only pre-existing warnings, both
  netstack closures with warnings denied (531 plus 7 and 670 plus 7 tests), and
  three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries or tolerated failures. The
  paired release `rnetbench` A/B/A is within the kill criteria: against the
  bracketing clean block, RR +1.30 usec / RX +1.67% / TX -0.91% on the default
  workload and RR +0.47 usec / RX -0.67% / TX -0.55% on bulk. The host's known
  two default regimes appeared again in the first block, which the A/B/A design
  brackets; all samples are retained in the patch plan.
- Step 6 patch 7 is complete, which completes item 2 and unblocks Step 8. The
  netstack's testing device now carries a `PacketMeta` per queued frame, so its
  `RxToken::meta()` states a real verdict, and two `Interface::poll` regressions
  -- one TCP, one UDP -- run the same frame through five combinations of verdict
  and checksum-field content. A corrupt or pseudo-header-only field nobody
  vouched for is dropped, counted in `net.rx.csum_failed`, and draws no reply at
  all; the same fields vouched for are delivered unexamined; and a correct
  unvouched frame is delivered, which is what makes the drops attributable to
  the checksum.
- `NEEDS_CSUM` and `DATA_VALID` are one bool by the time a frame reaches the
  netstack, so the two vouched cases differ in what the checksum field holds: a
  corrupted value, and the real pseudo-header sum a host's partial-checksum
  egress path leaves there.
- Fail-first, by sabotage in both directions: ignoring the verdict fails both
  tests at the vouched-corrupt case, and waiving it unconditionally -- the
  pre-patch-6 behavior -- fails both at the first case, accepting a corrupt
  segment. The trust gap patch 6 closed is now caught by a test rather than by
  argument.
- Nothing in the shipped image changed: the testing device and both regressions
  are `#[cfg(test)]`, so no paired `rnetbench` A/B was required.
- Patch 7's first gate attempt stopped on a pre-existing defect outside this
  repository, root-caused and fixed under the entry below. Its six runs were
  discarded rather than retried; the recorded gate is the rerun.
- The exact patch-7 source state passed formatting, Motor-target debug and
  release builds, debug and release clippy with only pre-existing warnings, both
  netstack closures with warnings denied (533 plus 7 and 672 plus 7 tests), and
  three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries or tolerated failures. Both new
  regressions, `test_device_rx_validation`, both DNS resolver self-tests across
  the restart, systest's `PASS` marker, and the tokio suite are present in all
  six, and the negative DNS query returned `NotFound` directly in all six.
- Step 6 patch 8 is complete, which starts item 6 with the measurement its cap
  must be chosen against. `net.tcp.half_open` counts listening sockets that have
  taken a peer's SYN and are still waiting for the handshake to finish -- the
  memory a SYN flood commands, bounded today only by the 15-second
  listening-socket timeout. sys-io keeps it with a guard spanning the listen
  task's SYN-RECEIVED wait, so every exit decrements, including the socket
  disappearing under the task. `net.tcp.syn_rst_unmatched` counts bare SYNs the
  netstack reset because no socket accepted them; it is counted at the reset site
  and drained per poll, the same shape as `net.rx.csum_failed`.
- Patch 8's specified full-OS test could not be built, and the deviation was
  approved before implementation. Holding a socket in SYN-RECEIVED needs a peer
  that sends a SYN and withholds the ACK: the guest has no packet injection, the
  host would need `CAP_NET_RAW` in an unprivileged gate, and every peer that
  answers finishes the handshake in the poll after the one that took its SYN. The
  gauge is therefore real but never sampleable for ordinary traffic. A third
  metric, `net.tcp.half_open_total`, carries the full-OS half: eight loopback
  connect/accept pairs must raise it by exactly eight and return the gauge to its
  baseline, and a connect to a closed port must raise `syn_rst_unmatched` by
  exactly one. The deliberately stalled handshake is a netstack `Interface::poll`
  regression, where withholding the ACK is trivial: the socket is still in
  SYN-RECEIVED ten seconds on, retransmitting its SYN|ACK.
- Fail-first, by sabotage in four directions: no guard fails the systest at 0
  against 8; a leaked guard fails it at 58 against a 50 baseline; removing the
  netstack increment fails the unmatched-SYN case; and counting every unmatched
  reset fails the unmatched-ACK case. Live evidence through the ordinary stats
  path: `half_open_total` reads 2 on a freshly booted VM whose only traffic is
  two inbound ssh connections and 107 after a full systest run, the gauge 0 both
  times.
- The exact patch-8 source state passed formatting, Motor-target debug and
  release builds, debug and release clippy whose output is identical to clean
  `HEAD`'s, both netstack closures with warnings denied (534 plus 7 and 673 plus
  7 tests), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries or tolerated failures. No paired
  `rnetbench` A/B: the plan's gate list does not ask for one, and nothing on a
  packet success path changed.

Between patches 8 and 9 -- a place to test sys-io from (2026-07-31):

- Patch 9's cap lives in sys-io, and sys-io had no reachable unit-test seam.
  It cannot build for the host (`moto-async` refuses to compile off a Motor
  target, `lib/moto-async/src/timeq.rs:12`), no cargo runner is configured for
  the Motor target, and no harness or Makefile target runs its tests. The
  `#[cfg(test)] mod tests` in `runtime/net/config.rs` and
  `runtime/fs/lock_manager.rs` had therefore never run.
- By user direction, sys-io now carries its own self-tests instead of a crate
  extracted for testability: `crate::self_test` holds the runner, each module
  keeps its tests beside the code they cover, and `runtime::net::SELF_TESTS`
  gathers the net-side ones because the modules holding them are private to
  `net`. All of it is `#[cfg(debug_assertions)]`, so a release sys-io has no
  self-test code in it at all.
- systest triggers them over the existing socket-stats service with a new
  `CMD_SELF_TEST`, also debug-only on both sides, and fails with the first
  failure's name, file, line, and values. The tests report failures rather than
  asserting them: sys-io is `panic = "abort"`, so an assertion firing inside it
  would take networking down and present a test failure as a dead VM.
- The config tests moved in with this patch, converted to return `Err` instead
  of panicking; `lock_manager`'s follow in the next patch. Fail-first, both
  directions: inverting the longest-prefix comparison in `find_route` fails one
  of the five with `Some((0, 192.168.4.2)) != Some((1, 192.168.6.2))` and leaves
  sys-io serving, and emptying the registry trips systest's guard against a
  suite that silently became empty.
- The seam paid for itself immediately: `LockManager::disconnect` unwrapped
  `files.get_mut(entry)` for every entry a departing connection tracked, and
  `grant` unwrapped the connection behind each waiter. Neither is reachable
  through the client API today -- `files` loses an entry only once no connection
  holds or waits on it -- so these were latent, not live. They are now a skipped
  entry and a logged mismatch: restoring the unwrap and booting shows why, with
  `panicked at lock_manager.rs:165` on `sys-io:ss` taking sys-io down
  (`status 0xbadc0de`), which costs the VM its filesystem and its networking and
  presents as a hang rather than a test failure.
- The four `lock_manager` tests moved next, under `runtime::fs::SELF_TESTS`
  chained into the same runner, bringing the suite to nine. That is every
  `#[cfg(test)]` block sys-io had; a new one now has a place to go. Fail-first:
  suppressing the shared-batch grant loop in `LockManager::grant` fails
  `compatibility_fifo_and_shared_batching` with `Ok([4]) != Ok([4, 5])`, again
  with sys-io still serving.

Step 6 patch 9 -- the half-open cap (2026-07-31):

- `runtime/net/half_open.rs` caps half-open listening sockets at 128 globally
  and 32 per listener, consulted where `create_tcp_listening_socket` used to
  spawn a replacement unconditionally. At the cap the replenishment oneshot is
  parked instead of sent, and `HalfOpenGuard::drop` hands one back. Six
  self-tests cover the accounting; details and the sizing rationale are in
  `core-safety-hardening.md`, item 6.
- User decision on the roadmap question raised here: SYN cookies stay where the
  2026-07-29 review put them, after Step 10 item 2. They need TCP timestamps
  (sys-io installs no `tsval_generator`, so wscale and SACK have nowhere to
  survive) and the RFC 6528 ISN work's keyed hash, and this cap is the trigger
  they engage on rather than something they replace.
- Follow-up the same day, by user request: both caps are now
  `max_half_open_global` and `max_half_open_per_listener` in
  `/sys/cfg/sys-net.toml`, defaulting to 128 and 32. `NonZeroUsize` rejects a
  zero while parsing -- at zero the listening pool would never be refilled
  again. Three more self-tests, 19 in all, and the config-to-budget wiring
  (which no self-test can reach) was proved by shipping
  `max_half_open_global = 1` in the image: sys-io logged the 1 and deferred 11
  replenishments, with systest still reaching `PASS`.

Step 6 patch 10 -- the listening pool grows into bursts (2026-07-31):

- Measured before designing, because this patch's entry left its mechanism to
  patch 9's measurements. A host client that issues every `connect` before
  collecting any completion loses half of sixteen simultaneous connections
  against a listener that bound through `std`, and what gets through does not
  improve from one burst to the next: the pool is the backlog, and by default it
  is four sockets deep. A refusal is an RST, so the peer gets `ECONNREFUSED`
  rather than a retry.
- `runtime/net/backlog.rs` gives each listening address a pool that starts at
  the size the client asked for and doubles whenever it is drained, with
  replenishment creating the whole deficit rather than one replacement. Bounded
  per pool by `max_backlog_per_listener` (32, where an explicit request would
  have been refused anyway) and across pools by `max_backlog_global` (128 extra
  sockets, 32 MiB), both in `/sys/cfg/sys-net.toml` and both rejecting zero.
- After: sixteen at once loses 2 of 80 rather than 42 of 80, and thirty-two
  loses 7 of 160 rather than 118. Only the first burst of a given depth pays;
  every one after it is served whole, up to the cap.
- Nine more self-tests, 28 in all, and four sabotages, each rebuilt and booted
  with sys-io still serving. Sizing rationale, the full before-and-after tables,
  and the half-open ceiling this raises are in `core-safety-hardening.md`,
  item 6.
- User decision recorded there too: the shrink is patch 10.1, and
  drop-rather-than-reset -- which item 6 had parked until Step 8's batching
  evidence -- becomes patch 10.2, immediately after.

Step 6 patch 10 follow-up -- growth triggers on a refused request (2026-07-31):

- Found while gating patch 10.1: patch 10 grows a pool when sys-io's count of
  sockets in `Listen` reaches zero, and that count can never reach zero for a
  pool the netstack has actually run out of. The netstack takes and refuses
  SYNs inside one poll; the departures are counted afterwards, interleaved with
  the replenishment each one spawns. Six identical bursts of 24 simultaneous
  connects drew 17 or 18 resets each while the pool grew in only one of them.
- The netstack now records the local endpoint of each connection request it
  reset, deduplicated and capped at eight per poll because the addresses come
  from the network. sys-io drains them where it already drains the counter and
  deepens the pool that owns the address; an address nothing listens on owns no
  pool. A refusal also zeroes that window's low-water mark, since a pool that
  lost a request was using everything it had.
- Emptying the pool still grows it -- it is the last warning before a request is
  refused -- so the two triggers are kept together. One netstack regression and
  two self-tests, 34 in all; the rationale and the traced evidence are in
  `core-safety-hardening.md`, item 6.

Step 6 patch 10.1 -- the growth is returned (2026-07-31):

- A sweep every 5 seconds returns the sockets a pool kept in `Listen` through a
  whole window, down to what the client asked for at bind, so one burst -- or a
  scan of a few dozen ports -- no longer pins the memory for the listener's
  life. What sat above the window's low-water mark is what goes back, so a pool
  that dipped keeps the depth it dipped to, and the window a burst falls in
  returns nothing at all: a burst therefore holds its growth for 5 to 10
  seconds after the last connection, and for as long as bursts keep arriving.
- The timer exists only while there is growth to reclaim. The first growth to
  charge the global bound starts the sweep task and the sweep that leaves the
  bound empty ends it, so a VM that never meets a burst never arms one and boot
  arms nothing.
- A sweep drops a socket by aborting it, which ends its listen task exactly as a
  socket that took a SYN and lost it does; the teardown, the gauge, and the pool
  accounting all run on the path that already owns them. The drops it asks for
  are recorded on the pool and spent before growth is considered, so a pool
  cannot read its own reclamation as the burst it was too shallow for. Sockets
  in SYN-RECEIVED are handshakes, not slack, and are left alone.
- `net.tcp.backlog_extra` is new: the listening sockets demand added beyond what
  clients asked for, which is what `max_backlog_global` bounds and what patch 10
  left unobservable. Four self-tests, 32 in all, and the full-OS half is
  `test_backlog_growth_and_shrink`: 24 simultaneous connects must raise it, and
  both it and the listening-socket gauge must return to their pre-burst values
  while the listener is still bound.
- Five sabotages, each rebuilt and booted with sys-io still serving; the two
  implementation decisions above, the sizing rationale, and the full fail-first
  record are in `core-safety-hardening.md`, item 6.
- The exact source state of the follow-up and this patch together passed
  formatting, Motor-target debug and release builds, debug and release sys-io
  clippy byte-identical to clean `HEAD`, both netstack closures with warnings
  denied (535 plus 7 and 674 plus 7 tests), and three consecutive debug plus
  three consecutive release `full-test-networking.sh` runs with no retries and
  no tolerated failures. All six contain the new full-OS regression, the
  netstack closure's 535 tests, a negative DNS query returning `NotFound`
  directly, and all four flush-stress workers completing 4,000 iterations; the
  debug three report 34 self-tests and the release three none. The two patches
  were gated as one tree because this patch's full-OS regression cannot pass
  without the follow-up's trigger fix. The paired release `rnetbench` A/B/A for
  the follow-up's per-poll check is within the kill criteria; all samples are in
  the hardening plan.
- An earlier three-run debug gate of this patch alone is discarded: it is what
  found the trigger defect, failing in two runs of three. Two harness runs also
  collided over the shared VM image during that attempt, which presents as
  sys-io reporting `Cannot proceed without a filesystem`; those runs are
  discarded as an environment error, not a product signal.

Step 6 patch 10.2 -- an overloaded listener drops rather than resets
(2026-08-01), which completes item 6:

- Growth cannot help the first burst of a new depth: a pool only learns it is
  too shallow from the requests it loses. Losing them to a reset is what made
  them terminal. `process_tcp` now drops a connection request no socket took
  when a listener owns the endpoint, counts it in the new
  `net.tcp.syn_backlog_dropped`, and records the endpoint for the pool to
  deepen; a request for an endpoint no listener owns keeps its reset, so a
  closed port still means `ECONNREFUSED`.
- The netstack answers "is a listener there?" from state it already owns rather
  than from a set sys-io mirrors into it. `listen_endpoint` is set by `listen`,
  survives every state a socket that took a SYN moves through, and is cleared by
  `connect`'s reset, so a socket whose listen endpoint would have accepted the
  request is proof of a listener that is out of sockets -- and an outbound
  connection's local port can never answer for one. The decision, the shape it
  was chosen over, and its one stated limit are in `core-safety-hardening.md`,
  item 6.
- Measured, five bursts of 24 simultaneous guest-side connects against a
  four-deep pool: 74 of 120 lost with the patch reverted, none of 120 with it,
  and the resets are gone rather than converted. The endpoint list moved from
  the reset site to the drop site, so a scan of closed ports can no longer crowd
  out the listener that really ran out.
- `test_backlog_growth_and_shrink` now requires the whole burst to arrive, and
  `test_half_open_accounting`'s closed-port connect is bounded so that turning
  its reset into a drop fails the gate instead of hanging it. One netstack
  regression covers both verdicts, the endpoint bound, and that a dropped
  request draws no reply at all. Three sabotages, each rebuilt and booted with
  sys-io still serving; the full record is in the hardening plan.
- The exact patch-10.2 source state passed formatting, Motor-target debug and
  release builds, debug and release sys-io and systest clippy identical to clean
  `HEAD`, both netstack closures with warnings denied (535 plus 7 and 674 plus 7
  tests, unchanged because the existing unmatched-SYN regression was reworked
  rather than added to), and three consecutive debug plus three consecutive
  release `full-test-networking.sh` runs with no retries and no tolerated
  failures. All six contain both backlog regressions, the netstack closure's 535
  tests, a negative DNS query returning `NotFound` directly, and all four
  flush-stress workers completing 4,000 iterations; the debug three report 34
  self-tests and the release three none. An earlier debug run is not counted: it
  built a tree differing from the final one by three comments in `backlog.rs`,
  so a fourth debug run was added rather than claiming six runs on one tree.
- No paired `rnetbench` A/B: the gate list does not ask for one and nothing on a
  packet success path changed. The new socket-set walk runs only for a request
  no socket took, a path that already walks the whole set with the heavier
  `accepts()` predicate.

Step 6 patch 11 -- an unsolicited packet may not displace a neighbor
(2026-08-01), which starts item 5:

- Eight forged ARP requests used to flush the whole neighbor cache, the gateway
  included, because the cache filled from any same-subnet request aimed at us
  and filling a full cache evicted the entry closest to expiry. A request now
  admits through `Cache::fill_unsolicited`, which may refresh or replace a
  mapping the cache already holds and may take a free slot, but may never
  displace another entry. A reply keeps the evicting fill, which is what still
  lets our own resolution through a cache someone has filled.
- Found while implementing it, and corrected in the hardening plan: the item's
  verified state said IPv6 fills only from neighbor advertisements. A neighbor
  *solicitation* carrying a link-layer address fills the same shared cache --
  the identical primitive under a different name -- so it takes the same
  admission path, while advertisements stay with replies.
- Patch 11's own wording is corrected there too. "Removes the eviction primitive
  outright" would mean no fill may ever evict, which strands the gateway
  permanently behind a request flood: the reply to our own ARP could never be
  admitted, so all off-subnet egress would die and the patch would leave the
  tree worse than `HEAD`. What it removes is the *forgeable* primitive; forged
  replies remain, and protecting the gateway from those is exactly patch 12.
  Decided with the maintainer before implementation.
- `net.neighbor.admission_refused` is new: mappings a full cache refused,
  drained per poll where the other netstack counters are. Four netstack
  regressions -- two on the cache, one each driving a real ARP request and a
  real neighbor solicitation through `process_ethernet` -- and the full-OS half
  is systest's `test_neighbor_admission`, which requires the counter to be 0
  after a boot whose traffic includes the ssh session systest arrives over.
- Two sabotages, in both directions: routing the admission back to the evicting
  fill fails three of the four regressions, and dropping only the counter
  increment fails both interface regressions at 0 against 1. Details, the three
  implementation decisions, and the full fail-first record are in
  `core-safety-hardening.md`, item 5.
- No paired `rnetbench` A/B: the gate list does not ask for one, and the split
  costs one enum comparison on ARP/NDISC ingress, which is control traffic that
  already parses and replies.
- The exact patch-11 source state passed formatting, Motor-target debug and
  release builds, debug and release sys-io and systest clippy byte-identical to
  clean `HEAD`, both netstack closures with warnings denied (539 plus 7 and 678
  plus 7 tests), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries and no tolerated failures. All
  six contain both new interface regressions, the netstack closure's 539 tests,
  `test_neighbor_admission`, a negative DNS query returning `NotFound` directly,
  and all four flush-stress workers completing 4,000 iterations; the debug three
  report 34 self-tests and the release three none.
  `net.neighbor.admission_refused` stayed 0 in all six, which is the
  unaffected-ordinary-traffic evidence the item's gate asks for. Only the plan
  documents changed across the six runs, so all six built one compiled tree.

Step 6 patch 12 -- a forged reply may not evict a router (2026-08-01):

- Patch 11 left one eviction an off-path peer could still aim. The netstack
  keeps no record of which requests are outstanding, so every ARP reply and
  neighbor advertisement counts as answering one of ours, and a stream of them
  from distinct same-subnet addresses evicted entry after entry -- the gateway
  among them, because nothing in the victim choice treated it differently from
  any other mapping. Losing it stalls all off-subnet egress: the next packet
  gets `NeighborPending` and TCP waits out an RTO of at least a second.
- A solicited fill now chooses its victim among the entries no route depends
  on: `Routes::is_active_router` is true for the `via_router` of any route that
  has not expired, and the neighbor cache skips those when it picks the entry
  closest to expiry. Any route, not only a default one -- a more specific
  route's router carries everything behind its prefix. Not an expired route,
  which carries nothing, the same test `Routes::lookup` already applies.
- Where every entry is protected, the entry closest to expiry goes anyway. That
  is unreachable in the shipped configuration -- eight cache slots against two
  routes -- and is the deliberate choice where it is reachable: a cache that
  can evict nothing can never learn anything again. `Cache::fill`, the
  unprotected fill, is now `#[cfg(test)]`, so no production path can reach for
  it by mistake.
- Five netstack regressions: the route predicate including both sides of its
  expiry boundary, the redirected victim, the all-protected fallback, and one
  each driving real forged ARP replies and neighbor advertisements through
  `process_ethernet` against a configured gateway. The IPv4 one then asks
  `lookup_hardware_addr` for an off-subnet destination and requires the
  gateway's MAC back, which is the plan's "egress keeps working across the
  flood" asserted where egress actually resolves.
- Three sabotages, each failing exactly its own subject and nothing else:
  dropping the protection filter, removing the fallback, and making the route
  predicate ignore expiry. Details and the three implementation decisions are
  in `core-safety-hardening.md`, item 5.
- The exact patch-12 source state passed formatting, Motor-target debug and
  release builds, debug and release sys-io and systest clippy identical to
  clean `HEAD`, both netstack closures with warnings denied (544 plus 7 and 683
  plus 7 tests), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries and no tolerated failures. All
  six contain the five new regressions by name, the netstack closure's 544
  tests, `test_neighbor_admission`, a negative DNS query returning `NotFound`
  directly, and all four flush-stress workers completing 4,000 iterations; the
  debug three report 34 self-tests and the release three none. Only the plan
  documents changed across the six runs, so all six built one compiled tree.

Step 6 patch 13 -- one black hole no longer starves every other address
(2026-08-01):

- The neighbor cache rate-limited discovery with a single `silent_until`
  instant, so any dispatched request silenced discovery for every address.
  One destination nobody answers for therefore held back resolution of every
  other one, and sys-io's aggressive 5 ms value made that a machine-wide cap of
  200 ARP requests per second rather than a per-destination one.
- The silence is now a map from destination to the instant it may be asked
  about again, sized like the neighbor cache, consulted for the address being
  resolved and armed for the routed next hop the request went to. A flush
  clears it: the requests those silences paid for are stale once the mappings
  are gone.
- The machine-wide bound this removes is deliberate -- per-destination is the
  point -- and a socket is still capped at one request per interval by the
  per-socket silence the egress loop arms on a failed dispatch.
- Five netstack regressions: per-destination independence, the full-map
  eviction, a refresh that must not displace another silence, the flush, and
  the plan's interface test driving `lookup_hardware_addr` through a real
  device token and reading the ARP requests off its transmit queue.
- Four sabotages, each failing exactly its own subject. Details, the four
  implementation decisions, and the paired release `rnetbench` A/B/A are in
  `core-safety-hardening.md`, item 5.

Step 6 patch 14 -- a blind reset must guess the whole sequence space
(2026-08-01):

- Past SYN-SENT, any reset with a sequence number anywhere in the receive window
  closed the connection. With a 128 KiB window that is one guess in ~32768, not
  one in 2^32, and sys-io's linear ephemeral ports made the rest of the 4-tuple
  guessable too.
- RFC 9293 3.10.7.4, from RFC 5961 section 3: a reset is acted on only at
  exactly `RCV.NXT`, one elsewhere in the window draws a rate-limited challenge
  ACK and changes no state, and one outside the window is dropped with no reply
  -- silence, so a prober cannot tell a near miss from a wild one.
- The check covers SYN-RECEIVED as well, so an off-centre reset cannot knock a
  pending accept back to LISTEN; the return to LISTEN that sys-io's listen task
  depends on still fires, because a real peer's reset sits at `RCV.NXT`.
- The one legitimate path it costs a round trip -- a peer resetting after data
  we never received -- recovers by design: our challenge ACK carries `RCV.NXT`,
  and the peer's answer to it is a reset at that number, which we accept.
- Five netstack regressions and six sabotages. Three inherited tests moved: the
  plan's expectation that none would came back negative, since the fork's own
  suite predates Step 5 and asserts the RFC 793 behavior in passing.
- Details, the four implementation decisions, the three moved tests, and the
  paired release `rnetbench` A/B/A are in `core-safety-hardening.md`, item 4.

Step 6 patch 15 -- a rebooted peer must not be stranded (2026-08-01):

- A SYN arriving on a synchronized connection was dropped in silence, so a peer
  that rebooted and redialled the same 4-tuple got nothing back, while our half
  of the connection it has forgotten sat here until a keepalive noticed. Motor
  leaves `keep_alive` off by default, so possibly forever.
- RFC 9293 3.10.7.4, from RFC 5961 section 4: the SYN now draws the same
  rate-limited challenge ACK, irrespective of its sequence number. A peer in
  SYN-SENT answers an ACK it cannot place with a reset seeded from that
  acknowledgement -- our `RCV.NXT` exactly, the one number patch 14 accepts a
  reset at -- so the stale socket closes and the peer's next SYN is answered.
- The plan's placement for the check could not have worked and was measured
  before it was changed: a rebooted peer's SYN carries no acknowledgement and
  is dropped long before the state machine, so the block sits ahead of the
  acknowledgement match instead. Sabotaging the placement fails the same tests
  as deleting the block.
- SYN-RECEIVED is deliberately left out, where patch 14 included it: there a
  repeated SYN is the peer asking for the SYN|ACK it missed, which our own
  retransmit answers. A SYN also no longer extends TIME-WAIT.
- Five netstack regressions and six sabotages, with no existing test changed.
  Details and the paired release `rnetbench` A/B are in
  `core-safety-hardening.md`, item 4.

Step 6 patch 16 -- RDRAND failure must not kill the process (2026-08-01):

- D3, fixed in `rt.vdso` rather than in networking because that is where it
  lives, and immediately before patch 17, which is its only consumer here.
  `fill_random_bytes` discarded RDRAND's carry flag and panicked whenever the
  drawn value was zero.
- It now reads the flag, retries a failed draw up to ten times per the Intel
  SDM, and panics only after ten consecutive failures -- on real hardware, a
  broken DRNG. No fallback to a weaker source, since callers key hashes and
  ciphers with these bytes. The retry is the AGENTS.md-sanctioned kind, with
  the 2026-07-29 review as its prior approval.
- Half of D3's diagnosis turned out to be wrong: RDRAND zeroes its destination
  whenever it clears CF, so no garbage was ever accepted and `val == 0` was a
  correct detector. The defect was the response to it, not the detection.
- Gated on the repository-wide `full-test.sh`, not the networking subset:
  `rt.vdso` is in every process, including the rush and rmux ones the subset
  drops. New systest regression `test_random_bytes`; details in
  `core-safety-hardening.md`, item 3.

Step 6 patch 17 -- the netstack's seed stops being the boot clock (2026-08-01):

- Each interface's PCG32 was seeded with `SystemTime::now()` nanoseconds, so an
  off-path peer who knows roughly when the machine booted could search a small
  range offline for the state behind every ISN and IPv4 identifier that
  interface would ever emit. `random_seed` now takes eight bytes from
  `moto_rt::fill_random_bytes` -- one RDRAND per device at initialization,
  measured below the boot log's millisecond resolution, and nothing per packet
  or per connection.
- Stated narrowly, because the headline overclaims: the generator is unchanged.
  Consecutive connections are still consecutive PCG32 outputs, so a peer that
  can open a few of them still recovers the state whatever it was seeded with.
  Patch 18's per-connection hashing is what closes that, and this patch is what
  gives its key a source.
- `NetDev::new`'s inline interface configuration moved into `iface_config`, so
  the seed has exactly one call site and the self-test can take configurations
  the way two devices would. That indirection is the test seam: the netstack's
  PRNG is `pub(crate)`, so a constructed `Interface` will not say what seeded
  it.
- One self-test, `net::device::interfaces_do_not_share_a_seed`, 35 in all. It
  checks the seeds' high 32 bits separately, which is where a clock-derived
  seed betrays itself. Two sabotages, each failing exactly one of the two
  checks; live evidence from a booted VM shows the two real devices drawing
  distinct, non-clock-shaped seeds. The full record is in
  `core-safety-hardening.md`, item 3.
- The exact patch-17 source state passed formatting, Motor-target debug and
  release builds, debug and release sys-io clippy identical to clean `HEAD`,
  both netstack closures with warnings denied (559 plus 7 and 698 plus 7 tests,
  unchanged because the netstack is untouched), and three consecutive debug plus
  three consecutive release `full-test-networking.sh` runs with no retries and
  no tolerated failures. All six contain the netstack closure's 559 tests,
  `test_random_bytes`, `test_simultaneous_open`, a negative DNS query returning
  `NotFound` directly, and all four flush-stress workers completing 4,000
  iterations; the debug three report 35 self-tests and the release three none.
  No paired `rnetbench` A/B: the gate list does not ask for one, and the draw
  happens once per device before the interface exists.

Step 6 patch 18 -- RFC 6528 initial sequence numbers (2026-08-01):

- Every ISN came from one PCG32 per interface, and that generator is linear: a
  peer that opens a handful of connections recovers its state and can predict
  the sequence numbers of connections it cannot see, including ones between two
  other machines. The ISN is now `M + F(4-tuple, key)`, with `F` SipHash-2-4
  under a per-interface key and `M` the interface's clock at RFC 6528's four
  microseconds per tick. The PCG32 stays, for IPv4 identifiers and DNS
  transaction ids, which are not secrets.
- This is the patch patch 17 exists for, and vice versa: an unguessable seed
  does nothing for a generator whose state is recoverable from its outputs, and
  a keyed hash needs somewhere to get a key. Neither is worth much alone.
- The key is drawn separately from the seed rather than derived from it.
  Deriving it would key the hash with a value the attacker can recover, which
  is the whole thing it defends against.
- SipHash-2-4 rather than a `core::hash` hasher, because `Hasher`'s output is
  not specified to be any particular function and so cannot be checked against
  published vectors. All 64 reference vectors are a test, and the
  implementation was cross-checked against an independent reimplementation
  written from the specification.
- Ephemeral ports are still lowest-free, so the local port of the next outbound
  connection is still guessable. That is patch 19, the last of item 3.
  Superseded the same day: patch 19 randomized them.
- Five netstack tests and one sys-io self-test, 36 in all. Six sabotages, each
  failing exactly one test; live evidence from a booted VM shows the two real
  devices drawing distinct, non-zero keys two milliseconds before each device
  comes up. The full record is in `core-safety-hardening.md`, item 3.
- The exact patch-18 source state passed formatting, Motor-target debug and
  release builds, debug and release sys-io clippy identical to clean `HEAD`
  from wiped target directories on both sides, both netstack closures with
  warnings denied (564 plus 7 and 703 plus 7 tests, each five more than patch
  17's), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries and no tolerated failures.
- The paired release `rnetbench` ran four blocks rather than three: the host's
  known default-workload bimodality appeared mid-run, and both trees visited
  both regimes. Same-tree pairs differ by up to 13.8% on that workload with no
  code difference at all, so only within-regime comparisons mean anything;
  those are all under 2% with mixed sign, and the 64 KiB workload -- which is
  not bimodal -- agrees to within 1.9% across all four blocks. Both are well
  inside the kill criteria. `rnetbench` does not really stress connection
  setup, though: its RR test opens one connection and loops on it. The numbers
  say the data path is untouched, which is also what the code says.
- The first gate attempt failed in debug run 1 and was root-caused to the
  fail-first tooling, not the patch: the sabotage script restored files with
  `mv`, leaving mtimes older than the sabotaged build, and cargo kept serving
  the sabotaged object code. Everything captured after the sabotages was
  re-established from forced-fresh compiles, the recorded gate is the rerun,
  and the script now touches what it restores.

Step 6 patch 19 -- randomized ephemeral ports, and the premise that lets
loopback keep lowest-free (2026-08-01):

- Ephemeral ports were handed out lowest-free from 49152, so with patch 18's
  sequence numbers in place the local port was the last field of an outbound
  4-tuple an off-path attacker could still guess. On a device that carries
  external traffic the scan now starts at a uniform point in the range (RFC
  6056), drawn from the hardware RNG per allocation rather than from a
  generator whose state a few outputs would give away. It still wraps through
  the whole range, so a port is refused only when all 16384 are in use.
- The logical loopback device keeps lowest-free, as item 3 decided: a local
  process can already enumerate those ports through the socket-stats service,
  so randomizing them buys nothing, and lowest-free is what makes
  `test_simultaneous_open` deterministic. That regression is unchanged and
  passes -- the cost item 3 was scheduled last to avoid was not paid.
- The exemption is only sound if nothing off the machine can present a loopback
  address, so the same patch makes it so: the netstack now drops a 127/8 source
  or destination on any interface that is not a loopback one and counts it as
  `net.rx.loopback_dropped`. The source half is the load-bearing one -- it
  passes every check that precedes it, and a peer that could hold such a source
  would reach any local program that trusts its counterparty for being on
  loopback.
- TCP and UDP share the one scan, so sys-io's DNS query source ports are
  randomized too: the Kaminsky defense, obtained rather than designed. ICMP
  echo identifiers are deliberately left linear.
- One netstack test and four sys-io self-tests, 40 in all. Ten sabotages, each
  failing exactly one test; live evidence from a booted VM shows twelve
  outbound connections taking twelve scattered source ports, the loopback
  self-connect still working, and the new counter at zero after a full boot --
  no false positives on real traffic. The full record is in
  `core-safety-hardening.md`, item 3.
- The exact patch-19 source state passed formatting, Motor-target debug and
  release builds, debug and release sys-io clippy identical to clean `HEAD`
  from wiped target directories on both sides, both netstack closures with
  warnings denied (565 plus 7 and 704 plus 7 tests, one more than patch 18's in
  each), and three consecutive debug plus three consecutive release
  `full-test-networking.sh` runs with no retries and no tolerated failures,
  passing first time.
- The paired release `rnetbench` ran five blocks. The host's default-workload
  bimodality was worse than during patch 18: clean against clean differs by
  -12.85% on RX with no code difference at all, which is what a plain A-then-B
  would have reported as a failure. Within a regime the trees are level, and
  the best default-workload block of the five is a patched one. The 64 KiB
  workload, which is not bimodal, runs 1.9% RX and 1.3% TX below clean on
  means -- inside the patched arm's own spread and inside the kill criteria,
  recorded because it is the one direction that consistently favors clean.
- This completes item 3 and Step 6.

Pre-existing defect found while gating patch 7 -- mlibc's unlocked open-file
list (fixed 2026-07-30, with approval):

- The third release `full-test-networking.sh` run failed at the DNS resolver
  restart step: the replacement resolver died seconds after starting, so
  `--self-test` never succeeded. Patch 7 could not have caused it -- both
  files it touches are `#[cfg(test)]` and are in no Motor binary.
- Reproduced five times with a focused loop that repeats only the harness's
  kill/restart sequence. Release only, roughly one failure per 40-170 cycles,
  and reliable with `nproc/2` host spinners; 0 in 60 debug cycles.
- The kernel records a worker thread of the fresh resolver as `Killed(GPF)`,
  which is how `invalid_opcode_handler` tags a userspace `ud2`, and
  `panic = "abort"` then takes the whole process down. It is not a Rust panic:
  a process-wide panic hook never fired and no message was printed. Dumping the
  faulting instruction pointer and disassembling it showed a bare `ud2` reached
  by an explicit branch, among frigg's `frg/list.hpp` assertion strings and
  mlibc's "File is not flushed before destruction".
- `mlibc::abstract_file`'s constructor and destructor link and unlink every FILE
  in one global `frg::intrusive_list` with no lock at all -- each FILE's own
  `_lock` covers its buffer, not the list. Every `getaddrinfo` opens and closes
  `/etc/hosts`, and `dns-resolver` calls it concurrently from four worker
  threads, so two simultaneous lookups corrupt the list.
- Fixed in `~/motor-dev/mlibc` (outside this repository, by maintainer
  decision): one `FutexLock` guards the list across insertion, removal, and the
  three iteration sites. Lock order is list-then-file; `fclose` holds no file
  lock when it destroys one, so there is no inversion. Verified by 250 restart
  cycles under the same host load, with no failure and no userspace abort.
- The earlier `threads should not terminate unexpectedly` panic seen in this
  investigation was downstream of the same abort: a worker killed mid-closure
  never drops its `Packet` `Arc`, so `run_service`'s `join()` trips std's check.
  `rt.vdso`'s `join()` is not implicated.

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
debug and three release passes through that focused harness. `AGENTS.md` is
unchanged.

On 2026-07-31 the two harnesses were resynchronized so that their networking
coverage is identical: `src/tests/full-test.sh` gained the netstack feature
closure it had been missing, and the focused harness picked up the
build-conditional `rnetbench` run that `main` had added to `full-test.sh` after
the copy was taken. The rmux/tmux tests are now the only difference between
them, so every netstack regression written for this work is reachable from the
repository-wide harness as well.

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

9. **Open, and not networking: `rmux`'s host-side pty test is flaky
   (2026-08-04).** Found re-baselining at `e55c0223` after the branch merged
   `main`: three debug `full-test.sh` runs passed, and one of three release runs
   failed in `a_config_file_moves_the_prefix` with
   `failed to spawn rmux on a pty: PermissionDenied`. The EPERM comes from the
   `pre_exec` closure at `src/bin/rmux/tests/host.rs:132`, so from `setsid()` or
   `ioctl(TIOCSCTTY)`. PID reuse is implausible on this host -- `pid_max` is
   4194304 against live PIDs around 268k -- which points at `TIOCSCTTY`, i.e. a
   pts already owned by another session, and `rmux`'s own `Drop` comment records
   that a server and a pane shell outlive each test on purpose. It did not
   reproduce in 20 isolated runs: 12 of `cargo test --release --test host` and 8
   of the harness's exact `red`/`rmux`/`rush` loop. It runs before the VM boots
   and is absent from `full-test-networking.sh`, which is why this work gates on
   that harness. Unowned; it needs a decision, and it is not evidence about
   networking either way.

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

Add reviewed, separately gated core steps for six items. The items are topics
and keep the numbers they were reviewed under; the **patch numbers are the
execution order**, and they run 1 to 19 monotonically down this list:

- **Item 1 -- patches 1-4.** P3 sequence arithmetic, attacker-influenced
  assertions, and short RX-ring writes that could expose stale contents.
- **Item 2 -- patches 5-7.** Per-packet virtio RX checksum metadata, including
  unflagged, `NEEDS_CSUM`, and `DATA_VALID` cases.
- **Item 6 -- patches 8-10.** Bounded half-open sockets, backlog behavior, and
  lazy/small initial socket buffers from core Step 4 (the buffers were since
  moved to Step 12; see the scope decisions below).
- **Item 5 -- patches 11-13.** ARP cache admission, eviction, and request-rate
  behavior.
- **Item 4 -- patches 14-15.** RFC 5961 RST handling and PAWS/timestamp policy
  (timestamps and PAWS were since moved to Step 10 item 2; see below).
- **Item 3 -- patches 16-19.** ISN and ephemeral-port generation.

Each item needs a design-sized patch plan before implementation. In
particular, do not expand the receive-offload feature set until item 2 lands.

Status: the required plan is `docs/plans/core-safety-hardening.md`, reviewed on
2026-07-29. It carries the verified state, the patch breakdown, the tests, and
the gate for each item, and its Sequencing section is the execution order of
record for Step 6, holding the numbered patch table and the crosswalk from the
old item-local labels. Patches 1 (D1), 2, and 3 (D4) are complete and gated;
their result notes, including the SYN-RECEIVED window-update decision, the
fourth panicking subtraction patch 2 added to its scope, and patch 3's finding
that patch 2's write-site check was already D4's caller-side bound, are in that
plan's Item 1. Patch 4 completes item 1: the seven abort-shaped sys-io sites the
Step 1 audit deferred now log and recover locally, with no success-path change
and, by that section's own provision, no new test -- every one of them is
unreachable through the public protocol. Patch 5 starts item 2 and closes D2:
the virtio RX header now reaches the driver as `RxMeta` before its descriptor
chain is released, and completions the negotiated feature set cannot produce
are rejected, counted in `net.device.rx_dropped`, and their buffers re-posted.
Patch 6 closes the trust gap itself: receive verification is advertised as on
for every frame, and patch 5's verdict waives it per frame at the TCP and UDP
ingress parse sites, so a frame nobody vouched for is verified rather than
trusted and a failure is counted in `net.rx.csum_failed`. Patch 7 completes
item 2 with the deterministic per-verdict coverage patch 6's measurement made
mandatory: the testing device states a verdict per frame, and one TCP and one
UDP `Interface::poll` regression prove that an unvouched bad checksum is dropped
and counted while a vouched one is delivered unexamined. All three result notes,
including patch 6's three implementation decisions, the sabotage evidence for
patches 6 and 7, and the finding that this rig delivers no unvouched L4 frames
at all, are in that plan's Item 2. Item 2 is complete and Step 8 is unblocked.
Patch 8 starts item 6 with its measurement: `net.tcp.half_open` counts the
listening sockets waiting on an unfinished handshake, `net.tcp.syn_rst_unmatched`
counts the connection requests no socket took, and `net.tcp.half_open_total` --
a third metric, added because a handshake with a peer that answers is over long
before a stats query can see it -- is what makes the gauge's rise and fall
provable in the full-OS suite. The deliberately stalled handshake this section
asked for is not constructible without packet injection, so it is a netstack
regression instead; that deviation was approved before implementation and its
result note is in the hardening plan's Item 6. Patch 9 caps the half-open
sockets, patch 10 lets a listening pool grow into the bursts that drain it, and
patch 10.1 gives that growth back once the bursts stop. Patch 10.2 completes
item 6 by answering overload with a drop rather than a reset: a connection
request for an endpoint a listener owns is dropped, counted, and used to deepen
that listener's pool, so the peer retransmits into the growth its own loss paid
for, while a request for an endpoint no listener owns keeps the reset that
`ECONNREFUSED` depends on. Item 6 is complete, so its half of the Step 9 and
`tcp-receive-window.md` Step 1 prerequisite is met. Patch 11 starts item 5 by
removing the forgeable neighbor-eviction primitive: an ARP request, or its IPv6
counterpart a neighbor solicitation, may refresh a cached mapping or take a free
slot but may never displace an entry, so forged requests no longer flush the
cache; replies keep the evicting fill, and `net.neighbor.admission_refused`
counts what a full cache turns away. Patch 12 closes the reply path that
eviction still reached: a solicited fill picks its victim among the entries no
unexpired route depends on, so a stream of forged replies can no longer displace
a router, and the unprotected fill is now test-only. Patch 13 completes item 5
by replacing the global request-rate silence with a per-destination one, so a
black-holed address holds back requests for itself alone and no longer starves
resolution of a reachable one. Item 5 is complete. Patch 14 starts item 4 with
RFC 5961 section 3: past SYN-SENT a reset is acted on only at exactly `RCV.NXT`,
one elsewhere in the window draws a rate-limited challenge ACK and changes no
state, and one outside it is dropped unanswered, so a blind off-path reset costs
the whole sequence space rather than one guess per window. Patch 15 completes
item 4 with section 4: a SYN on a synchronized connection draws the same
rate-limited challenge ACK wherever its sequence number sits, which is how a
rebooted peer redialling the same 4-tuple gets its port back instead of being
stranded behind our half of a connection it has forgotten. Item 4 is complete.
Patch 16 starts item 3 outside networking, in `rt.vdso`: `fill_random_bytes`
now honors RDRAND's carry flag and retries a transient failure instead of
killing the calling process, which is what patch 17 would otherwise inherit the
moment it draws a seed. Patch 17 then spends it: each interface draws its PCG32
seed from that hardware entropy at initialization instead of from the boot wall
clock, so the state behind every ISN and IPv4 identifier is no longer searchable
offline from an approximate boot time. The generator is unchanged and says so --
consecutive connections remain consecutive outputs. Patch 18 replaces that
generator, for sequence numbers, with RFC 6528's `M + F(4-tuple, key)`: `F` is
SipHash-2-4 under a key the interface draws from the same hardware entropy, so
the numbers a peer sees on its own connections stop being a window onto the ones
between other machines, and `M` is a four-microsecond timer, so a reused 4-tuple
never rewinds. The two patches only matter together -- an unguessable seed does
nothing for a recoverable generator, and a keyed hash needs a key. Patch 19
completes item 3, and Step 6 with it, by taking the last guessable field of an
outbound 4-tuple: on a device that carries external traffic the ephemeral
allocator now starts its scan at a hardware-drawn point in the range (RFC 6056)
instead of at the bottom. The logical loopback device keeps lowest-free, which
is what `test_simultaneous_open` depends on, and the same patch earns that
exemption by making the netstack drop 127/8 addresses arriving on any interface
that is not a loopback one -- so the claim that loopback has no off-path
attacker is enforced rather than assumed. All six items are done.

Why the items are worked in that order -- 1, 2, 6, 5, 4, 3, which is what makes
the patch numbers run 1 to 19: item 1 leads because it is the only remotely
reachable abort in the list and because Step 5 built exactly the harness that
proves it. Items 2 and 6 follow because they gate later steps -- item 2 gates
Step 8's receive-offload expansion, item 6 gates Step 9 and
`tcp-receive-window.md` Step 1 -- so delaying them stalls other work. Items 5, 4,
and 3 block nothing else; item 3 is last because item 4's exact-sequence RST
check already removes the cheapest blind attack that predictable ISNs and ports
enable, and because item 3 is the only item whose cost includes an existing
regression's determinism. Every patch is separately gated and leaves a runnable
tree, so a single patch can be resequenced; if one is, the patches are
renumbered rather than given a fraction.

The nineteen patches, in that order: 1 (D1's fix with its fail-first test), 2,
3 (D4), 4 -- item 1; 5 (D2), 6, 7 -- item 2; 8, 9, 10 -- item 6; 11, 12, 13 --
item 5; 14, 15 -- item 4; 16 (D3, an `rt.vdso` patch), 17, 18, 19 -- item 3.
Each one's subject, status, and landed commit are in the hardening plan's
Sequencing table.

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
  Superseded: patch 10's measurement settled it early, and patch 10.2 landed the
  drop for endpoints a listener owns while leaving the closed-port reset alone.
- D1-D4 keep their places in the order above. Each was reviewed and approved on
  2026-07-29; the fix shapes are recorded in the plan's defects section.

Design choices, resolved in the 2026-07-29 review (details in the plan):

- Item 2 lands as shape A: the per-packet verdict rides `PacketMeta` and is
  honored at the two netstack ingress parse sites. Verifying in sys-io's RX
  token was rejected for duplicating parsing on the hot path and dead-ending on
  coalescing's `NEEDS_CSUM` super-segments.
- Item 3 randomizes ephemeral ports on external devices only; the logical
  loopback keeps lowest-free allocation, so `test_simultaneous_open` keeps its
  determinism with no test-only hook. Patch 19 also drops 127/8 addresses
  arriving on external ingress, enforcing the premise that loopback has no
  off-path attacker. Revisit unification once Step 12's local-port work lets
  the test pin its source port. Both landed as specified on 2026-08-01.
- Patch 15 is kept: the silent drop already defeats the blind-SYN attack, but
  it strands an honest rebooted peer reusing the tuple (keepalive is off by
  default); the challenge ACK is the RFC 9293 3.10.7.4 recovery path.

Roadmap note from the same review: **SYN cookies are planned** after this step.
They slot in after Step 10 item 2, because cookies without timestamps lose
window scaling. Step 6 already lays their groundwork: D1's dual fix makes the
cookie path's second `remote_last_win` writer safe, patch 18's SipHash and key
handling are reusable (a cookie is an ISN), and patch 9's half-open cap is the
trigger a cookie mode engages on.

## Step 7 -- measure the receive ceilings

Run measurement-only work from:

- TCP receive-window analysis against representative full-OS workloads when
  available; and
- virtio receive-coalescing Step 0, including features, queue depth, and RX
  packet-size/header distributions.

Record exact commands and the Step 0 benchmark manifest.

Status: complete, 2026-08-01. Both halves ran; the results live in the
companion plans, and the manifest is below.

**Receive-window analysis** (`tcp-receive-window.md`, "Measured on the rig").
Verified live what the plan had only from source: window scaling engages at
shift 2, and the advertised window is the full 131072 bytes. The rig's RTT is
46 microseconds, so window/RTT is 2.65 GiB/s against the 697.31 MiB/s the
sampled transfer actually ran at -- **the window is 3.9x from binding and
cannot be made to bind here**, since that plan's own Step 0 removed the
synthetic delay that would have forced it. Step 9's finding is negative:
no local benchmark can justify the raise, so it needs either a representative
long-RTT workload, which does not exist on this host, or an explicit decision on
the Motivation table's arithmetic plus an approved memory budget. Method note:
this host grants no `CAP_NET_RAW`, so nothing was captured; `ss -i` on the host
end of a live connection reports what the peer advertised, which is the same
fact without the privilege.

**Coalescing Step 0** (`virtio-rx-coalescing.md`, "Step 0 result"). Landed as
196 lines across four files: two boot log lines carrying
the offered and acked feature words and the ring depths, and a five-bucket
histogram of received frame lengths in `NetStats`. It settles the plan's
deciding unknown -- `virtq_rx.queue_size()` is **256**, so depth is 128 today
and 14 under Option A -- and confirms that this VMM offers every bit either
option needs, including `MRG_RXBUF` and `RING_INDIRECT_DESC`. The histogram
shows the bulk workload already 99.89% MTU-framed at 505k frames/sec, which is
the clean case for coalescing, and the default workload spread across three
buckets rather than uniform at its 567 B/pkt mean. The top bucket, above a
standard Ethernet frame, is empty as it must be while `GUEST_TSO4/6` is
unacked; it is the instrument Step 8 will be read with.

Two corrections to the coalescing plan fell out of the measurement. Its
negotiated-feature list was wrong -- `MTU` is not offered by this QEMU and
`STATUS` is not acked, while `RING_EVENT_IDX` was missing -- and its
packet-rate column is understated about 2.6x and never agreed with the
throughput recorded beside it. The throughput figures reproduce.

**A preexisting defect, found by measuring and then fixed on guidance.**
`VIRTIO_NET_F_MTU` is not negotiated, so sys-io fell back to a 1536-byte frame
MTU, `ip_mtu()` was 1522, and Motor advertised MSS 1482 on a tap that carries
1460. `ss` shows the host clamping to its own 1460, which is why nothing had
broken; a peer without a smaller path of its own would have made Motor emit a
1536-byte frame into a 1500-byte link, with no PMTU discovery to recover. It
dated to `d5a45ad3` and answered to no plan. A named `frame_mtu()` now converts
the virtio MTU -- which is an IP MTU -- into the frame size the netstack means,
defaulting to 1500, so the no-MTU case yields frame 1514 / MSS 1460. That closes
the off-by-14 `core-networking-rewrite.md` recorded in the other direction too,
since one conversion now covers both. `run-qemu.sh` was left alone deliberately:
the guest should be right about a link that tells it nothing.

Also reverted on guidance: an earlier draft promoted the virtio feature word
from `log::debug!` to `log::info!` so release boots would report it. **Release
builds do not get new boot-time logging** -- characterizing a new VMM means
booting a debug build there, which costs nothing.

Gate: `full-test-networking.sh` three times debug and three times release, all
passing on the first attempt, with the sys-io self-test suite at 43 (up from 40)
and no failures; `cargo +nightly fmt` clean; sys-io clippy byte-identical to
clean `HEAD` in both profiles from wiped target directories.

Plus a paired A/B/A/B rnetbench run, twice: once on the instrumentation, then
again after the MTU fix, since that changes `max_transmission_unit`. The full
tables are in the coalescing plan. The same-tree noise floor swamped the
comparison in both -- **clean against clean was default RX -14.29% and TX
-6.07% with no code difference at all** -- while the within-regime pair was
RX +2.02% / TX -0.17% and the 64 KiB workload sat inside a 1.4% four-block
spread. No throughput regression.

The first run also showed default RR consistently +2.05 usec on the patched
arm, which was recorded as the one signal favoring clean. **The second run
reversed it** (-0.84 usec), and pooling all eight RR samples per arm leaves
+1.31 usec with almost entirely overlapping ranges -- host drift, as the
mechanism predicted, since the added per-frame work is some 200x too small to
produce it.

### Benchmark manifest

Required by Step 0's decision gate above; this is the reference for every
measurement recorded in this step and the baseline for Step 8's paired A/B.

**Tree.** `93a8e4e0` plus the four instrumentation files that later landed as
`33df3c02`: `src/sys/lib/virtio-async/src/virtio_net.rs`,
`src/sys/sys-io/src/runtime/net.rs`,
`src/sys/sys-io/src/runtime/net/device.rs`,
`src/sys/sys-io/src/runtime/net/stats.rs`. Nothing else was dirty, so the
measured source state is exactly `33df3c02`.

**Build.** Release, `make -j$(nproc) BUILD=release`. Measurements are release
only; the debug image was built and gated but not measured.

**VMM.** QEMU 10.2.1 (Debian `1:10.2.1+ds-1ubuntu3.1`) at
`/usr/bin/qemu-system-x86_64`, launched by `vm_images/release/run-qemu.sh`
with `MOTO_SMP` and `MOTO_CPU_AFFINITY` unset, which is 4 vCPUs and no pinning:

```
qemu-system-x86_64 -m 1024M -enable-kvm -cpu host -smp 4 \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -device virtio-blk-pci,drive=drive0,id=virtblk0,num-queues=1,disable-legacy=on \
  -drive file=<image dir>/motor-os.img,if=none,id=drive0,format=raw \
  -netdev tap,ifname=moto-tap,script=no,downscript=no,id=nic0 \
  -device virtio-net-pci,disable-legacy=on,mac=a4:a1:c2:00:00:01,netdev=nic0 \
  -no-reboot -nographic
```

Note what the `-device virtio-net-pci` line does not carry: no `host_mtu=`, which
is why `VIRTIO_NET_F_MTU` is not offered, and no `rx_queue_size=`, which is why
the ring is QEMU's default 256.

**Host.** Linux `7.0.0-28-generic #28-Ubuntu SMP PREEMPT_DYNAMIC`, x86_64.
Intel Core i9-10885H @ 2.40 GHz, 8 cores / 16 threads, 800-5300 MHz. Governor
`powersave` on every CPU, driver `intel_pstate`, `no_turbo=0` (turbo enabled).
No CPU affinity for either the VM or the client. **The frequency is therefore
not pinned**, which is the most likely source of the bimodal
default-workload regimes recorded in the Step 6 patch results; anyone
tightening the noise floor should start here.

**Network.** Tap `moto-tap`, `192.168.4.1/24`, MTU 1500, `vnet_hdr on`,
`gso_max_size 65536`, VM at `192.168.4.2`. qdisc `fq_codel` at its defaults
(`limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms
memory_limit 32Mb ecn`). Offloads: `rx-checksumming off [fixed]`,
`tx-checksumming on`, `tcp-segmentation-offload off`,
`generic-segmentation-offload on`, `generic-receive-offload on`.

**Benchmark binaries.** Host client
`src/bin/rnetbench/target/release/rnetbench`, md5
`789679cb2416c95b5cf5b7f20b2098c4`. In-VM server `build/bin/release/rnetbench`
(installed as `/sys/tests/rnetbench`), md5 `1ce3eedfd8afe244100eff282005adf6`.
Both moved on 2026-08-02 with the flow-completion mode (Step 10 item 1c); the
pair before it was `ef658330af440e3f0cf7f8ab08f4125f` /
`f8c08d904ea095b26638eac461e3774a`, and the three standard phases are unchanged
between them. **Both ends must match** -- the flow command is a protocol
addition, and an older server answers it with `unrecognized command`.

**Command lines.** Server `/sys/tests/rnetbench -s -p 5542`. Client
`rnetbench -c 192.168.4.2:5542 -t 5` for the default workload and the same plus
`-b 65536` for the bulk one; flow completion is
`rnetbench -c 192.168.4.2:5542 -b 65536 --flow-bytes 16384 --flow-count 200`.
Window measurement: `ss -tinm dst 192.168.4.2` on
the host, sampled six seconds into a `-t 20 -b 65536` run. Histogram readout:
`/sys/sysbox stats get 2` in the VM for cumulative values, and the in-VM
rnetbench server's own per-phase report for deltas.

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

Gate result, 2026-08-02: **measured, and it settles which option is portable.**
The repository ships a run script for each of the three VMMs, so each was booted
on the same HEAD debug image and its feature word read from the log Step 7
added. No code changed.

| VMM | version | `GUEST_TSO4/6` | `MRG_RXBUF` | `INDIRECT_DESC` | `MTU` |
|---|---|---|---|---|---|
| QEMU | 10.2.1 | yes | yes | yes | no |
| Cloud Hypervisor | 52.0 | yes | **no** | **no** | yes |
| Firecracker | 1.15.1 | yes | yes | **no** | no |

Portability does not require mergeable buffers; it forbids depending on them,
because Cloud Hypervisor does not offer the bit at all. The gate's conditional
therefore does not fire and no Step 3 plan is owed. **Option A is the only
scheme with universal reach**, which is the reverse of what the coalescing
plan's recommendation said from review memory; that plan is corrected.

Two consequences have to be decided before the work rather than discovered
inside it:

- **Ring depth falls to 14 slots on every VMM.** All three report a 256-entry
  RX ring, and only QEMU offers the indirect descriptors that would restore
  depth. CHV can buy it back with `--net queue_size=`; Firecracker's network
  interface has no queue-size control at all, so it binds.
- **Posted receive memory goes from 262 KB to 918 KB per device** (14 x 65550
  against today's 128 x 2048). The Step 0 result flagged this as a decision to
  take up front.

**Decided 2026-08-02: coalescing is held here.** Neither option is taken. The
gate's evidence is recorded and stands on its own -- Option A is portable but
costs the depth and the memory above, Option B is not portable at all -- and
execution moves to Step 10. Step 8 resumes from this record, not from a rerun:
the feature words, ring depths, and the frame-size histogram are all in the
tree, so restarting costs a boot, not a measurement campaign.

The same boots answered a second question. The MTU fix in `33df3c02` is **not**
cosmetic on Cloud Hypervisor, which is the one VMM of the three that offers
`VIRTIO_NET_F_MTU` and reports 1500. A build with only the old line restored
advertises MSS 1446 there, against HEAD's 1460, and nothing clamps that
direction because it is below the path MSS rather than above it. So the defect
had a live cost of 1% of every segment's payload on CHV, and the QEMU rig where
Step 7 called it unobservable was simply the wrong place to look. Recorded in
both companion plans.

Commands:

```
~/bin/cloud-hypervisor-static --version   # v52.0
~/bin/firecracker --version               # v1.15.1
make -j$(nproc)                           # debug image at HEAD
vm_images/debug/run-chv.sh                # log has "NET features available"
vm_images/debug/run-fc.sh
ss -tinm dst 192.168.4.2                  # host end of a live connection
```

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

1. Enable congestion control. Split into 1a (enable), 1a.1 (fix the Cubic
   implementation), 1b (make the window bind), and 1c (the initial window); all
   are done.
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
   this item indefinitely. Item 4 turned out not to be a capacity question at
   all -- it was a boot-time abort -- and it uncovered 4a below.
4a. Read `/sys/cfg/sys-net.toml` whole. Added 2026-08-03, found while doing item
   4: the loader took the first 4096 bytes as the file, so a longer config was
   silently a *different* config.

Keep congestion control's local performance cost separate from its
deterministic protocol-correctness evidence.

Status: complete. Item 1 splits in two, by guidance 2026-08-02.

**Item 1a -- enable congestion control. Done, committed as `6f003620`.**
39 lines across four files: `socket-tcp-cubic` in sys-io's netstack features,
and `set_congestion_control(CongestionControl::Cubic)` at the one place sys-io
creates a TCP socket. Naming the variant rather than relying on
`AnyController::new()` is deliberate -- the variant does not exist without the
feature, so a build that dropped it fails here instead of quietly returning to
the uncontrolled `usize::MAX` window. One sys-io self-test pins the default
controller; `pub(super) mod tcp` is what lets it register.

Reno first, then Cubic on guidance 2026-08-02. The argument for Reno had been
that Cubic's `f64` does not belong in a system process; that was imported from
smoltcp's own Cargo.toml, whose reasons are FPU-less Cortex-M parts, interrupt
handlers, and kernel-mode code, and describes none of sys-io -- Motor enables
SSE/AVX at boot and the kernel `xsave`s across context switches. The surviving
objection is about this implementation, not the algorithm: its congestion
avoidance grows the window only from a 100ms timer, which is thousands of RTTs
here. That is unobservable while the window is inert, so it is scheduled with
item 1b. Recorded in `core-networking-rewrite.md`.

**Item 1a found that enabling Reno is inert**, which is a preexisting defect and
by guidance became item 1b rather than growing this patch. The congestion
window was read once in the netstack, in `seq_to_transmit()`, against unsent
octets still inside the offered window rather than octets in flight;
`dispatch()` then sized the segment at `win_limit.min(max_seg)` with no cwnd
term at all. Reno's floor is the peer's MSS, so the one comparison that existed
could never bind. Closed by item 1b below; recorded in
`core-networking-rewrite.md` under "No congestion control at all".

Gate: `full-test-networking.sh` three times debug and three times release, all
passing first attempt, no retries; sys-io self-tests 44 (up from 43) with none
failing; netstack 565 + 7 + 6 in all six; `cargo +nightly fmt` clean; sys-io
clippy 35 debug / 32 release with warning texts **identical** to clean `HEAD`
from wiped target directories on both sides.

Benchmark: paired A/B/A/B, twice per tree, ten samples per arm per run. Reno was
measured this way before the switch and Cubic-plus-fixes after it; **neither
regresses**, which is what item 1a's own finding predicts, since nothing reads
the congestion window yet.

**The method needed correcting to see that, and the correction applies to every
paired gate from here.** Pooling all four blocks made the Reno arm look 12.09%
down on default RX. That is an artifact of the design, not of any tree: `A1` is
always the first block, the first block of a sitting is the only one that stays
in the host's fast regime, and `A1` is always the clean arm -- so A/B/A/B
confounds the tree with block position and flatters clean by over 10%. Dropping
the first block from both arms is what the numbers below do.

| tree | RR | default RX | default TX | 64k RX | 64k TX |
|---|---|---|---|---|---|
| Reno vs clean | -0.11% | -1.04% | -0.71% | -1.44% | -0.18% |
| Cubic+fixes vs clean | +0.95% | -0.20% | +1.76% | -0.14% | -1.69% |

Each figure pools 10 clean against 20 patched samples across two sittings. Both
trees sit inside a same-tree noise floor that reached 2.3% on the 64 KiB
workload in one sitting and 2.15% in another.

Three times now a single sitting has produced a number past or near the kill
criterion that the next sitting reversed: 64 KiB RX -5.59% then +0.54% for Reno;
64 KiB TX -3.81% then +0.04% for Cubic. In both cases the within-block spread
was larger than the between-arm gap, and in both cases no mechanism existed --
the congestion window bounds nothing today, and for the RX phases Motor is
receiving, where a send-side window governs only ACKs. **One sitting is not
evidence on this host.** Two, with the first block dropped, is the minimum.

**Item 1a.1 -- fix the Cubic implementation. Done, committed as `6f003620`.**
On guidance, once Cubic was chosen: it had **four** defects, and the one I had
been calling the problem was the least of them.

RFC 8312's TCP-friendly region was **absent entirely**, which is why Cubic was
the strictly worse choice at LAN RTTs -- the curve alone climbs slower than Reno
on a low-BDP link, and there was no Reno floor under it. Slow start was
**undone periodically**: the recovery curve was applied before any loss had
happened, dropping the window to one segment every 100ms on a link that had
never lost a packet. The 100ms floor is gone and the curve runs in microseconds.
And `cube_root` converged on an absolute per-decade tolerance that left K 0.16%
high, starting the curve below the very window it should meet at t = 0 --
affordable to fix because K is now cached per congestion epoch rather than
recomputed per transmit, which is what made a floor necessary at all.

Four netstack tests, each verified to fail against a faithful restoration of the
original `pre_transmit` rather than a paraphrase. That mattered: the first
paraphrase was misleading twice, and the first version of the slow-start test
passed against the real original because the 100ms floor happens to protect slow
start after the first clobber. Deferred to item 1b: the every-duplicate-ACK
reaction, which is caller-side and controller-agnostic.

**MTU hardening. Done, committed as `6f003620`.** Two holes the 2026-08-01
units fix left behind, both in `frame_mtu()`. The receive path posts 2048-byte
buffers and cannot take delivery of more without `MRG_RXBUF`, so any reported
MTU above 2034
advertised an MSS Motor could not receive -- reachable through a jumbo tap under
Cloud Hypervisor, which is where the reported MTU comes from. And a reported MTU
below 40 underflowed the netstack's `usize` MSS arithmetic, in a process that
aborts on panic. Now capped at `SMALL_BUF_SIZE - ETHERNET_HEADER_LEN` and
floored at 576 by falling back to the default rather than clamping upward. No
behavior change on any current rig; the existing self-test carries both cases
and ties the cap to the buffer size. Recorded in `core-networking-rewrite.md`.

**A gap in the harness, found by these patches.** `NETSTACK_FEATURES` in
`full-test.sh` and `full-test-networking.sh` is a hand-maintained copy of
sys-io's netstack feature list, and both scripts say it is meant to be "the
exact feature closure sys-io builds it with". Adding `socket-tcp-cubic` to
sys-io left it behind, so the first gate of these patches ran the netstack's
tests against a build with **no congestion controller compiled in** -- still 565
tests, silently missing all eleven of Cubic's, three of them new. Synced in both
scripts and re-gated at 576. Nothing enforces the copy: it is duplicated twice
and drifts silently whenever sys-io's features change, which is worth closing
properly rather than by remembering.

**Item 1b -- make the congestion window bind. Done, committed as `712e4a18`.**
This is what closes the finding item 1a opened: until now every congestion
signal was computed, delivered, and acted on, and none of it reached the wire.

One helper, `congestion_window_headroom()`, and three call-site changes in
`netstack/src/socket/tcp.rs`:

- `seq_to_transmit()` compared `cwnd` against the octets still *unsent* inside
  the offered window. RFC 5681 section 4 bounds the octets *outstanding*,
  SND.NXT minus SND.UNA. Bounding the unsent octets cannot bind at all once a
  dispatch drains the send buffer, which is the mechanism behind item 1a's
  finding.
- `dispatch()` sized the segment at `win_limit.min(max_seg)` with no `cwnd`
  term whatever. It now clamps `win_limit` to the same headroom, and does so
  *before* the zero-window-probe fixup: a probe is what reopens a connection
  whose peer advertised a zero window, so it must go out even when the
  congestion window has nothing left. Both call sites have to move together --
  `poll_at()` asks `seq_to_transmit()` whether to schedule, so a predicate that
  says yes while the sizer emits nothing is a busy loop.
- `on_duplicate_ack` fired on **every** duplicate ACK. RFC 5681 section 3.2
  reduces once per loss event, on the third duplicate -- the same signal that
  arms the fast retransmit. The first two are as likely to be reordering. On
  Cubic, whose reduction is multiplicative, reacting to all of them was `beta`
  raised to the size of the flight: a measured 65536 to 7709 across six
  duplicates, where one event costs 65536 to 45875.

The upstream smoltcp checkout on this host carries the same two window gaps, so
they are not fork drift.

Three netstack tests, each verified to fail against a faithful restoration of
the original. The first two fail on the segment sizer; the third fails with
"six duplicates compounded into more than one congestion event: 65536 -> 7709".
The dup-ACK test is Cubic-only by `#[cfg]` and says why in place: Reno's
`on_duplicate_ack` only lowers `ssthresh` and is idempotent, and Reno brings the
window itself down in `on_retransmit` -- Cubic's two hooks are the same
reduction, so Cubic is where a repeated signal compounds. The whole section is
gated on a controller existing at all, since `NoControl` reports `usize::MAX`.

Gate: `full-test-networking.sh` three times debug and three times release, all
passing first attempt, no retries; sys-io self-tests 44 with none failing;
netstack 580 + 7 + 6 in all six; `cargo +nightly fmt` clean; netstack clippy
`--all-targets` clean from a wiped target directory; sys-io clippy 35 debug / 32
release, unchanged from `HEAD`. The netstack suite was also run under all four
controller feature combinations: 580 with Cubic, 570 with Reno, 583 with both,
565 with neither.

Benchmark: paired A/B/A/B twice, first block dropped from both arms per the
method correction above, ten samples per arm pooled across the two sittings.

| pair | RR | default RX | default TX | 64k RX | 64k TX |
|---|---|---|---|---|---|
| item 1b vs clean | +0.08% | +0.60% | -0.44% | -1.26% | +0.78% |
| clean vs clean | +3.10% | -0.45% | -0.99% | +0.61% | +0.56% |

**This was the change expected to cost something, and it did not.** The reason
is worth recording rather than celebrating: this rig loses no packets, so the
window climbs through slow start to the remote window's cap and stays there,
and nothing after the first few round trips of a connection is congestion
limited. `rnetbench` transfers run five seconds, which amortises those trips to
nothing. The measurement therefore says the patch is free *here*; it says
nothing about a lossy path, which is the case the patch exists for and which
this host cannot produce.

The first block's position artifact reproduced at full strength in both
sittings -- `A2` came in 13.4% and 14.6% below `A1` on default RX, same tree
both times. The clean-vs-clean row above is the two non-first clean blocks
against each other, and its +3.10% on RR is the widest same-tree spread
recorded so far; RR deltas below about 2 usec are not measurable on this host.

**Still owed, and now reachable.** A loss event reaches Cubic twice: once from
the third duplicate ACK and once from the fast retransmit it arms, since
`dispatch()` reports both through `on_retransmit`. Cubic's two hooks are the
same `on_congestion`, so a loss costs `beta` squared, 0.49, rather than 0.7 --
Reno-like rather than catastrophic, and strictly better than the every-duplicate
behavior this item removed, but not what RFC 8312 specifies. Fixing it properly
needs a loss-epoch notion that does not exist in this fork: the controller
cannot tell an RTO from a fast retransmit, and Reno genuinely wants both hooks
(they are section 3.2's separate `ssthresh` and `cwnd` halves). Also unchanged:
`on_congestion` uses `ssthresh = cwnd >> 1` where RFC 8312 specifies
`cwnd * beta`.

**Item 1b.1 -- FIN on close. Fixed 2026-08-02, on instruction.** The
flow-completion tool built for item 1c did not run against Motor: every flow
ended in `ECONNRESET`, because **sys-io reset a drained TCP connection instead
of closing it**. The full account, the fix, and what it deliberately leaves
alone are in `core-networking-rewrite.md` under "P2: protocol hardening gaps".
It is preexisting and it is not in the netstack but in sys-io's
`close_tcp_socket_inner`; it was raised rather than worked around, per
AGENTS.md, since a benchmark that swallowed the reset would be concealing
exactly the thing it tripped over.

Two things the fix dragged in, both of which are the point rather than
incidental:

- **A preexisting poll bug in the vdso veneer.** `stream_maybe_raise_events`
  (`SL/rt.vdso/src/net/rt_tcp.rs`) raised `POLL_READ_CLOSED` *without*
  `POLL_READABLE` for a stream whose read half was already closed when the
  interest was registered, so a reader registering after a peer's FIN never
  learned of the EOF. mio's `test_connection_reset_by_peer` caught it the moment
  the close became a FIN. The event path was always right
  (`TcpStream::set_tcp_state` raises `READABLE | READ_CLOSED`); only the
  registration-time synthesis was missing it. Reachable before this change via
  `shutdown(WRITE)` -- the reset just meant nothing ever hit it. Note that
  `SI/runtime/mod.rs:1` carries a blanket `#![allow(unused)]` over the whole
  runtime tree, which is why dead code in this area does not warn: the
  `delayed_notify` branch of `close_tcp_socket_inner` `take()`s `close_req` into
  a dead binding and never answers it. Harmless today -- moto-io discards the
  response (`NetCmd::TcpStreamClose => {}`) -- and left alone.
- **Three systests asserted the reset, not the close.** The cancelled-connect
  and cancelled-accept tests each hold the peer open on purpose and then
  required the abandoned socket to *vanish* within 2s, which is only true of an
  RST. Under a FIN it sits in FIN-WAIT-2 until the peer answers. They now assert
  the thing they were written for -- that sys-io *initiated* the close, via a
  closing protocol state -- and then release the peer and assert the socket is
  actually reclaimed, which is strictly stronger than disappearance (which could
  also happen for the wrong reasons). No sys-io behaviour was adjusted to suit
  them.

One test needed an unrelated isolation fix that this change exposed:
`test_failed_tcp_setup_rolls_back_socket` takes an exact `net.tcp_sockets`
baseline, and its predecessor `test_stale_cross_connection_accept_is_requeued`
waited only for `net.active_clients` before returning, leaving an established
pair still exchanging FINs. Latent before -- a reset pair disappeared within the
~1ms of `drop_tcp_socket`'s flush -- and reproducible at about 1 run in 3 in
release afterwards. The predecessor now waits for its own sockets. Confirmed by
running systest six consecutive times in release.

**Item 1b.2 -- a connection that sent nothing resets on close. Fixed
2026-08-05, on instruction, committed as `cc4940f1`.** Item 1b.1 replaced the
reset of a *drained*
connection with a graceful close, which is right for a flow that has sent its
payload and wrong for one that has sent nothing at all. `close_tcp_socket_inner`
now returns `CloseAction::Abort` when `stat_tx_bytes == 0`, alongside the
existing SO_LINGER(0) and unread-data cases: 11 lines and one comment.

**The predicate is deliberately "never transmitted a byte", not item 1b.1's
`drained`.** `tx_queue.is_empty() && send_queue() == 0` is also true of a flow
that sent its whole payload and had it acknowledged, which is exactly the case
item 1b.1 fixed -- every rnetbench flow ending in `ECONNRESET`. A reset cannot
truncate a stream that carried nothing, so this narrower rule takes the reset
only where it is safe, and 1b.1's fix stands.

What went wrong is worth stating precisely, because the symptom was a stall
rather than an error. The peer socket closed into FIN-WAIT-2, where
`tcp_linger_task` waits for `!is_open()` -- true only in CLOSED and TIME-WAIT.
FIN-WAIT-2 only advances when the peer sends its own FIN, and the peer was a
writer that would never send one, so the wait always ran to the deadline while
the socket accepted that writer's data. The stall therefore equals
`DEFAULT_LINGER_SECS` exactly, which a probe confirmed causally: at 7 the stall
was 7.03s, at 60 it was 60.01s.

Measured on mio's `tcp::test_write_error`, which is the test that exposed it:
the `test_connect_error` to `good error` interval falls from 60.01s to 0.03s in
debug and 0.00s in release, a whole mio-test run from ~65s to ~8s, and 25
consecutive mio-test runs pass where the pre-fix tree hung inside 10 runs on
three separate trees (this one, `fdc24bb5`, and the pre-series merge base
`e55c0223` -- so the hang predates the wrapper work and is this defect's tail,
not a separate one).

Verified by `tcp::test_write_to_dropped_peer_fails_fast`: a peer accepts,
drops without reading or writing, and the writer must fail promptly. It is
bounded -- a 200 ms write timeout and a 5-second deadline -- because the failure
it guards against is a stall, and an unbounded test would arrive as a harness
timeout instead of an assertion. Fail-first with the sys-io change stashed and
the test in place: `writing to a dropped peer never failed: its data was
absorbed for the linger`. mio's own test cannot guard this -- it passes either
way, just slowly.

**Found while gating, and fixed on instruction as item 5 below: sys-io aborts
on an accept whose client has gone.** `runtime/net/tcp_listener.rs:496` does
`SysObj::get_pid(sender.remote_handle()).unwrap()`, and that call returns
`BadHandle` (17) when the accepting client's channel is already torn down --
a legitimate race, not a violated invariant. sys-io is `panic = "abort"`, so
it takes networking on the whole machine down; the release run that hit it
left the VM refusing SSH. Two things make it worth prioritising rather than
filing: the unwrap dates to `345a18450` (2026-04-20), long before this series,
and **every accept executes it**, because `post_accept` reserves a fresh
channel per accept, so the listener's connection and the accepting connection
are always different handles and the same-process check always runs. It fired
once in about twenty-five logged full-suite runs on this branch. The fix has
the shape Step 6 patch 4 used for the other abort-shaped sites: treat a failed
`get_pid` as "that client is gone", refuse the request, and log. It is item 5
below.

Gate on the staged patch alone, with the uncommitted 3.1 and 4 work set aside
so that what was measured is what would be committed: `full-test-networking.sh`
three times debug (203/197/196s) and three times release (140/138/134s), all
`rc=0` on the first attempt, with no retries or tolerated failures. The new
regression, `mio-test: ALL PASS`, systest's `PASS` marker, the tokio suite and
the netstack closure's 591 tests are present in all six, and no sys-io panic
occurred in any of them. `cargo +nightly fmt` clean; both profiles build
standalone; `make clippy` against clean `HEAD` differs only by the four
pre-existing `sys-io` warnings moving down by exactly the eleven lines this
patch inserts. No paired `rnetbench` A/B: the change is one comparison on the
close path and nothing on a packet path moved.

**Item 1c -- the initial congestion window. Done 2026-08-02, on decision.**
38 lines across three netstack files, most of them comment, plus a 67-line test.
The behavioural change is four statements.

Item 1b is what made this worth doing: until the congestion window bounded
anything, the initial window bounded nothing and raising it was free in both
directions. Both controllers started at `cwnd: 1024 * 2` with `min_cwnd: 1024 *
2` (`netstack/src/socket/tcp/congestion/cubic.rs:34` and `reno.rs:17`), and
`set_mss` set `min_cwnd = mss` without touching `cwnd`, so after a normal
handshake the initial window was **2048 bytes against a 1460-byte MSS: 1.4
segments** -- under every RFC's floor of two. Slow start here is byte-counting
(`cwnd += ack_len`), so the gap is roughly one round trip per doubling, which is
tens of microseconds on this link and tens of milliseconds on a real one.

`set_mss` now also assigns `cwnd = initial_window(mss)`, a new shared
`congestion.rs` helper computing RFC 6928 section 2's `min(10*MSS, max(2*MSS,
14600))`. The three decisions the item was holding, settled:

1. **RFC 6928 (IW10) over RFC 5681 (IW3), on decision 2026-08-02** after both
   were measured. IW10 is what Linux has shipped since 2.6.39, so it is what
   peers are already tuned for; IW3 captured about a third of the win. The
   measurement's limit was stated and accepted at the point of decision: this
   rig loses no packets, so it can only show IW10's upside, and Motor's TX path
   can emit the ten-segment burst as a single TSO super-segment, so a real NIC's
   pacing is absent as well.
2. **In the controllers, in `set_mss`.** The handshake is the only place an MSS
   arrives, so it is the only place an initial window can be sized; it is also
   the only place the value is meaningful, because nothing has been sent or
   acknowledged yet and `cwnd` is still the constructor's placeholder. A
   sys-io-side setter would have needed new netstack API for no gain. Assigning
   rather than taking the larger of the two is deliberate -- at a small enough
   MSS the placeholder is the *bigger* number (at 100 bytes it is twenty
   segments), so `max()` would keep a window the RFC does not allow.
3. **Measured with the flow-completion mode**, described below -- the standing
   `rnetbench` workload cannot see this change, and the tool exists because of
   that.

Verified: `test_handshake_sets_the_initial_congestion_window` walks a passive
open at four MSS values -- covering the ten-segment, 14600-cap, and two-segment-
floor branches, including the 100-byte case where the RFC window is below the
old placeholder -- and an active open, since sys-io opens connections both ways
and the two reach `set_mss` through different arms of `process`. 581 netstack
tests pass under sys-io's exact feature closure, 571 under the Reno one, and the
crate still builds warning-free with no controller at all (`initial_window` is
`cfg`-gated on the two, since `NoControl` has no window to initialise).

Not needed, and worth recording so it is not re-derived: no clamp to the remote
window. `dispatch()` computes `win_limit` from the peer's advertised window
first and only then takes `min` with the congestion headroom, so a large initial
window cannot put anything extra on the wire against a peer that advertised a
small one.

**Result, p50 flow completion in microseconds** (server to client, transfer
only), each cell pooled over two 200-flow blocks, run A1 B1 C1 A2 B2 C2 so that
no arm owns the host's fast first-block position -- and the baseline is the arm
that got it:

| flow | IW 2048 | IW3 = 4380 | IW10 = 14600 |
| ---- | ------- | ---------- | ------------ |
| 4 KiB | 188.2 | 154.2 (-18%) | 135.8 (-28%) |
| 8 KiB | 185.6 | 178.5 (-4%) | 120.3 (-35%) |
| 16 KiB | 259.6 | 221.5 (-15%) | 159.8 (-38%) |
| 32 KiB | 301.1 | 266.8 (-11%) | 203.4 (-32%) |
| 64 KiB | 338.0 | 290.9 (-14%) | 246.7 (-27%) |
| 256 KiB | 485.2 | 463.5 (-4%) | 420.2 (-13%) |

The `min` of each sample set moves monotonically with p50 in every arm, which is
what says this is the slow-start ramp and not tail noise: the baseline's minimum
steps up by roughly one round trip (35-45 usec here) per doubling of flow size,
exactly as byte-counting slow start from a 2048-byte window predicts.

Both benchmark binaries were bit-identical across all six blocks -- the manifest
md5s below, `789679cb...` and `1ce3eedf...`, unchanged, because nothing outside
the netstack was rebuilt. The whole difference between the arms is the two
constants inside `initial_window`.

Contrast this with item 1b, which measured as free on the same rig. The reason
is the same in both cases: five-second `rnetbench` transfers amortise the first
round trips to nothing, so the standing workload cannot see either change. Item
1b really was free here and this really is a large win here; both statements are
about connections short enough for slow start to still be running.

Gate: `full-test.sh` three times release and three times debug, all six passing
on the first attempt with no retries; `mio-test` ALL PASS and `tokio-tests` PASS
from their unmodified upstream copies; sys-io self-tests 44 with none failing;
`cargo +nightly fmt` clean; sys-io clippy 33 debug / 30 release, with the
warning *sets* diffed against `HEAD` and identical, not merely the counts. The
netstack suite under all four controller feature combinations: 581 with Cubic,
571 with Reno, 584 with both, 565 with neither -- each one above item 1b's
record except "neither", which is unchanged, because the new test lives inside
the module gated on a controller existing at all.

Standard-workload paired gate, run as a regression check rather than as
evidence, order `W A1 B1 B2 A2` -- a discarded warm-up block to absorb the fast
first-block regime, then the arms at mirrored positions (A at 2 and 5, B at 3
and 4) so neither owns the better half of the sitting. Pooled n=10 per arm it
reads +3.92% RR, +0.78% default RX, -2.68% default TX, -0.09% 64k RX, -1.04%
64k TX, and **none of it is attributable to the change.** The per-block medians
say why, and are the reason to record blocks and not just pools:

| block | arm | RR | default RX | default TX | 64k RX | 64k TX |
| ----- | --- | -- | ---------- | ---------- | ------ | ------ |
| W (discarded) | IW10 | 54.03 | 163.51 | 329.61 | 640.95 | 1245.90 |
| A1 | base | 53.33 | 162.41 | 324.61 | 640.07 | 1202.86 |
| B1 | IW10 | 56.50 | 163.63 | 316.99 | 640.06 | 1200.30 |
| B2 | IW10 | 56.43 | 164.75 | 313.08 | 634.27 | 1208.08 |
| A2 | base | 54.69 | 164.42 | 302.32 | 639.68 | 1221.78 |

Default TX falls monotonically across the whole sitting, 329.6 to 302.3 (-8.3%),
straight through both arm boundaries, and its worst block is a *baseline* one --
so the pooled -2.68% is drift, not the arm. RR is the same story from the other
direction: the discarded warm-up block was IW10 and scored 54.03, among the
baseline blocks, while the two counted IW10 blocks scored 56.4. One tree spanned
the entire apparent effect. Same-tree floors in this sitting reach +2.55% on RR
and -6.87% on default TX, both larger than anything in the pooled row.

**Method note, and it generalises past this item:** a monotone drift across a
sitting is invisible in a pooled A-vs-B table and obvious in a per-block one.
Record per-block medians for every paired gate from here, and prefer an
interleaved order to a blocked one -- mirrored positions bound the confound but
do not remove it.

**The measurement tool, built 2026-08-02**, because the standing benchmark could
not do this and any later congestion work will want it again. Do not accept a
flat default-workload `rnetbench` result as evidence either way.

`--flow-bytes N [--flow-count M]` replaces the three standard phases with M
fresh connections each carrying exactly N bytes from the server, reporting
p50/p90/p99/min/max of the transfer alone (connect and handshake excluded, timer
stopped on the last byte). Fresh connections are the point -- a congestion
window is per-socket state. Only the server-to-client direction is measured,
because in the other direction it is the host's congestion control that governs,
not Motor's. The client closes first so the TIME-WAITs land off the system under
test, which is the step that exposed the reset defect above. Run it with `-b
65536`: the default 1KB buffer deliberately stresses per-write costs, which is
the opposite of what this needs. New protocol command `CMD_TCP_FLOW = 4`, with
its byte count riding after the two standard handshake fields so the older
phases parse unchanged; two tests, 6 to 8 in the `rnetbench` suite. The host
client's md5 in the benchmark manifest changes with it.

Method note for anyone repeating this: six flow sizes from 4 KiB to 256 KiB at
200 flows each takes about a minute per block, so a counterbalanced three-arm
sitting is cheap. Report `min` alongside p50 -- it is the least noisy statistic
here and the one that makes the round-trip quantisation legible.

Related, noticed while reading and deliberately not changed: `set_remote_window`
in both controllers only ratchets *upward* (`if self.rwnd < remote_window`), so
`rwnd` -- which caps `cwnd` -- records the largest window the peer ever
advertised rather than its current one. Benign today, because `dispatch()`
enforces the real remote window separately through `win_limit`, but it means
`cwnd` is capped by a number that never comes down.

**Item 2, part one -- TCP timestamps and PAWS. Done 2026-08-03, on decision.**
Item 2 was taken in the order it could be *measured* rather than the order it is
written, and the reason is recorded under "the RTT estimator" below: the RTO
floor cannot be gated on this rig at all, and TSopt can.

sys-io now offers RFC 7323 timestamps, and the netstack applies section 5.3's
PAWS checks R1 and R3. The wire layer, the `tsval_generator` hook and the
`tsecr` echo were all already there; what was missing was a generator to install
and a comparison to make. Details of both checks, and why R3 had to become
conditional, are in `core-networking-rewrite.md` under RFC 5961.

The clock lives in sys-io (`runtime/net/device.rs`, `mod tsval`) because the
netstack asks for a bare `fn() -> u32` with nowhere to keep state. Three
decisions in it:

- **A cached value advanced once per poll, not a clock read per segment.** It is
  read once for every segment emitted; a poll is also exactly the granularity
  that matters, since every segment a poll emits leaves together.
- **A monotonic source**, unlike the wall clock the netstack's own timers run
  on. A clock that stepped backwards would take our timestamps with it, and the
  peer's PAWS would then refuse everything we sent until its view caught up.
- **A random per-boot offset.** Without one the timestamps a machine puts on the
  wire *are* its uptime in milliseconds, told to every peer it talks to, which
  dates its last reboot and so its patch level. Note what one offset per machine
  does *not* buy: connections remain linkable to each other, which needs a
  per-connection offset as RFC 7323 section 7.1 describes -- and that needs
  per-socket state the generator signature cannot carry, so it is a netstack
  change and is **not done**. The existing per-interface `tcp_isn_key` is the
  natural key for it, with domain separation, since using it unmodified would
  make the timestamp leak the ISN hash.

**A preexisting defect this exposed, and the reason the first gate run hung.**
`dispatch()` sized our own packets against the twenty-byte `TCP_HEADER_LEN`
constant rather than `repr.header_len()`, so every option we send was MTU the
packet did not have -- 12 bytes over on every full segment the moment timestamps
came on. The debug full-test sat on `No route to host` until its 600-second
timeout. Three sites fixed, one deliberately not; the account is in
`core-networking-rewrite.md` under "Smaller, cheap". It is preexisting and
present upstream, and it was fixed rather than raised only because TSopt cannot
land over it.

Verified, each check confirmed to fail against a faithful restoration of the
behaviour it replaces:

- `test_paws_drops_a_perfectly_sequenced_old_duplicate` -- fails without R1.
- `test_paws_lets_a_retransmission_repair_a_hole_behind_an_early_segment` --
  fails without R3, with `left: 6000, right: 5000`. This is the one that matters:
  it is the stall R3 exists to prevent, written out.
- `test_timestamps_come_out_of_the_payload_not_the_mtu` -- fails against the old
  sizing with `left: 1460, right: 1448`, a 1492-byte packet on a 1480-byte IP
  MTU. Stated as a difference between a timestamped and an untimestamped segment
  rather than as an absolute, so it holds for either IP version.
- Also `test_paws_admits_a_current_timestamp`,
  `test_paws_compares_timestamps_modularly` (the clock wraps every 49 days and
  "before" has to survive it), and
  `test_paws_does_not_shield_the_socket_from_a_reset`.
- One sys-io self-test, `the_timestamp_clock_is_offset_and_advances`. It asserts
  the *relation* -- that the clock is uptime plus a constant -- rather than the
  two properties separately, which is what lets it run with no wait in it: both
  terms advance together, so it holds whether or not a millisecond passes. A
  boot self-test must not spend time.

**Confirmed on the wire, which `ss` makes harder than it sounds.** This host's
`ss -i` prints no `ts` flag even for a loopback socket that certainly uses
timestamps, so its absence proves nothing; the MSS does. Against the same
`pmtu:1500`, the baseline arm reports `mss:1460 advmss:1460` and this one
reports `mss:1448 advmss:1448`. Those 12 bytes are the option.

That also *is* the cost, exactly and without a benchmark: at a fixed frame rate,
application bytes fall by 12/1460 = **0.82%**. The standard workload's job was
only to not contradict it. Pooled over mirrored blocks (`W A1 B1 B2 A2`, warm-up
discarded) it reads -1.4% on 64k TX and -2.4% on 64k RX -- right direction, but
the same-tree floors in that sitting are +2.83% (A2 vs A1, 64k RX) and +1.66%
(B2 vs B1, 64k TX), as large as the effect. It bounds the cost at a couple of
percent and does not resolve 0.82% out of the noise. Default TX was useless
here, swinging between ~300 and ~320 MiB/sec *within* each arm.

Gate: `full-test.sh` three times release and three times debug, all passing.
Netstack under all four controller feature combinations: 587 Cubic, 577 Reno,
590 both, 571 neither -- each six above the item 1c record, since the six new
netstack tests are outside the controller-gated module. sys-io self-tests 45, up
from 44. `cargo +nightly fmt` clean; sys-io clippy 33 debug / 30 release with
the warning sets diffed against `HEAD` and identical.

**One failure worth recording rather than explaining away.** A seventh run, the
first release attempt, failed at `full-test: ping 'google.com' failed`: an
earlier `ping google.com` in the same run had succeeded at 15.8 ms, then a
resolve returned `NotConnected (os error 19)`, then an echo timed out. Across 92
logs on this host that run that step it is the only failure ever recorded, and
it landed on this arm, so it is written down here rather than dismissed. It
cannot be this change: the netstack resolves over UDP (`socket/dns.rs` is
`UdpRepr` and `IpProtocol::Udp`) and the failing step is an ICMP echo, while
this change is TCP-only. Six subsequent runs on the same tree passed. Read as a
transient loss of the host's external connectivity.

**Still owed, found while reading and deliberately not fixed.** The immediate
reply path echoes the *incoming* segment's tsval
(`generate_reply`, `SM/socket/tcp.rs`), not TS.Recent. For the duplicate ACK an
out-of-order segment draws, RFC 7323 section 4.3 wants the timestamp of the last
segment that advanced the window; echoing the out-of-order one understates the
peer's RTT sample during exactly the loss recovery where it matters most. It is
independent of everything above -- that path never reads `last_remote_tsval` --
which is why it was left rather than folded in.

**Item 2, part two -- RTT sampling in microseconds. Done 2026-08-03.** The
finding that ordered the item: `RttEstimator` sampled with
`(now - sent).total_millis()`, and `Instant` is microseconds internally, so on a
path whose RTT is ~60 usec **every sample truncated to zero**. Driving a real
socket through send and ACK 60 usec apart gave `have_measurement=true srtt=0
rttvar=0 rto=1000ms`: it sampled, and it sampled nothing.

Every constant and every field of the estimator is now microseconds, each
keeping the physical value it had. Only the unit is finer, and that is the whole
of the intended change: **on the wire this patch does nothing**, because
`RTTE_MIN_RTO` rounds a 60-usec estimate up to a second exactly as it rounded up
a zero. `test_rtt_sampling_survives_a_lan_round_trip` asserts both halves --
`srtt = 60`, and `rto = RTTE_MIN_RTO` still -- so the record of what did and did
not change is in the test rather than only here.

Landing it separately from the floor is deliberate, and reverses what this entry
previously said. The two were going to land together on the grounds that the
conversion is inert alone; inert-and-provable is exactly what makes it a good
patch to land alone, and the alternative was one patch that both changes
resolution and changes loss recovery, on a rig that can measure neither. Now the
floor is one constant, over an estimator already shown to hold real values.

Three things milliseconds were hiding:

- **`u32` microseconds run out at 71 minutes**, and `sample()` multiplies `srtt`
  by seven. Samples are capped at `RTTE_MAX_RTO`, which loses nothing -- a
  sample past the longest wait the timer will ever take cannot inform it.
  Without the cap, `rttvar * RTTE_K` on a `u32::MAX` sample overflows: an abort
  in debug, since sys-io is `panic = "abort"`, and a silent wrap in release.
  `test_rtt_estimator_caps_an_implausible_sample` fails both ways without it.
- **The `total_micros()` conversion saturates** rather than truncating. `as u32`
  on a stall past 71 minutes would report it as a *short* round trip, which is
  the wrong direction for a retransmission timer.
- **The old estimator's plateau was an artifact of its unit.** `test_rtt_estimator`
  walked a 2-second path down to 2012 ms and stopped, because `rttvar` cannot
  fall below 1 under `div_ceil` and 1 ms of variance times K is 4 ms. In
  microseconds that term is negligible and the plateau is `RTTE_MIN_MARGIN`
  above `srtt`, where RFC 6298 puts it. The whole table was recomputed from an
  independent model of the RFC arithmetic, not read off the new code; every
  entry lands within 8 usec per millisecond of the old one, which is the
  rounding the old units did.

`RTTE_MIN_MARGIN` deliberately keeps its 5 ms. It stands where RFC 6298 (2.4)
spends `G`, the clock granularity, and 5 ms has never been this clock's
granularity -- it is a floor under how tight an RTO the variance alone may ask
for, and microsecond sampling is what first makes it reachable. Changing it is
part of the floor decision, not part of a change of units.

**A comment corrected rather than acted on.** Part one left a claim in sys-io
that timestamps buy "RTT samples that survive a retransmission". They would, but
nothing reads the peer's `TSecr` -- and on this path nothing should: RFC 7323
section 5.4 bounds a timestamp tick at a millisecond or coarser, so sampling
from the option is the truncation this patch just removed, reintroduced. What
the option would still add is a sample per ACK rather than one per window, and
one that survives a retransmission instead of being discarded for Karn's
ambiguity. Both are worth having on a lossy path and neither is worth having
here; the comment now says so.

Gate: `full-test.sh` three times release and three times debug, all passing
first attempt. Netstack under all four controller feature combinations: 589
Cubic, 579 Reno, 592 both, 573 neither -- each two above the part-one record,
matching the two tests added. sys-io self-tests 45, unchanged, which is correct:
the change is entirely inside the netstack. `cargo +nightly fmt` clean; sys-io
clippy warning sets diffed against `HEAD` in both profiles and identical.

No `rnetbench` measurement, and deliberately none. There is no mechanism for
this patch to move a number: the clamp makes the estimate unreachable, and this
rig never retransmits.

**Item 2, part three -- the RTO floor. Done 2026-08-03, on decision:
`RTTE_MIN_RTO` is 200 ms, matching Linux.** One constant, over an estimator
part two had already shown to hold real values.

The value was checked against this host rather than recalled: `TCP_RTO_MIN` is
`HZ / 5` in `/usr/src/linux-headers-*/include/net/tcp.h`, and
`net.ipv4.tcp_rto_min_us` reads 200000. RFC 6298 (2.4) permits it in the same
breath as the second -- "a lower minimum SHOULD be used when it is known that a
path has a shorter RTT" -- and every path this stack serves is a virtio link to
its own host.

Two neighbouring constants deliberately did **not** move. `RTTE_INITIAL_RTO`
stays at 1 second: it governs a connection with no measurement at all, which is
RFC 6298 (2.1) and is also Linux's `TCP_TIMEOUT_INIT`, verified in the same
header. `RTTE_MIN_MARGIN` stays at 5 ms, so on this path the floor still binds
-- the estimate under it is about 5 ms, of which all 5 are the margin. Going
below 200 ms is therefore a further decision and not this one, and part two
already recorded why the margin belongs to it.

**The interaction worth writing down: `TCP_DELACK_MAX` is also `HZ / 5`.** A
Linux peer may sit on an ACK for exactly as long as this timer now waits. What
keeps that from being a spurious retransmit is that the delay is *inside* the
RTT sample that sets `srtt`, and the floor is a floor under `srtt`, not a
replacement for it -- which is only true because part two made `srtt` real. Our
own delayed ACK is 10 ms (`ACK_DELAY_DEFAULT`) and is not close.

A second effect, unasked for and welcome: the zero-window probe arms from the
same `retransmission_timeout()`, so a measured connection now re-probes a
closed window at 200 ms instead of a second.

Verified by `test_a_measured_short_path_retransmits_at_linuxs_floor`, which
states the *wire* behaviour -- an unacknowledged segment comes back 200 ms after
it left, and not a microsecond earlier -- rather than reading `RTTE_MIN_RTO`
back, so the constant cannot quietly move without it failing. It fails against
the one-second floor. The test has to take a round trip first, because the floor
governs only a measured path; the unmeasured first RTO is still a second.

**What is still not measured is loss recovery itself, and that has not
changed.** `tc qdisc ... netem loss` on `moto-tap` needs CAP_NET_ADMIN; the
capability set here is empty and `sudo` wants interactive authentication, so it
has to come from outside this work. It would also invalidate the benchmark
manifest's recorded `fq_codel` defaults until reverted. So this change is
argued, not demonstrated: the gate shows it breaks nothing, not that it helps.
The same rig is why item 1's two owed Cubic defects (`beta` squared per loss,
`ssthresh = cwnd >> 1`) have never been observed either.

**Item 3 -- raise the out-of-order assembler capacity. Done 2026-08-03.**
`assembler-max-segment-count-32` in sys-io's dependency on the netstack: 32
holes rather than 4, no fork change to reach it, since the cargo features
already exist (1, 2, 3, 4, 8, 16, 32 -- 32 is the largest offered).

The harm at 4 is not that data is lost, it is *how* it is refused. Past capacity
`add_then_remove_front` fails and `process()` returns `None`, which drops the
segment **and sends no ACK at all**. A sender learns of loss from the duplicate
ACKs that out-of-order arrivals draw, so at capacity the receiver stops telling
it anything and recovery falls from fast retransmit to the RTO -- 200 ms as of
item 2, and a full second before it. That is a receiver silently converting a
recoverable loss burst into a stall. Four holes against a 128 KiB window --
about ninety segments -- is a few percent loss.

Cost: `Contig` is two `usize`, so 16 bytes per hole, 512 per socket against the
256 KiB of buffers that socket already holds. 0.2%.

**The trap in this item is that the obvious change is untestable, and silently
so.** `lib.rs` gives `cfg(test)` its own hardcoded `config` module, so
`build.rs`, the `MOTO_NETSTACK_*` env vars and the `*-count-N` features all
reach the deployed build and **none of them reach a test**. Enabling the feature
alone would have left every assembler test running at 4 and passing, proving
nothing about the capacity that ships. So the test constant is raised to match,
by hand, and a `const` assertion in `sys-io/src/runtime/net/socket/tcp.rs` --
which *can* see the deployed value -- fails the build if the two ever disagree.
Verified by dropping the feature: `error[E0080]`, carrying its own message.

This is a general hazard, not one about this constant. Several other entries in
that `cfg(test)` module already differ from the deployed defaults --
`IFACE_NEIGHBOR_CACHE_COUNT` is 3 under test against 8 deployed,
`REASSEMBLY_BUFFER_COUNT` 4 against 1, `FRAGMENTATION_BUFFER_SIZE` 4096 against
1500 -- so those capacities are tested at values nothing runs. Making the test
config *be* the deployed config is the real fix and is deliberately not
attempted here: it would change ARP eviction and fragmentation coverage in the
same patch as an unrelated capacity change. **Recorded as owed.**

Verified by `test_the_assembler_absorbs_a_multi_loss_window`: twelve holes in
one window, each of which must draw an ACK. It states the number as a literal
rather than reading `ASSEMBLER_MAX_SEGMENT_COUNT` back, because a test that
reads the constant passes at any capacity including the one this replaced. At 4
it fails on the **fifth** segment with the message spelling out the
consequence. The existing `test_out_of_order_overflow_preserves_state`
parameterises on the constant and so now exercises 32 for free.

A stale comment corrected in passing, in the same Cargo.toml: it recorded
Cubic's window growing only from a 100 ms timer as a known gap, which item 1a.1
closed -- `pre_transmit` runs the curve in microseconds.

Gate: `full-test.sh` three times release and three times debug. Netstack 591
Cubic, 581 Reno, 594 both, 575 neither -- each one above item 2. sys-io
self-tests 45, unchanged; the drift check is a `const` assertion, so it fails at
build time rather than needing anything to run. (This entry first justified that
by saying a self-test would cost boot time. It would not: `CMD_SELF_TEST` drives
the suite on demand under `debug_assertions`, and it is not on the boot path.)
`cargo +nightly fmt` clean;
clippy warning sets diffed against `HEAD` and identical, in three
configurations: sys-io debug, sys-io release, and the netstack's own -- the
netstack needs its own run because `clippy -p sys-io` does not lint a path
dependency, and this change is mostly inside one.

**A seventh run failed, and the cause is worth recording as a property of the
suite rather than of this patch.** `full-test: ping 'does-not-exist.motor.invalid'
did not report 'NotFound'` -- the negative-DNS check, which resolved
`NotReady` instead. The log dates it exactly: the query left at `11:041`,
nothing arrived until `13:899`, and 8.8.8.8's answer reached the socket at
`13:905`, **2.86 seconds** after the query and well past the resolver's
timeout. sys-io handled the late reply correctly; it was simply late. It cannot
be this change either: DNS is UDP, this change is the TCP receive assembler, and
`_proto-fragmentation` is off in sys-io's feature set so the IP reassembler --
the other user of `Assembler` -- is not even instantiated.

**The standing observation: `full-test.sh` is not hermetic.** It resolves
through 8.8.8.8 and pings `google.com`, so a slow or lossy path to the internet
fails the suite for reasons that have nothing to do with Motor. That is now
twice in about 200 runs, once here and once at `ping google.com` during item 2
part one, and both landed on a patch arm where they read as regressions until
the log was examined. Adding retries or longer timeouts is exactly the wrong fix
and is ruled out by the standing instruction. The right one is to make the
external-network checks distinguishable from the rest -- **recorded as owed.**

No benchmark, for the same reason as item 2 part three: this rig loses no
packets, so nothing here can move a number on it.

**Item 4 -- neighbor and route capacities. Done 2026-08-03, on decision.**
The item asked for capacities to be revisited as a performance question, since
Step 6 item 5 had already made ARP admission an attack-surface question. It is
not only a performance question. **The current capacities are a boot-time panic
with an ordinary trigger, and that was reproduced rather than reasoned about.**

`cidrs` and `routes` are unbounded `Vec`s deserialised from
`/sys/cfg/sys-net.toml`; the interface's storage was two of each; sys-io pushed
with `.unwrap()` in a `panic = "abort"` process. Three routes in the config
gave, on a real boot:

```
panicked at sys-io/src/runtime/net/device.rs:717:34:
called `Result::unwrap()` on an `Err` value: Route { cidr: Ipv4(172.16.0.0/12), ... }
kernel::init - sys-io exited with status 0xbadc0de.
```

sys-io is the I/O server, so that is the whole machine. And two of each is
exactly one dual-stack device -- a v4 address and a v6 one, a default v4 route
and a default v6 one -- so a *correct* configuration had no headroom at all. The
shipped config's own worked example is titled "A device with two IP addresses and
two routes", and the loopback device sys-io builds for itself spends both
address slots on `127.0.0.1/8` and `::1/128`.

Capacities, all measured rather than estimated (`Route` 72 bytes, `Neighbor` 16,
`IpCidr` 18):

| constant | was | now | cost per interface |
|---|---|---|---|
| `IFACE_MAX_ADDR_COUNT` | 2 | 8 | +108 B |
| `IFACE_MAX_ROUTE_COUNT` | 2 | 8 | +432 B |
| `IFACE_NEIGHBOR_CACHE_COUNT` | 8 | 64 | +1.6 KB |

64 neighbours and not the 1024 on offer, for a reason specific to the structure:
the cache is a `LinearMap`, so a lookup scans what is **occupied**, not what is
reserved -- a quiet VM with two neighbours scans two entries whether capacity is
8 or 1024, and capacity costs only memory. The catch is that `fill_unsolicited`
lets any peer on the segment take a *free* slot (it may never evict one), so
occupancy, and with it the scan, is exactly the thing a peer spoofing source
addresses can inflate. 64 buys a busy segment eight times the room without
handing that peer a 1024-entry scan.

**On decision: past the limit, clamp and keep booting.** Install what fits, name
each dropped entry at ERROR, come up with partial routing. The alternative
considered was refusing the config outright -- `config::load` already has a
working error channel that `init` propagates with `?` -- and the objection to
clamping is real and worth stating: the machine boots with a routing table that
is not what the file says. The ERROR line is what makes that discoverable.

Demonstrated the same way the defect was, on a real boot with nine routes
configured:

```
ERROR ...device.rs:738: net0: route 10.8.0.0/16 via 192.168.4.1 dropped:
  the route table holds 8 and /sys/cfg/sys-net.toml configures more.
```

Eight `adding route` lines, one drop, no panic, and sys-init came up behind it.

Verified by `net::device::an_oversized_config_is_clamped_not_fatal`, which
builds a `NetDev` over a loopback with nine addresses and nine routes and
asserts eight of each survive -- reaching the assertion at all is most of the
point. Written against a literal 8 and not `IFACE_MAX_ROUTE_COUNT`, because a
test that reads the limit back passes at any limit including the two that was
fatal. Falsified by restoring the `unwrap()`: the suite hangs and the console
carries `sys-io exited with status 0xbadc0de`, the same failure as the
three-route boot.

**A correction to item 3's entry, which this item disproved.** That entry
implied the netstack's `cfg(test)` config diverging from the deployed one is
always an oversight. For `IFACE_NEIGHBOR_CACHE_COUNT` it is load-bearing:
eviction is only reachable in a test that can *fill* the cache, so `test_evict`,
`test_protected_entry_is_not_evicted` and `test_all_protected_still_fills` each
fill exactly three entries and would stop testing anything at 64. What they
cover is the policy -- evict closest to expiry, protect a route's gateway, never
evict for an unsolicited packet -- which does not depend on the number. The
interface-level ARP and NDISC tests range over the constant and follow it. So
this constant stays 3 under test, deliberately and with the reason written next
to it, and the `const` assertion in sys-io is the only check on the deployed
number. `IFACE_MAX_ADDR_COUNT` and `IFACE_MAX_ROUTE_COUNT` are kept equal to
what deploys.

Gate: `full-test.sh` three times release and three times debug. Netstack 591 /
581 / 594 / 575 across the four controller feature combinations, unchanged from
item 3 -- the netstack gains no test here, since what changed is sys-io's
handling of its own config. sys-io self-tests **46, up from 45**. `cargo
+nightly fmt` clean; clippy warning sets diffed against `HEAD` and identical in
all three configurations.

**Item 4a -- the config is read whole. Done 2026-08-03, on request.** Found
while reading for item 4 and raised there rather than folded in; taken next on
guidance.

`config::load` read `/sys/cfg/sys-net.toml` with a single `read` into
`let mut buf = [0; 4096]` -- one `async_fs::BLOCK_SIZE` -- and took whatever
came back as the whole file. Both halves of that were wrong, and the important
part is that both failed *silently into a wrong answer* rather than into an
error. A prefix of a TOML file is usually still valid TOML.

**Demonstrated, because the severity is entirely in whether anything says so.**
A 7715-byte config, identical to the shipped one except for comment padding and
a second device declared at byte 6795:

| | `net1` present | errors or warnings logged | `net0` |
|---|---|---|---|
| before | **no** | **none, at any level** | up, healthy |
| after | yes | none | up, healthy |

The old loader booted a machine that looked completely fine and was missing a
device its operator had configured, and said nothing. `devices` is a
`BTreeMap`, so an absent key is not a deserialisation error; the same goes for a
route or an address lost off the end of its array. An earlier attempt to
demonstrate this with the *route* cut off instead produced
`missing field 'routes'` -- masked, by luck, because `DeviceCfg::routes` has no
serde default. Luck is the right word: nothing about the design prevents the
silent case.

**A second defect the fix had to discover.** `FileSystem::read`'s doc comment
says cross-block reads "may not be supported", which is weaker than the truth:
`MotorFs::read` **fails** such a read outright with
`cross-block reads are not supported (yet?)`. The first version of this fix
looped on short reads, which is the ordinary contract, and could not read a
config larger than one block at all -- it errored on the first call and network
init failed. So the loop reads a block at a time, aligned, and cannot discover
the boundary by asking. That is recorded here because the same trap waits for
any other caller reading a file larger than 4 KiB.

The size now comes from `metadata()`, bounded at 64 KiB -- about 28 times the
shipped config, and small enough that allocating a filesystem-reported size is
uninteresting. Over the bound, and on a read that ends early, `load` returns
`Err` with a message naming the size and the limit, through the error path it
already had.

Verified by `net::config::the_config_read_walks_whole_blocks`, over the
extracted `chunk_end`, which is the part that can be quietly wrong: an
over-long chunk is refused outright by the filesystem, an over-short one merely
costs a round trip, and neither shows up in a config that fits in one block --
which every config did until now. It checks the walk terminates and covers the
file exactly, and spells `BLOCK_SIZE` symbolically so it tests the arithmetic
and not the constant.

Gate: `full-test.sh` three times release and three times debug. sys-io
self-tests **47, up from 46**. Netstack counts unchanged -- nothing in this
patch is in the netstack. `cargo +nightly fmt` clean; sys-io clippy warning sets
diffed against `HEAD` in both profiles and identical.

**Noticed in the failure path, not fixed, and worth its own look.** When network
init fails, the console shows
`ERROR virtio-net: VirtIO NetDev must not be dropped: RxPackets reference it
statically`, and a panic follows in `moto-io/src/net/channel.rs`. So "config
load fails cleanly and sys-io survives" -- which is how the option was described
when item 4's clamping decision was taken -- **is not true end to end**: the
error propagates out of `init` correctly and then something further along does
not tolerate a machine with no networking. The machine kept running in the
observed case, but that path is not the clean shutdown the error channel
implies.

**Item 5 -- sys-io does not abort on a request whose client has gone. Fixed
2026-08-05, on instruction, committed as `58622c82`.** The abort item 1b.2's gate
turned up: `tcp_listener.rs` validated that a listener and the channel a
request arrived on belong to one process by unwrapping `SysObj::get_pid` on
both handles, and `get_pid` answers `BadHandle` once a client's connection is
torn down. sys-io is `panic = "abort"`, so a client that died with a request
still queued in shared memory took networking down for the whole machine.

The check moves into `check_same_process`, shared by `accept` and
`drop_from_client`, which had identical copies of it. **A pid that cannot be
read is refused rather than trusted**: an ownership claim that cannot be proven
must not be honoured, so an unreadable handle takes the same
`InvalidData` path as a genuinely foreign process, and the debug log now
carries both `get_pid` results rather than two unwrapped values. 42 lines
added, 31 removed, in one file. Both sites are hot -- every accept takes this
path, because each is posted on a freshly reserved channel, so the two handles
always differ.

**Reproduced before fixing, and the reproduction is a race, not a switch.** A
systest subcommand binds 256 listeners, arms them all in a tight loop so every
accept is posted microseconds before the exit, and then dies without unwinding;
a harness runs it once per ssh session so each child's death overlaps the next
session's channel setup. On the unfixed tree that produced, in the VM console,
`panicked at sys-io/src/runtime/net/tcp_listener.rs:495:22: called
Result::unwrap() on an Err value: 17` followed by
`sys-io exited with status 0xbadc0de` -- note **495**, the *listener's* handle,
not the accepting one that item 1b.2 recorded, which is why the fix covers
both. The console log is character-interleaved with concurrent output, so it
reads back only through a tolerant match.

**No in-suite regression, deliberately, and this is the part to review.** The
window fired once in roughly four hundred attempts across three harnesses, and
a test that passes on the broken tree guards nothing: a sequential 24-child
version was written, run against the unfixed tree, and **passed**, so it was
removed rather than kept as false assurance. Forcing the window by volume
instead of by timing does not work either -- see the finding below. Making it
deterministic needs a test hook inside sys-io, on the order of moto-io's
`arm_rpc_response_cancel_test`, which is a patch of its own rather than a rider
on an eleven-line fix. Guidance welcome on whether to add one.

**Reported, not fixed: the kernel panics with OOM under many listeners.** Four
concurrent processes each holding 256 TCP listeners -- 4 listening sockets and
a channel reservation apiece -- ended the run with
`KERNEL PANIC (cpu 6): panicked at kernel/src/mm/phys.rs:469: OOM`. A guest
process that asks for more than the machine has should get `ENOMEM` from
`bind`, not stop the machine; `allocate_frame` already returns
`E_OUT_OF_MEMORY` and logs, so the panic is above it. One process holding 256
listeners is fine and ran hundreds of times, so it is the aggregate, not a
per-listener leak. This is not networking-specific and predates this series.

Gate: `full-test-networking.sh` three times debug (202/198/198s) and three times
release (140/138/138s), all `rc=0` on the first attempt with no retries or
tolerated failures; all six carry systest's `PASS`, `mio-test: ALL PASS`, the
tokio suite and the netstack closure's 591 tests, and none contains a panic.
`cargo +nightly fmt` clean; `make clippy` warning locations and texts diffed
against clean `HEAD` and **identical in both profiles** -- the four pre-existing
`tcp_listener.rs` warnings all sit above the insertion point, so nothing even
shifts. No paired `rnetbench` A/B: the check runs once per accept request and
per listener drop, and it replaces two syscalls with the same two.

## Step 11 -- introduce the vDSO wrappers

Execute vDSO Stage 3. Once it lands, re-scope Stages 4 and 5 and update this
document before starting them.

Status: **complete and fully committed.** What the stage
leaves, which is what Stages 4 and 5 were re-scoped against (`3fa997fe`):
`moto_io::net` holds no POSIX state, no raw option-pointer dispatch and no
mandatory vdso object; the FD table stores an `Rt*` wrapper per socket kind;
and no downcast crosses the crate boundary in either direction. The stage's
five
bullets were taken as four patches, one per socket type and then the shared
listener work, because the state each bullet moves is per-type and moving one
type's flags without its raw option dispatch would leave `setsockopt` writing
one copy while the blocking path reads another. Order was UDP, TCP stream, TCP
listener, then the optional readiness observer; patch 3.1 sits between the last
two and is a defect fix rather than a stage bullet.

**Patch 1 -- `RtUdpSocket`. Done 2026-08-04, committed as `6ee7ba50`.** The
vdso now stores a wrapper in
the FD table instead of the native socket, and the wrapper owns what is POSIX
about a UDP descriptor: `O_NONBLOCK`, `SO_RCVTIMEO`/`SO_SNDTIMEO`, the raw
option-pointer `setsockopt`/`getsockopt` dispatch, the `PosixFile` impl, and
the `EventSourceManaged`. `moto_io::net::udp::UdpSocket` keeps only what sys-io
must be told, which is the typed `set_ttl_async`/`ttl_async` pair. 276 lines
added, 209 removed, across five files.

Holding the concrete event source in the wrapper is what removes UDP's
`as_any` downcast rather than deferring it to the observer patch: the wrapper
is what constructs the source and installs it, so it never has to recover it
from the socket's abstract handle. `new_event_source` therefore returns the
concrete type now; `accept` still takes a factory typed in terms of the trait,
so a one-line adapter stands in until the accepted stream is wrapped too.

Two option arms changed shape, both toward less blocking. `SO_NONBLOCKING`,
`SO_RCVTIMEO` and `SO_SNDTIMEO` no longer run through `block_on_sync` on a
future that was always immediately ready -- they are plain stores on the
wrapper. `SO_TTL` is the only arm that still bridges, because it is the only
one that costs an RPC.

Verified by `udp::test_udp_dup_shares_posix_flags`, and it needed writing:
where these flags live is exactly a claim about `dup`, the suite had no UDP
`try_clone` coverage at all, and `test_udp_timeouts` uses a single descriptor
so it cannot tell a per-descriptor flag from a shared one. The test asserts
each flag is both read back through the other FD and *acted on* through it,
since the getter and the blocking path are separate readers and only the
second is the behavior. Sabotaging the `O_NONBLOCK` store fails it with
`left: TimedOut, right: WouldBlock`, which is the deliberately bounded failure:
a deadline is left set across that assertion only so the receive that proves
the flag reached the dup has something to stop it, because an unshared flag
would otherwise hang there rather than fail.

Gate: `full-test.sh` three times debug and three times release, all rc=0 first
attempt, with the new test passing in each. `cargo +nightly fmt` clean; clippy
warning sets diffed against `HEAD` for the whole `make clippy` set and
identical in both profiles (108 debug, 105 release), and a fresh clippy of
moto-io and rt.vdso from a cold build emits nothing.

**Patch 2 -- `RtTcpStream`. Done 2026-08-04, committed as `f178dfbf`.**
It mirrors patch 1 over `moto_io::net::tcp::TcpStream`: `O_NONBLOCK`, both
`SO_*TIMEO` deadlines, the raw `setsockopt`/`getsockopt` dispatch, the
`PosixFile` impl and the poll-event synthesis now live on the wrapper, and the
native stream keeps only what sys-io must be told -- the typed
`shutdown_async`, `set_nodelay_async`, `set_ttl_async` and `set_linger_async`
pairs, plus `take_error`, which became public because `SO_ERROR` is now read
from outside. `TcpStream::event_listener` is gone with the stream's `as_any`
downcast; the listener keeps both until patch 3. 488 lines added, 352 removed,
across five files.

Both traps recorded above were real, and both were answered:

- **The accept factory was widened, not worked around.** `accept` and
  `try_accept` are generic over the listener type -- `&dyn Fn() -> Arc<L>` --
  and return the source they installed alongside the stream, so the vdso wraps
  the accepted stream with the concrete `EventSourceManaged` it just made and
  never recovers it by downcast. The `Cell<Option<..>>` closure this document
  offered was not needed, and it would have hidden from the signature what the
  call actually does. It stays a *factory* rather than a ready-made `Arc` for
  the reason it was one: `try_accept` must be able to answer `E_NOT_READY`
  without allocating a source, which is every turn of mio's accept loop. The
  three native systest call sites got shorter, losing their
  `as Arc<dyn NetEventListener>` casts.
- **The inherited `O_NONBLOCK` copy moved into the vdso**, reading
  `TcpListener::is_nonblocking` once before the accept and seeding the wrapper
  with it.

Three option arms stopped blocking, as in patch 1: `SO_NONBLOCKING` and both
`SO_*TIMEO` are plain stores on the wrapper rather than `block_on_sync` on a
future that was always immediately ready. `SO_SHUTDOWN`, `SO_NODELAY`, `SO_TTL`
and `SO_LINGER` still bridge, because each costs an RPC.

**The inherited flag is load-bearing for the whole SSH path, which the fail-first
work established rather than assumed.** mio's Motor shim marks only the listener
nonblocking and never touches the accepted stream, so with the inheritance
sabotaged the VM boots and `russhd` never serves: five accept events against
sixty on a healthy boot, and the harness cannot log in to run anything. It is
also a deliberate divergence from std on Linux, where an accepted socket does
*not* inherit `O_NONBLOCK`. This patch preserves it exactly; it is flagged here
because nothing else in the tree states it, and it deserves an explicit decision
rather than continued inheritance by accident.

Verified by `tcp::test_tcp_dup_shares_posix_flags`, the TCP analogue of patch
1's UDP test, which needed writing: the suite had no TCP `try_clone` coverage at
all. Each flag is both read back through the other FD and *acted on* through it,
since the getter and the blocking path are separate readers and only the second
is the behavior. The test pins **both values** of the inherited flag, not one:
an early assertion requires a blocking listener's accepted stream to be
blocking, because a build that made every accepted stream nonblocking would
otherwise satisfy the nonblocking half and still be wrong. Both accepted-stream
assertions carry a deadline for the reason patch 1's does -- without one a
regression parks forever and arrives as a harness timeout instead of an
assertion.

Fail-first, three sabotages, each rebuilt and booted:

- dropping the wrapper's `O_NONBLOCK` store fails the test with
  `left: TimedOut, right: WouldBlock`, the same shape as patch 1's;
- seeding the accepted stream `false` takes SSH down as described above, so no
  test runs at all -- the strongest available statement that the copy matters;
- seeding it `true` regardless of the listener is caught first by the existing
  `test_channel_teardown`, but only as a bare `unwrap()` on `WouldBlock` that
  never names a cause; with the ordering temporarily changed, the new assertion
  fails with `a stream accepted from a blocking listener was nonblocking`.

Gate: `full-test-networking.sh` three times debug and three times release, all
`rc=0` on the first attempt, with the new test present in each of the six.
`cargo +nightly fmt` clean. `make clippy` warning sets diffed against clean
`HEAD` for the whole set and **identical in both profiles** (131 debug, 128
release); compare under byte collation, because `en_US` collates
`get(socket_id)` and `get(&socket_id)` equal and clippy does not emit them in a
stable order, which shows up as a phantom transposition.

Paired release `rnetbench` A/B/A, five default and five bulk reps per block:

| block | default RR / RX / TX | bulk RR / RX / TX |
| --- | --- | --- |
| A1 clean | 56.84 us / 164.02 / 299.49 | 54.69 us / 632.92 / 1212.76 |
| B patched | 52.78 us / 162.64 / 296.43 | 54.43 us / 632.64 / 1211.99 |
| A2 clean | 55.23 us / 138.38 / 297.22 | 52.74 us / 628.23 / 1198.36 |

**The patched block is bracketed by the two clean ones on every metric, and the
two clean blocks differ from each other by more than either differs from the
patched one** -- default RX moved -15.6% clean-to-clean (164.02 to 138.38)
against -0.84% for patched-versus-first-clean. So the honest reading is that
this rig cannot resolve an effect of this patch, not that the patch is +0.8% or
-15%; a single A/B pair would have reported whichever answer the block order
produced. Bulk is the tight measurement -- all three blocks within 0.75% on RX
and 1.2% on TX -- and it shows nothing. Per-rep medians are used because the
documented within-block drift is monotonic and large.

The benchmark and the clippy diffs were taken on production source byte-
identical to the gated tree; the only change after them was in systest.

**Patch 3 -- `RtTcpListener`. Complete and gated 2026-08-04; not yet
committed.** It finishes what patches 1 and 2 started: the FD table now stores
a wrapper for every socket kind. `O_NONBLOCK` -- a listener's only POSIX flag,
because the ABI has no accept timeout -- plus the raw `setsockopt`/`getsockopt`
dispatch, the `PosixFile` impl and the poll-registry source live on the
wrapper, and `moto_io::net::tcp::TcpListener` keeps the typed
`set_ttl_async`/`ttl_async` pair and the accept machinery. 272 lines added, 166
removed, across five files.

Three consequences of moving the flag rather than copying it:

- **`listen()`'s nonblocking precondition moved with it, because it is a veneer
  rule.** The native `listen` now takes any backlog and arms the accept queue;
  the wrapper is what refuses a blocking descriptor, which is exactly what the
  native listener did while it owned the flag. mio depends on the pair -- its
  Motor shim marks the descriptor nonblocking and only then calls `listen`.
- **Becoming nonblocking still arms the backlog**, at 1024 as before, since a
  nonblocking accept can answer only from the queue. That side effect moved
  into the wrapper's `SO_NONBLOCKING` arm along with the flag, and the standing
  TODO about already-issued blocking accepts moved with it.
- **The listener's `as_any` downcast is gone**, and with it the
  `listener_event_source` helper that recovered the concrete
  `EventSourceManaged` from the abstract handle, and `TcpListener::event_listener`
  which fed it. This is the same removal patches 1 and 2 made for their types,
  and it was the last one: `NetEventListener::as_any` now has no caller in the
  tree, which is what patch 4 removes.

`moto-io`'s net API is left holding no POSIX state and no raw option-pointer
dispatch at all. `net/mod.rs`'s `into_error_code`, the shared helper for the
option ABI's bare-`ErrorCode` shape, went with the listener's dispatch. Unlike
patches 1 and 2 this patch stops no arm from blocking: the listener's
`SO_NONBLOCKING` never bridged, and `SO_TTL` still does, because it costs an
RPC.

Verified by `tcp::test_tcp_listener_dup_shares_posix_flags`, the listener
analogue of patches 1 and 2, and it needed writing for the same reason: where
the flag lives is a claim about `dup`, and the suite had no listener
`try_clone` coverage at all. Both of its values are pinned, as in patch 2 -- an
accepted stream must be blocking when its listener is and nonblocking when it
is not -- and the flag is read through the three things that consume it rather
than through a getter, because the ABI has no `SO_NONBLOCKING` getter and the
consumers are the behavior.

**Assertion order is load-bearing in that test, in two places.** `listen()` is
the only reader that answers without waiting for a connection, so the sharing
claim is asserted through it first: an unshared flag fails there instead of
parking the accept that follows on a listener nothing is connecting to. And the
blocking-inherit case runs before anything arms the accept queue, which kept
the test clear of the starvation defect patch 3.1 then fixed.

Fail-first, two sabotages, each rebuilt and booted:

- making the `SO_NONBLOCKING` arm read the flag instead of storing it -- one
  copy written, another read, which is the defect the test exists for -- takes
  SSH down exactly as patch 2's second sabotage did: the VM boots, `russhd`'s
  mio accept loop takes the blocking path and parks, the harness cannot log in,
  and no test runs at all. The strongest available statement that the store is
  load-bearing, and the reason the clearing direction is what carries the clean
  assertion;
- ignoring a clearing store -- which `russhd` never issues, so the boot is
  healthy -- fails the new test at its last assertion with
  `left: Ok(()), right: Err(InvalidArgument)` and the message
  `O_NONBLOCK cleared on one listener FD did not reach its dup`.

Gate: `full-test-networking.sh` three times debug and three times release, all
`rc=0` on the first attempt and with no retries or tolerated failures. All six
contain the new regression, patch 2's `test_tcp_dup_shares_posix_flags`, the
netstack closure's 591 tests plus 7 doctests, systest's `PASS` marker, the
tokio suite, and a negative DNS query returning `NotFound` directly; the debug
three report 47 sys-io self-tests and the release three none, which is the
expected split. `cargo +nightly fmt` clean. `make clippy` warning sets diffed
against clean `HEAD` for the whole set and **identical in both profiles** (118
debug, 115 release warning locations), compared under byte collation for the
reason patch 2 records, and re-taken on the final tree after the last comment
edits.

No paired `rnetbench` A/B: nothing on a packet path changed. The moved state is
read once per `accept`, per `listen` and per option call, and the wrapper's
`listen` gate replaces a load the native listener was already doing.

**Patch 3.1 -- a blocking accept cannot be starved. Done 2026-08-05,
committed as `b571a5be`.** The defect patch 3's test work turned up,
taken on guidance because the fix is small: an `accept()` caller was keyed to
the accept request it had itself posted, but sys-io answers the *oldest*
outstanding request, which after any `listen()` is somebody else's. The
response then went to `async_accepts`, and the caller waited for a second
connection nothing was going to make.

The listener now owns the dispatch. `accept_waiters` holds the awaiting
callers in arrival order; `on_accept_response` hands each connection to the
longest-waiting one and falls back to `async_accepts` only when none is
waiting. `RpcWaiter::Accept` loses its sender, and `post_accept` its argument,
so the state it adds is one queue and no per-request coupling: 84 lines added,
30 removed, across three files.

Two properties, both load-bearing:

- **The outstanding-request count still balances.** Every waiter contributes
  exactly one sender and one posted request, so a waiter that takes the
  response of somebody else's request leaves its own standing in that
  request's place. The re-arm and the readiness edge are skipped exactly when
  a waiter took the connection, which is when there is nothing to be readable
  about.
- **A cancelled caller still spends a connection.** Its sender is popped, the
  send fails, and `PendingAccept`'s rollback closes the accepted stream, which
  is what `test_cancelled_native_accept_closes_socket` and its delivered-then-
  cancelled sibling require. An earlier draft re-homed such a connection to
  the next waiter instead; the gate failed it, and the contract stands.

Mixing blocking and nonblocking accepts on one listener is still not something
callers should do; the reason to fix it is that the failure was a silent hang.

Verified by `tcp::test_blocking_accept_is_not_starved`, which arms the backlog
by setting and clearing `O_NONBLOCK`, then accepts one connection from a
thread. Fail-first, re-taken on this tree with the `moto-io` change reverted
and the test in place: the debug suite fails in 174 seconds at
`tests/systest/src/tcp.rs:2656` with `a blocking accept was starved by the
listener's own outstanding accept`. The accept runs on its own thread precisely
so that starvation is an assertion rather than a harness timeout.

The gate earned its keep twice on this patch, and both failures are worth
recording because neither was visible by reading the diff. A first draft
returned `Option` from the dispatch helper and used `pop_front()?`, so an empty
waiter queue took the same path as a delivered connection and **every**
nonblocking accept dropped its connection on the floor: the VM booted, sys-io
logged the incoming connection, and `russhd` never finished an SSH banner
exchange. The outcome is `Result` now, where the two cases cannot be spelled
the same way. The second draft is the cancellation contract above.

Gate on this patch alone, re-taken on top of item 1b.2 rather than reused from
the tree it was first written against: `full-test-networking.sh` three times
debug (203/196/200s) and three times release (148/139/140s), all `rc=0` on the
first attempt with no retries or tolerated failures. All six contain the new
regression, both cancelled-accept regressions, patch 3's listener-dup test,
item 1b.2's dropped-peer test, `mio-test: ALL PASS`, systest's `PASS` marker,
the tokio suite and the netstack closure's 591 tests, and none contains a
sys-io panic. `cargo +nightly fmt` clean; both profiles build standalone;
`make clippy` warning locations and warning texts diffed against clean `HEAD`
and **identical in both profiles** (125 debug, 121 release warning locations),
both sides captured back to back so that neither is a warm-cache artifact.

No paired `rnetbench` A/B: the dispatch runs once per accept response, which is
not a packet path.

**Patch 4 -- the optional readiness observer. Complete and gated 2026-08-05,
committed as `39a0b9b4`, and it completes vDSO Stage 3.**
`NetEventListener::as_any` is gone, having lost its last caller when the
listener was wrapped, and every socket constructor now takes
`Option<Arc<dyn NetEventListener>>`. A native owner passes `None` and reads the
readiness futures; the vdso passes the `EventSourceManaged` it keeps for
interest registration. 126 lines added, 165 removed, across nine files, of
which systest is 67 lines shorter.

The one design decision, recorded for review: **accept is split rather than
made generic over an optional factory.** `accept`/`try_accept` install no
observer and return `(stream, addr)`; `accept_observed`/`try_accept_observed`
take the factory and return the concrete observer alongside. The alternative --
one method taking `Option<&dyn Fn() -> Arc<L>>` -- cannot be called with `None`
without naming an `L` the caller does not have, and Rust has no default type
parameter for a function. Both observed forms keep the factory rather than a
ready-made `Arc` for the reason patch 2 gave: `try_accept_observed` must answer
`E_NOT_READY` without allocating one.

The payoff is visible in the tests rather than in the vdso: systest's two
`NoopNetEventListener` types and every `Arc::new(NoopNetEventListener)` are
gone, along with the `make_listener` closures its native accept sites carried.
That is the Stage 3 goal stated as code -- a native user of `moto_io::net` now
names nothing from the vdso and constructs nothing it does not want.

**No new test, and two sabotages instead.** Patch 4 removes an API requirement
rather than adding behavior. That a socket built *without* an observer still
works is what systest's native tests now do on every run, having lost the
observers they were previously required to pass. The other half -- that
`Some(...)` at a construction site is what actually makes readiness arrive --
has no natural assertion, so it is shown by breaking it. Both sabotages were
rebuilt and booted:

- **accepted streams get no observer** (`build_observed_stream` passes `None`):
  the VM boots and `russhd` accepts, but its mio loop never sees a readiness
  edge, the harness cannot complete an SSH login, and the suite reaches its
  600-second timeout without running a single test. The same shape patches 2
  and 3 produced, and the strongest available statement that the accept path's
  observer is load-bearing;
- **connected streams get no observer** (`rt_net.rs`'s blocking
  `TcpStream::connect` passes `None`): the boot is healthy, systest passes, and
  the suite fails 188 seconds in at `tests/mio-test/src/util.rs:151` with
  `the following expected events were not found: [ExpectEvent { token:
  Token(0), readiness: Readiness(1) }]` -- a connected socket whose readiness
  never reaches the poll registry, named exactly.

Gate, taken on `HEAD` at `b571a5be` -- the earlier 2026-08-04 run against
`fdc24bb5` was discarded rather than reused, because item 1b.2 and patch 3.1
landed in between: `full-test-networking.sh` three times debug (201/202/197s)
and three times release (146/138/138s), all `rc=0` on the first attempt with no
retries or tolerated failures. All six carry systest's `PASS`, the tokio suite,
`mio-test: ALL PASS`, the netstack closure's 591 tests, both cancelled-accept
regressions, patch 3.1's starvation regression, patch 3's listener-dup test,
item 1b.2's dropped-peer test and a direct `NotFound`, and none contains a
panic. `cargo +nightly fmt` clean; both profiles build standalone. `make clippy`
warning texts are identical to clean `HEAD`'s in both profiles, and the warning
locations differ in exactly one line, in systest, where deleting the no-op
observers moved a pre-existing `manual implementation of a no-op waker` warning
from `tcp.rs:747` to `tcp.rs:714`; no warning was added or removed.

No paired `rnetbench` A/B: the emit sites gained an `Option` check on a path
that already made an indirect call, and no packet path changed.

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

Status: **in progress -- re-scoped Stage 4 is complete (patches 1-8,
2026-08-07/08); next is re-scoped Stage 5, the ownership flip.**

**Stage 4 patch 1 -- the `NetClient`/`NetDriver` pair exists, and the channel
tasks are hosted through it. Done 2026-08-07, committed as `c2137b85`.** `moto_io::net::connect()` is
the design section 4 constructor: async, fallible, no thread spawned, no
global state touched, and the documented connect backoff preserved. The
policy moved into a `ConnectBackoff` shared by the async path (which sleeps
on the runtime via `moto_async::sleep_until`) and the compatibility path's
synchronous connect (which keeps its thread sleep and its panic, and is
deleted with the host in Stage 5), so the two cannot drift. The re-scope's
connection-storm soak is owed when the vDSO path switches to the async
connect in Stage 5, not here: the production path still runs the unchanged
synchronous policy, and the async path's only caller is the native test.

`NetDriver::run` hosts the rx and tx tasks, and the compatibility thread
entry now constructs a `NetDriver` and `block_on`s it -- the stage's "one
channel's internals become a `NetClient`/`NetDriver` pair while a temporary
compatibility host continues to back the existing global vDSO path" bullet.
Deleting the thread entry's unsafe `&'static NetChannel` fabrication came
with it for free: the spawned tasks now own `Arc` clones. `NetClient`
carries `request_shutdown` only; `try_reserve` and the reservation
accounting are the next patch's subject, as the re-scope sized them.

Three implementation decisions, recorded for review:

- `NetDriver::run(self)` is an async method rather than the sketched
  `impl Future for NetDriver`. Section 4 allows the spelling to move; a
  hand-rolled poll adds nothing until a host needs to select over the
  driver, and both current hosts just await it.
- The driver's output is `()` for now. Nothing on the driver's path can
  fail and report today -- transport errors still panic where they always
  did -- so `Result<(), DriverError>` would be a fiction; it arrives with
  design 5.6's teardown reporting.
- `request_shutdown` maps to the existing `begin_exit`, now documented as
  callable without the pool lock (it touches only the exiting flag and the
  task wakers); the pool path is unchanged and still tears a channel down
  by releasing its last reservation.

The native test is the first slice of the stage's native-test bullet,
written first as the re-scope directed. `net_driver::test_connect_drive_
shutdown` creates a LocalRuntime, connects a pair, spawns the driver,
requests shutdown, and requires the driver future to complete within a
bounded wait, so a wedged teardown is an assertion rather than a harness
timeout. What it cannot yet prove is I/O through a host-owned channel --
that needs explicit reservations -- and the driver's liveness is meanwhile
covered by every other net test, because the compatibility host runs the
same `NetDriver::run`. Fail-first, by sabotage, rebuilt and booted: with
the `request_shutdown` call removed the debug suite fails deterministically
rather than hanging -- at `NetChannel::drop`'s existing `exiting`
debug-assert (`assertion failed: self.exiting.load(...)`, systest status
255), because dropping a host-owned channel that was never asked to shut
down violates the teardown invariant before the test's own bounded
assertion is reached. In release, where debug asserts vanish, the test's
assertion is what fires. Together with the clean runs this pins the
driver's exit to the shutdown request.

Gate, on the exact committed tree: four debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures. All seven contain the new test's marker,
systest's `PASS`, `mio-test: ALL PASS`, the netstack closure's tests, and a
negative DNS query returning `NotFound` directly; the debug four report 47
sys-io self-tests and the release three none, the expected split.
`cargo +nightly fmt` clean; both profiles build with no new warnings. `make
clippy` warning texts are identical to clean `HEAD`'s in both profiles, and
the warning locations differ only in six pre-existing systest `main.rs`
warnings shifted one line by the new module declaration (118 to 118 debug,
115 to 115 release). No paired `rnetbench` A/B: no per-message code changed
-- the rx/tx task bodies are untouched, and what moved (channel
construction, the thread entry) runs once per channel.

**One anomaly from patch 1's gating is recorded open rather than
explained.** The first gate attempt's first debug run timed out at 600
seconds: systest hung at `test_stdio_pipe_async_fd`, its freshly spawned
`systest subcommand` child never producing output while sys-io kept serving
(the closing `No route to host` is the harness timeout killing qemu). That
run built a tree differing from the final one by one comment edit and is
excluded from the gate for that reason; the hang itself did not reproduce
in four instrumented debug reruns under a stall watchdog armed to capture
`/sys/mdbg print-stacks` forensics before teardown, nor in the three
release runs. Nothing in patch 1's changed code runs in that test's path --
the child does not touch networking, and the per-message paths are
unchanged -- but the log is retained at
`~/motor-dev/gate-anomalies/20260807-netdriver-p1-stdio-hang-debug.log`,
and the mdbg-first procedure applies if it recurs.

**Stage 4 patch 2 -- the host-side reservation protocol. Done 2026-08-07.**
`NetClient` now carries the full design section 4 surface: `try_reserve`,
`capacity`, `reservations`, and `request_shutdown`. `try_reserve` returns a
`Reservation` whose drop releases the slot, and whose *last* drop closes the
channel to new reservations and asks the driver to drain and exit -- the
one-to-zero transition the design specifies. The protocol is one atomic word
(`client_state`: count, an ever-reserved bit, a closed bit) and the closing
release travels in the same CAS as the final decrement, which is the
re-scope's "one atomic state protocol so a reserve cannot race a channel
from idle into teardown": a reserve racing the closing release either wins
the CAS (the channel stays open, holding its reservation) or re-reads the
closed bit and is refused with `ShuttingDown`. A full channel refuses with
`AtCapacity`. Only host-owned channels use the word; a pooled channel's
transitions all stay under `NET.lock()`, whose discipline already provides
the same close-on-last-release semantics, and the two owners never share a
channel instance. Stage 5 unifies them when the pool moves onto
`NetClient`. `request_shutdown` also sets the closed bit now, so a reserve
after an explicit shutdown is refused rather than stranded on an exiting
driver.

Two implementation decisions, recorded for review:

- `try_reserve` takes only the capacity slot; subchannel binding stays
  lazy, exactly as the pool path's `ChannelReservation` defers it to the
  socket constructors. The explicit-reservation constructors (next patch)
  decide what a `Reservation` must hand them, and widening it then is
  additive.
- `ReserveError` distinguishes `AtCapacity` from `ShuttingDown`, because the
  vDSO `NetPool` will react differently: try another channel or provision
  versus discard the client. It is a plain enum, not an `ErrorCode`, since
  it never crosses the ABI.

The native test grew its second case, `test_reservation_lifecycle`: exactly
`capacity()` reservations succeed, the next refuses with `AtCapacity`, a
non-final release keeps the channel open and its slot reusable, and the
final release alone -- no `request_shutdown` anywhere -- flips `try_reserve`
to `ShuttingDown` and exits the driver within the bounded wait. Fail-first,
by sabotage, rebuilt and booted: with the closing release neutered (the last
release neither sets the closed bit nor begins exit), the debug suite fails
deterministically at `the last release did not close the channel`.

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures, under the same stall watchdog as patch 1
(it stayed quiet). All six contain both native driver test markers,
systest's `PASS`, `mio-test: ALL PASS`, the netstack closure's tests, and a
negative DNS query returning `NotFound` directly; the debug three report 47
sys-io self-tests and the release three none. `cargo +nightly fmt` clean;
both profiles build with no new warnings; `make clippy` warning sets are
byte-identical to `c2137b85`'s in both profiles (118 debug, 115 release) --
an earlier draft used `fetch_update`, whose deprecation warning the parity
check caught, and the landed code is a plain CAS loop. No paired
`rnetbench` A/B: the new word is touched only by host-owned reservations,
which no production path creates; per-message code is unchanged.

**Stage 4 patch 3 -- the explicit-reservation socket constructors, for the
socket types that need no accept machinery. Done 2026-08-07.**
`UdpSocket::bind_reserved` and `TcpStream::connect_reserved` take a
[`Reservation`] and create the socket on the host-owned channel it names;
the global pool is not consulted. As the stage plan asks, the new forms are
the real implementation and the old entry points delegate: `bind_inner` and
`connect_setup` now take the `ChannelReservation` as a parameter, and
`bind`/`bind_for_remote`/`connect`/`connect_nonblocking` pass
`reserve_channel()` exactly where they used to call it, so the pool path's
behavior is unchanged by construction.

The mechanism is an owner tag rather than a second reservation type.
`ChannelReservation` carries `ReservationOwner::{Pool, Client}` and its drop
dispatches: pool releases run under `NET.lock()` as always, client releases
run the patch 2 protocol. Patch 2's public `Reservation` became a newtype
over a client-owned `ChannelReservation` (its API and its test are
unchanged), so the reservation flows through everything already built for
the pool's -- `rpc_bind`'s `RpcWaiter::Bind` rollback, the socket's stored
reservation, and the teardown records that hold the channel open until
sys-io has the socket's release -- with the owner deciding only how the
final drop is accounted. No unsafe, no drop gymnastics, and every rollback
path is shared rather than duplicated.

Two decisions, recorded for review:

- `bind_for_remote` has no reserved variant yet: nothing consumes one, and
  the vdso's sendto-on-unbound path stays on the pool until Stage 5. It is
  a six-line addition when a consumer exists.
- The listener is deliberately absent. A listener's accepted streams draw
  reservations of their own, so `TcpListener::bind_reserved` without the
  accept work would create a half-host-half-pool hybrid; the re-scope
  already sized accept as its own patch, and the listener bind goes with
  it.

The native test grew its third case, `test_reserved_socket_io`, which is
the stage's native-test bullet doing real work for the first time: two UDP
sockets bound on the host channel exchange a datagram, a TCP stream
connected on it writes to a std echo peer (on the ordinary pool path) and
reads its bytes back, `reservations()` reads 3, and dropping the three
sockets alone -- their releases travelling through teardown records --
closes the channel and exits the driver inside the bounded wait, with the
count back at zero. Every byte moved because the host's own runtime polled
the driver.

Fail-first, by sabotage, rebuilt and booted: with the owner dispatch
removed -- every release routed through the pool path regardless of owner
-- the debug suite fails deterministically at the pool's own
`released a channel with no reservations` debug-assert, because a
host-owned channel was never counted in the pool's ledger. The dispatch is
load-bearing, and the two accounting disciplines cannot silently absorb
each other's releases.

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures, under the stall watchdog (quiet). All six
contain all three native driver test markers, systest's `PASS`,
`mio-test: ALL PASS`, the netstack closure's tests, and a negative DNS
query returning `NotFound` directly; the debug three report 47 sys-io
self-tests and the release three none. `cargo +nightly fmt` clean; both
profiles build with no new warnings; `make clippy` warning sets identical
to `8f616fdc`'s in both profiles (118 debug, 115 release). No paired
`rnetbench` A/B: the pool path's per-message code is unchanged, and its
constructors changed only where the reservation is created -- the same
call, made by the caller instead of the callee.

**Stage 4 patch 4 -- accept cancellation re-queues, and accept dispatch is
atomic. Done 2026-08-07.** Decision 5's contract: a cancelled accept
spends nothing. Both cancellation windows now funnel into redelivery. A
caller cancelled while parked leaves a dead oneshot sender in the waiter
queue; the dispatch loop skips it (the failed `send` hands the connection
back) and tries the next waiter. A caller cancelled after delivery -- the
response sent into the oneshot, the receiver dropped unpolled -- drops the
`PendingAccept` inside the channel, and its rollback now re-queues a live
connection on its listener instead of closing it, re-raising READABLE
because the original edge was consumed. Error responses never re-queue
(they would cycle between the queue and the error path forever), and
rollbacks with no listener -- teardown -- keep closing, so the
listener-drop path is unchanged. `resp` moved into `PendingAcceptCleanup`
so the rollback can rebuild the pending it re-queues; `close_stream` fell
out as derivable from `resp.status()`.

The patch also fixes a preexisting dispatch race, found while designing
the re-queue and folded in on review approval (2026-08-07):
`async_accepts` and `accept_waiters` were separate mutexes, so a caller
could observe an empty ready queue, and -- before it parked -- the rx
dispatch could find no waiter and queue a connection; the caller then
parked and was woken only by the *next* connection. mio-shaped hosts were
immune (READABLE drains the queue), but a native `accept()`-only server
could serve a connection arbitrarily late. The two queues are now one
`AcceptDispatch` under one lock: check-then-park and give-or-queue are
each atomic, and the ready-queue push happens under the same lock that
observed the last waiter gone. No deterministic regression test is
possible -- the merged lock removes the window by construction -- so the
fix rides on the accept tests around it.

Three implementation decisions, recorded for review: a reclaimed
connection re-enters at the queue *front* (it is older than anything
queued behind it) while fresh completions keep pushing to the back; the
dispatch loop skips dead waiters explicitly even though the rollback
would back-stop a dropped return (re-entering dispatch from inside a
`Drop` is the shape being avoided); and the re-queue path re-raises
READABLE only when the connection actually reaches the ready queue,
matching the fresh-completion path.

Tests: the two systest regressions pinning close-on-cancel are rewritten
to pin redelivery, as decision 5 directs. Each cancels an accept (one
parked, one delivered-unpolled), then requires the next accept caller to
receive that same connection -- remote address matched -- and proves it
live with a byte exchange between the native stream and the std client.
The cleanup-wait helpers only the old contract used are deleted.

Fail-first, by sabotage, rebuilt and booted: with both redelivery paths
disabled -- the dispatch restored to single-waiter send-and-discard and
the rollback's re-queue branch short-circuited -- the debug suite fails
deterministically: systest hangs at
`test_cancelled_native_accept_redelivers_connection` (its second accept
waits for a connection the sabotaged dispatch closed) and the suite
watchdog kills the run at 600 seconds. Both mechanisms are load-bearing:
either alone covers the parked-cancel case, so only disabling both makes
the first test fail, and the rollback alone covers delivered-then-
cancelled.

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures. All six contain both redelivery test
markers, systest's `PASS`, `mio-test: ALL PASS`, the netstack closure's
tests, and a negative DNS query returning `NotFound` directly; the debug
three report 47 sys-io self-tests and the release three none. `cargo
+nightly fmt` clean; both profiles build with no new warnings; `make
clippy` warning outputs are byte-identical to `933db0e8`'s in both
profiles (131 warning lines debug, 128 release, per-crate summary lines
included). No paired `rnetbench` A/B: no per-message code changed -- the
accept dispatch runs once per connection setup, and the data path is
untouched.

**Stage 4 patch 5 -- the host-owned listener: `bind_reserved` and
`post_accept`. Done 2026-08-08.** The accept/listener surface decisions 1-4
specify. `TcpListener::bind_reserved(reservation, addr, observer)`
consumes the one `Reservation` the listener itself lives on, through the
same `bind_inner` the pool path now shares (the `udp.rs` shape).
`post_accept(&self, reservation: Reservation)` is decision 4's donation
call: infallible, posts one accept request immediately -- donation is
posting -- carrying the reservation as the future stream's channel slot.
Internally the old pool `post_accept` split into `post_pool_accept`
(reserve from the pool, unchanged behavior) and
`post_accept_reservation` (the shared posting body), so both families
travel one code path once posted, which is also what keeps decision 5's
cancellation semantics family-uniform for free.

Decision 3's family separation is three gates off one bit, read from the
listener's own reservation owner tag (`ChannelReservation::
is_client_owned`, the one new `channel.rs` surface): `listen()`
debug-asserts pool ownership, `post_accept` debug-asserts host ownership,
and -- behavioral, not an assert -- a host-owned listener neither
self-re-arms in `on_accept_response` nor posts from the pool when an
`accept()` caller parks. Decision 2's park semantics follow: a reserved
`accept()` with no outstanding donation parks until one produces a
completion.

The native test (`net_driver::test_reserved_listener_accept`) is the
review flow from question 4, end to end: bind on one reservation, donate
one accept slot, `try_accept` answers `E_NOT_READY` before any
connection, a std client connects on the pool path, and a bounded
`try_accept` sleep-loop -- the only accept caller anywhere -- claims the
connection once this host's own driver poll dispatches the completion.
Bytes cross both ways, `reservations()` reads 2 throughout (listener +
donation-become-stream), and dropping the stream and listener alone
drains the client to zero and exits the driver inside the bounded wait.
The design 5.5 six-point ownership table gained the accept row
(`vdso-rewrite.md`), which decision 5 owed. The reserved siblings of the
two cancellation regressions are the next patch, alongside a
parks-until-donation regression.

Fail-first, by sabotage, rebuilt and booted: with `post_accept`
consuming the donation without posting, the debug suite fails
deterministically at the native test's own bound -- `panicked at
net_driver.rs: no connection within 10s` (systest rc=1, suite rc=1, no
watchdog involved) -- because sys-io holds the established connection
and nothing the client does can surface it without a posted request.
The donation-is-posting rule is load-bearing, not decorative.

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures. All six contain the new native marker,
both patch 4 redelivery markers, systest's `PASS`, `mio-test: ALL
PASS`, the netstack closure's tests, and the negative DNS `NotFound`;
the debug three report 47 sys-io self-tests and the release three none.
`cargo +nightly fmt` clean; no new warnings; `make clippy` warning
outputs byte-identical to `6d213ec8`'s in both profiles (131 lines
debug, 128 release). No paired `rnetbench` A/B: nothing on the
per-message path changed -- posting moved callers, not code, and the
pool re-post body is byte-for-byte the shared one.

**Stage 4 patch 6 -- the reserved cancellation siblings and the park
regression. Done 2026-08-08.** Test-only: the three `net_driver` natives
that decisions 2 and 5 still owed. The two cancellation siblings mirror
the pool redelivery regressions on a `bind_reserved` listener -- one
cancels an accept parked against a donated request, one cancels after
the response reached the caller's one-shot unpolled -- and each requires
the next accept caller to receive that connection and complete a
ping/pong round trip with the std peer. The park regression pins
decision 2 from the sharp side: with the peer's connection already
established *and waiting inside sys-io*, an accept on a listener with no
donation outstanding must sit out its whole bound -- nothing was posted,
so nothing may arrive -- and the donation then completes the same accept
against the waiting connection. All three end by draining the client to
zero reservations with the driver exiting inside the bounded wait. Every
wait in these tests is a bounded assert, so a future regression fails a
test rather than hanging the suite.

Fail-first, by two sabotages, each rebuilt and booted. First, both
redelivery mechanisms disabled (single-waiter dispatch restored, the
rollback's re-queue branch short-circuited) with the two pool
regressions bypassed so the run reaches the reserved tests: the suite
fails deterministically -- the eaten connection is closed (the sys-io
log shows the accept and the close back to back), the std peer dies on
`UnexpectedEof`, and systest exits 255. Second, decision 2's gate
removed (a parked caller on a host-owned listener posts from the pool):
the park regression's own assert fires -- `an accept with no donation
outstanding completed` -- systest rc 1. Both failure points are the new
tests' own asserts or their peers, never the watchdog.

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures. All six contain the three new markers and
the full patch 4/5 marker set; the debug three report 47 sys-io
self-tests and the release three none. `cargo +nightly fmt` clean; no
new warnings; `make clippy` warning outputs byte-identical to
`a1db0ab2`'s in both profiles (131 lines debug, 128 release). No
`rnetbench` A/B: no product code changed at all.

With patch 6, the accept/listener work item the 2026-08-07 decisions
unblocked is complete: decisions 1-5 are all implemented and pinned by
regressions. Next in Stage 4 is whatever the stage ledger lists after
the accept work; the notification-state patch is dissolved (decision 6).

**Stage 4 patch 7 -- the vDSO `NetPool` and channel-thread entry, landed
additively. Done 2026-08-08.** The first half of the stage's preparation
bullet ("prepare the vDSO `NetPool`, channel-thread entry, and accept-pump
types without switching production construction to them yet").
`rt.vdso/src/net/pool.rs` holds the design 6.1/6.2 pair: `NET_POOL`, whose
`reserve()` scans the listed clients under a short lock and provisions a
channel on a miss, and the channel-thread entry that owns one pool
channel's whole vDSO lifecycle -- spawn/stack/name, `LocalRuntime`, the
async `moto_io::net::connect`, publishing the `NetClient`, driving the
`NetDriver`, unpublishing on driver exit, `rt_tls::on_thread_exiting`,
and `SysObj::put(SELF)`. Nothing constructs sockets through it until the
Stage 5 flip; the crate-level `allow(unused)` `rt.vdso` already carries
covers the interim dead code.

Four implementation decisions, recorded for review:

- The miss path provisions one channel per unsatisfied caller. Design
  6.1's shared provisioning (coalescing) and the queued
  cancellation-aware pool waiters are the two Stage 5 patches the
  re-scope sized -- sequenced coalescing-first there -- and both replace
  only this method's miss path; the types around it are what they build
  on.
- The channel thread takes the caller's reservation *before* publishing
  the client, so a miss caller cannot lose its own channel to a
  concurrent scan, and no retry loop is needed. A caller that cancels
  fails the oneshot send instead; the reservation the failed send
  returns drops on the channel thread, and if it was the only one that
  closes the fresh channel again -- cancellation spends nothing
  permanent. Startup failure travels to the caller as an `Err`, and a
  thread-spawn failure is reported the same way rather than panicking
  (design 6.1 step 6).
- The pool keeps no open/full bookkeeping of its own: `try_reserve` is
  the source of truth, and full or shutting-down clients simply refuse
  and are skipped (a client stays listed while its driver drains; its
  thread unlists it on exit). This is the design's "does not duplicate
  the per-channel subchannel bitmap", applied to channel state
  generally.
- The file is `net/pool.rs`, not the design's "likely
  `net/runtime.rs`": the crate already has `runtime.rs` and
  `io_runtime.rs`, and a third `*runtime.rs` invites confusion.

No fail-first run is possible and none is claimed: the patch adds no
reachable behavior to sabotage -- that is the bullet's own "without
switching production construction". The types' first execution and their
regressions (concurrent cold-start creating ~`ceil(N / IO_SUBCHANNELS)`
threads, sys-io-unavailable startup) are Stage 5 gate items, as the
stage plan lists them.

Gate, on the exact committed tree (the stage gate for this bullet:
build, native driver tests, and the existing vDSO network suites): three
debug and three release `full-test-networking.sh` runs, all `rc=0` on
the first attempt with no retries or tolerated failures. All six contain
the full Stage 4 marker set; the debug three report 47 sys-io self-tests
and the release three none. Before the patch, one debug and one release
run on the freshly merged tree established the resume baseline (see
Current status). `cargo +nightly fmt` clean; both profiles build with no
new warnings; `make clippy` warning outputs byte-identical to
`aa910b1e`'s in both profiles (131 lines debug, 128 release). No
`rnetbench` A/B: no reachable code changed.

**Stage 4 patch 8 -- the accept-pump type. Done 2026-08-08.** The second
half of the preparation bullet, completing Stage 4's list.
`rt.vdso/src/net/accept_pump.rs` holds `AcceptPump`, the design 6.5 task
as a type: `run()` donates pool reservations through `post_accept` while
the native listener's accept load is below the vDSO backlog, then parks;
`poke()` is the wake the Stage 5 wiring calls from the wrapper's
readiness observer (a completion was queued) and its accept shims (a
caller claimed one); `set_backlog()` serves the `listen()` ABI, since a
host-owned listener never calls native `listen()`; `stop()` and a `Weak`
listener reference end the pump. Like patch 7's pool, nothing constructs
it until the Stage 5 flip.

Three design decisions, recorded for review:

- The pump is a level-driven policy loop, not an edge counter: each wake
  recomputes the load from ground truth. A completion handed straight to
  a parked `accept()` caller raises no READABLE edge, so any
  edge-counting scheme drifts on exactly the blocking-accept path;
  recomputation makes coalesced, spurious, and missed-classification
  wakes all harmless.
- The ground truth is one new `moto-io` accessor,
  `TcpListener::outstanding_accepts()`: posted-but-unanswered requests
  plus queued-but-unclaimed connections. The two live under different
  locks; the requests are read first, so a completion moving between
  them during the read can only be double-counted -- the pump may
  transiently under-post but never overshoots its backlog.
- The pump's wake is a vdso-local `PumpSignal` (an epoch counter and a
  single parked waker): its raisers run on the channel runtime thread
  and on caller threads, so `moto_async::LocalNotify` (single-threaded
  by construction) cannot serve, and exporting `moto-io`'s internal
  `WaitSet` would widen that crate's API for one consumer. The
  cross-thread wake of a parked runtime is the pattern
  `moto_async::oneshot` already relies on.

One provisional policy is flagged rather than decided: on a failed pool
reservation (sys-io unreachable past the connect budget) the pump logs
and parks until the next poke. Stage 5's sys-io-unavailable startup
tests own that decision; the comment marks it.

Tests: `test_reserved_listener_accept` now pins the accessor across its
three states -- 0 before the donation, 1 from posting through the
completion's arrival in the ready queue (the claim loop was reworked to
wait on `has_async_accepts()`, making the queued state deterministically
observable rather than racing `try_accept` against it), and 0 after the
claim. The pump loop itself stays unexercised until Stage 5 wires it;
its policy input is what the assertions pin.

Fail-first, by sabotage, rebuilt and booted: with the posted-requests
component dropped from `outstanding_accepts()`, the debug suite fails
deterministically at the test's own assert (`net_driver.rs` `left: 0,
right: 1` immediately after `post_accept`; systest 255, suite rc=1, no
watchdog involved).

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures. All six contain the full Stage 4 marker
set including the reworked test's marker; the debug three report 47
sys-io self-tests and the release three none. `cargo +nightly fmt`
clean; both profiles build with no new warnings; `make clippy` warning
outputs byte-identical to `aa910b1e`'s in both profiles (131 lines
debug, 128 release). No `rnetbench` A/B: the accessor is called only by
the new test, and the per-message path is untouched.

With patch 8, re-scoped Stage 4 is complete: every stage bullet is
either delivered (patches 1-8) or dissolved on review (decision 6). Next
is re-scoped Stage 5, sequenced provisioning-coalescing-first, with the
connection-storm soak owed at the flip.

**Stage 5 patch 1 -- provisioning coalescing in the vDSO `NetPool`. Done
2026-08-08.** The re-scope's "load-bearing half" of the reservation
bullet, sequenced before the waiter work as it directed, and still
additive: the pool stays unreachable until the flip. `reserve()`'s miss
path now parks the caller as a pool waiter and starts one channel per
`IO_SUBCHANNELS` of parked demand instead of one per caller (design 6.1
steps 2-5): a spawn happens only when demand exceeds
`provisions_in_flight * IO_SUBCHANNELS`, and a connecting channel
satisfies up to its whole capacity of waiters under one pool lock before
publishing itself for scans. The supply invariant is stated on the
waiter queue: a publication consumes at least as much demand as the
supply it retires, so no waiter is ever parked without a channel on the
way.

Four implementation decisions, recorded for review:

- Failure fails everyone: a provision that cannot spawn or connect
  delivers its error to *all* current waiters, including those covered
  by other in-flight provisions. sys-io is one process -- a connect that
  failed for one channel is failing for the others -- and over-failing
  keeps the accounting hole-free by construction. Nothing retries: the
  connect budget inside `moto_io::net::connect` already spent its ~10s.
- A channel that finds no live waiters shuts itself down rather than
  being published idle. The mechanism is free: the satisfy loop's spare
  reservation drops, and with nothing satisfied that is the last
  release. This keeps "a quiescent runtime holds no channels" true for
  the pool ahead of the leak-assertion bullet.
- The satisfy loop pins the channel open by reusing a reservation
  bounced off a dead (cancelled) waiter for the next waiter instead of
  dropping it -- the count cannot touch zero mid-loop and close the
  channel under the loop. Cancelled waiters are thereby skipped at
  satisfy time; removing them from the *demand* accounting at cancel
  time is the next patch (deregistration), and until then a
  cancellation storm can briefly over-provision, which the
  shuts-itself-down rule above bounds.
- A slot freed on an existing channel does not wake parked waiters;
  only a publication does. Waiters exist only while every channel is
  full with provisioning already in flight, so the wasted window is one
  channel connect. If the connection-storm soak owed at the flip shows
  this matters, release notification is the recorded follow-up.

The oneshot sends to waiters run under the pool lock (unlike patch 4's
accept dispatch, which sends outside its lock): the wakers involved
flag-and-wake a parked thread and take no pool re-entry, and
provisioning events are rare where accept dispatch is per-connection.

No fail-first run is possible and none is claimed: the pool remains
unreachable by construction. The coalescing property gets its regression
at the flip -- the stage's "concurrent cold-start tests proving that N
simultaneous sockets create approximately `ceil(N / IO_SUBCHANNELS)`
channel threads" -- which is also where the sys-io-unavailable tests pin
the fail-all policy.

Gate, on the exact committed tree: three debug and three release
`full-test-networking.sh` runs, all `rc=0` on the first attempt with no
retries or tolerated failures. All six contain the full marker set; the
debug three report 47 sys-io self-tests and the release three none.
`cargo +nightly fmt` clean; both profiles build with no new warnings
(the vdso build's clippy pass caught a collapsible-`if` in the draft,
fixed with a let-chain; one extra duplicate of the pre-existing
toolchain `memcpy` warning in the release build log is rebuild
multiplicity, settled by the byte-identical clippy sets); `make clippy`
warning outputs byte-identical to `aa910b1e`'s in both profiles (131
lines debug, 128 release). No `rnetbench` A/B: no reachable code
changed.

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

## Open design questions -- vDSO Stage 4 (2026-08-07)

What Stage 4 had to decide, collected here for review before the work that
depended on them, and decided in review on 2026-08-07. They are distinct
from the implementation decisions patches 1-3 already took and flagged for
review inside their Step 13 records (the async `NetDriver::run` spelling,
the `()` driver output, `request_shutdown`'s scope, the owner-tagged
`ChannelReservation`, and the deferred `bind_for_remote` variant).
Questions 1-5 blocked the accept/listener patch, which is the next patch;
question 6 blocked the notification-state patch after it. Each question
keeps its statement and proposed answer, with the recorded decision
beneath it.

**1. Who owns the reservation an accepted stream is created on -- the
caller, or the listener?** The design section 4 sketch spells
`listener.accept(reservation).await`, which reads as "the caller's
reservation becomes the stream". The tree cannot deliver that reading:
`post_accept` binds a reservation to the accept *request* it posts (it is
stored in `accept_requests` keyed by request id, and the request carries
that reservation's subchannel), sys-io answers the *oldest* outstanding
request, and since patch 3.1 the listener hands the answered connection to
the *longest-waiting* caller -- deliberately not the caller whose request
carried it, because keying callers to their own requests is the starvation
defect 3.1 fixed. So under per-caller reservations, the stream a caller
receives would routinely live on a different caller's channel slot, which
with host-owned (non-fungible) reservations is an aliasing surprise the
pool never had. Proposed answer: the listener owns a small supply --
`accept` hands the reservation *to the listener's supply*, not to its own
connection, and the stream a caller gets is built on whichever supplied
reservation the answered request carried. This keeps 3.1's dispatch,
makes reservations fungible again within one listener (their owner tags
still release correctly, per patch 3's dispatch), and matches design 6.5,
whose vdso accept pump already feeds a listener reservations decoupled
from accept callers.

Decided (2026-08-07): as proposed. The listener owns the reservations its
accept requests carry, and an accepted stream is built on whichever
reservation the answered request held; accept callers bring nothing
(question 4). Patch 3.1's oldest-request/longest-waiter dispatch stays.

**2. Where does a host-owned listener's replenishment draw from?** The
native listener self-replenishes: `post_accept` runs ahead of callers, up
to the armed backlog (1024 when the vdso arms it), and each posted request
consumes a pool reservation today -- deliberately never the listener's own
channel, because one listener can spawn millions of sockets. A host-owned
listener has no pool. Options: (a) the listener does not pre-post -- each
accept call supplies the reservation its request posts, so a host listener
holds at most as many outstanding requests as waiting callers; (b) the
host registers a replenishment source (a callback or a handed-over batch)
the listener draws on, which is design 6.5's accept pump moved into
`moto-io`. Proposed answer: (a) for the native API now -- it is the
caller-driven shape section 4 sketches, it needs no new callback surface,
and its cost (no pre-posted accepts, so a burst waits on round-trips) is
the vdso pump's job to solve in Stage 5, where NetPool supplies the pump
exactly as 6.5 specifies. The listener's *own* channel slot comes from the
one `Reservation` that `bind_reserved` consumes.

Decided (2026-08-07): amended in review, because strict (a) cannot serve
a `try_accept`-only host, which is mio's shape. sys-io parks an
established connection no accept request has claimed in its listener's
`pending_sockets` and sends nothing unsolicited -- the protocol has no
"connection arrived" message, so a client learns of a connection only
through the completion of an accept request it posted. A listener whose
requests are posted only by parked `accept()` callers never posts for a
host that only polls `try_accept`, so no completion, readiness edge, or
accepted connection could ever reach it. Posting is therefore
supply-driven: donation is posting (question 4's `post_accept`), each
donated reservation is posted as an accept request immediately, there is
no held-supply queue and no cap, and a reserved listener never re-arms by
itself -- re-arming is the host donating again, which on the vdso path
becomes the Stage 5 pump's job. Supply drains one reservation per
accepted connection. `accept().await` with no outstanding request parks
until a donation produces a completion: an empty supply is a normal
transient in a replenish loop, so there is no fail-fast error. The
listener's *own* channel slot still comes from the one `Reservation`
that `bind_reserved` consumes.

**3. May one listener mix pool-sourced and host-sourced accepts?** Stage 4
is additive, so the old entry points keep working; nothing today stops a
host from calling the old `accept()` (pool re-post) on a listener it
created with `bind_reserved`, or the reserved accept on a pool listener.
A hybrid listener would hold pool-owned and client-owned reservations in
one `accept_requests` map -- each releases correctly (patch 3's owner
dispatch), but the channel a stream lands on becomes unpredictable to the
host, and `NetClient::reservations()` stops meaning "slots I handed out
minus slots released" the moment the pool donates streams to a host
channel's accounting boundary. Proposed answer: a listener remembers how
it was bound and refuses the other family's accept calls with
`E_INVALID_ARGUMENT`; the restriction is one tag and one check, and
lifting it later is additive if a use appears.

Decided (2026-08-07): no hybrid listeners, and no public refusal contract
either -- the pool-sourced accept path dies with the compat host in
Stage 5, so mixing support has no future to serve. While the families
coexist, a listener remembers how it was bound and the wrong family's
arming call debug-asserts (`listen` on a reserved listener, `post_accept`
on a pool listener); the assert dies with the old path.

**4. What is the reserved accept's signature family, and what happens to
the reservation on `E_NOT_READY`?** Stage 3 left four accept entry points
-- `accept`, `try_accept`, `accept_observed`, `try_accept_observed` --
and the re-scope already sized "add a reservation parameter across them"
as its own 200-300 loc patch. The open part is the `try_*` contract: a
nonblocking accept answers `E_NOT_READY` on every empty turn of mio's
loop, and a signature that consumes a `Reservation` per attempt must give
it back undamaged on the miss (`Result<..., (Reservation, ErrorCode)>` is
the honest but ugly spelling). Under question 1's proposed answer this
dissolves: the supply is handed to the listener separately (a
`donate_reservation`-shaped call), the four accept signatures stay as
Stage 3 left them, and a `try_*` miss touches no reservation at all.
Proposed answer: take question 1's listener-supply shape and keep all
four signatures unchanged, which also spares the observed variants a
third parameter axis.

Decided (2026-08-07): as proposed -- the four accept signatures stay as
Stage 3 left them, and a `try_*` miss touches no reservation. The one new
surface is `pub fn post_accept(&self, reservation: Reservation)` on
`TcpListener`, named for the internal verb it performs: post one accept
request now, carrying this reservation as the future stream's channel
slot. It is infallible and returns `()` -- the enqueue is a guaranteed
post, and with donation-is-posting there is no supply-full condition to
refuse. No batch variant; `max_backlog` remains a pool-path knob and dies
with it. The review question this answered -- how `try_accept` learns of
a connection sys-io already holds -- is recorded under question 2: through
the completion of a previously posted request, dispatched into
`async_accepts` by a driver poll, which is also what raises READABLE.

**5. Does the cancellation contract survive verbatim?** Two systest
regressions pin it today: a cancelled accept caller still spends a
connection (its rollback closes the accepted stream), and a
delivered-then-cancelled accept does the same. With host reservations in
the supply, the reservation inside a cancelled `PendingAccept` must
release through its owner tag when the rollback closes the stream --
which patch 3's dispatch gives for free -- and the listener-drop path
must drop a host supply's unspent reservations without posting anything.
Proposed answer: this is a property to *prove*, not a shape to choose:
the accept patch's gate must include both existing cancellation
regressions plus a reserved-variant sibling of each, and the design 5.5
six-point ownership table gets an accept row naming who holds the
reservation at each point. Listed here because it constrains question
1's implementation rather than being decided by it.

Decided (2026-08-07): the verbatim contract is rejected -- a cancelled
accept spends nothing. A failed hand-off in `give_to_waiter` moves to the
next waiter, and when none remain the connection re-queues at the front
of `async_accepts` with READABLE raised; a delivered-then-cancelled
accept (sent into the oneshot, receiver dropped unpolled) re-queues
through the rollback when the listener is still alive and the response
status is ok. Error-status and listener-teardown rollbacks keep closing:
an error pending that re-queued would cycle between the queue and the
error path forever. No time bound: a re-queued pending is
indistinguishable from a completed accept no caller has claimed yet,
which `async_accepts` already holds indefinitely, bounded by the armed
backlog on the client side and by sys-io's backlog budget on the wire.
This matches tokio's documented cancel-safety -- a dropped accept future
loses no connection, as on Linux, where the connection stays in the
kernel queue. The two systest regressions pinning close-on-cancel are
rewritten to pin redelivery, each gaining a reserved-variant sibling, and
the design 5.5 ownership table gains an accept row naming who holds the
reservation at each point.

**6. What does "move LocalRuntime-local notification state into
NetDriver" still mean, and does the startup spin go now or in Stage 5?**
Bullet 2 of the stage predates patches 1-3, and most of what it named is
already resolved: the unsafe `&'static NetChannel` fabrication is gone
(patch 1), and the task wakers (`tx_task_waker`, `rx_task_waker`) are
cross-thread channel state that belongs where it is. What remains on
`NetChannel` is `io_thread_wake_handle` -- written by the compat thread,
read only by `new()`'s startup spin -- and `io_thread_join_handle`,
written and never read. Stage 5's deletion list already includes the
spin and the thread handles with the rest of the compat host. Options:
(a) declare bullet 2 satisfied, fold the two fields' deletion into Stage
5 where the spin dies anyway; (b) a small patch now that moves the
wake-handle publication into the compat thread entry (it is host
lifecycle, not channel state) and deletes the join handle. The rx task's
netdev stats print, which locks the global `NET`, is Stage 5's
"per-client diagnostics" bullet either way. Proposed answer: (a) --
declare it satisfied and record that here; the fields are dead weight
only the compat host touches, deleting them early buys nothing the
Stage 5 deletion does not, and a patch that only shuffles them would be
churn.

Decided (2026-08-07): (a), recorded here -- bullet 2 is satisfied, and
the two fields are dead weight that Stage 5's compat-host deletion
removes. The notification-state patch dissolves.

Decisions 1-5 settle the accept/listener patch's design, and decision 6
dissolves the notification-state patch; nothing else in Stage 4 waits on
review. The re-scope's connection-storm soak stays owed at Stage 5's
flip, when the async connect gains its production caller.
