# Networking: remaining steps

2026-08-09. This document replaces the seven networking plan documents
(`networking-step-by-step.md`, `core-networking-rewrite.md`,
`core-safety-hardening.md`, `tcp-receive-window.md`,
`virtio-rx-coalescing.md`, `vdso-rewrite.md`, `tcp-listener-backlog.md`),
deleted with this change. Everything completed -- designs, patch records,
gate transcripts, measurements -- lives in those files' git history
(`git log --follow -- docs/plans/<name>.md`). This document carries forward
only what is still actionable, plus the measured facts the remaining
decisions rest on. The old numbering (Steps 0-14, vDSO Stages 0-7) is
retired; steps below are numbered fresh, in recommended execution order.

Where the tree stands: sys-io owns its smoltcp fork with working congestion
control (Cubic + IW10, 200 ms RTO floor, TSopt/PAWS, microsecond RTT
sampling), completed safety hardening (exhaustive connect-state handling,
half-open caps, demand-grown listener backlog, ARP admission, RFC 5961,
RFC 6528 ISNs, randomized ephemeral ports), and deterministic packet-level
test coverage. The vDSO ownership rewrite is production: `rt.vdso` owns the
net channel pool, blocking policy, and POSIX state; the `moto-io` compat
pool is deleted; kernel TLB shootdowns are targeted. Every commit passed a
3 debug + 3 release full-suite gate. One bug is active (step 1); the final
validation soak (step 2) is blocked on it.

## Step 1 -- fix the SFTP stall (the only active bug)

A russhd SFTP session freezes mid-transfer (~1 in 13 iterations under
churn) while the system stays healthy.

**2026-08-09, PDIAG round: Motor OS is exonerated by direct
measurement; the wedge is above the OS, in vendored russh/tokio.** The
specified diagnosis round ran: the poll registry and the net readiness
path were instrumented WDIAG-style (per-stream edge/WouldBlock counters
and a channel watchdog in moto-io, per-source delivery counters and
per-registry wait/collect/park counters in the vdso, all committed as
observation-only "PDIAG" kernel-log lines), and the stall was captured
live at iteration 12. The wedged socket's ledger closes exactly: the
reader saw WouldBlock, the next data arrival raised READABLE, the edge
was delivered into the live registration, the poller collected it 33 ms
later, and the tokio runtime parked 1 ms after that -- permanently --
with the data still queued. Nothing pending anywhere below mio, no
drop, no stale token (every counter accounted; the one
dropped-no-registration edge is the by-design accept-time raise whose
replacement the registration synthesis delivered). A new SFTP session
to the wedged daemon works perfectly and drives the poller through
fresh cycles while the wedged session stays frozen: one task is
starved, the runtime is healthy. This matches the pre-rewrite diag-6/7
finding (session task parked 84+ s inside russh
`packet_writer.flush_into` with the vdso never returning WouldBlock on
write) and resolves the round-8 contradiction: the old
"pending-event-uncollected" evidence came from the old single-slot
poller protocol, which the rewrite's PollerSlot replaced. Suspect shape
(unproven, matches all evidence and russh issue #549): the russh 0.52
session loop blocks in its write/flush arm while the message that
would unblock it sits in the unread read direction. Full record:
`/tmp/motor-stress/run-pdiag1/FINDINGS.txt` (+ repro driver
`repro-sftp.sh`, captures, raw PDIAG series).

**2026-08-09, option-(a) fork-stamp round: ROOT CAUSE FOUND AND
FIXED -- in moto-io after all.** Position stamps in the russh fork plus
readiness stamps in the tokio fork pinned it frame by frame: the
session loop parks forever in the post-select
`packet_writer.flush_into(...).await`; the sftp task is not parked in
ChannelTx (every russh-internal theory dead); tokio's log shows the
socket's cached WRITABLE being cleared with **no WouldBlock ever
issued**, and the next write parking on empty readiness. The clearing
site is tokio `PollEvented::poll_write`: a PARTIAL write (`0 < n <
buf.len()`) clears cached WRITABLE -- a valid epoll-ET assumption
("partial write means the send buffer is full and the kernel owes the
next EPOLLOUT edge"). Motor owed a WRITABLE edge only after
`E_NOT_READY` armed the write-waiter; `write_nonblocking` returns
`Ok(partial)` when the channel TX page pool exhausts mid-copy (churn)
and armed nothing. Fix: a partial write arms the same re-raise as
`E_NOT_READY` (one `maybe_can_write()` call), making the poll ABI
honor the epoll-ET implication mio/tokio rely on. Regression:
`net_driver::test_partial_write_raises_writable`. This also explains
the recorded httpd-axum lost-wake freeze (same tokio clear on bulk
responses). No russh or tokio change needed; the fork instrumentation
(../russh working tree, ~/motor-dev/tokio-motor-diag copy) is
diagnostic-only and uncommitted. Full record:
`/tmp/motor-stress/run-pdiag1/FINDINGS.txt` (runs run-russhdiag1..3,
run-fixval1).

## Step 2 -- the 3600s clean storm soak

The standing validation deliverable for the rewrite: all seven workloads
(http-std, http-axum, net-rr, net-bulk, fs-write, fs-sftp, looping test
suites) under the oversubscribed storm config for 3600s with zero failures.
The 2026-08-09 attempt ran every workload clean at full intensity except
the step 1 stall.

2026-08-10, first post-fix attempt (`run-step2-storm-postfix`): 1730 s
of load, fs-sftp 69/69 clean (the stall used to fire ~1/13 -- the fix
holds under the real storm), every other workload clean, stopped by one
mio-test `test_udp_socket_discard` failure at suite iteration 92. Root
cause found and fixed the same night: a connected UDP socket's source
filter ran only at read time, so a foreign datagram's arrival raised a
spurious READABLE (Linux filters before readiness; mio's discard
contract). Fixed by purging foreign datagrams at the arrival edge and
the level checks (`purge_foreign_have_datagram`, `04c3d791`),
regression `net_driver::test_connected_udp_ignores_foreign_datagrams`
(sabotage-verified).

**DONE 2026-08-10 (`run-step2-storm-full`): 3601 s of load under the
oversubscribed storm config, zero failures, zero anomalies.** fs-sftp
145/145, suites 197/197, http-std 4655, http-axum 2203, fs-write 1233,
net-bulk 96, net-rr 96. The standing validation deliverable for the
rewrite is met.

## Step 3 -- remove the vDSO wake-race safety polling

The last correctness-relevant remainder of the vDSO rewrite. The blocking
net paths still carry defensive rechecks (`block_on_recheck`,
`TX_PARK_RECHECK` = 500 ms, `RX_PARK_RECHECK` = 5 s in
`rt.vdso/src/net/blocking.rs`) that would mask exactly the class of lost
wake step 1 is about. Work (~2 patches): delete the rechecks, drive the
blocking waits with the real deadlines, and add a test running timeout
storms concurrently with live TCP/UDP traffic, asserting progress and zero
retained wait registrations after futures drop (the enabling invariant:
dropping many futures on a quiet socket must leave waiter counts at zero
without help from a later packet).

Precondition, by earlier decision: the known debug full-suite flakes must
be diagnosed and fixed before this step begins -- a comparative pass
percentage is not an acceptable gate.

Question 1 ANSWERED 2026-08-10: flakes that are likely in system modules
(kernel + sys-io + their tests) must be diagnosed and resolved; rare TUI
flakes (rush, rmux, red) may be deferred unless they recur regularly.
Operationally: a system-module flake during a gate stops the commit and
gets diagnosed; the one-shot watch-list items stay on watch. The step-1
fixes satisfied the poll-registry half of the precondition, so this step
proceeded (2026-08-10).

**DONE 2026-08-10.** `block_on_recheck`, `TX_PARK_RECHECK` (500 ms) and
`RX_PARK_RECHECK` (5 s) are deleted; every blocking net park drives the
real `SO_*TIMEO` deadline (`block_on_sync` / `block_on_sync_deadline`)
and a lost wake now hangs its caller instead of self-healing on a tick.
Two tests state the enabling invariant and the storm claim:
`net_driver::test_dropped_futures_leave_no_waiters` (dropped
read/write/readable/writable futures leave rx/tx waiter counts at zero
on a quiet socket, no later packet needed; sabotage-verified against a
Drop that leaks its registration) and
`tcp::test_timeout_storm_under_traffic` (RCVTIMEO/SNDTIMEO storms on
quiet and backpressured sockets concurrent with live TCP+UDP traffic on
other sockets: every short-timeout call returns on time, live traffic
keeps its progress floors, and the post-storm socket still echoes).
Found while re-testing under the new semantics and fixed in passing: the
admission suite's post-fault-storm probes (`fs::metadata` and
`used_pages`) both race the killed child's asynchronous reclamation and
now share one bounded convergence helper (`assert_recovered`).

## Step 4 -- vDSO cleanup and the final performance gate

Closes out the rewrite. Mechanical half -- **DONE 2026-08-10**:

- Exports narrowed: `NetChannel`, `ChannelReservation`,
  `claim_rx_page`/`clear_rx_queue`, the stats hooks, and
  `inner_rx_stream` are `pub(crate)`; the module's visible surface is
  the intended API plus the netdev-gated, `#[doc(hidden)]` test hooks
  (each documented in place; the connect poison keeps its
  sys-io-unavailable justification).
- Terminology swept: the retired Stage/D4b labels in `pool.rs`,
  `accept_pump.rs`, `rt_net.rs`, `blocking.rs`, `channel.rs` now
  describe the present design. (`moto-io/src/net/tcp.rs:376` turned out
  accurate, not stale: the veneer still drives `accept` with
  `block_on_sync` at `rt_net.rs`.) The SeqCst fence block in
  `channel.rs` is re-flagged as its own independently-tested,
  perf-measured audit step.
- Source guard added: `moto-io/build.rs` fails the build if
  `moto_io::net` code (comments exempt) contains `SysCpu::spawn`,
  `block_on_sync`, `SyncWaiter`, `thread::sleep`, or `sched_yield`.
- Question 3's decision is documented at the accept shim.

Measurement half: record the benchmark manifest (see Method), then run the
paired same-host release rnetbench A/B against the reference sample taken
at `ab81c861`: RR 58.8/57.4 usec, default RX/TX 163.6/328.3 MiB/s, bulk
RX/TX 678.9/1356.4 MiB/s. Kill criteria: no sustained throughput loss over
5%, no sustained RR regression over ~5 usec. If step 5 ever lands
coalescing, this reference must be re-recorded first.

Known performance debt going into that gate: a paired A/B on 2026-07-25
measured the rewrite costing 8-22% single-stream throughput (TX merge
factor and sys-io wake batching are the suspected mechanisms; RR was also
worse) with the gap closing at 4 parallel streams. That measurement
predates the ownership flip and the TLB work, so it must be re-taken, not
assumed.

**2026-08-10 sitting: measured, comparison DEFERRED by the method's own
rule.** Two sittings (unpinned, then qemu pinned to P-cores 0,2,4,6 with
the client on 8,10; manifests in `/tmp/motor-stress/bench-step4/` and
`bench-ab/`) put the rig squarely in the OTHER host regime -- the one the
retired 2026-07-19/21 baselines were taken in, on all three axes at once:
RR ~112-126 usec (~2x the reference's 58.8), bulk TX ~735 (~half of
1356.4), default RX 445-570 (the retired 473-525 band vs the reference's
163.6). The vdso-rewrite history already proved this exact bimodality is
the rig, not the code (the same tree measured 525 and 164 on different
days). A same-sitting A/B against `ab81c861` itself was attempted and is
blocked: the old tree builds, but its image pairs a moto-rt-16 vdso with
the current sysroot's moto-rt-17 std and sys-io refuses to boot -- a valid
reference build needs its era's toolchain/sysroot. Per the standing rule
("an out-of-band reading stops the sitting", "never gate on a figure
recorded on another day"), the kill-criteria verdict and the
one-tuning-round policy wait for either a same-regime day or an
era-correct reference build. The in-band cross-check that is possible --
default TX median 337.5 vs the recorded 298-330 regime band -- shows no
new regression. Step 9's probe rode the sitting: 64 parallel streams
sustain ~660 MiB/s aggregate each way (RR 125 usec) with a 5x per-stream
fairness spread (tiers near 6 / 13 / 30 MiB/s) -- that spread is the
O(N)-egress/subchannel-packing signal to profile when step 9 opens.

Question 2 ANSWERED 2026-08-10: if the re-measured gap exceeds the kill
criteria, one bounded tuning round (TX merge factor, sys-io wake
batching), then record the measured regression and continue; not an
open-ended merge blocker.

Question 3 ANSWERED 2026-08-10: keep the inheritance and document it.
(Direction check while documenting: the divergence is that accepted
streams DO inherit the listener's `O_NONBLOCK` -- std-on-Linux hands back
a blocking socket regardless -- because Motor has no
`accept4(SOCK_NONBLOCK)` and mio marks only the listener. Documented at
the accept shim in `rt_net.rs`.)

## Step 5 -- decide receive coalescing

Held 2026-08-02 with its evidence measured; resumes from the record, not
from a rerun. Default-workload RX is packet-rate bound (~164 MiB/s) until
this lands, and the RX axis of every performance gate is blind to
per-message regressions for the same reason.

Measured VMM feature matrix (same image, feature words read from the boot
log):

| VMM | version | `GUEST_TSO4/6` | `MRG_RXBUF` | `INDIRECT_DESC` | `MTU` |
|---|---|---|---|---|---|
| QEMU | 10.2.1 | yes | yes | yes | no |
| Cloud Hypervisor | 52.0 | yes | no | no | yes |
| Firecracker | 1.15.1 | yes | yes | no | no |

Option A (ack `GUEST_TSO4/6`, post 64K RX buffers) is the only universally
portable scheme, and it costs: RX ring depth falls from 128 to 14 slots on
every VMM (Firecracker has no queue-size control, so it binds), posted
receive memory grows 262 KB to 918 KB per device, and the refill budget at
measured packet rates is 28-42 usec per ring turnover. It must land as one
atomic patch -- acking guest TSO while still posting 2048-byte buffers is a
spec violation that drops or corrupts traffic. Success criterion is already
instrumented: the `net.device.rx_size` histogram's over-1514-byte bucket
must go from zero to carrying most bulk traffic, or the step is shelved.
Option B (`MRG_RXBUF` + gather) is demoted to a per-VMM optimization:
Cloud Hypervisor does not offer the bit, and gather costs a contiguous-copy
(up to 64K memcpy per super-frame).

Questions 4/5/6 ANSWERED 2026-08-10: **SHELVED.** The ~164 MiB/s
default-RX packet-rate ceiling is accepted for now; Option A's costs
(ring depth 14, 918 KB/device, atomic landing) buy their universality in
a dedicated sitting, not as a side item. Re-open triggers: a workload
that needs more than ~164 MiB/s single-stream RX without jumbo frames, or
the step 4/9 measurements showing RX-bound regressions the gate cannot
see. On re-open, the step 4 benchmark reference must be re-recorded
first (the RX axis moves).

## Step 6 -- TCP window and per-socket buffer sizing

Three sub-decisions, in order.

(a) Fixed default raise (128 KiB to a proposed 512 KiB per direction, i.e.
256 KiB to 1 MiB per socket). The local rig cannot justify it: the window
is 3.9x from binding at 46 usec RTT and cannot be made to bind, so the
decision is throughput arithmetic (a 128 KiB window caps a 100 ms path at
~10 Mbit/s) plus an approved memory budget -- explicitly not a local
benchmark. A raise before (b) also commits full buffers to every listening
socket.

(b) Per-socket sizing (`SO_RCVBUF`/`SO_SNDBUF`). Needs a reviewed design
first; the open design questions: how an outbound socket carries requested
sizes before its SYN (the current connect API returns an FD only after
setup begins -- native builder, new vDSO ABI, or growable rings); listener
timing and accepted-socket inheritance; post-connect behavior; requested
vs. effective `getsockopt` (silently reporting an unapplied size is not
acceptable); RX/TX floor, cap, units, and zero semantics. The fork surface
is the expensive part and must be designed once for both this and lazy
listening-socket buffers: window scale is fixed from receive capacity at
SYN time, so the netstack needs a construct-with-shift API plus a
grow-an-empty-ring API.

(c) Follow-ups that ride on (b): unify ephemeral-port randomization
(loopback is exempt today only so `test_simultaneous_open` stays
deterministic; once a connect can pin its source port, the exemption can
go), and receive autotuning stays deferred until fixed-plus-per-socket is
shown insufficient on a real workload.

Questions 7/8 ANSWERED 2026-08-10: WAN workloads ARE a product target
(step in scope). Sizing goes through the (b) design round first -- the
design doc (`docs/plans/socket-buffer-sizing-design.md`, 2026-08-10)
covers the builder/ABI fork surface, listener inheritance, requested-vs-
effective reporting, and floors/caps; the fixed default raise (a) waits
on that review rather than pre-committing 1 MiB to every listening
socket.

## Step 7 -- TCP loss-recovery quality

Everything here is invisible on the loss-free local rig and matters in
proportion to real-Internet exposure. Known state, all recorded rather
than fixed: retransmission is go-back-N (the whole unacked window resends
on RTO or fast retransmit); received SACK is parsed and discarded (our own
SACK generation fills one block of three); a loss reaches Cubic twice
(beta applied squared, 0.49 -- fixing it needs a loss-epoch notion the fork
lacks); `on_congestion` sets `ssthresh = cwnd >> 1` instead of RFC 8312's
`cwnd * beta`; the immediate-reply path echoes the incoming timestamp
instead of TS.Recent, understating peer RTT samples during recovery; and
the 200 ms RTO floor is argued from Linux's default, not measured.

The deterministic packet harness can inject loss at the netstack level, so
protocol-correct recovery tests are buildable without a lossy rig; a
host-level lossy path would additionally need CAP_NET_ADMIN this
environment does not have.

Question 9 ANSWERED 2026-08-10: YES, loss-recovery quality matters (real
-Internet exposure is a target). Execution follows the recorded order:
harness-driven loss-injection tests first, then the small pinned fixes
(double-beta Cubic, `ssthresh = cwnd * beta` per RFC 8312, TS.Recent
echo), then SACK-based recovery as the scheduled big-ticket item (its own
design+patch series; go-back-N stays until then).

The small-fix half is **DONE 2026-08-10**, tests first, each
sabotage-verified against its reverted fix:

- Double beta: dispatching the fast retransmit the third duplicate ACK
  armed charged the controller a second `on_congestion` (0.49 per loss).
  The dispatch now signals `on_retransmit` only for an expired RTO
  (`test_fast_retransmit_charges_the_controller_once`,
  `test_rto_still_charges_the_controller`). The fuller NewReno-style
  recovery-point epoch (partial-ACK dupack runs) goes with the SACK
  series, where the recovery point has to exist anyway.
- `ssthresh = cwnd * beta` per RFC 8312 section 4.7 (was `cwnd >> 1`).
- The immediate ACK path (`ack_reply`) echoes TS.Recent, not the
  arriving segment's TSval; before TS.Recent exists the arriving TSval
  is the fallback
  (`test_immediate_ack_echoes_ts_recent_not_the_arriving_tsval`).

Still open here: SACK-based recovery (parse is discarded today), the
200 ms RTO floor justification, go-back-N.

## Step 8 -- SYN cookies

All prerequisites landed on purpose: TSopt carries wscale/SACK through
cookie mode, RFC 6528 SipHash ISN generation is the cookie primitive (a
cookie is an ISN), the half-open cap is the engagement trigger ("cap hit:
drop" becomes "cap hit: cookie mode"), and the window-accounting
normalization was done knowing cookies add a second writer of it. The
standing recorded decision is "not the next marginal gain" -- the cap plus
connect-state hardening already bound the damage of a SYN flood.

Question 10 ANSWERED 2026-08-10: SCHEDULED -- Motor is expected to face
untrusted networks as a server. Cookie mode rides the prerequisites
already landed (TSopt-carried wscale/SACK, SipHash ISN as the cookie,
half-open cap as the trigger); it queues behind the step 7 loss work in
priority since the cap already bounds flood damage.

## Step 9 -- architectural netstack work

The measure-then-decide step, last because every prior step changes what it
would measure. In one sitting, with the benchmark manifest: re-baseline the
full benchmark set and profile a many-connection server workload. Then
decide which of the recorded O(N) structures are worth replacing -- every
segment does a linear listener scan, every egress pass visits every socket
(K packets from one socket cost (K+1)xN visits), `poll_at` recomputes state
across all sockets, and the socket store walks its holes. The candidate
pieces, each separable: hashed 4-tuple demux, an egress ready-list, a timer
wheel, an allocating interval-list assembler, real neighbor/route tables.

Two design consolidations are scoped together with it: merging or formally
projecting the two TCP state enums (the 7-variant client-ABI enum vs. the
fork's 11-variant protocol enum -- needs an ABI compatibility story), and
collapsing the double socket bookkeeping (`SocketBase` carries both a
sys-io id and a smoltcp handle; two maps per operation). Zero-copy token
work stays deferred until a profile shows the copies dominating. Once any
of this lands, upstream smoltcp cherry-picks become real work: budget for
the divergence or explicitly pin.

Question 11 ANSWERED 2026-08-10: measure first, decide later. The
re-baseline plus a many-connection profile runs with the step 4
measurement sitting and gets recorded; which O(N) structures to replace
is decided on that evidence in review, not scoped tonight. First probe
recorded under step 4's 2026-08-10 sitting: -P 64 holds ~660 MiB/s
aggregate with a 5x per-stream fairness spread.

## Step 10 -- small owed items and the watch list

Fix-or-decline items, each small and independent:

- Kernel `phys.rs:469` OOM panic when four processes each hold 256 TCP
  listeners (aggregate exhaustion; `bind` should get ENOMEM, the machine
  should not stop). **RE-TESTED 2026-08-10: the machine survives** -- four
  processes binding until refused (4 x up to 512) get clean refusals and
  exit cleanly; the 2026-08-07 OOM handling holds. The driver is
  committed as a manual probe (`systest` subcommand `listener_flood` +
  the unregistered `admission::test_aggregate_listener_exhaustion`)
  because the probe exposed two NEW items, each needing its own
  diagnosis before the test can gate:
  - Releasing ~2k listeners at once leaves ~8k pages (~32 MB)
    unreclaimed -- static minutes later, not converging (sys-io
    listener/channel teardown accounting suspect).
  - On a dirty pool, bind-until-refused crawls for minutes through the
    vdso channel-provisioning retry budgets (~10 s per attempt) instead
    of failing promptly; on a fresh boot the same loop finishes in
    seconds. A bind at exhaustion should fail within a bounded budget.
- The slab allocator fix (`9ad34f0e`, 2026-08-09) awaits review: it was a
  kernel change made under the overnight keep-progressing instruction.
- The sys-io listener abort fixed in `58622c82` has no in-suite regression
  because its window needs a sys-io fault-injection hook. Build the hook or
  accept the gap.
- ssh exec through a user-mode russhd fails ("closed by remote host") while
  SFTP over the same daemon works. **ROOT-CAUSED AND FIXED 2026-08-10**:
  `local_session::spawn` requested `CAP_SPAWN | CAP_LOG |
  CAP_SPAWN_DETACHED` for every session child unconditionally; the
  system daemon holds `CAP_SPAWN_DETACHED` via sys-init.cfg, a
  user-launched instance does not, and requesting caps the parent lacks
  is `E_NOT_ALLOWED` -- so every exec's spawn failed and the session
  closed, while in-process SFTP never spawned. The request is now the
  intersection with the instance's own capabilities; verified live
  (exec/exec -tt/exec-via-rush/SFTP all pass on :2223, system daemon
  unchanged). Two diagnosis-path notes: a non-terminal russhd logs only
  to the kernel log (moto_log), and nothing on the image reads that log
  remotely -- `sysbox` has an unwired `do_syslog`; wiring it would have
  saved an hour.
- The unmatched-SYN RST on a truly closed port is an unrate-limited 1:1
  reflector (listening ports are bounded; this is the no-listener path).
- Config parsing still aborts at boot on more than the supported CIDR/route
  counts instead of rejecting gracefully (boot-time only, not
  packet-reachable).
- The 127/8 external-ingress drop is IPv4-only; revisit the day an external
  device gets an IPv6 address.
- Two deliberate close-path divergences from Linux stand recorded: a
  half-closed peer holds our socket and its 128 KiB of buffers in
  FIN-WAIT-2 for the 60 s linger, and data arriving after our FIN is
  ignored rather than answered with RST. Re-affirm or schedule.
- One review offer stands open: the corrective window update is restricted
  to post-handshake states (anti-amplification); reverting to
  SYN-RECEIVED-time updates is one line if review prefers.
- Perf micro-items, measure before fixing: TSO super-segments truncate at
  the TX ring wrap (likely halves effective TSO size -- measure first); the
  checksum loop is u16-at-a-time; `DeviceCapabilities` is cloned per
  transmitted packet; per-packet `net_trace!` logging has no `enabled()`
  filter in sys-io's logger.
- Test debt: `REASSEMBLY_BUFFER_COUNT` and `FRAGMENTATION_BUFFER_SIZE` are
  tested at values that differ from deployment; the RDRAND retry path and
  the external-device checksum arm are untestable without seams; the
  crafted-packet regression backlog (RST in every state, window shrink,
  zero-window probes, assembler-overflow storms) is partially enumerated,
  not closed.

Watch-list flakes -- recorded, unattributed, no action unless they recur:

- dns-resolver negative lookup returned `NotReady` instead of `NotFound`
  once (2026-08-09); if it recurs, the in-flight-upstream-query race is
  real.
- `moto_async::test_event_stream` assumes strictly alternating wakes; one
  legal spurious wake broke it once in ~40 runs. Fix is a tolerant resync
  loop if it recurs.
- RESOLVED 2026-08-09: the admission test's post-fault-storm recovery
  flake recurred (`pool did not recover: 30818 -> 255534 pages` -- the
  probe read `used_pages` racing the killed child's asynchronous
  reclamation) and got the prescribed recovery-tolerant probe (bounded
  convergence wait; a real leak still fails past the bound).
- `udp_rebind_after_close_test` failed roughly half of full-suite runs on
  2026-07-28; it has not failed once in the ~40 gate runs of 2026-08-09.
  Treat as fixed-in-passing, unconfirmed.
- `test_stdio_pipe_async_fd` hung once (2026-08-07, log retained in
  `~/motor-dev/gate-anomalies/`); mdbg-first procedure applies on
  recurrence.
- RESOLVED 2026-08-09: systest dying "silently" with ssh status 222 was
  the cross-channel accept-request id collision (fixed with a global
  request-id allocator + `test_accept_ids_unique_across_channels`).
  222 = `0xbadc0de & 0xff`, the vdso panic handler's exit code; the
  panic text lands in the kernel log but the console buffer does not
  always drain before teardown, which is why the gate logs looked
  silent -- worth its own look someday. Artifacts:
  `~/motor-dev/gate-anomalies/20260809-systest-silent-exit222-*` and
  `~/motor-dev/gate-anomalies/systest222/`.
- rmux's host-side pty test threw one EPERM in ~26 runs (non-networking,
  unowned).
- RESOLVED 2026-08-10: motor-fs `tests::random_file` failed one gate run
  in ~9 on `empty_blocks() < 1` after StorageFull. Diagnosis: the
  refusing write needs its data block plus btree-split blocks, so a
  refusal can strand a few free blocks depending on the random insertion
  order; a leak would strand fewer, never more. The randomized site's
  bound is now `< 4` (30/30 local reruns clean); the sequential-fill
  siblings keep the strict `< 1`.
- 2026-08-10, once: a debug-VM systest run's ssh OUTPUT froze after the
  moto_async suite while the VM stayed busy (console showed live net/FS
  activity at 300 s; no PDIAG stall) -- an output-path (sshd/stdio)
  freeze, not a systest hang. Not reproduced in 13+ full-test runs since,
  including two 3+3 gates. On recurrence: sysbox ps + mdbg print-stacks
  of sshd and systest while frozen (`repro-freeze.sh` in the 2026-08-10
  session scratchpad automates the capture).

## Method (carried forward)

- Patches stay near 100-300 lines including tests. Gate per commit: `cargo
  +nightly fmt`, zero new warnings, and three debug plus three release runs
  of `src/tests/full-test.sh` (or `full-test-networking.sh`, identical
  minus the host rmux/tmux tests). No retries, pass percentages, or timeout
  raises that can conceal a defect; stop for guidance on decision gates and
  newly found preexisting defects.
- Performance changes take paired same-host measurements. Protocol learned
  the hard way: A/B/A/B confounds tree with block position -- drop the
  first block or counterbalance, record per-block medians, and know the
  host has two throughput regimes (~164/330 vs ~138/298 MiB/s default
  RX/TX) so an out-of-band reading stops the sitting.
- Benchmark manifest, required before the step 4/9 measurements: commit and
  dirty-tree exclusions; build profile; VMM binary, version, and full
  command line; host kernel, CPU model, governor, turbo state, affinity;
  tap addresses, qdisc and offload state; client/server command lines and
  binary identities.
- Hangs: `/sys/mdbg print-stacks <pid>` plus addr2line on unstripped
  binaries first, before any speculation.
