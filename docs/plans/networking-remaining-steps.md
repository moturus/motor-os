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

Post-capture code analysis of the in-tree russh (moturus fork
`23758e31`, v0.62.5 -- 0.62 is already in tree, so the old "upgrade to
0.62" option is spent): the session loop can only be parked inside
`reply()` -- flush_into cannot park (no write WouldBlock was ever
issued), no timers are configured, and a select!-parked loop would
have been woken by the delivered READABLE. The one blocking await on
the incoming CHANNEL_DATA path is `server/encrypted.rs:1157`,
`chan.send(ChannelMsg::Data).await` on the bounded per-channel mpsc
(`channel_buffer_size` default 100, not overridden). The fork already
hardened the WINDOW_ADJUST arm below it with try_send for exactly this
reason; the Data forward is the remaining blocking hole. Suspected
cycle: the spawned russh-sftp task parks writing its response, the
channel mpsc fills with pipelined READ requests, the session loop
parks forwarding the next one, and the WINDOW_ADJUST that would free
the write sits unread in the socket. (Unproven: the July diag5 round
on the old loop reported capacity 2048 still wedging.)

Remaining work, pending a decision on strategy:

- Option a: stamp ~6 positions in the current russh fork (pre-drain
  flush, select entry, the encrypted.rs:1157 send, handler dispatch,
  post-select flush, the russh-sftp write await) and pin the parked
  line in one ~10-min repro; then fix the fork.
- Option b: fix encrypted.rs:1157 speculatively with the fork's own
  try_send pattern plus an overflow strategy, and soak; risks masking
  rather than pinning if the primary block is elsewhere.
- Option c: accept and document as an app-library defect.

Open question: which option; and whether step 2's zero-failure bar
stands while the fs-sftp workload can trip an app-library bug. Note
any fork fix lives in the moturus/russh repo plus a Cargo.lock pin
bump here, not in this tree.

## Step 2 -- the 3600s clean storm soak

The standing validation deliverable for the rewrite: all seven workloads
(http-std, http-axum, net-rr, net-bulk, fs-write, fs-sftp, looping test
suites) under the oversubscribed storm config for 3600s with zero failures.
The 2026-08-09 attempt ran every workload clean at full intensity except
the step 1 stall. Blocked on step 1; nothing else is known to stand in the
way.

Open question: none.

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

Question 1: does that precondition mean only the poll-registry findings
(step 1), or also the unattributed items on the step 10 watch list?

## Step 4 -- vDSO cleanup and the final performance gate

Closes out the rewrite. Mechanical half:

- Narrow `moto_io::net::channel` exports to the intended surface
  (`NetClient`/`NetDriver`/`Reservation`, sockets, futures, typed options,
  readiness bits, the optional observer).
- Sweep stale terminology (e.g. `moto-io/src/net/tcp.rs:376` still
  documents a `block_on_sync` that no longer exists); remove or explicitly
  justify remaining test hooks (the netdev-gated connect poison earns its
  keep as sys-io-unavailable coverage).
- Add a source-level guard that `moto-io` networking contains no
  `SysCpu::spawn`, `block_on_sync`, `SyncWaiter`, or thread sleep.

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

Question 2: if the re-measured single-stream gap still exceeds the kill
criteria, is closing it (a TX-merge / wake-batching tuning round) a merge
blocker, or is a recorded, bounded regression acceptable?

Question 3: accepted TCP streams currently do not inherit the listener's
`O_NONBLOCK` -- a deliberate divergence from std-on-Linux that russhd's mio
shim depends on. Keep and document, or match Linux?

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

Question 4: accept Option A's costs (depth 14, 918 KB/device) for
universal portability?

Question 5: if not -- is Cloud Hypervisor/Firecracker portability actually
binding for this decision, or is a QEMU-first scheme acceptable?

Question 6: or is the ~164 MiB/s default-RX ceiling acceptable for now and
the whole step stays shelved?

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

Question 7: are long-RTT (WAN) workloads a product target? If no, this
entire step can be parked indefinitely.

Question 8: if yes -- approve the 1 MiB/socket budget for (a) now, or go
straight to the (b) design round and size per workload?

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

Question 9: does loss-recovery quality matter for the product now? If
yes, the order is: harness-driven loss tests first, then the Cubic/ssthresh
/TS-echo fixes they pin, then SACK-based recovery as the big-ticket item.

## Step 8 -- SYN cookies

All prerequisites landed on purpose: TSopt carries wscale/SACK through
cookie mode, RFC 6528 SipHash ISN generation is the cookie primitive (a
cookie is an ISN), the half-open cap is the engagement trigger ("cap hit:
drop" becomes "cap hit: cookie mode"), and the window-accounting
normalization was done knowing cookies add a second writer of it. The
standing recorded decision is "not the next marginal gain" -- the cap plus
connect-state hardening already bound the damage of a SYN flood.

Question 10: schedule cookie mode, or keep the recorded decision to
decline? (Relevant only if Motor is expected to face untrusted networks as
a server.)

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

Question 11: are server workloads with thousands of concurrent connections
a Motor OS product target? This is the product question the whole step
hangs on, and it should be answered before any of it is scoped.

## Step 10 -- small owed items and the watch list

Fix-or-decline items, each small and independent:

- Kernel `phys.rs:469` OOM panic when four processes each hold 256 TCP
  listeners (aggregate exhaustion; `bind` should get ENOMEM, the machine
  should not stop). Predates the networking series and may already be fixed
  by the kernel/sys-io OOM handling merged 2026-08-07 -- re-test before
  treating as open.
- The slab allocator fix (`9ad34f0e`, 2026-08-09) awaits review: it was a
  kernel change made under the overnight keep-progressing instruction.
- The sys-io listener abort fixed in `58622c82` has no in-suite regression
  because its window needs a sys-io fault-injection hook. Build the hook or
  accept the gap.
- ssh exec through a user-mode russhd fails ("closed by remote host") while
  SFTP over the same daemon works. Unexplained; found while building the
  step 1 repro.
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
- The admission test's fs probe got a transient OOM right after its own
  deliberate fault storm (once); wants a recovery-tolerant probe if it
  recurs.
- `udp_rebind_after_close_test` failed roughly half of full-suite runs on
  2026-07-28; it has not failed once in the ~40 gate runs of 2026-08-09.
  Treat as fixed-in-passing, unconfirmed.
- `test_stdio_pipe_async_fd` hung once (2026-08-07, log retained in
  `~/motor-dev/gate-anomalies/`); mdbg-first procedure applies on
  recurrence.
- rmux's host-side pty test threw one EPERM in ~26 runs (non-networking,
  unowned).

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
