# Networking: remaining steps

2026-08-10. Rewritten after the overnight run that closed out the vDSO
rewrite: steps 1-4 of the 2026-08-09 numbering (the SFTP stall, the 3600 s
storm soak, the wake-race recheck removal, the vDSO cleanup) are done, as
are the step 7 small loss-recovery fixes and the step 10 items that had
clear fixes. Their full records -- diagnoses, patch lists, gate and soak
transcripts, measurements -- live in this file's git history
(`git log --follow -- docs/plans/networking-remaining-steps.md`). This
document carries forward only what is still actionable, plus the measured
facts the remaining decisions rest on. Steps are renumbered fresh, in
recommended execution order; the decision queue lists everything blocked
on a human call.

Where the tree stands: sys-io owns its smoltcp fork with working
congestion control (Cubic + IW10, once-per-loss congestion charging,
RFC 8312 ssthresh, 200 ms RTO floor, TSopt/PAWS with TS.Recent echo,
microsecond RTT sampling), completed safety hardening (exhaustive
connect-state handling, half-open caps, demand-grown listener backlog,
ARP admission, RFC 5961, RFC 6528 ISNs, randomized ephemeral ports), and
deterministic packet-level test coverage. The vDSO ownership rewrite is
production and closed out: `rt.vdso` owns the net channel pool, blocking
policy, and POSIX state; the blocking paths park on real deadlines with
no safety rechecks; the `moto_io::net` surface is narrowed and guarded
async-first by `moto-io/build.rs`. The 3600 s oversubscribed storm soak
ran clean. Every commit passed a 3 debug + 3 release full-suite gate.

## Decision queue -- awaiting review / a call

Resolved 2026-08-11: the socket-buffer-sizing design is approved -- the
8 MiB cap stands, UDP sizing is declined for the series, the fixed
default raise stays deferred behind lazy backlog rings -- with one
amendment: `SO_RCVBUF` on an armed listener applies to later accepts
instead of erroring (the design doc is updated in place). The
`58622c82` listener-abort regression gap is accepted rather than
hooked; its record moved to step 6 test debt. The close-path
divergences from Linux are scheduled as a step 6 work item. The
post-handshake restriction of the corrective window update is affirmed
as permanent (the one-line revert offer is withdrawn).

Resolved 2026-08-11 (second round, for the close-path/step-3 run): the
close-path design (`tcp-close-path-design.md`) is approved -- rings
release to the 16 KiB floor at orphaned FIN-WAIT-2/TIME-WAIT entry, and
the RST-on-data trigger covers both close and shutdown(RD). Step 3 goes
RACK-TLP (RFC 8985) directly at full fidelity -- adaptive reorder
window and DSACK in the same series, dupack fast retransmit kept as
fallback (`sack-loss-recovery-design.md`) -- and the RTO floor gets one
tuning round on the loss harness. Run scope: after close-path and the
step-3 series, write the step-4 SYN-cookie design doc and stop it at
review; approved fillers for remaining time are the listener page-leak
investigation, bind-at-exhaustion bounded failure, and sysbox syslog
wiring. The unmatched-SYN RST rate limit was NOT approved as a filler;
it stays a fix-or-decline item below.

Still open:

1. **russh fork end-state**: the diagnostic stamps in `../russh` may
   stay through development, but the fork must end holding only the
   upstream-PR candidate commit. (`~/motor-dev/tokio-motor-diag` is a
   disposable scratch copy.) Decided 2026-08-11: leave as is; revisit
   when the remaining steps are done.

## Step 1 -- the deferred performance verdict

The rewrite's final gate: paired same-host release rnetbench against the
`ab81c861` reference (RR 58.8/57.4 usec, default RX/TX 163.6/328.3
MiB/s, bulk RX/TX 678.9/1356.4 MiB/s). Kill criteria: no sustained
throughput loss over 5%, no sustained RR regression over ~5 usec; if
exceeded, one bounded tuning round (TX merge factor, sys-io wake
batching), then record and continue (decided 2026-08-10). The recorded
debt to confirm or retire: 8-22% single-stream loss measured 2026-07-25,
predating the ownership flip and TLB work.

Why it is deferred, not skipped (2026-08-10 sitting, manifests in
`/tmp/motor-stress/bench-step4/` and `bench-ab/`): the rig was in its
other regime on all three axes at once (RR ~112-126 usec, default RX
445-570, bulk TX ~735 -- the retired 2026-07-19/21 band), and history
proves the bimodality is the rig, not the code. A same-sitting A/B
against `ab81c861` is blocked: the old tree builds but its moto-rt-16
vdso will not boot against the current moto-rt-17 sysroot. Unblock
paths: a same-regime day (check RR first -- it is the host-steal gauge),
or an era-correct toolchain/sysroot build of the reference. The one
in-band cross-check possible (default TX median 337.5 vs the 298-330
regime band) showed no new regression. Re-probed 2026-08-11 before
starting step 2 (manifest in `/tmp/motor-stress/bench-0811-probe/`):
RR 97.2/111.7/112.6 usec -- still the other regime; stays deferred.

Also owed here eventually: the `channel.rs` SeqCst fence audit (the
wake edges now carry their own ordering; removing the fences is its own
independently-tested, perf-measured step).

## Step 2 -- per-socket buffer sizing (design approved 2026-08-11)

WAN workloads are a product target (decided 2026-08-10), so the 128 KiB
per-direction default is a real cap (a 128 KiB window caps a 100 ms path
at ~10 Mbit/s). The design review landed 2026-08-11 (one amendment:
armed-listener `SO_RCVBUF` applies to later accepts). The series in the
design doc: netstack `SocketBuffer::grow_to` + construct-with-shift
(landed 2026-08-11: empty-ring-only owned-storage growth, a
`win_shift_override` that survives the listen-time reset, nine tests,
both closures green, 3+3 gate clean);
grow latches + ESTABLISHED-edge growth (landed 2026-08-11: requests
latch until the connection is synchronized -- the implementation note
in the design doc records why and where they apply --
effective-capacity getters, four packet tests including the
lazy-backlog flow end to end); sys-io
wire decode + listener inheritance + lazy 16 KiB backlog rings (landed
2026-08-11: sizes ride payload bytes 18/19 of connect and bind as
ceil-log2 16 KiB codes, const-asserted in api_net.rs since moto-sys-io
has no host test runner; a fresh Msg is zeroed so old clients get
defaults; sys-io clamps to 16 KiB..8 MiB; backlog sockets build
16+16 KiB floor rings under the configured shift and latch growth
after listen()); `SO_RCVBUF`/`SO_SNDBUF` + effective-size getters
(landed 2026-08-11 as codes 14/15 -- the draft's 13 was taken -- riding
the existing option RPCs and vtable entries, so no RT_VERSION bump;
systest test_tcp_buffer_sizes covers defaults, effective/clamp
reporting including the announced-scale rx ceiling, no-shrink, and
armed-listener inheritance end to end); the native moto-io
`TcpSocketOptions` on connect/bind (landed 2026-08-11:
`Option<&TcpSocketOptions>` on `connect_reserved`/`bind_reserved`,
encoding the patch 3 wire bytes; systest test_native_buffer_options
covers pre-SYN sizes honored and power-of-two round-up on both paths);
then
the fixed default raise -- decided 2026-08-11: deferred to the step 1
in-regime perf sitting, after the close-path patch lands (FIN-WAIT-2
pins full rings for the linger, and a bigger default multiplies that);
until then 128 KiB stands and WAN workloads size per socket. Follow-ups riding on it: unify
ephemeral-port randomization (the loopback exemption can go once a
connect can pin its source port); receive autotuning stays deferred
until fixed-plus-per-socket is shown insufficient on a real workload.

## Step 3 -- RACK-TLP loss recovery (design approved 2026-08-11)

The design round landed 2026-08-11: RACK-TLP (RFC 8985) directly, full
fidelity -- adaptive reorder window with DSACK in the same series,
dupack fast retransmit retained as fallback. The nine-patch series,
scoreboard design, and the seeded loss harness live in
`sack-loss-recovery-design.md`.

THE SERIES LANDED IN FULL the same day (nine patches, 9c187fd1 ..
453850fe + the floor round): recovery-point episode with head-only
fast retransmit, bounded 64-run scoreboard, SACK/DSACK processing,
RACK detection with reorder timer and DSACK-adaptive reo_wnd, lost-
driven retransmission replacing go-back-N (RTO keeps SACKed islands,
reneging guard), tail-loss probes, three-block SACK + DSACK
generation, and the seeded loss harness whose reordering scenario
forced the RFC-correct split: on SACK flows RACK owns conviction,
episode, and charge; the dupack edge serves SACK-less peers. Every
patch passed a 3+3 full-test-networking gate; the netstack suite runs
in both controller configs (plain cargo test leaves the cubic tests
dormant -- run --features socket-tcp-cubic too, recorded in 9c187fd1).

RTO floor verdict (measured 2026-08-11, one-round policy): KEEP
200 ms. The harness matrix (floors 200/100/50 ms x delay 5/20/100 ms
x loss 1%/5% x 3 seeds) shows identical completion times under every
floor -- with RACK-TLP, actual RTOs essentially never fire; the probe
covers tails at 2 x srtt. Details in the design doc; the matrix
instrument stays in-tree (rto_floor_matrix, run with --ignored).

The deterministic packet harness injects loss at the netstack level
with a virtual clock, so all of this is testable without a lossy rig
(a host-level lossy path would need CAP_NET_ADMIN this environment
does not have).

## Step 4 -- SYN cookies (design AWAITING REVIEW)

Scheduled (decided 2026-08-10: Motor is expected to face untrusted
networks as a server). The design round is done: `syn-cookies-design.md`
(2026-08-11) -- engage at the half-open caps instead of refusing,
classic ISN cookie over the RFC 6528 SipHash primitive, wscale/SACK
through the TSval echo with a safe no-TS degradation, restoration into
the step 2 lazy backlog build, three patches. Four decisions are listed
at the doc's tail for review; per the 2026-08-11 run-scope ruling,
implementation waits for that review.

## Step 5 -- architectural netstack work (measure, then decide)

Measure-first (decided 2026-08-10). The profiling sitting shares step
1's manifest discipline and should run when step 1 unblocks: re-baseline
the benchmark set and profile a many-connection server workload, then
decide in review which O(N) structures to replace -- every segment does a
linear listener scan, every egress pass visits every socket (K packets
from one socket cost (K+1)xN visits), `poll_at` recomputes state across
all sockets, and the socket store walks its holes. Candidates, each
separable: hashed 4-tuple demux, an egress ready-list, a timer wheel, an
allocating interval-list assembler, real neighbor/route tables. First
recorded signal (2026-08-10): 64 parallel streams hold ~660 MiB/s
aggregate each way with a 5x per-stream fairness spread (tiers near
6 / 13 / 30 MiB/s) -- the egress/subchannel-packing signal to profile.

Scoped together with it: merging or formally projecting the two TCP
state enums (7-variant client-ABI vs 11-variant protocol enum; needs an
ABI compatibility story) and collapsing the double socket bookkeeping
(`SocketBase` carries a sys-io id and a smoltcp handle; two maps per
operation). Zero-copy token work stays deferred until a profile shows
the copies dominating. Once any of this lands, upstream smoltcp
cherry-picks become real work: budget for the divergence or explicitly
pin.

## Shelved: receive coalescing

Decided 2026-08-10: the ~164 MiB/s default-RX packet-rate ceiling is
accepted for now. The record it resumes from: Option A (ack
`GUEST_TSO4/6`, post 64K RX buffers) is the only universally portable
scheme -- QEMU/Cloud Hypervisor/Firecracker all offer the bits -- and
costs RX ring depth 128 -> 14 (Firecracker has no queue-size control, so
it binds), 262 KB -> 918 KB posted receive memory per device, 28-42 usec
refill budget per ring turnover, and must land as one atomic patch
(acking guest TSO while posting 2048-byte buffers is a spec violation).
Success criterion is already instrumented (`net.device.rx_size`
histogram's over-1514 bucket must carry most bulk traffic). Option B
(`MRG_RXBUF` + gather) is a per-VMM optimization only; Cloud Hypervisor
lacks the bit. Re-open triggers: a workload needing more than ~164 MiB/s
single-stream RX without jumbo frames, or RX-bound regressions the gate
cannot see. On re-open, re-record the step 1 benchmark reference first.

## Step 6 -- small owed items

New findings from the 2026-08-10 listener-exhaustion probe (the driver
is committed: `systest` subcommand `listener_flood` + the unregistered
`admission::test_aggregate_listener_exhaustion`; it can gate once these
are fixed):

- Releasing ~2k listeners at once leaves ~8k pages (~32 MB)
  unreclaimed -- static minutes later, not converging. Suspect: sys-io
  listener/channel teardown accounting.
- On a dirty pool, bind-until-refused crawls for minutes through the
  vdso channel-provisioning retry budgets (~10 s per attempt) instead of
  failing promptly; on a fresh boot the same loop finishes in seconds.
  A bind at exhaustion should fail within a bounded budget.
  Analysis 2026-08-11: the client backoff (moto-io channel.rs
  ConnectBackoff) retries only NotFound from connecting the io_channel
  -- the policy exists for sys-io's per-accept listener re-arm window.
  At exhaustion the re-arm itself apparently fails, so NotFound
  persists and every attempt burns the full 10 s budget; the client
  CANNOT distinguish the race from exhaustion. Fix direction: sys-io
  keeps its io_channel listener armed and refuses at capacity with an
  explicit error (accept, reply, close) so clients fail fast; that is
  server-side io_channel work, and it likely shares a root with the
  page-leak item above (leaked pages exhausting the shared pool is
  what makes the pool "dirty"). Investigate the two together with the
  listener_flood driver.

Standing small items, fix-or-decline:

- Close-path Linux divergences (scheduled 2026-08-11, design approved
  same day in `tcp-close-path-design.md`): release the dead rings to
  the 16 KiB floor when an orphaned socket enters FIN-WAIT-2/TIME-WAIT,
  and answer data arriving after our FIN with RST (trigger: close and
  shutdown(RD), Linux RCV_SHUTDOWN parity). Two patches. Land before or
  with the step 2 default raise.
- Write-after-reset reports `NotConnected`, not `ConnectionReset`
  (found 2026-08-11 by the close-path systest): moto-rt has no
  connection-reset error code, so every dead stream's write fails the
  same way. Faithful ECONNRESET needs a new moto-rt code, the std
  mapping, and reset-cause in `EvtTcpStreamStateChanged` args_32[1]
  (free and zeroed today, so wire-compatible). RT-surface decision --
  awaiting a call; the design doc's implementation note has the
  details.
- The unmatched-SYN RST on a truly closed port is an unrate-limited 1:1
  reflector (listening ports are bounded; this is the no-listener path).
- Config parsing aborts at boot on more than the supported CIDR/route
  counts instead of rejecting gracefully (boot-time only, not
  packet-reachable).
- The 127/8 external-ingress drop is IPv4-only; revisit the day an
  external device gets an IPv6 address.
- Wire `sysbox syslog` (`do_syslog` exists unwired): nothing on the
  image reads the kernel log remotely, which is where every headless
  daemon's output goes -- it cost an hour in the russhd exec diagnosis,
  and it is also why vdso panic text can look silent (the console buffer
  does not always drain before teardown; that drain is worth its own
  look).
- Perf micro-items, measure before fixing: TSO super-segments truncate
  at the TX ring wrap (likely halves effective TSO size); the checksum
  loop is u16-at-a-time; `DeviceCapabilities` is cloned per transmitted
  packet; per-packet `net_trace!` logging has no `enabled()` filter in
  sys-io's logger.
- Test debt: `REASSEMBLY_BUFFER_COUNT` and `FRAGMENTATION_BUFFER_SIZE`
  are tested at values that differ from deployment; the RDRAND retry
  path and the external-device checksum arm are untestable without
  seams; the crafted-packet regression backlog (RST in every state,
  window shrink, zero-window probes, assembler-overflow storms) is
  partially enumerated, not closed; the `58622c82` listener-abort fix
  has no in-suite regression (gap accepted 2026-08-11: forcing the
  window needs a sys-io fault-injection seam, and the fixed path
  refuses unreadable pids by construction -- revisit only if sys-io
  ever grows test seams for the other items above).

## Watch list -- recorded, unattributed, act on recurrence

- dns-resolver negative lookup returned `NotReady` instead of `NotFound`
  once (2026-08-09); recurrence means the in-flight-upstream-query race
  is real.
- `moto_async::test_event_stream` assumes strictly alternating wakes;
  one legal spurious wake broke it once in ~40 runs. Fix is a tolerant
  resync loop if it recurs.
- `udp_rebind_after_close_test` failed roughly half of full-suite runs
  on 2026-07-28; not once in the 50+ gate runs since. Fixed-in-passing,
  unconfirmed.
- `test_stdio_pipe_async_fd` hung once on 2026-08-07 and again on
  2026-08-11 (release gate run, `20260811-stdio-pipe-async-fd-hang-release.log`
  in `~/motor-dev/gate-anomalies/`; the suite watchdog killed the VM
  before an mdbg capture was possible). Two occurrences make it real
  and it is not networking: both runs' tcp suites had passed. Next
  occasion needs a watchdog that captures mdbg print-stacks of systest
  before killing qemu; until then it stays a known non-networking
  flake that can cost a gate run.
- Debug-VM ssh OUTPUT freeze after the moto_async suite while the VM
  stays busy -- an output-path (sshd/stdio) freeze, not a systest hang.
  First seen 2026-08-10; recurred TWICE 2026-08-11 (close-path and
  RACK-7 gate runs; both logs in `~/motor-dev/gate-anomalies/`, both
  killed at the 600 s timeout before a live capture was possible,
  sys-io still processing virtio traffic at death). Three occurrences,
  roughly 1 in 20 gate runs; predates the close-path work. A bounded
  hunt the same day (4 boot+ssh-systest iterations with a
  capture-on-freeze watchdog: fresh ssh session, sysbox ps, mdbg
  print-stacks before killing qemu -- `freeze-hunt-iter.sh`, session
  scratchpad, artifacts in `/tmp/motor-stress/freeze-hunt/`) ran 4/4
  clean: it has not reproduced outside the full-test harness. Next
  occasion: run the hunt script INSIDE a full-test-shaped loop, or
  fold its watchdog into full-test itself.
- rmux's host-side pty test threw one EPERM in ~26 runs (non-networking,
  unowned; TUI-deferrable per the 2026-08-10 flake policy).
- full-test's external ping/DNS check failed one gate run on the host
  NAT path (transient; host side verified healthy). It is the suite's
  only external dependency; if it flakes again, consider gating it on a
  host-side preflight instead of failing the run.

## Method (carried forward)

- Patches stay near 100-300 lines including tests. Gate per commit:
  `cargo +nightly fmt`, zero new warnings, and three debug plus three
  release runs of `src/tests/full-test.sh` (or
  `full-test-networking.sh`, identical minus the host rmux/tmux tests).
  No retries, pass percentages, or timeout raises that can conceal a
  defect; stop for guidance on decision gates and newly found
  preexisting defects. Nothing edits the tree while a gate runs -- two
  gates were lost to that on 2026-08-10.
- Performance changes take paired same-host measurements in ONE
  sitting; never gate on a figure recorded on another day. RR is the
  host-steal gauge: distrust any run whose RR is out of band. The host
  is bimodal on all axes at once (default RX ~164 / RR ~58 / bulk TX
  ~1356 vs default RX ~450-570 / RR ~112-126 / bulk TX ~735); an
  out-of-band reading stops the sitting. A/B/A/B confounds tree with
  block position -- drop the first block or counterbalance, record
  per-block medians. Reference builds of old commits need their era's
  toolchain/sysroot (moto-rt version skew makes mixed images unbootable).
- Benchmark manifest, required before the step 1/5 measurements: commit
  and dirty-tree exclusions; build profile; VMM binary, version, and
  full command line; host kernel, CPU model, governor, turbo state,
  affinity; tap addresses, qdisc and offload state; client/server
  command lines and binary identities.
- Hangs: `/sys/mdbg print-stacks <pid>` plus addr2line on unstripped
  binaries first, before any speculation.
