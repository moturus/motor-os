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
after listen()); moto-io
options + `SO_RCVBUF`/`SO_SNDBUF` + effective-size getters; then
optionally the fixed default raise, now safe because listening sockets
no longer pre-commit full buffers. Follow-ups riding on it: unify
ephemeral-port randomization (the loopback exemption can go once a
connect can pin its source port); receive autotuning stays deferred
until fixed-plus-per-socket is shown insufficient on a real workload.

## Step 3 -- SACK-based loss recovery (the step 7 big ticket)

The small fixes are landed; what remains is the series that needs a
design round of its own:

- SACK-based retransmission (received SACK is parsed and discarded
  today; our own generation fills one block of three). The
  NewReno-style recovery-point epoch (suppressing repeat congestion
  charges across partial-ACK dupack runs) belongs here -- the recovery
  point has to exist for SACK anyway.
- Replace go-back-N (the whole unacked window resends on RTO or fast
  retransmit) as part of the same work.
- The 200 ms RTO floor is argued from Linux's default, not measured;
  justify or tune it with the loss harness.

The deterministic packet harness injects loss at the netstack level, so
all of this is testable without a lossy rig (a host-level lossy path
would need CAP_NET_ADMIN this environment does not have).

## Step 4 -- SYN cookies

Scheduled (decided 2026-08-10: Motor is expected to face untrusted
networks as a server), queued behind step 3 since the half-open cap
already bounds flood damage. All prerequisites are landed on purpose:
TSopt carries wscale/SACK through cookie mode, the RFC 6528 SipHash ISN
is the cookie primitive, the half-open cap is the engagement trigger,
and the window accounting was normalized knowing cookies add a second
writer.

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

Standing small items, fix-or-decline:

- Close-path Linux divergences (scheduled 2026-08-11): release the dead
  rings when an orphaned socket enters FIN-WAIT-2 -- TX is fully acked
  and RX has no reader ever again, yet 128 KiB stays pinned for the
  60 s linger, and step 2's per-socket sizing raises the worst case to
  8 MiB -- and answer data arriving after our FIN with RST instead of a
  shut window (Linux resets an orphaned socket on new data; a writing
  peer should get ECONNRESET promptly, not a 60 s zero-window hang).
  The two interact: the RST path also releases FIN-WAIT-2 early when
  the peer keeps sending. Land before or with the step 2 default raise.
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
- `test_stdio_pipe_async_fd` hung once (2026-08-07, log in
  `~/motor-dev/gate-anomalies/`); mdbg-first procedure on recurrence.
- One debug-VM systest run's ssh OUTPUT froze (2026-08-10) after the
  moto_async suite while the VM stayed busy -- an output-path
  (sshd/stdio) freeze, not a systest hang. Not reproduced in 19+
  full-test runs since. On recurrence: sysbox ps + mdbg print-stacks of
  sshd and systest while frozen (`repro-freeze.sh` in the 2026-08-10
  session scratchpad automates the capture).
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
