# Networking: remaining steps

2026-08-15. Pruned after the SYN-cookie series closed out the last
scheduled protocol work. Everything that landed -- the vDSO ownership
rewrite, per-socket buffer sizing, RACK-TLP loss recovery, the close
path, SYN cookies -- has its full records (designs, diagnoses, patch
lists, gate transcripts, measurements) in this file's git history
(`git log --follow -- docs/plans/networking-remaining-steps.md`) and in
the history of the four design docs deleted with this revision
(`socket-buffer-sizing-design.md`, `sack-loss-recovery-design.md`,
`tcp-close-path-design.md`, `syn-cookies-design.md`). This document
carries only what is still actionable. Steps are renumbered fresh.

Where the tree stands: sys-io owns the Motor OS networking stack
(`moto-netstack`, `src/sys/sys-io/netstack`; grown out of smoltcp, no
longer a fork tracking upstream). TCP has working congestion control
(Cubic + IW10, RFC 8312 ssthresh, 200 ms RTO floor), RACK-TLP loss
recovery with SACK/DSACK and an adaptive reorder window, RFC 7323
timestamps with PAWS, per-socket buffer sizing (`SO_RCVBUF`/`SO_SNDBUF`
up to 8 MiB, lazy 16 KiB backlog floor rings), Linux-parity close-path
behavior, SYN cookies at the half-open caps, and the safety hardening
set (exhaustive connect-state handling, half-open caps, demand-grown
listener backlog, ARP admission, RFC 5961, RFC 6528 ISNs, randomized
ephemeral ports), all under deterministic packet-level tests. `rt.vdso`
owns the net channel pool, blocking policy, and POSIX state.

## Decision queue -- awaiting a call

1. **Fixed buffer default raise.** 128 KiB per direction stands; a
   128 KiB window caps a 100 ms path at ~10 Mbit/s, and WAN workloads
   size per socket meanwhile. The close-path prerequisite (orphaned
   FIN-WAIT-2/TIME-WAIT rings release to the 16 KiB floor) has landed,
   so the raise is purely a call -- informed by the user's regular
   benchmarking (performance is user-owned, ruled 2026-08-15).
   Answered 2026-08-15: keep 128 KiB for now; remains open as a
   future call.
2. **russh fork end-state.** The diagnostic stamps in `../russh` may
   stay through development, but the fork must end holding only the
   upstream-PR candidate commit (`~/motor-dev/tokio-motor-diag` is a
   disposable scratch copy). Decided 2026-08-11, reaffirmed
   2026-08-15: leave as is; revisit when the remaining steps are done.

## Performance (user-owned, not a step)

Ruled 2026-08-15: the user runs the benchmark set regularly and owns
the verdicts; the standing expectation is that performance only goes
up. Nobody measures proactively -- only when a specific change gives
reason to suspect a regression, under the Method discipline below. The
reference record for such a measurement: `ab81c861` (RR 58.8/57.4
usec, default RX/TX 163.6/328.3 MiB/s, bulk RX/TX 678.9/1356.4 MiB/s,
run-qemu.sh); the investigation records (2026-08-10..12 sittings,
including the launcher-fingerprint finding and the chv platform gap)
are in this file's git history.

## Step 1 -- architectural netstack work (measure, then decide)

Measure-first (decided 2026-08-10). When picked up: re-baseline the
benchmark set (Method manifest discipline), profile a many-connection
server workload, then decide in review which O(N) structures to
replace -- every segment does a linear listener scan, every egress
pass visits every socket (K packets from one socket cost (K+1)xN
visits), `poll_at` recomputes state across all sockets, and the socket
store walks its holes. Candidates, each separable: hashed 4-tuple
demux, an egress ready-list, a timer wheel, an allocating
interval-list assembler, real neighbor/route tables. First recorded
signal (2026-08-10): 64 parallel streams hold ~660 MiB/s aggregate
each way with a 5x per-stream fairness spread (tiers near 6 / 13 /
30 MiB/s) -- the egress/subchannel-packing signal to profile.

Scoped together with it: merging or formally projecting the two TCP
state enums (7-variant client-ABI vs 11-variant protocol enum; needs
an ABI compatibility story) and collapsing the double socket
bookkeeping (`SocketBase` carries a sys-io id and a netstack handle;
two maps per operation). Zero-copy token work stays deferred until a
profile shows the copies dominating.

## Step 2 -- small owed items

From the 2026-08-10 listener-exhaustion probe (driver committed:
`systest` subcommand `listener_flood` + the unregistered
`admission::test_aggregate_listener_exhaustion`; it can gate once
these are fixed) -- investigate the two together:

- Releasing ~2k listeners at once leaves ~8k pages (~32 MB)
  unreclaimed -- static minutes later, not converging. Suspect: sys-io
  listener/channel teardown accounting.
- On a dirty pool, bind-until-refused crawls for minutes through the
  vdso channel-provisioning retry budgets (~10 s per attempt) instead
  of failing promptly. Analysis 2026-08-11: the client backoff
  (moto-io channel.rs ConnectBackoff) retries only NotFound, the
  policy for sys-io's per-accept listener re-arm window; at exhaustion
  the re-arm itself fails, NotFound persists, and the client cannot
  distinguish the race from exhaustion. Fix direction: sys-io keeps
  its io_channel listener armed and refuses at capacity with an
  explicit error so clients fail fast -- likely the same root as the
  page leak (leaked pages are what make the pool "dirty").

Approved work items (2026-08-15 answers to the open-questions round;
the Q&A is in this file's git history):

- **Write-after-reset ECONNRESET** (approved): a new moto-rt
  `E_CONNECTION_RESET` code, the std mapping, and reset-cause carried
  in `EvtTcpStreamStateChanged` args_32[1] (free and zeroed today, so
  wire-compatible). The close-path systest asserts promptness and
  tolerates either error kind until this lands.
- **Egress rate limits** (approved, scope set by the user): token
  buckets for BOTH the no-listener RST reflector and the SYN-cookie
  SYN|ACK responses -- two separate rates, both configurable via
  `sys-net.toml`, reasonable Linux-like defaults -- with counters for
  suppressed responses.
- **Dynamic route/address tables** (ruled 2026-08-15): boot must not
  abort or truncate on config size -- if `sys-net.toml` wants 100
  routes, grow the tables. The netstack has alloc; replace the fixed
  `IFACE_MAX_ADDR_COUNT`/`IFACE_MAX_ROUTE_COUNT` storage with growable
  tables (and retire sys-io's const-asserts on those caps).

Standing items, fix-or-decline:

- The 127/8 external-ingress drop is IPv4-only; revisit the day an
  external device gets an IPv6 address.
- Perf micro-items, measure before fixing: TSO super-segments truncate
  at the TX ring wrap (likely halves effective TSO size); the checksum
  loop is u16-at-a-time; `DeviceCapabilities` is cloned per
  transmitted packet; per-packet `net_trace!` logging has no
  `enabled()` filter in sys-io's logger.
- Platform: cloud-hypervisor host->VM delivery caps at ~240-340k pkt/s
  where qemu sustains ~720k with the same MTU-sized frames, capping
  chv client->server at ~250-325 MiB/s vs qemu ~950 (measured
  2026-08-12; the netstack sustains the qemu rate, so this is the chv
  net backend interaction, not a netstack limit). Same sitting:
  neither hypervisor negotiates GSO into the guest, so RX is
  per-MTU-frame everywhere; guest-offload support would lift both.
- Test debt: the SYN-cookie engage/restore glue in sys-io has no in-VM
  test -- engaging the half-open cap needs withheld-ACK packet
  injection, which neither the VM nor the unprivileged host tap can
  produce (the half-open stall test records the same constraint). The
  protocol machine is covered by netstack packet tests; the glue would
  become testable with a packet-injection seam or a boot-time low-cap
  test config (the low-cap experiment was declined 2026-08-15 --
  revisit only if something concretely needs it).
- Test debt: `REASSEMBLY_BUFFER_COUNT` and `FRAGMENTATION_BUFFER_SIZE`
  are tested at values that differ from deployment; the RDRAND retry
  path and the external-device checksum arm are untestable without
  seams; the crafted-packet regression backlog (RST in every state,
  window shrink, zero-window probes, assembler-overflow storms) is
  partially enumerated, not closed; the `58622c82` listener-abort fix
  has no in-suite regression (gap accepted 2026-08-11 -- revisit only
  if sys-io grows fault-injection seams).

Follow-ups riding on landed work: unify ephemeral-port randomization
(the loopback exemption can go once a connect can pin its source
port); receive autotuning stays deferred until fixed-plus-per-socket
sizing is shown insufficient on a real workload.

## Shelved: receive coalescing

Decided 2026-08-10: the ~164 MiB/s default-RX packet-rate ceiling is
accepted for now. The record it resumes from: Option A (ack
`GUEST_TSO4/6`, post 64K RX buffers) is the only universally portable
scheme -- QEMU/Cloud Hypervisor/Firecracker all offer the bits -- and
costs RX ring depth 128 -> 14 (Firecracker has no queue-size control,
so it binds), 262 KB -> 918 KB posted receive memory per device,
28-42 usec refill budget per ring turnover, and must land as one
atomic patch (acking guest TSO while posting 2048-byte buffers is a
spec violation). Success criterion is already instrumented
(`net.device.rx_size` histogram's over-1514 bucket must carry most
bulk traffic). Option B (`MRG_RXBUF` + gather) is a per-VMM
optimization only; Cloud Hypervisor lacks the bit. Re-open triggers: a
workload needing more than ~164 MiB/s single-stream RX without jumbo
frames, or RX-bound regressions the gate cannot see. On re-open,
re-record the performance reference first.

## Watch list -- recorded, unattributed, act on recurrence

- dns-resolver negative lookup returned `NotReady` instead of
  `NotFound`: recurred 2026-08-15 (second occurrence) and was
  DIAGNOSED -- not an in-process race. The resolver bridges to the SDK
  libc's `getaddrinfo`; `EAI_AGAIN` maps to TemporaryFailure ->
  `NotReady`, so an upstream query to 8.8.8.8 that loses a packet over
  the host NAT reports the honest transient while full-test demands a
  terminal `NotFound` from one shot. Fix options, both needing a call
  (the AGENTS bounded-retry rule): retry `NotReady` to a short
  deadline in the harness check -- `NotReady` is documented as "ask
  again", and the resolver's own self-test polls exactly this way --
  or gate the external DNS/ping checks on a host-side preflight.
- `moto_async::test_event_stream` assumes strictly alternating wakes;
  one legal spurious wake broke it once in ~40 runs. Fix is a tolerant
  resync loop if it recurs.
- `udp_rebind_after_close_test` failed roughly half of full-suite runs
  on 2026-07-28; not once in the 50+ gate runs since.
  Fixed-in-passing, unconfirmed.
- `test_stdio_pipe_async_fd` hung once on 2026-08-07 and again on
  2026-08-11 (log in `~/motor-dev/gate-anomalies/`; the suite watchdog
  killed the VM before an mdbg capture was possible). Real but not
  networking: both runs' tcp suites had passed. A capture watchdog in
  full-test would make the next occurrence diagnosable; ruled
  2026-08-15: build it only if flake rates become an issue (~20% of
  runs), not to chase one-offs.
- Debug-VM ssh OUTPUT freeze after the moto_async suite while the VM
  stays busy -- an output-path (sshd/stdio) freeze, not a systest
  hang. Three occurrences by 2026-08-11 (~1 in 20 gate runs; logs in
  `~/motor-dev/gate-anomalies/`). A bounded 4-iteration hunt with a
  capture-on-freeze watchdog (`freeze-hunt-iter.sh`, artifacts in
  `/tmp/motor-stress/freeze-hunt/`) ran clean: it has not reproduced
  outside the full-test harness. Same 2026-08-15 ruling as above:
  harness capture work only if the flake rate becomes an issue.
- `test-terminal-size.sh` hung once at its 600 s timeout in a debug
  gate run (2026-08-15); the same suite passed the other five runs of
  that gate. A rare flake on the serial-console resize section.
- rmux's host-side pty test threw one EPERM in ~26 runs
  (non-networking, unowned; TUI-deferrable per the 2026-08-10 flake
  policy).
- full-test's external ping/DNS check failed one gate run on the host
  NAT path (transient; host side verified healthy). It is the suite's
  only external dependency; if it flakes again, consider gating it on
  a host-side preflight instead of failing the run.

## Method (carried forward)

- Patches stay near 100-300 lines including tests. Gate per commit:
  `cargo +nightly fmt`, zero new warnings, and three debug plus three
  release runs of `src/tests/full-test.sh` (or
  `full-test-networking.sh`, identical minus the host rmux/tmux
  tests). No retries, pass percentages, or timeout raises that can
  conceal a defect; stop for guidance on decision gates and newly
  found preexisting defects. Nothing edits the tree while a gate runs
  -- two gates were lost to that on 2026-08-10.
- Routine benchmarking is user-owned (2026-08-15); measure only when a
  change gives reason to suspect a regression. A measurement, when
  warranted, takes paired same-host readings in ONE sitting; never
  gate on a figure recorded on another day. Pin the launcher:
  run-qemu.sh vs run-chv.sh differ ~3x on client->server RX with
  IDENTICAL RR and TX (2026-08-12), so the RR gauge cannot detect a
  hypervisor swap -- record which script booted the VM next to every
  number. RR remains the host-steal gauge: distrust any run whose RR
  is out of band. The host is bimodal on all axes at once (default RX
  ~164 / RR ~58 / bulk TX ~1356 vs default RX ~450-570 / RR ~112-126 /
  bulk TX ~735); an out-of-band reading stops the sitting. A/B/A/B
  confounds tree with block position -- drop the first block or
  counterbalance, record per-block medians. Reference builds of old
  commits need their era's toolchain/sysroot (moto-rt version skew
  makes mixed images unbootable).
- Benchmark manifest, required before step 1 measurements: commit and
  dirty-tree exclusions; build profile; VMM binary, version, and full
  command line; host kernel, CPU model, governor, turbo state,
  affinity; tap addresses, qdisc and offload state; client/server
  command lines and binary identities.
- Hangs: `/sys/mdbg print-stacks <pid>` plus addr2line on unstripped
  binaries first, before any speculation.

