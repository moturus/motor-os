# Networking: remaining steps

What remains to do on Motor OS networking, roughly in pickup order.
Records of finished work -- designs, diagnoses, patch lists, gate
transcripts, measurements -- live in git history, not here: see
`git log --follow -- docs/plans/networking-remaining-steps.md` and the
histories of the retired design docs (`socket-buffer-sizing-design.md`,
`sack-loss-recovery-design.md`, `tcp-close-path-design.md`,
`syn-cookies-design.md`, `netstack-scalability-design.md`).

Orientation: sys-io owns the Motor OS networking stack
(`moto-netstack`, `src/sys/sys-io/netstack`; grown out of smoltcp, no
longer a fork). TCP has Cubic + IW10 congestion control, RACK-TLP loss
recovery with SACK/DSACK, RFC 7323 timestamps with PAWS, per-socket
buffer sizing up to 8 MiB, Linux-parity close-path behavior, SYN
cookies at the half-open caps, token-bucket egress limits on the
socketless replies (no-listener resets and cookie SYN|ACKs;
`max_rst_rate`/`max_syn_cookie_rate` in `sys-net.toml`, loopback
exempt), per-interface address/route tables that grow to the
configuration (SLAAC's network-driven inflow stays bounded on its own
side), and the safety-hardening set, all under deterministic
packet-level tests. Since 2026-08-16: the netstack is unconditionally
std; a socket has one identity, the u64 sys-io allocates, on the
wire, in the stores, and in every log line; and ingress demux is
authoritative maps end to end -- exact 4-tuple, then listener
endpoint (specific address over wildcard), then the socketless
paths, with UDP by port -- the per-packet linear scans are deleted,
identity-changing socket operations exist only on the SocketSet, and
debug builds re-verify index completeness against every segment (the
retired scans live on as debug-only oracles). `rt.vdso` owns the net
channel pool, blocking policy, and POSIX state.

## Next up (approved)

Empty. The architectural scalability series landed in full 2026-08-16
(five gated commits; the design doc is retired, its record in git
history); the user's benchmark verdict on it is the outcome measure,
the fairness spread the number to watch. What remains architectural
is parked below under "measure, then decide".

## Waiting

On the toolchain (not on a decision):

- **ECONNRESET flip.** The plumbing is landed end to end (moto-rt
  `E_CONNECTION_RESET = 22`, the netstack reset cause, the cause bit
  in `EvtTcpStreamStateChanged`, moto-io's sticky
  `TcpStream::peer_reset()`), but the std-visible write error must
  stay `E_NOT_CONNECTED` until the toolchain's vendored moto-rt knows
  code 22 -- an unknown code launders to `Unknown` (raw 2) through its
  `Error::from(u16)`. After the toolchain refresh, flip: the
  dead-write error selection in moto-io `try_write` and vdso
  `blocking.rs` (see the comment at `TcpStream::peer_reset`), the std
  ErrorKind mapping, and the close-path systest assertion (marked
  "Tighten this to raw code 22").

On a user call:

- **External DNS/ping transient in full-test.** The external checks
  are the suite's only external dependency, and they fail when an
  upstream query to 8.8.8.8 loses a packet over the host NAT: the SDK
  libc's `getaddrinfo` maps `EAI_AGAIN` to `NotReady`, while the
  checks demand a terminal answer from one shot (worst observed: 3
  failures in ~25 gate runs in one day). Two remedies, either needs
  approval under the bounded-retry rule: retry `NotReady` to a short
  deadline in the affected checks (`NotReady` is documented as "ask
  again", and the resolver's own `resolve_external` polls exactly this
  way), or gate the external checks on a host-side preflight.
  Second mechanism, diagnosed 2026-08-16 (one release gate run; log
  in `~/motor-dev/gate-anomalies/`): the guest's IPv6 address
  (`2001:db8::2`, the documentation prefix) is tap-local by
  construction -- no NAT66, no global route -- so whenever a
  `ping_external google.com` resolve returns the AAAA answer first,
  the echo times out deterministically; the other runs resolved to
  IPv4 and passed. Not flaky networking: a dead end selected by DNS
  answer order, present since `644db546`; two hits on 2026-08-16
  alone (2 of that day's 12 gate runs, both archived) -- no longer
  rare. Remedies, same decision slot: pin the external ping legs to
  IPv4; teach dns-resolver RFC 6724-style destination ordering (rank
  global v6 below v4 when the only v6 source is non-global -- the
  principled fix); or host NAT66 for the tap.
- **Registering `test_aggregate_listener_exhaustion`.** The
  flood/recover cycle converges to ~4-6k pages of accepted drift
  (kernel slabs, sub-threshold allocator slack) against the admission
  module's 256-page `DRIFT_TOLERANCE_PAGES`; the test needs its own
  justified tolerance, plus the fast-bind and refusal-kind assertions,
  before it can gate. Manual probe meanwhile:
  `systest listener-exhaustion-probe [cap]`.

Standing calls, revisit later:

- **Fixed buffer default.** 128 KiB per direction stands (a 128 KiB
  window caps a 100 ms path at ~10 Mbit/s; WAN workloads size per
  socket via `SO_RCVBUF`/`SO_SNDBUF`). The close-path prerequisite has
  landed, so raising it is purely a call, informed by the user's
  regular benchmarking.
- **russh fork end-state.** The diagnostic stamps in `../russh` stay
  through development; the fork must end holding only the upstream-PR
  candidate commit. Revisit when the steps above are done.

## Architectural netstack work (measure, then decide)

The netstack scalability series landed in full 2026-08-16 (design
doc retired, record in its git history): the egress fairness cursor, the poll index (egress visits
only ready/due sockets, `poll_at` answers in O(log N), the retired
scans living on as debug oracles), the keyed neighbor cache and
ordered route table, and the ring-sized assembler. Parked candidates,
measure before picking up: merging or formally projecting the two TCP
state enums (7-variant client ABI vs 11-variant protocol enum; needs
an ABI compatibility story -- a user decision); zero-copy token work
(deferred until a profile shows the copies dominating); and one
recorded fallback -- sys-io's per-page store access is a BTreeMap
walk (depth <= 4 at realistic socket counts); if the user's
benchmarking ever shows that line, the swap is a packed
generation+slot slab behind the same SocketSet API. The old profiling
signal for reference: 64 parallel streams held ~660 MiB/s aggregate
each way with a 5x per-stream fairness spread (tiers near
6 / 13 / 30 MiB/s).

## Smaller items, fix or decline

- The 127/8 external-ingress drop is IPv4-only; revisit the day an
  external device gets an IPv6 address.
- Perf micro-items, measure before fixing: TSO super-segments truncate
  at the TX ring wrap (likely halves effective TSO size); the checksum
  loop is u16-at-a-time; `DeviceCapabilities` is cloned per
  transmitted packet; per-packet `net_trace!` logging has no
  `enabled()` filter in sys-io's logger.
- Platform: cloud-hypervisor host->VM delivery caps at ~240-340k pkt/s
  where qemu sustains ~720k with the same MTU-sized frames, capping
  chv client->server at ~250-325 MiB/s vs qemu ~950. The netstack
  sustains the qemu rate, so this is the chv net-backend interaction,
  not a netstack limit. Neither hypervisor negotiates GSO into the
  guest, so RX is per-MTU-frame everywhere; guest-offload support
  would lift both.
- Test debt: the SYN-cookie engage/restore glue in sys-io has no in-VM
  test -- engaging the half-open cap needs withheld-ACK packet
  injection, which neither the VM nor the unprivileged host tap can
  produce (the half-open stall test records the same constraint). The
  protocol machine is covered by netstack packet tests; the glue
  becomes testable with a packet-injection seam or a boot-time low-cap
  config (declined for now -- revisit only if something concretely
  needs it).
- Test debt: `REASSEMBLY_BUFFER_COUNT` and `FRAGMENTATION_BUFFER_SIZE`
  are tested at values that differ from deployment; the RDRAND retry
  path and the external-device checksum arm are untestable without
  seams; the `58622c82` listener-abort fix has no in-suite regression
  (gap accepted -- revisit only if sys-io grows fault-injection
  seams).
- Follow-ups riding on landed work: unify ephemeral-port randomization
  (the loopback exemption can go once a connect can pin its source
  port); receive autotuning stays deferred until fixed-plus-per-socket
  sizing is shown insufficient on a real workload.

## Shelved: receive coalescing

The ~164 MiB/s default-RX packet-rate ceiling is accepted for now.
The record to resume from: Option A (ack `GUEST_TSO4/6`, post 64K RX
buffers) is the only universally portable scheme -- QEMU, Cloud
Hypervisor, and Firecracker all offer the bits -- and costs RX ring
depth 128 -> 14 (Firecracker has no queue-size control, so it binds),
262 KB -> 918 KB posted receive memory per device, 28-42 usec refill
budget per ring turnover, and must land as one atomic patch (acking
guest TSO while posting 2048-byte buffers is a spec violation).
Success criterion is already instrumented: the `net.device.rx_size`
histogram's over-1514 bucket must carry most bulk traffic. Option B
(`MRG_RXBUF` + gather) is a per-VMM optimization only; Cloud
Hypervisor lacks the bit. Re-open triggers: a workload needing more
than ~164 MiB/s single-stream RX without jumbo frames, or RX-bound
regressions the gate cannot see. On re-open, re-record the performance
reference first.

## Watch list -- act on recurrence

- `moto_async::test_event_stream` assumes strictly alternating wakes;
  one legal spurious wake broke it once in ~40 runs. Fix on
  recurrence: a tolerant resync loop.
- `udp_rebind_after_close_test` failed about half of full-suite runs
  on 2026-07-28, then not once in 50+ gate runs since.
  Fixed-in-passing, unconfirmed; reopen if it returns.
- `test_stdio_pipe_async_fd` hung twice (2026-08-07, 2026-08-11; logs
  in `~/motor-dev/gate-anomalies/`). Real but not networking -- both
  runs' tcp suites had passed. A capture watchdog in full-test would
  make the next occurrence diagnosable; build it only if flake rates
  become an issue (~20% of runs), not to chase one-offs.
- Debug-VM ssh OUTPUT freeze after the moto_async suite while the VM
  stays busy -- an output-path (sshd/stdio) freeze, not a systest
  hang; three occurrences in 40+ debug gate runs, latest 2026-08-16
  (logs in `~/motor-dev/gate-anomalies/`). A bounded
  capture-on-freeze hunt ran clean; it has not reproduced outside the
  full-test harness. Same rule as above: harness capture work only if
  the flake rate becomes an issue.
- `test-terminal-size.sh` flaked twice in debug gate runs, differently
  each time: once hanging at its 600 s timeout, once (2026-08-15,
  logs in `~/motor-dev/gate-anomalies/`) reporting console prompt
  widths `100 60 60` with the first `80` missing. Both point at the
  serial-console resize section; each gate's other runs passed.
- rmux's host-side pty test threw one EPERM in ~26 runs
  (non-networking, unowned; TUI-deferrable).

## Method (carried forward)

- Patches stay near 100-300 lines including tests. Gate per commit:
  `cargo +nightly fmt`, zero new warnings, and three debug plus three
  release runs of `src/tests/full-test.sh` (or
  `full-test-networking.sh`, identical minus the host rmux/tmux
  tests). No retries, pass percentages, or timeout raises that can
  conceal a defect; stop for guidance on decision gates and newly
  found preexisting defects. Nothing edits the tree while a gate
  runs.
- Performance is user-owned: the user benchmarks regularly and owns
  the verdicts; the standing expectation is that performance only
  goes up. Measure only when a change gives reason to suspect a
  regression. A measurement, when warranted, takes paired same-host
  readings in ONE sitting; never gate on a figure recorded on another
  day. Pin the launcher: run-qemu.sh vs run-chv.sh differ ~3x on
  client->server RX with IDENTICAL RR and TX, so the RR gauge cannot
  detect a hypervisor swap -- record which script booted the VM next
  to every number. RR remains the host-steal gauge: distrust any run
  whose RR is out of band. The host is bimodal on all axes at once
  (default RX ~164 / RR ~58 / bulk TX ~1356 vs default RX ~450-570 /
  RR ~112-126 / bulk TX ~735); an out-of-band reading stops the
  sitting. A/B/A/B confounds tree with block position -- drop the
  first block or counterbalance, record per-block medians. Reference
  builds of old commits need their era's toolchain/sysroot (moto-rt
  version skew makes mixed images unbootable). Reference record for
  comparisons: `ab81c861` (RR 58.8/57.4 usec, default RX/TX
  163.6/328.3 MiB/s, bulk RX/TX 678.9/1356.4 MiB/s, run-qemu.sh).
- Benchmark manifest, required before architectural-work
  measurements: commit and dirty-tree exclusions; build profile; VMM
  binary, version, and full command line; host kernel, CPU model,
  governor, turbo state, affinity; tap addresses, qdisc and offload
  state; client/server command lines and binary identities.
- Hangs: `/sys/mdbg print-stacks <pid>` plus addr2line on unstripped
  binaries first, before any speculation.
