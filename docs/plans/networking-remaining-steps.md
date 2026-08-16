# Networking: remaining steps

What remains to do on Motor OS networking, roughly in pickup order.
Records of finished work -- designs, diagnoses, patch lists, gate
transcripts, measurements -- live in git history, not here: see
`git log --follow -- docs/plans/networking-remaining-steps.md` and the
histories of the retired design docs (`socket-buffer-sizing-design.md`,
`sack-loss-recovery-design.md`, `tcp-close-path-design.md`,
`syn-cookies-design.md`).

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
packet-level tests. `rt.vdso` owns the net channel pool, blocking
policy, and POSIX state.

## Next up (approved)

Two structural refactorings, promoted 2026-08-15 ahead of everything
else, then the crafted-packet tests. One gated commit at a time
(Method applies unchanged); the series takes the nights it takes.
The identity step goes first for a hard reason: the demux step keeps
socket identities in maps, and an identity that names a *reusable*
slot index can silently alias a recycled socket, while one that names
a never-reused id can only go stale. So ids become stable before
anything stores them in a map.

### 1. One socket identity

Today every socket carries two names: the client-visible `socket_id`
(u64, from `NetRuntimeInner::next_socket_id`, never reused) and the
netstack's `SocketHandle` (a reusable slot index into the per-device
`SocketSet`, which stores sockets in a `Vec<Option<Item>>` slab).
`SocketBase` holds both; every operation translates between them, logs
show different numbers for the same socket, and the slab brings the
recorded residual that a survivor in a high slot pins the storage
below it. After this step there is one u64 id, allocated by sys-io
(it must own the id space anyway: TCP listener ids come from the same
counter and have no netstack socket at all), used identically on the
wire, in `inner.sockets`, in the netstack store, and in every log line.

- **Commit A0 -- netstack: require std unconditionally** (per the
  answer to question 1). The deployed build already has the `std`
  feature on (sys-io's Cargo.toml) and the tests compile with std, so
  this deletes the `#![cfg_attr(..., no_std)]` machinery and the
  ~20 `cfg(feature = "std")` sites the same way no-alloc builds were
  retired: the crate runs in exactly one place, sys-io, which is std.
  Discipline note that survives the change: time stays *injected*
  (`poll(timestamp)`); std being available is not license for
  `std::time` or ambient randomness inside the netstack.

- **Commit A1 -- netstack: key the socket store by stable ids.**
  `SocketSet` storage becomes `BTreeMap<u64, Item>`; handles wrap a
  u64 allocated monotonically per set in this commit, never reused.
  The store is ordered, not hashed, deliberately: egress, `poll_at`,
  and the packet tests *iterate* it, and iteration must run the same
  way every time (question 1's carve-out) -- keyed-lookup-only maps
  are where HashMap goes. `SocketSet::new()` loses its storage
  argument (three call sites; borrowed storage was never used
  in-tree); `SocketStorage` and the slab's shrink machinery retire --
  a `BTreeMap` returns memory per remove, which closes the recorded
  "survivor pins the storage below it" residual outright. The two
  storage-return tests are replaced by one asserting storage follows
  removal exactly, in any teardown order. Iteration order becomes id
  (creation) order; the netstack tests run under the deployed feature
  set to catch any test pinned to slot order. Public API otherwise
  unchanged, so sys-io compiles untouched but for `SocketSet::new`.

- **Commit A2 -- one id end to end.** `SocketSet::add` takes the id
  from the caller (`add(id, socket)`); sys-io passes
  `next_socket_id()` at the three creation sites (TCP, UDP, the
  transient ICMP echo guard). `SocketBase` drops `netstack_handle`;
  `device.rs` signatures (`tcp_connect`, `tcp_restore`) and the
  remove/drop paths take the id. Netstack tests supply literal ids
  (27 mechanical sites). After this commit `0x{socket_id:x}` in
  sys-io logs and `[id]` in netstack traces are the same number,
  which is also the mdbg correlation win.

### 2. Ingress demux: from linear scan to tuple maps

Today `process_tcp` walks every socket in the set calling `accepts()`
until one takes the segment, and `process_udp` does the same -- every
data packet costs O(live sockets). The end state: demux is a map
lookup -- `std::collections::HashMap` (keyed-lookup only, so hash is
right; std's RandomState is seeded SipHash, which also answers
hash-flooding by peer-chosen tuples) -- and the per-packet linear
scan is *deleted*, not kept as a fallback. How the maps are kept
coherent with the sockets is open question 2; the commit shape below
follows that question's recommendation (authoritative maps behind a
mutable-access chokepoint) and collapses to a shorter self-healing
series if the ruling goes the other way. Either way the maps live
inside `SocketSet` so `remove()` purges entries (each `Meta` records
the key it is indexed under; index size <= live sockets).

- **Commit B1 -- netstack: identity transitions become set-visible.**
  A socket's demux identity is (state, tuple, listen endpoint) --
  the catalog under open question 2 -- and every change to it
  happens at one of two kinds of site. The five socket methods that
  change it at call time (`listen`, `connect`, `close`, `abort`,
  `restore_from_cookie`) become crate-private, re-exposed as
  `SocketSet` operations that delegate and then re-sync the
  socket's `Meta`-recorded demux key; sys-io's seven call sites
  update mechanically, and `get_mut` survives for data operations,
  which after this commit *cannot* change identity -- enforced by
  visibility, not convention. The in-stack transitions are covered
  at the two loops that already hold the set: `process_tcp`
  re-syncs the socket it just ran `process()` on, `socket_egress`
  the one it just ran `dispatch()` on. No maps yet: this commit is
  the invariant "Meta always knows the socket's current demux key",
  pinned by tests across every class in the catalog.

- **Commit B2 -- netstack: demux TCP by exact tuple.** A
  `HashMap<TupleKey, id>` keyed by the full 4-tuple (local addr:port,
  remote addr:port), maintained from the B1 key changes, serves every
  segment first -- including SYNs, so a segment matching a live
  connection reaches that connection (RFC 5961 challenge handling)
  deterministically rather than by slot order (pinned per answered
  question 4). The linear scan remains only for what the tuple map
  does not claim (listeners, until B3). Debug builds assert map/store
  coherence on every demux; release trusts the invariant. Packet
  tests: data segments reach the right socket among many without a
  scan; close-and-reopen on the same tuple; a packet after removal
  draws the reflector RST, not a stale hit; the exact-tuple-SYN
  contract.

- **Commit B3 -- netstack: demux listener endpoints, delete the TCP
  scan.** `HashMap<(port, addr-or-wildcard), Vec<id>>` for
  `State::Listen` sockets, consulted for SYNs the tuple map does not
  claim: exact (port, dst addr) first, then the wildcard entry -- a
  specific-address listener outranks a wildcard one (answered
  question 4); within an entry, id order, so pool selection is
  deterministic. With both maps live the per-packet scan in
  `process_tcp` is deleted: a miss now *means* no socket, and goes
  straight to the existing socketless paths (cookie mint, backlog
  attribution, reflector). `listener_owns` -- the refusal-path walk
  -- keeps its linear scan: its predicate is different
  (`listen_endpoint` survives past Listen) and it runs only when no
  socket took a SYN, at reflector rates. Tests: SYN to a pool member
  among many established sockets; specific-over-wildcard pinned;
  pool replenishment.

- **Commit B4 -- netstack: UDP port demux** (in scope per answered
  question 3). Same key shape, (port, addr-or-wildcard), maintained
  through the same B1 chokepoint; `process_udp`'s scan is deleted.
  ICMP, raw, and DNS sockets keep their linear walks: two of the
  three are compiled out of sys-io, the ICMP echo set is transient
  and tiny, and none of them is a data path.

Performance note, for the standing perf-only-goes-up rule: on the
sys-io side, every per-page operation swaps a slot-index access for a
BTreeMap walk on the store (depth <= 4 at realistic socket counts,
tens of ns); demux itself becomes an O(1) hash probe; the guard adds
a key compare per mutable release. Single-stream benchmarks run with
1-3 sockets where old scan and new maps alike degenerate to a couple
of comparisons. No regression is expected and none of this gets
agent-run benchmarks (perf is user-owned); the recorded fallback if
the next bench sitting shows one: a packed generation+slot slab
behind the same `SocketSet` API, which restores O(1) store access
without reintroducing reusable identities.

### 3. Crafted-packet regression tests

RST in every TCP state, window shrink, zero-window probes,
assembler-overflow storms. The list is partially enumerated; close it
as the tests get written.

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

Measure-first. When picked up: re-baseline the benchmark set (manifest
discipline under Method), profile a many-connection server workload,
then decide in review which O(N) structures to replace next -- with
ingress demux and the socket store promoted above, what remains here:
every egress pass still visits every socket (K packets from one
socket cost (K+1)xN visits); `poll_at` recomputes state across all
sockets; neighbor and route lookups stay linear. Candidates, each
separable: an egress ready-list, a timer wheel, an allocating
interval-list assembler, real neighbor/route table structures.
Profiling signal to start from: 64 parallel streams hold ~660 MiB/s
aggregate each way with a 5x per-stream fairness spread (tiers near
6 / 13 / 30 MiB/s) -- the egress/subchannel-packing path.

Scoped together with it: merging or formally projecting the two TCP
state enums (7-variant client ABI vs 11-variant protocol enum; needs
an ABI compatibility story). Zero-copy token work stays deferred until
a profile shows the copies dominating.

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

## Open questions

Only question 2 remains open. Answered entries stay for the record.

1. **ANSWERED (2026-08-15): make the netstack std, use std's
   HashMap.** Verified against the tree: sys-io already builds
   moto-netstack with the `std` Cargo feature, so the deployed stack
   is a std build today and the change deletes dead generality
   (commit A0), the same ruling as unconditional alloc. Downsides
   found, both minor and both carved out in the plan: (a) HashMap
   iteration order is nondeterministic, so it cannot hold anything
   the stack *iterates* -- egress and `poll_at` walk the socket
   store, and the packet tests need those walks reproducible -- so
   the store itself stays an ordered `BTreeMap<u64, Item>` while
   every keyed-lookup-only demux map is a std HashMap (whose seeded
   SipHash also covers hash-flooding by peer-chosen tuples for
   free); (b) std being available must not become ambient time or
   randomness inside the netstack -- time stays injected through
   `poll(timestamp)`, kept by review. Foreclosing a future no_std
   port is accepted, as with alloc.

2. **OPEN: how do the demux maps stay coherent with the sockets?**
   Resolved down to one design after cataloging every identity
   transition in the code (the 5-tuple question); awaiting the nod.

   The catalog -- every way a TCP socket's demux identity changes,
   beyond listen => connected (`socket/tcp.rs` lines as of A0):

   - At an API call, identity changes *at the call*: `listen()`
     (:1215, also legal on a previously connected, now closed,
     socket -- reuse), `connect()` (:1355; the tuple is claimed
     immediately, in SynSent, so the SYN|ACK can come back),
     `restore_from_cookie()` (:1258; a connection appears with no
     Listen socket involved), `abort()` (:1470; `accepts()` refuses
     from the instant state is Closed, even though the tuple field
     lingers until the RST is emitted -- identity is (state, tuple,
     listen endpoint), not the tuple alone), `close()` (on a
     *listening* socket only: Listen => Closed; on a connection it
     starts the FIN handshake and identity is unchanged until the
     handshake ends).
   - Inside `process()`, driven by the peer: RST in any state =>
     Closed, tuple cleared (:2755); the peer's ACK of our FIN in
     LastAck => Closed, tuple cleared (:2902) -- every passive
     close ends here; data-after-FIN on an rx-shutdown socket =>
     RST + Closed (:2670); and the one that breaks a pure
     listen=>connected model: **RST in SynReceived => back to
     Listen, tuple cleared** (:2745) -- a pool listener that took a
     SYN returns to the listening map without ever being removed.
   - Inside `dispatch()`, driven by timers and the interface:
     TimeWait expiry => reset (:3669); the interface no longer owns
     the socket's source address (operator reconfiguration) =>
     reset (:3481); the post-abort RST transmission clears the
     lingering tuple (:3982); the socket timeout gives up on a dead
     peer the same way.
   - UDP has none of this: (port, addr) set at `bind()`, cleared at
     `close()`, never changed by traffic -- the easy case. The
     protocol element of the 5-tuple is structural, not a key
     field: TCP and UDP get separate maps consulted from
     `process_tcp`/`process_udp`.

   The consequence: the update sites are *enumerable*. Five socket
   methods change identity at call time, and everything else
   happens under exactly two loops (`process_tcp` ingress,
   `socket_egress` dispatch) that already hold `&mut SocketSet`.
   So no yesterday's Drop-guard machinery and no self-healing scan:
   commit B1 makes the five methods crate-private and re-exposes
   them as `SocketSet` operations that re-sync after delegating,
   the two loops re-sync the one socket they just touched, and
   `get_mut` (data operations only, by visibility) cannot move a
   socket between maps. Maps become the truth, the per-packet scan
   is deleted, debug builds assert map/store coherence on every
   demux. The recorded alternative remains self-healing (map as
   hint, `accepts()` validation, linear-scan fallback as the
   authority) if moving the five methods behind the set is
   unwanted; its cost is keeping the O(N) scan alive forever, with
   a SYN flood as its worst case. Recommendation: the set-mediated
   authoritative design above.

3. **ANSWERED (2026-08-15): UDP demux is in scope for this work**
   -- maps-not-linear is the proper architecture; scheduling is
   secondary. Commit B4. ICMP/raw/DNS stay linear (compiled out or
   transient-and-tiny; revisit if one becomes a data path).

4. **ANSWERED (2026-08-15): both demux-order behavior changes are
   pinned as contract** -- an exact 4-tuple match beats a listener
   on the same port (RFC 5961 handling, the Linux rule), and a
   specific-address listener beats a wildcard one. Both are
   strictly more correct than today's slot-order accident; tests
   pin them in B2/B3.
