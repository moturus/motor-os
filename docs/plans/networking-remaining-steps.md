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
buffer sizing up to 8 MiB, and recent close-path work (an immediate
write on a peer-reset connection fails with `ECONNRESET`), plus SYN
cookies at the half-open caps, token-bucket egress limits on the
socketless replies (no-listener resets and cookie SYN|ACKs;
`max_rst_rate`/`max_syn_cookie_rate` in `sys-net.toml`, loopback
exempt), per-interface address/route tables that grow to the
configuration, and the safety-hardening set, with broad deterministic
packet-level test coverage. (Correction 2026-08-18: deployed sys-io
compiles SLAAC OUT -- the `proto-ipv6-slaac` feature is off,
so router advertisements do not configure addresses; the bounded
SLAAC-inflow code exists but only the crate's own tests build it.
IPv6 addressing is static config plus NDISC.) Since 2026-08-16: the netstack is unconditionally
std; a socket has one identity, the u64 sys-io allocates, on the
wire, in the stores, and in every log line; and ingress demux is
authoritative maps end to end -- exact 4-tuple, then listener
endpoint (specific address over wildcard), then the socketless
paths, with UDP by port -- the per-packet linear scans are deleted,
identity-changing socket operations exist only on the SocketSet, and
debug builds re-verify index completeness against every segment (the
retired scans live on as debug-only oracles). `rt.vdso` owns the net
channel pool, blocking policy, and POSIX state. The review below found
that the close/reset behavior is not yet Linux-equivalent in every path.

## Next up (approved)

Implement the first series in this security-first order, as one small
independently gated commit per defect:

1. TCP ACK upper-bound validation.
2. Right-window-clipped TCP FIN handling.
3. SYN-cookie restore deduplication and handle-checked demux retirement.
4. The malformed-UDP-fragment sys-io panic.
5. The unbounded completed accept backlog.
6. The std-reachable vdso socket-option panics.
7. The listener-flood memory-admission gap that can terminate sys-io.
8. Option RPCs on unconnected/failed-connect TCP streams.
9. Peer-reset reads laundered to clean EOF.

IPv4 and IPv6 fragmentation/reassembly are also approved. This is a
larger, security-sensitive change, so first write a dedicated design in
`docs/plans/`, including resource bounds, overlap handling, PMTU, and
production-feature tests, and ask for review before changing code.

## Found by the 2026-08-18 full review -- triaged

A five-track static review (TCP machine, netstack infrastructure,
sys-io glue, vdso/moto-io client side, cross-cutting hygiene) on
2026-08-18, across two passes (v1 + v2). Each item's mechanism was
traced through the deployed feature closure and read against the code;
a representative sample was independently re-verified line by line on a
third pass. No tests were run, at the user's request. The first series
and explicit resolved decisions below were approved on 2026-08-18;
other work remains recorded until selected.

Most items are located code defects. The exceptions carry a tag:
**[doc]** marks a documentation or accounting task with no code change;
**[resolved]** records a product decision already made. Everything
untagged is a located defect with a concrete fix.

TCP protocol machine (`netstack/src/socket/tcp.rs`):

- ACK acceptance upper bound is `SND.UNA + tx_buffer.len()`, not
  SND.NXT (tcp.rs:2468) -- an ACK of bytes never sent is accepted,
  dequeues unsent data as "delivered", and desyncs the stream; also
  widens the RFC 5961 challenge-ACK window by up to the send ring.
  Fix: track SND.MAX and challenge-ACK above it.
- A FIN whose payload was clipped at the RIGHT window edge is
  still processed (tcp.rs:2754 quashes only left-hole FINs;
  receive_overlap clips at 2338; Established|Fin bumps remote_seq_no
  at 2880) -- a window-overrunning peer causes sequence desync and
  premature EOF. Fix: quash the FIN when `segment_end > window_end`.
- TS.Recent is never seeded in the Listen/SynSent SYN arms, and
  the general update's window base is uninitialized during the
  handshake (tcp.rs:2508, 3171), so ~half of connections (by peer
  ISN sign) emit TSecr=0 until established -- RFC 7323 violation,
  lost handshake RTT sample, PAWS disarmed. The cookie-restore path
  already seeds it correctly (tcp.rs:1336); the SYN arms should too.
- TLP probe timeout lacks the RFC 8985 WCDelAckT (~200 ms) term for
  single-segment flights (tcp.rs:2025) -- with LAN srtt the PTO
  floors at 10 ms, so request/response traffic draws a spurious tail
  probe per exchange, and the resulting DSACKs ratchet the RACK
  reordering window (tcp.rs:1918).
- A segment carrying an old ACK is dropped wholesale
  (tcp.rs:2479 `return None`), discarding in-window payload; RFC
  9293 says ignore the ACK field and keep the data. Matters under
  the ruled-in WAN/reordering scope.
- No SND.WL1/WL2 guard on window updates (tcp.rs:2955) -- reordered
  ACKs can regress the send window; worst case arms persist against
  a window the peer already reopened.
- No floor on the peer's MSS (tcp.rs:2791/2844 reject only 0) -- a
  crafted SYN advertising MSS=1 turns the send path into a 1-byte-
  per-packet amplifier (Linux clamps post-CVE-2019-11477).
- Karn's rule skipped for RACK/TLP-staged retransmits (rtte
  notified only in the RTO branch, tcp.rs:3666) -- inflated RTT
  sample when the sampled segment is repaired by staging; low
  impact, errs safe.
- [resolved] Reno (selectable, not default) grows cwnd a full MSS per ACK in
  congestion avoidance and overwrites ssthresh (congestion/
  reno.rs:30). Remove the Reno controller/feature and its selectable
  surface; deployed sys-io uses Cubic.

netstack infrastructure:

- SYN-cookie restores have no dedup: two cookie-completing ACKs
  for one 4-tuple in one poll batch (ACK + first data, or a dup ACK
  -- normal under the floods that engage cookies) each push a
  restore (iface/interface/tcp.rs:147), each builds a socket, and
  the second demux insert hits `debug_assert!(evicted.is_none())`
  (socket_set.rs:53) -- debug builds panic from network input;
  release overwrites, and since `retire` removes purely by tuple
  key, closing the zombie deregisters the LIVE connection from
  ingress demux. Fix: dedup at the push and/or skip restores whose
  tuple is claimed; make retire handle-checked.
- ICMP error replies (UDP port unreachable, proto unreachable,
  v6 param problem) bypass the reflector token buckets entirely --
  `try_take` exists only on the TCP RST/cookie paths -- leaving the
  spoofed-source reflection primitive the RST bucket was built to
  close open via ICMP. Approved fix: add a separate
  `max_icmp_error_rate` bucket/config key and keep loopback exempt. The
  default is 200 replies/second, matching `max_rst_rate`.
- [resolved] Incoming ICMP errors are delivered only to raw ICMP
  sockets; they are never associated with the TCP/UDP flow quoted by
  the error. In particular, connected UDP never observes
  port-unreachable, packet-too-big/PMTU, or another asynchronous
  error, and rt.vdso's UDP `SO_ERROR` always reports success. This is
  a scope call first. Doing nothing leaves connected UDP failures as
  timeouts with `SO_ERROR == 0`, and TCP/UDP cannot react to a smaller
  downstream MTU. The latter permanently black-holes oversized IPv6
  traffic because routers cannot fragment IPv6. If in scope, validate
  the quoted flow before updating PMTU or stored error/readiness; forged
  ICMP must not be allowed to tear down an unrelated connection. As the
  minimum scope in the fragmentation series, validate and associate
  quoted flows, handle IPv4 Fragmentation Needed and IPv6 Packet Too
  Big, keep bounded PMTU state, and let TCP/UDP resegment or refragment.
  Defer other destination-unreachable delivery and `SO_ERROR`/ERROR
  readiness to later work.
- Neighbor-cache admission is weaker than the earlier diagnosis stated.
  NDISC NeighborAdvert ignores SOLICITED and keys the cache by the IPv6
  source rather than the advertised target (ipv6.rs:462-479); proxy NAs
  therefore update the wrong address. ARP likewise treats every reply
  aimed at the local IP as solicited without correlating it with an
  outstanding request. Simply trusting an NA's SOLICITED bit is not a
  fix because an attacker can set it. Correlate replies with the cache's
  recorded probes, enforce the NA destination/flag rules, use the target
  address, and make uncorrelated advertisements non-evicting. This is an
  admission/eviction defense, not neighbor authentication: ARP/NDISC are
  still spoofable by an on-link peer. Low impact in practice: source and
  target coincide for every non-proxy NA, so the mis-keying bites only
  proxy-NA and crafted setups; the eviction-DoS angle needs an on-link
  attacker.
- [resolved] IPv4/IPv6 fragmentation and reassembly are compiled out of
  sys-io.
  Ingress IPv4 fragments and IPv6 Fragment headers are rejected; egress
  IPv4 packets over the interface MTU and oversized IPv6 packets are
  logged and dropped while interface dispatch returns success. UDP then
  dequeues the datagram, so an application can successfully send up to
  the advertised 65,507-byte API limit while every external packet above
  the path MTU silently disappears. Implement bounded,
  overlap-safe IPv4 and IPv6 fragmentation/reassembly rather than an
  `EMSGSIZE`-only fix. This requires the dedicated design named under
  "Next up"; successful silent drop must disappear in the same series.

sys-io runtime glue:

- A TCP close with `SO_LINGER(secs > 0)` is never answered: the
  `delayed_notify` branch takes `close_req` but `tcp_linger_task`
  drops it, and the immediate-reply path is gated `!delayed_notify`
  (socket/tcp.rs:1628-1650). Latent only because moto-io's `drop`
  fire-and-forgets the close; any client that awaits the close reply
  on a lingering socket hangs forever. Fix: hand `close_req` to the
  linger task and reply when linger resolves.
- [resolved] UDP TX datagrams parked on netstack `BufferFull` are never
  re-driven -- there is no UDP send-waker anywhere in sys-io, so the
  queue drains only when the client next sends (socket/udp.rs:447).
  A burst >64 KiB that then goes quiet strands its tail datagrams
  until socket drop discards them. Dropping is permitted by UDP, but
  doing so here turns temporary local congestion into silent loss for
  DNS, QUIC, and other retry/timeout-driven protocols. Prefer the simple
  bounded policy: drop the complete newest datagram immediately on
  `BufferFull` and increment a reason-specific counter; do not park it.
- [resolved] The per-socket UDP TX queue is unbounded and the client page
  budget doesn't bound it -- non-first fragments are copied to a
  `Vec` and the io page freed at once (moto-io-internal/
  udp_queues.rs:150,412), so a client outrunning the device grows
  sys-io's heap without pushback; sys-io aborts on alloc failure.
  The drop policy fixes this only if admission is bounded before these
  copies. Bound bytes and datagrams from the existing channel-page
  budget; on overflow drop the complete newest datagram and increment a
  reason-specific counter. Never retain a partial datagram beyond the
  same bounds.
- The same UDP defragmenter accepts client-controlled fragment IDs and
  asserts that a zero-length datagram has ID zero. A malformed empty
  fragment with a nonzero ID therefore panics all of sys-io instead of
  rejecting the client. Validate every fragment sequence, total byte
  count, and fragment count before queueing; return an error rather than
  asserting across this trust boundary.
- [resolved] A listener's fully established `pending_sockets` queue is
  unbounded.
  Remote peers can complete handshakes faster than the application calls
  accept, and each socket grows from the 16 KiB-per-direction lazy floor
  to its full configured 128 KiB-per-direction rings on entering
  Established. `max_backlog_global`/`max_backlog_per_listener` limit
  growth of the spare listening-socket pools, not this completed accept
  backlog. Worst case, an unauthenticated remote peer completes and
  holds enough connections to consume roughly 256 KiB of rings each
  (about 1 GiB per 4,096 connections), until sys-io exhausts memory and
  the whole networking service aborts. The half-open/SYN-cookie caps do
  not help after the handshake. Add independent hard completed-
  connection limits of 128 global and 32 per listener, preserving the
  original intended 32 MiB/8 MiB budgets; do not rely on rt.vdso's
  `listen(backlog)` as the security boundary. Reset and count overflow.
- [resolved] Listener creation could terminate sys-io instead of returning
  `OutOfMemory` near the admission floor. The third debug gate for the
  socket-option patch reproduced this in
  `test_aggregate_listener_exhaustion`: after two passing runs in which
  each of four children was refused cleanly at about 671--674 listeners,
  the VM exited during the same flood before any child reported. The new
  socket-option tests had not run.
  The initial concurrency diagnosis was wrong: sys-io's local runtime is
  single-threaded, and listener construction does not yield. The actual gap
  was deferred allocation. Each socket queued an outer listen future, which
  did not allocate its connection signal and lifecycle/replenishment task
  until its first poll; the executor also allocated a retained heap-backed
  waker at poll time. A burst of successful bind RPCs could therefore queue
  substantial heap work after the admission samples, and a later allocation
  refusal aborted the critical sys-io process.
  Recheck pressure for every listening socket, construct its signal and both
  lifecycle tasks synchronously before returning success, and have the
  lifecycle waiter replenish directly instead of spawning a third task.
  Cache each runtime task's waker at spawn time (and the root waker once per
  `block_on`) so polling does not move retained allocation past that
  boundary. A focused runtime regression checks stable root/task waker
  identity across polls. The aggregate listener flood remains the integration
  regression: it must return prompt `OutOfMemory`, preserve the armed
  net-channel listener floor, recover its memory, and pass the focused
  networking gate three times in both debug and release builds.
- The memory accounting/docs for half-open and spare listening sockets
  are stale: both use `RingBuild::LazyFloor` (16 KiB per direction), but
  `half_open.rs`, `backlog.rs`, and shipped `sys-net.toml` comments price
  them as 128 KiB per direction. Correct the operator guidance and retune
  the limits from measured object/ring costs; keep completed established
  sockets accounted separately because they do grow to the full rings.
- RX ring depth ratchets down permanently on transient buffer-alloc
  failure: a failed `pop_buf` drops the slot forever, and enough
  memory-pressure episodes stop RX for good (device.rs:243) -- the
  same pressure state pressure.rs now models. Fix: track the deficit
  and top the ring back up on a later successful poll.
- [resolved] A bad `sys-net.toml` (e.g. one out-of-range numeric key) fails the
  whole `NetConfig` parse and `net::init` returns before the
  loopback device or the io_channel listener exist (runtime/
  mod.rs:184, net.rs:678) -- every client's connect gets `NotFound`,
  the one symptom the armed-listener floor was built to avoid, with
  one kernel-log line. A malformed file must abort sys-io
  startup loudly; do not fall back or default an invalid key. A valid
  configuration that produces zero devices is supported and deliberately
  does not start the client net-channel listener. Log both outcomes
  distinctly and test them.
- [resolved] `tx_task` headroom loop `unwrap`s a possibly-empty completion deque
  when the raw virtqueue has fewer than 18 descriptors
  (`txq_sz() < 9` in sys-io's two-descriptors-per-entry units), not only
  at the previously stated "<=8 descriptors" threshold (device.rs:280).
  Raw queue sizes 8 or 16 are legal and abort sys-io at boot.
  Reject a device with fewer than 18 raw TX descriptors during
  initialization with a clear error; supporting smaller chains is out of
  scope.
- Ephemeral-port selection and explicit binds do not share one source of
  truth. TCP connects can draw an explicitly bound listener's port as
  their source (`net.rs` stubs the reserved-port predicate and fixed
  listeners never enter `tcp_ports_in_use`). Explicit UDP binds likewise
  never enter `udp_ports_in_use`; on loopback, the deterministic allocator
  can repeatedly choose that occupied port and fail instead of trying the
  next one. Preserve loopback's simultaneous-open test requirement while
  checking all live bindings and retrying candidates.
- Per-listener `pending_accepts` is unbounded and cleared without an
  error reply on listener teardown (tcp_listener.rs:556,89,240) --
  same "request never answered" family as the linger case, benign
  for today's clients. Cap native queued accept RPCs at 1,024 and answer
  every queued RPC with a closed/canceled error on teardown.
- `drop_tcp_socket` asks the device to poll, sleeps a fixed 1 ms, then
  removes the aborted socket without confirmation that its RST reached
  the device. Scheduler or device delay can therefore turn abort into a
  silent close. Use an explicit transmit-completion/state condition.
- [resolved] In the graceful close path, an established connection on
  which the local side sent no payload is deliberately aborted rather
  than FIN-closed (`stat_tx_bytes == 0`, socket/tcp.rs:1550) -- see the
  in-code rationale (the client is gone and a peer still writing must
  learn at once nobody will read it). Keep this intentional RST behavior;
  it is an accepted non-POSIX exception, not a defect.

vdso / moto-io client side:

- Ordinary std socket-option calls abort the whole process: the
  `_ => panic!("unrecognized option")` arms in vdso set/getsockopt
  (rt_udp.rs:109,146; rt_tcp.rs:165,235,531,569) and the multicast
  ops wired to `vdso_unimplemented` (main.rs:369-374) are reachable
  from safe std -- `UdpSocket::set_broadcast`, `join_multicast_v4`,
  `set_multicast_ttl_v4`, `TcpListener::set_only_v6` all map to
  moto-rt options the vdso doesn't handle, so a routine call dies
  with exit-222 and nothing on stderr instead of an `io::Error`.
  Fix: return `E_NOT_IMPLEMENTED` from those arms.
- [resolved] Option RPCs on a not-yet-connected / failed-connect
  `TcpStream` aborted the process because `handle()` asserted non-zero
  while those states retain handle zero. All remote stream options now use
  a fallible option-only handle accessor and return `E_NOT_CONNECTED`
  before queueing an RPC. Local descriptor options and `SO_ERROR` remain
  available, so callers can still configure blocking/timeouts and consume
  the connect error. A native regression holds the local channel driver
  unpolled to cover `Connecting`, then drives the refusal to cover `Closed`,
  across shutdown, linger, nodelay, TTL, and both buffer-size options; the
  public vdso nodelay path is covered after a refused nonblocking connect.
- [resolved] A read on a peer-RESET stream was laundered to clean EOF
  `Ok(0)`, so truncation-by-EOF protocols could silently accept truncated
  data. moto-io now records locally committed `shutdown(Read)` separately
  from the combined read-closed state. After queued bytes are drained, every
  reset EOF branch returns `E_CONNECTION_RESET`; an earlier local read
  shutdown continues to return clean EOF. The vdso blocking adapter propagates
  terminal fast-path errors instead of asserting that every read error is
  `E_NOT_READY`. Full-stack regressions cover an immediate reset, data
  ordered before a reset, and local-shutdown
  suppression of the reset error.
- A writer that was already parked when reset/closure arrives takes a
  different path from an immediate write: `TcpWriteFuture` returns
  `Ok(written)`, including `Ok(0)`, once the state is dead or TX is
  closed. Preserve partial-write semantics, but return the stored reset/
  broken-pipe error when zero bytes were committed.
- Nonblocking connect fails spuriously with `WouldBlock` when the
  channel staging queue is transiently full (moto-io tcp.rs:1100 via
  `post_rpc`, channel.rs:1795) -- under bulk TX on a pooled channel,
  mio sees a hard connect error where nothing is wrong. Fix: fall
  back to the guaranteed driver FIFO (`enqueue_rpc`) for connect.
- Local `shutdown(Write)` raises no WRITABLE/WRITE_CLOSED readiness
  edge (moto-io tcp.rs:1716; the read arm raises READABLE) -- blocking
  writers recover via the per-pass waker sweep, but a mio poller
  holding WRITABLE interest gets no edge where epoll reports EPOLLOUT
  after SHUT_WR. Fix: raise the edge in the write arm. Same family:
  registration-time synthesis omits the write-half-closed state
  (rt_tcp.rs:263) and omits `POLL_ERROR` on the failed-connect Closed
  branch (rt_tcp.rs:248), contradicting its own delivery-parity
  comment. Peer RST also raises only readable/writable/closed, not ERROR,
  and is not retained in TCP `SO_ERROR`; align immediate I/O, stored
  error, and readiness semantics.
- Wildcard + ephemeral bind `0.0.0.0:0` is rejected (moto-io
  udp.rs:152, tcp.rs:321) -- the canonical portable UDP-client idiom
  fails with InvalidInput, and there is no std-reachable way to learn
  a concrete local IP instead. Fix: treat unspecified-IP + port 0 as
  "let sys-io pick".
- Dropping/canceling a native `TcpListener` accept future leaves its
  oneshot sender in `accept_dispatch.waiters` until a connection arrives
  or the listener closes. Repeated canceled accepts grow process memory;
  give waiter registration a cancellation/removal path.
- `UdpSocket::close` discards queues and routing state but wakes neither
  RX nor TX waiters; a concurrent receive can remain parked indefinitely.
  Send also does not reject the closed state, so it can enqueue and report
  success for a datagram the closed socket will never transmit. Wake both
  sides and make all post-close operations fail consistently.
- [resolved] UDP RX backpressure is bypassed for fragmented channel datagrams: the
  client defragmenter copies non-first fragments into heap `Vec`s and
  returns their channel pages immediately. If the application does not
  receive, multi-fragment datagrams can grow its heap without the bounded
  page pool applying pressure. Bound bytes and datagrams from the existing
  channel-page budget and drop the complete newest datagram on overflow,
  with a reason-specific counter; partial reassembly is subject to the
  same bounds.
  Also, the public native `send_to_future` bypasses `MAX_UDP_PAYLOAD`
  validation present in `try_send_to`/rt.vdso; enforce the limit at the
  shared enqueue boundary.

Cross-cutting hygiene (all confirmed by the sweep):

- [resolved] The per-channel PDIAG/RXSTALL/TXSTALL watchdog (moto-io
  channel.rs:229-249,1195-1245 + StreamDiag counters on the data
  path) ships in every app via the always-on `netdev` feature. It
  was built for the russhd-wedge diagnosis, now root-caused and
  fixed (poll stale-token UAF); the RXSTALL heuristic also
  false-positives on legitimate read-side backpressure, logging every
  15 s per socket. Remove it in this series.
- [resolved] The `netdev`-gated moto-io test scaffolding (LISTENER_DROP_TEST,
  `poison_connect_for_test`, pool leak hooks -- ~62 sites) compiles
  into every production app because rt.vdso is always built
  `--features netdev`. Retain it because systests drive a
  stock image.
- [resolved] Three phy helpers (fault_injector.rs, pcap_writer.rs, tracer.rs,
  ~950 lines) are ungated in `phy/mod.rs` and compiled though sys-io
  never references them -- generic, so near-zero binary cost, but
  build-time and audit surface. `wire/igmp.rs`+`wire/mld.rs` compile
  under proto-ipv4/6 while every use is `multicast`-gated (off). Leave
  these generic helpers alone.
- `netstack/src/socket/tcp.rs:2419` `unreachable!()` is reachable
  only if the demux hands a Listen socket an ACK-bearing segment; the
  guard now lives across the demux condition and cookie-restore path
  rather than locally -- a defensive drop or debug assert would
  localize it. (Consistent with TCP finding on cookie restores.)
- [resolved] The deployed feature boundary needs an explicit support
  statement. DHCPv4, SLAAC, multicast, raw sockets, and a general IPv6
  extension-header chain are out of scope for this series and are
  recorded for later work. IP fragmentation is the explicit exception
  approved above. (The multicast std entry points aborting the process
  remains a separate located defect; they must return an error while
  multicast is unsupported.)
- [resolved] IPv6 source-address selection implements RFC 6724 rules 1,
  2, and 8; rules 3 through 7 are explicit TODOs
  (interface/ipv6.rs:131-136). Low impact: deprecation/temporary-address
  rules matter little while SLAAC is off, and label/outgoing-interface
  selection only bites a host given multiple static IPv6 addresses.
  Document the reduced selection policy for this series and leave the
  missing rules for later protocol work.
- [doc] No `docs/` reference page for `sys-net.toml`; the shipped config
  file's comments are the de-facto docs, but their half-open/listener
  memory figures are stale and `auto_icmp_echo_reply` and `loopback` are
  uncommented. The reference page should also state the deployed feature
  limits above and the completed-connection backlog semantics.
- [resolved] `src/sys/sys-io/Cargo.lock` is a stale member-level lock
  cargo ignores (the workspace lock is `src/sys/Cargo.lock`). Remove
  the stale member lock in this series.

## Standing calls, revisit later

- **Fixed buffer default.** 128 KiB per direction stands (a 128 KiB
  window caps a 100 ms path at ~10 Mbit/s; WAN workloads size per
  socket via `SO_RCVBUF`/`SO_SNDBUF`). The close-path prerequisite has
  landed, so raising it is purely a call, informed by the user's
  regular benchmarking.

## Architectural netstack work (measure, then decide)

Parked candidates,
measure before picking up: merging or formally projecting the two TCP
state enums (7-variant client ABI vs 11-variant protocol enum; needs
an ABI compatibility story -- a user decision); zero-copy token work
(deferred until a profile shows the copies dominating); and one
recorded fallback -- sys-io's per-page store access is a BTreeMap
walk (depth <= 4 at realistic socket counts); if the user's
benchmarking ever shows that line, the swap is a packed
generation+slot slab behind the same SocketSet API. Scale reference,
recorded before the 2026-08-16 scalability series landed: 64 parallel
streams held ~660 MiB/s aggregate each way with a 5x per-stream
fairness spread (tiers near 6 / 13 / 30 MiB/s); the series' egress
cursor targets that spread, and the user's benchmark verdict on it is
the outcome measure.

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
- Test-debt correction: `REASSEMBLY_BUFFER_COUNT` and
  `FRAGMENTATION_BUFFER_SIZE` do not merely differ from deployment.
  The deployed sys-io feature closure and both full-test scripts omit
  IPv4/IPv6 fragmentation, so those tests are not compiled at all and
  there are no deployed values to compare. The approved fragmentation
  implementation must enable and test exactly its production features,
  including external-MTU boundaries, overlap rejection, resource caps,
  expiry, and IPv6 Packet Too Big handling.
- Test debt found by this review: no direct regression coverage was
  located for the unbounded completed accept backlog, malformed/overlong
  UDP channel fragment sequences, UDP close with parked waiters, reset
  arriving at an already parked TCP read/write, abort/RST transmit
  completion, or the intentional no-listener outcome for a valid
  zero-device configuration. Add each test with the corresponding fix
  or resolved policy. Separately, the RDRAND retry path and
  external-device checksum arm remain untestable without seams, and the
  `58622c82` listener-abort fix has no in-suite regression.
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

- External DNS/ping legs, after the 2026-08-16 resolver fix (rule-1
  destination ordering + one in-resolver v4 re-ask; the user chose it
  over pinning the checks to IPv4, check-side retries, a host-side
  preflight, and host NAT66, all declined): a remaining failure means
  the upstream A query was lost twice in a row, or the host NAT broke
  (it resets on reboot). Revisit the declined remedies if the rate
  stays visible.
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
- Hangs: `/devtools/bin/mdbg print-stacks <pid>` plus addr2line on unstripped
  binaries first, before any speculation.

## Final-review status

All questions from the 2026-08-18 triage are resolved and incorporated
above. The security-first series and the fragmentation design step are
approved, but implementation must not begin until this document passes
the requested final review.
