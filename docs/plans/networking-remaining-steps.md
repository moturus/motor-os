# Networking: remaining steps

This file tracks only unfinished Motor OS networking work. Historical designs,
diagnoses, patch sequences, gate transcripts, and measurements remain
available in git history.

No implementation series is currently selected. Select and review a bounded
series before changing code; larger work needs a dedicated design round.

Status after the 2026-08-22 full review (six static tracks over `41a18e9f`:
ledger reconciliation, TCP machine, IP/fragmentation/PMTU/ICMP/neighbor,
sys-io runtime, client side, production operations). Every item pruned from
this file since 2026-08-18 has a landed implementation. The earlier statement
that the shared-L2 deployment prerequisites were complete is withdrawn: the
review found new ways for a release sys-io to die or wedge from ordinary or
trivially forged traffic, replies sent with source addresses we do not own,
TCP lifecycle gaps, and an operational layer (configuration, supervision,
secrets, DNS) this file had never covered. All findings were traced
statically; none was reproduced, so re-confirm each at the code before
designing its fix.

What is ready today: a development VM on a host tap, which is what the gate
proves. A static-address server on a trusted LAN is usable once the sys-io
panics and the client-path items in (a) are fixed, accepting image-per-host
configuration and console-only diagnostics. A shared or untrusted Ethernet
segment, an internet-facing service, or a cloud instance needing DHCP each
wait on the rest of (a).

Within each group, order is the suggested pickup order.

## (a) Highest priority: critical for production readiness

### sys-io dies or wedges

- COMPLETED: Drop IPv4 packets from the unspecified source `0.0.0.0` unless they are
  DHCP, which is not compiled. `iface/interface/ipv4.rs` admits them; a SYN to
  any listening port becomes a Listen-state connection whose remote is
  `0.0.0.0`, and the SYN|ACK hits the release `assert!` on an unspecified
  destination in `iface/interface/mod.rs` dispatch. Under `panic = "abort"`
  one forged 60-byte frame stops sys-io; the SYN-cookie path reaches the same
  assert. Also refuse an unspecified remote in the Listen SYN arm.
- COMPLETED: Sweep every `assert!`, `debug_assert!`, and `unreachable!` on the
  ingress-to-dispatch path so none is reachable from network input. Known
  cases: the Listen-state `unreachable!()` in `netstack/src/socket/tcp.rs`
  (defense in depth against demux or cookie-restore regressions), and
  `rst_reply`'s `debug_assert!(control != Rst)`, reached when an RST carrying
  payload at RCV.NXT arrives on an rx-shutdown FIN-WAIT socket because the
  rx-shutdown check runs before the RST arm. Debug builds, which the gate
  runs, panic; release answers an RST with an RST. Move the RST arm first.
- COMPLETED: Clear a socket's queued client TX pages before the socket is dropped at
  linger expiry. In `runtime/net/socket/tcp.rs`, a close with unsent pages
  takes `DrainThenFinish`; when the peer stalls for the whole linger, step 1
  times out, step 2 registers the linger task on the single-slot send waker
  (overwriting the TX task's), `drop_tcp_socket` never clears `tx_queue`, and
  `on_tcp_socket_drop` trips its release `assert!(tx_queue.is_empty())`.
  Trigger: an application writes more than the 128 KiB ring to a peer that
  stops reading, then closes or exits. Clear the queue in `drop_tcp_socket`
  and never let the linger task take a waker the TX task still needs.
- COMPLETED: Give the inline data path a yield budget. `runtime/net.rs` dispatches
  `TcpStreamTx` and `TcpStreamRxAck` inline and loops while the ring is
  non-empty; the executor polls a task until it returns `Pending`. A client
  that keeps its ring non-empty (two producer threads suffice) starves device
  polls, timers, every other channel, and the file system on sys-io's only
  thread.
- Bound the netstack-to-device TX queue and the abort wait. `device.rs`
  `transmit()` always hands out a token and `consume` pushes to `tx_queue`,
  falling back to a heap buffer when pooled buffers run out, so a client
  faster than the device grows sys-io to allocation failure; the same scratch
  path silently loses the packet, including an abort's RST. Return `None`
  past a queue depth. `drop_tcp_socket` awaits `transmit_completion()` with
  no timeout, so a wedged host or device turns every close, linger, and
  client teardown into a permanent hang and leaks channel-budget slots; bound
  the wait and count the timeouts.
- Give neighbor discovery per-destination backoff and a give-up. sys-io sets
  `discovery_silent_time` to 5 ms; egress is re-permitted when it expires,
  TCP re-solicits every 5 ms until its timeout, and UDP keeps the datagram at
  the head of its queue forever (`storage/packet_buffer.rs`), blocking the
  socket. Spoofed on-link sources (half-open sockets plus every socketless
  RST, cookie, and ICMP reply) turn into tens of thousands of ARP/NS
  broadcasts per second onto the segment; a peer that powers off wedges the
  UDP socket. Back off to about 1 s, fail the datagram or socket after a few
  probes as Linux does (`EHOSTUNREACH`), and add an interface-wide
  solicitation token bucket. The 64-entry silent map evicts under churn and
  then suppresses nothing.

### Replies on a shared segment

- Require the `ff02::1:ff00::/104` prefix and compare 24 bits in the
  solicited-node check (`iface/interface/ipv6.rs` compares the low 16 bits of
  any destination; the comment says 24). Today a frame to our MAC or the
  broadcast MAC with any destination sharing our low 16 bits passes the
  ownership check, and we answer echo, Parameter Problem, Port Unreachable,
  and socketless RST with a source address we do not own; wildcard listeners
  and UDP sockets also see it.
- Do not reply for destinations we should ignore: run the destination check
  before Hop-by-Hop processing (a broadcast frame with a bad option makes
  every host emit Parameter Problem from a foreign source); send no Port
  Unreachable or Parameter Problem for multicast destinations (RFC 4443
  2.4(e)); discard TCP to broadcast or multicast destinations instead of
  answering with an RST sourced from that address (RFC 9293 3.10.7.2).
- Turn broadcast echo replies off by default. `ipv4.rs` answers echo to the
  limited and subnet broadcast, `auto_icmp_echo_reply` ships enabled, and
  echo replies are exempt from the error limiter.

### TCP lifecycle

- Cap SYN retransmissions and give `connect()` a default timeout. The
  netstack has no retry counter, only the optional `timeout`; sys-io sets it
  only when the request carries a deadline, and std and mio pass none. A
  connect to a black hole retransmits forever with the RTO capped at 60 s,
  pinning the socket, channel slot, and ephemeral port. Linux fails after
  about 127 s.
- Collapse cwnd after an RTO. `congestion/cubic.rs` shares `on_congestion`
  between both loss signals, so after a timeout cwnd stays at 0.7x and slow
  start is never re-entered; with everything written off as lost at RTO, up
  to 0.7 cwnd of retransmissions bursts out. RFC 5681 and RFC 8312 require one
  segment.
- Check the assembler before growing the receive ring.
  `apply_pending_rx_growth` tests `rx_buffer.is_empty()` but not the
  assembler; `grow_to` resets `read_at` to zero, so out-of-order payload
  already in the ring is mapped to different offsets and a later hole fill
  publishes stale bytes as stream data. Trigger: an `SO_RCVBUF` raise latched
  until the ring drains, plus reordering at that drain.

### Client path

- Detect a refused or dead channel and fail every waiter on it. sys-io's
  `refuse_client` answers only the first RPC, while the pool hands up to four
  parked reservers a fresh channel; moto-io has no disconnect detection, so
  `rx_park` on a dead server handle spins and every parked RPC, read future,
  and blocking call on that channel hangs forever. The same happens when
  sys-io dies. Set `exiting`, drop the RPC map, and fail the sockets.
- Arm WRITABLE at poll registration when the subchannel's TX pages are
  exhausted. `rt_tcp.rs` synthesizes WRITABLE only if page space exists and
  arms nothing otherwise; a subchannel index reused while sys-io still holds
  the previous occupant's pages (a lingering close to a slow peer) leaves an
  accepted connection that reads its request and never becomes writable.
  Same shape as the fixed partial-write bug.
- Accept wildcard binds. UDP refuses any unspecified address, not only
  `0.0.0.0:0`, so no UDP server can start and the idiomatic client bind
  fails; let sys-io choose the address (and port when zero). Make wildcard
  TCP listeners family-correct: `0.0.0.0:P` currently accepts IPv6 peers and
  `[::]:P` then fails with `AddrInUse`, so services that bind both families
  cannot start; implement `IPV6_V6ONLY`.
- Clamp `SO_LINGER` seconds and reclaim lingering sockets when the client
  dies. The value is an unbounded `u32`; a lingering socket leaves
  `client.sockets`, so it, its rings, and its ephemeral port outlive the
  process for the whole linger. A few thousand such sockets pin the
  ephemeral range for every other process.

### Deployment prerequisites outside the netstack

These are not netstack defects, but no production deployment exists without
them, so they are tracked here until they have homes of their own.

- Design a per-instance configuration path. `sys-net.toml` is copied into
  the image and bound to hardware by MAC equality; a mismatch leaves the VM
  loopback-only with one warning line, and every instance needs its own image
  build. Options: DHCPv4 in deployed sys-io (lease lifecycle, addresses,
  routes, DNS), or at minimum MAC-agnostic device selection plus a
  configuration source outside the image. Cloud networks that offer only
  DHCP are unusable today.
- Decide what happens when sys-io dies and make its logs reachable. The
  kernel halts the VM when sys-io exits; sys-init never waits on or restarts
  services; headless daemons log only to the kernel log (`sysbox syslog` is
  unwired; see `future-work.md`). Given the panics above, every failure is a
  silent outage.
- Ship no working secrets. `sshd.toml` carries a password and an authorized
  key whose private half is in its comments, listening on `0.0.0.0:2222`,
  detected with a warning nobody can read; `ssl-key.pem` is committed. Refuse
  to start on default secrets and document provisioning.
- Replace or harden the DNS client. The only backend is mlibc with a constant
  transaction id, an unconnected socket that accepts any source, no retry or
  TCP fallback, and a generated `resolv.conf` hard-coded to `8.8.8.8`.
  Off-path forgery needs only the 16-bit source port; on-path is trivial.

## (b) Medium priority: robustness

### TCP protocol

- Carry a per-connection timestamp offset across SYN-cookie restore.
  `syn_cookies.rs` repurposes the low six bits of the advertised TSval, so it
  can run up to 63 ms ahead of our clock; a Linux peer PAWS-discards every
  segment we send until the clock catches up, and the restored socket has no
  RTT sample (TLP disarmed, RTO at the 1 s initial value).
- Retain TIME-WAIT. The sys-io linger exits on `!is_open()`, which is true
  in TIME-WAIT, and dropping the socket removes it from the socket set, so the
  netstack's `CLOSE_DELAY` never runs; a retransmitted peer FIN is answered
  by the reflector's RST.
- Floor the send MSS and make the PMTU header subtraction saturating. With
  the IPv4 floor of 68 the `path_mtu - headers` arithmetic underflows (debug
  aborts, release wraps and source-fragments with DF clear); without SACK the
  segment size reaches 16 bytes. Linux floors at 48 and uses a practical
  552-byte minimum for IPv4.
- Ignore an old ACK field while still processing in-window payload. The
  current path drops the whole segment, contrary to RFC 9293.
- Add SND.WL1/SND.WL2 guards to window updates so reordered ACKs cannot
  regress the send window.
- Fully `reset()` a pool socket returned to LISTEN by an RST in
  SYN-RECEIVED; today `tsval_generator = None` and `remote_win_shift = 0`
  from the reset peer survive into the next connection (no PAWS, 64 KiB
  window). Narrow race, since sys-io drops a socket it sees in LISTEN.
- Split the per-socket challenge-ACK budget from mandatory ACKs. One 1/s
  bucket serves RFC 5961 challenges, PAWS rejects, out-of-window and
  zero-window ACKs, and LAST-ACK duplicates, and half of arbitrary ACK values
  trigger it, so a blind sender can starve probe and FIN-retransmit ACKs.
- Run netstack timers on a monotonic clock. `time.rs` `Instant::now()` is
  `SystemTime`; a forward step of 300 s aborts every idle connection, a
  backward step freezes every timer.

### Netstack ingress and egress

- Evict when the reassembly slots are full. Four slots, first-free, held to
  expiry including tombstones, so four spoofed fragments per minute drop all
  legitimate fragmented ingress. Memory is already bounded; evict the oldest
  or a slot that never saw offset zero.
- Narrow what a forged Fragmentation Needed can do. The UDP association
  accepts any 4-tuple sent to in the last 60 s (the resolver's port is
  guessable), and the PMTU cache is per destination, so a UDP-validated
  forgery throttles every TCP connection to that host for ten minutes,
  renewable. Consider a higher floor for UDP-associated updates and
  per-flow state for TCP.
- Extend the off-loopback filter to `::ffff:127.0.0.0/104`; only `::1` is
  dropped today.
- Stop returning success for an IPv6 non-UDP packet over the path MTU
  (`iface/interface/mod.rs` "supported only for UDP"); reachable for an
  ICMPv6 echo reply to a reassembled oversize request and sys-io's own ICMP
  socket.
- State in the operator documentation that ARP/NDP spoofing is accepted as
  Linux parity: unsolicited ARP requests, NS, and NA with OVERRIDE still
  rewrite a cached MAC (`neighbor.rs` `fill_unsolicited`); the landed
  correlation gates eviction only. Optionally offer static neighbor entries
  for gateways in `sys-net.toml`.
- Key IPv6 fragment identifiers as IPv4's are; the per-boot PCG stream is
  predictable after a few observations (RFC 7739).

### sys-io as a service

- Recover virtio RX-ring initialization when the first buffer allocation
  fails. Deficit repair depends on a later RX completion; if no buffer was
  posted, none can arrive and the device's RX task exits permanently. Cover
  both zero-buffer startup and partial-ring recovery without adding boot work
  on the successful path.
- Add per-process quotas: channels (one process can hold all 896, after
  which every other process is refused), sockets and listeners (no count
  limit anywhere), and committed ring bytes (two 8 MiB rings per socket at
  creation). Port squatting on 22/80/443 by any role is part of the same
  gap.
- Retune the memory-pressure model. The kernel flag trips at 2 MiB free and
  clears at 3 MiB; `pressure.admit()` passes a 16 MiB ring request at 5 MiB
  free and the allocator then aborts sys-io, and while the flag is up every
  new client and every listener replenish is refused for all tenants until
  the hog exits.
- Record the capacity: 896 net channels times four subchannels is about
  3,500 concurrent sockets per machine, one 64 KiB-stack client thread per
  channel, and kernel work per sys-io park proportional to registered
  handles (the wait-set item in `future-work.md`).
- Close the listener teardown race: `accept()` and cookie restore hold an
  `Rc<TcpListener>` across awaits, and `unregister_and_drop`/`hard_reset`
  assert they hold the last reference; a socket reaching ESTABLISHED in that
  window panics sys-io. Same family as the `58622c82` fix.
- Small trust-boundary nits: the subchannel index from `args_8[23]` is
  guarded only by `debug_assert!`; a second `TcpStreamClose` on a lingering
  socket races the linger task against `assert!(!base.lingering)`; the
  `runtime/mod.rs` comment claims server-page double frees panic when the
  code kills the client.

### Client path

- Remove canceled native `TcpListener` accept waiters immediately. Every
  canceled `accept()` leaves its oneshot sender queued until a connection
  arrives or the listener closes, so repeated cancellation against an idle
  listener grows memory without bound.
- Align TCP shutdown, reset, and failed-connect readiness with immediate I/O
  and stored errors. Raise the write-closed edge after local
  `shutdown(Write)`, synthesize it at registration, report `POLL_ERROR` for a
  failed connect and peer reset, and retain the reset in TCP `SO_ERROR`.
- When nonblocking connect cannot use the transient channel staging queue,
  fall back to the guaranteed driver FIFO instead of reporting `WouldBlock`
  as a hard connect failure.
- Include staging-queue room in the "can write" predicate. When `post_msg`
  fails on a full staging queue the page is retracted and WRITABLE is raised
  synchronously, so mio, tokio, and native `try_write` spin until the TX task
  drains.
- Return real error codes. sys-io's `util.rs` maps refused, reset,
  unreachable, aborted, and broken-pipe conditions all to `NotConnected` and
  has `todo!()` arms that would abort sys-io for any new `io::ErrorKind`;
  add `ConnectionRefused`, `BrokenPipe`, and the unreachable codes to moto-rt
  and the toolchain std together (see the ECONNRESET precedent).
- Fail a UDP send to an unroutable destination instead of dropping it
  silently without an ack; a queue of such datagrams never yields WRITABLE.
- Try every resolved address in std `TcpStream::connect` (Motor's std takes
  only the first); return the bound address from `local_addr` during a
  nonblocking connect; make `SO_KEEPALIVE` configurable (always on today).
- Raise DNS capacity: one IPC connection per lookup into four synchronous
  resolver workers, so a 33rd concurrent client gets `NotConnected` from
  name resolution.

### Platform and gate

- Read virtio link status and react to carrier changes
  (`VIRTIO_NET_F_STATUS` is commented out); document that MTU comes only
  from `VIRTIO_NET_F_MTU` or 1500, and that the neighbor cache holds 64
  entries.
- Gate cloud-hypervisor and firecracker boots, and TLS on the main image;
  today all gates boot qemu, chv and fc are exercised only against a fake
  VMM, and the only in-VM TLS leg is the dev-image `gears-test.sh`.

## (c) Lower priority: completeness

Within this section, correctness and resource robustness come before protocol
features, performance work, and cleanup.

### Socket lifecycle

- Give ephemeral allocation and explicit TCP/UDP binds one authoritative port
  reservation view. Check all live bindings, retry occupied candidates, and
  preserve loopback simultaneous-open behavior.
- Fix `close()` in SYN-RECEIVED mistaking the SYN's ACK for the FIN's ACK
  (`sent_syn` is derived from the current state). Latent: sys-io aborts pool
  sockets rather than closing them.
- Make `moto-async` oneshot `send` observe a concurrent receiver drop
  atomically; it can return `Ok` after the receiver is gone. Benign today
  because every dropped payload self-heals.
- Allow sockets as child stdio and across spawn, or document that they are
  not inheritable (`Command::stdin(Stdio::from(TcpStream))` fails today).

### TCP protocol completeness

- Seed TS.Recent in the Listen and SynSent SYN paths. The general update's
  window base is uninitialized during the handshake, so some connections emit
  TSecr=0 until Established, lose the handshake RTT sample, and begin with PAWS
  disarmed. The cookie-restore path already has the required behavior.
- Include RFC 8985's delayed-ACK allowance (WCDelAckT, approximately 200 ms) in
  the TLP timeout for single-segment flights. The current 10 ms floor can cause
  a spurious probe on request/response traffic and make DSACK widen RACK's
  reordering window.
- Apply Karn's rule when RACK/TLP staging retransmits the segment used for the
  RTT sample; today only the RTO branch invalidates that sample.

### Netstack behavior

- Associate remaining incoming ICMP destination-unreachable errors with their
  validated TCP/UDP flows. Connected UDP should expose asynchronous errors via
  `SO_ERROR` and ERROR readiness without allowing forged ICMP to affect an
  unrelated flow.
- Answer duplicate-address and address-conflict probes (NS from `::`, ARP
  probes from `0.0.0.0` are dropped today), so peers running RFC 4862/5227
  detection learn they collide with our static address.

### Cross-cutting cleanup and documentation

- Correct memory accounting and operator comments for half-open and spare
  listening sockets. They use the 16 KiB-per-direction lazy ring floor, not the
  128 KiB full rings. Measure object/ring costs before retuning the limits and
  account for established sockets separately.
- Add a `docs/` reference for `sys-net.toml`. Document every key and deployed
  feature limit, correct half-open/listener memory figures, and cover
  `auto_icmp_echo_reply`, `loopback`, and completed-connection backlog
  semantics. Include the deployed-feature support statement (no DHCP, SLAAC,
  multicast, raw sockets, or general IPv6 extension headers), the reduced RFC
  6724 source-selection policy, and the capacity figures from (b).
- Record the accepted non-POSIX exception that a graceful close of a
  connection which never sent a byte is reset rather than FIN-closed
  (`runtime/net/socket/tcp.rs`, in-code rationale), and the mio-test
  expectations widened for it (`close_on_drop.rs`, `poll.rs`).
- Relocate the performance method record dropped from this file on
  2026-08-21 (paired same-sitting A/B, launcher pinning, the `ab81c861`
  reference, the 64-stream scale reference, the receive-coalescing resume
  notes) to a `docs/` page or state that git history is its home.
- Update `README.md`: it still says DNS lookup is not implemented and that
  most pieces are not ready for production use; make it agree with this file.
- Remove `src/sys/sys-io/Cargo.lock`; Cargo uses the workspace lock at
  `src/sys/Cargo.lock`.
- Client UDP receive-queue overflow has no reason-specific counter
  (`moto-io/src/net/udp.rs` discards the `dropped` result); the UDP TX bounds
  are fixed constants rather than charged to the channel-page budget. Either
  add the counter and the charge, or amend the intent.

### Protocol and feature work

These need scope/design decisions before implementation. DHCPv4 moved to
(a) as the per-instance configuration item.

- Design and enable IPv6 SLAAC. The netstack feature is not in the deployed
  sys-io closure, so router advertisements currently do not configure
  addresses.
- Add multicast support through the netstack, sys-io, moto-io, rt.vdso, and std
  entry points.
- Decide whether and how to expose raw sockets securely, then enable them if
  approved.
- Extend the production IPv6 parser beyond the base header and its current
  single Hop-by-Hop case with a reviewed, bounded extension-header policy.
- Complete RFC 6724 IPv6 source-address selection rules 3 through 7. Rules 1,
  2, and 8 exist; deprecation, temporary-address, label, and outgoing-interface
  selection remain.
- Decide on a network privilege boundary: today any role binds any port and
  requests maximum buffers, and russhd's pre-authentication code runs with
  the interactive user's authority (`docs/process-roles.md` calls this
  interim).

### Conditional architecture and performance work

- Decide whether to merge or formally project the 7-state client TCP ABI and
  the 11-state protocol enum. Any merge needs an ABI compatibility plan.
- Profile before attempting zero-copy token work. Similarly, replace sys-io's
  per-page `BTreeMap` lookup with a generation-and-slot slab only if profiling
  shows the lookup matters.
- Measure before addressing the smaller hot-path candidates: TSO truncation at
  TX-ring wrap, the u16-at-a-time checksum loop, per-packet cloning of
  `DeviceCapabilities`, and unfiltered `net_trace!` formatting.
- Investigate the Cloud Hypervisor host-to-VM packet-rate cap and guest-offload
  support if that backend's receive throughput becomes a target.
- Revisit receive coalescing only for a workload that needs more than the
  current single-stream RX ceiling without jumbo frames. The portable design
  candidate is `GUEST_TSO4/6` with 64 KiB posted RX buffers; acknowledge those
  features and enlarge buffers atomically.
- Add receive autotuning only after a real workload shows fixed defaults plus
  per-socket sizing are insufficient.
- Unify ephemeral-port randomization once connect can pin its source port and
  the loopback exemption can be removed.

### Test debt

- Add an in-VM SYN-cookie engage/restore test when a safe packet-injection seam
  or reviewed low-cap test configuration exists.
- Add direct regressions with their corresponding fixes for: abort/RST
  transmit completion (the await landed without a test), the invalid
  `sys-net.toml` abort and the valid zero-device configuration (only a
  parse-level self-test exists), RX-ring deficit repair (arithmetic self-test
  only; now the basis of the (b) init-recovery item), undersized virtio TX
  queue rejection (compile-time asserts only), sys-io-side UDP TX admission
  and `BufferFull` drop counters, the UDP RX byte bound and mid-reassembly
  drop, the global 128 completed-backlog cap in-VM, a neighbor advertisement
  whose source differs from its target, and `::ffff:127/104` ingress.
- Add a regression for the listener-abort fix identified by commit `58622c82`.
- Add test seams for the RDRAND retry path and external-device checksum arm if
  those paths are changed.
- Make the end-to-end negative DNS fixture deterministic without adding a
  check-side retry or weakening mixed-family error semantics. Cover name-wide
  `NotFound` and transient mixed-family outcomes.
- Plain `cargo test` in the netstack omits `proto-ipv6-fragmentation`; the
  IPv6 fragmentation and Packet Too Big tests compile only under the gate
  scripts' feature closure.

### Watch list

- If external DNS or ping failures remain visible, determine whether both A
  queries were lost or host NAT failed, then revisit resolver/NAT remedies.
- If `moto_async::test_event_stream` again fails on a legal spurious wake, make
  its expectation resynchronize instead of requiring strict alternation.
- If `udp_rebind_after_close_test` recurs, reopen the close/rebind diagnosis.
- If the debug-VM ssh output freeze recurs often enough to investigate, capture
  stacks and output-path state before changing the harness.
