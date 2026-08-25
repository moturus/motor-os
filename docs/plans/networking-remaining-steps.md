# Networking: remaining steps

This file tracks only unfinished Motor OS networking work. Historical designs,
diagnoses, patch sequences, gate transcripts, and measurements remain
available in git history.

## Current status

As of 2026-08-23, we believe Motor OS networking is ready for production
deployment within its currently supported feature set and deployment model.
The critical shared-L2, sys-io availability, TCP lifecycle, client-path, and
deployment-prerequisite findings from the full review are fixed and covered by
the networking gate. The final gate ran three times each in debug and release.

The production-ready path includes static IPv4/IPv6 configuration, DHCPv4
address/default-route/DNS lifecycle, native DNS resolution, TCP and UDP,
family-correct wildcard listeners, bounded neighbor discovery and queues,
TCP TIME-WAIT retention, and fail-stop diagnostics if sys-io terminates.

This is not a claim of protocol completeness. In particular, DHCPv6, SLAAC,
and Router Advertisement address/route configuration are intentionally
deferred. IPv6 currently requires static addresses and routes. Multicast, raw
sockets, and general IPv6 extension-header support are also unavailable.
Production image policy and credential provisioning remain separate pipeline
work. Deployments with mutually untrusted local processes or an untested VMM
need a separate review of the quota and platform-gate items below.

The remaining items are follow-up robustness, completeness, documentation,
and test work. Within each group, order is the suggested pickup order.

## Medium priority: robustness

### TCP protocol

- Carry a per-connection timestamp offset across SYN-cookie restore.
  `syn_cookies.rs` repurposes the low six bits of the advertised TSval, so it
  can run up to 63 ms ahead of our clock; a Linux peer PAWS-discards every
  segment we send until the clock catches up, and the restored socket has no
  RTT sample (TLP disarmed, RTO at the 1 s initial value).
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

## Lower priority: completeness

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
- Expand `docs/networking.md` to document every `sys-net.toml` key and deployed
  feature limit, correct half-open/listener memory figures, and cover
  `auto_icmp_echo_reply`, `loopback`, and completed-connection backlog
  semantics. Include the deployed-feature support statement (DHCPv4 but no
  DHCPv6/SLAAC/Router Advertisement configuration, multicast, raw sockets, or
  general IPv6 extension headers), the reduced RFC 6724 source-selection
  policy, and the capacity figures above.
- Record the accepted non-POSIX exception that a graceful close of a
  connection which never sent a byte is reset rather than FIN-closed
  (`runtime/net/socket/tcp.rs`, in-code rationale), and the mio-test
  expectations widened for it (`close_on_drop.rs`, `poll.rs`).
- Remove `src/sys/sys-io/Cargo.lock`; Cargo uses the workspace lock at
  `src/sys/Cargo.lock`.
- Client UDP receive-queue overflow has no reason-specific counter
  (`moto-io/src/net/udp.rs` discards the `dropped` result); the UDP TX bounds
  are fixed constants rather than charged to the channel-page budget. Either
  add the counter and the charge, or amend the intent.

### Deferred IPv6 autoconfiguration

- Defer DHCPv6, SLAAC, and Router Advertisement address/default-route
  configuration until a later design effort. When resumed, treat them as one
  lifecycle: Router Advertisements provide the default router, SLAAC may
  provide addresses, and DHCPv6 may provide addresses or other configuration.
  Static IPv6 remains supported in the meantime.

### Protocol and feature work

These need scope/design decisions before implementation.

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
- If `udp_rebind_after_close_test` recurs, reopen the close/rebind diagnosis.
- If the debug-VM ssh output freeze recurs often enough to investigate, capture
  stacks and output-path state before changing the harness.
