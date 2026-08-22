# Networking: remaining steps

This file tracks only unfinished Motor OS networking work, in priority order.
Historical designs, diagnoses, patch sequences, gate transcripts, and
measurements remain available in git history.

No implementation series is currently selected. Select and review a bounded
series before changing code; larger work needs a dedicated design round. The
highest-priority work below should not wait for DHCP or another feature effort.

## Quick simplification first

These are ahead of the stabilization work only because they are bounded
deletions that shrink active hot paths or remove misleading configuration
surface. If either uncovers non-obvious coupling or grows beyond straightforward
deletion and rewiring, stop it rather than delaying the highest-priority items.

- COMPLETED: Make Cubic the only TCP congestion controller. Deployed sys-io and both full
  test scripts select only Cubic; the only other controller-selection callers
  are netstack tests. Remove Reno, `NoControl`, their feature/fallback paths,
  and the public `CongestionControl` selector API; compile Cubic whenever TCP
  sockets are enabled and replace `AnyController`/dynamic dispatch with a
  concrete Cubic field. Also remove sys-io's now-redundant explicit Cubic
  selection. This deletes a broken unused Reno implementation and makes it
  impossible to build TCP accidentally without congestion control.
- COMPLETED: Remove the temporary PDIAG readiness instrumentation end to end. This is
  naturally two bounded deletion patches if needed: first remove moto-io's
  per-channel RXSTALL/TXSTALL watchdog, `StreamDiag`, data-path stamps, and
  listener logging hook; then remove rt.vdso's `SourceDiag`/`RegistryDiag`
  counters, registry watchdog/map, and remaining logging plumbing. Commit
  `5b1c83f6` added about 400 lines for a completed wedge diagnosis. Keeping it
  costs periodic tasks and allocations plus timestamps and relaxed atomic
  operations on readiness paths, while RXSTALL can flag ordinary read-side
  backpressure.

## Highest priority

These are small, high-consequence stabilization items. Land them before wider
network exposure or a release that treats networking as robust.

- Clamp an advertised peer MSS to a safe minimum. Accepting MSS=1 permits a
  crafted SYN to turn the send path into one-byte packets. This is reachable
  before application authentication on externally listening services.
- Rate-limit ICMP error replies (UDP port unreachable, protocol unreachable,
  and IPv6 parameter problem) with a dedicated `max_icmp_error_rate` token
  bucket. Keep loopback exempt; the approved default is 200 replies per second.
  Without a bound, spoofed-source traffic can use an external interface as a
  reflector and consume sys-io at packet rate.
- Make an invalid `sys-net.toml` abort sys-io startup loudly. Do not continue
  without loopback and the net-channel listener after a parse failure. Preserve
  the supported, intentional no-listener outcome for a valid configuration
  containing zero devices, and log/test the two cases distinctly.
- Reject virtio-net devices with fewer than 18 raw TX descriptors during
  initialization. The TX headroom loop otherwise unwraps an empty completion
  deque for legal 8- or 16-descriptor queues.

## Must do before L2 deployment

Here, L2 deployment means attaching Motor OS to a shared or untrusted Ethernet
segment. A host-private TAP used for development does not count. The MSS clamp
and ICMP error rate limit above are also prerequisites; they remain in the
highest-priority section because they matter before L2 deployment.

- Harden neighbor-cache admission. Correlate ARP replies and NDISC Neighbor
  Advertisements with recorded probes, enforce Neighbor Advertisement
  destination/flag rules, key entries by the advertised target, and make
  uncorrelated advertisements non-evicting. This limits admission/eviction
  attacks but does not authenticate on-link peers.
- Before assigning an external device an IPv6 address, extend the
  external-ingress loopback-source filter beyond IPv4 127/8.

## Remaining things to do for completeness

These can wait for a larger networking effort. Within this section, correctness
and resource robustness come before protocol features, performance work, and
cleanup.

### Socket lifecycle and resource robustness

- Complete `SO_LINGER(secs > 0)` close RPCs. Pass the close request to the
  linger task and reply when linger resolves instead of leaving an awaiting
  client parked forever. The ordinary moto-io drop path is fire-and-forget, so
  this does not make every positive-linger close hang, but the RPC contract is
  incomplete.
- Make a TCP writer that was already parked when reset/closure arrived return
  the stored reset or broken-pipe error when it committed zero bytes. Preserve
  partial-write semantics when it committed data.
- On `UdpSocket::close`, wake RX and TX waiters and reject every later send or
  receive consistently; a closed socket must not report success for a datagram
  it cannot transmit.
- Restore RX ring depth after transient buffer-allocation failures. Track the
  deficit caused by a failed `pop_buf` and refill it on a later successful
  poll.
- Replace `drop_tcp_socket`'s fixed 1 ms delay with an explicit
  transmit-completion/state condition so an abort is not removed before its RST
  reaches the device.
- Bound each listener's queued native `pending_accepts` RPCs at 1,024 and reply
  to every queued request with a closed/canceled error during teardown.
- Bound the per-socket UDP TX queue by bytes and datagrams before channel
  fragments are copied out of their pages. On admission overflow or netstack
  `BufferFull`, drop the complete newest datagram immediately and increment a
  reason-specific counter; do not retain partial datagrams or park a datagram
  without a send-waker. The finite channel-page budget is an indirect global
  bound today, not a per-socket admission policy.
- Bound the client UDP RX defragmenter by bytes and datagrams from the existing
  channel-page budget. Apply the same bound to partial reassembly and drop the
  complete newest datagram on overflow with a reason-specific counter.
- Give ephemeral allocation and explicit TCP/UDP binds one authoritative port
  reservation view. Check all live bindings, retry occupied candidates, and
  preserve loopback simultaneous-open behavior.
- When nonblocking connect cannot use the transient channel staging queue, fall
  back to the guaranteed driver FIFO instead of reporting `WouldBlock` as a
  hard connect failure.
- Align TCP shutdown, reset, and failed-connect readiness with immediate I/O
  and stored errors. Raise the write-closed edge after local
  `shutdown(Write)`, synthesize it at registration, report `POLL_ERROR` for a
  failed connect and peer reset, and retain the reset in TCP `SO_ERROR`.
- Accept wildcard ephemeral binds such as `0.0.0.0:0` and let sys-io choose the
  concrete address and port.
- Remove canceled native `TcpListener` accept waiters immediately instead of
  retaining their oneshot senders until a connection arrives or the listener
  closes.

### TCP protocol completeness

- Ignore an old ACK field while still processing in-window payload. The current
  path drops the whole segment, contrary to RFC 9293.
- Add SND.WL1/SND.WL2 guards to window updates so reordered ACKs cannot regress
  the send window.
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
- Replace or guard the TCP Listen-state `unreachable!()` at
  `netstack/src/socket/tcp.rs` with a defensive drop/debug assertion local to
  the socket, so demux or cookie-restore regressions cannot turn network input
  into a release panic. The current demux and `accepts()` invariants prevent an
  ordinary packet from reaching it; this is defense in depth.

### Cross-cutting cleanup and documentation

- Correct memory accounting and operator comments for half-open and spare
  listening sockets. They use the 16 KiB-per-direction lazy ring floor, not the
  128 KiB full rings. Measure object/ring costs before retuning the limits and
  account for established sockets separately.
- Add a `docs/` reference for `sys-net.toml`. Document every key and deployed
  feature limit, correct half-open/listener memory figures, and cover
  `auto_icmp_echo_reply`, `loopback`, and completed-connection backlog
  semantics.
- Remove `src/sys/sys-io/Cargo.lock`; Cargo uses the workspace lock at
  `src/sys/Cargo.lock`.

### Protocol and feature work

These need scope/design decisions before implementation:

- Design and enable DHCPv4 in deployed sys-io, including ownership of lease
  lifecycle, addresses, routes, and DNS configuration.
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
- Add direct regressions with their corresponding fixes for UDP close with
  parked waiters, reset arriving at an already parked TCP writer, abort/RST
  transmit completion, and valid zero-device configuration.
- Add a regression for the listener-abort fix identified by commit `58622c82`.
- Add test seams for the RDRAND retry path and external-device checksum arm if
  those paths are changed.
- Make the end-to-end negative DNS fixture deterministic without adding a
  check-side retry or weakening mixed-family error semantics. Cover name-wide
  `NotFound` and transient mixed-family outcomes.

### Watch list

- If external DNS or ping failures remain visible, determine whether both A
  queries were lost or host NAT failed, then revisit resolver/NAT remedies.
- If `moto_async::test_event_stream` again fails on a legal spurious wake, make
  its expectation resynchronize instead of requiring strict alternation.
- If `udp_rebind_after_close_test` recurs, reopen the close/rebind diagnosis.
- If the debug-VM ssh output freeze recurs often enough to investigate, capture
  stacks and output-path state before changing the harness.
