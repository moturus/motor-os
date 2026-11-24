# Remaining networking work

## TCP correctness

- Use a monotonic clock for netstack timers. `time::Instant::now` reads
  `SystemTime`, so a clock correction can advance or suspend timeouts.
- Keep TCP timestamps monotonic across SYN-cookie restoration and obtain an
  initial RTT sample for the restored connection. Seed TS.Recent from the
  incoming SYN on ordinary passive and active handshakes.
- Use saturating header subtraction wherever a path MTU determines the TCP
  payload. Define a usable IPv4 floor that accounts for TCP options.
- Process in-window payload independently of an old ACK field. Apply
  SND.WL1/SND.WL2 when updating the send window. Give mandatory ACKs and
  RFC 5961 challenge ACKs separate budgets.
- Clear per-peer options when a reset returns a SYN-RECEIVED socket to
  LISTEN. Distinguish acknowledgement of the SYN from acknowledgement of
  a FIN if a socket is closed during the handshake.
- Apply Karn's rule to RTT samples when RACK or a tail-loss probe
  retransmits the sampled segment. Include the delayed-ACK allowance in
  the probe timeout for a single-segment flight.

## IP and the device driver

- Define an eviction policy when fragment-reassembly slots are full,
  including entries held after a datagram is discarded. Use keyed IPv6
  fragment identifiers.
- Limit the effect of UDP-validated path-MTU updates on unrelated TCP
  flows to the same destination. Deliver other validated ICMP errors to
  the originating flow, including asynchronous errors on connected UDP.
- Extend off-loopback address checks to IPv4-mapped IPv6 loopback
  addresses. Report an error when an oversized non-UDP IPv6 packet cannot
  be transmitted. Respond to duplicate-address probes for static IPv4
  and IPv6 addresses.
- Document when unsolicited ARP and NDP messages may refresh a cached
  mapping. Decide whether deployments need static neighbor entries for
  gateways.
- Recover a virtio RX queue if the first buffer allocation fails. Deficit
  repair needs an RX completion, which cannot arrive on an empty queue.
  Preserve the ordinary startup path. Handle carrier changes reported
  through the virtio link-status feature.

## Service resources and socket behavior

- Decide per-process limits for network channels, sockets, listeners and
  committed ring memory among clients with `CAP_NET`. Decide separately
  who may reserve service ports. Size the limits using idle, half-open and
  established sockets, channel threads and kernel wait-set costs.
- Remove a canceled `TcpListener::accept` waiter from the SDK queue even
  on an idle listener. Make oneshot delivery and concurrent receiver
  closure agree on whether a value was accepted.
- Make poll registration and delivery agree about write closure after
  local shutdown and pending errors after connect failure or peer reset.
  Retain an established connection's reset for `SO_ERROR`.
- A nonblocking connect can return `NotReady` when the channel staging
  queue fills. Give it a way to queue the request. TCP write readiness
  also needs to account for room to enqueue a TX marker when accepting
  another page.
- Preserve refused, reset, unreachable and broken-pipe errors through
  sys-io's native error mapping. Replace its unhandled-error `todo!()`
  with a defined result. Report an unroutable UDP send and release its
  send credit on the `Unaddressable` path.
- Record client UDP receive-queue overflow and relate TX limits to the
  channel page budget. Make the bound local TCP address available while a
  nonblocking connect is in progress and expose configurable keepalive.
- The Motor stdlib TCP connector consumes only the first resolved address
  and unwraps an empty iterator. Handle empty results and try the remaining
  addresses before returning an error. Review lookup capacity under load
  with four synchronous DNS IPC workers.
- Unify explicit and ephemeral port reservation within each transport.
  Preserve wildcard binds, live TCP tuples and simultaneous open on
  loopback when changing port selection.
- Decide whether sockets should be inheritable across spawn as child
  stdio. Clarify the supported behavior in the socket documentation.
- Correct the description of server-page double frees on sys-io's
  `on_channel_error`. It terminates the peer for both page-error cases.
  Remove the redundant `src/sys/sys-io/Cargo.lock` if the workspace
  lockfile is the sole supported build input.

## Protocol features and operator documentation

- Design production IPv6 autoconfiguration as one address and route
  lifecycle. Router Advertisements supply the default router, SLAAC can
  supply addresses, and DHCPv6 can supply addresses or other settings.
- Decide the scope of multicast, raw-socket access and bounded IPv6
  extension-header parsing. Complete the applicable RFC 6724 rules for
  source selection, including address state, labels and outgoing interface.
- Document the 16 KiB per-direction starting allocation for a spare or
  half-open TCP socket separately from the configured established-socket
  sizes. Include MTU selection, neighbor capacity and the reset a peer can
  see when a connection closes without having transmitted any bytes.
  [Networking configuration](../networking.md)

## Coverage gaps

- Cover SYN-cookie restoration end to end and the global completed-accept
  backlog across multiple listeners in a guest. Exercise the TCP accept
  path when its client process exits with a request still queued. Check
  that an abort's reset reaches the peer before socket teardown.
- Exercise startup with invalid configuration and with zero devices,
  recovery from empty or partially filled RX rings, and rejection of an
  undersized virtio TX queue. Add coverage of randomness retries and
  external-device checksums when those paths change.
- Cover sys-io UDP TX admission and buffer-full drop accounting, the
  receive byte limit during fragmented delivery, neighbor advertisements
  whose source differs from the target, and mapped loopback addresses.
- Make the end-to-end negative DNS fixture deterministic, including
  name-wide absence and a transient failure in only one address family.
  Make IPv6 fragmentation coverage discoverable to contributors running
  the netstack's default unit-test configuration.

## Performance decisions

- Measure memory and throughput on the target workload before raising the
  default TCP ring sizes or adding receive autotuning. Assess the cost of
  projecting the client ABI's TCP states from the protocol states before
  changing either representation.
- For small host-to-guest writes, measure bounded RX batching, read-side
  polling and wakeups per packet. If Cloud Hypervisor receive throughput
  becomes limiting, distinguish backend packet-rate limits from guest
  processing. Evaluate guest receive coalescing only together with buffers
  large enough for the negotiated segment size.
- Profile before changing packet copies, per-page lookups, TSO at ring
  wrap, checksum loops, capability cloning or trace formatting. The
  channel-slot wakeup and intermittent debug loopback resets have separate
  investigations in [future work](future-work.md).
