# WireGuard through a process-backed IP device

Completed steps: 0 through 4.
Current step: 5 - ping through packet devices.

2026-10-24. Design and implementation plan, grounded in the tree at
a3d739f9. This document specifies the process-backed IP device, WireGuard
integration, configuration, order of work and acceptance gates. Exact Rust
interfaces, wire encodings and module layout are left to the implementation
steps.

## Architecture and scope

`wg` is a separate process holding WireGuard keys, peers, cryptographic
state and timers. It registers an IP device with sys-io and exchanges
complete inner IP packets over native IPC. sys-io owns the inner TCP/IP
stack and all application sockets. `wg` sends encrypted packets using
ordinary UDP through sys-io's physical network.

| Component             | Responsibility                                                           |
|-----------------------|--------------------------------------------------------------------------|
| sys-io                | Application socket protocol, TCP/UDP/ICMP, interface routes and sources, |
|                       | socket admission, physical NICs and outer UDP delivery                   |
| Packet-device adapter | Device registration, bounded packet transfer, notifications and removal  |
| `wg`                  | Config and keys, peer ownership, WireGuard authentication/encryption,    |
|                       | endpoint learning, outer UDP sockets and timers                          |
| Applications          | Existing socket APIs and the existing sys-io connection pool             |

```text
+-------------------------+
|       Application       |
+-------------------------+
             ^
             | Socket IPC
             v
+-------------------------+
|  sys-io: inner TCP/IP   |
+-------------------------+
             ^
             | IP packet IPC
             v
+-------------------------+
|  wg: peers and crypto   |
+-------------------------+
             ^
             | UDP socket IPC
             v
+-------------------------+
|  sys-io: physical UDP   |
+-------------------------+
             ^
             |
             v
+-------------------------+
|      Physical NIC       |
+-------------------------+
```

The two sys-io boxes are one process. The packet boundary allows crypto to
fail independently while keeping one socket server. Applications retain
their existing socket APIs and sys-io connection pool; `wg` exchanges IP
packets and does not run another TCP/IP stack.

V1 supports IPv4/IPv6 IP packets, one device per registration channel and
MTU 1420 for WireGuard. Multiple devices, such as `wg0` and `wg1`, may be
registered concurrently and unregistered independently, within the device
quota. This is an IP device, not an Ethernet/TAP device.
V1 includes Motor's `ping`: ICMPv4/ICMPv6 Echo Request/Reply through the
tunnel, both guest-initiated probes and policy-controlled replies to peers
that ping a local tunnel address.
Inter-interface forwarding, bridging, automatic transport failover,
persistent devices, live configuration reload and a persistent kill switch
are outside v1. Boot and launch policy are outside this plan: `wg` is
started by the user.

Device lifecycle is part of this plan: a device is added when `wg` registers
and removed when `wg` unregisters or exits. Routes and addresses come and go,
sockets on a removed device fail, listeners are updated and queued work is
released.
Step 2 completes removal safety; step 3 exposes registration together with
live-operation tests. Step 4 extends UDP invalidation to physical
transport-address loss; step 5 expands ping coverage.

## Design decisions

* `wg` retains boringtun's upstream `ring` backend. The separate `wg`
  workspace owns its crypto dependencies and C/assembly build requirements;
  they stay outside the core workspace.
* Keys and configs live under `/user/cfg/wireguard/`. The binary ships as
  `/system/bin/wg`.
* `wg` is started by the user; starting it at boot is out of scope.
* The boringtun fork is work outside this repository. It is announced
  explicitly when it starts (step 0).

## Registration and ownership

`wg` opens its physical UDP transport and a dedicated connection to the
existing `sys-io` service, then registers its interface. Conceptually:

```rust
RegisterIpDevice {
    name: "wg0",
    addresses: ["10.20.0.2/32"],
    routes: ["10.20.0.0/24"],
    mtu: 1420,
}
```

This describes the request data, not final Rust types. Addresses are local
interface addresses with CIDRs; routes are destination prefixes using this
device without a gateway. `wg` derives routes from its peers' allowed IPs.
Registration contains no keys, peer identities, endpoints or WireGuard
protocol state. The same operation must work for other IP-device providers.

sys-io retains normal `CAP_NET` admission, allows registration from System
or Interactive, and rejects None. It obtains PID and role from the kernel
channel metadata, using `SysObj::get_pid` and capabilities. There is no new
capability, URL ownership rule or authentication exchange. The existing
`sys-io` name is already kernel-reserved; `wg` publishes no service URL.

The reply confirms activation and establishes bounded packet transfer in
both directions. The dedicated channel identifies its one device; packet
and unregister messages do not select a device ID. Only that channel may
submit packets or unregister it. Unregister is terminal: registering again
requires a new channel, and later packet messages on the old channel are
rejected. A caller-supplied PID never establishes ownership. Internal tasks
and callbacks must handle removed slots safely; registering another device
with the same name must not retarget old work to it.

Validate bounded names, address/route counts, IP families and MTU before
activation. Local addresses and device names must be unique among registered
devices; route conflicts follow the deterministic rules below. A removed
device's name may be registered again on a new channel. Names, including
numeric suffixes such as the `0` in `wg0`, do not select a sys-io device
index. Require a local source address for every routed family. These are
interface validity checks, not an additional prefix-ownership permission
system.

Registration is transactional: reserve resources, construct the device and
check listener expansion before publishing it. Failure, cancellation or
channel closure rolls back partial state. Success means routes, addresses
and the packet consumer are ready together. The SDK must close the dedicated
channel if it abandons an in-progress registration.

## Packet transport and resource limits

Use the existing [io_channel and IoPage machinery](../../src/sys/lib/moto-sdk/src/ipc/io_channel.rs).
Each message describes one complete IP packet and its length. V1 packets
fit in one shared page; enforce a page-sized maximum negotiated MTU and
the IPv6 minimum MTU where applicable. Socket-level MTU handling stays in
the netstack: fragment where supported or report the applicable send error.
Never transfer packets larger than the registered MTU or fragment them in IPC.
WireGuard's fixed 1420-byte MTU is not a path-MTU guarantee.

* Outbound: sys-io emits an IP packet into the device's bounded TX queue.
  The IPC adapter transfers it to `wg`, which selects a peer, encrypts it
  and sends it through its physical UDP socket.
* Inbound: `wg` authenticates/decrypts outer UDP and checks inner source
  ownership before submitting the IP packet. sys-io validates its framing
  and delivers it to that device's `Interface` and `SocketSet`.

Use existing page ownership/release rules and checked page references.
Check message lengths before copying, and parse packets from private
bounded storage so shared-memory changes cannot invalidate prior checks.
Malformed IP packets are dropped and counted; malformed IPC follows the
existing channel-error policy and must not panic sys-io. A provider can
inject only through the interface belonging to its channel.

Keep `Interface::poll` synchronous over private RX/TX queues. A separate
adapter task transfers IPC messages; no runtime or queue borrow crosses an
await. A TX token reserves capacity before emission, including reply tokens
returned by receive. Exhaustion stops TX; releasing an unused token or
draining the queue restores capacity and wakes the poll task. Full RX drops
and counts packets rather than growing a queue. Page release and ring
capacity changes must wake blocked producers without polling or lost wakes.

Bound channels, live and retiring devices, addresses, prefixes, staging
bytes, and queued/in-flight packets. Initial candidates are four live and
retiring packet devices in total and 64 packets per direction per device;
account for the channel's fixed shared-memory allocation as well. Vacant
vector slots do not consume the live/retiring-device quota; their retained
storage is accounted for separately as described below. Fix concrete limits
during implementation and test their exhaustion and recovery. Reuse sys-io's
[channel budget](../../src/sys/sys-io/src/runtime/channel_budget.rs).

Application TCP/UDP sockets retain sys-io's existing global and per-listener
budgets, SYN cookies and pressure handling. Listener expansion must consume
those budgets. `wg` separately bounds peers, crypto buffers, pending
ciphertext and boringtun's internal queues; authentication replaces none of
these limits. Process packets in bounded batches and yield, preserving timer
and unrelated network/filesystem progress under sustained traffic.

## Interface integration and routes

Add a process-backed variant to
[NetstackDevice](../../src/sys/sys-io/src/runtime/net/device.rs), using
`Medium::Ip`, software checksums, no TSO and no DHCP or Ethernet neighbor
discovery.
It is external for randomized ephemeral ports and loopback-ingress rejection;
physical-transport selection must distinguish physical from virtual devices.

Every registered device gets the existing per-device `Interface`,
`SocketSet` and poll task. Change the
[runtime](../../src/sys/sys-io/src/runtime/net.rs) device vector to optional
entries, conceptually `Vec<Option<Device>>`. Boot-time devices keep their
indices. Each new registration appends `Some(device)` at the end, regardless
of its name or any vacant entries. Unregister removes the device from the
active vector by taking its entry, leaving `None` at the same index. Do not
compact or truncate the vector, shift devices or fill vacant slots in this plan.
Retiring state remains available to cleanup until its users have detached.

For example, after the boot-time entries:

```text
Register wg0 and wg1: [..., Some(wg0), Some(wg1)]
Unregister wg0:       [..., None,      Some(wg1)]
Register wg0 again:   [..., None,      Some(wg1), Some(wg0)]
```

Reusing vacant indices much later is future work and outside this plan.
There is no permanent guarantee that an index is never reused; any future
reuse must prevent stale references from reaching a new device. For now,
the vector's empty-slot storage grows with registration history even though
removed devices release their resources. This is an explicit limitation of
deferring slot reuse, not a requirement to retain removed-device state.

[Current routes](../../src/sys/sys-io/src/runtime/net/config.rs) require an
on-link gateway. Add explicit gateway-free interface routes in both runtime
device selection and netstack reachability. Preserve existing Ethernet
gateway validation and the `sys-net.toml` format.

Deterministic selection:

1. Preserve handling of destinations that are local addresses.
2. Use longest-prefix matching across connected, physical-gateway and
   registered interface routes. At equal length, connected routes win,
   then registered routes, then physical gateway routes. Keep existing
   physical-route tie behavior.
3. Reject identical registered prefixes on different packet devices;
   different-length overlaps are valid. A registered `/0` overrides the
   physical default while more-specific connected routes remain usable.
4. Select a configured source of the chosen device and destination family:
   prefer its most-specific containing local CIDR, otherwise its first
   configured address of that family. Respect explicit source binds.

Local CIDRs and remote routes stay separate: a local `/32` or `/128` must
reach remote prefixes outside that CIDR. The WireGuard peer table decides
ownership after routing; a packet with no peer owner is dropped. Registered
routes remain installed while a peer has no session or transport is
unreachable. No retry sends that selected plaintext via the physical default.

## Application sockets and physical UDP

TCP connects use normal sys-io route selection. Bind and listen
on registered local addresses work through the same socket service. Existing
wildcard TCP listeners gain and lose endpoints using
[address-change hooks](../../src/sys/sys-io/src/runtime/net/tcp_listener.rs).
This must work for listeners created before or after registration, subject
to ordinary port conflicts and admission limits; there is no merged accept
queue across processes.

An application UDP socket stays attached to its device. Binding a tunnel
address selects the packet device; ordinary wildcard binds retain physical
or loopback selection and do not start choosing virtual devices.
`connect` and `send_to` do not migrate sockets.
UDP to a local address is delivered locally, preserving the bound source
and receive-queue limits, subject to the device-boundary policy below.

Use the existing `udp_bind_for_remote` operation when the destination is
known at creation. Change the DNS resolver to use it for query sockets;
it selects the appropriate route and local source without redirects or a
new moto-rt/stdlib API. DNS-server configuration itself remains separate.
Drop and count ordinary datagrams that would cross the physical/virtual
device boundary or switch virtual devices. Preserve existing behavior
between physical devices; registering a packet device must not impose a
new restriction on unrelated physical UDP traffic. These per-datagram
policy drops do not invalidate the socket. UDP sends report local queue
acceptance, so this policy does not promise a synchronous `send_to` error
or an error queue for individual datagrams.

WireGuard transport sockets explicitly select a physical local address and
port, one socket per enabled outer address family. Their physical binding
bypasses registered interface routes, including `/0`, for all peer endpoints.
Expose that intent through the native SDK UDP bind path; exact message flags
are an implementation detail. This is not a general policy-routing API.
Keep existing physical UDP port reservations and cleanup.

Use one terminal UDP socket-invalidation notification for device removal
and loss of a transport's bound physical address. sys-io discards queued
traffic for the invalidated socket; the SDK marks it failed and wakes
waiting senders and receivers to observe the error. Subsequent sends and
receives fail. This notification is part of the native SDK/socket protocol,
not a new moto-rt/stdlib API or a general network-change subscription.

V1 uses stable configured physical addresses. Address loss/replacement
invalidates the affected transport binding through that notification and
discards queued output using the old source. `wg` treats this as fatal,
unregisters and closes its outer sockets; restart it to bind the new address.
No automatic rebinding or NIC failover is planned. Peer silence or temporary
transport unreachability does not invalidate the binding or withdraw tunnel
routes while registration remains alive. Peer endpoint roaming still works
within the available outer address families.

## Ping / ICMP echo (v1)

Motor's `ping` keeps its existing `IcmpEchoClient` connection to sys-io.
The `NetCmd::IcmpEcho` handler selects the packet device and an inner source
address, then sends via its ICMP socket and the ordinary packet IPC path.
Both ICMPv4 and ICMPv6 work independently of the outer UDP family; no
redirect handling or general-purpose raw-socket API is needed.

Incoming peer probes pass WireGuard authentication and allowed-IP source
validation before reaching sys-io's netstack. Preserve its existing
`auto_icmp_echo_reply` policy for the registered interface, enabling it in
inbound-ping tests. Replies to probes of a local tunnel address travel back
through the packet device and `wg`. Retain existing echo payload/MTU bounds,
reply source/identifier/sequence/payload matching, timeout and admission.

Transient ICMP sockets and identifiers participate in device lifetime
tracking. Removal cancels pending probes with an error and releases these
resources before reclaiming the device; a later timeout or guard drop must
not access a removed/reused device. Peer silence while it remains registered
times out normally, without plaintext fallback. All lifetime handling is
part of step 2 and is tested with live probes in step 3; it is not deferred
to the later ping-coverage step.

## Removal and failure behavior

Unregister or channel death withdraws the device's routes and local addresses,
stops packet delivery, detaches listener endpoints and fails sockets bound to
that device. Wildcard listeners keep their other endpoints. Stop poll tasks,
release pages and reservations, and finish pending operations with an error.
Leave `None` in the removed device's vector slot and keep retiring state
outside the active vector until users have detached. Repeated create/remove
must release removed-device sockets, tasks, pages, queue allocations and
channel-budget entries. The retained storage for vacant vector slots is
expected in this plan. UDP sockets use the terminal invalidation notification
described above.

Cleanup must handle queued packets, pending accepts, TCP TIME-WAIT, pending
ICMP echo requests and parked capacity waiters. Old callbacks must never
target a replacement device.
Explicit tunnel-only listeners fail on removal; existing connections do not
migrate to a physical interface. Physical and other virtual devices continue.

New connections after removal use remaining routes, including the physical
default. This is the agreed tunnel-off behavior; no persistent blocking
route is retained. A missing peer/session alone is not device removal.
`wg` closes its outer sockets when stopping; process death also invokes
ordinary sys-io client-channel cleanup.

## WireGuard process and protocol

Use a separate `src/bin/wg` workspace and lockfile, standard Rust and native
Motor APIs. Each process loads one config/key pair and registers one device;
multiple processes can provide independently managed devices. Keep boringtun
and its crypto dependencies outside the core sys workspace.

Use boringtun 0.7.1's `noise` protocol implementation, with one `Tunn` per
peer. Do not enable its platform-specific `device` daemon feature. The
embedding process calls `encapsulate`, `handle_verified_packet` and
`update_timers`; results request outer UDP output (`WriteToNetwork`), inner
IP delivery (`WriteToTunnelV4`/`WriteToTunnelV6`), completion (`Done`) or
error handling (`Err`). Replay protection, rekeying and keepalives remain
in boringtun; `wg` supplies peer ownership, dispatch, endpoint learning,
bounded I/O and timer scheduling as specified below.

### The boringtun fork

The fork work is **outside this repository**, in `../boringtun/`:
`github.com/moturus/boringtun`, branch `motor-os`, based on the 0.7.1
release commit `253f7afb2b3df9e952065d10bf2af19913cb176b`. Announce that work
explicitly when it starts. The user has reviewed and published the fork changes.
Pin revision `dcad5645547a89b278b346a399dbc0fae19a02f4` in `wg`'s git
dependency and lockfile. The fork has two changes:

1. Add a `std::time::Instant` fallback to `sleepyinstant` for targets that
   are neither Unix nor Windows, including Motor OS. Suspend-time accounting
   follows each target's `Instant` implementation. The existing `SystemTime`
   implementation supplies the handshake's TAI64N timestamp; no runtime or
   std changes.
2. Expose and document `Tunn::handle_verified_packet`, currently
   `pub(crate)`. Its caller must first use the device's shared
   `RateLimiter::verify_packet`. This permits dispatch without a second MAC
   check or limiter charge. Keep the normal public `decapsulate` checks.

Keep boringtun's crypto implementation unchanged. Before integration, run
upstream tests on Linux, including known-answer cipher tests and
`mock-instant` timer tests. Compile and link for the Motor target with its
random-source adapter as well. The reference peer uses unchanged upstream
0.7.1 with `ring` and a separate workspace/lockfile.

Register `getrandom` 0.2's custom backend over
`moto_sdk::rt::fill_random_bytes`, following
[russhd's adapter](../../src/bin/russhd/src/lib.rs). The standalone workspace
uses the existing Motor `ring` port from
[russhd's manifest](../../src/bin/russhd/Cargo.toml), plus the Motor
`parking_lot` and `parking_lot_core` patches already used in
[the core manifest](../../src/sys/Cargo.toml); these patches are not
inherited from other workspaces. No additional changes to the `ring` fork
are planned. Build its C/assembly sources with an explicit Motor-target
compiler configuration, such as `motor-clang`. Recheck the target dependency
closure after pinning the fork and its features.

### Peer ownership, dispatch and roaming

Maintain one longest-prefix owner table per registered WireGuard device.
TX looks up the inner destination; RX looks up the inner source and requires
the authenticated peer to be that address's owner. Different-length
overlaps are valid; duplicate exact prefixes and duplicate peer public keys
are rejected. A peer owning `/0` cannot send as an address assigned to
another peer's `/32` or `/128`. Check inner IP framing, lengths and MTU
before delivery. Drop and count packets with no owner; never send their
plaintext through the physical default.

Use one `Arc<RateLimiter>` per device, shared by all of its `Tunn`s, with
the upstream threshold of 100 handshakes/second before cookies. This is a
cookie threshold, not a hard CPU-work cap. Dispatch each datagram as follows:

1. Call `verify_packet(Some(outer_source.ip()), datagram, scratch)` before
   any X25519 operation. Send a cookie challenge back to that datagram's
   source and stop processing; drop verification errors. Neither a challenge
   nor a cookie reply authenticates a peer for endpoint learning.
2. For a handshake initiation, call `parse_handshake_anon` once with the
   device key pair and look up the recovered static public key. Do not try
   every peer. For handshake responses, cookie replies and data, look up
   `receiver_idx >> 8`. Give each `Tunn::new` a unique 24-bit peer index
   within this device, independent of the sys-io device-vector index.
   Reject unknown indices and public keys.
3. Call the fork's exposed `handle_verified_packet` for the selected peer.
   Do not pass the original datagram through `decapsulate` again: that
   repeats MAC verification and limiter accounting. Full handshake/session
   authentication and replay checks still occur in the verified handler;
   recovering a public key alone does not authorize an endpoint change.
4. Track the input packet kind as well as `TunnResult`. Successful handshake
   initiation/response handling returns `WriteToNetwork`; an authenticated
   empty data keepalive returns `Done`. Both must learn the outer source IP
   and port without requiring an inner packet. Cookies, authentication
   failures and replays never change endpoints. Inner IP source addresses
   never become outer endpoints. Endpoint learning is separate from the
   inner source-ownership check.
5. Send handshake responses to the authenticated datagram's source. When
   output requires a queued-packet flush, call `decapsulate(None, &[], scratch)`
   until `Done`, stopping on `Err` and respecting the work/buffer limits
   below. Preserve pending flush work across yields and UDP backpressure.

A responder-only peer with no configured endpoint becomes usable after an
authenticated handshake or keepalive alone. Outbound traffic with neither
a configured nor a learned endpoint is dropped and counted; receiving
cookie traffic does not make such a peer usable.

### Crypto buffers, queues and timers

Bound `wg`'s packet staging and outer UDP buffers as well as the packet IPC
queues. Reserve new staging/queue storage and reusable scratch buffers
fallibly before activation. Account for boringtun's existing maximum of 256
queued plaintext packets per peer when choosing peer and memory limits;
its internal allocations remain an upstream limitation, not a promise of
allocation-free crypto. Process-local limits apply to every `wg` instance;
sys-io separately bounds the number of live/retiring registered devices.

Use reusable crypto buffers, initially 2048 bytes, sized for handshakes,
MTU-sized data and padding. Detect oversized or truncated outer datagrams
before library calls, reject inner packets over the 1420-byte tunnel MTU,
and never give boringtun a short output buffer. Test maximum padded lengths
and all inner/outer IPv4/IPv6 combinations. Outer UDP uses the physical
stack's existing fragmentation/PMTU handling; test paths smaller than 1500
bytes. Tunnel PMTU propagation is outside v1.

If the SDK cannot accept an outer send yet, retain at most one additional
ciphertext datagram per `wg` device and register its send waker. Stop
advancing plaintext TX and queued flushes until capacity returns, while
continuing RX and timers. Drop and count a response that fits neither the
socket queue nor that pending slot. Never spin or build an unbounded retry
queue. SDK acceptance is not delivery confirmation; downstream UDP loss
uses ordinary protocol recovery. Pending ciphertext retains its destination
and is discarded when the physical binding is invalidated.

Retain an absolute 250 ms timer deadline across packet wakeups. When due,
call `update_timers` for every peer and `reset_count` on the shared limiter;
the limiter internally resets at most once per second. Timer output follows
the same bounded send path. Initially process at most 32 packet operations
per batch, including drops and queued flushes, then check timers and yield.
Alternate RX and TX when both are ready. Service deadlines under continuous
traffic, not only when queues become idle. Count queue drops, malformed or
unauthenticated input, disallowed sources and unavailable transport; avoid
per-packet warning logs under floods. Measure progress of unrelated network
and filesystem work under saturation.

## Configuration and secrets

Load one explicit config/key pair, for example
`wg /user/cfg/wireguard/wg0.toml` with adjacent `wg0.key`. Read once;
restart to change configuration or rotate keys. The config filename stem
supplies the registered device name (`wg0` here); it does not select a
sys-io vector index. Use standard Rust/native filesystem APIs in `wg` to
load these two regular files; no directory discovery or sys-io-specific
loader is needed. The key file is a single base64 value decoding to exactly
32 bytes. Peer public keys and optional preshared keys use the same encoded
32-byte format.

```toml
transport_addresses = ["192.0.2.2"]
listen_port = 51820
cidrs = ["10.20.0.2/32"]

[[peers]]
public_key = "..."
preshared_key = "..."         # optional
endpoint = "192.0.2.1:51820"  # optional for a responder-only peer
allowed_ips = ["10.20.0.0/24"]
persistent_keepalive = 25     # optional, seconds
```

`transport_addresses` selects one currently assigned physical local address
per enabled outer family; require at least one and reject duplicate families
or nonphysical addresses. `listen_port` is an explicit nonzero `u16` port.
Endpoint addresses are numeric unicast socket addresses with nonzero ports;
DNS endpoint resolution is outside v1. Their families must have a configured
physical transport. The bound physical device provides link-local IPv6 scope;
reject explicit scope IDs rather than silently discarding them. An omitted
endpoint permits responder-only operation. Keepalive absent or zero means
disabled; otherwise it is a `u16` interval in seconds.

`cidrs` assigns local tunnel addresses; peers' `allowed_ips` supply remote
routes and peer ownership. Require a local tunnel address for each allowed-IP
family. Reject unknown fields, malformed keys/CIDRs, duplicate peer public
keys, duplicate exact prefix owners, missing file partners, unsupported
families and local address/device-name conflicts. Port reservations use the
ordinary physical UDP admission rules; conflicts fail before activation.

Bound each file read (initially 64 KiB maximum), total configuration bytes,
peer count and prefix count per process before allocating peer runtime state.
Include every peer's internal queue budget in admission. Choose the concrete
peer/prefix limits during implementation; sys-io's device quota remains
separate from these process-local crypto limits. Validate both files and
reserve resources before activation. Failures close any opened outer sockets
and registration channel, releasing their reservations. The private key and
any PSK-bearing TOML are secrets.

`/user/cfg/` already has the imager policy `rwxrwx---` for directories and
`rw-rw----` for files: System and Interactive can read them, None cannot,
and all Interactive processes share that access. `wg` checks the actual
permissions of both files when loading them and refuses either file if None
can read it. Apply this rule to every config, whether or not it contains a
PSK. Imager policy does not establish the permissions of files uploaded or
created later. Do not silently widen permissions. Report sanitized errors,
never keys, packet contents or TOML excerpts containing secrets.
sys-io has no WireGuard-specific loader or crypto state, although it remains
the filesystem service through which config and key bytes are read.

## Implementation plan

Rules for every step:

* Patches are 100-300 lines including tests. Split steps as needed to keep
  patches small; patch counts are not prescribed.
* Each intermediate step requires one debug and one `--release` run of
  `src/tests/full-test.sh` before its commits. Keep those commits small and
  check that each intermediate tree builds. When all implementation work
  is complete, the final gate requires three debug and three `--release`
  runs. Steps 6-8 also run their component tests. Step 9 introduces a
  minimal VM gate alongside activation, and step 10 expands it. From step 9
  onward, WireGuard changes also pass that VM gate.
* With no packet device registered, sys-io behaves as today. Each step
  leaves the tree buildable, formatted with the repository toolchain, and
  free of new compiler and clippy warnings.
* `wg` listens on its transport only from step 9 on, when authentication,
  ownership, bounds and timers are all present.
* No kernel, moto-rt or Rust std changes. No new statics in `src/sys`.
  Failures are diagnosed, never masked by retries or longer timeouts.

Steps 1-5 are sequential. Step 0 and the host work in steps 6-8 can proceed
alongside them; step 7 needs the step 0 fork, and the Motor transport in
step 8 needs step 4. Step 9 requires all earlier steps, including step 5's
ping coverage.

### Step 0: boringtun fork (outside this repository)

Implement [the boringtun fork](#the-boringtun-fork) at the pinned upstream
base: the generic `sleepyinstant` fallback and documented public
`handle_verified_packet`, retaining the upstream `ring` backend. This work
changes `github.com/moturus/boringtun`, outside the main repository, and must be
announced when it starts. Before step 7 pins the reviewed revision, pass
upstream tests, including vector and mock-clock tests, and a Motor
compile/link check with the existing `ring` port and custom random-source
adapter.

### Step 1: routes without a gateway

First correct the existing SLAAC route-installation bug so an IPv4 route
does not suppress an advertised IPv6 default route. Keep regression coverage
in the full test suite; enabling SLAAC in sys-io is outside this change.

sys-io `config.rs` (`IpRoute`, `find_route`) and route installation in
`device.rs`; netstack `iface/route.rs` and the next-hop lookup for
`Medium::Ip` interfaces.

Add a route kind that names a device and no gateway, and implement the
selection order of "Interface integration and routes". `sys-net.toml` and
the gateway validation of Ethernet routes stay as they are. The netstack
returns the configured next hop today; on an IP-medium interface that hop
is not used, so the step picks the smallest representation that leaves
the Ethernet path unchanged.

Tests: sys-io self-tests for the selection order, `/0` against the physical
default, both families, source selection and unchanged boot-config gateway
requirements; netstack host tests for the lookup. Rejection of duplicate
registered prefixes on two devices is tested with registration in step 3.

### Step 2: devices that come and go

First fix the preexisting outgoing TCP port collision with explicit and
wildcard listeners. Ephemeral source selection must exclude their local
endpoints while preserving existing connection and TIME-WAIT exclusions.
Cover both IP families with native connection and accept tests.

Also fix preexisting UDP self-delivery on local physical addresses. Cover
both families, wildcard and explicit binds, same-socket delivery, source
identity, connected-peer filtering and empty/maximum-size datagrams.

sys-io `net.rs` (the device vector, `ip_addresses`, `find_route`, the
per-device poll task), `tcp_listener.rs` (`add_address`, `remove_address`),
the socket modules and `icmp.rs`; the native UDP client and socket protocol
for terminal invalidation.

Use optional device entries as specified in "Interface integration and
routes". Boot-time devices keep their indices. Registration appends a new
entry even when earlier entries are `None`, including when a name such as
`wg0` is used again. Multiple registered devices operate independently.
Adding installs addresses and routes, starts the poll task and expands
wildcard listeners. Removing takes the entry, leaving `None`, withdraws its
addresses and routes, fails its sockets, detaches listener endpoints,
cancels pending echo requests and stops the poll task. Keep retiring state
until every user has detached; delayed work must tolerate the removed slot.
Repeated add/remove releases device resources and budget while leaving the
expected empty slots. Slot reuse and compaction are outside this plan.

This includes ICMP sockets, identifiers, timeout tasks and guard drops, plus
the UDP invalidation notification and client wakeup/error handling. All
removal safety is complete before step 3 exposes registration. Step 4 reuses
the notification for physical transport-address loss; step 5 does not add
missing lifetime protection.

Tests: sys-io self-tests for append-only registration despite vacant slots,
`None` after removal, stable boot-time and remaining-device indices, and
re-registration of the same name at a new index. Cover independent device
removal, listener expansion with a loopback-backed device, retired-resource
cleanup and UDP invalidation/wakeup. Step 3 must land external registration
together with tests that remove devices during live TCP/UDP/ICMP operations.

### Step 3: packet device and registration IPC

moto-sdk `sys_io/api_net.rs` plus a small native client module for device
providers; sys-io `net.rs` dispatch and admission, a `NetstackDevice`
variant with its adapter, and `channel_budget.rs` for the channel itself.

Three commands: register, unregister, and packet, the last used in both
directions with one packet per message and page, as the UDP socket path
moves datagrams today. Registration data travels in a page; the reply
confirms activation. The channel identifies the device without a device-ID
field in packet or unregister messages. Unregister is terminal; another
registration requires a new channel. sys-io already keeps each client's PID
and capabilities, so the System-or-Interactive gate and channel ownership
need no new authentication. Registration validates and reserves everything
before publishing the device, and rolls back on failure. The variant is
`Medium::Ip`, software checksums, external, with bounded RX and TX queues
of 64 packets each to start. TX tokens reserve slots, and a full queue
reports `tx_exhausted` the way virtio does. Incoming packets are checked
and copied into private storage, and their page is released at once; a
full RX queue drops and counts. Channel death runs the removal of step 2.
Four live/retiring packet devices to start, with the channel's fixed shared
memory accounted for; vacant vector entries do not consume that quota.

Tests: an in-guest test provider in systest registers a test prefix and
reflects packets with their IP source and destination addresses swapped.
TCP/UDP servers listen on the guest's registered address, clients target a
different address in the test prefix, and automatic ICMP replies are enabled.
UDP clients use destination-aware binding to select the packet device.
Reflected requests reach those guest servers; reflected responses reach the
clients. The guest netstack supplies TCP and echo replies, so the provider
needs no transport-protocol implementation. Use this fixture for correctness,
not as the remote-server performance baseline in step 11.

Cases: registration from Interactive and from a child without the role,
terminal unregister and rejection of later messages, bad names, counts,
families and MTU, duplicate addresses and route conflicts, quota, malformed
page references and lengths, oversized packets, full queues and their
recovery, provider exit with live TCP/UDP sockets, blocked operations,
pending ICMP probes and wildcard listeners, and multiple concurrent devices
whose names do not determine their indices. Repeated registration on fresh
channels, including reuse of a removed name, appends new slots and leaves
old ones `None`; other devices keep working, removed-device resources are
released and old work never reaches a new device. Check expected slot growth
separately from resource leaks, and verify that empty slots do not exhaust
the live/retiring-device quota.

### Step 4: UDP rules and the physical transport

sys-io `socket/udp.rs` and address-change handling, the UDP bind encoding in
`api_net.rs` and the SDK UDP client, and `dns-resolver/src/dns.rs`.

Wildcard UDP binds choose physical or loopback devices only. A bind option
marks a socket as physical transport: it binds on the physical device that
owns the given local address and is exempt from the check below. A
datagram whose selected route crosses the physical/virtual boundary or
switches virtual devices is dropped and counted without a synchronous send
error. Differences between physical devices retain their existing behavior.
Destination-aware binding already follows step 1 routes. The resolver's
query sockets bind for their server instead of the unspecified address,
through the `udp_bind_for_remote` call moto-rt already exposes.

Address loss/replacement invalidates an affected transport socket, discards
queued output with its old source and uses step 2's terminal notification
to wake the client and fail further I/O. Implement this in sys-io and the
SDK before `wg` relies on it; peer silence does not trigger invalidation.

Tests: systest UDP cases over the test provider: a socket bound to the
test address exchanges datagrams, a wildcard socket sending into the test
prefix has its datagram dropped and counted, unrelated physical traffic is
unaffected even with multiple NICs, a transport-flagged socket reaches a
destination inside a registered `/0`, and the resolver's query socket takes
the registered source for a server inside the prefix. Exercise address loss
with queued output and blocked I/O; assert notification, wakeup, stale-output
discard and errors on subsequent sends/receives.
Also cover physical UDP port conflicts and reservation release after failed
construction, registration failure and shutdown.

### Step 5: ping through packet devices

sys-io ICMP and packet-device test coverage.

The echo handler already selects its device through `find_route`, so steps
1 and 3 route it. Lifetime tracking and removal cancellation are complete
in step 2 and exercised in step 3. This step expands IPv4/IPv6 ping coverage
and verifies that registered interfaces inherit the existing echo-reply
policy, including both enabled and disabled replies.

Tests: systest ICMP cases over the test provider for IPv4 and IPv6,
peer silence/timeouts, reply validation, MTU bounds, policy on/off and an
unaffected physical ping. Removal during a pending probe remains in the
step 3 lifecycle gate.

### Step 6: `wg` crate and configuration

New `src/bin/wg` workspace with its own lockfile, like russhd; a Makefile
target; the image entry `/system/bin/wg`.

`wg <config.toml>` loads the TOML and the adjacent key file, applies the
bounds and validation of [Configuration and secrets](#configuration-and-secrets),
and reports sanitized errors. No network code yet. Config and keys live
under `/user/cfg/wireguard/`, whose existing policy already fits; no new
imager entry. The image ships no WireGuard files.

Tests: host `cargo test` for parsing and validation, including permission
decisions for both files. Step 10 also exercises actual Motor permissions
on uploaded files, including PSK-bearing configs.

### Step 7: peers, dispatch and timers

`src/bin/wg`, with the step 0 fork pinned as a git dependency and
`getrandom` registered as russhd does.

Implement [peer ownership and dispatch](#peer-ownership-dispatch-and-roaming)
and [crypto scheduling](#crypto-buffers-queues-and-timers): one owner table,
the receiver-index map, one shared cookie limiter, one anonymous handshake
parse, verified dispatch and authenticated endpoint learning. Preserve the
250 ms timer deadline and bounded flush work. Packets in and out are byte
slices here; nothing touches sys-io.

Tests: known-answer cipher tests; longest-prefix TX/RX
ownership with `/0` and narrower owners; all message kinds and unknown
indices/keys; cookie threshold/reset and single accounting; replay rejection;
handshake/empty-keepalive endpoint learning; and mock-clock retry, keepalive,
rekey and expiry transitions.

### Step 8: outer UDP transport and the host peer

`src/bin/wg` and a new host-only crate `src/tests/wg-peer/`.

One UDP socket per enabled family, bound to the configured physical address
and port. On Motor it uses step 4's physical-transport option and terminal
invalidation notification; Linux host tests use an ordinary explicit bind.
Pending-ciphertext slot and send-waker backpressure, endpoint learning,
bounded batches, and a clean stop when the local address is lost. Peer
silence or temporary transport unreachability does not stop the process.

The host peer uses unchanged upstream boringtun 0.7.1 with `ring` over
plain UDP, with no tun device and no root. It can initiate and respond,
send valid, malformed and replayed packets, change its source port, answer
inner echo requests, send its own, and run TCP/UDP echo services inside the
tunnel on moto-netstack built for the host. It also supplies a keygen command
for the VM gate. Its workspace stays separate from `src/bin/wg`, so the fork
and upstream never share a lockfile.

The same host netstack provides a service implementing the rnetbench
handshake and the request/reply and throughput commands used in step 11;
TCP echo alone does not implement that protocol. A test-only unencrypted
IP-over-UDP mode feeds the same netstack and services as the WireGuard mode.
This keeps the application endpoints and inner TCP implementation the same
in the two packet-device measurements, without a host TUN device.

Tests: `wg`'s transport and peer logic run against the host peer over
localhost on Linux, before any VM is involved. Exercise the benchmark
service with rnetbench-compatible traffic in both host-peer transport modes.

### Step 9: device adapter and activation

`src/bin/wg`, using the native client module of step 3. All earlier steps,
including the ping gate, must be complete before activation lands.

Routes come from the peers' allowed IPs. TX takes a packet from sys-io,
finds its owner, encapsulates and sends. RX authenticates, checks the
inner source against the owner table and submits. Counters cover drops,
unauthenticated input, disallowed sources and unavailable transport. `wg`
unregisters on exit and on fatal transport errors. The transport starts
listening only here, with every earlier piece in place.

Land a minimal `src/tests/test-wireguard.sh`, called from
`src/tests/full-test.sh`, alongside activation. This gate proves registration,
authenticated ping and a TCP exchange through the independent host peer,
and teardown with routes and resources released. Activation is not committed
without that passing VM test; step 10 expands it.

The host peer listens on the moto-tap address; the guest `wg` binds its
own. The test script makes fresh key pairs with the host peer's keygen
command, writes the guest config, uploads both by sftp into
`/user/cfg/wireguard/`, sets and verifies restrictive permissions on both
files, and removes them at the end. Test keys exist for the test only: never
in git, never in an image. `wg` runs in the guest inside a coproc ssh session,
as the networking suite runs `rnetbench --server`. No Internet destinations.
New test binaries go into both the sftp upload list and `motor-os-dev.yaml`.

### Step 10: expand the VM gate

Extend `src/tests/test-wireguard.sh` and reuse step 9's peer, provisioning,
permissions and cleanup rather than creating another harness.

Cases: Motor `ping` to the peer's inner address over IPv4 and IPv6, peer
probes of the guest's tunnel address with the reply policy on and off, TCP
and UDP through the tunnel, malformed and replayed packets rejected,
roaming, a responder-only peer, stopping `wg` restores ordinary routing for
new requests while a stale tunnel socket fails, and a restart works.

Cover all inner/outer IPv4/IPv6 combinations, maximum padded packets,
oversized/truncated input, smaller outer paths, peer ownership overlaps,
cookie exchange and source IP/port roaming. Saturate both directions to
exercise bounded queues, pending flush resumption and timer progress while
unrelated networking and filesystem work continues. Long timer transitions
use mock clocks rather than multi-minute VM sleeps.

Also cover transport-address loss waking `wg` and causing its clean exit,
unaffected physical UDP with multiple NICs, and rejection of either a
None-readable key or config, including a PSK-bearing TOML. Verify sanitized
errors without exposing secret values. No Internet destinations.

### Step 11: measurement and documentation

Keep the rnetbench client in the guest and the server on the host in all
three runs, with the same workloads and VM shapes:

* Physical reference: the guest connects directly to the host's ordinary
  `rnetbench --server` over the physical network.
* Unencrypted packet device: a test-only guest provider transfers registered
  device packets over physical UDP to the host peer's plain IP mode and
  rnetbench service. Reuse the bounded packet client and transport path;
  production `wg` has no unencrypted mode.
* WireGuard: `wg` transfers packets to the same host peer's WireGuard mode,
  using the same inner netstack, rnetbench service, addresses and MTU as the
  unencrypted run.

The in-guest address-swapping reflector remains a correctness fixture; it
is not this performance baseline. Match endpoint placement and inner packet
paths between the unencrypted and WireGuard runs. Their difference measures
incremental WireGuard cost. The physical run is an end-to-end reference with
a different host TCP stack; do not attribute its entire difference from a
packet-device run solely to IPC or crypto.

On the default and small VM shapes, record throughput, small-packet rate,
CPU, latency, queue high-water marks and IPC wakeups. Use those results to
decide whether batching is worth pursuing. Add a `docs/networking.md`
section on provisioning and permissions, routing
rules, limits and diagnostics.

### Left to the steps

Rust types and traits, message layouts, final queue and quota values,
batching, page reuse, counter names, the exact self-test and systest layout,
and the host peer's command line. Each step states in its patch descriptions
what it fixed.

## Acceptance

| Area             | Acceptance coverage                                                           |
|------------------|-------------------------------------------------------------------------------|
| Registration     | System/Interactive vs None, kernel PID/channel ownership, conflicting         |
|                  | names/addresses/routes, invalid families/MTU, quota exhaustion, partial       |
|                  | failure and cancellation rollback                                             |
| Configuration    | Base64/key lengths, unknown fields, missing/nonregular files, malformed or    |
|                  | oversized configs, duplicate peers/prefix owners, invalid                     |
|                  | endpoints/scopes/families/ports and admission failure before activation       |
| Packet IPC       | Both directions, invalid page references and lengths, malformed IP, maximum   |
|                  | MTU, IPv4/IPv6 large-datagram behavior, full queues/rings, page release and   |
|                  | wakeup, provider disconnect while blocked                                     |
| Routing/sockets  | Remote prefix outside local CIDR, overlaps/default route, correct sources,    |
|                  | physical-only outer UDP, TCP/UDP/ICMP, wildcard listeners before/after        |
|                  | registration, DNS through the tunnel; physical UDP port conflicts and         |
|                  | reservation cleanup                                                           |
| UDP failure      | Boundary-policy drops counted without synchronous send errors;                |
|                  | physical-to-physical behavior unchanged; removal/address loss invalidates     |
|                  | sockets, wakes waiters, discards stale output and fails later I/O             |
| Ping / ICMP      | Motor ping and peer probes over IPv4/IPv6; echo-reply policy, source/MTU and  |
|                  | reply checks, timeout, removal mid-probe, resource cleanup and unaffected     |
|                  | physical ping                                                                 |
| Lifecycle        | Peer outage retains routes; unregister/crash restores ordinary routing;       |
|                  | terminal unregister requires a new channel; old                               |
|                  | sockets/accepts/TIME-WAIT/ICMP/waiters retire; removed-device resources       |
|                  | released; no stale work reaches new devices                                   |
| Device slots     | Concurrent devices; names independent of indices; append despite holes;       |
|                  | removal leaves None; other indices stay stable; same-name registration        |
|                  | appends; vacant slots grow but do not consume device quota                    |
| Crypto           | Unchanged upstream peer in both roles and families; vectors and authenticated |
|                  | seal/open with zero/nonzero counters, empty keepalives, MTU payloads and      |
|                  | associated data; changed ciphertext/tag/nonce rejected                        |
| Peer ownership   | Multiple peers; IPv4/IPv6 longest-prefix TX destination and RX source         |
|                  | ownership; /0 plus another peer's /32 or /128; unknown destinations/sources   |
|                  | and duplicate prefixes rejected                                               |
| Dispatch/cookies | All four wire message types; unknown indices/keys and malformed lengths; one  |
|                  | anonymous parse; shared threshold/reset; cookie                               |
|                  | challenge/reply/retransmission; no duplicate MAC check or limiter charge      |
| Replay/roaming   | Authenticated handshakes and empty keepalives learn source IP/port;           |
|                  | responder-only peers can subsequently send; cookies, forged packets and       |
|                  | replays cannot move endpoints                                                 |
| Queues/fairness  | Full RX/TX/UDP queues, dropped unused TX token, fallible reservations, wakeup |
|                  | after drain, pending flush resumption, bounded crypto staging and peer        |
|                  | queues, RX/TX/timer and unrelated-service progress                            |
| Packets/timers   | All IPv4/IPv6 inner/outer combinations; maximum padded lengths,               |
|                  | oversized/truncated packets, smaller-path outer fragmentation; persistent     |
|                  | keepalive, handshake retry, rekey and session expiry                          |
| Limits/secrets   | Channel/socket/listener/crypto limits, slow providers/consumers, capacity     |
|                  | recovery, physical network/filesystem progress, actual key/config permissions |
|                  | (including PSKs), sanitized errors                                            |
| Measurement      | Compatible rnetbench service; guest client/host server in each run; matched   |
|                  | inner path/MTU/host stack for unencrypted and WireGuard; physical-reference   |
|                  | differences reported                                                          |

The VM gate starts with activation in step 9 and expands in step 10. It
uses the host peer with unchanged upstream boringtun from step 8;
fork-to-fork exchange alone is not interoperability evidence. Run Motor's
actual `ping` command as well as peer probes; packet-only echo tests do not
cover the client/command path. Long timer transitions use mock clocks;
adapter scheduling and lifecycle behavior run inside Motor OS. All new
tests run directly or transitively through `src/tests/full-test.sh`, with
dependencies prepared before the gate and hermetic runtime traffic only.
Any developer-image gate for this work is release-only.

## Tradeoffs and reuse

This keeps WireGuard failures outside sys-io while retaining one socket
implementation and its admission policies. It adds packet IPC, device
lifecycle and routing work; it does not eliminate sys-io TCP/IP processing.
Measure throughput, small-packet rate, CPU, latency, memory/queue high-water
marks, IPC wakeups and concurrent-service latency on representative VMs.
Use step 11's matched remote-endpoint setup for the unencrypted and full
WireGuard paths, plus the physical reference, including a small VM. Report
the topology and host-stack differences when interpreting the measurements.
Batching may reduce overhead; do not assume shared pages mean zero-copy or
promise a throughput figure before measuring.

The same IP-device contract could support other VPN/mesh transports, a host
link over vsock, controlled loss/delay/reordering test links, or packet
inspection/shaping for traffic deliberately routed through the device.
These are future consumers, not additional v1 implementations. Ethernet
bridging would require a separate extension.

## Open questions

None currently.
