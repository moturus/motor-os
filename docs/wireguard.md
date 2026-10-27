# WireGuard

## Using WireGuard

The standard Motor OS image includes `/system/bin/wg`. Run it from a System
or Interactive process with `CAP_NET` and read access to its configuration
and key. Each process provides one tunnel device. Startup is manual; the
image contains no WireGuard keys or configurations.

### Prepare the configuration and keys

Create a WireGuard key pair for the Motor OS instance and obtain the other
peer's public key. From the repository root on the Linux host, the included
host helper can generate the pair:

```sh
cargo run --release --locked --manifest-path src/tests/wg-peer/Cargo.toml -- \
  keygen wg0.key wg0.pub
```

This creates new files without overwriting existing ones. `wg0.key` holds
the private key; give only `wg0.pub` to the other peer. Keys are single
base64 values encoding 32 bytes. Motor OS's `wg` command takes a TOML filename;
key generation is provided by the host helper above.

Create `wg0.toml` alongside the key, replacing the example physical addresses
and public key with your own:

```toml
transport_addresses = ["192.0.2.2"]
listen_port = 51820
cidrs = ["10.20.0.2/32"]

[[peers]]
public_key = "<other peer's base64 public key>"
endpoint = "192.0.2.1:51820"
allowed_ips = ["10.20.0.0/24"]
# persistent_keepalive = 25
# preshared_key = "<optional shared base64 32-byte key>"
```

`transport_addresses` must name an address already assigned to a physical
interface on Motor OS. `endpoint` is the other peer's reachable UDP address;
`cidrs` supplies this tunnel's local addresses, and `allowed_ips` supplies
destinations routed to that peer. Configure the other peer with Motor OS's
public key, an inner address such as `10.20.0.1`, and an allowed prefix
covering Motor OS's `10.20.0.2/32`. Permit the configured UDP port on the outer
network. If using a preshared key, configure the same value at both ends.

Both inner and outer traffic support IPv4 and IPv6 independently. For inner
IPv6, add a local CIDR such as `fd20::2/128` and a peer prefix such as
`fd20::/64`. For outer IPv6, select an assigned physical IPv6 address and
use a bracketed numeric endpoint, for example `[2001:db8::1]:51820`.
There may be one physical transport address per IP family. Endpoints must
be numeric; DNS names and explicit IPv6 scope IDs are unsupported. Omit
`endpoint` for a responder that learns it from authenticated peer traffic.

### Install the files and restrict access

Create `/user/cfg/wireguard/` in the guest if needed, then copy `wg0.toml`
and `wg0.key` there, for example using SFTP. The filename stem supplies the
device name, and the adjacent `.key` file is mandatory. Names contain up to
31 ASCII letters, digits, underscores or hyphens.

Keep **both files unreadable by None**, including configurations without a
preshared key. For files uploaded by Interactive under `/user/cfg/`, these
Motor OS shell commands retain System read/write access, give Interactive read
access, and exclude None:

```sh
cd /user/cfg/wireguard
chmod rw-r----- wg0.toml wg0.key
ls -l wg0.toml wg0.key
```

A System-only instance can use `r--------` on both files, set by System.
Protect the parent directory as well when lower roles must not replace
files. Motor OS's `chmod` uses the nine-character System/Interactive/None
permission word. SFTP translates numeric modes into Motor OS permissions;
`chmod 660` when uploading as Interactive also excludes None. See
[filesystem permissions](fs-permissions.md) for the role and directory rules.

### Start, check and stop the tunnel

Run this in a Motor OS terminal:

```sh
wg /user/cfg/wireguard/wg0.toml
```

The process stays in the foreground and prints `wg0: active (pid=...)`
after registration. This confirms that addresses and routes are installed;
it does not confirm a handshake. From a second Motor OS terminal, probe the
other peer's configured inner address:

```sh
ping -c 3 10.20.0.1
stats providers
```

Use `stats get PID` with the printed PID to read the `wg:PID` provider's
authentication, ownership, drop and timer counters. Snapshots update on the
250 ms timer tick. `stats list` describes metrics; sys-io also reports
`net.ip_device.*` queue/buffer counters and `net.udp.tx_boundary_drops`.
Incoming peer pings require `auto_icmp_echo_reply` in
`/system/cfg/sys-net.toml`; registered interfaces inherit that setting.

Press Ctrl+C in the foreground terminal to stop `wg`. Its routes and local
addresses are removed, existing tunnel sockets fail, and new connections
use remaining routes, including the physical default. A silent peer leaves
the tunnel routes installed. Physical transport-address loss ends the
process; restart after correcting the configuration. Changes to configuration
or keys also require a restart.

To run another device, prepare `wg1.toml` and `wg1.key` and launch another
`wg` process. Device names, local addresses and identical route prefixes
must not conflict. Use another listen port when sharing a physical address.
sys-io admits up to four active or retiring packet devices.

### Routing and troubleshooting

New TCP connections, ping and destination-aware UDP binding select the
tunnel automatically for matching routes. Ordinary wildcard UDP binding
still selects a physical or loopback address; bind explicitly to a tunnel
address when needed. Existing sockets do not migrate between devices.
WireGuard does not change DNS-server configuration. DNS queries follow the
route to the configured server, so its address must be covered to tunnel DNS.

If startup fails, check both file permissions, the paired filenames, physical
address assignment, UDP port conflicts and device/address/route conflicts.
Errors identify the operation without printing keys or TOML contents. If an
active tunnel cannot reach its peer, check the endpoint, keys and reciprocal
allowed prefixes, then inspect the authentication and drop counters. Ping
also requires the peer to answer ICMP echo requests.

WireGuard uses MTU 1420. Each instance accepts at most 16 peers, 16 local
addresses and 128 allowed prefixes in total, with each input file limited to
64 KiB. See the design below for routing and resource-lifetime details, and
[the measurements](wireguard-measurements.md) for throughput and its limits.

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
V1 includes Motor OS's `ping`: ICMPv4/ICMPv6 Echo Request/Reply through the
tunnel, both guest-initiated probes and policy-controlled replies to peers
that ping a local tunnel address.
Inter-interface forwarding, bridging, automatic transport failover,
persistent devices, live configuration reload and a persistent kill switch
are outside v1. `wg` is started by the user; automatic boot startup is not
provided.

Device lifecycle follows its provider: a device is added when `wg` registers
and removed when `wg` unregisters or exits. Routes and addresses come and go,
sockets on a removed device fail, listeners are updated and queued work is
released.

## Design decisions

* `wg` retains boringtun's upstream `ring` backend. The separate `wg`
  workspace owns its crypto dependencies and C/assembly build requirements;
  they stay outside the core workspace.
* Keys and configs live under `/user/cfg/wireguard/`. The binary ships as
  `/system/bin/wg`.
* `wg` is started by the user; starting it at boot is out of scope.
* The boringtun fork supplies the clock fallback and verified-packet entry
  point described below; its protocol and crypto implementation are unchanged.

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

This is a conceptual view of the request data. Addresses are local
interface addresses with CIDRs; routes are destination prefixes using this
device without a gateway. `wg` derives routes from its peers' allowed IPs.
Registration contains no keys, peer identities, endpoints or WireGuard
protocol state. The same operation supports other IP-device providers.

sys-io retains normal `CAP_NET` admission, allows registration from System
or Interactive, and rejects None. It obtains PID and role from the kernel
channel metadata, using `SysObj::get_pid` and capabilities. There is no new
capability, URL ownership rule or authentication exchange. The existing
`sys-io` name is already kernel-reserved; packet exchange needs no
provider-owned service URL. The separate statistics service exposes counters.

The reply confirms activation and establishes bounded packet transfer in
both directions. The dedicated channel identifies its one device; packet
and unregister messages do not select a device ID. Only that channel may
submit packets or unregister it. Unregister is terminal: registering again
requires a new channel, and later packet messages on the old channel are
rejected. A caller-supplied PID never establishes ownership. Internal tasks
and callbacks must handle removed slots safely; registering another device
with the same name must not retarget old work to it.

Registration validates bounded names, address/route counts, IP families and
MTU before activation. Local addresses and device names are unique across
devices; route conflicts follow the deterministic rules below. A removed
device's name may be registered again on a new channel. Names, including
numeric suffixes such as the `0` in `wg0`, do not select a sys-io device
index. Every routed family requires a local source address. These are
interface validity checks, not an additional prefix-ownership permission
system.

Registration is transactional: it reserves resources, constructs the device
and checks listener expansion before publishing it. Failure, cancellation or
channel closure rolls back partial state. Success means routes, addresses
and the packet consumer are ready together. The SDK closes the dedicated
channel if it abandons an in-progress registration.

## Packet transport and resource limits

Packet transfer uses the existing
[io_channel and IoPage machinery](../src/sys/lib/moto-sdk/src/ipc/io_channel.rs).
Each message describes one complete IP packet and its length. V1 packets
fit in one shared page, with a page-sized maximum registered MTU and
the IPv6 minimum MTU where applicable. Socket-level MTU handling stays in
the netstack: fragment where supported or report the applicable send error.
IPC neither transfers packets larger than the registered MTU nor fragments
them.
WireGuard's fixed 1420-byte MTU is not a path-MTU guarantee.

* Outbound: sys-io emits an IP packet into the device's bounded TX queue.
  The IPC adapter transfers it to `wg`, which selects a peer, encrypts it
  and sends it through its physical UDP socket.
* Inbound: `wg` authenticates/decrypts outer UDP and checks inner source
  ownership before submitting the IP packet. sys-io validates its framing
  and delivers it to that device's `Interface` and `SocketSet`.

The adapter follows existing page ownership/release rules and uses checked
page references. It checks lengths before copying and parses packets from
private bounded storage so shared-memory changes cannot invalidate prior
checks.
Malformed IP packets are dropped and counted; malformed IPC follows the
existing channel-error policy and must not panic sys-io. A provider can
inject only through the interface belonging to its channel.

`Interface::poll` stays synchronous over private RX/TX queues. A separate
adapter task transfers IPC messages; no runtime or queue borrow crosses an
await. A TX token reserves capacity before emission, including reply tokens
returned by receive. Exhaustion stops TX; releasing an unused token or
draining the queue restores capacity and wakes the poll task. Full RX drops
and counts packets rather than growing a queue. Page release and ring
capacity changes must wake blocked producers without polling or lost wakes.

Channels, live and retiring devices, addresses, prefixes, staging bytes,
and queued/in-flight packets are bounded. sys-io allows four live and
retiring packet devices in total, with 64 packets per direction per device,
16 local addresses and 128 routes. The channel's fixed shared memory also
consumes sys-io's [channel budget](../src/sys/sys-io/src/runtime/channel_budget.rs).
Vacant vector slots do not consume the live/retiring-device quota; their
retained storage is accounted for separately as described below.

Application TCP/UDP sockets retain sys-io's existing global and per-listener
budgets, SYN cookies and pressure handling. Listener expansion consumes
those budgets. `wg` separately bounds peers, crypto buffers, pending
ciphertext and boringtun's internal queues; authentication replaces none of
these limits. Bounded batches and yields preserve timer and unrelated
network/filesystem progress under sustained traffic.

## Interface integration and routes

The process-backed variant of
[NetstackDevice](../src/sys/sys-io/src/runtime/net/device.rs) uses
`Medium::Ip`, software checksums, no TSO and no DHCP or Ethernet neighbor
discovery.
It is external for randomized ephemeral ports and loopback-ingress rejection;
physical-transport selection distinguishes physical from virtual devices.

Every registered device gets the existing per-device `Interface`,
`SocketSet` and poll task. The
[runtime](../src/sys/sys-io/src/runtime/net.rs) device vector has optional
entries, conceptually `Vec<Option<Device>>`. Boot-time devices keep their
indices. Each new registration appends `Some(device)` at the end, regardless
of its name or any vacant entries. Unregister removes the device from the
active vector by taking its entry, leaving `None` at the same index. The
vector is not compacted or truncated, and vacant slots are not filled.
Retiring state remains available to cleanup until its users have detached.

For example, after the boot-time entries:

```text
Register wg0 and wg1: [..., Some(wg0), Some(wg1)]
Unregister wg0:       [..., None,      Some(wg1)]
Register wg0 again:   [..., None,      Some(wg1), Some(wg0)]
```

Reusing vacant indices much later is future work.
There is no permanent guarantee that an index is never reused; any future
reuse must prevent stale references from reaching a new device. For now,
the vector's empty-slot storage grows with registration history even though
removed devices release their resources. This is an explicit limitation of
deferring slot reuse, not a requirement to retain removed-device state.

[Route selection](../src/sys/sys-io/src/runtime/net/config.rs) supports
gateway-free interface routes in both runtime device selection and netstack
reachability. Physical gateway routes retain their on-link gateway validation
and the existing `sys-net.toml` format.

Deterministic selection:

1. Local destinations retain their local-address handling.
2. Longest-prefix matching covers connected, physical-gateway and
   registered interface routes. At equal length, connected routes win,
   then registered routes, then physical gateway routes. Physical-route ties
   retain their existing behavior.
3. Identical registered prefixes on different packet devices are rejected;
   different-length overlaps are valid. A registered `/0` overrides the
   physical default while more-specific connected routes remain usable.
4. Source selection uses the chosen device and destination family:
   prefer its most-specific containing local CIDR, otherwise its first
   configured address of that family. Explicit source binds are respected.

Local CIDRs and remote routes stay separate: a local `/32` or `/128` must
reach remote prefixes outside that CIDR. The WireGuard peer table decides
ownership after routing; a packet with no peer owner is dropped. Registered
routes remain installed while a peer has no session or transport is
unreachable. No retry sends that selected plaintext via the physical default.

## Application sockets and physical UDP

TCP connects use normal sys-io route selection. Bind and listen
on registered local addresses work through the same socket service. Existing
wildcard TCP listeners gain and lose endpoints using
[address-change hooks](../src/sys/sys-io/src/runtime/net/tcp_listener.rs).
This works for listeners created before or after registration, subject
to ordinary port conflicts and admission limits; there is no merged accept
queue across processes.

An application UDP socket stays attached to its device. Binding a tunnel
address selects the packet device; ordinary wildcard binds retain physical
or loopback selection and do not start choosing virtual devices.
`connect` and `send_to` do not migrate sockets.
UDP to a local address is delivered locally, preserving the bound source
and receive-queue limits, subject to the device-boundary policy below.

The existing `udp_bind_for_remote` operation selects the route and source
when the destination is known at creation. The DNS resolver uses it for
query sockets; DNS-server configuration itself remains separate.
Ordinary datagrams that would cross the physical/virtual device boundary
or switch virtual devices are dropped and counted. Behavior between
physical devices is unchanged. These per-datagram policy drops do not
invalidate the socket. UDP sends report local queue
acceptance, so this policy does not promise a synchronous `send_to` error
or an error queue for individual datagrams.

WireGuard transport sockets explicitly select a physical local address and
port, one socket per enabled outer address family. Their physical binding
bypasses registered interface routes, including `/0`, for all peer endpoints.
The native SDK UDP bind path exposes that physical-transport intent while
retaining physical UDP port reservations and cleanup.

One terminal UDP socket-invalidation notification covers device removal
and loss of a transport's bound physical address. sys-io discards queued
traffic for the invalidated socket; the SDK marks it failed and wakes
waiting senders and receivers to observe the error. Subsequent sends and
receives fail. This notification is part of the native SDK/socket protocol,
not a new moto-rt/stdlib API or a general network-change subscription.

V1 uses stable configured physical addresses. Address loss/replacement
invalidates the affected transport binding through that notification and
discards queued output using the old source. `wg` treats this as fatal,
closes its registration channel and outer sockets, and exits. sys-io retires
the device without making process exit wait for slow application clients.
Restart `wg` to bind the new address.
There is no automatic rebinding or NIC failover. Peer silence or temporary
transport unreachability does not invalidate the binding or withdraw tunnel
routes while registration remains alive. Peer endpoint roaming still works
within the available outer address families.

## Ping / ICMP echo (v1)

Motor OS's `ping` keeps its existing `IcmpEchoClient` connection to sys-io.
The `NetCmd::IcmpEcho` handler selects the packet device and an inner source
address, then sends via its ICMP socket and the ordinary packet IPC path.
Both ICMPv4 and ICMPv6 work independently of the outer UDP family; no
redirect handling or general-purpose raw-socket API is needed.

Incoming peer probes pass WireGuard authentication and allowed-IP source
validation before reaching sys-io's netstack. The registered interface
inherits its `auto_icmp_echo_reply` policy. Replies to probes of a local
tunnel address travel back through the packet device and `wg`. Existing
echo payload/MTU bounds, reply source/identifier/sequence/payload matching,
timeout and admission still apply.

Transient ICMP sockets and identifiers participate in device lifetime
tracking. Removal cancels pending probes with an error and releases these
resources before reclaiming the device; a later timeout or guard drop must
not access a removed/reused device. Peer silence while it remains registered
times out normally, without plaintext fallback.

## Removal and failure behavior

Unregister or channel death withdraws the device's routes and local addresses,
stops packet delivery, detaches listener endpoints and fails sockets bound to
that device. Wildcard listeners keep their other endpoints. Cleanup stops
poll tasks, releases pages and reservations, and finishes pending operations
with an error. It leaves `None` in the removed device's vector slot and keeps
retiring state outside the active vector until users have detached.
Removed-device sockets, tasks, pages, queue allocations and channel-budget
entries are released; vacant vector slots retain their storage. UDP sockets
use the terminal invalidation notification described above.

Cleanup covers queued packets, pending accepts, TCP TIME-WAIT, pending
ICMP echo requests and parked capacity waiters. Old callbacks cannot target
a replacement device.
Explicit tunnel-only listeners fail on removal; existing connections do not
migrate to a physical interface. Physical and other virtual devices continue.

New connections after removal use remaining routes, including the physical
default. No persistent blocking route is retained. A missing peer/session
alone is not device removal.
`wg` closes its outer sockets when stopping; process death also invokes
ordinary sys-io client-channel cleanup.

## WireGuard process and protocol

`wg` has a separate `src/bin/wg` workspace and lockfile, using standard Rust
and native Motor OS APIs. Each process loads one config/key pair and registers
one device; multiple processes provide independently managed devices.
boringtun and its crypto dependencies stay outside the core sys workspace.

The process uses boringtun 0.7.1's `noise` protocol implementation, with one
`Tunn` per peer and its platform-specific `device` daemon feature disabled.
The embedding process calls `encapsulate`, `handle_verified_packet` and
`update_timers`; results request outer UDP output (`WriteToNetwork`), inner
IP delivery (`WriteToTunnelV4`/`WriteToTunnelV6`), completion (`Done`) or
error handling (`Err`). Replay protection, rekeying and keepalives remain
in boringtun; `wg` supplies peer ownership, dispatch, endpoint learning,
bounded I/O and timer scheduling as specified below.

### The boringtun fork

The dependency is maintained outside this repository in
[moturus/boringtun](https://github.com/moturus/boringtun), branch `motor-os`,
based on the 0.7.1 release commit
`253f7afb2b3df9e952065d10bf2af19913cb176b`. `wg`'s manifest and lockfile pin
revision `dcad5645547a89b278b346a399dbc0fae19a02f4`. The fork has two changes:

1. A `std::time::Instant` fallback in `sleepyinstant` for targets that
   are neither Unix nor Windows, including Motor OS. Suspend-time accounting
   follows each target's `Instant` implementation. The existing `SystemTime`
   implementation supplies the handshake's TAI64N timestamp; no runtime or
   std changes.
2. A public, documented `Tunn::handle_verified_packet`, which upstream
   keeps `pub(crate)`. Its caller must first use the device's shared
   `RateLimiter::verify_packet`. This permits dispatch without a second MAC
   check or limiter charge. Normal public `decapsulate` checks remain intact.

boringtun's crypto implementation is unchanged. The independent reference
peer in `src/tests/wg-peer` uses upstream 0.7.1 with `ring` and a separate
workspace/lockfile.

`getrandom` 0.2 uses a custom backend over
`moto_sdk::rt::fill_random_bytes`, following
[russhd's adapter](../src/bin/russhd/src/lib.rs). The standalone workspace
uses the existing Motor OS `ring` port from
[russhd's manifest](../src/bin/russhd/Cargo.toml), plus the Motor OS
`parking_lot` and `parking_lot_core` patches already used in
[the core manifest](../src/sys/Cargo.toml); these patches are not
inherited from other workspaces. The Makefile builds `ring`'s C/assembly
sources with the selected Motor OS toolchain's `motor-clang` and `ar`.

### Peer ownership, dispatch and roaming

Each registered WireGuard device has one longest-prefix owner table.
TX looks up the inner destination; RX looks up the inner source and requires
the authenticated peer to be that address's owner. Different-length
overlaps are valid; duplicate exact prefixes and duplicate peer public keys
are rejected. A peer owning `/0` cannot send as an address assigned to
another peer's `/32` or `/128`. Inner IP framing, lengths and MTU are checked
before delivery. Packets with no owner are dropped and counted; their
plaintext never goes through the physical default.

One `Arc<RateLimiter>` per device is shared by all of its `Tunn`s, with
the upstream threshold of 100 handshakes/second before cookies. This is a
cookie threshold, not a hard CPU-work cap. Datagram dispatch works as follows:

1. `verify_packet(Some(outer_source.ip()), datagram, scratch)` runs before
   any X25519 operation. A cookie challenge goes back to that datagram's
   source and ends processing; verification errors are dropped. Neither a
   challenge nor a cookie reply authenticates a peer for endpoint learning.
2. A handshake initiation uses `parse_handshake_anon` once with the device
   key pair, then looks up the recovered static public key. It does not try
   every peer. Handshake responses, cookie replies and data use
   `receiver_idx >> 8`. Each `Tunn::new` receives a unique 24-bit peer index
   within this device, independent of the sys-io device-vector index.
   Unknown indices and public keys are rejected.
3. The fork's exposed `handle_verified_packet` processes the selected peer.
   The original datagram does not go through `decapsulate` again, avoiding
   duplicate MAC verification and limiter accounting. Full handshake/session
   authentication and replay checks still occur in the verified handler;
   recovering a public key alone does not authorize an endpoint change.
4. Dispatch tracks the input packet kind as well as `TunnResult`. Successful
   handshake initiation/response handling returns `WriteToNetwork`; an authenticated
   empty data keepalive returns `Done`. Both learn the outer source IP
   and port without requiring an inner packet. Cookies, authentication
   failures and replays never change endpoints. Inner IP source addresses
   never become outer endpoints. Endpoint learning is separate from the
   inner source-ownership check.
5. Handshake responses go to the authenticated datagram's source. When
   output requires a queued-packet flush, `decapsulate(None, &[], scratch)`
   runs until `Done`, stopping on `Err` and respecting the work/buffer limits
   below. Pending flush work survives yields and UDP backpressure.

A responder-only peer with no configured endpoint becomes usable after an
authenticated handshake or keepalive alone. Outbound traffic with neither
a configured nor a learned endpoint is dropped and counted; receiving
cookie traffic does not make such a peer usable.

### Crypto buffers, queues and timers

`wg` bounds packet staging and outer UDP buffers as well as the packet IPC
queues. Staging/queue storage and reusable scratch buffers are reserved
fallibly before activation. Up to 32 decrypted packets can wait for delivery
to sys-io. Admission allows 16 peers and accounts for boringtun's existing
maximum of 256 queued plaintext packets per peer; its internal allocations
remain an upstream limitation. Process-local limits apply to every `wg`
instance; sys-io separately bounds live/retiring registered devices.

Reusable 2048-byte crypto buffers hold handshakes, MTU-sized data and
padding. Oversized or truncated outer datagrams are rejected before library
calls, as are inner packets over the 1420-byte tunnel MTU. boringtun always
receives a sufficiently sized output buffer. Outer UDP uses the physical
stack's existing fragmentation/PMTU handling. Tunnel PMTU propagation is
outside v1.

If the SDK cannot accept an outer send yet, `wg` retains at most one
additional ciphertext datagram per device and registers its send waker. Plaintext TX
and queued flushes stop advancing until capacity returns, while RX and
timers continue. A response that fits neither the socket queue nor that
pending slot is dropped and counted. There is no spinning or unbounded
retry queue. SDK acceptance is not delivery confirmation; downstream UDP
loss uses ordinary protocol recovery. Pending ciphertext retains its destination
and is discarded when the physical binding is invalidated.

An absolute 250 ms timer deadline survives packet wakeups. When due,
`wg` calls `update_timers` for every peer and `reset_count` on the shared
limiter; it internally resets at most once per second. Timer output follows
the same bounded send path. A batch processes at most 32 packet operations,
including drops and queued flushes, then checks timers and yields. RX and
TX alternate when both are ready. Deadlines remain active under continuous
traffic. Counters cover queue drops, malformed or unauthenticated input,
disallowed sources and unavailable transport, without per-packet warning
logs under floods.

## Configuration and secrets

`wg` reads one explicit config/key pair once, using standard Rust/native
filesystem APIs. The [usage section](#prepare-the-configuration-and-keys)
shows the file layout and TOML format. Both files must be regular files.
The filename stem supplies the registered device name, not a sys-io vector
index. Private keys, peer public keys and optional preshared keys are
base64 values decoding to exactly 32 bytes. Configuration or key changes
require a restart.

`transport_addresses` selects one currently assigned physical local address
per enabled outer family. At least one is required; duplicate families and
nonphysical addresses are rejected. `listen_port` is an explicit nonzero
`u16` port.
Endpoint addresses are numeric unicast socket addresses with nonzero ports;
DNS endpoint resolution is outside v1. Their families must have a configured
physical transport. The bound physical device provides link-local IPv6 scope;
explicit scope IDs are rejected rather than silently discarded. An omitted
endpoint permits responder-only operation. Keepalive absent or zero means
disabled; otherwise it is a `u16` interval in seconds.

`cidrs` assigns local tunnel addresses; peers' `allowed_ips` supply remote
routes and peer ownership. Each allowed-IP family requires a local tunnel
address. Unknown fields, malformed keys/CIDRs, duplicate peer public keys,
duplicate exact prefix owners, missing file partners, unsupported families
and local address/device-name conflicts are rejected. Port reservations use
the ordinary physical UDP admission rules; conflicts fail before activation.

Each file read is bounded at 64 KiB, and each process allows at most 16 peers,
16 local addresses and 128 allowed prefixes before allocating peer runtime
state. Peer limits account for their internal queues; sys-io's device quota
is separate from these process-local crypto limits. Both files are validated
and resources reserved before activation. Failures close any opened outer
sockets and registration channel, releasing their reservations. The private key and
any PSK-bearing TOML are secrets.

`/user/cfg/` already has the imager policy `rwxrwx---` for directories and
`rw-rw----` for files: System and Interactive can read them, None cannot,
and all Interactive processes share that access. `wg` checks the actual
permissions of both files when loading them and refuses either file if None
can read it. This rule applies to every config, whether or not it contains a
PSK. Imager policy does not establish the permissions of files uploaded or
created later. `wg` does not change file permissions. Errors are sanitized;
they never include keys, packet contents or TOML excerpts containing secrets.
sys-io has no WireGuard-specific loader or crypto state, although it remains
the filesystem service through which config and key bytes are read.

## Tradeoffs and reuse

This keeps WireGuard failures outside sys-io while retaining one socket
implementation and its admission policies. It adds packet IPC, device
lifecycle and routing work; it does not eliminate sys-io TCP/IP processing.
The [measurements](wireguard-measurements.md) compare an unencrypted packet
device and WireGuard with matched guest-client/host-server endpoints, plus
a physical-network reference, on default and small VMs. Their interpretation
accounts for different forwarding schedules and host TCP stacks. V1 retains
one packet per IPC message; batching is a possible profiling follow-up.
Shared pages do not imply zero-copy. Single-vCPU WireGuard receive throughput
was variable in those measurements and remains a profiling limitation.

The same IP-device contract could support other VPN/mesh transports, a host
link over vsock, controlled loss/delay/reordering test links, or packet
inspection/shaping for traffic deliberately routed through the device.
These are future consumers, not additional v1 implementations. Ethernet
bridging would require a separate extension.
