# WireGuard

## Using WireGuard

The standard image includes `/system/bin/wg-tool` and `/system/bin/wg`.
Run the tool in an Interactive session. Each daemon provides one tunnel
device; activation is explicit, and the image contains no keys or configs.

```sh
wg-tool new
wg-tool add-peer /user/cfg/wireguard/wg0.toml
wg-tool up /user/cfg/wireguard/wg0.toml
wg-tool status
wg-tool down wg0
```

### Create a configuration and add peers

`new` prompts for the interface name, config filename, UDP port, tunnel CIDRs,
and physical transport addresses. Enter accepts the value in brackets. The
suggested name is the first unused `wgN`, considering saved configurations
and running interfaces. The default directory is `/user/cfg/wireguard`, the
port is `51820`, and the tunnel CIDR is `10.20.0.1/24`. Review these choices
for your network. A custom filename does not change the interface's name.

Name suggestions consider config names and filename stems in the default
directory, plus running interfaces; inactive configs elsewhere are not scanned.
An unreadable or invalid `.toml` there aborts `new` with the failing path in
the diagnostic. Discovery errors also abort rather than suggesting a name
whose availability is unknown. The physical-address suggestion comes from a
local UDP bind, without sending traffic or consulting DNS; supply an assigned
address if no suitable default is available.

Lists accept comma-separated values with surrounding whitespace ignored.
Invalid input explains the constraint and prompts for that field again.
Backspace/Delete edits the current line; Ctrl+U clears it. Newline-delimited
answers on stdin are also accepted. Creation and peer additions require an
explicit `yes` or `y`; confirmation defaults to `no`, and EOF never confirms.

After an explicit confirmation, the tool generates a key pair using the
native random source and writes both keys inside TOML. It prints the public
key to exchange with the other peer. Keep the config private: it contains
the private key. No adjacent key file is created or read. Existing files
are never overwritten by `new`.

`add-peer [FILE]` prompts for an optional peer name, public key, numeric
endpoint, allowed IPs, keepalive interval, and optional hidden preshared key.
Without `FILE`, it prompts for the filename, defaulting to
`/user/cfg/wireguard/wg0.toml`. Peer names are comments, such as
`# Peer: office laptop`; identity still comes from the public key. Names
may repeat and are limited to 128 UTF-8 bytes without control characters.
The tool neither generates nor exchanges a PSK automatically. Existing
comments and formatting survive additions, including handwritten inline
peer arrays. Empty endpoint input waits to learn an authenticated endpoint;
at least one side needs a reachable endpoint. Keepalive defaults to off;
25 seconds is a common choice for maintaining a NAT mapping.

The generated schema is:

```toml
cidrs = ["10.20.0.2/32"]
listen_port = 51820
name = "wg0"
private_key = "<generated base64 private key>"
public_key = "<derived base64 public key>"
transport_addresses = ["192.0.2.2"]

# Peer: office laptop
[[peers]]
allowed_ips = ["10.20.0.0/24"]
endpoint = "192.0.2.1:51820"
# persistent_keepalive = 25
# preshared_key = "<optional shared base64 32-byte key>"
public_key = "<other peer's base64 public key>"
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

`name` and `private_key` are required. `public_key` may be omitted in a
handwritten file; if supplied, it must match the derived key. Names contain
1–31 ASCII letters, digits, underscores or hyphens. Zero peers is valid:
`new` omits the peer list, and `peers = []` is also accepted.

Files created by the tool use `rwxrw----`; its private directory uses
`rwxrwx---`, in System/Interactive/None order. The native filesystem requires
an Interactive creator to leave System permissions at `rwx`. None receives
no access. The daemon and tool reject None-readable files and None-writable
directory ancestry. See [filesystem permissions](fs-permissions.md).

`new` and `add-peer` require `CAP_FS_WRITE` as well as filesystem access.
`new` also needs `CAP_NET` for discovery and the transport suggestion;
`status` and `down` require `CAP_NET`.

Edits preserve permissions and publish through a private staging file. A
read-only target or parent is an error. An existing file with more restrictive
System permissions can be loaded, but `add-peer` refuses to replace it:
Interactive cannot create a staging file preserving those permissions.
Run at most one `wg-tool` at a time and do not manually edit a file while the
tool is editing it; there is no coordination between writers.

### Start, check and stop the tunnel

`up FILE` starts a detached Interactive daemon and waits for local activation.
It remains running after the tool, terminal, and SSH session exit. The launcher
needs `CAP_NET`, `CAP_SPAWN`, and `CAP_SPAWN_DETACHED`. The shipped Rush config
grants detached-spawn authority to these programs:

```toml
spawn-detached = ["rmux", "wg-tool"]
```

This is the `spawn-detached` setting in `/user/cfg/rush.toml`. If a customized
config lacks `wg-tool`, update it and start a new shell. Only the launcher
needs spawn authority: the daemon receives `CAP_INTERACTIVE | CAP_NET`, with
no spawn, detached-spawn, filesystem-write, or System capability.

`wg0: up (pid=..., peers=...)` confirms local registration, not a handshake or
reachability. A zero-peer interface owns its addresses and port but cannot
exchange tunnel traffic. To probe a configured peer explicitly:

```sh
ping -c 3 10.20.0.1
stats providers
```

`status` shows actual loaded settings, public keys, lifecycle state, uptime,
snapshot age, and peer endpoints, handshake ages and tunnel byte counters.
Snapshots refresh on the existing 250 ms tick. A missing session is shown
as `none (no current session)`; it does not imply no handshake ever occurred.
Status remains available after moving or deleting the original config.
Interfaces are sorted by name. A peer's endpoint is its authenticated roaming
address when learned, its configured address otherwise, or `not learned` if
neither exists. If some daemons cannot be queried, status retains successful
results, reports each failed PID, and exits 1. An empty successful discovery
prints `No WireGuard interfaces are running.` and exits 0. Status sends no
WireGuard traffic and is a human-readable format, not a versioned scripting API.

Use `stats get PID` with the printed PID to read the `wg:PID` provider's
authentication, ownership, drop and timer counters. Snapshots update on the
250 ms timer tick. `stats list` describes metrics; sys-io also reports
`net.ip_device.*` queue/buffer counters and `net.udp.tx_boundary_drops`.
Incoming peer pings require `auto_icmp_echo_reply` in
`/system/cfg/sys-net.toml`; registered interfaces inherit that setting.

`down INTERFACE` waits for acknowledged retirement and release of physical
UDP bindings. Routes and addresses are removed, existing tunnel sockets fail,
and new connections use remaining routes, including the physical default.
Repeating `down` for an absent interface succeeds. A timeout reports an
unconfirmed outcome; use `status` to inspect it. There is no force-kill fallback.
Discovery or candidate-query errors are failures, not evidence that an
interface is absent. `down` matches the exact, case-sensitive interface name
without rereading its config, and leaves the config and keys on disk.

`add-peer` changes only the saved config. A running daemon keeps its loaded
peers until an explicit `down`/`up`. Repeating `up` fails instead of reloading
or replacing a running instance. Device names, addresses, identical route
prefixes and physical listen ports must not conflict. Sys-io allows four
active or retiring packet devices.

For foreground diagnostics, `wg FILE` uses the same schema and control service
and prints `NAME: active (pid=...)`. Stop it with Ctrl+C or `wg-tool down NAME`.
Both tool and daemon require Interactive authority. A silent peer leaves
routes installed; physical transport-address loss ends the daemon. Correct
the config and start it again. There is no automatic restart or boot startup.

Use `wg-tool --help` or `wg-tool COMMAND --help` for syntax. Operands beginning
with `-` need `--` before them.
Ctrl+C, a declined confirmation, or EOF exits 130; syntax errors exit 2 and
operational errors exit 1. Prompts and errors go to stderr, results to stdout.
Keys and PSKs are never included in errors.

Relative config paths resolve against the caller's working directory; `~`
and environment expansion belong to the calling shell. Files must have a
`.toml` extension, with an absolute UTF-8 path of at most 1024 bytes and
filename components of at most 255 bytes. The default private directory can
be created after confirmation; a custom parent directory must already exist.
Existing directory permissions are checked rather than silently changed.

### Routing and troubleshooting

New TCP connections, ping and destination-aware UDP binding select the
tunnel automatically for matching routes. Ordinary wildcard UDP binding
still selects a physical or loopback address; bind explicitly to a tunnel
address when needed. Existing sockets do not migrate between devices.
WireGuard does not change DNS-server configuration. DNS queries follow the
route to the configured server, so its address must be covered to tunnel DNS.

If startup fails, check configuration permissions, launcher capabilities, physical
address assignment, UDP port conflicts and device/address/route conflicts.
Errors identify the operation without printing keys or TOML contents. If an
active tunnel cannot reach its peer, check the endpoint, keys and reciprocal
allowed prefixes, then inspect the authentication and drop counters. Ping
also requires the peer to answer ICMP echo requests.

Startup and control operations have five-second deadlines. If `up` reports
an unconfirmed activation, run `wg-tool status` and look for the reported PID
before trying another start. A rejected configuration or an observed daemon
exit is a definite failure; uncertainty is reported for a deadline expiry or
a lost startup connection after readiness. A timed-out stop can still finish.

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
* Configs with inline keys default to `/user/cfg/wireguard/`; explicit paths
  elsewhere are supported. The binaries ship as `/system/bin/wg` and
  `/system/bin/wg-tool`.
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
and native Motor OS APIs. Each process loads one inline-key config and registers
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

`wg` reads one explicit inline-key configuration once, using native filesystem
APIs. The [usage section](#create-a-configuration-and-add-peers) shows the TOML
format. The config must be a regular file. Its `name` field supplies the
registered interface name, independently of the filename. Private keys,
peer public keys and optional preshared keys are
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
address. Local CIDRs retain their host addresses; allowed prefixes are
normalized to network addresses. Nested prefixes use longest-prefix
ownership. Unknown fields, malformed keys/CIDRs, duplicate peer public keys,
duplicate exact prefix owners, missing identity fields, unsupported families
and local address/device-name conflicts are rejected. Port reservations use
the ordinary physical UDP admission rules; conflicts fail before activation.

Each file read is bounded at 64 KiB, and each process allows at most 16 peers,
16 local addresses and 128 allowed prefixes before allocating peer runtime
state. Peer limits account for their internal queues; sys-io's device quota
is separate from these process-local crypto limits. The config is validated
and resources reserved before activation. Failures close any opened outer
sockets and registration channel, releasing their reservations. The private key and
any PSK-bearing TOML are secrets.

`wg-tool` creates files with `rwxrw----` and directories with `rwxrwx---`.
All Interactive processes share this access; None has none. `wg` checks the
actual entry's permissions and rejects None-readable configs and None-writable
ancestry before reading secret bytes by that same entry ID. This applies to
every config, including those without a PSK. `wg` does not change permissions.
Errors are sanitized; they never include keys, packet contents or TOML
excerpts containing secrets. Displayed paths escape control characters.
sys-io has no WireGuard-specific loader or crypto state, although it remains
the filesystem service through which config bytes are read.

The writer creates staging files with their final permissions before writing
any secret bytes. It writes and flushes a private staging file in the destination
directory, then publishes with a non-replacing move for `new` or a replacing
move for `add-peer`, and flushes publication before reporting success.
Peer edits insert only the new entry, using TOML source spans, and reparse the
result before publication. Existing settings, keys, peer order, comments,
formatting and LF/CRLF convention are preserved, including inline peer arrays.

A failure before publication preserves the original; the tool removes its
staging file or reports a cleanup failure. A crash may leave a private staging
file, which is never loaded or automatically published. If the final flush
fails after publication, the destination has been updated but durability is
unconfirmed. The tool reports this without rolling back. It makes no automatic
secret-bearing backups and does not coordinate concurrent editors.

## Daemon management

### Discovery and control

`new`, `status` and `down` issue one
[`IoStatsService::list_external_net_device_pids`](../src/sys/lib/moto-sdk/src/sys_io/stats.rs)
request to `sys-io-stats-service`. This generic query requires `CAP_NET` and
returns unique kernel-authenticated owners of active and still-retiring
external IP devices. Physical NICs and loopback are excluded; non-WireGuard
providers can be present. The complete response fits one 4 KiB IoBuf, with
no paging or truncation. Query failure is distinct from a successful empty
list, and ownership disappears when device retirement finishes.

The tool closes the discovery connection, then contacts only returned PIDs
at `wg-control-PID`, sequentially. `E_NOT_FOUND` skips a provider without a
WireGuard endpoint or one that disappeared after discovery. Busy, denied,
malformed or failed connections are errors. There is no process enumeration,
PID-file lookup, statistics-provider fallback, or automatic retry. New
registrations appear on the next invocation.

Each daemon uses native synchronous IPC with
`LocalServer::new(url, ChannelSize::Small, 1, 1)`: one listener, at most one
connected client, and one request in flight. Both ends authenticate kernel
PID and capability information. The client verifies the discovered PID;
both peers must be Interactive with `CAP_NET`. A process with `CAP_SYS` is
System even if `CAP_INTERACTIVE` is also set, and is rejected. The endpoint
name or a caller-supplied identity does not establish authority.

`GET_INTERFACE` captures one redacted snapshot and returns interface fields
and the peer count. `GET_PEER(index)` reads peers from that snapshot on the
same connection. `STOP` uses the connection that identified the interface,
wakes the forwarding scheduler, and replies after device retirement and
physical UDP cleanup. One control thread serves requests independently of
packet forwarding; control-service failure ends the daemon. Disconnecting
releases the query snapshot and allows the next invocation to connect.
There are no subscriptions, concurrent requests or client-idle timers.

The five-second control deadline covers discovery and all replies; the tool
disconnects on completion or failure. Messages fit the 4 KiB channel. Shared
input is copied before validating versions, flags, lengths, counts and
indices, and response reserved fields are initialized. Only explicitly
redacted interface and peer fields cross IPC. See
[`control.rs`](../src/bin/wg/src/control.rs) for payloads and
[`motor_ipc.rs`](../src/bin/wg/src/motor_ipc.rs) for framing and authentication.
The existing statistics protocol remains separate.

### Managed startup

`up` resolves the config path and launches `/system/bin/wg` with null standard
streams, an explicit detached request, and the reduced capability mask
described above. The daemon reads its own config; argv, environment variables
and startup IPC contain no keys or TOML. The launcher first creates a private
synchronous endpoint with one listener and one connection, authenticated on
both ends for that launcher and child.

The daemon connects before loading its config, so load errors can be reported
as bounded error codes. After physical bindings, the control service and
interface registration are ready, it sends `READY`. Startup remains
provisional until the launcher acknowledges that message. Earlier launcher
exit, connection loss or deadline expiry releases provisional resources and
ends the daemon. After acknowledgment, the daemon survives launcher exit;
it sends `COMMITTED`, and a lost final receipt does not undo activation.
The startup deadline is five seconds, and uncertain outcomes retain the PID
for inspection with `status`. See [`launch.rs`](../src/bin/wg/src/launch.rs).

## Validation

The focused guest gate builds its image and native test binaries, then runs
with a hermetic local host peer. With the repository's VM test networking
configured, run either build mode from the repository root:

```sh
src/tests/test-wireguard.sh
src/tests/test-wireguard.sh --release
```

This exercises configuration creation and edits, native permissions and
capabilities, discovery and malformed IPC, startup/stop failure paths,
detached lifetime, and IPv4/IPv6 traffic with the independent upstream peer.
`src/tests/test-system-tty.sh` (also accepting `--release`) covers System-role
rejection, including a System caller that also has `CAP_INTERACTIVE`.

Host parser, prompt, editor, redacted-protocol and interoperability tests run
with `cargo test --manifest-path src/bin/wg/Cargo.toml --locked`; add
`--release` for the release build. These checks and the native discovery
API tests are reached through `src/tests/full-test.sh` in the selected build
mode. WireGuard tests use local peers and do not require Internet access.
Use the existing [benchmark procedure](wireguard-measurements.md) when changing
forwarding or statistics publication.

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
