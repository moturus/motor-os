# Networking configuration and operation

Motor OS reads `/system/cfg/sys-net.toml` when sys-io starts. A malformed file
prevents sys-io from starting; a valid file that matches no NIC deliberately
leaves only loopback and logs the unmatched devices. The file is currently an
image input, so use DHCP for one reusable cloud image or provision a distinct
file into each static-address image.

## Interface configuration

`loopback` enables the built-in `127.0.0.1/8` and `::1/128` interface.
`auto_icmp_echo_reply` controls automatic echo replies. It does not bypass the
rules that suppress multicast, broadcast, or foreign-destination replies.

Each `[devices.NAME]` table consumes one virtio-net device. With `mac`, the
entry selects that exact hardware address. Without `mac`, entries consume the
remaining devices in deterministic table-name order. Unmatched entries and
unconfigured NICs are logged.

A static device uses:

```toml
[devices.net0]
cidrs = ["192.0.2.10/24", "2001:db8::10/64"]
dns_servers = ["192.0.2.53", "2001:db8::53"]

[[devices.net0.routes]]
ip_network = "0.0.0.0/0"
gateway = "192.0.2.1"
```

`dns_servers` supplies resolver addresses for a static device. Each route's
gateway must be reachable through a CIDR on the same device.
Route selection uses the longest matching prefix and prefers a connected route
over an equally specific gateway route.

For a reusable DHCPv4 image:

```toml
[devices.net0]
dhcp = true
```

DHCP owns the device's IPv4 address, default route, and advertised DNS servers.
Static IPv4 CIDRs, routes, or DNS servers on the same device are rejected,
while static IPv6 configuration may coexist. On renewal, replacement, or lease
loss, sys-io updates the address and route and atomically republishes the
aggregate active DNS server list in `/system/cfg/libc/resolv.conf`. Duplicate
servers are removed without reordering devices or servers.

Wildcard TCP listeners begin accepting on an address when a lease installs it
and stop accepting new connections when the address disappears. Established
and already-progressing TCP connections are not aborted solely because a lease
was lost. Applications must still handle the ordinary I/O failure that follows
when the old address is no longer usable.

## WireGuard

`wg` runs as a separate process. Each instance registers one IP device with
sys-io; applications keep using the normal TCP, UDP and ICMP APIs. Start it
from a System or Interactive process with `CAP_NET` and access to its files:

```sh
wg /user/cfg/wireguard/wg0.toml
```

The filename supplies the device name. The adjacent `wg0.key` contains the
base64 encoding of the 32-byte private key. Names contain up to 31 letters,
digits, underscores or hyphens. Another configuration, such as `wg1.toml`,
can run concurrently. No keys or automatic tunnel startup are installed by
the standard images.

A minimal configuration is:

```toml
transport_addresses = ["192.0.2.10"]
listen_port = 51820
cidrs = ["10.20.0.2/32"]

[[peers]]
public_key = "<peer's base64 public key>"
endpoint = "192.0.2.1:51820"
allowed_ips = ["10.20.0.0/24"]
# persistent_keepalive = 25
# preshared_key = "<optional base64 32-byte key>"
```

`transport_addresses` names existing physical addresses, at most one for
each IP family. `wg` binds these explicitly; a tunnel default route cannot
capture its encrypted UDP traffic. IPv6 endpoints use bracketed numeric
addresses. Omit `endpoint` for a responder that learns the peer's address
from authenticated traffic. DNS endpoint names, scoped IPv6 endpoints and
configuration reload are not supported in v1; restart with a revised file.

Keep **both** files unreadable by None. The TOML can contain PSKs, so it is
checked like the private key. A System instance can use `r--------` for both
files; an Interactive instance needs Interactive read permission too, for
example `r--r-----` installed by System. SFTP's numeric modes are translated
to Motor roles: uploading from Interactive and applying `chmod 660` in SFTP
keeps None excluded while leaving the higher System permission unchanged.
Inspect the installed permissions with `ls -l`. Motor's own `chmod` takes
the nine-character permission word; see [filesystem permissions](fs-permissions.md).
Protect the parent directory as well when lower roles must not replace a file.

Allowed prefixes install routes directly to the IP device, including
prefixes outside its local CIDRs and optional defaults. Longest prefixes
win; at equal length connected routes precede registered routes, which
precede physical gateway routes. Different peers may own nested prefixes;
an exact prefix cannot have two owners. Inbound source addresses must belong
to the authenticated peer under the same longest-prefix rule.

New TCP connections, ping and destination-aware UDP binding select the
tunnel source automatically. Ordinary wildcard UDP binding still picks a
physical address. Bind UDP explicitly to a tunnel address when needed;
sending across a physical/packet-device boundary from an existing ordinary
UDP socket drops that datagram and increments the boundary-drop counter.
WireGuard does not change resolver configuration. DNS uses the route to the
configured DNS server, so that server's address must be covered to tunnel DNS.

Stopping or killing `wg` removes its routes and addresses. Existing tunnel
sockets fail; new requests use the remaining routes, including the physical
default. A silent peer leaves the device and routes installed. Physical
address loss invalidates the outer UDP socket and ends the tunnel process.
Reusing a name creates a new device slot; old sockets cannot reach it.

WireGuard uses MTU 1420. Each instance accepts up to 16 peers, 16 local
addresses and 128 allowed prefixes in total. Config and key files are bounded
at 64 KiB each. sys-io admits at most four active or retiring packet devices,
with 64 packets per queue in each direction. Slow consumers cause bounded
backpressure or counted packet drops. Registered interfaces inherit
`auto_icmp_echo_reply` from `sys-net.toml`.

The startup line includes the process PID. `stats providers` lists its
`wg:PID` provider; `stats get PID` reads its authentication, ownership, drop
and timer counters. These snapshots update on the 250 ms timer tick. sys-io
also exposes `net.ip_device.*`, including queue high-water marks and buffer
bytes, and `net.udp.tx_boundary_drops`. `stats list` describes the current metric
names. Errors name the failed operation without printing keys or TOML content.

The local integration gate is `src/tests/test-wireguard.sh`, sourced by the
full system test. It creates temporary keys and uses the independent host
peer over moto-tap. For matched release measurements, run
`src/tests/bench-wireguard.sh physical`, `plain`, and `wireguard`. The script
builds its artifacts and starts a fresh release VM for each mode. The client
always runs in the guest. The latter two use the same host netstack and inner
MTU; the physical reference uses Linux TCP. Set `MOTO_SMP` and
`MOTO_MEMORY_MIB` to repeat with another VM size.
See [the initial measurements](wireguard-measurements.md) for throughput,
latency, CPU, queue occupancy and wait/wake counts, with their limitations.

## Admission and response limits

`max_half_open_global` and `max_half_open_per_listener` bound sockets in
SYN-RECEIVED. `max_backlog_global` and `max_backlog_per_listener` bound the
demand-grown pools behind listeners. All four values must be nonzero; each
socket reserves receive and transmit rings, so large values have a direct
memory cost. They default to 128 globally and 32 per listener, as does the
limit on connections waiting to be accepted; below 256 MiB of RAM each is a
quarter of that. TCP buffers default to 128 KiB per direction, 64 KiB below
256 MiB of RAM and 32 KiB below 128 MiB.

`max_icmp_error_rate`, `max_rst_rate`, and `max_syn_cookie_rate` are per-device
responses-per-second limits with a one-second burst. They limit traffic whose
destination is controlled by a possibly forged source address. Zero is
rejected; omit a key to use its compiled default.

The client runtime reserves storage for socket close requests and pending
TCP transmissions before admitting a socket. Closing it uses that storage
without allocating or waiting for send-queue space, including after a
canceled operation receives a late reply. Insufficient cleanup storage
refuses a new reservation with `OutOfMemory`.

## Failure and diagnostics

sys-io owns live filesystem and networking state that cannot currently be
reconstructed safely in a replacement process. Motor OS therefore uses a
fail-stop policy: if sys-io exits or is killed, the kernel logs its status and
halts the VM instead of attempting an unsafe partial restart.

Configure the hypervisor to retain the VM's serial console. Kernel, sys-io,
sys-init, and headless service logs are emitted there, and it remains the only
diagnostic channel when networking or sys-io itself has failed. For QEMU,
`run-qemu.sh` uses `-nographic`, so redirect its stdout/stderr to a retained log.
Cloud deployments should enable their provider's serial-console capture before
first boot.
