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

## Admission and response limits

`max_half_open_global` and `max_half_open_per_listener` bound sockets in
SYN-RECEIVED. `max_backlog_global` and `max_backlog_per_listener` bound the
demand-grown pools behind listeners. All four values must be nonzero; each
socket reserves receive and transmit rings, so large values have a direct
memory cost.

`max_icmp_error_rate`, `max_rst_rate`, and `max_syn_cookie_rate` are per-device
responses-per-second limits with a one-second burst. They limit traffic whose
destination is controlled by a possibly forged source address. Zero is
rejected; omit a key to use its compiled default.

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
