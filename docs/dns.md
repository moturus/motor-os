# Motor OS DNS resolver service

DNS resolver serves bounded IPC and DNS on `127.0.0.1:53` (UDP and TCP). Its
backend is native Rust and depends only on Motor OS networking and
filesystem APIs.

## Request path

```text
Rust application
  -> rt.vdso lookup_host
  -> moto-dns bounded synchronous IPC
  -> dns-resolver service
  -> connected UDP, with TCP fallback
  -> sys-io
```

Numeric addresses and `localhost` retain their VDSO fast paths. Other names use
a fresh `moto_dns::Client` per lookup, so a dead resolver connection is not
cached and a restarted service is discoverable by the next call. The service
keeps four fixed IPC workers and the versioned, pointer-free request/response
contract in `moto-dns`. The loopback listener has two UDP and two TCP workers.
It is optional: listener startup failures are logged and IPC startup continues.
Workers already started remain running if a later spawn fails. A UDP receive or
TCP accept error is logged and stops only the affected worker while IPC continues.
Unmodified mlibc uses this listener through its default nameserver when
`/system/cfg/libc/resolv.conf` is absent; images no longer generate that file.

## Configuration

The service checks numeric addresses and `/system/cfg/libc/hosts` first.
For other names it reads `/system/cfg/sys-net.toml` and the current
`/system/tmp/sys-io/dhcp.toml` snapshot on each lookup. Static devices supply
`dns_servers`; devices with `dhcp = true` use an unexpired lease's servers.
Absent interfaces and lost or expired leases supply no servers. In device-name
order, at most the first two unique nameservers are used, preserving each
device's server order. Unspecified addresses and `127.0.0.1` are excluded to
avoid forwarding to the listener itself.

sys-io atomically replaces the snapshot at boot and on DHCP acquisition,
renewal (including unchanged addresses), and loss. It contains `active_devices`
and a `[devices.NAME.lease]` table for each current DHCP lease, with address/prefix,
router, DNS servers, server address and identifier, and acquisition, renewal,
rebinding and expiry timestamps in Unix milliseconds. An unleased DHCP device
has an empty `[devices.NAME]` table. See [networking.md](networking.md).

The snapshot's mode is `rw-r-----`: System writes, Interactive reads, None has
no access. `/system/tmp` and its `sys-io` directory permit Interactive traversal.
The resolver runs with CAP_INTERACTIVE, CAP_NET and CAP_LOG, without CAP_FS_WRITE.
Read-only roots work with writable `/system/tmp` and `/system/logs` mounts;
DNS no longer writes under `/system/cfg/libc`. An older image's existing
`resolv.conf` must be removed offline to select mlibc's loopback default.

## Transport and validation

Each native address lookup's UDP attempt:

- creates a fresh socket, giving it a freshly randomized ephemeral source port;
- connects it to the selected nameserver, so packets from other sources are
  discarded by the socket;
- generates a fresh random 16-bit transaction ID;
- sends one recursive A or AAAA question;
- applies a one-second receive deadline;
- validates the transaction ID, response bit, opcode, one echoed question,
  canonical question name, type, class, response code, record bounds, and DNS
  compression pointers;
- accepts address records only for the question name or a preceding validated
  CNAME target;
- deduplicates returned addresses.

UDP delivery is intentionally unreliable, so the backend performs one bounded
retransmission. Each attempt uses a new socket and transaction ID. NXDOMAIN is
terminal and is not retried. A response with the truncated bit set is repeated
over a connected DNS-over-TCP stream using the same query and strict parser.

There is no cache. Correct caching requires retaining and applying each DNS
record's TTL and negative-cache policy; an arbitrary service TTL would trade a
small speedup for stale answers.

The loopback frontend accepts one IN-class question per request, up to 4096
bytes. It answers local A/AAAA queries from the same hosts/numeric lookup and
forwards other queries, including PTR, preserving upstream records and TTLs.
UDP replies are at most 512 bytes; larger answers return the question with TC
set for TCP fallback. TCP serves one query per connection with a one-second
request-read deadline. Malformed requests receive FORMERR; unavailable upstreams
receive SERVFAIL; zone transfers are unsupported. It binds only IPv4 loopback.

## Result contract

The existing resolver statuses remain unchanged: success, not found,
temporary failure, timeout, out of memory, unsupported family, system failure,
resolver failure, invalid request, and busy. The VDSO maps those to stable
Motor OS errors. Combined lookups preserve IPv4-before-IPv6 collection before the
existing destination-ordering policy is applied.

`dns-resolver --self-test` covers numeric and hosts-file lookup, malformed
requests, result ordering, IPC restart behavior, live external resolution, and
a deterministic loopback DNS fixture. The fixture drops the first UDP query,
returns a truncated response to the retransmission, and completes the lookup
over TCP.

`--self-test-local` covers the hermetic subset, both loopback transports, IPC,
and snapshot permissions. `test-block-mounts.sh`, called by `full-test.sh`, runs
it on a read-only root containing the libc directory. Its QEMU DHCP fixture
checks a real acquired lease and resolver selection with `--test-dhcp`, and
verifies that the root image remains byte-for-byte unchanged. `full-test.sh` also
restarts the service while another process holds port 53. It waits only for
service discovery, then checks a native lookup once and verifies that the log
reports the loopback listener startup failure.
