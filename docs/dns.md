# Motor OS DNS resolver service

DNS resolver is a standalone bounded IPC service. Its
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
keeps four fixed workers and the versioned, pointer-free request/response
contract in `moto-dns`.

## Configuration

The service reads `/system/cfg/libc/hosts` first and
`/system/cfg/libc/resolv.conf` second. sys-io owns `resolv.conf`: before
starting services it atomically publishes the DNS servers from active static
device configuration, then republishes the aggregate whenever a DHCP lease
changes. Static servers are declared with `dns_servers` in `sys-net.toml`;
DHCP-configured devices use the servers in their leases. At most the first two
unique nameservers are queried, keeping one-family lookup latency inside the
IPC deadline when both are unavailable.

## Transport and validation

Each UDP attempt:

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

## Result contract

The existing resolver statuses remain unchanged: success, not found,
temporary failure, timeout, out of memory, unsupported family, system failure,
resolver failure, invalid request, and busy. The VDSO maps those to stable
Motor errors. Combined lookups preserve IPv4-before-IPv6 collection before the
existing destination-ordering policy is applied.

`dns-resolver --self-test` covers numeric and hosts-file lookup, malformed
requests, result ordering, IPC restart behavior, live external resolution, and
a deterministic loopback DNS fixture. The fixture drops the first UDP query,
returns a truncated response to the retransmission, and completes the lookup
over TCP.
