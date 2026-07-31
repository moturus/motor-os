# TCP listener burst/backlog fix

## Problem

The 2026-07-28 release soak recorded 161 rnetbench client
`ConnectionRefused` failures across 118 runs. The failures occurred immediately
after a successful round-robin phase, while the rnetbench server, QEMU, sys-io,
and the rest of the VM remained live. A later client iteration generally
passed.

The stress harness runs two independent rnetbench clients against one server:

- `net-rr`: four parallel streams
- `net-bulk`: four parallel streams

When their throughput phases align, they can initiate eight TCP connections at
once.

Motor OS currently creates four sys-io listening sockets for a standard
`TcpListener`. Each incoming SYN consumes one listening socket and schedules a
replacement asynchronously. If more than four SYNs arrive before those tasks
run, no listening socket remains to match the port and the extra connection is
reset. The API documentation for `bind_tcp_listener_request` describes this
exact rejection mode.

The user-space backlog passed to `listen()` currently controls queued accept
requests in `moto-io`, but it is not propagated to the sys-io listening-socket
pool. Thus a standard listener can advertise a much larger backlog while
sys-io can absorb only a four-connection SYN burst.

This is a TCP listener/backlog defect exposed by rnetbench. Retrying in
rnetbench, staggering its connections, increasing timeouts, or splitting the
stress workloads across ports would hide the defect and is not proposed.

## Goals

- Make the sys-io listening pool reflect the backlog requested by a standard
  TCP listener, up to sys-io's existing limit of 32 sockets per address.
- Preserve the existing four-socket pool until `listen()` supplies a larger
  backlog.
- Prevent the aligned two-client, eight-connection rnetbench burst from being
  refused.
- Add deterministic regression coverage to the VM-side system tests already
  included transitively by `src/tests/full-test.sh`.
- Avoid retries, ignored failures, or longer timeouts.

## Proposed implementation

### Patch 1: propagate listener capacity

1. Append a TCP-listener capacity command to `moto-sys-io`'s network protocol
   without renumbering existing commands.
2. Add a request helper carrying the listener handle and requested capacity.
3. Track the configured per-address listening-socket target in sys-io's
   `TcpListener`.
4. On a capacity increase, create only the additional listening sockets and
   return success after they are installed. Keep the existing upper bound of
   32 and reject invalid values.
5. Add an async `moto-io` listener method that sends this request.
6. Have the POSIX `listen()` path configure sys-io before returning, then apply
   the existing local accept backlog.

The initial bind remains at four listening sockets. Standard services allocate
the additional sockets during `listen()`, not earlier during bind or OS boot.
Native users that bind and accept without requesting a backlog retain the
current four-socket behavior.

### Patch 2: deterministic regression test

Add a `systest` TCP case that:

1. Binds one standard loopback `TcpListener`.
2. Releases eight client threads from a barrier so their connects form one
   burst.
3. Accepts all eight connections and verifies a byte round trip on each.
4. Fails on any refused connection rather than retrying it.
5. Runs from `tcp::run_all_tests()`, which is already exercised by
   `src/tests/full-test.sh`.

The test should fail against the current four-socket implementation and pass
after backlog propagation.

## Validation

1. Run focused host/unit tests for touched crates.
2. Build debug and release images without new compiler or clippy warnings.
3. Run a focused VM reproduction with two simultaneous rnetbench clients using
   four parallel streams each; do not retry failed client invocations.
4. Run `src/tests/full-test.sh` three times in debug mode.
5. Run `src/tests/full-test.sh --release` three times.
6. Compare boot/gate timing and listening-socket metrics before and after the
   change. Stop for review if the additional pool creation causes a material
   boot-time or steady-state resource regression.
7. Run `cargo +nightly fmt`.

## Alternative not recommended

Raising the global default pool from four to eight would be a smaller patch and
would cover the current rnetbench workload, but it would leave the documented
failure for any burst larger than eight and would allocate extra sockets for
listeners that never request a larger backlog. Propagating the requested
backlog is the correctness-oriented fix.
