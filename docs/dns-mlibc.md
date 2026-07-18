# Using mlibc DNS from a Motor OS resolver service

Status as of 2026-07-18:

- the generic mlibc DNS resolver is unchanged;
- the Motor-specific UDP plumbing and direct mlibc proof are committed;
- a direct, unchanged-mlibc `getaddrinfo("google.com", ...)` call passes in the
  Motor OS VM;
- the standalone resolver service, C bridge, bounded IPC contract/client, and
  startup configuration are committed;
- the VDSO now routes nonnumeric host lookups through that service;
- `ping google.com`, NXDOMAIN, stopped-service error, later recovery, resolver
  self-test, and the complete system test suite pass in the VM;
- Phase 5 is complete locally and is not committed;
- extended Phase 5 stress corrected the earlier claim of exactly stable daemon
  memory: the service remains functional, but its allocator high-water mark
  continues to rise slowly during repeated full self-tests. That finding is
  recorded below and is not hidden by the successful functional result.

This document is based on:

- Motor OS commit `1f4571024047390d06ce4a4905ee1d50fc7c343f`
  (the committed DNS UDP plumbing is `4e91d01` and the resolver service is
  `1f45710`);
- the `motor-os-rustc` branch of `../mlibc` at commit
  `c0c0509ef0d837c0fbc2f0cc9f48be2b18f087b0`;
- the native-toolchain process in `docs/build-llvm.md`.

## Scope correction

An earlier local phase replaced mlibc's generic DNS parser and much of
`options/posix/generic/lookup.cpp`. That was the wrong boundary. The purpose of
this work is to use mlibc's resolver, not to maintain a Motor-specific fork of
the resolver.

Those changes have been removed completely. The following tracked mlibc files
are identical to the checked-in mlibc revision:

```text
meson.build
meson_options.txt
options/posix/generic/lookup.cpp
options/posix/generic/netdb.cpp
options/posix/meson.build
tests/posix/getaddrinfo.c
```

The temporary generic parser and test files were also removed. The only mlibc
change is now:

```text
sysdeps/motor/generic/socket.cpp
```

That is the intended porting boundary: generic mlibc decides how DNS works;
the Motor sysdeps make the required socket operations work on Motor OS.

Generic resolver shortcomings discovered during the audit are not Motor DNS
integration work. They can be reported or fixed upstream independently after
the service is working.

## Target architecture

The intended final path is:

```text
Rust application
      |
      | ToSocketAddrs / moto_rt::net::lookup_host
      v
rt.vdso -- bounded synchronous IPC --> dns-resolver service
                                           |
                                           | narrow C bridge
                                           v
                                  mlibc getaddrinfo()
                                           |
                                           | Motor socket sysdeps
                                           v
                         destination-selected UDP source bind
                                           |
                                           v
                                         sys-io
```

The resolver service owns name-resolution policy by calling ordinary mlibc
APIs. It does not copy DNS packet parsing into Rust, the VDSO, or `sys-io`.

Rust now owns the service process, IPC validation, bounded concurrency,
timeouts, and Motor error mapping. A small C bridge owns `struct addrinfo`
traversal and exposes only fixed-size address results to Rust.

## Audited blockers

Three Motor integration issues prevented the existing mlibc resolver from
working.

### 1. `AI_ADDRCONFIG`

`getaddrinfo(name, NULL, NULL)` enables `AI_ADDRCONFIG`. The Motor mlibc
sysdeps do not currently implement `InetConfigured`, so that form can return
`EAI_SYSTEM` with `ENOSYS`.

This does not require a generic mlibc change. The resolver bridge must pass an
explicit `struct addrinfo` with:

```c
ai_flags = 0
ai_family = AF_INET or AF_INET6
ai_socktype = SOCK_STREAM
```

For dual-stack results, call mlibc once with `AF_INET` and once with
`AF_INET6`, then merge and deduplicate the bounded results. This also avoids
depending on the current behavior of `AF_UNSPEC`.

Implementing the Motor `InetConfigured` sysdep remains a useful general libc
follow-up, but it is not needed by the resolver service.

### 2. Missing services database

The generic resolver obtains the DNS port with:

```text
lookup_serv_by_name("domain", IPPROTO_UDP, SOCK_DGRAM, 0)
```

mlibc reads this from:

```text
MLIBC_SYSCONFDIR "/services"
```

Motor builds mlibc with:

```text
MLIBC_SYSCONFDIR="/sys/cfg/libc"
```

The image previously installed `resolv.conf` but not `services`, so the
generic resolver failed with `EAI_SERVICE` before sending a packet.

The build now stages:

```text
/sys/cfg/libc/resolv.conf
/sys/cfg/libc/services
```

with the minimal services content:

```text
domain 53/tcp
domain 53/udp
```

This change is made in `src/build-llvm.sh` and documented in
`docs/build-llvm.md`. No hard-coded port-53 fallback was added to mlibc.

### 3. Unbound UDP materialization

The generic resolver follows the normal POSIX sequence:

```c
fd = socket(AF_INET, SOCK_DGRAM, 0);
sendto(fd, query, ..., nameserver);
```

The Motor mlibc port represents a fresh BSD socket with a pseudo-fd. Before
this change, its first `sendto()` tried to materialize the socket by binding
`0.0.0.0:0`.

That did not work because:

- `rt.vdso` rejected an unspecified address with port zero;
- `sys-io` requires a concrete local IP so it can choose the owning `NetDev`;
- `sys-io` stores smoltcp sockets per device.

For an outbound unbound UDP socket, the destination supplies the missing
information. `sys-io` can use the same route selection already used for TCP
connect and ICMP.

## Implemented Motor UDP plumbing

### Motor mlibc sysdeps

`../mlibc/sysdeps/motor/generic/socket.cpp` now lets
`materialize_udp()` receive an optional remote address.

On a fresh UDP socket:

- `sendto(fd, ..., destination)` passes `destination` into materialization;
- UDP `connect(fd, destination)` does the same;
- the Motor C ABI creates a bound socket using the route to that destination;
- subsequent I/O continues to use the resulting ordinary Motor fd.

The address-family match is checked before materialization. Existing explicit
`bind()` behavior is unchanged.

The no-destination path is deliberately retained. A fresh UDP `recvfrom()` or
`poll()` still has no remote from which to select a source device, so it still
attempts the pre-existing wildcard bind. That unresolved wildcard-receive
case does not affect DNS because mlibc sends its query before polling or
receiving.

### Motor C ABI and runtime

The C ABI adds:

```c
int64_t moto_rt_net_udp_bind_for_remote(
    const moto_sockaddr_t *remote_addr);
```

Its Rust implementation calls `moto_rt::net::udp_bind_for_remote()`.

No VDSO vtable field was added. The first implementation attempted to add one
and increment `RT_VERSION` from 16 to 17. The VM correctly rejected it because
the installed Rust standard library expects version 16. Requiring a Rust
toolchain rebuild for this plumbing would be unnecessary.

The corrected implementation keeps `RT_VERSION == 16` and reuses the existing
private `net_bind` vtable call with:

```text
PROTO_UDP_FOR_REMOTE = 3
```

This value is an internal Motor socket-creation selector, not an IP protocol
number exposed to POSIX applications. A future intentional VDSO ABI revision
can give the operation a dedicated vtable slot.

### VDSO

`rt.vdso` handles `PROTO_UDP_FOR_REMOTE` by calling
`UdpSocket::bind_for_remote()`.

The VDSO reserves its normal UDP channel/subchannel and sends a distinct
`UdpSocketBindForRemote` IPC request. The response contains the concrete local
address and allocated port, which become the VDSO socket's `local_addr`.

Ordinary `UdpSocket::bind()` still uses `UdpSocketBind` and preserves its
existing validation.

### Networking IPC

`moto-sys-io::api_net::NetCmd` adds:

```text
UdpSocketBindForRemote
```

It was appended after existing commands so the numeric values of current
commands do not change.

The request carries:

- the remote `SocketAddr`;
- the UDP subchannel index.

The successful response carries:

- the new socket handle;
- the selected concrete local `SocketAddr`, including its ephemeral port.

An API unit test verifies command, address, subchannel, and UDP command
classification encoding.

### `sys-io`

`sys-io` handles the new request as follows:

1. Reject an unspecified remote IP.
2. Call `NetRuntime::find_route(remote.ip())`.
3. Obtain both the selected device index and source IP.
4. Allocate an ephemeral UDP port on that device.
5. Bind the smoltcp UDP socket to the concrete source IP and port.
6. Return that concrete address to the VDSO.

The ordinary explicit-bind and route-selected-bind paths share one socket
creation helper after device selection.

The refactor also preserves the allocated ephemeral port in `UdpState`.
Previously `udp_bind()` allocated a port but initialized
`UdpState::ephemeral_port` to `None`, preventing the port allocator from
reclaiming it when the socket was dropped. Route-selected sockets would have
made that leak much more visible, so the common path now records and frees the
port correctly.

## UDP plumbing and direct-proof validation

### Source and build checks

The following passed:

```text
make -j2 BUILD=release vdso sys-io
cargo +dev-x86_64-unknown-motor build \
    --target x86_64-unknown-motor --release -p moto-rt-cabi
cargo +dev-x86_64-unknown-motor test -p moto-sys-io \
    --target x86_64-unknown-motor --features std --no-run
ninja -C ../mlibc/build
make -j4 BUILD=release img
git diff --check
```

The mlibc diff was also checked explicitly: no generic resolver, netdb,
Meson, or generic test file differs from the checked-in mlibc revision.

A host `cargo test -p moto-sys-io --features std` attempt is not a valid test
configuration for this workspace: Motor-only dependencies intentionally fail
to build for the Linux host. The target builds and VM tests are the relevant
validation.

### Direct VM proof

The release VM was built with:

```text
/sys/cfg/libc/resolv.conf
/sys/cfg/libc/services
the rebuilt unmodified-generic mlibc libc.a
the rebuilt Motor C-ABI shim
```

Testing used `src/vm_scripts/ssh-into-motor-os-vm.sh`. A C smoke program was
compiled inside Motor OS with the staged native `cc`. It first created a fresh
UDP socket, sent to `8.8.8.8:53`, and checked `getsockname()`. It then called:

```c
getaddrinfo("google.com", "80", &hints, &result);
```

with `AF_INET`, `SOCK_STREAM`, and `ai_flags == 0`.

The result was:

```text
UDP auto-bind: 192.168.4.2:49152
mlibc DNS: google.com -> 142.251.219.142
```

The exact Google address is expected to vary. The relevant assertions are that
the UDP source address is concrete, its port is nonzero, and unchanged mlibc
returns at least one address.

The full `/sys/tests/systest` suite also passed in the same VM, including:

```text
TCP tests PASS
UDP tests PASS
ICMP echo tests PASS
PASS
```

The temporary smoke-test source was removed from the staging tree after the
test. It is not a product file.

## Pinned minimal mlibc runtime

“Pinned minimal mlibc runtime” has two parts:

- a build-time resolver C SDK;
- a small runtime payload in the Motor image.

### Pinned

The normal Motor build must identify immutable inputs rather than rely on
whatever happens to be checked out in `../mlibc`. Lock metadata should record:

- the mlibc repository and full commit;
- the LLVM repository and full commit used to produce target objects;
- the Motor target triple and architecture;
- the mlibc Meson options and `MLIBC_SYSCONFDIR`;
- the Motor C-ABI compatibility version;
- the SDK archive name and SHA-256 digest;
- the manifest schema version.

The final mlibc pin must include the reviewed Motor socket-sysdep change while
leaving the generic resolver at its upstream revision.

### Minimal build-time SDK

The resolver C SDK should contain:

```text
manifest
licenses
include/                    mlibc public C headers
lib/crt1.o
lib/libc.a
lib/libc++.a
lib/libc++abi.a
lib/libunwind.a
lib/libclang_rt.builtins*.a
```

It should not contain the full native LLVM installation, Lua, sample programs,
or a prebuilt `libmoto_rt_cabi.a`. The original plan omitted `libc++.a`, but
Phase 4 corrected that: the established Motor Rust+C opt-in uses the clang
ToolChain's full runtime group, which names `-lc++` even though the resolver's
C bridge does not itself use libc++. Keeping the complete archive in the SDK
does not add it wholesale to the service; normal archive extraction and section
garbage collection still apply.

The complete static `libc.a` is intentional. The linker already extracts only
referenced archive members; maintaining a hand-pruned DNS libc would be
fragile. mlibc is implemented in C++, so libc++abi and libunwind are still
needed even though the service bridge itself should be C.

`libmoto_rt_cabi.a` should be built from the current Motor checkout so it
remains synchronized with the current VDSO and networking IPC.

### Runtime payload

Because the resolver service is statically linked, the final image needs only:

```text
/sys/dns-resolver
/sys/cfg/libc/resolv.conf
/sys/cfg/libc/services
/sys/cfg/libc/hosts
the sys-init service configuration
```

The compiler, SDK headers, and static archives are build-time inputs, not
runtime requirements.

## Implemented resolver service

### C bridge

`src/sys/dns-resolver/bridge.c` exposes this narrow C ABI:

```c
struct motor_dns_bridge_addr {
    uint8_t family;
    uint8_t reserved[3];
    uint8_t bytes[16];
};

int motor_dns_lookup(
    const uint8_t *name,
    size_t name_len,
    uint8_t family,
    struct motor_dns_bridge_addr *out,
    size_t out_capacity,
    size_t *out_len,
    uint8_t *out_truncated);
```

The bridge:

- copies at most 253 request bytes into a 254-byte NUL-terminated stack buffer;
- rejects empty, embedded-NUL, overlong, and unknown-family requests;
- uses explicit `getaddrinfo()` hints with `ai_flags == 0` and
  `ai_socktype == SOCK_STREAM`, avoiding the unimplemented `AI_ADDRCONFIG`
  path;
- resolves `Any` by calling `AF_INET` and then `AF_INET6`, giving stable
  IPv4-before-IPv6 ordering;
- recognizes numeric literals before that split so an IPv4 literal is not
  accidentally sent to DNS as an IPv6 hostname, or vice versa;
- traverses and frees each complete `addrinfo` result list;
- deduplicates addresses while preserving resolver order;
- copies only the address family and 4 or 16 address bytes to Rust;
- reports capacity truncation with a separate flag;
- translates `EAI_*` and `errno` into resolver-specific statuses before
  returning to Rust.

The VDSO already owns the destination port supplied to `lookup_host`, so the
service returns addresses only. The Phase 5 client attaches the caller's port
after validating every returned address.

### Shared protocol and client

The no-std `moto-dns` crate owns the permanent IPC contract so the service and
the VDSO client cannot drift. The well-known URL is
`moto-dns-resolver`, protocol version is 1, maximum hostname length is 253, and
the response holds at most 16 addresses.

The fixed-layout request includes the sync-IPC header, request ID, family,
length, reserved fields, and a 253-byte name array. The fixed-layout response
includes the IPC response header, matching request ID, resolver status,
address count, flags, and 16 pointer-free addresses. Compile-time size checks
fix the layouts at 288 and 352 bytes respectively, well within a small IPC
channel.

`moto_dns::Client`:

- maps absent service discovery to `ClientError::ServiceUnavailable`;
- validates names before IPC;
- uses a six-second deadline for one family and eleven seconds for `Any`,
  matching mlibc's five-second-per-family bound plus IPC margin;
- validates the transport result, protocol version, request ID, status, flags,
  count, address family, padding, and IPv4 zero tail;
- rejects the non-concrete `Any` family in response addresses; this validation
  omission was found and corrected while adding the Phase 5 consumer;
- never caches a failed service lookup, so a caller can create a new client and
  retry after the daemon appears or restarts.

The resolver-specific wire statuses are:

```text
Ok
NotFound
TemporaryFailure
OutOfMemory
UnsupportedFamily
TimedOut
System
ResolverFailure
InvalidRequest
Busy
```

POSIX `EAI_*` numbers are not exposed over IPC.

### Rust daemon and bounded concurrency

`src/sys/dns-resolver` is a Rust process with four fixed workers. Each worker
owns a separate `moto_ipc::sync::LocalServer` on the same service URL, with two
listeners and at most eight retained client connections. A worker copies and
validates its request before entering C, performs at most one mlibc call at a
time, writes the fixed response, and completes that RPC.

This structure has two useful bounds:

- at most four calls can be inside mlibc concurrently;
- idle or blocked clients consume only one of the fixed connection slots.

There is no global service lock around IPC or mlibc. One slow DNS query occupies
one worker while the others continue accepting work. The service gives
malformed requests a transport-level `E_INVALID_ARGUMENT` plus
`InvalidRequest`, logs them, completes the RPC, and keeps serving.

There is no cache. mlibc's current resolver does not expose DNS TTL data through
`getaddrinfo()`, so a correct TTL-aware cache cannot be built at this layer
without additional resolver APIs. A short arbitrary cache would risk stale
answers.

### IPC contract

The implemented versioned request/response is conceptually:

```text
LookupRequest {
    version
    request_id
    family: V4 | V6 | Any
    name_len
    name[253]
}

LookupResponse {
    version
    request_id
    status
    address_count
    flags
    addresses[16]
}
```

The service rejects:

- unsupported versions;
- unknown family values;
- zero-length or overlong names;
- embedded NULs;
- nonzero protocol flags or reserved fields.

The client rejects inconsistent transport results, response versions, request
IDs, status values, flags, counts, families, and address padding.

The bridge uses this status mapping:

```text
EAI_NONAME / EAI_NODATA -> NotFound
EAI_AGAIN               -> TemporaryFailure
EAI_MEMORY              -> OutOfMemory
EAI_FAMILY              -> UnsupportedFamily
EAI_SYSTEM + ETIMEDOUT  -> TimedOut
other EAI_SYSTEM        -> System
other failures          -> ResolverFailure
```

### Build and startup integration

`make dns-resolver` compiles the C bridge with the host Motor clang and links
the Rust daemon against the local Motor C sysroot. This is intentionally the
Phase 4 development input, not the final reproducible SDK: the Make variables
default to sibling `../llvm-project` and `../motor-sysroot`. Phase 6 must
replace those defaults with the checksum-verified SDK lock and a shim built
from the current Motor checkout.

The daemon cannot be linked by merely appending `libc.a` to a normal Motor Rust
binary. mlibc needs its own startup to initialize its TCB, startup data, stdio,
and C++ static constructors. The build therefore uses Motor's established
Rust+C flags:

```text
-C link-self-contained=no
-C default-linker-libraries=yes
```

and the Motor clang driver, so `crt1.o`'s strong `motor_start` owns process
entry and calls Rust's generated C `main` after mlibc initialization. The
linked ELF entry point was disassembled and matches `crt1.o` exactly.

The locally registered `dev-x86_64-unknown-motor` toolchain is older than the
source documented in `docs/libc_start_redesign.md`: it reports LLVM 22 and its
prebuilt `libstd`/`libmoto_rt` still export strong `motor_start` and `mem*`
symbols. The current source expects those fallback definitions to be weak.
Until the local toolchain is rebuilt, the resolver link passes lld's
`--allow-multiple-definition`; link order selects mlibc's `crt1.o` entry, and
the VM tests below prove that initialization path runs. Phase 6 must pin a
rebuilt toolchain with the weak-symbol change and remove this compatibility
flag; leaving a broad duplicate-symbol allowance in the reproducible product
build would hide future collisions.

The image build installs `/sys/dns-resolver`, and `sys-init.cfg` starts it with
`CAP_LOG`. `sys-init` itself is started by `sys-io`, so networking is available
before the resolver is launched. The image now also carries a minimal hosts
database:

```text
127.0.0.1 localhost
::1 localhost
127.0.0.53 motor-dns-test
::1 motor-dns-test
```

`motor-dns-test` gives the self-test deterministic dual-stack answers without
depending on public DNS.

### Phase 4 validation

The following passed:

```text
make -j2 BUILD=release dns-resolver
cargo clippy ... --target x86_64-unknown-motor --release -- -D warnings
make -j4 BUILD=release img
git diff --check
```

The release service is a stripped 1.2 MiB static PIE. Its dynamic section has
no `DT_NEEDED` entries, so it has no runtime dependency on the on-image
compiler, SDK, or static archives.

The VM was booted and tested through
`src/vm_scripts/ssh-into-motor-os-vm.sh`, as required. Running:

```text
/sys/dns-resolver --self-test
```

passed twice. That self-test covers:

- direct-bridge IPv4 numeric resolution;
- direct-bridge IPv4-only, IPv6-only, and deterministic combined hosts-file
  resolution;
- direct-bridge public DNS resolution of `google.com`;
- direct and IPC rejection of empty, overlong, embedded-NUL, unknown-family,
  unsupported-version, and nonzero-reserved requests;
- a normal request after malformed requests, proving the daemon stays alive;
- eight repeated `.invalid` NXDOMAIN requests;
- 64 repeated bridge successes and 32 short-lived IPC connect/lookup/drop
  cycles;
- eight concurrent IPC clients against the four-worker bound;
- a connection to an intentionally absent endpoint mapping to
  `ServiceUnavailable`.

The original Phase 4 validation observed the daemon at 12,344 KiB before and
after its short repeated-self-test run, with seven threads (process/runtime
threads plus the fixed four workers). The longer Phase 5 stress run below
supersedes the conclusion that this proves an exactly stable long-run memory
size. The full `/sys/tests/systest` suite passed, including UDP and ICMP:

```text
UDP tests PASS
ICMP echo tests PASS
PASS
```

### VDSO client

Phase 5 replaces the hostname `E_NOT_IMPLEMENTED` path in
`rt.vdso/src/net/rt_net.rs`. The implementation:

1. validates the ABI pointers, rejects empty and embedded-NUL input, bounds the
   hostname at 253 bytes, and validates UTF-8 before use;
2. preserves `localhost` and numeric IPv4 as resolver-free fast paths, and adds
   the corresponding numeric IPv6 fast path;
3. creates a fresh `moto_dns::Client` only for nonnumeric names and requests
   `AddressFamily::Any`;
4. relies on the shared client to validate the complete response before
   creating caller-visible socket addresses;
5. converts concrete IPv4 and IPv6 address bytes to Motor socket addresses and
   attaches the caller's port;
6. checks caller-result allocation failure and publishes the pointer/count only
   after the complete result has been copied;
7. drops the client on every success and error path, releasing its IPC handle
   and shared page.

A connection is intentionally not cached in the VDSO. A permanent cache would
retain one of the service's bounded connection slots for the lifetime of every
process that ever resolved a name. A cached dead connection would also
complicate restart recovery. Per-call construction makes missing discovery
prompt, releases the slot deterministically, and lets the next lookup discover
a restarted service.

Wire/client errors map to Motor errors as follows:

| Resolver/client result | Motor error |
| --- | --- |
| invalid input | `E_INVALID_ARGUMENT` |
| service unavailable | `E_NOT_CONNECTED` |
| client or resolver timeout | `E_TIMED_OUT` |
| NXDOMAIN / no address | `E_NOT_FOUND` |
| temporary failure / busy | `E_NOT_READY` |
| resolver out of memory | `E_OUT_OF_MEMORY` |
| mlibc system/resolver failure | `E_INTERNAL_ERROR` |
| invalid response or impossible resolver status | `E_INVALID_DATA` |
| other IPC transport error | unchanged transport `ErrorCode` |

The resolver service must not call `moto_rt::net::lookup_host`, directly or
indirectly. Its mlibc path goes straight through the socket sysdeps, avoiding a
resolution recursion.

### Phase 5 validation

Static and image validation passed:

```text
make -j2 BUILD=release vdso
make -j4 BUILD=release img
git diff --check
```

The VDSO build script runs both `cargo build` and `cargo clippy` for the Motor
target. The only emitted diagnostics were the existing `moto-rt` runtime-symbol
signature warnings.

The release VM was tested only through
`src/vm_scripts/ssh-into-motor-os-vm.sh`. The primary result was:

```text
PING google.com (142.251.219.142): 56 data bytes
64 bytes from 142.251.219.142: icmp_seq=0 time=8.339 ms
1 packet transmitted, 1 received, 0.0% packet loss
```

Additional focused results:

- `motor-dns-test` resolved through the hosts-file path to `127.0.0.53`,
  proving service ordering without relying on public DNS. That non-local
  loopback address does not answer ICMP, so resolution, not an echo reply, is
  the acceptance result for this fixture.
- `localhost` still resolved to `127.0.0.1` and replied.
- numeric `127.0.0.1` still replied. Numeric `::1` reached the ICMP path
  without DNS, although the existing IPv6 loopback echo path timed out.
- repeated `.invalid` lookups returned `NotFound (os error 10)` promptly and
  the daemon continued serving.
- after killing resolver PID 6, `ping google.com` failed in about 5 ms with
  `NotConnected (os error 19)`, while numeric `127.0.0.1` still replied.
- starting a new resolver in a held SSH session restored a subsequent
  `ping google.com` without rebuilding or restarting the caller.
- repeated resolver self-tests passed after recovery, and approximately 60
  repeated `ping -c 1 google.com` process cycles all resolved and received ICMP
  replies.
- after the extended run, `sys-io` reported 559 total UDP sockets created and
  zero active UDP sockets. `UdpState` frees its ephemeral port on the same drop
  path that decrements this gauge, so the socket/port lifecycle completed even
  though allocator KBYTES retained a higher watermark.
- the final full `/sys/tests/systest` run passed, including TCP loopback, UDP,
  and ICMP:

```text
UDP tests PASS
ICMP echo tests PASS
PASS
```

#### Extended stress correction

The longer Phase 5 run does not support Phase 4's stronger wording that the
daemon's reported memory size is exactly stable:

- the freshly booted daemon was 9,824 KiB with five threads;
- after lazy runtime/stdio initialization and 20 full resolver self-tests, it
  was 12,432 KiB with seven threads;
- another 20 self-tests increased it to 12,536 KiB;
- a further batch of roughly 60 end-to-end DNS+ICMP processes increased it to
  12,600 KiB.

Most of the first increase is fixed lazy initialization and two runtime
threads. The subsequent increase is small relative to the workload, all IPC
connections remained usable, service capacity recovered, and the full system
test still passed. Nevertheless, the later slope means this run cannot claim
that long-run allocator growth is bounded. One self-test in a batch of 20 also
failed its exact NXDOMAIN assertion; the daemon stayed alive and the following
self-tests passed.

This behavior is below the VDSO/service contract boundary implemented in Phase
5: every `moto_dns::ClientConnection` drops its handle and unmaps its shared
page, the resolver frees every returned `addrinfo` list, and the zero active-UDP
gauge confirms socket cleanup. Both Motor's process allocator and mlibc's slab
allocator retain freed small-allocation slabs as high-water memory.
Distinguishing allocator retention from a true allocation/handle leak needs
dedicated allocator and handle counters; RSS/KBYTES alone cannot do so.

Do not treat this as a reason to fork or rewrite generic mlibc DNS. Add a
separate follow-up stress test with explicit counters, a warmed baseline, and
thousands of same-process lookups. If counters show a real leak, fix its owner
(`moto-ipc`, the Motor socket path, the runtime allocator, or generic mlibc)
rather than hiding it with a cache in the VDSO.

### Remaining service supervision work

DNS becomes shared infrastructure once the VDSO delegates to the service.
`sys-init` should therefore:

- start it after `sys-io` is available;
- make startup ordering explicit;
- log early initialization failure clearly;
- eventually restart it after an unexpected exit.

General restart supervision is not currently available. Phase 4 provides the
client-side pieces needed for a safe first integration: missing discovery is a
defined error and no permanent failure is cached. Phase 5 uses that behavior by
creating and dropping a client per nonnumeric lookup instead of caching a dead
connection.

## Delivery phases

| Phase | Status | Result |
| --- | --- | --- |
| 0: build decision | Complete | Use a pinned, checksum-verified resolver C SDK as a required normal-build input. |
| 1: preserve mlibc resolver | Committed | All accidental generic resolver changes removed; only Motor sysdeps changed. |
| 2: Motor UDP plumbing | Committed | Destination-selected UDP auto-bind works through mlibc, C ABI, VDSO, IPC, and `sys-io` without a VDSO version bump. |
| 3: direct mlibc proof | Committed | Native C `getaddrinfo("google.com")` passed in the VM; full systest passed. |
| 4: resolver service | Committed | C bridge, shared protocol/client, four-worker daemon, startup configuration, self-test, image build, and full systest landed in `1f45710`. |
| 5: VDSO integration | Complete locally | Nonnumeric `lookup_host` uses the service; DNS ping, error/recovery paths, image build, and full systest pass; awaiting review/commit. Extended stress found allocator high-water growth that needs counter-based follow-up. |
| 6: reproducible product integration | Not started | Add SDK/toolchain lock, verified fetch/cache, producer job, licenses, remove the old-toolchain duplicate-symbol compatibility flag, and run clean-cache CI. |
| 7: resolver quality | Separate follow-up | Report or improve generic mlibc DNS behavior upstream without Motor-specific forks. |

Stop for review and commit at the end of each phase. Do not combine the
service, VDSO integration, and reproducible SDK work into one unreviewable
change.

## Phase 4 acceptance criteria

Completed before the Phase 4 commit, with the memory criterion corrected by the
longer Phase 5 run:

- [x] a direct bridge self-test resolves numeric, hosts-file, and DNS names;
- [x] malformed and overlong requests are rejected without process failure;
- [x] IPv4-only, IPv6-only, and combined calls have deterministic ordering;
- [ ] repeated success, NXDOMAIN, connection, and malformed-request paths leave
  the daemon's reported memory size stable. Short Phase 4 runs appeared stable,
  but longer Phase 5 stress shows slow high-water growth and needs explicit
  allocation/handle/socket counters;
- [x] resolver startup/discovery failure produces `ServiceUnavailable`;
- [x] concurrent lookups are bounded at four and do not serialize on an IPC
  lock;
- [x] the static service binary has no dependency on the on-image compiler.

## Phase 5 acceptance criteria

Inside the VM:

- [x] `ping google.com` resolves through the service and sends ICMP;
- [x] numeric `ping` still avoids the resolver service;
- [x] `localhost` behavior is unchanged;
- [x] NXDOMAIN returns promptly and does not crash the service;
- [x] a stopped resolver yields a defined error and later recovery works;
- [ ] repeated lookups do not leak handles, sockets, UDP ports, or memory.
  Connection teardown and the socket/ephemeral-port path pass (559 total UDP
  sockets, zero active), but KBYTES grows slowly; allocator/handle counters are
  required to distinguish high-water retention from a real memory leak;
- [x] the existing TCP, UDP, ICMP, and system test suites still pass.

## Phase 6 acceptance criteria

From an empty resolver-SDK cache:

- the normal build obtains the exact locked SDK;
- SHA-256 and manifest compatibility are verified before use;
- offline mode gives an actionable missing-artifact error;
- no sibling `../mlibc` checkout is consulted implicitly;
- the resolver service is built and installed by the normal image build;
- all required source/license metadata ships with the SDK;
- CI builds the image and runs the resolver VM tests.

## Explicit non-goals for the Motor integration

The Motor DNS service work should not:

- replace mlibc's DNS packet parser;
- hard-code port 53 in mlibc;
- shell out to a command-line utility;
- put mlibc inside the VDSO;
- expose `struct addrinfo` over IPC;
- add a second DNS protocol implementation in Rust;
- add an arbitrary-TTL cache;
- require a VDSO ABI bump solely for UDP source selection.

Generic mlibc improvements such as randomized transaction IDs, stricter packet
validation, TCP fallback, EDNS, search domains, multiple nameservers, or
TTL-aware APIs are valuable upstream projects. They are deliberately outside
this Motor plumbing change.
