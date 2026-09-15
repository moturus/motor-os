# Virtio-vsock implementation plan

Status: revised after A1–A13 and the topology/Virtio 1.1 clarifications.
Remaining questions await review. Repository and references inspected on
2026-09-14; no implementation has started.

Implement a modern virtio-vsock driver in `src/sys/lib/virtio-async`, serve
vsock streams through sys-io, and expose moto-io's native Rust API. Follow
the existing block and network drivers' structure and reuse their virtqueue
implementation and networking IPC machinery. This revision
is documentation only. Incremental implementation commits are requested once
implementation is approved; the full repeated gate belongs at agreed larger
milestones, not every commit. Unsettled choices remain in the final section.

## Scope and simplicity

- One Virtio 1.1 modern PCI implementation requiring `VIRTIO_F_VERSION_1`, with
  the existing split virtqueues and MSI-X support. No legacy transport,
  packed-ring implementation, alternate queue library, or VMM-specific guest
  protocol.
- Native Motor OS I/O using existing in-tree libraries and Rust facilities.
  Preserve moto-io's `no_std` boundary by using `core`, `alloc`, and native
  APIs there; do not add a dependency on `std` or virtio-async to moto-io.
- Reliable byte streams with connect, listen/accept, bidirectional I/O,
  shutdown, and transport-reset handling. The change to Virtio 1.1 supersedes
  A1's seqpacket requirement: no seqpacket/datagram API or associated feature
  negotiation, message reassembly, or record-boundary handling in this work.
- Support one vsock device for now, per the follow-up clarification. Do not
  assume that there is only one NIC or that the shared driver infrastructure
  will only serve one block device. Preserve sys-io's current rejection of
  multiple block devices until multiple filesystems are supported. Preserve
  the multiple-NIC path; testing or fixing multi-NIC support is out of scope.
- Reuse the existing networking endpoint, client/driver, reservations, and
  shared pages. Add a vsock stream socket kind without using the IP
  netstack. Keep packet/event I/O in virtio-async and connection/credit state
  in sys-io, as agreed in A2/A4.
- Keep queues, buffers, tasks, connections, and pending operations bounded.
  Use ordinary structs, explicit state transitions, and existing async
  primitives. Add abstraction only when two concrete consumers need it.
- Add `CAP_VSOCK` as requested in A8. This requires in-tree moto-sys/kernel
  capability changes and auditing explicit process-launch masks. No new
  syscall, kernel vsock driver, Rust-stdlib, moto-rt, libc, or toolchain work
  is planned. rt.vdso already calls the shared default-capability helper;
  avoid changing it unless the capability audit demonstrates a need.
- Initialize lazily on authorized native use. An absent device or an attached
  but unused device must add no queue initialization, polling, host rendezvous,
  or background tasks to boot. No hot-plug/unplug or migration support.
- Support QEMU, Cloud Hypervisor, and Firecracker using unprivileged host
  UDS backends. The stream-only profile removes the seqpacket/backend gap;
  no changes to external VMM/backend repositories are planned (Q11).
- Add tests only through guest `systest`, reached from `full-test.sh` in
  debug and release. No new host-only tests or sys-io self-tests; a host UDS
  peer is test infrastructure, not a second test suite (A12).

## Existing code and integration points

Paths below are relative to the repository root.

| Location | Existing facility and planned use |
| --- | --- |
| `src/sys/lib/virtio-async/src/virtio_device.rs` | Modern PCI discovery, feature negotiation, device status, queue setup, and MSI-X. Add the vsock device kind and reuse these operations. |
| `src/sys/lib/virtio-async/src/virtio_blk.rs` | `BlockDevice::from`, initialization failure reporting, and nonblocking descriptor submission provide a compact driver pattern. |
| `src/sys/lib/virtio-async/src/virtio_net.rs` | Separate RX/TX queues, owned `IoBuf` submissions, and validated receive completions provide the packet-I/O pattern. |
| `src/sys/lib/virtio-async/src/virtio_queue.rs` | Reuse `Virtqueue`, `VqAlloc`, `UserData`, `VqCompletion<T>`, and `WriteCompletion<T>` for all three vsock queues. |
| `src/sys/sys-io/src/runtime/mod.rs` | `async_runtime` discovers devices and runs services on one `LocalRuntime`, affined to CPU 0. Attach the vsock runtime here. |
| `src/sys/sys-io/src/runtime/net.rs` and `src/sys/sys-io/src/runtime/net/socket/tcp.rs` | Examples of channel admission, client ownership, socket dispatch, shared-page I/O, and disconnect cleanup. Reuse applicable mechanisms without adopting TCP/IP-specific state. |
| `src/sys/lib/moto-sys-io/src/api_net.rs` | Extend shared-channel command dispatch without changing existing TCP/UDP command values; keep vsock-specific fields in `api_vsock.rs`. |
| `src/sys/lib/moto-io/src/net/{channel,tcp,wait,readiness}.rs` | Reuse `NetClient`, `NetDriver`, reservations, page ownership, waits, and cancellation; narrowly generalize TCP-specific dispatch. |
| `src/sys/lib/moto-sys/src/caps.rs`, `src/sys/kernel/src/uspace/process.rs` | Add the capability, default inheritance, and non-escalation checks, including for System parents. |
| `src/sys/lib/moto-sys/src/sys_obj.rs` | `SysObj::get_capabilities` can query an admitted channel's peer; use existing trusted identity rather than client-supplied claims. |
| `src/sys/tests/systest/src/{virtio,net_driver}.rs` and `src/tests/full-test.sh` | Existing guest queue-fixture, native API, and VM acceptance paths. Do not add a self-test runner. |

The following constraints affect the design:

1. Queue scratch buffers are **16 bytes**. Both `get_buffer<T>` and
   `read_header<H>` assume that limit. A vsock header is **44 bytes**; using
   either helper with that header would violate the existing contract.
   A3 is correct: reuse `HeaderBuffer` by enlarging scratch storage for vsock
   queues and updating both helpers and the existing fixture (Q3).
2. A completion owns its descriptors until it is dropped after completion.
   Dropping it while DMA is outstanding asserts. Application cancellation
   therefore cannot directly cancel a submitted device request.
3. `Virtqueue::allocate_virtqueue` already spawns the IRQ reclamation task.
   `Virtqueue::drop` has no device teardown implementation. Keep device
   lifetime separate from socket lifetime; do not promise hot-unplug or
   reset/recreation of queues as part of socket cleanup.
4. The sys-io mapper currently permits IRQs 64–69, but the kernel registers
   16 custom IRQs, 64–79 (`src/sys/kernel/src/config.rs` and
   `src/sys/kernel/src/arch/x64/irq.rs`). Reuse
   that existing range with bounded allocation and an exhaustion error.
   One block device, two NICs, and one vsock device need eight queue IRQs;
   a future second block device would need nine. No IRQ-sharing framework or
   kernel vector expansion is needed for those examples. Queue sizes remain
   capped at 256; account for aggregate ring use of the existing 2 MiB pool.
5. `PciBar::read_u64` performs two 32-bit reads. Reading a changing guest CID
   needs configuration-generation consistency, not an assumption that this
   helper gives an atomic snapshot.
6. `runtime/channel_budget.rs` accounts for net/fs channels. Sharing net's
   endpoint also shares its admission budget; no third channel kind is needed.
7. `api_net::NetCmd::try_from` and client dispatch assume the current command
   set. A shared service requires updates on both sides. Existing command
   numbers must remain stable. TCP's RX acknowledgement is a wakeup signal,
   not a byte-credit acknowledgement. Its receive window opens when sys-io
   drains socket data into an already allocated IPC page. Reuse that boundary
   for vsock credits; keep client-held pages independently bounded (Q6).
8. Ordinary `#[cfg(test)]` tests inside these Motor-target crates are not
   automatically run by the suite. sys-io's registered self-tests run in
   debug only. All new coverage must instead execute in guest systest in
   both profiles. Existing registered tests remain unchanged.
9. `async_runtime` already collects NICs in a vector but explicitly rejects
   a second block device before `fs::init`, which takes one device. This is
   an intentional filesystem limitation to preserve, not a vsock fix. Do not
   add singleton assumptions to virtio-async or consume IRQs reserved for
   other device kinds. Multi-NIC testing/fixing and multi-filesystem work are
   outside this plan.
10. `SocketState` has TCP/UDP variants, but `SocketBase` also embeds an IP
    address, a net-device index, and netstack-specific handle/cleanup logic.
    Adding enum variants alone is insufficient. Separate those IP-backend
    fields and cleanup paths narrowly, retaining common ownership/IPC code.

## Protocol reference and ownership

Use [Virtio 1.1, sections 4.1 and 5.10](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
as the reference for the modern PCI/socket interface. Device type 19 maps
to modern PCI device ID `0x1053`. Queue indices are RX=0, TX=1, event=2.
The configuration contains a little-endian 64-bit guest CID with zero upper
32 bits. Guest CIDs exclude 0, 1, 2, and `0xffffffff`; CID 2 addresses the
host. Version 1.1 defines no vsock-specific feature bits and only stream
sockets. Negotiate no device-specific bits, including on newer backends;
retain the modern transport requirement and existing supported ring features.
`VIRTIO_F_VERSION_1` distinguishes modern transport, not 1.1 from 1.2.

The wire header contains source/destination CIDs and ports, payload length,
type, operation, flags, receive allocation, and forwarded-byte count. Use
the 44-byte wire layout, little-endian fields, and checked decoding. Stream
type is 1. Operations are REQUEST=1, RESPONSE=2, RST=3, SHUTDOWN=4, RW=5,
CREDIT_UPDATE=6, and CREDIT_REQUEST=7. Shutdown flag masks are receive=1 and
send=2. The transport-reset event is a four-byte event with ID 0. Newer
socket types are unsupported; retain required unknown-type refusal handling.
[Linux's published virtio-vsock wire definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_vsock.h)
provide an interoperability cross-check.

The agreed boundaries, with API details proposed in Q5, are:

```text
Application: native moto-io vsock API
    <-> existing NetClient/NetDriver and shared networking IPC channel
    <-> sys-io vsock connections, credits, listeners, and client ownership
    <-> virtio-async vsock packet/event submissions and completions
    <-> existing Virtqueue / PCI / MSI-X infrastructure
```

The driver returns validated packet data and device events. sys-io owns
connection state and stream buffering. moto-io owns application waits and
IPC resources. Neither Ethernet, IP addressing, DNS, DHCP, nor the TCP
netstack participates in the vsock data path.

## Implementation sequence

Each numbered step is an implementation stage, not necessarily one commit.
Split implementation and tests into roughly 100–300 changed lines per patch.
Keep every intermediate patch buildable, and keep partial functionality
unpublished until its resource ownership and error paths work. Required
review decisions are identified by Q-number. Tests arrive with behavior;
the validation section groups related commits into larger gating milestones.

### 1. Review the contract and record the baseline

Resolve the remaining questions before implementing dependent interfaces.
In particular, Q11 records the three-VMM UDS test prerequisites, and Q13
selects milestone gate frequency. A1's multi-vsock and seqpacket requirements
are superseded by the follow-ups. Do not reopen the settled Virtio 1.1,
ownership, capability, lazy-init, or guest-only-test decisions.

Record the selected Motor toolchain, baseline image build/test results,
current boot measurements, and existing warnings. Keep logs for any initial
failure. Diagnose a newly encountered preexisting bug before discussing an
out-of-scope fix, following AGENTS.md. Make no external-repository changes.

### 2. Define capability and wire contracts, with guest tests

Add `CAP_VSOCK` in `moto-sys/src/caps.rs` using an unused capability bit
(bit 7 is currently free). Include it in default child capabilities only
when the parent holds it. Explicit child masks can omit it; a denied child
cannot restore it in descendants. Preserve all unrelated role/cap rules.

In `kernel/src/uspace/process.rs`, enforce the CAP_VSOCK parent-subset rule
even when the parent has `CAP_SYS`: the existing general subset check exempts
System parents, but A8 does not. A System process lacking CAP_VSOCK must
neither use vsock nor grant it. Audit initial kernel-created processes and
explicit launch masks in sys-init, sys-tty, russhd, and service configuration
so normal system/user processes start with the capability by default.
rt.vdso's `default_child_capabilities` call should pick up the new default
without a new API. Document explicit denial via `MOTOR_OS_CAPS`.

When adding the IPC handlers in stages 9–10, use `SysObj::get_capabilities`
on the admitted peer at its first vsock request and cache the trusted,
immutable capability word. Do not add a query to every net-channel admission
at boot. Authoritatively check connect and bind/listen (including accept
ownership) before device activation or vsock resource reservation. Do not
reject the entire shared channel:
a process denied vsock must still be able to use its existing TCP/UDP APIs.
Client-side checks are only convenience, never the security boundary.

Add systest child-process cases for default inheritance, explicit grant and
denial, denied descendants, attempted escalation, and System-parent denial.
With the IPC handlers, exercise the real server check using a client that
bypasses moto-io's check.
No new host-only capability tests or boot-time self-tests are needed.

Add `virtio_vsock.rs` under virtio-async, splitting out a small wire helper
only if that improves readability. Define the header/event layouts and
constants, with size/offset assertions and explicit endian conversions.
Decode untrusted integer tags with matches rather than unchecked enum
transmutes. Keep wire structures separate from native API addresses.

Validate used length, header presence, payload length, and the posted
buffer capacity before creating any payload slice. Validate CID width,
socket type, operation, and operation-specific flags before changing state.
Keep enough decoded metadata to produce a required protocol refusal
when a complete header is present. Never use a malformed length to allocate
a buffer or resize an `IoBuf`.

Keep new assertions in systest; expose only the fixtures/helpers necessary
to exercise real driver code through the existing `test-support` feature.
Run them from `systest/src/virtio.rs` in both profiles. Cover exact header
size, ignored unsupported feature bits, short headers, truncated payloads,
oversized used lengths, integer overflow, high CID bits, unknown tags, and
control packets carrying invalid payloads. Use fixed examples with expected
field values, not just encode/decode round trips. For sys-io's small pure
credit/state helpers, compile the same source into systest with a narrow
source include if needed; do not duplicate the algorithm, extract a broad
protocol crate, or introduce `SELF_TESTS` registrations.

### 3. Add modern discovery and device initialization

Update `VirtioDeviceKind`, the modern PCI ID match, and crate exports. Add
`VsockDevice` following the existing `from`/initialization/error pattern.
Require modern features and leave unsupported optional features disabled.
Do not negotiate vsock-specific features. Check feature confirmation and
configuration length, and read a generation-consistent CID. Keep discovery
separate from initialization so
boot can retain the device without creating its queues.

Use `init_virtqueues(3, 3)`, existing MSI-X assignment, and existing status
operations. Validate queue capacity against the chosen packet layout and
control reserve. Add only the small configuration-read helper necessary for
a generation-consistent CID read. Use it at lazy activation and transport reset.

Extend the mapper's bounded IRQ allocation to the already installed 64–79
range, returning an error on exhaustion rather than asserting or wrapping
the `u8`. Keep one IRQ per queue and existing per-device MSI-X setup. Check
aggregate ring allocation, including block and all configured NIC queues,
before consuming the fixed pool. This is shared-infrastructure capacity
work, not a multi-NIC repair or permission to remove the multi-block guard.

Prepare RX/event storage and arrange buffer publication, `DRIVER_OK`, and
notifications in the standard initialization order. Do not announce service
readiness before these paths can make progress. Check initial allocations
before publishing DMA buffers where possible; partial initialization must
not free memory already visible to the device.

Test device-ID mapping, feature combinations, invalid configuration/CID,
insufficient queues, and IRQ/ring capacity arithmetic with systest fixtures.
The capacity checks must not assume one NIC or one block queue; this does
not require new multi-NIC VM tests. Leave activation to step 12; recognition
alone does not make the new device an application service.

### 4. Implement RX, TX, and event completions using the existing queues

Implement small post/try-post operations with explicit buffer ownership.
Reuse queue-owned `HeaderBuffer` for headers and retain payload `IoBuf`s in
the generic completion's owned value. A successful submission retains both
until completion is reaped; failed admission returns payload ownership
without changing connection accounting. Receive and event descriptors are
device-writable; transmit descriptors are
device-readable. A header-only control packet needs no empty data descriptor.

Use the Q3 proposal: 64-byte scratch buffers for vsock, retaining 16 bytes
for block/net. Update allocation, `get_buffer<T>`, `read_header<H>`, and the
memory-backed fixture together. Check the actual capacity and alignment in
release before typed access; copy received headers only after completion.
Zero header storage before publication and expose only the 44-byte wire
header, not padding. No separately managed header pool is needed.

Use a page-aligned 4 KiB payload as the proposed starting point: two
descriptors for data and one for a header-only control or four-byte event.
Respect physical page boundaries; virtual contiguity does not imply physical
contiguity. Verify backend packet splitting against posted RX capacity and
reject invalid used lengths without resizing to a peer-provided length.

Return buffers on valid and invalid completions so the runtime can reuse
them. Use a dedicated receive completion wrapper, like `NetReadCompletion`,
where header/length validation is needed. Do not request block status for
vsock chains. TX completion means the device released the buffers, not that
the remote application consumed the data.

Extend the real memory-backed queue fixture minimally to cover vsock
descriptor direction, header-only TX, valid/invalid RX and events,
out-of-order chain completion, descriptor exhaustion/reuse, and owned-buffer
lifetime. Preserve the existing premature-drop regression.

### 5. Build the device pumps and bounded scheduling

Add the proposed `src/sys/sys-io/src/runtime/vsock.rs`. Use the existing
single-threaded executor and `Rc` ownership; never hold `RefCell` borrows
across awaits. Keep RX processing, event handling, TX admission, and TX
completion draining independently able to progress.

Maintain a fixed RX pool, promptly repost completed buffers, and copy or
transfer accepted data into bounded per-stream storage. A blocked application
must not retain the entire device RX ring. Use a bounded pending-control
queue or equivalent reserved state, with the sizing reviewed in Q7. RX must
continue while TX is full whenever this extra storage can hold the resulting
replies, as required by the
[virtqueue flow-control rules](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).

Drain completed TX requests before waiting for more descriptors. If using
`VqAlloc`, ensure another live task releases the completions on which it
depends; do not make one task wait for descriptors while retaining the only
completions that can free them. Preserve per-stream ordering, including
data before write-shutdown, while keeping credit and refusal traffic able
to run. Bound work per dispatch so a busy vsock cannot monopolize sys-io.

Test a full TX ring while RX produces replies, all control slots occupied,
completion-driven resumption, and one slow stream alongside an active one.
Every exhausted state needs a concrete wakeup source, without a polling
timer or an automatic retry loop.

### 6. Implement and test byte-credit accounting

Add a small credit-state helper, independent of PCI and IPC. Track local
receive capacity/occupancy, local forwarded count, transmitted payload count,
and the peer's advertised allocation/forwarded count. Keep header and control
bytes out of byte accounting. Use explicit wrapping arithmetic for protocol
counters and checked arithmetic for allocation sizes and local totals.

Calculate outstanding bytes as `tx_cnt.wrapping_sub(peer_fwd_cnt)`. Available
credit is the peer allocation minus outstanding bytes when that subtraction
is valid; never let an invalid advertisement become a huge writable window.
Accept ordinary zero-credit conditions, distinguish them from impossible
counter advances, and account for advertised buffer-size changes without
panicking. Validate any claimed consumption against what was actually sent.

Choose one point at which queued data reserves credit, and one rollback path
if it is abandoned before submission. Multiple pending writes must not each
spend the same credit. Reclaiming a TX descriptor does not replenish peer
credit. Update credit information from appropriate incoming packets and
include current local accounting on every stream-associated outgoing packet.

Follow the existing TCP receive boundary (Q6): advertise only the dedicated
sys-io receive buffer. Reserve an IPC RX page before removing bytes from
that buffer; advance `fwd_cnt` as those bytes leave it. Client-held pages
are separately bounded by the existing subchannel page pool. When it fills,
sys-io stops draining the receive buffer and peer credit eventually reaches
zero. Reposting a DMA buffer or reaping a TX completion releases no receive
credit. No new client byte-acknowledgement protocol is necessary.

Handle CREDIT_REQUEST and CREDIT_UPDATE without consuming payload credit.
Coalesce redundant updates, send an update when a blocked peer can progress,
and allow at most the reviewed number of outstanding credit requests per
stream. Schedule them from state changes; do not periodically probe an idle
stream. Control capacity must still work when payload credit is zero.

Test counters near `u32::MAX`, exact exhaustion, partial credit, duplicate
updates, invalid advances, peer allocation changes, reserved-credit rollback,
and receive capacity restored at the sys-io-to-IPC boundary. Run arithmetic
tests in guest systest in release as well as debug. Include a stalled
application to prove that the two independently bounded stages backpressure
the peer without blocking other streams or exhausting device RX buffers.

### 7. Implement connect, connection lookup, and protocol transitions

Use a small explicit state machine and a connection table keyed by the full
local/remote CID-and-port tuple. Keep a separate opaque client handle; a wire
tuple is not authority to access another client's socket. Allocate outgoing
ports with collision checks and bounded exhaustion behavior under Q8.

Implement REQUEST/RESPONSE establishment, refused connects, stream data,
credit messages, peer shutdown, and reset. Bound pending connects and ensure
response handling verifies the expected peer and state. Reserve receive and
control resources before accepting a connection. Check unknown tuples and
unsupported socket types before delivering data, including protocol-required
RST replies. Do not generate a reset-response loop for an incoming RST.

Record state transitions in tests as inputs and expected outputs: emitted
control packets, byte/accounting changes, state, and waiter notifications.
Cover refusal, unexpected responses, duplicate requests, wrong destinations,
data before establishment, and stale packets after closure. Implement only
the approved scope; unsupported operations need explicit errors.

### 8. Implement bind, listen, and accept

Keep a listener table separate from active streams. Follow Q8 for binding
the current local CID, explicit ports, and automatic ports. Reject conflicts
deterministically. Use a fixed reviewed backlog,
with each pending accepted stream charged to its owner and global limits.

Create a stream only after reserving its resources. Queue it for accept
without changing the listener's identity. Define how data arriving between
RESPONSE and application accept is buffered within that reservation. Refuse
requests that cannot be admitted without losing an existing stream's data.

Test multiple accepts, backlog exhaustion, bind collisions, listener drop,
accept cancellation, early peer data/close, and release of unaccepted streams
when their owning channel disappears. Keep blocked accepts from holding a
runtime borrow or preventing dispatch to established sockets.

### 9. Define the native IPC contract

Add `src/sys/lib/moto-sys-io/src/api_vsock.rs` and export it from the crate.
Extend the existing networking endpoint/dispatch; do not add another service
name, channel-budget kind, or client driver. Specify each message's direction,
handle, request ID, payload fields, ownership transfers, and terminal reply.

The minimal semantic operations are query local CID/availability, connect,
bind/listen, accept, TX, RX delivery, receive-storage release, shutdown,
close/drop, and terminal-state/error notification. A field needed only for
the wire protocol, such as a guest-chosen source CID or peer credit counter,
should remain sys-io-owned rather than client-controlled.

Use fixed-width address fields and existing `io_channel::Msg`/shared pages.
Do not encode CID/port as an IP `SocketAddr`; vsock ports are 32-bit. Avoid
a second serialization framework or a variable-size control protocol.
Reuse page release and wakeup machinery: releasing a client page allows more
RX delivery, but does not directly alter peer byte credit. Check IDs, page
indices, lengths, flags, and ownership in release.

Preserve existing command values and update `NetCmd::try_from`, range checks,
and both dispatchers intentionally. Reuse existing operation bodies where
their layouts/semantics truly match, with explicit socket-kind validation;
add vsock commands for different address/control layouts. Existing TCP/UDP
and rt.vdso callers must keep their current wire contracts.

Add `SocketState::Vsock` and a vsock listener state. Refactor only the
netstack-dependent fields of `SocketBase`/listener dispatch into an explicit
backend/address distinction. Retain common socket IDs, client ownership,
notifications, and cleanup bookkeeping. In particular, dropping a vsock
socket must not remove a handle from a NIC's netstack socket table. Avoid
fake IP addresses, copied TCP state machines, and a new transport framework.

Test fixed wire examples, 32-bit ports above 65535, invalid fields, foreign
handles/pages, duplicate releases, cancellation/late replies, and stale IDs.
Use existing Motor error values and explicitly map absence, unsupported
operations, invalid addresses, refusal, reset, exhaustion, and timeout.
If a necessary error cannot be represented, raise it for review instead of
expanding moto-rt as a side effect.

### 10. Bridge sys-io streams and client pages

Implement IPC handlers around the state machine. Validate owner identity
before touching a socket, and snapshot client-controlled message fields
before using them. Keep raw packet headers and device DMA memory private
to sys-io. Follow Q6 for copies and ownership of payload bytes.

On TX, retain a bounded number of client pages until their data is copied
into private packet-sized DMA buffers; then release pages through the
existing ownership mechanism. Do not DMA directly from client-controlled
memory. Preserve stream order across partial progress. A writable notification
must correspond to capacity the application can actually use. Record when a native
write becomes successful and what a later reset does to unsent bytes.

On RX, copy validated payload into the bounded sys-io buffer, then use the
existing allocation-before-drain sequence to deliver IPC pages. Reuse page
ownership validation, not an invented client-reported consumed-byte count.
On refusal or error, return every recovered page exactly once. Coalesce
small wire payloads in byte storage so a peer cannot exhaust metadata by
sending many one-byte packets within its advertised receive credit.

Exercise a stalled reader/writer, IPC page exhaustion, slow response queues,
and client death during transfer. Verify another client and the device's
event/control paths still progress. Keep pending close/error delivery bounded
when the channel itself is full.

### 11. Add the moto-io native API and cancellation behavior

Proposed placement: `src/sys/lib/moto-io/src/net/vsock.rs`, exported through
`moto_io::net::vsock`. Reuse `NetClient`, its reservation API, and the same
explicitly driven `NetDriver` (Q5). Generalize typed socket maps, waiter
dispatch, and cancellation records only where needed for vsock. Reuse the
existing Arc/locking model; do not introduce a second local-only client,
background thread, global singleton, or a copy of the TCP client driver.

The reviewable API surface is an address type, local-CID discovery, a stream
with async connect/read/write/shutdown, and a listener with bind/accept.
Define EOF, zero-length operations, short reads/writes, peer/local addresses,
and error propagation. Preserve the existing async read/write and readiness
patterns, including concurrent read/write on a shared handle. Do not add
blocking wrappers, stream-cloning semantics beyond shared ownership, TCP-only
options, seqpacket abstractions, or an FD/vDSO compatibility layer.

Document which future/task drives IPC, whether handles cross threads, and
what drop does. Cancellation must remove waiter registrations and release
reservations. If a canceled connect/accept later produces a live socket,
close it and reclaim its pages. Define cancellation of a partially admitted
write so it cannot silently duplicate bytes if the caller retries.

Add native tests patterned after `systest/src/net_driver.rs`: construct and
drive the client, reserve/use/release resources, shut down the driver, and
observe its exit. Cover cancellation while waiting for a reply, data, TX
pages, and a close notification. Include registration/recheck/wakeup races
and the approved concurrent-use semantics.

### 12. Wire device discovery, the runtime, and service admission

Extend `runtime::async_runtime` to retain the supported vsock device and
pass its dormant state to the networking runtime. Keep filesystem and IP
initialization working when vsock is absent or rejected. Preserve the vector
of NICs and the explicit multi-block rejection. The one-vsock limit belongs
to service admission, not to generic PCI/queue or other device-kind code.

Use a small absent/dormant/initializing/ready/failed state. The first
authorized operation needing a CID or socket initializes once; concurrent
callers await the same result. Cancellation of one caller must not drop
partially initialized queues. An availability query can report discovery
without activation; querying the actual CID may trigger it. No queue tasks
or buffers are created for an unused device, and no device rescan is needed.

Add vsock dispatch and client cleanup to the existing endpoint, independent
of IP configuration. Reuse net-channel admission and reserved fs/net capacity.
Do not start another listener, count a shared channel twice, or treat a
CAP_VSOCK denial as denial of the channel's TCP/UDP operations. Proposed
initialization-failure/extra-vsock handling is recorded in Q9.

Bound connections, listeners, pending accepts/connects, queued bytes/pages,
and control work as specified in Q7. The proposed copy-based design should
charge committed storage before accepting work that needs it. Do not add
unbounded tasks as an alternative to bounded queues. Use the existing
trusted channel/process identity for Q8 authorization checks.

Test ordinary no-vsock boot and fail-fast native discovery, attached-but-idle
boot, first-use initialization, simultaneous first callers, canceled first
callers, capacity boundaries, and denied operations. Exercise coexistence
with the ordinary block/network configuration and existing channel budget;
do not add multi-NIC testing/fixing or multi-filesystem support. Verify no
host rendezvous or per-application driver initialization.

### 13. Finish shutdown, reset, and teardown under load

Implement directional shutdown as permanent state. Drain already accepted
outgoing bytes before write-shutdown; deliver received bytes before EOF
when the chosen close policy permits them. Complete graceful shutdown with
the protocol's reset exchange, retaining the tuple until safe to release.
Peer SEND shutdown means EOF after queued data; peer RECEIVE shutdown stops
local writes. Accumulate shutdown flags rather than clearing earlier ones.
Distinguish the RST completing an orderly close from an unsolicited reset,
so a successful close is not reported as a failed connection.

Use the Q10 deadline only for an actual connect/close operation, not as an
idle poll or reliability workaround. The proposal is Linux's 2-second
connect and 8-second transport-close defaults, not Motor TCP's 123-second
connect/60-second linger constants. Drop must remain nonblocking, with
bounded server cleanup. Test simultaneous close and reuse.

Continuously service the event queue. On transport reset, refresh the CID,
terminate active and connecting streams, discard unaccepted streams from
the old transport, and wake affected clients; keep listeners usable with
the current CID. Validate and replenish event buffers, including after an
unknown event. The event path in
[Linux's virtio transport](https://github.com/torvalds/linux/blob/master/net/vmw_vsock/virtio_transport.c)
is a useful cross-check for CID refresh and event-buffer recycling.

Remove unsent old-connection packets and prevent late completions from
changing new socket state. A transport-reset event does not itself return
DMA ownership of every outstanding descriptor. Keep submitted completions
alive and reap them through the existing queue; never implement reset by
dropping all queue futures. Do not reset/recreate the whole device to close
one socket.

On channel failure or client exit, remove that client's listeners, abort or
finish its streams under Q10, and drain/release pages, pending replies,
waiters, timers, and reservations. Keep cleanup idempotent across peer reset,
client drop, and late reply races. Device failure must be distinguishable
from a single stream failure under Q9.

In guest systest fixtures, test reset during connect, queued accept, read,
credit-blocked write, and in-flight DMA. Test the same CID and a changed CID,
repeated events, invalid
event lengths, listener continuity, stale completions, and bounded resource
counts after repeated create/use/drop cycles. No migration test, new sys-io
self-test, or production event-injection command is planned. Distinguish
fixture coverage from actual VMM-triggered reset coverage; if another test
hook is necessary, discuss it first (Q12). Transport reset remains required
Virtio 1.1 behavior even though migration support is out of scope.

### 14. Add a hermetic host/guest acceptance phase

Add `src/sys/tests/systest/src/vsock.rs` and an explicit vsock test command
in `systest/src/main.rs`. Run hardware-independent tests in the ordinary
systest path. Run real peer tests through a dedicated
`src/tests/test-vsock.sh`, called directly from `src/tests/full-test.sh` with
the selected debug/release mode. Device-present testing must be an actual
required phase, not a successful skip when no device was attached.
Bring the necessary pieces of this phase forward with the implementation
commits that need them; do not postpone executable tests until this stage.

Run the guest suite on all three VMMs, with one modern PCI vsock device each:

- QEMU: use `vhost-user-vsock-pci` and an unprivileged UDS backend such as
  `vhost-device-vsock`, with shared guest RAM and a separate vhost-user
  control socket. Do not use `/dev/vhost-vsock` or host `AF_VSOCK`.
- Cloud Hypervisor: use the built-in `--vsock cid=3,socket=<path>` backend.
- Firecracker: supply its `vsock` configuration with `guest_cid` and
  `uds_path`. The existing `src/vm_scripts/run-fc.sh` already uses
  `--enable-pci`; no virtio-MMIO driver is needed for this plan.

Use one small standard-Rust host peer based on `std::os::unix::net`. It only
provides deterministic peer actions/data and orchestration; guest systest
owns test assertions and verdicts. The UDS mapping uses `<path>_<port>` for
guest-to-host service connections; host-to-guest connects send a `CONNECT`
line and consume the backend's `OK` reply before application data. See the
[Firecracker UDS protocol](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
and [vhost-device-vsock setup](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md).
Confirm installed versions and prerequisites as described in Q11. Existing
tap setup is unchanged; the vsock backend itself must need no new privileges.

Use per-run temporary sockets, a deterministic framed test protocol,
bounded deadlines, explicit readiness, and cleanup of owned processes/files.
Serialize all three VMM phases against other VM tests using the existing
exclusion mechanism; the runners share tap/address resources. Save logs and
verify that results came from the VM launched by this invocation. Change runner
sources under `src/vm_scripts/` if needed, not generated copies in
`vm_images/`. Keep ordinary runners usable without a vsock device. Account
for each runner's image/console conventions: Firecracker currently uses the
raw base image and 64 MiB RAM. Ensure the selected debug/release systest is
actually in its test image and report results from that instance.

The acceptance cases are:

- Guest connects to host and host connects to a guest listener, using
  explicit non-default ports and exact byte-content checks.
- Zero-length API operations, one-byte transfers, packet/page boundaries,
  and transfers much larger than the receive window in both directions.
- Full-duplex transfer; a stopped reader that resumes through credits; a
  blocked connection alongside another active connection.
- No listener, duplicate bind, unsupported address/type, connection timeout,
  backlog exhaustion, peer reset, half-close, clean close, and port reuse.
- Cancellation and client process exit during connect, accept, RX, and TX;
  repeated cycles must return observable resource counts to baseline.
- Capability inheritance and denial, including raw IPC attempts; no-device
  errors and attached-but-idle/first-use behavior.
- Transport-reset handler/listener recovery through the guest fixture route,
  clearly labeled as such, not migration or a new sys-io self-test.
- Block and TCP/UDP I/O while vsock transfers run, plus a no-device VM run
  verifying existing services and prompt native unavailability errors. Keep
  the existing NIC/block topology; multi-NIC tests/fixes and enabling multiple
  filesystems are explicitly not acceptance requirements of this work.

Keep payload peers local. The new tests do not contact the Internet, fetch
dependencies, or add retries. Missing mandatory test prerequisites must
produce a clear failure before launching the phase.

### 15. Measure, document, and complete the integration

Measure unchanged-topology boot latency with no vsock device, startup cost
with the device attached but unused, first-use cost, idle CPU/wakeups,
fixed device memory, per-stream memory, small-message latency, and sustained
transfer rate. Include a
concurrent block/network workload to detect executor starvation. Report
the buffer sizes and topology with results; agree material acceptance
thresholds during review instead of inventing a performance target. Attached
but unused must not allocate the lazy device's queues or run device pumps.

Document the native API with one small client/listener example, driver
lifetime requirements, error/drop semantics, supported endpoints, resource
limits, and the tested launch configuration. State that native vsock support
does not imply a libc, Rust-stdlib, mio, or Tokio socket API.

Keep diagnostics small: initialization/error logs and the resource counters
needed to prove admission and teardown are sufficient initially. Do not add
per-packet production logs or a new monitoring service. Remove temporary
instrumentation before final validation. Update this document with completed
steps and evidence only after the corresponding behavior is implemented.

## Validation and completion criteria

The test wiring must make the following coverage real:

| Coverage | Execution path |
| --- | --- |
| Wire validation and actual queue ownership/exhaustion | Existing virtio-async `test-support` fixture route -> `systest/src/virtio.rs` -> ordinary full-test VM, both profiles. |
| Pure credits, connection transitions, and reset handling | Same implementation helpers compiled into guest systest; no separate host suite or sys-io self-test registration. |
| Capability defaults, delegation, and denial | Systest child-process and native/raw-IPC cases, both profiles. |
| Native API, real DMA, peer interoperability, and cleanup | `test-vsock.sh` -> guest systest plus local UDS peer on QEMU, Cloud Hypervisor, and Firecracker, both profiles. |
| Existing OS behavior and absent-device behavior | Existing full-test phases, preserving their device configuration and assertions. |

For implementation, format changed Rust with `cargo fmt` from the
repository-selected Motor toolchain and run targeted clippy checks for the
changed crates with `--target x86_64-unknown-motor`. Introduce no new compiler
or clippy warnings and do not broaden existing warning suppressions.

A13 explicitly changes the default per-commit repeated gate to a
milestone-based gate. Recommended grouping (frequency remains open in Q13):

- M1, foundations: stages 1–6, covering capability delegation, modern device
  support, shared-queue changes, and credit arithmetic. Fully gate this
  related group before moving into the client/server integration.
- M2, complete integration: stages 7–15, covering state machines, shared
  networking IPC, native API, lazy activation, cleanup, and all three VMMs.
  Full gates include the complete new vsock phase by this milestone.

Each small implementation commit must build and run its affected guest
systest cases in debug and release, plus directly affected existing queue,
capability, TCP/UDP, or native-driver regressions. Keep those tests in
full-test transitively; no commit gets to defer its tests to the milestone.
Bring real-peer test plumbing forward whenever a commit needs it.

At each agreed repeated-gate milestone, obtain three passing debug and three
passing release main-image builds/runs, retaining logs for the whole group:

```sh
make -j"$(nproc)"
src/tests/full-test.sh
make -j"$(nproc)" BUILD=release
src/tests/full-test.sh --release
```

Run each profile's build/full-test cycle three times at that milestone.
These are validation runs, not a retry-until-green policy. Diagnose any
failure, preserve its original evidence, and rerun to test a specific
hypothesis. Do not extend timeouts, weaken assertions, or ignore errors.
Only the already accepted DNS/ping external-network flakes get the single
retry allowed by AGENTS.md; stop and discuss if that retry fails.

If a developer-image gate is needed, use only
`src/tests/full-test-dev.sh --release`, including its release-only
`test-dev-sources.sh` phase. This is not Lorry work. No debug developer-image
run or Lorry changes are planned.

Completion means an application using moto-io can use the approved stream
operations through sys-io and the real virtio queues; flow control and
teardown remain bounded under the listed tests; both present/absent-device
configurations work on all three VMMs with UDS peers; CAP_VSOCK cannot be
escalated or bypassed; required tests are reachable from full-test; and the
agreed boot/performance checks pass. A discovered PCI device or a packet
echo alone is not completion of the integration.

## Review responses and remaining open questions

Q-numbers are retained to match the original review. Recorded decisions are
requirements; paragraphs labeled **Open** are not yet approved. Suggestions
answer the requests for more information without silently settling policy.

### Q1. Profile and topology: resolved; endpoint scope to confirm

Original A1 requested multiple devices and seqpacket. The subsequent
clarifications supersede it as follows:

- Virtio 1.1, stream-only, modern PCI; no legacy or newer socket features.
- One vsock device is sufficient now; no multi-vsock implementation or tests.
- Keep generic virtio/IRQ infrastructure compatible with multiple NICs and
  block devices. Do not impose a one-NIC topology to make vsock fit.
- Preserve sys-io's second-block-device rejection until multiple filesystems
  arrive. Do not change root-disk selection or implement secondary-disk use.
- Multiple NICs should continue working; new multi-NIC testing/fixing is out
  of scope. Existing tests and ordinary networking regressions still run.

**Open:** Is host CID 2 the only required peer for this implementation?
Recommend yes for the UDS-backed acceptance profile. Guest-to-guest routing
and guest-local loopback would add backend/routing policy and separate tests;
neither is implied by supporting stream connect and listen.

### Q2. Ownership: resolved

A2 agrees that virtio-async owns packet/event I/O and sys-io owns connection
state, credits, listeners, and client routing. No socket framework in the
driver crate and no new reusable protocol crate are planned.

### Q3. HeaderBuffer reuse: yes; sizing proposal

A3 asks whether `HeaderBuffer` and `get_buffer<T>()` can be reused. Yes:
their lifetime rules already fit vsock. Only the hard-coded 16-byte capacity
prevents the 44-byte header today. Change allocation and the checks in both
`get_buffer<T>` and `read_header<H>`, plus their fixture; retain the existing
completion ownership and use one page-aligned payload buffer.

**Open:** Recommend 64-byte scratch for vsock queues, keeping block/net at
16 bytes. A small device-kind size choice avoids another header allocator
and changes no block/net memory footprint. Uniform 64-byte scratch is a
slightly smaller edit but adds 12 KiB per 256-entry existing queue. For
vsock, three 256-entry queues would use 48 KiB of scratch in total. Use
release capacity/alignment checks before typed access in either case.

### Q4. Networking reuse: shared channel, with a small backend split

A4 requests maximum networking reuse and asks whether vsock can be another
socket type. Yes: add a vsock stream variant alongside TCP and UDP, plus a
vsock listener, on the same endpoint. Virtio 1.1 removes the proposed second
vsock/message socket kind entirely.

Reuse client identity, socket IDs, reservations, pages, notification queues,
and cancellation plumbing. The concrete changes are in `SocketState`,
IP-specific `SocketBase` fields/drop, listener dispatch, and `NetClient`'s
TCP-specific maps/waiters. A vsock socket must not require a NIC index or
netstack socket handle. This is narrower than another service/client stack;
existing TCP/UDP wire values and behavior remain unchanged.

### Q5. Simplest native API: reuse NetClient/NetDriver

A5 asks for the simplest implementation. Recommend `VsockAddr`,
`VsockStream`, and `VsockListener` in `moto_io::net::vsock`, created through
the existing client/reservation model. The caller drives the same NetDriver
as TCP/UDP, and handles reuse existing Arc/waiter synchronization. This
retains concurrent read/write and existing thread-sharing behavior without
adding a local-only alternative or a hidden runtime.

**Open:** Confirm that minimal surface and module placement. Start with
connect, bind/accept, read/write, shutdown, addresses, and existing-style
readiness/try-I/O where reusable; no blocking wrapper, new socket options,
or FD integration. Define partial-write/cancellation semantics before
publishing signatures, using the existing networking behavior as the model.

### Q6. Receive-credit boundary: follow existing TCP

A6 requests existing networking behavior unless another approach is simpler.
`tcp_read_task` in `runtime/net/socket/tcp.rs` first reserves an IPC page,
then removes bytes with `recv_slice`, reopening the server TCP receive
window. The client later frees whole pages; `TcpStreamRxAck` wakes the
server but does not carry a validated consumed-byte count.

Use exactly that separation: vsock advertises its sys-io receive-buffer
capacity and advances `fwd_cnt` when bytes are moved into a reserved IPC
page. IPC storage stays independently bounded; a stalled client eventually
fills both stages. The earlier end-to-end credit/byte-ACK suggestion is
withdrawn because it would add bookkeeping that TCP does not need.

### Q7. Resource bounds: reuse networking where it fits

A7 prefers existing networking mechanisms or simple fixed limits. TCP uses
128 KiB RX/TX defaults (with adaptive sizing); native net reservations divide
each direction's IPC pages into four 16-page subchannels, or 64 KiB per
reserved socket. Reuse the reservations/page pools and the 128 KiB RX size.
Vsock needs neither TCP retransmission storage nor UDP's dropping queues.

**Open:** Approve these fixed starting bounds, subject to measured memory
and throughput? They are proposals, not Virtio or Linux defaults.

| Resource | Proposed starting bound |
| --- | --- |
| Queue sizes | Use existing negotiated power-of-two sizes, capped at 256; require RX capacity of at least two, TX at least 16 for the reserve below, and event at least one. |
| RX payloads | `min(64, rx_descriptors / 2)` page-sized buffers, reposted promptly. |
| TX payloads | `min(64, (tx_descriptors - 8) / 2)` page-sized buffers; reserve eight descriptors for control. |
| Events / pending control | Up to four posted event buffers; 64 pending control records, coalescing credit updates. |
| Stream receive buffer | Fixed 128 KiB in sys-io, allocated/charged before establishing a connection. |
| Stream IPC / pending TX | Existing 16 pages per direction per reservation; no additional per-stream TX ring. |
| Stream/listener admission | 64 streams globally, counting connecting, unaccepted, and closing states; 32 listeners, backlog eight each, still within the global stream cap. |
| Per-channel admission | Existing four data reservations and channel budget; do not create a separate quota framework. |

At 256 descriptors per queue, the proposed RX/TX pools hold at most 512 KiB
of payload, plus 48 KiB of header scratch, ring allocations, and bookkeeping.
Sixty-four receive buffers reserve 8 MiB before IPC pages and other overhead.
Check total committed memory against the 64 MiB Firecracker configuration;
allocation/admission failure must return an error, not kill existing streams.
Allocate on demand, not at boot or for every potential connection.

Pack small payloads into byte buffers, bounding metadata independently of
wire packet count. Round-robin ready streams with bounded work per turn;
stop accepting new work at capacity, preserve active-stream data, and keep
reserved control/completion work runnable. No timers for idle credit probing,
new adaptive-buffer policy, or unbounded per-request tasks.

### Q8. CAP_VSOCK: resolved; address/port policy still open

A8 requires CAP_VSOCK for connect/listen, granted by default to normal system
and user processes, with parent-controlled grant/denial. Only parents holding
the bit may grant it. This applies even to System parents; CAP_SYS is not an
override. Step 2 covers defaults, explicit masks, trusted peer checks, and
the kernel enforcement needed to keep denial transitive.

**Open:** Recommend `VsockAddr { cid: u32, port: u32 }` for peer addresses,
with `bind(port)` using the current local CID supplied by sys-io. Port zero
requests automatic allocation, consistent with the native networking API;
reserve `0xffffffff`, use a collision-checked automatic range starting at
49152, and permit other explicit ports to any CAP_VSOCK holder. No additional
privileged-port classes, cross-device wildcard binds, or reuse options.
Confirm these conventions; CAP_VSOCK alone does not decide them. Keep tuples
reserved through close so automatic reuse cannot attach to an old connection.

### Q9. Lazy initialization: resolved; failure policy proposal

A9 requires lazy init, an unchanged no-device boot path, and no hot-plug or
unplug. Host-to-guest service becomes available only after an authorized
guest operation activates the device and binds its listener. That is a
consequence of lazy initialization, not a boot-time host handshake.

**Open:** Recommend retaining the first discovered vsock device and logging/
ignoring any additional devices without initializing their queues. Failed
initialization leaves vsock unavailable while fs/IP continue. Cache the
failure; do not automatically retry, rescan, or rebuild queues. A fatal later
configuration failure similarly fails vsock clients without dropping
outstanding DMA ownership. Normal transport reset follows the protocol and
keeps listeners operational when the refreshed configuration is valid.

### Q10. Linux deadlines: suitable defaults, with native close semantics

A10 asks for Linux defaults and whether they can be reused. Yes. Linux
v6.18 provides a concrete reference (not a claim about every kernel version):

| Behavior | Linux reference | Proposal for Motor |
| --- | --- | --- |
| Connect timeout | 2 seconds in `af_vsock.c`. | Use 2 seconds, reusing native deadline/cancellation machinery. |
| Virtio transport close cleanup | 8 seconds in `virtio_transport_common.c`. | Use an 8-second bounded server cleanup deadline. |
| Read/write waits | Generic socket defaults have no timeout. | No implicit I/O timeout; callers can use existing cancellation/deadlines. |
| Blocking linger | Opt-in through `SO_LINGER`, not the 8-second transport timer. | Nonblocking Drop; no new linger option initially. |

Sources: [Linux vsock defaults/linger](https://github.com/torvalds/linux/blob/v6.18/net/vmw_vsock/af_vsock.c),
[virtio close timer](https://github.com/torvalds/linux/blob/v6.18/net/vmw_vsock/virtio_transport_common.c),
and [generic socket initialization](https://github.com/torvalds/linux/blob/master/net/core/sock.c).
Motor's existing TCP constants are 123 seconds for connect and 60 seconds
for default linger; reuse their machinery, not those durations.

**Open:** Adopt these defaults? Proposed native policy: explicit async
shutdown drains accepted TX before sending shutdown; Drop/client exit starts
nonblocking bounded cleanup. Use a single 8-second cleanup budget including
pending-data drain, then force reset if necessary. This last choice adapts
the Linux duration to Motor's IPC buffering; it is not identical Linux close
semantics. Keep already validated buffered RX readable before reporting a
reset, distinguish orderly EOF, and never reuse an old tuple before terminal
cleanup. A completed write is local acceptance, not proof of peer receipt.

### Q11. VMM coverage: all three, using UDS

A11 requires QEMU, Cloud Hypervisor, and Firecracker, unprivileged UDS host
backends, and no migration. The later Virtio 1.1 decision removes the earlier
seqpacket backend incompatibility; no external-backend development is needed
for the selected stream protocol.

| VMM | Planned transport/backend | Setup evidence and remaining validation |
| --- | --- | --- |
| QEMU | Modern `vhost-user-vsock-pci` plus UDS `vhost-device-vsock`; shared guest RAM. | Installed QEMU 10.2.1 exposes that device/chardev interface. `vhost-device-vsock` is not currently on PATH. Pin/install a released backend during test setup, not during regular tests. |
| Cloud Hypervisor | Built-in `--vsock cid=3,socket=<path>`. | Installed v52.0; native vsock config is a singleton and its documented protocol is streams over UDS. |
| Firecracker | Built-in `vsock` JSON configuration over PCI and UDS. | Installed v1.15.1; native config stores one device. The repository runner already enables PCI. |

The native singleton/stream observations come from
[Cloud Hypervisor's vsock documentation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/vsock.md),
[its config representation](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/vmm/src/config.rs),
and [Firecracker's vsock builder](https://github.com/firecracker-microvm/firecracker/blob/main/src/vmm/src/vmm_config/vsock.rs).
For QEMU, the [backend's documented setup](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md)
separates the vhost-user control socket from the host application's UDS.
These are source/help checks, not completed Motor guest interoperability tests.

**Open:** Approve `vhost-device-vsock` as the QEMU host prerequisite? It
avoids host AF_VSOCK, `/dev/vhost-vsock`, FFI in the Rust peer, and backend
source changes. Keep all guest protocol/API code identical across VMMs and
make missing prerequisites a clear gate failure, never a successful skip.
No external repository changes or automatic dependency downloads are planned.

### Q12. Test route: resolved, guest systest only

A12 selects systest in the guest and prohibits new self-tests without
discussion/approval. Withdraw the previous host-helper unit-test suite and
sys-io `SELF_TESTS` proposals. Extend the existing guest queue-fixture route;
compile the real pure credit/state helpers into systest where needed.
Keep new assertions in systest and run them in both profiles via full-test.

The host UDS peer supplies actions/data only. Reset fixtures do not imply
VMM migration coverage. If testing requires a new production injection hook
or self-test entry point, stop and discuss it before adding one; do not
silently replace missing coverage with a debug-only test.

### Q13. Incremental commits: resolved; choose milestone gate frequency

A13 requests incremental commits grouped into fully tested larger milestones,
not three debug/three release full gates on every commit. Every option below
keeps per-commit affected tests in both profiles and the complete final suite,
including all three VMMs. M1 is foundations (stages 1–6); M2 is complete
integration (stages 7–15), as described in the validation section.

**Open:** Which full-gate schedule should be used?

| Option | M1 full gate | M2/final full gate | Tradeoff |
| --- | --- | --- | --- |
| Recommended: two repeated milestones | Three debug + three release. | Three debug + three release. | Checks the shared queue/capability foundation before layering on the service; much less repetition than per commit. |
| Lighter intermediate milestone | One debug + one release. | Three debug + three release. | Same test coverage, less intermediate repetition, later detection of intermittent foundation regressions. |
| Final-only full gate | Targeted guest tests only. | Three debug + three release. | Fewest full runs, but broad cross-component regressions may be discovered after more dependent commits. |

Do not reduce case coverage, skip a VMM, weaken assertions, or add retries to
save gate time. A failed milestone stops progression for diagnosis; preserve
the original failure even if a later diagnostic run passes. This document
revision makes no implementation commit and does not itself start the work.
