# Virtio-vsock design

Status: implemented, including the lifecycle and dispatch review fixes.
This document records the current contracts, not an implementation checklist.
The original D1–D28 identifiers are retained for references from other plans.
The superseded stage diary, investigations, and gate logs remain in Git
(the last unabridged version is at `d8559ce2`).

See [the native API guide](../vsock.md) for usage and launch commands,
[measurements](vsock-measurements.md) for performance and accounting limits,
and [the simplification plan](vsock-simplification.md) for proposed changes.

## Ownership and integration

| Component | Responsibility |
| --- | --- |
| `src/sys/lib/virtio-async/src/virtio_vsock.rs` | Device initialization, bounded DMA pools, ordered packet reception, packet submission, and device events. |
| `src/sys/sys-io/src/runtime/vsock/` | Connection state, credits, receive storage, tuple admission, and listener backlog. |
| `src/sys/sys-io/src/runtime/net/vsock.rs` | Protocol pumps, native IPC, client ownership, pending accepts/shutdowns, and cleanup. |
| `src/sys/lib/moto-sys-io/src/api_vsock.rs` | Native control-message layouts and checked codecs. |
| `src/sys/lib/moto-io/src/net/vsock.rs` | Native streams/listeners, application waits, and client IPC resources. |

Vsock uses the existing NET endpoint, driver, reservations, shared pages,
and channel budget. It does not use Ethernet, IP, DNS, DHCP, or the TCP
netstack. Device lifetime is independent of socket and client lifetime.

## Protocol reference

The profile is [Virtio 1.1, sections 4.1 and 5.10](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html):
modern PCI device type 19 (`0x1053`), with RX queue 0, TX queue 1, and
event queue 2. Require `VERSION_1`, optionally negotiate the supported
`EVENT_IDX` feature, and negotiate no device-specific bits or `IN_ORDER`.
`VERSION_1` distinguishes modern transport, not Virtio 1.1 from 1.2.

The little-endian header is 44 bytes. Stream type is 1; operations are
REQUEST=1, RESPONSE=2, RST=3, SHUTDOWN=4, RW=5, CREDIT_UPDATE=6, and
CREDIT_REQUEST=7. Shutdown masks are RECEIVE=1 and SEND=2. Transport reset
is a four-byte event with ID 0. Checked decoding includes unsupported-type
refusal handling.

Configuration contains a little-endian 64-bit guest CID whose upper word
must be zero. Valid guest CIDs are 3 through `u32::MAX - 1`; host CID is 2.
The existing split read is sufficient for this profile's single meaningful
32-bit field; it is not a general coherent-snapshot mechanism.

## Decisions

### D1. Supported profile

One modern PCI vsock device, existing split queues and MSI-X, reliable
host/guest byte streams only. No legacy transport, packed rings, datagrams,
seqpacket, guest-to-guest routing, loopback, hot-plug, or migration.
Preserve shared Virtio support for multiple NICs and sys-io's intentional
single-block-device restriction; neither is a vsock singleton assumption.

### D2. Layer boundaries

Virtio owns packet/event I/O and DMA. Sys-io owns connections, credits,
listeners, and client authority. Moto-io owns native application operations.
Keep moto-io's `no_std` boundary and existing in-tree dependencies. There
is no separate reusable protocol crate or socket framework inside the driver.

### D3. Queue scratch storage

Vsock queues use 64-byte scratch slots; block/net retain 16-byte slots.
Header capacity and alignment checks apply in release as well as debug.
Payload pages retain the existing alignment and descriptor-ownership rules.
Three 256-entry vsock queues use 48 KiB of scratch storage, allocated on
activation, not boot. Queue/IRQ allocation remains bounded by the shared
mapper; this feature does not expand kernel vectors or add IRQ sharing.

### D4. Shared NET service

Reuse channel identity, socket IDs, reservations, page ownership, and
cancellation. Keep the IP backend separate. An attached vsock device can
provide native NET service without a NIC or IP configuration; when both
IP and vsock are absent, native NET service remains unavailable.
Vsock alone must not start IP tasks or DNS work.

### D5. Native API

Expose `VsockAddr`, `VsockStream`, and `VsockListener` through the existing
`NetClient`/`NetDriver` and reservations. Support discovery, local CID,
connect, bind/listen, accept, addresses, try/async read/write, readiness,
and directional shutdown. No blocking FD, libc, Rust stdlib, mio, or Tokio
adapter or new socket-option framework.

### D6. Credit and publication boundaries

Advance receive `fwd_cnt` only when copying bytes into an already reserved
IPC page, not when the application reads or returns that page. Client-held
pages are independently bounded. Checked wrapping counters reject impossible
peer forwarding atomically; shrinking peer allocation below outstanding
bytes merely produces zero send allowance.

One TX pump checks peer credit and descriptor capacity, publishes, and
charges payload bytes without yielding between those operations. Headers
do not consume byte credit. DMA completion returns ownership, not peer
credit; client cancellation does not roll back published bytes.

### D7. Fixed bounds and scheduling

| Resource | Bound |
| --- | --- |
| Queue size | Power of two, at most 256; RX at least 2, TX at least 16, event at least 1. |
| Posted RX pages | `min(64, rx_queue_size / 2)`. |
| TX data pages | `min(64, (tx_queue_size - 8) / 2)`; eight TX descriptors remain reserved for controls. |
| Posted event buffers | `min(4, event_queue_size)`. |
| Pending wire-control records | 64 globally, including stateless refusals. |
| Streams | 64 globally, including connecting, unaccepted, and closing streams. |
| Listeners | 32 globally. |
| Unaccepted streams | Eight per listener, also charged to the global stream cap. |
| Waiting accept RPCs | Eight per listener, separately from unaccepted streams. |
| Outstanding shutdown RPCs | Eight per stream, including replies waiting for IPC space. |
| Buffered receive payload | 128 KiB per stream. |
| Pending stream TX | 16 IPC pages per stream. |
| IPC subchannel pages | 16 per direction; four socket reservations per native NET channel. |

These are distinct bounds, not a total-memory estimate: 64 receive buffers
alone can hold 8 MiB. Allocate fallibly on demand before publication.
No unbounded per-request task spawning, adaptive quotas, or polling timers.

Controls have TX capacity independent of data saturation. Per-stream work
uses round-robin selection and pumps yield after a quantum of 32. Preserve
wire ordering and control coalescing; never reuse a tuple before required
terminal control publication. Changes to bounds or scheduling policy require
review, not just a smaller line count.

Accept/shutdown waits do not retain NET dispatch tickets. A shutdown slot is
reserved before sys-io applies a new direction, and released when its reply
is published or discarded. Cancellation of a sent request does not retract
it. Native `shutdown_async` may already have closed the direction locally
and discarded buffered RX before server admission fails. Continued use after
that overflow is not guaranteed; drop the stream and drive normal cleanup.
No client-side rollback protocol is required. Server health, bounded work,
and reclamation after client death remain required.

### D8. Authority, addresses, and ports

`CAP_VSOCK` is bit 7. A parent must own it to grant it, including a System
parent; default inheritance and explicit launch masks preserve that rule.
Sys-io uses trusted peer identity/capabilities, never client-supplied claims.
The service-to-shell-to-application grant chain must carry the capability,
while explicit denial remains effective.

Native bind port 0 requests an ephemeral port, starting at 49152 with
wrapping collision checks. Bind `u32::MAX` and connect ports 0/`u32::MAX`
are invalid. No privileged-port classes, wildcard binding, or reuse option.
Wire peer ports retain their full `u32` range, including 0 and `u32::MAX`;
native local-port restrictions do not apply to a peer's source port.
A live or closing tuple stays reserved until cleanup completes.

### D9. Lazy initialization

Use absent/dormant/ready/failed state on the existing `LocalRuntime`.
Authorization precedes activation. First-use initialization is synchronous,
with no host wait, shared initialization future, or waiter list.
Availability reports discovery without activation; querying the actual CID
may initialize. An unused device allocates no queues, buffers, or pumps.

Retain the first discovered device and log/ignore additional devices without
initializing them. Prepare allocations and validate queue task setup before
DMA publication; publish only when initialization can safely complete.
Failure is cached, with no rescan, retry, or reconstruction. Retain any
already device-visible memory. Host-to-guest service starts only after an
authorized guest activates the device and binds a listener.

### D10. Deadlines and close

Connect has a two-second deadline. Drop/client exit starts nonblocking
cleanup with one eight-second budget, including accepted-TX drain, followed
by forced reset if necessary. Read/write have no implicit timeout; callers
use existing cancellation/deadlines. There is no blocking linger option.

Explicit async SEND shutdown drains previously accepted TX before wire
publication. A successful write is local acceptance, not peer receipt.
Shutdown directions are permanent: peer SEND yields EOF after buffered RX
without closing local writes; local SEND or peer RECEIVE stops new writes.
Complete graceful close with the protocol reset exchange, distinguishing its
RST from an unsolicited reset.

Retain validated buffered RX before a connection-local reset error. Device
failure instead discards RX and fails immediately (D26). Reclaim a dead
client's terminal stream independently of notification success. Successful
notification to a dead client must never be a prerequisite for map/tuple
removal, and cleanup must not release outstanding DMA ownership.

### D11. VMM coverage

Support QEMU, Cloud Hypervisor, and Firecracker with unprivileged local UDS
backends and one common guest implementation. QEMU uses
`vhost-user-vsock-pci` with pinned `vhost-device-vsock` 0.3.0; installation
is developer setup, not a test action. Cloud Hypervisor and Firecracker use
their built-in UDS backends, with Firecracker's PCI mode.
Missing prerequisites fail the gate rather than silently skipping it.
See [test setup](../tools.md#vsock-test-prerequisites).

### D12. Test route

Tests execute in guest systest through `src/tests/full-test.sh`, in both
profiles. Queue fixtures use the existing guest route; pure sys-io helpers
are source-included by `virtio-task-tests`. The UDS peer supplies test
actions/data, not a separate host-only unit suite. Do not add sys-io
`SELF_TESTS` registrations or production injection hooks without review.
Fixtures for reset/failure are not live migration/reset coverage.

### D13. Gate policy

The original implementation milestones and review-fix gate are complete.
Their per-commit gate exceptions do not apply to subsequent work.
Follow [AGENTS.md](../../AGENTS.md): core patches require fresh debug and
release builds/full tests, at least three passes each before committing.
Non-Lorry developer-image validation is release-only. Diagnose failures;
do not weaken assertions, add retries, or extend timeouts to obtain a pass.
Existing DNS/ping external-failure handling follows AGENTS.md.

### D14. Error mapping

Return existing native `moto_rt::Error` values directly; do not route vsock
through TCP's error mapper or expand moto-rt.

| Condition | Result |
| --- | --- |
| Missing capability | `NotAllowed`, before device presence. |
| No device | `NotFound`. |
| Permanent initialization/device failure | Cached `InternalError`. |
| Unsupported operation/type/option or syntactically valid non-host destination | `NotImplemented`. |
| Invalid address, flags, or request shape | `InvalidArgument`. |
| Bind conflict | `AlreadyInUse`. |
| Refused connect | `NotConnected`. |
| Established peer/protocol reset | `ConnectionReset` after validated RX drains. |
| Write after local SEND, peer RECEIVE, or orderly close | `NotConnected`. |
| Expired connect | `TimedOut`. |
| Local stream/listener/accept/shutdown admission or required allocation failure | `OutOfMemory`. |
| Try-I/O without progress | `NotReady`. |
| Unknown, stale, or foreign socket handle | `NotFound`. |
| Orderly read EOF | `Ok(0)`. |

Peer credit stalls, full established-stream buffers, and busy IPC pages are
backpressure, not allocation/admission failure. Preserve accepted bytes,
return successful partial writes where possible, and give pending async I/O
a concrete data/capacity wakeup. An empty live listener waits.
Over-capacity incoming REQUESTs receive wire RST, not a native error reply.
Retain connection-local terminal causes; D26's device failure overrides them.

### D15. QEMU shared guest RAM

Only a vsock QEMU launch opts into `MOTO_SHARED_MEM=1`, using
`memory-backend-memfd,share=on` and `-machine memory-backend=` instead of
`-mem-path`; retain hugepage use when available. Do not change ordinary
runner defaults or boot-time-measured configurations. Edit runner sources
in `src/vm_scripts/`, not generated copies in `vm_images/`.

### D16. VMM selection and images

`full-test.sh [--release] [--vmm qemu|chv|fc]` runs the suite and vsock phase
on the selected VMM, defaulting to QEMU. Each standard main-image run also
boot-checks the other two VMMs, including an SSH command and liveness check.
Boot checks and dedicated vsock VMs finish before the long-lived suite VM
starts. Runners share the VM exclusion lock; do not overlap their
tap/address ownership.

| Image/phase | QEMU / Cloud Hypervisor | Firecracker |
| --- | --- | --- |
| Standard suite | `main.img` → `motor-os.qcow2`. | Opt-in `raw.img` → `motor-os.img`, with standard-image contents. |
| System console | Raw `motor-os-system-tty.img`. | Same. |
| Developer image | `dev.img` → `motor-os-dev.qcow2`. | Unsupported. |
| Non-selected boot check | Main qcow2 image. | `base.img` → `motor-os-base.img`. |
| IP-disabled vsock discovery | Isolated raw `motor-os-vsock-test.img`. | Same. |

Keep `raw.img` out of default build targets. Resolve runner, profile, image,
and CPU/memory settings consistently through every launch phase, including
console/TUI tests. Preserve caller overrides and reject incompatible
selections before launch; never silently fall back to QEMU or reuse stale
images. Firecracker developer selection fails before builds/launches, and
developer gates do not require Firecracker boot checks.

### D17. RX completion ordering inside virtio-async

Preserve device used-ring order, not buffer posting or future polling order.
Vsock has no payload sequence numbers to repair reordered bytes. If buffers
A then B are posted and used heads arrive B then A, polling A first reverses
the stream. Wake order alone does not solve coalesced or already-ready
completions.

A crate-private ordered-head accessor observes completions already processed
by the existing reclaimer. One RX-owner cursor, claimed before publication,
tracks wrapping ring position and resolves each head to its owned completion.
Check device-published and reclaimed lag against queue capacity before
reading a retained slot; exactly one ring of lag is valid. Never reclaim
twice, reread a reused slot, or reopen a dropped cursor's claim.
An empty poll registers a concrete reclaimer wakeup.

Resolve and consume each ready head synchronously before fetching another,
reposting, or awaiting. The bounded, preallocated RX pool calls sys-io to
validate/copy into stream storage, then reposts the same page while ready.
Malformed packets must not stall consumption or leak ownership.
Applications never own device RX pages. No completed-head FIFO, sorting
pass, sequence tags, or per-stream reordering protocol is required.

Do not negotiate `IN_ORDER`: the pinned QEMU backend does not offer it,
and the shared split queue does not implement that feature's sequential
descriptor allocation and batched-completion semantics. Keep block/net
completion APIs unchanged. TX completion ordering does not establish TX
wire order; submission does. Failed devices follow D26's retention rules.

### D18. Shared reset completion check

Initialization writes status zero and reads it once before acknowledgment
or queue setup. A nonzero read fails initialization synchronously; there is
no polling/retry or asynchronous-reset support. This approved shared check
adds one MMIO read per initialized device. A zero status is not proof that
arbitrary outstanding DMA can be freed; D26 does not reset/reinitialize PCI.

### D19. Connection-local invalid-credit rejection

Atomically reject an advertised `fwd_cnt` advance beyond outstanding sent
payload without changing either peer credit field. Reset only the identified
connection, preserving earlier validated RX before its reset error.
Shrinking `buf_alloc` below outstanding bytes is ordinary zero allowance,
not this violation. Never answer incoming RST with another RST.

### D20. VMM defensive hardening

Additional hardening against buggy/malicious VMM metadata is outside this
design. The deferred PCI BAR-boundary work is in
[future work](future-work.md#deferred-pci-bar-boundary-hardening-2026-09-15).
This does not remove existing validation, normal protocol checks, or D18's
reset-completion check, and does not authorize new boot-time PCI work.

### D21. Availability discovery

`availability(&NetClient) -> Result<(), moto_rt::Error>` needs no reservation.
Query/cache the trusted capability word at first vsock use, not at channel
admission or boot; preserve native capability-query errors.
Check capability first. For authorized requests, require zero handle, flags,
and payload before testing device presence. Return success for dormant/ready,
`NotFound` for absent, and cached `InternalError` for failed.
Discovery does not read the CID, initialize queues, or start pumps.

### D22. Connection-local protocol rejection

A decoded packet with the right tuple but an operation invalid in that
connection state resets that connection. An RW payload exceeding advertised
receive allowance is rejected atomically and likewise resets only its
connection, without accepting its credit/payload or losing earlier RX.
These are protocol violations, unlike ordinary buffer backpressure.
Retain the first connection-local terminal cause, never answer RST with RST,
and leave unrelated streams and the device operational.

### D23. Shared NET subchannel validation

Validate raw TCP/UDP/vsock subchannel indices before computing a mask,
reserving a port, or creating a socket, in release as well as debug.
There are four valid indices, 0–3. Reject invalid requests with
`InvalidArgument`; native-client construction is not an ingress check.
Keep command values and valid wire layouts unchanged.

### D24. UDS test semantics

UDS half-close is not an independent Virtio shutdown-direction injector.
The supported proxies can translate host EOF into BOTH flags and need not
turn guest SEND-only shutdown into Unix EOF. Keep directional wire semantics
covered by real connection-helper fixtures; do not change production flags
or VMMs to fit a false fixture premise.

Live tests use a data stream and a separate framed synchronization stream.
Validate exact pre-shutdown data, await local shutdown, and exchange barriers
before the opposite-direction transfer. Cover local SEND retaining reads,
local RECEIVE retaining writes, and host Unix close draining RX to EOF and
rejecting new writes. Do not synchronize by sleeping.

An absent host UDS port need not produce wire refusal. The pinned QEMU
backend is a silent-connect fixture expecting exactly `TimedOut`, including
the two-second deadline; CHV/FC expect exactly `NotConnected`.
The harness declares the expected behavior. Do not accept either error
interchangeably or add VMM-specific production logic. Linux comparisons are
diagnostic evidence in Git, not a regular test dependency.

### D25. Pending accepts and handoff

Eight waiting accept RPCs per listener store bounded request/channel
metadata, independently of eight unaccepted streams and their receive
buffers. The ninth wait returns `OutOfMemory`; native reservation limits
do not replace server bounds on raw or cross-channel requests.
Unmatched waits return their NET dispatch tickets immediately.

Cross-channel accept is allowed only within the owning process. While a
reply waits for IPC space, recheck listener validity, destination lifetime,
and device state. Publish the reply before RX/state messages; install
ownership/routing without an intervening await after successful publication.
A disappearing destination is an ordinary cleanup path, never an assertion.
Invalidate a disconnecting owner's listeners before any unrelated teardown
can yield, so stale matched accepts cannot become usable afterward.

### D26. Permanent failure on device reset

A transport reset permanently fails vsock for sys-io's lifetime. Cache
`InternalError`, wake pending operations, fail listeners/accepts/streams,
discard buffered RX and queued TX, and reject later use. Leave shared-channel
TCP/UDP healthy. No CID refresh, listener rebinding, snapshots, or recovery.

The transition is idempotent. Stop submissions/reposting and reap returned
completions without dispatching their contents. Retain unreclaimed
device-owned buffers/queues; never fabricate completion, drop outstanding
DMA futures, or reinitialize the device to justify freeing them.
Guest fixtures cover failure and ownership, not live VMM reset injection.

### D27. Kernel thread-creation rollback

Thread-creation failure must not leave unpublished threads, object cycles,
kernel stacks, or active-thread accounting behind when process exit races
creation. The separate kernel fix is complete. It is not part of vsock's
runtime architecture or permission for further kernel changes.

### D28. Driver exit and abandoned operations

`NetClient` is weak; drivers, reservations, and real in-flight operations
retain channel ownership. An idle client must not keep sys-io's peer alive
after driver completion. Once the channel closes, reject new admission and
resolve residual waiters as `NotConnected`; do not wait for late successful
opens or add cancellation IPC.

Discarding abandoned work does not mean unmapping borrowed pages. An
in-flight future can retain an inert channel until polled after its error
wake or dropped. Normal connection Drop releases the mapping/peer only
after real owners leave. A freshly connected, unstaged driver can be dropped;
once work is staged, keep driving to completion. Preserve ordinary socket
Drop's queued-TX drain and TCP/UDP behavior.

A canceled accept on a live channel may hold one bounded pending slot until
a peer arrives or the listener drops. Late-success cleanup closes the child.
Prompt server-side retraction, successful delivery of abandoned operations,
and extra per-request cancellation state are not required.

## Validation coverage to preserve

The implementation and follow-up fixes have completed their recorded gates.
Historical runs are not validation of a new refactor; use fresh gates per D13.

- Existing guest Virtio fixtures: queue layout/ownership, used-ring order,
  wrapping counters, wakeups, pool reuse, malformed packets, and failure.
- Source-included protocol helpers: credit boundaries, RX atomicity, state
  transitions, half-close, terminal-cause precedence, admission, and cleanup.
- Native/raw IPC: wire layouts, capabilities, addresses, cancellation, driver
  lifetime, full receive rings, and TCP/UDP sharing.
- Live UDS cases: transfers beyond the receive window, pending-TX drain,
  shutdown ordering, accept handoff, backpressure, and device/no-IP discovery
  on all three VMMs.
- Lifecycle regressions: idle-driver process death, reply-backpressured
  cross-channel teardown, listener invalidation before a yielding disconnect,
  and accept/shutdown saturation without NET dispatch starvation.
- Exact global capacity and reuse after cleanup, not just peer EOF, port
  reuse, a successful allocation, or coarse memory samples.

Keep failures diagnosable and assertions exact. No new host-only suite,
production self-test framework, external-network dependency, VMM/backend
source change, or performance/boot-time regression is implied by this design.
