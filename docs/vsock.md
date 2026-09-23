# Native virtio-vsock API

Motor OS exposes virtio-vsock streams through `moto_io::net::vsock`. This is
a native Rust API. It does not provide libc, Rust `std::net`, mio, or Tokio
vsock sockets.

The process must have both `CAP_VSOCK` (bit 7) and `CAP_NET` (bit 8), granted
by an authorized parent. Even a System parent must own each capability to
grant it. Default inheritance and explicit service/shell/application launch
masks preserve that restriction. See [process capabilities](caps.md).
Device failure is permanent; snapshots and reset recovery are unsupported.
Component fixtures cover terminal failure and ownership, not live VMM reset
injection.

## Driver lifetime and a listener

`moto_io::net::connect()` returns a `NetClient` and its `NetDriver`. The
driver must be continuously polled on a `moto_async::LocalRuntime` while any
operation or socket on that channel is live. Run only one network driver on a
given local runtime. This example gives the listener and accepted stream
different channels and drives each on its own thread/runtime:

```rust
use moto_io::net::vsock::VsockListener;
use moto_io::net::{NetDriver, connect};

fn drive(driver: NetDriver) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(driver.run());
    })
}

fn main() {
    moto_async::LocalRuntime::new().block_on(async {
        let (listener_client, listener_driver) = connect().await.unwrap();
        let listener_thread = drive(listener_driver);
        let listener = VsockListener::bind_reserved(
            listener_client.try_reserve().unwrap(),
            70_001,
        )
        .await
        .unwrap();

        let (stream_client, stream_driver) = connect().await.unwrap();
        let stream_thread = drive(stream_driver);

        // A reservation from another channel is valid when both channels
        // belong to this process. This waits for a host (CID 2) connection.
        let stream = listener
            .accept_reserved(stream_client.try_reserve().unwrap())
            .await
            .unwrap();
        let local = stream.socket_addr().unwrap();
        let peer = stream.peer_addr().unwrap();
        assert_eq!(local.port, 70_001);
        assert_eq!(peer.cid, 2);

        // Socket Drop is nonblocking. Keep each driver alive until it has
        // published queued teardown and drained its channel.
        drop(stream);
        drop(listener);
        stream_thread.join().unwrap();
        listener_thread.join().unwrap();
    });
}
```

Use `VsockStream::connect_reserved(reservation, VsockAddr { cid: 2, port })`
for an outgoing connection. `try_read`, `read_future`, `readable`,
`try_write`, `write_future`, and `writable` provide nonblocking and async I/O.
`shutdown_async` accepts `Shutdown::Read`, `Shutdown::Write`, or
`Shutdown::Both`. Writes report local acceptance, not peer receipt.
During ordinary teardown, the driven channel publishes queued TX before
SEND shutdown or close; Drop itself does not wait.

Shutdown directions are permanent. Peer SEND produces EOF after buffered RX
drains and leaves local writes open; local SEND leaves reads open, while peer
RECEIVE stops further TX publication. Local RECEIVE discards buffered RX and
leaves writes open. Read/write have no implicit timeout; callers supply their
own cancellation or deadlines. A write returns an accepted prefix immediately,
so canceling a still-pending write has accepted no bytes.

`availability(&client)` checks authorization and discovery without activating
the device or reserving a socket. `local_cid(&client)` activates lazily and
returns the device's fixed CID without a reservation. A listener retains its
port; `socket_addr_async()` queries sys-io so permanent device failure is
reported instead of returning stale metadata.

Releasing the last reservation retires its channel; connect a new channel for
later sockets. For a channel used only for discovery/CID queries, call
`client.request_shutdown()` once the queries finish, then wait for its driver
to return.

## Errors, cancellation, and Drop

Errors are native `moto_rt::Error`/`ErrorCode` values; there is no TCP errno
translation layer.

- Missing `CAP_NET` means sys-io drops the channel when it accepts it, so
  every operation fails with `NotConnected`; `connect()` itself may still
  succeed. With `CAP_NET`, missing `CAP_VSOCK` is `NotAllowed`, checked
  before device presence.
  No discovered device is `NotFound`, and a syntactically valid non-host
  destination is `NotImplemented`.
- Invalid CIDs, ports, flags, and request shapes are `InvalidArgument`.
  Binding an occupied local port is `AlreadyInUse`.
  A refused connection is `NotConnected`; a silent connect reaches the fixed
  two-second deadline as `TimedOut`. Established peer/protocol reset is
  `ConnectionReset`, delivered after earlier validated RX drains. The first
  connection-local terminal cause is retained.
- Writes after local SEND, peer RECEIVE, or orderly close are `NotConnected`;
  a retained terminal error takes precedence. Try-I/O without progress is
  `NotReady`, and orderly read EOF is `Ok(0)`.
- Global stream/listener/pending-accept/shutdown admission and required socket
  allocation failures return `OutOfMemory`. A full client channel returns
  `ReserveError::AtCapacity`; a retiring channel returns
  `ReserveError::ShuttingDown`.
- Initialization failure or device reset permanently caches `InternalError`
  for vsock. Existing streams, listeners, and pending operations fail,
  buffered RX and queued TX are discarded, and later vsock operations return
  the cached error. There is no reset recovery or listener rebinding.
- Canceling an accept releases its client reservation. A sent cancellation
  can still occupy one bounded server accept slot until a peer arrives or the
  listener is removed; a late successful child is closed rather than exposed.
- Dropping a stream or listener is nonblocking. Continue driving its channel
  until `NetDriver::run()` returns so accepted TX and queued teardown drain.
  Stream Drop/client exit starts one eight-second cleanup budget in sys-io,
  including accepted-TX drain, followed by forced reset if necessary. There
  is no blocking linger option. Dropping an active, undriven driver is
  unsupported; a freshly connected driver with no staged work can be dropped.

Peer credit stalls, full established-stream buffers, and busy IPC pages apply
backpressure rather than admission errors. Async I/O waits for data/capacity
wakeups; an empty live listener waits for a child. Incoming connections that
exceed admission limits receive wire RST.

An idle retained `NetClient` is weak: it does not keep a completed driver or
IPC mapping alive. After driver exit, RPCs return `NotConnected`, reservations
are zero, and new reservations are `ShuttingDown`. An operation already in
flight may retain inert channel ownership until it is polled to completion or
dropped; the idle client alone does not.

## Supported endpoints and limits

The implementation supports one modern virtio-vsock device and stream sockets
to the host endpoint (CID 2). Datagram, seqpacket, guest-to-guest routing,
loopback, wildcard/reuse binding, privileged-port classes, legacy transport,
packed rings, and hot-plug are not provided.

`VsockAddr` contains full-width `u32` CID and port fields. Explicit bind port
zero requests an ephemeral port beginning at 49152; `u32::MAX` is invalid.
Connect target ports zero and `u32::MAX` are invalid. An accepted peer's wire
source port is preserved even when it is zero or `u32::MAX`.
Ephemeral search wraps and excludes live or closing local ports.

The fixed bounds are:

| Resource | Bound |
| --- | --- |
| Virtqueue size | Power of two, at most 256; RX at least 2, TX at least 16, event at least 1. |
| Posted RX pages | `min(64, rx_queue_size / 2)`. |
| TX data pages | `min(64, (tx_queue_size - 8) / 2)`; eight TX descriptors remain available for controls even with all data pages in flight. |
| Posted event buffers | `min(4, event_queue_size)`. |
| Pending wire-control records | 64 globally, including stateless refusals. |
| Streams | 64 globally, including connecting, unaccepted, and closing streams. |
| Listeners | 32 globally. |
| Unaccepted children | Eight per listener, also charged to the global stream cap. |
| Waiting accept RPCs | Eight per listener, separately from unaccepted children. |
| Outstanding shutdown RPCs | Eight per stream, including replies waiting for client IPC space. |
| Buffered receive payload | 128 KiB per stream. |
| Pending stream TX | 16 IPC pages per stream in sys-io. |
| IPC subchannel pages | 16 per direction; four socket reservations per native NET channel. |

These are separate bounds, not a total-memory estimate: the 64 stream receive
buffers alone can hold 8 MiB. Device pools allocate on activation; socket
storage allocates fallibly on demand before admission/publication.

The accepted-child and pending-accept bounds are independent. A pending
accept may reserve a slot from another channel owned by the same process;
foreign or stale handles are `NotFound`.

Pending accepts and shutdowns do not retain NET dispatch tickets while they
wait for peer progress. Canceling a sent shutdown does not retract it: its
slot is released when the reply is published or discarded. A shutdown
rejected at the limit does not apply a new shutdown direction in sys-io.
This is not a guarantee that the native stream remains usable: `shutdown_async`
commits local closure when it queues the request, before sys-io checks the
limit. On overflow, the requested direction may already be closed locally and
buffered RX may have been discarded. Do not rely on continuing to use that
stream after shutdown admission overflow; drop it and keep driving the channel
for normal cleanup. The limit bounds server work, not client-side rollback.

## Implementation contracts

### Components and activation

| Component | Responsibility |
| --- | --- |
| [virtio-async/virtio_vsock.rs](../src/sys/lib/virtio-async/src/virtio_vsock.rs) | Device initialization, bounded DMA pools, ordered packet/event reception, and TX submission. |
| [sys-io/runtime/vsock/](../src/sys/sys-io/src/runtime/vsock/) | `Connection` owns protocol phase, RX storage/credit, and shutdown flags; helpers manage buffers, tuple admission, and listener backlog. |
| [sys-io/runtime/net/vsock.rs](../src/sys/sys-io/src/runtime/net/vsock.rs) | Protocol pumps, native IPC, client ownership, pending accepts/shutdowns, and cleanup. |
| [moto-sys-io/api_vsock.rs](../src/sys/lib/moto-sys-io/src/api_vsock.rs) | Native control-message layouts and checked codecs. |
| [moto-io/net/vsock.rs](../src/sys/lib/moto-io/src/net/vsock.rs) | Native streams/listeners, application waits, and client IPC resources within moto-io's `no_std` boundary. |

Vsock reuses the NET endpoint, channel budget, socket IDs, reservations,
shared pages, and cancellation. Its protocol is independent of Ethernet, IP,
DNS, DHCP, and the TCP netstack. With an attached vsock device, NET service
works without a NIC or IP configuration and starts no IP/DNS tasks. With
neither a usable IP device nor vsock, NET service remains unavailable.
The vsock singleton does not restrict support for multiple NICs; sys-io's
single-block-device restriction is separate.

The runtime retains the first discovered vsock device and logs/ignores any
additional devices without initializing them. Its states are absent, dormant,
ready, and permanently failed. Authorization precedes activation; trusted peer
capabilities are queried once when sys-io admits the connection, and a failed
query drops it.
Availability validates zero handle, flags, and payload after authorization
and before presence. It succeeds for dormant/ready, without reading the CID.
First activation is synchronous on the existing `LocalRuntime`, with no host
wait, rescan, retry, or initialization waiter list. An attached unused device
allocates no queues, DMA buffers, or protocol pumps. Host-to-guest service
requires an authorized guest to activate the device and bind a listener.

Native codecs check command-specific layouts and reserved-zero fields.
Raw TCP/UDP/vsock subchannel indices must be 0–3 and are validated before
mask construction or resource admission in both debug and release. Socket
authority comes from the trusted IPC peer and common socket map, never from
client-supplied identities.

### Transport and DMA ownership

The implemented profile uses modern PCI device type 19 (`0x1053`), split
queues and MSI-X: RX queue 0, TX queue 1, event queue 2. It requires
`VERSION_1`, optionally negotiates `EVENT_IDX`, and negotiates no
device-specific bits or `IN_ORDER`. `VERSION_1` indicates modern transport,
not a distinction between Virtio 1.1 and 1.2. The wire reference is
[Virtio 1.1, sections 4.1 and 5.10](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html).

The little-endian packet header is 44 bytes. Stream type is 1; operations
are REQUEST=1, RESPONSE=2, RST=3, SHUTDOWN=4, RW=5, CREDIT_UPDATE=6, and
CREDIT_REQUEST=7. Shutdown flags are RECEIVE=1 and SEND=2. Transport reset
is a four-byte event with ID 0. Checked decoding validates lengths, CIDs,
types, operations, flags, and control payloads, retaining complete raw headers
for unsupported-type refusal handling. The configured CID is a little-endian
`u64` with a zero upper word and a valid guest value of 3 through
`u32::MAX - 1`. The split config read serves this single meaningful 32-bit
field; it is not a general coherent-snapshot mechanism.

Queue scratch slots are 64 bytes for vsock and 16 for block/net. Three
256-entry vsock queues therefore use 48 KiB of scratch on activation.
Header size/alignment checks remain active in release. Payload pages retain
the shared DMA alignment/ownership rules; queue/IRQ allocation uses the
existing bounded mapper without expanding kernel vectors or sharing IRQs.

Initialization writes device status zero and checks it once before
acknowledgment/queue setup; a nonzero result fails synchronously. All fallible
pool allocation and queue-task setup precede DMA publication. The driver
installs the event/RX owners, sets `DRIVER_OK`, then sends deferred queue
notifications. The device/BAR owner outlives queue and buffer owners.

RX consumption follows device used-ring order, not posting or future-polling
order: vsock has no sequence numbers to repair reordered payload. Each RX
or event pool claims one ordered cursor before publication; it observes heads
already processed by the shared reclaimer and resolves them to retained
completions. Wrapping device/reclaimer lag is checked against queue capacity;
exactly one ring of lag is valid. Empty polls register a reclaimer wakeup.
The cursor never reclaims a chain again or rereads a reused slot, and its
single-owner claim cannot be reopened after Drop.
Each completed packet is synchronously validated/copied into stream storage
before another head is consumed, the page is reposted, or the task awaits.
While active, malformed packets still release/repost their buffers.
Applications never own device RX pages. The shared queue does not implement
`IN_ORDER` semantics, and the pinned QEMU backend does not offer that feature.

The event pool retains up to four completions using the same ordered-head
mechanism. Its records occupy queue scratch, not separate payload pages.
Malformed/unknown events are consumed and reposted while active. The
synchronous event consumer runs before the repost decision: transport reset
stops reposting immediately, then sys-io propagates failure after the event
owner's borrow is released.

Permanent failure is idempotent. It stops new submissions/reposting, discards
logical RX/TX and controls, and wakes/fails listeners, streams, and pending
operations with `InternalError`; TCP/UDP on shared channels remain healthy.
The retained driver and RX/event/TX reclaim pumps reap returned completions
without applying protocol effects. Unreturned DMA buffers, queues, and the
device stay owned for sys-io's lifetime if necessary. Stopping reposting or
reading status zero does not authorize freeing outstanding DMA. Failure
neither fabricates completions nor resets/reinitializes PCI, refreshes the
CID, or rebinds listeners.

Additional defenses against malformed VMM PCI metadata are outside this
implemented profile; the separate [PCI BAR-boundary hardening note](plans/future-work.md#deferred-pci-bar-boundary-hardening-2026-09-15)
records that scope limit. Existing validation and protocol checks still apply.

### Credits, scheduling, and connection ownership

Receive `fwd_cnt` advances when sys-io copies bytes into an already reserved
IPC page, not when the application reads or releases that page. Client-held
pages have their own bounds. Checked wrapping counters atomically reject peer
forwarding beyond outstanding sent payload without changing either peer
credit field. Shrinking peer allocation below outstanding bytes yields zero
send allowance. A tuple-matched operation invalid for the connection state,
or RX exceeding advertised allowance, resets only that connection without
accepting the invalid packet's credit/payload or losing earlier validated RX.
Incoming RST is never answered with RST.

One TX pump checks credit and descriptor capacity, publishes, and charges
payload bytes without yielding between those steps. Headers consume no byte
credit. DMA completion returns ownership, not peer credit, and cancellation
does not roll back published bytes. TX submission determines wire order.
The bounded global control queue provides shared admission, coalescing, and
ordering for stream controls and stateless refusals. RX waits for control
space before consuming a packet that may require a response. Controls have
descriptor capacity independent of data saturation; per-stream work is
selected round-robin, and pumps yield after a quantum of 32. REQUEST/RESPONSE
precede data, accepted TX precedes local SEND, and reset supersedes obsolete
control work. Tuple ownership lasts through required terminal publication;
orderly close finishes with the protocol reset exchange.
The pumps wait on concrete notifications; there are no adaptive quotas or
periodic vsock polling timers.

Pending accepts are FIFO and release their NET dispatch tickets immediately.
Matched replies retain their stream slot through IPC backpressure. Cross-channel
handoff rechecks the listener, destination channel, and device while waiting
for reply space. The reply is published before RX/state messages, then
ownership and routing are installed without an intervening await. A missing
destination follows cleanup. Disconnect removes the owner's vsock listeners
before any unrelated teardown can yield. A dead client's terminal stream is
removed from maps/tuple accounting independently of notification success,
without releasing outstanding device DMA.

## Tested launch configuration

The hermetic entrypoint is:

```sh
src/tests/test-vsock.sh [--release] [--vmm qemu|chv|fc]
```

It runs `src/tests/test-vsock-outgoing.sh` with the local
`src/tests/vsock-peer.rs` UDS peer, followed by IP-disabled discovery. The
default topology is four vCPUs, 1 GiB RAM, guest CID 3, host CID 2, and local
host port 70000. QEMU uses `vhost-user-vsock-pci`, shared guest memory, and the
pinned `vhost-device-vsock` 0.3.0 backend with queue size 256. Cloud Hypervisor and
Firecracker use their built-in UDS transports; Firecracker selects the raw
standard image and PCI mode. Tests use local Unix-domain peers, with no
host `AF_VSOCK` or `/dev/vhost-vsock` requirement. The QEMU harnesses install
the backend once when the host has none; any other missing prerequisite, or
a failed install, fails the test run.
See [tools.md](tools.md#vsock-test-prerequisites) for setup.

Only vsock QEMU launches opt into `MOTO_SHARED_MEM=1`, using
`memory-backend-memfd,share=on` and `-machine memory-backend=` while preserving
hugepage support and caller overrides. Ordinary runner defaults are unchanged.
Runner sources live in `src/vm_scripts/`; copies in `vm_images/` are generated.

| Image/phase | QEMU / Cloud Hypervisor | Firecracker |
| --- | --- | --- |
| Standard suite / vsock peer tests | `main.img` → `motor-os.qcow2`. | Opt-in `raw.img` → `motor-os.img`, with standard-image contents. |
| System console | Raw `motor-os-system-tty.img`. | Same. |
| Developer image | `dev.img` → `motor-os-dev.qcow2`. | Unsupported. |
| Non-selected VMM boot check | Main qcow2 image. | `base.img` → `motor-os-base.img`. |
| IP-disabled vsock discovery | Isolated raw `motor-os-vsock-test.img`, with and without the device. | Same. |

`raw.img` stays outside default build targets. Both peer and discovery phases
use the selected VMM, profile, and CPU/memory settings. Main-image full tests
also boot-check the other two VMMs, including SSH and liveness checks; these
are separate from vsock protocol coverage. Boot checks and dedicated vsock
VMs finish before the long-lived suite VM starts. All runners share the VM
exclusion lock and run sequentially to avoid overlapping tap/address ownership.
Incompatible selections fail before launch, without fallback or stale-image
reuse; Firecracker developer selection fails before building or launching.
Developer gates do not require Firecracker boot checks.

Run both profiles and all supported VMM selections explicitly when validating
the vsock phase, for example:

```sh
src/tests/test-vsock.sh --vmm qemu
src/tests/test-vsock.sh --release --vmm qemu
src/tests/test-vsock.sh --vmm chv
src/tests/test-vsock.sh --release --vmm chv
src/tests/test-vsock.sh --vmm fc
src/tests/test-vsock.sh --release --vmm fc
```

`src/tests/full-test.sh [--release] [--vmm qemu|chv|fc] [--cpus N] [--memory MIB]` includes this phase.
Core changes follow [AGENTS.md](../AGENTS.md): fresh builds and at least three
passing main-image full tests in each profile before committing. Non-Lorry
developer-image validation uses `src/tests/full-test-dev.sh --release` only.

### Coverage and test interpretation

All component/native tests run in guest `systest`, directly or transitively
through `full-test.sh`. Pure sys-io helpers are source-included by
`virtio-task-tests`; the local UDS peer supplies actions/data for live cases.

| Test source | Coverage |
| --- | --- |
| [Virtio queue fixtures](../src/sys/lib/virtio-async/src/virtio_queue/tests.rs) | Layout/DMA ownership, used-ring ordering, wraparound, wakeups, pool preparation/reuse, malformed packets/events, and failure retention. |
| [Protocol helper fixtures](../src/sys/tests/virtio-task-tests/src/lib.rs) | Credit boundaries, atomic RX rejection, state transitions, both half-close directions, terminal-cause/device-failure precedence, admission, and cleanup. |
| [Native codecs](../src/sys/tests/systest/src/vsock.rs) and [NET driver tests](../src/sys/tests/systest/src/net_driver.rs) | Independent wire-layout expectations, malformed IPC, capability/address checks, cancellation, driver lifetime, receive-ring backpressure, and TCP/UDP sharing. |
| [Live guest cases](../src/sys/tests/systest/src/vsock_outgoing.rs) and [UDS peer](../src/tests/vsock-peer.rs) | Transfers beyond the receive window, accepted-TX drain, shutdown ordering, accept handoff/backpressure, client death, coexistence, and exact global capacity/reuse. Shared framing and payload helpers live in [vsock-protocol.rs](../src/tests/vsock-protocol.rs). |

Lifecycle regressions cover idle-driver process death separately from unread
replies/pages, reply-backpressured cross-channel teardown, listener
invalidation before a yielding disconnect, and accept/shutdown saturation
without NET dispatch starvation. Capacity tests fill all 64 stream slots,
verify refusal of the next connection, clean up, and repeat to prove reuse;
peer EOF, port reuse, or coarse memory samples alone do not prove reclamation.
The teardown tests cover backpressure and the unsafe former cleanup ordering;
the exact former accept-assertion interleavings were source-confirmed, not
directly reproduced. Reset fixtures test terminal failure and DMA ownership,
not live migration or VMM reset injection.

UDS half-close is not an independent Virtio shutdown-direction injector.
The proxies can translate host EOF into BOTH flags and need not translate
guest SEND-only shutdown into Unix EOF. Directional wire semantics are
checked in connection-helper fixtures. Live cases use separate data and framed
synchronization streams, validate exact pre-shutdown bytes, await local
shutdown, then exchange barriers before opposite-direction transfer. Host
Unix close must drain RX to EOF and reject further writes; synchronization
uses explicit handshakes rather than guessed sleeps.

An absent host UDS port also differs by backend: the pinned QEMU backend
leaves connect silent, so its test expects exactly `TimedOut` after the
two-second deadline; CHV/FC expect exactly `NotConnected`. The harness selects
the expected result without VMM-specific production behavior. Neither error
is accepted interchangeably. The vsock suite requires no Internet traffic,
Linux reference guest, or backend/source modifications.

## Historical measurements (2026-09-16)

These are single functional-test observations on 2026-09-16, not acceptance
thresholds, percentiles, peak-throughput claims, or a controlled comparison
against the pre-vsock revision. The production revision was `bf4539d8`; the
measurement-only patch and source hashes were recorded under
`/tmp/vsock-stage15-gate.b3pd2N/`.

### Configuration and validation

Host: Intel Core i7-11800H, 16 logical CPUs. Each VM used four vCPUs and 1 GiB
RAM. Installed VMMs were QEMU 10.2.1, Cloud Hypervisor 52.0, and Firecracker
1.15.1. QEMU uses vhost-device-vsock 0.3.0, queue size 256, and shared memfd
RAM; the other VMMs use their built-in UDS proxies. Guest CID is 3, host CID
is 2, and the host service port is 70000. The measured implementation used
the fixed bounds: 64 streams, 32 listeners, eight children and eight pending
accepts per listener, and 128 KiB RX storage per stream.

At measurement time, both profiles passed image builds, component/native-network
tests, all twenty peer actions, discovery, formatting, source-hash checks, and
Clippy without new warnings. Every measurement below accompanies a functional
PASS; byte, credit, EOF, and cleanup assertions remained active. These
observations are separate from repeated full-suite validation.

### Boot, activation, and transfer observations

Boot is the guest's “most services up” timestamp before the discovery command.
The two columns within each boot cell are System-console/IP-disabled boots
with vsock absent and attached-but-unused. Image, VMM, profile, vCPUs, RAM,
and backing match within each pair; QEMU's disabled measurement also used
`MOTO_SHARED_MEM=1`. Single samples still include scheduling/startup noise
and do not establish an attributable overhead or regression.

The unchanged standard QEMU no-device topology, with its ordinary NIC and
default non-shared RAM, booted at 489 ms debug and 107 ms release. Do not
subtract these from the System/IP-disabled observations. The earlier release
baseline was 108 ms, also an observation rather than a controlled benchmark.

| VMM/profile | Boot absent / attached (ms) | First CID (ms) | Warm CID (µs) | Mean framed 1-byte RTT (µs) | Duplex payload (MiB/s) | Coexistence payload (MiB/s) |
| --- | --- | --- | --- | --- | --- | --- |
| QEMU debug | 501 / 516 | 10.257 | 538.1 | 285.8 | 64.6 | 33.3 |
| CHV debug | 317 / 313 | 7.844 | 1312.9 | 295.4 | 59.8 | 13.3 |
| FC debug | 259 / 273 | 8.018 | 536.2 | 376.9 | 67.0 | 39.1 |
| QEMU release | 121 / 132 | 6.186 | 33.9 | 110.9 | 207.0 | 82.5 |
| CHV release | 39 / 29 | 4.426 | 25.4 | 105.6 | 219.3 | 32.7 |
| FC release | 16 / 15 | 5.123 | 34.1 | 63.6 | 178.0 | 144.4 |

CID timing measures the native query round trip, including lazy activation
on its first use. The RTT is the mean of 128 sequential framed one-byte
request/echo exchanges on one already-connected stream. It excludes connect
and final EOF but includes native framing, copies, and scheduling.

Duplex times 3 MiB aggregate application payload across concurrent send/read
work. Coexistence times 1 MiB aggregate payload while filesystem and TCP/UDP
work overlaps, including synchronization and worker completion. Both exclude
framing bytes from the numerator. Their volumes, barriers, and workloads
differ: do not divide these rates to claim a controlled slowdown or peak
throughput. Exact byte patterns, work completion, and EOF are checked.

### Memory observations

All values below are whole-process sys-io page usage, not attributed vsock
allocator residency. Activation is sampled after availability and after the
first/warm CID queries. Capacity includes one control stream, 63 newly admitted
streams, eight listeners and their channels. Thus the quotient per 63 streams
also contains listener/channel cost and allocator growth. Cleanup may retain
allocator capacity; its nonzero delta is not a count of unreclaimed streams.

These recorded cleanup values follow one full-capacity cycle and its
child-EOF barrier. The later `87eebf7e` regression repeats that cycle to prove
immediate reuse before sampling cleanup; new cleanup values therefore have
different provenance from this table.

| VMM/profile | Before / after activation (KiB) | Activation delta (KiB) | Control / full / cleanup (KiB) | Full delta / 63 (KiB) |
| --- | --- | --- | --- | --- |
| QEMU debug | 39904 / 40520 | 616 | 50936 / 63388 / 51132 | 197.7 |
| CHV debug | 41884 / 42564 | 680 | 52980 / 65400 / 53144 | 197.1 |
| FC debug | 41384 / 42064 | 680 | 52848 / 65200 / 52944 | 196.1 |
| QEMU release | 25720 / 26336 | 616 | 34000 / 46448 / 34192 | 197.6 |
| CHV release | 27700 / 28380 | 680 | 36440 / 48888 / 36632 | 197.6 |
| FC release | 27200 / 27880 | 680 | 35940 / 48388 / 36132 | 197.6 |

These measurements do not justify changing the approved resource limits.
Exact fixed-pool sizes and ownership remain defined and tested in
virtio-async; these process-level deltas are an empirical footprint estimate.

### Idle CPU and waits

Each sample requests 100 ms; actual intervals were 100.221–100.948 ms.
Four kernel metric queries per snapshot are disclosed in the logs. CPU is
the delta in cumulative process TSC ticks divided by the actual elapsed TSC
interval, expressed below as a percentage of one core. The interval includes
observer queries. These early post-boot/query/activation windows can include
settling work, so they are not steady-state averages.

Each cell is **CPU % / wait-count delta / wake-count delta**:

| VMM/profile | Endpoint disabled | Attached unused | After availability | After activation |
| --- | --- | --- | --- | --- |
| QEMU debug | 0.0000 / 0 / 0 | 0.0000 / 0 / 0 | 0.1879 / 1 / 0 | 0.7258 / 4 / 0 |
| CHV debug | 2.9411 / 4 / 0 | 0.2031 / 1 / 0 | 0.4397 / 2 / 0 | 0.6873 / 1 / 0 |
| FC debug | 2.5776 / 4 / 0 | 2.4351 / 4 / 0 | 0.4635 / 3 / 0 | 0.1697 / 1 / 0 |
| QEMU release | 0.0000 / 0 / 0 | 0.0000 / 0 / 0 | 0.6940 / 7 / 0 | 0.0083 / 1 / 0 |
| CHV release | 0.0224 / 2 / 0 | 0.0136 / 2 / 0 | 0.0070 / 1 / 0 | 0.0077 / 1 / 0 |
| FC release | 0.0281 / 2 / 0 | 0.0124 / 2 / 0 | 0.0314 / 1 / 0 | 0.0121 / 1 / 0 |

The standard QEMU NIC-present/no-vsock sample was 16.8693% / 195 / 28 in
debug and 0.0527% / 4 / 0 in release. It includes ordinary IP/service activity
and is not a vsock idle baseline for the IP-disabled topology. The temporary
collector also ran a redundant discovery call labeled `nonstandard`; that
label is excluded from the standard-topology comparison.

No queues or device pumps are created until activation in the reviewed code.
The zero attached-unused QEMU sample is consistent with that design, but a
100 ms whole-process sample alone cannot prove the absence of all background
work on every VMM.

### Raw evidence

The parent directory recorded builds, Clippy, focused no-device logs, the
tested patch/hashes, and per-VMM results. Discovery directories recorded
`present-console.log` and `disabled-console.log`; peer directories recorded
the guest action logs and `console.log`. These `/tmp` paths are temporary,
not repository-managed artifacts. The original measurement notes are also
archived in Git at `05f24d91`.

| VMM/profile | Discovery directory | Peer directory |
| --- | --- | --- |
| QEMU debug | `/tmp/test-vsock.latSlN` | `/tmp/test-vsock.iilVoW` |
| CHV debug | `/tmp/test-vsock.oVpVmk` | `/tmp/test-vsock.reAaqN` |
| FC debug | `/tmp/test-vsock.98z28A` | `/tmp/test-vsock.ZiuKmV` |
| QEMU release | `/tmp/test-vsock.VVfCet` | `/tmp/test-vsock.xdbmd3` |
| CHV release | `/tmp/test-vsock.PuReb2` | `/tmp/test-vsock.7f07FW` |
| FC release | `/tmp/test-vsock.SCTlM7` | `/tmp/test-vsock.F7KvZB` |
