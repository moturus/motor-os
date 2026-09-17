# Native virtio-vsock API

Motor OS exposes virtio-vsock streams through `moto_io::net::vsock`. This is
a native Rust API. It does not provide libc, Rust `std::net`, mio, or Tokio
vsock sockets.

The process must have `CAP_VSOCK`, granted by an authorized parent. Device
failure is permanent; snapshots and reset recovery are unsupported. Component
fixtures cover terminal failure and ownership, not live VMM reset injection.

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

`availability(&client)` checks authorization and discovery without activating
the device or reserving a socket. `local_cid(&client)` activates lazily and
returns the device's fixed CID without a reservation. A listener retains its
port; `socket_addr_async()` queries sys-io so permanent device failure is
reported instead of returning stale metadata.

## Errors, cancellation, and Drop

Errors are native `moto_rt::Error`/`ErrorCode` values; there is no TCP errno
translation layer.

- Missing `CAP_VSOCK` is `NotAllowed`, checked before device presence.
  No discovered device is `NotFound`, and a syntactically valid non-host
  destination is `NotImplemented`.
- Invalid CIDs, ports, flags, and request shapes are `InvalidArgument`.
  A refused connection is `NotConnected`; a silent connect reaches the fixed
  two-second deadline as `TimedOut`. Peer reset is `ConnectionReset`.
- Global stream/listener/pending-accept/shutdown admission returns `OutOfMemory`. A full
  client channel returns `ReserveError::AtCapacity`; a retiring
  channel returns `ReserveError::ShuttingDown`.
- A device reset permanently caches `InternalError` for vsock. Existing
  streams, listeners, and pending operations fail, buffered RX and queued TX
  are discarded, and later vsock operations return the cached error. There is
  no reset recovery or listener rebinding.
- Canceling an accept releases its client reservation. A sent cancellation
  can still occupy one bounded server accept slot until a peer arrives or the
  listener is removed; a late successful child is closed rather than exposed.
- Dropping a stream or listener is nonblocking. Continue driving its channel
  until `NetDriver::run()` returns so accepted TX and queued teardown drain.
  Dropping an active, undriven driver is unsupported.

An idle retained `NetClient` is weak: it does not keep a completed driver or
IPC mapping alive. After driver exit, RPCs return `NotConnected`, reservations
are zero, and new reservations are `ShuttingDown`. An operation already in
flight may retain inert channel ownership until it is polled to completion or
dropped; the idle client alone does not.

## Supported endpoints and limits

The implementation supports one modern virtio-vsock device and stream sockets
to the host endpoint (CID 2). Datagram, seqpacket, guest-to-guest routing,
wildcard/reuse binding, and privileged-port classes are not provided.

`VsockAddr` contains full-width `u32` CID and port fields. Explicit bind port
zero requests an ephemeral port beginning at 49152; `u32::MAX` is invalid.
Connect target ports zero and `u32::MAX` are invalid. An accepted peer's wire
source port is preserved even when it is zero or `u32::MAX`.

The fixed bounds are:

- four socket reservations per native NET channel;
- 64 streams globally, including connecting, unaccepted, and closing streams;
- 32 listeners globally;
- eight unaccepted children and, separately, eight waiting accept RPCs per
  listener;
- eight outstanding shutdown RPCs per stream, including replies waiting for
  client IPC space; and
- 128 KiB of buffered receive data per stream.

The accepted-child and pending-accept bounds are independent. A pending
accept may reserve a slot from another channel owned by the same process;
foreign or stale handles are `NotFound`.

Pending accepts and shutdowns do not retain NET dispatch tickets while they
wait for peer progress. Canceling a sent shutdown does not retract it: its
slot is released when the reply is published or discarded. A shutdown
rejected at the limit does not apply a new shutdown direction.

## Tested launch configuration

The hermetic entrypoint is:

```sh
src/tests/test-vsock.sh [--release] [--vmm qemu|chv|fc]
```

It runs `src/tests/test-vsock-outgoing.sh` with the local
`src/tests/vsock-peer.rs` UDS peer, followed by IP-disabled discovery. The
default topology is four vCPUs, 1 GiB RAM, guest CID 3, host CID 2, and local
host port 70000. QEMU uses shared guest memory and the pinned
`vhost-device-vsock` 0.3.0 backend with queue size 256. Cloud Hypervisor and
Firecracker use their built-in UDS transports; Firecracker selects the raw
standard image. See [tools.md](tools.md#vsock-test-prerequisites) for setup.

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

`src/tests/full-test.sh [--release] [--vmm qemu|chv|fc]` includes this phase.
See [the implementation plan](plans/vsock.md) for validation status and
[Stage 15 measurements](plans/vsock-measurements.md) for observed latency,
footprint, and transfer rates with their accounting limitations.
