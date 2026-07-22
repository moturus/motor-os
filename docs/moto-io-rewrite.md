# `moto-io` rewrite review

## Network channel runtime ownership

The move of the network stack from `rt.vdso` to `moto-io` was only partly
warranted:

- Moving the network channel logic and socket state machines into `moto-io`
  was appropriate.
- Making `moto-io` create and own the per-channel OS thread was not appropriate
  for the intended "native async client mirroring FS" architecture.

A network progress engine is necessary. It must continuously drain unsolicited
RX and state messages, dispatch them to sockets, drive queued TX, and publish
readiness. Unlike FS, network progress cannot always be tied to polling one
outstanding request future. This justifies a long-lived channel driver, but not
having the low-level async library choose and own the driver's thread.

Currently, `NetChannel::new()` synchronously connects to sys-io and directly
calls `SysCpu::spawn`. Channels hold at most four socket reservations, so a
native user implicitly acquires roughly one hidden thread per four live socket
reservations, even if the application already has an executor.

This differs materially from the FS layering. `moto_io::fs::FsClient` exposes
futures which poll the IPC receiver themselves, while the POSIX adapter in
`rt.vdso` decides to run the FS client on its background IO-runtime thread. In
the network implementation, execution policy has moved into `moto-io` along
with the state machine.

The thread-exit hook is a particularly clear layering smell. `moto-io` exposes
a global callback because its raw thread needs vDSO TLS cleanup, and the vDSO
installs that callback during initialization. A reusable async client should
not need a host-specific lifecycle callback merely because it unilaterally
created a host thread.

The resulting public interface is also not fully asynchronous.
`TcpStream::connect().await` performs channel reservation before its first
await. Reservation holds the process-global network lock while channel
construction may retry with sleeps for about ten seconds, spawn a thread, and
spin waiting for startup. Its `send_rpc` path can also park the polling thread
under channel backpressure. Therefore, the narrower claim that the data path
contains no `block_on` is true, but it is insufficient to characterize the
client as fully async.

### Recommended boundary

`moto-io` should retain the channel state, RX/TX tasks, routing, and socket
state machines, but expose channel progress as a driver future. Conceptually:

```rust
let (client, driver) = NetClient::connect().await?;
executor.spawn(driver);
```

The vDSO adapter can continue running each driver on exactly the current
dedicated `LocalRuntime` thread. That preserves thread-per-channel scaling,
inline RX dispatch and readiness delivery, caller-thread data copies,
warm-CPU and wake-folding behavior, and the absence of an extra scheduling
hop. A native client can instead spawn the driver on its chosen executor. Raw
thread setup and vDSO TLS teardown then remain vDSO policy.

The channel and socket state form a mutually recursive cluster: the channel
holds weak socket references for incoming dispatch, and sockets hold channel
reservations. That explains why their state moved together, but it does not
require the thread-spawning wrapper to move with them.

The current arrangement is defensible as an interim, behavior-preserving
relocation. It should not be considered the final async `moto-io` architecture.
