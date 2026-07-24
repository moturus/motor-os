# Refactoring `moto-io` and `rt.vdso` again

2026-07-23. This is a plan only. It does not propose an ABI change and it
does not imply that the current code should be changed in one large step.

## 1. Decisions and scope

Two boundary decisions are settled for this pass:

1. A network driver is allowed to depend on
   `moto_async::LocalRuntime`. It does not need to be portable to an
   arbitrary Rust executor.
2. `moto-io` does not own a process-wide channel pool or create OS threads.
   A host owns the pool and decides where each driver runs. For the POSIX
   compatibility path, that host is `rt.vdso`.

The intended definition of a "purely async" `moto-io` API is:

- no hidden OS-thread creation;
- no `block_on_sync`, `SyncWaiter::wait`, thread sleep, spin-until-thread-
  startup, or other caller-thread parking;
- no synchronous request/response operation that can wait for sys-io or
  channel backpressure;
- no POSIX `O_NONBLOCK` or `SO_*TIMEO` policy in native socket objects;
- immediate state inspection and `try_*` operations are still synchronous,
  because they never wait;
- the `NetDriver` itself may use LocalRuntime-only handle waits, yielding, and
  deferred wake folding.

This pass covers the `moto-io`/`rt.vdso` network boundary and the network
findings in `vdso-rewrite-review.md`: hidden threads, blocking control paths,
global-lock stalls, cancellation-retained wakers, periodic lost-wakeup
polling, and the mandatory vDSO-shaped readiness listener. It preserves the
connect/accept ownership fixes already made after that review.

The stdio `SysHandleFuture` leak, the TLB watchdog, and the soak-harness
cleanup findings are separate work. The general `SysHandleFuture`
cancellation issue only enters this plan if the new `NetDriver` needs to
cancel such a future during its own lifetime; the driver should preferably
reuse one persistent handle wait.

## 2. What is wrong with the current boundary

The useful state machines are in the right crate, but execution and
compatibility policy moved with them:

- `moto-io/src/net/channel.rs` owns the process-global `NET` pool,
  synchronously connects to sys-io, retries with thread sleeps, creates a
  `LocalRuntime` OS thread with `SysCpu::spawn`, and spins until it starts.
- The same file exposes the vDSO TLS-cleanup workaround
  `set_thread_exit_hook`.
- Queue pressure can enter `send_msg`, `wait_can_send`, and
  `send_msg_guaranteed`, which park a caller thread. `send_receive` calls
  `block_on_sync` inside `moto-io`.
- TCP listener bind, UDP bind, socket-option RPCs, shutdown, and parts of
  connect/accept setup use those synchronous channel operations. An
  `async fn` such as `TcpStream::connect` can therefore block its polling
  thread before or during the await.
- Creating a channel happens while the global pool lock is held. A sys-io
  connection retry can stall every unrelated reservation, release, teardown,
  statistics call, and test hook.
- TCP and UDP objects store `nonblocking`, receive timeout, and send timeout
  fields solely for the vDSO blocking veneer. Their raw-pointer
  `setsockopt`/`getsockopt` dispatch is a POSIX ABI concern.
- Every socket constructor requires `Arc<dyn NetEventListener>`, and the vDSO
  later downcasts that trait object back to `EventSourceManaged`. This makes
  a vDSO adapter mandatory in the native API.
- Read/write/readiness waits retain cloned wakers in vectors. Deduplicating
  with `will_wake` prevents repeated registration by one stable bridge waker,
  but dropping native futures with distinct wakers still retains executor
  state until a later socket event.
- `rt.vdso/src/net/blocking.rs` compensates for unresolved wake races with
  500 ms and five-second recheck timers.

The result is async in naming and on much of the data path, but it is not an
async library boundary.

## 3. Target architecture

```
native LocalRuntime host                 rt.vdso POSIX host
------------------------                 ------------------
creates a LocalRuntime                   owns process NetPool
connects one NetClient                   creates one OS thread/channel
spawns/awaits NetDriver                  runs NetDriver on LocalRuntime
chooses its own pooling                  owns TLS/thread teardown
          \                                  /
           \                                /
            +------------------------------+
            |          moto-io             |
            | NetClient: one sys-io channel|
            | NetDriver: rx/tx progress    |
            | Reservation: one channel slot|
            | TCP/UDP async state machines |
            +------------------------------+
                              |
                              v
                           sys-io
```

### Ownership table

| Concern | Owner after the refactor |
|---|---|
| One `io_channel::ClientConnection` and its routing state | `moto-io::net::NetClient` |
| RX/TX progress and LocalRuntime-only driver state | `moto-io::net::NetDriver` |
| Per-channel capacity/subchannel reservations | `moto-io::net::Reservation` |
| Process-wide selection among channels | `rt.vdso::net::NetPool` |
| OS-thread creation, stack size, name, and exit | `rt.vdso` |
| vDSO TLS destructor and `SysObj::put(SELF)` | `rt.vdso` thread entry |
| TCP/UDP protocol and data-path state | `moto-io` |
| Blocking, deadlines, spins/yields, and `O_NONBLOCK` | `rt.vdso` wrappers |
| Raw `setsockopt`/`getsockopt` ABI parsing | `rt.vdso` |
| Typed network option RPCs | async methods in `moto-io` |
| Poll registry and mio compatibility synthesis | `rt.vdso` |
| Native read/write/readiness futures | `moto-io` |

The tuned data-path invariants remain specifications:

- one LocalRuntime thread per sys-io network channel in the vDSO host;
- at most `IO_SUBCHANNELS` reservations per channel;
- caller/poller-thread data copies;
- fixed staging queue and late-bound TCP pending-TX markers;
- multi-page TCP TX and single-page RX;
- inline RX dispatch;
- bounded message batches;
- direct sys-io wake at the measured batch boundary plus LocalRuntime
  wake-on-sleep folding;
- no steady-state scheduling hop between RX dispatch and a vDSO poll event.

## 4. Proposed `moto-io` surface

The exact Rust spelling can be adjusted during implementation, but the
ownership should resemble:

```rust
// Must be called and driven within a moto_async::LocalRuntime.
pub async fn connect() -> Result<(NetClient, NetDriver)>;

// NetClient is Send + Sync. NetDriver is a LocalRuntime resident and may be
// deliberately !Send.
impl NetClient {
    pub fn try_reserve(&self) -> Result<Reservation, AtCapacity>;
    pub fn capacity(&self) -> usize;
    pub fn reservations(&self) -> usize; // primarily diagnostics
    pub fn request_shutdown(&self);
}

impl Future for NetDriver {
    type Output = Result<(), DriverError>;
}
```

`NetClient` represents exactly one channel, not a global or process-wide
runtime. A new client may sit briefly at zero reservations while its host
publishes it. After its first reservation, the transition from one
reservation to zero closes it to new reservations and asks the driver to
drain and exit. `try_reserve` and the last-release transition need one atomic
state protocol so a reserve cannot race a channel from idle into teardown.

Socket creation consumes an explicit reservation selected by the host:

```rust
TcpListener::bind(reservation, addr).await
UdpSocket::bind(reservation, addr).await
UdpSocket::bind_for_remote(reservation, addr).await
TcpStream::connect(reservation, addr, connect_deadline).await
listener.accept(reservation).await
```

Supplying the accepted stream's reservation explicitly preserves the current
rule that a long-lived listener does not force all accepted sockets onto its
own channel. It also removes the last reason for a socket state machine to
reach into a global channel pool.

The primary data API should read naturally:

```rust
stream.read(bufs).await
stream.write(bufs).await
stream.readable().await
stream.writable().await

socket.recv_from(buf).await
socket.send_to(buf, addr).await
socket.readable().await
socket.writable().await
```

The existing `try_read`, `try_write`, `try_recv_from`, and `try_send_to`
forms remain. They are nonblocking primitives, not a blocking API. A
nonblocking connect-start operation may also remain for the POSIX
`O_NONBLOCK` adapter, provided it only attempts an immediate queue insertion
and reports `E_NOT_READY` rather than parking.

Remote socket options become safe, typed async methods, for example:

```rust
stream.set_nodelay(bool).await
stream.nodelay().await
stream.set_ttl(u32).await
stream.ttl().await
stream.shutdown(Shutdown).await
stream.set_linger(Option<Duration>).await
stream.linger().await
listener.set_ttl(u32).await
listener.ttl().await
```

There should be no raw pointer, POSIX option number, timeout field, or
`O_NONBLOCK` flag in these APIs. Purely local operations such as UDP peer
filter selection and address/state queries can remain immediate methods.

## 5. `NetClient` and `NetDriver` internals

### 5.1 Construction

Replace `connect_to_sys_io` and `NetChannel::new` with an async connection
constructor. Each individual `ClientConnection::connect` attempt is an
immediate syscall path; transient `NotFound` retry delays use
`moto_async::sleep` on the LocalRuntime. Exhaustion or a permanent error is
returned to the host instead of panicking.

Construction must not:

- hold a process-global lock;
- call `SysCpu::spawn`;
- sleep a caller thread;
- spin on a thread-start field;
- install a host lifecycle callback.

### 5.2 Driver state

Move LocalRuntime-local objects out of shared `NetChannel` state and into
`NetDriver`. In particular, the leaked `LocalNotify`, raw pointer publication,
`io_thread_wake_handle`, `io_thread_join_handle`, `on_io_thread`, and unsafe
`&'static NetChannel` fabrication should disappear.

The driver owns and concurrently polls the RX and TX loops. It may use
`LocalRuntime::spawn`, `yield_now`, `SysHandleFuture`, and
`set_wake_on_sleep`; those are explicit parts of its runtime contract. Socket
futures remain executor-neutral in the narrower sense that a caller thread
may poll them through `block_on_sync`; only the channel progress driver
requires LocalRuntime.

Use one persistent sys-io handle wait where practical. Teardown should wake
the driver's own registered waker or control notification rather than
repeatedly creating and cancelling handle futures.

### 5.3 Async send and RPC paths

Replace the current three-way send family with:

- `try_send(msg)`: immediate fixed-queue push for data-path and
  `O_NONBLOCK` use;
- `send(msg).await`: waits asynchronously for staging-queue room;
- `rpc(req).await`: registers before queueing, awaits async send room, then
  awaits the response;
- a nonblocking, guaranteed driver-control queue for close/rollback records.

`moto-io` must no longer contain `send_msg` backed by `SyncWaiter`,
`send_receive` backed by `block_on_sync`, or a
`send_msg_guaranteed` branch that blocks non-driver threads.

Destructors cannot await. A stream/listener/socket drop therefore transfers a
teardown record to a driver-owned control queue and wakes the driver. That
record owns everything needed to preserve ordering, including unsent TCP
pages that must precede `TcpStreamClose`. The driver drains control records
before it declares teardown complete. The number of live reservations bounds
normal close traffic, so this queue is not a second unbounded data path.

### 5.4 Cancellation-aware waiting

Introduce one internal wait-registration abstraction instead of storing bare
`Waker` clones in vectors. A registration has an identity; polling updates
its waker, readiness removes or completes it, and `Drop` physically removes
it.

Use it for:

- TCP RX/data-or-close waits;
- TCP TX page/send-room waits;
- UDP RX and TX waits;
- `readable()`/`writable()` futures;
- channel staging-queue room.

Every poll follows check/register/recheck. Dropping many distinct futures on
a quiet socket must leave waiter counts at zero without requiring a later
packet or socket drop. Once that invariant is true, the vDSO can remove the
500 ms and five-second correctness rechecks.

### 5.5 RPC and resource ownership

Keep the insert-before-send request ordering, but make cancellation an
explicit RPC state rather than an assumption that a receiver remains alive.

For each request kind, document ownership at these points:

1. before the request enters the send queue;
2. queued but not sent to sys-io;
3. sent, response outstanding;
4. response received but not delivered to the awaiting future;
5. delivered resource accepted by the caller;
6. future or socket dropped at each earlier point.

Connect and accept responses can create server-side handles after their
future has been cancelled. Response dispatch must install routing state
before exposing a successful resource, and a cancelled or undeliverable
success must enqueue a close. A pending accepted stream should own its
rollback through RAII until `TcpStream` construction commits it. Early stream
messages must have a channel-owned pending route, so they cannot be lost
while the accept future is waiting to run.

Ordinary option RPC cancellation may remove its delivery waiter, but response
dispatch must tolerate the absent receiver. It must not panic because an
async caller legitimately dropped a future.

### 5.6 Driver shutdown

The last reservation requests shutdown but does not make the driver exit
immediately. The driver completes only after:

- queued data/control messages that own resources are sent or explicitly
  rolled back;
- close records are delivered;
- successful late connect/accept responses are either handed off or closed;
- retained RX pages are reclaimed;
- all RPC-map and socket-routing entries have reached a terminal state.

Only then may `ClientConnection` drop. `NetDriver::Output` reports unexpected
transport/protocol failure to the host; expected service unavailability and
startup failure are ordinary errors, not panics.

## 6. The `rt.vdso` host

### 6.1 `NetPool`

Add a vDSO-owned pool, likely in `rt.vdso/src/net/runtime.rs`. It stores
`NetClient`s and chooses one by calling `try_reserve`. It does not duplicate
the per-channel subchannel bitmap.

`reserve().await` follows this sequence:

1. Under the short pool lock, scan existing open clients and try to reserve
   one.
2. If none has room, register the caller as a cancellation-aware pool waiter.
3. Ensure enough channel provisioning is in flight for unsatisfied demand,
   but do not hold the pool lock while creating a channel.
4. Start a vDSO channel thread. Its LocalRuntime performs async
   `moto_io::net::connect`.
5. Publish a successful client back under the pool lock and satisfy up to
   `IO_SUBCHANNELS` waiting reservations before creating another channel.
6. Propagate startup failure to waiters. Do not panic or leave the pool in a
   permanent "creating" state.

This avoids both the current ten-second global-lock stall and a thundering
herd that would create one channel per concurrent socket rather than roughly
one per four reservations.

Synchronous POSIX entry points call `block_on_sync(NetPool::reserve())`.
That bridge future only waits for a pool/client result; sys-io retry timers
run on the new channel's LocalRuntime thread, not on the caller-thread bridge.

### 6.2 Channel thread

The vDSO thread entry owns:

- `SysCpu::spawn`, stack size, and thread name;
- construction of `LocalRuntime`;
- awaiting `moto_io::net::connect`;
- publishing the `NetClient`;
- driving `NetDriver` to completion;
- removing the completed client from `NetPool`;
- logging/reporting driver failure;
- `rt_tls::on_thread_exiting`;
- `SysObj::put(SELF)`.

This deletes `moto_io::net::channel::set_thread_exit_hook` and its
initialization from `rt.vdso/src/main.rs`. A native application that runs a
driver on an existing LocalRuntime needs none of this vDSO lifecycle code.

### 6.3 Concrete POSIX wrappers

Stop implementing `PosixFile` directly for `moto_io` socket types. Introduce
vDSO-local wrappers:

```rust
struct RtTcpListener {
    inner: Arc<moto_io::net::TcpListener>,
    events: Arc<EventSourceManaged>,
    nonblocking: AtomicBool,
    // vDSO accept-pump/backlog state
}

struct RtTcpStream {
    inner: Arc<moto_io::net::TcpStream>,
    events: Arc<EventSourceManaged>,
    nonblocking: AtomicBool,
    read_timeout_ns: AtomicU64,
    write_timeout_ns: AtomicU64,
}

struct RtUdpSocket {
    inner: Arc<moto_io::net::UdpSocket>,
    events: Arc<EventSourceManaged>,
    nonblocking: AtomicBool,
    read_timeout_ns: AtomicU64,
    write_timeout_ns: AtomicU64,
}
```

The FD table stores these wrappers, and ABI downcasts target them. This puts
POSIX state at the correct layer and removes the current trait-object
downcast from `NetEventListener` back to `EventSourceManaged`. Because the
wrapper is the shared `Arc<dyn PosixFile>`, its flags continue to follow the
existing duplicated-FD/open-file-description behavior.

`rt.vdso/src/net/blocking.rs` takes the wrapper, reads its compatibility
flags/deadlines, and polls the inner native future. It is the only networking
layer allowed to spin, yield, or call `block_on_sync[_deadline]`.

Raw pointer and option-number validation stays in `rt_net.rs`. A remote
option invokes the corresponding typed async `moto-io` method through
`block_on_sync`; local options update the wrapper. Preserve current error
codes and the existing shutdown and partial-write-on-timeout rules.

### 6.4 Readiness adapter

Native sockets must not require a vDSO event object at construction. Their
own futures and state queries are the primary interface.

Retain an optional, mio-agnostic readiness observer as an adapter for hosts
that need push delivery. It should:

- be absent by default;
- be attachable without changing socket semantics;
- have no `as_any` downcast;
- use only `Readiness` bits, never poll ABI constants;
- run inline at the current state-transition points.

The `Rt*` wrapper owns both the observer implementation and the concrete
`EventSourceManaged`, so it never needs to recover one from the other.
`maybe_raise_events` remains vDSO code and synthesizes the current level when
poll interests are registered. That synthesis also covers data or state that
arrived before an accepted socket had its vDSO wrapper attached.

### 6.5 Listener accept pump

Removing the global pool from `moto-io` means an accepted stream's channel
reservation must be supplied by the host. The vDSO listener therefore owns a
small accept-pump task:

1. obtain a reservation from `NetPool`;
2. post one native accept using that reservation;
3. await its completion;
4. repeat while the vDSO backlog has room;
5. pause when the backlog is full and resume when an accept caller removes
   an entry.

The native listener still owns the pending-accept state and queues the
accepted stream during inline response dispatch. It raises its optional
readiness observer there, before the pump task is rescheduled. Thus the pump
supplies execution policy and channel capacity without inserting a
source-to-poller scheduling hop.

Dropping the vDSO listener stops the pump and drops any in-flight accept
future. The native cancellation protocol then closes a successful late
accept. `listen`, backlog behavior, listener-WRITABLE compatibility, and
inheritance of the listener's nonblocking flag by an accepted vDSO stream
must remain as today.

### 6.6 Removing periodic polling

After cancellation-aware waiter registrations and register/recheck tests are
in place, simplify `blocking.rs`:

- no-deadline waits use `block_on_sync`;
- deadline waits use one `block_on_sync_deadline` with the actual
  `SO_RCVTIMEO`/`SO_SNDTIMEO` deadline;
- timed-out TCP writes still inspect and return committed progress;
- no 500 ms TX or five-second RX recheck constants.

Periodic checking may be kept temporarily as a migration diagnostic, but it
must not remain part of the final correctness protocol.

## 7. Staged implementation plan

Each stage should be reviewable and leave a runnable tree. Behavioral changes
land with their regression tests. The large ownership flip may require one
explicitly flagged mechanical commit, but preparation should keep that commit
small in logic.

### Stage 0: refresh gates

- Record the exact starting commit and dirty-tree exclusions.
- Run the targeted native cancellation/backpressure tests, systest network
  suite, mio-test, tokio-tests, and one debug `full-test.sh`.
- Record a same-host release rnetbench sample using the methodology in
  `vdso-rewrite-baselines.md`. Do not compare a later stage only against the
  cross-day 2026-07 numbers.
- Add no production behavior in this stage.

### Stage 1: cancellation-aware wait registrations

- Add the internal wait-registration/token primitive.
- Convert TCP read/readiness, channel/TCP write, and UDP waiters one family at
  a time.
- Add quiet-socket cancellation storms using distinct wakers and assert that
  registration counts return to zero immediately.
- Keep the existing vDSO periodic rechecks until this stage's lost-wakeup
  stress tests pass.

Gate: targeted systest + mio-test + tokio-tests. There should be no data-path
behavior or performance change.

### Stage 2: async channel control plane

- Add async queue-room and RPC futures beside the old blocking helpers.
- Convert bind and typed socket-option internals to those futures.
- Make response dispatch tolerate cancelled ordinary RPC receivers.
- Add the nonblocking driver-control/teardown queue.
- Convert stream, listener, UDP, orphan, and cancelled-connect/accept cleanup
  to teardown records; prove drop never parks under full staging/ring queues.
- Delete the old blocking helpers once all internal callers have moved.

Gate: explicit executor-liveness tests under saturated queues, existing
connect/accept cancellation tests, listener-drop backpressure test, and the
network suites.

### Stage 3: introduce vDSO `Rt*` wrappers

- Add `RtTcpListener`, `RtTcpStream`, and `RtUdpSocket`.
- Move nonblocking flags, read/write timeouts, raw option dispatch, concrete
  event sources, and `PosixFile` implementations into them.
- Change all ABI downcasts and FD insertion sites atomically.
- Replace mandatory constructor listeners with the optional readiness
  observer and remove `as_any`.
- Convert remote options/shutdown to typed async native calls bridged only in
  vDSO.

Gate: focused duplicated-FD, socket-option, shutdown, timeout, poll
registration, and nonblocking tests; then mio-test and tokio-tests.

### Stage 4: prepare the driver/ownership split additively

- Change one channel's internals into a `NetClient`/`NetDriver` pair while a
  temporary compatibility host continues to back the existing global vDSO
  path. This temporary host is deleted in Stage 5; it prevents an unbuildable
  half-migration.
- Move LocalRuntime-local notification state into `NetDriver`.
- Make sys-io connection retry async and fallible.
- Add explicit-reservation variants of bind, connect, and accept while the
  old entry points temporarily delegate through the compatibility pool.
- Add a native test that creates a LocalRuntime, drives `NetDriver`
  explicitly, performs TCP/UDP I/O, drops every reservation, and observes a
  clean driver result.
- Prepare the vDSO `NetPool`, channel-thread entry, and accept-pump types
  without switching production construction to them yet.

Gate: build, native driver tests, and the existing vDSO network suites. At
this intermediate point `moto-io` still contains the explicitly temporary
compatibility thread/pool adapter.

### Stage 5: flip ownership to `rt.vdso`

- Switch vDSO socket construction to `NetPool` and explicit reservations.
- Enable cancellation-aware reservation waiters and provisioning
  coalescing.
- Enable the vDSO channel thread entry and lifecycle cleanup.
- Change native accept to consume a host-supplied reservation.
- Add the vDSO accept pump and backlog notification.
- Preserve inline accepted-stream routing and readiness before resolving the
  pump's completion.
- Move netdev statistics/leak assertions to per-client diagnostics plus the
  vDSO pool.
- Delete the temporary `moto-io` host, global `NET`, `SysCpu::spawn`, thread
  handles, startup spin, leaked `LocalNotify`, unsafe static channel borrow,
  and thread-exit hook.
- Add concurrent cold-start tests proving that N simultaneous sockets create
  approximately `ceil(N / IO_SUBCHANNELS)` channel threads, not N threads.
- Add sys-io-unavailable startup tests proving other pool inspection and
  already-live channels remain usable while a new connection retries.
- Cover cancellation before response, after response delivery but before
  consumption, listener drop, backlog saturation, and early RX/state
  messages.

This is the one ownership flip that may exceed the normal step size. All
state-machine and wrapper preparation should already have landed, so its
logic is limited to selecting the new host and deleting the temporary one.

Gate: native accept cancellation, listener-drop backpressure, channel
churn/teardown, cold-start/provisioning tests, all listener mio tests,
repeated tokio loopback tests, all network suites, and debug
`full-test.sh`.

### Stage 6: remove the wake-race safety polling

- Delete `block_on_recheck`, `TX_PARK_RECHECK`, and `RX_PARK_RECHECK`.
- Drive action futures directly with the real vDSO deadlines.
- Run timeout storms concurrently with active TCP and UDP traffic and assert
  both progress and zero retained wait registrations.

Gate: network suites, at least five consecutive debug `full-test.sh` runs,
and release `full-test.sh`.

### Stage 7: cleanup and final gate

- Make `moto-io::net::channel` private or narrow its public exports to
  `NetClient`, `NetDriver`, `Reservation`, sockets, futures, typed options,
  readiness bits, and the optional observer.
- Remove `blocking-path` terminology, vDSO-specific comments, global test
  hooks, unused dependencies, and stale design references.
- Add a source-level guard that `moto-io` networking does not use
  `SysCpu::spawn`, `block_on_sync`, `SyncWaiter`, or thread sleep.
- Update `vdso-rewrite-design.md` after implementation so it no longer says
  `moto-io` owns channel runtime threads or a global channel registry.
- Record code-size and paired same-host release rnetbench results.

Final gate: full untrimmed systest, mio-test, tokio-tests, repeated debug
`full-test.sh`, release `full-test.sh`, channel leak assertions, and paired
rnetbench.

## 8. Required regression coverage

The implementation is not complete without tests for:

- no implicit thread creation by `moto-io`;
- driver startup failure returned as an error;
- concurrent vDSO pool cold start without global-lock stalls or channel
  over-creation;
- pool reuse until a channel is full and clean exit after its last
  reservation;
- async bind/options/connect remaining pending under queue pressure without
  blocking the polling LocalRuntime or caller thread;
- drops on caller, RX-driver, TX-driver, and accept-pump contexts with both
  staging and sys-io rings full;
- connect and accept cancellation at every ownership phase;
- cancellation storms on all data/readiness futures with immediate waiter
  deregistration;
- no lost wake after check/register/recheck races;
- partial TCP write returned on `SO_SNDTIMEO`;
- UDP datagram atomicity across timeout/cancellation;
- accepted-stream early data/state delivery;
- listener backlog, nonblocking inheritance, and mio listener-WRITABLE quirk;
- socket option parity, shutdown ordering, linger, local/peer addresses, and
  `SO_ERROR`;
- poll close tombstones and duplicate-FD registration semantics;
- no periodic idle wakeups on quiet sockets;
- channel teardown with outstanding RPC cancellation and pending close
  records.

## 9. Completion criteria

The refactor is done when all of the following are true:

1. Searching `moto-io/src/net` finds no thread spawn, blocking bridge,
   `SyncWaiter`, thread sleep, process-global channel pool, POSIX timeout/
   nonblocking state, raw socket-option pointer dispatch, or vDSO thread-exit
   hook.
2. A native test must explicitly drive a `NetDriver`; constructing or using a
   native client never creates an OS thread.
3. All potentially waiting native control and data operations are futures;
   all immediate `try_*` methods return rather than park.
4. Every wait registration and RPC-created resource has a tested
   cancellation cleanup path.
5. `rt.vdso` alone owns channel threads, process pooling, blocking policy,
   POSIX state, and poll compatibility.
6. The vDSO ABI and observable std/mio/tokio behavior remain unchanged.
7. The fixed data-path architecture remains intact, and paired same-host
   rnetbench stays within the existing rewrite kill criteria: no sustained
   throughput loss over 5% and no sustained RR regression over roughly
   5 microseconds after tuning.
