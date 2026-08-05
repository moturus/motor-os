# Refactoring `moto-io` and `rt.vdso` again

2026-07-23. This is a plan only. It does not propose an ABI change and it
does not imply that the current code should be changed in one large step.

Status update (2026-07-26): the Stage 0 same-host sample has been recorded at
`ab81c861`, and the default-RX gap against the older numbers has been
attributed (Section 10). A three-point A/B shows the pre-rewrite tree
measuring the same ~164 MiB/s on this host, so the gap is a rig change, not a
code regression, and the 2026-07-19/21 figures are retired as gates.

Review update (2026-07-26): the receive-coalescing work is sequenced between
Stages 2 and 3. A later cross-plan review rejected Stage 6's statistical
flake gate: the known debug failures must be fixed before that stage, after
which the ordinary AGENTS.md gate applies. See
`docs/plans/networking-step-by-step.md`.

This document is self-contained. Section 0 summarizes what is left, Sections 1
through 6 describe the target architecture, Section 7 records the work landed
and the remaining implementation order, and Section 10 holds the performance
gate and its reference numbers.

## 0. Remaining work

Stages 0 through 2 are complete. The DNS resolver restart failure that blocked
Stage 2's final gate was an IPC listener-ownership defect and is fixed with a
deterministic regression; the required three debug and three release full
suites passed. Stage 3 is in progress -- three of its four patches,
`RtUdpSocket`, `RtTcpStream` and `RtTcpListener`, are done as of 2026-08-04,
plus patch 3.1, the accept-starvation fix taken along the way. Stages 4
through 7 have not started.

| Stage | State | Items left | Est. patches | Risk |
|---|---|---|---|---|
| 2: async control plane | complete | 0 | 0 | complete |
| 3: `rt.vdso` wrappers | in progress | 3 of 4 patches | 1 | medium; wide but mechanical |
| 4: additive driver split | not started | 6 | 6-8 | high; new architecture |
| 5: ownership flip | not started | 11 | 5-8 | highest; flagged in Stage 5 |
| 6: remove polling | not started | 3 | 2 | low logic, flake-sensitive gate |
| 7: cleanup | not started | 5 | 2-3 | low |

**Roughly 23-33 patches remain** at the 100-300 loc size AGENTS.md calls for.

Three things make the raw patch count misleading:

- **The remaining stages are the expensive ones.** Stages 4 and 5 are more
  than half the work and carry nearly all the design risk. Their estimates are
  the softest, because the plan describes them at bullet granularity and their
  real shape will not be clear until Stage 3 lands. They should be re-scoped
  then rather than trusted now.
- **Gating is a material fraction of the cost.** AGENTS.md requires three
  debug and three release `full-test.sh` runs per patch; across 25-35 patches
  that is 150-200 full-test runs, and it will dominate wall-clock for the
  mechanical Stage 3 patches. A per-reviewed-group relaxation for that stage
  would cut this substantially and is worth asking for explicitly; it is not
  assumed here. The known Stage 6 debug flakes must be fixed before that stage;
  they cannot be handled with a statistical acceptance rule. Stage 5's gate
  lists nine suites.
- **Section 8 adds coverage beyond the stage bullets** -- seventeen regression
  areas, some of which land with their stages and some of which are extra.

Stages 3 and 6-7 are tractable and mostly mechanical. Stages 4-5 are the
actual project.

### Sequencing against the coalescing plan

Interleave, do not serialize. Stage 2 is complete. This section asked for
`docs/plans/virtio-rx-coalescing.md` Steps 0-2 before Stage 3; that work is now
held by decision (networking Step 8, 2026-08-02) and Stage 3 started without
it, for the reason recorded in Section 7. The three reasons below stand, and
now bear on Stages 4 and 5:

- The performance gate's default-RX axis is currently blind. Section 10's own
  finding is that default RX is packet-rate bound in the virtio driver, below
  every layer Stages 3-5 touch. A per-message RX regression introduced by the
  rewrite could hide behind that bottleneck and surface only when coalescing
  later removes it, misattributed to the coalescing change. Landing
  coalescing first makes the RX axis measure the code the risky stages churn.
- The coalescing work is small (~250 loc across its Steps 0-2) against this
  series' remaining 20-30 patches, and it touches no file this series
  touches.
- A new reference sample is needed after coalescing anyway, and Section 10's
  paired same-host methodology makes re-baselining routine.

If the coalescing experiment shows large frames do not reach the guest, that
plan is shelved after ~200 loc and this series continues with nothing lost.

`src/vm_scripts/run-qemu.sh` is already tracked and copied into each generated
image. Before further measurement, record the complete benchmark manifest
described by `docs/plans/networking-step-by-step.md`; the unexplained
525-to-164 rig drift shows that tracking the VM script alone is insufficient.

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
findings of the preceding review: hidden threads, blocking control paths,
global-lock stalls, cancellation-retained wakers, periodic lost-wakeup
polling, and the mandatory vDSO-shaped readiness listener. It preserves the
connect/accept ownership fixes already made after that review. Section 2
records the state of each finding.

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
  `send_msg_guaranteed`, which park a caller thread.
- Parts of connect/accept setup still use synchronous channel operations.
  Bind, the typed socket options, TCP shutdown, and TCP listener/stream
  destruction are async, but UDP destruction and some rollback/control paths
  still block.
- Creating a channel happens while the global pool lock is held. A sys-io
  connection retry can stall every unrelated reservation, release, teardown,
  statistics call, and test hook.
- TCP objects store `nonblocking`, receive timeout, and send timeout fields
  solely for the vDSO blocking veneer. Their raw-pointer
  `setsockopt`/`getsockopt` dispatch is a POSIX ABI concern. Fixed by Stage 3's
  first three patches: `RtUdpSocket`, `RtTcpStream` and `RtTcpListener` hold
  all of it, and `moto_io::net` holds none of it.
- Every socket constructor requires `Arc<dyn NetEventListener>`, and the vDSO
  later downcasts that trait object back to `EventSourceManaged`. This makes
  a vDSO adapter mandatory in the native API. Every downcast is gone after
  Stage 3's first three patches; the mandatory constructor argument remains
  for every type, and so does the now-callerless `as_any`.
- Read/write/readiness waits originally retained cloned wakers in vectors.
  Stage 1 replaced those vectors with cancellation-aware registrations.
- `rt.vdso/src/net/blocking.rs` still retains its 500 ms and five-second
  recheck timers pending the Stage 6 cleanup.

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

A remote option invokes the corresponding typed async `moto-io` method through
`block_on_sync`; local options update the wrapper. Preserve current error
codes and the existing shutdown and partial-write-on-timeout rules.

**Corrected as built (patches 1-3, 2026-08-04):** raw pointer and
option-number validation did not stay in `rt_net.rs`. It is per-type -- the
option set, the lengths and which arms are remote all differ by socket kind --
so each wrapper owns its own `setsockopt`/`getsockopt`, and `rt_net.rs` keeps
only the FD lookup and the downcast that picks the wrapper.

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

Current status: Stage 2 is complete and Stage 3 is in progress. The same-host
reference sample exists at `ab81c861`, and the default-RX gap against the older
numbers has been attributed to the rig, not to code, so the performance gate is
closed and later stages compare against `ab81c861`.

**The coalescing sequencing below did not hold, and Stage 3 started anyway.**
Section 0 asks for the virtio receive-coalescing plan's Steps 0-2 between Stage
2 and Stage 3, so that the performance gate's default-RX axis measures the code
Stages 3-5 churn rather than a virtio bottleneck beneath it. That work is
**held by decision** as networking Step 8 (2026-08-02): booting one image under
three VMMs showed Cloud Hypervisor does not offer `MRG_RXBUF`, and the only
scheme with universal reach costs RX ring depth on every VMM, so neither option
was taken. The reasoning that ordered coalescing first is unaffected -- the RX
axis is still blind -- so it applies to Stages 4 and 5, which are the risky
ones, and not to Stage 3, whose patches move state between structs and add no
per-message work to any data path. If coalescing later lands, a fresh same-host
sample replaces `ab81c861` as the comparison point.

| Stage | Status | Summary |
|---|---|---|
| 0: gates and baselines | Complete | Same-host sample recorded at `ab81c861`; the default-RX gap was A/B'd against the pre-rewrite tree and attributed to the rig, retiring the 2026-07-19/21 numbers as gates. |
| 1: cancellation-aware waiters | Complete | TCP and UDP read/write/readiness waiters use removable token registrations. |
| 2: async control plane | Complete | Async control and teardown paths are implemented; the IPC listener restart defect is fixed, and the final three debug plus three release full suites passed. |
| 3: `rt.vdso` wrappers | In progress | `RtUdpSocket`, `RtTcpStream` and `RtTcpListener` done 2026-08-04, plus patch 3.1's accept-starvation fix; the optional-observer patch remains. |
| 4: additive driver split | Not started | `NetDriver` has not yet been split out. |
| 5: ownership flip | Not started | Runtime-owned driver tasks are not yet the default. |
| 6: remove polling | Not started | Periodic vDSO rechecks remain. |
| 7: cleanup | Not started | Compatibility and blocking internals remain. |

### Stage 0: refresh gates - complete

- Record the exact starting commit and dirty-tree exclusions.
- Run the targeted native cancellation/backpressure tests, systest network
  suite, mio-test, tokio-tests, and one debug `full-test.sh`.
- Record a same-host release rnetbench sample using the methodology in
  Section 10. Do not compare a later stage only against cross-day numbers.
- Add no production behavior in this stage.

Functional gates were run repeatedly through the landed work. The same-host
sample was recorded at `ab81c861` on 2026-07-26 and is the comparison point
for every later stage. Default RX measured ~164 MiB/s against 473-525
historically, so a three-point A/B was run against `d81ca60d` (pre-series)
and `c898d4b5` (pre-rewrite, the tree the 525 was taken on). Both reproduce
~164 on this host, attributing the gap to the rig and clearing the series.
The older figures are retired as gates. The investigation also found that the
virtio-net driver negotiates no receive-side segment coalescing (`GUEST_TSO4/6`
and `MRG_RXBUF` are absent, though `GUEST_CSUM` is present), which is a
standing optimization opportunity outside this plan.

### Stage 1: cancellation-aware wait registrations - complete

Landed:

1. Added the internal wait-registration/token primitive with removal on
   future drop.
2. Converted TCP RX/readiness, channel/TCP TX/readiness, and UDP RX/TX/
   readiness waiters.
3. Added cancellation and distinct-`Waker` regression tests that verify
   registration counts return to zero.
4. Fixed separately discovered pre-existing page-reclamation progress and
   channel lost-wakeup defects before continuing.

The vDSO periodic rechecks intentionally remain until Stage 6.

### Stage 2: async channel control plane - complete

Landed:

1. Added async queue-room and RPC futures, including safe cancellation after
   a request has been queued.
2. Made response dispatch tolerate cancelled ordinary RPC receivers.
3. Added typed async TCP TTL, `TCP_NODELAY`, `SO_LINGER`, and shutdown paths,
   plus typed async UDP TTL support.
4. Added the nonblocking teardown queue with reservation-owning records.
5. Converted TCP listener and TCP stream destruction while preserving
   ordering between already-queued per-handle messages and close.
6. Added cancellation, full-staging, ordering, and teardown-progress tests
   for the converted paths.
7. Converted TCP listener bind and UDP bind to the async RPC path. A bind
   whose future is cancelled after its request was queued rolls back through
   an RAII record that carries the reservation, so the listener/socket
   sys-io created for it is closed on the teardown queue.
8. Routed the POSIX `setsockopt`/`getsockopt` dispatch through the typed
   async option and shutdown methods, deleting the duplicate blocking option
   methods and `send_receive`. The raw-pointer dispatch itself still lives in
   `moto-io` and moves to the `Rt*` wrappers in Stage 3.
9. Split UDP release out of `Drop` into an idempotent `UdpSocket::close()`
   invoked when the socket's last descriptor closes. Posting the release from
   `Drop` was a defect: the channel IO thread briefly upgrades the weak
   reference it keeps to every live UDP socket, so `Drop` -- and the message
   that makes sys-io free the bound address -- could run there after the
   caller's `close()` had returned, behind a rebind of the same address.

10. Converted UDP destruction to the teardown queue. `close()` transfers the
    release and the socket's channel reservation to the driver, empties the
    socket's TX queue, and blocks `try_tx` from staging anything afterwards,
    so the closing thread never parks on a full staging queue and item 9's
    guarantee still holds. The confirmed contract is that datagrams already
    handed to the channel reach sys-io before the release, and that anything
    still in the socket's own queue is discarded (UDP is lossy, and the
    fragmenting queue already drops datagrams when full).
11. Gave teardown records a staging fence. Teardown outranks ordinary staged
    work, so a UDP close would otherwise overtake its own socket's staged
    datagrams and sys-io would discard them. A record carries the staging
    queue's absolute push count at enqueue time and waits until the driver
    has drained that many messages -- absolute, so a pop racing the capture
    cannot let the caller's next bind overtake the release.
12. Converted TCP connect, accept re-posts, and successful late-response
    cleanup to async, driver-owned work with cancellation-safe weak routing and
    explicit reservation transfer for unclaimed accepts.
13. Removed the last `SyncWaiter`, synchronous send/RPC,
    `send_msg_guaranteed`, and their condvar/backoff and detached-task
    machinery from `moto-io` networking.

Final gate:

1. The DNS resolver restart failure was root-caused to shared IPC listener
   ownership outliving the owner's live process status. Listener creation and
   lookup now discard entries owned by a non-live process.
2. A deterministic systest retains the killed owner's process handle, starts a
   replacement listener on the same URL, and connects to it.
3. The exact source state passed formatting, relevant debug/release builds and
   clippy checks, then three consecutive ordinary debug and three consecutive
   ordinary release full suites without retries or tolerated failures.

Gate: explicit executor-liveness tests under saturated queues, existing
connect/accept cancellation tests, listener-drop backpressure test, and the
network suites.

### Stage 3: introduce vDSO `Rt*` wrappers - in progress

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

Taken as four patches, one per socket type and then the shared listener work,
rather than one per bullet. The bullets do not separate: a type's flags and its
raw option dispatch must move together, or `setsockopt` writes one copy of
`O_NONBLOCK` while the blocking path reads another. Order is UDP, TCP stream,
TCP listener, then the optional observer -- the accepted stream inherits the
listener's nonblocking flag, so the stream must own the flag before the
listener stops holding it.

`RtUdpSocket` landed 2026-08-04 as `6ee7ba50`. It is what the FD table stores; it owns
`O_NONBLOCK`, `SO_RCVTIMEO`/`SO_SNDTIMEO`, the raw option-pointer dispatch, the
`PosixFile` impl and the `EventSourceManaged`, and `moto_io::net::udp::UdpSocket`
keeps only the typed `set_ttl_async`/`ttl_async`. Two consequences worth
recording against the sections above:

- **UDP's `as_any` downcast is already gone**, ahead of the observer patch,
  because the wrapper constructs the event source and installs it and so never
  has to recover it (Section 6.4). What remains for UDP is the *mandatory*
  listener at construction, not the downcast.
- **The local option arms no longer block.** `SO_NONBLOCKING` and the two
  `SO_*TIMEO` options were being driven through `block_on_sync` on futures that
  were always immediately ready; they are plain stores on the wrapper now.
  `SO_TTL` still bridges, being the only UDP option that costs an RPC.

Its gate was the AGENTS.md one -- three debug and three release `full-test.sh`,
all passing first attempt -- plus a new `udp::test_udp_dup_shares_posix_flags`.
That test was missing and is what makes the placement checkable: where these
flags live is a claim about `dup`, and the suite had no UDP `try_clone`
coverage at all.

`RtTcpStream` followed on 2026-08-04 as `f178dfbf`, and it
answers the design question patch 1 deferred. `TcpListener::accept` built the
accepted stream's event source internally through a factory, so the vDSO never
saw the concrete source it had just created; rather than recover it with an
interior-mutability closure, `accept` and `try_accept` are now **generic over
the listener type** (`&dyn Fn() -> Arc<L>`) and **return the source they
installed** alongside the stream. The signature now states what the call does,
and the accepted stream loses its downcast exactly as UDP did. It stays a
factory rather than a ready-made `Arc` because `try_accept` must answer
`E_NOT_READY` without allocating one, which is every turn of mio's accept loop.
The one-line `new_event_listener` adapter is gone.

Two facts this patch established, both bearing on later stages:

- **The accepted stream's inherited `O_NONBLOCK` is load-bearing for `russhd`,
  not just a convenience.** mio's Motor shim marks only the listener; with the
  inheritance sabotaged the VM boots and never serves SSH. Any later stage that
  moves this copy must keep it. It is also a deliberate divergence from std on
  Linux, where an accepted socket does not inherit the flag, and it deserves an
  explicit decision.
- **The local option arms no longer block for TCP either**, the same three as
  UDP; `SO_SHUTDOWN`, `SO_NODELAY`, `SO_TTL` and `SO_LINGER` still bridge.

`RtTcpListener` closed the type work on 2026-08-04, gated but not yet
committed. A listener's only POSIX flag is `O_NONBLOCK` -- the ABI has no
accept timeout -- and it moved with the raw option dispatch, the `PosixFile`
impl and the poll-registry source, leaving the native listener the typed
`set_ttl_async`/`ttl_async` pair and its accept machinery. Three facts from it
bear on later stages:

- **`listen()`'s "nonblocking only" precondition is a veneer rule and moved
  with the flag.** The native `listen` arms the accept queue for any backlog;
  the wrapper refuses a blocking descriptor. So does the side effect in the
  other direction: becoming nonblocking still arms the queue at 1024, because
  a nonblocking accept can answer only from it.
- **`as_any` is now dead.** All three socket kinds hold their concrete
  `EventSourceManaged` in their wrapper, so nothing recovers it from the
  abstract handle any more, and `NetEventListener::as_any` has no caller left
  in the tree. Removing the trait method is the observer patch's, along with
  the mandatory constructor listener (Sections 6.4 and 5.1).
- **`moto_io::net` now holds no POSIX state and no raw option-pointer dispatch
  at all**, which is the Stage 3 outcome Sections 6.3 and 6.4 asked for. Only
  the mandatory listener argument remains of the constructor surface.

A pre-existing defect turned up while writing its regression and was fixed
straight after it, as patch 3.1: a blocking `accept()` could be starved on a
listener that also had an accept request outstanding, because the caller was
keyed to the request it posted rather than to the next response. The listener
now dispatches responses to a queue of awaiting callers, which also removes
`RpcWaiter::Accept`'s sender. It needs a descriptor used both ways, which
neither std nor mio produces.

Next is the optional observer. `docs/plans/networking-step-by-step.md` Step 11
holds the resume notes and the full patch-2, patch-3 and patch-3.1 records.

### Stage 4: prepare the driver/ownership split additively - not started

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

### Stage 5: flip ownership to `rt.vdso` - not started

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

### Stage 6: remove the wake-race safety polling - not started

- Delete `block_on_recheck`, `TX_PARK_RECHECK`, and `RX_PARK_RECHECK`.
- Drive action futures directly with the real vDSO deadlines.
- Run timeout storms concurrently with active TCP and UDP traffic and assert
  both progress and zero retained wait registrations.

Gate: the known debug `full-test.sh` flakes must be diagnosed and fixed before
this stage begins. Then run the network suites and the ordinary AGENTS.md
gate: at least three consistently passing debug and three consistently
passing release `full-test.sh` runs. A comparative pass percentage is not an
acceptable substitute.

### Stage 7: cleanup and final gate - not started

- Make `moto-io::net::channel` private or narrow its public exports to
  `NetClient`, `NetDriver`, `Reservation`, sockets, futures, typed options,
  readiness bits, and the optional observer.
- Remove `blocking-path` terminology, vDSO-specific comments, global test
  hooks, unused dependencies, and stale design references.
- Add a source-level guard that `moto-io` networking does not use
  `SysCpu::spawn`, `block_on_sync`, `SyncWaiter`, or thread sleep.
- Update Sections 2 and 3 of this document after implementation so they
  describe the delivered ownership rather than the pre-refactor boundary.
- Record code-size and paired same-host release rnetbench results in
  Section 10.

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
   rnetbench stays within the kill criteria in Section 10: no sustained
   throughput loss over 5% and no sustained RR regression over roughly
   5 microseconds after tuning.

## 10. Performance gate

### Methodology

`rnetbench --server -p 40000` on-image at `/sys/tests/rnetbench`; the client
on the host as `rnetbench --client 192.168.4.2:40000 [-b 65536]`, default
`-t 5`. Each client run reports TCP RR, then client->server (**Motor RX**),
then server->client (**Motor TX**). The default buffer is 1KB-average random
writes with NODELAY, which stresses per-message cost; `-b 65536` measures the
pipe instead.

A run's RR is the host-steal gauge: distrust the throughput of any run whose
RR is far out of band. Debug-build throughput is additionally logging-bound
(per-packet console output), so compare debug only against debug.

Only same-host, back-to-back numbers count. Build both sides, bench them in
one sitting, and never gate on a figure recorded on another day -- the
attribution below is what happens when that rule is broken.

### Reference: release at `ab81c861`, 2026-07-26

Three rounds, medians. The default-RX figure was confirmed over 8 samples
spanning 145.7-167.7 MiB/s.

| Metric | Value |
|---|---|
| RR default / bulk | 58.8 / 57.4 usec |
| default RX / TX | 163.6 / 328.3 MiB/s |
| bulk RX / TX | 678.9 / 1356.4 MiB/s |

**Kill criteria:** no sustained throughput loss over 5% and no sustained RR
regression over roughly 5 microseconds after tuning.

### Why the older numbers were retired

Baselines recorded 2026-07-19 and 2026-07-21 put default RX at 473-525 MiB/s.
The `ab81c861` sample measured 164, apparently a threefold regression -- while
RR halved and bulk TX doubled, which no code change produces. A three-point
A/B settled it:

| Commit | def RX | RR | What it is |
|---|---|---|---|
| `c898d4b5` | 164.1 | 56.6 | pre-rewrite; the tree the 525 was taken on |
| `d81ca60d` | 164.9 | 56.3 | last commit before this series |
| `ab81c861` | 163.6 | 58.8 | HEAD at the time |

The tree that once measured 525 measures 164 on this host, so the gap is the
rig, not the code, and the series is clear. The host client binary was held
constant across all three runs, which is a valid control: `do_throughput_write`
is unchanged between `c898d4b5` and HEAD.

What changed on the rig was attributed but never identified -- governor,
host kernel, and tap configuration are all candidates. The paired same-host
rule makes the gate robust to this, but an unexplained 3x drift can recur
mid-series: treat an out-of-band RR reading as a stop signal for that sitting,
and record the benchmark manifest before further tuning.

### Standing finding: no receive-side coalescing

The investigation found that the virtio-net driver negotiates `CSUM`,
`GUEST_CSUM`, `MTU`, `MAC`, `STATUS`, `HOST_TSO4`, and `HOST_TSO6`. Receive
*checksum* offload is therefore present, but receive *segment coalescing* is
not: `GUEST_TSO4/6` and `MRG_RXBUF` have no constants in the repo. Measured on
`moto-tap`, the guest receives 509 B/pkt on the default run while sending
4372 B/pkt, so RX is packet-rate bound and its throughput tracks
bytes-per-packet.

This is long-standing, not a regression, and it is why default RX is low in
absolute terms. It is outside this plan but is now sequenced between Stage 2
and Stage 3 of it (Section 0); see `docs/plans/virtio-rx-coalescing.md`.

### Environment caveats

The host cpufreq governor is `powersave`. The source
`src/vm_scripts/run-qemu.sh` is tracked, but historical measurements did not
record enough host state to recover the rig. The benchmark manifest in
`docs/plans/networking-step-by-step.md` is required before further
measurements.
