# Re-implementing the rt.vdso runtime on moto-async: target design

2026-07-19. This is the desired long-term design for the vdso runtime rewrite
recommended by `vdso-rewrite-analysis.md`. It describes the end state only;
staging and migration order are a separate implementation plan. The analysis
document's "keep unchanged" list is treated as normative here: where this
design says "as today", the current behavior is the specification.

## 1. End state in one paragraph

Every process runs one concurrency model: moto-async `LocalRuntime` threads
hosting long-lived tasks, with a single pair of sync/async bridge primitives
connecting them to caller threads. The client-side net stack is extracted into
`moto-io::net`, a native async client mirroring `moto-io::fs`; `rt.vdso`
becomes a thin synchronous POSIX-compatibility veneer over `moto-io::fs`,
`moto-io::net`, and a push-based readiness ("event sink") layer that the mio
poll ABI consumes but does not own. The vdso ABI (`RtVdsoVtable` v16), the
mio-compat event semantics, and the tuned TCP/UDP data-path design are
unchanged. No kernel changes are required.

```
caller threads (std / mlibc / tokio, via the synchronous vdso ABI)
     |                                        ^
     | block_on_sync(future)                  | SyncWaiter::signal()
     v                                        |
+--------------------------------+   +--------------------------------+
| core IO runtime (1 lazy thread)|   | net channel runtimes           |
|  - moto-io::fs FsClient        |   |  (1 lazy thread per NetChannel)|
|  - unmanaged-handle readiness  |   |  - rx task                     |
|    tasks (child stdio, ...)    |   |  - tx task                     |
|  - (later) async DNS client    |   |  - control tasks (accept,      |
|  (+ sibling relay runtime      |   |    connect, teardown)          |
|   thread for stdio relays)     |   |                                |
+--------------------------------+   +--------------------------------+
     |                                        |
     +----------> event sinks (poll registries) <----------+
                  push (token, bits); poll_wait and async
                  readiness() are consumers
```

## 2. Design rules

These are the invariants every component below obeys; the implementation plan
should treat a violation of any of them as a bug, not a tradeoff.

1. **One concurrency model.** All in-vdso I/O multiplexing runs as long-lived
   tasks on `moto_async::LocalRuntime` threads. No hand-rolled park/wake
   protocols outside the two bridge primitives.
2. **The sync/async boundary is implemented exactly twice**, in `moto-async`:
   - thread -> runtime: `block_on_sync` (a parker-waker poll loop);
   - runtime -> thread: `SyncWaiter` (a lost-wakeup-safe signal a task fires).
   Every place a user thread blocks — reads, writes, RPCs, `poll_wait`,
   backpressure — goes through one of these two. No third implementation,
   ever.
3. **The data-path design is a specification, not code.** Caller-thread
   copies, `pending_tx` marker messages with late length binding, multi-page
   TX, single-page RX, thread-per-channel, warm-CPU wake-target semantics,
   and per-loop message batching survive verbatim (section 8).
4. **Executor discipline** (the sys-io lessons): long-lived tasks only, never
   per-message spawns; data-path messages dispatched inline in the receive
   task; spawned futures stay under the 2048-byte allocator slab cliff
   (`spawn` boxes futures); no allocation on steady-state data paths.
5. **Syscall parity.** Converted paths issue the same number of syscalls as
   today's tuned code. In particular the channel runtime folds the sys-io
   wake into its sleep syscall, and net readiness pushes go source-to-poller
   with no intermediary task hop.
6. **Compatibility is bit-for-bit.** The vtable, the edge-triggered poll ABI,
   and the mio-quirk event rules (`maybe_raise_events` synthesis, close
   tombstones, timeout-returns-0, listener-accepts-WRITABLE) do not change.
7. **Cancel safety on bridged futures.** Any future a caller thread can await
   with a deadline (reads, RPCs, `poll_wait`) must be safe to drop on
   timeout: dropping deregisters its waker and loses no data. Partial
   progress counts as data: a timed-out future must surrender it before
   being dropped — `block_on_sync_deadline` returns the future so the
   veneer can extract, e.g., the bytes a blocking write already committed
   to `pending_tx` when `SO_SNDTIMEO` fired (today's write returns
   `Ok(written)` in that case — `rt_tcp.rs:1321` — and that is the
   specification). This replaces today's park-with-deadline-and-recheck
   idiom.
8. **No panicking backpressure.** "Queue full" and "no pages" are awaits (on
   the runtime) or parks (on caller threads) — never `unwrap()`, `todo!()`,
   or dropped messages.

## 3. moto-async: bridge primitives and executor extensions

New module `moto-async/src/sync_bridge.rs` plus the executor extensions
below. These are general-purpose: sys-io and `rt_fs` use them too.

### 3.1 `block_on_sync`

```rust
pub fn block_on_sync<F: Future>(fut: F) -> F::Output;
pub fn block_on_sync_deadline<F: Future>(fut: F, deadline: Instant)
    -> Result<F::Output, F /* timed out; returned for progress extraction and cleanup-by-drop */>;
```

Polls `fut` on the calling thread. The waker performs the standard
empty/notified/parked protocol and `SysCpu::wake`s the calling thread's
handle; between polls the thread parks in `SysCpu::wait` with the deadline.
Properties:

- No `LocalRuntime`, no runtime TLS context, no timer queue: the deadline
  rides on the parker's wait syscall.
- Zero steady-state allocation: the waker's `Arc` state is cached per thread
  (created once, reused by every subsequent call on that thread).
- Illegal on a `LocalRuntime` thread (would deadlock the executor);
  debug-asserted.
- A ready future completes in one poll with no syscall — the fast path for
  RPCs whose response already arrived and reads with buffered data.

`rt_fs::blocking_run`'s throwaway-`LocalRuntime`-per-call pattern is deleted
and re-expressed as `block_on_sync(async { tasks_tx.send(task).await;
rx_result.await })`; it is the first consumer and the validation vehicle.

### 3.2 `SyncWaiter`

```rust
pub struct SyncWaiter { /* three-state atomic + thread handle */ }
impl SyncWaiter {
    pub fn wait(&self, deadline: Option<Instant>);  // caller thread
    pub fn signal(&self);                           // any thread, incl. tasks
}
```

The empty/waiting/waking dance that `EventSourceManaged`'s futexes implement
today, written once. Used where a sync thread waits for a broadcast condition
maintained by a task (send-queue room, io-page availability) and re-checks on
wake; spurious signals are allowed and harmless by contract. `block_on_sync`'s
parker is built on the same state machine, so there is exactly one parking
protocol in the codebase with one set of memory-ordering reasoning.

### 3.3 Executor: deferred-wake slot (wake folding)

`LocalRuntime` gains a per-runtime slot: `set_wake_on_sleep(SysHandle)`. A
task that knows its peer must be woken (the tx task after sending messages to
sys-io) sets the slot instead of issuing `SysCpu::wake` on the sleep path.
Contract: the wake is delivered exactly once, folded as the wake-target
argument of the executor's next `SysCpu::wait` when the runtime sleeps, or
issued explicitly by the executor if it starts another poll cycle instead.
The handle is a wake target, never a swap target (design rule 5; the measured
+11 usec set_nodelay regression when swapping is the reason).

### 3.4 Executor: run-state wake elision

`MotoWaker::wake` today issues `SysCpu::wake` unconditionally
(`local_runtime.rs:130`). The current net send path avoids exactly this
syscall when the io thread is already awake — that is what the double-swap
protocol is for — so unconditional wakes would break rule 5 on every
caller-thread send that lands while the runtime is mid-batch. The fix is
executor-level: `LocalRuntime` maintains an atomic run-state (polling /
committing-to-park / parked), and cross-thread wakes enqueue the task but
issue the syscall only when the runtime is parked or committing to park,
with the standard recheck-after-commit step closing the lost-wakeup window.
One protocol, one memory-ordering proof, colocated with the parker; sys-io
inherits the same saving. A channel-local "tx task running" flag was
considered and rejected: it would re-create the bespoke wake-protocol
family that rules 1-2 exist to eliminate.

### 3.5 Multi-waiter notify

`LocalNotify` currently panics on a second concurrent waiter. The end state
needs N tasks awaiting one condition (e.g. several tasks awaiting send-queue
room). Extend `LocalNotify` to a waiter list with `notify_one`/`notify_all`,
or provide a documented composition; either way, concurrent waiters become
legal.

### 3.6 Known executor debt to retire

The `futures::stream::for_each_concurrent` incompatibility noted in sys-io
(`net.rs:220`) is understood and fixed (or documented as a waker-contract
rule) before a second major consumer inherits it.

## 4. The core IO runtime

One lazily created `LocalRuntime` thread per process (name:
`rt::io_runtime`), started on first use of any of its residents. It is the
consolidation point that today's FS runtime thread hints at; the FS thread
*becomes* this thread. Residents:

- **`moto-io::fs` client.** Exactly today's architecture (`AsyncFsClient`
  dispatching boxed `IoTask`s over a `moto_async::channel`), with
  `blocking_run` on the cheap bridge (3.1).
- **Unmanaged-handle readiness tasks.** One task per registered
  `EventSourceUnmanaged` (child stdio, child-process FDs): awaits the
  handle's `SysHandleFuture`, runs the owner's level-to-edge
  `check_interests`, pushes resulting events into every registered sink
  (section 6), and on `E_BAD_HANDLE` runs `on_handle_error` + closed
  semantics and exits. This deletes the per-wait handle-list rebuild and the
  bad-handle special-casing from `Registry::wait`, and moves these waits off
  the `poll_wait` caller's thread. The added thread hop is on paths where
  latency cannot matter (child stdio, process exit).
- **(Later) async DNS client.** `dns_lookup` currently blocks the caller
  thread inside `moto_dns::Client`; the design gives it a natural home as a
  runtime task with the caller bridging via `block_on_sync`, but this is an
  opportunistic follow-up, not part of the rewrite proper.

The runtime's timer wheel serves all residents (DNS retries, future
client-side timeouts). Nothing here is on an RR-critical path, so
consolidation onto one thread is free.

One deliberate non-resident: stdio relay tasks run on a dedicated sibling
runtime thread (`rt::stdio_relay` — at most one per process, created only
while inherited-stdio children exist). FS work, including client-side
copies, shares the core runtime thread, and a child's interactive output
must not queue behind file I/O; the isolation costs one thread and still
collapses today's thread-per-pipe relays into one. The relay conversion
itself (threads to tasks, await-readable / copy / await-writable, the stdin
ownership rule) is specified in 7.2.

## 5. The net stack

### 5.1 Crate split

The client TCP/UDP state machine moves out of the vdso into
`moto-io/src/net/` (`moto_io::net`), sibling of `moto_io::fs`:

- channel management: `NetChannel` (the `io_channel::ClientConnection`, the
  subchannel bitmap, the per-channel runtime thread), channel reservation
  (`reserve_channel`, `ChannelReservation`) and the global channel registry;
- socket state machines: `TcpStream`, `TcpListener`, `UdpSocket` — pending
  accept queues, RX message ordering (`InnerRxStream`), shutdown/linger
  semantics, `pending_tx`, TCP state tracking;
- an async-first public API (5.4).

`rt.vdso`'s `net/` directory keeps only the veneer: the `extern "C"` shims,
`PosixFile` implementations wrapping `moto_io::net` objects, sockopt
plumbing, and mio event synthesis (`maybe_raise_events` and friends), which
translates `moto_io::net` state-change notifications into the poll ABI's
event rules.

The seam between the two is a per-socket event listener: `moto_io::net`
sockets emit clean, mio-agnostic readiness edges (readable, writable,
read-closed, write-closed, error) through a hook the veneer installs at FD
creation; the veneer layers the mio-specific quirks (`maybe_raise_events`
synthesis, tombstones, listener-WRITABLE) on top and pushes into sinks. The
listener runs inline in the rx task's dispatch — same thread, no task hop
(rule 5) — so the crate boundary costs one indirect call, not a scheduling
edge. The edge vocabulary stays mio-free: native async consumers use the
readiness futures and never see the hook, and compat quirks never leak into
the native API.

### 5.2 The channel runtime

Each `NetChannel` owns one `LocalRuntime` thread (name:
`rt_net::channel_runtime`) — thread-per-channel is kept per the scaling
rationale in `rt_net.rs:466`. The hand-rolled `io_thread()` is replaced by
long-lived tasks:

- **rx task.** `loop { msg = conn.recv().await; dispatch inline }` where the
  async recv is: try `conn.recv()`, on `NotReady` await the connection
  handle's `SysHandleFuture`. Dispatch is exactly today's
  `io_thread_poll_messages` logic: `msg.id == 0` routes to the owning
  stream/socket/listener (`process_incoming_msg`, `on_udp_msg`, pending
  accept queues, orphan handling); `msg.id != 0` resolves through the RPC
  map (5.3). The 32-message batch limit is kept as a `yield_now` so the tx
  task and timers interleave under load.
- **tx task.** Drains the send queue (5.3), expands `TCP_TX_MARKER_FLAGS`
  markers by claiming the stream's pending TX pages at send time (late
  binding, unchanged), pushes to `conn.send`, and on making room signals:
  send-queue waiters (`SyncWaiter` list + `LocalNotify` for tasks),
  `write_waiters` via `maybe_can_write` (unchanged event semantics), and
  page waiters after a sys-io page-freed wake. On its sleep edge it uses the
  deferred-wake slot (3.3) so a send-then-sleep cycle stays one syscall; the
  explicit `wake_driver()` calls at batch boundaries stay as today.
- **control tasks.** Nonblocking connect and accept completions are tasks
  awaiting RPC oneshots; a listener whose `post_accept` hits a full queue
  awaits send room and re-posts (deleting the `TODO: how to post an accept
  later?` panic); teardown is a task (5.5).

Deleted outright: the `io_thread_running`/`io_thread_wake_requested`
double-swap park protocol (the executor owns sleeping), `deferred_msgs` and
`restage_deferred_msgs` (a task awaits room instead), `send_waiters` as a
thread-handle deque (now `SyncWaiter`s), `legacy_resp_waiters` and
`response_handlers` (now the RPC map), the "sad story" hold-the-lock-while-
processing rule and the 5-second debug timeout in blocking reads (waker
registration is race-free by construction), and the mystery `fence(SeqCst)`s
(the executor's wake edges carry the ordering).

### 5.3 Channel data structures

- **Send queue.** A fixed `ArrayQueue<io_channel::Msg>` of
  `CHANNEL_PAGE_COUNT`, as today (data-path pushes from caller threads must
  stay one lock-free push + conditional wake, the condition being the
  executor run-state, 3.4). Backpressure:
  - caller threads: push; on full, enlist a `SyncWaiter`, wake the runtime,
    park, retry — today's `send_msg` semantics with the one shared primitive;
  - runtime-local tasks: push; on full, await the send-room `LocalNotify`,
    retry. This is the guaranteed-delivery path (`send_msg_guaranteed`'s
    replacement): never dropped, never deadlocked, never panicking.
- **RPC map.** One `Mutex<BTreeMap<u64 /* req_id */, oneshot::Sender<Msg>>>`
  per channel, replacing both `legacy_resp_waiters` and `response_handlers`.
  Callers insert the sender *before* queuing the request (today's ordering
  rule, kept). Sync RPCs (`send_receive`) become `block_on_sync(rx)`;
  async completions (connect, accept) are tasks awaiting the same receivers.
  The rx task resolves entries by `remove + send`.
- **Per-stream readiness.** The per-stream `rx_waiter` thread-handle slot and
  `EventSourceManaged`'s futex pair dissolve. Blocking reads become
  `block_on_sync_deadline(stream.read(bufs), deadline)` (SO_RCVTIMEO on the
  parker, as today); the read future's waker is woken by the rx task when it
  queues RX data or a state change. Multiple concurrent readers (multiple
  FDs on one stream) follow the wake-all-and-recheck model the current code
  already has.

### 5.4 `moto-io::net` public API shape

Mirrors `moto-io::fs` in spirit — a native async client usable outside the
vdso — with one extra constraint that FS does not have: **read/write futures
perform their copies in the polling context**, i.e. on whatever thread polls
the future (a vdso caller thread via `block_on_sync`, or a native app's
executor thread). Copies never run on the channel runtime thread; moving
them there would serialize all sockets of a channel through one core (bulk
RX is measured bilaterally CPU-bound). Sketch, not a signature contract:

```rust
TcpListener::bind(addr) -> Result<TcpListener>;   // sync setup + async accept()
listener.accept().await -> Result<(TcpStream, SocketAddr)>;
TcpStream::connect(addr).await -> Result<TcpStream>;
stream.read(bufs).await / stream.write(bufs).await -> Result<usize>;
stream.try_read / try_write   // nonblocking forms for the veneer's
                              // O_NONBLOCK paths and native reactors
stream.readable().await / writable().await;       // readiness futures
set_event_listener(..)  // per-socket mio-agnostic edge hook (5.1);
                        // installed by the veneer, ignored by native users
UdpSocket: bind / connect / send_to / recv_from, same pattern
```

All futures on the data path are cancel-safe (design rule 7). Readiness
futures are what a future Motor-native tokio reactor backend consumes
directly, skipping mio emulation; that consumer is enabled by this design
but not part of it.

*Implemented (F4c-1 `b5051cb`, F4c-2 `b747054`): `moto-io::net` is async-first
with no data-path `block_on`; the blocking spin/park/`SO_*TIMEO`/`O_NONBLOCK`
lives in the veneer (`rt.vdso/src/net/blocking.rs`), mirroring `rt_fs` over
`moto-io::fs`. Setup (bind/listen/sockopts) stays sync as sketched above. The
`readable()`/`writable()` readiness futures exist but have no consumer yet.*

### 5.5 Lifecycle and teardown

- `TcpStream`/`UdpSocket` drop: state cleanup runs synchronously as today;
  the close message goes through the guaranteed send path (5.3). A drop that
  executes on the channel runtime thread (rx task briefly holding the last
  strong ref) hands the message to a task rather than blocking — the
  scenario `send_msg_guaranteed` documents, now expressed as an await.
- `NetChannel` teardown (currently `todo!()`): when the last reservation is
  released, the channel signals an exit notify; the tx task drains the send
  queue (all closes delivered to sys-io), the rx task drains responses in
  flight, tasks finish, `block_on` returns, the runtime thread exits and is
  joined. If the last release happens on the channel's own runtime thread
  (a socket dropped by the rx task), the join is handed to the core IO
  runtime rather than performed in place — self-join is a deadlock.
  Channels are actually torn down; `NetRuntime::assert_empty` becomes
  meaningful in tests.

## 6. The poll registry: registration model + event sink

The registry's three layers get the treatment the analysis prescribes: keep
layers 1-2, rewrite layer 3.

**Kept unchanged.** The registration data model (`EventSourceBase`'s
many-to-many `(source, registry, fd) -> (token, interests)` map with
supported-interest masks) and the event-generation policy — the mio-compat
rules encoded in `maybe_raise_events`, close tombstones, `READ_CLOSED`
ordering relative to queued RX bytes, `poll_wait` returning 0 on timeout, the
listener WRITABLE-registration quirk. These rules live in the sources (in the
vdso veneer) and are gated by the on-image mio-test suite.

**Rewritten: delivery.** A `Registry` is, in delivery terms, an event sink:

- state: the `(Token -> EventBits)` map plus tombstones, as today;
- input: `push(token, bits)` — callable from any thread; one map update plus
  one wake of a parked poller (or one waker fire for an async consumer);
- sync output: `poll_wait` = collect-or-park loop on the bridge parker with
  the ABI deadline. Waiting pollers register in a one-slot fast path backed
  by an overflow list: the single-poller case (mio/tokio's `&mut Poll`)
  costs exactly today's one atomic slot on the push-to-wake path, while a
  second concurrent `poll_wait` overflows into a locked list, making
  multi-poller use correct (the ABI never promised mio's `&mut self`
  serialization) without taxing the RR-critical path;
- async output: a `readiness()` future over the same state, for future
  native consumers. The poll ABI becomes one consumer of the sink, not its
  substrate;
- `poll_wake` pushes a synthetic event, as today.

**Feeders.**

- *Net sources push exactly as today*, now from channel-runtime tasks:
  `process_incoming_msg -> listener edge -> veneer quirks
  (maybe_raise_events) -> sink.push -> wake poller`, all inline on the
  channel runtime thread (5.1).
  This path is on tokio's critical latency path; it keeps its
  one-push-one-wake shape and gains no hop. Routing net events through an
  intermediary poll task is explicitly ruled out.
- *Unmanaged `SysHandle` sources* feed from their core-IO-runtime tasks
  (section 4), deleting `Registry::wait`'s handle-list plumbing.
- *New source kinds are trivial*: the FS runtime pushes readiness for
  nonblocking files (unblocking `O_NONBLOCK` FS, today `E_NOT_IMPLEMENTED`
  for the structural reason the analysis describes); timers, DNS, and any
  future service push like any other task.

## 7. The posix layer and stdio

Two boundary components deserve explicit treatment: the posix layer, which
is architecturally simple and stays a separate layer on top of everything
above, and stdio, which is in an unsatisfactory state and needs its own deep
redesign. That redesign is out of scope here — this rewrite is about the
async runtime — but the interaction surface is pinned down now so that the
future stdio work is a consumer of this architecture, not a revision of it.

### 7.1 The posix layer: a sync dispatch table on top

`posix.rs` — the `RtFd -> Arc<dyn PosixFile>` descriptor table and the
`extern "C"` read/write/flush/close/duplicate entry points — remains exactly
what it is today: a synchronous dispatch layer with no waiting logic of its
own. It has no park/wake protocol, so it neither violates rule 1 nor needs
the bridge; it routes caller threads into `PosixFile` implementations and
nothing else. The rewrite changes the bodies of those implementations (net
veneers become `block_on_sync` / `try_*` calls over `moto_io::net`), never
the trait or the table. Two layering rules, made explicit:

- **FDs stay in the vdso.** `moto-io` (fs, net, and anything future) has no
  notion of an `RtFd`; the descriptor table, `duplicate` aliasing, and
  per-FD close semantics are veneer concerns. The crate split (5.1) moves
  none of them.
- **The posix layer serves caller threads only.** Runtime tasks never
  re-enter I/O through the FD table — that path ends in `block_on_sync`,
  which is illegal on a runtime thread (3.1). In-runtime residents (relays,
  readiness tasks, the DNS client) hold direct references to their objects
  and speak native async to `moto_io::*`.

### 7.2 Stdio

Today stdio is three things: `SelfStdio` (the process's own stdin/out/err
over `StdioPipe` shared-memory rings, synchronous under a spinlock),
per-child relay OS threads for `STDIO_INHERIT` spawns, and `ChildStdio` pipe
FDs for `STDIO_MAKE_PIPE` (pollable via `EventSourceUnmanaged`). Its known
deficiencies are acknowledged and deliberately not fixed by this rewrite:
`SelfStdio` has no nonblocking or pollable mode (`poll_add` on one's own
stdin returns `E_INVALID_ARGUMENT`); `flush` is a `sched_yield`, not a
delivery guarantee — a child can flush stdout and exit, and the parent can
observe the exit before the output appears, because the parent-side relay
drains the pipe asynchronously; `is_terminal` is a spawn-time env-var
heuristic (`STDIO_IS_TERMINAL_ENV_KEY`), not a property of the descriptor;
and `SelfStdio::close` is a `todo!()`.

**In scope for this rewrite** — the mechanical conversion already implied by
section 4, behavior preserved:

- Relay threads become tasks on the dedicated relay runtime thread (section
  4). The stdout/stderr relay is a
  straightforward await-readable / copy / await-writable loop; the stdin
  relay replaces its 1-usec `read_timeout` polling hack with a native await
  on "stdin readable or child pipe gone" (`SysHandleFuture` on both
  handles) plus nonblocking pipe operations.
- The stdin relay's exclusivity rule changes mechanism, not meaning. Today
  it holds the `SelfStdio` spinlock for the child's entire lifetime; a task
  cannot hold a lock across awaits, so the relay task instead claims
  ownership of the stdin reader (overflow stash included) and returns it
  when the child goes away. Reads on the parent's own stdin block meanwhile,
  as they effectively do today. A side effect: the relay holds a direct
  reference to the stdio object, dissolving the unsafe FD-table
  self-reference in `StdioKind::get`.
- `ChildStdio` readiness feeding moves to unmanaged-source tasks (section
  4); `SelfStdio` read/write/flush semantics — including the unsatisfactory
  flush — are bit-for-bit unchanged.

**Left to the stdio redesign, structurally enabled here.** The redesign must
be expressible in this architecture's vocabulary — if it requires a new
synchronization protocol, that is a bug in this design (rule 2):

- *Pollable / async stdio.* A stdin readiness task on the core runtime
  pushes `POLL_READABLE` into sinks exactly like any unmanaged source, after
  which `SelfStdio` can support `set_nonblocking` and `poll_add` the way
  sockets do. This is the "new source kinds are trivial" property of
  section 6; no new machinery.
- *Real flush.* "The written bytes have reached the consumer" becomes an
  awaitable pipe condition (ring drained, or reader acknowledgment),
  bridged by `block_on_sync` for the sync ABI. What flush should promise —
  in particular whether a parent observing a child's exit implies the
  child's stdio has been drained — is a semantics question that touches
  process exit reporting, and belongs to the stdio redesign, not this
  rewrite.
- *A real terminal story.* Replacing the env-var `is_terminal` guess with an
  actual terminal object (identity, size, modes) is a service design; at the
  runtime level it is just another moto-io-style client plus an event-sink
  feeder on the core runtime.
- Whether redesigned stdio lives as `moto_io::stdio` (a client crate beside
  fs and net) or stays vdso-local is the redesign's decision; runtime
  residency (the core IO runtime) and the bridge/sink interfaces are
  identical either way.

## 8. Data-path specification (normative)

The 2026-07 performance series lives in these structures; the rewrite
preserves them as written:

| Property | Specification |
|---|---|
| Copies | `read`/`write` copy on the caller/polling thread, never the channel runtime |
| TX | `pending_tx` queue + marker messages (`TCP_TX_MARKER_FLAGS`); lengths bound at claim time by the tx task; multi-page TX kept (A/B-settled twice) |
| RX | single-page RX messages; `InnerRxStream` ordering; ack cadence as today |
| Channel topology | thread-per-channel, `IO_SUBCHANNELS` sockets per channel, subchannel page masks |
| Sleep path | one `SysCpu::wait` per idle cycle with the sys-io wake folded in (3.3) |
| Wake semantics | sys-io is a wake target, never a swap target |
| Batching | 32-message recv/send batches with `wake_driver` at batch boundaries |
| Allocation | zero allocations on steady-state read/write paths (bridge waker cached; futures live on caller stacks or in long-lived tasks); RPCs may allocate their oneshot — control-plane, and today's map inserts allocate too |

Acceptance for the rewrite as a whole: rnetbench A/B parity on bulk TX/RX and
RR against the recorded baselines, and green on-image systest / mio-test /
tokio-tests suites. (Per-stage gates and kill criteria belong to the plan.)

## 9. Old-to-new protocol map

The nine hand-rolled synchronization protocols and where each lands:

| Today | End state |
|---|---|
| `NetChannel::send_waiters` (parked sender threads) | `SyncWaiter` list signaled by the tx task |
| `NetChannel::write_waiters` (POLL_WRITABLE re-check) | unchanged semantics; driven by the tx task via `maybe_can_write` |
| `NetChannel::page_waiters` (io-page exhaustion) | `SyncWaiter` list signaled by the tx task on page-freed wakes |
| `NetChannel::legacy_resp_waiters` (sync RPC slots) | RPC map oneshot + `block_on_sync` |
| `NetChannel::response_handlers` (async RPC callbacks) | RPC map oneshot + awaiting control task |
| per-stream `rx_waiter` (blocked readers) | read/readiness futures woken by the rx task |
| `io_thread_running`/`io_thread_wake_requested` park dance | executor run-state (parking + wake elision, 3.4) + deferred-wake slot |
| `EventSourceManaged` futex pair (blocking UDP) | recv futures over the bridge, same as TCP |
| `Registry::wait` `wait_handle` protocol | event-sink waiter slot + overflow list (single-poller fast path; multi-poller safe) |

Also dissolved: `deferred_msgs` (task awaits send room), the io thread's
`carry` deque (tx-task local state, kept trivially).

## 10. End-state module map

| Module | End-state role |
|---|---|
| `moto-async` | + `sync_bridge` (`block_on_sync`, `SyncWaiter`), multi-waiter `LocalNotify`, deferred-wake slot and run-state wake elision in `LocalRuntime` |
| `moto-io/src/fs.rs` | unchanged API; callers reach it via the cheap bridge |
| `moto-io/src/net/` | new: channel runtime, TCP/UDP state machines, async client API (section 5) |
| `rt.vdso/rt_fs.rs` | sync veneer; `blocking_run` on `block_on_sync`; FS runtime thread becomes the core IO runtime |
| `rt.vdso/net/*` | sync veneer over `moto_io::net`: ABI shims, `PosixFile` impls, sockopts, mio event synthesis |
| `rt.vdso/runtime.rs` | registration model + event sink; `EventSourceUnmanaged` feeding moves to core-runtime tasks |
| `rt.vdso/rt_poll.rs` | unchanged ABI shims |
| `rt.vdso/stdio.rs` | relay threads become tasks on the dedicated relay runtime (4, 7.2); `ChildStdio` readiness feeds sinks from core-runtime tasks; `SelfStdio` behavior unchanged pending its own redesign |
| `rt.vdso/posix.rs`, FD table | unchanged (7.1): impl bodies change, the trait and the table do not |
| thread/futex/time/tls/alloc/process modules | unchanged (kernel-facing; no runtime involvement) |

Thread inventory per process, end state: zero I/O threads until first use;
then one core IO runtime thread (FS, unmanaged readiness, DNS), at most one
relay runtime thread (only while inherited-stdio children exist), plus one
thread per active net channel. Today's thread-per-pipe relays collapse into
the single relay thread. The count is never higher than today and usually
lower.

## 11. Capabilities the design must leave structurally open

Not deliverables of the rewrite, but the design is wrong if any of these
requires a new synchronization protocol rather than a task or an await:

- pollable files / `O_NONBLOCK` FS (FS runtime pushes into sinks);
- pollable/async `SelfStdio` and delivery-acknowledged flush (7.2);
- graceful channel teardown and guaranteed close delivery (5.5);
- accept re-posting under backpressure (listener control task);
- UDP multicast and richer UDP control (control-task RPCs);
- an async in-vdso DNS client (core-runtime task);
- process-exit readiness without dedicated waiter threads (unmanaged-source
  task);
- a Motor-native tokio reactor backend consuming `moto_io::net` readiness
  futures and the sinks' async output directly.

## 12. Deliberately out of scope

- **Small-process thread consolidation** (hosting the first net channel on
  the core IO runtime thread): allowed by the architecture, decided later on
  measurement; thread-per-channel is the designed default.
- **The stdio deep redesign** (async/pollable stdio, real flush and
  exit-ordering semantics, terminal treatment): a separate effort; 7.2
  fixes the interaction surface it builds on.
- **Kernel changes**: none. The design uses existing `SysCpu::wait`/`wake`
  semantics, including the existing wake-target folding.
- **vdso ABI evolution** (a native async ABI surface): the sink/futures
  architecture is the prerequisite; any new ABI is a separate design.
- **sys-io changes**: none required; `moto-async` additions are shared
  library work that sys-io may adopt at leisure.
