# Re-implementing the rt.vdso runtime on moto-async: analysis

2026-07-19. Question: `rt.vdso` internally implements a hand-rolled I/O runtime
(most visibly the per-channel net I/O threads plus the epoll-like poll registry)
that predates `moto-async`. `moto-async` has since matured and powers all of
`sys-io`. Does re-implementing the vdso runtime on top of `moto-async` — keeping
the vdso ABI intact — make sense? The decision horizon is years, so long-term
runtime benefits weigh more than short-term development cost.

## Recommendation

Yes — do it, in stages, with two conditions:

1. The TCP/UDP data-path *design* (caller-thread copies, `pending_tx` late
   claim binding, multi-page TX, single wake-folded syscall on the io-thread
   sleep path) is treated as a specification to preserve, not code to rewrite.
   The 2026-07 performance series (RX 16.6 -> ~900 MiB/s, TX 46 -> ~730 MiB/s,
   RR 166 -> 81 usec) lives in these structures; the executor swap must not
   disturb them.
2. A small amount of groundwork lands in `moto-async` first (a cheap
   sync-to-async bridge, a wake-folding executor wait, a multi-waiter notify).
   Without the bridge, the rewrite would inherit `rt_fs::blocking_run`'s
   throwaway-`LocalRuntime`-per-call pattern, which is too heavy for the net
   data path.

The end-state to aim for is not "the same code, but async": it is a native
async net client (`moto-io::net`, mirroring `moto-io::fs`) with `rt.vdso`
reduced to a synchronous ABI veneer over it — the architecture FS already has.

## Where things stand today

`rt.vdso` currently contains three separate concurrency machineries:

| Subsystem | Model | Threads (lazy, per process) |
|---|---|---|
| FS (`rt_fs.rs` + `moto-io::fs`) | moto-async: one `LocalRuntime` thread, callers bridge via channel + oneshot + throwaway `block_on` | 1 |
| Net (`net/rt_net.rs`, `rt_tcp.rs`, `rt_udp.rs`) | hand-rolled io thread per `NetChannel`, bespoke queues and wake protocols | ceil(sockets / IO_SUBCHANNELS) |
| Poll (`runtime.rs`, `rt_poll.rs`) | hand-rolled edge-triggered registry; two readiness paths (managed push from net io threads, unmanaged `SysCpu::wait` on handles for stdio/process FDs) | 0 (waits on caller threads) |

Plus stdio relay threads (one per inherited child pipe) and purely
kernel-facing modules (thread/futex/time/tls/alloc) that no runtime choice
affects.

So the question is not "should the vdso adopt async" — FS already did, and
`moto-async` + `futures` are already linked into the vdso binary. The question
is whether the net path (~3.7K lines, the largest and most subtle part) and,
opportunistically, the poll/stdio glue should follow.

### What the hand-rolled net runtime costs us

The net path works and is fast, but it maintains roughly nine distinct
hand-rolled synchronization protocols, each with its own wake-loss reasoning:

- `NetChannel::send_waiters` — threads parked waiting for send-queue room;
- `NetChannel::write_waiters` — streams to re-check for `POLL_WRITABLE`;
- `NetChannel::page_waiters` — writers blocked on io-page exhaustion
  (added 2026-07 to fix a measured 18.8 MiB/s collapse caused by the previous
  timer-ladder fallback);
- `NetChannel::legacy_resp_waiters` — sync RPC response slots keyed by req id;
- `NetChannel::response_handlers` — async RPC callbacks (accept/connect);
- per-stream `rx_waiter` — blocking readers' thread handles;
- the `io_thread_running` / `io_thread_wake_requested` double-swap park
  protocol in `io_thread()`;
- `EventSourceManaged`'s three-state futex per direction;
- `Registry::wait`'s `wait_handle` store/clear protocol.

The code itself documents the cost of this style:

- `rt_net.rs:477-485`: `fence(SeqCst)` calls that "appear unneeded" but without
  which "weird things happen"; "the code below is somewhat fragile and probably
  has to be refactored (again)".
- `rt_tcp.rs:845`: "we must hold the lock while processing the message,
  otherwise the wait handle might get updated and we will lose the wakeup.
  Sad story, don't ask...".
- `rt_tcp.rs:1243`: a lost-wakeup-class assert that actually fired twice in
  2024, now papered over with a 5-second debug timeout in every blocking read.
- `NetChannel::drop`: `todo!("wait for the IO thread to finish")` — channels
  are never torn down.
- `TcpListener::on_response`: `self.post_accept(false).unwrap(); // TODO: how
  to post an accept later?` — a full send queue at the wrong moment is a
  process panic, as is `UdpSocket::drop`'s `post_msg(req).unwrap()`.

These are not incidental bugs; they are the structural signature of hand-rolled
wake protocols. Every one of the TODO panics ("post an accept later", "wait for
channel to become ready", guaranteed close delivery) is a one-line `await` in
an async model, because "wait until there is capacity, then act" is the thing
an executor natively expresses.

### What FS already proves inside the vdso

`rt_fs.rs` is the in-vdso precedent: a `!Send` async client (`moto-io::fs`) on
one lazily-created `LocalRuntime` thread; the synchronous ABI bridges via
`blocking_run` (boxed task over a `moto_async::channel`, result via `oneshot`).
It works, and it also demonstrates the one part that must not be copied: each
blocking call spins up a fresh `LocalRuntime` (`Box` + TLS context + `Arc`
waker) just to await the oneshot. For FS metadata ops this is tolerable; for a
net data path running at 100K+ ops/s it is not. The 2026-07 FS work measured
~15 usec/msg of per-message machinery on this path and explicitly listed
`blocking_run` as an optimization target. A parker-based bridge (below) fixes
both consumers.

### What sys-io proves about moto-async at scale

`sys-io` runs its entire net + FS server on a single `LocalRuntime`: smoltcp,
virtio drivers, per-socket long-lived tasks, bounded-concurrency command
dispatch. The executor's blocking primitive — aggregate all awaited
`SysHandle`s into one `SysCpu::wait` with the timer queue supplying the
deadline — is exactly the shape of the vdso io thread's hand-rolled loop.
Measured under rnetbench, sys-io sustains ~140K msgs/s per direction with
per-message CPU dominated by protocol work, not executor overhead; the
2026-07 optimization series was fought and won *on top of* moto-async without
the executor ever being the limiter.

Equally important, sys-io established the performance idioms a vdso rewrite
must follow: long-lived tasks, never per-message spawns (removing sys-io's
per-msg spawn was worth ~2-4 usec/msg); data-path messages dispatched inline
in the receive task; `spawn` boxes futures to dodge the 2048-byte allocator
slab cliff (per-alloc `SysMem` map/unmap means a broadcast TLB shootdown per
free).

## The ABI constraint, and why it does not block the rewrite

The vdso ABI (`RtVdsoVtable`, version 16) is synchronous `extern "C"`:
blocking calls with at most a deadline parameter (`net_tcp_connect`,
`poll_wait`, `thread_sleep`, `futex_wait`, socket `SO_*TIMEO`), plus the
edge-triggered poll ABI for mio. Nothing about the rewrite changes the vtable;
std, mlibc, and the crates.io `moto-rt 0.16` spec are unaffected.

The consequence worth stating explicitly: **the sync/async boundary is
essential complexity that no rewrite removes.** User threads will always park
and be woken; io pages will always be claimed by threads that cannot await.
What the rewrite changes is *where* that boundary lives and *how many times it
is implemented*. Today it is implemented ad hoc roughly nine times in the net
path alone. The target is twice, as reusable primitives:

- thread -> runtime: a cheap `block_on_sync(future)` that polls with a
  thread-parker waker (`SysCpu::wait`/`wake` on the calling thread's handle) —
  no `LocalRuntime`, no TLS, no allocation beyond the future itself;
- runtime -> thread: a `SyncWaiter`/semaphore a task can signal (the futex
  protocol `EventSourceManaged` already uses, written once and tested).

That is precisely the surviving, load-bearing subset of today's "ugly" code —
promoted into `moto-async`, named, and shared with `rt_fs` (whose
`blocking_run` gets cheaper as a side effect).

## What the rewrite actually replaces (and what it must not touch)

Keep unchanged:

- the posix FD table and `PosixFile` dispatch;
- the poll *registration model* and the mio event-generation *semantics*
  (`maybe_raise_events`, close tombstones, timeout-returns-0) — ad-hoc-looking
  rules that are in fact reverse-engineered mio test semantics, i.e. encoded
  compatibility knowledge. The registry's *wait plumbing* is a different story
  — see the dedicated section below;
- the data-path structures: `pending_tx` with marker messages and late length
  binding, caller-thread copies in `read`/`write` (moving copies onto the
  runtime thread would serialize all sockets of a channel through one core —
  bulk RX was measured bilaterally CPU-bound, the client side at 91-94%),
  multi-page TX (A/B-settled twice), single-page RX;
- thread-per-channel (the scaling rationale in `rt_net.rs:466` still holds;
  consolidation with the FS thread is a separate, later decision);
- warm-CPU placement: the io thread stays a wake target, not a swap target
  (measured +11 usec on set_nodelay when swapped).

Replace:

- `io_thread()`'s loop, park protocol, and carry/deferred plumbing become a
  `LocalRuntime` hosting two long-lived tasks per channel: an rx task
  (`conn.recv()` inline-dispatching to the same per-stream
  `process_incoming_msg` handlers) and a tx task (drain `send_queue`, claim
  markers, wake parked writers). The `deferred_msgs` mechanism dissolves:
  a close message on a full queue becomes a task that awaits send capacity —
  the `todo!` in `NetChannel::drop` and both `unwrap()` panics become
  ordinary awaits.
- `legacy_resp_waiters` + `response_handlers` collapse into one
  `BTreeMap<req_id, oneshot::Sender<Msg>>` owned by the rx task; sync callers
  do `bridge::block_on_sync(rx)`; nonblocking connect/accept completions are
  tasks awaiting the same oneshots.
- `send_waiters`/`page_waiters`/`write_waiters` become `SyncWaiter` lists
  signaled by the tx task (same wake points as today, one implementation).
- Read timeouts keep their current caller-side shape (park with deadline); the
  io runtime itself needs no timers today, and gets a correct timer wheel for
  free the day it does (e.g. client-side connect timeouts, DNS retries).
- `Registry::wait`'s delivery plumbing and the unmanaged-handle path are
  rewritten onto the same primitives — see the next section.

## The poll registry: async plumbing under a mio veneer

(Revised 2026-07-19 after review: the first version of this analysis
recommended leaving the `Registry` untouched. That conflated two layers that
deserve opposite treatment.)

The registry is really three things:

1. A **registration data model**: many-to-many `(source, registry, fd) ->
   (token, interests)`, with per-source supported-interest masks.
2. **Event-generation policy** — the mio-compat rules: `maybe_raise_events`'
   state-dependent event synthesis, close tombstones, `READ_CLOSED` ordering
   relative to still-queued RX bytes, `poll_wait` returning 0 on timeout, the
   listener-accepts-WRITABLE-registration quirk.
3. **Delivery/wait plumbing**: `Registry::wait`'s loop with its two readiness
   paths — the managed push path (the net io thread calls `on_event`, which
   inserts bits into the registry's map and `SysCpu::wake`s the parked
   poller) and the unmanaged pull path (the `poll_wait` caller itself
   `SysCpu::wait`s on the `SysHandle`s of ChildStdio/ChildFd sources and
   converts level to edge on wake).

Layers 1 and 2 are compatibility knowledge and survive any rewrite untouched.
Layer 3 is the same hand-rolled-protocol class the rest of this document
proposes to retire, and on re-examination it should be retired with the rest:

- The `wait_handle` protocol (store handle, re-check events, wait, clear) is
  one more manually derived lost-wakeup dance — and its single `wait_handle`
  slot is only correct because mio's `Poll::poll(&mut self)` happens to
  serialize callers per registry. The ABI itself does not enforce that; two
  concurrent `poll_wait` calls on one registry silently clobber each other's
  wakeups today.
- "Park this thread until readiness" is currently implemented three separate
  ways: the `EventSourceManaged` futex pair (used only by blocking UDP,
  `rt_udp.rs:192/290`), TCP's per-stream `rx_waiter` thread-handle slot, and
  the registry `wait_handle`. All three are the same concept — precisely the
  `SyncWaiter` bridge primitive, written three times with three sets of race
  reasoning.
- The unmanaged path hard-codes what a readiness source can *be*: either a
  kernel `SysHandle` the polling thread can wait on, or a push from the net io
  thread. Readiness that is neither — an FS completion arriving as an
  io_channel message, a DNS reply, any future service — cannot feed a registry
  at all. This is the structural reason pollable files / `O_NONBLOCK` FS are
  `E_NOT_IMPLEMENTED`, not an oversight waiting for spare time.

Target design: a registry keeps its registration model and becomes, in
delivery terms, an **event sink**. Sources push `(token, bits)`; `poll_wait`
is `bridge::block_on_sync` over the sink with the deadline on the parker wait;
`poll_wake` pushes a synthetic event. The feeders:

- **Net sources push exactly as today**, now from the task-based channel
  runtimes: one push, one `SysCpu::wake` to the parked poller. This path is on
  tokio's critical latency path (every tokio wakeup transits `poll_wait`), so
  it must not gain a hop; routing net events through an intermediary poll task
  would regress RR and is explicitly ruled out.
- **Unmanaged `SysHandle` sources move off the caller thread**: a core IO
  runtime awaits them as `SysHandleFuture`s (the executor already owns
  `E_BAD_HANDLE` semantics), runs the owner's level-to-edge
  `check_interests`, and pushes into the sink. This adds one thread hop on
  paths where it cannot matter (child stdio, process exit) and deletes the
  per-wait handle-list rebuild and the bad-handle special-casing from
  `Registry::wait`.
- **New source kinds become trivial**: the FS runtime pushes readiness for
  nonblocking files; timers, DNS, and future services push like any other
  task.

The "core IO runtime" is the consolidation point the FS thread already hints
at: one lazily created runtime thread per process hosting the FS client,
unmanaged-handle waiting, and the stdio relays (today a dedicated OS thread
per inherited child pipe; as tasks they cost nothing), with net channels
keeping their own runtime threads.

The second-order payoff: once readiness is task-fed internally, the poll ABI
becomes just one *consumer* of it — the mio compatibility view. A future
Motor-native reactor (a tokio reactor backend that skips mio emulation
entirely) can await the same readiness futures directly. That is the vdso-side
counterpart of the `moto-io::net` end-state: the async model is the
implementation, and epoll-style polling is a veneer for the clients that need
it, rather than the substrate everything else is built on.

What this does not change: layer 2. `maybe_raise_events`, the tombstone rules,
and the mio-quirk allowances stay rule-for-rule; the on-image mio-test suite
is the gate that they did.

## Long-term benefits

1. **One concurrency model across the OS.** sys-io, rt_fs, and rt.vdso net
   currently span three models. Every future contributor (and every future
   debugging session) pays for that. After the rewrite, "how does blocking
   work on Motor" has one answer: `SysHandle` futures + `LocalRuntime` +
   the sync bridge.
2. **Structural elimination of the lost-wakeup bug class.** The mystery
   fences, the "sad story" lock-hold rule, the 2024 asserts, the debug
   timeouts in every blocking read — these are symptoms of re-deriving waker
   semantics per call site. Futures centralize that reasoning into primitives
   that sys-io has been hardening since 2025 (lost-wakeup fix, timer
   cancel-on-drop, spawn boxing).
3. **Feature velocity where it is currently blocked.** Concretely unlocked:
   graceful channel teardown; accept re-posting under backpressure; pollable
   files / `O_NONBLOCK` FS (structurally blocked today — the registry's feeder
   model cannot express FS readiness at all; see the poll registry section);
   stdio relay threads becoming tasks; UDP multicast; an async in-vdso DNS
   client; process-exit readiness without dedicated waits. Each is a task or
   an await in the new model, and a new bespoke protocol in the old one.
4. **The strategic payoff: `moto-io::net`.** Today the client-side TCP state
   machine (pending-accept queues, rx-message ordering, shutdown semantics,
   pending-TX protocol) exists only inside the vdso, unreachable by native
   code. Extracting it as `moto-io::net` — the natural stage 2 once it runs on
   moto-async — gives Motor OS a canonical async net client usable by native
   async applications, by future system services, and eventually by a native
   tokio reactor backend (replacing mio emulation for Motor-native builds of
   tokio apps). FS already followed exactly this trajectory
   (`moto-io::fs` -> `rt_fs` veneer); net converging on it makes the vdso
   what it should be long-term: a thin POSIX-compatibility shim over native
   async services, ~all of whose logic is reusable and testable outside the
   vdso.
5. **No new footprint cost.** moto-async and futures are already in the vdso
   binary via rt_fs; the marginal code-size cost is near zero. Thread count
   per process can only go down (a later option: small processes sharing one
   IO runtime thread for FS + first net channel).

## Costs and risks

1. **Performance regression risk on a heavily tuned path.** This is the main
   risk. ~20 measured optimization rounds live in the net client; several wins
   (page_waiters, wake folding, marker late binding, inline dispatch) are
   exactly in the code being restructured. Mitigations: the "keep unchanged"
   list above; rnetbench A/B with per-phase self-reporting after every stage
   (the harness already exists and its baselines are recorded); the on-image
   systest / mio-test / tokio-tests suites as semantic gates. Kill criterion:
   if after tuning, a stage still regresses bulk TX/RX by >5% or RR by more
   than ~5 usec, stop at the previous stage (the hybrid is a valid resting
   point — control plane async, data plane as today).
2. **Executor overhead on the hot loop.** Two specific hazards, both
   addressable up front: (a) the current io thread folds the sys-io wake into
   its sleep syscall (`SysCpu::wait` with a wake target); `LocalRuntime`'s
   wait does not support folding, so without an executor extension every
   io-thread sleep cycle gains a syscall — likely a visible RR regression.
   (b) per-message allocations/spawns are forbidden (2048-byte task cliff,
   N6 lesson); the design uses only long-lived tasks, so this is a discipline
   to keep, not a cost to pay.
3. **moto-async gaps** (all small, all pay off for sys-io too — see next
   section).
4. **Rewrite-introduced semantic bugs** of the class the N7 RX-stall bug
   exemplified (a missing notify surviving until a specific traffic pattern).
   The mio/tokio suites catch protocol-visible breakage; rnetbench catches
   throughput-visible breakage; the staged plan keeps each diff reviewable.
5. **Effort.** Roughly: groundwork ~1 stage, io-thread conversion ~1-2,
   RPC conversion ~1, poll-registry plumbing (event sink + core IO runtime,
   independent of the net stages once the bridge exists) ~1,
   cleanup/extraction ~1-2 — each stage VM-verified. Meaningful, but bounded,
   and the codebase has done larger staged migrations recently with the same
   harness.

## Prerequisites in moto-async

- `block_on_sync` (parker-waker poll loop, no runtime) and `SyncWaiter` —
  the two bridge primitives; port `rt_fs::blocking_run` to them as the first
  consumer and validation.
- Wake-target folding in the executor wait path (an API for "fold this wake
  into the next sleep syscall"), so the converted io thread keeps today's
  syscall count.
- A multi-waiter notify (or documented composition), since `LocalNotify`
  panics on concurrent waiters.
- Worth fixing opportunistically: the `futures::stream::for_each_concurrent`
  incompatibility noted in sys-io (`net.rs:220`) — unresolved, it hints at a
  waker-contract subtlety in the executor that a second major consumer would
  rather have understood than inherited.

## Alternatives considered

- **Status quo.** Zero cost now; permanently three concurrency models, the
  bug class stays structural, the TODO panics stay, and the client net stack
  stays locked inside the vdso. On a multi-year horizon this is the expensive
  option.
- **Permanent hybrid** (control-plane RPCs on moto-async, data plane
  hand-rolled). Captures maybe half the correctness benefit at a third of the
  cost, but freezes two models side by side in one file forever. Acceptable
  as a fallback resting point if stage benchmarks fail, not as a target.
- **Jump straight to `moto-io::net`** (write the native client from scratch,
  then re-veneer the vdso). Cleanest end-state, but it front-loads all risk:
  the tuned data-path behavior would have to be re-derived rather than
  preserved, and there is no intermediate shippable state. The staged
  in-place conversion reaches the same end-state with benchmarks green at
  every step.

## Verdict

The hand-rolled vdso runtime was the right call when it was written — it
predates a usable moto-async. It is now the odd one out in its own binary:
FS beside it and sys-io across the channel both run the model it avoids, the
executor has been production-hardened by exactly the workload the vdso client
mirrors, and the crate is already linked in. The recurring cost of the status
quo (a structural lost-wakeup bug class, panicking backpressure TODOs, three
models to hold in one head, and a net client no native code can reuse) is
permanent; the cost of the rewrite is one-time and gated by an unusually good
measurement harness. On a multi-year horizon: re-implement, in stages, with
the data-path design preserved and the moto-async groundwork done first.
