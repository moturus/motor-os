# VDSO rewrite review

## Scope

This review covers all 78 commits after `3980c9ec735bc7a3496b1a4779b9f8c37fb5a301` (`vdso rewrite analysis`) through `ccbafc82`. The cumulative change spans 49 files, with approximately 8,146 insertions and 3,639 deletions. I reviewed the commit series, cumulative diff, design documents, and the principal call paths and lifecycle invariants. The unrelated untracked `src/bin/lorry/` tree was excluded. No builds or tests were run, and no source changes were made as part of the review.

## Findings

### 1. High: cancellation of asynchronous connect and accept can leak server-side sockets

The new native async control plane does not give cancellation a complete ownership protocol. `RpcWaiter::Connect` holds a weak stream reference, and connect-response dispatch explicitly accepts that a stream dropped during connect leaves the sys-io stream behind (`src/sys/lib/moto-io/src/net/channel.rs`, around line 501). If the future and its last stream reference are dropped before the response, the weak upgrade fails and no close request is generated. As long as the shared channel remains alive, the sys-io socket can remain allocated indefinitely.

Accept has a similar but distinct leak. `TcpListener::next_pending_accept` creates a one-shot sender/receiver and posts an accept request (`src/sys/lib/moto-io/src/net/tcp.rs`, around line 240). If that future is cancelled, `on_accept_response` can still create the pending-accept state and accepted stream, then ignore failure to send it through the abandoned one-shot (`tcp.rs`, around line 91). The accepted socket is neither handed to a caller, returned to a listener queue, nor closed. This is a fundamental mismatch between future cancellation and ownership transfer, not merely a missing error check. The protocol should define who owns every remotely created socket at each phase and arrange explicit close/rollback when delivery to the requester fails.

### 2. High: `TcpListener::drop` can deadlock the channel runtime under backpressure

`TcpListener::drop` uses the blocking `send_msg` path (`src/sys/lib/moto-io/src/net/tcp.rs`, around line 69). Incoming dispatch deliberately keeps upgraded listener `Arc`s alive until it has left listener/channel locks (`src/sys/lib/moto-io/src/net/channel.rs`, around line 440), so a concurrent application drop can make the RX runtime thread release the last listener reference. If the outgoing staging queue is full, the destructor waits synchronously for send capacity. The TX task that must create that capacity runs on the same `LocalRuntime` thread, yielding a self-deadlock.

The stream and UDP teardown paths were moved to guaranteed/nonblocking-in-context sends, apparently in response to closely related lifecycle failures, but the listener path was missed. More broadly, destructors reachable from an event-loop thread must never depend synchronously on work scheduled to that same loop.

### 3. High: cancelled system-handle futures remain registered, and the stdio relay creates an unbounded accumulation path

`LocalRuntimeInner` owns a map of system-handle futures. Dropping `SysHandleFuture` only marks its state as dropped; the registration remains until the underlying handle signals and the runtime removes the handle entry (`src/sys/lib/moto-async/src/local_runtime.rs`, around line 752). That policy becomes a concrete long-lived leak in the rewritten stdio relay.

The relay input-claim loop races a 1 ms timer against `dest.handle().as_future()` on every iteration (`src/sys/lib/rt.vdso/src/stdio.rs`, around line 214). While another relay owns stdin and the destination process stays alive, the timer repeatedly wins. Each losing handle future is dropped but remains retained in the runtime registry, producing roughly one new retained allocation/registration per millisecond until the process exits. Timer cancellation received careful cleanup, but handle cancellation did not. Registrations need an identity/token and deregistration on drop, or the relay needs to reuse one persistent handle future rather than manufacturing losing futures in a tight select loop.

### 4. High: the public async control plane can block an executor thread, while global networking state is held across slow setup

The API is async in type but not consistently nonblocking in behavior. `TcpStream::connect` invokes synchronous `send_rpc` from inside its future (`src/sys/lib/moto-io/src/net/tcp.rs`, around line 816); a full queue parks the thread polling the future. Native accept similarly falls back to blocking send outside the special channel-runtime context. This is especially surprising after moving networking into a reusable async-first library: arbitrary executor threads can be stalled by internal channel backpressure.

Channel reservation compounds this problem. `reserve_channel` takes the process-global networking mutex and, if no channel is available, calls `NetChannel::new` while still holding it (`src/sys/lib/moto-io/src/net/channel.rs`, around lines 212 and 1298). Construction calls `connect_to_sys_io`, which performs exponential-backoff sleeps for up to roughly ten seconds, may start a runtime thread, spins for startup, and eventually panics on failure. During that interval, reservations, releases, teardown, and even statistics access serialized through the same lock are blocked. Slow and fallible service connection belongs outside the global state lock, and a public library should propagate service-unavailable errors rather than panic.

### 5. High: data-path futures are functionally cancellation-safe but not resource cancellation-safe

The design states that dropping a future deregisters its waker, but TCP RX, channel TX, and UDP readiness paths append cloned wakers to vectors and the corresponding futures have no `Drop` cleanup. `will_wake` deduplication limits repeated registration by the blocking VDSO veneer because it reuses a cached thread parker, but it does not protect native async callers: repeatedly creating and cancelling tasks with distinct wakers can retain task/executor graphs until the next socket event or socket destruction.

This matters most for quiet, long-lived sockets, where the awaited event may never occur. Existing timeout-storm coverage uses the stable blocking waker and therefore cannot expose this native cancellation behavior. Waker registrations should have removable identities or be represented by a cancellation-aware waiter object.

### 6. Medium: the blocking veneer masks unresolved lost-wakeup races with periodic polling

The rewritten blocking network adapter openly documents that cross-process TX wakeup is not reliably race-free and therefore rechecks every 500 ms; RX uses a five-second recheck (`src/sys/lib/rt.vdso/src/net/blocking.rs`, around line 18). This avoids permanent hangs, but it converts synchronization failures into potentially large latency spikes and creates periodic idle wakeups. It also undercuts the architectural premise that the new notification and registry primitives close the lost-wakeup windows.

Periodic checking can be a safety net, but half-second and five-second intervals should not be the correctness mechanism. The underlying publish/register/recheck protocol and cross-process wake delivery need a precise invariant and stress coverage that can distinguish a genuine wake from timer recovery.

### 7. Medium: the extracted native API remains shaped around VDSO integration details

Every TCP listener, TCP stream, and UDP socket constructor requires an `Arc<dyn NetEventListener>`, and accepted streams require a listener factory. Yet the design says ordinary native users should not have to see or populate this hook (`src/sys/lib/moto-io/src/net/readiness.rs`, around line 45). There is no optional/default no-op path, and readiness futures currently have no native consumer.

This makes the extraction feel like VDSO internals moved behind a public module boundary rather than a stable native networking abstraction. Before treating it as a reusable API, the event hook should be private, optional, or separated into an adapter layer, and the native cancellation/error semantics should be exercised directly rather than only through the blocking veneer.

### 8. Medium: the TLB watchdog relaxation risks hiding real global stalls

The TLB shootdown wait changed from panicking after roughly one million spins to logging at one billion and panicking at one hundred billion (`src/sys/kernel/src/arch/x64/tlb.rs`, around line 86). This is a 100,000-fold increase in the terminal threshold. The path holds the global TLB message lock throughout, while the spin count is dependent on CPU and hypervisor behavior rather than elapsed time. A genuine missed acknowledgement or descheduled virtual CPU can therefore freeze memory-management progress for a very long time, and the spinning vCPU may compete with the peer that needs to run.

Replacing a sensitive watchdog with a vastly larger fixed spin count is architectural masking, not a liveness strategy. A time-based escalation policy, diagnostics that do not prolong global lock ownership, and an explicit yield/recovery approach would be safer.

### 9. Medium: the soak harness can kill unrelated host processes and cannot run safely in parallel

The stress harness uses fixed VM addressing and ports, then performs broad `pkill` cleanup matching the VM SSH target, benchmark clients, curl processes, `run-qemu`, and every `qemu-system-x86_64` process (`src/tests/stress-soak.sh`, around line 115). Although it records the QEMU PID and startup state, teardown does not use them to target the instance it created. The trap is installed before boot validation, so even an early setup failure can terminate unrelated developer VMs or test jobs.

This is a test-infrastructure ownership problem: cleanup must be scoped to resources created by this invocation. Per-run ports/state, PID-based teardown, and unique process/session identifiers are needed before the harness is safe for routine or concurrent use.

## Overall assessment

The series has substantial strengths. The staged design documentation is unusually clear; moving network state machines into `moto-io`, simplifying the VDSO into a blocking veneer, adding caller-thread copies and pending-TX ownership, introducing multi-poller wake handling, and making sys-io teardown idempotent are directionally sound. The history also shows diligent diagnosis of several difficult failures, including listener lock recursion, stale queued kernel wakers, residual stdio EOF, and sys-io backpressure crashes.

However, I would not consider the rewrite merge-ready in its current form. The central architectural risk is that ownership, cancellation, backpressure, and destructor behavior are not yet consistently defined across the new native async boundary. Findings 1 through 4 can cause persistent resource loss, event-loop deadlock, unbounded retention, or executor stalls under entirely plausible workloads. The periodic wake polling, public VDSO-shaped hooks, relaxed TLB watchdog, and unsafe soak cleanup further suggest that some failures have been contained operationally rather than resolved at their abstraction boundary. The next pass should establish explicit lifecycle state machines for every RPC-created resource, ensure all event-loop-reachable operations are nonblocking, make registration cancellation physically remove retained state, and add native async cancellation/backpressure tests independent of the blocking VDSO compatibility layer.
