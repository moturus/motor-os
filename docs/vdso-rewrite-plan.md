# Re-implementing the rt.vdso runtime on moto-async: implementation plan

2026-07-19. Companion to `vdso-rewrite-analysis.md` (the decision) and
`vdso-rewrite-design.md` (the end state). This document sequences the work.
The design doc is normative for target behavior; where a step preserves
today's behavior, the current code is the specification.

## Status (2026-07-20, checkpoint 3 root-caused; bench remains)

Stages 0, A, B, and C are complete on `vdso-rewrite`; stage D's
implementation is landed (D1-D5). Full x5 (flake checkpoint 3) reproduced the
tokio loopback freeze on run 1 and root-caused it: the D4b flip's auto-merge
silently reverted the 42e1359 rx-task self-deadlock fix, and `812e7da`
restores it (60/60 warm tokio-tests, was a run-1 freeze). That freeze — not a
stdio hang — was the checkpoint-3 target all along. The stage-D gate still
needs full x5 re-run on `812e7da` plus bench (kill checkpoint 2). One stage-C
gate metric still sits at the kill boundary (below), the review's open
question.

- **Checkpoint 3 / flake fix** (`812e7da`): `mdbg print-stacks` on a frozen
  VM (all threads InWait) showed `channel_runtime` deadlocked in
  `tcp_listener_dropped`'s `lock_contended` mid-`dispatch_incoming`, `main`
  parked in `TcpListener::bind` awaiting a bind reply the wedged rx task
  cannot deliver — the exact 42e1359 signature. `git show a9f899f` confirmed
  the D4b auto-merge deleted 42e1359's `upgraded_listeners` deferred drop and
  restored the `return`-under-lock form, so a last-ref `TcpListener::drop`
  re-locks `tcp_listeners` on the rx thread and self-deadlocks. The fix
  re-applies the deferred drop; the a9f899f revert was audited to this one
  pattern (the other removals are intended D4b retirements). The earlier
  "~1/37 stdio hang" reading was wrong — it was this freeze surfacing at the
  tokio-tests output, where block-buffered stdout hid the final
  `tokio-tests PASS` and made the freeze look like a lost stdout tail.

- **D5** (`c1f4ff8`): blocking `UdpSocket::recv_or_peek_from`/`send_to`
  flip onto `UdpRecvFuture`/`UdpSendFuture` via the shared
  `block_on_recheck` (now `pub(super)`), woken by per-socket
  `rx_wakers`/`tx_wakers` at the RX / TX-ack points. With UDP off the
  futex, the `EventSourceManaged` readable/writable futex wait/wake
  protocol is retired (UDP was its last user); `on_event` is now purely
  the poll-registry notification, and the registration side of managed
  sources stays (TCP and UDP both use it for mio readiness). Suites pass:
  systest UDP suite + full x3 to `PASS`, mio-test ALL PASS (incl. the
  `udp_socket` edge-triggered tests), tokio 2/2.

- **Stage D (through D4b)**: D1 (`9d993d5`, RPC oneshot map), D2a/D2b
  (`f5c3beb`/`b5a29e0`, RpcWaiter + blocking accept/connect await
  oneshots), D3 (`da94974`, send/page waiters as `SyncWaiter` lists),
  D4a (`bdfbc97`, read/write future machinery beside the old path),
  D4b (`a9f899f` flip + `23ab3ac` systests). The flip drives blocking
  read/write through `block_on_recheck` (`block_on_sync_deadline` capped
  at TX 500ms / RX 5s, the old debug-timeout resilience) and retires
  `rx_waiter`, `page_waiters`, and the `dispatch_incoming` wake-handle;
  the `rt_net.rs` fences stay one more step. Suites pass (all net
  systests, mio-test, tokio-tests 5/5); a 2 MB slow-reader backpressure
  systest proves the write future's retract-and-recopy is byte-exact.
  The tokio "flake" was the rx-task self-deadlock, fixed `42e1359` — but
  this flip's auto-merge silently reverted that fix, resurfacing the freeze
  until `812e7da` (checkpoint 3 above). Two D4b side-findings: (1) `666bcf0`
  — sys-io RX robustness: a client vanishing under backpressure made
  `alloc_page().await.unwrap()` crash sys-io (all networking down); now
  a graceful break. (2) The "rare NET-INDEPENDENT stdio/process-spawn hang"
  logged here was a mis-read of the same tokio freeze at the tokio-tests
  output tail (block-buffered stdout); checkpoint 3 resolved it as the
  `812e7da` self-deadlock, not a stdio-relay bug. D4b bench gate still owed.

- **Stage C** (`963e7ca..` + two tuning commits): C1-C3 landed as
  planned; the channel thread is a `LocalRuntime` hosting the C1 rx/tx
  task bodies, the `io_thread_running`/`io_thread_wake_requested` park
  protocol and `deferred_msgs`/`restage_deferred_msgs` are deleted, and
  guaranteed sends from the runtime thread await a send-room
  `LocalNotify`. Two C2 review/tuning findings, both fixed on the
  branch: the old sleep-edge send-waiter release had to move into the
  tx task's park poll (a sender enlisting between drain and park was
  otherwise stranded), and the drained-edge `wake_driver()` had to stay
  explicit per design 5.2 — folding it into the A6 slot alone cost ~9%
  of default-buffer bulk TX (sys-io idled until the park committed).
  A 16-pass linger before the tx park (standing in for the old
  `wake_requested` hysteresis) recovered most of the rest.

  Stage gate (paired same-window release A/B vs the stage-B tip,
  4 rounds each, medians): default RR 123.5 -> 126.3 usec, b64k RR
  145.3 -> 134.6 usec; bulk b64k TX +13.1%, b64k RX +5.0%, default RX
  +4.7%, **default TX 310.9 -> 293.2 MiB/s (-5.7%)** — at the kill
  bound on the metric with the widest run-to-run spread (distributions
  overlap; parity with the stage-B gate-day reference of 295.4). Three
  of four bulk metrics improved; the review decides whether the kill
  criterion is satisfied in spirit. FS smoke release 239/241 mbps vs
  236/231 stage-B reference. Syscall shape: client wake counts back at
  stage-B levels, client waits +20% (parks replacing the old hot spin
  — the executor owns sleeping now), the A6 fold present at every park.
  full x5 (debug): 4/5 green; the hang was mio-test `tcp::test_write`
  (missed WRITABLE, client-side, ssh alive) — a new site in the same
  suspected wake-protocol family (`write_waiters` is D3 delete
  territory), and 30/30 green on a warm mio-test loop after.

**Flake status after stage C**: the tokio loopback freeze reproduced in
warm loops at today's elevated ambient rate on BOTH the C2 image and
the stage-B image (iter 11/1 vs iter 1, same window) with the same
flat-counter total-freeze signature — stage C exonerated by A/B; the
c2-1 full-test hang matched the pre-existing sys-io-side wedge
fingerprint (socket dispatch silent amid teardown churn, device task
alive). New live-forensics facts: during the client-side freeze ssh
stays up and a second tokio-tests run on the same VM passes, so the
wedge is per-process client state, not sys-io; the io_channel ring's
WaitingToRecv/WaitingToSend flags plus kernel signal latching cover
both C2 await edges. The stage-D deletions (rx_waiter, write_waiters,
futex protocol) remain the prime suspects, with checkpoint 3 the
mandatory root-cause point.

- **Stage 0** (`344191b` plus the uncommitted watchdog harness): baselines
  recorded in `vdso-rewrite-baselines.md`; 10 wrapped runs (one hang in
  the boot/ssh window, one early ssh failure).
- **Stage A** (`2159e69..edfcc5c`): A1-A8 landed as planned; A7's outcome
  was an executor fix (timer/SysHandle wakes under combinators). Stage
  gate passed.
- **Stage B** (`73bd747..f5fa0c3` plus four fix commits): B1-B6 landed as
  planned. The flake checkpoints caught three real bugs beyond the B6
  step itself, all fixed on the branch:
  - `4ed03da` — pre-existing: `ChildStdio::read` reported EOF while the
    ring still held a fast-exiting child's final output; exposed once B4
    delivered the closed flag promptly. No-delay tail smoke now 20/20.
  - `e27f3e1` — B6 regression: the stdio spinlock was held across
    blocking pipe ops; the single-threaded relay runtime hard-spun on it
    and froze `rt_process::spawn` before waking the child (tokio-tests
    hung 3/3 at checkpoint 2 until fixed).
  - `3900a7e` — pre-existing moto-async bug: the kernel queues wakers
    even while a thread is awake, so `SysCpu::wait` can report a handle
    from an earlier wait epoch; the `unwrap` on the future-map lookup
    panicked sys-io live (0xbadc0de, VM down) under ssh churn.
  - `e123bc1` — pre-existing, unmasked by B6's prompt EOF delivery:
    `input_listener` threads in ten binaries spun at 100% CPU on stdin
    EOF (a dead stdin pipe read returns `E_BAD_HANDLE` with no syscall,
    and std's blanket `is_ebadf` maps any stdin error to `Ok(0)`).
    `rnetbench --server` always burned one vCPU this way, polluting all
    pre-fix bench sessions. Follow-ups flagged: `SelfStdio::read` should
    return `Ok(0)` at EOF itself; the std shim's `is_ebadf` blanket
    deserves a real mapping.

  Stage gate passed on a paired, same-window, spin-free A/B (stage-A tip
  plus `e123bc1` cherry-pick vs branch tip; release, 3 rounds each).
  Medians: RR default 125.4 -> 126.8 usec, RR b64K 153.1 -> 152.9 usec;
  bulk deltas -2.5%..+4.7% — all within the kill bounds. FS smoke
  (release): 236 write / 231 read mbps, recorded as the stage-B
  reference. Unpaired cross-session bulk comparisons falsely tripped the
  kill criterion twice; the measurement discipline of section 1 (paired
  runs, same window) is mandatory for every later gate.

**Flake status: ROOT-CAUSED AND FIXED (in D, commit "fix rx-task
self-deadlock dropping a listener under its lock").** The premise below
that it was "a lost wake" was wrong; it is a **self-deadlock**, which is
why every wake-protocol suspect (and, later, every thread-park timeout
bound) came back clean. `dispatch_incoming()`, routing a packet with no
live stream, iterated `tcp_listeners.values()` under the `tcp_listeners`
lock and upgraded each `Weak<TcpListener>`; when an upgraded Arc was a
listener's last strong ref (owner dropped it concurrently), dropping the
temporary inside the loop ran `TcpListener::drop -> tcp_listener_dropped
-> tcp_listeners.lock()`, re-locking the mutex the rx task already held.
The rx task wedged, the channel died, and any socket op on it hung.
Diagnosed by attaching **`mdbg print-stacks`** to a frozen VM and
symbolizing against the unstripped `build/obj/*/rt` and
`build/obj/tokio-tests/*/tokio-tests` (`addr2line`): `channel_runtime`
was parked in `tcp_listener_dropped`'s `lock_contended`, `main` in
`TcpListener::bind`. Fix: defer dropping the upgraded listener Arcs until
after both map locks release. 60/60 warm tokio-tests loop green.

Historical fingerprint (kept for context): 3/5 green on the final
series; both hangs one pre-existing signature. The freeze is entering
tokio's loopback-socket tests (`test_socket_from_blocking`,
`test_local_set_client_server_block_on`, `test_io_driver_called_when_under_load`)
-- the tests *after* the last printed PASS, which earlier notes
misattributed to `test_sleep_from_blocking` -- with every thread blocked
and zero syscalls while the VM and sys-io stay healthy; present since at
least the stage-A series.

## 1. Process rules

- **Branch.** All work happens on the `vdso-rewrite` branch; `main` is not
  touched until final acceptance (stage G). There is no production soak
  between stages — all confidence comes from the gates below.
- **Step size.** The unit of work is a *step*: one commit, target under 300
  changed lines. Pure-refactor (noop) steps are encouraged whenever they make
  the next behavioral step smaller. Two exemptions, always flagged in the
  commit message: mechanical crate moves (stage F) and, if it cannot be split
  further, the C2 executor flip.
- **Green discipline.** Every commit builds (`make all`). Suites pass at every
  marked gate; between gates a step may temporarily regress something only if
  its commit message says exactly what.
- **Tests ride with their step.** A behavioral step lands with its test when
  one is feasible (moto-async and vdso logic is Motor-only, so new tests go
  into `src/sys/tests/systest`); tests-only commits are fine.
- **Gate vocabulary.**
  - `suites` — on-image `systest`, `mio-test`, `tokio-tests` over ssh, debug
    build. Run for every behavioral step; noop steps need build + spot-check.
    Long systest pieces (concurrent FS flush, FS smoke, and similar) may be
    temporarily shortened or disabled to speed up per-step runs — each trim
    marked `TODO(vdso-rewrite)` — but the full untrimmed systest runs at
    every stage gate, and all trims are reverted before stage G.
  - `full xN` — N consecutive green runs of `src/tests/full-test.sh` under
    the stage-0 watchdog wrapper. Expensive; used at flake checkpoints and
    stage gates only.
  - `bench` — on-image rnetbench A/B against the stage-0 baselines: RR, bulk
    TX/RX, default and `-b64K`; FS smoke numbers for FS-adjacent steps.
    Measurement discipline from the 2026-07 series applies: compare the same
    run number within a boot, treat RR as the host-steal gauge, repeat runs
    rather than trust one.
  - `release` — `full-test.sh --release` in addition to the debug run.
- **Kill criterion** (restated from the analysis): if, after tuning, a stage
  still regresses bulk TX/RX by more than 5% or RR by more than ~5 usec, stop
  at the previous stage. The post-C and post-D states are coherent hybrids
  (executor swapped / protocols partially retired, data-path design intact)
  and are valid resting points to merge.

## 2. The full-test.sh flake is a first-class deliverable

Acceptance requires `src/tests/full-test.sh` to pass reliably. Today it
occasionally hangs in tokio-tests' edge-wait paths, more rarely elsewhere.
Two consequences for sequencing:

1. **A gate that flakes cannot gate.** Stage 0 wraps the script in a watchdog
   that captures state on hang and records a baseline flake rate, so later
   "did my change cause this?" questions have an answer.
2. **The prime suspects are the protocols this rewrite deletes**: the
   registry `wait_handle` delivery protocol (single-slot, clobberable) and
   the net-side wake protocols (`rx_waiter`, `write_waiters`, the
   `maybe_raise_events` call sites) — the code with the documented
   lost-wakeup scars (`rt_net.rs` fences, the `rt_tcp.rs` "sad story" rule
   and 5-second debug timeout). The plan therefore rewrites poll delivery
   (stage B) *before* the net conversion, and re-checks the flake at three
   checkpoints: after B2 (delivery), after B6 (relays), after D5 (all net
   wake protocols gone). If the hang still reproduces after stage D, feature
   work stops and the hang is root-caused on the new, simpler machinery
   before stage E.

Stage ordering rationale, beyond the flake: the core IO runtime built in
stage B is a dependency of net teardown (design 5.5 hands channel joins to
it), and stage B is the smaller conversion — it exercises the new bridge
primitives end-to-end before the riskiest stage begins.

## 3. Stage 0 — baselines and flake characterization

*Status: complete (`344191b` + scratchpad harness).*

| Step | Content | Gate |
|---|---|---|
| 0.1 | Watchdog wrapper for `full-test.sh` (scratch script, uncommitted): global timeout; on hang, capture `/tmp/full-test.log` and, if ssh still answers, `ps`, `stats get`, and which suite/test was running. | — |
| 0.2 | Baseline flake rate: at least 10 wrapped runs (debug); record failure count and hang sites. | — |
| 0.3 | Record rnetbench + FS smoke baselines for this rig and branch in `docs/vdso-rewrite-baselines.md` (committed): RR, bulk TX/RX default and `-b64K`, several runs each. | — |

If 0.2 captures evidence pointing outside the vdso (sys-io, tokio itself,
the test harness), the sequencing bet in section 2 is re-assessed before
stage B.

## 4. Stage A — moto-async groundwork

*Status: complete (`2159e69..edfcc5c`); gate passed.*

Design sections 3.1–3.6. Every primitive lands with a systest exercising its
race edges. A5 changes `LocalRuntime` under sys-io's feet — it is the one
step here with real regression surface, and gets its own bench gate.

| Step | Content | ~Lines | Gate |
|---|---|---|---|
| A1 | `sync_bridge.rs`: the three-state parker state machine + `SyncWaiter` (`wait(deadline)`, `signal`); tests for signal-before-wait, spurious wakes, deadline. | 200 | suites |
| A2 | `block_on_sync` on the same parker: cached per-thread waker state, ready-future fast path (no syscall), debug-assert against use on a runtime thread. | 150 | suites |
| A3 | `block_on_sync_deadline` returning `Result<T, F>` (timed-out future handed back for progress extraction); test with a synthetic partial-progress future. | 100 | suites |
| A4 | `LocalNotify` multi-waiter: waiter list, `notify_one`/`notify_all`. Decision: extend in place rather than a composition — one primitive, one proof. | 120 | suites |
| A5 | `LocalRuntime` run-state (polling / committing-to-park / parked) + `MotoWaker` wake elision with recheck-after-commit (design 3.4). sys-io inherits this immediately. | 180 | suites, bench (neutral-or-better; compare wake counters) |
| A6 | `set_wake_on_sleep` deferred-wake slot with the exactly-once contract (design 3.3). No consumer yet — behavior-noop until C2. | 100 | suites |
| A7 | `for_each_concurrent` debt (sys-io `net.rs:220`): timeboxed root-cause; outcome is an executor fix or a documented waker-contract rule (design 3.6). | small | suites |
| A8 | Port `rt_fs::blocking_run` to `block_on_sync`; delete the throwaway-`LocalRuntime`-per-call pattern. First real consumer. | 100 | suites, bench (FS smoke, same-run-number) |

Stage gate: `full x3` + bench. Flake status noted; no change expected yet.

## 5. Stage B — poll delivery rewrite, core IO runtime, stdio relays

*Status: complete (`73bd747..f5fa0c3` + `4ed03da`, `e27f3e1`, `3900a7e`, `e123bc1`); gate passed. See Status section.*

Design sections 4, 6, 7.2. Registration model and mio event-generation
semantics (layer 1–2) are untouched throughout; only delivery changes, so
`mio-test` is the semantic gate at every step.

| Step | Content | ~Lines | Gate |
|---|---|---|---|
| B1 | Noop: split `Registry::wait` into collect vs wait phases; isolate the `wait_handle` protocol behind one seam. | 100 | suites |
| B2 | Replace delivery: sink `push(token, bits)`; `poll_wait` = collect-or-park on the bridge parker with the ABI deadline; one-slot poller fast path + overflow list (multi-poller now correct); `poll_wake` pushes a synthetic event. `on_event` call sites unchanged. Delete the `wait_handle` protocol. Add a multi-poller `poll_wait` systest. | 280 | suites, **full x5 (flake checkpoint 1)** |
| B3 | Generalize the FS runtime thread into the core IO runtime (`rt::io_runtime`): rename, shared spawn access for other residents; FS client untouched. | 120 | suites |
| B4 | Unmanaged-source readiness tasks on the core runtime: per-`EventSourceUnmanaged` task (`SysHandleFuture` await, `check_interests`, push into sinks; `E_BAD_HANDLE` -> `on_handle_error` + exit). Delete `Registry::wait`'s handle-list rebuild and bad-handle special-casing. | 250 | suites (systest stdio_pipe + process tests) |
| B5 | Relay runtime (`rt::stdio_relay`, lazily created, exits when the last inherited-stdio child goes away) + stdout/stderr relay tasks (await-readable / copy / await-writable). | 200 | suites |
| B6 | Stdin relay task: ownership claim of the stdin reader + overflow stash (replaces holding the `SelfStdio` spinlock for the child's lifetime); delete the 1-usec `read_timeout` polling hack, the per-child relay threads, and the `StdioKind::get` unsafe self-reference. | 250 | suites, interactive child-pipeline smoke over ssh, **full x5 (flake checkpoint 2)** |

Stage gate: bench — RR especially; `poll_wait` is on tokio's critical
latency path and must keep its one-push-one-wake shape.

## 6. Stage C — net executor swap

*Status: complete (see Status section); gate run, one metric at the kill
bound pending review.*

Design 5.2, first half: the channel thread becomes a `LocalRuntime` hosting
rx/tx tasks; every hand-rolled *waiter* protocol survives this stage
unchanged, called from tasks instead of the io thread. Data-path rules
(section 8 of the design) are in force from here on.

| Step | Content | ~Lines | Gate |
|---|---|---|---|
| C1 | Scaffolding, mostly noop: async recv wrapper (`conn.recv()`, on `NotReady` await the connection's `SysHandleFuture`) + rx/tx task bodies wrapping today's `io_thread_poll_messages` / `io_thread_send_messages` logic; landed unused. | 150 | build |
| C2 | The flip: `io_thread()` (`rt_net.rs`) becomes `LocalRuntime::block_on` over the rx and tx tasks (thread name `rt_net::channel_runtime`, still a sys-io wake target, never a swap target). Delete the `io_thread_running`/`io_thread_wake_requested` double-swap park protocol. Caller-side sends now wake the runtime — elided by A5 when it is mid-batch. tx task sets the A6 deferred-wake slot on sleep edges; explicit `wake_driver()` at batch boundaries and the 32-message batch limit (as `yield_now`) stay. | 300+ (flagged; split flip/delete if possible) | suites, bench |
| C3 | Retire `deferred_msgs`/`restage_deferred_msgs`: the tx task awaits send room (A4 notify) instead. | 100 | suites |

Stage gate: `full x3` + bench = **kill checkpoint 1**. Verify syscall parity
via stats counters (wakes/s as in the N3b measurements): idle cycle must stay
one `SysCpu::wait` with the sys-io wake folded in.

## 7. Stage D — net protocol retirement

Design 5.2 second half + 5.3. Each hand-rolled protocol is replaced by its
mapped primitive (design section 9), one commit per protocol.

| Step | Content | ~Lines | Gate |
|---|---|---|---|
| D1 | RPC map: `Mutex<BTreeMap<req_id, oneshot::Sender<Msg>>>` replaces `legacy_resp_waiters`; sync RPCs = insert-before-queue + `block_on_sync(rx)`. | 200 | suites |
| D2 | `response_handlers` -> control tasks awaiting the same oneshots (connect and accept completions). | 200 | suites |
| D3 | `send_waiters`/`page_waiters` -> `SyncWaiter` lists signaled by the tx task; `write_waiters` semantics unchanged, driven via `maybe_can_write`. | 150 | suites |
| D4a | Noop-ish: TCP read/write future machinery (woken by the rx task on RX data or state change), landed beside the existing path. | 150 | build |
| D4b | Flip blocking TCP reads/writes to `block_on_sync_deadline` over the D4a futures. `SO_RCVTIMEO`/`SO_SNDTIMEO` ride the parker deadline; progress extraction per design rule 7 (partial write returns `Ok(written)` on timeout — `rt_tcp.rs:1321` behavior preserved). Delete per-stream `rx_waiter`, the 5-second debug timeout, the hold-the-lock "sad story" rule, and the `rt_net.rs` mystery fences. Add SO_*TIMEO partial-progress systests + a concurrent-readers (dup'd FD) test. | 280 | suites, bench |
| D5 | UDP: blocking recv -> futures over the bridge; retire the `EventSourceManaged` futex wait/wake protocol (UDP is its last user; the registration side of managed sources stays). | 250 | suites, **full x5 (flake checkpoint 3)** |

Stage gate: `full x5` above + bench = **kill checkpoint 2**. RR is the
sensitive metric here (read-wake latency now flows through the bridge). If
the full-test hang still reproduces at checkpoint 3, stop: root-cause it now
on the simplified machinery before proceeding.

## 8. Stage E — lifecycle

Design 5.5 and the control-task half of 5.2: the paths that today panic or
`todo!()`. Control-plane only; bench is a sanity check, not a gate risk.

| Step | Content | ~Lines | Gate |
|---|---|---|---|
| E1 | Guaranteed sends become awaits: replace `send_msg_guaranteed`'s panic/spin paths; a drop executing on the channel's own runtime thread hands the close message to a task. Delete the `UdpSocket::drop` unwrap. | 150 | suites |
| E2 | Accept re-post under backpressure: listener control task awaits send room and re-posts; delete the `post_accept(false).unwrap()` TODO panic. | 100 | suites |
| E3 | Channel teardown (design 5.5): exit notify on last reservation release; tx drains (closes delivered), rx drains in-flight responses, runtime exits, thread joined — join handed to the core IO runtime when release happens on the channel's own thread. `NetRuntime::assert_empty` becomes meaningful. Add a channel-churn systest (connect/close past `IO_SUBCHANNELS` repeatedly; assert teardown via stats). | 280 | suites, new tests |

Stage gate: `full x3` + bench sanity.

## 9. Stage F — extraction: moto-io::net and the veneer

Design 5.1, 5.4. The seam is built in place first so the crate moves are
purely mechanical.

| Step | Content | ~Lines | Gate |
|---|---|---|---|
| F1 | In-place seam: per-socket mio-agnostic event-listener hook emitting clean readiness edges; the veneer (still same-crate) installs it and layers `maybe_raise_events` + tombstones + listener-WRITABLE on top, inline in rx dispatch — one indirect call, no task hop. | 250 | suites, bench (RR) |
| F2 | Mechanical move: channel layer (`NetChannel`, reservation, registry, runtime thread) to `moto-io/src/net/`. Textually large, semantically zero; flagged. | move | suites |
| F3 | Mechanical move: socket state machines (`TcpStream`/`TcpListener`/`UdpSocket`, `InnerRxStream`, `pending_tx`). `rt.vdso/net/` keeps only the veneer: ABI shims, `PosixFile` impls, sockopts, mio synthesis. FDs stay in the vdso (design 7.1). | move | suites |
| F4 | Native API polish: `accept`/`connect`/`read`/`write`/`try_*`/`readable()`/`writable()` per design 5.4; sink async `readiness()` output; cancel-safety audit of every data-path future (rule 7) + a timeout-storm-during-transfer systest. | 250 | suites, bench |

Stage gate: `full x3` + bench parity + vdso binary size check (expected
~neutral; moto-async and futures are already linked in).

## 10. Stage G — acceptance

| Step | Content |
|---|---|
| G1 | Dead-code sweep against the design section 9 map: grep for every retired protocol (`send_waiters` deque, `legacy_resp_waiters`, `response_handlers`, `rx_waiter`, park flags, futex protocol, `wait_handle`, `deferred_msgs`) — zero hits. Restore every `TODO(vdso-rewrite)` test trim — zero hits. |
| G2 | Full bench matrix vs stage-0 baselines, recorded in `vdso-rewrite-baselines.md`: RR, bulk TX/RX both directions, default + `-b64K`, FS smoke, debug + release. |
| G3 | Reliability: `full x10` (debug) + `full x2 --release`, all green — the acceptance bar. |
| G4 | Doc updates: mark the design doc implemented, note any deviations; merge `vdso-rewrite` into `main`. |

## 11. Contingencies

- **Kill criterion fires** (C or D): stop at the previous gated state; the
  branch up to that point is mergeable as the hybrid the analysis describes.
- **Flake survives checkpoint 3**: halt features; instrument the tokio-tests
  edge wait (watchdog + on-hang state dump) and root-cause against the new
  machinery, where every wait is one of two primitives.
- **A5 destabilizes sys-io**: revert-first (it is an isolated commit),
  re-land with the fix; nothing before C2 depends on it.
- **A step will not fit 300 lines**: prefer an extra noop-prep commit over an
  oversized diff; flag the exceptions listed in section 1.

## 12. Out of scope

Unchanged from design section 12: the stdio deep redesign, kernel changes,
vdso ABI evolution, sys-io adoption of the new primitives, small-process
thread consolidation. Follow-ups the rewrite unlocks but does not include
(design section 11): async DNS client, `O_NONBLOCK` FS readiness, pollable
`SelfStdio`, a native tokio reactor backend.
