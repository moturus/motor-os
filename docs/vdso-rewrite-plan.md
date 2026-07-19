# Re-implementing the rt.vdso runtime on moto-async: implementation plan

2026-07-19. Companion to `vdso-rewrite-analysis.md` (the decision) and
`vdso-rewrite-design.md` (the end state). This document sequences the work.
The design doc is normative for target behavior; where a step preserves
today's behavior, the current code is the specification.

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

| Step | Content | Gate |
|---|---|---|
| 0.1 | Watchdog wrapper for `full-test.sh` (scratch script, uncommitted): global timeout; on hang, capture `/tmp/full-test.log` and, if ssh still answers, `ps`, `stats get`, and which suite/test was running. | — |
| 0.2 | Baseline flake rate: at least 10 wrapped runs (debug); record failure count and hang sites. | — |
| 0.3 | Record rnetbench + FS smoke baselines for this rig and branch in `docs/vdso-rewrite-baselines.md` (committed): RR, bulk TX/RX default and `-b64K`, several runs each. | — |

If 0.2 captures evidence pointing outside the vdso (sys-io, tokio itself,
the test harness), the sequencing bet in section 2 is re-assessed before
stage B.

## 4. Stage A — moto-async groundwork

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
