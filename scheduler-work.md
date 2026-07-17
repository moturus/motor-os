# Scheduler / syscall / IRQ handling: analysis and improvement plan

Date: 2026-07-12. Branch: agent-tree. Analysis only — no changes made yet
(except the already-landed tickless-idle work, see "Round 0" below).

All line references are to the current working tree (with the tickless-idle
changes applied, uncommitted).

---

## TL;DR — ranked findings

| # | Finding | Type | Cost today | Fix effort |
|---|---------|------|-----------|-----------|
| S1 | Every IRQ landing in userspace fully deschedules the thread (xsave, 2×CR3, job queue round trip, xrstor) — even when nothing else is runnable — **done, Round 2** (86–96 % of uspace IRQs now fast-return; RR 2.2×, TX stabilized) | perf | ~1–3 µs direct + TLB refill (dominant) per IRQ | medium |
| S2 | Every syscall switches CR3 to KPT and back; no PCID, no GLOBAL pages ⇒ 2 full TLB wipes per syscall, 2 more per preempt/resume — **W6a done, Round 5** (kernel TLB survives CR3 writes; #PF −7 %; W6b/W6c remain) | perf | dominant hidden cost of IPC | medium–large |
| S3 | `sys_wait` always pauses, even with wakers already pending ("wait is at least a yield") ⇒ full deschedule + job round trip + possible CPU migration for a no-op wait — **done, Round 4** (22 % of waits skip the pause; RR −25 %, new all-time record) | perf | ~2×5 µs per IPC RTT | small |
| S4 | Preempted threads are re-queued to "first idle CPU by index", not their last CPU; `last_cpu` field exists but is never written ⇒ constant migrations, cold caches/TLBs — **done, Round 3** (52 % of placements now land on the warm CPU; timer IRQs −26 %; bench-neutral otherwise) | perf | unquantified, likely large | small–medium |
| S5 | xsave/xrstor (full RFBM=~0) on every uspace IRQ and every uspace #PF, even when the same thread resumes on the same CPU (the common case) | perf | ~500–1000 cyc + 2×~1 KB memory traffic per IRQ | small once S1 lands |
| S6 | Every demand page fault costs the full preempt/deschedule machinery | perf | ~2–5 µs per minor fault | medium |
| S7 | `swap` (IPC handoff) round-trips through the job queue instead of switching threads directly | perf | queue + locks + latency per message | large |
| S8 | `slow_swapgs()`: 2–3 rdmsr on every IRQ and #PF entry — **done, Round 1** (see the GS-model correction there) | perf | ~200–500 cyc per IRQ | small |
| S9 | Vector 72 is registered with irqnum 71 (`naked_irq_handler!(irq_handler_72, 71)`) ⇒ devices on vector 72 wake the wrong waiter — **fixed, Round 1** | **bug** | correctness | trivial |
| S10 | MXCSR / x87 CW are not preserved across blocking syscalls (pause/resume skips FPU entirely) ⇒ another thread's FP env can leak in — **fixed, Round 4** (saved/restored in pause/resume; systest coverage added) | **bug** (latent) | correctness | small |
| S11 | No priorities, FIFO everywhere; sys-io competes equally with bulk compute; a many-threaded process starves others | isolation | I/O latency under load | medium |
| S12 | All device IRQs (virtio MSI-X) + serial + system-time duty target CPU 0 | isolation/perf | CPU 0 saturation (seen in FS rounds) | medium |
| S13 | Per-wait heap churn: `Vec` allocs + per-object `BTreeMap` insert/remove on every wait | perf | allocs on the hottest path | medium |
| S14 | Every sched-loop iteration on every CPU does an atomic **swap** on the global `WAKE_QUEUE` and takes the global-queue spinlock every 3rd iteration even when empty — **done, Round 1** | perf | cross-CPU cacheline traffic | trivial |
| S15 | No NX (EFER.NXE never set, no XD PTE bit), no SMEP/SMAP ⇒ all user memory is W+X; kernel can execute/read user pages freely | security | policy decision | small–medium |
| S16 | Wake IPIs (`IRQ_WAKEUP`) do not preempt userspace ⇒ a cross-CPU wake targeting a busy CPU waits for the next tick (up to 10 ms) | latency semantics | tail latency under load | small (policy) |

Concern 1 from the session brief ("every IRQ and many syscalls deschedule") = S1 + S3 + S6.
Concern 2 ("every IRQ and syscall trigger xsave+xrstor") = S5 (IRQs/#PF yes; plain
syscalls actually do **not** xsave — see "FPU facts" below).
"Usual workload isolation issues" = S11 + S12 + S16 (+ S15 on the security side).

---

## Round 0 (done this session): tickless idle

Non-BSP CPUs now disarm the APIC timer when idle (`program_idle_timer()`,
scheduler.rs:303) and re-arm on userspace entry (`ensure_preemption_timer()`,
scheduler.rs:656). Idle timer IRQs: 373/s → 95/s (BSP only) on a 4-CPU VM.
Verified: systest passes release+debug; debug watchdog exempts idle CPUs.
Relevant to this plan because the invariant it introduced — *"thread in user
mode ⇒ live tick armed; the tick chain is only broken when a CPU goes idle"* —
must be preserved by every change below.

---

## Round 1 (done 2026-07-17): roadmap step 1 — W4-prep trivial fixes (S9, S14, S8)

All uncommitted, on top of Round 0. Files: `arch/x64/irq.rs`, `arch/x64/mod.rs`,
`sched/scheduler.rs`, `uspace/sysobject.rs`, plus a new `bench_page_faults()`
microbench in systest (`tests/systest/src/main.rs`).

### Changes

- **S9 (bug)**: `naked_irq_handler!(irq_handler_72, 72)` — was 71. The IDT
  registration (irq.rs:310) already pointed vector 72 at this handler; only
  the number passed to `irq_handler_inner` was wrong. No compile-time
  handler↔vector assertion added: `macro_rules!` can't paste identifiers on
  stable, so tying the fn name to the literal would need the `paste` crate or
  a proc macro — left open.
- **S14**: `process_wake_events()` now does a plain load of `WAKE_QUEUE` and
  returns if 0, instead of an unconditional atomic swap (exclusive cacheline
  acquisition per iteration per CPU). The sched loop peeks both job queues
  via atomic length counters before taking their spinlocks: the local queue
  reuses the existing `queue_length` (which had no readers until now), the
  global queue gets a new `GLOBAL_QUEUE_LENGTH` maintained on push/pop. No
  lost-wakeup risk: local-queue pushers always `wake()` *after* the
  increment, and global-queue pushers keep polling themselves (pre-existing
  "poster will pop it" invariant, post() only uses the global queue when no
  CPU is idle).
- **S8**: external IRQ vectors (36 serial, 64..=79 custom/MSI-X, 192 timer,
  193 wakeup, 194 TLB shootdown) now decide swapgs from the interrupted CS
  (`is_external_irq()` in irq.rs): swapgs iff CS.RPL == 3 — zero rdmsr on
  the hot path. Synchronous exceptions (#PF/#GP/#DB/#BP/NMI/...) keep the
  paranoid `slow_swapgs()`, whose post-swap verification rdmsr is now
  debug-only (uspace #PF entry: 3 rdmsr → 2). The redundant `cli` in
  `naked_irq_handler!` was dropped (all IDT entries are interrupt gates —
  gate type 0b1110, `disable_interrupts()` never called — so IF is already
  clear on entry).

### Correction to the S8 analysis: Motor's GS model is not Linux's

Found by a debug assertion that instantly panicked at boot ("timer IRQ from
uspace, but slow_swapgs says the kernel GS is already live"). The S8 finding
claimed "CS.RPL == 3 ⇔ user GS live". That is Linux's discipline, not
Motor's:

- `GS::init` sets **GS_BASE == KERNEL_GSBASE == gs_val** (mod.rs:224), and
  every kernel↔user transition does an *unconditional* swapgs
  (`spawn_usermode_thread` syscall.rs:622, syscall entry :639, syscall exit
  :707). So **userspace runs with the kernel per-CPU GS value in GS_BASE**,
  every swapgs is a value-level no-op, and `slow_swapgs()` has never
  actually swapped — its swap branch is dead code unless user code repoints
  GS_BASE (CR4.FSGSBASE is enabled, so `wrgsbase` from ring 3 *can*).
- The CS-based fast path is correct anyway: its entry/exit swapgs pair is
  balanced (the preempt paths are noreturn, but there the swap exchanged
  equal values), and under the unconditional-swapgs discipline the invariant
  "kernel window ⇒ GS_BASE = kernel GS" holds *even if* user repoints GS.
- Better: the old paranoid check was itself **wrong** in the one scenario it
  defends against. User `wrgsbase(X)` + syscall (entry swapgs leaves
  KERNEL_GSBASE = X) + external IRQ inside the IF=1 syscall window →
  `slow_swapgs` sees the MSRs differ → swaps → the handler runs with GS = X
  (user-controlled). The CS check (kernel CS → don't touch GS) fixes this
  latent bug for external IRQs; sync exceptions keep `slow_swapgs` and keep
  the latent wrongness — irrelevant until something actually sets a user GS,
  but worth fixing whenever S15/W6-era hardening happens.
- Debug builds now assert the *real* invariant after the swap decision on
  every IRQ: `validate_kernel_gs()` (mod.rs) checks the self-referential
  `gs:[8]` (GS.gs_val) against `rdmsr(GS_BASE)`.
- Side-finding (S10-adjacent): user GS_BASE is not context-switched — a
  preempt leaves the user's GS value in KERNEL_GSBASE of the *old* CPU, and
  resume elsewhere installs that CPU's kernel value. `wrgsbase` from user
  code is silently unsupported today. Fine, but remember it if FSGSBASE is
  ever exposed as a feature.
- Consequence for **W1** (IRQ fast-return): the iretq fast path needs *no*
  GS work at all beyond the entry/exit pair this round added — the invariant
  is maintained by construction.

### Verification

- Release: full systest pass ×5 (two extra attempts hit the pre-existing
  flaky logging test — logging.rs's 30 ms flush-timing assumptions; it also
  flaked once during the baseline runs, so the rate is unchanged).
- Debug: full systest pass with `validate_kernel_gs()` asserting on every
  external IRQ, then 40 s idle with no watchdog false-death.
- Tickless-idle invariant (Round 0): idle-ish `irq_timer_fired` ≈ 153/s with
  two live ssh sessions (broken tickless would show ~400/s on 4 CPUs).
- S9 is verified by inspection only: the qemu config only exercises custom
  IRQs 0–2 (vectors 64–66), so vector 72 has no runtime repro here.

### Benchmarks

Setup: qemu/KVM `-smp 4` (run-qemu.sh), release, host otherwise idle;
systest over ssh, sequential runs within one boot; rnetbench server in
guest, client on host, defaults (5 s/test, 1 KB buffers). New microbench:
`bench_page_faults` = 8192 first-touch faults on a lazy mapping (the
uspace-#PF preempt path, S6/S8).

Result in one line: **no measurable macro change, as predicted** — the
fixes remove ~2 rdmsr (~200–500 cycles) per external IRQ, 1 rdmsr per
uspace #PF, and empty-queue lock traffic; at the 1–10 K IRQs/s these
benchmarks generate, that is <0.1 % of any macro number, far below this
rig's run-to-run spread. The value of the round is the S9 correctness fix,
the latent slow_swapgs bug fix, the GS-model correction (changes W1's
design), and removing dead-weight costs that would otherwise pollute
Phase-A A/B measurements.

Page-fault microbench (ns/fault; first-in-boot run always slow — new
bench-trap, same class as the FS one):

| | first full run in boot | steady-state samples |
|---|---|---|
| baseline | 15466 | 7080, 7061, 8224, 7041 |
| after | 15136 | 7306, 12377, 7100, 7242 |

Steady-state medians 7071 vs 7242 (+2.4 %): within spread (each side has
one high outlier; the after-boot also caught two runs where the host was
visibly interfering — see FS numbers below).

FS smoke / hot-cache (mbps) and liveness, per run — noise-dominated on this
rig (same-kernel spread far exceeds any plausible effect; recorded for
completeness only):

| run | baseline w/r/hot | after w/r/hot |
|---|---|---|
| first-in-boot | 166/284/807 | 142/234/229 |
| 2nd | 224/75/1027 | 57/25/259 |
| 3rd | 106/426/241 | 226/40/957 |
| 4th | 252/322/217 | 123/400/215 |

liveness p50/p99 (ms): baseline 5–6/7–10, after 5–6/7–9 — unchanged.

rnetbench, 3 runs each (RR µs/iter; guest-RX; guest-TX MiB/s):

| | RR | guest RX | guest TX |
|---|---|---|---|
| baseline | 508 / 421 / 414 | 146 / 120 / 194 | 16 / 48 / 37 |
| after | 438 / 454 / 510 | 162 / 189 / 248 | 42 / 40 / 6 |

All within spread. Note: these absolute numbers are far off the net-perf
round records (RR 152.6 µs, default TX 336) — an environmental condition of
this session affecting baseline and after equally, not a regression from
these changes (baseline was measured on the pre-change kernel in the same
session).

---

## Round 2 (done 2026-07-17): roadmap step 2 — W1 IRQ fast-return

Committed as 97f97f0, on top of Round 1 (643aaf5). Files:
`arch/x64/irq.rs`, `sched/scheduler.rs`, `sched/timers.rs`,
`uspace/process.rs`, `xray/stats.rs`.

### Changes

Userspace interrupts now return straight to the interrupted thread (plain
`iretq` through the existing naked-handler epilogue — no TCB writes, no
xsave/xrstor, no CR3 switches, no job-queue round trip) unless this CPU
actually has something else to do:

- **Timer IRQ in uspace** (`timer_irq_fast_path_ok()`, scheduler.rs):
  fast-return iff the wake flag is clear, both job queues are empty (the
  Round-1 atomic length counters made this free), no software timer on this
  CPU is due, and the BSP doesn't owe a housekeeping pass. The fast path
  re-arms the tick itself (`rearm_tick_from_irq()`) — preserving both the
  Round-0 invariant (*thread in user mode ⇒ live deadline armed*) and any
  armed-early software deadline (without the sched loop's
  `maybe_program_timer()` pass, re-arming blindly to now+10 ms would stretch
  wait-timeouts to the next tick). It deliberately does NOT set the wake
  flag (on_timer_irq() does, and that would make every other tick preempt).
- **Custom/serial IRQ in uspace** (`irq_wake_fast_path_ok()`): the SysObject
  wake is queued as before (`queue_custom_irq_wake()` — the old
  `on_custom_irq()` minus the unconditional `local_wake()`); then
  fast-return iff nothing is runnable on this CPU AND an idle CPU exists —
  that CPU is woken by IPI to drain `WAKE_QUEUE` (it typically then runs
  sys-io itself; no thread is CPU-affined today, so no placement loss).
  With no idle CPU, preempt as before: this CPU's loop must do the work.
- **Kill/debuggee plumbing**: contrary to the S1 analysis, `post_kill` on a
  Running thread never IPI'd anyone (a `TODO` comment) — it silently relied
  on the tick always preempting, as did `dbg_pause`. Both now poke the
  relevant CPUs' wake flags (`poke_cpu()` reading the victim's
  `utcb.current_cpu`, best-effort but sufficient: a Running thread stays on
  its CPU until it passes through the scheduler, which sees Killed anyway;
  `poke_all_cpus()` for dbg_pause). A set wake flag forces the next tick to
  preempt, so kill/pause latency stays ≤1 tick, as today.
- **BSP housekeeping**: `update_system_time()` cadence moved from a
  sched-loop local into `LAST_SYSTEM_TIME_UPDATE` (atomic) so the timer
  fast path can refuse to fast-return when the BSP owes an update (>3 s
  stale). Debug builds also stamp the watchdog's `last_alive_check` from
  the fast path — a fast-returning CPU is alive but never iterates its
  loop, which would otherwise false-trigger the watchdog.
- **Timers**: `Timers` grew an atomic raw-TSC mirror of the earliest
  deadline (`next_deadline_tsc`, maintained under its lock) — the fast path
  runs in IRQ context where taking the timers spinlock could deadlock
  against a same-CPU holder running with IRQs enabled.
- **Metrics**: `irq_fast_return_timer/wake`, `irq_preempt_timer/wake`.
- **Adjacent fix**: `MetricType::from_custom_irq` accepted index 8 (which
  transmutes to `TotalChildren`) and only vectors 64–71 have dedicated
  metrics — after the Round-1 S9 fix, a device on vector 72 would have
  corrupted the TotalChildren metric and vectors 73–79 would have panicked
  (assert) in IRQ context. The assert is now `< 8` and the dispatch arm
  skips the per-vector metric for 72–79 (`IrqFired` still counts them).

Known bounded race (accepted, same class as S16): the idle CPU chosen for
wake-handoff can pick up other work before the IPI lands and re-enter
userspace; the wake then sits until that CPU's next kernel entry (≤1 tick).
Same worst case as today's wake-to-busy-CPU path; fix belongs to
S16/priority work.

### Verification

- Release: systest ×3 full pass, tokio-tests PASS, mio-test pass — same
  suite as the baseline run below.
- Debug: full systest pass (69 PASS lines) with the per-IRQ
  `validate_kernel_gs()` assertion live and fast paths engaged (6.5 K
  timer + 5.9 K wake fast-returns during the run); 40 s idle with no
  watchdog false-death. Kill paths exercised by systest's spawn_wait_kill +
  test_pid_kill (now going through `poke_cpu`).
- Round-0 invariant: the tick chain is re-armed by the fast path itself;
  idle CPUs still quiesce (post-benchmark timer-IRQ totals *dropped* vs
  baseline, see below).

### Benchmarks

Same rig and methodology as Round 1 (fresh baseline captured immediately
before the change, same boot pattern, same host session). **This time the
effect is far above the noise floor.**

rnetbench (3 runs; RR µs/iter; guest-RX / guest-TX MiB/s):

| | RR | guest RX | guest TX |
|---|---|---|---|
| baseline (Round 1) | 407 / 451 / 551 | 196 / 120 / 203 | 74 / 26 / 7 |
| **W1** | **184 / 206 / 226** | **324 / 298 / 408** | **346 / 266 / 331** |

- RR latency ≈ **2.2× better**. The baseline's erratic guest-TX (7–74,
  wildly unstable across the whole session) is *gone*: TX is now stable at
  ~300 MiB/s — the instability was the preempt storm itself (every RX/ack
  IRQ evicted the sending thread through xsave/2×CR3/queue/xrstor with a
  likely migration).
- This session's environment ran ~3× worse than the historical records
  (baseline RR ~450 µs vs the 152.6 µs record); W1's 184 µs approaches the
  all-time record *under the degraded conditions*.

systest (per boot, sequential runs; FS write/read, hot-cache mbps):

| run | baseline w/r/hot | W1 w/r/hot |
|---|---|---|
| 1st clean | 138/48/849 | 203/266/957 |
| 2nd | 195/214/142 | 239/415/1110 |
| 3rd | — (flake) | 256/375/1116 |

Hot-cache 1110–1116 mbps are the best numbers seen this session; FS
smoke reads/writes all up. Page-fault bench unchanged (6987–7052 ns steady
vs 7180 — #PF path not touched by W1). test_liveness p50/p99: 5–6/7–8 ms
vs 6–7/9 ms — no regression, slightly better.

Fast-path engagement (whole release-benchmark boot):

| counter | value |
|---|---|
| irq_fast_return_wake | 313 049 (**96 %** of uspace device IRQs) |
| irq_preempt_wake | 12 629 |
| irq_fast_return_timer | 28 977 (**86 %** of uspace ticks) |
| irq_preempt_timer | 4 597 |

Total IRQs doubled vs baseline (5.2 M vs 2.6 M — the same benchmarks moved
~2× the data), while timer IRQs *fell* 104 K → 88 K: work finishes sooner
and tickless idle keeps the quiet CPUs quiet.

Consequences for the roadmap: S5 (xsave/xrstor) and much of S1's cost are
gone for the 86–96 % fast-return majority; W2 (placement) and W3 (lazy FPU)
now only concern the remaining real deschedules; W5/W6/W7 (wait fast path,
CR3/TLB policy, direct swap) are the next big levers for the IPC lockstep,
which still pays full price.

---

## Round 3 (done 2026-07-17): roadmap step 3 — W2 placement (S4)

Committed as 9b83538, on top of Round 2 (97f97f0).

### What was done

`Thread::last_cpu` (process.rs), dead since it was added, is now maintained
and drives job placement:

1. **Stamp**: `TCB::set_fs()` — the choke point of every kernel→user
   transition (spawn, preempt-resume, and syscall exit; the latter also
   covers wait-resume, since a syscall that blocked exits through the same
   path on whatever CPU it resumed on) — stores `current_cpu` into
   `Thread::last_cpu`. One extra Relaxed store next to the `current_cpu`
   store the function already does.
2. **Placement** (`post()`, scheduler.rs): for unaffined jobs
   (`job.cpu == MAX`), the idle-CPU scan now starts at the thread's
   `last_cpu` and wraps, so the home CPU wins ties instead of
   first-idle-by-index. The no-idle fallback remains the global queue
   (see the negative result below for why it must). The hint is read by
   upgrading the job's `Weak<Thread>`; detached jobs have no hint and
   keep the old scan-from-0.
3. **Metrics 41–43**: `placement_hint_idle` / `placement_other_idle` /
   `placement_queue_global`. `PerCpuStatsEntry` had exactly three free
   metric slots, so its size is unchanged (384 B).

### Negative result: a non-work-conserving fallback convoys

The plan's original direction ("prefer last_cpu-if-idle → any-idle →
*last_cpu's queue*") was implemented first: with no CPU idle, the job was
pushed onto `last_cpu`'s local queue (+wake) instead of the global queue —
nominally the same worst case (one tick, since the W1 fast path checks
`queue_length`), but with warm caches and no cross-CPU stealing.

Measured: RR 178 µs → **55 481 µs** (~300×), guest TX/RX ~300 →
1.6 MiB/s, two of three systest runs hit the 420 s timeout, and
`irq_preempt_timer` exploded 4.4 K → 141 K (≈ every other tick a preempt).
The new `placement_queue_last` counter fired 386 K times.

Root cause: local queues are private to their CPU, so the fallback is
**not work-conserving**. "No CPU idle" at post time is routinely a few µs
stale: in the IPC lockstep the poster blocks right after posting, and
under the old policy its own CPU popped the job from the global queue
within microseconds. Parked on another CPU's local queue instead, the job
waits out that CPU's current thread (up to a full 10 ms tick) — while the
CPUs that went idle a moment later find nothing to steal and hlt. Convoys
form on one CPU as the rest of the machine sleeps; an RR iteration crossed
~5 such parking events (55 ms ≈ 5.5 ticks).

The rule, now also recorded at the fallback site in `post()`: **the
no-idle path must stay stealable**, and the global queue is the only
stealable structure. If targeted queueing is ever wanted (it is the right
cache policy!), idle-time work stealing from other CPUs' local queues has
to be built first — relevant to W10 (priorities) too.

### Results (final policy: scan-from-last_cpu, global fallback)

Same rig and method as Rounds 1–2; fresh same-session baseline at 97f97f0.
rnetbench (3 host-client runs, in run order):

| metric | baseline | W2 |
|---|---|---|
| RR µs | 177.7 / 206.9 / 223.3 | 182.5 / 203.9 / 227.5 |
| client⇒server MiB/s | 305.7 / 271.5 / 434.2 | 324.7 / 287.8 / 404.9 |
| server⇒client MiB/s | 340.1 / 263.8 / 336.2 | 343.2 / 262.3 / 338.4 |

All within run-to-run noise, as are the FS smoke / hot-cache / page-fault
numbers. test_liveness improved slightly (p99/max 8–9 → 6 ms on runs 2–3).
Scheduler-machinery activity dropped measurably (same whole-boot suite):

| counter | baseline | W2 |
|---|---|---|
| irq_timer_fired | 87 632 | 65 094 (−26 %) |
| irq_preempt_wake | 15 924 | 11 553 (−27 %) |
| irq_preempt_timer | 4 433 | 3 619 |

Placement counters (whole boot, 4.7 M unaffined placements): **52 % land
exactly on the thread's last CPU** (`placement_hint_idle` 2 469 033 = 75 %
of idle-handoffs), 17 % on another idle CPU, 30 % global fallback.

Verified: release systest ×3 + tokio-tests + mio-test all pass; debug
systest passes with the per-IRQ GS assert live; 40 s idle stays
watchdog-quiet on debug.

### Consequences for the roadmap

- S4's "constant migrations, likely large cost" was overstated for this
  rig: ~70 % of placements find an idle CPU anyway, and the fix is
  latency-neutral here. The measurable wins are −26 % timer IRQs and
  −27 % preempt-wakes (stickiness ⇒ fewer forced preemptions), plus
  counters to watch placement under heavier load. Bigger machines and
  saturated CPUs should benefit more.
- W3 (lazy FPU) now has its precondition ("W1+W2 establish same-CPU
  resume") in place, with 52 % exact-home placement as the floor.
- Next: roadmap step 4 — W5 wait-with-pending-wakers fast path (+ S10
  MXCSR fix folded in).

---

## Round 4 (done 2026-07-17): roadmap step 4 — W5 wait fast path (S3) + S10 fix

Committed as addccf1, on top of Round 3 (9b83538).

### What was done

**W5 — sys_wait pending-wakers fast path.** The kernel already had the key
fact in `on_thread_paused()`: a thread that pauses with pending wakes is
*not* parked — it is flipped back to Runnable and re-posted immediately, so
the whole pause/deschedule/queue/(often migrate)/resume trip is observable
only as cost. `sys_wait_impl` now short-circuits it: after
`process_wait_handles` (validation + registration unchanged, including its
funneling of unconsumed object wakes into the thread's waker list), if

- the thread has pending wakes (`Thread::has_pending_wakes()` — the exact
  negation of `on_thread_paused()`'s park condition), and
- this CPU has nothing ready to run (`sched::this_cpu_has_no_ready_work()`
  — wake flag clear, local queue empty, global queue empty),

it takes the wakers and returns without descheduling. The "wait is at
least a yield" semantic is preserved: if anything is runnable on this CPU
the pause happens as before. The F_SWAP_TARGET exclusion falls out
automatically — the swap wakee is posted to *this* CPU's local queue right
before the check, so `queue_length != 0` forces the handoff pause. The
fast path sits before timeout registration, so no timer is created and
cancelled for nothing. Metrics 44/45: `wait_fast_path` / `wait_paused`.

**S10 — FP-environment leak across blocking syscalls, fixed.** MXCSR and
the x87 control word are callee-saved in the SysV ABI, but the
pause/resume path never touched FPU state, so a thread that blocked could
resume with another thread's (or init) FP env. `TCB::pause()` now saves
MXCSR+FCW (`stmxcsr`+`fnstcw`) into a new `fp_env` field at the end of the
TCB, and `TCB::resume()` restores them (`ldmxcsr`+`fldcw`) before
re-entering the thread — ~20 cycles per blocking round trip, zero effect
on the W5 fast path (which never leaves the CPU). New systest
`test_fp_env_across_blocking_syscall` sets FTZ/DAZ, sleeps 30 ms (a real
pause/resume), and asserts they survived.

### Results

Same rig; baseline = the Round 3 "after" run (identical binary to the
committed 9b83538, measured under an hour earlier). rnetbench:

| metric | baseline (R3) | W5 |
|---|---|---|
| RR µs | 182.5 / 203.9 / 227.5 | **137.4 / 155.3 / 179.4** |
| client⇒server MiB/s | 324.7 / 287.8 / 404.9 | 325.3 / 260.4 / 468.6 |
| server⇒client MiB/s | 343.2 / 262.3 / 338.4 | 336.0 / 270.7 / 336.0 |

**RR improved ~25 % and 137.4 µs is a new all-time record** (previous:
152.6 µs from the net-perf delayed-ack round — beaten by 10 % despite this
session's environment running ~3× worse than that round's). Throughput,
FS, hot-cache, page-fault and liveness numbers all within noise (best
client⇒server of the whole session, 468.6, appeared here).

Engagement (whole benchmark boot): `wait_fast_path` 1 417 888 vs
`wait_paused` 5 136 035 — **21.6 % of blocking-capable waits skip the
deschedule entirely**. The IPC-lockstep prediction in S3 ("removes ~half
the descheduling from lockstep") shows up as the RR win; bulk throughput
is unaffected because its waits genuinely park (server ahead of client or
vice versa).

Verified: release systest ×3 + tokio-tests + mio-test pass; new FP-env
test passes on release; debug systest 69 PASS + 40 s idle watchdog-quiet.

### Consequences for the roadmap

- The remaining 78 % of waits genuinely park; their cost is the
  pause/resume machinery itself — that is W6 (CR3/TLB policy) and W7
  (direct-switch swap) territory, now the clear next levers for IPC.
- W3 (lazy FPU) got cheaper to reason about: pause/resume now carries the
  *control* env explicitly, so a future lazy-FPU scheme only concerns the
  bulk register state.

---

## Round 5 (done 2026-07-17): W3 skipped on measurement; roadmap step 6 — W6a GLOBAL kernel pages (S2 part 1)

Uncommitted, on top of Round 4 (addccf1).

### W3 (lazy FPU) — skipped, with the measurement the roadmap asked for

Roadmap step 5 gated W3 on "measure first — W1 may capture most of the
win". It did: xsave/xrstor only happens on IRQ-preempts and #PF-preempts
(syscalls/pause/resume never touch the FPU), and after W1/W2 a whole
release bench boot shows only ~23 K IRQ-preempts + ~25 K #PFs ≈ 48 K
xsave/xrstor pairs × ~0.2–0.4 µs ≈ **10–20 ms per boot (~0.005 % of CPU)**.
Lazy-FPU bookkeeping (per-CPU owner tracking, cross-CPU flush IPIs before
migration) cannot pay for itself at that rate. Revisit only if preempt
rates rise by orders of magnitude.

### W6a — what was done

Kernel translations now survive CR3 writes; kernel-range TLB invalidation
made correct first (it was a real, pre-existing hole):

1. **The correctness fix** (`paging::invalidate`, called on every CPU by
   the shootdown IRQ): it used to skip whenever the CPU's current CR3
   differed from the target page table. Correct for user tables; wrong for
   the kernel table — kernel VAs are valid in *every* address space via
   the shared L3s, so a CPU running a user process skipped kernel-range
   invalidations (e.g. a recycled kernel stack freed by another CPU) and
   kept stale entries until its next incidental CR3 wipe. That masking is
   exactly the `validate_rsp`/"invalid rsp fixed by flushing KPT" bug
   class. Now: kernel-PT invalidations (`page_table == kernel_pt_phys()`,
   a new static stashed at `init_paging_bsp`) run unconditionally;
   large-range kernel flushes use a new `flush_all_including_global()`
   (CR4.PGE toggle — a CR3 reload no longer flushes kernel entries);
   `invlpg` handles global entries natively. The debug `validate_rsp`
   canary now uses the global-capable flush too.
2. **PTE::GLOBAL (bit 8)** on kernel leaves: set automatically in
   `map_page` for non-USER mappings in the kernel table only (a global
   leaf in a *user* table would dodge that table's CR3-gated shootdown —
   deliberately excluded), plus a one-time boot walk
   (`set_global_on_kernel_leaves`, from `init_paging_bsp`, before APs
   boot) that retrofits the boot-time mappings: kernel text/data, direct
   map, early heap.
3. **CR4.PGE (bit 7)** enabled in `GS::init`'s existing CR4 write on every
   CPU. Ordering is a non-issue: the G bit changes flush behavior, not the
   translation, and unmap correctness is carried by (1).

Syscall/preempt/resume asm is untouched — the CR3 switches remain (W6b
drops them); they just stop destroying the kernel TLB.

### Results

Baseline = the Round 4 "after" run (identical binary to committed
addccf1). rnetbench RR 141.3/155.2/186.9 µs vs 137.4/155.3/179.4 — within
noise, as expected (RR is user-TLB and wait-path bound). The real signals:

- **bench_page_faults steady-state: 6568/6529 ns vs a ~7000–7180 ns floor
  across the entire session (−7 %)** — the #PF path's two CR3 switches no
  longer wipe the kernel TLB, so the fault handler runs warm.
- test_liveness p99/max improved again (5–7 ms vs 6–9).
- Hot-cache/FS/throughput unchanged within noise (syscall-path kernel-TLB
  benefits are mostly deferred until W6b removes the switch itself and the
  software user-copy walks).

Verified: release systest ×3 + tokio-tests + mio-test + FP-env test pass;
debug systest ×2 (thread churn exercises kernel-stack recycling — the
fixed shootdown path) all PASS; idle watchdog-quiet; zero
"invalid rsp" canary hits in the debug serial log.

### Consequences for the roadmap

- W6a is deliberately the *small* half of S2: its value is correctness
  (the stale-kernel-TLB class is now fixed rather than masked) plus the
  #PF/liveness gains. The dominant S2 cost — the switch itself and the
  per-4K-page spinlocked software walks in `read_from_user` — falls to
  **W6b**, which is now unblocked and is the next round.
- After W6b, re-measure before considering W6c (PCID).

---

## How things work today (reference)

### Execution model

There are no kernel threads and no in-kernel blocking (except `Thread::wait`).
Each CPU runs one `Scheduler::sched_loop` (scheduler.rs:318) forever, cycling
through three job sources by `iteration % 3`: the CPU-local queue, the global
queue (`GLOBAL_READY_QUEUE_NORMAL`), and due software timers. Every iteration
also drains the global `WAKE_QUEUE` (`process_wake_events`, sysobject.rs:275).
After `HALT_POLLING_ITERS = 5` empty iterations the CPU halts (now tickless
for non-BSP).

A `Job` is a `fn(Weak<Thread>, u64)` + a CPU hint. `post()` (scheduler.rs:529):
if the hint is `uCpus::MAX`, hand directly to the **first idle CPU by index**,
else push to the global queue (drained by whichever CPU polls first); with an
explicit hint, push to that CPU's local queue and IPI it.

User threads run *inside* jobs: `job_fn_start` / `job_fn_resume_in_kernel` /
`job_fn_resume_in_userspace` call into TCB methods that context-switch to the
user thread; the job "returns" when the thread goes off-CPU again
(`ThreadOffCpuReason`: Paused / Preempted / Exited / Killed*).

### Kernel↔user transitions (arch/x64/syscall.rs)

- `spawn_usermode_thread` (:233) — first entry; xrstor + `sysretq`.
- `syscall_handler_asm` (:633) — syscall entry: `swapgs`, **CR3←KPT**, switch
  to the per-thread syscall stack, `sti`, call `syscall_handler_rust`. On
  return: `cli`, **CR3←UPT**, `sysretq`. FMASK masks IF+TF during entry.
- `pause` (:340) — called mid-syscall to block: swaps from the syscall stack
  back to the scheduler stack; the job that ran the thread returns `Paused`.
- `resume` (:357) — re-enters the middle of the blocked syscall (no xrstor).
- `preempt_current_thread_irq/pf` (:396/:424) — called from IRQ context when
  the IRQ arrived in userspace: **xsave**, copy the IrqStack into the TCB,
  **CR3←KPT**, EOI, return `Preempted` to the job.
- `resume_preempted_thread` (:442) — set_fs + **xrstor**, **CR3←UPT**, `iretq`.
- `exit` (:272) — completes a syscall back to user (part of the sysret path).

### IRQ dispatch (arch/x64/irq.rs, `irq_handler_inner` :510)

Every IRQ/exception entry calls `slow_swapgs()` (mod.rs:236 — 2×rdmsr to
decide whether to swap). Then:

- `IRQ_APIC_TIMER` (:562): if in uspace → full preempt (noreturn); in kernel →
  `on_timer_irq()` re-arms + wakes the loop.
- custom IRQs 64..79 (:548): queue the SysObject wake (IRQ-safe lock-free
  `WAKE_QUEUE` push), then **if in uspace → full preempt** of whatever thread
  happened to be running.
- `IRQ_SERIAL` (:540): same — full preempt if in uspace.
- `IRQ_WAKEUP` (:576): sets the local wake flag, **does not preempt uspace**.
- `IRQ_TLB_SHOOTDOWN`: handled entirely in the IRQ handler (correct model —
  this is what the other IRQs should mostly look like).

All virtio MSI-X vectors are programmed with APIC ID 0
(virtio-async/src/virtio_device.rs:558 — "most IRQs are affined to CPU 0"),
and the serial IRQ is routed to the BSP. So *all* device interrupts land on
CPU 0.

### Preemption round trip (the S1 path)

Timer/serial/custom IRQ in uspace ⇒

1. `slow_swapgs` (2×rdmsr), stats, tracing.
2. `preempt_current_thread_irq`: **xsave (full)**, IrqStack copy (~160 B),
   CR3←KPT (full TLB wipe), EOI, return `TOCR_PREEMPTED` into the job.
3. `thread_off_cpu_reason` (:494): calls `on_timer_irq()` **unconditionally**,
   even when the preemption came from a serial/virtio IRQ (re-arms and phase-
   shifts the tick; conflates "timer fired" with "was preempted").
4. `on_thread_descheduled` → status lock → `Live(Preempted)` → **post a new
   job** (`job_fn_resume_in_userspace`) with the thread's *affinity* hint
   (default `MAX`) — `post()` then hands it to the **first idle CPU**, i.e.
   the thread migrates whenever any lower-indexed CPU is idle.
5. Some CPU's sched loop eventually pops the job (after up to 2 other phase
   sources), takes the status lock again, `resume_preempted_thread`: set_fs,
   **xrstor**, CR3←UPT (full TLB wipe), `iretq`.

Total: 2 full TLB invalidations, 2 heavyweight FPU ops, 2+ spinlocked status
transitions, one queue round trip, 2–3 rdmsr, and a possible CPU migration —
*per interrupt*, even when the interrupted thread is the only runnable thing
in the system. On a busy CPU this happens ≥100/s from the tick alone, plus
every virtio interrupt on CPU 0.

### Blocking syscall (wait/swap) round trip (the S3/S7 path)

`sys_wait_impl` (uspace/sys_cpu.rs:189):

1. Syscall entry: CR3←KPT (TLB wipe #1), status lock ×2 (`on_syscall_enter`).
2. Optional swap-wake: wakee's resume job posted **to this CPU** (`this_cpu=
   true`).
3. `process_wait_handles`: `Vec` allocations, per-handle object lookup,
   `add_wait_objects`, and a `BTreeMap` insert into every waited object's
   `waiting_threads` — per wait call.
4. **Always** `tcb.pause()` — comment at sys_cpu.rs:260: "wait is at least a
   yield" — even if wakers are already queued. (Single exception: IO-manager
   threads with `timeout == 0` use `take_wakers()` and skip the pause.)
5. `on_thread_paused`: if wakers arrived meanwhile → immediately re-post a
   resume job (with affinity hint ⇒ possibly *another* CPU: a wait-that-
   should-be-a-no-op can migrate the thread).
6. Resume pops the job, `tcb.resume()` back into the syscall,
   `clear_wait_objects_on_wake` (BTreeMap removals), sysret: CR3←UPT (TLB
   wipe #2).

The IPC lockstep (client swap → server → swap back) pays this twice per
message. Existing data: FS message machinery ≈ 15 µs (llvm rounds), wake→run
latency p50 ≈ 5 µs (`test_liveness`), rnetbench RR 152.6 µs.

### Page fault (the S6 path)

Uspace #PF → `page_fault_handler_inner` → `preempt_current_thread_pf`
(**xsave**, CR3←KPT) → job returns → `on_pagefault` (process.rs:1848) → fault
fixed **while holding the thread status spinlock** → resume job posted to the
same CPU → sched loop → xrstor, CR3←UPT, iretq. Motor uses lazy mapping
heavily, so first-touch of every allocated page pays ~2–5 µs instead of the
~1 µs a fault handled entirely in exception context would cost.

### FPU facts (for concern 2)

- The kernel is built soft-float (`kernel.json`: `-sse,+soft-float`) — kernel
  code never touches vector/FP registers. This makes lazy-FPU schemes safe.
- Plain (non-blocking) syscalls do **not** xsave/xrstor — user vector state
  stays live in registers across the syscall. Correct per the ABI (vector regs
  are caller-saved), and cheap. Good.
- IRQ preemption and #PF do a **full** `xsave`/`xrstor` (xsave-2.0.2 crate,
  RFBM = ~0, no xsaveopt/xsavec) — S5.
- Blocking syscalls (`pause`/`resume`) save/restore **nothing**. Vector regs:
  fine (caller-saved). MXCSR control bits and the x87 control word: **not
  fine** — the SysV ABI makes them callee-saved, so a thread that sets FTZ/DAZ
  or a rounding mode, then blocks, can resume with another thread's FP
  environment (whatever the last xrstor on that CPU installed) — S10.
- `spawn_usermode_thread` xrstors a default image and the asm also does
  `fninit`; threads start with a clean env. The leak is only across blocking
  syscalls.

### Paging facts (for S2)

- User page tables share the kernel's L3 tables via two L4 entries
  (`map_kernel_to_user`, paging.rs:673): the kernel region and the direct map.
  Kernel mapping changes propagate to all processes automatically. There is no
  KPTI-style isolation to preserve — the CR3 switch buys nothing
  security-wise.
- IRQ handlers, the wake queue, tracing, stats — all already run on the *user*
  page table (irq.rs comment at :522) and touch kernel heap freely. The kernel
  provably functions on UPTs.
- No PCID (CR4.PCIDE never set), no GLOBAL PTE bit anywhere (paging.rs PTE
  consts stop at USER/ACCESSED/HUGE). Consequence: **every `mov cr3` wipes the
  entire TLB, kernel entries included.** Syscall entry+exit = 2 wipes;
  IRQ-preempt+resume = 2 wipes; one IPC message (2 swaps) ≥ 8 wipes.
- Because syscalls run on the KPT (user memory unmapped — L4[0] is cleared at
  boot), every access to user buffers goes through `read_from_user`
  (mm/user.rs:576): a **software page-table walk per 4 KB page, taking the
  page-table spinlock per page**, then a copy via the direct map.
- The `validate_rsp` / `flush_kpt` workaround (syscall.rs:318-338, "invalid
  rsp fixed by flushing KPT") is evidence of a stale-TLB bug for kernel
  mappings: kernel stacks are cached/reused (`SegmentCache`), and there is no
  cross-CPU shootdown for kernel-region unmaps — masked today by the constant
  full TLB wipes. Any CR3-avoidance work (W6) must fix this properly first.

### Watchdog / debug

`alive()` checks + `die_on_next_wake` exist in debug builds only (now
idle-aware after Round 0). Tracing (`xray::tracing`) is disabled unless
`tracing::start()` is called (currently commented out in init.rs:389); each
call site costs a load+branch when off — fine.

---

## Findings in detail

### S1 — every uspace IRQ is a full deschedule

**Done in Round 2** — implemented essentially as designed below, with two
corrections found en route: (1) kills/dbg_pause never actually IPI'd the
victim CPU (the doc's precondition assumed they did) — both now poke wake
flags; (2) no separate `need_resched` flag was needed — the existing per-CPU
`wake` flag has exactly those semantics.

Where: irq.rs:540-575 (`IRQ_SERIAL`, `64..=79`, `IRQ_APIC_TIMER` all call
`preempt_current_thread_irq` when `uspace`).

Why it's wrong: an interrupt is not a scheduling decision. The handler work
(queue a SysObject wake; console byte; tick bookkeeping) takes well under a
microsecond and is already IRQ-safe. Descheduling should happen only when the
scheduler actually wants the CPU for something else. Today, a virtio RX
interrupt landing on CPU 0 while, say, `rush` runs there evicts rush through
the full xsave/CR3/queue/xrstor cycle, then usually resumes it — possibly on
a different CPU — while the *actual* work (waking sys-io) is just a queue
push. The tick does the same 100×/s per busy CPU even with an empty run
queue: preempt → `on_thread_descheduled` → post job → pop job → resume, all
to end up exactly where it started.

Also note irq.rs:571's assumption ("timer fires → preempted → thread_off_cpu
_reason calls on_timer_irq") makes *every* preemption re-arm the tick (S4
sub-issue): a stream of device IRQs continually pushes the tick deadline out,
so a compute thread on an IRQ-heavy CPU may effectively never see a timer
tick (it still gets descheduled by the device IRQs themselves, so no
starvation today — but once S1 lands, the deadline-reset must be removed or
quantum enforcement silently disappears).

Direction (W1): make IRQ handlers return to the interrupted thread by
default (`iretq` without touching the TCB), preempting only when needed:

- Custom/serial IRQ: do the wake-queueing as today, then decide:
  - if an idle CPU exists → wake it (IPI) to drain `WAKE_QUEUE`, and iretq;
  - else → set a per-CPU `need_resched` and take the preempt path (as today),
    because *this* CPU must run the follow-up work.
- Timer IRQ: peek (lock-free) local queue length, global queue emptiness, due
  timers, wake flag. All empty → re-arm tick, iretq (the lone-busy-thread
  case becomes ~200 cycles). Something runnable → preempt as today.
- Preconditions to keep correct:
  - killed threads: `Process::kill`/`post_kill` today relies on the victim
    hitting a syscall/preempt to die; the fast-return must still honor kills.
    Cheapest: kills already IPI the victim CPU — have the kill path set a
    per-CPU (or per-TCB) `need_resched`/`killed` flag the IRQ fast-return
    checks (a plain load; no status lock in the fast path).
  - `paused_debuggee` must force the preempt path (same flag mechanism).
  - EOI ordering: fast return must EOI before iretq (today EOI happens either
    in the handler or in preempt asm — the fast path just EOIs in-handler).
- Expected effect: eliminates nearly all xsave/xrstor (S5 rides along),
  2 TLB wipes, 2 status-lock transitions, and the queue round trip per IRQ.
  Device-IRQ victims keep their CPU; sys-io wake latency *improves* when idle
  CPUs exist (direct IPI instead of preempt+loop+queue).

### S2 — CR3 switching / TLB policy

Where: syscall_handler_asm :633 (entry: `mov rax, gs:[24]; mov cr3, rax`;
exit: reload UPT), preempt/resume asm (:794/:818), no-PCID, no-GLOBAL (see
"Paging facts").

This is almost certainly the largest *hidden* tax on IPC and syscall-heavy
workloads (the llvm/FS investigation repeatedly ran into TLB effects — the
2048-byte task cliff was a TLB-shootdown artifact; "TLB wipe per switch" was
identified in the co-location round). A null syscall's direct cost is small;
the damage is the *subsequent* page-walk storm in both kernel and user code.

Options, in increasing ambition:

- **W6a. GLOBAL kernel pages** (CR4.PGE + PTE.G on the two kernel L4 regions'
  leaves — set once in the shared L3/L2/L1 tables): kernel translations
  survive CR3 writes. Small, self-contained, benefits every syscall/IRQ/
  context switch immediately. Must first make kernel-region TLB invalidation
  correct (global pages are *not* flushed by CR3 writes — the `validate_rsp`
  bug class would become deterministic instead of masked): kernel unmaps need
  `invlpg` + cross-CPU shootdown (machinery already exists in tlb.rs) or a
  dedicated "flush globals" path (toggle CR4.PGE). The kernel-stack
  SegmentCache reuse is the main consumer to audit.
- **W6b. Stop switching CR3 on syscalls entirely.** The kernel already runs
  on UPTs in IRQ context; syscalls can too (the syscall stack, GS, heap, and
  direct map are all in the shared kernel regions). Benefits: zero TLB cost
  for syscalls; `read_from_user`/`write_to_user` software walks (spinlock per
  4 KB!) become plain memcpy from the user address (with `is_user` range
  checks — SMAP later if desired, S15). Preempt/resume paths can keep the KPT
  switch or drop it too (the scheduler only touches kernel + direct map).
  Risks: (1) the stale-kernel-TLB class above, same fix as W6a; (2) any code
  secretly relying on "user memory unmapped during syscalls" (audit: nothing
  found — `read_from_user` walks explicitly; `get_user_page_as_kernel` uses
  the direct map); (3) NMI/#MC paths (currently fatal anyway).
- **W6c. PCID/INVPCID** for user TLB survival across process switches. Real
  IPC win (client↔server switches stop wiping each other's user TLB), but
  meaningful design work (ASID allocation, shootdown protocol changes) and
  KVM-guest PCID quality varies. Do after W6a/b; measure first.

Recommended order: W6a (small, immediate), then W6b (kills the software-walk
copies too), PCID only if switch-heavy IPC still shows TLB pain.

### S3 — `sys_wait` with pending wakers still pauses

Where: sys_cpu.rs:260-268 + process.rs `wait()`/`on_thread_paused` (:1414,
:1465).

The "wait = at least a yield" semantic is reasonable, but its implementation
(full pause → discover wakers → re-post job → possibly *migrate* → resume) is
the most expensive possible yield. When wakers are already queued and no
other job is runnable on this CPU, the pause/resume round trip changes
nothing observable — it burns 2 status-lock transitions, a queue round trip
and often a migration.

Direction (W5): in `sys_wait_impl`, after `process_wait_handles`, check
wakers/wakes_queued; if wakes are pending: behave like the IO-manager fast
path (`take_wakers`) *unless* the local run queue is non-empty (in which case
the yield has real work to yield to — keep the pause). This preserves both
semantics ("at least a yield" when there is something to yield to) and
fairness, and removes ~half the descheduling from IPC lockstep. The swap path
(F_SWAP_TARGET) keeps its pause (the whole point is to hand the CPU over) —
its fix is W7.

### S4 — placement: resume goes to "first idle CPU", `last_cpu` is dead

Where: `on_thread_descheduled` posts with `get_cpu_affinity()` (default MAX)
→ `post()` scheduler.rs:529 hands to the first idle CPU by index;
`post_wake_locked` (process.rs:1664) same; `last_cpu` (process.rs:829) is
initialized to MAX and **never stored to**.

Effects: tick-preempted threads migrate whenever any lower-numbered CPU is
idle; a woken thread lands wherever, with cold L1/L2 and (no PCID) a fully
cold TLB after the first CR3 load. The earlier "IPC lockstep on CPU0"
finding and the idle-CPU handoff patch in `post()` are symptoms of the same
missing policy: there is no notion of "prefer where this thread (or its
working set) last ran".

Direction (W2): maintain `last_cpu` (store in `thread_off_cpu_reason` or
`set_fs`, which already writes `current_cpu` into the user TCB); make resume
jobs prefer last_cpu-if-idle → any-idle → last_cpu's queue; make preempt-
resume default to the *same* CPU unless the local queue is backed up. Most of
the tick-preempt case disappears entirely under W1 (iretq, no re-queue).

### S5 — unconditional full xsave/xrstor on IRQ/#PF

Where: `preempt_current_thread_irq/pf` (xsave), `resume_preempted_thread`
(xrstor); crate xsave-2.0.2 uses plain `xsave`/`xrstor` with RFBM=~0.

W1 removes the common case (same thread continues). For the remaining real
deschedules:

- Track a per-CPU `fpu_owner: *const Thread` + per-thread `fpu_saved` flag.
  On preempt: *don't* xsave; mark owner. On resume of thread T on CPU c: if
  `fpu_owner == T` and nothing else xrstored in between → skip xrstor. If a
  different thread needs the FPU (or T is about to run elsewhere) → xsave the
  owner's state first (owner is guaranteed off-CPU: it parked via this CPU's
  scheduler). Cross-CPU migration of a not-yet-saved owner needs care: only
  migrate threads whose state is saved, or IPI the owning CPU to flush. Given
  W1+W2 make same-CPU-resume the norm, the simple "save only when another
  thread wants the FPU on this CPU" covers nearly everything.
- Cheaper instructions regardless: `xsaveopt`/`xsavec` (init/modified
  optimizations) — small patch to the xsave crate usage or a local copy.

### S6 — page faults pay the scheduler machinery

Where: page_fault_handler_inner → preempt_current_thread_pf → on_pagefault
(process.rs:1848).

A minor fault (lazy map, CoW-ish fixups) could be fully handled in the
exception context: the fault handler already runs on a per-CPU IST stack with
the UPT loaded; `fix_pagefault` allocates phys pages and edits the current
process's page table — no blocking, no other-thread interaction. Direction
(W9): resolve user minor faults in the #PF handler itself (careful: it
currently runs with IRQs disabled on an IST stack — either keep it short or
switch to the thread's kernel stack and sti, Linux-style); fall back to the
preempt path for faults that must kill the thread or need heavy work. Also
stop holding the thread `status` spinlock across `fix_pagefault` (today a
concurrent `post_wake` spins for the whole fault fix).

Interaction: keeps xsave out of the alloc-heavy paths (malloc + first touch),
which the FS/llvm work showed matter.

### S7 — swap should be a direct switch

Where: F_SWAP_TARGET in sys_cpu.rs:221 → `do_wake(this_cpu=true)` + full
`wait()`.

Today "swap" = post wakee's job on this CPU + pause self + loop iteration +
pop + resume. A direct handoff — save caller's syscall context (already done
by `pause`'s mechanism), load wakee's TCB, switch CR3 to wakee's UPT, resume
it in-place — removes the queue round trip, the loop iteration, and one pair
of status transitions from *every* IPC message. With W6 the CR3 load is the
only TLB event, with PCID (W6c) not even that. Target: sub-µs kernel cost per
handoff. Largest single piece of work here; do after W1/W5/W6 have been
measured, since they shrink the same path.

### S8 — `slow_swapgs`

**Done in Round 1 — but note the premise below ("CS.RPL == 3 ⇔ user GS")
turned out to be wrong for Motor; see the Round 1 GS-model correction.**

Where: mod.rs:236, called at the top of `irq_handler_inner`,
`page_fault_handler_inner`, and every exception handler.

Two rdmsr (~100+ cycles each) per interrupt to decide swapgs, when the
interrupted CS is already on the stack. External IRQs (timer, wakeup, custom,
serial, TLB) can *only* arrive with IF=1, and every kernel window that runs
with user GS runs with IF=0 (FMASK masks IF at syscall entry; all the exit
paths cli before swapgs/sysretq/iretq) — so `CS.RPL == 3 ⇔ user GS` holds for
them and a CS check suffices. Synchronous exceptions (#PF/#GP/#DB) *can* hit
the user-GS kernel windows, so they keep the paranoid rdmsr entry (or compare
against the known per-CPU GS value — one rdmsr instead of two). Easy, pure
win for the hot IRQ path; also drop the redundant `cli` in
`naked_irq_handler` (interrupt gates already clear IF) and the extra
verification rdmsr in the swap branch.

### S9 — vector 72 handler bug

irq.rs:617: `naked_irq_handler!(irq_handler_72, 71);` — the handler for
vector 72 passes 71 to `irq_handler_inner`, so a device on vector 72 EOIs
fine but bumps metric custom-7 and wakes `USER_IRQ_WAITERS[7]` (vector 71's
waiter). With today's setup (few queues, low vectors) it may never fire —
which is why it survived — but any config with ≥9 MSI-X vectors in use will
lose interrupts. One-line fix; also worth a compile-time or boot-time
assertion tying handler ↔ vector.

### S10 — FP environment leaks across blocking syscalls

See "FPU facts". `pause()`/`resume()` never touch FPU state, but MXCSR and
the x87 control word are callee-saved in the SysV ABI, so user code legally
assumes they survive a function call (= syscall wrapper). A thread that sets
FTZ/DAZ (common in DSP/game code, and some allocators/matho libs set rounding
modes) and blocks can resume with defaults — or with another thread's flags —
depending on who xrstored on that CPU meanwhile. Rust code rarely trips this,
which is why it's latent. Fix: `stmxcsr`+`fnstcw` into the TCB in `pause()`,
`ldmxcsr`+`fldcw` in `resume()` (~20 cycles round trip), or fold into the
W5 fast path where no pause happens at all.

### S11 — no priorities / fairness classes

scheduler.rs's own header: "a process with many threads will negatively
affect a process with few threads". Everything is FIFO through two queues;
sys-io's wakeups queue behind arbitrary compute jobs; the only privilege
IO-manager threads have is the non-blocking-wait fast path. Under CPU
saturation, I/O latency degrades unboundedly (no preemption of running
threads by wakes — S16 — and no queue priority either).

Direction (W10, policy round): a small fixed ladder is enough for Motor's
scope — e.g. `IO` (sys-io/CAP_IO_MANAGER wakeups) > `Normal` > `Background`,
implemented as 2–3 queues checked in order, plus optional per-process RR
within `Normal` (index queues by process to stop thread-count domination).
Keep it simple; the "userspace can implement policy via wait/wake/swap"
philosophy mostly holds once IO is protected.

### S12 — everything lands on CPU 0

Virtio MSI-X → APIC 0 (virtio_device.rs:558), serial → BSP, system-time
updates + (debug) watchdog → BSP, and `post()`'s idle scan starts at CPU 0 so
it also fills first. The FS rounds already saw "CPU0 finally unsaturated"
only after multi-block messages. Direction (W11): let the IRQ-wait API
specify (or the kernel assign) a target CPU per vector — e.g. distribute
virtio queues' vectors across CPUs, ideally matching where the corresponding
sys-io runtime thread is affined; move serial off 0 if it ever matters. Needs
a small kernel API (`create_irq_wait_handle(cpu)`) + ioapic/MSI encoding.
With W1 in place the *cost* of a stray IRQ drops a lot, which lowers the
urgency here.

### S13 — allocation/BTreeMap churn per wait

`process_wait_handles`: `Vec<SysHandle>` + `Vec<WaitObject>` per call;
`add_wait_objects` clones into a `Vec` under a lock; every waited object gets
a `BTreeMap<ThreadId, …>` insert, and `clear_wait_objects_on_wake` removes
them again — every wait/wake cycle. The design comment (process.rs:1379)
justifies re-registration per wait, but not the allocation strategy. For the
dominant cases (1–3 handles; single waiter per IPC endpoint): inline
fixed-size arrays in `Thread` (no heap), and a single-waiter fast slot in
`SysObject` (fall back to the map only when a second waiter appears).
Combine with W5 (skip registration entirely when wakes are already pending).

### S14 — global-line traffic from every sched-loop iteration

`process_wake_events` does `WAKE_QUEUE.swap(0, AcqRel)` unconditionally —
an exclusive cacheline acquisition per iteration per CPU even when empty
(load-then-swap-if-nonzero fixes it); the global queue takes its spinlock
every 3rd iteration even when empty (unlocked `is_empty` peek first). Both
trivial; they matter because 5 polling iterations precede every halt and
busy CPUs iterate constantly.

### S15 — security hardening gaps (policy list, not a scheduler item)

No NX (EFER.NXE unset, PTE bit 63 never used): all user mappings are
executable, W^X is impossible for userspace to even opt into. No SMEP/SMAP:
kernel can execute and implicitly read/write user pages (relevant once W6b
runs syscalls on the UPT — adopting SMAP + explicit user-access windows at
that point would keep the accidental-deref protection the KPT currently
provides). No KPTI by design (VM-targeted OS; Meltdown-era hosts excepted).
Cheap first steps: enable NXE + set XD on non-code user mappings (mapping
options already distinguish them), enable SMEP. SMAP together with W6b.

### S16 — wakes don't preempt

`IRQ_WAKEUP` never preempts a running user thread, and jobs posted to a busy
CPU's local queue wait for the next natural kernel entry (tick ≤10 ms,
syscall, or device IRQ). On a mostly-idle system the idle-CPU handoff hides
this; at saturation, wake→run latency becomes tick-quantized. This is partly
a *policy choice* (throughput-friendly). Once W1's `need_resched` exists, the
wakeup IPI can set it and preempt — gated on priority (W10): IO-class wakes
preempt Normal threads, Normal wakes don't. Keep bulk throughput, fix I/O
tails.

---

## Suggested roadmap

Phase A — "stop descheduling by default" (concerns 1+2, mostly independent,
measurable individually):

1. **W4-prep (trivial fixes)**: S9 vector-72 bug; S14 lock-free empty checks;
   S8 CS-based swapgs for external IRQs. Low risk, immediate.
   **Done — see "Round 1" above** (incl. a correction to the S8 GS analysis).
2. **W1: IRQ fast-return (need_resched)** — the centerpiece. Includes S4's
   sub-issue (stop re-arming the tick on non-timer preemptions) and the
   kill/debuggee flag plumbing. Metrics to add: preempts by cause,
   fast-returns by cause.
   **Done — see "Round 2" above** (the wake flag serves as need_resched;
   fast-returns don't touch the tick deadline, so the S4 sub-issue is moot).
3. **W2: placement** — maintain `last_cpu`; same-CPU resume preference;
   idle-scan starting from last_cpu instead of 0.
   **Done — see "Round 3" above** (incl. a measured negative result: the
   "no idle CPU → queue on last_cpu" fallback convoys; the no-idle path
   must stay stealable).
4. **W5: wait-with-pending-wakers fast path** (+ S10 MXCSR fix folded in).
   **Done — see "Round 4" above** (22 % engagement; RR 182 → 137 µs, a new
   all-time record).
5. **W3: lazy FPU** for the remaining deschedules (after W1/W2 establish
   same-CPU-resume; measure first — W1 may capture most of the win).
   **Skipped — the Round 4 metrics settle the "measure first" gate**:
   post-W1 only ~23 K IRQ-preempts + ~25 K #PF-preempts per whole bench
   boot still xsave/xrstor (≈48 K pairs × ~0.2–0.4 µs ≈ 10–20 ms/boot,
   ~0.005 % CPU). W1 captured the win; lazy-FPU complexity (cross-CPU
   owner flush IPIs) is not worth it. Revisit only if preempt rates rise.

Phase B — TLB/syscall cost (S2), sequenced:

6. **W6a: GLOBAL kernel pages** (+ make kernel-region shootdowns correct —
   fixes the `validate_rsp` bug class properly).
   **Done — see "Round 5" above.**
7. **W6b: drop the KPT switch on syscalls**; replace software-walk user
   copies with direct access + checks. Re-measure IPC (FS smoke, rnetbench
   RR, getpid-style microbench).
8. **W7: direct-switch swap** (after A+B shrink the path; biggest surgery).
9. **W6c: PCID** — only if post-W6b profiles still show user-TLB pain.
10. **W8/S13: wait-path allocation elimination** (can run parallel to B).

Phase C — policy/isolation:

11. **W10/S11: priority classes** (IO > Normal > Background; per-process RR).
12. **S16: priority-gated wake preemption** (needs W1 + W10).
13. **W11/S12: IRQ spreading / IRQ→CPU affinity API.**
14. **W9/S6: in-exception minor-fault handling.**
15. **S15: NX/SMEP (any time), SMAP (with W6b).**

Dependencies: W3 depends on W1+W2. S16 depends on W1+W10. SMAP depends on
W6b. Everything else is independent enough to land and measure separately.

## Measurement plan

Baselines to capture before Phase A (all on the qemu/KVM 4-CPU rig):

- **Null-syscall RTT**: tight loop on `SysCpu` no-op (or cheapest existing
  op, e.g. `sys_cpu_usage` variant) — measures S2+entry overhead. No such
  microbench exists today (`crossbench` is FS-only; add `sysbench` to
  systest or crossbench).
- **IPC swap RTT**: two threads/processes ping-pong via swap — targets
  S3/S7; today's proxy: FS smoke (~15 µs/msg machinery), rnetbench RR
  (152.6 µs incl. network stack).
- **Preempt cost**: busy spin thread; measure achieved work/s with tick at
  100 Hz vs the same with device IRQ storm directed at its CPU (S1).
- **Fault cost**: `test_lazy_memory_map`-style first-touch over N pages,
  pages/s (S6).
- **Existing suite**: systest (has `test_liveness` p50/p99 wake latency),
  FS smoke same-run-number comparison (bench trap from memory), rnetbench
  RR/bulk before/after each phase — these guard against regressions in the
  paths that were just optimized in the net/FS rounds.
- **New kernel metrics** (cheap counters, sysio-stats style): preempt count
  by cause, IRQ fast-return count, xsave/xrstor count, thread migrations,
  resume-same-cpu vs moved, wait-fast-path hits.

## Key code references

- sched loop / post / timers: `src/sys/kernel/src/sched/scheduler.rs`
  (:318 sched_loop, :529 post, :629 on_timer_irq, :656
  ensure_preemption_timer, :303 program_idle_timer)
- IRQ dispatch: `src/sys/kernel/src/arch/x64/irq.rs` (:510
  irq_handler_inner, :540/:548/:562/:576 per-IRQ arms, :617 the vector-72
  bug, :867 wake_remote_cpu)
- context switch asm + TCB: `src/sys/kernel/src/arch/x64/syscall.rs`
  (:233 spawn, :272 exit, :340 pause, :357 resume, :396/:424 preempt,
  :442 resume_preempted, :494 thread_off_cpu_reason, :633
  syscall_handler_asm)
- swapgs / GS: `src/sys/kernel/src/arch/x64/mod.rs` (:236 slow_swapgs)
- thread state machine: `src/sys/kernel/src/uspace/process.rs` (:1414 wait,
  :1465 on_thread_paused, :1550 post_wake, :1664 post_wake_locked, :1848
  on_pagefault, :1914 on_thread_descheduled)
- wait/wake/swap syscalls: `src/sys/kernel/src/uspace/sys_cpu.rs` (:189
  sys_wait_impl, :260 the always-yield comment, :273 do_wake)
- wake queue: `src/sys/kernel/src/uspace/sysobject.rs` (:165 wake_irq, :275
  process_wake_events)
- paging / kernel-in-UPT: `src/sys/kernel/src/arch/x64/paging.rs` (:673
  map_kernel_to_user), `src/sys/kernel/src/mm/user.rs` (:576 read_from_user)
- MSI-X → CPU0: `src/sys/lib/virtio-async/src/virtio_device.rs` (:558)
