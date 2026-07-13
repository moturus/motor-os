# Scheduler / syscall / IRQ handling: analysis and improvement plan

Date: 2026-07-12. Branch: agent-tree. Analysis only — no changes made yet
(except the already-landed tickless-idle work, see "Round 0" below).

All line references are to the current working tree (with the tickless-idle
changes applied, uncommitted).

---

## TL;DR — ranked findings

| # | Finding | Type | Cost today | Fix effort |
|---|---------|------|-----------|-----------|
| S1 | Every IRQ landing in userspace fully deschedules the thread (xsave, 2×CR3, job queue round trip, xrstor) — even when nothing else is runnable | perf | ~1–3 µs direct + TLB refill (dominant) per IRQ | medium |
| S2 | Every syscall switches CR3 to KPT and back; no PCID, no GLOBAL pages ⇒ 2 full TLB wipes per syscall, 2 more per preempt/resume | perf | dominant hidden cost of IPC | medium–large |
| S3 | `sys_wait` always pauses, even with wakers already pending ("wait is at least a yield") ⇒ full deschedule + job round trip + possible CPU migration for a no-op wait | perf | ~2×5 µs per IPC RTT | small |
| S4 | Preempted threads are re-queued to "first idle CPU by index", not their last CPU; `last_cpu` field exists but is never written ⇒ constant migrations, cold caches/TLBs | perf | unquantified, likely large | small–medium |
| S5 | xsave/xrstor (full RFBM=~0) on every uspace IRQ and every uspace #PF, even when the same thread resumes on the same CPU (the common case) | perf | ~500–1000 cyc + 2×~1 KB memory traffic per IRQ | small once S1 lands |
| S6 | Every demand page fault costs the full preempt/deschedule machinery | perf | ~2–5 µs per minor fault | medium |
| S7 | `swap` (IPC handoff) round-trips through the job queue instead of switching threads directly | perf | queue + locks + latency per message | large |
| S8 | `slow_swapgs()`: 2–3 rdmsr on every IRQ and #PF entry | perf | ~200–500 cyc per IRQ | small |
| S9 | Vector 72 is registered with irqnum 71 (`naked_irq_handler!(irq_handler_72, 71)`) ⇒ devices on vector 72 wake the wrong waiter | **bug** | correctness | trivial |
| S10 | MXCSR / x87 CW are not preserved across blocking syscalls (pause/resume skips FPU entirely) ⇒ another thread's FP env can leak in | **bug** (latent) | correctness | small |
| S11 | No priorities, FIFO everywhere; sys-io competes equally with bulk compute; a many-threaded process starves others | isolation | I/O latency under load | medium |
| S12 | All device IRQs (virtio MSI-X) + serial + system-time duty target CPU 0 | isolation/perf | CPU 0 saturation (seen in FS rounds) | medium |
| S13 | Per-wait heap churn: `Vec` allocs + per-object `BTreeMap` insert/remove on every wait | perf | allocs on the hottest path | medium |
| S14 | Every sched-loop iteration on every CPU does an atomic **swap** on the global `WAKE_QUEUE` and takes the global-queue spinlock every 3rd iteration even when empty | perf | cross-CPU cacheline traffic | trivial |
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
2. **W1: IRQ fast-return (need_resched)** — the centerpiece. Includes S4's
   sub-issue (stop re-arming the tick on non-timer preemptions) and the
   kill/debuggee flag plumbing. Metrics to add: preempts by cause,
   fast-returns by cause.
3. **W2: placement** — maintain `last_cpu`; same-CPU resume preference;
   idle-scan starting from last_cpu instead of 0.
4. **W5: wait-with-pending-wakers fast path** (+ S10 MXCSR fix folded in).
5. **W3: lazy FPU** for the remaining deschedules (after W1/W2 establish
   same-CPU-resume; measure first — W1 may capture most of the win).

Phase B — TLB/syscall cost (S2), sequenced:

6. **W6a: GLOBAL kernel pages** (+ make kernel-region shootdowns correct —
   fixes the `validate_rsp` bug class properly).
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
