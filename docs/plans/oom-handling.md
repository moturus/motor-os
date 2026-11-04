# Replace memory admission control with kernel OOM killing

Adopted plan, in progress on branch `oom-handling`. Replace reservation-based
admission with simple physical-memory limits, fallible user-page allocation,
and kernel OOM jobs. Kill recent None-role processes first, then Interactive
processes if needed. The status section records what has landed; the sections
after it are the specification, each opening with its own state.

## Status

As of 2026-11-04:

| Step | Work                                                      | State                                   |
|------|-----------------------------------------------------------|-----------------------------------------|
| 1    | Admission cleanup, 4 MiB spawn and memfs checks           | Committed, `60c5cd09`                   |
| 2    | Two process IDs, statistics maps and lookups              | Committed, `02e9c17b`                   |
| 2a   | Live `free_pages` count, no pressure flag (proposal 5)    | Committed, `2e9c6a64`                   |
| 3    | Release user memory at process exit                       | Committed, `cda3c9d3`                   |
| 4a   | Fallible MM core, boot exhaustion self-test               | Committed, `3780bce0`                   |
| 4b   | Fallible frame-descriptor slab growth                     | Committed, `56eedffb`                   |
| 4c   | Real error codes in the syscall and process layers        | Committed, `b2dccf4e`                   |
| 5a   | Packed accounting, physical charges and transition tests | Committed, `dcd36704`                  |
| 5b   | Recipient classes and typed MM allocation failures       | Committed, `b71cad30`                  |
| 5c   | Scheduler dispatch, victim cleanup and OOM diagnostics   | Committed, `8c3a0b6f`                  |
| 5d   | Syscall retries, fault waiters and pager partial progress | Committed, `fdca1b82`                 |
| 5e   | Activation and native guest pressure tests               | Validated locally, awaiting review   |
| 5f   | Documentation, abort verification and developer gate     | [Planned](oom-handling-step5.md)      |

What the committed steps provide is described in
[docs/oom-handling.md](../oom-handling.md) and
[docs/kernel-mm.md](../kernel-mm.md). In short: admission, floors,
reservations, commitments and `AdmissionStats` are gone; spawns are refused
below 4 MiB by sys-io and by the kernel at creation and at the first `Created`
to `Running` transition; memfs refuses allocating mutations below 4 MiB;
`free_pages` is the allocator's live count; every process has a monotonic
`kernel_pid` beside its `user_pid`; a process's user memory goes back at exit
and an address space hosts one process; every page acquired for a
process's mappings is acquired fallibly, with the partial mapping unwound,
through frames, the per-space descriptor slabs, page-table growth, eager
mappings, lazy faults, pager fills, sharing, construction, both stacks and
the frame-descriptor slab's growth; and the memory syscalls and process
creation answer with the memory manager's own codes. The kernel heap stays
outside the guarantee by design.

Left to do:

- Review the validated local 5e activation. Policy is armed
  immediately before sys-io starts, after boot exhaustion and scheduler setup.
  Native console tests cover pressure, victims, syscall/fault waits, recovery
  and cancellation. Three full gates passed in each build, including a real
  one-vCPU run in each.
- Complete 5f: update production documentation, verify the victimless abort
  in a separate guest, and run `full-test-dev.sh --release`, as staged in
  [oom-handling-step5.md](oom-handling-step5.md).
- The three deferred issues at the end of this document.

## Intended behavior

Use actual free physical memory (`phys::available_small_pages()`), without
subtracting reservations or executable commitments. All sizes below are binary.

Publish that count as `KernelStaticPage::free_pages: AtomicU64`, replacing the
removed admission counters without moving earlier fields. It is the allocator's
live count: one snapshot when the kernel address space is created, then the
delta of every charge and release as a relaxed atomic add or subtract. There is
no published pressure flag; userspace compares the count with
`moto_sys::LOW_MEMORY_PAGES` (4 MiB) through `moto_sys::low_memory()`.
The allocator's internal count, OOM phase, generation and System block
change together in one atomic word. Kernel allocation checks use that
authoritative word, not a sample of the userspace mirror.

Only `ProcessRole::System` grants permission to allocate while an OOM run is
active. OOM killing also spares sys-io and its direct children and grandchildren
regardless of role; parentage alone grants no allocation privilege. DNS (None)
and russhd (Interactive) remain protected from killing, but their allocations
and faults that need new pages wait while a run is active.

| Physical free memory  | Action                                                        |
|-----------------------|---------------------------------------------------------------|
| < 4 MiB (1,024 pages) | Deny memfs mutations and process starts; allow reads/deletes. |
| < 2 MiB (512 pages)   | Start OOM killing; only unblocked `System` may allocate while it runs. A floor refusal below 3 MiB can also start it from Idle. |
| 512 KiB floor (128 pages) | A System floor refusal blocks System allocations/faults for the run; a kernel allocation crossing below 128 also sets this block. |
| >= 3 MiB (768 pages)  | End the OOM run; everyone allocates again.                    |

A run that started below 2 MiB or at a floor refusal stays active between
2 and 3 MiB. While it is active, allocation requests and faults from processes
without the System role wait for recovery. Once the System block is set,
System allocation requests and faults also wait until the run finishes;
crossing back above 512 KiB alone does not clear it. A victimless end at
2–3 MiB clears this block but keeps the non-System gate latched. Existing
mappings and operations that free memory remain usable. Below
4 MiB, deny memfs mutations that may allocate, including write, copy, create,
and move. Reads, stat, list, and deletes remain allowed. Allocating mutations
are allowed again at 4 MiB.

- Make every kernel allocation of user pages fallible and propagate failures
  through the mapping paths. Kernel-heap exhaustion remains outside this guarantee.
- Deny new process starts below 4 MiB free. sys-io rejects spawn requests
  with `E_OUT_OF_MEMORY`, including requests made by system processes. Also
  reject `Process::new_child` in the kernel at the same limit, against the
  allocator's count.
  Creation returns a stopped child, so enforce the rule again at its first
  `Created` to `Running` transition: a later parent wake must not bypass it.
  Keep the bootstrap `Process::new` path separate from runtime spawn checks.
- Walk eligible `ProcessRole::None` processes newest first by `kernel_pid`.
  Only after that walk completes, escalate to Interactive if memory stays low.
  Recheck free memory and generation before committing each kill and after
  the victim releases memory.
- If no eligible victim remains, abort only if free memory is still below
  2 MiB, after pending non-debugger exit cleanup has completed, printing
  remaining processes and their memory usage first. At 2–3 MiB, log that
  OOM could not reach 3 MiB and finish the run without aborting.
- Clear a process's user memory on every exit, including OOM kill, even if
  another process still holds its process or address-space handle.
- Remove the old admission policy in **one cleanup patch**, replacing the memfs
  reserve with the simple 4 MiB check.

Keep independent security checks, per-process memory limits, filesystem
capacity limits, socket/channel limits, and ordinary backpressure. Keep
low-memory reclamation of unused allocator/cache memory.

## Process IDs and lookup

Done in `02e9c17b`.

Each process has two IDs:

- `kernel_pid`: a monotonically increasing `u64`, never reused or wrapped.
  **Panic the kernel if the u64 limit is reached.**
- `user_pid`: the current public PID, retaining its existing wrap and reuse
  rules. Existing syscall arguments, process-info fields, and metric scopes
  continue to use this ID.

Until `user_pid` first wraps, `kernel_pid == user_pid`. Allocate both in the
existing serialized PID path. Failed construction may consume IDs; no special
user-PID reservation rollback is needed.

Use simple `BTreeMap`s in the existing statistics tree:

```text
KProcessStats::children             kernel_pid -> Weak<KProcessStats>
KProcessStats::children_by_user_pid user_pid   -> kernel_pid
```

`Weak<Process>` is also acceptable if it makes the code simpler.
`SYSTEM_STATS` has all processes as its children. Key parent child maps by
`kernel_pid` as well. Use the user-PID maps for public lookup and enumeration:
list ordering and pagination must remain in `user_pid` order after wrap.

Keep the maps consistent using existing locking. OOM selection scans all of
`SYSTEM_STATS.children` using `for_each_child` adapted to kernel PID keys.
Upgrade each weak reference under the map lock, then compare or drop candidates
after releasing it. Select None before Interactive, then the largest `kernel_pid`
within that role. Carry the kernel identity through posted jobs so user-PID reuse
cannot change the target. Public enumeration continues to use the user-PID maps.

The main changes are in `uspace/process.rs` and `xray/stats.rs` under
`src/sys/kernel/src`. No new registry abstraction or intrusive index is needed.

## Fallible user-page allocation

The audit list below is done: the MM core in steps 4a and 4b, the error
codes of `sys_mem.rs` and `process.rs` in 4c. The gates, waits and fault
parking from the paragraph on pausing at syscall entry onward are step 5.

Audit the complete mapping path, not just data-frame allocation. Relevant
kernel code:

- `mm/phys.rs`: expose the existing fallible frame allocation and propagate
  failures through small, huge, contiguous, and MMIO bookkeeping paths.
- `mm/slab.rs`: propagate existing fallible descriptor allocation to user mappings.
- `mm/virt_intrusive.rs`: propagate failure from page/segment descriptors,
  eager mappings, lazy faults, sharing, and file-page fills.
- `arch/x64/paging.rs`: remove allocation unwraps in page-table growth and
  unwind partially created tables.
- `mm/virt.rs` and `mm/user.rs`: make address-space initialization, fixed
  shared pages, mappings, and stack allocation fallible.
- `uspace/sys_mem.rs`, `sys_obj.rs`, `sys_cpu.rs`, `process.rs`, and
  `pager.rs`: propagate errors to callers instead of unwrapping or replacing
  allocation errors with unrelated errors.

Pause userspace allocation calls the gate denies at the outer syscall boundary,
after validating/resolving what is needed to identify the recipient and before
the allocating attempt. Release that lookup's owned resources before waiting.
Do not replace these waits with immediate `E_OUT_OF_MEMORY` returns. Once an
allocation is allowed to run:

- Return `E_OUT_OF_MEMORY` for an unsatisfied contiguous request; retain the
  normal small-page fallback for an opportunistic huge-page allocation.
- The floor depends on the role of the process allocated for, never on the
  request's size: an Interactive or None allocation never takes the pool
  below 2 MiB, a System allocation never below 512 KiB. A true floor
  refusal below 3 MiB starts OOM killing from Idle. During Killing or
  Latched, None and Interactive allocations are denied by a gate, not by
  substituting a higher numeric floor. A System floor refusal also sets
  the System block. (Revised 2026-11-03: the former rule that rejected
  requests of 2 MiB or more at once is withdrawn.)
- Never allow a non-kernel allocation, including a system process's allocation,
  to leave less than 512 KiB free. Reject it before committing the allocation.
- Preserve existing errors for invalid requests and per-process memory limits.

Use actual physical consumption, including huge-page rounding. Pass the
recipient's allocation class to the physical allocator; serialize its gate,
floor and count check with the charge in the same CAS. Do not pass a cached
numeric floor that can survive a phase change. Validate a suitable block under
its existing lock before charging, then commit ownership without another
fallible step. Failed searches and rejected charges consume no count. These
are allocation checks, not future reservation or commitment accounting.

Preserve pressure provenance through internal MM results: distinguish a
closed gate and a physical shortage from existing error codes, including
per-process-limit and virtual-address exhaustion errors. Pressure results
carry copyable class/generation/refusal information, not owned resources.
There is no new userspace error code.

Roll back incomplete mappings, frames, descriptors, and accounting before
waiting or returning an error. At the outer syscall boundary, a closed-gate
result waits for the recipient gate, or retries if it already opened. After a
physical shortage, sample free pages after rollback: at least 3 MiB returns
`E_OUT_OF_MEMORY`; below 3 MiB joins/requests reclamation and waits for the
refused attempt's generation to change and the recipient gate to permit a
retry. Recheck the count atomically when requesting a run, so recovery cannot
be followed by a stale start request. A System role alone does not satisfy a
wait caused by a refused allocation. If the refusal's run already ended,
preserve that completion and recheck the gate; do not retag its wait with a
new generation. A refusal that had no run uses the generation returned by
joining/requesting one.

A retry still blocked after a spurious wake carries its existing wait reason,
not a new physical-shortage receipt. Recovery racing this recheck permits a
retry; it cannot return permanent OOM without a new allocation attempt.

Thus a large eager request that restores at least 3 MiB by rolling itself back
returns OOM. A request whose post-rollback count remains below 3 MiB waits,
regardless of size. In an unchanged Latched state, an unsatisfied System
request waits for a later state change instead of restarting the same
victimless scan. Smaller System requests that fit can proceed.

Failed shared replacement must preserve the old destination; failed lazy
faults must not claim a page is mapped when it has no PTE. Pager fills retain
their explicit partial progress: keep installed pages and a copyable installed
count, release source pins before waiting, revalidate mapping identity on
retry, and resolve completed-page waiters outside MM locks.

Apply the kernel limits wherever physical pages are acquired for a process,
including faults, remote mappings, metadata, frame-descriptor slab growth and
page-table growth. Both a process's user and kernel stacks use its class;
placement in a kernel region does not by itself make an allocation exempt.
Pass the class explicitly through shared kernel regions/slabs when necessary.
Check each recipient's role, including both sides of a sharing operation that
can allocate metadata, so a System caller cannot bypass a non-System target's
limits. A process-less space counts as None until a successful process claim;
claim rollback restores None. Publish the role with the serialized claim.
Explicitly claim bootstrap sys-io's space as System before `Process::new`
constructs its stacks: that path bypasses `new_child` and its runtime claim.
For now, a sys-io caller may pause on a user target's allocation. Let OOM run and
then resume sys-io; add no separate deferred-request or service-progress machinery.

Park allocating syscalls the way faults are parked: a kernel-owned vector of
weak thread references and copyable wait reasons beside the fault queue in
`KernelAddressSpace`; add no static. Register under the waiter lock, recheck
the complete wait condition under that same lock, and return at once if it is
already satisfied. Otherwise pause with `Thread::oom_wait()`, not
`Thread::wait()`: the latter drains the thread's pending-wake latch, which the
userspace wait after the syscall still needs. The pause sleeps only while the
queue still owns the thread's resume; whoever removes the entry resumes the
thread with `Thread::oom_resume()`, which only moves an InWait thread to
Runnable. After any wake, recheck the recipient gate and any refused-attempt
generation, and register again if still blocked. Nothing is owned across the
pause.

Faults use the pager's existing park state: `Preempted` with no resume job.
Keep a vector of weak thread references and copyable wait reasons in the same
kernel-owned state. Register and recheck the complete condition against
recovery under the waiter lock. Whoever removes an entry owns its sole resume;
use the pager's status-checked resume path after releasing that lock.
Recheck queued faults under the lock and retain blocked entries in place;
detaching and later reinserting them must not lose a concurrent recovery.
Do not resume a killed thread or post duplicate resumes. Invalid/protection
faults retain their existing handling. A valid fault with a typed pressure
failure retries if recovery raced the failure; a later count of at least
3 MiB must not turn that recoverable result into a fatal fault. Apply this
to the pager's zero-fill path as well, without registering the same thread
in both the pager and OOM queues.

The end of an OOM run wakes the object and fault waiters
through the existing scheduler, outside allocator, run-state, process-list,
and waiter locks. Each waiter rechecks its own gate; waking grants no allocation
privilege. Unwind partial work and release MM locks before parking. Use existing
kill/wake handling, ensuring registrations are cleaned up even if the thread is
killed between registration and the pause.
Killed syscall stacks are discarded without Rust destructors. Release temporary
buffers, pins, and owned references before parking, or keep them in thread-owned
wait state that exit cleanup releases; do not rely on unwinding a killed stack.
In particular, put the retry loop above `sys_obj_impl`'s URL-owning helpers and
above `sys_pager`'s caller-`Arc` scope. Inner operations return copyable wait
outcomes, finish cleanup, and only then may the outer syscall loop park.
Re-read URLs and re-resolve/revalidate handles on retry. Cover every `OP_MAP`
flavor, thread spawn, address-space creation, shared IPC get, pager reserve
and pager fill. `zero_from` itself does not allocate. Process creation/start
keep their existing 4 MiB refusal instead of sleeping in construction.

Kernel allocations are exempt from the userspace gates. Keep existing scheduler,
queue, and kernel-heap allocation behavior; add no emergency reserve, preallocated
job storage, or general fallible `Arc`/`Box`/collection conversion. If the kernel
itself runs out of memory, its existing OOM failure is accepted.

## Release user memory on exit

Done in `cda3c9d3`, including the one-process claim on an address space.

Add an explicit, idempotent user-memory clear operation to
`UserAddressSpace`. Call it from normal process exit completion, and retain
final-drop cleanup for unused or partially constructed address spaces.

Today bulk mappings are freed in `UserAddressSpaceBase::drop`, so outstanding
handles can retain an exited process's memory. Move that work into exit:

1. Stop the threads and finish their stack/TCB cleanup. An empty thread map is
   insufficient: today threads are removed before their cleanup runs outside
   the process lock. Wait for that cleanup to finish before clearing memory.
2. Retire pager mappings and close the process's IPC endpoints.
3. Clear normal/custom user regions, private fixed pages, and reclaimable
   mapping metadata; complete TLB invalidation before frames are reused.
4. Publish exit completion and continue OOM handling if pressure remains.

Serialize the clear against remote mapping and pager operations so a retained
handle cannot repopulate an exited address space. Shared/pinned frames remain
alive until their last reference is released. Later object destruction must
not free pages twice. Keep kernel mappings and the page-table root alive for
as long as the remaining address-space object requires them.

## OOM jobs

Worker and exit-continuation machinery committed in 5c (`8c3a0b6f`); waiter
integration committed in 5d (`fdca1b82`). Local 5e changes activate runtime
policy and add guest pressure tests; validation passed and review is pending.
This section specifies the completed behavior.

Use posted jobs on the existing scheduler. **Do not create a worker thread.**
The pool's atomic word contains the count, armed flag, Idle/Killing/Latched
phase, generation and System block. The step-5 plan specifies its bit budget
against the existing 64 GiB allocator cap; generation reuse is forbidden.
Keep slow-path job, pending-exit and waiter bookkeeping beside the pager
registry in `KernelAddressSpace`, with no new static. Do not keep a victim
cursor or current role. Each selection scans the whole process list for the
newest eligible None process, falling back to the newest eligible Interactive
process only when no eligible None remains. This costs one traversal per
victim on the OOM path.

Use actual parentage to protect sys-io and its direct children and
grandchildren, not `SYSTEM_STATS`' aggregate child index. This protects DNS
(None) and russhd (Interactive), both launched by sys-init, a child of sys-io.
More distant descendants, such as their user sessions, remain eligible unless
they have the System role. Identify sys-io by its public `PID_SYS_IO` in the
process-stat entries; victim ordering still uses monotonic kernel PIDs.

Charge/release and refusal transitions change policy and count together,
covering small, huge and contiguous paths. A drop below 2 MiB from Idle or
Latched starts a fresh generation; a floor refusal below 3 MiB can start one
from Idle. A System floor refusal or a Kernel charge below 128 pages sets
the System block until the run ends. The pool records attention and, only
when armed, pokes a scheduler. It never posts, wakes, logs, allocates or
acquires the slow-path OOM lock while inside allocation callers' locks.

Dispatch from `sched_loop` beside `process_wake_events()`, holding no other
lock. Attention is only a scheduling hint; policy history lives in the
atomic word. Keep at most one queued/running selection per generation and
one committed victim awaiting cleanup. Release bookkeeping locks before
posting, logging, waking or resuming. Every selection starts from the whole
set, so a new run gives priority to the newest eligible None process.

When free memory reaches 3 MiB, the releasing CAS changes to Idle, clears
the System block and increments the generation. Scheduler dispatch later
wakes surviving allocation/fault waiters. Already committed kills still
finish normal exit cleanup. Queued jobs and pending-victim records carry
their generation; stale work cannot select victims or change the new run.
No queue removal or general cancellation API is needed. Recovery followed
by renewed pressure before dispatch must still invalidate the old work:
sampling only the latest count is insufficient.

Each job:

1. Checks the authoritative generation and Killing phase, which guarantees
   fewer than 3 MiB free.
2. Scans for the eligible live process ranked first by None before Interactive,
   then by largest `kernel_pid`, skipping dead, already-exiting, and protected
   processes. Keep only the best candidate, not a snapshot of the list.
3. Rechecks eligibility, then loads the state word with Acquire ordering under
   the bookkeeping lock to validate Killing and the generation before recording
   the pending victim. This load is the kill request's ordering point. Count
   changes within the run do not cancel a kill. Recovery before the load cancels
   selection; recovery after it allows this committed kill to finish. Call the
   normal termination machinery only after releasing locks. Created and parked
   threads use their existing exit paths; paused debuggees are skipped as
   described under deferred issue 2.
4. Waits for kernel exit cleanup. The completion hook and post-kill completion
   check claim the same pending record, so exactly one clears it and requests
   scheduler attention. Retain that record across recovery until cleanup
   actually completes; a later run waits for the occupied victim slot.

An old exit retires only its own `(generation, kernel_pid)` record. It does
not attach the current generation to an old continuation. Scheduler dispatch
separately determines what work the current state needs. Likewise, stale jobs
may clear only their own queued/running slot.

Do not hold process-list or allocator locks across termination or cleanup.
Repeat selection while free memory stays below 3 MiB. Skipping terminated/exiting processes
makes progress without a stored cursor. The complete None walk emerges from the
selection rule; the protected DNS resolver does not prevent escalation. No separate
pass transition or new-arrival handling is needed.

Before a victimless decision, wait for existing non-debugger exits whose
user-memory cleanup has not completed, even if OOM did not initiate them.
Use existing process status and exit notifications, not a second registry.
Record interest before the final status scan and reconcile racing notifications
before releasing the job slot. Wait without reposting scans until an exit
notification or generation change; every completed exit can supply that wake.
If no eligible None or Interactive processes remain after pending exits have
completed, atomically recheck generation, phase and free memory:

- Below 2 MiB: print physical free memory and every remaining process's name,
  both PIDs, and existing user/kernel memory counters to the console, then abort
  the kernel. Use direct output without allocating a process-list snapshot or
  relying on userspace services. After reporting, load a fresh snapshot
  and abort only if the generation still matches, the phase is Killing, and
  the count remains below 2 MiB. The count can rise to 2 MiB within the same
  generation, so the count check remains necessary.
- At least 2 MiB but below 3 MiB: log the free memory and that OOM could not reach
  3 MiB, then finish the run. CAS to Latched and increment the generation
  (kernel-internal state; nothing is published), clear the System block and
  wake waiters to recheck their gates. Only eligible System allocations may
  proceed; protected None and Interactive targets still wait for 3 MiB.
  Do not abort or spin.
- At least 3 MiB: finish normally and wake surviving waiters.

Waiters must recheck their process, target address space, generation condition
and allocation limits before retrying. A System waiter released by a latched
end may try again; if the unchanged latched state still cannot satisfy it,
wait for a later transition instead of restarting the same victimless scan.
Such a refusal does not set a run-wide System block while Latched; smaller
requests may still proceed.
After a stop at 2–3 MiB, a later drop below 2 MiB starts a fresh generation
even though the latch was set. Keep this explicit restart trigger. Do not
spin while free memory remains between 2 and 3 MiB.

Arming is a one-time operation in `init::start_userspace_processes`, after
bootstrap sys-io construction and immediately before its first start. All
per-CPU schedulers must already be published and both syscall/fault consumers
installed. Before arming, floors are zero and producer hooks cannot poke or
access scheduler state, preserving the boot exhaustion tests. Arming checks
the initial count atomically rather than discarding concurrent attention.

## One admission-cleanup patch

Done in `60c5cd09`; `2e9c6a64` then replaced the retained pressure flag with
the live `free_pages` count.

The first patch removes the old admission policy across the repository while
retaining the pressure flag, sys-io's spawn refusal, and the replacement memfs
check. Fallible allocation, exit reclamation, and the new kernel limits and OOM
jobs follow in separate patches.

The cleanup includes:

- Kernel `mm/admission.rs`, floors, charges, reservations, executable
  commitments, admission call sites, and address-space admission classes.
  Retain pressure publication independently of admission.
- `AdmissionStats`, its query, shared admission counters, and obsolete
  refusal/floor/commitment metrics. Preserve the pressure flag's ABI offset
  and unrelated physical-memory statistics. Replace the removed counters with
  `free_pages` and publish it with pressure updates in this same cleanup patch;
  sys-io reads it directly for the memfs check.
- sys-io `runtime/net/pressure.rs`, request/client refusals, parked listener
  replenishment, and its recovery task.
- sys-io filesystem pressure gates and the old 8/16 MiB memfs reserve in
  `runtime/fs.rs` and `runtime/fs/admission.rs`. Replace the reserve with a
  4 MiB check against actual free physical memory, for every guest size. Deny
  memfs mutations that may allocate, including write/copy/create/move;
  allow read/stat/list and delete. Reclaim unused cached blocks, recheck, then return
  `StorageFull` if still below 4 MiB. Keep capacity/cache sizing and unused-cache
  reclamation.
- Pressure-only gates in client runtime spawn, russhd, and strobe. Keep the
  cheap sys-io spawn refusal and the kernel creation/start checks while pressure
  is raised, handling of actual allocation failures, and allocator slack reclamation.
- Tests and documentation tied to admission refusal, floors, and guaranteed
  executable commitments.

Preserve capability checks and donated-page cleanup in other FS rejection
paths. Preserve unrelated mechanisms such as vsock admission and Lorry
workspace admission. Listener replenishment must still handle real allocation
failure after its pressure-specific recovery task is removed.

Update `docs/oom-handling.md` and the relevant memory/memfs documentation.
All work stays in the main repository.

## Patch sequence

1. Land the large admission-cleanup patch above, including removal of
   obsolete admission tests and documentation updates. Keep the pressure flag
   and spawn refusals in sys-io and the kernel. Publish `free_pages` and replace
   the old memfs reserve with the 4 MiB check. *Done, `60c5cd09`.*
2. Add the two process IDs and update the statistics maps/lookups. A
   follow-up patch then replaced the published pressure flag with the live
   `free_pages` count (proposal 5 below). *Done, `02e9c17b` and `2e9c6a64`.*
3. Clear user memory during process exit. *Done, `cda3c9d3`.*
4. Make user-page allocation fallible, splitting the MM changes into small
   patches with their tests. *Done: 4a, the MM core with a boot
   exhaustion self-test (`3780bce0`), 4b, frame-descriptor slab growth
   (`56eedffb`), and 4c, real error codes in the syscall and process
   layers with systest coverage (`b2dccf4e`), are done.*
5. Stage atomic accounting/policy, recipient classes and internal results,
   scheduler jobs, and both syscall and fault waits while runtime policy
   remains unarmed. Enable the complete mechanism only after all consumers
   are present, then complete pressure, blocking, recovery and abort coverage.
   *5a–5d committed; 5e implemented and validated locally, awaiting review; 5f planned in
   [oom-handling-step5.md](oom-handling-step5.md).*

Step 1 is the single large cleanup patch. Keep subsequent patches small,
normally 100–300 changed lines including tests; split dependency stages
further rather than treating a stage as permission for a large commit.

## Validation

Covered so far: the PID items; allocation failure and rollback at every
boundary that returns an error, by the debug boot exhaustion self-test, with
contiguous failure and huge-page fallback (the floors belong to step 5), and
the exact syscall codes by systest; exit
and kill releasing memory with handles held; the FS, networking, logging and
spawn items; and the quiescent `free_pages` comparisons. The boundary, victim,
episode, waiter and parked-allocation items are step 5.

Run kernel tests inside Motor OS and include regressions in
`src/tests/full-test.sh`, directly or through systest:

- PID equality before user-PID wrap, newest-first selection after wrap, and
  unchanged public PID ordering and pagination.
- Allocation failure and rollback at data, metadata, page-table, mapping,
  and address-space construction boundaries that return errors. Cover contiguous
  failure, huge-page fallback and both large-request outcomes: rollback to at
  least 3 MiB returns OOM; rollback below 3 MiB enters the wait/retry path.
- Normal exit and OOM kill releasing user memory while handles remain held;
  shared pages, pending pager fills, and concurrent thread exit remain safe.
- Boundaries at 4 MiB, 2 MiB, 512 KiB, and 3 MiB recovery; syscall and fault
  blocking for ordinary and System processes. Check large requests that reach
  the floor and concurrent requests against the floors. Verify that gate-denied
  calls park at entry, recovery cannot make a pressure fault fatal, quota errors
  retain their codes, and independent kernel allocations remain exempt. Cover
  both process stacks and allocation of MM metadata under the recipient's class.
- Victim order within each role and escalation only after the None walk completes.
  Spare DNS, russhd, and other protected services; user descendants remain eligible.
  Verify that ancestry alone gives no allocation privilege: protected None and
  Interactive services still pause allocations/faults while a run is active.
- Stop after sufficient reclaim, continue across small victims, and recover
  across repeated episodes. Account for total reclaimed memory when asserting
  that another victim is required; a 1 MiB buffer alone does not guarantee a
  prolonged pressure window. Cover concurrent pressure and single-CPU progress.
- Reject all new process starts under pressure, including a spawn begun before
  pressure rose, a stopped child woken later, and a start job already queued.
  Cover direct kernel creation requests as well as sys-io spawning.
- Clear and immediately re-raise pressure while an old job or victim-exit
  callback is pending, including both transitions before scheduler dispatch.
  Start again at the newest None process; stale callbacks must not select
  another victim or disturb the new run or its waiters. Retire existing victim
  cleanup before allowing a new selection; wait for unrelated pending exits
  before declaring the run victimless.
- Recovery between wait registration and pause must not lose a wake. Cover kill
  before/during the pause, spurious wakes, gate rechecks, and duplicate fault resumes.
- Parked allocations/faults resume when allowed; killing a parked process cancels
  its wait and releases resources from every suspended syscall frame. Cover
  created victims and skipping debugger-paused processes. With no victims left,
  verify logging and System waiter progress at 2–3 MiB, including exactly 2 MiB,
  and later OOM reactivation. Verify the console memory report and abort below
  2 MiB in a separate disposable guest run.
- FS, networking, logging, and spawn behavior with the old admission gates removed
  and the new memfs limit in place. Verify that memfs write/copy/create/move are
  rejected below 4 MiB while read/stat/list and delete still work.
- At quiescent checkpoints, compare shared `free_pages` with the allocator count
  after small, huge, and contiguous allocations/frees; preserve shared-page offsets.

Replace old squeeze tests that expect a None child to remain alive at the
admission floor. Preserve their useful resource-leak and service-recovery
coverage. Prepare children, buffers and synchronization resources before
pressure. Use separate eager syscall and lazy fault drivers; prove that the
intended worker registered a wait, with its thread state as additional evidence
for syscalls. Do not infer waiting from global counters alone or victim order
from parent `wait()` order. The step-5 plan defines the bounded, evidenced
pressure-window attempts; observed failures are never retried as missed windows.

Run System-role tests from the existing System console fixture and assert the
helper's role; an ordinary SSH process cannot grant itself System. Use actual
one-vCPU guests (`src/tests/full-test.sh --cpus 1` and the release counterpart)
for scheduler progress, alongside normal multi-vCPU runs. `systest --host-cpus=1`
only sizes workloads. Keep boot exhaustion unarmed, guard producer-side pokes
before scheduler publication, and test policy transitions with existing
in-guest scratch-pool hooks rather than a new live-pool boot drain.

Keep routine diagnostics small: physical free memory, OOM selections and the
victim's two IDs; print the full process memory list only before abort. The four
production metrics are `OomRuns`, `OomKills`, `OomParkedSyscalls` and
`OomParkedFaults`, with process attribution for the waiter counters. A short run
that ends before scheduler dispatch is counted without requiring an event queue
or an individual log entry. Add no test-only metrics or control hooks.

Follow `AGENTS.md`: format with the repository toolchain, introduce no new
warnings, and pass the main full-test gate at least three times each in debug
and release before committing core patches. Include at least one real one-vCPU
run in each build's activation validation. Run the completed transition
through `src/tests/full-test-dev.sh --release`; its developer-source phase
also stays release-only. Diagnose failures rather than masking them with
retries or longer timeouts.

## Simplification proposals

The simplifications reviewed against `52922797` are retained below, with
mechanism details updated for step 5. The two process IDs and the agreed
allocation and victim policies remain.

1. **Adopted: select from the whole list.** Drop the role and cursor fields;
   choose None before Interactive, then the largest `kernel_pid`. Keep the
   generation, phase and System block in the pool's atomic accounting word.
   The extra traversal per victim is a reasonable cost for simpler state.
   Restart triggers are still required when pressure rises or drops below
   2 MiB after a run stopped short of 3 MiB.

2. **Adopted, then revised in the 5d review: the pager's park pattern for
   both.** Weak references and copyable wait reasons for faults and syscalls
   alike. `Thread::wait()` was rejected for syscalls because it consumes wakes
   latched for the thread's next userspace wait. Keep register/recheck
   ordering, cleanup on all cancellation paths, sole ownership of each resume
   and status checks before resume. Recheck the complete wait reason,
   including the generation after a physical refusal, not merely the role gate.
   Keep both queues in `KernelAddressSpace`.

3. **Adopted with a correction: enforce spawn refusal in the kernel.** The
   `Process::new_child` check and sys-io's cheap early refusal are useful, but
   creation alone is insufficient: sys-io returns a stopped child, and the parent
   wakes it later. Also guard the first `Created` to `Running` transition so a
   delayed wake or already queued start cannot bypass pressure. The bootstrap
   path remains separate.

4. **Adopted: publish `free_pages` on the shared page.** Replace admission's
   counters in the first cleanup patch and use the existing serialized pressure
   publication for relaxed stores. Keep earlier field offsets. `MemoryStats`
   currently derives the same count from total minus used pages, but publishing
   the field in that same patch avoids a temporary syscall-based memfs check.

5. **Adopted: no published pressure flag.** `free_pages` is a live counter
   maintained by the allocator's charge and release (one snapshot at kernel
   address-space creation, then deltas), so nothing samples and no publication
   lock exists. Userspace compares it with `LOW_MEMORY_PAGES`; hysteresis
   exists only in the kernel. The pool serializes count, generation, phase and
   System block in one atomic update, preserving transitions even when recovery
   and renewed pressure both precede scheduler dispatch. The separate waiter
   and job lock protects bookkeeping, not allocation policy.

## Issues to resolve later

Corner cases accepted for now. Resolve them after the transition lands, or
move them to `future-work.md`.

1. **sys-io parked on a non-System target.** A loader fill into a child, a
   pager fill for a protected None or Interactive process, and a shared
   mapping are sys-io syscalls whose target is not System, so during a run
   they park, and that sys-io runtime loop, the pager included, stops until
   the run ends. A run that ends without a victim at 2–3 MiB releases only
   System waiters, and sys-io's wait is classified by the target's role, so
   sys-io stays parked until 3 MiB, which nothing guarantees. Candidate:
   release waiters by the caller's role at the end of a victimless run. Also
   decide what a refused pager fill does to a protected process: today
   `F_PAGER_FAIL` kills the faulting thread, which would kill DNS or russhd
   during a run despite the kill protection.

2. **Debugger-paused victims.** `Process::kill` has
   `PausedDebuggee => todo!()`, `post_kill` on a paused thread sets Killed
   without a wake or an exit job, and `resume_debuggee` refuses a Killed
   thread, so a paused victim never completes its exit or frees its memory.
   Until the kill path finishes paused threads (wake the ones paused in a
   syscall, post the exit job for the preempted ones), the OOM walk treats a
   paused process as ineligible and moves on. A pause racing a committed kill
   can still stall its pending cleanup indefinitely; existing debugger resume
   does not guarantee progress in that race. Fixing that path remains deferred.

3. **The abort rule.** "No eligible victim below 2 MiB" aborts a VM in which
   protected processes hold that memory legitimately while nothing is
   blocked. The only certain deadlock is a System allocation blocked at the
   512 KiB floor with nothing left to kill. Alternative: abort only there and
   treat every other victimless run alike: log, keep the flag, release
   System callers. The rule above stays until this is decided.

## Open questions

None beyond the deferred issues above.
