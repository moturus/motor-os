# Replace memory admission control with kernel OOM killing

Adopted plan, in progress on branch `oom-handling`. Replace reservation-based
admission with simple physical-memory limits, fallible user-page allocation,
and kernel OOM jobs. Kill recent None-role processes first, then Interactive
processes if needed. The status section records what has landed; the sections
after it are the specification, each opening with its own state.

## Status

As of 2026-11-02:

| Step | Work                                                      | State                                   |
|------|-----------------------------------------------------------|-----------------------------------------|
| 1    | Admission cleanup, 4 MiB spawn and memfs checks           | Committed, `60c5cd09`                   |
| 2    | Two process IDs, statistics maps and lookups              | Committed, `02e9c17b`                   |
| 2a   | Live `free_pages` count, no pressure flag (proposal 5)    | Committed, `2e9c6a64`                   |
| 3    | Release user memory at process exit                       | Committed, `cda3c9d3`                   |
| 4a   | Fallible MM core, boot exhaustion self-test               | Committed, `3780bce0`                   |
| 4b   | Fallible frame-descriptor slab growth                     | Working tree, awaiting review           |
| 4c   | Real error codes in the syscall and process layers        | Not started                             |
| 5    | Allocation gates, OOM jobs, waiters, recovery             | Not started                             |

What the committed steps and 4b provide is described in
[docs/oom-handling.md](../oom-handling.md) and
[docs/kernel-mm.md](../kernel-mm.md). In short: admission, floors,
reservations, commitments and `AdmissionStats` are gone; spawns are refused
below 4 MiB by sys-io and by the kernel at creation and at the first `Created`
to `Running` transition; memfs refuses allocating mutations below 4 MiB;
`free_pages` is the allocator's live count; every process has a monotonic
`kernel_pid` beside its `user_pid`; a process's user memory goes back at exit
and an address space hosts one process; and every page acquired for a
process's mappings is acquired fallibly, with the partial mapping unwound,
through frames, the per-space descriptor slabs, page-table growth, eager
mappings, lazy faults, pager fills, sharing, construction, both stacks and
the frame-descriptor slab's growth. The kernel heap stays outside the
guarantee by design.

Left to do:

- **4c.** `sys_mem.rs` answers every mapping failure, invalid arguments
  included, with `E_OUT_OF_MEMORY`, and `Process::new_child` turns any
  construction failure into `E_INTERNAL_ERROR`. Propagate the real codes and
  add systest coverage of exact codes. Thread spawning, `SysObj` address-space
  creation, shared-page connection and the pager already pass
  `E_OUT_OF_MEMORY` through.
- **5.** The gates and waits in "Fallible user-page allocation" from the
  paragraph on pausing at syscall entry onward, the 2 MiB and 512 KiB rules,
  "OOM jobs" in full, and the validation items for boundaries, victims,
  episodes and waiters. Until then a fault that cannot get a frame kills the
  faulting thread.
- The `full-test-dev.sh --release` run of the completed transition, and the
  three deferred issues at the end of this document.

## Intended behavior

Use actual free physical memory (`phys::available_small_pages()`), without
subtracting reservations or executable commitments. All sizes below are binary.

Publish that count as `KernelStaticPage::free_pages: AtomicU64`, replacing the
removed admission counters without moving earlier fields. It is the allocator's
live count: one snapshot when the kernel address space is created, then the
delta of every charge and release as a relaxed atomic add or subtract. There is
no published pressure flag; userspace compares the count with
`moto_sys::LOW_MEMORY_PAGES` (4 MiB) through `moto_sys::low_memory()`, and the
2 MiB and 3 MiB thresholds live only in the kernel's OOM run state. Kernel
allocation checks use the allocator's own count.

Only `ProcessRole::System` grants permission to allocate while an OOM run is
active. OOM killing also spares sys-io and its direct children and grandchildren
regardless of role; parentage alone grants no allocation privilege. DNS (None)
and russhd (Interactive) remain protected from killing, but their allocations
and faults that need new pages wait while a run is active.

| Physical free memory  | Action                                                        |
|-----------------------|---------------------------------------------------------------|
| < 4 MiB (1,024 pages) | Deny memfs mutations and process starts; allow reads/deletes. |
| < 2 MiB (512 pages)   | Start an OOM run; only `System` may allocate while it runs.   |
| < 512 KiB (128 pages) | Block `System` allocations/faults until OOM finishes.         |
| >= 3 MiB (768 pages)  | End the OOM run; everyone allocates again.                    |

A run that started below 2 MiB stays active between 2 and 3 MiB. While it is
active, allocation requests and faults from processes without the System role
wait for recovery. Once the 512 KiB limit is crossed, System allocation requests and faults
also wait until the OOM run finishes; crossing back above 512 KiB alone does not
wake them. Existing mappings and operations that free memory remain usable. Below
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
  Recheck free memory before each kill and after the victim releases memory.
- If no eligible victim remains, abort only if free memory is still below
  2 MiB, printing remaining processes and their memory usage first. At 2–3 MiB,
  log that OOM could not reach 3 MiB and finish the run without aborting.
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

The audit list below is done through the MM core in steps 4a and 4b, except
the error codes of `sys_mem.rs` and `process.rs` (4c). The gates, waits and
fault parking from the paragraph on pausing at syscall entry onward are
step 5.

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

Pause userspace allocation calls the gate denies at syscall entry, before
acquiring MM locks or allocating temporary resources. Do not replace these waits
with immediate `E_OUT_OF_MEMORY` returns. Once an allocation is allowed to run:

- Return `E_OUT_OF_MEMORY` for an unsatisfied contiguous request; retain the
  normal small-page fallback for an opportunistic huge-page allocation.
- Reject an allocation of 2 MiB or more with `E_OUT_OF_MEMORY` if it cannot be
  satisfied or would leave less than 2 MiB free. Smaller allocations may cross
  the 2 MiB threshold and start a run; smaller non-contiguous allocations
  that cannot proceed wait for the run to end.
- Never allow a non-kernel allocation, including a system process's allocation,
  to leave less than 512 KiB free. Reject it before committing the allocation.
- Preserve existing errors for invalid requests and per-process memory limits.

Use actual physical consumption, including huge-page rounding, and serialize
each limit check with allocation so concurrent callers cannot consume the same
free pages. These are allocation checks, not reservation or commitment accounting.

Roll back incomplete mappings, frames, descriptors, and accounting before waiting
or returning an error. Failed shared replacement must preserve the old destination;
failed lazy faults must not claim a page is mapped when it has no PTE. Preserve
the pager's explicit partial-fill handling and resolve affected waiters.

Apply the kernel limits wherever physical pages are acquired for a process,
including faults, remote mappings, metadata, and page-table growth. Check the
recipient's role so a System caller cannot bypass a non-System target's limits.
For now, a sys-io caller may pause on a user target's allocation. Let OOM run and
then resume sys-io; add no separate deferred-request or service-progress machinery.

Reuse the kernel-internal wait used by `sys_kill` for allocation syscalls. Keep
one lazily created, kernel-owned "memory recovered" `SysObject` beside the pager
registry in `KernelAddressSpace`; add no static. Register with `add_waiting_thread`
and `add_wait_objects`, recheck the gate, then call `Thread::wait()`. Use a non-NONE
internal sentinel handle so a wake before the pause remains pending. If the
recheck already permits allocation, add that sentinel as a waker before waiting;
the existing wake path then clears registration and resumes the call. After any
wake, recheck the gate and register again if still blocked.

Faults use the pager's existing park state: `Preempted` with no resume job.
Keep one `Vec<Weak<Thread>>` of memory-fault waiters in the same kernel-owned
state. Register and recheck the gate against recovery; remove an entry before
resuming it, and use the pager's status-checked resume path to retry the fault.
Do not resume a killed thread or post duplicate resumes. Invalid/protection
faults retain their existing handling.

The end of an OOM run wakes the object and fault waiters
through the existing scheduler, outside allocator, run-state, process-list,
and waiter locks. Each waiter rechecks its own gate; waking grants no allocation
privilege. Unwind partial work and release MM locks before parking. Use existing
kill/wake handling, ensuring registrations are cleaned up even if the thread is
killed between registration and the pause.
Killed syscall stacks are discarded without Rust destructors. Release temporary
buffers, pins, and owned references before parking, or keep them in thread-owned
wait state that exit cleanup releases; do not rely on unwinding a killed stack.

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

Not started (step 5).

Use posted jobs on the existing scheduler. **Do not create a worker thread.**
Keep an episode ID, a run-active flag, and the 512 KiB block in the existing
kernel address-space state. Do not keep a cursor or current role. Each selection
scans the whole process list for the newest eligible None process, falling back
to the newest eligible Interactive process only when no eligible None remains.
This costs one full process-list traversal per victim on the OOM path.

Use actual parentage to protect sys-io and its direct children and
grandchildren, not `SYSTEM_STATS`' aggregate child index. This protects DNS
(None) and russhd (Interactive), both launched by sys-init, a child of sys-io.
More distant descendants, such as their user sessions, remain eligible unless
they have the System role.

The allocator's charge and release see the count cross each threshold exactly
once, in the return value of their atomic update, covering small, huge, and
contiguous paths. Request OOM work after allocator locks are released. Every
drop below 2 MiB with no active run starts a fresh episode. Each
selection starts from the whole set, so a new run always gives priority to the
newest eligible None process regardless of what the previous run selected.

When free memory reaches 3 MiB, cancel the current run, clear the 512 KiB block,
and wake surviving allocation/fault waiters. Already requested
kills still finish normal exit cleanup. Queued jobs and exit continuations must
carry the episode ID in the existing scheduler job argument. Cancel by invalidating
that ID; stale work returns without selecting victims or changing the current run.
No queue removal or general cancellation API is needed. Checking only the count
is insufficient if it recovered and dropped again before an old job ran.

Each job:

1. Checks that it still belongs to the active run and free memory is still
   below 3 MiB.
2. Scans for the eligible live process ranked first by None before Interactive,
   then by largest `kernel_pid`, skipping dead, already-exiting, and protected
   processes. Keep only the best candidate, not a snapshot of the list.
3. Rechecks the run and pressure before requesting termination through the
   existing process kill/exit machinery, including created, debugger-paused,
   and parked threads.
4. Waits for the victim's kernel exit cleanup to complete, then continues with
   a fresh pressure check and selection. Keep only one victim awaiting cleanup.

Do not hold process-list or allocator locks across termination or cleanup.
Repeat selection while free memory stays below 3 MiB. Skipping terminated/exiting processes
makes progress without a stored cursor. The complete None walk emerges from the
selection rule; the protected DNS resolver does not prevent escalation. No separate
pass transition or new-arrival handling is needed.

If no eligible None or Interactive processes remain after pending exits have
completed, sample physical free memory again:

- Below 2 MiB: print physical free memory and every remaining process's name,
  both PIDs, and existing user/kernel memory counters to the console, then abort
  the kernel. Use direct output without allocating a process-list snapshot or
  relying on userspace services.
- At least 2 MiB but below 3 MiB: log the free memory and that OOM could not reach
  3 MiB, then finish the run. Keep the run latched (kernel-internal state;
  nothing is published), but release the 512 KiB block and wake waiters to
  recheck their gates. Only eligible System allocations may proceed; protected
  None and Interactive targets still wait for 3 MiB. Do not abort or spin.
- At least 3 MiB: finish normally and wake surviving waiters.

Waiters must recheck their process, target address space, and allocation limits
before retrying. After a stop at 2–3 MiB, a later drop below 2 MiB starts a fresh
episode even though the latch is still set. Keep this explicit restart
trigger: scanning afresh does not schedule a stopped run. Do not spin while free
memory remains between 2 and 3 MiB.

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
   patches with their tests. *In progress: 4a, the MM core with a boot
   exhaustion self-test, is done (`3780bce0`); 4b, frame-descriptor slab
   growth, is in the working tree; 4c, real error codes in the syscall and
   process layers with systest coverage, follows.*
5. Implement the 2 MiB and 512 KiB allocation gates, OOM jobs, and scheduler
   integration together, with the new pressure, blocking, and recovery tests.
   *Not started.*

Step 1 is the single large cleanup patch. Keep subsequent patches small,
normally 100–300 lines including tests.

## Validation

Covered so far: the PID items; allocation failure and rollback at every
boundary that returns an error, by the debug boot exhaustion self-test, with
contiguous failure and huge-page fallback (immediate rejection of large
allocations belongs to step 5, exact syscall codes to 4c); exit and kill
releasing memory with handles held; the FS, networking, logging and spawn
items; and the quiescent `free_pages` comparisons. The boundary, victim,
episode, waiter and parked-allocation items are step 5.

Run kernel tests inside Motor OS and include regressions in
`src/tests/full-test.sh`, directly or through systest:

- PID equality before user-PID wrap, newest-first selection after wrap, and
  unchanged public PID ordering and pagination.
- Allocation failure and rollback at data, metadata, page-table, mapping,
  and address-space construction boundaries that return errors. Cover contiguous
  failure, huge-page fallback, and immediate rejection of large allocations.
- Normal exit and OOM kill releasing user memory while handles remain held;
  shared pages, pending pager fills, and concurrent thread exit remain safe.
- Boundaries at 4 MiB, 2 MiB, 512 KiB, and 3 MiB recovery; syscall and fault
  blocking for ordinary and System processes. Check 2 MiB requests that would
  start a run and concurrent requests against the 512 KiB floor. Verify that
  gate-denied calls park at entry and kernel allocations remain exempt.
- Victim order within each role and escalation only after the None walk completes.
  Spare DNS, russhd, and other protected services; user descendants remain eligible.
  Verify that ancestry alone gives no allocation privilege: protected None and
  Interactive services still pause allocations/faults while a run is active.
- Stop after sufficient reclaim, continue across small victims, and recover
  across repeated episodes. Cover concurrent pressure and single-CPU progress.
- Reject all new process starts under pressure, including a spawn begun before
  pressure rose, a stopped child woken later, and a start job already queued.
  Cover direct kernel creation requests as well as sys-io spawning.
- Clear and immediately re-raise pressure while an old job or victim-exit
  callback is pending. Start again at the newest None process; stale callbacks
  must not select another victim or disturb the new run or its waiters.
- Recovery between wait registration and pause must not lose a wake. Cover kill
  before/during the pause, spurious wakes, gate rechecks, and duplicate fault resumes.
- Parked allocations/faults resume when allowed; killing a parked process cancels
  its wait and releases retained syscall resources. Cover created and debugger-paused
  victims too. With no victims left, verify logging and System waiter progress at
  2–3 MiB, including exactly 2 MiB, and later OOM reactivation. Verify the console
  memory report and abort below 2 MiB in a separate guest run.
- FS, networking, logging, and spawn behavior with the old admission gates removed
  and the new memfs limit in place. Verify that memfs write/copy/create/move are
  rejected below 4 MiB while read/stat/list and delete still work.
- At quiescent checkpoints, compare shared `free_pages` with the allocator count
  after small, huge, and contiguous allocations/frees; preserve shared-page offsets.

Replace old squeeze tests that expect a None child to remain alive at the
admission floor. Preserve their useful resource-leak and service-recovery
coverage. Keep routine diagnostics small: physical free memory, OOM selections,
and the victim's two IDs; print the full process memory list only before abort.

Follow `AGENTS.md`: format with the repository toolchain, introduce no new
warnings, and pass the main full-test gate at least three times each in debug
and release before committing core patches. Run the completed transition
through `src/tests/full-test-dev.sh --release`; its developer-source phase
also stays release-only. Diagnose failures rather than masking them with
retries or longer timeouts.

## Simplification proposals

Reviewed against `52922797`; the decisions below are incorporated above.
The two process IDs and the agreed allocation and victim policies remain.

1. **Adopted: select from the whole list.** Drop the role and cursor fields;
   choose None before Interactive, then the largest `kernel_pid`. Keep the
   episode, active flag, and 512 KiB block. The extra traversal per victim
   is a reasonable cost for simpler state. Restart triggers are still required
   when pressure rises or drops below 2 MiB after a run stopped short of 3 MiB.

2. **Adopted: reuse existing waits.** Use the kernel-owned memory-recovery
   object and `Thread::wait()` for syscalls, and the pager's park/resume pattern
   plus weak references for faults. Keep register/recheck ordering, a non-NONE
   sentinel, cleanup on all cancellation paths, and status checks before resume.
   Initialize the object on demand; keep its state in `KernelAddressSpace`.

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
   exists only inside the kernel's OOM run state, where it is serialized
   anyway, and threshold crossings are detected exactly once from the atomic
   update's return value.

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
   paused victim like an exiting one and moves on.

3. **The abort rule.** "No eligible victim below 2 MiB" aborts a VM in which
   protected processes hold that memory legitimately while nothing is
   blocked. The only certain deadlock is a System allocation blocked at the
   512 KiB floor with nothing left to kill. Alternative: abort only there and
   treat every other victimless run alike: log, keep the flag, release
   System callers. The rule above stays until this is decided.

## Open questions

None beyond the deferred issues above.
