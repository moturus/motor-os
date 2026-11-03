# OOM handling, step 5: floors, killing, waiting and recovery

Implementation plan for step 5 of [oom-handling.md](oom-handling.md), the
specification. Revised on 2026-11-03 against `b2dccf4e`. This revision
incorporates the readiness reviews; the separate review file is no longer
needed. Step 5a is committed as `dcd36704`, and 5b as `b71cad30`. Step 5c
is implemented locally and awaiting review; steps 5d–5f remain pending.

The 5a changes replace the pool's used counter with the packed state word,
perform class-aware charges before ownership changes, preserve refusal reasons
inside the physical allocator, and test charge/release transitions in the
existing debug guest scratch-pool suite. The 5b changes bind the recipient role
atomically with the one-process claim in the address-space base and carry its
allocation class through frames, both stacks, page tables and shared MM slabs.
Internal `AllocationFailure` results distinguish ordinary codes from pressure
receipts, including the original floor refusal through huge fallback. Current
syscall boundaries still convert failures to the existing ABI codes; waiting
arrives in 5d. The production word stays unarmed. The 5c changes add atomic
request/latch operations, scheduler attention, generation-checked selection,
exit continuations and victimless reporting. Run starts are counted in the
physical pool; committed kill requests are counted by the worker. All four
production metric names are registered, with waiter-counter producers still
pending in 5d. Activation remains in 5e.

The accepted policy stays: None and Interactive allocations have a 2 MiB
floor, System allocations a 512 KiB floor, and kernel allocations no floor.
Request size does not select the policy. Recovery is at 3 MiB. A process-less
address space counts as None. Protection from killing does not grant
allocation privilege. The three deferred issues in the specification remain
deferred: sys-io waiting on a non-System target, debugger-paused victims, and
the victimless abort rule.

## Current code and constraints

- `phys_blocks::Pool` owns the authoritative count; the published
  `KernelStaticPage::free_pages` mirrors charge/release deltas. Small, huge
  and contiguous allocations share this accounting.
- A pool caller can hold region, page-table, slab, kernel-heap, scheduler or
  thread-status locks. Pool code must not post jobs, wake threads, allocate,
  log, or acquire the OOM waiter/worker lock.
- `sched_loop`, beside `uspace::process_wake_events()`, is a safe place to
  dispatch OOM work. Timer fast-return does not guarantee a scheduler-loop
  iteration every tick; a transition must also poke a scheduler after boot.
- `Process::die()` uses normal thread termination. User memory is released
  after the last thread's stack cleanup, before process exit is published.
  Exit completion must notify OOM only outside the process and MM locks.
- Killed syscall stacks are discarded without Rust destructors. A wait must
  have no owned resources in its frame or any suspended caller frame.
- File faults already park as `Preempted`, without a resume job. The existing
  resume function does not claim that status when posting: queue ownership,
  not its status check alone, must prevent duplicate resumes.
- Boot exhaustion tests run before scheduler publication and intentionally
  allocate down to zero. Runtime policy and scheduler notifications remain
  disabled until every consumer is ready.

## One atomic source of policy and accounting

Use one packed `AtomicU64` in the physical pool for the used-page count and
its associated policy state:

```text
used_pages: 25 bits
phase: 2 bits                 // Idle, Killing, Latched; fourth value invalid
system_blocked: 1 bit
armed: 1 bit
generation: 35 bits           // never wraps
```

The allocator's existing 64 GiB span cap permits at most 2^24 managed 4 KiB
pages, including that endpoint, so 25 count bits suffice. Use named masks,
checked field updates and a compile-time bound against the allocator cap.
Generation exhaustion is a fatal internal limit, never silent reuse. Jobs
carry the generation in their existing `u64` argument. This generation is
separate from process IDs and does not shorten the kernel-PID lifetime.

The CAS changing this word is the ordering point for allocation, recovery,
run start, latching and the System block. There is no separately sampled
phase, no 768-page substitute floor, and no delayed threshold-event stream.
A recovery followed by new pressure changes the generation even if no
scheduler runs between them. Old work can therefore never become current
again merely because the count is low again.

Keep `total`, `high_water`, the published free-page mirror and block metrics.
Count readers mask the word; only count-changing operations update the
published mirror. Publication remains delta-based and agrees with the pool
at quiescent checkpoints. No new userspace pressure flag or ABI field is
introduced. A per-pool start counter supplies `OomRuns` even when an entire
short episode happens before scheduler dispatch.

### Charging pages

Pass an allocation class through physical allocation: `Kernel`, `System`,
or `User` (None and Interactive). Do not pass a precomputed numeric floor
that can outlive a phase change.

| Class | Idle | Killing | Latched |
|-------|------|---------|---------|
| Kernel | floor 0 | floor 0 | floor 0 |
| System | floor 128 | floor 128, or wait if `system_blocked` | floor 128 |
| User | floor 512 | wait | wait |

All counts are 4 KiB pages. Before arming, every class uses floor 0 and all
gates are open.

Find and validate a usable block under its existing lock, then CAS the
count/state word **before** committing its page ownership changes. Retry
that CAS against the complete word, recomputing the gate and floor each
time. Once it succeeds, the block mutation must be infallible: all corruption,
range and free-list checks precede the charge. This applies to `take_small`
and `take_huge`, including contiguous runs. A failed search or a rejected
charge consumes no count; no reservation is charged before block selection.
Preserve the free path's publication-before-release ordering.

The allocation class follows the operation through frames, page and segment
descriptors, page-table growth, both process stacks, MMIO descriptors and
frame-descriptor slab growth. Kernel virtual placement alone is not an
exemption: a process's kernel stack and the metadata its mapping needs use
its class. Independent kernel heap growth and kernel startup allocations use
Kernel. General `Arc`, `Box` and collection allocations remain unchanged.

Record the recipient's role on `UserAddressSpace` at successful process claim;
reset it on failed construction's claim rollback. Serialize role publication
with that claim so a failed competing claim cannot change the owner's class.
The bootstrap `Process::new` path bypasses `new_child`; explicitly claim its
space as System before constructing its stacks and before arming. Resolve the
class from that space, never from the caller's capabilities for remote operations.
Where kernel regions or shared slabs cannot recover the recipient, pass the
class explicitly from the owning operation. No current-thread accessor is
needed. A shared operation that allocates metadata in both spaces applies
each recipient's class to its own allocation.

### Transitions at the ordering point

- A successful charge that takes free memory below 512 starts Killing from
  Idle or Latched and increments the generation. A User allocation cannot
  cross that floor; System and Kernel allocations can.
- A true floor refusal below 768 pages starts Killing from Idle, without
  changing the count. A System floor refusal sets `system_blocked` for that
  run; a Kernel charge below 128 sets it as well. An existing run keeps its
  generation. A closed gate returns a wait outcome, not an ordinary OOM error.
- A release reaching at least 768 while Killing or Latched changes to Idle,
  clears the System block, and increments the generation in the same CAS.
  Recovery wins over every old request or job. There is no stale `requested`
  flag capable of starting a run above the recovery threshold.
- The victimless worker may CAS Killing to Latched only with its current
  generation and a count in 512..768. It clears the System block and increments
  the generation. A failed CAS requires a new state/count check.
- An unchanged Latched state does not restart on every waiter recheck or
  failed retry. A later drop below 512 starts a fresh run; recovery at 768
  opens all gates. A System refusal while Latched waits for a state change
  without setting the run-wide System block; smaller requests may proceed.
  This preserves the specification's no-spin rule.

Keep a per-pool `attention` flag solely to request scheduler work. A production
transition sets it and, **only if armed**, pokes the current CPU after the
accounting update. This producer path does not dereference scheduler state,
CPU-local state or the kernel address space while unarmed. Scratch pools do
not notify production schedulers. Neither the flag nor the wake order carries
policy history; that history is already represented by the generation.

## Refusal results and retry decisions

Preserve the reason through the internal MM interfaces. Use a small internal
result type distinguishing an existing `ErrorCode`, a closed-gate wait, and a
physical shortage. Pressure outcomes carry only copyable data: allocation
class, phase/generation, refusal kind and the free count at refusal. The public
ABI continues to return the existing error codes. Do not turn every
`E_OUT_OF_MEMORY` into a pressure wait: per-process limits, virtual-address
exhaustion and invalid requests keep their existing handling.

An ordinary syscall attempt has an outer retry loop and an inner operation
that returns completely before any wait. The inner operation releases its
locks, pins, strings and owned references and rolls back incomplete work.
Then the outer loop applies these rules:

1. A closed-gate outcome waits until the recipient's current gate permits a
   retry. If recovery already did so, resolve the handles and retry immediately.
   A gate refusal is never converted to a permanent error by a later count.
2. After a physical shortage, sample the count **after rollback**. At 768 or
   more free pages, return `E_OUT_OF_MEMORY` for the failed syscall. Below 768,
   join the generation from the current atomic load, or request one from Idle
   using a CAS that rechecks the count. If recovery wins that CAS, re-evaluate
   instead of starting a stale run. Joining an existing run needs no write;
   wait registration rechecks its generation. Preserve an already-observed end
   of the refusal's run: if its generation changed, recheck the gate and retry
   when allowed, rather than replacing that completed wait with the new
   generation. Otherwise wait for that attempt's run to end and for the role
   gate to permit retry. A refusal that had no run takes the generation returned
   by joining/requesting one. A System waiter cannot wake itself merely because
   its role ordinarily has allocation privilege.
3. If already Latched, an unsatisfied System request waits for a later state
   change; it must not repeatedly rescan an unchanged victimless process set.
   System requests that fit may still proceed. User gates remain closed.
4. Unsatisfied contiguous requests return `E_OUT_OF_MEMORY`; an opportunistic
   huge-page miss still falls back to small pages. A gate closure is a wait
   regardless of mapping flavor. Preserve the physical-refusal reason through
   huge fallback; do not mistake fragmentation for a closed gate.

In particular, an eager 16 MiB request starting with 10 MiB free may reach its
floor, unwind, and restore at least 3 MiB. It then returns OOM. It is not a
valid test fixture for an allocation that must remain parked. A large request
begun with less than 3 MiB free after rollback is the separate waiting case.
A run started at an actual refusal may already have been cancelled by rollback;
its generation prevents any later queued kill from acting on it.

Pager fills are the explicit partial-progress exception. Keep installed pages,
release source pins, and preserve the accumulated installed-page count across
retries as copyable state. Resolve waiters for completed pages outside MM locks;
revalidate the mapping ID before retrying the remainder. Never silently discard
its prefix or retain a vector of pinned pages across the syscall wait.

## Scheduler dispatch, selection and completion

`KernelAddressSpace` owns `OomState` beside the pager registry, with no new
static. Its lock protects only slow-path bookkeeping:

```text
observed_generation
queued_or_running_job: Option<generation>
pending_victim: Option<(generation, kernel_pid)>
waiting_for_exits: Option<generation>
recovered: Option<Arc<SysObject>>
fault_waiters: Vec<(Weak<Thread>, WaitReason)>
```

The 5c implementation installs the generation, job and exit bookkeeping in
`uspace::oom`. It also tracks the last dispatched run for start/end logs.
The recovery object and fault queue are added with their consumers in 5d;
5c does not allocate a recovery object or implement waiter wakeups.

`attend()` runs beside `process_wake_events()` in `sched_loop`, holding no
other lock. It consumes attention, reads the authoritative state word and
reconciles the bookkeeping. A generation change wakes the recovery object and
rechecks fault waiters under the bookkeeping lock. Remove only satisfied/dead
entries; retain blocked ones in the queue, so recovery cannot race a later
reinsertion. If Killing needs work, and no job, victim cleanup or current
exit wait occupies the slot, it records and posts one detached job.
Posting, logging, object wakes and thread resumes occur after releasing the
bookkeeping lock. Check for attention again before finishing; a concurrent
producer must leave work for this or a later iteration.

The job:

1. Checks Killing and its generation before scanning. Killing guarantees that
   the count is below 768; a release reaching recovery changes the generation.
2. Uses `KProcessStats::for_each_child` to select the newest eligible None
   process, otherwise the newest eligible Interactive process. Upgrade weak
   references under the map lock; compare and drop candidates after it.
   Skip System, sys-io and its actual children/grandchildren, exiting/dead
   processes and debugger-paused processes. Identify sys-io using the public
   PIDs in its ancestry; rank victims using kernel PIDs. Keep only the best
   candidate.
3. Rechecks eligibility before committing the kill. Under the bookkeeping
   lock, load the state word with Acquire ordering, validate Killing and the
   generation, and record the pending identity. This load is the kill request's
   ordering point. Count changes within the run do not cancel it or require
   another scan. Recovery before the load cancels selection; recovery after it
   permits the committed kill to finish. Release all locks before logging or
   calling the normal termination machinery.
4. Waits for that victim's exit cleanup. The post-kill completion check and
   `on_process_exited(kernel_pid)` atomically claim the pending record under
   the bookkeeping lock; exactly one clears it and requests attention.

Retain the one pending cleanup record across recovery and a later generation;
new killing waits for that cleanup instead of accumulating victims. Its stored
generation never becomes the new generation. An old exit may retire its own
record, but cannot post work tagged as a newer run or clear a newer job.
`attend()` separately decides what the current run now needs. Queued/running
jobs likewise clear only their own generation's work slot.

Before declaring a victimless result, account for existing non-debugger exits
whose user-memory cleanup has not completed, including exits not initiated by
OOM. Wait for their exit notifications and rescan; do not abort while their
reclamation is still pending. This uses existing process status/cleanup state,
not a second process registry. Set `waiting_for_exits` before the final status
scan. Every exit-completion hook clears that interest and requests attention;
if it raced the scan, dispatch another check after releasing the job slot.
Otherwise retain the interest and do not repost work until an exit or generation
change. Clear only matching-generation interest. This avoids both a lost
notification and repeated scans while cleanup has made no progress.
Paused debuggees remain the deferred exception.
A debugger pause racing a committed kill can still stall cleanup indefinitely;
the current kill/resume paths do not guarantee that the debugger can unstick it.

With no eligible victim or pending reclamation, atomically recheck the state:
below 512, report all remaining processes and abort; at 512..768, latch and
wake waiters to recheck; at 768 or above, recovery has already cancelled this
job. Console reporting uses direct output and the existing traversal, without
allocating a process-list snapshot or depending on userspace services.
After reporting, load a fresh snapshot and abort only if it still shows the
same Killing generation and fewer than 512 free pages. A rise to 512 can
cancel an abort without changing the generation; count changes below 512
do not invalidate the decision or force another report.

Keep diagnostics small: record dispatched run starts/ends and committed
selections with generation, free pages, name and both victim PIDs as applicable.
Episodes that finish before dispatch contribute to the start counter without
requiring a log/event queue. Use the four production metrics `OomRuns`,
`OomKills`, `OomParkedSyscalls` and `OomParkedFaults`: count starts, committed
kill requests and waiter registrations respectively. Attribute both waiter
counters through the existing process-statistics mechanism as well as aggregate
reporting, so tests can distinguish their worker from other waiters. A counter
alone does not prove a long wait. Add no test-only metrics or control hooks.

## Syscall wait ownership

Use one lazily created kernel-owned recovery `SysObject` and a non-NONE
sentinel below `CUSTOM_HANDLE_OFFSET`. Register with `add_waiting_thread` and
`add_wait_objects`, then recheck the **full wait reason** against the current
state word. If already satisfied, add the sentinel waker before `wait()`.
After every wake, recheck role, handles, target liveness and limits. Keep the
object alive in kernel/thread-owned state; do not leave a local `Arc` across
`Thread::wait()`.

An entry wait depends on the recipient's gate. A physical-shortage wait also
remembers the run generation established by the refusal/retry rules above.
It is satisfied only by a state change and an open recipient gate. Rechecking
is allowed to produce a new wait reason; spurious wakes never authorize allocation.

Put retry loops at the outer syscall boundary, above all owning helpers:

| Path | Ownership to release before waiting |
|------|-------------------------------------|
| `sys_mem_impl`, all `OP_MAP` flavors | owner/target `Arc`s and sharing temporaries |
| `sys_spawn_impl`, both process stacks | owner `Arc`, incomplete thread/stack resources |
| `sys_obj_impl`, `address_space:` creation | the URL `String` in the dispatcher and construction temporaries |
| `sys_obj_impl`, shared `OP_GET` | dispatcher URL, decoded URL, listener and process references; requeue an unconsumed listener |
| `sys_pager`, reserve/fill | dispatcher's caller `Arc`, target `Arc`, pins, vectors and mapping temporaries |

The inner helpers return a copyable wait outcome to these loops; they never
sleep while their caller owns a resource. Re-read URLs and re-resolve handles
on retry, including authorization and mapping IDs. Do not hold a borrowed
pointer into a dropped URL. Sharing must validate every recipient that can
acquire new physical metadata, including the caller's alias space.

Pager `zero_from` only records an offset; it needs no allocation gate. Process
creation and its first start retain the existing 4 MiB refusal, with tagged
pressure results converted to the creation error rather than sleeping inside
partially constructed process ownership.

## Fault waiting

Validate protection, guards, mapped-page races and pager availability using
the existing fault paths. Apply policy only when a valid fault needs a new
physical page or metadata. A typed gate/pressure outcome is recoverable even
if the count or generation changed before dispatch; it must not become a
fatal fault merely because a later sample is at least 768.

For a pressure refusal, unwind MM work, set `Preempted` under the thread status
lock, release that lock, then register `(Weak<Thread>, WaitReason)` under the
OOM bookkeeping lock. Recheck the complete reason against the state word
while registering. If recovery already permits retry, remove this entry and
post one resume after unlocking. Otherwise the scheduler owns removal when
processing a later transition. A valid fault whose physical shortage has
already recovered retries by the same resume path; an ordinary non-pressure
error retains today's fatal handling.

Whoever removes an entry owns its sole resume. Never assume that
`resume_file_fault()` itself deduplicates posted jobs. Kills use the existing
Preempted exit path; the resume status check then skips killed threads. A
new fault registration follows removal of the previous entry, and dead weak
references are discarded at the next drain. No status lock is nested inside
the OOM bookkeeping lock during a resume.

The pager's zero-fill allocation uses this same result and registration
protocol. Its nonzero file-pager misses retain their existing wait ownership;
a thread must never simultaneously belong to the pager queue and the OOM
fault queue.

## Bootstrap and patch sequence

Keep the production policy unarmed through all preparatory patches. Unarmed
charges/frees retain the current count behavior, floor 0, no OOM transition,
and no scheduler poke. Existing boot exhaustion coverage remains unchanged.

The final activation occurs in `init::start_userspace_processes`, after the
bootstrap sys-io process and its mappings have been constructed, immediately
before `process.start()`. At that point all per-CPU schedulers are published
and every wait/kill consumer is installed. Arming samples the initial count
in its CAS and requests work if it is already low; it cannot erase a
concurrent event. This is a constant-time setup operation, not a boot scan.

| Stage | Work and validation | Runtime OOM policy |
|-------|---------------------|--------------------|
| 5a | Packed accounting, class-aware charges and exact transition tests in the existing scratch-pool suite | Unarmed |
| 5b | Recipient-role and typed-result propagation through physical/MM paths, both stacks and metadata; rollback tests | Unarmed |
| 5c | Scheduler dispatch, generations, selection, exit continuations, latch/abort and production diagnostics | Unarmed |
| 5d | Outer syscall retries and resource audit; fault/pager-zero registration and unique resume ownership | Unarmed |
| 5e | Arm the complete mechanism; add guest pressure, cancellation, recovery and real one-vCPU gates | Armed |
| 5f | Complete documentation and separate abort verification; release developer-image gate | Armed |

These are dependency stages, not permission for six large commits. Split
stages into patches normally totaling 100–300 changed lines **including
tests**, following allocator, MM, syscall and scheduler boundaries. Each
preparatory patch must compile and preserve current behavior; exercise its
production helpers in the existing in-guest test framework. Do not introduce
a temporary runtime switch, a public test hook or warning suppressions just
to stage the work. In particular, do not enable floors before fault waiting
and all syscall callers are complete.

## Validation

5a review validation on 2026-11-03: debug and release kernel builds and Clippy
checks passed without warnings; repository-toolchain formatting checks passed.
`src/tests/full-test.sh` passed once (16.6 minutes of testing), and
`src/tests/full-test.sh --release` passed once (10.6 minutes). The debug log
includes `phys_blocks policy tests PASS`. These are the pre-review runs;
the three-per-build gate below still applies before an authorized core commit.

5b review validation on 2026-11-03: debug/release kernel builds and Clippy
checks passed without warnings, and formatting checks passed. The debug full
suite passed once (16.8 minutes). After the final refinement preserving the
original floor receipt across recovery/new pressure, a fresh debug
`src/tests/test-system-tty.sh` run passed, including `phys_blocks policy tests
PASS` and `allocation role tests PASS` during guest boot. The final sources
passed `src/tests/full-test.sh --release` once (10.6 minutes). Existing boot
exhaustion/rollback coverage remains enabled; no live allocator arming or new
drain was added. These changes are committed as `b71cad30`.

5c review validation on 2026-11-03, after the review corrections: debug/release
kernel builds and Clippy checks passed without warnings; formatting checks
passed. `src/tests/full-test.sh` passed once (16.9 minutes of testing), and
`src/tests/full-test.sh --release` passed once (10.6 minutes), both on the
corrected sources. Debug guest boot reported `phys_blocks policy tests PASS`,
`OOM dispatch tests PASS` and `allocation role tests PASS`. These are review
runs; the three-per-build gate still applies before committing.

The added cases exercise request/latch boundaries, unarmed attention, count
changes within one Killing generation, the 511/512 boundary within that same
generation, exact run counts despite coalesced dispatch, recovery/new pressure
before validation, role/ancestry selection, retained victim cleanup, duplicate
completion claims, out-of-order scheduler observations, stale exit-interest
registration and exit notification during a final scan. These use private
scratch pools and the worker's production bookkeeping; actual pressure kills
and the disposable-guest abort gate remain for 5e–5f.

All new tests run inside Motor OS and are reached from `full-test.sh`, through
existing kernel self-tests, systest or its console fixture. Keep pressure tests
out of `--under-load`. Extend existing debug boot test hooks with bounded
scalar/scratch-pool cases; do not add a live-pool drain or a new boot scan.

| Area | Required evidence |
|------|-------------------|
| Atomic policy | Exact 127/128, 511/512 and 767/768 boundaries; two competing charges with room for only one; small/huge/contiguous paths; unchanged counters on refusal; kernel exemption |
| Generations | Recovery and renewed pressure before dispatch; stale queued jobs and victim exits; refusal racing recovery; validated kill before/after recovery; generation overflow fails closed |
| Gates and errors | Every class/phase/block combination; System remains blocked after free rises above 128 but below recovery; gate refusal differs from permanent OOM, quota and address-space errors |
| Wait ownership | Registration/draining before and after recovery, cancellation before/during wait, spurious wakes and one removal/resume per fault; syscall caller resources released on kill |
| Mapping retry | Rollback below versus above 768; huge fallback; retained shared destinations; partial pager fill and mapping retirement; zero-fill fault recovery |
| Victims | Newest None first, then Interactive; actual ancestry protections; created/parked victims; paused victims skipped; unrelated exits before/during wait registration cannot cause premature abort, lost notification or polling |
| Run ends | Stop at recovery; continue across genuinely insufficient reclaim; latch at exactly 512 and at 767; System progress after latch; later downward crossing restarts without polling/spinning |

Scratch tests invoke the production transition/charge logic with private state;
they verify orderings explicitly, not just a duplicate model of the rules.
Registration/drain tests exercise the production bookkeeping without actually
posting duplicate resumes. Runtime guest tests cover actual scheduling and
thread cleanup; the scalar tests do not substitute for those tests.

Guest fixtures prepare children, shared control pages, worker threads, handles
and buffers before creating pressure. Use an eager, small-request driver for
syscall pressure and a separate lazy-touch driver for fault pressure. Do not
wait for output from a child that may already have parked or died. The newest-
first/repeated-run fixture can retain the 32 MiB holder, with an explicit ready
handshake before the driver starts. Assert actual victim selection/order and
recovery, not the order in which the parent chose to call `wait()`.

For waiter tests, observe the specific worker's registration metric and, for
syscalls, its thread state/syscall identity before asserting cancellation or
recovery. Global counter growth can be caused by the driver and is not proof
that the tested operation waited. A first blocking map followed by a thread
spawn does not demonstrate that both parked: use separate workers/scenarios.
Free-page polling is only a pressure hint, not an observation of Killing.

No fixed victim size promises a scheduling window. In particular, reclaiming
1 MiB at the User floor can already reach recovery. A continue-across-victims
case must measure/account for the victim's total reclaimable footprint, not
only its requested buffer, and verify that the first cleanup leaves less than
768 pages free. Keep references to shared frames when needed to control how
much a victim can actually return, and release them during cleanup.

The maintainer permits at most three attempts when the intended pressure
window was missed. Report each miss and its evidence. Require successful
operations and independent evidence of recovery before entry to classify a
miss; absence of a park counter alone is insufficient. Once a waiter was
observed, a wrong result, leak, hang or lost wake is a failure, never a retry.
If all three attempts miss, fail the gate rather than silently skip coverage.

Test both large-request outcomes: a partial eager allocation that unwinds to
at least 768 returns OOM; one whose post-rollback count remains below 768 waits
and is either killed or retried after recovery. Preserve quota-error checks
under pressure. Fault tests include recovery between refusal and registration
and must prove that a valid fault survives that recovery.

Run System wait/floor cases from the existing System console fixture used by
`test-system-tty.sh`, with a dedicated helper granted `CAP_SYS` by that parent.
Assert its role. Ordinary SSH systest cannot grant itself System. Exercise an
actual System allocation/fault refusal and cancellation/recovery; merely testing
the gate table is not sufficient coverage of the 512 KiB rule.

Use a real one-vCPU guest for scheduler progress:
`src/tests/full-test.sh --cpus 1` and its release counterpart, with the OOM scenarios included. The
`systest --host-cpus=1` workload-sizing hint is not a substitute. The usual
multi-vCPU gate supplies concurrent pressure coverage.

Verify the victimless abort in a separate disposable guest driven from the
System console, after ordinary tests. The fixture must assert the remaining
process roles and absence of eligible/pending victims, check the console
memory report, and treat the expected guest termination as success only with
that report. A smaller guest makes the setup cheaper; a 1 GiB guest is not
inherently incapable of this case. Keep a manual reproduction procedure too.

Each core patch is formatted with the repository toolchain, introduces no
warnings, and passes `full-test.sh` three times in debug and three in release
before any authorized commit. Include at least one real one-vCPU run in each
build's activation validation. Once the complete transition passes, run
`src/tests/full-test-dev.sh --release`; its source phase remains release-only.
Do not extend timeouts, weaken assertions or retry defects to obtain a pass.
The current 5c changes remain uncommitted for review.

## Decisions retained and implementation choices

Recorded maintainer decisions remain: four production OOM metrics; process-less
spaces use None; at most three evidenced pressure-window attempts; role-based
floors independent of request size; and refusal/recovery handling replaces the
former immediate rejection rule for requests of at least 2 MiB.

This revision chooses the atomic count/state word, typed internal pressure
results, post-rollback syscall sampling, explicit generation-dependent waits,
and activation after all consumers are complete. It treats process-attributed
MM metadata as part of the process allocation even in kernel virtual regions.
These are implementation choices made to resolve the reviews, not additional
claims of prior maintainer approval. The three deferred policy issues remain
listed in the specification with their current behavior unchanged.
