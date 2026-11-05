# OOM handling: deferred issues

Kernel OOM handling replaced reservation-based admission control; the plan
that introduced it is implemented. The behavior is documented in
[docs/oom-handling.md](../oom-handling.md) and the memory-manager mechanics
in [docs/kernel-mm.md](../kernel-mm.md). This file keeps only the work that
was deliberately left open. Each entry records what the code does today and
why that matters. Issues 1 and 2 are being implemented; issue 3 records a
deferred alternative to the abort rule, which stays unchanged.

## 1. sys-io parked on a non-System target

Today the allocation class follows the recipient's role: System, or User for
None, Interactive and process-less spaces. A loader fill into a child, a
pager fill for a protected None or Interactive process, and a shared mapping
into such a process are sys-io syscalls with a User recipient. While a run is
active the User gate is closed, the syscall parks, and sys-io's one runtime
thread, which serves the pager, the filesystem listeners and networking,
makes no progress until the run ends. A run that ends without a victim at
512–767 free pages reopens only the System gate, so the syscall stays parked
until a release reaches 768 pages, which nothing guarantees.

The same latch holds protected None or Interactive processes allocating or
faulting for themselves, and System requests that do not fit above 128 free
pages, which wait for the next generation change. In the shipped image the
protected set is sys-io, sys-init and strobe (System), sys-tty and russhd
(Interactive) and dns-resolver (None); everything a user runs is a
great-grandchild of sys-io and eligible. After a victimless run those
services and the System processes are all that remain.

sys-io's allocations into a target outside SystemMemory are fallible. The
target's User class keeps them from taking free memory below 512 pages
(2 MiB). A refusal at that floor starts a run, or joins the one in progress;
the syscall waits for it and fails with `E_OUT_OF_MEMORY` if it ends without
recovery. A request refused with at least 768 pages free fails at once, as
today. Patch 1 keeps the class, patch 2 supplies the failure.

For a valid pager fill into SystemMemory, physical pressure must not become
`E_OUT_OF_MEMORY` and then `F_PAGER_FAIL`. A required page that reaches the
128-page (512 KiB) floor waits for the active OOM run and retries after
reclamation. If the run ends in Latched at 512–767 free pages, the fill
retries through the reopened System gate; if no victim or pending cleanup
remains below 512 pages, the existing rule aborts the guest. Recovery before
the syscall registers its wait must also permit a retry. This guarantee
concerns physical pressure, not invalid arguments, retired mappings or I/O
errors, and does not make ordinary large allocating syscalls infallible.
The debugger race in issue 2 remains a separate limitation.

Plan, three small patches, followed by the debugger cleanup in issue 2.
The implementation request includes full validation and one-line commits.
Each code patch includes its affected tests and passes the main-image full
gate three times in debug and three times in release before commit. Final
validation also includes the release developer-image gate and stress-soak.

1. Allocation class by protection group. SystemMemory is the set `classify()`
   never selects: System-role processes, sys-io, and sys-io's children and
   grandchildren. `claim_for_process()`, called from `new_child` where the
   parent is known, records the System class for SystemMemory and User for
   everything else; process-less spaces stay User, so sys-io's loader keeps
   the 512-page floor. `classify()` reads the recipient's class instead of
   recomputing ancestry, so eligibility and class cannot diverge. The
   accounting word, floors and gates do not change.
   This reverses the spec sentence that ancestry protection "grants no
   allocation privilege to protected None or Interactive processes": sys-tty,
   dns-resolver and russhd get the 128-page floor and an open gate in
   Latched; capabilities are unaffected. A protected process's allocations
   and faults, and sys-io's fills for it, use that gate and floor. The class
   change removes their User-gate stall; the protected-fill guarantee also
   requires the retry change in patch 2.

2. Wake blocked allocating syscalls when the OOM run ends, and retry them.
   Each syscall wait records the run generation. Recovery to Idle and
   stopping in Latched both release that wait; the syscall revalidates its
   arguments and target, then tries again. If the run already ended before
   wait registration, retry without sleeping. If another run has started,
   the retry checks that new state. A gate refusal followed by recovery to
   Idle must not itself cause `E_OUT_OF_MEMORY`.

   After retry, the current gates and floors still apply. In Latched, the
   User gate remains closed, so an ordinary allocation into a User space
   returns `E_OUT_OF_MEMORY`. A System allocation proceeds if it fits above
   128 pages, otherwise it returns `E_OUT_OF_MEMORY`. Neither waits for a
   finished run. The same rules apply to new requests arriving in Latched.
   This lets sys-io's in-flight loader fail the spawn cleanly. Faults keep
   their class-based waits; they have no error return.

   `F_PAGER_FILL` into SystemMemory is the exception to the ordinary syscall
   error rule. Today `after_failure()` passes `fault = false`, so a floor or
   capacity refusal followed by a post-unwind sample of at least 768 free
   pages returns OOM, even if another CPU reclaimed those pages before the
   wait was registered. For a protected fill, retry the unfinished suffix
   instead. A run ending in Latched likewise permits a protected fill to
   retry. Retain the completed prefix, revalidate the mapping ID on every
   attempt, and wait again if renewed pressure blocks the fill. Keep the
   current error rule for ordinary allocations whose rollback restores at
   least 768 pages, so an oversized request cannot loop indefinitely. This
   change concerns retry policy, not the faulting thread's queue ownership:
   the sys-io syscall still waits and resumes through the syscall queue.

3. Retry later when sys-io cannot allocate a buffer for a page fill.
   `PageBuf::new()` and relocation buffers allocate in sys-io before
   `F_PAGER_FILL`. These allocations may return OOM. Keep the existing
   reduction from read-ahead to a single required page. If preparing that
   page still fails with OOM, keep the request, yield to the async runtime
   so other sys-io work can run, and retry later. Do not call `pager_fail`
   for that buffer-allocation error. On retry, discard a request whose
   mapping has been retired. This handles buffer preparation separately
   from errors returned by `F_PAGER_FILL`, whose pressure behavior is
   specified in patch 2; other errors keep their existing handling.

   Update `docs/oom-handling.md`: the floors table, "Allocation floors and
   waiting", "Victims and recovery" and the remaining limitations.

Patch 1 makes issue 3 more likely: a leaking protected service can take free
memory below 512 pages with nothing left to kill, and the current rule aborts
the guest where today it stalls in Latched.

## 2. Debugger-paused victims

`Process::kill` has `PausedDebuggee => todo!()` (`uspace/process.rs`), so a
paused process cannot be killed through the kill syscall at all. `post_kill`
on a thread paused by the debugger sets it `Killed` without a wake or an exit
job, and `resume_debuggee` resumes only threads still paused, so a paused
victim never completes its exit or frees its memory. Victim selection
therefore treats a paused process as ineligible and moves on.

A pause that lands between a committed kill and the victim's thread cleanup
can still leave that cleanup pending indefinitely. The one pending-victim
record stays occupied, so the worker selects no further victim, never reaches
a victimless decision, and User-class allocations, sys-io's fills into them
included, wait until something else frees memory to 768 pages. The issue 1
plan does not help here: its syscalls wait for the run to end, and this run
does not end. Debugger resume does not guarantee progress in that race.

Direction: finish paused threads in the kill path, waking the ones paused in
a syscall and posting the exit job for the preempted ones, and give
`Process::kill` a `PausedDebuggee` arm.

## 3. The abort rule

With no eligible victim and no pending exit cleanup below 512 free pages,
the kernel prints every remaining process and panics
(`OOM: no eligible victims or pending reclamation below 512 free pages`).
Protected processes, meaning System processes, sys-io and its children and
grandchildren, can hold that memory legitimately while nothing is blocked:
System allocations still succeed down to 128 pages. The guest is terminated
although it would have kept working. After issue 1 patch 1 every protected
process allocates in the System class, so a leaking service reaches this
rule instead of stalling at 512 pages.

Alternative: end a victimless run below 512 pages like the 512–767 case:
latch, keep the User gate closed, release System callers. Ordinary
allocating syscalls could then return `E_OUT_OF_MEMORY` if their retry still
fails. A running program that needs a missing page cannot receive an error
that way; its handling would need a separate decision. The rule that a
charge below 512 pages while Latched starts a new run must also change, or
every charge in that state rescans the same process set. This alternative
is deferred and is not part of issue 1; the current abort rule stays.
`src/tests/test-oom-abort.sh` and its `systest system-oom-abort` helper
assert the current rule and change with it.

## Related

The one-vCPU debug full gate used to validate this work runs at its
50-minute budget because of a systest poll test unrelated to memory; see
[future-work.md](future-work.md).
