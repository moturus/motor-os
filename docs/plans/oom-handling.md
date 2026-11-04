# OOM handling: deferred issues

Kernel OOM handling replaced reservation-based admission control; the plan
that introduced it is implemented. The behavior is documented in
[docs/oom-handling.md](../oom-handling.md) and the memory-manager mechanics
in [docs/kernel-mm.md](../kernel-mm.md). This file keeps only the work that
was deliberately left open. Each entry records what the code does today, why
that matters, and the direction considered so far. None of it is scheduled.

## 1. sys-io parked on a non-System target

The allocation class comes from the recipient address space, not from the
caller. A loader fill into a child, a pager fill for a protected None or
Interactive process, and a shared mapping into such a process are sys-io
syscalls whose recipient is None or Interactive. While OOM killing is active
that gate is closed, so the syscall parks, and the sys-io runtime loop that
issued it, the pager included, makes no progress until the run ends. A run
that ends without a victim at 512–767 free pages reopens only the System
gate, and sys-io's wait is classified by the recipient's role, so sys-io
stays parked until a release reaches 768 pages, which nothing guarantees.

Candidate: at the end of a victimless run, release waiters by the caller's
role; the charge itself would still apply the recipient's floor.

Related: a page fill that sys-io cannot complete ends in `F_PAGER_FAIL`
(`uspace/pager.rs`), and the kernel then kills the faulting thread. During a
run this would kill a protected None or Interactive process such as DNS or
russhd despite its kill protection. What a refused fill should do for a
protected process is undecided.

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
a victimless decision, and None and Interactive allocations wait until
something else frees memory to 768 pages. Debugger resume does not guarantee
progress in that race.

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
although it would have kept working. The only certain deadlock is a System
allocation blocked at the 128-page floor with nothing left to kill.

Alternative: abort only in that deadlock and treat every other victimless
run like the 512–767 case: log, latch, release System callers. Undecided;
the current rule stays until it is. `src/tests/test-oom-abort.sh` and its
`systest system-oom-abort` helper assert the current rule and change with it.

## Related

The one-vCPU debug full gate used to validate this work runs at its
50-minute budget because of a systest poll test unrelated to memory; see
[future-work.md](future-work.md).
