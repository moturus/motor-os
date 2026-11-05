# OOM handling follow-up

The four follow-up patches are implemented. The current behavior is described
in [docs/oom-handling.md](../oom-handling.md); the memory-manager mechanics
are in [docs/kernel-mm.md](../kernel-mm.md). The abort-policy alternative
below remains deliberately deferred.

## Completed patches

1. **Give protected processes System allocation class.** System-role
   processes, sys-io, and sys-io's children and grandchildren use the
   128-page (512 KiB) floor. Other processes and process-less spaces use the
   512-page (2 MiB) floor. A child records its class from its actual parent,
   including delegated spawns. Victim selection reads that recorded class;
   process roles and capabilities do not change.

2. **Retry allocating syscalls when their OOM run ends.** Recovery to Idle
   and stopping in Latched both release syscall waits. Every retry checks
   the arguments and target again. In Latched, User allocations return
   `E_OUT_OF_MEMORY`; System allocations succeed if they fit and otherwise
   return `E_OUT_OF_MEMORY`. Neither waits for a finished run. Ordinary
   oversized allocations whose rollback restores at least 768 free pages
   still fail instead of looping.

   A valid `F_PAGER_FILL` for a protected process retries physical pressure,
   including recovery before wait registration. It preserves the completed
   prefix and retries only the unfinished suffix after checking the mapping
   ID. Latched reopens its System gate; if no victim or pending cleanup
   remains below 512 pages, the existing kernel abort rule applies. Invalid
   mappings and I/O errors retain their normal handling. Faults keep their
   class-based waits because they have no error return.

3. **Retry temporary pager-buffer exhaustion in sys-io.** Read-ahead still
   falls back to one required page. If preparing that page's read or
   relocation buffer returns OutOfMemory, sys-io yields to its async runtime
   and retries later. It drains retirement events even when all serve
   tickets are occupied and discards retired requests. This buffer error
   does not call `pager_fail`; kernel fill errors remain separate.

4. **Finish kills of debugger-paused threads.** Killing a paused process
   now works. Saved syscall contexts wake to finish their exit; preempted
   threads receive an exit job. A thread still saving its context completes
   that handoff before cleanup, preventing an early or duplicate resume.
   A process can finish exiting while paused, and its pending cleanup counts
   when OOM decides whether any memory can still be reclaimed.

The validation run also found unnecessary stdin writes in sysbox's tests of
invalid arguments for cut, tr and xargs. Those cases now send empty input;
their exact exit-status and diagnostic checks are unchanged. The underlying
pipe-error classification issue remains recorded in
[future-work.md](future-work.md).

## Validation

Final source validation on 2026-11-05:

| Check | Result |
|-------|--------|
| Main full suite, debug, 4 vCPUs | Three passes |
| Main full suite, release, 4 vCPUs | Two passes |
| Main full suite, release, 1 vCPU | One pass |
| Developer full suite, release | Passed, including native tools, Lorry and 256 MiB wasm checks |
| Release stress soak, 4 vCPUs, 1 GiB, 7,200 seconds | Passed; all 14 workloads had zero failures |

The soak completed exactly 7,200 seconds with no anomaly, including 1,648
paging cycles, 4,029 sparse-memory cycles and 4,687 cancellation cycles.

The main gates include the kernel boot checks, the System-console OOM
suite and the expected victimless-abort fixture. Focused OOM checks also
passed on one and four vCPUs in both build profiles. Formatting and kernel
Clippy checks passed; component Clippy checks found only existing warnings
outside the changed code.

Earlier failures are preserved, not counted as passes:

- An extra one-vCPU debug full run reached its unchanged 3,000-second
  limit. Its OOM and debugger checks passed; the existing poll test consumed
  1,507 seconds and later passed. The full run timed out during network tests.
- The first developer release main gate reached its unchanged 1,500-second
  limit after its OOM and debugger checks passed. Later measurements showed
  steady filesystem-fill progress with no OOM waits. The original timing
  variation is still unexplained.
- A developer diagnostic run exposed the invalid-argument stdin race fixed
  above. The production pipe-error classification is still unresolved.
- A host SSH full-duplex test failed before any guest boot with
  `Channel send error`. Isolated and concurrent diagnostic runs passed,
  so its cause remains open. Temporary diagnostics were removed.

Details and original log locations are in [future-work.md](future-work.md).
Final main/developer logs are under
`/tmp/motor-oom-validation/final-v4/`; stress output is under
`/tmp/motor-stress/run-oom-final-v4/`.

The guest checks cover victimless syscall refusal, System progress in
Latched without rescanning, wake preservation, cancellation, normal fault
recovery, protected allocations, and reclamation of a victim whose thread
is still debugger-paused. Kernel boot tests cover retry decisions at the
floor and recovery boundaries, including protected pager-fill recovery
before wait registration. The expected victimless-abort fixture remains in
the full gate. Pager-buffer retry also runs with the existing demand-paging,
relocation, retirement and stress-soak coverage.

## Deferred: changing the abort rule

With no eligible victim and no pending exit cleanup below 512 free pages,
the kernel prints every remaining process and panics
(`OOM: no eligible victims or pending reclamation below 512 free pages`).
Protected processes can hold that memory legitimately while nothing is
blocked: System allocations still succeed down to 128 pages. The guest can
therefore terminate even though those processes could have kept working.
This policy is unchanged by the follow-up patches.

An alternative would end a victimless run below 512 pages like the
512–767-page case: latch, keep the User gate closed, and release System
callers. Ordinary allocating syscalls could return `E_OUT_OF_MEMORY` when
the retry still fails. A running program needing a missing page cannot
receive an error that way, so its handling needs a separate decision. The
rule that a charge below 512 pages while Latched starts a new run would also
need changing to avoid rescanning the same process set on every charge.
This alternative remains outside the implementation scope.
`src/tests/test-oom-abort.sh` and its `systest system-oom-abort` helper assert
the current rule and would change with it.
