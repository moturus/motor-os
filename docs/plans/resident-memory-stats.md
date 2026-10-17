# Reserved and resident process memory

## Scope and accounting

Separate virtual reservations from RAM backing in process statistics and
`sysbox ps`, in two implementation commits. Descriptor-pool shrinking is
tracked separately as P2 in `future-work.md`.

- Preserve the existing metric names, IDs and meanings: `memory_usage` is
  reserved bytes; `pages_user` and `pages_kernel` are reserved 4 KiB pages.
- Add `memory_resident`, in bytes, for RAM backing the same tracked mappings.
  Untouched lazy pages, unbacked reservations, guard pages and MMIO contribute
  zero. A resident huge page contributes its full size.
- Count shared RAM once per mapping, including aliases. These process totals
  are not unique physical-memory usage; the existing system `mem.used` metric
  remains the source for that. Kernel stacks remain attributed both to their
  process and to the kernel address space, as in the existing statistics.
- Keep the existing accounting coverage: kernel bookkeeping, boot mappings
  and the fixed per-process static-page mappings are not newly attributed.
  Resident statistics describe tracked mappings, not the process's full cost
  to the kernel. Cached kernel stacks stay resident until actually freed.
- Keep reservation limits and admission policy unchanged. No new global
  statics, scans when collecting statistics, or additional boot-time tests.

## Patch 1: kernel statistics

1. Add a resident-page counter to `MemStats`, propagate its changes to the
   existing system aggregate, and seed early kernel allocations at stats
   initialization. Append the new byte metric without changing wire layouts
   or existing metric IDs.
2. Account RAM when attaching frames through eager allocation, lazy faults,
   file-paged fills, sharing, contiguous allocations and adopted frames.
   Use the existing mapping locks. Repeated faults and replacement of an
   already-backed shared destination must not increase the count.
3. Subtract backing during the existing teardown walk, after TLB invalidation.
   Balance failed construction and rollback without scanning untouched ranges.
   Account attributed kernel-stack backing separately, excluding both guards.
4. Extend existing in-VM memory tests to check reserved and resident counts
   across untouched reservations, first and repeated touches, sharing,
   huge/eager pages, guards, failed operations and unmap. Exercise the public
   metric through the existing systest/full-test path, including release.
5. Document metric semantics and mark this deferred item implemented in the
   sparse-reservations plan. Format and validate, then commit with a one-line
   message: `kernel: report resident memory separately from reservations`.

## Patch 2: sysbox ps

1. Resolve `memory_resident` by name alongside the existing reservation metric.
   Label the byte totals `VIRT_KB` and `RES_KB`, and the existing reserved-page
   columns `V_USER` and `V_KERN`. Size columns for both totals and their labels.
2. Explain units, untouched reservations, sharing and accounting coverage in
   help. Use the same columns in flat and tree output; preserve PID first and
   status/name last for existing consumers.
3. Add an integration check reached by `src/tests/full-test.sh` for flat and
   tree headers and memory values, with a large mostly untouched reservation.
4. Format and validate, then commit with a one-line message:
   `sysbox: show reserved and resident memory in ps`.

## Validation

Owner-approved gate: validate patch 1 with `systest`, then run
`src/tests/full-test.sh` three times in debug and three times with `--release`
after both patches are implemented, before committing patch 2. Run kernel
tests only inside Motor OS. Diagnose failures without adding retries,
changing timeouts or weakening assertions. No changes outside this repository
are planned.

Patch 1 validation (2026-10-17): debug `systest --vsock` passed in Motor OS,
including exact public-metric checks on an unstarted process, and the debug
boot's extended huge-page, sparse-fault, sharing and rollback assertions.
The combined three-debug, three-release gate follows patch 2.
