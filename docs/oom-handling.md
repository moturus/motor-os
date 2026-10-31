# Physical memory pressure and the OOM transition

The first step of [the OOM plan](plans/oom-handling.md) removes reservation-based
memory admission. There are no allocation classes, admission floors or charges,
transient reservations, or guaranteed executable-page commitments. Per-process
memory limits, filesystem capacities, capability checks, socket/channel limits,
and ordinary backpressure remain independent.

The replacement OOM killer and fallible user-page mapping paths are later steps.
Until those land, physical exhaustion can still panic in frame allocation or
page-table growth. Removing admission does not make those operations fallible.

## Published physical memory

`kernel/src/mm/pressure.rs` maintains `KernelStaticPage::memory_pressure` and
`free_pages`. The latter is actual free physical memory in 4 KiB pages, from
`phys::available_small_pages()`, without subtracting reservations. Both are
sampled inside the existing serialized pressure update after small, huge, and
contiguous allocations/frees release their allocator locks. Initialization
publishes a snapshot before userspace starts.

Pressure rises below 512 pages (2 MiB) and clears at 768 pages (3 MiB). Between
these watermarks it retains its previous value. `moto_sys::memory_pressure()`
and a relaxed load of `KernelStaticPage::free_pages` need no syscall. The shared
page's earlier fields, including the pressure flag at offset 60 and boot identity
at offset 64, retain their offsets; `free_pages` starts at offset 72.

The `AdmissionStats` query and admission metrics have been removed. Physical
memory statistics, the physical low-water mark, block allocator metrics, and
per-process user/kernel memory statistics remain available.

## Services and spawning

While pressure is raised, sys-io rejects spawn requests with `E_OUT_OF_MEMORY`,
including those from System processes. The kernel also refuses runtime child
creation and the first `Created` to `Running` transition, so a delayed wake or
queued start cannot bypass the check. Bootstrap construction stays separate.

Other pressure-only refusals have been removed from sys-io networking and
filesystem services, client runtime spawning, russhd, and strobe. Socket errors
and actual allocation failures retain their normal handling. Allocator slack
reclamation and reclamation of unused filesystem cache blocks remain enabled.

## Memfs

For every guest size, memfs write, copy, create, and move requests check actual
free physical memory. Below 1,024 pages (4 MiB), sys-io releases unused cached
memfs blocks and samples again; if still below 4 MiB it returns `StorageFull`.
At exactly 4 MiB allocating mutations are allowed. This is a sampled check,
not a reservation: it does not promise a lower bound after the request completes.

Reads, stat, list, resize, and delete are served independently of this check.
Memfs resize changes sparse logical length without allocating data blocks.
Deleting or shrinking under pressure releases unused cached blocks. Capability
checks and donated-page cleanup still apply on rejected requests. Mount capacity
and cache sizing are unchanged; `fs.memory_refused` counts memfs refusals after
cache reclamation.

## Validation

The main full-test suite includes Motor OS kernel and sys-io self-tests, systest
mapping/accounting and concurrent frame churn, mounted memfs fill/delete and
service-recovery tests, and filesystem, network, logging, and spawn regressions.
Quiescent kernel checks compare the shared snapshot with the allocator after
small, huge, and contiguous allocations/frees. Memfs tests cover mutation
classification, the 4 MiB boundary, and cache reclamation. Old tests that expected
refusal at admission floors or guaranteed executable commitments are removed.
