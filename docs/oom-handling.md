# Free physical memory and the OOM transition

The first step of [the OOM plan](plans/oom-handling.md) removes reservation-based
memory admission. There are no allocation classes, admission floors or charges,
transient reservations, or guaranteed executable-page commitments. Per-process
memory limits, filesystem capacities, capability checks, socket/channel limits,
and ordinary backpressure remain independent.

The replacement OOM killer is a later step. The kernel's mapping paths are
fallible: physical exhaustion answers `E_OUT_OF_MEMORY` at every frame,
descriptor and page-table allocation made for a process and unwinds the
partial mapping (see [kernel-mm.md](kernel-mm.md)). `SysMem::map` still
reports every mapping failure as `E_OUT_OF_MEMORY`, and a fault that cannot
get a frame kills the faulting thread until the OOM gates park it. The
kernel heap still panics on exhaustion.

## Process identities

Step 2 gives each process a monotonic `u64` kernel PID and a public user PID.
Kernel PIDs never wrap or repeat; exhausting that counter panics the kernel.
Public PIDs keep their existing positive-i32 range, wrap to 4,096, and skip
IDs still in use. Both IDs are equal before the first public-PID wrap.

The statistics tree keeps kernel-PID and user-PID indexes under the same
children lock, along with the system node's PID counters. Internal child
traversal uses kernel-PID order. Public lookup, process-list pagination, metric
scopes, and per-CPU process statistics continue to use user PIDs and their order.
The shared-page and syscall process-identity formats are unchanged.

## Memory release at exit

Step 3 returns a process's memory when it exits rather than when the last
handle to it is dropped. The kernel completes an exit only after every
thread's stacks are unmapped, then retires the executable pager's mappings,
closes the process's IPC endpoints and releases its address space before
waiters see the exit: private frames, page descriptors, the process static
page and cached kernel stacks go back, shared frames stay alive through their
other mappings, and the process's user and kernel memory statistics read
zero. The emptied regions are closed, so a retained process or address-space
handle cannot map or share pages into the dead space, and the pager cannot
fill it; only the page-table root and its kernel entries stay until the last
handle goes. An address space hosts one process: a second process on the
same space is refused with `E_ALREADY_IN_USE`, as the first one's exit frees
what the second would run on. The mechanics are in
[kernel-mm.md](kernel-mm.md).

## Published free memory

`KernelStaticPage::free_pages` is the physical allocator's live count of free
4 KiB pages. The kernel stores one snapshot when the kernel address space is
created, on the BSP before other CPUs allocate, and from then on the block
allocator's `charge` and `release` apply the delta of every small, huge, and
contiguous allocation and free with a relaxed atomic add or subtract. Nothing
samples, no lock is involved, and no stale copy can overwrite a newer one: the
value is exact up to the operations still in flight on other CPUs. Userspace
reads it with one relaxed load through `moto_sys::free_pages()`.

There is no published pressure flag. `moto_sys::LOW_MEMORY_PAGES` (1,024
pages, 4 MiB) is the one limit services compare the count against, through
`moto_sys::low_memory()`; the 2 MiB and 3 MiB OOM thresholds belong to the
kernel's OOM run state in a later step, where hysteresis is serialized anyway.
The word at offset 60 that held the flag is reserved, so the boot identity at
offset 64 and `free_pages` at offset 72 keep their offsets.

The `AdmissionStats` query and admission metrics have been removed. Physical
memory statistics, the physical low-water mark, block allocator metrics, and
per-process user/kernel memory statistics remain available.

## Services and spawning

Below 4 MiB free, sys-io rejects spawn requests with `E_OUT_OF_MEMORY`,
including those from System processes. The kernel refuses runtime child
creation and the first `Created` to `Running` transition at the same limit,
against its own allocator count, so a delayed wake or queued start cannot
bypass the check. Bootstrap construction stays separate.

Other memory-based refusals have been removed from sys-io networking and
filesystem services, client runtime spawning, russhd, and strobe. Socket errors
and actual allocation failures retain their normal handling. Below the same
4 MiB, every process's allocator returns idle pages eagerly and sys-io releases
unused memfs cache blocks.

## Memfs

For every guest size, memfs write, copy, create, and move requests check the
free-page count. Below 1,024 pages (4 MiB), sys-io releases unused cached
memfs blocks and checks again; if still below 4 MiB it returns `StorageFull`.
At exactly 4 MiB allocating mutations are allowed. This is a check, not a
reservation: it does not promise a lower bound after the request completes.

Reads, stat, list, resize, and delete are served independently of this check.
Memfs resize changes sparse logical length without allocating data blocks.
Deleting or shrinking below the limit releases unused cached blocks. Capability
checks and donated-page cleanup still apply on rejected requests. Mount capacity
and cache sizing are unchanged; `fs.memory_refused` counts memfs refusals after
cache reclamation.

## Validation

The main full-test suite includes Motor OS kernel and sys-io self-tests, systest
mapping/accounting and concurrent frame churn, mounted memfs fill/delete and
service-recovery tests, and filesystem, network, logging, and spawn regressions.
Quiescent kernel checks compare the shared count with the allocator's after
small, huge, and contiguous allocations/frees. Memfs tests cover mutation
classification, the 4 MiB boundary, and cache reclamation. Old tests that expected
refusal at admission floors or guaranteed executable commitments are removed.
Debug-guest PID tests exercise isolated counter/index state across public-PID
wrap and reuse, kernel-ID exhaustion, and both traversal orders without changing
the live system counters. Systest also checks public listing pagination.
A debug-guest self-test releases a populated address space and checks that
every later reservation is refused while a peer's shared frame survives;
systest spawns a child that maps 8 MiB, exits normally or is killed, and
verifies with the handle still held that its user pages read zero, the pool
recovered, a shared page survived, and the dead space takes no new mapping;
it also checks that an address space refuses a second process before and
after the first one's exit.
