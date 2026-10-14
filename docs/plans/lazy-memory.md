# Lazy memory reservations on Motor OS

Findings from the wasm milestone 3 work (2026-10-14). Wasm runtimes on Motor
back each guest linear memory with one lazy reservation of its whole capacity,
so the cost of a lazy mapping sets how many memories, and how large, a process
can afford. Nothing under `src/sys` has been changed; this records the
measured behavior and the options for a later decision.

## How a lazy mapping works today

- `SysMem::map(SELF, F_READABLE | F_WRITABLE | F_LAZY, ...)` allocates no data
  pages, but the kernel creates one 72-byte `Page` descriptor for every 4 KiB
  page of the range at map time (`map_small`/`new_page` in
  `src/sys/kernel/src/mm/virt_intrusive.rs`), 56 per 4 KiB slab page. A
  reservation therefore holds about 1.8% of its size in kernel memory for its
  lifetime, touched or not. Unmapped (`flags == 0`) mappings do the same.
- Map-time admission charges `mapping_charge(0, pages)`: one page per 32
  reserved pages plus 64 (`src/sys/kernel/src/uspace/sys_mem.rs`,
  `src/sys/kernel/src/mm/admission.rs`). The charge is held only while the
  call runs, so a map needs about 1/32 of its size free above the 1 MiB user
  floor; it is not retained memory.
- Each lazy fault is admitted separately (`lazy_fault_charge`). A refused fault
  kills the faulting process; it cannot be reported as a failed allocation.
- Descriptors come from a per-address-space `PageAllocator`
  (`virt_intrusive.rs`, `PageAllocatorInner`). A freed descriptor goes to that
  process's free list and is reused by it; slab pages return to the system only
  when the address space is torn down at process exit. There is no shrink path.
- The per-process accounted cap (`DEFAULT_MAX_USER_MEMORY`) is `u64::MAX`, so
  it is not a quota. User space has 32 TiB of normal address space
  (`VMEM_USER_END`, `src/sys/kernel/src/mm/virt.rs`).

## Measurements

A probe maps N lazy regions of a given size, optionally writes one byte per
page of the first part of each, then unmaps them, reading free-for-admission
(`AdmissionStats`) and used memory (`MemoryStats`) after every step. Release
wasm image under QEMU at 224 MiB, about 187 MiB free at the start of each run:

| Reservation | Held per map | Map time |
| --- | ---: | ---: |
| 96 MiB | 1.75 MiB | 2.3 ms |
| 512 MiB | 9.3 MiB | 8 ms |
| 1 GiB | 18.6 MiB | 16 ms |
| 4 GiB | 74.5 MiB | 80 ms |
| 96 MiB, 8 MiB touched | 9.76 MiB | 1–2.5 ms |

The cost is linear in the reserved size. Sixteen 96 MiB maps held 28.3 MiB.
After unmapping everything the process still held all of it (28.3 MiB; 7.0 MiB
in the touched run, whose data pages did come back); the next process started
with the memory free again. One 4 GiB reservation fits at 224 MiB, because the
second needs 128 MiB free; two fit at 256 MiB (computed, not run).

## Consequences for Wasm

The Javy/Wasmi and Wasmtime forks limit each memory to 96 MiB, a process to
four memories and 128 MiB of total capacity; `docs/plans/javy-wasmtime.md`
records where the numbers came from. With today's kernel:

- Every live memory costs about 1.75 MiB and 2.3 ms to map. `wasmtime serve`
  under p2 creates an instance per request, so it pays this per request.
- A long-running process keeps the descriptors of its busiest moment: a server
  that once held N memories keeps about N × 1.75 MiB until it exits. This
  probably explains why 8 concurrent p2 requests measured only +7–10 MiB
  (the baseline already included retained descriptors); not verified.
- Removing the limits does not work. Guests normally declare no maximum, so
  each memory would reserve WebAssembly's 4 GiB ceiling: 74.5 MiB held, 80 ms
  to map and 128 MiB free needed at map time. At 224 MiB one instance fits;
  Javy's TypeScript compile has about 119 MiB free when it maps its compiler
  memory, so it could not start even at 256 MiB.

On Linux, upstream Wasmtime reserves 4 GiB plus a 32 MiB guard per memory, and
`wasmtime serve`'s pooling allocator reserves about 6 TiB for 1,000 slots at
startup, with no byte totals. That is affordable because a Linux reservation
is one mapping record and page metadata exists per physical page; running out
of RAM is left to the OOM killer.

## Options

1. **Keep finite capacities** (current). Wasm counts its per-process total
   against grown size rather than capacity; that is a wasm fork decision
   tracked in the wasm plan (3a).
2. **Cap each memory at the VM's RAM, with no count or total.** No kernel
   change. Each live memory holds about 1.8% of RAM (3.9 MiB at 224 MiB), and
   running out of memory kills the process.
3. **Memories that move** (grow by allocating and copying). No caps, and a
   refused growth fails cleanly, but growth briefly needs both copies; this is
   what 2b replaced.
4. **Kernel: create descriptors on first touch.** A reservation of any size
   would cost about one segment, map time would no longer grow with size, and
   map-time admission for lazy ranges could become a flat charge. This is what
   would allow Linux-like Wasm memories with no per-memory cap or total. The
   fault path currently requires an existing descriptor
   (`find_page_mut(pf_addr).unwrap()` in `fix_pagefault`), and teardown,
   unmap and sharing assume one descriptor per page, so they must handle sparse
   ranges. A core memory-management change: separate plan, review and the full
   three-debug, three-release gate.
5. **Kernel: let the descriptor pool shrink.** Return empty slab pages to the
   system. Independent of 4; it helps any long-running process that maps and
   unmaps large ranges.

Open for the owner: whether to pursue 4 and/or 5, and whether they go into
`future-work.md`.
