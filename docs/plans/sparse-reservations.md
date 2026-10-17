# Sparse lazy memory

Implemented on 2026-10-17 as the five patches listed below. The plan was
revised on 2026-10-16 after review and the decisions
below. This develops option 4 of [lazy-memory.md](lazy-memory.md).

## Goal and scope

Make the cost of an untouched `F_LAZY` reservation independent of its
size. Today `allocate_pages` in `src/sys/kernel/src/mm/virt_intrusive.rs`
creates a 72-byte `Page` descriptor for every 4 KiB page at map time.
Instead, create the descriptor when the page gets its frame, as
file-paged segments do already.

Scope, as decided:

- Explicit lazy maps stay lazy and become sparse.
- Spawn stays lazy and sparse. A child's binary is demand paged by
  sys-io through file-paged segments, which are sparse already. User
  stacks are lazy segments and become sparse with the rule above. The
  loader's own mappings are eager and stay eager.
- Everything eager today stays eager. That includes unmapped
  reservations (flags 0), which exist to receive shared frames. They
  keep one descriptor per page, so every share destination stays dense.
- Sharing into a lazy segment is refused, as sharing with file-paged and
  huge-eligible segments is refused today. A lazy segment can still be
  a share source once every page of the shared range has been touched.

Checked on 2026-10-16: no lazy segment is shared anywhere in the tree.
An IPC share maps the client's pages into the server's listener
segment, which moto-ipc creates with flags 0 (io channels) or eagerly
(sync channels); the clients' pages are eager. The share-self paths
always build their destination inside the kernel, as an unmapped
reservation. The kernel never creates a lazy fixed segment, and no
in-tree caller passes a lazy address to any share.

Decisions recorded:

1. Descriptor allocation never fails. `phys::allocate_frame` panics on
   OOM and must never run under memory pressure; admission keeps it
   away. It now returns the frame itself, callers lose their descriptor
   and frame failure branches, and no test tries to provoke that path.
   Pressure is tested from userspace instead: a large sparse
   reservation, memory drained to the floor, then faults on more pages,
   which must kill the process.
2. Shared mappings stay eager. The IPC path needs no admission change.

The page-table retirement fix found on the way is committed as
`da57e934` with its self-test.

## What it buys

Kernel memory held and admission charge per reservation, touched or not:

| Reservation | Held today | Charge today | Held sparse | Charge sparse |
|---|---:|---:|---:|---:|
| 96 MiB | 1.75 MiB | 3.25 MiB | 72 B | 256 KiB |
| 4 GiB | 74.5 MiB | 128 MiB | 72 B | 256 KiB |
| 1 TiB | refused | refused | 72 B | 256 KiB |

The charge is held only during the syscall. Map time stops growing with
size: 80 ms for 4 GiB today, one segment insert sparse. A thread spawn
allocates 256 stack descriptors today and one sparse. Per touched page
nothing changes: 72 bytes of descriptor, 20 bytes of frame, the page
table share, one admitted fault.

## Design

A segment is sparse when its options contain `LAZY` or `FILE_PAGED`.
Sparse segments are never huge-eligible.

| Path | Today | Sparse |
|---|---|---|
| Map, `allocate_pages` | one descriptor per page | nothing for sparse segments |
| Fault, `fix_pagefault` | `find_page_mut(..).unwrap()` | check guard pages and rights by address and segment options; find or create the descriptor with its per-page options; then as today |
| Share, `share_range_with` | the source cursor assumes dense pages; a frameless source is found mid-loop | source walked by address; holes, frameless pages and lazy destinations refused before any replacement |
| Unmap, `clear` | frees every descriptor and sums their sizes | frees the existing ones, returns the segment size |
| Readers: `vaddr_map_status`, `pin_user_page`, user copies | a missing descriptor is an absent page | unchanged; rights of a hole come from its per-page options |
| Admission, `map_charge` | pages / 32 + 64 for lazy and unmapped maps | lazy: flat `mapping_charge(0, 0)`, 64 pages; unmapped: unchanged |

Details:

- Per-page options come from `page_mapping_options` by index, as at
  construction: guard ends are unmapped, the interior loses GUARD and
  LAZY.
- `VmemSegment::is_empty` goes by segment size, not by page count, so
  the drop assertion keeps its meaning. The nonempty-tree assertion
  that a sparse source can violate goes.
- Construction owns rollback. `allocate_pages` clears the segment when
  a page-table allocation fails; `map_frame` undoes only its own page.
  A fault that fails at the page table leaves its fresh descriptor
  frameless, which is a hole.
- `lazy_fault_charge` is written as `mapping_charge(1, 1)`. It now
  covers one descriptor too, and is still 66 pages.
- Accounting does not change. A reservation counts in full in
  `bytes_used`, `pages_user` and the process cap, so `ps` shows
  reservations, not residency.
- A new stack's top page is mapped through `fix_pagefault`, so no other
  path creates descriptors.

## Patches

Five patches, in order. Each leaves the existing paths usable; the lazy
charge stays per page until the last one.

1. **kernel: validate a share before replacing anything.** In
   `share_range_with`, look the source page up at each address, refuse
   a hole or a frameless page, refuse a lazy destination, all before the
   first PTE changes. This also fixes the existing replaced-prefix bug.
   Self-tests next to `huge_mapping_self_test`: a lazy source with an
   untouched page is refused and the destination keeps its bytes; the
   same source is accepted once fully touched; a lazy destination is
   refused.
2. **kernel: frame allocation is infallible.** Decision 1:
   `phys::allocate_frame` returns the frame; the descriptor allocators
   and `new_page` lose their error paths; `map_frame` fails only at the
   page table and undoes only its own page; `allocate_pages` rolls the
   segment back at its boundary.
3. **kernel: sparse lazy segments.** In `virt_intrusive.rs`: the sparse
   predicate, no construction for sparse segments, find-or-create in the
   fault path, `clear` returns the segment size, `is_empty`. Self-tests:
   an untouched 4 GiB lazy segment holds no descriptors and unmaps with
   full accounting; the first touch adds one descriptor and repeated
   touches keep the data; guard pages and plain reservations still
   fault; a lazy reservation of a quarter of the user region maps.
4. **kernel: `alloc_user_shared` cleanup.** When the second reservation
   fails, unmap the first and reverse each charge once; propagate the
   share result instead of unwrapping it, cleaning up both mappings.
   Self-test: fill the peer's address space with lazy reservations until
   a small one is refused, then `alloc_user_shared` must fail and leave
   nothing behind. This is testable only once reservations are cheap.
5. **kernel: flat lazy charge, systest, docs.** `map_charge` for lazy
   maps. Systest `test_sparse_reservations`, reached from
   `src/tests/full-test.sh`: a 64 GiB and a 1 TiB lazy reservation with
   bounded metadata growth, first, middle and last page touched, zeros
   first and data after; a map above the 1 TiB cap refused; the pressure
   test of decision 1, shaped like `test_lazy_fault_at_floor`; a
   half-touched lazy source refused by share-self and accepted once
   touched; unmap and process exit with live reservations return the
   accounting. Print the map time, do not assert it. Update
   `docs/kernel-mm.md`, `docs/oom-handling.md` and `lazy-memory.md`.

## Validation

Kernel tests run inside Motor OS, reached from `src/tests/full-test.sh`
through the debug self-tests or `systest`. Format with the repository
`cargo fmt`; no new compiler or clippy warnings. Each patch gets a
debug boot with its self-tests and, where it has one, its systest
subcommand. The series is gated as one core change: three debug and
three release runs of `src/tests/full-test.sh`, then
`src/tests/full-test-dev.sh --release`. No retries, longer timeouts or
weakened assertions. No boot-time work is added; thread spawn does less.

Gate results, 2026-10-17: three debug and three release runs of
`src/tests/full-test.sh` passed. The first `src/tests/full-test-dev.sh
--release` run failed in javy-smoke's `memory-refused-fault`: the wasm
smoke suite read the refusal counters at the system scope, where they have
not lived since 4207b96e. Fixed in the suite (5d619731); the rerun passed.

## Deferred

- Shrinking descriptor pools: the pool keeps its reuse-until-exit
  behavior. With sparse segments it only ever holds the busiest
  moment's touched pages.
- Splitting reserved from resident in process stats.
- Sharing into lazy segments. It would need descriptor creation in the
  share path and admission in the IPC get path, which takes no admission
  today. Add it only if a client needs it.
- The wasm forks' 96 MiB and 128 MiB caps. Their pooling allocator must
  stay under the 1 TiB per-map cap. Outside this repository.
