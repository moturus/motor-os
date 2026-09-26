# Kernel memory

The design of physical and virtual memory management in the Motor OS
kernel: `src/sys/kernel/src/mm`. Low-memory admission control and the
memory-pressure flag are specified in [oom-handling.md](oom-handling.md);
this document covers what they sit on.

All sizes use binary units. A small page is 4 KiB; a block or huge page is
2 MiB, containing 512 small pages. "Huge" means an ordinary allocation
backed by a level-2 page-table entry.

One rule governs the code: the kernel stays as simple as the design allows,
and tests adapt to the kernel. No counter, hook, failure-injection point or
observation mechanism is added so that a test runs deterministically; a
test that cannot be made deterministic with what the kernel already exposes
is redesigned or its case is recorded as untested.

## Module map

| Module | Role |
|---|---|
| `mm/mod.rs` | Constants (direct map at 1 << 46, kernel at 16 MiB physical), page sizes, the raw slab page supplier. |
| `mm/kheap.rs` | The kernel heap: `frusa` ([frusa.md](frusa.md)) with a per-CPU stage (private blocks and a magazine of freed slots) over a page supplier that bumps from the boot heap until memory is initialized, then allocates from the kernel heap region. |
| `mm/slab.rs` | Fixed-size slabs with intrusive refcounts (`SlabArc`); used for `Frame`, `Page` and segment descriptors, never deallocated. |
| `mm/phys.rs` | The physical allocator facade: `Frame` ownership, stage-2 release, metrics and statistics. |
| `mm/phys_blocks/` | The block pool: descriptors, free lists, search, boot shaping and the production instance. |
| `mm/virt.rs` | The kernel address space, its fixed virtual layout, mapping primitives, kernel self-tests. |
| `mm/virt_intrusive.rs` | Segment trees and per-page descriptors built on intrusive collections, so virtual allocation never recurses into the heap. |
| `mm/user.rs` | User address spaces: heaps, stacks, lazy and shared mappings, huge-page sizing, user-memory access. |
| `mm/mmio.rs` | MMIO mapping for the kernel's own devices. |
| `mm/admission.rs` | Admission floors, charges and the pressure flag (see oom-handling.md). |
| `mm/cache.rs` | A cache of freed same-size virtual segments. |

## Physical memory

### Memory outside the pool

Two physical regions are never managed by the block pool:

- The kernel image and its boot heap, loaded at 16 MiB. The boot heap is a
  bump allocator with checked, aligned reservation that serves startup
  allocations only; nothing is taken from it once memory is initialized. It
  is sized for the pool's descriptor lines plus 512 KiB for everything else
  (`phys_blocks::boot_heap_bytes`): 512 KiB on small guests, about 1 MiB at
  the span cap; measured use leaves over 100 KiB spare from 32 MiB to 40 GiB. If it
  cannot hold a startup allocation the kernel panics with the failing layout
  and the remaining bytes.
- MMIO, which is not RAM. Validation refuses any block carrying the RAM flag
  or a non-absent state, so RAM is refused at 2 MiB granularity, and rejects
  addresses beyond the x86 PTE's 52-bit address field. Outside-RAM addresses
  are accepted; this is not device discovery.

### Blocks

The pool divides the physical address span into 2 MiB blocks; block index is
`physical_address >> 21`. A flat array of descriptors covers the span through
the end of the last raw available-RAM range, holes included, up to 64 GiB
(32768 blocks). The span limit keeps one table allocation and direct indexing;
it is a support limit, not a claim about installed RAM.

Each descriptor is 16 bytes, four to a 64-byte `BlockLine`:

| Field | Meaning |
|---|---|
| `inner` | `SpinLock<Inner>`; protects every mutable ownership field below. |
| `inner.head` | First free-list index plus one, or zero for empty. |
| `inner.used` | All non-free positions in the block, including non-RAM positions; 512 - used is the block's free capacity. |
| `inner.unused_lo/hi` | Half-open range of pages never handed out. |
| `inner.alloc_lo/hi` | Half-open interval of RAM positions that may be allocated or freed. |
| `state` | `AtomicU8`: absent, whole, split or taken. |
| `flags` | `AtomicU8`: SMALL_ONLY, CLAIMED, RAM. |

State and flags are written only under the block's lock; unlocked reads are
selection hints.

| State | Invariants |
|---|---|
| absent | Not managed. RAM may still be set. |
| whole | 512 free RAM pages; allocatable interval [0, 512), used = 0, empty list, closed unused range. SMALL_ONLY whole blocks never supply huge pages. |
| split | Small-page ownership; free count = 512 - used; used > 0 whenever the lock is released. |
| taken | One owning huge allocation; used = 512, empty list, closed range; never SMALL_ONLY. |

A block is partial when its allocatable interval is narrower than [0, 512).
Positions outside the interval are permanently unavailable or non-RAM, so a
partial block can never become whole. The shaping rule below guarantees that
every block has exactly one allocatable interval; a firmware hole is never
spanned.

Memory below `DUAL_PURPOSE_START = 128 MiB` is small-only. Above it, whole
blocks may supply either huge pages or, as a last resort, small pages. Huge
allocation searches downward from the top; small allocation searches upward
from the bottom.

### Free lists and integrity

Each split block keeps a LIFO free list threaded through the freed pages
themselves, plus a fresh "unused" range that is handed out in address order
without ever writing links into it. Lists start empty at boot, so no free
page is touched during initialization.

The first u64 of a free page is an unkeyed check word:

| Bits | Contents |
|---|---|
| 0–15 | Next index plus one; zero terminates. |
| 16–39 | This page's physical page number. |
| 40–55 | Bitwise complement of bits 0–15. |
| 56–63 | Constant 0xa5. |

Decoding compares the whole word against the encoding of the expected page
identity and next index, and rejects out-of-range and self links before the
next head is installed. This catches mismatched redundancy and links copied
between pages or blocks; it is a diagnostic, not a MAC.

Each block also has eight u64 list-state words, one bit per small page, set
exactly for pages on its free list. The words live in one permanent
contiguous table outside the boot heap, 64 bytes per block, carved from
managed RAM at boot and never freed. Only split blocks have initialized
words: they are zeroed on the whole-to-split transition and never read for
whole, taken or absent blocks. The bits, together with the allocatable
bounds, independently prevent a forged link from allocating a page that is
already allocated or reserved. An exhausted list and unused range with
used < 512 is a panic, not a stranded block.

### Ownership operations

All of these run under the owning block's lock, which is a leaf: no other
lock is taken and nothing is allocated while it is held. Owning `Frame`
handles are created, and admission notified, only after the lock is dropped.

- Push: validate alignment, bounds, split state, the allocatable interval,
  used > 0, position outside the unused range, and a clear list bit. Encode
  the old head into the page, set the bit and the head, decrement used.
- List pop: validate the head, its set bit and bounds; decode before
  changing ownership; the next index, if any, must name another set bit
  inside the bounds. Clear the bit, advance the head, increment used.
- Unused pop or run: check bounds and that every requested bit is clear;
  advance `unused_lo`, add to used.
- Split: require whole; zero the eight words, install an empty head, unused
  range [0, 512), used = 0, split state; consume the requested page or run
  before releasing the lock.
- Huge take and return: validate alignment, bounds, dual-purpose eligibility,
  full interval, empty list and closed range. Take requires whole; return
  requires taken with used = 512. List words are never read.
- Re-combine: a push that brings used to 0 in a block with the full
  interval and list-bit count + unused length = 512 clears the words, closes
  the range, clears CLAIMED and sets whole. This applies to small-only blocks
  too; it restores contiguous-run capacity after churn without walking the
  list. A single live page pins its block.

Ownership checks are factored into helpers that return a failure reason;
production panics with the reason and the physical address.

### Accounting and indexes

`total_pages = free_pages + used_pages` in small-page units. `total_pages` is
normalized managed RAM, excluding the kernel heap, and is constant after
init. `used_pages` is allocated plus reserved RAM; a
taken block contributes 512; initrd and the list-state table count as
allocated. `reserved_pages` is the reserved subset: boot reservations before
stage 2, then permanent reservations and discarded free runs, constant after
stage 2. Non-RAM positions contribute to no global counter. A high-water used
count backs `min_free_small_pages`.

Two atomic bitmaps index blocks: F for split blocks with free pages and W for
whole blocks, including small-only ones. Bits match the descriptor whenever
its lock is released; a scan always revalidates under the lock. Updates are
AcqRel read-modify-writes, since different block locks protect bits in one
word. Split and taken counts are separate atomics; whole is W's popcount.

Publication order is fixed: descriptor changes and index updates happen in
the same critical section, and G (the global used counter) is updated with
Release RMWs.

| Operation | Order |
|---|---|
| Small pop or run of n | Update ownership; G += n and the high-water; clear F if the block is now full. |
| Push, block stays split | Update ownership; set F; G -= 1. |
| Push and re-combine | Update ownership, clear CLAIMED and list metadata; set W; clear F; G -= 1. |
| Split | Update descriptor; set F; clear W. G unchanged. |
| Huge take | Update ownership; G += 512 and the high-water; clear W. |
| Huge return | Update ownership; set W; G -= 512. |
| Stage-2 release of n | Reshape the descriptor; publish its final F or W; reduce reserved and G by n. |

Between free whole and split states the receiving index is published before
the old one is cleared. Allocation accounts consumption before withdrawing
indexed capacity; freeing indexes capacity before releasing its charge. This
is what makes the exhaustion protocol sound: after a failed complete scan of
F then W, the allocator Acquire-loads G. If G equals `total_pages` the pool
is out of memory at that observation. If G is smaller, a free has published
its bit before its counter decrement, so a rescan will find it. This is the
concurrent search protocol, not a retry loop; admission does not bound it.

### Search

Allocation and free are forbidden in interrupt and NMI context; page-fault
repair allocates only after returning to thread context. The spinlock panic
diagnoses a violation.

Before all CPUs are initialized, allocation scans F and W under block locks
with no cursors or claims; this path reads neither GS nor per-CPU state and
serves `virt::init` and AP stack/GS allocation. After the all-CPU
publication, each CPU has a cursor: an atomic block index, initially none.

A small page in runtime mode:

1. Pop from the cursor block: list first, then unused range.
2. If that fails or the block is no longer split, clear its CLAIMED hint
   and the cursor. Scan F upward for an unclaimed candidate; claim it, set
   the cursor, pop.
3. Scan every remaining F candidate, claimed or not; adopt a success as the
   cursor.
4. Only then split the lowest W candidate. Small-only whole blocks are lowest,
   so splitting them preserves the huge-eligible pool.
5. Otherwise apply the exhaustion protocol above.

CLAIMED is a contention-avoidance hint, not ownership. Cursors may share a
block, a stale cursor may point at a reused block, and clearing a hint may
clear another CPU's preference; block locks and ownership metadata decide,
so all of these are harmless. Kernel pages follow the same policy, which
tends to pack them low without reserving low memory.

A contiguous run of 2 through 512 pages checks the cursor's unused range,
then every other split block's unused range, then splits the lowest whole
block. List links are never searched for runs, and a fragmented split-only
pool may legitimately refuse a run despite sufficient free capacity. A huge
page scans W downward above the dual-purpose line and takes one whole block;
failure is a recoverable fallback signal, not exhaustion.

### Frames

A `Frame` (16 bytes, slab-allocated, refcounted through `SlabArc`) owns one
physical page of a given kind. Dropping the last reference returns the page
through the matching small or huge path, except for MMIO frames, whose drop
frees nothing. Page tables and slab backing pages are allocated frameless.
Boot-time reservations such as the initrd are adopted into frames whose
owners live as long as the reservation.

Consumers of direct-map addresses (copy-out, pinned user pages, the console's
control page) hold an owning `Frame` reference acquired under the region lock
and retained until use finishes. An address-space reference alone does not
prevent an explicit unmap.

If a frame descriptor cannot be constructed after a physical allocation, the
allocation is returned. For a contiguous run, existing handles own their
prefix and a guard owns the remaining suffix; rollback drops each exactly once.

### Boot shaping

`phys::init` receives available ranges with the kernel and boot heap already
subtracted, in-use ranges (the low 16 MiB and an above-kernel initrd), and the
raw firmware ranges for the RAM flag. Ranges are page-normalized, checked for
order and overlap, and coalesced; the initrd must lie wholly inside managed
RAM with no hole. Shaping touches no free data page:

| Layout | Initial shape |
|---|---|
| No managed RAM | Absent; RAM flag retained where applicable. |
| Managed RAM below 16 MiB | Split, fully reserved, empty list, intervals [0, 0). |
| Entirely free managed RAM | Whole; SMALL_ONLY below 128 MiB. |
| Other layout, no initrd | Split; the largest free run is both the allocatable and the unused interval. |
| Layout with initrd | Split; the largest free run immediately adjacent to the initrd, or none. Allocatable interval is that run plus the initrd; unused interval is the run only. |

Equal lengths pick the lowest run. Every other free run is discarded and
counted as reserved. The adjacency rule for the initrd keeps one interval
per block instead of a mask table, even when a disconnected run is larger;
with one internal reservation and no holes the loss is at most 1 MiB.

Construction order: check the span limit and compute the list-state table
size (one page per 64 blocks); find the lowest block whose retained free run
holds it and record those pages as allocated; install the table's direct-map
base and build descriptors and indexes; zero the words of every initially
split block; initialize global accounting; expose the allocator. Descriptor
lines and the two bitmaps are permanent boot-heap allocations, under 1 MiB
at the span cap.

Stage 2 runs on the BSP after every CPU has finished its own allocation and
before the schedulers are published. It reclaims managed RAM below the kernel
except page zero and the two kloader page tables still in use, through the
same layout code as stage 1 with those reservations in a fixed array. Most low
blocks become small-only whole; mixed ones follow the no-initrd rule.
`total_pages` never changes. Debug builds independently recount managed,
reserved and free pages from the input ranges at the end of init and of
stage 2, both quiescent points, and run the exact descriptor, list and index
invariants.

### Metrics

The pool reports gauges `mem.blocks_total`, `mem.blocks_whole`,
`mem.blocks_split`, `mem.blocks_taken`, `mem.blocks_whole_low`,
`mem.pages_reserved` and `mem.pages_free_low`, and cumulative events
`mem.block_splits`, `mem.block_recombined`, `mem.huge_pages_mapped` and
`mem.huge_fallbacks`. They are collected under no common lock, so only their
bounds hold at any moment; the exact state sum holds only at quiescent
points. `mem.pages_reserved` is constant after boot. Debug `PhysStats` and
`dump_serial` include block counts and reserved and discarded totals.

## Virtual memory

### Layout

The full physical memory is mapped at `PAGING_DIRECT_MAP_OFFSET = 1 << 46`;
the kernel runs at that offset plus 16 MiB. Kernel data lives in a 512 GiB
region below the direct map, laid out so a single L3 table covers it:
static (4 GiB), kernel stacks (8 GiB), kernel heap (8 GiB), MMIO (1 GiB),
slabs (7 GiB), then the kernel's copy of sys-io. User addresses run from zero
to 1 << 45. Two shared pages sit just below kernel data at fixed user
addresses: the kernel static page (which carries the pressure flag) and the
process static page. There is no KASLR.

### Segments and pages

An address space is a red-black tree of `VmemSegment`s; each segment holds
its `Page` descriptors. Both live in slabs of intrusive nodes so that
allocating virtual memory never allocates from the heap. `Page` and
`SegmentNode` are 72 bytes each, and admission's per-page metadata budget
(128 bytes per data page) is asserted at compile time to cover `Page`,
`Frame` and page-table growth.

A `Page`'s kind is derived from its `Frame`; a page without a frame is a
small lazy or unmapped reservation. Lookup finds the greatest page start not
above the queried address and checks its kind-sized extent. A segment's
creation policy (`HUGE_ELIGIBLE`) is stored as an internal bit in its mapping
options, never inferred from permissions or size, and stripped before any
hardware PTE is written.

`VmemKind` distinguishes boot, MM slab, MMIO, heap, stack, static, user,
user-stack and unmapped segments. `VaddrMapStatus` reports unallocated,
unmapped, zero-page, MMIO, private or shared for a user address; copy-in,
copy-out, pinning and sharing refuse MMIO and frame-less pages.

`PageTable::map_page` zeroes the entire frame before publishing its PTE.
Clearing a segment unmaps each page by its actual kind, flushes the whole
segment before dropping frames, and subtracts the sum of page byte sizes,
not the descriptor count times 4 KiB, from region and process statistics.
The region lock is held continuously from reservation through mapping or
rollback for MMIO and contiguous allocation, so a concurrent unmap cannot
remove or replace the reservation in between.

### User heaps and huge pages

Only `alloc_user_heap` requests above 256 small pages are huge-eligible.
Lazy, guard, shared, fixed-address, contiguous, MMIO and kernel allocations
stay small-only. `HeapSizing` decides the shape:

```text
whole = p / 512
tail  = p % 512
huge  = whole + (tail > 256 ? 1 : 0)
small = (tail > 256 ? 0 : tail)
mapped_pages = huge * 512 + small
```

| Requested | Huge candidates | Small tail | Returned size |
|---|---|---|---|
| 1 MiB | 0 | 256 | 1 MiB |
| 1 MiB + 4 KiB | 1 | 0 | 2 MiB |
| 2 MiB | 1 | 0 | 2 MiB |
| 3 MiB | 1 | 256 | 3 MiB |
| 3 MiB + 4 KiB | 2 | 0 | 4 MiB |
| 5.5 MiB | 3 | 0 | 6 MiB |

An eligible segment is 2 MiB aligned. Huge entries are stored first, then
the small tail. A refused huge candidate becomes 512 small mappings, and
after the first refusal every remaining candidate is served small without
asking again; the segment keeps its policy bit either way. Returned size,
statistics and admission all use `mapped_pages`; the charge is
`mapping_charge(M, M)` aggregated over the request, which conservatively
covers full fallback and needs no refund on huge success. `SysMem::map2`
exposes the returned size; `free` frees the complete segment.

Huge availability is best effort. After a pressure episode most blocks are
split and pinned by other processes' pages, so huge requests fall back until
those pages die.

### Sharing

`share_range_with` validates both ranges before replacing any destination
PTE or frame and returns `E_INVALID_ARGUMENT` if either endpoint belongs to
a huge-eligible segment, whatever its actual backing, or contains MMIO. This
applies to `F_SHARE_SELF` and to IPC's `map_shared`, including same-space
sharing. Supported shared buffers are fresh-frame `F_SHARE_SELF`, unmapped
reservations at the receiving end, and populated lazy small-only
allocations. On refusal an existing destination keeps its bytes and
translations, and a freshly created reservation is removed with its
statistics reversed.

### MMIO

Every successfully mapped MMIO page gets a `Frame` with the `mmio` flag, so
ordinary clear unmaps exactly the successful prefix with the usual
flush-before-drop order, and no physical memory is ever freed for it. The
descriptor is allocated before `map_page` and installed only on success. On
failure the virtual segment is removed and its accounting reversed once.
Kernel LAPIC, IOAPIC and sys-io BAR mappings use the same path.

## Admission and pressure

Admission is specified in [oom-handling.md](oom-handling.md). The parts
that touch the allocator directly:

- `available_small_pages` is the pool's free count; `min_free_small_pages`
  is derived from the pool's high-water mark and includes allocations made
  outside any admission window.
- Every successful free notifies admission after the block lock is dropped.
- Pressure sampling and publication are serialized by one `SpinLock<()>`,
  taken with interrupts disabled and holding nothing else. Every update site
  samples the reservation count (Acquire) and then physical availability
  inside the lock; callers cannot pass a stale count, and small-page frees
  participate even while the flag is clear. Only real transitions across the
  512/768-page hysteresis write the shared flag. This guarantees that a
  delayed publisher cannot restore an older observation over newer completed
  updates; it does not make the two counters an instantaneous snapshot.

## Validation

Kernel self-tests run in debug boots on Motor OS through full-test.sh, on a
scratch pool with independent descriptors, counters and list words; link
reads and writes are factored so the tests use an array of u64s and
production uses the direct map. They cover check-word integrity and every
corruption class, source order and cursor behavior, contiguous runs,
ownership transitions, re-combination, shaping across holes and initrd
layouts, table rounding and span limits, and the publication order of each
transition. A mapping self-test on the live pool, run on the BSP before the
schedulers are published, holds every whole dual-purpose block to force
fallback, releases one dirtied block to prove a huge leaf maps it zeroed,
and checks that sharing is refused at either eligible endpoint.

Systest (`mem_blocks.rs`, reached by full-test.sh) covers placement of fresh
1 MiB pieces within `10 + 2 * CPUs` blocks on the plain 1 GiB guest, mixed
size churn across threads with readback through every constituent page,
the sizing table through `map2`, huge reuse and zeroing, sharing refusals
and the supported sharing shapes, forced fallback on the 64 MiB launcher,
the pressure episode, and process and region accounting. The MMIO suite runs
from the System console fixture with `CAP_IO_MANAGER`: a mapping outside RAM
is queried, freed and then faulted on; RAM, wrapped and unaligned ranges are
refused with their rollback checked; an MMIO page is refused as syscall
buffer.

Pool-squeezing cases run only in plain systest, never under load.
Benchmarks are user-owned.

## Accepted costs and non-goals

Accepted: free-page link writes and a block lock per operation; 64 bytes of
list metadata per block; the 64 GiB span cap and the runs discarded to keep
one interval per block; rounding waste below 1 MiB per eligible request;
best-effort huge availability; large eager buffers ineligible for sharing;
possible descriptor false sharing between CPUs.

Out of scope: 1 GiB pages, NUMA, migration, randomized placement, host
free-page reporting, heap-size expansion, huge-page demotion, claim-spacing
heuristics, and any tuning knob without evidence and a separate review.
