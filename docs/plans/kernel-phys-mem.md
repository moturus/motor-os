# Kernel physical memory allocation

2026-09-02, revised 2026-09-03 (v9). The first half describes what the
physical frame allocator does today and what it costs, collected while
working on boot time (`docs/plans/boot-time.md`, item 7). The second half
lays out design alternatives for the redesign: a free pages list,
contiguous allocations for hugepages, dual-purpose memory above 128 MB
(2 MB pages that split into 4 KB pages only as a last resort), and
best-effort re-combination of split 2 MB pages. Rulings from the review
rounds are folded in and marked as such. Decision: alternative B,
confirmed 2026-09-03 after the fourth review round, which proposed
alternative C and was declined on that point; the fifth to ninth
rounds (same day) corrected the integrity mechanism, the boot protocol,
the page-ownership representation, the MMIO and shadow details, and
the boot heap's alignment, and v9 carries them. The last part is the
plan: the final
design, the patch list, the tests, and the discipline for landing it.
Nothing is implemented yet; the plan is ready to implement.

Code: `src/sys/kernel/src/mm/phys.rs`, with `mm/slab.rs` for the frame
descriptors and `mm/admission.rs` for the floors. Every 4 KB frame in the
system comes from this allocator: user pages, kernel-static pages, page
tables, and the slab pages that hold per-page metadata.

## Today

### Data structures

Physical RAM is split into units of 64 small pages (256 KB), one
`DesignatedSegment` each: a start address, a page count, and a 64-bit
"used" bitmap. The units of all available RAM live in one `Vec` sorted by
address inside `MemoryArea<PageSizeSmall>`, together with three counters:
total pages, used pages, and the highest used count ever reached. A 1 GB
guest has about 4000 units, an 8 GB guest about 32000, a 48 GB guest about
196000; the descriptors take 32 bytes each, so 1 MB of them at 8 GB.

Besides the units there is:

- A one-slot cache, `free_frame`: the address of the most recently freed
  frame, shared by all CPUs, exchanged with atomic swaps.
- A slab of `Frame` descriptors (`MMSlab<Frame>`, 4 KB slab pages,
  refcounted through `SlabArc`). Every allocated frame that is mapped
  somewhere gets one, plus a 72-byte `Page` in the owning address space.
  The admission budget `METADATA_BYTES_PER_PAGE` covers both.
- Four 2 MB "mid" pages in a fixed range at physical [2 MB, 10 MB), with
  their own 4-bit bitmap. Small-page units are never created inside that
  range. Only sys-io takes a mid page (its MMIO region, one page, and
  `alloc_user_mid_pages` asserts that it comes back at physical 2 MB), and
  a mid page is never given back: the deallocation arm is commented out.
  The page tables can map and unmap 2 MB pages already (`map_page` with
  `PageType::MidPage` writes a level-2 entry).

### Boot

`phys::init` walks the PVH memory map, cuts every available range into
64-page units (two passes over the ranges, one to count and one to push,
so the vector never reallocates from the bump heap), sorts them, and marks
the reserved ranges used: everything below 34 MB, and the initrd when it
sits above the kernel (it holds sys-io's pages, mapped in place since
78e8042b). Stage 2 frees the low 34 MB again except the kloader's page
tables. Measured cost of `phys::init`: 0.5 ms at 1 GB, 3.0 ms at 8 GB, so
about 0.4 ms per GB, all of it building the unit vector.

### Allocating one frame

`MemoryArea::do_allocate_frame`, in order:

1. Take the cached frame from the one-slot cache if there is one.
2. If used pages equal total pages, return out-of-memory. This is the only
   exhaustion check, and it is O(1).
3. Pick a unit with a Lehmer generator (`util::prng`), up to three times,
   and take the lowest free bit of its bitmap with a compare-and-swap
   loop. A full unit fails the try.
4. Walk the unit vector from index zero until a unit has a free bit.

Nothing is remembered between calls: no cursor, no hint, no per-unit
summary. The generator is called with `add_entropy = false` by its only
caller, so it starts from the constant 13 on every boot and produces the
same sequence of unit numbers every time; the placement is reproducible,
not random, so it has no security value as it stands (details in
`boot-time.md`, item 7). Note that physical addresses are not hidden from
processes: `SysMem::virt_to_phys` (`sys_mem_query`) has no capability
check, so any process can read the physical address behind its own pages.
Whether that query should require a capability is a separate question;
placement randomization would be no defense while it is open.

`phys::allocate_frame`, the public entry, panics on an out-of-memory
result. The admission floors below exist so that this never happens.

### Freeing one frame

`MemoryArea::deallocate_frame` decrements the used counter, tells the
admission code that pages came back, and in release builds swaps the
address into the one-slot cache; the frame that was there before, if any,
goes back to its unit: a binary search over the sorted unit vector finds
the owner (O(log units)), and a compare-and-swap clears the bit. Debug
builds skip the cache and clear the bit directly.

### Contiguous allocations

`allocate_contiguous_frames` serves `VmemRegion::allocate_contiguous_pages`
(sys-io's virtqueues, through `SysMem::alloc_contiguous_pages`, which
sends anything over 1 MB as mid pages, and `sys_map` rejects contiguous
mid-page requests, so small-page runs are at most 256 pages). Requests
above 64 frames panic on an assertion in the outer allocator
(`PhysicalMemory::allocate_contiguous_frames`) before the inner path,
which would return out-of-memory above 256 and hit a `todo!` from 65 to
256, is reached; 2 to 64 frames
walk every unit from index zero and look for a run inside one unit's
bitmap, since a run cannot cross a unit boundary. The in-unit search stops
one bit early (`0..num_pages - 1`), so a run that ends on a unit's last
page is never found.

### Admission floors

`mm/admission.rs` refuses userspace operations that would take the free
count below 256 pages (128 for sys-io), holding the charge as an atomic
reservation while the operation runs, and raises a memory-pressure flag
in the kernel static page between 512 and 768 free pages. The floors keep
the allocator from emptying; they do nothing about how expensive an
allocation is on the way there. A mid-page map is charged no data pages
at all (`map_charge`: "come from outside the small-page pool").

### Costs and worst cases

The cheap parts: the cache hit, the exhaustion check, a random try (one
descriptor read plus a compare-and-swap; the descriptor is a random cache
line, so about 100 ns when the 1 MB descriptor vector is not in cache),
and a free (a binary search of 12 to 18 steps plus one compare-and-swap).

The expensive part is step 4. A random try fails with probability equal to
the used fraction of RAM, so at 95 percent full about 86 percent of the
allocations fall through to the walk, and every walk starts at index
zero. Each step reads a 32-byte descriptor and tests its bitmap; the
descriptors are contiguous, so the walk is prefetch-friendly, roughly 5 ns
per unit from cache and 20 ns from memory. The worst case is when the
only free frames sit near the top of RAM:

| guest RAM | units | worst case per allocation |
|---|---|---|
| 1 GB | ~4000 | 20 to 80 us |
| 8 GB | ~32000 | 0.2 to 0.6 ms |
| 48 GB | ~196000 | 1 to 4 ms |

Two things make the worst case the usual case over time. The walk always
takes the lowest free frame, so the holes that frees open low in RAM are
consumed first and free space drifts toward high addresses, which makes
the next walk longer. And a burst of N allocations when the first free
unit sits at index k costs N times k descriptor reads, since the walk
forgets where it found the last frame. The random tries add three wasted
cache misses on top of each walk.

So the allocator is cheap when the machine is empty (boot, tests) and gets
slower as it fills, which is also when it is called most: a busy 8 GB
guest at 95 percent full pays a fraction of a millisecond per page
allocation, and a process fault-in of a few hundred pages tens of
milliseconds, all of it in the kernel with interrupts enabled but the
calling thread stalled.

The contiguous path is worse in principle (a full walk from zero on every
call, plus a bitmap scan per unit) but is only used at boot.

### Other effects of the placement

- Runs of allocations land in unrelated 256 KB units across all of RAM.
  Under hugepage-backed guest RAM (QEMU with transparent hugepages here,
  cloud-hypervisor or Firecracker once the pools are enabled) every fresh
  frame then costs a 2 MB host fault: the 591 frames of the old sys-io
  copy fell into 347 distinct 2 MB regions and took 57 ms on QEMU against
  9 ms on 4 KB-backed cloud-hypervisor. With preallocated pools the cost
  is bounded by the number of 2 MB regions in the guest, 512 per GB, one
  cheap mapping each.
- Free runs inside a unit fragment immediately, so the contiguous
  allocator finds fewer runs the longer the system has been up.
- The one-slot cache serves only alternating free/allocate patterns; two
  frees in a row push the older frame back into its unit.

## Redesign

### What it has to do

In the words of the request, with what each point implies for the data
structures:

- (a) Free pages list. A singly-linked list of free 4 KB pages, empty
  (head = 0) on boot; a freed page points at the previous head and the
  head repoints to the freed page. Because the list is empty on boot,
  pages that have never been freed are not on it, so the allocator needs
  a second source for them: memory that has never been handed out, taken
  in address order by a cursor. This second source is what delivers (b).
- (b) Contiguous allocations that help with hugepages. Consecutive
  allocations should fill one 2 MB region before touching another, so a
  hugepage-backed host takes one fault per 2 MB instead of one per 4 KB
  (the item 7 finding). And the contiguous-frames path for sys-io's
  virtqueues should serve any run up to 512 pages without the `todo!`
  and the off-by-one.
- (c) Dual-purpose memory above 128 MB. When the guest has more than
  128 MB, memory above that line is managed in 2 MB pages that can also
  be split into 4 KB pages. Large allocations get 2 MB pages when any are
  free: ruled in the first review, a request of 2 MB or more gets
  (size >> 21) 2 MB pages, anything strictly larger than 1 MB gets a 2 MB
  page, anything shorter than 64 KB gets 4 KB pages; ruled in the second
  round, the line is at 1 MB, strictly larger, and the remainder of a
  request above 2 MB follows the same rule (the section on which requests
  get 2 MB pages has the table). A 2 MB page
  above the line is split into 4 KB pages only when there is no other way
  to satisfy a 4 KB allocation: no free 4 KB page anywhere, nothing left
  below the line, no already-split 2 MB page with room. Memory below the
  line stays 4 KB-only.
- Ruled in the first review: sys-io's 2 MB MMIO page stays as it is,
  whatever the guest's memory size: the fixed mid-page segment at
  [2 MB, 10 MB), `alloc_user_mid_pages`, and the physical 2 MB assertion
  are untouched, and the explicit 2 MB request path in `sys_map` stays
  sys-io-only. The dual-purpose 2 MB pages serve ordinary requests
  through the ordinary map path, by size.
- (d) Re-combination. When all 512 pages of a split 2 MB page are free
  again, it should become a whole 2 MB page again, best effort.

Out of scope, stated so they are not designed for by accident: 1 GB
pages, NUMA, randomized placement (see item 7: it buys nothing), and
compaction or page migration. Re-combination is best effort exactly
because a 2 MB page holding one long-lived 4 KB page (a page table, a
slab page) never re-combines; only migration would fix that, and the
policy section below keeps such pages out of the dual-purpose region
instead.

### Common ground

All the alternatives below share this much.

The unit of management is the 2 MB block: physical RAM cut into
2 MB-aligned, 2 MB-sized pieces, block number = address >> 21. One
descriptor per block in a flat array indexed by block number over the
whole physical address range, holes included (a hole costs one descriptor
marked absent; the PCI hole below 4 GB costs a few hundred), so that
address to block is a shift and a load rather than today's binary search.
The array is built arithmetically from the memory map: 512 entries per GB,
tens of microseconds at 48 GB, against 0.4 ms per GB today. This also
retires boot-time item 5.

Each block is in one of these states:

| state | meaning |
|---|---|
| whole | all 512 pages free, not split; the only state a 2 MB allocation takes from |
| taken | handed out as one 2 MB page |
| split | its 4 KB pages are managed individually |
| absent | not managed: not RAM, or RAM kept out of the allocator (the kernel and its boot heap, the fixed mid-page segment). Whether a block holds RAM at all is a separate flag from the firmware map, kept for the MMIO rule whatever the state |

Blocks whose 2 MB range is only partly available (memory-map edges, the
kernel and its boot heap at 34 MB, the initrd when it sits above the
kernel, page 0, the two kloader page-table pages left after stage 2) are
split from the start and never become whole; their reserved pages count
as used forever, as `mark_used` counts them today.

The line: `DUAL_PURPOSE_START = 128 MB`. Blocks below it are "small-only":
the 2 MB allocator never takes them. Blocks above it are dual-purpose. A
guest with 128 MB or less (Firecracker's `run-fc.sh` defaults to 64 MiB)
has no dual-purpose memory: every ordinary request gets 4 KB pages, and
sys-io's MMIO page comes from the fixed mid-page segment as it does today.
The fixed segment stays out of the block array as it stays out of the
unit vector now, so nothing about it changes. Freeing a dual-purpose
2 MB page returns its block to whole; the mid-page segment's pages are
never freed, as now.

Counters: one global `used` in 4 KB units (a taken block counts 512), so
`available_small_pages()` and the admission floors keep their meaning;
a global count of whole blocks above the line; a per-block `used` (u16),
which is what re-combination watches. Admission charges a dual-purpose
2 MB page 512 data pages plus descriptors; sys-io's fixed mid page stays
outside the pool and uncharged, as now.

Never-used memory is handed out by cursor from the block being split
("the current block"): a per-block `next_unused` index, advanced with a
fetch-add, so consecutive allocations fill one 2 MB region in address
order. A block with boot-time reservations in the middle keeps the larger
free run as its never-used range and gives up the smaller one (at most
1 MB per such block, three or four blocks per boot) rather than writing
list links into every page of it at boot, which would touch up to 128 MB
of fresh guest memory under a hypervisor.

Order of sources for a 4 KB allocation, which is (c) spelled out (as
the plan's per-CPU order has it; the first draft put every list before
the current block's range, which the plan's order supersedes):

1. The current block: its list, then its never-used range.
2. Another split block with free pages, lowest address first.
3. An untouched block below the line: split it.
4. A whole block above the line, lowest address first: split it. This is
   the last resort.

The 2 MB allocator takes the highest whole block above the line, so 2 MB
allocations and splits grow toward each other from opposite ends of the
dual-purpose region and stay apart as long as possible.

Long-lived kernel pages (page tables, slab pages for `Page` and `Frame`,
kernel stacks; all of them come through `phys_allocate_frameless` or the
kernel address space) follow the same order, so they land below the line
until it is full. At 8 GB fully mapped, per-page metadata is about 200 MB
(72-byte `Page` plus 20-byte `Frame` per page, plus page tables), so some
of it must land in the dual-purpose region; those allocations share one
current block, so they pack into a few blocks instead of holding one
page in each of many.

Zeroing is unchanged: a page is zeroed at map time unless `DONT_ZERO`.
Never-used pages are zero on every VMM here (anonymous or hugetlbfs
memory), but the BIOS path cannot promise it, so the allocator does not
track "known zero"; a per-block known-zero bit for untouched blocks is a
later optimization if 2 MB zeroing (0.1-0.2 ms bare metal, ~5 ms first
touch nested) shows up.

Concurrency: today's page-level operations are lock-free compare-and-swap
loops on bitmaps, and the alternatives keep that shape. Each has a
lock-based variant (a per-block spinlock around a few loads and stores,
20-40 ns uncontended) that is simpler to reason about; the block-level
lists, where they exist, change rarely enough (about once per 512 page
operations) to sit under one spinlock without further thought.

### Alternative 0: keep the format, add state (the item 7 minimum)

For reference, the smallest change: keep the 256 KB units, add a cursor
(the unit the last frame came from; fill it, then move on) and a
second-level bitmap with one bit per unit meaning "has a free frame"
(64 words at 1 GB, 3072 at 48 GB). A free sets its unit's bit with one
atomic OR; an allocation that finds its unit full clears the bit, re-reads
the unit, and sets it again if a free slipped in between. The search
scans words from the cursor: under a microsecond at 1 GB, about 30 us at
48 GB worst case, one word in the usual case, at any fill level. About 50
lines. It fixes the walk and gives sequential placement (b), and the
contiguous path can use the summary to skip full units; it does nothing
for (a), (c), or (d), and the unit stays 256 KB, so 2 MB pages would
still need a separate mechanism.

### Alternative A: one global free pages list, links in the pages

This is (a) taken literally.

Data: a global `head` (atomic u64) and, in the first 8 bytes of every free
page (through the direct map), the address of the next free page or 0.
Per block: `used`, `next_unused`, state; 8 bytes. The current block for
never-used pages is a global pointer.

| operation | steps |
|---|---|
| allocate 4 KB | pop: load head, load next from the page, CAS head; on empty, fetch-add the current block's `next_unused`; on exhaustion, claim the next block in the order above |
| free 4 KB | store head into the page, CAS head; decrement the block's `used`; if it reached 0 and the block is dual-purpose, count it as a re-combination candidate |
| allocate 2 MB | take the highest whole block above the line (a bitmap of whole blocks, one bit per block, scanned from the top); none: run a sweep if there are candidates, then retry; else fail, and the caller falls back to 4 KB |
| free 2 MB | block back to whole |
| contiguous n <= 512 | from the current block's never-used range if n fit, else split a fresh block and take its first n; n > 512: consecutive whole blocks from the bitmap |
| re-combine | the sweep, below |

The pop has the classic ABA hazard: CPU A reads head = X and X's next = Y;
CPU B pops X, pops Y, pushes X; A's CAS from X to Y succeeds while Y is
allocated. A tag in the head word closes it: 40 bits of page number (52-bit
physical addresses) plus a 24-bit counter that changes on every CAS. The
counter wraps after 16 million pops, well under a second of sustained
allocation across 8 vCPUs, and a vCPU can be descheduled by the host for
longer than that, so the tag should be 64 bits, which means a 128-bit
compare-and-swap (`cmpxchg16b`) or a spinlock around the pop.

Re-combination cannot be done in place: a singly-linked list has no
way to remove the 512 pages of one block, and their links live inside the
pages, so the block cannot be handed out as a 2 MB page while its pages
are still linked (the new owner would overwrite the links and break the
chain). The sweep: swap the head to 0, taking the whole list; walk it,
dropping every page whose block has `used == 0` and re-pushing the rest;
a block whose dropped count reaches its free count becomes whole. It
costs one cache miss per free page: 1 million pages at 8 GB half full,
50-100 ms of one CPU, during which allocations find an empty list and
take never-used pages, which may split fresh blocks, the very thing (c)
wants to avoid. Triggers: a 2 MB request that finds no whole block (adds
the sweep's latency to that request), or an idle CPU when candidates pass
a threshold such as 16 blocks.

Other properties: the list interleaves pages of all blocks, so LIFO reuse
scatters across 2 MB regions (harmless for hugepage backing, since those
regions are already faulted in). Contiguous runs among freed pages are
invisible; only never-used memory serves runs. Freeing writes a cache
line into the page (a page that was just unmapped is usually not in
cache, so a miss per free). A use-after-free bug that writes into a freed
page corrupts the allocator; debug builds can store `next XOR key XOR
own address` and check it on pop. Handing free memory back to the host
(the guest reporting free pages for the host to discard; open question 3)
would be limited to whole blocks and never-used ranges, since a discarded
page loses its link.

Metadata: 4 KB per GB of block descriptors plus 64 bytes per GB for the
whole-block bitmap.

### Alternative B: one free pages list per 2 MB block, links in the pages

Still (a), with the head inside the block descriptor instead of one global
head. Chosen (2026-09-02, third review round); the reasons are in the
comparison, and the plan at the end has the final form. The plan replaces
the head tag and the compare-and-swap protocols described here with one
lock per block (a review found a window between a pop and its `used`
increment that the tag does not cover); the data structure is otherwise
the same.

Data per block, 16 bytes: `head` (atomic u64: 9-bit page index within the
block, an empty marker, and a 54-bit tag that never wraps), `used` (u16),
`next_unused` (u16), state and flags. In each free page, the index or
address of the next free page of the same block. Global: a "has free
4 KB pages" bitmap (one bit per block: the block is split and its list
or never-used range is non-empty), a "whole" bitmap, one cursor each, the
counters.

| operation | steps |
|---|---|
| allocate 4 KB | the cursor's block (sticky: it stays on one block until the block is dry, so consecutive allocations come from one 2 MB region); pop from its list, else fetch-add its `next_unused`; if it yields nothing, clear its bit, re-check (a free may have slipped in; if so set it again), and take the next set bit from the cursor; no set bit: split a block per the source order |
| free 4 KB | push onto the page's own block (block number from the address); decrement `used`; if the block was dry, set its bit; if `used` reached 0 and the block is dual-purpose and full-sized, re-combine |
| allocate 2 MB | highest whole block above the line from the whole bitmap; none: fail |
| free 2 MB | block back to whole, bit set |
| contiguous n <= 512 | a split block whose never-used range has n left (contiguous by construction), else split a fresh block and take its first n, leaving 512 - n for 4 KB use; n > 512: consecutive whole blocks |
| re-combine | O(1), in place, below |

Re-combination is immediate and exact: `used == 0` means all 512 pages
are on the block's list or in its never-used range, and both live in the
descriptor, so they can be forgotten. Close the never-used range (CAS
`next_unused` to 512), empty the list (CAS `head` to empty with the tag
advanced), set the state to whole, clear the has-free bit, set the whole
bit. A CPU in the middle of a pop on this block had read the old head;
its CAS fails against the advanced tag and it moves to another block. If
a pop lands between the `used` read and the head CAS, the head CAS fails
and re-combination is abandoned; the next free that brings `used` to 0
tries again. Nothing walks anything.

Contention: with a sticky cursor every CPU pops from the same block's
head at once. If that shows in a profile, the cursor becomes per-CPU
(each CPU claims its own current block; frees still go to the page's own
block), which keeps the 2 MB locality per CPU. The bitmap protocol
(set on free, clear-then-recheck on a dry block) is the one from
alternative 0.

Properties shared with A: links in the pages (one write per free, the
use-after-free exposure, host reclaim of free memory only by whole
blocks). Unlike A, a
block's pages stay together, so pops from one block stay in one 2 MB
region, and the ABA tag fits in 64 bits without a 128-bit CAS. Contiguous
runs among freed pages are still invisible.

Metadata: 8 KB per GB of descriptors, 128 bytes per GB of bitmaps;
384 KB at 48 GB, which fits the 2 MB boot heap. The plan adds a page-state
bitmap of 32 KB per GB outside the heap (decision 5), which brings B to
C's metadata size.

### Alternative C: per-block bitmaps, no free pages list

Today's structure with the unit grown to 2 MB and given state. Not (a),
included because it is the only one that keeps the allocator out of the
pages entirely.

Data per block, 80 bytes: a 512-bit used bitmap (8 words), `used`, state.
The same has-free and whole bitmaps and cursors as B.

| operation | steps |
|---|---|
| allocate 4 KB | cursor's block; scan its 8 words for a zero bit, CAS it; dry: clear bit, re-check, next |
| free 4 KB | CAS the bit clear; decrement `used`; `used == 0` on a dual-purpose block: state to whole, bitmaps updated; the bitmap is all zero by then, nothing to close |
| allocate 2 MB, free 2 MB | as B |
| contiguous n <= 512 | scan a block's bitmap for a run of n zero bits, including runs that frees opened; CAS the mask; n > 512: consecutive whole blocks |
| re-combine | O(1), a state change |

Properties: no write into freed pages, so the host can reclaim any free
4 KB page, use-after-free bugs cannot corrupt the allocator, and a double
free is detected (the bit is already clear). Allocation takes the lowest free bit, not the most
recently freed page, so the returned page is usually cold in cache;
whether that costs anything measurable is unknown. Never-used memory
needs no separate cursor: the bitmap says which pages are free.

Metadata: 40 KB per GB; 1.9 MB at 48 GB, which does not fit the 2 MB boot
heap next to everything else, so the array would be placed in pages taken
from the first blocks instead of heap-allocated. Boot cost stays small:
the bitmaps of untouched blocks are zero and need no writes beyond the
descriptor.

### Alternative D: one global list with links outside the pages

A global list as in A, but the link of each page lives in a per-page
array (next index u32 plus a generation u32, 8 bytes per 4 KB page), not
in the page. Because the links survive whatever the page's owner writes,
re-combination needs no sweep: `used == 0` flips the block to whole at
once, and its pages stay on the list as stale entries that a pop
recognizes (the entry's generation differs from the block's, which
advances on every split) and discards. Each stale entry is popped at most
once, so the tax is one extra pop per free, amortized; the worst burst is
a list full of stale entries after many blocks re-combined.

Metadata: 2 MB per GB, 96 MB at 48 GB, 0.2 percent of RAM, allocated at
boot from the blocks themselves. This is the Linux `struct page` shape at
a fraction of the size. It keeps (a) global and gets O(1) re-combination,
at a cost in memory and in mechanism that B does not have.

### Comparison

| | 0 | A | B | C | D |
|---|---|---|---|---|---|
| free pages list as in (a) | no | global | per block | no | global |
| metadata per GB | 128 KB | 4 KB | 8 KB, 40 KB with the plan's page-state table | 40 KB | 2 MB |
| fits the 2 MB boot heap at 48 GB | yes | yes | descriptors yes, the table is taken from blocks | no | no |
| allocate 4 KB, usual case | word scan + CAS | pop (2 loads, 1 CAS) | pop (2 loads, 1 CAS) | up to 8 loads + CAS | pop |
| free 4 KB | CAS + atomic OR | 1 store, 1 CAS | 1 store, 1 CAS | 1 CAS | 2 stores, 1 CAS |
| 2 MB pages (c) | separate mechanism | yes | yes | yes | yes |
| re-combination (d) | no | sweep, O(free pages), 50-100 ms at 8 GB | O(1), exact | O(1), exact | O(1), lazy |
| contiguous runs among freed pages | in-unit | no | no | yes | no |
| sequential placement (b) | cursor | never-used range | never-used range | lowest bit per block | never-used range |
| allocator writes into free pages | no | yes | yes | no | no |
| a write into a free page detected | no | debug | yes (authenticated link) | no | no |
| double free detected | yes | no | yes (page-state table, see the plan) | yes | no |
| ABA | none | 128-bit CAS or lock | 64-bit tag | none | generation |
| boot init at 48 GB | 20 ms (today's shape) | tens of us | tens of us | tens of us | ms (array zeroing) |

Recommendation: B. It is (a) as asked, block by block; it gets (b) from the
never-used range, (c) from the block states, and (d) in constant time
with nothing to walk, which A cannot do without a sweep whose cost grows
with free memory and which undoes (c) while it runs. C is the fallback if
writing links into free pages turns out to be unwanted (free-page
reporting, debuggability); it costs five times the metadata and loses
the LIFO warmth, and it is not (a). D buys nothing over B for its size.
Ruled 2026-09-03: C is not an option. The fourth review proposed it on
the grounds that B needs a production per-page bitmap to detect double
frees. The fourth version of this plan claimed that release checks
without a bitmap were exact; the fifth review showed they are not (a
write into the free page between two frees defeats a conditional
check), so the plan now carries a per-page state bitmap in every build
(decision 5). That erases B's metadata advantage over C. What B keeps is
the list itself, which is what was asked for, its LIFO order, the
never-used range, and the detection of a write into a free page, which a
bitmap alone never gives.

### Which requests get 2 MB pages

Ruled in the first review: a request of 2 MB or more gets (size >> 21)
2 MB pages; anything strictly larger than 1 MB gets a 2 MB page; anything
shorter than 64 KB gets 4 KB pages. So a request is served with real 2 MB
page-table entries, rounded up, not merely backed by contiguous 4 KB
frames from one block. Ruled in the second round: the line is at 1 MB,
"strictly larger than 1 MB", and the same rule applies to the remainder
of a request above 2 MB. In one formula: a request of S bytes gets
(S + 1 MB - 4 KB) >> 21 pages of 2 MB, and whatever is left in 4 KB
pages. Round to the nearest 2 MB, ties down. The reasoning that led
there is kept below for the record.

| request | 2 MB pages | 4 KB pages | mapped | waste |
|---|---|---|---|---|
| 64 KB to 1 MB | 0 | S / 4 KB | S | 0 |
| exactly 1 MB | 0 | 256 | 1 MB | 0 |
| 1 MB + 4 KB | 1 | 0 | 2 MB | just under 1 MB |
| 1.5 MB | 1 | 0 | 2 MB | 0.5 MB |
| 3 MB | 1 | 256 | 3 MB | 0 |
| 3 MB + 4 KB | 2 | 0 | 4 MB | just under 1 MB |
| 5.5 MB | 3 | 0 | 6 MB | 0.5 MB |

At the line itself: exactly 1 MB gets 256 4 KB pages. The tie goes to the
side with no waste, because at 1 MB the 2 MB page's advantages (one entry
instead of 256, 23 KB less descriptor memory) are worth far less than the
1 MB it would leave unused, and because "strictly larger" is how the
ruling was phrased. Just above the line the mapping jumps from S to 2 MB:
the syscall returns the rounded size, the process is charged the rounded
size in its memory stats, and `SysMem::free` frees the segment whole, as
now. Note that `SysMem::alloc` discards the returned size and hands back
only the address (`map2` returns both), so a caller of `alloc` does not
learn that it holds 2 MB; nothing depends on it, and surfacing the size in
the library is a `moto-sys` change outside this plan. When no whole block
is free, or the
guest has no dual-purpose memory, the same request gets 4 KB pages; a
caller that reads the returned size is unaffected, and the only code that
depends on physical contiguity (sys-io) uses the contiguous path anyway.

Why 1 MB and not lower (the recommendation the ruling adopted):

- The waste is bounded only above 1 MB. There it stays below 1 MB and
  below 100 percent of the request. Below it grows without bound: three
  times the request at 512 KB, seven times at 256 KB, thirty-one times at
  64 KB. A process making a hundred 300 KB allocations would hold 200 MB
  instead of 30.
- The benefit does not scale down. What a 2 MB page saves is proportional
  to the request: page-table entries, TLB entries, 92 bytes of descriptors
  per 4 KB (23 KB at 1 MB, 6 KB at 256 KB). The host-side benefit, one
  hugepage fault instead of 512, comes from the block cursor for 4 KB
  pages already: consecutive 4 KB allocations fill one 2 MB region, so a
  256 KB request lands inside one host hugepage either way. Below 1 MB
  the marginal benefit is guest TLB reach for a range that fits in at
  most 256 of the 1500 to 2000 entries of a second-level TLB.
- The map gets slower, not faster. A 2 MB page is zeroed in full at map
  time, 0.1 to 0.2 ms on bare metal and milliseconds on a nested host
  with fresh pages, whatever the request was. For a 256 KB request that
  is eight times the zeroing of its 4 KB pages.
- Whole blocks are a finite pool. Small requests taking whole blocks
  leave fewer for the requests above 1 MB that benefit most, and a 2 MB
  page cannot be returned in part.
- What Motor OS's own userspace asks for today (from the code, not
  measured): the process heap (frusa, behind the vdso's `sys_alloc`)
  requests 4 KB or 32 KB chunks for small size classes, the exact size for
  classes up to 256 KB, and max(size, 2 MB) above 256 KB with 2 MB
  alignment in the layout, which the vdso backend currently drops
  (`sys_alloc(layout.size())`). So the heap already sends 2 MB requests
  for everything above 256 KB, and its only traffic in the 64 KB to 1 MB
  band is exact-size slabs for objects of 32 KB to 256 KB, which a lower
  line would inflate two to thirty-one times. A process image is loaded
  through a temporary buffer the size of the file, hundreds of KB to a
  few MB. Thread stacks are 254 pages, lazy, with guards; the vdso and
  read-only ELF segments are shared maps. None of these gain from a line
  below 1 MB.

If a measurement later shows that guest TLB misses on 256 KB to 1 MB
objects matter for some workload, the better fix is in the allocator that
owns the objects: it can ask for 2 MB and fill it with several objects,
as frusa does above 256 KB and as jemalloc, tcmalloc, and mimalloc do,
where the kernel cannot know how densely a request will be used. That is
the division of labor every system below uses. The line should be one
constant in one place, so moving it is a one-line change once there is a
number. Frusa's 2 MB alignment request needs nothing from anyone: frusa
uses it only to build the layout it hands the vdso, never to compute an
address, and the vdso drops it; a 2 MB request that the kernel serves
with a 2 MB page lands 2 MB-aligned by construction, and one served with
4 KB pages is unaligned exactly as today.

Eligible requests: private, eager, read-write, anonymous segments, which
is the process heap, image-load buffers, and explicit allocations. Not
eligible, always 4 KB: lazy segments (a 2 MB page would defeat lazy
fault-in and cannot hold a guard page, so stacks stay as they are), guard
segments, shared maps (`F_SHARE_SELF`, io_channel pages), MMIO, and the
contiguous path. What changes at the mapping layer: `Page` must carry a
size (`contains` and the tree assume 4 KB), a segment can mix 2 MB and
4 KB pages, the 2 MB part goes first at a 2 MB-aligned virtual address
(so the vmem allocator gains an aligned allocation), unmap and the fault
handler handle both sizes, and one `Frame` of kind `MidPage` describes a
2 MB page. A first step can keep the 4 KB part of a large request as one
run from a single block (the contiguous-frames path), which costs nothing
extra and keeps it inside one host hugepage.

What Linux does, for comparison. None of the mainstream systems rounds a
request up to a huge page; the ruling here is deliberately more generous
than all of them.

- Anonymous memory (transparent hugepages): the decision is made per
  2 MB-aligned range at fault time, not per request. A huge page is used
  when the aligned 2 MB range lies entirely inside the mapping and
  hugepages are enabled for it (`always`, or `madvise` plus
  `MADV_HUGEPAGE`). A mapping is never rounded up: the parts of it that
  are not a full aligned 2 MB get 4 KB pages, a 1.9 MB mapping never gets
  a huge page, and a 3 MB mapping gets at most one, and only if it
  contains an aligned 2 MB range. To make that likely, since 6.7 `mmap`
  places large anonymous mappings on 2 MB boundaries; after regressions
  this was narrowed (6.8 to 6.9) to mappings whose length is a multiple
  of 2 MB.
- The waste in Linux is of a different kind: the first touch of any byte
  in an eligible aligned range allocates all 2 MB, so a sparse access
  pattern bloats memory up to 512 times, which is why distributions ship
  `enabled=madvise` and why the `defrag` knob exists. The background
  collapser, khugepaged, is even more tolerant: its `max_ptes_none`
  defaults to 511, so a 2 MB range with one populated page out of 512 is
  collapsed into a huge page.
- Multi-size hugepages (6.8 and later, off by default): the same rule at
  16 KB to 1 MB, each size enabled separately; the fault takes the largest
  enabled size whose aligned range fits inside the mapping and is not yet
  populated.
- Page cache: folios are sized to the readahead window, growing by two
  orders per sequential round, aligned to their own size, capped at 2 MB,
  never larger than the range being read.
- hugetlbfs: explicit and exact; the length must be a multiple of the
  huge page size or the map fails.
- Userspace: glibc `malloc` serves requests of 128 KB and up by `mmap`
  (the threshold grows dynamically to 32 MB) and, with the
  `glibc.malloc.hugetlb` tunable, advises hugepages and aligns those
  mappings to 2 MB. jemalloc, tcmalloc, and mimalloc manage memory in
  2 MB or larger aligned chunks and place many objects in each, which is
  how mid-size objects get hugepages without waste.

Two other systems, since they are the two readings of the original
request: FreeBSD reserves a 2 MB physical block for a mapping at the
first fault in an aligned range that fits inside it, populates it 4 KB at
a time from that block, and promotes the range to a superpage once all 512
pages are mapped with the same protection; never a rounding, and the 4 KB
pages of one range always come from one block, which is what the block
cursor does here. Windows gives 2 MB pages only on explicit request
(`MEM_LARGE_PAGES`), with the size a multiple of 2 MB.

## Decision and plan

Alternative B, with the rulings above: 2 MB blocks, the line at 128 MB,
sys-io's mid page untouched, 2 MB pages for requests strictly larger than
1 MB and for the remainder above 2 MB by the same rule, round to the
nearest 2 MB with ties down. A second review of the first version of this
plan (same day) found a race in its lock-free protocols and several
smaller defects; its findings are folded in below and listed at the end.

### Decisions taken for the plan

Each of these is a call made to make the plan concrete; any of them can
be reversed before the patch that depends on it.

1. One spinlock per block covers the block's head, `used`, and never-used
   range; every page-level operation on a block runs under it. The lock
   is the kernel's `SpinLock` (an `AtomicBool`; the u32 passed to `lock`
   is a diagnostic tag, not a field), a leaf lock: nothing else is taken
   while it is held, and it is not held across any allocation. The
   global bitmaps and the per-CPU cursors are hints, always validated
   under the lock. This replaces the compare-and-swap protocols of the
   alternative B section: the review found that a pop which has taken a
   page but not yet counted it lets re-combination publish a whole block
   with an allocated page in it, and that the give-up path lost the
   detached list; both are trivial under a lock and were three more
   invariants without one. Uncontended cost is a few tens of
   nanoseconds; the per-CPU cursors keep unrelated CPUs on different
   blocks.
   The lock does not mask interrupts, so the allocator is not re-entrant
   from an interrupt handler the way today's compare-and-swap loops are.
   Rule: no physical allocation or free in IRQ or NMI context. The IRQ
   paths today (`irq_handler_inner`: the console wake, the timer tick,
   the custom-IRQ wakes) are lock-free by design and allocate nothing;
   the kernel heap grows through `allocate_frame`, so a heap allocation
   from an interrupt handler would be the way to break the rule. A
   per-CPU IRQ depth counter, incremented on entry to `irq_handler_inner`
   and decremented on its return, reset to zero on the preemption switch
   (which never returns to the interrupted context), backs a debug
   assertion where the allocator takes a block lock. The counter lives
   in per-CPU storage behind GS, which `init_cpu_postboot` sets up
   after `phys::init` has already taken block locks (P1b takes the
   page-state table there), so the assertion is gated on the existing
   `cpu_initialized` status and reads nothing before it. A counter
   rather
   than a flag: an NMI that lands inside an IRQ must not clear the outer
   one on its way out. Every exception entry that can reach allocator
   code counts the same way; today there is none besides the page
   fault, which runs in the faulting thread's context.
2. The line is one constant, `DUAL_PURPOSE_START = 128 MB`. Whether it
   should scale with RAM is decided later from the metrics, not now.
3. The 4 KB cursor is per CPU. A CPU marks the block it fills with a
   claim bit so other CPUs' scans prefer unclaimed blocks, which keeps
   CPUs off each other's locks in the common case. The claim is a
   preference, not exclusion: a CPU that finds no unclaimed block with
   free pages allocates from claimed ones before it splits a whole block
   or reports out of memory. Without that, idle CPUs would strand up to
   511 pages each, admission would count those pages as free, and
   `allocate_frame` would panic on a guest that has memory. Descriptors
   are exactly 16 bytes (a `const` assertion) and the array is laid out
   as 64-byte-aligned groups of four (`#[repr(C, align(64))]
   BlockLine([Block; 4])`), so a block's line-mates are the other three
   of its group by construction, not by luck of the heap's alignment; a
   CPU claims the
   lowest unclaimed block whose three line-mates are unclaimed too, and
   only when there is none the lowest unclaimed block; otherwise the
   "lowest unclaimed" rule would seat every CPU on the same line and
   bounce it between them even though the locks differ. Whether the
   line still bounces under cross-CPU frees is a measurement, listed
   below.
4. The link word in a free page is authenticated as a whole: bits 0-15
   hold the next index, bits 16-63 a tag computed by a keyed mixer (a
   64-bit multiply-xorshift finalizer, keyed with `LINK_CHECK`) over the
   tuple (block number, the page's own index, the next index).
   `LINK_CHECK` is drawn at boot (`RdRand::new()` from the `x86_64`
   crate, which checks CPUID first; the TSC when it is absent), so it is
   not a constant that a write into a free page could reproduce from the
   binary. A pop recomputes the tag from the block, the page's index, and
   the stored next index, compares, and range-checks the index (at most
   512) before installing it as head; a mismatch panics with the
   address. Because the tag covers the next index, a write that changes
   only the low bits (a self-link, a redirect to an allocated page, a
   skip) fails like any other; because it covers the page's own index, a
   valid word copied from another page of the block fails too. The tag
   is a keyed corruption cookie, not a message authentication code: the
   2^-48 acceptance figure is for accidental corruption (a stray write,
   DMA into a freed buffer, a stale mapping), and an adversary who can
   read and rewrite a free page's word can forge one. What protects the
   allocator against a forged link is the page-state bitmap of decision
   5: a link to a page whose bit is clear panics, so a forgery cannot
   select an allocated page, only strand free ones. So a write into a
   free page, the failure mode D handles and B does not, becomes a crash
   at the point of detection rather than a double allocation found
   later. One mixer and two compares per pop; one mixer per push.
5. A per-page state bitmap, one bit per 4 KB page (set = free and on
   its block's list), is production data in every build: 64 bytes per
   block, 32 KB per GB, 256 KB at 8 GB, 1.5 MB at 48 GB. A push panics
   if the bit is set (double free); a pop from the list panics if it is
   clear (the link led to a page that is not free); a pop from the
   never-used range asserts it clear. Re-combination discards the list,
   so it validates the block first (the set bits plus the never-used
   length equal 512) and then clears the block's eight words; split and
   a 2 MB allocation find them zero and assert it. A push also panics if
   the page's index lies inside the never-used range (never handed out)
   or the block's `used` is 0 or its state is not split; these are cheap
   and independent of the table.
   The state bit cannot say whether a page may ever be free: allocated,
   reserved, never-used, and non-RAM pages all have it clear, so a free
   of page 0 after stage 2 would pass every check above (the seventh
   review). The pages that can never be free live only in `PARTIAL`
   blocks, so a `PARTIAL` block carries a 512-bit allocatable mask (set
   = RAM the allocator manages, whether free, allocated, or initrd;
   clear = reserved, discarded, or not RAM) in a small boot-heap table
   of `MAX_PARTIAL` (256, the reach of the u8 index) entries of 64
   bytes, 16 KB, indexed by a byte in the descriptor; entry 0 is a
   shared all-clear mask, permanent, which the fully reserved low
   blocks use before stage 2 (thirteen of them at init, which would
   otherwise take most of a smaller table) and which is never returned
   to the pool when a block stops using it, so real entries are spent
   only on blocks with a mixed layout: the ones holding page 0 and the
   kloader page tables after stage 2, the block at the boot heap's end,
   the top of RAM, and the edges of firmware holes, a handful on every
   map seen here. The supported topology is therefore at most 255 mixed
   blocks; `phys::init` panics past it with the required and the
   supported count in the message, and the shaping self-test has a case
   at the boundary (a synthetic map with 255 mixed blocks shapes, one
   with 256 is refused). Every other block is entirely allocatable. A push
   validates, before anything else, the address alignment, the block index
   against the array, the block's split state, and on a `PARTIAL` block
   the mask bit; a pop on a `PARTIAL` block asserts the mask bit too, from
   the list (so a corrupted link cannot hand out a reserved page) and from
   the never-used range (so a shaping defect cannot). The validation of
   push and pop is factored into checkers that return a reason instead of
   panicking (`check_push`, `check_pop`); the production path panics on a
   reason with the address, and the self-test inspects it.
   Version 4 of this plan tried to do without the table by walking the
   list only when the page's first word looked free; the fifth review
   showed the gap: a write into the free page between two frees makes the
   word look allocated, the walk is skipped, and the second push succeeds.
   One bug does that, an aliased frame with two owners. The table closes
   it exactly, at one bit test per push and pop on a cache line that the
   sticky cursor keeps warm. The table is not in the boot heap: it is
   chunked by 32768 blocks (64 GB of address span per chunk), each chunk
   one run of at most 512 pages (a full chunk is exactly one whole block,
   which the run takes entire; the last chunk is sized to the remaining
   blocks), addressed as chunk[block >> 15] plus 64 bytes per block, the
   chunk pointers in the boot heap. The chunks are taken as the last step
   of `phys::init` by an internal primitive, `take_permanent_run(n) ->
   phys`: the block-level contiguous operation under the block lock,
   `used_pages` charged, no `Frame` handles returned (the public
   contiguous path returns owning handles that free the run when dropped,
   which a table must never do); the pages are never freed and count as
   allocated like any other kernel-static page. A guest so small or
   fragmented that no run can be found panics at boot with the sizes in
   the message. Each chunk is zeroed, then installed; the checks are
   enabled only after the last one, at which point every block's list is
   asserted empty, which holds because nothing has been freed yet. There
   is no separate debug table.
6. Handing free memory back to the host is assumed to be at 2 MB
   granularity or not at all (open question 3): B can report whole
   blocks.
7. Long-lived kernel pages are not forced below the line; the source
   order sends them there while it has room, and kernel-internal
   allocations use the same per-CPU cursor, so when they spill they pack
   into a few blocks. Revisit if `mem.blocks_split` grows with uptime on
   the 8 GB guest.
8. No host tests: the allocator is tested on Motor OS through systest,
   kernel metrics, and `SysMem::virt_to_phys` (2026-08-29 ruling).
9. `moto-sys` is not touched: every new observable is a kernel metric
   read through `moto_stats` (kernel-only `MetricType`), or an existing
   syscall. An edit to `moto-sys` costs a 20-minute assembly rebuild and
   is not needed.
10. Accounting has one invariant: `total_pages = free + used_pages`,
    where `total_pages` is the RAM the allocator manages and `used_pages`
    is allocated plus permanently reserved RAM. Pages that are not RAM
    are counted nowhere globally; RAM the allocator gives up at boot (the
    smaller free run of a block with a reservation in the middle) is
    reserved, so it is inside both totals and `available()` needs no
    third term. What is outside the managed total, in neither count: the
    kernel and its boot heap, as today (`init_mm_bsp` subtracts them
    from the available ranges before `phys::init`); and the fixed
    mid-page segment, whose four blocks are absent, so that
    `PhysStats::used()` keeps adding the segment separately as it does
    now and nothing counts it twice. The low 34 MB is managed from init
    and `total_pages` is constant after init, as today: its blocks are
    shaped at init as split and `PARTIAL` with every page reserved (no
    never-used range, an empty list, has-free bit clear, so no source
    can reach them), and its RAM sits in `used_pages` and
    `reserved_pages` until stage 2, which is what today's `mark_used`
    does. Stage 2 reshapes each of those blocks under its lock from the
    free run that excludes page 0 and the two kloader page tables,
    drops `PARTIAL` where the block becomes whole, and releases the
    freed pages from `used_pages` and `reserved_pages` in the
    publication order of decision 17 (the other CPUs are in their
    schedulers by then). A constant total keeps `PhysStats::total_size`
    and the low-water metric `min_free_small_pages` (`total_pages -
    used_high_water`) valid without change; a total that grew at stage
    2 would have overstated the historical minimum. The initrd, when it
    sits above the kernel, is allocated, not reserved: its pages are
    freeable through `adopt_frame`, so its blocks are split with those
    pages counted in `used`, and they re-combine if everything in them is
    ever freed.
11. A fixed-address reservation (an MMIO map) is refused for any address
    inside a block that holds RAM (the `RAM` flag, set from the firmware
    map for managed and absent blocks alike: the kernel and its boot
    heap, the fixed mid-page segment, and every managed block) and for
    any address inside a non-absent block, whatever its state; the whole
    range (its end computed with a checked add; a wrap is
    `E_INVALID_ARGUMENT`) is checked before any page is reserved or
    mapped. Addresses in blocks without RAM and beyond the array return
    Ok as today. Today's check returns Ok for the kernel's own pages,
    because it only knows the ranges it manages (a pre-existing defect,
    P0). MMIO is charged no data pages, so serving such a map from RAM
    would take memory below the floors uncharged; and no launcher maps a
    device into RAM today (the kernel's LAPIC and IOAPIC and sys-io's
    virtio BARs are all outside the memory map). `phys::init` therefore
    takes the raw available ranges of the firmware map as a third
    argument, for the flag only.
12. Admission charges a 2 MB request at the fallback shape: 512 data
    pages and 512 descriptor pages per 2 MB, whether or not the huge page
    is granted. Admission runs before the allocator knows, so it must
    charge the larger of the two outcomes; the overcharge on a granted
    huge page is 15 pages per 2 MB.
13. The block-state gauges live in one packed `AtomicU64` (whole, split,
    taken, 21 bits each): a state transition is one `fetch_add` of a
    signed delta, so any reader sees a consistent triple, and the three
    metrics are derived from one load when the metrics are collected.
    Other counters (`used_pages`, the event counters) are separate
    atomics and are eventual with respect to it; no test correlates them.
    `phys::init` asserts that the block count is strictly below 2^21,
    since the packed arithmetic is unchecked, and that the allocator's
    boot-heap footprint fits what the heap has left. The heap is
    guaranteed 2 MB and less than 4 MB (`init_mm_bsp_stage1`), and it
    also holds the bitmaps (2 bits per block), the mask table (4 KB),
    the chunk pointers, and everything allocated before memory init
    (the IDT, the APIC state, per-CPU tables; measured in debug builds
    by the "startup alloc" log), so the descriptors get at most 1 MB:
    16 bytes per 2 MB, a maximum physical address span of 128 GB,
    subject to the checked boot-heap remainder. The remainder is read
    through `kheap::startup_remaining()`, which P-1 adds (the heap has
    no such query today) and which counts the alignment padding P-1
    introduces; whether a given span fits depends on what booted before
    the allocator, so 128 GB is an upper bound, not a promise. Today's
    ceiling is already heap-bound: the unit vector costs 128 KB per GB
    of RAM, so a 2 MB heap holds a guest of roughly 12 GB, and the
    largest guest exercised is 8 GB. P1a2's shadow is built in debug
    builds only, so release builds keep exactly today's ceiling; a
    debug build of P1a2 holds both structures and asserts the same sum,
    which costs 8 KB per GB against that ceiling. Metadata
    scales with the span, not with installed RAM; a sparse map with a
    little RAM far above the rest is out of scope, and every VMM here
    places RAM contiguously apart from the hole below 4 GB. A larger
    guest needs a deliberately larger boot heap, a boot-time change
    outside this plan.
14. In a segment that asks for several 2 MB pages, the first refusal
    switches the rest of the segment to small pages: a segment is a run
    of huge pages followed by small ones, never huge, small, huge, even
    if a whole block frees up meanwhile.
15. Three pre-existing MMIO defects the reviews found are fixed in a
    separate patch before P1a1 (P0), per AGENTS.md's rule on pre-existing
    bugs and the user's ruling of 2026-09-03: teardown of an MMIO
    segment leaves its page-table entries in place (`clear` unmaps only
    pages with a `Frame`, and MMIO pages have none); a failed MMIO map
    leaks its virtual segment (`UserAddressSpace::mmio_map` reverses
    only the statistics); and the fixed-address check returns Ok for
    RAM it does not manage, so sys-io can map the kernel's pages.
    Representation for the first: an MMIO page gets a `Frame` with an
    `mmio` flag (it fits the 16-byte `Frame` beside `kind`), whose drop
    frees nothing; `clear` then unmaps it like any mapped page, the
    mid-loop rollback comes for free, and `VmemSegment` is unchanged.
    The frame is allocated before `map_page` and installed in the
    `Page` only after the mapping succeeded, so `clear` never unmaps a
    page that was not mapped and never misses one that was. A frame is
    not a licence to touch the memory through the direct map: today an
    MMIO page has no frame and `vaddr_map_status` reports it unmapped,
    which is what keeps `copy_to_user` and `get_user_page_as_kernel`
    (and through them syscall output buffers and pinned pages) off
    device memory. With a frame they would report it private or shared
    and write through the direct map with the wrong caching attributes,
    or fault where the direct map has no entry. So `vaddr_map_status`
    gains a `Mmio` status for a frame with the flag, and every consumer
    that translates to the direct map refuses it: `copy_to_user`,
    `get_user_page_as_kernel`, `read_from_user_into` (which today walks
    the page table itself and consults the status from P0 on), and
    `share_range_with`. `SysMem::virt_to_phys` keeps reporting the
    device address, as it does today; nothing depends on hiding it.
16. `share_range_with` refuses a source range inside a huge-eligible
    segment (eager, private, read-write, anonymous, larger than 1 MB)
    whether or not the huge page was granted, so the outcome does not
    depend on allocator state; the whole source range is checked before
    the destination is touched. Ruled 2026-09-03. The callers that
    share an existing range today, the vdso bytes and the vdso's
    read-only ELF segments, share regions that were created by sharing,
    never an eager allocation, so nothing in the tree changes behavior;
    a large buffer meant for sharing uses the fresh-frame shape of
    `F_SHARE_SELF` or lazy pages. The alternative, mapping a huge frame
    as 512 small entries in the target with an offset in every `Page`,
    was declined as more machinery.
17. Publication order, for every operation: `used_pages` moves before a
    bit is cleared and after a bit is set, so the capacity the counters
    show is never ahead of the bitmaps. A pop that empties a block
    increments `used_pages` before clearing the has-free bit; a push
    sets the has-free bit before decrementing; a split sets the has-free
    bit before clearing the whole bit; stage 2 publishes a block's bits
    before releasing its pages from `used_pages`. A block in transition
    never has both bits clear: re-combination sets the whole bit before
    clearing the has-free bit, split the reverse. Bitmap updates are
    `AcqRel` read-modify-writes; the counters are `Release` on the
    writer's side and `Acquire` where admission and the allocator read
    them. Out of memory is declared by a loop, not a rescan: scan the
    has-free bitmap, then the whole bitmap (both with `Acquire` loads,
    word by word from the cursor); on failure, `Acquire`-load
    `used_pages`; if it equals `total_pages`, no page was free at that
    load, and that load is the point where the out-of-memory result
    takes effect, since any page that became free set its bit before
    the decrement the load did not see; if it is smaller, a free page
    existed and its bit is visible after the load, so scan again; if
    another CPU took it meanwhile, re-read the counter and repeat. Two
    separate bitmaps can each miss a block moving between whole and
    split, which is why a failed scan proves nothing by itself and the
    counter is the arbiter. The loop ends at a successful scan or at a
    full counter; the admission floor keeps it to one or two rounds.
18. The boot heap's fallback allocator does not honor a layout's
    alignment: for anything frusa has no size class for (everything
    above 4 KB), `RawAllocator::alloc` advances its offset by the size
    alone and returns the address that results, checking only that the
    requested alignment is at most a page. Every current caller happens
    to be fine; the block array of decision 3, 64 KB at 8 GB and
    64-byte-aligned by declaration, would be the first to be handed a
    misaligned pointer, which is an allocator-contract violation. A
    pre-existing kernel bug, so a separate prerequisite patch (P-1)
    before everything else, per AGENTS.md's rule: the bump path rounds
    the absolute start up to the alignment with checked arithmetic and
    reserves padding plus size in one atomic step, every returned
    pointer is asserted aligned, the offset arithmetic is a pure helper
    with a debug boot self-test (awkward offsets, alignments 1 to 4096,
    exhaustion, overflow), and the change stays in `mm/kheap.rs`; frusa
    is untouched. The same patch adds `kheap::startup_remaining()` for
    decision 13.

### Final design

Block descriptor, exactly 16 bytes (a `const` assertion), stored in
64-byte-aligned groups of four (decision 3), one per 2 MB of physical
address space up to the top of RAM:

| field | type | meaning |
|---|---|---|
| `inner` | `SpinLock<Inner>` | a 1-byte lock plus the fields below; 13 bytes used with the mask index, padded to exactly 16 |
| `inner.head` | u16 | index plus one of the first free page on the block's list, 0 when empty, never above 512 |
| `inner.used` | u16 | pages not free: allocated, reserved, or not RAM; 512 for a taken block, 0 only for a whole block |
| `inner.unused_lo`, `inner.unused_hi` | u16, u16 | the never-used range, pages never handed out; closed (`lo == hi`) in a whole or taken block |
| `state` | AtomicU8 | absent, whole, taken, split; readable without the lock as a hint, written only under it |
| `flags` | AtomicU8 | `SMALL_ONLY` (below the line), `PARTIAL` (can never be whole), `CLAIMED` (a CPU's cursor prefers it), `RAM` (holds RAM per the firmware map; set for absent blocks too) |
| `mask` | u8 | for a `PARTIAL` block, the index of its allocatable mask (decision 5) |

The link word at offset 0 of a free page: bits 0-15 the index plus one of
the next free page of the same block, 0 at the end, never above 512; bits
16-63 the tag of decision 4, a keyed mixer over (block, own index, next
index). A word is valid for a page when the recomputed tag matches and
the index is in range; every pop checks both. `LINK_CHECK` and the mixer
live in `block.rs` as `link_encode(block, own, next) -> u64` and
`link_decode(block, own, word) -> Option<u16>`, pure functions, which
the boot self-test exercises (P1a1).

Global state in `PhysicalMemory`: the block array (from the boot heap),
the has-free bitmap (one bit per block, set when the block is split and
may have a page on its list or in its never-used range), the whole
bitmap, a per-CPU cursor (block index or none), the counters below, the
page-state table of decision 5, chunked by 32768 blocks, and the
allocatable-mask table for `PARTIAL` blocks. The
has-free and whole bitmaps are arrays of
`AtomicU64` changed with `fetch_or` and `fetch_and`: the 64 blocks that
share a word have 64 different locks, so a plain read-modify-write under
one of them would lose another's update. A block's bits change only
under that block's lock. The whole bit is exact. The has-free bit is a
hint: a pop that takes a block's last page leaves it set, and the next
pop that finds nothing clears it, so a scan that picks a block from the
bitmap re-checks under the lock, as it must anyway because the block can
change between the scan and the lock. The fixed mid-page segment and
`MMSlab<Frame>` are unchanged.

Accounting (decision 10), one invariant: `total_pages = free +
used_pages`.

- `total_pages`: the RAM pages the allocator manages, the sum over
  non-absent blocks of their RAM pages: the available ranges as
  `init_mm_bsp` passes them (the kernel and its boot heap already
  excluded), minus the fixed mid-page segment (absent). Constant after
  init (decision 10).
- `used_pages`: RAM pages allocated or reserved, in 4 KB units; a taken
  block counts 512. Allocated includes the initrd's pages when it is
  above the kernel (freeable, decision 10) and the page-state table.
  Reserved means the low 34 MB until stage 2, then page 0 and the two
  kloader page tables, and always the RAM the allocator gives up at boot
  (the smaller free run of a block with a reservation in the middle, see
  boot). Free for admission is `total_pages - used_pages`, as today, and
  `PhysStats::available()` keeps its shape with no third term; its
  `used()` keeps adding the fixed mid-page segment, which is in neither
  counter.
- `reserved_pages`: the reserved part of `used_pages`, kept as its own
  counter so the boot loss is visible (`mem.pages_reserved`); constant
  after stage 2.
- Pages inside a block's 2 MB that are not RAM (memory-map edges) are
  counted nowhere globally: they are neither managed nor used. The
  block's own `used` absorbs them so that the per-block arithmetic stays
  `free = 512 - used`.

Per-block `used` counts every page of the block that is not free:
allocated, reserved, or not RAM. Re-combination is `used == 0`, which a
`PARTIAL` block never reaches because its reserved and non-RAM pages
never come back; `PARTIAL` is set exactly when the block has any such
page, so a whole block always has 512 free RAM pages. The global
`used_pages` and the sum of per-block `used` differ by the non-RAM page
count, fixed at boot.

The invariant is checked exactly, not only through the metrics: in a
quiescent state, `total_pages - used_pages` equals the sum over
non-absent blocks of `512 - used`, since a block's `used` absorbs its
non-RAM pages and the global counter excludes them. Debug builds run
the check on the real allocator at the end of init and at the end of
stage 2, the two single-threaded moments, and the boot self-test runs
it on its scratch instance after every kind of operation: allocation
and free, split, a contiguous run and its rollback, a huge take and
return, and re-combination. The metrics never promise it under
concurrency.

Operations, each under the block's lock unless stated:

- Push (free a 4 KB page to its block, block number from the address):
  first the checks of decision 5, in every build: the address is
  page-aligned and its block index inside the array, the block's state
  is split (a free into a whole, taken, or absent block panics), on a
  `PARTIAL` block the allocatable mask bit is set (a free of page 0, a
  kloader page table, a discarded run, or a hole panics here), `used >
  0`, the index is outside the never-used range, and the page's state
  bit is clear (set means double free); any failure panics with the
  address. Then set the bit, write the link word (`link_encode` of the
  block, the page's index, and the current head) into the page; head =
  the page's index; `used -= 1`. If `used` reached 0 and the block is
  not `SMALL_ONLY` (a `PARTIAL` block cannot reach 0), re-combine: check
  that the block's set state bits plus `unused_hi - unused_lo` equal 512
  (every page is on the list or in the range; a shortfall means a
  stranded or double-counted page and panics), clear the block's eight
  state words (the list is being discarded, and every page on it had
  its bit set), head = 0, range closed, state = whole, whole bit set,
  has-free bit cleared, the packed state word moved from split to whole,
  re-combinations counted. Otherwise, if the block had no free page
  before, set its has-free bit.
- Pop (allocate a 4 KB page from a block): if head != 0, take the head
  page, check that its state bit is set and clear it (clear means the
  list led to a page that is not free), on a `PARTIAL` block that its
  mask bit is set, `link_decode` its word (the tag
  and the range are checked there; a failure panics with the address),
  head = the decoded index; else if `unused_lo < unused_hi`, take
  `unused_lo`, assert its state bit clear and, on a `PARTIAL` block,
  its mask bit set, and advance; else clear the has-free
  bit and return none. On success `used += 1`. `head` is range-checked
  when it is read, so a corrupted descriptor cannot index past the
  block.
- Split (a whole block for 4 KB use): state must still be whole under
  the lock and the block's state words zero (asserted); `unused_lo = 0`,
  `unused_hi = 512`, head = 0, state = split,
  whole bit cleared, has-free bit set, the state word moved from whole
  to split, splits counted.
- Allocate 2 MB: scan the whole bitmap from the top down to the line;
  lock the candidate; if it is still whole (its state words zero,
  asserted): state = taken, `used = 512`,
  whole bit cleared, the state word moved from whole to taken. Otherwise
  continue the scan. Nothing above the line: out of memory, and the
  caller serves that 2 MB, and the rest of its segment, as small pages
  (decision 14).
- Free 2 MB: under the lock, in every build: the address is 2 MB-aligned
  and its block is above the line, neither `SMALL_ONLY` nor `PARTIAL`,
  state exactly taken, `used == 512`, head 0, range closed; any failure
  panics with the address (a repeated or misdirected huge free would
  otherwise corrupt the state and the packed gauges). Then state =
  whole, `used = 0`, whole bit set, the state word moved from taken to
  whole; after the lock is dropped, `admission::note_pages_freed`, as
  the small-page free does today, so the pressure flag can clear on a
  huge free.
- Contiguous run of n pages, n at most 512: under the cursor block's
  lock, if `unused_hi - unused_lo >= n`, take `[unused_lo, unused_lo +
  n)`; else split the lowest whole block and take its first n. The check
  precedes the advance, so a range with fewer than n pages left keeps
  them for single-page use. A run above 512 pages is refused; the syscall
  caps contiguous requests at 64 pages and the library at 256. If the
  `Frame` descriptors for a run cannot all be built, the whole run goes
  back to its block before the error is returned, as today's rollback
  intends (its loop returns one frame too few, since the failing
  iteration consumes a slot), and `used` is exact after it.
- Fixed-address reservation (`fixed_addr_reserve`, the MMIO map path;
  decision 11): an address inside a block with the `RAM` flag or inside
  a non-absent block returns `E_ALREADY_IN_USE` whatever the block's
  state; an address in a block without RAM or beyond the array returns
  Ok as today, with today's caveat that the allocator cannot confirm it
  is a device. `VmemSegment::mmio_map` runs the check over its whole
  range (a checked add for the end) before it reserves or maps anything,
  so a refused range leaves nothing behind; the remaining failure inside
  its loop is a page-table allocation, which panics on exhaustion rather
  than returning. The teardown and the failed-map leak are P0's
  (decision 15): with an MMIO `Frame` on every MMIO page, `clear` unmaps
  the mapped pages and frees nothing, whatever point the loop reached.

Allocate 4 KB, per CPU, in order (the source order of "Common ground"
with claims as preferences):

1. The cursor's block: pop. If it yields nothing, drop the claim and the
   cursor.
2. The lowest unclaimed block in the has-free bitmap: claim it, make it
   the cursor, pop.
3. Any block in the has-free bitmap, claimed or not: pop from it without
   moving the cursor. Free 4 KB pages anywhere come before any split.
4. The lowest whole block (small-only blocks are the lowest): split it,
   claim it, make it the cursor, pop.
5. Out of memory, declared by the loop of decision 17: a failed scan
   of both bitmaps followed by an `Acquire` load of `used_pages` that
   reads the total; anything less rescans. `allocate_frame` panics on
   it as today; the admission floors keep it unreachable, and steps 3
   and 4 are what make "free for admission" and "the allocator can
   deliver" the same number.

Global counters: `total_pages` (constant after init; decision 10),
`used_pages` and `used_high_water` as today, `reserved_pages`, the
packed block-state word of decision 13, and the event counters (splits,
re-combinations, huge maps, fallbacks). All are atomics updated inside
the critical section that changes the block, in the order of decision
17. Only the packed word promises a consistent snapshot; the others are
eventual with respect to it and to each other, and nothing correlates
them.

Boot: the block array has one entry per 2 MB up to the end of the last
available range; `phys::init` asserts the span and block-count limits of
decision 13 and that the `PARTIAL` count fits the mask table. It takes
the available ranges (the kernel and its boot heap already subtracted by
`init_mm_bsp`), the in-use ranges (everything below 34 MB, the initrd
when it is above the kernel), and, new, the raw available ranges of the
firmware map for the `RAM` flag. The ranges are normalized as today:
starts rounded up and ends rounded down to a page, the initrd's range
rounded outward to pages, sorted and non-overlapping (asserted), every
end computed with checked arithmetic. Shaping, per block:

- The `RAM` flag from the raw ranges, whatever follows.
- No available RAM in the block, or the block lies in the fixed
  mid-page segment: absent. Absent blocks are in no counter.
- Below 34 MB: split and `PARTIAL` with every page reserved (an empty
  list, no never-used range, the shared all-clear mask entry 0); its
  RAM is in
  `total_pages`, `used_pages`, and `reserved_pages` (decision 10).
- Entirely free RAM: whole (small-only below the line).
- Otherwise split, with its largest free run as the never-used range.
  Its initrd pages are allocated (in `used` and `used_pages`), and the
  block is not `PARTIAL` on their account. Everything else that is not
  free, reserved RAM (a smaller free run) and non-RAM pages, is in its
  `used`, makes it `PARTIAL` with a mask that clears exactly those
  pages, and the RAM among it goes to `used_pages` and `reserved_pages`.

Stage 2 reshapes the blocks under 34 MB by the same rules from the free
run that excludes page 0 and the two kloader page tables, the fixed
mid-page segment staying absent: under each block's lock, most become
whole (`PARTIAL` dropped; they used entry 0, which is permanent, so
nothing is returned to the mask pool), the blocks holding the
three excluded pages stay `PARTIAL` with a mask, and the freed pages
leave `used_pages` and `reserved_pages` after the block's bit is set
(decision 17); `total_pages` does not move. The last steps of init take
the page-state table and enable its checks (decision 5). Cost: one pass
over the memory map per block, no per-page work, plus zeroing the table
(256 KB at 8 GB); the descriptors are 64 KB at 8 GB and 384 KB at 48 GB
from the boot heap. (Today's unit
vector would be 6 MB at 48 GB, more than the boot heap holds, so the
48 GB figures throughout this document are projections; the largest
guest exercised is 8 GB.)

Metrics, all under the kernel provider and all declared in P1a2 (the
ones
without a producer yet read 0): gauges `mem.blocks_total` (the
descriptor count, one per 2 MB of address span up to the top of RAM,
absent blocks included), `mem.blocks_whole`, `mem.blocks_split`,
`mem.blocks_taken` (the three
from one load of the packed state word in `collect_metrics`),
`mem.blocks_whole_low` (whole and small-only), `mem.pages_reserved`,
`mem.pages_free_low` (free 4 KB pages in small-only blocks, summed from
their `used` at collection time, at most 64 blocks); counters
`mem.block_splits`, `mem.block_recombined`, `mem.huge_pages_mapped`,
`mem.huge_fallbacks`. `PhysStats` gains the block counts and the
reserved count for `dump_serial`. A test that needs several of these
from one snapshot reads them from one `Collector::query`, not one query
per name as `admission.rs`'s `kernel_metric` does.

Mapping layer, for the 2 MB patches: `Page` gains a `kind`; `find_page`
uses the tree's upper bound so any address inside a 2 MB page finds its
`Page`; `clear` unmaps with the page's kind; `share_range_with` refuses
a source range inside a huge-eligible segment with `E_INVALID_ARGUMENT`,
checking the whole range before it touches the destination (decision
16). `VmemRegion::
allocate_pages` takes an alignment: 2 MB for a segment that will hold a
2 MB page, so the segment starts aligned and its 2 MB pages come first.
`huge_split(num_pages) -> (huge, small)` in `mm` implements the rounding
rule and is shared by `alloc_user_heap`, `map_charge`, and the stats
charge, so admission, the process's memory stats, and the mapping agree
on the rounded size. It saturates: `small` is `num_pages - huge * 512`
clamped at 0, since a request that rounds up has fewer pages than its
huge part covers. A 2 MB page that the allocator cannot provide is
served as 512 small pages from the same segment, counted in
`mem.huge_fallbacks`; the segment's size is the rounded size either way,
and after the first refusal the segment's remaining 2 MB candidates are
served small without asking (decision 14). `map_charge` charges every
2 MB at the fallback shape, 512 data and 512 descriptor pages
(decision 12).
Eligible: `alloc_user_heap` only (eager, private, read-write, anonymous).
Lazy, guard, shared, custom-address, contiguous, MMIO, and mid-page
requests are unchanged.

### Patch list

Every patch: kernel-only unless stated, `cargo fmt`, no new warnings,
comments at about one line in five, and before it is committed
`src/tests/full-test.sh` three times each in debug and release plus
`src/tests/full-test-dev.sh --release` once (AGENTS.md), and the manual
boot legs listed for it. Sizes are new lines including tests; removed
lines are not counted.

**P-1. The boot heap honors alignment** (decision 18). A pre-existing
kernel bug; independent of everything below; its own gate.

- `mm/kheap.rs`: `RawAllocator::alloc` computes the aligned start
  through a pure helper, `bump_offset(used, size, align) ->
  Option<(start, new_used)>`, and reserves `new_used - used` with one
  compare-exchange loop (a plain `fetch_add` cannot reserve padding
  that depends on the old value); a debug assertion that every pointer
  it returns is aligned to its layout; `startup_remaining()` reporting
  the raw area's unused bytes. About 30 lines.
- `mm/kheap.rs`, debug builds: a boot self-test of `bump_offset` over
  awkward offsets, alignments 1 to 4096, an exhausted area, and an
  overflowing size. About 30 lines.
- Tests: the existing suite; every boot exercises the path. Manual:
  boot on every launcher; the debug "startup alloc" log shows the
  padding.

**P0. Three pre-existing MMIO defects** (decision 15). Independent of
the allocator; its own gate.

- `mm/phys.rs`: an `mmio` flag in `Frame`; `deallocate_frame` frees
  nothing for it. `mm/virt_intrusive.rs`: `VmemSegment::mmio_map`
  allocates such a `Frame` before each `map_page` and installs it in
  the `Page` after the mapping succeeded, so `clear` unmaps exactly the
  mapped MMIO pages and the mid-loop rollback needs no code;
  `vaddr_map_status` returns the new `Mmio` status for a frame with the
  flag; `share_range_with` refuses it. `mm/user.rs`: `copy_to_user`,
  `get_user_page_as_kernel`, and `read_from_user_into` refuse the
  `Mmio` status (decision 15), and the virtual segment is freed when
  the inner MMIO map fails, with a debug assertion that the region
  holds no segment at that address afterwards. `fixed_addr_reserve`:
  refuses addresses inside the kernel and its boot heap and the fixed
  mid-page segment, which today's unit vector does not know (a small
  explicit range list until P1b's `RAM` flag replaces it). About 60
  lines.
- `src/tests/full-test.sh`: the `mmio-unmap-suite` invocation. About 5
  lines.
- Tests: `mmio-unmap-suite`, a systest subcommand that `full-test.sh`
  runs as a separate invocation with `MOTOR_OS_CAPS=0x4e` (the gate's
  0x4c plus `CAP_IO_MANAGER`, the way the stdio suite already runs at
  0x6c), since MMIO maps need that capability. A child process maps one
  page at a physical address beyond the end of RAM (no RAM there, so the
  map succeeds, as today), unmaps it, and reads the address; the parent
  asserts the child did not exit normally (killed by the page fault).
  With today's stale entry the read returns the VMM's default for an
  unassigned address and the child exits normally, which is the defect.
  A second case maps a page of the kernel (its physical start, 34 MB)
  and asserts the map fails; a third maps a page inside RAM and asserts
  the same, and in debug builds the freed-segment assertion above runs
  on both. A fourth maps a page beyond RAM and uses it as a syscall
  output buffer (a read into it) and as an input buffer (a write from
  it); both must fail with the error an unmapped buffer gets today,
  never reach device memory through the direct map. The LAPIC and
  IOAPIC maps at boot and sys-io's virtio BARs exercise the outside-RAM
  path on every boot.

**P1a1. The block allocator's core, with its self-test.** No production
allocation behavior change: the boot path calls only its debug
self-test, at the end of `phys::init`. The plan requests the
size exception for this patch: the core is one data structure with one
set of invariants, and the self-test that proves them belongs with it.

- `mm/block.rs`, new: the descriptor and its lock (with the exact-size
  assertion and the 64-byte-aligned groups of decision 3),
  `link_encode` and `link_decode` with the per-boot `LINK_CHECK`, the
  chunked page-state table with `chunk_of(block) -> (chunk, offset)`
  and `take_permanent_run`, the allocatable-mask table with its shared
  entry, `check_push` and `check_pop` and the push and pop built on
  them (decisions 4 and 5), the never-used range, split, the 2 MB take
  and return, contiguous runs, the packed state word, the counters of
  decision 10 in the order of decision 17, and the invariant check.
  About 330 lines. Until P1b the module carries a module-level
  `#![allow(dead_code)]` with a comment naming P1b, since release
  builds reach none of it; the allowance goes with the switch.
- `mm/block.rs`, debug builds: a boot self-test, run at the end of
  `phys::init`, over pure functions and a scratch instance of the
  allocator (a handful of descriptors over a fake address range, with
  their own state words and one `PARTIAL` mask; nothing in it touches a
  real page except the push and pop cases, which use one real scratch
  page): the link codec round-trips; flipping each of the 64 bits of an
  encoded word, copying a word to another index of the same block, a
  self-link, and an index above 512 all fail to decode; `check_push`
  and `check_pop` return the reason for a double free, a free into the
  never-used range, a free into a non-split block, a pop of a page whose
  state bit is clear, and, on the `PARTIAL` block, frees of page 0, of
  the two kloader page tables, of a discarded run, and of a hole, and a
  never-used pop that reaches a masked page; contiguous runs of 1, 2,
  64, 65, 256, and 512 pages, the split fallback when the range is
  short, and a run returned whole when its caller fails; the invariant
  of decision 10 after each of those and after a 2 MB take and return;
  and `chunk_of` at blocks 0, 32767, 32768, and the last block of a
  partial final chunk, against a fake block count above 32768. P2 adds
  the re-combination transition (a scratch block whose pages are partly
  on the list and partly in the range: validates, clears the words,
  closes both, keeps the invariant; and its refusal when a page is in
  neither), P3 the cases for its `aligned_start` helper. About 130
  lines. Churn is not relied on to reach these; this is.

**P1a2. Shaping and the shadow.** No release behavior change: the
shadow is built in debug builds only, the unit vector keeps serving
every allocation in both, and the block array is built, shaped, and
validated against it. In P1b the block array becomes the allocator;
what goes is the unit vector and the oracle.

- `mm/block.rs`: the has-free and whole bitmaps, the per-CPU cursor and
  claim with the four-step source order and the line-spacing rule, the
  shaping of a block from free ranges with the `RAM` flag, and the
  reshaping at stage 2; the self-test gains the shaping cases (a range
  with a hole, an initrd in the middle, a range end inside a block, a
  low block before and after stage 2). About 150 lines.
- `mm/phys.rs`, debug builds only (`cfg(debug_assertions)` around the
  shadow): `init` builds the block array beside the unit vector from
  the same inputs plus the raw ranges, and `mark_unused` reshapes the
  low blocks beside the unit vector's release. The oracle: immediately
  after construction, before any allocation,
  the unit vector's free count equals the shadow's `total_pages -
  used_pages` plus the shadow's discarded pages (the smaller free runs
  of `PARTIAL` blocks, counted separately for this; the unit vector
  keeps every page-aligned RAM page outside the mid range, including
  units shorter than 64 pages, so nothing is added on its side); and
  across stage 2, the unit vector's free delta equals the shadow's free
  delta plus its discarded delta. No comparison later: real allocations
  happen between init and stage 2 (`virt::init`, the per-CPU GS pages,
  the kernel stack) and after it, and the shadow does not see them. The
  real page-state table is not taken here: the unit vector owns every
  free page, so the shadow takes none; `take_permanent_run` runs only
  on the self-test's scratch instance, and P1b takes the table at init.
  The invariant check of decision 10 runs on the shadow at both points.
  `PhysStats` gains the block and reserved counts. About 90 lines.
- `xray/stats.rs`: all eleven metrics above, the block-state three from
  one load, reading the shadow in debug builds and 0 in release. About
  50 lines.
- Tests: the existing suite, unchanged; the shadow oracle is the test.
  Manual: boot debug builds on every launcher listed under P1b, so a
  shaping mismatch is found here and not there.

**P1b. The switch.** Larger than the 300-line guideline; the plan asks
for the exception here as for P1a1: the unit vector and the block
array cannot serve allocations side by side, and contiguous runs must
work in the same patch because sys-io allocates its virtqueues at
boot.

- `mm/block.rs`: the `#![allow(dead_code)]` of P1a1 goes; the real
  page-state table is taken at init and its checks enabled (decision
  5). `mm/phys.rs`: `DesignatedSegment`, `MemoryArea`, the random
  tries, the one-slot cache, the linear walks, and the shadow oracle go;
  `PhysicalMemory` holds the block array and the mid-page segment;
  `allocate_frameless`, `deallocate_frame`, `allocate_contiguous_frames`
  (the assertion at 64, the `todo!`, and the off-by-one go; a run whose
  descriptors cannot all be built goes back whole), `fixed_addr_reserve`
  on the `RAM` flag and the block state (P0's range list goes),
  `dump_serial` on blocks. About 150 lines net.
- `arch/x64/irq.rs`, `arch/x64/syscall.rs`: the per-CPU IRQ depth
  counter, incremented at the top of `irq_handler_inner`, decremented on
  its return, zeroed in `preempt_current_thread_irq` before the switch;
  `block.rs` asserts it zero in debug builds when it takes a block lock,
  once `cpu_initialized` holds (decision 1). About 10 lines.
- `docs/plans/boot-time.md`: items 5 and 7 marked done with the
  measured `phys::init` stamps.
- Tests, new `src/sys/tests/systest/src/mem_blocks.rs`, registered in
  `main.rs` and so in `full-test.sh`'s systest leg. Every allocation in
  these tests that must be 4 KB-backed is made in pieces of exactly
  1 MB, which the rounding rule of P5 never serves with a huge page, so
  the tests keep testing what they test after P4 and P5:
  - `test_sequential_placement`: allocate 8 MB as eight 1 MB pieces,
    touch every page, read each page's physical address with
    `SysMem::virt_to_phys`, count distinct 2 MB blocks. Assert at most
    4 + the number of CPUs: four blocks hold 8 MB, and the thread can
    migrate across every CPU's cursor block. Today's allocator scatters
    2048 pages over hundreds of blocks, so the bound fails on it.
  - `test_reuse_before_split`: read `mem.block_splits`, allocate and
    touch 64 MB as 64 pieces, read again (first delta, about 32), free,
    allocate and touch 64 MB again, read again (second delta). Assert
    the second delta is below a quarter of the first: the second pass
    is served from the lists. Other processes can split a block or two
    meanwhile; a quarter of 32 leaves room for that without hiding a
    regression to the old behavior, where the second pass splits as
    many as the first.
  - `test_block_state_partition` (the page-accounting invariant itself
    is checked inside the kernel, decision 10): from one metrics query,
    `mem.blocks_whole + mem.blocks_split + mem.blocks_taken` plus the
    absent count (`mem.blocks_total` minus the three, read once at start)
    equals `mem.blocks_total`, exactly, before and after the tests above
    and, from P2 on, sampled while `test_block_churn` runs; the packed
    state word is what makes the exact sum hold under load. And
    `mem.pages_reserved` never changes after boot (stage 2 runs before
    any process exists).
  - Contiguous runs are not writable from systest (contiguous maps need
    `CAP_IO_MANAGER`); the coverage is the self-test's run cases,
    sys-io's virtqueues on every boot, and the existing debug-build
    contiguity assertion in `VmemRegion::allocate_contiguous_pages`.
  - Existing coverage that exercises the new code on every run:
    `admission.rs` (floors, the all-CPU fault storm, charge boundaries),
    `pressure.rs` (`test_large_allocs`, `test_frame_churn`, the pressure
    episode), `test_oom`, the lazy-map tests, and every other test that
    allocates memory. The all-CPU fault storm is the test that would
    have caught the claimed-block false OOM; it stays as is. The
    admission tests that read `PhysSmallPagesLowWater` keep their
    meaning because the total is constant (decision 10).
- Manual legs, recorded in the commit message: boot to the console on
  cloud-hypervisor, Firecracker at 64 MiB and at 1 GiB, QEMU `-kernel`,
  and QEMU through the BIOS; `run-dev.sh` at 8 GB with a `PhysStats`
  dump, including the reserved count; `phys::init` stamped at 1 GB and
  8 GB with the boot-time.md method, expected under 0.1 ms against 0.5
  and 3.0 ms today. Boot time must not go up anywhere.

**P2. Re-combination.**

- `mm/block.rs`: the re-combination arm of push, described above. About
  40 lines.
- The page-state table is P1a1 (it is production data); this patch adds
  the re-combination transition over it: the validation that set bits
  plus the never-used length equal 512, and the clearing of the eight
  words before the block is published whole, plus the self-test case
  for both. The split-side and huge-allocation zero assertions are P1a1.
  About 25 lines.
- Tests in `mem_blocks.rs`:
  - `test_recombination`: first fill the low region, since small-only
    blocks never re-combine: allocate 1 MB at a time (never huge-backed,
    so the filler stays in low 4 KB pages after P4 and P5), touching
    it, while `mem.pages_free_low` is above 512, and hold the
    filler (at most 128 MB). `mem.blocks_whole_low` reaching 0 would not
    do: it says the low blocks are split, not that their lists are
    empty. Then read `mem.block_recombined`, allocate and touch a 64 MB
    probe as 64 pieces of 1 MB, which now splits dual-purpose blocks (a
    huge-backed probe would take whole blocks and return them whole,
    which is not re-combination), free the probe, read
    again. Assert at least 32 minus twice the number of CPUs minus 2,
    saturating at 0 (a guest with more than 15 CPUs asserts nothing
    here and says so), re-combined: the probe fills about 32 blocks,
    its first and last
    block on each CPU's cursor can hold another owner's pages, and up to
    512 of its pages may have come from low leftovers, which is at most
    one block's worth. Free the filler. Also assert `mem.blocks_whole`
    after the probe's free is at least its value before the probe minus
    the number of CPUs minus 2.
  - `test_block_churn`: four threads, each 512 iterations of allocate a
    random 1 to 256 pages (at most 1 MB, never huge-backed, until P6
    widens it), touch, free oldest-first past four held,
    so blocks split, drain, re-combine, and split again under
    concurrent pops and pushes. The oracle is the kernel: the link
    authentication, the page-state table, the never-used-range and
    `used` checks (a pop never sees a block with `used == 512`), and
    `test_block_state_partition`'s sum, sampled during the churn and at
    the end.
- Manual: `stress-soak.sh` for one hour on the release build, watching
  `mem.blocks_whole` not trend down over the soak, which is what "best
  effort keeps up" means.

**P3. `Page` with a size, aligned virtual allocation.** No behavior
change; the existing suite is the test.

- `mm/virt_intrusive.rs`: `kind` in `Page` (fits the 72 bytes),
  `contains` by kind, `find_page` and `find_page_mut` by upper bound,
  `clear` and `vaddr_map_status` by kind. About 80 lines. The sharing
  refusal of decision 16 is P4's, with its test: it is a behavior
  change, and nothing is huge-backed before P4.
- `mm/virt.rs`: an `align` parameter on `VmemRegion::allocate_pages`;
  both the append-at-end and the gap-search branch place through one
  pure helper, `aligned_start(gap_start, gap_end, size, align) ->
  Option<u64>`, so the arithmetic exists once. Callers pass 4 KB. About
  40 lines.
- Test: `test_invalid_memory_map_options` and the lazy-map tests cover
  the find-by-upper-bound change on 4 KB pages; the suite passes
  unchanged. A debug assertion that every `Page` in a segment has the
  segment's expected kind, and one that the start `allocate_pages`
  returns has the requested alignment. The aligned append branch is
  tested in P4 (`test_huge_page_exact` with an unaligned region end);
  the gap-search branch runs only when the region's end has no room,
  which no test can force, so its arithmetic is covered through
  `aligned_start` in the boot self-test: gaps that fit exactly, fit
  with slack on either side, and do not fit once aligned.

**P4. 2 MB frames from whole blocks, first consumer: whole-2 MB requests.**

- `mm/block.rs`, `mm/phys.rs`: the taken state, `allocate_huge_frame`
  (top-down scan above the line, Frame of kind `MidPage`),
  `deallocate_frame` for `MidPage` by address (a block, never the fixed
  segment) with `note_pages_freed` after the lock; `mem.blocks_taken`,
  `mem.huge_pages_mapped`, and `mem.huge_fallbacks` start counting.
  About 100 lines.
- `mm/mod.rs`: `huge_split(num_pages)`. This patch uses it only for
  requests that are exact multiples of 2 MB; the general rule is P5.
- `mm/virt_intrusive.rs`, `mm/virt.rs`, `mm/user.rs`: a segment of n
  whole 2 MB pages: aligned virtual range, one `Page` and one 2 MB
  mapping per page, fallback to 512 small pages per 2 MB when the
  allocator refuses, and small pages for the rest of the segment after
  the first refusal (decision 14), unmap by kind, memory stats in 4 KB
  units; `share_range_with` refuses a huge-eligible source range,
  checked whole before the destination is touched (decision 16).
  `uspace/sys_mem.rs`: `map_charge` charges 512 data pages and 512
  descriptor pages per 2 MB for the ordinary path (decision 12). About
  130 lines.
- Tests in `mem_blocks.rs`:
  - `test_huge_page_exact`: map one 4 KB page first, so the region's
    end is not 2 MB-aligned, then allocate 2 MB with 4 KB page size;
    assert the returned size is 2 MB, the virtual and the physical
    address of the start are 2 MB-aligned, page k's physical address is
    start plus k times 4 KB for all 512, `mem.huge_pages_mapped` rose by
    one, `mem.blocks_whole` fell by one; free; assert `mem.blocks_whole`
    is back. Repeat with 6 MB: three 2 MB pieces, each 2 MB-aligned and
    physically contiguous within itself; they need not be adjacent to
    each other.
  - `test_huge_fallback`: allocate 2 MB at a time, touching the first
    and last page of each, until `mem.huge_fallbacks` rises, then free
    everything and assert that `mem.blocks_whole - mem.blocks_whole_low`
    (the dual-purpose whole count, from one query, as a saturating
    subtraction: the two gauges come from different sources, the packed
    word and a scan of the low blocks, so a low block mid-transition can
    put the difference off by one, which the tolerance absorbs) is at
    least its starting value minus the number of CPUs: taken blocks
    return to
    whole directly and the fallback pages go to lists and re-combine
    (P2), except that on each CPU the fallback's first pages may share a
    cursor block with another owner; pages that landed in a small-only
    block, which never re-combines, are excluded by subtracting the low
    count. A refusal with `E_OUT_OF_MEMORY` before the fallback is
    observed fails the test with the metrics printed; on the 1 GB test
    guest the whole pool empties with tens of MB still free, so that is
    a finding, not noise. The test holds the whole dual-purpose region
    for its duration, so it does not run in the under-load soak.
  - `test_large_allocs` gains a touch of the first and last page of
    every returned segment, so its 1 GB requests exercise the fallback
    path whenever whole blocks run out before admission refuses.
  - `test_share_huge_refused`: spawn a child and share into it a 2 MB
    eager allocation by its address (`F_SHARE_SELF` with the source
    set); assert `E_INVALID_ARGUMENT` whether or not
    `mem.huge_pages_mapped` rose for it, and that nothing was mapped in
    the child (a query at the target address fails). Share a 1 MB eager
    allocation the same way and assert success (decision 16).
  - The pressure episode in `pressure.rs` is run once more with a
    segment above 1 MB, so a huge free is what clears the flag.
  - `admission.rs`'s `test_charge_boundaries` is re-read against the new
    charge for sizes at multiples of 2 MB; if its sizes cross the new
    behavior its expectations are updated in this patch, as a behavior
    change, not as a test fix.
- Manual: Firecracker at 64 MiB: a 2 MB request returns 2 MB of small
  pages (`mem.huge_fallbacks` rises, `mem.huge_pages_mapped` stays 0);
  the vdso's frusa chunks exercise this on every process start.

**P5. The rounding rule for all sizes.**

- `mm/mod.rs`: `huge_split` becomes the full rule, `(S + 1 MB - 4 KB)
  >> 21` huge pages and the rest small, saturating at 0 when the request
  rounds up, with the constant `HUGE_ROUND_UP_MIN = 1 MB` in one place.
- `mm/virt_intrusive.rs`, `mm/user.rs`: mixed segments, 2 MB pages first
  at the aligned start, then the small tail; the returned size is the
  rounded size. About 80 lines.
- `uspace/sys_mem.rs`: `map_charge` through `huge_split`.
- Tests in `mem_blocks.rs`, `test_rounding_rule`, one table: 64 KB and
  1 MB exactly return their own size with no huge page; 1 MB + 4 KB
  returns 2 MB with one huge page; 1.5 MB returns 2 MB; 3 MB returns
  3 MB with one huge page and 256 small; 3 MB + 4 KB returns 4 MB with
  two; 5.5 MB returns 6 MB with three. For each: physical contiguity and
  alignment of the huge part, the small tail mapped and touchable,
  `mem.huge_pages_mapped` delta, `MemoryStats::used_pages` delta equal to
  the rounded size in pages, and the process's own `MemoryUsage` metric
  charged the rounded size. The test uses `SysMem::map2`, which returns
  the address and the size; `SysMem::map` and `SysMem::alloc` return
  only the address.
- The existing admission tests that map sizes across the 1 MB line are
  re-read as in P4.

**P6. Churn with mixed sizes, documentation.**

- `mem_blocks.rs`: `test_block_churn` widens its range from 1 to 256
  pages to 1 to 1024, so sizes above 1 MB: 2 MB allocations, splits,
  fallbacks, and re-combinations race on the same blocks; the same
  kernel oracles. About 40 lines.
- `docs/oom-handling.md`: the charge for 2 MB pages and the new metrics
  in the regression-coverage section. This document: the "Today"
  section becomes the "before" record and the design section is
  trimmed to what landed, with commit ids.

Order and dependencies: P-1, then P0, each on its own; P1a1, P1a2,
then P1b; P2
and P3 each need only P1b; P4 needs P1b, P2 (its fallback test relies on
re-combination), and P3; P5 needs P4; P6 needs P5. Nothing in the list
touches `src/sys/lib`, the vdso, or anything outside the kernel,
systest, and `full-test.sh`.

### Test discipline

- Every bound in the tests above is derived, not tuned: the number of
  CPUs enters where cursors are per CPU, and the constants 4, 32, and
  a quarter come from the sizes the tests allocate. A failing bound is a
  finding, not a reason to widen it (AGENTS.md, note 1).
- Every allocation that must be 4 KB-backed is made in pieces of
  exactly 1 MB, the boundary of the rounding rule, so the placement,
  reuse, re-combination, and churn tests test 4 KB behavior after P4
  and P5 too; a test that wants huge pages asks for more than 1 MB.
- The tests do not depend on ordering within systest except that
  `test_sequential_placement` runs before tests that leave many pages on
  the lists, so that its allocation is served mostly from never-used
  ranges; its bound holds either way.
- `test_recombination` and `test_huge_fallback` hold most of the
  guest's memory while they run; they run in the plain systest pass,
  not in the under-load soak, and they free everything they hold on
  every exit path.
- Under `--under-load` the placement bound keeps its derivation; if load
  makes it flaky, the fix is in the derivation (another CPU's process
  sharing a cursor block), reported as such.
- Metrics that must agree with each other (the block-state sum, the
  dual-purpose whole count) come from one `Collector::query`. The
  block-state sum is exact, from one packed word; the dual-purpose whole
  count is not, from two sources, and keeps its tolerance.
- The link authentication and the page-state table turn allocator
  corruption into an immediate panic in every build; the boot self-test
  proves the checkers reject what they must, and a full test run in
  debug is the run that exercises it.

### Measurements

- `phys::init` at 1 GB and 8 GB, before and after P1b, by the
  boot-time.md stamp method: the item-5 claim.
- The kernel phase on QEMU with hugepage backing, before and after P1b:
  the item-7 claim (about 55 ms today).
- Benchmarks are user-owned (2026-08-15 ruling): the plan does not run
  them. The allocator's per-operation cost is expected to fall at every
  fill level; if the user's regular runs show otherwise after P1b, the
  suspects are the block lock under cross-CPU frees into a cursor block
  and the has-free scan, and the answer is measured before it is changed.
- `mem.blocks_whole` over a full test run and over an hour of
  `stress-soak.sh` after P2: the "best effort keeps up" measure.
- The descriptor cache line under the claim-spacing rule of decision 3:
  whether adjacent-block locks still bounce between CPUs under
  cross-CPU frees. Measured under the same discipline as the item above
  it, only if the user's runs point at the allocator, and before
  anything is changed for it.

### Risks

- P1a1 and P1b are the large patches. P1a1's self-test and P1a2's
  shadow oracle are what make P1b reviewable: the core's invariants and
  the shaping are proven on every launcher before the switch, so P1b's
  review is the wiring and the removal. The shadow oracle is throwaway
  code, about 30 lines.
- Boot-time reservations that are not block-aligned lose the smaller
  free run of their block: up to 1 MB per `PARTIAL` block and a few such
  blocks per boot, so a few MB at most, visible in `mem.pages_reserved`
  and in `dump_serial`.
- The MMIO fixed-address path refuses addresses inside any block that
  holds RAM or is managed; if a launcher ever maps a device into RAM
  addresses, the map fails with `E_ALREADY_IN_USE` before anything is
  mapped and is diagnosed rather than silently served uncharged.
- The page-state table adds one cache line per push and pop beyond the
  descriptor; the sticky cursor keeps a block's line warm for
  allocations, and a cross-CPU free into a cold block pays the miss. It
  is the price of exact double-free detection, and the measurements
  above would show it.
- The per-block lock is not interrupt-safe; the IRQ depth assertion is
  the guard, and it is debug-only. A release-only allocation from an
  interrupt handler would deadlock that CPU and end in the spin lock's
  "deadlock?" panic, which names the lock.
- Rounding changes what the admission tests see for sizes above 1 MB;
  P4 and P5 carry those updates explicitly.
- `SysMem::virt_to_phys` being unprivileged is what the placement tests
  use; if it is ever restricted, the tests move behind
  `CAP_IO_MANAGER` or to a kernel metric.
- The block lock is taken on every free from whatever CPU frees; a
  workload where one CPU allocates and another frees the same block's
  pages serializes on it. That is the contention the per-CPU cursor
  does not remove, and it is what the measurements above watch.

### Second review, folded in

The first version of this plan was reviewed by another model on the
same day. Its findings and what changed: the lock-free re-combination
could publish a whole block with a page popped but not yet counted, and
its give-up path lost the detached list (the per-block lock replaces the
protocols); persistent cursor claims could strand free pages and reach
the allocator panic (claims are preferences, steps 3 and 4 of the source
order); the n-page fetch-add could overshoot the never-used range and
strand its tail (check before advance, under the lock); counting edge
pages as used distorted `mem.used` (the three-way accounting, itself
replaced by decision 10 in v4);
the debug bitmap did not fit the boot heap (allocated from the block
allocator at the end of init); `test_recombination` would have measured
small-only blocks that never re-combine (it fills the low region first);
the 1 GB-request fallback test was not deterministic (2 MB requests until
the counter rises); `mem.blocks_taken` was used before it was declared
(all metrics declared in P1); the dev-image run was missing from the
per-patch discipline; and "the process sees the real size" was too broad
(`SysMem::alloc` discards it).

### Fourth review, folded in

The third version of this plan was reviewed by another model on
2026-09-03. Its findings and what changed: release builds had no
double-free detection and the link check did not range-check the index
(decisions 4 and 5 as they stood in v4: per-boot `LINK_CHECK`, range
checks on head and link, release double-free detection through the
never-used range, `used`, the state, and an "already free" test; the
fifth review found that version short, see below); the accounting
definitions could not all hold at once and
mixed non-RAM holes with discarded RAM (decision 10: one invariant,
non-RAM pages counted nowhere, the kernel and boot heap kept outside the
managed total as today); fixed-address reservations inside RAM were
uncharged and contradicted the constant-after-boot test (decision 11:
refused, with a whole-range check first, and the virtual-segment leak in
`UserAddressSpace::mmio_map` fixed); the fallback's descriptor charge
was unspecified (decision 12); bitmap words shared by blocks under
different locks need atomic read-modify-write (stated); the has-free bit
was called exact (a hint); the gauges could be read torn (decision 13,
and one query per snapshot in the tests); the lock is an `AtomicBool`,
not a 4-byte word (12-byte descriptor, size assertion); the lock does
not mask interrupts (the rule and the `in_irq` assertion in decision 1);
a mixed segment could come out huge, small, huge (decision 14);
`huge_split` needed a saturating tail (stated); `SysMem::map` returns
only the address (`map2` in P5); `test_huge_fallback` could not demand
the whole count back to baseline (the dual-purpose count with the
per-CPU bound); `mem.blocks_whole_low == 0` did not mean the low lists
were empty (`mem.pages_free_low`); the 6 MB test implied mutual
adjacency (per-piece contiguity); and P3's aligned allocation had no
test (the alignment assertion on both branches, and the exact test with
an unaligned region end for the append branch; the gap branch runs only
when the region's end is exhausted, which no test can force).

Declined, with reasons: switching to alternative C, a user ruling; the
reason v4 gave, that the release checks made a per-page bitmap
unnecessary, was wrong (fifth review), and the ruling stands on the list
being what was asked for and on the detection of writes into free pages;
and a fault-injection harness for mid-operation rollback, because
`allocate_frame` panics on exhaustion and descriptors and page tables
come from the same allocator, so the only reachable mid-operation
failure is the huge refusal, which is the fallback path and is tested.

### Fifth review, folded in

The fourth version was reviewed by the same model on 2026-09-03. Its
findings and what changed: the link tag authenticated only the block
number, so a write that changed the index alone (a self-link, a redirect
to an allocated page, a skip) passed (decision 4: the tag is a keyed
mixer over block, own index, and next index); the release double-free
check was not exact, because a write into the free page between two
frees makes the conditional walk skip (decision 5: the page-state bitmap
is production data in every build, and v4's claim is withdrawn); the
fixed mid-page segment would have been counted in `used_pages` and again
by `PhysStats::used()` (decision 10: its blocks are absent, and the
reservation classes are spelled out: the initrd allocated, the low 34 MB
absent until stage 2); a huge free had no preconditions (stated,
unconditional); the table was capped at 64 GB again and "every block is
whole then" was false (chunked by 32768 blocks through the contiguous
path; a 4 TiB span assertion for the packed state word); the MMIO rule
said "managed RAM" in one place and "managed block" in another (one
rule: any non-absent block, with a checked range end); MMIO segment
teardown leaves page-table entries because `clear` unmaps only pages
with a frame (fixed in P1, moved to P0 in v7); P4 depends on P2
(stated); corruption
detection had no deterministic coverage (the debug boot self-test over
the codec and the checkers); the gap-alignment branch was uncovered
(`aligned_start`, tested in the self-test from P3); and the contiguous
path's descriptor-failure rollback was unnamed (named, and its
off-by-one goes).

### Sixth review, folded in

The fifth version was reviewed by the same model on 2026-09-03. Its
findings and what changed: re-combination asserted the block's state
words zero when every page on the list has its bit set (decision 5 and
the push operation: validate that set bits plus the never-used length
equal 512, then clear the words; split and huge allocation assert zero;
the transition is a self-test case in P2); MMIO teardown had nothing to
unmap from, since MMIO segments carry empty options and `mmio_map`
stores nothing (v6: `mmio_phys` in `VmemSegment`; v7 replaces it with
an MMIO `Frame` flag in P0, decision 15; the `mmio-unmap-suite` at caps
0x4e proves the entry goes); stage 2 grows `total_pages` while the
other CPUs run (v6: an atomic total and a derived `PhysStats`; v7
keeps the total constant instead, decision 10, and states the
publication order in decision 17); the table's
chunks were taken through a path that returns owning handles
(`take_permanent_run`, a boot panic when no run exists, checks enabled
after the last chunk with every list asserted empty); the mixer is not
a MAC (named a keyed corruption cookie, threat model stated, the bitmap
named as what stops a forged link); `rdrand` needs a CPUID gate
(`RdRand::new`); `mem.blocks_total` was undefined (the descriptor count,
absent blocks included); the re-combination bound could underflow
(saturating); the dual-purpose whole count is not atomic (saturating,
with its tolerance); and the chunk index was exercised only in chunk 0
(self-test cases at 32767, 32768, and a partial final chunk).

### Seventh review, folded in

The sixth version was reviewed by the same model on 2026-09-03. Its
findings and what changed: a free of a reserved or non-RAM page (page 0
after stage 2, a kloader page table, a discarded run, a hole) passed
every push check, since all of them have a clear state bit (decision 5:
an allocatable mask per `PARTIAL` block, and pushes validate alignment,
bounds, state, and the mask first; negative self-test cases); absent
blocks included the kernel's RAM, so the MMIO rule let sys-io map it,
which today's check also allows (decision 11: a `RAM` flag from the
firmware map, `phys::init` takes the raw ranges; P0 for today's
defect); the placement, reuse, and re-combination tests would have been
huge-backed after P4 and P5, and the churn's range contradicted P6
(every 4 KB-backed allocation in pieces of exactly 1 MB; churn 1 to 256
pages until P6); a growing `total_pages` broke the low-water metric
(decision 10: the low 34 MB is managed from init as reserved and
released at stage 2, so the total is constant, as today; the atomic and
the derived `PhysStats` are gone); the publication protocol was
unstated (decision 17); a huge-backed source made sharing
nondeterministic (decision 16, a user ruling: deterministic refusal of
huge-eligible sources, checked whole, with a test); P1 was too large and
folded pre-existing bugs (decision 15: P0 for the three MMIO defects, a
user ruling per AGENTS.md; P1a, split in v8 into P1a1 and P1a2, builds
and validates beside the unit vector, P1b switches); metadata scaled
with the address span without a stated limit (decision 13: 256 GB in
v7, 128 GB from v8 against the boot heap, strictly below 2^21 blocks,
asserted); shaping did not state normalization (stated); a boolean IRQ
flag broke under an NMI inside an IRQ (a depth counter); four
descriptors share a cache line (the claim-spacing rule of decision 3,
and a measurement); contiguous runs had no deterministic coverage and
the "Today" text missed the assertion at 64 (self-test cases at 1, 2,
64, 65, 256, 512, the split fallback, and the rollback; the text
corrected); a huge free did not notify the pressure code (it does,
after the lock, with a test); the MMIO representation touched
`VmemSegment`'s size (the MMIO `Frame` flag instead, decision 15,
amended in v8 with the `Mmio` map status); and
the common-ground source order and the boot-loss figures disagreed with
the plan (both reconciled).

### Eighth review, folded in

The seventh version was reviewed by the same model on 2026-09-03. Its
findings and what changed: an MMIO page with a `Frame` would have been
reported private or shared by `vaddr_map_status`, so `copy_to_user`,
`get_user_page_as_kernel`, and the input path would have gone through
the direct map into device memory (decision 15: a `Mmio` status that
every direct-map consumer refuses, the frame installed only after the
mapping succeeds, and suite cases for output and input buffers and for
the freed segment); the P1a shadow compared absolute free counts after
real allocations and assumed the unit vector drops short tails, which
it does not (P1a2: one absolute comparison right after construction
and a delta across stage 2, with only the shadow's discarded runs added
back); the out-of-memory rescan was not a linearization argument and
two bitmaps can miss a block in transition (decision 17: the counter is
the arbiter, the loop is written out); `MAX_PARTIAL` of 16 was consumed
by the low blocks at init (a shared all-clear entry, a table of 64);
the claim-spacing rule assumed a layout the plan did not require (exact
16-byte descriptors in 64-byte-aligned groups, asserted); 256 GB of
span left nothing of the boot heap (128 GB, asserted against the heap's
remainder, with the P1a2 bound); the primary accounting invariant was
not tested (an exact quiescent check at init, at stage 2, and on the
scratch instance after every operation kind); P3 carried a behavior
change under a no-behavior-change label (the sharing refusal and its
test moved to P4); a never-used pop skipped the mask (asserted); P1a
was over the guideline without saying so (split into P1a1 and P1a2,
the exception requested for P1a1 and P1b, and a dead-code allowance
named); and the negative self-tests could not reach panicking paths
(`check_push` and `check_pop` return a reason).

### Ninth review, folded in

The eighth version was reviewed by the same model on 2026-09-03. Its
findings and what changed: the boot heap's fallback allocator ignores
a layout's alignment, so the 64-byte-aligned block array would have
been handed a misaligned pointer (decision 18: P-1, a prerequisite
patch that aligns the bump path, asserts every returned pointer, and
self-tests the offset arithmetic); the plan's boot-heap remainder
check had no API behind it (`kheap::startup_remaining()` in P-1, and
128 GB restated as a maximum subject to that remainder); P1a2 held both
representations and so lowered an untested ceiling under a
no-behavior-change label (the shadow is debug-only; today's ceiling
and the tested one are stated); the shared mask entry could read as
returnable (permanent, stated) and the IRQ-depth assertion would have
read per-CPU state before it exists (gated on `cpu_initialized`);
`MAX_PARTIAL` of 64 was still a guess (256, the u8's reach, 255 mixed
blocks as the stated limit, the panic naming both counts, a boundary
self-test); and three wordings were wrong (the block array is not
thrown away in P1b, P1a1's self-test does run at boot, and
`test_accounting_invariant` is now `test_block_state_partition`).
