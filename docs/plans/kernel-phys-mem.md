# Kernel physical memory allocation

2026-09-04 (v11). Implementation specification; no code is implemented by
this document. This revision simplifies metadata, bootstrapping, diagnostics,
and claims while preserving ownership checks and deterministic validation.
Earlier alternatives and review transcripts are retained in Git history.

The selected design is one free-page list per 2 MiB block, links in freed
pages, and a lock per block (alternative B in earlier revisions). Follow
the prerequisite fixes, implementation sequence, and acceptance gates below.

All sizes use binary units. A small page is 4 KiB; a block or huge page is
2 MiB, containing 512 small pages. “Huge” below means an ordinary allocation
backed by a level-2 page-table entry, distinct from sys-io's fixed mid page.

Implementation status (2026-09-06): P-1's boot-heap alignment fix is in
`6efc3276` (alongside the wait-set fix). P0b is in progress, split into
range validation first, then MMIO ownership/teardown and consumer refusals.
The block allocator and huge-page mapping changes are not implemented yet.

## Requirements and scope

- Maintain a LIFO free-page list per block. Lists start empty; allocate
  never-used memory in address order without writing links into it at boot.
- Pack consecutive small allocations into the current block. Reuse
  available split-block capacity before splitting another block.
- Keep memory below `DUAL_PURPOSE_START = 128 MiB` small-only. Above it,
  whole blocks can supply either huge pages or, as a last resort, small
  pages. Huge allocation searches downward; small allocation searches upward.
- Re-combine every entirely free, fully allocatable split block immediately,
  including small-only blocks, without walking its list. This restores
  contiguous-run capacity after churn. A live small page still pins a block.
- Support internal contiguous runs of 1 through 512 small pages. The syscall's
  existing 64-page cap and the library's size-selection behavior stay intact.
- Use huge pages only for ordinary eager, private, read-write anonymous
  allocation through `alloc_user_heap`, with the sizing rule below.
- Preserve sys-io's fixed [2 MiB, 10 MiB) segment, its physical-2-MiB
  assertion, its separate accounting, and its privileged explicit-mid path.
- Preserve admission floors, zero-before-mapping, and unmap/flush-before-free.

Out of scope: 1 GiB pages, NUMA, migration, randomized placement, host
free-page reporting, heap-size expansion, and changes to `src/sys/lib`,
rt.vdso, Rust stdlib, frusa, or other repositories.

Code scope: `src/sys/kernel`, `src/sys/tests/systest`,
`src/tests/full-test.sh` and its test helpers, and the relevant documentation. Tests run on
Motor OS, including kernel boot self-tests; no host allocator tests.
Benchmarks remain user-owned.

## Motivation and existing defects

The current allocator in `mm/phys.rs` manages 64-page segments with a
bitmap each. A small allocation tries a one-slot cache, then three random
segments, then scans all segments from zero. Free finds the owner by binary
search. A 32-byte segment descriptor costs about 128 KiB per GiB of RAM.

Recorded `phys::init` measurements are about 0.5 ms at 1 GiB and 3.0 ms at
8 GiB; see [boot-time.md](boot-time.md), items 5 and 7. Random placement
also touches many host hugepages: the earlier sys-io copy put 591 frames in
347 distinct 2 MiB regions. Sequential placement reduces fresh-region
touches without requiring guest huge mappings.

The scan's O(number of segments) worst-case frequency depends on full
segments, not overall page occupancy. Do not extrapolate timings above
8 GiB without measurements.

Known defects relevant to this work:

| Defect | Diagnosis | Patch |
|---|---|---|
| Boot heap alignment | `RawAllocator::alloc` advances by size without aligning the returned address. | P-1 |
| Page-zero accounting | `DesignatedSegment::new` sets bit zero, but `add_segment` adds no corresponding used count; later `mark_used` sees the bit already set and counts no allocation. Free capacity is overstated by one when page zero belongs to a managed range. | P1b replacement |
| MMIO teardown and failure | MMIO pages have no `Frame`, so `clear` leaves their PTEs; a failed map reverses statistics but leaves its virtual segment. | P0b |
| MMIO into RAM | `fixed_addr_reserve` can consume free managed RAM uncharged and accepts excluded kernel RAM. | P0b |
| Contiguous allocation | Outer assertion caps at 64; the inner scan omits the last page; descriptor-failure rollback misses one frame. | P1b replacement |

Page zero must be charged exactly once and never released. Test that in
the replacement. There is no shadow allocator or prerequisite repair of
soon-deleted accounting code; retain the diagnosis, not an oracle dependency.

## Representation and invariants

### Blocks, ownership, and metadata

Block index is `physical_address >> 21`. A flat array covers the physical
address span through the end of the last raw available-RAM range, including
holes. Padding needed to store the array in groups of four is not part of
the logical block count.

Each descriptor is exactly 16 bytes, checked at compile time. Store four
in a `#[repr(C, align(64))] BlockLine([Block; 4])`. The initial implementation
does not space CPU claims by cache line; that heuristic is deferred until
the user's measurements justify it.

| Field | Representation and meaning |
|---|---|
| `inner` | `SpinLock<Inner>`; protects all mutable ownership fields below. |
| `inner.head` | u16; first list index plus one, or zero for empty. |
| `inner.used` | u16; all non-free positions in the block, including non-RAM positions. |
| `inner.unused_lo/hi` | u16 each; half-open range of pages never handed out. |
| `inner.alloc_lo/hi` | u16 each; half-open interval of RAM positions that may be allocated or freed, including live initrd and metadata pages. |
| `state` | `AtomicU8`: absent, whole, split, or taken. |
| `flags` | `AtomicU8`: SMALL_ONLY, CLAIMED, RAM. |

Choose explicit padding/alignment as needed for the size assertion; do not
assume the lock occupies only its AtomicBool byte without padding. State
and flags are writable only under this block's lock; unlocked reads are
selection hints. All six u16 fields are lock-protected, including the
allocatable bounds that stage 2 changes.

| State | Meaning and stable invariants |
|---|---|
| absent | Not managed; no allocation source or block-state gauge includes it. RAM may still be set. |
| whole | 512 free RAM pages; allocatable interval [0, 512), used = 0, empty list, closed unused range. SMALL_ONLY whole blocks cannot supply huge mappings. |
| split | Small-page ownership; free count = 512 - used; used > 0 at lock release. List-state words are initialized. |
| taken | One owning huge allocation; allocatable interval [0, 512), used = 512, empty list, closed range; not SMALL_ONLY. |

Partial is derived: alloc_lo != 0 or alloc_hi != 512. Positions outside
this interval are permanently unavailable or non-RAM after stage 2; such
a block cannot become whole. An initrd page is allocated and freeable,
so its presence alone does not make a block partial. An empty interval
is [0, 0). Never represent a firmware hole with an interval spanning it.

Each block has eight list-state u64s: one bit per small page, set exactly
for pages on its free list. The list and unused range are disjoint and
inside the allocatable interval. Allocated and never-used positions have
clear bits. Bounds replace the allocatable-mask table and its topology cap;
the shaping rule below deliberately guarantees one interval.

List-state storage is one permanent contiguous allocation outside the boot
heap: 64 bytes per block, 32 KiB per GiB of address span. Address a block's
words at base + 64 * block. Initialize only initially split blocks and
blocks transitioning from whole to split. Never read words of whole,
taken, or absent blocks: they may be uninitialized. This avoids eager
table zeroing and chunk indexing without weakening split-block checks.

### List integrity

A free page's first u64 is an unkeyed check word:

| Bits | Contents |
|---|---|
| 0–15 | Next index plus one; zero terminates, valid values 0–512. |
| 16–39 | This page's physical page number (address >> 12), fitting 24 bits under the 64 GiB span limit. |
| 40–55 | Bitwise complement of bits 0–15. |
| 56–63 | Constant 0xa5. |

`link_encode` and `link_decode` are pure helpers. Decode compares the full
word with the encoding of the expected page identity and decoded next.
It validates the range and absence of a self-link before installing the
next head. Validate a descriptor's head before dereferencing a page.
Factor ownership checks into `check_push`/`check_pop` returning
a failure reason; production panics with the reason and physical address.

The word detects mismatched redundancy and links copied between pages or
blocks. It is not a MAC; coordinated writes can forge it. Random key
generation and a mixer are unnecessary for this diagnostic. The list-state
bits and allocatable bounds independently prevent a forged link from
allocating an already allocated or reserved page. An exhausted list and
unused range must have used = 512; otherwise panic, rather than clearing
a summary bit and stranding capacity in the exhaustion loop. Do not claim
detection of every stale-owner error after a page has been reallocated.

### Global accounting and indexes

Keep `total_pages = free_pages + used_pages`, in small-page units.

| Quantity | Includes |
|---|---|
| total_pages | Normalized managed RAM, excluding the kernel/boot heap and fixed mid segment; constant after init. |
| used_pages | Allocated plus reserved managed RAM. A taken block contributes 512; initrd and list-state storage count as allocated. |
| reserved_pages | The reserved subset of used_pages: low boot reservations before stage 2, then permanent reservations and discarded free runs. Constant after stage 2. |
| Per-block used | Allocated + reserved + non-RAM positions, so 512 - used is this block's free capacity. |

Non-RAM positions contribute to no global page counter. Kernel and boot
heap RAM are excluded before shaping. Fixed-mid RAM contributes to neither
small-page counter; `PhysStats` retains its separate treatment, counting
the entire fixed segment unavailable. Keep the historical high-water used
count so `min_free_small_pages` remains meaningful across stage 2.

A quiescent exact check is:
`total_pages - used_pages == sum(512 - block.used)` over non-absent blocks.
Also check list-bit count + unused length = 512 - used for split blocks;
whole and taken blocks follow their separate invariants above.

Two atomic bitmaps index blocks: F for split blocks with free pages and W
for whole blocks, including small-only whole blocks. Their values match
the descriptor when its lock is released; a scan must always revalidate
after acquiring the lock. Updates use AcqRel `fetch_or`/`fetch_and`,
because different block locks protect bits in the same word. Scans use
Acquire loads. Transitions may briefly publish both bits.

Use separate atomic split/taken counters; derive whole count from W's
popcount during collection. Diagnostic counters may use Relaxed ordering;
they are not inputs to allocation or its exhaustion protocol. Only a
quiescent check requires whole + split + taken + absent = blocks_total.
Packing these gauges would complicate updates without strengthening
ownership checks; collection under churn is explicitly not a snapshot.

### Limits and boot-heap budget

Centralize these limits and compute sizes with checked arithmetic:

| Item | Limit or cost |
|---|---|
| Physical address span | At most 64 GiB (32768 blocks), also subject to the actual heap remainder. |
| Block descriptor storage | 16 bytes per block, rounded to BlockLine groups; at most 512 KiB. |
| F and W | Two bits per logical block, each array rounded to u64 words. |
| List-state table | ceil(block_count / 64) small pages in one block-local run; at most 512 pages. |

Include table pointer, embedded cursor storage, and alignment padding
in the preflight budget against `kheap::startup_remaining()`. Metadata
scales with address span, including holes. Sparse high-address maps and
larger heaps are outside scope. The 64 GiB span limit deliberately replaces
v10's proposed 128 GiB limit to keep one table allocation and direct indexing;
it is a support limit, not a claim about the amount of installed RAM.

## Allocation and publication protocols

### Locking, bootstrap, and interrupt context

A block lock is a leaf: hold no newly acquired lock and perform no heap,
frame-descriptor, page-table, or diagnostic formatting allocation while
holding it. Existing outer mapping/slab locks may call into the allocator.
Drop the block lock before constructing owning Frame handles or calling
`admission::note_pages_freed`.

After `phys::init` and before `mm::cpu_initialized()`, allocation scans F/W
under block locks, without cursors or claims. This includes `virt::init`
and concurrent AP stack/GS allocation: it reads neither GS nor an
uninitialized per-CPU container and has no shared bootstrap cursor.

Runtime cursors are a static array of atomic block indexes, initially
“none”. Acquire-read the existing all-CPU initialization publication before
using GS CPU identity and the cursor path. No new barrier or allocation.

Kernel allocation/free is forbidden in IRQ/NMI context. Check frameless
callers too; page-fault repair allocates only after returning to thread context.
Existing non-masking mapping/slab locks already require non-reentrancy.
No IRQ-depth counters, exception resets, or GS/assembly changes are needed.
The spinlock panic diagnoses a violation; it does not make one safe.

### Small pages, runs, and huge pages

For a small page in runtime mode:

1. Pop from this CPU's cursor block: list first, then unused range.
2. If unavailable or no longer split, clear its claim hint under the lock and
   clear the cursor. Scan F upward for an unclaimed candidate; claim it,
   set the cursor, and pop.
3. Scan all remaining F candidates, including claimed blocks; adopt any
   successful candidate as the cursor and set CLAIMED. Cursors may share it.
4. Only after those scans fail, split the lowest W candidate and take a
   page. Set CLAIMED and the cursor. Small-only whole blocks come first
   because splitting them preserves the huge-eligible pool.
5. Apply the exhaustion loop below if no candidate succeeds.

CLAIMED is only a contention-avoidance hint, not ownership. Clear it on
every transition out of split. A stale cursor may refer to a subsequently
reused block; validate its current state under the lock. Clearing a hint
may also clear another CPU's preference, and multiple CPUs may retain the
same cursor. Both are harmless: block locks and ownership metadata, not
claims, decide allocation. No owner IDs, generations, or stale-claim
preservation rules are needed.

Bootstrap mode uses steps 3 and 4 without cursors or claims. Source priority
is a scan-order guarantee: a concurrent free can occur after a scan. No global
snapshot or lock across all blocks is introduced.

For a contiguous run, reject zero or more than 512 pages; a public
one-page request uses normal small allocation. For a larger run, check the
cursor's unused range, then every other split candidate's unused range,
claimed or not, before splitting the lowest whole block. Do not search
list links for runs. Check that n fits before advancing; retain short
tails for later allocation. On success, adopt the block as the runtime
cursor and set its claim hint, as for one page. A fragmented split-only
pool may legitimately refuse a run despite sufficient total free capacity.

For a huge page, scan W downward above the line, lock and revalidate,
and take one whole block. Failure to find one is recoverable fallback,
not the panicking small-frame allocation entry point. Neither adjacency
between huge frames nor successful huge allocation is guaranteed.

Kernel pages follow the same small-page policy. This tends to pack them
low but does not reserve low memory for them or guarantee that spilled
metadata occupies a fixed number of blocks.

### Ownership operations

All of these run under the owning block's lock:

Candidate pop/run first checks split state; a stale cursor or bitmap hint
for a whole, taken, or absent block returns none. Only a split block's
empty sources are subject to the used = 512 consistency check below.

- Push: validate small-page alignment, array bounds, split state,
  alloc_lo <= index < alloc_hi, used > 0, index outside the unused range,
  and a clear list-state bit. Encode the old head into the page, set its
  bit and the new head, and reduce per-block used.
- List pop: validate head, its set list-state bit and allocatable bounds;
  decode the link before changing ownership. A nonzero next index must
  name another set list-state bit and pass the bounds. Clear the popped
  bit, advance head, and increase used.
- Unused pop/run: check bounds, require every requested list-state bit
  clear, and validate the allocatable bounds; advance unused_lo and increase
  used. Initial shaping guarantees a contiguous unused range. A new
  whole block goes through split before this operation.
- Empty pop: require used = 512 if both sources are empty, then return
  none. This also diagnoses a truncated list with unaccounted free pages.
- Split: require whole; zero its eight list-state words before any read,
  install empty head and unused range [0, 512), used = 0, and split state.
  Consume the requested page/run before releasing the lock, so used = 0
  is only a transient split state.
- Huge take/return: validate alignment, bounds, dual-purpose eligibility,
  full allocatable interval, empty list and closed range. Take requires
  whole; return requires taken and used = 512. Do not read list-state
  words. Repeated or misdirected returns panic.
- Re-combine: on any push reaching used = 0, require full allocatable bounds
  and list-bit count + unused length = 512; clear all eight words, empty the
  head, close the range, clear CLAIMED, and set whole. This applies below
  128 MiB too. A partial block cannot reach used = 0.

An owning Frame is created only after the block lock is dropped. If its
construction fails, return the physical allocation through the matching
small/huge path. For a contiguous run, existing handles own their prefix;
a guard owns the remaining suffix, including the failed iteration. Rollback
drops each exactly once. Never free the entire run in addition to dropping
already constructed handles. The boot table is carved from an input free
run before allocator construction; it has no owning Frame handles.

### Publication order and exhaustion

This table is the sole publication-order specification. Descriptor changes
and gauge/event updates happen inside the same critical section. G is the
global used_pages counter; updates to it are Release atomic RMWs. “Publish”
means the bitmap RMWs in the stated order, before unlocking.

| Operation | Ordered accounting and index updates |
|---|---|
| Small pop/run of n | Update ownership; G += n and update high-water; clear F if the split block is now full. |
| Push, remaining split | Update ownership; set F; G -= 1. |
| Push and re-combine | Update ownership, clear CLAIMED, validate/clear list metadata; set W; clear F; G -= 1. |
| Split | Update descriptor; set F; clear W. No change to G. |
| Huge take | Update ownership; G += 512 and high-water; clear W. |
| Huge return | Update ownership; set W; G -= 512. |
| Stage-2 release of n | Reshape descriptor; publish its final F or W; reduce reserved_pages and G by n. |

For transitions between free whole and split states, publish the receiving
index before clearing the old one. Allocation accounts consumption before
withdrawing indexed capacity; freeing indexes capacity before releasing
its charge. After any successful free, notify admission outside the lock.

After a failed complete small-page scan of F then W, Acquire-load G.
If G equals total_pages, return out of memory at that observation; an
in-flight allocation may already have charged capacity it is consuming.
If G is smaller, rescan: a prior free publishes its bit before its counter
decrement, and Acquire observes that publication. Revalidate candidates
under their locks because other CPUs may take them in the meantime.

This is the allocator's concurrent search protocol, not a timeout or a
retry workaround. Admission does not bound it to a fixed number of rounds.
The panicking small-allocation wrapper and admission floors remain as today.

## Boot shaping and initialization

`phys::init` receives three inputs: available ranges with kernel/boot heap
already subtracted, in-use ranges (low 34 MiB and an above-kernel initrd),
and raw firmware available ranges for the RAM flag. Normalize available
starts upward and ends downward to pages; round initrd reservations outward.
Check all arithmetic, ordering and overlaps; coalesce adjacent available
ranges. The page-rounded above-kernel initrd must be wholly contained in
managed RAM, without firmware holes or permanent exclusions. Set RAM
for any raw-RAM intersection, even on absent blocks, before page trimming.

Shape every block without touching its free data pages:

| Layout | Initial shape |
|---|---|
| No managed RAM, or fixed mid segment | Absent. Retain RAM if applicable. |
| Managed RAM below 34 MiB | Split, fully reserved, empty list, allocatable and unused intervals [0, 0). |
| Entirely free managed RAM | Whole; SMALL_ONLY below 128 MiB. |
| Other layout, no initrd | Split; retain the largest free run as both allocatable and unused interval. |
| Layout with initrd | Split; retain the largest free run immediately adjacent to the block's initrd interval, or none. Allocatable interval is that run plus the initrd; unused interval is only the retained free run. |

Choose the lowest-address run on equal lengths for deterministic low-first
placement. Discard all other free runs, count them in reserved_pages, and
exclude them from allocatable bounds. Loss is the sum of free-run lengths
minus the retained length. With one internal reservation and no other
holes, loss is at most 1 MiB; no such bound applies to arbitrary layouts.

The initrd-adjacency rule is intentional. For `free | hole | initrd | free`,
keeping the largest free run regardless of adjacency could require two
allocatable intervals. Prefer simple bounds to an extra mask table, even
if this discards a larger disconnected run. Check every retained interval
against the original RAM and reservation ranges; never include the hole.

Construct the allocator in this order:

1. Preflight the address-span/heap budget and compute table size n pages.
   Using the pure shaping helper on input ranges, find the lowest block
   whose retained free run holds n pages; a whole block offers [0, 512).
   Record the first n pages of that run as the permanent table allocation.
   Refuse insufficient space with requested sizes and limits.
2. Install the table's direct-map base and construct descriptors/indexes.
   In its backing block, keep the original allocatable bounds; set unused
   to [retained_lo + n, retained_hi) and used to 512 - unused_length.
   Table pages are allocated, never reserved or discarded. The table is
   never freed, and its backing block starts split.
3. Zero the eight words of each initially split block before publishing
   that descriptor. Leave whole/absent words untouched. Initialize global
   accounting including the table, then expose the allocator to callers.

This requires neither a not-yet-installed-table allocator mode nor a call
into allocation during table construction. The no-GS allocation path
still exists for subsequent virtual/CPU initialization; it is a separate
constraint. No free data pages are touched except table storage itself.

Stage 2 reclaims managed low RAM, excluding page zero and the actual two
kloader page-table addresses. Preserve firmware holes and the fixed segment.
Most blocks become small-only whole; mixed ones use the no-initrd
largest-run rule after excluding these permanent reservations. Recompute
the bounds without allocation, reset the empty list/words for split
results, and apply the publication table; total_pages never changes.

Check accounting at the end of init and stage 2 in debug builds. Both are
quiescent: init precedes CPU allocations;
[init::cpu_main](../../src/sys/kernel/src/init.rs) waits for all CPUs before
calling BSP stage 2, so AP stack/GS allocation is already done.
APs then wait for PERCPU_SCHEDULERS publication in
[scheduler::start](../../src/sys/kernel/src/sched/scheduler.rs) before allocating.
They do not race low-memory release. Keep the second check at stage-2 end;
arbitrary later metric collection is not quiescent.

Independently recount managed, reserved, discarded, and retained free pages
from input-range intersections in debug builds, without using descriptor
totals or the shaping helper as the expected result. Initially subtract
the table pages from retained free capacity; at stage 2 compare the
independently computed low-memory release with the actual free-count delta.
Absolute counts then include intervening stack/GS allocations. Also run
the exact descriptor/list/index invariants at both checkpoints. Log whole,
split, reserved, and discarded counts per launcher at these checkpoints.
This validates shaping without a second allocator or legacy-count oracle.

## Mapping and syscall behavior

### Eligibility and sizing

Store creation policy as an internal `MappingOptions::HUGE_ELIGIBLE` bit
(512) in VmemSegment's existing mapping_options. Bit clear means SmallOnly;
bit set means HugeEligible. No new field or stored policy enum is needed.
Only `alloc_user_heap` requests above 256 small pages set it. Keep Page
and SegmentNode's existing 72-byte size/slab assertions.

Pass policy through the existing options path. Do not infer it from
permissions, size, alignment, or Frame kind: fresh shared allocations can
have the same permissions as ordinary heap allocations. Lazy, guard,
shared, custom-address, contiguous, MMIO, fixed-mid, and kernel allocations
stay SmallOnly. Retain HugeEligible in the segment even after complete
fallback. Strip the policy bit from per-page hardware mapping options
before `PageTable::map_page`, which validates the remaining option set.
This is not a new public SysMem flag or an inference from Frame kind.

For an eligible request of p small pages, define one checked helper:

```text
whole = p / 512
tail = p % 512
huge = whole + (tail > 256 ? 1 : 0)
small = (tail > 256 ? 0 : tail)
mapped_pages = huge * 512 + small
```

The implementation uses Rust boolean conversion/conditionals, checked
arithmetic, and the syscall's existing input limits. The mapping never
covers less than requested. Huge candidates round upward only for a tail
strictly larger than 1 MiB; smaller tails remain small pages.

| Requested | Huge candidates | Small tail | Returned size |
|---|---|---|---|
| 64 KiB | 0 | 16 | 64 KiB |
| 1 MiB | 0 | 256 | 1 MiB |
| 1 MiB + 4 KiB | 1 | 0 | 2 MiB |
| 1.5 MiB | 1 | 0 | 2 MiB |
| 2 MiB | 1 | 0 | 2 MiB |
| 3 MiB | 1 | 256 | 3 MiB |
| 3 MiB + 4 KiB | 2 | 0 | 4 MiB |
| 5.5 MiB | 3 | 0 | 6 MiB |

For SmallOnly policy, mapped_pages = p and there are no huge candidates.
For HugeEligible policy, align the virtual segment to 2 MiB even if every
candidate falls back. A refused candidate becomes 512 small mappings.
After the first refusal, serve all remaining candidates small without
asking again. Then append the small tail. Returned size and statistics
use mapped_pages in every case, including guests of 128 MiB or less.

`SysMem::map2` exposes returned size; `map` and `alloc` continue returning
only the address. `free` frees the complete segment. No library ABI change.

### Virtual descriptors, zeroing, and accounting

Derive Page kind from its non-null Frame; a Page without a Frame is small
(lazy/unmapped reservation). One Page and one owning MidPage Frame describe
each actual huge page. Do not add a second kind field that can disagree.
Find the greatest Page start not above the queried address and check its
kind-sized extent; this handles interior addresses and gaps correctly.
Never install an unbacked huge placeholder in the tree, including on
failure paths. Validate each Page's alignment, extent, and non-overlap; a
mixed segment does not have one common Page kind.

Use `aligned_start(gap_start, gap_end, size, align)` for empty-region,
append, and gap placement, with checked arithmetic and exact end bounds.
Make the decision before mapping. Store huge entries first, followed by
small entries; a fallback therefore cannot produce huge/small/huge ordering.

Keep `PageTable::map_page` zeroing the entire frame before publishing its
PTE. Newly reused huge pages and rounded padding must be zero too. On
clear, unmap each actual kind, flush the complete segment before dropping
Frames, and return the sum of Page byte sizes, not the descriptor count
times 4 KiB. Capture each size before taking its Frame; otherwise the
unbacked-small default would undercount huge teardown. This is the size
subtracted from region and process statistics.
Keep the fixed sys-io mid mapping outside these owning-Frame paths.

Use the same policy/sizing helper in allocation, returned size, memory
statistics, and `map_charge`. Admission dispatch must match the ordinary
heap branch, including flags and unset addresses; excluded paths keep their
existing charges. If mapped_pages = M, charge `mapping_charge(M, M)`.
Its second argument counts per-page descriptors, not physical metadata
pages. For one 2 MiB candidate, the existing helper gives
512 + ceil((512 + 512) / 32) + 64 = 608 pages. Aggregate the whole request
before adding the flat charge; do not add that flat charge per candidate.
This conservatively covers full fallback and requires no admission refunds
for actual huge success.

### Sharing: both endpoints

`share_range_with` validates both ranges before replacing any destination
PTE or Frame. Return `E_INVALID_ARGUMENT` if either endpoint belongs to a
HugeEligible segment, regardless of actual backing, or contains MMIO.
A subrange of a HugeEligible segment is refused too. Segment provenance
keeps this deterministic even after fallback; huge-page demotion is out of scope.

Apply this rule to both `F_SHARE_SELF` and IPC's `shared::get` ->
`UserAddressSpace::map_shared`, including same-address-space sharing.
Existing mapped destinations are possible in IPC. A huge-backed destination
must never reach the old one-small-Page-per-iteration replacement loop.

Validate the entire range for these refusals before destructive work.
`share_from` may construct its usual empty destination reservation; on
failure it must remove it and reverse its statistics. Existing destination
mappings must retain their bytes and translations after refusal.

Supported shared buffers use fresh-frame `F_SHARE_SELF`, unmapped
reservations at the receiving end, or populated lazy SmallOnly allocations.
The normal small-buffer IPC and vdso/ELF paths remain supported. Large
ordinary eager IPC buffers become explicitly unsupported at either endpoint;
do not claim that the only existing sharing callers are the ELF paths.

### MMIO prerequisite and direct-map consumers

P0b fixes MMIO before the allocator switch. Whole-range validation uses
checked size/end arithmetic and alignment and rejects RAM regardless of
whether it is allocated, free, excluded, or in the fixed mid segment.
Reject addresses outside the x86 PTE's 52-bit address field too: upper
bits must not be interpreted as PTE flags or alias a lower RAM address.
Use raw firmware RAM ranges initially, expanded to the same 2 MiB block
boundaries as the final policy; P1b replaces this check with RAM flags and
non-absent state. Check the full range before reserving/mapping pages.
Outside-RAM addresses remain accepted; this is not device-discovery validation.

Give each successfully mapped MMIO Page a Frame with an `mmio` flag,
preserving Frame's size and admission assertions. Allocate the descriptor
before map_page, install it only after success, and make its drop free no
physical memory. Reset the flag when recycling descriptors. Ordinary clear
then unmaps exactly the successful prefix, including rollback, with its
existing flush-before-drop ordering. On failure remove the virtual segment
and reverse its accounting exactly once.

Return a distinct `VaddrMapStatus::Mmio`. `copy_to_user`,
`get_user_page_as_kernel`, `read_from_user_into`, and sharing refuse it;
retain the existing handling of other statuses and special fixed mappings.
Do not turn the input path into a blanket refusal of everything outside
the normal segment tree. `virt_to_phys` still reports device addresses.
Kernel LAPIC/IOAPIC mappings and sys-io BAR mappings must continue booting.

## Validation

### Deterministic kernel self-tests

Run debug self-tests on Motor OS, through ordinary boots in full-test.sh.
Use a small scratch allocator with independent descriptors, bounds, counters,
and list words. Factor link reads/writes so tests use a fixed array of u64s
and production uses the direct map; no fake physical-address dereferences,
real-pool exhaustion, or general fault-injection framework.

| Area | Required controlled cases |
|---|---|
| Integrity | Check-word round trips; corruption of each field; copied links between pages and between equal indexes in different blocks; self-link; out-of-range head; double free; never-used/reserved/non-RAM free; wrong state; bounds-rejected pop; truncated list with used < 512. |
| Source order | Sticky sequential allocation from fresh blocks; LIFO reuse; other split before whole; claimed capacity used before split/OOM; shared/stale cursors through re-combination/take/return; clearing another cursor's hint is harmless; bootstrap with no CPU identity available. |
| Contiguous | 1, 2, 64, 65, 256, 512; reject 0/513; insufficient cursor tail preserved; another claimed split range satisfies the request with no whole block; fresh split; descriptor-prefix/suffix rollback exactly once. |
| Ownership | Huge take/return and invalid returns; split/free transitions; accounting after every operation; no duplicate live ownership. |
| Re-combination | List plus unused capacity; validate/clear words; both low and dual-purpose blocks become whole; recovered low block supplies a contiguous run but never huge; partial blocks never whole. |
| Shaping | Raw/managed RAM; holes and exact discarded sum; initrd-adjacent selection even when a disconnected free run is larger; lowest-run tie; invalid initrd crossing a hole; page zero and both kloader tables before/after stage 2; more than 255 mixed blocks. |
| Storage/arithmetic | Table rounding at 63/64/65 blocks and 32768-block maximum; over-limit refusal; backing carved from whole and partial retained runs; initialize every initial split including the backing block; whole/taken paths never read poisoned words; heap limits; ordinary counter transitions; sizing/placement boundaries and overflow. |

Use the same production checkers and transition helpers; compare against
explicit ownership and accounting expectations. Verify publication traces
for each transition with a small test-only recording hook, including
F-before-W-clear on split and W-before-F-clear on re-combination. Keep
this confined to the scratch instance and compiled out of release builds.

Exact reuse tests hold a live page in their split block when they intend
to test list reuse. A separate re-combination test expects another split
when that recovered whole block is used small again. No ratio between two
global split-counter deltas is a correctness condition. Assert exact
placement on a fresh scratch pool: 2048 small pages with one sequential
cursor occupy four blocks. Fragmented-pool cases assert source priority,
not the same packing bound.

### Systest and observability

Register `mem_blocks.rs` in systest; the main suite reaches it through
full-test.sh. Keep allocations that must remain small-backed at or below
1 MiB per segment. Use RAII cleanup for every mapping and child handle.

- Placement: allocate eight 1 MiB pieces, touch/verify them, query every
  physical page, and count distinct blocks. Preallocate test bookkeeping.
  A focused placement subcommand runs early in full-test.sh on its plain
  1 GiB guest, before allocation-heavy tests, and asserts at most
  `4 + 2 * CPUs` blocks: four for ideal packing plus a loose allowance for
  boot fragmentation, metadata, and cursors. This fixture-specific budget
  needs activation-gate validation; it is not a universal derived bound.
  Diagnose failures, without raising the limit or retrying. Later or
  under-load runs report placement; scratch tests prove the exact rule.
- Churn: four threads, 512 iterations each, initially 1–256 pages and
  later 1–1024 pages; retain several allocations, verify distinct patterns
  before freeing, and exercise cross-thread frees as well as local frees.
  Include disjoint writes/readback across all constituent small pages of
  huge allocations so aliasing cannot pass as simple successful touching.
- Mapping sizes: the sizing table above through map2; touch the first/last
  bytes and boundaries, check returned sizes, alignment for eligible
  segments, and query all pages. On an actual aligned contiguous 2 MiB
  physical piece verify offsets; that alone does not prove the PTE is huge.
  Deterministic kernel mapping tests inspect Frame kinds, PTE leaf levels, and
  whole/fallback decisions; global event metrics are supporting evidence.
- Huge reuse: controlled kernel mappings dirty, unmap, and remap the same
  physical frame; check full zeroing and rounded padding before user
  exposure. Keep a test owner across unmap so reuse is guaranteed; allocator
  take/return is tested separately. End-to-end pattern/free/reallocate
  tests verify zeroing too, but prove reuse only if physical addresses
  overlap. Also use huge interiors and huge/small boundaries as syscall
  input/output and pinned-page buffers.
- Sharing: refuse eligible source and eligible destination, whole ranges
  and subranges, actual huge and forced-small fallback. Exercise F_SHARE_SELF
  and IPC, and verify preexisting destination contents remain intact.
  Verify 1 MiB eager sharing, populated 2 MiB lazy sharing, and large
  fresh-frame sharing still work. Use controlled mapping-policy tests to
  force fallback without exhausting the live machine.
- Fallback: require actual fallback in the controlled 1 GiB test and the
  64 MiB launcher case, including eligible policy retention and rounded
  size. Admission refusal does not satisfy either assertion. Do not add
  another whole-machine squeeze loop solely to attempt this coverage.
- Pressure: retain the existing end-to-end pressure episode, including
  recovery after the squeeze releases its mixed allocations. In controlled
  huge-return tests verify the post-unlock admission notification path;
  do not attribute a live system's flag transition to one specific huge
  free without evidence of its backing and the other concurrent releases.
  Report observed fallback during this existing squeeze, without treating
  an admission-refusal endpoint as a fallback test.
- Process/region accounting: use controlled mapping tests for exact deltas,
  rollback and teardown; live-process metrics include helper allocations.
  Existing admission boundaries, lazy faults, all-CPU fault storm, OOM,
  pressure, process teardown, and sys-io virtqueues remain required.

Keep one narrow test seam in the actual mapping loop: a local huge-frame
callback. Production calls the physical allocator; debug tests supply
held owning huge Frames or a deliberate refusal. Small Frames and page
tables always use the real allocator. Use an ordinary private test address
space, not another mapping backend; never install its CR3. Inspect its PTEs
and access backing bytes through the Frames' direct-map addresses; flush
before releasing Frames. Run immediately after BSP `xray::stats::init`,
before `uspace::init` and scheduler publication: CPU/TLB setup and the stats
used by invalidation are ready, and APs can acknowledge teardown IPIs.
Provision bounded backing through ordinary allocations.

This small seam remains because RAM size and an unlimited process cap do
not guarantee admission reaches fallback. A 2 MiB request needs 608 charge
pages plus the 256-page floor; with 768 pages left after the final whole
take, admission refuses despite 3 MiB free. Sufficient low-memory headroom
on the default guest has not been established as a fixture guarantee.
No new syscall, global failure switch, or general frame-supplier framework.

Declare these eleven metrics together; inactive producers report zero:

| Gauges | Counters |
|---|---|
| mem.blocks_total, mem.blocks_whole, mem.blocks_split, mem.blocks_taken | mem.block_splits, mem.block_recombined |
| mem.blocks_whole_low, mem.pages_reserved, mem.pages_free_low | mem.huge_pages_mapped, mem.huge_fallbacks |

blocks_total includes absent logical descriptors. Whole count is W's
popcount; whole_low/free_low scan at most 64 low blocks under their locks.
These and atomic counters need not agree instantaneously. Count
huge_pages_mapped after each successful huge PTE installation; huge_fallbacks per
candidate served small, including candidates skipped after the first
refusal. These are cumulative events, including subsequently undone maps.

A single Collector::query avoids mixing collection rounds but does not make
all counters simultaneous. Check the exact state sum only at quiescent
points; under churn check individual bounds and stable reserved_pages.
Do not require exact global huge/whole deltas around a syscall
or a fixed number of pinned blocks per CPU. PhysStats/dump_serial include
block counts and reserved/discarded totals for diagnosis.

Run pool-squeezing cases only in plain systest, not under-load soak.
A one-hour release stress-soak.sh run after re-combination is integrated
records block counts and allocation failures. A trend is diagnostic
evidence; metadata growth can legitimately pin blocks.

### MMIO suite

Add `mmio-unmap-suite` transitively to full-test.sh with `MOTOR_OS_CAPS=0x4e`:
the current 0x4c plus CAP_IO_MANAGER. Launch privileged cases from the
existing test-only System console fixture, not from an Interactive SSH
shell: only a System parent can grant CAP_IO_MANAGER. Keep production
capability policy and SSH grants unchanged. Run separate child cases and verify
setup succeeded before interpreting a child's fault as a passing test.

1. Map the page at physical 128 GiB (1 << 37) in the QEMU gate: it is
   outside this plan's supported RAM span. Confirm the mapping by a
   translation query, free it, verify translation is gone, then attempt a
   volatile read in the child.
   Check the expected fault termination, not merely any abnormal exit.
2. Refuse kernel-start RAM (34 MiB), fixed-mid RAM, managed RAM, and a
   range crossing into RAM; include an address obtained from a currently
   allocated page.
3. Refuse wrapped/unaligned ranges and confirm failed-map virtual/stat
   rollback. Debug checks inspect the region after removal.
4. Refuse an MMIO page as syscall input/output and pinned-page buffer,
   without accessing device memory through the direct map.

Use the existing outside-RAM mapping policy, and never assume physical RAM
ends at total_size when a firmware hole exists. All launcher boot legs
exercise real LAPIC/IOAPIC/BAR mappings.

## Patch sequence and acceptance

Keep patches around 100–300 changed code lines including tests where
practical. The core and the switch are the two justified size exceptions:
one cohesive ownership implementation and the atomic replacement of its
production caller. Split other work at the boundaries below rather than
compressing tests to meet optimistic line estimates. No code changes are
part of this documentation revision; commits require the user's chosen
workflow.

| Patch | Deliverable | Acceptance beyond the common gate |
|---|---|---|
| P-1 | In mm/kheap.rs, checked aligned bump-offset helper, CAS reservation of padding + size, pointer-alignment assertion, startup_remaining. Frusa untouched. | Debug boot arithmetic test: awkward base/offset, alignments 1–4096, exhaustion and overflow; launcher boots. |
| P0b | MMIO validation, owning descriptor with no physical free, Mmio status, consumer refusals, teardown and rollback. Keep this independent of blocks. | MMIO suite and all launchers; current suite unchanged otherwise. |
| P1a1 | Descriptor/bounds, link check word, ownership and uniform re-combination, F/W publication, ordinary counters, core scratch tests. | Debug self-tests; production still uses old allocator. Temporary module dead-code allowance names P1b. |
| P1a2 | Pure shaping/table-carve helper, F/W search, advisory claims/no-GS path, contiguous search; input-range and source-order fixtures. | Hole/initrd/lazy-initialization cases; no real shadow allocator or table allocation. |
| P1b | Switch phys.rs to blocks including low/dual re-combination; carve/install table, route small/run/free/adopt/MMIO and runtime cursors; remove old vector/cache/search. | Page-zero regression; independent boot recounts, no-GS/AP and rollback tests, fresh-boot placement/churn, pressure/admission; launcher matrix and boot measurements. |
| P2 | Add the eleven metrics, collection helpers and PhysStats/dump diagnostics with real block producers; huge-mapping events remain zero until P4b. | Collection tests, controlled low contiguous recovery and cross-CPU churn; release soak. |
| P3 | Frame-derived Page kind, internal policy option bit, kind-sized lookup/clear, aligned virtual placement. | Size assertions, all alignment branches, option stripping and 4 KiB behavior; no public allocation-policy change yet. |
| P4a | Dual-purpose owning huge Frames and controlled take/return tests. | Frame construction rollback; huge return notifies admission; fixed-mid route unchanged. |
| P4b | Mark all >1 MiB ordinary heap segments HugeEligible, refuse sharing at both endpoints, but map huge only for exact multiples of 2 MiB. Add conservative matching admission/stats. | Whole-size mappings, forced fallback, IPC/F_SHARE_SELF refusal and supported sharing, zeroing/translation/teardown tests. |
| P5 | Enable the full sizing rule and mixed huge/small segments; rounded fallback sizes everywhere. | Table boundaries, overflow, mixed lookup/copy/pinning, exact controlled accounting; re-read admission boundary expectations. |
| P6 | Widen churn to mixed sizes; document final accounting and metrics in docs/oom-handling.md and measured results here/boot-time.md. | Full integration gate and recorded residual risks/measurements. |

Order: P-1 -> P0b -> P1a1 -> P1a2 -> P1b.
P2 and P3 each depend on P1b; P4a depends on P2; P4b depends on P4a and
P3; P5 depends on P4b; P6 depends on P5. P4b's intermediate eligibility
rule is deliberate: non-multiple requests already get deterministic sharing
refusal but retain their old mapped size until P5.

Every production activation brings its tests in the same patch. The
scratch data structure tests do not use the real allocator before P1b;
controlled mapping tests begin only once ordinary owning huge Frames
exist. Keep all ordinary allocator reads/writes under the specified locks,
and remove temporary allowances with their wiring.

### Common gate

For each kernel patch, before commit:

- Repository-selected `cargo fmt`; no new compiler or clippy warnings.
- `src/tests/full-test.sh` three times in debug and three times with
  `--release`, consistently passing.
- `src/tests/full-test-dev.sh --release` once; this work is not Lorry
  work and does not add a debug developer-image run.
- All new tests reached directly or transitively by full-test.sh.

No Internet access in new tests. Existing approved DNS/ping flakes may be
retried once under AGENTS.md; no retries, enlarged timeouts, or ignored
failures to disguise a defect. Diagnose failures; pause implementation for
new non-test pre-existing bugs or a newly required policy decision.

P1b launcher matrix: cloud-hypervisor; Firecracker at 64 MiB and 1 GiB;
QEMU -kernel; QEMU BIOS; release developer image at 8 GiB with a PhysStats
dump. P0b also verifies real MMIO boot on each launcher. P4b/P5 repeat the
64 MiB small-only case, including a 1 MiB + 4 KiB request returning 2 MiB
of small mappings after P5. Expose the sizing/fallback tests through a
focused systest subcommand for this small guest, and call those same test
functions in ordinary systest so full-test.sh covers them transitively.
On 64 MiB require no huge successes and positive fallback coverage; the
launcher leg runs these assertions, not just a boot to the console.

Measure phys::init at 1/8 GiB and QEMU's kernel phase with the existing
boot-time.md method. Include table carving/lazy initialization and all
release bootstrap work. Under 0.1 ms for phys::init is a target, not an
established result.
Boot-time regression requires diagnosis/review before landing. Mark items
5 and 7 complete only when their measurements support it.

## Readiness and implementation limits

The design is specified for implementation, not yet validated in code.
P1b and P4b/P5 have separate activation gates. Those gates must establish
launcher support, the fresh-boot placement budget, and boot-time cost;
design readiness does not substitute for their results.

Accepted costs are explicit: free-page link writes and a block lock per
operation; 64 bytes of integrity metadata per block outside the boot heap;
the 64 GiB span cap and discarded runs needed for one allocatable interval;
rounding waste below 1 MiB per eligible request; best-effort huge
availability; and large eager buffers being ineligible for sharing.
Cross-CPU frees and descriptor false sharing may affect
performance. Do not add claim-spacing heuristics, migration, larger heaps,
or new tuning knobs without evidence and a separate review.

Implementation may start at P-1 under the requested local-change/commit
workflow. Keep this document as the active specification, update patch
status and measured outcomes as they land, and use Git history for the
superseded alternatives and review discussion.
