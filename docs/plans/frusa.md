# Frusa v2: the runtime allocator

`frusa_v2` (`src/sys/lib/frusa_v2`) is the allocator behind every process's
`GlobalAlloc`, wired in by `rt.vdso`. The kernel keeps the original `frusa`
crate. §1 to §6 describe the allocator as it is; §7 is the plan to close the
fast-path gap to glibc. This document follows the root `AGENTS.md`.

## 1. Overview and constraints

Requests are rounded to a power-of-two class, `max(next_power_of_two(size),
align)`, with 16 bytes the smallest class. `Frusa4K` has nine classes, 16 B
to 4 KiB; `Frusa2M` has seventeen, to 1 MiB, and has no user in the
repository. Anything larger goes straight to the backend. A block is 64
slots of one class with a 64-bit usage bitmap; a slab is one class.

Constraints the design keeps:

- no per-allocation header, no mandatory preallocation, no permanent
  runtime instrumentation, no new allocator dependency;
- the crate has no thread-local dependency: the per-thread cache is owned
  and passed in by the caller, so the kernel and the tests work without one;
- lazy initialization and no boot-time work;
- no lock held across a backend call, so a backend may allocate from the
  allocator it backs and a thread killed in a syscall leaves no sibling
  spinning;
- `src/sys/Cargo.toml` is a toolchain runtime input, so the crate is not a
  workspace member; it joins the workspace as `rt.vdso`'s path dependency.

Backend contract: a request with 4 KiB alignment returns 4 KiB-aligned
memory. Both in-tree backends hand out 4 KiB pages; the crate checks it
with a debug assertion and relies on no larger alignment.

## 2. Data structures

Every structure is 64 bytes, one cache line, enforced by size assertions.

`Block`, the descriptor of 64 slots:

| Field | Meaning |
|---|---|
| `entry_sz_log2` | slot size |
| `batch_pos`, `batch_sz` | position in and size of the growth batch it belongs to; a batch is reclaimed whole |
| `used_bitmap: AtomicU64` | one bit per slot |
| `data` | the slots, `64 << entry_sz_log2` bytes |
| `next: AtomicPtr<Block>` | batch list link |
| `partial_next: AtomicPtr<Block>` | partial stack link, valid while `ON_STACK` is set |
| `owner: AtomicPtr<()>` | the thread cache holding the block privately, or null |
| `flags` | `ON_STACK` |

Descriptors live in the metadata slab (§4.5), separate from the data they
describe, except metadata blocks, whose descriptor is their own first slot.

`Slab`, one size class:

| Field | Meaning |
|---|---|
| `entry_sz_log2`, `table_idx` | class and position in the slab table; the metadata slab is last |
| `guard: RwLock` | the writer bit of the readers/writer guard; reader counts are in the shards |
| `partial_lock: SpinLock` | protects the partial stack |
| `head`, `bytes_total` | batch list (newest first, each batch contiguous in it) and bytes held from the backend |
| `partial_head` | top of the partial stack |
| `index`, `index_len`, `index_cap` | address-sorted array of block pointers, null until the first growth, always null for the metadata slab |

Reader shards: `SHARDS` (16) cache-line-sized counters per slab, allocated
once at initialization for all slabs and reached through one pointer in
`Frusa`. A thread counts itself in the shard the caller names, normally its
CPU, so readers on different CPUs never write the same line.

Invariants:

- Index: entries `[0, index_len)` are live descriptors of this slab in
  strictly increasing `data` order; every block on the batch list is in the
  index and vice versa; read under the read guard, written under the write
  guard.
- Partial stack: a block is on it at most once; every block on it has a
  free slot; every non-full block is either on it or owned by a cache,
  except in the window between a freeing thread's bitmap update and its
  push, which happens under that thread's read guard. Mutated under
  `partial_lock`, or under the write guard, which excludes every reader and
  therefore every holder of `partial_lock`.
- Ownership: a block with a non-null `owner` is off the stack, is allocated
  from only by its owner, and is never reclaimed.

The stack head is never updated by CAS, so there is no ABA hazard, and
descriptors cannot be freed while any thread holds the read guard.

## 3. Locks and ordering

| Path | Locks, in order |
|---|---|
| Shared allocation | read guard, then `partial_lock` |
| Free | read guard, then `partial_lock` only on a full-to-non-full transition |
| Cached allocation from a private block | read guard |
| Cached allocation that takes a block from the stack | read guard, then `partial_lock` |
| Growth, link step | write guard alone |
| Reclaim, detach step | write guard alone, try-only, skip if busy |
| Metadata slab | the same table with its own guard and lock |

The read guard means "descriptors and the index are stable"; the write
guard means "nobody else is in this slab". A reader that finds a writer
pending backs off instead of joining, so a draining writer sees the counts
reach zero. A write guard is never requested while holding a read guard or
`partial_lock` of the same slab. Hot paths never spin on a growth lock.

## 4. Paths

### 4.1 Shared allocation

`Slab::alloc`: load `partial_head` without the lock; null means the slab
has no free slot, and the caller grows. Otherwise take `partial_lock`, claim
the lowest free slot of the top block with a bitmap compare-and-swap loop
(a CAS that loses to a concurrent free retries), pop the block if it became
full, release. `alloc_from_slab` wraps this in the read guard, using shard
zero, and grows on null.

### 4.2 Free

`dealloc_to_slab`, under the read guard: binary search the index for the
greatest `data` not above the pointer; validate the range and that the
offset is a multiple of the slot size, panicking otherwise; `fetch_xor` the
bit, asserting it was set. If the block was full, take `partial_lock` and
push it unless a cache owns it (the owner sees the free slot itself, and its
own release re-checks). No lock is taken otherwise.

### 4.3 Growth

Everything is allocated with no lock held; the write guard covers only
linking, indexing, and pushing. Batch size grows with the class's total:
small classes take 4 KiB, then 32 KiB, then 256 KiB batches; a class whose
block exceeds 256 KiB takes one block per batch, at least 2 MiB. Descriptors
come from the metadata slab, chained by `next`. If the index needs a larger
array (capacity doubles from 512 entries, always whole pages), it is
allocated before the guard and re-checked under it; a stale one is
released. Under the guard, if another grower refilled the stack meanwhile,
the batch goes back to the backend rather than multiplying the slab's
memory. Otherwise the batch is inserted into the index with one binary
search and one memmove, prepended to the batch list, and pushed on the
stack. There is no growth gate: two threads that both find the slab empty
may both grow, and the loser gives its batch back.

### 4.4 Reclaim

`reclaim()` walks every data slab; metadata pages are never returned. A
slab with less than a page of slack, or with another writer active, is
skipped. Under the write guard, every batch whose blocks are all empty and
unowned is detached from the batch list and the index and stack are rebuilt
from the survivors (the index by `sort_unstable_by_key`). After the guard,
the detached data goes back to the backend and the descriptors to the
metadata slab.

### 4.5 Metadata slab

Same `Slab` code, 64-byte entries in 4 KiB page-sized blocks whose
descriptor is their own first entry, so the owner of a descriptor pointer is
`ptr & !(PAGE - 1)` and no index is needed. Initialization allocates the
shard array first, then the first metadata page, whose entries `1..=SLABS`
hold the slab table. Metadata growth allocates a page with no lock held and
links it under the metadata slab's write guard, giving it back if another
thread refilled the stack meanwhile. The metadata path never touches a data
slab's locks and is entered only with no data-slab lock held.

### 4.6 Statistics and realloc

The hot paths keep no counters. `stats()` sums bitmap popcounts over each
slab's batch list under its read guard; index arrays and the shard array
count as metadata, so the vDSO's reclaim resident does not see them as
slack. `realloc` returns the same pointer when both layouts map to the same
class, and otherwise allocates, copies, and frees.

## 5. Per-thread caches

`ThreadCache<SLABS>` holds one private `current` block pointer per class and
the guard shard index. The caller owns it and passes it to `alloc_cached`,
`dealloc_cached`, `realloc_cached`, and `release_cache`; the `GlobalAlloc`
implementation is the shared path.

Allocation: under the read guard, claim a slot of `current[class]` with the
bitmap CAS. On a full or missing block, give up ownership (clear `owner`
with a swap, push the block if it has a free slot), pop a block from the
stack under `partial_lock` with `owner` set to this cache, and retry; grow
when the stack is empty. Only classes up to `CACHED_MAX_LOG2` (2 KiB) are
cached, so an idle thread holds at most 255 KiB; larger classes use the
shared path.

Free: if the pointer lies in the thread's current block of that class, flip
the bit and return; the block is owned, so its descriptor is stable and no
guard is needed, and it is never full here. Otherwise `dealloc_to_slab`
with the cache's shard. A free into a block another thread owns just flips
the bit; the owner sees the slot on its next allocation. The release re-check
and the free's owner check both use sequentially consistent operations, so a
remote free that lands while a block is being released is never lost.

`release_cache` gives every private block back; the cache may be used again
afterwards.

vDSO wiring (`rt.vdso`): the runtime's per-thread block, reached through
the `tls` word of the thread control block with one `rdfsbase`, holds the
TLS map and a `Cache4K`. It is created on the thread's first allocation or
TLS write, so the vDSO's own threads and C threads are covered, and freed
after the TLS destructors have run and the cache is released. The global
allocator fetches the cache and sets its shard from `current_cpu` on every
call; a thread without a block uses the shared path, and frees never create
one. The backend is `SysMem::alloc` and `SysMem::free` of 4 KiB pages. A
housekeeping resident calls `reclaim()` every five seconds when the slack
exceeds 1 MiB, or a page under kernel memory pressure.

## 6. Tests and measurement

The crate's suite runs in `src/tests/full-test.sh` in both profiles. It
covers synthetic blocks and slabs, the index and stack invariants
(`check_invariants` under the write guard), retained populations with churn
and insertion, reverse, random, and sparse-hole frees, growth under
concurrency, two-phase reclaim, a backend that allocates from the allocator
it backs, fault injection at every backend call, cross-thread frees, the
ownership protocol and its transition race, and Frusa2M at small
populations. Work bounds are asserted with test-only counters (index probes
per free, stack entries examined per allocation), never with wall-clock
time.

`systest alloc-bench` prints per-workload timings on Motor for retained
populations, immediate alloc/free, rings of live objects, and a
producer/consumer pair. A host harness with the same workloads compares the
crate's shared and cached paths against glibc over a common page backend;
it lives outside the repository.

## 7. Plan: closing the fast-path gap to glibc

### 7.1 Evidence

Host measurements, i9-10885H, release builds, the harness of §6,
nanoseconds per alloc+free pair, one thread unless noted (2026-09-09):

| Workload | glibc | frusa_v2 shared | frusa_v2 cached |
|---|---:|---:|---:|
| fixed 64 B | 6 | 50 | 34 |
| fixed 64 B, 8 threads | 10 | – | 51 |
| random 16 B to 4 KiB, 8 threads | 18 to 26 | 516 | 230 |
| fixed 4 KiB, 8 threads | 37 | – | 2,105 |
| FIFO queue of 64 × 64 B | 7.5 | 61 | 92 |
| ring of 4,096 live, random sizes, 1 thread | 49 | 85 | 96 |
| ring, 8 threads, per thread | 55 | 729 | 680 |
| free 262K × 64 B in random order, per free | 82 | 96 | 98 |
| free 4M × 64 B in random order, per free | 216 | – | 216 |

The costs, each confirmed with a variant build or the instruction stream:

1. **Four locked read-modify-writes per pair on the cached fast path.**
   `alloc_cached` takes the read guard around the private block's
   `lock cmpxchg` (a `lock incl` and `lock decl` on the shard line plus two
   writer checks); `dealloc_cached` adds a `lock btc`. Each is a full fence
   of about 20 cycles. glibc's tcache path has none. Dropping the guard on
   the owned-block path alone takes fixed 64 B from 34 to 21 ns and the
   8-thread case from 51 to 18 ns.
2. **`slabs()` is not inlined.** LTO keeps it as a call whose prologue
   saves six registers on every operation, because the cold
   initialization loop lives in the same function. Splitting the fast load
   from a cold init saves 3 ns per pair.
3. **The 4 KiB class is uncached and single-file.** Above
   `CACHED_MAX_LOG2` every request goes through `alloc_from_slab`, which
   uses guard shard zero for every thread and claims from the one block on
   top of the stack under `partial_lock`. At 8 threads that class costs
   2.1 µs per pair. It is one ninth of the random mix and by itself explains
   the 230 ns 8-thread average.
4. **Frees that miss the current block are expensive, and ownership
   churns.** Anything not in the thread's current block pays the guard, a
   binary search with two dependent loads per probe (the index entry, then
   the descriptor's `data`), a compare-and-swap loop for the xor, and a
   `partial_lock` push when the block was full. In ring-like patterns a
   popped block has about one free slot, so nearly every allocation pops
   and nearly every free pushes under the same spinlock. That is why the
   cached path is slower than the shared path on FIFO and ring workloads,
   and why 8 threads land at 540 to 680 ns.
5. **The lookup scales with the heap.** At 4M live objects (64K blocks) a
   random-order free costs 216 ns, the same as glibc's consolidation path.
   Searching an array of addresses instead of descriptor pointers brings it
   to 139 ns; at 262K it is worth 13 percent.

A prototype of the per-thread free lists below, in front of the cached
path with 32 entries per class, measured 3 to 5 ns on the immediate
workloads, 4 ns on FIFO, 21 ns on the ring at 1 thread and 23 ns at 8, and
3 ns for 4 KiB at 8 threads: at or below glibc on every row. A limit of 7
per class leaves the 8-thread ring at 72 ns; 256 gives 21 ns.

### 7.2 Changes

**A. Guard-free allocation from a private block.** An owned block is never
reclaimed and descriptors never leave the metadata slab, so
`alloc_cached` claims from `current[class]` with no guard. Only the paths
that touch shared structures keep it: giving a block up (its re-check may
push) and popping a replacement. `slabs()` becomes an inlined load with a
`#[cold]` initialization function. The shared path reached from a cached
entry point uses the cache's shard rather than shard zero. A test-only
counter of guard acquisitions asserts that allocation from and free into a
private block take none.

**B. Address-first index.** The index array holds `index_cap` sorted data
addresses followed by `index_cap` block pointers in the same order, 16
bytes per block instead of 8; the minimum capacity halves to 256 entries so
the first array is still one page. A probe touches the dense address array
only; the descriptor is loaded once, after the search. Growth, rebuild,
and replacement maintain both halves. The synthetic slab fixture in the
tests allocates both halves.

**C. Per-thread free lists.** The idea of glibc's tcache, in front of the
private blocks: `ThreadCache` gains a singly linked list of free slots per
class with a count. The link lives in the freed slot itself, which is at
least 16 bytes, encoded as `next ^ (slot >> 12)` so a stale or corrupted
link is unlikely to decode to a usable pointer; a decoded link that is not
aligned to the class's slot size panics.

- Allocation pops the list first; on an empty list, the private block; then
  the shared path. A popped slot is served as is; every slot of class `k`
  is `2^k`-aligned, so any layout that maps to the class fits.
- Free pushes when the list is below its limit, whatever block the slot
  belongs to and whichever thread allocated it; otherwise the existing
  path (current block, then the slab). A slot on a list stays marked in use
  in its block, so no block state changes and reclaim leaves its batch
  alone until the slot returns.
- The limit per class is `min(64, 16 KiB / slot size)`: 64 entries for
  classes up to 256 B, then 32, 16, 8, and 4 for 4 KiB; 2 and 1 for the 8
  and 16 KiB classes of Frusa2M and none above. An idle `Frusa4K` thread
  holds at most 95 KiB on its lists.
- `release_cache` returns every listed slot through the slab path before
  it releases the private blocks. Same-class `realloc_cached` is unchanged.
- Tests: LIFO reuse with no stack entry examined and no probe; the limit
  per class, with the overflow reaching the block; class isolation and
  alignment of served slots; a cross-thread free landing on the freeing
  thread's list; reclaim leaving a batch alone while its slots are listed
  and freeing it after release; a corrupted link panicking; Frusa2M's
  large classes keeping no list.

Not in this plan, recorded for later: requests above 4 KiB are a
`SysMem::alloc` and `SysMem::free` pair each on Motor, where glibc serves
up to 128 KiB from its heap; power-of-two classes waste up to half of each
object; the vDSO entry path (vtable call, `Layout` re-validation, shard
store) costs on the order of 20 ns on Motor and will dominate once the
allocator is at 5 ns; an O(1) lookup through 2 MiB-aligned segments with a
per-page descriptor table would remove the index and the search for very
large heaps but changes growth and reclaim granularity; caching the 4 KiB
class's private blocks would pin 256 KiB per thread and is left to the
free list.

### 7.3 Patches and gates

Three patches in the order A, B, C, each 100 to 300 lines including tests.
Each passes the crate's suite in both profiles, is Clippy clean and
formatted with the repository toolchain, and passes `src/tests/full-test.sh`
three times in debug and three times in release before it is committed. No
runtime change is needed: the vDSO already calls `release_cache` at thread
exit and the cache type grows in place. The plan ends with the §7.1 table
rerun on the host with the new crate as an added column.

### 7.4 Risks

- **Memory pinned by idle threads** rises from the private blocks' 255 KiB
  worst case by up to 95 KiB of listed slots per thread, and those slots
  block reclaim of their batches. Bounded by the limits above; the vDSO's
  reclaim resident cannot flush another thread's list, which is the
  documented limitation.
- **Free-list corruption** by a use-after-free write is the classic attack
  on this structure. The link encoding and the alignment check make it
  detectable rather than silent; the bitmap remains the ground truth.
- **Guard-free allocation** relies on ownership excluding reclaim. The
  invariant checker and the existing transition-race test cover it; the
  release path still takes the guard.
- **Index memory** doubles per block (16 bytes per 64 slots). The first
  page per slab is unchanged.
