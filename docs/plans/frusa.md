# Frusa v2: the runtime allocator

`frusa_v2` (`src/sys/lib/frusa_v2`) is the allocator behind every process's
`GlobalAlloc`, wired in by `rt.vdso`, and behind the kernel heap; §8 is the
assessment that moved the kernel off the original `frusa` crate and the
record of the switch. §1 to §6 describe the allocator as it is; §7 is the
plan to close the fast-path gap to glibc. This document follows the root
`AGENTS.md`.

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

Free lists: `SHARDS` lists per data slab (`ShardList`, one cache line each:
a spinlock, a head pointer, and a count), allocated at initialization
beside the reader shards. A list holds slots of its class that were freed
by a thread on that shard and are marked in use in their blocks. The list
runs through the slots themselves: word 0 is the next slot's address XOR
the slot's own address shifted right by 12, so a stale or overwritten link
rarely decodes to a usable pointer and a misaligned one panics; word 1 is
the list's key, which flags a double free. A list holds at most
`min(64, 16 KiB / slot size)` slots; classes above 16 KiB keep none.

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
- Free lists: a listed slot's bit is set in its block, so the block is
  neither reclaimed nor handed out twice; a list is read and written only
  under its own lock, except the head, which is read without it as a hint.

The stack head is never updated by CAS, so there is no ABA hazard, and
descriptors cannot be freed while any thread holds the read guard. The
lists have no ABA hazard either: they are mutated only under their lock.

## 3. Locks and ordering

| Path | Locks, in order |
|---|---|
| Shared allocation | read guard, then `partial_lock` |
| Free through the slab | read guard, then `partial_lock` only on a full-to-non-full transition |
| Cached allocation from a private block | none |
| Cached allocation or free through a list | the list's lock alone, tried once |
| Cached allocation that takes a block from the stack | read guard, then `partial_lock` |
| Cached allocation that takes from another shard's list | the list's lock alone, tried once, no guard held |
| Growth, link step | write guard alone |
| Reclaim, drain step | each list's lock in turn, then the slab free path |
| Reclaim, detach step | write guard alone, try-only, skip if busy |
| Metadata slab | the same table with its own guard and lock |

The read guard means "descriptors and the index are stable"; the write
guard means "nobody else is in this slab". A reader that finds a writer
pending backs off instead of joining, so a draining writer sees the counts
reach zero. A write guard is never requested while holding a read guard or
`partial_lock` of the same slab. A list lock is only ever tried, never spun
on, and is never held while any other allocator lock is taken, so a busy
list costs its caller one tier, never a wait. Hot paths never spin on a
growth lock.

## 4. Paths

### 4.1 Shared allocation

`Slab::alloc`: load `partial_head` without the lock; null means the slab
has no free slot, and the caller grows. Otherwise take `partial_lock`, claim
the lowest free slot of the top block with a bitmap compare-and-swap loop
(a CAS that loses to a concurrent free retries), pop the block if it became
full, release. `alloc_from_slab` wraps this in the read guard, using the
caller's shard, then tries the other shards' free lists, and grows only
when those are empty too.

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

`reclaim()` walks every data slab; metadata pages are never returned. For
each slab it first drains the class's free lists, so that listed slots
return to their blocks and count as free. A slab with less than a page of
slack, or with another writer active, is skipped. Under the write guard, every batch whose blocks are all empty and
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

Allocation, in tiers: claim a slot of `current[class]` with the bitmap CAS
and no guard (an owned block is never reclaimed and descriptors never
leave the metadata slab); a full block is given up under the guard. Then
pop the free list of the caller's shard. Then, under the guard, pop a block
from the stack under `partial_lock` with `owner` set to this cache, and
retry. Then, with no lock held, take from the other shards' lists in turn.
Only then grow. Classes above `CACHED_MAX_LOG2` (2 KiB) have no private
block: their tiers are the shard's list, the shared path, the other lists,
growth. A listed slot is served as is; every slot of class `k` is
`2^k`-aligned, so any layout that maps to the class fits.

Free, in tiers: if the pointer lies in the thread's current block of that
class, flip the bit and return, one locked instruction and the slot is the
thread's next allocation; the block is owned, so its descriptor is stable
and no guard is needed, and it is never full here. Otherwise push the slot
on the shard's list if the list is below its limit and not busy; the slot
stays marked in use, so nothing shared changes, whichever block and thread
it came from. Otherwise `dealloc_to_slab` with the cache's shard. A free
into a block another thread owns that reaches the slab just flips the bit;
the owner sees the slot on its next allocation. The release re-check and
the free's owner check both use sequentially consistent operations, so a
remote free that lands while a block is being released is never lost.

Memory on a list is reachable from every thread: the tier before growth
scans the other shards, and reclaim drains every list of a class before it
looks for empty batches. So the lists pin nothing the way a per-thread
cache would, and a process at its admission floor finds what another
thread freed before it asks the backend.

`release_cache` gives every private block back; the cache may be used again
afterwards. Listed slots need no release: they belong to the shard, not
the thread.

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
populations, immediate alloc/free of one fixed size and of random sizes,
the 4 KiB class on every CPU, a FIFO queue, rings of live objects, and a
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

A prototype of per-thread free lists in the style of glibc's tcache, in
front of the cached path with 32 entries per class, measured 3 to 5 ns on
the immediate workloads, 4 ns on FIFO, 21 ns on the ring at 1 thread and
23 ns at 8, and 3 ns for 4 KiB at 8 threads: at or below glibc on every
row. It was implemented, passed the crate suite and five gate runs, and
then failed `test_aggregate_listener_exhaustion`: a flood child at the
admission floor died on a 2 KiB-class allocation inside the vDSO. Objects
the main thread allocates and the IO runtime thread frees sat on the IO
thread's list instead of returning to the main thread's block, so the main
thread had to grow at the floor. The test's contract, that a process at the
floor cannot grow its heap, is a real requirement for admission-limited
processes, and any cache that keeps another thread's frees breaks the
margin; glibc avoids this case only by not caching sizes above 1 KiB.
That is why C below shards the lists by CPU instead.

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

**C. Free lists sharded by CPU.** Per class, `SHARDS` lists on their own
cache lines, indexed by the shard the cache already carries (the thread
control block's `current_cpu`), each guarded by a spinlock that is only
ever tried: a busy list is skipped and the caller uses its next tier. The
structure is described in §2 and the tiers in §5.

- A list push and pop each cost one locked instruction plus a few loads and
  stores, more than the bitmap's single locked bit flip, so the private
  block stays first on both paths and the lists serve what it cannot: frees
  of older objects, of other threads' objects, and of the 4 KiB class,
  which has no private block. The temporaries path is unchanged.
- A slot on a list stays reachable: an allocation that finds its own list
  empty, its private block gone, and the stack empty takes from the other
  shards' lists before it grows, and reclaim drains every list of a class
  before it looks for empty batches. A per-thread list cannot offer either.
- The limit per list is `min(64, 16 KiB / slot size)`: 64 for classes up to
  256 B, then 32, 16, 8, and 4 for 4 KiB; 2 and 1 for the 8 and 16 KiB
  classes of Frusa2M and none above. Listed slots count as in use in
  `stats()` until reclaim drains them.
- Tests: LIFO reuse from a list with no guard, stack entry, or probe; the
  limit per class, with the overflow reaching the block; class isolation
  and alignment of served slots; a slot freed on one shard taken on
  another when the backend refuses growth, and only then a null; reclaim
  draining the lists and returning the batch; a busy list skipped by both
  paths; a double free and a corrupted link panicking; Frusa2M's large
  classes keeping no list; the guard-count test of A with frees into the
  current block still guard-free and list-free.

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

Three patches in the order A, B, C. A and B are within 100 to 300 lines
including tests; C is about 400 because the list module is dead code
without its wiring and half of it is tests. Each passes the crate's suite
in both profiles, is Clippy clean and formatted with the repository
toolchain, and passes `src/tests/full-test.sh` three times in debug and
three times in release before it is committed. No runtime change is
needed: the caches are unchanged and the lists live in the allocator.
`systest alloc-bench` gains the host harness's fixed-size, per-CPU, and
FIFO rows in a patch of its own, so the Motor and host tables line up. The
plan ends with the §7.1 table rerun on the host with the new crate as an
added column, and the same rows measured on Motor (§7.5).

### 7.4 Risks

- **Memory held on lists** is at most 16 KiB per list per class, 9 KiB of
  list headers per `Frusa4K` instance, and is never pinned: every thread
  can take it before growing, and reclaim drains it. Between reclaims,
  `stats()` reports listed slots as in use, so the reclaim resident sees
  less slack than there is; it drains on its next pass.
- **Free-list corruption** by a use-after-free write is the classic attack
  on this structure. The link encoding and the alignment check make it
  detectable rather than silent; the bitmap remains the ground truth.
- **Guard-free allocation** relies on ownership excluding reclaim. The
  invariant checker and the existing transition-race test cover it; the
  release path still takes the guard.
- **Index memory** doubles per block (16 bytes per 64 slots). The first
  page per slab is unchanged.

### 7.5 Results

Host, the harness of §6, nanoseconds per alloc+free pair, one thread
unless noted. "Before" is the crate as it was on 2026-09-09, then the tree
after A and B, then after C.

| Workload | glibc | before | A + B | A + B + C |
|---|---:|---:|---:|---:|
| fixed 64 B | 6 | 34 | 20 | 21 |
| fixed 64 B, 8 threads | 10 | 51 | 19 | 19 |
| fixed 4 KiB, 8 threads | 37 | 2,105 | 2,009 | 22 |
| random 16 B to 4 KiB, 8 threads | 18 to 26 | 230 | 219 | 86 |
| FIFO queue of 64 × 64 B | 7.5 | 92 | 89 | 25 |
| ring of 4,096 live, random sizes, 1 thread | 49 | 96 | 94 | 43 |
| ring, 8 threads, per thread | 55 | 680 | 532 | 123 |
| free 262K × 64 B in random order, per free | 82 | 98 | 83 | 85 |
| free 4M × 64 B in random order, per free | 216 | 216 | 139 | not rerun |

Motor, `systest alloc-bench` on the release image, QEMU with 4 vCPUs on
the same host, two runs each within 5 percent except where noted. The
"before" column is the crate as it was before A, measured on 2026-09-08
with the rows that existed then.

| Workload | before | A + B | A + B + C |
|---|---:|---:|---:|
| free all, 65K retained, insertion order | 2.3 ms | 2.4 ms | 2.4 ms |
| free all, 65K retained, random order | 5.5 ms | 4.9 ms | 4.7 ms |
| fixed 64 B, 1 thread | – | 29 | 30 |
| fixed 64 B, 4 threads, per thread | – | 29 | 30 |
| fixed 4 KiB, 4 threads, per thread | – | 945 | 30 |
| random 16 B to 4 KiB, 1 thread | 61 | 34 | 32 |
| random, 2 threads, per thread | 119 | 59 | 33 to 41 |
| random, 4 threads, per thread | 216 | 102 | 53 to 56 |
| FIFO queue of 64 × 64 B | – | 97 | 31 |
| ring of 4,096 live, 1 thread | 107 | 105 | 60 |
| ring, 4 threads, per thread | 429 | 370 | 135 |
| producer/consumer cross-thread pair | 87 | 82 | 80 to 100 |

What the numbers say. A took the temporaries path from 34 to 20 ns on the
host by removing the guard; on Motor that row is 29 ns, and the 9 ns above
the host is the vDSO entry path (vtable call, layout re-validation, shard
store), which is now the largest fixed cost per operation. C changed
nothing on that row by design and took every other row down: the 4 KiB
class by 30 to 90 times because it no longer serializes on one block, FIFO
and ring by 3 to 4 times because a free of an older object is a list push
instead of a guarded search, and the mixed-size multi-thread rows by 2 to
3 times. glibc still leads on the temporaries row by three times, which
is the two locked instructions of the bitmap path against none, and the
lists cannot close that gap without the per-thread state that §7.1 shows
breaking the admission contract. The remaining Motor-specific cost is the
entry path; §7.2 lists it with the other follow-ups.

## 8. The kernel heap

The kernel's `GlobalAlloc` (`src/sys/kernel/src/mm/kheap.rs`) was the
original `frusa` crate behind `RawAllocator`, a page-granular backend that
bumps from a 2 MiB boot area until memory is initialized and then hands
out `VmemKind::KernelHeap` pages. §8.1 to §8.4 are the assessment of
replacing it with `frusa_v2`, measured on 2026-09-10; §8.5 records the
switch.

### 8.1 What a switch needs

Nothing the kernel does not already have.

- **Backend contract.** `Frusa4K` asks the backend for at most 256 KiB at
  4 KiB alignment (a batch of the 4 KiB class; the 2 MiB alignment tier in
  `batch_layout` is reachable only by classes above 4 KiB), inside the raw
  allocator's "align at most 4 KiB" assertion. Initialization takes the
  reader shards, the free lists, and one metadata page, about 28 KiB, plus
  a 4 KiB index per class on its first growth, all from the boot bump area
  when the first allocation precedes memory init. Frees inside the boot
  area are no-ops for both crates. Every backend free is the whole
  allocation at its start, which `vmem_free` requires.
- **Execution model.** An allocation on a CPU runs to completion before
  any other allocation can begin on that CPU: kernel code is never
  preempted, and interrupt handlers do not allocate (every IDT entry is an
  interrupt gate, the handlers touch atomics only, and object destruction
  runs in the scheduler loop). Three things follow. A holder of an
  allocator lock is never descheduled, so a lock wait is bounded by the
  critical section and the killed-while-holding hazard of §1 cannot arise.
  A per-CPU cache satisfies the one-user rule of §5 with nothing masked or
  disabled, and its shard, `arch::current_cpu()` (one gs-relative load),
  is exact for the whole operation, where a thread's `current_cpu` in the
  vDSO can go stale under migration. And the per-CPU stage can be a
  magazine of plain loads and stores with no atomic at all, the design of
  §7.1 that the vDSO had to reject; §8.4 takes this up.
- **Lock discipline.** Both crates spin without disabling interrupts,
  which the execution model makes safe. v2 is stricter on one point:
  `frusa` holds its slab lock across `vmem_allocate_pages`, v2 holds no
  lock across a backend call (§1).
- **Per-CPU state.** `StaticPerCpu` is the natural home; `MAX_CPUS = 16`
  equals `SHARDS`, so the shard is the CPU. Allocations before the per-CPU
  structures exist take the uncached path, as the vDSO does before a thread
  has its block. The wrapper needs an `unsafe impl Sync` justified by the
  execution model.
- **No flush hook.** The vDSO needed one for the per-thread lists of §7.1
  and rejected it: a thread can park forever holding another thread's
  frees, a process at its admission floor cannot reach them, and returning
  them would have meant a flush at every park, at the five `SysCpu::wait`
  call sites in `rt.vdso` and two more in `moto-async`, so C shards the
  lists by CPU instead. None of that applies to per-CPU state. A CPU never
  exits, and an idle CPU's magazine is used by its next allocation; what
  all CPUs hold together is bounded by 16 times the per-CPU caps, not by
  the thread count; the kernel heap has no admission floor; and its
  reclaim is an explicit, rare operation (see Consumers below) that simply
  leaves the cached slots where they are, since listed slots are marked in
  use and owned blocks are skipped (§4.4, §5). A drain would make that
  reclaim more exhaustive by a few hundred KiB at most; if ever wanted, it
  is one scheduler job posted to each CPU from `kheap::reclaim()`, and it
  can wait.
- **Consumers.** `kheap::reclaim()` has one caller, the reclaim syscall
  behind `sysbox free`; there is no periodic reclaim and no pressure hook.
  `heap_stats()` reads the raw allocator's page counter, not the crate.
  Neither changes.

A bare swap is one dependency and one type; the per-CPU cache and the
magazine in front of it are 60 to 100 lines each, gated as in §7.3.

### 8.2 Measurements

The host harness of §6 with a `frusa` column, nanoseconds per alloc+free
pair, 16 cores. "v1" is the kernel today, "v2 uncached" a bare swap, "v2
cached" the swap with a per-CPU cache (one cache per thread here).

| Workload | glibc | v1 | v2 uncached | v2 cached |
|---|---:|---:|---:|---:|
| fixed 64 B, 1 thread | 6 | 51 | 50 | 21 |
| fixed 64 B, 8 threads | 6 | 1,264 | 2,140 | 19 |
| fixed 4 KiB, 8 threads | 38 | 1,233 | 2,195 | 20 |
| random 16 B to 4 KiB, 8 threads | 20 | 546 | 574 | 97 |
| FIFO queue of 64 × 64 B | 8 | 57 | 58 | 26 |
| FIFO queue of 65,536 × 64 B | 8 | 2,965 | 64 | 25 |
| ring of 4,096 live, random sizes, 8 threads | 58 | 950 | 700 | 120 |

`frusa` frees by walking the slab's block list, so its cost grows with the
number of live objects of the class; per free, random order:

| Live 64 B objects | v1 | v2 uncached |
|---:|---:|---:|
| 4,096 | 98 | 43 |
| 16,384 | 208 | 31 |
| 65,536 | 2,190 | 30 |
| 262,144 | 7,760 | 30 |

### 8.3 Where the kernel allocates

The hot paths were made allocation-free on purpose. Syscall dispatch
passes arguments by value; wait and wake stage handles in stack arrays up
to 16 and wakers in an inline vector up to 4, a thread's wait-object
vector is cleared and reused, a single waiter registers without a map,
the wake queue is an intrusive list, the scheduler's queues are pre-sized
deques, and the `mm` layer has its own slabs. Page faults, IPC switches,
and mappings never touch the heap.

The one per-call heap user on a hot path is the timed wait:
`Timers::add_timer` builds a BTreeMap node and a BTreeSet per timer under
the timers spinlock, and the wake frees them. Everything else allocates at
object creation: process and thread setup, kernel objects and their
handles, shared-memory endpoints, URL parsing on object creation, and
diagnostics. Frees run under spinlocks in `put_object` and the timers, so
a free's cost is lock hold time that other CPUs spin on.

No systest row exercises the kernel heap directly; `wake-bench` (timed
waits) and an object-creation flood are the measurements that would move.

### 8.4 Assessment

- A bare swap is not worth a gate. It changes nothing on the temporaries
  path and is slower under contention, because the uncached path
  serializes every CPU on one partial block. Its only wins are `frusa`'s
  pathological cases, deep queues and large live populations.
- The switch pays in two places, both bounded. With a per-CPU cache the
  timed-wait pair gets a few hundred nanoseconds back on a busy machine.
  Independent of the cache, frees stop scaling with heap size: a listener
  flood or a process with tens of thousands of live kernel objects turns
  every free under `put_object` or the timers into microseconds of lock
  hold time with `frusa`, and stays at tens of nanoseconds with v2.
- The execution model lets the kernel take what the vDSO could not. The
  per-thread lists of §7.1 measured 3 to 5 ns on the immediate workloads
  and 4 ns on FIFO on the host, at or below glibc, against 21 to 26 for
  the private block; they were rejected because another thread's frees sat
  where the allocating thread could not reach them at the admission floor,
  and the only fix, a flush at every park, was judged not worth its reach
  into the runtime (§8.1). Per CPU, a free
  pushes onto the CPU's own magazine and an allocation pops from it with
  plain stores, since nothing else on that CPU can run in between, and
  what is held is bounded by 16 CPUs, not by the thread count, so no flush
  is needed (§8.1).
- The cost is pinned memory. A per-CPU cache holds up to one block per
  cached class (§5), at most about 255 KiB per CPU, and a magazine at most
  its limit per class, 16 KiB per class with the rule of §2; the lists add
  at most 16 KiB per class per shard. This memory stays with its CPU, since
  no CPU exits and nothing flushes it (§8.1): a bound of a few MiB on a
  16-CPU machine, comparable to the slab slack `frusa` keeps today until
  someone runs `sysbox free`.

Recommendation: switch, as the cached version only, in three patches: the
swap with the uncached path; the per-CPU `Cache4K`; the magazine in front
of it. Measure before and after with `systest
wake-bench` and a flood of object creation. Expect a modest system-level
effect and a robustness gain at scale.

### 8.5 The switch

Done on 2026-09-12 as one patch, the three pieces of the recommendation
together. The kernel depends on `frusa_v2` instead of `frusa`; `frusa`
stays in the tree as a published crate. `kheap.rs` wraps a `Frusa4K` over
the unchanged `RawAllocator` in a `GlobalAlloc` that consults a static
per-CPU stage: a `Cache4K` whose shard is the CPU, and per class a
magazine, the LIFO of §8.4 linked through the slots' first words with the
limit of §2, popped and pushed with plain loads and stores. Until CPU
identity is valid (`mm::cpu_initialized`, the same gate as the physical
allocator's cursors) the shared path serves, so nothing runs at boot; the
stage is 192 bytes per CPU of static data. `realloc` keeps the same-class
shortcut. `reclaim()` is unchanged and leaves what the stages hold, as
§8.1 says. The crate and the runtime are untouched.
