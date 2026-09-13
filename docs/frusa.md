# The allocator: frusa

`frusa` (`src/sys/lib/frusa`) is the allocator behind every process's
`GlobalAlloc`, wired in by `rt.vdso`, and behind the kernel heap
(`src/sys/kernel/src/mm/kheap.rs`). This document describes its design, how
the two users wire it in, and how it is tested and measured.

## 1. Overview and constraints

Requests are rounded to a power-of-two class, `max(next_power_of_two(size),
align)`, with 16 bytes the smallest class. `Frusa4K` has nine classes, 16 B
to 4 KiB; `Frusa2M` has seventeen, to 1 MiB, and has no user in the
repository. Anything larger goes straight to the backend. A block is 64
slots of one class with a 64-bit usage bitmap; a slab is one class.

The design keeps no per-allocation header, no mandatory preallocation, no
permanent runtime instrumentation and no allocator dependency; has no
thread-local dependency (the per-thread cache is owned and passed in by
the caller, so the kernel and the tests work without one); initializes
lazily with no boot-time work; and holds no lock across a backend call, so
a backend may allocate from the allocator it backs and a thread killed in
a syscall leaves no sibling spinning.

Backend contract: a request with 4 KiB alignment returns 4 KiB-aligned
memory. Both in-tree backends hand out 4 KiB pages; the crate checks it
with a debug assertion and relies on no larger alignment.

## 2. Data structures

Every structure is 64 bytes, one cache line, enforced by size assertions.
Descriptors live in the metadata slab (§4.5), apart from the data they
describe, except metadata blocks, whose descriptor is their own first slot.

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

`Slab`, one size class:

| Field | Meaning |
|---|---|
| `entry_sz_log2`, `table_idx` | class and position in the slab table; the metadata slab is last |
| `guard: RwLock` | the writer bit of the readers/writer guard; reader counts are in the shards |
| `partial_lock: SpinLock` | protects the partial stack |
| `head`, `bytes_total` | batch list (newest first, each batch contiguous in it) and bytes held from the backend |
| `partial_head` | top of the partial stack |
| `index`, `index_len`, `index_cap` | address-sorted index, null until the first growth, always null for the metadata slab |

The index array holds `index_cap` sorted data addresses followed by
`index_cap` block pointers in the same order, 16 bytes per block, at least
256 entries so the first array is one page; a lookup probes the dense
address half and loads one descriptor after the search. Reader shards are
`SHARDS` (16) cache-line-sized counters per slab, allocated once at
initialization; a thread counts itself in the shard the caller names,
normally its CPU, so readers on different CPUs never write the same line.

Free lists: `SHARDS` lists per data slab (`ShardList`, one cache line each:
a spinlock, a head pointer, and a count), allocated at initialization
beside the reader shards. A list holds slots of its class that were freed
by a thread on that shard and are marked in use in their blocks. The list
runs through the slots themselves: word 0 is the next slot's address XOR
the slot's own address shifted right by 12, so a stale or overwritten link
rarely decodes to a usable pointer and a misaligned one panics; word 1 is
the list's key, which flags a double free. A list holds at most
`min(64, 16 KiB / slot size)` slots; classes above 16 KiB keep none.

Invariants: the index holds exactly the live descriptors of the batch
list in strictly increasing `data` order, read under the read guard and
written under the write guard. A block is on the partial stack at most
once and only with a free slot; every non-full block is on it or owned by
a cache, except between a freeing thread's bitmap update and its push,
which happens under that thread's read guard; the stack changes under
`partial_lock` or under the write guard, which excludes every reader. A
block with a non-null `owner` is off the stack, is allocated from only by
its owner, and is never reclaimed. A listed slot's bit is set in its block,
so the block is neither reclaimed nor handed out twice; a list changes
only under its own lock. The stack head is never updated by CAS and
descriptors are never freed under a read guard, so there is no ABA hazard.

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
pending backs off, so a draining writer sees the counts reach zero. A
write guard is never requested while holding a read guard or `partial_lock`
of the same slab. A list lock is only ever tried, never spun on, and never
held while another allocator lock is taken; hot paths never spin on a
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
come from the metadata slab. A larger index array (capacity doubles, whole
pages) is allocated before the guard and re-checked under it. If another
grower refilled the stack meanwhile, the batch goes back to the backend;
otherwise it is inserted into the index with one binary search and one
memmove, prepended to the batch list, and pushed on the stack.

### 4.4 Reclaim

`reclaim()` walks every data slab; metadata pages are never returned. It
first drains the class's free lists, so listed slots return to their blocks
and count as free; a slab with less than a page of slack, or with another
writer active, is skipped. Under the write guard, every batch whose blocks
are all empty and unowned is detached and the index and stack are rebuilt
from the survivors; after the guard, the detached data goes back to the
backend and the descriptors to the metadata slab.

### 4.5 Metadata slab

Same `Slab` code, 64-byte entries in 4 KiB page-sized blocks whose
descriptor is their own first entry, so the owner of a descriptor pointer is
`ptr & !(PAGE - 1)` and no index is needed. Initialization allocates the
shard array and the free lists, then the first metadata page, whose entries
`1..=SLABS` hold the slab table. Metadata growth allocates a page with no
lock held and links it under the metadata slab's write guard; the metadata
path is entered only with no data-slab lock held.

### 4.6 Statistics and realloc

The hot paths keep no counters. `stats()` sums bitmap popcounts over each
slab's batch list under its read guard; index arrays, the shard array, and
the free lists count as metadata, so a reclaim resident does not see them
as slack. Listed slots count as in use until reclaim drains them. `realloc`
returns the same pointer when both layouts map to the same class, and
otherwise allocates, copies, and frees.

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
Only then grow. Classes above 2 KiB have no private block: their tiers are
the shard's list, the shared path, the other lists, growth. A listed slot
is served as is; every slot of class `k` is `2^k`-aligned, so any layout
that maps to the class fits.

Free, in tiers: if the pointer lies in the thread's current block of that
class, flip the bit and return; the block is owned, so its descriptor is
stable, no guard is needed, and it is never full here. Otherwise push the
slot on the shard's list if the list is below its limit and not busy; the
slot stays marked in use, so nothing shared changes. Otherwise
`dealloc_to_slab` with the cache's shard: a free into a block another
thread owns just flips the bit, and the owner sees the slot on its next
allocation. The release re-check and the free's owner check both use
sequentially consistent operations, so a remote free that lands while a
block is being released is never lost.

Memory on a list is reachable from every thread: the tier before growth
scans the other shards, and reclaim drains every list before it looks for
empty batches. A per-thread list would keep other threads' frees where a
process at its admission floor cannot reach them; that is why the lists
are sharded by CPU. `release_cache` gives every private block back; the
cache may be used again afterwards. Listed slots need no release: they
belong to the shard, not the thread.

## 6. Process heaps

In `rt.vdso`, the runtime's per-thread block, reached through the `tls`
word of the thread control block, holds the TLS map and a `Cache4K`. It is
created on the thread's first allocation or TLS write, so the vDSO's own
threads and C threads are covered, and freed after the TLS destructors have
run and the cache is released. The global allocator fetches the cache and
sets its shard from `current_cpu` on every call; a thread without a block
uses the shared path, and frees never create one. The backend is `SysMem`
pages; a housekeeping resident calls `reclaim()` every five seconds when
the slack exceeds 1 MiB, or a page under kernel memory pressure.

## 7. The kernel heap

The kernel's `GlobalAlloc` is a `Frusa4K` over `RawAllocator`, a
page-granular backend that bumps from a 2 MiB boot area until memory is
initialized and then hands out `VmemKind::KernelHeap` pages; frees inside
the boot area are no-ops. Initialization takes about 28 KiB (reader
shards, free lists, one metadata page) plus a 4 KiB index per class on its
first growth, from the boot area when it precedes memory initialization.

Kernel code is never preempted and interrupt handlers do not allocate, so
an allocation on a CPU runs to completion before another can begin on that
CPU, a holder of an allocator lock is never descheduled, and
`arch::current_cpu()` is exact for the whole operation. That lets each CPU
keep a static stage in front of the allocator: a `Cache4K` whose guard
shard is the CPU, and per class a magazine of freed slots, a LIFO linked
through the slots' first words with the free-list limit of §2, popped and
pushed with plain loads and stores. Until CPU identity is valid
(`mm::cpu_initialized`, the condition the physical allocator's per-CPU
cursors also use) the shared path serves, so nothing runs at boot. The
stage is 192 bytes of static data per CPU; what all CPUs hold together is
bounded by the CPU count, and no CPU exits, so nothing needs flushing.
`realloc` keeps the same-class shortcut.

`kheap::reclaim()` has one caller, the reclaim syscall behind `sysbox
free`; there is no periodic reclaim and no pressure hook. It leaves what
the stages hold, since listed and magazine slots are marked in use and
owned blocks are skipped. `heap_stats()` reads the backend's page counter.
The kernel's hot paths are allocation-free by design; the per-call heap
user is the timed wait, which builds a BTreeMap node and a BTreeSet per
timer, and everything else allocates at object creation.

## 8. Tests and measurement

The crate's suite runs in `src/tests/full-test.sh` in both profiles. It
covers synthetic blocks and slabs, the index and stack invariants
(`check_invariants` under the write guard), retained populations with
churn and every free order, growth under concurrency, two-phase reclaim, a
backend that allocates from the allocator it backs, fault injection at
every backend call, cross-thread frees, the ownership protocol and its
transition race, every free-list rule of §2 and §5, and Frusa2M at small
populations. Work bounds are asserted with test-only counters (index
probes, stack entries examined, guards taken), never with wall-clock time.

`systest alloc-bench` prints per-workload timings on Motor for retained
populations, immediate alloc/free of one fixed size and of random sizes,
the 4 KiB class on every CPU, a FIFO queue, rings of live objects, and a
producer/consumer pair. A host harness with the same workloads compares the
crate's shared and cached paths against glibc over a common page backend;
it lives outside the repository.

Measured on the host (i9-10885H, release builds) and on Motor (release
image, QEMU with 4 vCPUs on the same host), nanoseconds per alloc+free
pair, one thread unless noted, per thread where several:

| Workload | glibc, host | frusa, host | frusa, Motor |
|---|---:|---:|---:|
| fixed 64 B | 6 | 21 | 30 |
| fixed 64 B, 8 threads (4 on Motor) | 10 | 19 | 30 |
| fixed 4 KiB, 8 threads (4 on Motor) | 37 | 22 | 30 |
| random 16 B to 4 KiB, 8 threads (4 on Motor) | 18 to 26 | 86 | 53 to 56 |
| FIFO queue of 64 x 64 B | 7.5 | 25 | 31 |
| ring of 4,096 live, random sizes, 1 thread | 49 | 43 | 60 |
| ring, 8 threads (4 on Motor) | 55 | 123 | 135 |
| free 262K x 64 B in random order, per free | 82 | 85 | - |

On Motor the temporaries row is about 9 ns above the host: the vDSO entry
path (vtable call, layout re-validation, shard store), the largest fixed
cost per operation. glibc leads on that row by the two locked instructions
of the bitmap path against none.

## 9. Known limits

Requests above 4 KiB are a `SysMem::alloc` and `SysMem::free` pair each on
Motor, where glibc serves up to 128 KiB from its heap. Power-of-two classes
waste up to half of each object. Index memory is 16 bytes per block. The
4 KiB class has no private block (caching it would hold 256 KiB per
thread), so its temporaries go through the free lists. Listed memory, at
most 16 KiB per list per class, is reported as in use until reclaim.
