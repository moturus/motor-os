# Frusa allocator scalability

Status: implemented on 2026-09-08 and 2026-09-09 as `frusa_v2`, which the
runtime now uses; the kernel keeps `frusa`. §10 records what landed, the
decisions that changed on the way, and the measurements. The augmented AVL
index from the first draft was set aside (§3.1); replacing Frusa with
another allocator was evaluated and rejected (§3.2). Phase E (§5.4) and the
Linux attribution build (§6 step 0) remain open.
This plan follows the root `AGENTS.md`. The issue was isolated on 2026-09-08
while investigating native rust-analyzer's remaining string-hover timeout.

## 1. Problem and evidence

Frusa's small-allocation size classes store their blocks in linked lists.
Each block contains 64 allocation slots and a usage bitmap.
`Slab::alloc` starts at the list head and searches for a free slot;
`Slab::dealloc` starts at the head and searches for the block owning a
pointer. Both paths can visit every block in the size class.

Consequently, a small allocation/free can cost O(B), where B is the number
of blocks, even when almost no memory is being changed. Freeing a population
of N allocations can require O(N × B) work. The problem is retained heap
size and allocation history, not just the number of concurrent threads.
The existing immediate-allocate/immediate-free speed tests exercise relatively
little retained memory and do not adequately cover this case.

### 1.1 Isolated allocator measurements

A release-mode Linux diagnostic calls the unmodified Motor Frusa4K directly,
with Linux `System` as its backing allocator. This separates the algorithm
from Motor syscalls, VM networking, and rust-analyzer.

For each population below, it retains 64-byte, 8-byte-aligned allocations,
repeatedly frees/replaces the allocation in the first retained slot 10,000
times, then frees the whole population in insertion order. That slot starts
with the oldest allocation; subsequent allocations can move to another block.
Pointer-vector bookkeeping uses the host allocator, not the measured Frusa.
The churn/free timings exclude initial population.

| Live allocations | System churn | Frusa churn | System free-all | Frusa free-all |
|---|---:|---:|---:|---:|
| 16,384 | 0.073 ms | 6.394 ms | 0.310 ms | 2.755 ms |
| 65,536 | 0.074 ms | 73.250 ms | 1.278 ms | 97.972 ms |
| 262,144 | 0.072 ms | 340.767 ms | 5.191 ms | 2,044.160 ms |

These are diagnostic measurements, not portable CI timing thresholds.
They demonstrate a substantial scalability problem even without Motor's
backing allocator.

### 1.2 Native rust-analyzer evidence

The same selected analyzer revision,
`75940756edd423d88ba353ce720770f3061b285a`, analyzes the Motor target on
Linux and Motor. Linux initially uses Cargo; Motor uses Lorry and the
packaged native server.

On Linux, workspace readiness takes 5.659 seconds, integer hover 1.933 ms,
the first plain-string hover 870.377 ms, generated-integer hover 0.878 ms,
and the subsequent `env!`-derived string hover 16.395 ms. Motor reaches
readiness in 18.396 seconds and answers integer hover in 1.946 ms, but
plain-string hover exhausts the unchanged 90-second whole-case deadline.
The failure is therefore not specific to `env!` or build-script data.

Forcing Linux to use a diagnostic rust-src copy without its workspace
manifest selects the same ten-crate stitched sysroot used on Motor. Its
plain-string hover still completes in 576.699 ms. The sysroot-loading
difference does not explain the native timeout.

Integers have a direct rendering path. Strings instead take
`hir::EvaluatedConst::render_debug` ->
`mir::render_const_using_debug_impl` -> MIR/type inference for
`std::fmt::format`. Native query profiling and two bounded debugger stack
captures show active syntax/AST-map construction during inherent-method
lookup, not the earlier child-cleanup deadlock. Each capture immediately
resumes the process.

In the second capture, the hover worker is walking the allocator's block
list during allocation, while `ParseNodeDropper` is doing so during free.
The packaged vDSO is stripped: identification uses disassembly, not
symbolized vDSO frames. Offset `0x7a564` is the allocation list walk;
`0x7abc0` is the deallocation range test/list walk. These correspond to
`Slab::alloc` and `Slab::dealloc` in
[src/sys/lib/frusa/src/lib.rs](../../src/sys/lib/frusa/src/lib.rs).

This establishes an allocator problem on the observed hover path. It does
not by itself quantify its share of total hover latency. §1.3 estimates the
share; §6 step 0 measures it before any allocator code changes.

Diagnostic source and evidence are currently under
`/tmp/motor-ra-hover.qAVs4I/`: `src/bin/allocator-probe.rs`,
`allocator.log`, `linux-all.log`, `motor-all.log`,
`linux-stitched.log`, their corresponding `stderr` files,
`profile-stacks-{1,2}.log`, and `profile-stack-2-symbols.log`.
These temporary files are not permanent test dependencies; retain the
reproduction in checked-in regression tests during implementation.

### 1.3 Expected magnitude in rust-analyzer

Both Frusa columns in §1.1 are consistent with about 4 ns per block visited.
At 262,144 live 64-byte allocations the class holds 4,096 blocks; the churn
loop visits 2 × 4,096 blocks per iteration, and the insertion-order free-all
visits 64 × 4,096² / 2 blocks in total.

| Quantity | Estimate |
|---|---|
| Cost per block visited | ~4 ns |
| Blocks in one busy class with a few hundred MB retained | 50K to 200K |
| One free of an old allocation | 0.2 to 0.8 ms |
| A hover that drops a parse tree of 10K to 100K nodes | seconds to a minute |

That is the order of the 90-second deadline, so the allocator is the likely
whole cause of the native timeout rather than one contributor. Step 0 in §6
is the cheap experiment that settles this before implementation starts.

## 2. Scope and constraints

Primary changes belong in `src/sys/lib/frusa`, with tests in its own
`src/tests.rs` and the crate's `cargo test` wired into
`src/tests/full-test.sh` in both profiles. That wiring does not exist today:
the gate never runs Frusa's tests. Measured on this host from the `src/sys`
workspace, the existing tests take about 2 s in debug and 22 s in release.

The runtime already uses Frusa4K in the vDSO and the kernel; no runtime API
change is proposed for phases A and B. Phase C (§5.2) adds a caller-supplied
per-thread cache to the crate's API and wires it in the vDSO runtime under
`src/sys/lib/rt.vdso`; that is a core-component change with its own review
and gates, and it needs no kernel, moto-rt, or standard-library change.
Frusa2M has no user in the repository. It shares the implementation and
receives correctness coverage at small populations, but it does not drive
the design or the test budget.

Preserve:

- `GlobalAlloc`, Frusa4K/Frusa2M construction, size classes, alignment, and
  direct fallback for requests outside the managed range;
- batch-granular reclamation and the meaning of the existing statistics
  fields (index memory is added, §4.8; in-use bytes become computed, §5.1);
- safe cross-thread frees, allocation failure handling, and concurrent
  reclaim;
- lazy initialization, with no new boot-time work;
- the native analyzer's existing timeout and resource limits.

Backing-allocator contract, currently implicit and now stated: a request
with 4 KiB alignment returns 4 KiB-aligned memory. Both in-tree backends
ignore `Layout::align` and satisfy this anyway (the vDSO's `SysMem::alloc`
and the kernel's page allocator return pages; the kernel's startup bump
allocator honors alignment explicitly), and the metadata slab already
depends on it. The plan adds a debug assertion at the backend boundary.

In scope as a consequence of the lock restructuring: item 2 of
[future-work.md](future-work.md), the slab lock held across the backend
syscall, with its self-deadlock and stuck-sibling failure modes.

Do not add a new allocator dependency, per-allocation header, mandatory
preallocation, or permanent runtime instrumentation. The crate itself takes
no thread-local dependency: the per-thread cache of §5.2 is owned and passed
in by the caller, so the kernel and the tests keep working without one.
No changes are proposed in external repositories, Rust stdlib, or moto-rt.
The only touch outside this repository is the uncommitted scratch build in
§6 step 0. Any other expansion requires separate review.

## 3. Design review

### 3.1 The augmented AVL index is set aside

The first draft proposed one intrusive, address-ordered AVL tree per size
class, augmented with a "subtree has a free slot" summary, under a per-slab
lock held for every allocation and free. Review findings, recorded so the
decision is not revisited by accident:

- The block set of a slab changes only when a batch is added or reclaimed.
  Both are rare and already serialized. O(log B) insert and delete buy
  nothing; rotations, parent links, and balance bookkeeping solve a problem
  the allocator does not have.
- The augmentation moves cost onto the hot path. Every full/non-full
  transition updates the ancestor chain under the lock, and the lookup is
  about 17 dependent cache misses at 100K blocks, on the order of a
  microsecond of lock hold per free. Today's allocation fast path is a
  lock-free CAS on the head block, and sys-io runs on the same vDSO
  allocator. The regression the draft's Decision 2 worried about was built
  into the design.
- Four entangled invariants (order, balance, parent links, summary
  correctness) instead of two independent ones. The draft's argument that a
  map plus a free list means more invariants is backwards.
- The metadata slab needs no index at all (§4.6); the draft planned tree
  work for its self-hosted first page.
- The draft left open what happens to the hot-path spin on the slab's
  locked marker during growth, kept the backend syscall under the growth
  lock and read guard, and did not account index memory in statistics.

A page-keyed radix tree was also considered: O(1) lookups and lock-free
growth, but about 0.2 percent of heap in index pages, a 48-bit address
assumption, and special handling for the two classes whose blocks are
smaller than a page. Not needed for the bound we want.

### 3.2 Replacing Frusa was evaluated and rejected

Measured on 2026-09-08 on the Linux host (16 cores, release builds), every
candidate over one common backend that hands out 4 KiB-aligned pages and
counts the bytes it holds. glibc is the reference. The harness is in the
session scratchpad under `allocbench/`; it is not checked in.

| Allocator | Free 262K × 64 B, insertion / random | 1 thread ns/op | 8 threads ns/op | Backend memory after freeing everything |
|---|---:|---:|---:|---|
| glibc malloc (reference) | 7.6 / 22 ms | 19 | 15 | not comparable |
| Frusa today | 2,122 / 2,129 ms | 54 | 506 | all returned by `reclaim()` |
| dlmalloc-rs 0.2.14 | 5.5 / 22 ms | 26 | 1,150 to 1,480 | nothing, even after trim |
| talc 5.1.0 | 4.5 / 16 ms | 35 | 1,216 to 2,528 | all returned automatically |
| rlsf 0.2.3 | 4.3 / 23 ms | 37 | 2,374 | nothing until drop |
| slabmalloc 0.11 | 6.0 / 7.7 ms | 50 | 1,044 | all returned on explicit reclaim |

The 8-thread column is immediate alloc/free of random 16 B to 4 KiB sizes.
A ring workload with 4,096 live objects per thread gives the same ordering.
Frusa beats glibc on three things: growing a fresh population (12 versus
26 ms for 262K objects), cross-thread producer/consumer frees (113 versus
350 ns per pair), and memory returned (glibc kept 20 of 24 MB after a
random-order free and used 40 percent more peak RSS with 8 threads).

Conclusions:

- Every no_std crate removes the retained-heap cost, and every one of them
  serializes all threads behind one lock, landing 2 to 5 times slower than
  today's Frusa at 8 threads. Only talc returns memory the way the vDSO's
  reclaim resident needs; rlsf never does and dlmalloc-rs's release path is
  unexercised by the std targets that use it (wasm, SGX, xous cannot unmap).
- glibc's hot path is a per-thread cache reached through native TLS. Motor
  has no native TLS: the loader rejects PT_TLS, Rust's `thread_local!` goes
  through the vDSO key map, and the C side compiles with emulated TLS. No
  allocator in any language reaches glibc's numbers on Motor without a
  per-thread slot the runtime provides itself.
- C allocators are not blocked by Rust interop but by their OS surface:
  jemalloc needs autoconf host support, partial unmap, madvise, and native
  `__thread`; Google's tcmalloc is Linux-only on rseq; mimalloc is the one
  that would fit, with a Motor primitives file and a TLS slot, at the cost of
  C inside the vDSO.
- Frusa's per-block atomic bitmap already gives lock-free same-block
  operation and the best cross-thread free of the group. What it lacks is
  bounded structures (§4), fewer shared-line atomics, and a per-thread fast
  path (§5). Those are additive changes to the existing design.

### 3.3 Where the 8-thread time goes today

One alloc+free pair on the immediate workload performs, on the 64-byte
`Slab` line shared by every thread in the class: two read-guard increments
and two decrements, one `bytes_in_use` add and one subtract. It also
performs one bitmap CAS on the head block, which every thread starts from,
and one bitmap xor on the freed block. Six contended read-modify-writes on
one line at 50 to 100 ns each under 8-way contention is the measured
506 ns; the O(B) walks are not the limit on this workload.

| Phase | Shared-line atomics per alloc+free pair | Notes |
|---|---:|---|
| Today | 6, plus a contended head-block CAS | measured 506 ns at 8 threads |
| A (§4) | 6, plus `partial_lock` on allocation | removes the walks, not the atomics |
| B (§5.1) | 4 | accounting moves to `stats()` |
| C (§5.2) | 2, on the free side only | allocation touches only the private block |
| D (§5.3) | 0 contended | guard sharded by CPU |

After D the remaining contention is inherent: two threads working on the
same block's bitmap, which only cross-thread frees cause.

## 4. Design: sorted block index and partial stack

Two independent structures per slab, each with one invariant:

- an address-sorted array of block pointers answers "which block owns this
  pointer" in at most ⌈log2 B⌉ + 1 probes, with no lock;
- a stack of blocks that have a free slot answers "which block can serve
  this allocation" in O(1), under a short spinlock.

Both are mutated wholesale only at growth and reclaim, which hold the slab's
write guard and therefore have exclusive access. Ordinary allocation and
free run under the read guard as today.

### 4.1 Data structures

`Block` keeps its 64-byte size and existing fields. Two of the four reserved
words are used: `partial_next: AtomicPtr<Block>`, the link used while the
block is on its slab's partial stack, and `owner: AtomicPtr<()>`, null
until §5.2 gives blocks a private owner. Two reserved words remain.

`Slab` keeps its 64-byte size and existing fields. The reserved 32 bytes
become:

| Field | Type | Meaning |
|---|---|---|
| `partial_head` | `AtomicPtr<Block>` | top of the partial stack |
| `index` | `AtomicPtr<*mut Block>` | sorted block index base; null until first growth; always null for the metadata slab |
| `index_len` | `AtomicU32` | entries in use |
| `index_cap` | `AtomicU32` | entries the array can hold; the array's byte size is `index_cap × 8` |
| `partial_lock` | `AtomicU32` | spinlock guarding the partial stack |

Four bytes stay reserved. The size assertions in `Frusa::new` are unchanged
and continue to enforce both sizes.

`head` stays the batch list used by reclaim. It is no longer a lock: the
`LOCKED_MARKER` value, `Slab::try_lock`, `Slab::unlock`, and
`Slab::add_blocks` go away. The marker remains only in `Frusa::init` for the
one-time construction of the slab array.

Index invariants:

- Entries `[0, index_len)` point to live descriptors of this slab and are
  strictly increasing by `data` address. Block data ranges are disjoint, so
  strict order holds.
- Every block on the batch list is in the index and every indexed block is
  on the batch list.
- The array is read under the read guard and written only under the write
  guard.

Partial stack invariants (all mutations under `partial_lock`, which is
taken only while holding the read guard; growth and reclaim mutate the stack
under the write guard instead, which excludes every holder of the read guard
and thus of `partial_lock`):

- A block is on the stack at most once.
- Every block with a free slot is on the stack, except in the window between
  a freeing thread's bitmap update and its push. Both happen under that
  thread's read guard, so growth and reclaim never observe the window.
- Every block on the stack has a free slot: allocations are served only from
  the stack top under the lock, and a block that becomes full is popped in
  the same critical section. Hence a free that makes a full block non-full
  is the only push, and it can never double-push.

§5.2 adds one clause: a block with a non-null owner is off the stack and is
the only place its owner allocates from.

The stack's head is never updated by CAS, so there is no ABA hazard, and
descriptors cannot be freed while any thread holds the read guard.

### 4.2 Allocation

`Slab::alloc`:

1. Load `partial_head` without the lock. Null means the slab has no free
   slot: return null and let the caller grow, without touching the lock.
2. Take `partial_lock`. Read the top. Claim a slot with the bitmap CAS loop
   (`Block::alloc` retries on a CAS failure caused by a concurrent free
   instead of returning null). A block on the stack is never full; if the
   top is full anyway, debug builds assert and release builds pop it and
   continue. If the block is now full, pop it. Release the lock.
3. Add the entry size to `bytes_in_use` (until §5.1) and return the pointer.

The critical section is a few loads and one CAS. The `bytes_in_use ==
bytes_total` early exit is replaced by the null check in step 1.

### 4.3 Deallocation

`Slab::dealloc` for a data slab:

1. Binary search the index for the greatest `data` not exceeding the
   pointer. No entry, or a pointer outside `[data, data + block_size)`,
   panics with the existing bad-pointer message.
2. Assert that the offset within the block is a multiple of the entry size.
   The current code does not check this; a misaligned free flips a wrong
   bit and is caught only by the used-bit assertion. The check is one AND.
3. `used_bitmap.fetch_xor(bit)`, asserting the bit was set as today. If the
   previous value was all ones, the block was full: take `partial_lock`,
   push, release.
4. Subtract from `bytes_in_use` (until §5.1).

No lock is taken unless the block was full, which happens at most once per
64 frees into a block.

### 4.4 Growth

Replaces `add_blocks_to_locked_slab`. `alloc_from_slab` becomes: take the
read guard; call `Slab::alloc`; release the guard; return on success;
otherwise grow and retry. No slab lock is held during steps 1 to 4 below,
which is the fix for `future-work.md` item 2: a backend that allocates
from Frusa while serving Frusa no longer self-deadlocks, and a thread killed
during the syscall leaves no sibling spinning.

1. Choose the batch size exactly as today (this reads `bytes_total`).
2. Request the data from the backend. Null returns an error.
3. Allocate and initialize `num_blocks` descriptors from the metadata slab,
   chained by `next` and by `partial_next` in batch order. On failure, free
   the descriptors already taken and the data, and return an error.
4. If `index_len + num_blocks > index_cap`, allocate a replacement array
   from the backend with capacity `max(2 × index_cap, 512)` entries, always
   a whole number of 4 KiB pages. On failure, free the batch and return an
   error.
5. Take the write guard (a blocking variant; §4.7). If another grower has
   meanwhile installed an array with enough capacity, keep that one;
   otherwise copy the entries into the new array and install it. Insert the
   batch: its blocks have consecutive data addresses, so one binary search
   gives the position and one memmove opens the gap. Prepend the batch to
   `head`. Splice the batch's `partial_next` chain onto the partial stack.
   Add to `bytes_total`. Release the guard.
6. Free a superseded or unused array after releasing the guard. Readers
   drained before the write section and later readers load the new pointer,
   so nobody can still hold the old one.

There is no growth gate. Two threads that both find the slab empty may both
add a batch; the duplicate is bounded by the number of concurrent threads,
is linked and used like any other capacity, and reclaim returns it when it
empties. The alternative, a try-lock gate whose losers wait during the
winner's syscall, keeps the deadlock class this step removes (§9 question 2).

### 4.5 Reclaim

`reclaim_slab` keeps its policy: skip a slab with less than a page of slack,
skip if another writer holds the slab, free only batches whose blocks are
all empty. It runs in two phases so that no slab lock is held across a
backend call; today the write guard is held across every backend free.

Under the write guard: walk the batch list. A batch is free when every
bitmap reads zero and, from §5.2 on, no block has an owner; exclusive
access makes the CAS marking dance in `maybe_free_batch` (mark every block
full, unmark on failure) redundant, and it is removed. Move each free batch
from `head` onto a private chain through its existing `next` links and
subtract it from `bytes_total`. Then rebuild both structures from the
surviving list: fill the index and sort it by data address with
`sort_unstable_by_key`; push every surviving non-full, unowned block onto a
fresh partial stack. Release the guard.

After the guard: for each detached batch, return its data to the backend
and its descriptors to the metadata slab. Concurrent allocation and growth
cannot reach these batches; they left the index, the stack, and the batch
list under the guard.

The sort makes the guarded phase O(B log B) where the walk was O(B). A
one-pass compaction that decides, compacts, then detaches is the O(B)
alternative if step 7 shows reclaim time matters (§9 question 5).

### 4.6 Metadata slab

The metadata slab runs the same `Slab` code with two differences.

Owner lookup needs no index. Each metadata block is one page-aligned 4 KiB
page whose descriptor is its own first entry, so the owner of a descriptor
pointer is `ptr & !(PAGE_4K - 1)`. The lookup validates that the candidate's
`data` equals the page base before touching the bitmap. `index` stays null.

Growth allocates one page from the backend with no lock held, initializes
it, then links and pushes it under the metadata slab's write guard. Metadata
allocation and free take the metadata slab's read guard (today they take no
guard), so the protocol is uniform. `do_init` initializes every new `Slab`
field of the manually constructed slab array and every new `Block` field of
the first page, then links that page through the same routine as growth.

The metadata path never touches a data slab's locks, and it is entered only
with no data-slab lock held: growth allocates descriptors before taking its
guard, and reclaim returns them after releasing its guard. Metadata reclaim
stays unimplemented, as today; the batch list is kept for it.

### 4.7 Locks and ordering

Per slab there are exactly two locks: the existing `reclaim_lock` rwlock and
the new `partial_lock` spinlock.

| Path | Locks, in order |
|---|---|
| Allocation | read guard, then `partial_lock` |
| Free | read guard, then `partial_lock` only on a full-to-non-full transition |
| Growth link step | write guard alone (exclusive; no `partial_lock`) |
| Reclaim | write guard alone, try-only, skip if busy |
| Metadata slab | the same table with its own two locks |

Rules:

- The read guard means "descriptors and the index are stable"; the write
  guard means "nobody else is in this slab".
- No lock of any slab is held across a backend call or a metadata-slab
  call made on behalf of a data slab. Growth allocates before taking its
  guard; reclaim frees after releasing its guard.
- A write guard is never requested while holding a read guard or
  `partial_lock` of the same slab. `alloc_from_slab` releases the read guard
  before growing.
- `rwlock.rs` gains a blocking `write_lock` for growth. Reclaim keeps
  `single_write_lock`, which fails instead of waiting when another writer
  holds the slab.
- Hot paths never spin on a growth lock. The current spin on
  `LOCKED_MARKER` in `Slab::alloc` and `Slab::dealloc` is removed.

The kernel's allocator keeps the same constraint it has today with the
existing spin locks: interrupt handlers must not allocate. Nothing new.

### 4.8 Statistics and memory

Index arrays are backend allocations. `stats()` adds each data slab's
`index_cap × 8` to `allocated_from_fallback` and to `allocated_metadata`;
`in_use` and `in_use_metadata` are unchanged. The vDSO reclaim resident's
slack formula in `rt_alloc.rs` subtracts `allocated_metadata` from
`allocated_from_fallback`, so index pages do not count as reclaimable and do
not cause idle reclaim calls.

Costs: 8 bytes per block, which is 8 bytes per 64 allocations (0.8 percent of
heap for the 16-byte class, 0.2 percent at 64 bytes, less above). The first
growth of a data slab takes one 4 KiB index page; a process that uses all
nine Frusa4K classes pays at most 36 KiB, lazily. The kernel's bootup heap is
at least 2 MiB, so startup allocations are unaffected. `test_init`'s exact
byte expectations change to include the index page.

### 4.9 Behavior changes to confirm

- `Block::alloc` retries its CAS instead of returning null on contention;
  the "use another block" fallback is gone.
- Concurrent growers can add duplicate batches (§4.4).
- Threads no longer stall during another thread's growth syscall.
- Misaligned frees panic (§4.3 step 2).
- Reclaim's CAS marking is removed, and its backend frees happen after the
  guard is released.
- Metadata allocation and free take the metadata rwlock.

### 4.10 Fast path

The first revision proposed a lock-free peek of the partial stack as a
follow-up. It is superseded by the private blocks of §5.2, which remove the
shared structures from the allocation fast path entirely rather than
touching them without a lock.

## 5. Beyond the O(B) fix

Phase A is §4. The phases below are ordered by payoff per line and by risk,
each gated on the measurements of the one before it. §3.3 gives the atomics
budget each phase is expected to reach.

### 5.1 Phase B: cheaper shared state

- **Computed in-use bytes.** Drop the per-operation `bytes_in_use`
  add/subtract. `stats()` computes in-use bytes by summing bitmap popcounts
  over each slab's index under its read guard: O(B), about 100 µs at 100K
  blocks, and the reclaim resident calls it once every five seconds. The
  value stays exact at the time of the call. `bytes_total` is touched only
  at growth and reclaim. This frees one `Slab` word.
- **Same-class realloc.** Override `realloc`: when the old and new layouts
  map to the same class, return the same pointer. Today the default
  alloc-copy-free runs even when nothing would move.
- **Batch sizing.** Small classes grow by 4 KiB and then 32 KiB batches;
  larger classes by one block. A 500 MB heap of small objects means on the
  order of 16K growth syscalls, each an eager mapping. Let the batch grow
  with the class's total: 4 KiB, 32 KiB, 256 KiB, with the largest tier and
  2 MiB mid pages an open question. The tradeoff is reclaim granularity: a
  batch is returned only when all of its blocks are empty. The index and
  reclaim do not depend on batch size, so both settings are measured with
  the same code.
- **Lazy backend mapping, optional.** The vDSO backend maps eagerly, which
  commits and zeroes every page at growth, while the kernel offers lazy
  mapping that the C runtime already uses. For batches of 256 KiB and up,
  lazy mapping defers the cost to first touch and avoids committing unused
  pages. This is a change in `rt_alloc.rs`'s backend, not in Frusa, and is
  measured on Motor before adoption.

### 5.2 Phase C: per-thread private blocks

The idea from glibc, mimalloc, and SLUB, reduced to what Frusa's atomic
bitmap already permits: a thread allocates from one privately held block
per class without touching any shared structure, and frees go straight to
the owning block's bitmap from any thread, as they do today.

**Crate API.** A `ThreadCache<const SLABS: usize>` holding one `current`
block pointer per class plus a `shard` index for §5.3, about 80 bytes for
Frusa4K. The crate never looks it up; the caller owns it and passes it in:
`alloc_cached(&self, cache, layout)`, `dealloc_cached(&self, cache, ptr,
layout)`, `realloc_cached`, and `release_cache(&self, cache)`. The
`GlobalAlloc` implementation stays the uncached path of §4, used by the
kernel, by the tests, and by any thread without a cache.

**Allocation fast path.** Under the read guard: load `current[class]`; if
non-null, claim a slot with the bitmap CAS and return. No shared line is
touched. On null or full: release ownership of the old block, pop a block
from the partial stack under `partial_lock`, set its owner to this cache,
store it in `current`, retry. An empty stack grows the slab through the
§4.4 path and retries.

**Ownership.** The `owner` word of §4.1 names the cache that holds a block.
Set under `partial_lock` when a block is popped; cleared with a
compare-and-swap from this cache to null when the block is dropped, so a
stale clear can never remove another cache's ownership. Consequences:

- Reclaim skips a batch if any block has an owner, so a privately held
  block is never freed under its owner.
- A full block is dropped; ownership is cleared; the first remote free that
  makes it non-full pushes it onto the partial stack as in §4.3, and any
  thread may take it. This is the existing transition mechanism; nothing
  new is needed for orphaned blocks.
- The race where a remote free pushes a full-but-still-owned block, another
  thread pops and claims it, and then the first owner's clear runs, is
  resolved by the compare-and-swap: the late clear fails and the new owner
  stands.
- Invariant added to §4.1: a block with an owner is off the stack and is
  allocated from only by its owner; a non-full block is either on the stack
  or owned.

**Frees.** `dealloc_cached` is `dealloc` (§4.3) plus the shard index. A free
into a privately held block flips the bit and the owner sees the free slot
on its next allocation from that block. Cross-thread frees stay lock-free,
which is the property that already beats glibc in §3.2. The cost is that a
producer/consumer pair share a bitmap line while working on the same block;
that is inherent and bounded to one block at a time.

**Class policy.** Cache only classes with entries of 256 bytes and below,
whose blocks are 1, 2, 4, 8, and 16 KiB. The worst case held by an idle
thread is then 31 KiB. Larger classes use the shared path under
`partial_lock`; they are rarer by count. The threshold is one constant,
chosen by measurement (§9 question 12).

**Thread exit.** `release_cache` clears ownership of every held block and
pushes the non-full ones back onto their partial stacks under
`partial_lock`. Full ones just lose their owner. Allocations after release
fall back to the uncached path.

**vDSO wiring.** The runtime already owns the `tls` word of the thread
control block: `rt_tls.rs` stores its per-thread map pointer there. Replace
that pointer with a runtime-private per-thread block holding the map
pointer and a `ThreadCache<9>`, created at thread start in the trampoline
in `rt_thread.rs` and for the initial thread at runtime initialization, and
released after `on_thread_exiting` has run the TLS destructors, since
destructors may allocate. The control block is reached with one `rdfsbase`.
The `#[global_allocator]` in `rt_alloc.rs` becomes a wrapper that fetches
the cache and calls the cached entry points; a thread with no block uses
the uncached path. C threads reach the runtime through
`moto_rt_thread_spawn`, so they get a block too. No kernel, moto-rt, or
control-block layout change; a kernel-side slot is the alternative in §9
question 11.

**Kernel.** Unchanged in this plan. Per-CPU caches through the same API are
possible later because every block operation is atomic, so a context that
migrates mid-allocation only ever uses another CPU's block safely; the
interrupt and preemption rules need their own review.

**Tests.** On Linux the cache lives in a `thread_local!`. Cover: fast-path
allocation without a shared write, ownership set and cleared, remote frees
into an owned block, the transition race above under many threads, reclaim
skipping owned batches, `release_cache` returning every non-full block, no
non-full block ever off the stack without an owner (checked under the write
guard), and threads that exit with held blocks.

### 5.3 Phase D: sharded read guard

After Phase C the only shared-line atomics on a same-thread path are the
free side's read-guard increment and decrement. Replace the per-slab reader
count with `SHARDS` cache-line-sized counters per slab, 16 to start,
allocated once at initialization from the backend (16 × 64 B × 10 slabs is
10 KiB per instance) and reached through one pointer in `Frusa`, not in
`Slab`. A reader increments and decrements `shards[cache.shard]`; the vDSO
fills `shard` from the `current_cpu` field of the thread control block on
each call (one load), the kernel from its CPU id, and the uncached path uses
shard zero. The writer sets its bit in `reclaim_lock` as today, then waits
until every shard reads zero. Growth and reclaim are rare, so the writer's
extra cost is irrelevant.

With this, a same-thread alloc and free perform no contended atomic. Two
threads that migrate onto the same CPU share a shard line without any
correctness consequence.

### 5.4 Phase E, optional: finer size classes

Power-of-two classes waste up to half of each object and about a quarter on
average for mixed sizes. Four classes per doubling above 64 bytes (64, 80,
96, 112, 128, and so on) bring that to about an eighth. Costs: Frusa4K goes
from 9 to about 30 slabs (the slab array still fits the first metadata
page); batches must be page multiples of non-power-of-two block sizes (80
byte entries give 5 KiB blocks and 20 KiB batches); and a request with
alignment above 16 must round to a power-of-two class. Measure with the
native rust-analyzer's peak memory from the 8 GiB runs before deciding. Not
scheduled.

## 6. Implementation plan

Patches are 100 to 300 lines including tests, in the order below. Each patch
that touches `src/sys` passes `src/tests/full-test.sh` three times in debug
and three times in release before it is committed, is formatted with the
repository-selected toolchain, and adds no compiler or Clippy warnings. No
new test reaches the Internet. Stop for review on any non-obvious decision,
any pre-existing bug, and any reproducible performance regression. Every
phase ends with the step 7 comparison rerun and, from phase C on, a Motor
measurement.

### Phase A: bounded structures (§4)

**Step 0. Attribution on Linux, uncommitted.** In a scratch copy of the
pinned rust-analyzer revision, set `frusa::Frusa4K` over `System` as the
binary's global allocator, build the Linux host server, and run the same
plain-string hover case through the smoke harness. Record readiness and
hover timings beside the 870 ms baseline in §1.2. If hover balloons to the
same order as the Motor timeout, the allocator is the whole cause, and this
build is the minutes-scale check for every later step. This patches an
external tree; it is a diagnostic only and is not committed anywhere.
Decision: §9 question 1.

**Step 1. Reproduction tests and gate wiring.** Add a retained-population
test to `tests.rs`: 64-byte allocations, 16K in debug and 64K in release;
churn slot zero 10,000 times; free in insertion, reverse, and seeded-random
order; a sparse-holes case that frees one slot per block and reallocates
them. Assert disjoint ranges, payload retention, and statistics; print
timings, and keep the release output as the step 7 baseline; no wall-clock
assertion. Add the test-only work-counter scaffold:
`#[cfg(test)]` statics with a helper that compiles to nothing otherwise.
Wire `cargo test --manifest-path src/sys/lib/frusa/Cargo.toml` into
`full-test.sh` for both profiles. No allocator change.

**Step 2. Partial stack for allocation.** Add `partial_next`,
`partial_head`, `partial_lock`, the spinlock helpers, and push/pop/splice.
Initialize the new fields in `Block::init`, `Slab::new`, and `do_init`.
Switch `Slab::alloc` to §4.2 and add the transition push to `Slab::dealloc`
(still finding the owner by list walk). Growth pushes its batch under
`partial_lock`; reclaim rebuilds the stack under its write guard. Tests:
stack unit tests on synthetic blocks, a stack invariant checker used by
the retained test, and the allocation work counter asserting one stack
entry examined per allocation. Allocation is O(1) after this step; free is
still O(B).

**Step 3. Growth outside the locks.** Restructure `alloc_from_slab` and
growth to §4.4 without the index: allocate the batch with no lock held, add
`write_lock` to `rwlock.rs`, link under the write guard, remove
`LOCKED_MARKER` and the `try_lock`/`unlock`/`add_blocks` trio from `Slab`,
and move the metadata slab to the same protocol (§4.6, without the page-mask
lookup yet). Free still walks the list, now stable under the read guard.
Tests: rollback on injected failure at each growth stage (data, each
descriptor); many threads growing an empty slab with every allocation
succeeding and `bytes_total` equal to the sum of batches; a test backend
that, once per request, allocates and frees an object of the requested
layout from the Frusa it backs, which deadlocks today and must complete
here. This closes `future-work.md` item 2 for growth.

**Step 4. Reclaim in two phases.** Restructure `reclaim_slab` and
`maybe_free_batch` to §4.5 without the index: detach under the guard,
rebuild the partial stack, free after the guard, drop the CAS marking.
Tests: reclaim while other threads allocate and free in the same class,
checked with the stack invariant checker; the nested-allocation backend on
the free path; statistics and address reuse after reclaim. Item 2 of
`future-work.md` is closed after this step.

**Step 5. Sorted block index.** Add the index fields, array allocation and
replacement, insertion at growth, rebuild at reclaim, the §4.3 lookup with
range and alignment validation, the metadata page-mask lookup, the backend
alignment debug assertion, statistics accounting, and the `test_init`
update. Remove the list walk from `Slab::dealloc`. Tests: lookup at the
first and last byte of every block in several batches, a `should_panic`
case for a pointer between batches, index invariants after growth, reclaim,
and seeded random operations, array replacement while other threads free,
injected index-array failure with the batch fully rolled back, and the free
work counter asserting at most ⌈log2 len⌉ + 1 probes. Free is O(log B)
after this step. This patch is the largest and may approach the 300-line
ceiling; §9 question 7.

**Step 6. Coverage.** Frusa2M at bounded populations for every managed size
and the fallback boundary; cross-thread frees; concurrent allocation, free,
and reclaim with both invariant checkers; the flaky backend across growth,
index replacement, and metadata growth.

**Step 7. Performance comparison.** Same host, release builds, fixed seeds,
baseline and candidate runs interleaved (A/B/A) so that a host-level
throughput shift is not read as a regression. Compare against the step 1
baseline: the existing concurrent speed test at 1, 2, 4, and 8 threads; the
retained populations of §1.1; mixed lifetimes; growth and reclaim time;
memory and metadata overhead. Report same-class contention and the largest
Frusa2M classes separately, not in aggregate. Any reproducible regression
stops for review rather than being traded away.

**Step 8. Native rust-analyzer validation.** Rebuild the developer image,
run the packaged native analyzer, restore the queued environment-string
hover assertion in its multi-root LSP case, and pass
`src/tests/full-test-dev.sh --release`. The 90-second whole-case bound and
the approved memory, thread, and image limits are unchanged. If hover still
fails, keep the evidence and continue the diagnosis without raising the
deadline. Full native completion remains tracked in
[rust-analyzer.md](rust-analyzer.md).

### Phase B: cheaper shared state (§5.1)

**Step 9. Computed in-use bytes and same-class realloc.** Remove the
`bytes_in_use` atomics from both hot paths, compute the value in `stats()`
from bitmap popcounts under the read guards, and override `realloc` for the
same-class case. Tests: statistics exactness against a shadow count under
concurrent operations; realloc within and across classes preserving
contents; the existing `test_init` expectations. About 120 lines.

**Step 10. Batch sizing.** Add the growth tiers of §5.1 behind one table of
constants, with the reclaim-granularity effect measured on the retained
workload and on a grow-then-free-half workload. Lazy backend mapping, if
approved, is a separate small patch in `rt_alloc.rs` measured on Motor with
the systest allocation cases. About 80 lines each.

### Phase C: per-thread private blocks (§5.2)

**Step 11. Crate API.** `ThreadCache`, the `owner` word and its
compare-and-swap protocol, reclaim skipping owned batches, the cached entry
points, `release_cache`, and the class threshold constant. The
`GlobalAlloc` path is unchanged. Tests as listed in §5.2, with the cache in
a `thread_local!`. Likely two patches: ownership and reclaim first, the
cached entry points second, so that the first is a behavior-preserving
change.

**Step 12. vDSO wiring.** The runtime per-thread block replacing the map
pointer in `rt_tls.rs`, its creation in the `rt_thread.rs` trampoline and at
runtime initialization, release after the TLS destructors, and the wrapper
global allocator in `rt_alloc.rs`. This is a `src/sys/lib/rt.vdso` change:
full gate three times per profile, the developer-image gate in release, the
systest thread and allocation cases, and the native analyzer run. About
150 lines.

### Phase D: sharded read guard (§5.3)

**Step 13. Shards.** The shard array, its allocation at initialization,
reader increment and decrement through `cache.shard`, the writer drain, and
the `current_cpu` load in the vDSO wrapper. Tests: many readers on distinct
shards against a writer, the drain completing under churn, and a debug
assertion that no shard goes negative. About 150 lines. Measured on the host
at 1, 2, 4, and 8 threads and on Motor with the systest cases.

## 7. Validation and acceptance

Deterministic correctness and complexity tests cover:

- both Frusa variants, every managed size and alignment boundary, and the
  fallback path;
- index order, length, and one-to-one correspondence with the batch list
  after growth, reclaim, array replacement, and randomized operations;
- partial stack membership: at most once, every non-full block present or
  owned outside a freeing thread's window, no full block present;
- disjoint live allocations, payload retention, accounting, and address
  reuse after reclaim;
- owner lookup in at most ⌈log2 len⌉ + 1 probes and allocation examining
  one stack entry, measured with test-only counters, never wall-clock;
- all-full, one-hole, alternating-hole, and widely separated-hole
  populations;
- cross-thread frees, concurrent allocation, free, and reclaim, partial
  batches, and descriptor reuse after reclaim;
- injected backend and metadata failures at every growth stage, including
  the index array, with rollback and no dangling index entry or stack entry;
- the nested-allocation backend that deadlocks today;
- from phase C: ownership, remote frees into owned blocks, reclaim skipping
  owned batches, release at thread exit, and the transition race;
- from phase D: shard accounting under a concurrent writer.

Performance comparisons follow step 7 and are rerun at the end of
every phase, on the host and, from phase C, on Motor. Gates follow the
rules at the top of §6; the developer-image gate runs in release only, as
`AGENTS.md` requires for work that is not Lorry work.

Targets, all to be measured rather than assumed: after phase A, the
retained workloads of §1.1 within a factor of two of talc and dlmalloc;
after phase D, the 8-thread same-thread workloads within a small factor of
glibc on the host, and the cross-thread producer/consumer case no worse
than today.

## 8. Risks

- **Same-class lock contention** on `partial_lock` at 8 threads in phase
  A. The critical section is an order of magnitude shorter than the
  existing cache-line traffic per operation, so a large regression is
  unlikely; phases C and D remove the lock from the fast path.
- **Duplicate batches** under concurrent growth (§4.4). Bounded and
  reclaimable; the alternative keeps a deadlock class.
- **Reclaim cost** rises from O(B) to O(B log B) through the sort. Reclaim
  runs on a five-second cadence and only above a megabyte of slack; the
  one-pass compaction is the fallback.
- **Memory held by idle threads** in phase C: at most 31 KiB per thread
  with the 256-byte threshold, not reclaimable while held.
- **Ownership protocol errors** in phase C would surface as reclaim freeing
  a held block. The invariant checker and the transition-race test are the
  defense, and the owner word makes the check one load per block.
- **Runtime change surface** in step 12: thread start and exit paths in the
  vDSO touch every process. The gate and the systest thread cases cover it;
  a thread without a block always has the uncached path.
- **Step 5 size.** If it cannot be split without a temporary dead-code
  allowance, it goes in as one reviewed patch.

## 9. Open questions

1. **Run step 0 before implementation?** It needs an uncommitted patch to
   the pinned rust-analyzer binary crate in a scratch copy of an external
   tree. Recommended: yes, it is the cheapest decisive test and the fastest
   post-fix check.

OK

2. **Growth without a gate.** Accept bounded duplicate batches under
   contention in exchange for removing the syscall-under-lock deadlock, or
   keep a try-lock gate whose losers wait through the winner's syscall?
   Recommended: no gate.

OK
  
3. **Index memory in statistics.** Fold it into `allocated_metadata` as in
   §4.8, or add a new `FrusaStats` field? Recommended: fold it in; nothing
   else changes.

OK
  
4. **Initial index page per slab.** One lazy 4 KiB page per used data slab,
   at most 36 KiB per process, or carve small initial indexes from a shared
   page at the cost of a second allocation path? Recommended: one page.

OK
  
5. **Reclaim rebuild.** Sort-based rebuild, the least code, or the O(B)
   three-pass compaction? Recommended: sort, then measure in step 7.

OK
  
6. **Metadata slab under the rwlock.** Uniform protocol as in §4.6, or keep
   metadata operations guard-free with a `partial_lock`-only link path and a
   second growth routine? Recommended: uniform.

OK
  
7. **Step 5 size.** Accept one patch near 300 lines, or split it with a
   temporary `#[allow(dead_code)]` that names the follow-up patch?
   Recommended: one patch.

OK
  
8. **Behavior changes in §4.9**, in particular the panic on misaligned frees
   and the CAS retry in `Block::alloc`. Any caller that depends on the old
   behavior?

What is the simplest correct behavior? Use it.
  
9. **Gate cost.** Frusa's tests add about 2 s to the debug gate and about
   22 s to the release gate on this host, before the new tests. Acceptable?

No; why release gate is so slow vs debug? Usually debug tests are slower...
  
10. **Frusa2M.** Keep it with light coverage, or retire it in a separate
    change since nothing in the repository uses it?

Keep it with light coverage.
    
11. **Per-thread slot.** Use the runtime-owned `tls` word of the thread
    control block as in §5.2, which changes only the vDSO, or add a
    dedicated control-block field with a kernel version bump? Recommended:
    the runtime word; a kernel field can come later if C runtimes need it.

use vdso-only approach
    
12. **Cached class threshold.** Entries of 256 bytes and below, holding at
    most 31 KiB per idle thread, or up to 1 KiB, holding at most 127 KiB?
    Recommended: 256 bytes, then measure.

Ok
    
13. **Shard count.** Sixteen fixed shards, or the CPU count read at
    initialization? Recommended: sixteen; two threads sharing a shard only
    share a line.

CPU count
    
14. **Batch tiers and lazy mapping.** Approve the 4, 32, 256 KiB tiers and
    the lazy-mapping experiment in `rt_alloc.rs`, or keep today's sizing?
    Recommended: measure both in step 10.

measure both
    
15. **Phase E.** Worth measuring finer size classes against rust-analyzer's
    peak memory, or leave power-of-two classes? Recommended: measure only
    after phase D lands.

ok
    
16. **Kernel caches.** Confirm the kernel stays on the uncached path in this
    plan. Recommended: yes.

the kernel keep using old frusa; this is new frusa, create frusa_v2 crate
(motor-os only; publishing to crates.io is not in scope)

## 10. Implementation record (2026-09-08)

What landed, as `frusa_v2` beside the unchanged `frusa` that the kernel
keeps:

| Patch | Content |
|---|---|
| 1 | Crate skeleton, readers/writer guard, partial-stack spinlock, block descriptor |
| 2 | Slab: batch list, partial stack, address-sorted index |
| 3 | Allocator core: growth with no lock held, computed statistics, same-class realloc, batch tiers |
| 4 | Two-phase reclaim; readers back off while a writer drains; index capacity re-checked under the guard |
| 5 | Fault-injection sweep, work-bound counters, cross-thread frees, Frusa2M reclaim; both allocators wired into the gate |
| 7 | Per-thread private blocks (phase C) |
| 8 | CPU-sharded reader counts (phase D) |
| 8a | Growth gives back a batch when another grower refilled the stack |
| 9 | `rt.vdso` switches to `frusa_v2`; a per-thread block holds the TLS map and the allocator cache |
| 10 | `systest alloc-bench`, the host harness's workloads on Motor |

Phase B's computed statistics, same-class realloc, and batch tiers went into
patch 3 rather than a separate phase, since the crate was new. Step 0 of §6
(the Linux attribution build) was not run: the allocator's share was
established directly by the before/after measurement on Motor below.

Decisions that changed during implementation:

- **Workspace membership.** `src/sys/Cargo.toml` is a toolchain runtime
  input; adding a member there invalidates the pinned assembly and forces a
  toolchain assembly rebuild. `frusa_v2` is therefore not listed as a member
  and joins the workspace as `rt.vdso`'s path dependency; before that
  dependency existed it built as its own root.
- **Duplicate batches.** Ungated growth stayed (§4.4), but a grower that
  finds the partial stack refilled when it takes the write guard returns its
  batch to the backend instead of linking a second one.
- **Thread block creation.** The runtime creates a thread's block on its
  first allocation or TLS write rather than at thread start, so the vDSO's
  own threads and C threads are covered without touching every spawn path.
  Frees never create one, so a thread whose block was released at exit does
  not get a new one for a late free.
- **Test isolation.** Test-only work counters are thread-local and tests
  that share a static allocator were merged, since the suite runs in
  parallel.

### 10.1 Host measurements

Linux host, 16 cores, release builds, common 4 KiB page backend with byte
counting; `v2 cached` uses one `ThreadCache` per thread with its own guard
shard. Retained figures are for 64-byte objects.

| Workload | frusa | frusa_v2, shared path | frusa_v2, cached |
|---|---:|---:|---:|
| Churn on the oldest slot, 262K live, 10K rounds | 357 ms | 0.76 ms | 0.99 ms |
| Free all, 262K, insertion order | 1,995 ms | 10.0 ms | 9.5 ms |
| Free all, 262K, random order | 2,018 ms | 26.3 ms | 27.2 ms |
| Backend bytes at 262K live / after reclaim | 16.3 MB / 0.3 MB | 16.3 MB / 0.3 MB | 16.3 MB / 0.3 MB |
| Immediate alloc+free, 1 thread | 54 ns | 57 ns | 56 ns |
| Immediate, 8 threads, per thread | 507 ns | 465 ns | 332 ns |
| Ring of 4,096 live objects, 1 thread | 70 ns | 86 ns | 97 ns |
| Ring, 8 threads, per thread | 1,025 ns | 688 ns | 674 ns |
| Producer/consumer cross-thread pair | 110 ns | 112 ns | 79 ns |

The retained-heap pathology is gone: churn and free-all are 200 to 470
times faster and now scale with the population. Single-thread immediate
cost is unchanged; the single-thread ring is 20 to 40 percent slower because
each free pays a binary search over the index. Eight-thread throughput
improves 1.5 times, not the order of magnitude glibc's thread cache shows,
because the immediate workload draws half its sizes above the 256-byte
cache threshold and so takes the shared path under the partial lock. Peak
process RSS in this harness is set by the cross-thread queue depth, not by
the allocator, so backend bytes are the memory comparison.

### 10.2 Motor measurements

`systest alloc-bench` on the release image, QEMU with 4 vCPUs, two runs
each; first run shown, the second within 5 percent except where noted.

| Workload | frusa (old vDSO) | frusa_v2 (new vDSO) |
|---|---:|---:|
| Free all, 65K retained, insertion order | 107 ms | 2.3 ms |
| Free all, 65K retained, random order | 106 ms | 5.5 ms |
| Populate 65K after a random free-all | 109 ms | 1.9 ms |
| Immediate, 1 thread | 57 ns | 61 ns |
| Immediate, 2 threads, per thread | 186 ns | 119 ns |
| Immediate, 4 threads, per thread | 372 ns | 216 ns |
| Ring of 4,096 live, 1 thread | 88 ns | 107 ns |
| Ring, 4 threads, per thread | 584 ns | 429 ns |
| Producer/consumer cross-thread pair | 121 ns | 87 ns |

The second frusa_v2 run's single-thread retained figures were two to three
times the first (still 20 to 50 times faster than frusa); the threaded
figures were stable.

### 10.3 Gates

Patch 5: three debug and three release `full-test.sh` runs. Patches 9 and
10: three debug and three release `full-test.sh` runs and one
`full-test-dev.sh --release`. Every crate patch: three debug and three
release runs of the crate's own suite, Clippy clean, no build warnings.

### 10.4 Native rust-analyzer

With the new runtime allocator, the maintained native LSP case passes with
the `env!`-derived string-hover assertion restored. The hover that
exhausted the unchanged 90-second whole-case deadline under `frusa` (§1.2)
answers in 920 ms on Motor, against 870 ms for the first plain-string hover
on Linux. First completion after it takes 1.2 ms. The release
developer-image gate passed twice with the new allocator, once before and
once after the assertion was restored.
