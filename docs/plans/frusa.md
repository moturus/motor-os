# Frusa allocator scalability

Status: proposed; awaiting design review. No allocator code has been changed.
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
not quantify its share of total hover latency or prove that fixing it alone
will meet the native bound. An end-to-end before/after comparison is required.

Diagnostic source and evidence are currently under
`/tmp/motor-ra-hover.qAVs4I/`: `src/bin/allocator-probe.rs`,
`allocator.log`, `linux-all.log`, `motor-all.log`,
`linux-stitched.log`, their corresponding `stderr` files,
`profile-stacks-{1,2}.log`, and `profile-stack-2-symbols.log`.
These temporary files are not permanent test dependencies; retain the
reproduction in checked-in regression tests during implementation.

## 2. Scope and constraints

Primary changes belong in `src/sys/lib/frusa`, with focused host and native
tests wired directly or transitively into `src/tests/full-test.sh`.
The runtime already uses Frusa4K; no runtime API change is proposed.
Frusa2M shares the implementation and must receive the same correctness
coverage, using appropriately bounded test populations for large classes.

Preserve:

- `GlobalAlloc`, Frusa4K/Frusa2M construction, size classes, alignment, and
  direct fallback for requests outside the managed range;
- existing batch allocation/reclamation policy and statistics semantics;
- safe cross-thread frees, allocation failure handling, and concurrent reclaim;
- lazy initialization, with no new boot-time work;
- the native analyzer's existing timeout and resource limits.

Do not add a new allocator dependency, per-allocation header, thread-local
cache, mandatory preallocation, or permanent runtime instrumentation.
No changes are proposed in external repositories, Rust stdlib, or moto-rt.
Any necessary expansion into those areas or other runtime code requires
separate review.

## 3. Proposed design: one augmented block index

Replace hot-path linked-list searches with an intrusive, address-ordered
AVL tree per size class. Each node is an existing block descriptor, keyed by
its data-range start. Augment each node with whether its subtree contains
a block with a free slot.

This single index answers both questions:

- Free: find the greatest block start not exceeding the pointer, then validate
  its range and slot alignment before updating the bitmap.
- Allocate: descend only into subtrees marked as having free space, then
  claim a slot in the selected block.

Both searches become O(log B), independent of where the free slot or pointer
lies in the old list. Bitmap transitions between full and non-full update
the subtree summary along the ancestor path. AVL rotations maintain both
height/balance information and that summary. This is a structural bound,
not a claim of bounded wall time under scheduling or lock contention.

Retain the existing batch-ordered linked list for explicit reclamation.
Reclaim can still scan all batches: the goal is to remove those scans from
ordinary allocation/free, not eliminate necessary whole-heap maintenance.
Reclamation must remove descriptors from the tree before returning either
their data or metadata to the allocator.

Use the four reserved machine words in each 64-byte `Block` for left,
right, parent, and packed height/free-subtree state. Use reserved `Slab`
space for the root and index lock. Keep the 64-byte descriptor and slab
sizes enforced by assertions; do not silently grow metadata.
The metadata slab needs the same index, including its self-hosted first
page, so growth and descriptor frees do not retain a hidden linear search.
Explicitly initialize every new field in both normal block initialization
and the manually initialized slab array.

### 3.1 Synchronization and lock ordering

Favor an ordinary short per-slab index lock over a new lock-free tree.
Hold it for index lookup, slot bitmap/accounting changes, and tree updates.
This serializes same-size-class operations; different classes remain
independent. It is the main performance tradeoff requiring review and
measurement, especially with multiple threads.

Retain the existing reclaim read/write exclusion to protect descriptor
lifetimes and the existing growth serialization. Proposed order:

1. Ordinary allocation/free: reclaim read guard, then index lock.
2. Growth: reclaim read guard, growth lock, then index lock when needed.
   Drop the index lock before requesting backing memory or metadata.
3. Reclaim: reclaim write guard, growth lock, then index lock for removal.
   Release the index lock before freeing detached descriptors/backing memory.

An allocation that finds no free slot releases the index lock before
acquiring the growth lock, then rechecks availability. A concurrent free
or completed growth may have made expansion unnecessary.
Do not acquire the growth lock while holding the index lock.

Construct a complete batch privately, then publish its tree entries and
batch-list links under the appropriate locks. On allocation failure,
release unpublished backing memory/descriptors, restore locks, and leave
the visible index and accounting unchanged.

Metadata allocation/free may be called while a data slab's growth/reclaim
guard is held; the metadata path must never acquire a data slab's locks.
No caller may hold an index lock across a backing allocator call.
Document the initialization, publication, rollback, and reclaim ordering
in code and tests before integrating the new index.

Do not retain raw descriptor hints beyond their lifetime guard. No new
epoch system, hazard pointers, ABA-sensitive free list, or TLS lifetime
protocol is proposed.

### 3.2 Why this design

A last-used-block hint is smaller, but does not bound arbitrary frees or
fragmented allocation searches. A pointer/page map plus a separate free
list introduces two indexes and more synchronization invariants. In-band
headers or address-masked ownership would change allocation layout or
backing alignment requirements. Thread caches add cross-thread-free and
reclaim complexity without fixing the underlying owner lookup.

The augmented tree adds balancing code and a contended lock, but preserves
allocation layout and solves both searches with one index. It is a proposal,
not a measured improvement yet. If it regresses small-heap or concurrent
workloads, stop for review rather than adding caches, changing batch sizes,
or accepting the regression implicitly.

## 4. Implementation sequence after approval

Use small patches, normally 100–300 lines including tests. A larger atomic
integration patch needs an explicit explanation before implementation.

1. Add the retained-population reproduction and structural work-count hooks
   in test builds. Cover old/new/random-order frees and sparse holes among
   full blocks. Preserve baseline timing evidence without checking in a
   deliberately failing wall-clock assertion.
2. Implement and test the intrusive index independently: insertion, removal,
   rotations, owner lookup, free-subtree selection, and invariant checking.
   No allocator behavior changes in this patch.
3. Integrate the metadata and data slabs, including initialization, growth,
   rollback, and reclaim. If splitting this step would leave unsafe mixed
   lifetime rules, keep the integration atomic and review its size.
4. Add the deterministic logarithmic-search regression assertions, expand
   cross-thread/failure/reclaim coverage, and compare performance against the
   recorded baseline. Remove obsolete hot-path list traversal, not the
   reclamation list.
5. Validate native rust-analyzer, restore its queued string-hover assertion,
   and complete all core/developer gates. If hover still fails, preserve the
   failed evidence and continue diagnosis without increasing its deadline.

Steps 1–3 should already include the relevant correctness tests; step 4 is
not a reason to defer safety coverage. Run required gates before committing
each core-code patch, not merely once at the end.

## 5. Validation and acceptance

Deterministic correctness and complexity tests should cover:

- both Frusa variants and every managed size/alignment boundary, plus fallback;
- AVL ordering/balance/parent links and exact free-subtree summaries after
  insertions, removals, full/non-full transitions, and randomized operations;
- disjoint live allocations, payload retention, accounting, and successful
  address reuse after reclaim;
- owner lookup and free-slot selection visiting no more than the actual tree
  height, with height bounded logarithmically in block count;
- all-full, one-hole, alternating-hole, and widely separated-hole populations;
- cross-thread frees, concurrent allocation/free/reclaim, partial batches,
  and metadata reuse after descriptors are detached;
- injected backing/metadata allocation failures at each growth stage,
  checking rollback and absence of dangling index entries.

Use test-only counters for work bounds, not flaky timing assertions or
production overhead. Preserve existing stress coverage and add deterministic
interleaving tests at publication/removal boundaries where practical.

Performance comparisons must include retained populations from section 1,
low-occupancy immediate churn, mixed lifetimes, and 1/2/4/8-thread workloads.
Measure allocation, free, growth, reclaim, memory use, and metadata overhead
separately. Use identical release builds and workload seeds for comparisons;
do not select only favorable runs. Same-class contention and large Frusa2M
classes must not be hidden in aggregate throughput.

Before committing a core change, pass `src/tests/full-test.sh` at least
three times each in debug and release, with the new tests included.
Also pass `src/tests/full-test-dev.sh --release` for the rust-analyzer
integration. Format with the repository-selected toolchain and introduce
no compiler/Clippy warnings. No new tests should use the Internet.

For end-to-end closure, use the packaged native analyzer and restore the
environment-string hover assertion in its maintained multi-root LSP case.
The original 90-second whole-case bound and approved memory/thread/image
limits remain unchanged. Keep a plain-string diagnostic to distinguish
allocator behavior from build-script/macro issues. Full native completion
remains tracked in [rust-analyzer.md](rust-analyzer.md).

## 6. Decisions for review

1. Approve the augmented AVL index with a short per-size-class index lock,
   preserving block layout and batch reclamation? This is the recommended
   initial design; no implementation begins before review.
2. Is any measured low-occupancy or same-class concurrent throughput regression
   acceptable in exchange for scalable retained-heap behavior? The default
   proposal is to stop and review any reproducible regression rather than
   choose an implicit allowance. Do not relax existing OS or analyzer gates.
