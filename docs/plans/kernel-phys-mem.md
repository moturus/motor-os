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

## Resume checkpoint (2026-09-11)

Current state, superseding the checkpoint below and the history after it:
P-1, P0b, P0c, P1a1, P1a2 and P1b are committed and production allocates
small pages from the block pool (`3738d69d`). P3 is implemented and gated
(see its section under the progress notes) and committed as `48a2a701`.
P2 is next; its metric catalog is kernel-only. Two preexisting intermittent
failures recurred during this session's gates and are recorded with
evidence: the quiet VM exit during pressure tests (now self-reporting on
the console) and one stall of the developer image's native Lorry phase.
The `phys::init` boot cost is measured but first-touch dominated on this
host; the 0.1 ms target is unverified.

## Checkpoint after 5e401fc9

This checkpoint preceded the P1a2 completion and P1b. The five patches
listed here are committed; no code or validation is pending for that series.
Production then still used `mm/phys.rs`, with the `mm/phys_blocks`
implementation inactive except for debug scratch tests.

P-1, P0b, P0c and P1a1 are complete. P1a1's ownership core is `ad1e42dc`.
Commit `6ead6302`, titled "patch P1a2", completed the search increment only.
The original P1a2 deliverable is still partial: search and block-local shaping
are implemented; byte-range/span integration and table preparation remain.
Do not repeat the search or shaping work or treat that commit title as
completion of the entire P1a2 row in the patch sequence.

| Commit | Completed change |
|---|---|
| `2276eda8` | Isolate console rmux stderr from terminal-size measurements, preserving diagnostics and assertions. |
| `a3c9785e` | Accept an initrd starting exactly at the boot heap's end (`>=`). |
| `09cda9fd` | Retain five process/thread reader guards, clone the main-thread Arc under its lock, and safely handle empty thread-list buffers; add the existing lifecycle test's empty-buffer assertion. |
| `0153db5b` | Serialize fresh pressure sampling/publication and refresh on every small-page free, preserving 512/768-page hysteresis. |
| `5e401fc9` | Add pure block-local shaping and deterministic fixtures without production allocator wiring. |

Resume with a small P1a2 increment for physical byte-range normalization and
validation, following [boot shaping and initialization](#boot-shaping-and-initialization).
Round available RAM inward to pages and initrd reservations outward; check
arithmetic/order/overlap and coalesce adjacent available ranges. Keep helpers
pure and use deterministic fixtures through the existing boot hook. Then add
raw-RAM/SMALL_ONLY flags and span-wide shaping integration, including more than
255 mixed blocks, followed by checked table sizing, boot-heap preflight, pure
table carving and lazy-storage fixtures. Split these into reviewable increments.
Production table allocation, installation and CPU-publication wiring belong to
P1b, after P1a2 is complete.

Start in `src/sys/kernel/src/mm/phys_blocks/`: `mod.rs` owns descriptors, list
integrity and accounting; `search.rs` owns selection/cursor helpers;
`shaping.rs::Shape::new` takes ordered block-local page intervals in 0..512.
It already validates/coalesces them, subtracts reservations, retains the largest
free interval adjacent to an initrd (lowest-address tie), and returns bounds
plus managed/reserved/discarded counts. It does not normalize physical byte
ranges, derive flags, iterate the span or carve a table. The core, search and
shaping fixtures run through `init.rs`'s existing debug-only
`phys_blocks::test()` hook in ordinary boots, hence transitively through
`src/tests/full-test.sh`. Release does not run these scratch tests. The
empty-buffer regression runs in ordinary systest in both profiles.

The combined source committed through `5e401fc9` passed ten debug and ten
release `src/tests/full-test.sh` runs, plus
`src/tests/full-test-dev.sh --release` (native source builds and complete Lorry
suite). Strict kernel Clippy passed in both profiles. No retries, enlarged
timeouts, weakened assertions or temporary probes were used; no probes remain.
Source hashes matched after committing. Intermediate commits were not
independently gated; the user explicitly authorized this split using combined
results. Future code changes still require the [common gate](#common-gate).
Keep developer-image validation release-only.

Neither the quiet VM exit nor the five-second filesystem client-refusal timeout
recurred in those 10+10 runs. That meets the user's continuation threshold;
neither failure is claimed causally resolved. One diagnostic caught normal
sys-io exit (`Exited(0)`) triggering shutdown; the initiating service exit is
unproven. Do not restart investigations merely because this history exists.
Diagnose a recurrence and fix kernel-memory defects within the authorized
scope. Pause only for a diagnosed non-obvious fix or a specific outside-scope
issue; an undiagnosed failure is not a reason to stop. No new race tests or
reproducers are authorized. Temporary targeted instrumentation and diagnostic
runs of existing tests are authorized; remove probes before acceptance.

The host motor-fs explicit-flush race is separately diagnosed and deferred by
the maintainer until the filesystem branch merges; see
[future-work.md](future-work.md#deferred-filesystem-flush-race-2026-09-09).
The old allocator's page-zero and contiguous-allocation defects below belong
to P1b's replacement, not prerequisite repairs for these pure helpers.

Evidence on the development host is under
`/tmp/kernel-initrd-adjacent-gate.cRf0oY/publication-lifetime-gate-2/`:
`results.log`, `source-hashes.txt`, `main-validation-summary.json` and `FINAL.md`.
Earlier failures are in sibling directories described below. These temporary
paths may be absent on another host; durable findings are in
[kernel-pressure-publication.md](kernel-pressure-publication.md) and
[kernel-process-readers.md](kernel-process-readers.md). Page-fault medians were
11.631 microseconds debug and 6.449 release, with some slower samples. These
are uncontrolled observations, not a free-path contention benchmark. The
pressure fix adds shared synchronization to small-page frees. All release
boot milestone checks passed; P1b's controlled boot/placement measurements
remain required before activation.

Continue in small local patches for review. The request to commit the five
patches above is fulfilled, not blanket authorization for future commits.
No new design decision or approval is pending at this checkpoint.

### Progress after the checkpoint (2026-09-11)

The first remaining P1a2 increment is the byte-range normalization in
`mm/phys_blocks/layout.rs`: `Layout::new` converts available, reserved,
initrd and raw firmware segments to sorted page intervals with checked
arithmetic, rounds available RAM inward and reservations outward, coalesces
adjacent runs, excludes the fixed mid segment (now the module constant
`phys::FIXED_MID_SEGMENT`), requires available RAM inside raw RAM and the
page-rounded initrd inside one managed run clear of reservations, records
block indexes touching raw RAM, and refuses spans beyond 32768 blocks. Its
debug fixtures run from the same boot hook. The increment also carries the
`cargo fmt` of one untouched `virt.rs` function that was left unformatted.

The increment's first common gate passed two debug runs, then the third
guest exited quietly during the pressure tests (no panic, no fatal line).
Its evidence is on the host under the session scratchpad
`gate-layout-attempt1/` (`debug-3.log`, captured console and systest logs,
`debug-3-failed.qcow2`). Compared with the earlier saved failure
(`debug-2-console-at-exit.log` in the initrd-adjacent evidence directory),
both consoles end with one terminal-size probe (`ESC 7`, `ESC [9999;9999H`,
`ESC 8`) immediately before `vm_exit: bye.`; passing runs print that probe
only in pairs during the rmux tests. A virtio block-queue stall report from
sys-io's debug monitor appeared 13 seconds earlier in this run only, while
kernel builds ran on the host, and is absent from the earlier failures.

Source inspection gives the exit chain: sys-io returns when sys-init returns,
sys-init returns when sys-tty exits, and sys-tty returns when its console
shell exits, printing nothing when that exit status is zero. Rush treats an
error from its terminal event read as end of input and exits normally. Every
diagnostic channel (kernel-log forwarding, strobe files) dies with sys-tty,
which is why these exits are silent. Below the user floor, user-class
processes are refused lazy faults, object creation and mappings; the pressure
squeeze deliberately parks free memory a few hundred pages above that floor,
so concurrent kernel work can briefly cross it. This mechanism is inferred,
not observed: no probe has yet caught the first exiting process. The kernel
now prints `process <pid> '<name>' exited: <status>` on the serial console for
the first eight processes (the boot services and the console shell), a
permanent line that costs nothing until one of them exits, so a recurrence
names its initiator. The gate was restarted on that snapshot.

On that snapshot three debug and three release main-image runs passed. The
release developer-image run then failed its native Lorry self-gate: the
8 GiB guest's compile output stopped nine minutes into the phase and stayed
silent until the phase's 1200-second budget expired, with no panic on its
console; the earlier passing run finished that phase in 831 seconds, and
host-side preparation took the same 196 seconds in both. That is a guest
stall, not a slow run, in code this increment does not touch (the retained
evidence is under `gate-layout-2/dev-1-native-hang/` in the scratchpad and
the Lorry `native-self-tests` directory named in `dev-1-hang.log`). The
developer leg was rerun once with the failure preserved; it passed with the
native phase at 844 seconds. The increment is committed as `c3cbd5cc`,
after the console exit line `3f25f1ed`.

The second increment completes the P1a2 helpers: `Layout::block` clips the
page intervals to one block, shapes it, and derives its RAM and SMALL_ONLY
flags (blocks below 128 MiB); `Budget::preflight` sizes descriptor lines,
the two bitmaps and the list-state table (64 blocks per page) with checked
arithmetic against the boot heap remainder and refuses over-limit spans;
`Layout::carve_table` finds the lowest block whose retained free run holds
the table; and `Shape::carve` records the table pages as allocated in a
whole or partial backing block without changing its bounds. Fixtures cover
a 351-block span with 289 mixed blocks, whole blocks on both sides of the
dual-purpose line, absent blocks with and without raw RAM, an initrd across
three blocks, table rounding at 1/63/64/65/32768 blocks, exact heap-budget
boundaries, and carving from whole, partial and exhausted runs. Production
still uses `mm/phys.rs`; P1b is next. That increment is committed as
`fe4f8607` after a full common gate (3 debug, 3 release, developer run with
the native phase at 832 seconds).

### P1b: the production switch (2026-09-11)

`mm/phys.rs` now allocates small pages from the block pool. The pool is
built in `phys_blocks/production.rs` from the boot inputs (available RAM,
the above-heap initrd, raw firmware RAM): `Layout::new`, `Budget::preflight`
against the boot heap remainder, `carve_table`, then every descriptor
constructed in place with counters and index words accumulated locally
before the pool is published; split blocks get their list words zeroed.
Stage 2 re-shapes only the blocks below the kernel with page zero and the
two kloader page tables as the remaining reservations, publishing each
block's final index bit and releasing its free pages; managed totals never
change. Debug builds recount managed, reserved and retained pages by walking
the pages of every block a reservation or initrd touches, check every
descriptor, list and index invariant at both checkpoints, and compare the
stage-2 free delta with the independent low-memory release; block 0's
allocatable bounds must exclude page zero. Runtime cursors are a static
per-CPU array used only after the all-CPU publication (an Acquire load);
before it, allocation scans the indexes without CPU identity. Contiguous
runs come from `allocate` with the syscall's 64-page cap; a failed frame
descriptor frees the suffix once while the prefix handles free themselves.
MMIO validation rejects blocks with raw RAM or managed pages. Frees notify
admission after the block lock is released. `PhysStats` gains reserved,
discarded and whole/split/total block counts; the old segment vector,
random tries, one-frame cache and linear search are gone. `take_huge`,
`return_huge` and `allocate_huge` keep a dead-code allowance naming P4a.

`systest mem_blocks` adds fresh-boot placement (eight 1 MiB pieces, every
page queried through `virt_to_phys`, distinct blocks counted) and churn
(four threads in a ring, 512 iterations of 1 to 256 pages, verified
patterns, every other release handed to the next thread). The placement
budget asserted by the focused `mem-placement` subcommand, which
`full-test.sh` runs right after uploading the test binaries, is
10 + 2 * CPUs: four blocks of ideal packing, up to six blocks that boot
leaves partially free and that the split-before-whole rule drains first
(the page-zero block, the kloader page-table block, up to two initrd
boundary blocks, the list-state table block), and two per CPU cursor. The
original 4 + 2 * CPUs budget failed on Firecracker at 1 GiB with two CPUs
(9 blocks against 8) for exactly that reason; the allocator behaved as
specified. Observed fresh-boot placement, release builds:

| launcher | blocks | budget |
|---|---|---|
| cloud-hypervisor 1 GiB, 4 CPUs | 8 | 18 |
| Firecracker 64 MiB, 2 CPUs | 8 and 10 | 14 |
| Firecracker 1 GiB, 2 CPUs | 9 | 14 |
| QEMU direct kernel 1 GiB, 4 CPUs | 7 | 18 |
| QEMU BIOS 1 GiB, 4 CPUs | 6 | 18 |
| QEMU developer image 8 GiB, 8 CPUs | 9 | 26 |

All six launchers boot and pass the placement run; "kernel up" times were
52 ms (cloud-hypervisor), 10 to 20 ms (Firecracker), 100 ms (QEMU direct
kernel), 321 ms (QEMU BIOS) and 438 ms (developer image), in line with
boot-time.md. A temporary probe around `phys::init` and the stage-2
release, since removed, measured release builds with three boots each:

| launcher | phys::init | stage 2 |
|---|---|---|
| cloud-hypervisor 1 GiB | 0.3 to 1.6 ms | 1 to 6 us |
| QEMU direct kernel 1 GiB | 0.19 to 0.38 ms | 1 to 2 us |
| Firecracker 1 GiB | 0.50 to 0.58 ms | 3 to 35 us |
| cloud-hypervisor 8 GiB | 0.40 to 1.45 ms | 1 to 2 us |
| QEMU developer image 8 GiB | 0.91 to 1.88 ms | 2 us |

The spread between boots of one launcher is larger than the difference
between 1 and 8 GiB, and rewriting the construction loop without locks or
atomics did not move it, so the time is dominated by first-touch faults
on fresh guest memory (the descriptor lines, the table page, the boot heap)
rather than by the per-block work. This host has no hugetlbfs pool and
passwordless configuration is unavailable, so the prefaulted method of
boot-time.md could not be applied; the compute cost and the 0.1 ms target
remain unverified. Against the recorded 0.5 ms at 1 GiB and 3.0 ms at
8 GiB of the old allocator this is not a regression at either size.

Not covered by a test: the descriptor-failure rollback in
`allocate_contiguous_frames` (no fault injection into the frame slab); the
no-GS bootstrap path is exercised by every boot's kernel stack and GS
allocations before the all-CPU publication. P1b is committed as `3738d69d`
after its common gate (3 debug, 3 release, developer run with the native
phase at 812 seconds).

### P3: page kind, policy bit, placement (2026-09-11)

`MappingOptions::HUGE_ELIGIBLE` (512) is the internal creation policy;
nothing sets it yet. `Page::kind` is its frame's kind, small without a
frame, and `contains` uses that size. `find_page` takes the greatest page
start not above the address and checks the kind-sized extent, so interior
addresses of a huge page resolve and gaps do not. `VmemSegment::clear`
unmaps each page with its frame's kind and sums each page's size before
taking its frame. `page_mapping_options` derives per-page options, dropping
the policy bit before any page or `map_page` sees it, with guard handling
unchanged. `aligned_start` places segments with checked arithmetic and an
exact end bound for the empty-region, append and gap cases; eligible
segments align to 2 MiB. Debug boot self-tests cover the placement helper's
fits, one-byte-short gaps, rounding past a narrow gap and overflow, and the
option stripping; the 2 MiB alignment branch runs end to end only once P4b
sets the bit. `Page` and `SegmentNode` keep their 72-byte assertions.

### P2: metrics and diagnostics (2026-09-11)

The eleven metrics are declared together in the kernel catalog
(`MetricType` in `kernel/src/xray/stats.rs`, names `mem.blocks_total`,
`mem.blocks_whole`, `mem.blocks_split`, `mem.blocks_taken`,
`mem.blocks_whole_low`, `mem.pages_reserved`, `mem.pages_free_low`,
`mem.block_splits`, `mem.block_recombined`, `mem.huge_pages_mapped`,
`mem.huge_fallbacks`) and reported at the PID_SYSTEM scope. The pool
counts split and re-combination events cumulatively; the whole count is the
W bitmap's popcount; the low-memory pair scans at most 64 blocks under
their locks; the two huge-mapping counters are statics in `mm/virt.rs`
that report zero until P4b's mapping path produces them. `PhysStats` (and
the debug dump) carry the event counters beside the block counts. The
scratch re-combination test asserts the event counts and that a recovered
low block supplies a contiguous run but never a huge page. `systest
mem_blocks` reads all eleven metrics in one query around a controlled
allocate/free cycle and after churn, checking the bounds that hold at any
moment (state sum within the total, low-memory gauges within 64 blocks,
huge counters zero), that the event counters only grow, and that the block
count and reserved pages never move; it does not require a split or a
re-combination from the cycle, since boot-split capacity can absorb one and
metadata pages can pin a block. `stress-soak.sh` now appends the block
gauges and admission refusals to `blocks.log` at every progress interval.

The one-hour release `stress-soak.sh` run (all ten workloads, no failures:
fs-sftp 1725, fs-write 9053, http 18060, suites 709, tui 15094 iterations)
sampled the gauges twelve times. From the first sample on, the pool held 3
whole and 503 split blocks of 512 with 35235 to 47675 pages in use (137 to
186 MiB, growing slowly through the hour), reserved pages constant at 167,
the phys low-water mark at 321 pages, and no admission refusals after the
gate. The state was set by the mandatory gate's systest pressure squeeze
before the workloads started: the squeeze fills nearly every block, and
pages that other processes and the kernel allocate meanwhile stay behind in
them, so re-combination (2043 events against 2543 splits) recovers only
the blocks with nothing else in them. The soak's own workloads never run
the squeeze, so the count neither recovered nor worsened. Consequence for
P4: after any pressure episode, huge availability is close to nil until the
pinning pages die; the plan lists best-effort huge availability as an
accepted cost, and the slow growth in used pages is an observation, not a
diagnosis.

Two soak-harness fixes were needed to run it at all, both test-only and
preexisting. Its HTTP fetch target, `/devtools/www/motor-os-256.png`, was
removed with the website rewrite (`6a2b7166`), so the soak has been unable
to pass its server validation since; it now uploads its own 108776-byte
asset under `/devtools/tmp/www` (the packaged `/devtools/www` is not
writable over sftp, and httpd serves only extensions it knows). Its
fs-write workload copied that same missing file, so it had never actually
churned; churning `/devtools/tmp` while the fs-sftp workload lists that
directory failed one listing in about 200 with "error reading directory"
(motor-fs rejects a directory read that races a create or remove there).
The same listing-under-churn loop against the pre-P1b kernel `fe4f8607`
failed 50 of 5028 listings against 34 of 6818 on this kernel, so it is
preexisting motor-fs behavior, outside this plan; fs-write now churns its
own subdirectory.

### P4a: owning huge frames (2026-09-11)

`phys::allocate_huge_frame` takes one whole dual-purpose block through the
pool's downward search and wraps it in a `Frame` of kind MidPage; failure
is `E_OUT_OF_MEMORY`, the recoverable fallback signal, and a failed frame
descriptor returns the block. Dropping such a frame returns the block and
then notifies admission, after the block lock. The fixed sys-io mid segment
keeps its frameless path. A debug boot test on the live pool takes and
returns one huge frame while the BSP is alone: kind, 2 MiB alignment, the
128 MiB line, taken and whole counts, the free-page delta, and an admission
notification counted by a debug-only oracle; guests without a dual-purpose
block see the refusal instead. The descriptor-failure rollback has no fault
injection; the scratch tests cover the pool's take and return paths.

### P4b: eligible heaps map huge pages (2026-09-11)

Ordinary eager private heap requests above 1 MiB carry HUGE_ELIGIBLE. The
mapping loop maps each whole 2 MiB unit of an eligible segment through a
local huge-frame source, small pages first-failure onward, with the
`mem.huge_pages_mapped` and `mem.huge_fallbacks` events produced there;
the rest of the segment maps small. For now only exact multiples map huge
(the rounding rule is P5). `share_range_with` refuses when either segment
is eligible, whatever its backing, before any destructive work, which
covers F_SHARE_SELF and IPC's `map_shared` at both endpoints, subranges
included. The debug huge-frame source is a seam (`HUGE_SEAM`: production,
refuse, or held frames). A controlled boot test on private address spaces
whose CR3 is never installed maps a held, dirtied huge frame and checks
the 2 MiB leaf, translation of an interior address, zeroing, pinning, the
refusals at either end with the destination's bytes intact, teardown
returning the block, and the refusal path (512 small leaves, one fallback,
the policy retained). It also exposed a latent placement defect: a region
whose segments were all freed still holds node slabs, so the old empty-map
test failed and the append and gap searches found nothing; placement now
keys on the last segment. systest mem_blocks adds the sizing table through
map2 (sizes, alignment, every page touched and queried, huge runs reported,
event counters moving by at least the candidate count), zeroed reuse of a
dirtied 2 MiB mapping, F_SHARE_SELF refusals for eligible sources and
subranges with 1 MiB sharing still working, and a `mem-huge-sizes`
subcommand that asserts no huge success and positive fallback coverage on
guests of 128 MiB or less.

Launcher matrix, release: every 1 GiB or larger guest (cloud-hypervisor,
Firecracker, QEMU direct kernel and BIOS, the 8 GiB developer image)
mapped 5 huge pages for the sizing table plus the reuse test with no
fallback and 3 contiguous huge runs; Firecracker at 64 MiB mapped none
with 5 fallbacks and reused 438 of 512 pages zeroed. Placement stayed at
7 to 10 blocks.

### P2 is not blocked

An earlier note here claimed the metric catalog lives in `moto-sys`; that
was a misread of a grep. `MetricType` and its `name` table are in
`kernel/src/xray/stats.rs`, and userspace discovers metrics by name through
the kernel's stats provider. The eleven P2 metrics are a kernel-only change.

## Implementation and diagnostic history

These records describe earlier checkpoints and diagnostic sequences. Use the
resume checkpoint above for current completion and validation status.

Implementation status (2026-09-10): P-1's boot-heap alignment fix is in
`6efc3276` (alongside the wait-set fix). P0b's range validation is in
`83f09a60`, and MMIO ownership/teardown and consumer refusals are in
`a94eb213`. Reservation and mapping now share the region lock, including
contiguous mapping and failure rollback. Both P0b snapshots passed the
common gate and launcher matrix, including Firecracker at 64 MiB; these were
functional checks, not controlled boot-time measurements. Checked copy-in is
in `ba6da613`. P0c's direct-map consumer lifetime fix is in `56e66622` and passed
the common gate: three debug, three release and one release developer-image
run, without test retries or temporary probes. That exact source snapshot also
included the native-driver test cleanup (`d2aef7fd`) and the separately reviewed
spin-source lifecycle fix (`ec28676d`). P1a1's ownership core and deterministic
scratch tests are committed in `ad1e42dc`, with the approved debug-only hook
in ordinary boots. Strict kernel Clippy passes in both profiles. With the
separate timestamp self-test correction described below, the unchanged kernel
candidate passed the common gate: three consecutive debug runs, three release
runs and one release developer-image run, including native source builds and
the bundled Lorry suite. No retries or temporary source probes were used in
that sequence. P1a1 is implemented and reviewed; production
still uses the old allocator. P1a2 and huge-page changes are not installed.
The earlier unexplained pressure exit remains recorded below, not resolved by
these later passes. That checkpoint preceded the later increments below.

Residual diagnostic history: P0c's original third debug gate exited during
pressure without a recorded cause; the failed image had 193 MiB free. A later
TCP test lost two exchanges, followed by expected harness shutdown. Traces
proved that earlier native-driver tests left two FIN-WAIT-2 peers occupying
orphan slots; the cleanup drains these owners, but quota cancellation was not
recorded as the original reset cause. Another gate exposed a timing-dependent
spin-source test and missing cleanup when block_on ends; both are now fixed.
The passing common gate does not establish the original pressure exit's cause
or relation to P0c. Original failures and before/after evidence are preserved
under `/tmp/kernel-user-page-pin.DtyP1d`, `/tmp/kernel-failure-cause.C67ZxC`,
and `/tmp/spin-source-lifecycle.vcaNn7` on the development host.

P1a1's new failure stopped timestamped guest output at 66.84 s, during the first
pressure episode, with 193.6 MiB disk space free and before the harness deadline.
The final shutdown line has no timestamp. QEMU exited
while systest's SSH session was still waiting; its later termination was
cleanup, not the initiating cause. Temporary service-exit/admission probes,
a shutdown-only fixed journal, and debugger observations of the uninstrumented
candidate have not caught another unexpected exit. Later debug and release
diagnostic passes do not resolve this failure or count toward acceptance.
The initiating caller/status remains unknown; a console/service-exit cascade
or privileged shutdown is not yet established. All source probes are removed.
Evidence and run-by-run notes are under `/tmp/kernel-phys-p1a1-gate.FtzLmO`.
A separate preexisting SSH test-capture defect (stderr could split its expected
stdout line) is fixed in `4265358e`, with debug/release component checks passing.

A later diagnostic also exposed a preexisting transaction-logger race in the
host `motor-fs` suite: explicit flush can acknowledge before a timeout-owned
batch commits. The existing crash/regrow test reproduced it with ordering
traces; the diagnosis and proposed correction are recorded in
[future-work.md](future-work.md#deferred-filesystem-flush-race-2026-09-09).
Temporary logs are removed. The maintainer has deferred its separate production
fix until after merging the pending filesystem branch and requested continued
kernel validation without skipping or weakening tests. It is not established
as the cause of the earlier quiet VM exit.

Renewed uninstrumented validation passed one full debug run, then failed in
sys-io's existing timestamp self-test, after both pressure checks passed. Its
unsigned comparison of two offset estimates rejects a valid millisecond
boundary; it also assumes the separate clock reads cannot be preempted for
longer. A separate, local test-only correction brackets the timestamp read
with uptime readings and checks the actual interval and offset stability.
Production clock behavior is unchanged. The original failure and diagnosis
are retained under `/tmp/kernel-phys-resumed-gate.jzP5OI`; the fresh common gate
with that correction passed under `/tmp/kernel-phys-clock-test-gate.yS7I2b`.
All three debug runs passed the block-core scratch suite and all 63 sys-io
self-tests. The correction is in `584e873c`. Strict sys-io
Clippy additionally reported existing lints in untouched code, none in the
corrected test; strict kernel Clippy passed with warnings denied in both
profiles. Tested source hashes and complete gate results are retained with
the logs. The findings-only commit `91eadfe2` did not change the tested code.

P1a2 is only partially implemented. Commit `6ead6302`, titled "patch P1a2",
contains the search increment: F/W search, advisory cursor adoption/clearing,
a cursor-free bootstrap path, contiguous-run selection, and downward
huge-block selection around P1a1's
locked ownership helpers. Debug scratch tests cover exact four-block packing
for 2048 pages, split-before-whole selection, claimed capacity before splitting
or OOM, sticky/shared/stale cursors, preserved short tails, and LIFO reuse.
They run through the existing ordinary-boot hook; production is unchanged.
Strict kernel Clippy passes with warnings denied in both profiles. The
unchanged source passed three consecutive debug runs, three release runs, and
one release developer-image run, including native source builds and the
complete Lorry suite. Both scratch suites passed in all three debug boot logs.
No test retries or temporary probes were used. Source hashes and complete
results are under `/tmp/kernel-phys-p1a2-search-gate.XGoygD`. This approximately
250-line code/test increment is committed and reviewed.
Commit `5e401fc9` supplies pure block-local shaping: validate ordered
page intervals, coalesce adjacent managed runs, subtract reservations, select
the largest free run adjacent to any initrd (lowest-address tie), and compute
managed/reserved/discarded counts and descriptor bounds. It allocates no
storage and touches no page data. Debug boot fixtures cover holes, initrd
containment/adjacency, malformed ranges, full/partial/absent shapes, and low
RAM before/after release with page zero and two synthetic loader-table pages.
The approved initrd boundary correction below is included in this snapshot.
Strict kernel Clippy passes in both profiles. The common gate passed its first
debug run, then the second guest exited during the later pressure episode
at about 193.488 seconds, before systest completion and before the harness
timeout. All three block scratch suites passed in both boot logs. The failed
boot used the low initrd path, so it did not exercise the changed comparison.
The stopped image has about 193 MiB free; persisted logs identify no shutdown
caller. This resembles the previously recorded quiet exit but does not prove
a common cause. The stranded SSH session was cleaned up only after evidence
capture; no release/developer-image acceptance run or test retry followed.
One diagnostic run of the existing debug suite, with a hardware kernel_exit
breakpoint installed before the main VM booted, passed both pressure episodes
and the full suite. It captured only the normal final shutdown through
sys_kill_impl from PID 8; the optional process-name read failed, but the stack
and PID were retained. This does not establish the original exit's cause and
receives no acceptance credit. Logs, image and source hashes are under
`/tmp/kernel-initrd-adjacent-gate.cRf0oY`. Under the user's session-specific
continuation policy, a fresh uninstrumented sequence then checked 10 debug and
10 release full-suite runs for recurrence, followed by the release developer
gate. The sequence stops on failure for diagnosis; no source probes or
weakened assertions were used. This increment and the boundary fix were still
local during diagnosis.
The fresh sequence passed debug-1 and release-1, then debug-2 failed in
`probe_fresh_client("sys-io-fs")`: the server handle remained live through its
five-second deadline in the second filesystem pressure episode. Both network
pressure episodes passed; this VM shut down after the harness reported the
assertion. It is distinct from the quiet exit. The failed log/image are in
`characterization/` under the same evidence directory. Temporary snapshots
in the existing test investigated whether waiter cleanup cleared pressure
before client acceptance, versus an incorrect retained server connection.
The diagnostic full run retains the shutdown breakpoint, changes no assertion
or timeout, and receives no acceptance credit. That diagnostic passed; the
second FS episode rose from 433 to 536 free pages with pressure still raised,
and sys-io correctly dropped the newly admitted client.
A terminal-test diagnostic stopped before systest: a TCP runtime stderr fragment
interrupted a 100-column rmux repaint, making the terminal test count 180.
The test already isolates Red's stderr; the local correction does the same
for the outer console rmux client and retains its diagnostics separately.
Its Rush wrapper explicitly preserves the original console rmux capability
mask (0x6c); no production permission policy changes. The existing terminal
suite passes in debug and release, with the TCP diagnostics present in the
retained stderr. This small test-only fix was kept separate from the kernel
changes. Pressure diagnosis continued using the existing complete systest
with snapshots and the shutdown breakpoint; no new workload or reproducer.
That direct systest diagnostic passed too: FS pressure stayed raised at 448
and 472 free pages, covering both kernel refusal and service-side drop.
Temporary snapshots are removed; neither pressure failure has been explained.
A fresh uninstrumented 10-debug/10-release sequence then included the validated
terminal-test correction, followed by the release developer gate. Its logs
are in `characterization-2/` under the evidence directory; any failure stops
that sequence for diagnosis. No diagnostic pass receives acceptance credit.
That sequence passed three debug/release pairs, then debug-4 repeated the
five-second FS client-refusal failure, now in the first filesystem episode.
The original quiet exit did not recur. A lighter temporary observer adds no
extra diagnostic syscall until the original final failed wake poll; earlier
snapshots may affect scheduling. Complete systest with this observer passed,
as did 20 existing standalone `test-fs-pressure 128` runs without GDB. Full
harness diagnosis without GDB then preserved the original workload order and
sought the pressure/admission/connection state at the timeout. At that point
the 10+10 threshold had not been met. The original and recurring failures remain saved.
The full-harness failure-only diagnostic passed once; its second scheduled
run was intentionally canceled before VM/pressure testing, with status 143
recorded separately from test regressions. All temporary test probes are
removed. Source inspection established a stale-snapshot pressure-publication
race in `mm/admission.rs`: a delayed high-free observation can clear the flag
after another CPU completes allocations below the low watermark; the reverse
ordering can miss recovery too. This is not yet established as the cause of
either recorded failure. The synchronization decision and ordering example
are in [kernel-pressure-publication.md](kernel-pressure-publication.md).
The user confirmed that fixing this race is within the authorized work. The
fix serialized fresh sampling and publication, including every small-page
free; validation and performance comparison were pending at that point. The
shaping, boundary and terminal-test changes were then still local.
The fix passed strict kernel Clippy and one full debug/release pair; the
page-fault benchmark remained within the saved baseline ranges. Debug-2
then exited quietly during the first network-pressure episode, at guest
66.415 seconds after expected TCP/UDP refusals. This is preserved under
`pressure-fix-gate/` in the same evidence directory. It does not establish a
common cause with earlier failures, but the publication fix has not eliminated
quiet exits. Subsequent temporary shutdown-only probes recorded the kernel
exit stack, privileged shutdown caller, and sys-io exit status in
`exit-only-diagnostic/`. No pressure-loop instrumentation or new test/reproducer
was added. Those diagnostic runs receive no acceptance credit.

Diagnostic update (2026-09-10): `exit-only-diagnostic/debug-2` captured the
quiet shutdown as `init_exited: Exited(0)`, with the stack through sys-io
process/thread teardown. It was not a privileged shutdown request. The
initiating event before sys-init/sys-io returned is still unproven. Inspection
also found five discarded process/thread lock guards and an unlocked
main-thread getter racing with teardown. The local correction retains guards
through reads/Arc clones and returns a main-thread Arc cloned under its lock;
no extra lock is held while querying thread stats. Details are in
[kernel-process-readers.md](kernel-process-readers.md).
Three subsequent full debug diagnostics with both fixes and service-exit
probes passed. All temporary probes are removed; exact backup comparisons
confirmed that both fixes remain. A further bounds fix makes `list_tids` safe
for a zero-length caller buffer; the existing shared-listener test checks that request against its live child.
The first clean gate was canceled during prelude before this fix/test and
receives no acceptance credit. Clean validation restarted in
`publication-lifetime-gate-2/` under the evidence directory: 10 debug plus
10 release runs, then release developer-image validation. No diagnostic
pass receives acceptance credit, and neither quiet-exit causality nor the
filesystem-refusal timeout is claimed resolved.

Clean main-image validation in `publication-lifetime-gate-2/` has now passed
ten debug and ten release full suites on unchanged source, with no retries
or temporary probes. Both pressure episodes and the empty-buffer lifecycle
regression passed in all twenty runs; shaping fixtures passed in every debug
boot. Neither intermittent failure recurred, satisfying the user's 10+10
threshold for moving on without asserting a root cause. Strict kernel Clippy
passes in both profiles. The release developer-image gate also passed,
including native source builds and the complete Lorry suite. Recorded source
hashes still match. The user authorized committing the five patches using
this combined validation; intermediate revisions were not independently gated.
Page-fault timing ranges and their limits are recorded in
[kernel-pressure-publication.md](kernel-pressure-publication.md).

The remaining deliverables in the original P1a2 row are not implemented:

- Physical byte-range normalization/validation, raw-RAM flags and span-wide
  shaping integration, including more than 255 mixed blocks.
- Table sizing, boot-heap preflight and pure table carving, with storage and
  lazy-initialization fixtures.

P1b still owns production installation and runtime CPU-publication wiring;
the search commit does not complete the original P1a2 deliverable.

Continuation checkpoint (2026-09-10): input inspection for the next shaping
increment found a preexisting initrd adjacency rejection in
[`init_mm_bsp_stage1`](../../src/sys/kernel/src/mm/mod.rs): the upper-initrd
branch requires `initrd_seg.start > bootup_heap_phys.end()`. An initrd starting
exactly at that end is non-overlapping and passes
[`KernelBootupInfo::is_available`](../../src/sys/kernel/src/init.rs)'s heap
check, but falls into the below-kernel branch and panics. The existing
half-open `MemorySegment::intersect` contract permits this adjacency; kloader's
separate 32 MiB heap check does not exclude an initrd above the kernel heap.
For example, the recorded debug boot heap ends at 38 MiB; placing an otherwise
valid initrd at 38 MiB in sufficient RAM reaches the incorrect branch. The
strict comparison predates this work (present in `5e42173e`). This is a
source-level diagnosis, not a launcher failure reproduced during validation.
The user approved the one-line `>` to `>=` correction for upper-initrd
classification; it is implemented in `a3c9785e`. No new boot self-test is added
for the comparison alone. The existing common gate validates compilation and
ordinary boots, but does not force the adjacent-initrd layout; that boundary
is validated by source inspection. Common-gate failure details are recorded
above; the corrected boundary itself was checked by source inspection.

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
| Reservation/mapping race | MMIO and contiguous mapping release the region lock after reserving a segment; concurrent unmap can remove or replace it before mapping. | P0b |
| Direct-map consumer lifetime | Copy-out, stats-page writes and the console retain physical addresses without owning their frames; concurrent unmap can free them. Concurrent console registrations can also replace the published control pointer. | P0c |
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

Hold the existing region lock continuously from reservation through mapping
or rollback, for both MMIO and contiguous allocation. Otherwise concurrent
unmap can remove the reservation, or replace it with another segment, before
the mapper reacquires the lock. A missing-segment error alone would not fix
the replacement case or double reversal of process accounting. Reuse a
locked reservation helper; no new lock or boot-time work is needed.

Return a distinct `VaddrMapStatus::Mmio`. `copy_to_user`,
`get_user_page_as_kernel`, `read_from_user_into`, and sharing refuse it;
retain the existing handling of other statuses and special fixed mappings.
Do not turn the input path into a blanket refusal of everything outside
the normal segment tree. `virt_to_phys` still reports device addresses.
Kernel LAPIC/IOAPIC mappings and sys-io BAR mappings must continue booting.

P0c gives copy-out and pinned-page consumers an owning Frame reference,
acquired under the region lock and retained until use finishes. Keep the
existing refusals of frame-less zero/CoW pages and MMIO. The console retains
its control-page pin beside its permanent address-space reference; an
address-space reference alone does not prevent explicit unmap. Serialize
registration with the existing state-then-driver lock order, rechecking
ownership before publishing the control pointer so its pin cannot be replaced.
No new locks, allocations, race tests or reproducers are needed.

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
   Finish output before unmapping: its allocations can reuse the address.
   Between free, translation check, and the deliberate read, do not allocate;
   distinguish setup failures and unexpected survival with separate exit codes.
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
| P0c | Retain Frame ownership for direct-map consumers; serialize console registration and retain its control-page pin. | Existing copy, stats, console, MMIO and pressure coverage; source-inspected race fixes, without new race tests/reproducers. |
| P1a1 | Descriptor/bounds, link check word, ownership and uniform re-combination, F/W publication, ordinary counters, core scratch tests. | Debug self-tests; production still uses old allocator. Temporary module dead-code allowance names P1b. |
| P1a2 | Pure shaping/table-carve helper, F/W search, advisory claims/no-GS path, contiguous search; input-range and source-order fixtures. | Hole/initrd/lazy-initialization cases; no real shadow allocator or table allocation. |
| P1b | Switch phys.rs to blocks including low/dual re-combination; carve/install table, route small/run/free/adopt/MMIO and runtime cursors; remove old vector/cache/search. | Page-zero regression; independent boot recounts, no-GS/AP and rollback tests, fresh-boot placement/churn, pressure/admission; launcher matrix and boot measurements. |
| P2 | Add the eleven metrics, collection helpers and PhysStats/dump diagnostics with real block producers; huge-mapping events remain zero until P4b. | Collection tests, controlled low contiguous recovery and cross-CPU churn; release soak. |
| P3 | Frame-derived Page kind, internal policy option bit, kind-sized lookup/clear, aligned virtual placement. | Size assertions, all alignment branches, option stripping and 4 KiB behavior; no public allocation-policy change yet. |
| P4a | Dual-purpose owning huge Frames and controlled take/return tests. | Frame construction rollback; huge return notifies admission; fixed-mid route unchanged. |
| P4b | Mark all >1 MiB ordinary heap segments HugeEligible, refuse sharing at both endpoints, but map huge only for exact multiples of 2 MiB. Add conservative matching admission/stats. | Whole-size mappings, forced fallback, IPC/F_SHARE_SELF refusal and supported sharing, zeroing/translation/teardown tests. |
| P5 | Enable the full sizing rule and mixed huge/small segments; rounded fallback sizes everywhere. | Table boundaries, overflow, mixed lookup/copy/pinning, exact controlled accounting; re-read admission boundary expectations. |
| P6 | Widen churn to mixed sizes; document final accounting and metrics in docs/oom-handling.md and measured results here/boot-time.md. | Full integration gate and recorded residual risks/measurements. |

Order: P-1 -> P0b -> P0c -> P1a1 -> P1a2 -> P1b.
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

No Internet access in new tests. The user approved the existing developer
gate's public dependency downloads for all patches in this work. Retry a
confirmed external-network flake once, including approved DNS/ping cases;
never retry hermetic failures or enlarge timeouts/ignore failures to disguise
a defect. Diagnose failures; pause implementation for
new non-test pre-existing bugs or a newly required policy decision, except
that the user explicitly authorized fixing discovered races and continuing
without creating race tests or reproducers. For this session, the user further authorized continued diagnosis of
undetermined failures and kernel-memory regressions: pause only for a diagnosed
non-obvious fix in the current work or a specific issue outside it. An issue
that does not recur across 10 debug and 10 release full-test.sh passes may be
treated as an extremely rare flake and work may continue. Preserve the original
failure and report it. Existing acceptance gates remain required.

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

Resume at the remaining P1a2 work identified in the current checkpoint,
under the requested local-change/commit workflow. Keep this document as the active specification, update patch
status and measured outcomes as they land, and use Git history for the
superseded alternatives and review discussion.
