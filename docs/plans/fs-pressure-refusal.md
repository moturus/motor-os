# FS-side pressure refusal and the sys-io self-usage gauge

2026-08-06. **Status: awaiting review. No implementation code has been
changed.** Addresses the first open follow-up in `docs/oom-handling.md`:

> FS-side request growth (file caches, device buffers) is not yet in the
> refusal set; grow it from observed soak metrics. The per-address-space
> sys-io memory-usage gauge (from the kernel's existing accounting) belongs
> to the same follow-up.

## Summary

Pressure mode currently stops sys-io's *net*-side demand, but the FS side has
one uncounted client drop and otherwise keeps serving every command while the
`memory_pressure` flag is up. Every FS command can allocate fresh block-cache
buffers on a cold-cache miss, so established FS clients can grow sys-io's heap
straight through an episode until kernel admission refuses sys-io itself — and
a refused Rust global-allocator call aborts sys-io. That is exactly the
failure pressure mode exists to prevent.

Plan, in three patches, sys-io/tests/docs only, no kernel changes:

1. refuse every FS command except `UNLOCK` at the dispatch point while the
   flag is up, allocation-free, releasing client-donated channel pages, and
   count both request refusals and the existing accept-time client drop;
2. extend the `systest` pressure regression with FS arms (refusal, unlock
   carve-out, donated-page release, client drop, recovery);
3. add a `mem.self_usage_pages` gauge to sys-io's metric set from the
   kernel's existing per-pid accounting, and sample the pressure metrics
   periodically in soak so future refinement of the refusal set has recorded
   observations to work from.

## What grows on the FS side

From reading `sys-io/src/runtime/fs.rs`, `lib/async-fs/src/block_cache.rs`,
`lib/motor-fs`, and `lib/virtio-async`:

| structure | bound | grows during an episode? |
|---|---|---|
| block cache (`BlockCache`, `motor-fs` `CACHE_SIZE = 4096`) | 16 MiB | in principle yes (`block_cache.rs` `pop_free_block` allocates on a miss while the cache is below capacity) — **measured no**, see below |
| cache free-block list, expiring map | unbounded, never trimmed | only via cache churn above |
| lock manager held locks (`lock_manager.rs` `files`/`connections`) | unbounded | **yes, measured** — each new acquire inserts entries |
| readahead tasks (`fs.rs` `maybe_readahead`) | no in-flight cap | yes — spawned by reads, each prefetches up to 32 blocks |
| per-request transients (task `Box::pin`s, path `String`s, decode `Vec`s) | 64 in flight per connection | bounded and released per request |
| txn machinery, virtio rings, device vectors | fixed or per-request | no |

### Measured, 2026-08-07 (debug, QEMU/KVM, 4 vCPUs, 1 GiB)

The static read above made the block cache look decisive — a 16 MiB ceiling
is ~4096 pages, an order of magnitude more than the gap between the pressure
watermark and the sys-io floor. Direct measurement (temporary
`systest fs-grow-probe`, reverted before submission; sys-io's own
`pages_user` read from the kernel catalog at pid 2) says otherwise:

| workload | sys-io growth |
|---|---:|
| 4096 sequential 4 KiB writes (16 MiB, one file) | **0 pages** |
| 40,000 open file handles (no locks) | **1 page** |
| 100,000 held shared locks | **+546 pages** while held, released on unlock |

(The lock figure is release; debug measured +273 pages at 50k, the same
~22 bytes per held lock. 100k opens+locks take ~11 s on release.)

The cache does not grow because it is capacity-bounded *and already full*:
boot-time binary loads fill all 4096 slots, after which every miss recycles
an evicted `IoBuf` rather than allocating (the probe's misses stayed flat
while `device.write_blocks` climbed). The cache is therefore "bounded" in the
sense the doc's rule requires, and it is not the lever.

The **lock manager is the unbounded grower**: ~22 bytes of sys-io heap per
held lock, materializing as ~68-page slab allocations every ~12k locks. That
is what can cross the sys-io floor mid-episode, and it is what the
demonstrator uses. Opens are nearly free on the sys-io side (the client pays,
~1 page of sys-io per 40k opens), so the cost is specifically the held lock
state, and it is returned on unlock.

Note the shape of the resulting death, which the demonstrator reproduces:
the refused allocation is not the lock manager's own. Growth consumes
sys-io's heap slack, and whichever allocation asks next is the one that gets
nothing back. Two shapes were observed across runs, both fatal to the
machine:

```text
# heap allocation refused, unwrapped by the block cache
panicked at lib/async-fs/src/block_cache.rs:64: called `Option::unwrap()` on a `None` value
sys-io exited with status 0xbadc0de.

# lazy fault refused: the kernel kills the faulting thread, which kills sys-io
sys-io exited with status 0xffffffff.
```

The first is `BlockHolder::new` unwrapping `IoBuf::new_from_size_align(4096)`,
which returns `None` when the global allocator returns null. The second is
the documented lazy-fault path (`oom-handling.md`: "the faulting thread is
killed, which kills its process"); `u64::MAX` is the exit status the kernel
records for a killed thread (`uspace/process.rs:709,733`). Both are the
documented consequence of a refused sys-io allocation, not separate defects —
but they mean the victim site is arbitrary, so neither panic location is
evidence about which structure grew.

The doc's rule — "any sys-io structure that can keep growing while pressure
is active must be bounded, reclaimed, or added to the refusal set" — leaves
three options for the growers that remain (locks, readahead tasks,
per-request transients):

- **Bounded**: a cap on held locks changes FS semantics (a legitimate
  workload holding many locks would start failing outside episodes too);
  rejected.
- **Reclaimed**: freeing sys-io heap returns buffers to its allocator free
  lists; nothing guarantees pages return to the kernel's small-page pool, so
  reclaim cannot be counted on to clear system pressure.
- **Refusal**: deterministic, allocation-free, mirrors the net side. Chosen.

Refusing every command (not just lock acquires) still stands: the block cache
is full *today*, on a machine whose boot fills it, and a refusal set that
silently depends on that is one `CACHE_SIZE` bump or one smaller-RAM profile
away from being wrong. Per-request transients (two `Box::pin`s, path
`String`s) also allocate on every command, bounded per connection but
unbounded across connections.

## Design

### Refusal at the dispatch point

At the top of `on_msg` (`sys-io/src/runtime/fs.rs:450`): if
`moto_sys::memory_pressure()` is set, refuse the command with
`E_OUT_OF_MEMORY` via the existing `empty_resp_encode` error path, bump
`fs.pressure_refused`, and return — for **every** command except
`CMD_FILE_LOCK` with `moto_rt::fs::UNLOCK`.

Why all commands, not just writes: reads, stats, and readdir walk metadata
blocks through the same block cache and allocate on any miss. A
hit-serving/miss-refusing split would need a cache probe before dispatch, and
would make refusal depend on cache state — nondeterministic to test and easy
to regress. Refusing everything is the honest counterpart of the net-side
argument: established TCP traffic survives *because it allocates nothing*;
FS traffic cannot make that claim.

The `UNLOCK` carve-out: releasing a lock only removes lock-manager entries
and grants queued waiters (each grant sends a pre-encoded response held by
the waiter). Refusing it would leak locks past the episode, because
`Drop`-based unlock on file close never retries. The grant path allocates one
transient `Vec` (`LockManager::release`), bounded by the per-connection
waiter cap of 64 and net-freeing; noted as the same class of bounded runtime
work the floors absorb. Lock *acquires* (all four modes) are refused.

`CMD_FLUSH` is refused: the checkpoint path can allocate via copy-on-write
(`CachedBlock::block_mut` → `pop_free_block`) and txn-log batches. Already
submitted background writes keep draining — that is in-flight work, which
the floors absorb. Durability of new data is deferred to after recovery; a
refused flush surfaces to the client as an ordinary recoverable I/O error.

**Donated-page release.** Six request types carry client-allocated channel
pages (`api_fs.rs`: `stat_msg_encode`, `create_entry_msg_encode`,
`write_msg_encode`, `write_multi_msg_encode`, `move_entry_req_encode` /
`move_noreplace_req_encode`). Normal handlers release them by decoding
("the decode above recovered every page, so all paths below free them on
drop", `fs.rs:707`). The refusal path must do the same or the channel's
64-slot page pool leaks one slot per refused request. Add a small helper in
`api_fs` (next to the decoders, which own the slot-index layout) that
recovers and drops the donated page(s) for a given command without
allocating — for `CMD_WRITE_MULTI`, by iterating the embedded page indices
rather than collecting the decoder's `Vec`. An invalid page index is skipped,
same as today's decode-error behavior.

The check stays in `on_msg` rather than before the task spawn in
`fs_listener`: it mirrors the net side ("at the top of the handlers"), keeps
one site instead of a loop rewrite, and the two per-message `Box::pin`s it
tolerates are transient and ticket-bounded at 64 per connection.

Allocation-free by construction: one shared-page load, `Cell` counter bumps,
`empty_resp_encode` (POD), a channel send, and the page-release helper.

Out of scope by construction: sys-io's own internal use of the FS object
(`net::init` holds it) does not go through the io_channel dispatch and is
unaffected; refusal applies to client requests only.

### Counting the existing client drop

`fs_listener` already drops new clients under pressure (`fs.rs:402-406`) but,
unlike `net.rs:273-278`, bumps no counter — `pressure::Pressure` is
`pub(super)` inside `runtime::net` and unreachable from `runtime::fs`. Add
`fs.pressure_refused_clients`, bumped at the drop site (`runtime.fs_stats` is
already in scope). The accept-slot replacement before the check stays as-is —
the same accepted cost as on the net side ("the consumed accept slot is
replaced so refusals stay prompt").

### Metrics

`sys-io/src/runtime/fs/stats.rs`: two new ids after the current 1000–1013
block — `FS_PRESSURE_REFUSED = 1014`, `FS_PRESSURE_REFUSED_CLIENTS = 1015` —
as `Cell<u64>` fields on `FsStats`, plus `entries()` and `descriptors()`
rows (`fs.pressure_refused`, `fs.pressure_refused_clients`). No episode-edge
counter on the FS side; `net.pressure_entries` already counts episodes
globally.

### The sys-io self-usage gauge

The kernel already accounts per-address-space usage and exports it per-pid
through its metric catalog (`kernel/src/xray/stats.rs`: `pages_user`,
`pages_kernel`, `memory_usage`, filled unconditionally in
`collect_metrics`). What is missing is the *sys-io-provider* gauge, so one
`stats get 2` — what soak forensics already dump — shows sys-io's own
footprint next to `fs.*`/`net.*`.

In `sys-io/src/stats_server.rs`, where net and fs entries are already
concatenated per query: append `mem.self_usage_pages` (id 2000) =
`pages_user + pages_kernel` for `moto_sys::current_pid()`, read via
`moto_stats::Collector` against the kernel provider. Kernel metric ids are
provider-private, so resolve them by name from `describe` once, lazily, on
the first stats query (`OnceLock`) — no new boot-time work. The stats RPC
already allocates and is documented as unavailable mid-episode; the gauge
inherits that, which is acceptable (it is a soak/observability signal, not
an episode-time input).

### Soak observations

`src/tests/stress-soak.sh` currently dumps all metrics only in forensics.
Add a small periodic sample to the monitor loop — `net.pressure_*`,
`fs.pressure_*`, `mem.self_usage_pages` appended to the soak log each
monitor tick — so "grow the refusal set from observed soak metrics" has
recorded observations to grow from, and the doc's "watch
`net.pressure_deferred_replenish` / `net.pressure_refused_clients` in soak"
instruction is actually mechanized.

## What refusal means for clients

During an episode, `std::fs` operations fail with
`ErrorKind::OutOfMemory` (`E_OUT_OF_MEMORY` over the wire, mapped by the
existing `util.rs` conversion): recoverable, no side effects, exactly the
net-side contract. Processes that treat any I/O error as fatal will exit —
which frees memory; processes that surface the error keep running and
succeed after recovery.

## Implementation steps

Small patches per AGENTS.md; each formatted with `cargo +nightly fmt` and
warning-clean. Revised order (2026-08-07, review feedback): the regression
lands first as a *demonstrator* — validated to consistently OOM sys-io on a
build without the refusal set, then left out of the suite (standalone
subcommand `systest test-fs-pressure` only, no full-test gate for this
patch); the refusal patch then enables it in the suite and runs the full
gate (three debug + three release `full-test.sh` passes); the gauge/soak
patch follows.

**Patch 0 — the demonstrator (revised patch 2, test only).**
- `src/sys/tests/systest/src/pressure.rs`: `test_fs_under_pressure`,
  detailed under "Regression additions". Both mid-episode hammers classify
  outcomes instead of asserting per request, so on a pre-refusal build the
  lock-acquire hammer grows sys-io's lock manager past the sys-io floor and
  demonstrates the abort. Validated standalone on disposable boots, then
  left out of the suite pending the refusal set.
- Sized by the measurement above: an episode entered at the standard squeeze
  target leaves sys-io ~350 pages above its floor, and admission refuses a
  ~68-page slab growth (charge ~135 pages) once free-for-admission is within
  a charge of it — roughly 40k held locks, so the standalone default is
  100,000 (~546 pages of growth, comfortably past). In the suite (once
  refusal lands) the spam shrinks to 128: a refused acquire proves the gate
  at any size.
- **Validated on release only.** A debug guest logs several lines per FS
  request to the serial console, which throttles a 100k-request hammer below
  any usable timeout (a debug run made ~5 s of progress in 10 minutes). The
  pre-refusal demonstration is therefore a release-build exercise; the
  suite-sized version (128) is cheap enough for both builds.
- Every mid-episode probe classifies rather than asserts, and all assertions
  run after recovery. An assertion mid-episode would end the run at the first
  *successful* request on a pre-refusal build — before the lock hammer, the
  arm that actually kills sys-io, ever runs.

**Patch 1 — refusal set (~150 loc), enables the test (+ full-test gate).**
- `lib/moto-sys-io/src/api_fs.rs`: allocation-free donated-page release
  helper.
- `sys-io/src/runtime/fs.rs`: pressure gate at the top of `on_msg` with the
  `UNLOCK` carve-out; counter bump at the `fs_listener` drop site.
- `sys-io/src/runtime/fs/stats.rs`: the two counters, ids 1014/1015.
- `docs/oom-handling.md`: extend the pressure-mode bullet list and metrics
  list with the FS refusal semantics.

**Patch 2 — regression (~150 loc).**
- `src/sys/tests/systest/src/pressure.rs`: FS arms, detailed below.
- `docs/oom-handling.md`: regression-coverage section.

**Patch 3 — gauge + soak (~120 loc).**
- `sys-io/src/stats_server.rs`: `mem.self_usage_pages` (id 2000), lazily
  resolved from the kernel catalog by name.
- `src/sys/tests/systest/src/pressure.rs`: post-recovery sanity assertion on
  the gauge.
- `src/tests/stress-soak.sh`: periodic pressure/self-usage sample in the
  monitor loop.
- `docs/oom-handling.md`: observability section; remove the first open
  follow-up bullet.

## Regression additions (patch 2)

All inside the existing `test_pressure_mode` episode, reusing its child
aggressor, `assert_refused`, and read-counters-only-after-recovery
discipline:

- **Pre-squeeze**: create and open a file (which also warms the rt.vdso FS
  connection, so mid-episode ops test the established-connection path rather
  than a fresh connect), take a lock on a second open of it, and open the
  `lock_spam` handles the acquire hammer will use — opens are themselves
  refused once the flag is up.
- **Mid-episode**:
  - a write on the pre-opened file is refused with `OutOfMemory`, repeated
    4096 times — far more than the channel's 64-slot page pool, so a refusal
    that leaked its donated page would wedge the channel and fail the test;
    this is what pins the release helper;
  - the lock-acquire hammer (`lock_spam` acquires) is refused; on a
    pre-refusal build this is the arm that kills sys-io;
  - `std::fs::metadata` is refused, showing that read-only commands are in
    the set too;
  - `unlock()` on the pre-taken lock succeeds (the carve-out); a `try_lock`
    from the other handle is refused with `OutOfMemory`;
  - `moto_ipc::io_channel::ClientConnection::connect("sys-io-fs")` dies at
    one of the two hands, mirroring the existing net-client arm.
- **Post-recovery**: FS operations on the same file succeed;
  `fs.pressure_refused` advanced by at least the refusals issued;
  `fs.pressure_refused_clients` advanced iff the drop arm fired;
  `mem.self_usage_pages` present and plausible (patch 3).

`systest` runs wholesale from `full-test.sh`, so the new arms are covered
transitively, as required.

## Verification

- `src/tests/full-test.sh` ×3 debug, ×3 release per patch (one harness
  instance at a time).
- Perf: the gate is one shared-page load and a predictable branch per FS
  message; the suite's `hot_cache_read_test` and boot-time checks act as
  canaries. No new boot-time work (gauge resolution is lazy).
- Soak: one `stress-soak.sh` run after patch 3; confirm the periodic sample
  lines appear and `mem.self_usage_pages` is steady under the fs/net
  workloads.

## Decisions to confirm at review

1. **Refusal breadth** — recommended: all commands except `UNLOCK`, for the
   cold-cache reason above. The narrower alternative (exempt `CMD_METADATA`,
   `CMD_READ`, readdir) keeps read-mostly workloads alive through episodes
   at the cost of unbounded cache growth exactly when it is least
   affordable; not recommended.
2. **`CMD_FLUSH` refused** — recommended, since checkpointing can allocate;
   the alternative (allow flush for durability) contradicts the
   allocation-free rule.
3. **Gauge shape** — recommended: one gauge, `mem.self_usage_pages`, pages
   to match the doc's denomination; alternatives: bytes, or split
   user/kernel gauges.
4. **Soak-script change in scope** — recommended yes (it is what "grow it
   from observed soak metrics" needs); can be dropped to keep the change
   sys-io-only.

## Deliberately not done

- No cache shrink or reclaim under pressure (does not reliably return pages
  to the kernel pool).
- No bound on held locks or trimming of the cache free-block list: their
  growth stops during episodes once acquires and cache misses are refused;
  outside episodes memory is available and admission governs.
- No kernel changes, no new syscalls, no mid-episode metrics reads, no
  retries anywhere.
