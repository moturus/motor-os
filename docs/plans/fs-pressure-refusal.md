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
| block cache (`BlockCache`, `motor-fs` `CACHE_SIZE = 4096`) | 16 MiB | **yes** — every miss can allocate a fresh 4 KiB `IoBuf` (`block_cache.rs` `pop_free_block`), from any command, until warm |
| cache free-block list, expiring map | unbounded, never trimmed | only via cache churn above |
| lock manager held locks (`lock_manager.rs` `files`/`connections`) | unbounded | yes — each new acquire can insert entries |
| readahead tasks (`fs.rs` `maybe_readahead`) | no in-flight cap | yes — spawned by reads, each prefetches up to 32 blocks |
| per-request transients (task `Box::pin`s, path `String`s, decode `Vec`s) | 64 in flight per connection | bounded and released per request |
| txn machinery, virtio rings, device vectors | fixed or per-request | no |

The block cache is the decisive one: its 16 MiB ceiling is ~4096 pages, an
order of magnitude more than the whole gap between the pressure watermark and
the sys-io floor. The doc's rule — "any sys-io structure that can keep growing
while pressure is active must be bounded, reclaimed, or added to the refusal
set" — leaves three options:

- **Bounded**: the cache is bounded, but far above the episode budget; the
  bound does not protect the floor.
- **Reclaimed**: evicting cache blocks returns `IoBuf`s to sys-io's allocator
  free lists; nothing guarantees pages return to the kernel's small-page
  pool, so reclaim cannot be counted on to clear system pressure.
- **Refusal**: deterministic, allocation-free, mirrors the net side. Chosen.

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

Small patches per AGENTS.md; each formatted with `cargo +nightly fmt`,
warning-clean, and gated on `src/tests/full-test.sh` passing three times as
debug and three as release before commit.

**Patch 1 — refusal set (~150 loc).**
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

- **Pre-squeeze**: create and open a file, do one metadata read (warms the
  rt.vdso FS connection so mid-episode ops test the established-connection
  path, not a fresh connect), and take a lock on a second open of it.
- **Mid-episode**:
  - `std::fs::metadata` and a write on the pre-opened file are refused with
    `OutOfMemory`;
  - repeat the refused write more times than the channel's 64-slot page pool
    (e.g. 96): if refusal leaked donated pages, the client's pool runs dry
    and the test fails — this pins the release helper;
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
