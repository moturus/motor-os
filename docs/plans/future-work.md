# Future work -- recorded, deliberately not scheduled

## Deferred filesystem flush race (2026-09-09)

Fix after merging the pending filesystem branch, per maintainer direction.
Recheck the proposed change against that branch before implementing it.

`motor-fs` can acknowledge an explicit flush before committing all preceding
writes. This is a preexisting production race, shared by the host Tokio and
Motor OS runtime paths, not an allocator-test defect. During kernel allocator
validation, the existing host test `tests::resize_truncate_crash_regrow`
failed with `InvalidData`: main transaction 12 versus logged transaction 11.
The failure preceded the main VM boot; guest allocator code was not running.

Cause in `src/sys/lib/motor-fs/src/txn_log.rs`: the timeout task takes the
pending batch out of its shared holder before sending it to the committer.
An explicit `Flush` can already be queued ahead of that batch. The committer
then sees an empty holder, flushes earlier device writes, and acknowledges
the caller; the timeout-owned batch commits afterward. A caller that drops
and reopens the filesystem after the acknowledgment can overlap that commit.
`BlockCache::new` reads the pinned log blocks before the main superblock, so
the reopened cache can combine the previous log with the new superblock.

Temporary ordering logs on the existing concurrent filesystem suite captured
this sequence for the failing crash/regrow case (capacity 1):

1. Explicit flush requested with transaction 12, four blocks pending.
2. Timeout takes transaction 12 and queues its batch behind `Flush`.
3. Committer handles `Flush` with an empty transaction-13 holder and
   acknowledges completion.
4. Committer only now consumes transaction 12; the test concurrently reopens
   and rejects main transaction 12 versus logged transaction 11.

Both preserved disk images had matching transaction-12 headers by the time
they were copied: the later commit completed, but the reopening cache had
already observed inconsistent generations. A later consistent image does
not disprove the race.

Proposed fix: timeout tasks enqueue a transaction-ID-tagged request without
taking the batch. Only the committer handles that request by checking and
taking the matching pending batch. This keeps timeout ownership changes
ordered with explicit flushes. Preserve stale-ID checks, error propagation,
and the rule that no holder borrow spans an await. Do not mask the defect
with a longer timer or a reopen retry.

Validation: from `src/sys/lib/motor-fs`, run
`cargo test --features image-admin` in debug and release; the crate-local
Cargo configuration supplies `tokio_unstable`. These existing tests are
already part of `src/tests/full-test.sh`; the eventual production fix also
needs the normal core-OS gate. No new reproducer or test workaround was added.
All temporary source logging has been removed. Original failures, ordering
traces, diagnostic patch, and disk images are retained on the development
host under `/tmp/kernel-phys-host-shutdown.9ox3kE/` (`DIAGNOSIS.md` indexes them).

This establishes the filesystem test failure's cause, not the earlier quiet
VM exit during pressure. That separate unresolved finding and its evidence
remain in Git history (the retired kernel-phys-mem.md plan). Kernel validation resumes
with this filesystem fix explicitly deferred; no test is skipped or weakened.

## Open bugs from the 2026-08-28/29 performance run (address soon)

Found while reviewing file I/O and the async runtime; the run's report
(`docs/perf-run-2026-08-28.md`, since removed) and its measurements are in
git history. Unlike the rest of this file these are scheduled: pick them up
in this order.

The former sys-tty/kernel-log interleaving item is complete; see
[Kernel logs and the serial console](../kernel-logs.md).

1. **Loopback accepts take a second each after a dozen connections.** A
   process that connects to its own listener sees every accept take ~1.00 s
   after the first 9-15 connections: the closed connections still hold the
   NetPool reservations the listener needs, the accept pump's reservation
   request times out, and it retries after 10 ms, 100 ms, then 1000 ms
   (`rt_net: accept pump reservation failed: TimedOut; retry in ...`, which
   `test_mio_accept_pump_progress` prints on every passing run). Remote
   clients are unaffected, since their sockets live in another process, but
   loopback services and tests are: `systest close-race 300` takes 298 s, at
   HEAD and with the perf patches alike. Fix: release, or stop counting, the
   reservations of closed connections before the pump asks, and replace the
   exponential backoff with a bounded short retry. Gain: loopback accepts
   about 50x faster after a burst (20 ms instead of 1 s per connection), no
   retry noise in the suite, and the close-race reproducer usable at scale.

2. **Resolved: the allocator held its slab lock across the fallback
   `SysMem::alloc`.** The allocator now holds no lock across a backend call,
   so a backend may allocate from the allocator it backs and a thread killed
   in a syscall leaves no sibling spinning; see
   [the allocator document](../frusa.md).

3. **sys-io never returns allocator slack.** The vdso's `reclaim_resident`
   gives freed slab pages back to the kernel every 5 s, but only in
   processes that run a vdso IO runtime; sys-io drives its own runtime and
   has none, so its slab slack stays resident forever. A listener flood left
   ~76 MB of freed slab memory in sys-io in the 2026-08-15 probe, and every
   burst since keeps its high-water mark. Fix: run the same reclaim tick as
   a timer task on sys-io's runtime, with the same slack threshold and
   memory-pressure rule. Gain: sys-io's resident memory returns to its
   baseline after bursts instead of holding the peak, which matters on small
   VMs and for the memory-pressure model's accounting.

4. **Resolved 2026-09-09: `MAX_BLOCKS_IN_TXN_LOG` 256 stopped sys-io on the
   first large write.** The mechanism was descriptor retention: a completion
   held its descriptors until dropped, and the worker held completions until
   `Commit`. `docs/plans/virtio-descriptor-waiters.md` moved all block-queue
   traffic behind one I/O task that drops completions as the device finishes
   them, so batch size no longer interacts with queue depth. Raising the
   batch is still one of the write-path levers below and still unmeasured.

5. **sys-io allocates a Vec of every wait handle on each park.**
   `LocalRuntime::wait` builds the array of registered wait handles anew per
   park; sys-io registers one per channel, so under a listener flood that is
   a 16-24 KB allocation per park, which the allocator serves with a page
   map/unmap pair and a TLB shootdown IPI. Fix: keep the handle array
   resident between parks and rebuild it only when the registration set
   changes. Gain: one map/unmap and one IPI less per park while many
   channels are open (sys-io parks up to ~130k times in a benchmark run);
   the structural fix is the kernel wait-set item at the end of this file.

6. **Debug-only loopback `ConnectionReset` in the suite.** In 2 of 3 debug
   full runs with the perf patches a net test read `ConnectionReset` where
   an orderly close was expected (`poll.rs:147`: the child got an RST
   instead of "pong" after the server wrote it and dropped the stream;
   `net_driver.rs:272` in another run); the debug baseline (2 runs) and ~15
   release runs did not show it, and `systest close-race-child` did not
   reproduce it standalone (300 release and 200 debug iterations clean). The
   patches only shorten the gap between the write and the close, so this
   looks like a close/linger ordering race made likely by fast wakes and a
   slow peer. Fix: an in-suite reproducer first (the failing tests' shape
   with the suite's preceding state), then the close path. Gain: data
   written just before a close is never replaced by a reset, a correctness
   bug once it reaches a real peer.

7. **Killing the ssh session mid-suite leaves two vCPUs spinning.** Killing
   the ssh client while systest was in its pressure/admission tests (child
   processes being killed by design) twice left the guest with two vCPUs at
   100% and the network dead, once on a debug build and once on release; an
   uninterrupted run of the same image passes and leaves the guest idle. Not
   reproduced deliberately, not investigated. Fix: script the kill at that
   point, then take `mdbg print-stacks` of sys-io and of the spinning
   threads from the console. Gain: closes a hang class that any operator can
   trigger with Ctrl+C on a session.

8. **sys-io's statistics provider is absent for a moment after boot.**
   `moto_stats::Collector::providers()` does not list sys-io (provider 2)
   for a short window after boot: `systest fs-bench` started ~2 s after ssh
   came up panicked on the lookup, and two places in the suite retry around
   it. Fix: register with the stats registry before sys-io accepts its
   first client, or have the collector wait for the registry's first
   snapshot. Gain: tools and scripts read sys-io's counters as soon as the
   VM answers, and the retry loops in the suite can go.

The former item 9, `CpuStatsV1::entry`'s incorrect slice length, is fixed.
The correction and three synthetic snapshot tests pass three debug and three
release full-system gates, plus `full-test-dev.sh --release` (2026-09-06).
No package publication or stdlib change was needed. See the
[rust-analyzer gate record](rust-analyzer.md#421-release-gate-budget-stop)
for the initial cold-build timeout and approved unchanged warm-artifact run.

## Performance follow-ups from the same run (not scheduled)

What landed on 2026-08-29: kernel halt polling with IPI elision, the tree
frusa in the vdso, local `seek`, one-request path resolution, and runtime
polling of active io_channels. Measured on qemu with 4 vCPUs: a hot 4 KB
read 107 -> 9 us, crossbench sequential 4 KB read 19 -> 380 MB/s, random
read median 208 -> 6 us, write 190 -> 280 MB/s, rnetbench round trip
100 -> 41 us. `systest wake-bench` is the first number to take on a new host
or hypervisor (a cross-CPU hop is ~1 us with halt polling and ~25 us
without). Left on the table, largest first:

- **Write path** (Finding 6 of the run). Three device barriers per 64-block
  transaction batch, every data block journaled twice, and one transaction
  per 4 KB chunk of a write message; for a 20 MB write about 36 of 80 ms
  are barrier waits and the background committer tops out near 300-450 MB/s
  regardless of CPU. Levers: one transaction per message instead of per
  chunk, metadata-only journaling for newly allocated data blocks (no second
  copy of the data), and larger batches once bug 5 above is understood.
  Estimate: up to ~2x on writes.
- **Client-side work per synchronous FS op** (Finding 7). Of a ~9 us hot
  read, ~4 us is the vdso's own runtime work: boxing the task closure, a
  oneshot, `LocalRuntime::spawn` per op (five allocations), a `BTreeMap`
  response slot. Running the io task inline instead of spawning measured
  10.7 -> 8.0 us per read. Candidates: resident worker tasks or a
  `FuturesUnordered` of in-flight io tasks polled alongside the task
  channel, a slot array for responses, a preallocated per-thread request
  block. Estimate: 2-3 us per op (20-25% of a hot read), more for open and
  stat, which do two to three round trips.
- **One round trip for `open` and `stat`.** Fold the metadata into the
  `CMD_STAT_PATH` response so that a stat is one request and an open two
  (path plus create/open) instead of two and three. Estimate: 3-5 us per
  open or stat.
- **Halt-poll placement and policy.** `post()` scans from the thread's last
  CPU and treats a polling CPU as idle; the residual IPIs (0.2-1.8 per op in
  some runs) are wakes aimed at a CPU that is running, so preferring a
  polling CPU explicitly is the next step. An activity-based idle policy
  (poll only within some milliseconds of the last resumed thread) would
  cost nothing on a guest that only ticks if the idle host CPU of the
  fixed window ever matters; the KVM-style adaptive window was measured and
  rejected (it loses most of the latency win: 25 us hot reads).
- **Recorded verdicts.** The sliding read window (DEPTH 5) was dropped
  after a same-sitting A/B: cold_fs_read 269-279 vs 526-649 MB/s and
  crossbench sequential read 309-323 vs 382-435 MB/s for the batch of 4; it
  keeps 60 of the channel's 64 server pages busy and starves readahead.
  Floating sys-io's runtime thread off CPU 0 changed nothing within noise:
  the CPU 0 concentration was the affinity plus every other thread sleeping
  between hops, never the cause of the slowness. The cloud-hypervisor
  cross-check showed the same effects as qemu.
- Networking follow-ups from the run (small-write throughput under halt
  polling, RX batching, per-packet wakes) are in
  `networking-remaining-steps.md`.

## Recorded, deliberately not scheduled

Items moved out of active plans by explicit ruling. Each entry names
the ruling; nothing here should be picked up without a fresh call.

- **Per-process resident-memory accounting and peaks** (deferred from
  rust-analyzer by U. Lasiotus, 2026-09-06). The current kernel
  `memory_usage` metric counts virtual mappings, including shared mappings
  and lazily mapped stacks; it is not resident physical memory (RSS).
  `MemoryStats::get()` reports physical use for the whole system, not each
  process. Design per-process resident accounting and high-water reporting,
  with explicit shared-page attribution and allocation/reclamation semantics,
  before implementation. This would support reliable memory-regression
  measurements for rust-analyzer, compilers, and other applications. It is
  not a prerequisite for native rust-analyzer: use existing counters and
  label sampled maxima and whole-VM physical usage accurately meanwhile.

- **Complete descendant-process execution audit** (deferred from
  rust-analyzer by U. Lasiotus, 2026-09-06). `ProcessInfoV1::list` can omit
  exited processes with no running descendants, and its debug names are
  limited to 32 bytes. Periodic snapshots therefore cannot establish a
  complete history of executed programs or arguments. Design an opt-in,
  bounded execution-event facility with process/parent identity, executable
  identity, explicit event-loss reporting, and reviewed access/privacy rules
  before implementation; arguments may contain secrets. It should capture
  short-lived descendants without polling races or extra boot-time work.
  This would support execution audits beyond rust-analyzer. Native
  rust-analyzer acceptance may use invocation logs and sampled descendants,
  stating that this evidence is non-exhaustive; it must not depend on this
  new OS facility.

- **`channel.rs` SeqCst fence audit** (out of scope, ruled
  2026-08-15). The io_channel wake edges now carry their own ordering;
  the SeqCst fences predate that and are likely removable. Removing
  them is its own independently-tested step whose perf verdict should
  close promptly in the same sitting -- correctness-sensitive and
  unhurried, so it waits for a sitting dedicated to it.

- **Wire `sysbox syslog`** (moved out of the networking ledger,
  2026-08-15: not networking). `do_syslog` exists unwired, and nothing on
  the image reads the kernel log remotely. Ordinary rt.vdso diagnostics now
  go to stderr first, and authorized service records go through System-role
  strobe to `/system/logs`; the kernel log remains relevant for kernel and
  direct `SysRay::log` records and for the capability-gated fallback when
  stderr fails. A remote reader is therefore still useful, but no longer the
  primary way to diagnose every headless daemon. The related console-buffer
  drain is worth a look in the same sitting: fallback panic text can be lost
  when the console buffer does not drain before teardown, which is why a vdso
  panic on that path can present as silent exit-222.

- **Resolved 2026-08-20: intermittent `moto_async` channel hang.**
  It recurred in `test_moto_channel_multithreaded`; a focused unchanged
  reproduction stalled on round 26. Two `mdbg` snapshots showed both sender
  threads had exited while the receiver alone remained parked. The last
  `Sender` used to wake the receiver from its `Drop` body before Rust
  dropped the underlying MPMC sender field, allowing the receiver to register
  after the early wake, still observe a connected empty channel, and sleep
  forever. Sender teardown now drops the underlying endpoint before the
  last-sender notifier. A deterministic regression holds teardown inside the
  old gap while the receiver re-registers; the fixed focused suite then
  passed 100 consecutive runs under the same stall detector. No retry or
  timeout workaround was added.

- **kernel `wait-set`** - a kernel-side wait-set/aggregation primitive
  (the structural fix). Beyond the cap, the current shape is O(n) per park: every SysCpu::wait
  re-validates and re-registers all ~1024 objects (the loop in sys_cpu.rs:78-121), on every one of sys-io's ~130k waits in this run. An
  epoll-like kernel object — register a handle once into a wait set, block on the set's single handle — removes both the cliff and the
  per-wait linear cost. This fits the netstack-scalability trajectory, but it's a significant kernel + moto-async project.

- **virtio queue: smarter allocation-waiter wakeups** (recorded 2026-09-08
  from `virtio-descriptor-waiters.md`, v03). Releasing a descriptor chain
  wakes at most two queued allocation waiters, and a waiter that does not
  fit re-registers at the back of the line. Under the single-owner design
  the block queue has one submitter that never waits in the driver, and
  each net queue has one submitter, so at most one waiter exists per queue
  and the policy is moot. It matters again only if a queue ever gets
  several independent allocators; the v02 review showed that waking the
  first waiter only can then starve a fitting waiter behind a non-fitting
  one once the last in-flight request has completed. Options then: wake
  every waiter, or select the first that fits from per-entry sizes and a
  free-descriptor count.

- **Block I/O task: recover the sequential cost** (recorded 2026-09-09 from
  `virtio-descriptor-waiters.md`). The single-owner task costs 3 to 5
  percent of sequential throughput against the old driver. Three measured
  changes recover it and more (593 versus 506 MiB/s for 4 KiB sequential
  reads): drain the used ring at the start of the task's poll, keep a
  single-chunk response inline instead of in shared state, and a channel
  receiver that does not spin on an empty inbox, with the inbox at 16
  entries. Not adopted because the 64-thread p99 latency rose from 5.9 to
  10.7 ms and one boot showed TCP throughput halving under 16 saturated disk
  readers. Pick up only with a matched-load network measurement and the
  threaded latency probe; patch and data under `build/virtio-waiters-results/`.
