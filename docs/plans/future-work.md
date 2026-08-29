# Future work -- recorded, deliberately not scheduled

## Open bugs from the 2026-08-28/29 performance run (address soon)

Found while reviewing file I/O and the async runtime; the run's report
(`docs/perf-run-2026-08-28.md`, since removed) and its measurements are in
git history. Unlike the rest of this file these are scheduled: pick them up
in this order.

1. **sys-tty interleaves application output with the kernel log, which
   breaks the debug full test.** The console driver's stdout relay writes
   each chunk it reads (80 bytes at most) under its own `SERIAL1` lock
   acquisition while the main thread drains the kernel log ring in between
   (`sys-tty/src/main.rs`), so a log line can land inside an application's
   escape sequence. In a debug build the vdso's `file_open`/`stat` logs and
   sys-io's TCP logs add ~1200 lines to the console while rmux runs, and
   `src/tests/test-terminal-size.sh` fails at clean HEAD 228e46c6 (two
   clean-worktree runs and three full runs: "the console resize did not
   reach red inside rmux"); release builds emit no debug logs and pass. The
   leg passed on 2026-08-15; the test and the tty changed on 08-23..26
   (9c5421a7, 13735ac7, 4939cdbb), not bisected. Fix: one serial writer that
   emits whole chunks and drains the log ring only between them, or hold the
   lock across a relay burst. Gain: the debug half of the AGENTS.md test
   requirement becomes runnable again (every debug `full-test.sh` stops
   there today), and console TUI output stays intact whenever the kernel
   log is busy.

2. **Loopback accepts take a second each after a dozen connections.** A
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

3. **frusa holds its slab lock across the fallback `SysMem::alloc`.** The
   allocator's spin lock stays held while a slab grows through the fallback
   path, i.e. across the syscall; any allocation on that path (a `format!`
   in a diagnostic, a log record) self-deadlocks the thread, and a thread
   killed while holding the lock leaves every sibling spinning. A sampling
   diagnostic in `SysMem::map` reproduced it in 6 of 12 listener-flood runs
   during the perf run (sys-io stopped with two vCPUs spinning; diagnosed
   through the qemu monitor). Fix: grow outside the lock (allocate the new
   block, then take the lock to link it), or make the fallback path
   allocation-free by contract with a debug assertion. Gain: removes a
   self-deadlock class from every process, sys-io included, and makes the
   allocator safe to instrument.

4. **sys-io never returns allocator slack.** The vdso's `reclaim_resident`
   gives freed slab pages back to the kernel every 5 s, but only in
   processes that run a vdso IO runtime; sys-io drives its own runtime and
   has none, so its slab slack stays resident forever. A listener flood left
   ~76 MB of freed slab memory in sys-io in the 2026-08-15 probe, and every
   burst since keeps its high-water mark. Fix: run the same reclaim tick as
   a timer task on sys-io's runtime, with the same slack threshold and
   memory-pressure rule. Gain: sys-io's resident memory returns to its
   baseline after bursts instead of holding the peak, which matters on small
   VMs and for the memory-pressure model's accounting.

5. **`MAX_BLOCKS_IN_TXN_LOG` 256 stops sys-io on the first large write.**
   Raising the transaction-log batch from 64 to 256 blocks compiles (the
   superblock still fits) but the first 20 MB write stops sys-io without a
   panic. The likely mechanism: `write_blocks_with_completion` posts every
   16-block chunk of a run before awaiting any, a 256-block batch is 16
   requests of 18 descriptors = 288 entries against a 256-entry virtqueue,
   and descriptors are reclaimed only when a completion is awaited -- the
   shape the July TSO work hit on the net side; 64-block batches post at
   most 72. Fix: bound the in-flight descriptors per run (await a completion
   when the queue is full) or derive the batch size from the virtqueue
   depth. Gain: unblocks the write-path work below (a larger batch is one of
   its three levers) and removes a latent stall for any device with a
   smaller queue.

6. **sys-io allocates a Vec of every wait handle on each park.**
   `LocalRuntime::wait` builds the array of registered wait handles anew per
   park; sys-io registers one per channel, so under a listener flood that is
   a 16-24 KB allocation per park, which the allocator serves with a page
   map/unmap pair and a TLB shootdown IPI. Fix: keep the handle array
   resident between parks and rebuild it only when the registration set
   changes. Gain: one map/unmap and one IPI less per park while many
   channels are open (sys-io parks up to ~130k times in a benchmark run);
   the structural fix is the kernel wait-set item at the end of this file.

7. **Debug-only loopback `ConnectionReset` in the suite.** In 2 of 3 debug
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

8. **Killing the ssh session mid-suite leaves two vCPUs spinning.** Killing
   the ssh client while systest was in its pressure/admission tests (child
   processes being killed by design) twice left the guest with two vCPUs at
   100% and the network dead, once on a debug build and once on release; an
   uninterrupted run of the same image passes and leaves the guest idle. Not
   reproduced deliberately, not investigated. Fix: script the kill at that
   point, then take `mdbg print-stacks` of sys-io and of the spinning
   threads from the console. Gain: closes a hang class that any operator can
   trigger with Ctrl+C on a session.

9. **sys-io's statistics provider is absent for a moment after boot.**
   `moto_stats::Collector::providers()` does not list sys-io (provider 2)
   for a short window after boot: `systest fs-bench` started ~2 s after ssh
   came up panicked on the lookup, and two places in the suite retry around
   it. Fix: register with the stats registry before sys-io accepts its
   first client, or have the collector wait for the registry's first
   snapshot. Gain: tools and scripts read sys-io's counters as soon as the
   VM answers, and the retry loops in the suite can go.

10. **`CpuStatsV1::entry` uses the wrong slice length.**
    `moto-sys/src/stats.rs` builds the per-CPU slice with
    `self.num_entries` as its length instead of `num_cpus` (lines 128-131),
    so the slice overruns into the next entry when there are more entries
    than CPUs and would panic if a process list ever had fewer entries than
    CPUs; harmless today only because callers index `[cpu]`. Fix: a one-line
    length correction with a unit test; moto-sys is a runtime input, so it
    ships with the next moto-sys bump. Gain: correct per-CPU statistics for
    `top` and the benchmarks, and no latent panic.

11. **The dev-image suite refuses a host with two assemblies.**
    `full-test-dev.sh` passes the main suite and TEST-DEV-SOURCES, but
    Lorry's `current-toolchain.sh` refuses when two assemblies exist for the
    toolchain key under `assemblies/` ("expected one assembly manifest ...;
    set LORRY_ASSEMBLY_MANIFEST explicitly"), and setting that variable makes
    `current-toolchain-contract.sh` fail silently because the contract test
    inherits it. Older assemblies are retained on purpose
    (`docs/assembly-selection.md`), so every host that has rebuilt one after
    a runtime-input commit is affected. Fix: prefer the assembly the checkout
    selected (`.motor-os/assembly-pins`) over directory discovery, and
    `unset LORRY_ASSEMBLY_MANIFEST` at the top of the contract test. Gain:
    the dev-image suite runs on such hosts again, which AGENTS.md asks to
    run in release mode for all non-Lorry work.

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
- **Publish frusa 0.1.4** and switch the vdso back to the registry
  dependency (the download-statistics reason of 1e51744c). The tree crate
  is versioned 0.1.4 and the vdso links it by path until then.
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
