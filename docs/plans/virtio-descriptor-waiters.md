# Virtio block descriptors: one owner for the block queue

2026-09-09, v05: implemented; results at the end. v03 replaced the
worker-side headroom design with a single I/O task that owns all block-queue
traffic; v04 folded in the review of v03 (channel handling, flush support,
migration order, the unsafe boundary, idle and shutdown handling).

## Terms used below

- **Descriptor.** One slot in a virtio queue. A device request is a chain of
  descriptors: for the block device, one for the request header, one per
  4 KB data block, one for the status byte. A one-block read or write is a
  chain of 3, a 16-block write a chain of 18, a flush a chain of 2.
- **Queue size.** The number of descriptors the queue has. Cloud Hypervisor
  (CHV) gives the block device 128 by default; QEMU gives 256 (our
  `run-qemu.sh` sets no size).
- **Request block cap (`seg_max`).** The most data blocks the device accepts
  in one request. QEMU: 126. CHV: 62. Firecracker: 1. Motor never issues
  more than `MAX_IO_RUN` = 16 blocks per request, so on QEMU and CHV a
  16-block run is always one request; on Firecracker it is 16 requests. A
  run that needs more than one request is called split below.
- **Completion.** The future a submitted request returns (`VqCompletion<T>`
  inside `WriteCompletion` / `ReadCompletion`). It owns the caller's buffer
  `T`. The request's descriptors are released when this completion is
  dropped, not when the device finishes the request. This contract stays.
- **The worker.** The block-cache background task in
  `src/sys/lib/async-fs/src/block_cache.rs` that submits writes on behalf of
  motor-fs and holds their completion futures until a `Commit` message.
- **The adapter.** `VirtioPartition` in
  `src/sys/sys-io/src/runtime/fs/virtio_partition.rs`, the `AsyncBlockDevice`
  implementation over the virtio block driver.
- **The I/O task.** New in this design: one task per virtio block device
  that is the only caller of the driver. Everything else sends it messages.

## Problem

In the release developer image, `lorry test` from
`/devtools/src/motor-os/bin/red` hangs under CHV and completes under QEMU.
Raising CHV's queue size hides the symptom; changing vCPU count or the disk
I/O backend does not. Queue size is a diagnostic variable, not the fix.

### Retained completions exhaust the queue

The worker submits each write and keeps its completion until `Commit`. A
finished write still holds its descriptors until then. With one-block
writes:

1. 42 retained writes hold 126 of CHV's 128 descriptors.
2. Write 43 needs 3 and waits for descriptors to be released.
3. The worker is the task waiting, so it never reaches `Commit`.
4. Every device operation has finished; the descriptors are held by
   completion objects nobody will drop. Waking allocation waiters cannot
   help.

Related cases the fix must cover:

- The adapter holds the completions of a split write's earlier requests while
  submitting its later ones. Bounding one request does not bound the write.
- 41 one-block writes plus one three-block write fill all 128 descriptors; a
  flush then needs 2 more.
- 42 retained writes followed by a cache-miss read from another task: the
  read needs 3 descriptors. Motor-fs's transaction ordering happens to avoid
  this today; the async-fs API does not enforce it.

### Stale allocation waiters

Releasing a chain wakes at most two queued allocation waiters. A waiter that
registered and then went away (its future dropped) leaves a dead entry that
absorbs a wake. A waiter that is polled again while still queued registers
twice. Either way a live waiter can stay asleep with descriptors free.
Cancelling an allocation wait before submission leaves no DMA running; it is
a different situation from dropping an in-flight completion.

## Validation against `927f1125`

### Retained completions

- `Virtqueue::reclaim_used` (`src/sys/lib/virtio-async/src/virtio_queue.rs`,
  655-700) clears the device-owned flag along the chain but releases the
  chain only if the completion-owned flag is already clear. That flag is
  set in `add_buffs` (619) and cleared nowhere but `VqCompletion::drop`
  (811-842). `alloc_descriptor_chain` (492-534) stops at the first
  descriptor with either flag set.
- The worker (`block_cache.rs`, 496-519) pushes each write's completion onto
  a deque and awaits them only on `Commit`. Its channel holds 64 messages;
  retaining dozens of completions is by design.
- motor-fs `commit_txn_batch` (`src/sys/lib/motor-fs/src/txn_log.rs`, about
  444-548) first writes the batch to the log in chunks of 16 consecutive
  blocks (at most 72 descriptors) and commits, then writes the main area as
  one request per run of consecutive block numbers and commits. A batch
  holds up to 62 non-superblock blocks (`MAX_BLOCKS_IN_TXN_LOG` = 64,
  `layout.rs:38`, minus the superblock; the batch closes when the next
  transaction would overflow it). If none are adjacent, the main-area phase
  needs 62 requests of 3 = 186 descriptors before the worker can reach
  `Commit`. That fits 256 and not 128. Replay of the transaction log on
  mount (`replay_txn_log_if_needed`) goes through the same committer.
- Hang mechanics: the first write that does not fit enters `VqAlloc::poll`,
  fails, drains the used ring (nothing new), registers a waker and sleeps.
  The only release path is `VqCompletion::drop`, and every retained
  completion belongs to the sleeping worker. The debug monitor task
  (`virtio_queue.rs`, 311-377) reclaims used entries and wakes completion
  waiters; it cannot release retained chains.
- The adapter's `write_blocks_with_completion` (204-247) submits every
  request of a split write before returning the joined completion, and
  `read_blocks` (127-182) does the same for split reads. On a device that
  splits, either can sleep waiting for descriptors while holding the
  completions of the requests it already submitted.

### Storage-only

The net driver uses the same queue code. Its callers follow the rule stated
at `virtio_net.rs:92-98`: `tx_task`
(`src/sys/sys-io/src/runtime/net/device.rs`, 376-411) awaits and drops its
oldest completions until `MAX_TX_DESCS` descriptors are free before every
`post_write`; `rx_task` (270-368) keeps exactly `rxq_sz` reads posted and
awaits them in order. Each net queue has exactly one submitting task. The
block queue has several: the worker, every cache-miss reader, prefetch and
flush. That is the structural difference this design removes.

### Stale waiters are latent on storage

`VqAlloc::poll` (142-167) pushes a waker clone on every `Pending` return;
`free_descriptor_chain` (558-565) pops and wakes at most two. No sys-io FS
path cancels an in-flight `post_*` future (no `select` or timeout under
`runtime/fs.rs` or `runtime/fs/`; the worker and committer tasks are never
dropped), so dead entries from cancellation do not occur on storage today.
Duplicate entries from re-polls can. A robustness defect, not the CHV cause.

### Premature drop is silent

`VqCompletion::drop` (811-842) leaves device-owned descriptors marked and
then drops `data`, the DMA source or target, with no check; its
`debug_assert_eq!` only compares the two flags along the chain. No HEAD
holder (worker, adapter, `read_blocks`, `post_flush`, net `rx_task` and
`tx_task`) drops an in-flight completion, so making the check fatal adds no
abort on an existing path.

### Same mechanism, already on record

`docs/plans/future-work.md`, item 4 of its open-bugs list, describes the
256-block batch experiment stopping sys-io on the first large write: 16
requests of 18 descriptors = 288 against a 256-entry queue, released only
when their completions are awaited. That is this bug with a streaming
workload and a larger batch. Step 2 below resolves it; close that item when
Step 2 lands.

### Host build

`cargo check -p virtio-async` fails on the host inside `moto-async`
(`timeq.rs:12`, `compile_error!` for non-Motor targets). The driver, the
adapter and the I/O task run only in a guest.

### Facts the design relies on

- `futures::select!` and `core::future::poll_fn` are already used under the
  local runtime in sys-io (`runtime/net.rs`, `runtime/net/icmp.rs`), and
  sys-io depends on `futures 0.3`.
- `moto_async::channel` is a bounded multi-sender channel (`Sender: Clone`);
  `moto_async::oneshot` exists. The worker already uses both.
- The driver's block entry points are called only by the adapter, except
  `post_read`, which `runtime/fs.rs:321` uses once at boot to read the MBR.
- sys-io mounts exactly one motor-fs partition per device (`runtime/fs.rs`,
  330-370, panics on a second), so one I/O task per device is one per queue.
- `IoBuf::new_from_size_align(4096)` buffers are one physically contiguous
  page; the driver already submits them as a single address and length.
- systest reads sys-io's FS counters (`read_sys_io_fs_metrics` in
  `systest/src/fs.rs`), including device write requests and blocks
  (`FS_DEVICE_WRITES`, `FS_DEVICE_WRITE_BLOCKS`; the adapter counts one
  request per submitted chain).
- `TxnBatch::renew` (`txn_log.rs`, 59-69) stamps the next batch's start at
  the moment the previous one is taken, so a batch's 500 ms timer includes
  the latency of the flush that took its predecessor.
- `moto_async::channel::Receiver::recv()` (`channel.rs`, 267-277) dequeues
  a message when the future is *created*, not when it is polled. A `recv`
  future built and then dropped unpolled, as the losing branch of a
  `select!` would be, loses that message. The task loop below therefore
  never builds a `recv` future it does not poll in the same step.
- `Sender::send` (`channel.rs`, 176-254) either enqueues the message and
  returns `Ready(Ok)` in the same poll, or keeps the message inside the
  future. An accepted message is never lost to cancellation, so "after
  `send().await` returned `Ok`" is a precise moment.
- `virtio_async::BlockDevice` keeps `flush_enabled` private; `post_flush`
  returns `Unsupported` before submitting when it is false, and the worker
  treats that as "flush not supported" (Firecracker).

## Approaches set aside

- **Release descriptors at device completion inside the driver** (the Linux
  `virtqueue_get_buf` behaviour). Correct and general, but about 250 driver
  lines plus a per-request result record and its storage design.
- **Worker-side headroom** (v01, v02): the worker makes room for its next
  write by completing old ones. Its correctness rested on a headroom
  invariant, a wake policy in the driver, and an assumption about producer
  message ordering that the async-fs API does not guarantee; the v02 review
  found two liveness holes (a fitting waiter starved behind a non-fitting
  one after the last in-flight completion, and a reader waiting on a
  producer message that waits on the reader). Fixable, but only by adding
  rules on a queue that several tasks allocate from independently.

## Buffer and completion contract

- Buffer types and wrappers may contain non-static references. Keep the
  generic bounds in async-fs and virtio-async as they are; no added
  `'static` or `Send`. Buffers therefore never move into a message owned by
  another task.
- `VqCompletion<T>` keeps the caller's `T`. Dropping it while the device
  still owns the request is a programming error and must panic in debug and
  release builds. Early cancellation is not supported. The same rule applies
  to the reply futures introduced below, which own the buffers a request is
  using.
- Distinguish a request the device has already finished (its used entry is
  published) from one still in flight; an unpolled completion need not mean
  ongoing DMA.
- Sys-io aborts on panic in both profiles, so the checks are fatal. They
  cannot detect `mem::forget`; they are not a general cancellation guarantee.
- Do not redesign `IoBuf`, add DMA leases or bounce buffers, or extend the
  runtime to support cancellation.

## Design: one owner for the block queue

### Principle

One task per virtio block device, the I/O task, is the only code that
submits to the queue. Every read, write and flush from the filesystem is a
message to it. Because it is the only allocator:

- It knows exactly what is in flight. The queue can be full only of its own
  in-flight requests, which the device will finish.
- It never waits inside the driver. It submits with non-blocking entry
  points that report "no room" instead of sleeping; when there is no room,
  it keeps the request pending and waits for one of its own in-flight
  requests to finish.
- It awaits every completion as soon as the device finishes it and drops it
  at once, releasing the descriptors. Results travel to requesters over
  oneshots. Nobody outside the task ever holds a descriptor.

Why this cannot deadlock: the only thing the task ever waits for is a
completion of a request it has already submitted, and the device finishes
every submitted request. A pending request therefore always gets room
eventually, and no waiter, wake policy or producer message ordering is
involved. The driver's allocation-waiter queue is no longer used by storage
at all; on the net side each queue has exactly one submitter, as before.

What this changes for the rest of the system: nothing in async-fs, motor-fs
or the `AsyncBlockDevice` trait. The worker still holds write result futures
until `Commit`, but they no longer hold descriptors, so the retention is
harmless. Readers still call `read_block`; the call now sends a message and
awaits the reply.

### Messages

The inbox is a bounded `moto_async::channel` (capacity 64, matching the
worker's channel), one cloneable sender shared by the adapter's methods.
Messages carry physical addresses, never buffers:

- `Read { first_sector, pages: Vec<u64>, reply }`: one 4 KB page address
  per block; reply `Result<()>`.
- `Write { first_sector, pages: Vec<u64>, reply }`: same; reply `Result<()>`.
- `Flush { reply }`: reply `Result<()>`.

Rules:

- Inbox order is submission order. The device may complete requests in any
  order; nothing here depends on completion order.
- A request with no pages is answered `Ok` at once without touching the
  device, as the adapter's empty run does today.
- A request whose `pages` exceed the request block cap is split by the task
  into `ceil(n / seg_max)` device requests of at most `seg_max` blocks each.
  Its reply is sent only when every chunk has been submitted and every
  submitted chunk has completed; the reply carries the error of the
  lowest-numbered failed chunk, which is today's "first error in request
  order". All chunks are submitted even after an earlier one failed, as
  today.
- Flush has no barrier semantics of its own beyond inbox order: it is
  submitted after every earlier message was submitted, not after those
  completed. Motor-fs already awaits its writes (`Commit`) before asking
  for a flush, so a `Flush` message always follows the completion of the
  writes it is meant to cover. Unchanged from today.
- A flush on a device without flush support never becomes a message: the
  adapter checks a new `BlockDevice::flush_supported()` and returns
  `Unsupported` directly, which the worker already handles.

### Buffers stay with the requester

The adapter's methods keep the generic `T`. `read_block(block, T)` checks
the buffer is one 4096-byte page (the size checks move here from the driver
entry points that are removed), takes its address from
`T.as_mut().phys_addr()`, sends `Read`, and awaits a reply future that owns
`T` and the oneshot receiver; on success it sets the buffer length to 4096
and returns `(T, result)`. `read_blocks` does the same with one `Read` for
the whole run. `write_blocks_with_completion` returns the trait's
`Completion`: a future owning the `Vec<CheckpointedBlock>` and the oneshot
receiver, resolving to `(blocks, result)` exactly as today. The buffers are
alive for as long as the device may touch them because the future owning
them is alive until the reply arrives.

Reply guard lifecycle:

- Armed at construction, which happens only after `send().await` returned
  `Ok`; there is no await between the two. Before that point the buffer is
  owned by the method's frame and no DMA can be pending, so a caller dropped
  while waiting for inbox admission frees nothing the device is using.
- If admission fails (the task is gone), the method returns the buffer with
  an error and constructs no guard.
- Dropping an armed guard before the reply future resolved panics. This is
  strict on purpose: it does not ask whether the reply has already arrived,
  because the oneshot exposes no readiness query and adding one is a
  moto-async change. No current holder drops a reply future before awaiting
  it (worker deque and `Commit`, `get_block`, `prefetch_range`,
  `BlockCache::new`, `flush`), and the contract does not support early
  cancellation.

### The task loop

State: `pending: Option<Request>` (accepted from the inbox but not fully
submitted; for a split request, a cursor to the next chunk), `inflight`, the
set of submitted device completions each tagged with its request and chunk
index, and `inbox_open: bool`.

The loop does not use `select!`: `recv()` dequeues at construction (see
facts), so a `recv` future must be polled in the step that builds it. One
`poll_fn` per iteration does that:

    loop {
        let event = poll_fn(|cx| {
            if !inflight.is_empty() {
                if let Ready(Some(done)) = inflight.poll_next_unpin(cx) {
                    return Ready(Event::Done(done));
                }
            }
            if pending.is_none() && inbox_open {
                let mut recv = inbox.recv();           // may dequeue right here
                if let Ready(msg) = Pin::new(&mut recv).poll(cx) {
                    return Ready(Event::Msg(msg));     // never dropped unpolled
                }
            }
            if inflight.is_empty() && (pending.is_some() || !inbox_open) {
                unreachable!()  // see the invariant below
            }
            Pending
        }).await;

        match event {
            Event::Msg(Some(msg)) => pending = Some(Request::from(msg)),
            Event::Msg(None) => inbox_open = false,   // inbox closed: drain, then exit
            Event::Done(done) => deliver(done),
        }
        while let Some(req) = pending.as_mut() {      // submit what fits
            match try_submit(req.next_chunk()) {
                Some(completion) => { inflight.push(completion); req.advance(); if req.all_submitted() { pending = None } }
                None => break,                         // full of our own requests; wait for one
            }
        }
        if !inbox_open && inflight.is_empty() && pending.is_none() { return; }
    }

`deliver` drops the driver completion (releasing its descriptors), records
the chunk's result on its request, and sends the reply when the request's
last chunk is in. The inbox is polled only while nothing is pending, so the
channel's bound still applies backpressure to callers; `FuturesUnordered`
is polled only while non-empty, since an empty one reports `None` instead
of waiting. Invariant: a request blocked on capacity implies `inflight` is
non-empty, because an empty queue fits any single request (the driver
asserts chains fit half the queue) and a request with no pages never
reaches `try_submit`. The `unreachable!` above checks it.

The completion set is `futures::stream::FuturesUnordered`. Its per-future
wakers are `Arc` based rather than the runtime's `LocalWaker`; whether that
matters is a Step 4 measurement, not a design decision.

### Driver entry points

`virtio_blk.rs` gains non-blocking, address-based variants of the block
operations, each returning `None` when the queue has no room, with nothing
allocated and no waiter registered:

- `unsafe fn try_read(sector, pages: &[u64]) -> Option<RawCompletion>`
- `unsafe fn try_write(sector, pages: &[u64]) -> Option<RawCompletion>`
- `fn try_flush() -> Option<RawCompletion>` (call only when
  `flush_supported()`; asserted)
- `fn flush_supported() -> bool`

They are `unsafe` because the driver no longer owns the buffers: the caller
promises that every page address is the physical address of a readable (for
writes) or writable (for reads) 4096-byte page that stays allocated and
untouched until the returned completion resolves. The I/O task is the only
caller and gets that promise from the reply guards. `RawCompletion` is
`WriteCompletion<()>`: it resolves to `Result<()>` from the device status
byte, as `post_flush` already does with `bytes = ()`. Implementation is the
existing chain-building code with `Virtqueue::alloc_descriptor_chain`
called directly (it already fails without waiting) instead of awaiting
`VqAlloc`. `post_read` stays for the boot-time MBR read; `post_read_many`,
`post_write`, `post_write_many` and `post_flush` lose their last callers in
Step 2b and are removed there.

### Where the task lives

One per `virtio_async::BlockDevice`, created where the device is set up in
`runtime/fs.rs` and handed to the partition as a cloneable sender. Today
that is one task per queue; if a second partition on the same device were
ever mounted, both would share the task, which is the property that matters.

### Costs and what to measure

Every read and write gains an inbox send, a task poll and a oneshot, a few
microseconds against a device latency of a hundred or more. Cold reads are
boot critical, so Step 4 measures before and after on the same image: boot
time to services, small cold reads (a single cache-miss `get_block`), the
fs `smoke_test` read and write MB/s and sys-io CPU, `fsbench`, and the llvm
startup time that the scatter-gather read work used (`3f3f5d60`: cold read
145 to 342 MB/s, llvm startup 0.8 to 0.21 s). Hot-cache reads are unaffected
and serve as a control. If cold reads regress beyond noise, attribute the
cost first (channel handoff, oneshot allocation, `FuturesUnordered` wakers,
scheduling) and fix that; no remedy is chosen in advance.

Split requests on Firecracker regain pipelining: the task submits chunks as
room appears and never waits inside the driver.

## Step-by-step plan

Each step is one patch, reviewed before the next. Sizes are estimates;
split a step rather than exceed about 300 lines including tests.

### Step 0: reproduction in `systest` (no fix)

A new case in `src/sys/tests/systest/src/fs.rs`, run by `fs::run_tests()`
in the suite and by a `systest test-fs-scattered-writes` subcommand for a
manual CHV run. It must hang on CHV at the baseline and pass after Step 2,
and it checks its own preconditions so a pass means the workload had the
shape that hangs a 128-entry queue.

- Create 248 files of 1024 bytes each in the temp dir, in order, then flush
  the filesystem with `moto_rt::fs::flush(fd)` on any open file, the call
  `concurrent_flush_stress_test` uses; it sends sys-io's flush command,
  which commits the pending transaction batch and flushes the device. This
  empties the batch left over from the creations. A 1024-byte file is
  stored inline in its own entry block (`INLINE_CAPACITY` = 3640), so each
  file is one block.
- Read sys-io's device write request and block counters.
- Overwrite the first 1024 bytes of every fourth file (62 files), opening
  each with `write(true)` and no truncate, then flush the same way. Each
  overwrite is one transaction dirtying exactly one block (`do_write_txn`
  inline path plus `set_file_size_in_entry`, same block). 62 is the batch's
  non-superblock capacity, so they form one batch if they finish inside the
  timer; the timer started at the previous flush, and 62 small writes take a
  few milliseconds against 500 ms.
- Read the counters again. Over the batch: 62 log blocks in 4 requests, 1
  superblock write to the log, `runs` main-area requests for 62 blocks, 1
  superblock write. Assert the block delta is exactly 126 (no unrelated
  writes) and `runs = requests - 6 >= 34`: the main-area phase then needs
  `62 + 2 * runs >= 130` descriptors, more than 128. Print `runs` and the
  overwrite phase's elapsed time; on an assertion failure that output says
  whether adjacency or the timer broke the precondition. No retry.
- Read every file back and check contents; delete them.
- At the baseline on CHV the second flush never returns: the committer's
  flush waits on the worker, which waits for descriptors it holds itself.
  The failure is a hang, reported by the gate's timeout or the person
  running it. No watchdog.
- Manual CHV run: `vm_images/release/run-chv.sh` boots the main image on the
  same tap and address the QEMU scripts use, so
  `vm_images/release/ssh-into-motor-os-vm.sh` and `scp` work unchanged.

### Step 1: driver, non-blocking address-based entry points (~80 lines)

`try_read`, `try_write`, `try_flush`, `flush_supported` and
`RawCompletion` as specified, with the unsafe contract documented on the
entry points. Existing entry points untouched. No caller yet, so this patch
is reviewed together with Step 2 and committed only once Step 2b's gate run
passes; that run is its test.

### Step 2a: the I/O task module, not yet wired (~150-200 lines)

`runtime/fs/block_io.rs` (new): the message enum, `Request` bookkeeping for
split requests, the task loop exactly as above, and the reply futures with
their guards. Created nowhere yet, so no runtime change; reviewed with 2b.

### Step 2b: route every block operation through the task (~100-150 lines)

All at once, never piecemeal: routing writes through the task while readers
still allocate directly would let readers fill the queue while the task has
a pending write and nothing in flight, which the loop's invariant declares
impossible.

- `runtime/fs.rs`: create the task next to the device; pass its sender to
  `VirtioPartition::from_virtio_bd`. The boot-time MBR read through
  `post_read` stays as it is: it completes before the task exists.
- `virtio_partition.rs`: `read_block`, `read_blocks`, `write_block`,
  `write_blocks_with_completion` and `flush` become send-and-await, with the
  page-size checks and the `flush_supported` check at this boundary;
  `WrapperCompletion` becomes the write reply future; the FS stats counters
  move to where the task submits (one request per chain, as today).
- `virtio_blk.rs`: remove the entry points that lost their callers.
- The Step 0 case passes on CHV after this step. The main gate passes on
  QEMU.

### Step 3: driver, premature drop panics (~20 lines)

In `VqCompletion::drop`, before clearing completion ownership: if any
descriptor of the chain is still device owned, drain the used ring once
(`reclaim_used` until it returns `None`, under the borrow already held) and
check again; if still device owned, `panic!`. A completion dropped after the
device published its used entry but before the reclaimer ran is not an
error. This step has no dedicated test: the driver runs only in a guest
and the panic guards a path no current code takes; the gate's FS and net
suites exercise the queue.

### Step 4: gate, measurement, acceptance

- Per AGENTS.md: `cargo fmt` with the repository toolchain, no new
  warnings, three debug and three release `src/tests/full-test.sh` passes,
  one `src/tests/full-test-dev.sh --release` pass. No retries or relaxed
  timeouts.
- The Step 0 case passes on CHV (manual run).
- Performance before and after on the same image, recorded in this doc:
  boot time to services, a single cold `get_block`, fs `smoke_test` read
  and write MB/s and CPU, `fsbench`, llvm startup. A regression beyond
  noise is attributed before any remedy is picked.
- End-to-end acceptance is the original symptom: `lorry test` from
  `/devtools/src/motor-os/bin/red` in the release developer image completes
  under CHV.
- Close item 4 of `future-work.md`'s open-bugs list.

## Decisions

- One I/O task per virtio block device owns all submissions; it never
  waits inside the driver; it drops every completion as soon as the device
  finishes and forwards results over oneshots.
- The task loop is a `poll_fn` per iteration, not `select!`, because the
  channel's `recv` dequeues at construction. The completion set is polled
  only while non-empty; the inbox only while nothing is pending and it is
  still open; on close the task drains in-flight work and exits.
- Messages carry physical addresses; buffers stay with the requester in
  reply futures that are armed after admission and panic if dropped before
  they resolve, without asking whether the reply already arrived.
- The driver gains `unsafe` non-blocking address-based entry points plus
  `flush_supported`, and loses the owned-buffer entry points that become
  unused; its release-on-drop contract and its wake count are unchanged.
- Unsupported flush is answered by the adapter before any message is sent.
- No change to async-fs, motor-fs or the `AsyncBlockDevice` trait.
- Requests are served in inbox order; split requests pipeline and reply
  once every chunk completed, with the lowest-numbered chunk's error.
- Migration is all-or-nothing: the task module lands unused, then every
  block operation switches in one patch.
- The only new test is the self-checking `systest` reproduction. No host
  harness, no QEMU queue-size change.
- The premature-drop checks are `panic!`s, in the driver and in the reply
  futures.

## Deferred, not scheduled

- Serving reads ahead of queued writes in the I/O task (a priority rule on
  the inbox). Not needed for correctness; reads wait at most for the
  requests already accepted ahead of them.
- Driver allocation-waiter hygiene: no duplicate entry for a task already
  queued, removing a queued entry when allocation succeeds on an unrelated
  poll, a panic on dropping a registered `VqAlloc` before it allocated, and
  smarter wakeups. All moot while every queue has a single submitter, which
  Step 2b makes true for storage and the net tasks already are. Review
  separately if ever wanted.
- Focused tests of the task itself were added after all: the v03 review
  asked for them, and `src/sys/tests/virtio-task-tests` compiles the real
  `block_io.rs` against a fake device to cover split chunks, out-of-order
  errors, buffer ownership, a closed inbox, and the fatal early drop.

## Open questions

None for this revision.

## Results (2026-09-09)

Implemented as planned, Steps 0 to 3, plus the two test pieces the v03
review asked for: a memory-backed fixture that drives the real queue code
(`virtio-async` feature `test-support`, module `virtio_queue/tests.rs`) and
a model of the actual `block_io.rs` against a fake device
(`src/sys/tests/virtio-task-tests`), both run by `systest`. The driver's
allocation-waiter code is unchanged. One pre-existing bug was fixed on the
way: `alloc_descriptor_chain` asserted that a free-list link never points
at its own descriptor, but a freed chain whose tail was the exhausted free
head legitimately does, and the ownership marks already handle it; the
fixture's `test_exhausted_self_link` is the regression case.

### Correctness

- CHV, release, 128-entry queue: the reproduction hangs at its final flush
  on the baseline (62 overwrites in 0.8 ms) and completes after the change:
  62 main-area runs, 68 requests, 126 blocks, 1.2 ms of overwrites, 10 ms
  through the flush. QEMU reports the same counts; the release suite asserts
  them.
- `lorry test` from `/devtools/src/motor-os/bin/red` in the release
  developer image under CHV: three runs, all 72 tests, 11.5 to 11.9 s.
- Firecracker (request cap 1): request counts equal block counts, so the
  split path is exercised; scattered writes and checked 128 MiB passes
  complete.
- Gates on the committed tree: see the commit messages.

### Performance

Same host, guest vCPUs pinned, fresh disk seed per boot, seven boots per
variant, medians of per-boot medians, MiB/s. Reads verify every byte.

| Workload | Original driver | This change |
| --- | ---: | ---: |
| Sequential read, 4 KiB calls | 506.3 | 493.2 |
| Sequential read, 1 MiB calls | 880.2 | 834.6 |
| Sequential write, 4 KiB calls | 258.1 | 244.9 |
| Sequential write, 1 MiB calls | 347.8 | 332.6 |
| Random 4 KiB reads, 1 thread | 111.2 | 104.6 |
| Random 4 KiB reads, 4 threads | 204.2 | 201.9 |
| Random 4 KiB reads, 16 threads | 205.3 | 243.4 |
| Random 4 KiB reads, 64 threads | 131.3 | 249.2 |

Services-up time is 36 ms for both (31 to 41 versus 31 to 49 ms); a cold
single-block read is 51.8 versus 48.4 us; LLVM cold startup is 361 versus
365 ms with overlapping ranges. Sequential throughput costs 3 to 5 percent.
The original driver collapses under many concurrent readers because every
reader contends in the allocation-waiter queue; the single owner removes
that, which is where the 64-thread gain comes from.

### Optimizations measured, not adopted

Three changes to the task recover and exceed the original's sequential
throughput: draining the used ring at the start of the task's poll, keeping
a single-chunk response inline instead of in shared state, and a receiver
variant that does not spin on an empty inbox, with the inbox at 16 entries.
Five-boot medians: 593, 875, 271 and 350 MiB/s for the four sequential
cases. The cost: 64-thread p99 latency 10.7 versus 5.9 ms, and in one boot
with 16 saturated disk readers TCP throughput roughly halved. Deferred until
measured at matched load; recorded in `future-work.md`. A driver-side
result-record variant matched the original sequentially but fell to 85
versus 235 MiB/s at 64 threads and was archived. The experiment journal,
raw data, and archived variants are under `build/virtio-waiters-results/`,
outside the repository.
