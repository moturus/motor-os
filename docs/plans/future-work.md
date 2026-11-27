# Future work

## Networking issues queued for investigation

- **Wake callers when a channel slot becomes free.** In rt.vdso,
  `NetPool::reserve` parks callers until a new channel is published. A slot
  released on an existing channel can satisfy the request, but nothing
  wakes that waiter. Notify it after queued writes and close have entered
  the ring. Preserve cancellation and final-channel shutdown ordering.
- **Identify the cause of occasional loopback resets in debug systest.**
  The poll and net-driver cases expect data followed by an orderly close.
  If a reset recurs, identify which reset branch ran and whether the last
  write reached the peer. Unread input, zero linger and orphan limits can
  each legitimately produce a reset.
- **Define when the sys-io statistics provider is ready.** sys-io starts
  its statistics server after a 500 ms sleep. A caller of
  `Collector::providers` can get a valid snapshot that omits sys-io.
  Callers that need its metrics need an explicit readiness or error
  contract. Filesystem startup cannot wait on strobe.

## `full-test.sh --all-debug` has not passed

- **System OOM fixture.** After the gate uses a RAM filesystem, a System
  allocation can be charged a whole 512-page block. The fixture assumes a
  single recovery round. Recovery can end at 768 free pages, so the next
  whole-block charge can take free memory below 512 and start a second
  round before the large victim releases its memory. Decide what the
  assertion should prove about victim selection and when recovery should
  end. A separate assertion infers that a child parked by sampling it from
  the parent and can miss the wait.
- **Exact command output.** Rush tests in `phase0`, `phase3`, `phase5`,
  `phase6` and `shared_input`, and rmux pane tests, can receive rt.vdso
  DEBUG records along with command output. Decide where these records belong
  or teach the affected comparisons to recognize them. Keep command
  diagnostics visible. The remaining native suites still need a complete
  pass with normal logging in both capability profiles.
- **Wasm role matrix and editor deadlines.** The four-role Wasm matrix has
  a 120 s budget and takes roughly 180–210 s on a debug image. The toolchain
  editor check can miss its 20 s deadline for rust-analyzer's diagnostic
  after a save. Establish which costs belong to the debug system and which
  the checks are intended to bound.

## Other test coverage

- **Native filesystem and allocator tests.** The motor-fs unit tests use
  Tokio and a host file-backed block device. Port the fixture to a runtime
  and disposable device available on Motor. Native release coverage also
  omits netstack unit tests because of their build cost, and the frusa
  `stress_test` because of large-allocation cost.
- **Blocked TCP write deadline.** rnetbench's
  `timed_write_interrupts_blocking_io` joins a thread calling
  `shutdown(Write)`. sys-io waits for accepted data to enter the send ring
  and the FIN to be queued. A peer that stops reading can therefore stall
  the shutdown caller. Decide whether to acknowledge local shutdown as soon
  as further writes are refused and drain queued data asynchronously.
- **Wasm on small guests.** The 256 MiB gate misses sys-io's below-256-MiB
  limits. Decide whether release images should exercise the Wasm suite at
  224 MiB. The debug image needs more memory for `javy build`.
- **96 MiB systest.** Decide whether this size must run the full suite.
  `spawn_wait_kill::test_first_calls_at_once` starts 32 children together.
  Their working sets exceed the available RAM and the OOM killer ends
  children whose exit statuses the fixture expects to be successful.
- **One-vCPU poll contention.** The hammer in `test_add_races_source_close`
  and `test_registration_races_source_close` can occupy a full scheduler
  tick between operations. A woken waiter can lose the registry mutex
  again. Preserve contention coverage when assessing ordinary test cost,
  mutex handoff or scheduler changes.
- **WireGuard under load.** The manual `systest wireguard-load` can lose
  its single ICMP reply during a sustained UDP flood. The receive ring and
  host tap queue can fill while sys-io is off-CPU. UDP TX backpressure
  alone does not account for the lost probe. Establish where RX progress
  stops before putting the load case back in the gate.

## Stdio, terminals and tools

- **Buffered file-relay failure.** A child's write may finish before its
  parent copies the bytes from the pipe to the file. If the file refuses
  the write and the child exits without writing again, the file can be
  empty and the exit status zero. Decide how the caller learns of the
  failure. A spawn-time access check could catch a permission failure.
  Reporting a relay error at wait would also cover a full filesystem,
  and would change the meaning of a successful wait.
- **Broken pipe classification.** A reader that signals closure produces
  `NotConnected`. Dropping a directly captured child-output reader can also
  expose `BadHandle`, which Rust stdout treats as a locally closed
  descriptor. Give loss of a pipe reader a distinct error through moto-rt
  and the external Rust stdlib port. Preserve local-close and socket
  semantics. Cover Rust stdout and re-enable gix's
  `closed_stdout_reports_broken_pipe` and the WASI `p2_cli_stdout_epipe`
  fixture when they receive the expected error.
- **Terminal input ownership.** A helper with three captured streams can
  still receive fd 3 and hold its parent's terminal reader for its entire
  lifetime. Decide whether a child needs terminal output to inherit fd 3,
  or whether each editor and other terminal owner must opt its helpers out.
  Account for interactive pipeline stages such as `cmd | less`.
- **SSH session lifetime.** `release_channel` closes command input. A
  compute-only command and its descendants can continue indefinitely after
  the SSH client leaves. Define child and descendant lifetime separately
  for PTY and non-PTY sessions.
- **QuickJS multiline paste.** When several complete lines arrive in one
  read, the upstream REPL can append the next line to one it is already
  evaluating. Address line queuing in `repl.js`. Script input and `qjs -e`
  provide alternatives for bulk input.
- **Gears session locking.** Check the separate Gears checkout before
  changing session locks. The reported race is between creating a
  `.jsonl.lock` and publishing its owner's PID. If it still uses a PID
  file, hold an exclusive file lock for the session lifetime and keep the
  lock file at a stable path across owners.

## Filesystems and permissions

- **Device errors in the block cache.** An immediate device-write error
  panics the background writer in `moto-sdk/src/async_fs/block_cache.rs`.
  A later flush can panic on the closed response channel. A completion
  error can instead be logged while flush reports success. Decide how to
  propagate the first error through flush and whether sys-io should
  quarantine the affected mount once disk and cache may disagree.
- **Filesystem error codes.** sys-io maps `DirectoryNotEmpty` to
  `FileTooLarge` and `IsADirectory` to `InvalidArgument`. The latter
  obscures why a file cannot replace a directory on rename. Add distinct
  results at the native ABI and Rust stdlib boundaries.
- **Stale entry IDs.** A cached parent sent with `CMD_STAT` can refer to
  a freed slot or to an older generation. Distinguish a stale caller ID
  from a corrupt on-disk reference and report a missing entry to the caller.
- **Open-time access.** An ordinary non-truncating write open can succeed
  on an existing file whose role permissions refuse the subsequent write.
  Have sys-io check requested access for the authenticated role at open.
  Keep checks on later operations so that revoking permission takes effect.
- **Directory enumeration under mutation.** rt.vdso saves the next entry
  ID. If that entry is removed, `readdir` returns an error and loses the
  rest of the listing. This blocks pipelining in Lorry's native executor.
  A cursor ordered by (name hash, name) could return the next name,
  metadata and continuation under one filesystem lock. It must make
  progress through collisions, deletion and slot reuse in motor-fs and memfs.
- **None-role writes in system trees.** Image modes protect `/system` and
  `/user`, but a later mode change can grant None write access there.
  Decide whether sys-io should enforce this independently of modes and
  whether even System may grant such access. motor-fs stores parent IDs.
  Compare the cost of ancestor lookup with maintaining tree membership
  across renames, including the two role-specific temporary mounts.
- **Private staging for `sed -i`.** The external Motor sed fork can create
  its staging file with broader read permissions than the original. Choose
  memory staging or a create-with-permissions operation that protects the
  file from its first instant. Memory staging needs a recovery policy for
  a failed write-back.

## Performance and memory

- **I/O when all CPUs are busy.** With four compute-bound threads on four
  vCPUs, a loopback connect/accept can take 40 ms compared with 0.13 ms
  idle. A woken thread can wait in the global queue for a 10 ms tick, and
  the pinned sys-io thread waits for CPU 0. Evaluate local-queue priority,
  wake preemption and fairness together. Unconditional wake preemption
  hurts bulk TCP throughput, and zero-timeout pollers can starve other work.
- **Broadcasts at process exit.** `UserAddressSpace::release_user_memory`
  interrupts every CPU twice in a row: once to move the CPUs off the dying
  page table, and once to invalidate the cached kernel stacks it unmapped.
  Clear the stack mappings first and send one message that does both. The
  message has to carry an eviction and a kernel range together. A process
  with one thread, which gained nothing from batching its stacks, would
  benefit too.
- **Unmap order.** After clearing an entry, `unmap_page` scans the table
  from entry 0 to see whether it is empty. A dense segment is cleared in
  ascending order, so each scan reads every entry already cleared: about
  256 reads per page for a full table. In descending order the first read
  finds a live entry. This applies to every dense unmap, including the
  release of a whole address space at exit. Measure a large small-page
  unmap and a process exit before changing the order.
- **User stacks at process exit.** Each thread's cleanup unmaps its user
  stack while the page table is still live, with a TLB shootdown to the
  CPUs on that table. When the process is exiting, leave the stack to
  `release_user_memory`, which frees it on the dead table without one. A
  thread that exits in a live process must still unmap its stack.
- **Kernel stack reuse.** A kernel stack is mapped when a thread starts
  and unmapped, with a broadcast, when its process exits. A system-wide
  pool of stacks would save both. Decide who is charged for a pooled
  stack, how many are kept, and how the pool is emptied under memory
  pressure.
- **Heap allocations.** Rust's frusa heap maps and unmaps individual
  allocations above 4 KiB, and mlibc's frigg allocator does so above
  32 KiB. Consider larger frusa classes with the required alignment,
  recovering layout from an address for C callers, and moving reclaim off
  the allocation path. For mlibc, compare large-block reuse, in-place
  growth and populating pages at allocation. QuickJS's Unicode tests
  repeatedly grow such buffers.
- **Page tables.** `PageTable::phys_addr` takes a lock for an immutable
  root address, and `is_dead` could use an atomic flag. Both are
  infrequent, so measure before changing the lock.
- **P2. Reclaim empty descriptor slabs.** `PageAllocatorInner` keeps even
  entirely unused slabs until address-space teardown. Reclaim them safely
  during touch/unmap cycles and concurrent faults.
- **Sharing memory.** Evaluate a shared copy-on-write zero page for sparse
  reservations, including Wasm memory64. Executable pager fills give each
  process private text pages. Assess sharing immutable executable pages
  and identify any avoidable double copy at spawn.
- **Block cache size.** Decide whether to scale capacity as far as RAM/16.
  The present 144 MiB cache on an 8 GiB guest can hold either rustc or LLVM
  individually. Weigh avoiding repeated executable reads against the cache
  retaining memory after demand falls.
- **Filesystem writes.** `on_cmd_write_multi` executes a motor-fs
  transaction per block-sized chunk. A bounded multi-block transaction must
  preserve partial-write accounting. Metadata-only journaling for new
  blocks needs data-before-metadata ordering, and enlarging the 64-block
  journal would change the disk format.
- **Filesystem client overhead.** Each synchronous request spawns a task
  and allocates a reply slot. Compare bounded resident workers or reusable
  slots while keeping the response pump runnable. A path `stat` also makes
  separate lookup and metadata requests. Return both under the same role
  check and filesystem lock.
- **Debug installation and logging.** The external toolchain's
  `lib/toolchain-native-install.sh` walks the same destination to apply
  modes for each contributing overlay. Apply modes once per merged tree.
  In file logging mode each kernel record still costs a filesystem append.
  Frequent per-operation records need a way to detect that cost.
- **Idle CPU selection.** Evaluate preferring an already polling idle CPU
  against preserving cache affinity in `sched::post`. Measure idle host
  CPU cost before adopting an activity-based halt-poll window.
- **P3. TCP TIME-WAIT footprint.** Each connection in TIME-WAIT keeps a
  netstack socket, a sys-io socket and a linger task for ten seconds.
  Evaluate retaining just the tuple and timer. Small TCP writes and receive
  batching are tracked in the [networking plan](networking-remaining-steps.md).
- **Boot timestamps.** Attribute guest time from the kloader entry. The
  VMM can spend seconds syncing a recently copied qcow2 file before any
  guest instruction runs. See the [boot-time plan](boot-time.md).

## IPC and resource limits

- **Service ownership conflicts.** Decide whether `shared::create` should
  return `E_ALREADY_IN_USE` when a different owner holds the name. The
  kernel currently returns `E_INVALID_ARGUMENT`, which the ownership
  assertions in `systest/src/ipc_service.rs` also expect.
- **rmux service names.** The client authenticates the server's capability
  mask, but the intended server can be denied its name before startup.
  Decide whether service-name ownership should be bound to the creator's
  mask in the kernel.
- **Idle connections.** Strobe logging and the DNS resolver account for
  a connection before authorizing its first request. Bound idle occupancy
  while preserving normal long polls and the documented `NotAllowed`
  response to a forbidden request. Decide on per-peer limits or a
  first-request deadline.
- **Fallible socket bind.** The rt.vdso bind path and moto-sdk's
  `NetChannel::rpc_bind` use infallible allocations for the observer and
  pending request. Propagate allocation refusal to the caller.

## Optional change to the victimless OOM abort policy

Decide whether a run with no eligible victim below 512 free pages should
enter the latched state, keep the User gate closed and let System callers
continue. Specify fault handling, error returns and rearming before
changing the abort rule or its `cross_oom_abort` fixture.
[OOM handling](../oom-handling.md) describes the current policy.

## Deferred PCI BAR-boundary hardening (2026-09-15)

If the virtio mapper's trust boundary is extended, validate the selected
BAR and the width of a 64-bit pair before probing either register. Review
the additional boot-time PCI reads. See the [vsock transport profile](../vsock.md#transport-and-dma-ownership).

## Failures without a confirmed cause

- **Native Lorry self-build stall.** Compiler output and a separate SSH
  status query both stopped. If it recurs, capture the dispatched unit,
  child PID, pipe EOF, filesystem waits and server stacks together. A
  blocked compiler alone does not explain an unresponsive SSH query.
- **Logging RPC stall.** A rotation request waited indefinitely while the
  kernel log and other services continued. Correlate the RPC sequence
  with strobe's bounded I/O queue and file flush completion.
- **Host SSH channel-send failure.** In the full-duplex russhd case a
  child writes a large stdout while leaving stdin unread. Capture both
  channel and connection-close errors on recurrence. The channel error
  can obscure the underlying transport error.
- **Virtio RX monitor intervention.** If the monitor has to wake a stalled
  completion waiter, capture the used-ring indices, armed event index,
  IRQ wake count and waiter state together.
- **Network loss after SSH disconnect.** The reported loss of network
  service has no confirmed cause. If it recurs, capture sys-io and the
  busy threads' stacks from the console.

### Unresolved sys-io abort during listener exhaustion (2026-09-10)

The abort during listener pressure has no confirmed stack or allocation
site. If it recurs, retain the abort site and socket and memory state before
attributing it to TCP ring growth.

## Deferred work

- **Memory and process accounting.** Define per-process resident high-water
  marks and shared-page attribution. Current resident counters and periodic
  samples cannot report a peak between samples. A complete descendant
  execution audit would need an opt-in bounded start/exit stream, stable
  process identities and explicit event-loss reporting.
- **Large Git objects.** Decide whether gix should stream large blobs and
  how to bound memory during delta resolution. Streaming a delta base can
  require temporary storage in `gix-pack`.
- **Network channel memory ordering.** Audit the SeqCst fences in
  `dispatch_incoming` and `tx_send_batch` individually against the
  publication and wake protocol. The wait-bit handshakes in `io_channel`
  have a separate ordering requirement.
- **Final kernel logs.** On orderly sys-tty exit, drain the kernel ring to
  a defined boundary and acknowledge the forwarder's file queue. Define how
  to report records a failed sink could not accept, including what a panic
  path can guarantee.
- **Kernel wait sets.** Specify persistent registrations and a ready queue
  to avoid scanning every handle on each wait. Account for handle closure,
  duplication, cancellation and missed wakes, and preserve the small inline
  wait used for ordinary RPC.
- **Virtio descriptor waiters.** Register an allocation future once,
  update its waker on repoll and remove it on success or cancellation.
  Releasing a chain wakes at most two queued entries. Ensure a fitting
  waiter can progress if other entries are stale or need more descriptors.
- **Block I/O overhead.** Try an inline response for single-chunk requests.
  Evaluate draining used entries at poll entry, inbox sizing and a
  nonspinning receive separately. Compare sequential throughput, threaded
  tail latency and networking under disk load.
  
## IPC and thread teardown

- In `moto-sdk/src/ipc/sync.rs`, `ClientConnection::do_rpc` asserts on
  sequence numbers read from shared request and response pages. Return a
  protocol error and disconnect on a mismatch so a faulty server cannot
  panic its client.
- In `rt.vdso/src/rt_tls.rs`, a destructor can repopulate its key on every
  pass through `while run_dtor_round()`. Bound thread teardown while
  allowing Rust's cleanup guard to run after the other destructors.
- Decide whether all `LocalServer` users need the `retired` endpoint held
  across disconnect and a failed refill. Any simplification must account
  for service-name ownership while the last listener is gone.
- rmux uses two authenticated connections per client, a pairing token,
  output forwarders and a doorbell. Evaluate whether one bidirectional
  `io_channel` would simplify the thread-based server while preserving
  peer-mask checks, backpressure and hangup detection. Keep probe coverage
  for states the ordinary client cannot exercise.

## Shell and filesystem policy

- Rush refuses even `unset MOTOR_OS_CAPS` while the mask is exported.
  Decide whether the shell should provide a way to recover in-process
  while continuing to enforce an explicit mask on command invocations.
  The current contract is in [Capabilities](../caps.md).
- Decide whether a client without filesystem-write authority may request
  the global flush. Review the cost imposed on other clients, the read-only
  handle case and how the server rejects unknown commands. Account for
  inherited file-backed stdio using the relay parent's authority in any
  future confinement design.
- Rush peeks at stdin so reading one line leaves a following command its
  input. Measure byte-at-a-time reads on Motor before proposing removal of
  non-socket peek. Preserve input boundaries for both pipes and terminals.

## Sysbox and documentation

- `sort`, `uniq`, `cut`, `tr` and `echo` report ordinary write errors when
  a downstream reader exits. Decide their broken-pipe behavior and share
  the handling with `head`, `tail` and `diff`. Native pipe error
  classification is tracked in [future work](future-work.md).
- `xargs_tokens::arguments` tests for a nonempty byte buffer at EOF. It can
  drop an empty quoted argument or accept an unterminated empty quote.
  Check the intended scope of `-I` in the command name before changing
  substitution.
- Check `sort -hf` suffix handling against the intended compatibility
  rules. Replace `tr`'s hard-coded 26-byte class-length check. Decide
  whether `cut` needs to buffer the entire input for a newline delimiter.
- Consider sharing the error formatting in `wc::strerror`, the directory
  error mapping and common option parsing. The parsing shared by `head` and
  `tail` still lives in `head.rs` and uses command-specific function pointers.
- Decide which GNU `diff` tie-breaking and format options are part of the
  compatibility contract before simplifying confusing-line selection or
  removing fixtures. Preserve bounded search, usable hunk boundaries and
  exit statuses.
- Sysbox's command tests duplicate stderr filtering in the head, tail and
  diff fixtures. The utilities harness uses a narrower filter. Share the
  rule without hiding a command's own output.
- The installed HTML manuals repeat the stylesheet and navigation markup.
  Evaluate how to share them while keeping the offline manuals usable.
