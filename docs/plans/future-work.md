# Future work -- recorded, deliberately not scheduled

Source review: 2026-10-28, Motor OS `8bb9345c`. Non-memory issues were
checked against source only, without builds, tests, or runtime validation.
Memory capacity, allocation failure, reclamation, and accounting entries
were skipped and left unchanged. Runtime and I/O latency items, including
per-operation allocation overhead, were reviewed. Historical timings below
are not new measurements. An unexplained historical failure stays open
unless the source establishes that its cause was fixed.

## Shared zero page

Motor OS kernel should have a single shared copy-on-write zero page,
this will help wasm memory64 grow beyond 4G (and will overall be a
memory efficiency win)

## Frusa work

(a) Investigate moving Rust heap from Frusa4k to Frusa16k or Frusa32k

The problem is that 16k allocs must often be aligned on 16k, but
Frusa will only serve 4k-aligned buffers. Also how to make frusa
deduce layout from address so that it can replace mlibc's alloc
(so that C/C++ binaries on Motor OS have a single heap, not two).

(b) Investigate using RCU and a background memory reclaim task:
current reclaim stalls allocs/frees.

## Pipe closure is not reported as BrokenPipe (2026-10-09)

The native writer no longer keeps succeeding after its reader is dropped:
rt.vdso's `create_stdio_pipes` gives the child a direct pipe, closing the
parent descriptor drops its endpoint, and `StdioPipe::write_timeout_impl`
propagates peer-close errors. The source of
`systest::stdio::test_child_stdout_reader_drop` covers termination after
reader drop, but its child accepts any write error.

The remaining WASI EPIPE problem is error classification.
`src/sys/lib/moto-sdk/src/ipc/stdio_pipe.rs` returns `E_NOT_CONNECTED` for
`reader_closing` or propagates a failed kernel wait/wake. `moto_rt::Error`
has no `BrokenPipe` variant. The selected `x86_64-unknown-motor-1.99.1`
stdlib's `sys/stdio/motor.rs` propagates that error, and
`sys/io/error/motor.rs::decode_error_kind` never maps an error to
`std::io::ErrorKind::BrokenPipe`. In the separate Wasmtime checkout,
`crates/wasi/src/cli.rs::stream_error_from` recognizes only `BrokenPipe`
as `StreamError::Closed`; its `p2_cli_stdout_epipe` fixture rejects other
errors and remains excluded by `src/build-scripts/build-wasmtime.sh`.

Add a distinct pipe-closure error and propagate it through the ABI and
stdlib. Translate peer loss only for a valid pipe writer; do not globally
reinterpret invalid descriptors or disconnected sockets as broken pipes.
This needs reviewed moto-rt and external stdlib changes. Then strengthen the
native reader-drop assertion and enable the upstream EPIPE fixture with a
parent that closes its reader. No external source was changed in this review.

## Motor OS filesystem behavior that WASI guests see (2026-10-09)

Remaining native filesystem gaps, with some WASI workarounds:

- `src/sys/sys-io/src/util.rs::map_err_into_native` still maps
  `DirectoryNotEmpty` to `FileTooLarge`; `moto_rt::Error` has no distinct
  variant. Add an ABI error code and propagate it through sys-io, moto-rt,
  and std's error mapping. Changes to moto-rt and the external stdlib port
  need separate review. The Wasmtime workaround does not fix native callers.
- Native `CMD_STAT` still accepts a cached parent ID and passes it to
  `MotorFs::stat`. `motor-fs/src/layout.rs::DirEntryBlock::validate_entry`
  returns `InvalidInput` for a freed entry and `InvalidData` for a reused
  generation. Distinguish stale caller IDs from corrupt on-disk references
  and report a missing entry at the API boundary. The Wasmtime adapter now
  represents directory handles as paths and resolves them afresh, so the
  old sequential deleted-directory guest lookup no longer exercises this
  native defect. Concurrent stale-ID operations remain affected.
- `rt.vdso/src/rt_fs.rs::file_open_inner` now refuses write intent without
  `CAP_FS_WRITE`. It still does not check the existing file's role
  permissions for an ordinary non-truncating write open: path lookup
  checks traversal, and the later write checks write access. Add a server
  operation that validates the requested access against the authenticated
  role before returning an open result. Keep the existing per-operation
  checks unless permission-revocation semantics are deliberately changed.
- `motor-fs/src/txn.rs::do_move_entry_txn` still discards the destination
  kind returned by `lookup_child` and deletes the target before linking the
  source. Compare source and destination kinds inside this same exclusive
  transaction, before deletion, and return distinct directory/file errors.
  sys-io also currently maps `IsADirectory` to `InvalidArgument`; preserve
  that distinction through the ABI. A client-side preflight lookup cannot
  close the race with another rename.

Paths above are under `src/sys/lib` except the explicitly named sys-io file.

## sys-io aborts when a TCP connection is established at the memory floor (2026-10-04)

A release `full-test.sh` run on 2026-10-04 timed out after 900 s with
systest's last line `test_listener_pool_growth PASS`. The guest had not hung:
sys-io had aborted and the VM had exited, so the host's ssh client never saw
the connection close and waited out the suite's timeout. On the console the
kernel's `fatal: sys-io exited with status 0xffffffff` was garbled together
with its matching WARN line.

Cause, from a symbolized backtrace of the aborting thread. systest's
`ipc_service::test_listener_pool_growth` and
`ipc_service::test_refused_refill_retries`
(`src/sys/tests/systest/src/ipc_service.rs`) hold free memory at the user
floor. sys-io's memory-pressure mode
(`src/sys/sys-io/src/runtime/net/pressure.rs`) refuses new clients and
sockets and parks listening-pool replenishment, but a socket already in the
listening pool can still complete a handshake. On the ESTABLISHED edge,
`tcp::Socket::set_state` calls `apply_pending_rx_growth` and
`apply_pending_tx_growth`, which grow the rings with `RingBuffer::grow_to`, a
`Vec::resize` that cannot fail gracefully
(`src/sys/sys-io/netstack/src/socket/tcp.rs` and
`src/sys/sys-io/netstack/src/storage/ring_buffer.rs`, added in `2d9f8d26`).
`growth_deferred()` looks only at the TCP state, never at memory pressure,
although `pressure.rs` states that sys-io must stop growing before the kernel
refuses it. The allocation is refused, `rust_oom` aborts sys-io, and Motor OS's
std implements abort as `exit(-1)`, hence the status. The frames:
`process_ethernet` → `process_ipv4` → `process_tcp` → `Socket::set_state` →
`RingBuffer::grow_to` → `handle_alloc_error` → `rust_oom`. sys-io's panic hook
exits with 0xbadc0de, so this status from sys-io means an abort, not a panic.

Reproduction, one to ten minutes per hit: boot a fresh release image, run
`systest fs-bench` in a loop over ssh as background load, and loop
`systest test-ipc-service-ownership`. With the copy-policy change, 2 of 9
attempts ended with sys-io dying and 7 with russhd dying (next entry); on the
tree of `f301678c`, without that change, 3 of 4 ended with sys-io and 1 with
russhd. Without the background load, 400 iterations after a full systest run
passed. Scripts `repro-ipc.sh` and `repro-outer.sh` and the console logs
`round2-mine/outer-7/console.log` and `outer-1/console.log` are under
`/tmp/claude-1000/-home-posk-motor-dev-motor-os/0ddd88f0-50e4-41c1-8206-8ab305bedcba/scratchpad/gate/`.
The backtraces came from a temporary kernel print of every abnormal thread
exit in pids 1 to 8, written straight to the serial port and since removed.
Symbolizing needs an image built with `CARGO_PROFILE_RELEASE_STRIP=false`:
the `src/sys` release profile strips, and an unstripped rebuild links
differently, so it does not match a stripped binary that is already running.

Fix options, to decide: make the ring growth fallible (`try_reserve_exact`,
keeping the small rings and the latched request when it is refused), or skip
growth while `pressure::active()` and apply it once pressure clears. Either
is a core sys-io change and needs the full debug and release test runs. Two
older entries below probably share this cause; neither was checked. The
2026-09-27 stall under "IPC listener is published before its missed-wake
snapshot" ends at the same systest line and the suite's timeout, and
"Unresolved sys-io abort during listener exhaustion (2026-09-10)" ends with
the same sys-io status during a connection flood.

## russhd aborts when its heap has to grow at the memory floor (2026-10-04)

russhd runs in the user memory class. While the two tests above hold free
memory at the user floor, any growth of its heap is refused and Rust aborts
it, ending every ssh session at once; clients print `Connection to ... closed
by remote host`. Symbolized frames from its exiting main thread:
`local_session::pump_output::<ChildStderr>` → `send_output` → tokio
`mpsc::Sender::send` → `list::Tx::push` → `alloc::raw_vec::handle_error` →
`rust_oom` → `std::process::abort` → `moto_rt::process::exit(-1)`. russhd's
object binary keeps its symbols, so no special build is needed.

Seen with the reproduction above: 7 of 9 attempts with the copy-policy change
and 1 of 4 on the tree of `f301678c` (`head-russhd-3/console.log` in the same
directory). It has not been seen in a plain `full-test.sh` run, where little
output crosses russhd while memory is at the floor; systest's own output and
any second ssh session still go through the same queue.

Needs a decision. Options: keep russhd's relay path from allocating once a
session runs, with bounded queues reserved when the session starts; give
russhd the privileged memory class, which also lets a compromised russhd take
the reserve; or have the floor tests stop short of the user floor wherever
they do not measure the refusal itself. The same window can abort any other
user-class process that allocates during these tests.

## Memory usage optimizations

1. double-copy during process spawn
2. process text not shared across process copies

## Atomic publication of session locks (2026-10-02)

A saved session's `.jsonl.lock` uses exclusive file creation, then writes
its PID. Another Gears can see the new file before the PID is written,
mistake the empty record for a stale lock, remove it, and open the session
concurrently. PID reuse also means that liveness alone cannot establish that
the holder is the original Gears process.

The Gears directory lock had the same race until 2026-10-17; it now holds an
exclusive file lock (`File::try_lock`: `flock` on Linux, a sys-io lock on
Motor OS) on `gears.lock` for the whole run and never removes the file, so
the system releases it when Gears exits or is killed. Session locks can use
the same approach. Until then they treat a fresh or unreadable lock
conservatively. Do not add boot work or a lock service for this.

Still present in the separate `../gears` repository (read only for this
review): `src/session.rs::acquire_lock` calls
`src/run_lock.rs::create_pid_file`. Its two-second grace protects a fresh
empty record, but an owner paused longer can still lose its lock; concurrent
stale-file removers can also unlink a replacement owner's lock. Hold an
exclusively locked `File` in the session for its lifetime, as `DirectoryLock`
does, and never unlink the lock file on release. Keep the PID informational.
This proposed implementation belongs outside the Motor OS repository.

## FS block cache at RAM/16 (2026-10-01)

sys-io's block cache (`block_cache_blocks` in
`src/sys/sys-io/src/runtime/fs.rs`) stops at 16 MiB from 256 MiB of RAM up.
Executables larger than that are reread from the disk on every spawn, since
the vdso loader reads the whole file: rustc (119 MB) and llvm (105 MB) on the
developer image. Cached reads run at about 5.2 GB/s, uncached ones at
1.2-1.4 GB/s. Proposal: 1 MiB per 16 MiB of RAM from 256 MiB up (512 MiB on an
8 GiB guest); smaller guests unchanged.

Measured with a release prototype on 4 vCPUs pinned to host P-cores, 8 GiB:
a trivial rustc launch went from 150-180 to 85-94 ms, a no-op `lorry check`
from 1.6 to 0.87 s, and the native rust-analyzer case from 21.6 to 13.8 s to
quiescence and from 1.72 to 0.95 s from save to diagnostics.

Before adopting:

- Debug builds walk the whole cache on every transaction
  (`debug_check_clean`, called from `Txn`'s drop in `motor-fs`); keep debug
  at 16 MiB or make that check O(1).
- [OOM handling](../oom-handling.md) argues the cache is filled at boot and
  so never grows sys-io afterwards. With RAM/16 it grows after boot up to its
  capacity and never shrinks; revisit that argument and the memory floors.

## A TCP bind at the memory floor can abort the process (2026-09-27)

`std::net::TcpListener::bind` should either succeed or fail with
`OutOfMemory` when free memory is at the user floor. It can abort the whole
process instead. rt.vdso's `rt_net::bind` (`src/sys/lib/rt.vdso/src/net/rt_net.rs`)
makes several infallible allocations before sys-io is asked: the event
source, the listener observer, and the RPC state in `NetChannel::rpc_bind`
(`src/sys/lib/moto-sdk/src/io/net/channel.rs`: a `oneshot` `Arc` and an
`rpc_map` `BTreeMap` insert). If the process heap has no slack left, one of
them fails and rt.vdso aborts.

Seen once, in a release `full-test.sh` run on 2026-09-27 (commit
`960f9163`, which touches only rmux and tests). systest died in
`admission::test_aggregate_listener_exhaustion`, at its "one more bind while
the flood holds everything": "memory allocation of 136 bytes failed", status
222. The innermost frames were rt.vdso's `rt_net::bind` →
`NetChannel::rpc_bind` → `handle_alloc_error`, found by rebuilding rt.vdso
with symbols (the code shifts by 12 bytes, so the match is by nearby
function, not exact). The same test passed in the three other gate runs that
night, so whether it fails depends on how much heap slack the process has.
Log: `/tmp/claude-1000/-home-posk-motor-dev-motor-os/44e5b204-1009-467e-bf8e-bab1741e9591/scratchpad/gates/g2/run2-__release.log`.

A fix makes the bind path allocate fallibly, or reserve what it needs before
admission, as `57796b3d` did for network teardown. It touches rt.vdso and
moto-sdk, so it needs its own reviewed patch. Until then the test can flake.

## IPC listener is published before its missed-wake snapshot (2026-09-26)

Still present: `shared::create` publishes under `LISTENERS`, then
`sys_handle_shared` calls `Process::add_object` / `WaitObject::new` after
that lock is released. `OP_GET` now always wakes shared-service peers,
including silent clients, but that wake can still precede the snapshot.
Capture the initial `WaitObject` before publication and insert that same
snapshot into the process handle table; audit lock order if instead moving
handle creation under `LISTENERS`. Do not recapture the counter afterward.

A shared endpoint is created in two steps. `shared::create`
(`src/sys/kernel/src/uspace/shared.rs`) inserts the new listener into the
service pool under `LISTENERS` and returns the `SysObject`. Only then does
`sys_handle_shared` (`src/sys/kernel/src/uspace/sys_obj.rs`) call
`Process::add_object`, which builds the `WaitObject` and records the object's
wake count at that moment (`WaitObject::new`,
`src/sys/kernel/src/uspace/process.rs`). A later wait reports the handle only
if the object's counter has moved past that snapshot (`process_wait_handles`,
`src/sys/kernel/src/uspace/sys_cpu.rs`).

Between the two steps another process can already find the listener, map it,
and wake it: a client's first `do_rpc`, or a `SysObj::get` with `F_WAKE_PEER`,
which wakes inside the connect syscall itself. That wake lands before the
snapshot, so the snapshot counts it as already consumed. The server never
sees the connection, and the client blocks in `do_rpc` until its timeout, if
it has one. The window is a few hundred nanoseconds on another CPU. IPC pairs
are not affected: neither side learns its handle before the syscall that
creates both returns, and by then both snapshots are taken.

This predates the new-caps IPC fixes. It was found by code reading during
their review, not by a failure.

The fix is to take the snapshot before the listener is published: build the
`WaitObject`, or the handle itself, before `create` inserts into
`service.pending`. It touches `src/sys/kernel`, so do it as its own small
patch, with a stress test in the style of `test_dup_races_close`.

Possibly seen on 2026-09-27, not confirmed. A release `full-test-dev.sh` run
on `df60016d` (4 vCPUs, 8 GiB) stalled in systest's
`ipc_service::test_refused_refill_retries` for about 14 minutes, until the
suite's 1500 s timeout; the test normally takes 2 s. That test has a client
poll `connect` every 10 ms while the server's retry timer publishes a fresh
listener, then call `do_rpc(None)`, so a lost first wake would block it for
good. The stall did not come back in 150 runs of the IPC tests alone on the
same VM shape, in a full systest run there, or in the next two developer
gates. Log: `/tmp/claude-1000/-home-posk-motor-dev-motor-os/44e5b204-1009-467e-bf8e-bab1741e9591/scratchpad/gates/dev1/dev-release.log`
(its last systest line is `test_listener_pool_growth PASS`). Since
2026-09-27 that `do_rpc` has a 10 s deadline and panics with a message, so a
future stall fails the test quickly and names itself instead of running out
the suite's clock.

Seen again on 2026-10-07, on `0a91105d` (release `full-test-dev.sh`, 8 GiB):
the last systest line was again `test_listener_pool_growth PASS`, and the
suite ran out its 1500 s clock. The late `do_rpc` deadline did not fire, so
this stall was elsewhere in the test: most likely the first `do_rpc(None)`,
which has no deadline, or a read from the peer or the hoarder. The next run
on the same commit passed the test in under 5 s, as did three more runs.

Not reproduced on 2026-10-08 (`94a97b45`), with a temporary watchdog that
named the step that stopped for 60 s. These all passed, on the release dev
image with 8 GiB and 4 vCPUs:

- 15 full systest runs, each in a fresh boot;
- 3 runs of the developer gate's `full-test.sh` phase, where systest runs
  after the rest of the suite;
- 150 runs of the IPC tests alone while busy loops kept all 16 host CPUs
  busy.

Seen a third time on 2026-10-08, on the `dev` branch at `a4d30f3c` (the
lorry branch's kernel and sys-io fixes cherry-picked onto `99a13d6f`), in a
release `full-test-dev.sh` run with 8 GiB. The last systest line was again
`test_listener_pool_growth PASS`, and the suite ran out its 1500 s clock.
That tree has no step watchdog, so the stopped step is unknown. The console
shows nothing after 297 s and no `fatal: sys-io exited` line, but it also
dropped records. `dev`'s own future-work list traces an identical-looking
timeout on 2026-10-04 to sys-io aborting when a TCP connection is
established at the memory floor, and says these stalls probably share that
cause. The same tree had just passed `full-test.sh` three times in debug and
three times in release. Logs:
`/tmp/claude-1000/-home-posk-motor-dev-motor-os/8e448414-375a-41fc-8871-292a39ae0700/scratchpad/devbranch-stall/`.

Seen a fourth time on 2026-10-09, on the lorry branch at `b57d14d0` plus
uncommitted Lorry configuration changes (release `full-test-dev.sh`, 8 GiB,
4 vCPUs). The step watchdog named the step: "waiting for the server to retry"
(step 6). The server never printed `retrying`, so no `wait()` returned
without a request while the hoarder held memory. The console shows no sys-io
failure. Logs: `/tmp/claude-1000/-home-posk-motor-dev-motor-os/c73e7c97-f286-45f2-ab9d-03782d6b4132/scratchpad/refill-stall-2026-10-09/`.

A likely cause, by code reading, not verified: the test assumes every refill
stays refused during step 6, but the hoarder takes freed memory back only
once per millisecond (`fill()` then a 1 ms sleep). If the server's
`add_listener()` wins a freed page first, the refill succeeds, `wait()` gets
no timeout (`refused` stays false), and it waits for a client. The late
client connects only after the test reads `retrying`, so both sides wait
forever. A fix belongs in the test (for example, let `retry` also report a
successful refill) and touches `src/sys/tests`, so it needs the full gates.

The source still has this independent test handshake problem:
`run_child("retry")` prints only after a request-free return from `wait`,
while `LocalServer::wait` sets a deadline only after a refused refill.
The existing `refill_watchdog` diagnoses a stall but does not prevent it.
Make the test observe refill attempts/results directly, including successful
refills, and release the hoarder from that observation. If deterministic
refusal is required, use a targeted test hook rather than assuming that
memory pressure makes every attempt fail. This is not evidence that the
historical stalls all came from the kernel publication race.

## A directory listing ends when another process removes an entry (2026-10-08)

`readdir` in rt.vdso (`src/sys/lib/rt.vdso/src/rt_fs.rs`) remembers the next
entry before it returns the current one. If another process removes that next
entry first, the listing reports one error and ends, so later entries are
never returned. POSIX lets a listing skip or repeat only the entries that
change during it.

This keeps Lorry from pipelining builds on Motor OS. A dependent's rustc lists
each dependency directory while a library's rustc still removes temporary
files there, so the listing could miss a library and the build would fail
with "can't find crate". `src/bin/lorry/src/executor.rs::PIPELINING` is still
disabled on Motor OS.

Still present: `readdir` replaces its cursor with `Done` before
`get_next_entry`, which validates the saved entry ID in motor-fs. A removed
successor therefore exhausts the stream. Use a directory-relative cursor
that survives entry deletion, and return the next entry's name, metadata,
and continuation together under filesystem serialization. Its ordering must
handle name-hash collisions and block/generation reuse. Merely retrying the
stale ID, or restarting at the first entry, cannot guarantee progress.

## A process can take an rmux server's name first (2026-09-27)

rmux on Motor OS finds its server by a service name made of the server's mask
(`src/bin/rmux/details.md` §4.2.1). Any process may register that name before
the real server starts. The client checks the holder's mask before sending
anything, so the impostor learns nothing. But the real server cannot start
while the name is held: the client reports the holder's PID and gives up.
Open question: is that enough, or should a name like this be reserved for
processes with the matching mask? Reserving it would need kernel support.

Still present: `src/sys/kernel/src/uspace/shared.rs::create` reserves only
`sys-io`; `src/bin/rmux/src/sys/ipc.rs::service_name` embeds the mask and
`open` authenticates it only after connecting. A possible fix is a kernel
authenticated service namespace keyed by creator capabilities, with the
expected mask supplied by lookup. Keep the peer-mask check as well. This is
a namespace-policy decision, not a reason to kill the existing name holder
or silently fall back to an unauthenticated transport.

## IPC service error codes (2026-09-26)

Partially fixed: `shared::get` now returns `E_NOT_READY` for a live service
with no free listener, and `ipc_service.rs` asserts it. The remaining
decision is whether a conflicting `shared::create` should return
`E_ALREADY_IN_USE` instead of `E_INVALID_ARGUMENT`. Change that branch and
the ownership-conflict assertions together; check callers that classify
service-start failures before changing the contract.

## Any process can use up a sync IPC service's listeners (2026-09-26)

Partially fixed: kernel `sys_obj.rs::OP_GET` now wakes a shared-service
server on connection, `LocalServer::wait` reports it and replenishes the
pool, and `test_silent_connections` covers this behavior. Pool exhaustion
now returns `E_NOT_READY`.

The total connection limit remains vulnerable. In
`src/sys/strobe/src/logging.rs::process_ipc` and
`src/sys/dns-resolver/src/main.rs::process`, the `!have_req()` return
still precedes the capability check. Silent unauthorized peers can consume
all connection slots. `src/bin/rmux/src/sys/ipc.rs::serve` already checks
capabilities on a connection notification and disconnects unauthorized
silent peers; apply that ordering to the other services. For peers that are
authorized to connect, choose explicit per-peer quotas and an initial-request
deadline if idle occupancy must be bounded; notification alone does not
provide admission fairness. Do not expire legitimate long-poll RPCs.

## 96 MiB guests fail systest (2026-09-27)

Needs a decision: should `full-test.sh --release --cpus 1 --memory 96` pass
the full suite?

It fails every time, even on a freshly booted guest running only the IPC
tests, in systest's `ipc_service::test_listener_pool_growth` (added in
`0046aedc`). Measured with temporary prints:

- A fresh 1 vCPU / 96 MiB guest has about 12,200 pages (48 MB) free for
  admission, and the kernel uses 4.7 MB.
- The test's child created 131,072 listeners. Each 8,192 cost about 1,000
  pages, so the whole pool needed about 64 MB. At about 98,000 listeners free
  memory reached the floor, and the child died on a 4-byte heap allocation
  instead of getting a clean refusal.
- Afterwards the kernel held 53.8 MB and kept it: its heap does not shrink
  when the listeners are freed. Every later test on that guest ran out of
  memory, and a rerun failed at its first spawn.

The count 131,072 was chosen to make the old `VecDeque` pool double to 2 MiB;
the pool is a `BTreeMap` now. On 2026-09-27 the count was cut to 8,192, the
smallest pool whose next contiguous doubling (64 KiB to 128 KiB) exceeds the
16-page object charge. That costs about 4 MB of kernel heap instead of 64 MB.
Whether the 96 MiB shape now passes the full suite has not been checked.

Before that test existed, the same shape failed later, at
`stdio_file_relay.rs:597`, where a child that spawns two more copies of
systest exited with -1; probably also a memory shortage, never confirmed.
Such failures were hard to read because the loader reported running out of
memory as `E_INVALID_ARGUMENT`; `f3fec151` fixed that.

## Deferred PCI BAR-boundary hardening (2026-09-15)

Additional defenses against buggy or malicious VMMs are outside the
[implemented vsock profile](../vsock.md#transport-and-dma-ownership), per
maintainer direction. The shared virtio mapper checks that a BAR selector is
below six, but not whether it names the upper
half of a 64-bit BAR; malformed VMM metadata could therefore make it probe
the wrong register or derive an invalid mapping. No such failure was
observed on tested QEMU, CHV, or Firecracker configurations.

If this hardening is revisited, validate BAR boundaries before probing,
using a bounded cached walk from BAR0. Review its additional boot-time PCI
reads then; no change or extra boot work is scheduled now.

Still present in `src/sys/lib/virtio-async/src`: `virtio_device.rs` validates
`bar < 6`, but `pci.rs::PciBar::init` immediately probes the selected
register and, for a 64-bit BAR, the next one. Reject selectors naming an
upper half and a 64-bit BAR starting at BAR5 before either sizing write.
Keep the earlier boot-work review requirement; this source review does not
schedule the hardening.

## Unresolved native Lorry self-build stall (2026-09-05)

Source review: unresolved historical failure, not proof of a current
deadlock. `src/bin/lorry/src/executor.rs` now changes scheduling state under
one mutex, notifies after completions, and reports an empty ready queue
with no dispatched work as an error. It can still wait while a dispatched
unit is stuck. `src/bin/lorry/src/process.rs::execute_observed` drains
stderr, joins the stdout reader, and then waits for rustc, without a
compiler deadline. These are distinct places where progress can stop;
none identifies what happened in this run, especially the unresponsive SSH.
The next fix should follow evidence distinguishing dispatch, spawn, pipe
EOF, child exit, and filesystem/IPC waits. Record unit/PID/phase and the
corresponding blocked handles before changing synchronization. Do not add
a larger timeout or call the resolver optimization a liveness fix.

The release developer gate's `native-lorry-self-gate` timed out at its
unchanged 1,200-second limit in an 8-vCPU/8-GiB VM. Native vendoring had
verified `Cargo.lock`; the first release build stopped producing output
after dispatching initial dependencies through `bisync 0.3.0`. A diagnostic
SSH `ps` also stopped responding. All eight vCPUs were sampled waiting in
KVM, with no console panic; guest memory pressure and a lost wake remained
unproven.

Resuming the retained build, 256 synchronized compiler-launch probes, and
cold builds in a disposable snapshot did not reproduce the stall or record
a kernel memory-admission refusal. Sharing immutable resolver candidates
later reduced a separate measured cost, and the complete gate passed with
unchanged limits and concurrency. That optimization did not diagnose or
repair the original liveness failure. The maintainer deferred that failure
and authorized continuing analyzer work.

Evidence was recorded under
`src/bin/lorry/target/lorry/native-self-tests/self-20260905T165416Z-421811/`
(`summary.txt`, `timings.tsv`, `native.log`, `qemu.log`, `lorry-cross`) and
`/tmp/motor-ra-url-dev-rebased.log`. Diagnostic logs include
`/tmp/motor-lorry-diag-{build,samples,spawn-stress,cold-build}.log`,
`/tmp/motor-lorry-diag-vendor-build{,-timestamps}.log`, and
`/tmp/motor-lorry-diag-vendor-stacks.log`. A gap in the interactive resident
log came from host terminal job control stopping SSH, not a guest timer
failure. Preserve the original timeout independently of later passing gates.

## Unresolved logging RPC stall (2026-09-07)

Source review: unresolved. `systest/src/logging.rs::rpc_result` still uses
`do_rpc(None)`. `strobe/src/logging.rs::process_log_request` synchronously
sends to the 64-entry I/O queue before `process_ipc` calls `finish_rpc`;
the I/O thread can be in filesystem write/flush/rotation. Thus a parked
RPC client alone does not distinguish missing request delivery from queue
backpressure or a missing response wake. The old filesystem flush-ordering
race is fixed, but that does not establish this stall's cause. Correlate
the request/response sequence, server wait snapshot, queue send/receive,
and filesystem completion. Fix the demonstrated missing transition; a
nonblocking queue, if chosen, must return an explicit refusal rather than
silently discard accepted records. Paths are under `src/sys`.

During kill-after-wait kernel validation, the second debug main-image gate
stalled after `logging::basic test PASS`. Systest's main thread waited in
`logging::rotation_and_space_cleanup` -> `rpc_result` ->
`ClientConnection::do_rpc` -> `SysCpu::wait`, before reaching the kill
regression. The rotation file stayed at 216,624 bytes while `kernel.log`
grew and SSH/filesystem reads remained responsive. Strobe was processing
other records; samples in its filesystem flush/write path did not establish
the cause or a complete logging-service deadlock.

The gate was deliberately terminated with status 143. The maintainer
deferred further logging/IPC investigation. Subsequent unchanged main-image
and developer gates passed, including logging rotation; no test exclusion,
retry, or timeout change was added. Those passes do not resolve the original
stall or conclusively exclude interaction with the reviewed kernel change.

Evidence was recorded in `/tmp/motor-kill-full-debug-2.log`,
`/tmp/motor-kill-debug-2-{console,systest,ps}.log`,
`/tmp/motor-kill-debug-2-systest-stacks-uploaded.log`,
`/tmp/motor-kill-debug-2-strobe-stacks-{uploaded,later}.log`, and
`/tmp/motor-kill-debug-2-log-files{,-later}.log`. The initial debugger requests
used an absent guest path; only the later uploaded-debugger captures are
stack evidence. Logging IPC, wake delivery, and other causes remain to be
distinguished before proposing a production fix.

## Unresolved sys-io abort during listener exhaustion (2026-09-10)

The first release main-image gate during Helix integration failed after
`test_all_cpu_fault_storm PASS`: aggregate listener exhaustion did not
complete, sys-io exited with status `0xffffffff`, and the suite reached its
unchanged 900-second deadline. This status identifies an explicit abort
(`abort_internal()` exits -1), not the kernel's `u64::MAX` main-thread fault
status. The abort's root cause remains unresolved.

The diagnostic run of the unchanged systest sequence passed, as did eight
cycles of the existing listener probe with abort-stack reporting. Those
probes returned OutOfMemory and recovered. Subsequent release gates 2–4
passed after all temporary instrumentation was removed; they do not explain
the original failure. The child-pipe fix and the later client-side network
allocation fixes do not establish a cause for this sys-io abort.

Evidence paths recorded at the time: the original log is
`/tmp/motor-helix-ra-main-release-1.log` and the failed image is
`vm_images/release/motor-os-helix-forensics.qcow2`. Diagnostic logs are
`/tmp/motor-helix-ra-systest-diagnostic.log`,
`/tmp/motor-helix-ra-listener-probe.log`, and
`/tmp/motor-helix-ra-listener-soak.log`; the later gate order is in
`/tmp/motor-helix-ra-release-gates.log`. Preserve the original failure when
investigating; do not treat later passes as resolution or external-network
flakiness.

## Network RX monitor intervention (2026-09-06)

Source review: a related defect is fixed, but the recorded incident has
no established source-level attribution. In
`src/sys/lib/virtio-async/src/virtio_queue.rs`, allocation, completion drop,
and the main reclaim task all use `reclaim_used_and_rearm` (`da52055d`).
It updates EVENT_IDX after opportunistic reclamation and rechecks the used
ring after arming; `test_opportunistic_reclaim_rearms` covers both paths
and cursor wrap. The debug monitor remains as a detector/recovery path,
which does not by itself mean the old defect persists.

Keep the historical failure open until it can be tied to that corrected
path. If intervention recurs, capture the device/driver used indices,
armed event index, IRQ handle wake count, and completion waiter together.
Repair the specific interrupt/re-arm or waiter-registration edge indicated
by those values; do not make monitor polling part of normal RX progress.

Debug runs 1 and 3 of the network-channel allocation gates exhibited the
previously diagnosed network RX monitor intervention. Logs were recorded
under `build/network-allocation.YuWF2O/`. Those gates validated allocation
refusal and recovery; they did not establish a repair for the RX issue.

## Open bugs from the 2026-08-28/29 performance run (address soon)

Found while reviewing file I/O and the async runtime; the run's report
(`docs/perf-run-2026-08-28.md`, since removed) and its measurements are in
git history. Unlike the rest of this file these are scheduled: pick them up
in this order.

1. **Loopback accept latency / pool release notification.** The historical
   run saw ~1-second accepts after 9-15 connections and a 298-second
   `systest close-race 300`. Those timings are not established for this tree.
   The current `moto-sdk/src/io/net/tcp.rs::TcpStream::drop` transfers its
   reservation to a driver record; `channel.rs::next_driver_msg` releases
   it after the queued writes and close have entered the ring, not after
   TCP linger. However, `rt.vdso/src/net/pool.rs::NetPool::reserve` still
   satisfies parked callers only when a new channel is published: freeing
   a slot on an existing channel does not notify them.
   `net/accept_pump.rs` still backs off 10/100/1000 ms after a reservation
   failure. Add release notification so a free live-channel slot satisfies
   an existing waiter, preserving cancellation and final-channel shutdown
   ordering and avoiding callbacks under channel/pool locks. Keep teardown
   reservations until their messages are published. Do not substitute a
   shorter retry loop for fixing the missing notification. A later latency
   measurement must distinguish provisioning, slot release, and accept
   readiness; the old one-second symptom alone cannot identify the cause.

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

4. **Debug-only loopback `ConnectionReset` in the suite.** In 2 of 3 debug
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

   Source review: keep the incident unresolved, with a narrower hypothesis.
   `moto-sdk/src/io/net/tcp.rs::TcpStream::drop` now publishes queued TX
   before close; `sys-io/src/runtime/net/socket/tcp.rs::reclaim_tcp_socket`
   now lets queued TX drain after channel EOF under the orphan limit
   (`dc37ef4b`). That fixes a concrete teardown race, but the historical
   resets were never attributed to it. Current reset branches include
   unread incoming data, zero linger, the orphan limit, and linger expiry.
   Identify which branch fires with the failing ping/pong shape before
   changing close semantics; do not remove deliberate resets or extend
   linger to conceal a lost completion. Paths are under `src/sys/lib` for
   moto-sdk and `src/sys` for sys-io.

5. **Killing the ssh session mid-suite leaves two vCPUs spinning.** Killing
   the ssh client while systest was in its pressure/admission tests (child
   processes being killed by design) twice left the guest with two vCPUs at
   100% and the network dead, once on a debug build and once on release; an
   uninterrupted run of the same image passes and leaves the guest idle. Not
   reproduced deliberately, not investigated. Fix: script the kill at that
   point, then take `mdbg print-stacks` of sys-io and of the spinning
   threads from the console. Gain: closes a hang class that any operator can
   trigger with Ctrl+C on a session.

   Source review: unresolved; no current source path establishes the two
   spinning threads' identities. russhd's output pumps, child-reaping task,
   and input coordinator in `src/bin/russhd/src/local_session.rs` run
   independently. Kernel `Process::die` posts kills; endpoint cleanup in
   `src/sys/kernel/src/uspace/process.rs` precedes visible process exit.
   Neither the newer single-close guard in russhd nor other teardown fixes
   prove this hang repaired. Capture the spinning stacks and lock owners,
   then trace session close, descendant termination, and sys-io disconnect
   handling. Fix the demonstrated held-lock or wake/cancellation cycle;
   do not add sleeps to the kill path.

6. **sys-io's statistics provider is absent for a moment after boot.**
   `moto_sdk::stats::Collector::providers()` does not list sys-io (provider 2)
   for a short window after boot: `systest fs-bench` started ~2 s after ssh
   came up panicked on the lookup, and two places in the suite retry around
   it. Still present: `src/sys/sys-io/src/main.rs` starts sys-init before a
   500 ms sleep and `stats_server::start`; `stats_server.rs` sleeps another
   second before registration. It registers before binding `sys-io-stats`,
   so discovery can also briefly advertise an unavailable endpoint.
   `moto-sdk/src/stats/userspace.rs::Collector::providers` remains a
   best-effort snapshot, not a readiness barrier. Bind the provider before
   advertising it and replace timer-based startup with registry readiness.
   For callers that require a provider, expose an explicit readiness/error
   contract instead of unwrapping an optional snapshot entry. Do not block
   sys-io's first FS clients on strobe: startup depends on those clients.
   Any change to boot's critical path still needs boot-latency review.

## Performance follow-ups from the same run (not scheduled)

What landed on 2026-08-29: kernel halt polling with IPI elision, the tree
frusa in the vdso, local `seek`, one-request path resolution, and runtime
polling of active io_channels. Measured on qemu with 4 vCPUs: a hot 4 KB
read 107 -> 9 us, crossbench sequential 4 KB read 19 -> 380 MB/s, random
read median 208 -> 6 us, write 190 -> 280 MB/s, rnetbench round trip
100 -> 41 us. `systest wake-bench` is the first number to take on a new host
or hypervisor (a cross-CPU hop is ~1 us with halt polling and ~25 us
without). Left on the table, largest first:

- **Write path** (Finding 6 of the run). Still present, partly improved.
  `src/sys/sys-io/src/runtime/fs.rs::on_cmd_write_multi` holds one FS write
  guard per message but still calls `MotorFs::write` per block-sized chunk;
  each call runs `Txn::do_write_txn`. The log limit in
  `src/sys/lib/motor-fs/src/layout.rs` is still 64 blocks. `txn_log.rs` now
  groups log writes and contiguous home-block writes into scatter-gather
  runs, but data is still written to the log and then its home location.
  `commit_txn_batch` queues four `Commit` boundaries; these drain earlier
  completions in `moto-sdk/src/async_fs/block_cache.rs`, whereas explicit
  `Flush` issues a device flush. The old "three device barriers" description
  does not describe those distinctions.
  Start with a bounded multi-block transaction API, retaining partial-write
  and failure semantics. Metadata-only logging for newly allocated blocks
  requires ordering their data before committing metadata and proving crash
  recovery. A larger log also changes the on-disk layout and must not be
  treated as a local constant tweak. The former descriptor-retention
  deadlock is fixed; throughput and any claimed gain still need measurement.
- **Client-side work per synchronous FS op** (Finding 7). Of a ~9 us hot
  read, ~4 us is the vdso's own runtime work: boxing the task closure, a
  oneshot, `LocalRuntime::spawn` per op, a `BTreeMap`
  response slot. Running the io task inline instead of spawning measured
  10.7 -> 8.0 us per read. Candidates: resident worker tasks or a
  `FuturesUnordered` of in-flight io tasks polled alongside the task
  channel, a slot array for responses, a preallocated per-thread request
  block. The structural overhead remains in
  `rt.vdso/src/rt_fs.rs::{async_run,main_runtime_task}` and
  `moto-sdk/src/io/fs.rs::responses` (both under `src/sys/lib`). There is
  now a resident response pump, but each submitted operation still spawns
  its own task. Try a bounded resident worker design first; keep the
  response pump independently runnable and preserve synchronous callers'
  buffer lifetimes. Do not serialize all FS work behind an inline await.
  The old allocation count and latency estimate need remeasurement.
- **One round trip for `stat`.** Still present in
  `src/sys/lib/rt.vdso/src/rt_fs.rs::stat`: `stat_internal` obtains an ID and
  kind, then `metadata` makes a second request. `CMD_STAT_PATH` in
  `moto-sdk/src/sys_io/api_fs.rs` and sys-io's `on_cmd_stat_path` still return
  only ID/kind. Add a versioned path-plus-metadata response, with metadata
  resolved under the same filesystem lock and authenticated role. Plain
  non-truncating opens of existing files already need only the path lookup;
  they construct the local `File` directly. Create, append, and truncate
  have additional operations, so the old universal three-request open
  claim is removed. Coordinate this work with the open-permission fix above.
- **Halt-poll placement and policy.** `post()` scans from the thread's last
  CPU and treats a polling CPU as idle; the residual IPIs (0.2-1.8 per op in
  some runs) are wakes aimed at a CPU that is running, so preferring a
  polling CPU explicitly is the next step. An activity-based idle policy
  (poll only within some milliseconds of the last resumed thread) would
  cost nothing on a guest that only ticks if the idle host CPU of the
  fixed window ever matters; the KVM-style adaptive window was measured and
  rejected (it loses most of the latency win: 25 us hot reads).
  Source review: the placement follow-up remains in
  `src/sys/kernel/src/sched/scheduler.rs::post`, which selects by `idle`
  without prioritizing `polling`. Policy has already changed: `halt_poll`
  uses 200 us normally and 10 us after three consecutive misses, resetting
  on a hit. Evaluate a polling-CPU-first idle scan against cache affinity
  before adopting it, and retain the global queue when all CPUs are busy.
  A last-activity policy remains an experiment, not an established fix.
- **Recorded verdicts.** The sliding read window (DEPTH 5) was dropped
  after a same-sitting A/B: cold_fs_read 269-279 vs 526-649 MB/s and
  crossbench sequential read 309-323 vs 382-435 MB/s for the batch of 4; it
  keeps 60 of the channel's 64 server pages busy and starves readahead.
  Floating sys-io's runtime thread off CPU 0 changed nothing within noise:
  the CPU 0 concentration was the affinity plus every other thread sleeping
  between hops, never the cause of the slowness. The cloud-hypervisor
  cross-check showed the same effects as qemu.
  These are retained experimental decisions, not unresolved bugs. The
  current `moto-sdk/src/io/fs.rs::read` still uses `WINDOW = 4`; no source
  evidence justifies reviving the rejected window or affinity experiment.
- Networking follow-ups from the run (small-write throughput under halt
  polling, RX batching, per-packet wakes) are in
  `networking-remaining-steps.md`.
  Still candidates, with the old throughput regression unmeasured on this
  tree: sys-io's `runtime/net/device.rs::rx_task` consumes/reposts individual
  completions and calls `rx_notify.notify_one` for each accepted packet;
  virtio's reclaimer drains available used entries but has no timed RX
  coalescing window. `rt.vdso/src/net/blocking.rs::tcp_read` still goes
  directly to its blocking bridge after constructing the read future,
  without the write path's bounded spin. Start with bounded RX batches and
  one notification per batch; preserve the arm/recheck protocol and compare
  interactive latency before considering read-side busy polling. Notification
  coalescing in the runtime means a notify call is not necessarily a syscall.

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

  Still absent: `src/sys/lib/moto-sys/src/stats.rs::ProcessInfoV1` retains
  the 32-byte name and snapshot-only interface. Kernel
  `src/sys/kernel/src/xray/stats.rs::KProcessStats::iterate` walks weak
  process records, not an execution journal. An eventual opt-in event
  stream should record successful starts and exits with a stable identity
  across PID reuse, a monotonic sequence, and explicit overflow reporting.
  Keep arguments excluded by default and preserve the existing deferral.

- **gix: streaming for large objects, and an object size limit** (ruled by
  U. Lasiotus, 2026-09-20). `gix clone` of `moturus/helix` failed on a
  17.6 MiB generated parser because every object was limited to 16 MiB. Git
  has no such limit, so the limit was removed and gix now holds each object
  in memory whole, as Git does below `core.bigFileThreshold` (512 MiB).
  Investigate later whether to stream large blobs instead and whether to
  have a limit again, and at what value. Facts to start from:
  the receive path already streams;
  delta resolution and checkout can stream only a blob that is neither a
  delta nor a delta base, and the server decides that (helix's large blob is
  a base, so Git itself fails on its pack under a 16 MiB allocation limit);
  streaming a delta base needs temporary files in the two central `gix-pack`
  routines. Memory is still bounded by the caps that remain: 128 MiB per pack
  file, 512 MiB of buffers in total while a received pack is indexed, and
  128 MiB of files per tree. The 262,144-line diff limit also remains, so
  that parser cannot be diffed.

- **`channel.rs` SeqCst fence audit** (out of scope, ruled
  2026-08-15). The io_channel wake edges now carry their own ordering;
  the extra channel-driver fences predate that and are candidates for
  removal. Remove them in an independently tested change with a performance
  verdict in the same sitting; this waits for a dedicated review of the
  ordering argument.

  Still present in `src/sys/lib/moto-sdk/src/io/net/channel.rs` at
  `dispatch_incoming` and `tx_send_batch`. Prove publication and wake
  ordering separately for each before removing it. The SeqCst fences in
  `ipc/io_channel.rs::{set_client_waiting,is_client_waiting}` and the
  corresponding server/page-wait methods are part of the wait-bit versus
  queue/page-publication handshake; they are not covered by this proposed
  removal. Stronger individual loads/stores alone do not replace them.

- **Drain pending kernel logs when sys-tty exits** (remaining part of the
  2026-08-15 logging follow-up). Remote kernel-log access is now supplied by
  `src/sys/sys-tty/src/forwarder.rs` and strobe's `/system/logs/kernel.log`;
  the old unwired `do_syslog` is gone. See [kernel logs](../kernel-logs.md).
  The teardown guarantee is still incomplete: `sys-tty/src/main.rs` stops
  its kernel-ring reader on child exit and drains `Output`, but never waits
  for `Forwarder`'s file queue to finish. `Output::drain` does not cover that
  queue or kernel records not yet read. rt.vdso's panic path also exits
  without a sink-completion acknowledgment (its debug sleep is not one).
  For orderly teardown, drain a captured kernel-ring boundary and add a
  bounded forwarder flush acknowledgment before exit; define how an
  unavailable sink reports undelivered records. Do not delay boot or add a
  panic-path sleep. The old silent exit-222 observation is not enough to
  attribute a particular lost record to one of these queues.

- **kernel `wait-set`** — still absent. The retained vectors in
  `src/sys/lib/moto-sdk/src/async_runtime/local_runtime.rs` remove repeated
  user-space allocation, but `build_wait_list` still scans registrations
  and `src/sys/kernel/src/uspace/sys_cpu.rs::process_wait_handles` validates
  and registers every supplied handle on each wait. The configurable
  `max_wait_handles` limit also remains. A persistent kernel wait-set with
  incremental add/remove and a ready queue would remove that repeated
  scan. Specify handle-close, duplicate-handle, cancellation, and
  missed-wake semantics first; retain the small inline-wait fast path for
  ordinary RPCs. This remains a separate kernel/runtime project, not a
  reason to increase the limit or add polling.

- **virtio queue: allocation-waiter hygiene and wakeups** (recorded 2026-09-08).
  Releasing a descriptor chain wakes at most two queued allocation waiters,
  and a waiter that does not
  fit re-registers at the back of the line. Under the single-owner design
  the block queue has one submitter that never waits in the driver, and
  each net queue has one submitter. Supporting several independent
  allocators would require revisiting this policy: waking only the first
  waiter can starve a fitting waiter behind a non-fitting
  one once the last in-flight request has completed. Options then: wake
  every waiter, or select the first that fits from per-entry sizes and a
  free-descriptor count. That review should also cover duplicate registrations,
  removal when allocation succeeds on an unrelated poll, and cancellation
  of a registered `VqAlloc`; stale entries must not consume a live waiter's
  wakeup.

  Still present in `src/sys/lib/virtio-async/src/virtio_queue.rs`:
  `VqAlloc::poll` appends a waker on every pending poll, has no registration
  token or cancellation cleanup, and `free_descriptor_chain` pops at most
  two entries. Two stale or non-fitting entries can consume the last
  wake opportunity. Register each future once, update its waker on repoll,
  and remove it on success/drop. Then use a bounded wake-all or a
  descriptor-count-aware selection policy. The EVENT_IDX re-arm fix does
  not repair this separate waiter-queue issue.

- **Block I/O task: recover the sequential cost** (recorded 2026-09-09).
  The single-owner task costs 3 to 5 percent of sequential throughput against
  the old driver. Three measured
  changes recover it and more (593 versus 506 MiB/s for 4 KiB sequential
  reads): drain the used ring at the start of the task's poll, keep a
  single-chunk response inline instead of in shared state, and a channel
  receiver that does not spin on an empty inbox, with the inbox at 16
  entries. Not adopted because the 64-thread p99 latency rose from 5.9 to
  10.7 ms and one boot showed TCP throughput halving under 16 saturated disk
  readers. Pick up only with a matched-load network measurement and the
  threaded latency probe; patch and data under `build/virtio-waiters-results/`.

  The proposed implementation is still absent: `block_io.rs::Request::new`
  always uses `Rc<RefCell<Response>>`, including one-chunk requests; `run`
  polls completions without a direct used-ring drain at entry;
  `runtime/fs.rs` gives the inbox 64 entries; and
  `moto-sdk/src/async_runtime/channel.rs::RecvFuture::poll` still busy-spins on
  an empty inbox before arming. Revisit the one-chunk response first as a
  separate change, preserving early descriptor release and earliest-chunk
  error reporting. Evaluate drain/batching and a nonspinning receive mode
  independently. The old 3–5% cost and the rejected combined prototype's
  gains are historical measurements, not established current performance.

## Declined review findings (2026-09-24)

Considered in the review of the `CAP_NET`/`CAP_FS_WRITE` work and declined.
Do not raise them again.

- Fresh-boot placement budget (finding 8). The existing budget still limits
  added spread relative to the fragmentation at boot. A global split-event
  delta would test a different property.
- vsock credit on undecodable headers (finding 14). No credit stall was shown.
  Credit advertisements are cumulative, and malformed headers must not become
  trusted credit input.
  Source review: the declined behavior remains deliberate.
  `src/sys/sys-io/src/runtime/net/vsock.rs::handle_vsock_packet` returns on
  a decode error before updating connection state; only a validated
  `PacketHeader` reaches the credit logic. No fix is proposed and this
  finding is not reopened.

## P3: TIME-WAIT sockets still hold 10-25 KiB each (2026-10-18)

A connection that sys-io closes first, as an HTTP server usually does, stays
in TIME-WAIT for `CLOSE_DELAY`, 10 s
(`src/sys/sys-io/netstack/src/socket/tcp.rs:388`). Until 2026-10-18 it held
about 400 KiB of sys-io memory for that time. Its rings were released only if
the application had closed before FIN-WAIT-2 and the ACK of the FIN carried no
ACK of data. Its socket also kept the client channel, whose 512 KiB of shared
pages stayed mapped after the client let go. Both are released now. On a
224 MiB VM, 200 loopback HTTP/1.1 requests with `Connection: close` to
`wasmtime-rt serve` leave sys-io about 5 MiB above its baseline for the 10 s,
against 80 MiB before. With 800 sockets in TIME-WAIT, sys-io is about 10 MiB
above its baseline.

What stays is the netstack socket, the `MotoSocket` and its linger task. Only
the tuple and its timer need to stay (`cdd7c886`). A compact TIME-WAIT record
would bring a server taking 20 new connections a second from 2-5 MiB of
retained sys-io memory to well under 1 MiB. Measurements and the client used
are in `build/claude-targets/m3/` (`xtw.sh`, `x3b.sh`, `xtw-*.log`,
`x3b-224.log`).

## P2: Shrinking descriptor pools (2026-10-17)

Each address space keeps its page-descriptor slabs until teardown. Unmapping
returns descriptors to its free list, but even a completely unused slab
stays allocated. Sparse lazy reservations avoid descriptors for untouched
pages; a long-running process that temporarily touches many pages still
retains the descriptor pool from that peak.

Return completely unused descriptor slabs to the physical allocator while
preserving live descriptors and safe reuse under the existing allocator
lock. Keep reclamation simple and avoid adding boot-time work. Validate
repeated touch/unmap cycles and concurrent faults inside Motor OS, including
slab boundaries, and check that reclamation does not regress allocation
performance. This reclaims kernel bookkeeping memory, independently of
reserved-versus-resident process statistics.
