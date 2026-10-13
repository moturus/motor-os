# Cold spawn optimization: sys-io loading

Status (2026-10-09): the design is validated by a complete second
prototype, described in
[spawn-optimization-prototype-2.md](spawn-optimization-prototype-2.md),
which has since been reshaped in the working tree into the production form
this plan describes: the experimental modes, the shared page cache, the
relocation search, and the mlibc emulation are gone, and the hardening
items below are in. Section 3 is the order in which to carve that tree
into reviewed patches. Progress (2026-10-12): step 0 (the syscall-exit
yield) is committed as cdba6480, step 1 as 16172957, step 2 as
fbec3547 (simplified by a second reviewer, reviewed again and re-gated
with three release and three debug full-test runs), step 3 as
294ad2e2 (without the host test it was gated with: the parser's tests
move into systest later) and step 4 as 33646420; step 5 is staged and
gated (three release and three debug full-test runs, all passing),
awaiting review; e1b39bab, between them, is a test-only fix for a
pre-existing systest race that step 5's first gate attempt exposed;
the rest of the tree is uncommitted.

The goal is to read, allocate, and relocate only the executable pages a
program needs. On the prototype's host (nested KVM, so absolute times are
about 8x those of the earlier bare-metal prototype) `rustc --version`
through its shell wrapper went from 3178 ms to 463 ms (6.87x) over 50
alternating pairs with lazy relocation and the planned mlibc change
emulated; 563 ms (5.66x) without the mlibc change; eager loading moved
into sys-io on its own gives 1.54x. Clang 5.49x, `rush -c exit` 1.11x,
boot time unchanged. Ratios from different hosts are not compared, and
there is no numeric acceptance gate. Evidence, experiments, and the
earlier plan are in
[spawn-optimization-prototype.md](spawn-optimization-prototype.md).

## 0. Decisions

Settled by the prototype or by review:

- **A running executable cannot be deleted, renamed, or replaced** (user
  decision, 2026-10-08). `src/tests/test-tui.sh` now ends the guest child
  that its non-pty Ctrl+C check used to leak; that fix is in the working
  tree and lands first.
- **The parent writes the startup data.** sys-io's part ends when the
  stopped child exists; the parent writes `ProcessData`, arguments,
  environment, and stdio through the child's process handle, as it does
  today, and wakes the child. The protocol is one request and one
  response; large argument and environment payloads never cross the FS
  channel.
- **sys-io authorizes an `EntryId`**, taken from the parent's open
  descriptor, as the requester's role (regular file, readable and
  executable). The parent keeps PATH, script, and working-directory
  resolution. This is the authority `CMD_READ` already grants.
- **Relocation lookup is a load-time validating pass** that indexes the
  first record per page (the review's option a): correct for any record
  order and 59 ms of the 463 ms rustc run. Binary search per fault (option
  b, 409 ms) is dropped because it detects a malformed table only when a
  page is faulted. Packed relocations (RELR, option c) are a later step,
  taken only if measured worth it.
- **Sharing clean read-only pages is deferred.** It does not speed up a
  cold launch (475 vs. 463 ms) and saves about 10 MB per four concurrent
  rustc instances. It is not part of the series; the prototype's cache is
  archived in the working tree's history, not carried.
- **Read-ahead is the adaptive window only**: one page, doubling while
  faults continue where the last window ended, capped at 32. Fixed
  windows and first-fault read-ahead measured equal or worse.
- **Files under 1 MiB load eagerly** in sys-io: a demand fault costs more
  than copying a few pages.
- **Syscall buffers in absent pages are paged in by the caller** (user
  decision, 2026-10-09). The kernel never pages memory in on a syscall's
  behalf. A copy that hits an absent page of a demand-paged executable in
  the caller's own address space fails with the new `E_PAGE_ABSENT`, the
  page's address in the first result word; moto-sys's `do_syscall` reads
  that page, which faults it in, and repeats the syscall. Callers never see
  the refusal. This holds because every operation copies its inputs before
  any side effect (the wait syscall now reads its handle array before it
  wakes anyone) and the only copy-outs belong to side-effect-free queries.
  Copies into another process's memory, such as a debugger's, keep failing
  as for lazy memory. `mem.file_paged_syscall_misses` counts the retries.
- **No force-eager selector** (user decision, 2026-10-09). sys-io loads
  files under 1 MiB eagerly and falls back to eager loading for images
  demand paging cannot serve; nothing else selects it. Tests check image
  contents against recomputed values and use the read-only-relocation
  fallback where an eagerly built child is needed.
- **Memory floor: the commitment stays** (user decision, 2026-10-09).
  Every page of a paged mapping is admitted when the mapping is reserved
  and the fills draw on that commitment, so admission behaves exactly as
  with eager loading and a running program is never refused its own
  pages. The cost is that admission counts whole images while only
  touched pages use RAM. A spawn that cannot commit its image fails up
  front with `E_OUT_OF_MEMORY` (tested).

- **Syscall-exit preemption** (user decision, 2026-10-09). The debug
  watchdog's "dead CPU" on the prototype host was a scheduler bug: a timer
  tick that lands inside a syscall only sets the CPU's wake flag, which
  the next tick in user mode honors, so a thread that spends nearly all
  its time in syscalls keeps its CPU, and that CPU's timers, jobs, and
  scheduler loop, for seconds (measured: about 900 ticks and one
  preemption over a 9 s syscall-bound phase). Now a syscall during
  which a tick landed on its CPU yields to the scheduler loop before
  returning to user mode (`Thread::scheduler_tick_in_syscall`, wake accounting
  untouched), counted by `sched.syscall_exit_yields`. The condition is
  the CPU's existing timer-tick flag, set by every tick and cleared by
  the loop, not the CPU's wake flag: every job posted to a CPU raises the
  wake flag, and yielding on it handed the CPU to every thread the caller
  woke, which on one vCPU made a narrow pre-existing net-channel race (a
  refusal lost when sys-io disconnects right after sending it; prototype
  2 report, section 5) fail every run. The yielding thread is re-queued
  on its own CPU when nothing is queued there or globally; otherwise it
  goes through the usual placement, like a woken thread (user decision,
  2026-10-10: placement alone would have moved a lone syscall-bound
  thread to an idle CPU on every tick). The temporary liveness stamp is
  gone. A systest pins a syscall-bound thread
  and a sleeper to one CPU and bounds the sleeper's latency. Not done:
  `get_backtrace`'s array on the interrupt stack, which turns a real
  stall report into a crash.

Open: nothing before the series starts.

## 1. Ownership and API

Applications keep the existing spawn API and moto-rt ABI. rt.vdso sends
one `CMD_SPAWN` request on its existing FS channel; ELF segment
descriptions and paging operations are private to sys-io and the kernel.
General-purpose mmap and new public SysMem mapping operations are not
prerequisites.

| Component | Responsibility |
|---|---|
| Parent's rt.vdso | Resolve the path, PATH, and scripts; send the request with the executable's `EntryId`, capabilities, detached flag, and debug name; write startup data, arguments, environment, and stdio through the process handle; retain stdio descriptors, relays, terminal behavior, and relay draining; wake the child; kill it if anything fails first. |
| moto-sys | Repeat a syscall the kernel refused with `E_PAGE_ABSENT` after reading the named page. |
| sys-io | Authorize the executable as the requester and lock it; parse ELF; create the stopped child for the requester; construct its address space and vDSO; serve demand faults and relocations; refuse mutations of locked executables. |
| Kernel | Authorize delegated creation; preserve parentage, capabilities, handles, and accounting; own file-paged segments, fault parking and resumption, admission commitments, retirement, and teardown. |

The kernel's delegated creation is the `requester=<connection handle>`
argument of the existing `process:` URL, accepted only from sys-io. The
kernel resolves the connection's peer (which may be sys-io itself: it
launches sys-init through its own FS channel), checks that it is alive
and holds `CAP_SPAWN`, applies every capability, role, and detached-child
check to the peer, charges the creation to the child's address space
class as every spawn does, and returns two handles: sys-io's own, and the number of the one it placed in the peer's
table (`SysObj::create_res1`). sys-io returns the latter; its own handle
serves to kill the child if the response cannot be delivered, and is
dropped otherwise. Return `E_NOT_ALLOWED` to any other caller. When the
response cannot be delivered, or the connection is gone right after it
was sent (a send into the ring succeeds even then), sys-io abandons the
child: `SysObj::put_remote_1(own handle, number, ABANDON_DELEGATED)`,
sys-io only, kills the child and takes the number back from the
requester's table if the child's main thread was never woken, and does
nothing to a child the requester has woken. The requester is found as
the child's parent, not through the connection, which may be closed by
then; the number goes only while it still refers to that child (review
findings, 2026-10-11). Without this the requester would hold the dead
child and its address space until its own exit. A requester that closes
its channel after sys-io's check keeps the stopped child until it exits,
like any child it holds.

**Authorize before loading.** sys-io learns each client's capabilities
when the client connects and refuses `CMD_SPAWN` from one without
`CAP_SPAWN` before reading a byte; the kernel checks again at creation.
sys-io launches sys-init through the same path, with no boot-time
preparation; the kernel's bootstrap loader of sys-io stays eager.

**Stdio relays stay in the parent.** Finish startup data, handle handoff,
and stdio wiring before waking the child's main thread. Keep borrowed
descriptors open on success and failure.

## 2. Loading, paging, and lifetime

- **File lock.** sys-io counts references per `EntryId`: one while a
  child is under construction, one per live file-paged mapping. While any
  exists, every mutation returns `E_NOT_ALLOWED`: both write forms,
  truncate, delete, rename of the file, rename onto it, both permission
  forms, and `copy_file_range` into it. Before refusing, sys-io applies
  the retirements the kernel has already queued, so a mutation that
  follows a waited-for exit succeeds. The kernel retires an address
  space's mappings when its process exits, before the exit is visible to
  waiters, when the space is dropped, and when a file-paged segment is
  unmapped; a debugger's or parent's process handle does not keep the
  file locked.
- **Checked loading.** sys-io's own parser accepts ELF64 x86-64
  executables and PIEs with at most 64 program headers and a 64 KiB
  dynamic section, R/RW/RX `PT_LOAD` segments whose page ranges ascend
  without sharing a page, an entry point inside an executable segment, and
  `R_X86_64_RELATIVE` relocations in one segment's file bytes. It rejects
  W+X, `PT_TLS`, `PT_INTERP`, and every arithmetic or bounds error, and
  never panics. Images outside paging support are built eagerly in
  sys-io: segments whose file offset and address disagree modulo the page,
  relocations into read-only segments. Writable segments whose relocation
  records are not sorted by address load eagerly while the rest is paged.
  An oversized segment fails at admission (`E_OUT_OF_MEMORY`), not in the
  parser.
- **Demand pages.** A file-paged segment has no page descriptors until
  filled. The kernel serves only not-present user faults whose access the
  segment permits; the faulting thread is parked (preempted, with no
  resume job) and one request per page is queued, coalescing threads that
  wait for the same page; one notification object wakes sys-io. sys-io
  reads the window through the block cache into a page-aligned buffer,
  zeroes bytes past the file tail, applies every overlapping relocation
  clipped to the window (a record crossing a page boundary is written half
  by each page's fill), and installs private copies; the kernel keeps
  pages that are already present, releases the commitment for installed
  ones, and resumes the waiters. Pages past both the file bytes and the
  last relocation are zero-filled by the kernel without a request. A fill
  that fails kills the waiting threads. Each child gets the vDSO's
  read-only segments shared from sys-io's own mapping and a private
  writable segment built from the pristine ELF bytes, never a copy of
  sys-io's live state.
- **Cleanup.** A failed construction drops the address space, which
  retires its reservations and releases their lock references and
  commitments. Once the parent has woken the child, it follows normal
  parent/detached lifetime rules, and its pager does not depend on the
  launcher's connection. A child whose main thread was never woken is
  killed when its parent is torn down (detached or not: nobody else can
  wake it) and when sys-io cannot deliver the handle. "Never woken" is
  decided under the main thread's status lock, where the wake posts the
  start: a child whose start is queued but has not run yet is already
  started and is left alone (review finding, 2026-10-11). Killing a
  never-started process completes its exit: the kill of a `Created`
  thread now finishes the exit itself, which also removes a pre-existing
  zombie for any parent that killed a child it had not yet woken; a start
  job that such a kill leaves queued finds its process gone, with at most
  a thread handle keeping the thread, and does nothing (review finding,
  2026-10-11). A kill by pid can reach a child as soon as its pid exists,
  inside its construction: the child's handle object is therefore created
  first and handed to the creator directly, so an exit the kill completes
  has it to take and the creator still gets a handle, to a child that
  died at once; the main thread is built under the status lock a kill
  holds, and a kill that found no thread yet is finished by the thread
  once it exists (review finding, 2026-10-11). The abandonment counts a
  child killed before any wake as never woken, by a record of the first
  wake that outlives the thread, so its handle is withdrawn too (review
  finding, 2026-10-11). Stale fills after retirement are rejected
  (`E_BAD_HANDLE`) and ignored by sys-io.

Bound service work and memory: one request per parked thread, a fixed
cap on concurrent serves (32 windows of at most 32 pages, 4 MiB of
buffers), allocation failures reported as fill failures, and the FS
channel budgets for requests. No kernel lock is held across I/O or across
frame allocation (zero fills run outside the pager registry lock). Every
address sys-io passes is checked, even though only sys-io may call the
pager operations. Metrics: sys-io's `spawn.requests`, `pager.mappings`,
`exec.locked_files`, `pager.faults`, `pager.filled_pages`,
`pager.failed_fills`, and the `spawn.build_us`, `spawn.scan_us`,
`spawn.vdso_us`, and `pager.serve_us` times; the kernel's
`mem.committed_pages` and `mem.file_paged_syscall_misses`.

## 3. Implementation sequence

The prototype was kept and reshaped (2026-10-09): its structure is the
plan's, every non-obvious correctness detail in it was found by running
the gates, and what was experimental (seven loader modes, the shared page
cache, the binary-search index, the mlibc emulation, surplus timers) came
out cleanly. The working tree holds the result; the steps below are the
order in which to carve it into reviewed patches, each checked against
this plan and carrying its tests. Patches of 100 to 300 lines; the two
larger ones are marked.

0. **Prerequisite, separate from the series:** the syscall-exit yield
   (section 0), gated on its own (three debug and three release full-test
   runs). Committed as cdba6480.
1. **Tests:** `test-tui.sh` ends the non-pty Ctrl+C child before cleanup
   (passes at HEAD). Committed as 16172957.
2. **Kernel, delegated creation:** `requester=` in `Process::new_child`,
   the two handles, refusal of a dead requester, the abandonment of a
   delegated child through `put_remote_1` (kill and handle withdrawal,
   only if the child was never woken, a child already killed before any
   wake included), a creation that survives a kill by pid landing inside
   it, the kill of a `Created` thread
   completing its exit (with a start job that outlives its process doing
   nothing), and the kill of never-woken detached children at their
   parent's teardown, decided under the main thread's status lock. Also
   fixes a pre-existing panic found on the way (user request,
   2026-10-11): every wake of a `Created` thread queued a start job, and
   the second job asserted on a running thread; the first wake now posts
   the start and later ones are pending wakes, as for a running thread.
   Tests (`raw_spawn.rs`): a caller other than sys-io passing
   `requester=` is refused, the kill of a never-woken child completes its
   exit, a kill racing the first wake (64 rounds, a thread handle
   outliving the process), a thread woken twice before it runs (64
   rounds), and a kill by pid racing the creation (200 rounds) in the
   default suite; an unstarted detached child dies with
   its parent (`systest raw-spawn-detached`, run by `full-test.sh` under
   the detach-capable mask like the other detached tests). The positive
   path arrives with step 4. Staged 2026-10-11 and gated on HEAD plus the
   patch alone, three release and three debug full-test runs and the
   developer-image release run, all passing; the same gate was run again
   on the final tree after each round of review fixes and the double-wake
   fix. One
   debug run of that last gate failed in `test-terminal-size.sh`: its
   guest booted to the shell with networking up but its ssh service never
   listened, so the script's 600 s wait ran out. The failed boot's service
   logs did not survive the VM's kill, the kernel paths exercised at boot
   are unchanged from 27 earlier passing runs, and three further debug
   runs passed; the cause is unexplained (possibly the known net-channel
   lost-refusal race, hitting the ssh service's listener setup).
   Simplified by a second reviewer on 2026-10-12 and reviewed again: one
   parent-teardown job (`post_parent_dropped`) that kills a non-detached
   child outright and a detached one only if never woken, through the
   same `abandon_if_never_woken` the delegated rollback uses; the parent
   link read inline instead of through a stats accessor; and the
   creation-race test finding each round's child in the process list by
   parent pid and a per-round name rather than predicting the next pid,
   so other spawns cannot be mistaken for it. The redesigned test still
   lands the kill before the child's main thread exists in about 16 of
   its 200 rounds per run (about 21 with the pid prediction), measured
   with a temporary kernel log line over three runs each. The simplified
   tree was gated again on HEAD plus the patch alone, three release and
   three debug full-test runs, all passing (the developer-image run was
   skipped at the user's direction). Committed as fbec3547.
3. **sys-io parser and protocol:** `spawn/elf.rs`, `CMD_SPAWN` and
   `SpawnRequest`, `SysObj::create_res1` and `SysObj::ABANDON_DELEGATED`,
   the moto-io client. Nothing calls it yet. Carved 2026-10-12: the
   command id and the request and response codec (`spawn_msg_encode`,
   `spawn_msg_decode`, `spawn_resp_encode`, `spawn_resp_decode`,
   `SPAWN_MAX_DEBUG_NAME`), `FsClient::spawn`, the two moto-sys
   additions, and the parser file. sys-io's own treatment of the command
   (`known_cmd`, `is_read_command`, `release_donated_pages`, the module
   declaration) waits for the handler in step 4, so this step changes no
   behavior of sys-io, which goes on answering command 21 as unknown and
   does not compile the parser yet. Staged 2026-10-12 with a host test
   of the parser (`rustc --test` over `spawn/elf.rs`, like the kernel's
   wait set) and gated on HEAD plus the patch alone: three release and
   three debug full-test runs and the developer-image release run, all
   passing; no compiler warnings, clippy unchanged for sys-io, the three
   libraries and systest. Committed as 294ad2e2 without the host test
   (user decision, 2026-10-12: the parser's unit tests go into systest,
   natively, later; nothing in the image changed, so the gate stands).
4. **sys-io eager spawn** (larger patch): the spawn-capability gate at
   the connection, authorization of the entry, construction reference and
   the mutation refusals, eager segment loading, the vDSO installer moved
   from rt.vdso, the handler with the kill on an undeliverable response.
   Test: a systest that requests a child directly, checks the handle is
   its own and the child its own, kills the never-started child, and is
   refused a capability it lacks; malformed images; a client that
   disconnects right after sending `CMD_SPAWN` (the request is served,
   sys-io abandons the child, and no child of the client remains).
   Carved 2026-10-12 and staged: `spawn.rs` (the lock and its
   construction reference, `SpawnStats`, block-wise reads with prefetch,
   a local R+W alias per segment, one validating pass applying the
   relocations, the executable's kind, size and the requester's
   permission read before the lock and again under it, the handler),
   `spawn/vdso.rs` (sys-io's copy of rt.vdso's installer: read-only
   segments shared from sys-io's own mapping, the writable one copied
   from the pristine bytes), the capability gate and
   `refuse_if_executing` in every mutation handler (a construction is the
   only reference until step 8), the three api_fs dispatch hunks deferred
   from step 3, the metrics `exec.locked_files`, `spawn.requests`,
   `spawn.build_us` and `spawn.vdso_us`, and `systest cold-spawn` with
   four tests (section 4). rt.vdso keeps its own loader until step 5, so
   only the tests send the request yet, and no sys-io-built child runs
   before step 5's gate. Gate on HEAD plus the index, 2026-10-12: three
   release runs (10.7, 9.9 and 9.8 min), three debug runs (18.6, 18.5
   and 18.7 min) and the developer-image release run (41.4 min), all
   passing. One test-shape fix preceded it: a requester that closes its
   connection right after reading the response loses a never-woken
   child by design (sys-io abandons it), so the tests' helper keeps one
   connection open for the whole suite, as rt.vdso does for its process.
   Committed as 33646420.
5. **rt.vdso switch:** delete the local loader (`load.rs`, the elfloader
   path in `rt_process.rs`), send `CMD_SPAWN`, keep the kill-unstarted
   guard; the whole existing suite is the test. Carved 2026-10-12 and
   staged: `run_elf` takes the entry id from the open executable's
   attributes (sys-io authorizes it again, as the requester) and sends
   the request through `AsyncFsClient::spawn_child`; the returned
   process handle names the child's address space for the process data,
   arguments, environment and stdio setup; `KillUnstarted` kills the
   child on any failure before its first wake succeeds; `load.rs` and
   the elfloader dependency are gone from rt.vdso (`src/sys/Cargo.lock`
   follows). The malformed-image test now also expects
   `E_INVALID_ARGUMENT` through std's spawn and kills a child it should
   never get. The stripped release vDSO shrinks from 828,904 to 800,232
   bytes (28 KB). Gate on e1b39bab plus the index, 2026-10-12: three
   release runs (10.7, 9.9 and 9.9 min) and three debug runs (15.4,
   15.5 and 15.5 min), all passing; no developer-image run, at the
   user's direction. A first attempt on 33646420 passed its three
   release runs and failed debug run 1 in
   `tcp::test_disconnect_before_rx_ready_releases_channels`: sockets of
   clients that had already disconnected keep their sys-io channel
   slot while they sit in TIME_WAIT, and one such slot expired inside
   the test's exact-equality wait on `net.channels`, which then ended
   one below its baseline. Pre-existing and unrelated to the spawn
   work; the test now accepts a count at or below its baseline
   (e1b39bab, committed on its own).
6. **Kernel, file-paged segments:** the `FILE_PAGED` segment kind,
   reserve, fill, zero fill, protection checks and `E_NOT_READY` in the
   fault path, and the admission commitment with its metric. No behavior
   change yet; gated by the existing suite.
7. **Kernel, pager:** `uspace/pager.rs` (parking and resumption,
   coalescing, zero fills outside the registry lock, retirement at exit,
   drop, and unmap), the `OP_PAGER` syscall family and moto-sys wrappers,
   `E_PAGE_ABSENT` from user copies with the retry in `do_syscall`, the
   handle-array copy ahead of the wake in the wait syscall, and the miss
   metric. Lands with step 8, which carries its tests.
8. **sys-io demand paging of read-only segments:** the pager task, drain
   before refusing, mapping references, the adaptive window, bounded
   serves, the failed-fill metric. Tests: lock refusals while mapped,
   unlock after the last exit, an eagerly built child holding no
   reference, killed child, kill during startup faults, exit from another
   thread while one is parked, concurrent launches with ordinary I/O
   beside them, a syscall buffer in an untouched page (the miss metric
   must grow), image contents, spawn under the memory floor.
9. **Lazy relocation** (larger patch): the validating pass and per-page
   index, clipped application, the zero tail, and the fallbacks. Tests:
   digests over relocated tables with page-crossing pointers and zeroed
   BSS; a copy of the test binary with two relocation records swapped
   (falls back to eager data, same digest); a record retargeted into
   unused read-only data (falls back to an eager image, same digest).
10. **mlibc** in **`../toolchain-src/mlibc`, outside this repository:**
    remove the startup relocation walk on Motor OS, where the loader has
    always applied `R_X86_64_RELATIVE`, and relink the developer-image
    tools. Expected gain on the prototype host: 563 ms to 463 ms. Say so
    explicitly in the patch; nothing in-tree emulates it any more.
11. **Measure** (section 4) and decide on RELR and on sharing with the
    new numbers.

## 4. Validation

`systest cold-spawn` is part of the default systest suite, so of
`src/tests/full-test.sh`. Its tests, in
`src/sys/tests/systest/src/cold_spawn.rs`, as of step 5: the direct
request (the handle is the requester's, the child is the requester's and
carries the requested name, a never-woken child dies on kill, a
capability the requester lacks is refused), entries the requester may
not run (a directory, a file without execute permission), seven
malformed images refused as requests and through std's spawn, and a
requester that closes its channel before the response (the response
ring is filled first, so the handoff fails and not the request; sys-io
abandons the child and no active child of the requester remains). With
steps 8 and 9: image contents checked against recomputed values
(relocated pointers, pointers
crossing page boundaries, read-only tables, zeroed data, function
pointers), eight concurrent launches with a file copied and verified
beside them, the executable lock (every refused mutation, unlock after
the last exit, an eagerly built child holding no reference), a killed
child unlocking, twenty kills during startup faults, twenty exits while
another thread is faulting, a syscall buffer in a page nothing touched
(the kernel's miss metric must grow), relocation fallbacks (a table with
two records swapped, a record retargeted into read-only data), and a
spawn under the memory floor refused with `E_OUT_OF_MEMORY` and leaving
no lock behind.
The parser's own unit tests join systest later, natively (user decision,
2026-10-12), in place of the host-side test step 3 was gated with.
systest's `checked_copy_in`
covers a raw syscall given an untouched read-only static. `raw_spawn.rs`
(step 2) covers the kernel alone, through the raw `address_space:` and
`process:` URLs: `requester=` refused to a caller other than sys-io, a
never-woken child's kill completing its exit (the wait returns, the
process is gone once its handle closes), a kill racing the first wake
over 64 rounds with the main thread's handle outliving the process, a
thread woken twice before it runs over 64 rounds, and a kill by pid
racing the creation over 200 rounds (a killer thread finds each round's
child in the process list by parent pid and a per-round name, so that
other spawns cannot be mistaken for it, and retries the kill the kernel
refuses while the child's `Arc` is not yet upgradable; on an instrumented
debug kernel about 15 rounds of 200 land the kill before the main thread
exists), in the default suite;
and an unstarted detached child dying with its parent
in `systest raw-spawn-detached`, which `full-test.sh` runs under the
detach-capable mask because the suite's own caller lacks
`CAP_SPAWN_DETACHED`. The abandonment's positive path is the abandoned
request in `cold_spawn.rs`. Not covered here: the
started-but-not-yet-running detached child surviving its parent's exit
(the window is a queued scheduler job; the suite's detached tests cover
the started case).

Not covered, by decision: injected I/O errors and allocation failures in
fills (no hook; add one only if cheap), and unmapping an executable's own
segment from inside the process.

Follow [AGENTS.md](../../AGENTS.md): standard Rust and native APIs,
repository formatting, no new warnings, and at least three debug plus
three release full-test build/runs before committing each core patch; the
developer-image gate `src/tests/full-test-dev.sh --release` for the
series. The reshaped tree's gate results are in the prototype report's
section 4. No commits unless asked.

Measurement follows the archive's method and the prototype report's
section 2: 50 alternating baseline/candidate pairs of the normal rustc
wrapper, one invocation per fresh VM, plus 10 pairs each for Clang and
Rush; exact stdout, empty stderr, success; same relinked targets on both
builds; record hashes, host-cache conditions, memory, CPU, and boot
behavior. The landed series must reproduce the prototype's ratios on the
same host within noise, or the difference must be explained.
