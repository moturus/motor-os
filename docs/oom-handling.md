# Physical memory pressure and OOM handling

The kernel decides from the actual number of free physical pages whether an
allocation proceeds, waits or fails, and below a floor it kills eligible
processes, newest first, until memory recovers. Reservation-based admission
and guaranteed executable commitments are gone. Per-process memory limits,
filesystem capacities, capabilities, socket/channel limits and ordinary
backpressure remain independent of this mechanism.

What a process observes:

- An allocating syscall or a page fault that arrives while OOM killing is
  active completes later instead of failing. The delay is the only visible
  effect; the retry happens inside the kernel.
- A victim is terminated like any killed process: its threads stop, its
  memory goes back at exit, and its parent sees the killed status.
- Below 4 MiB free, process spawns fail with `E_OUT_OF_MEMORY` and memfs
  mutations with `StorageFull`.
- A request that still cannot be satisfied although at least 3 MiB is free
  after its own rollback fails with `E_OUT_OF_MEMORY` rather than waiting.
  If nothing can be killed and free memory stays below 2 MiB, the kernel
  reports every process on the console and aborts the VM.

The mapping paths acquire frames, descriptors and page-table pages fallibly
and unwind partial mappings before deciding whether to wait or return an
error (see [kernel-mm.md](kernel-mm.md)). Existing error codes remain:
`E_OUT_OF_MEMORY` for an unsatisfied allocation, quota or address-space limit,
`E_INVALID_ARGUMENT` for a bad address, size or flag, `E_NOT_ALLOWED` for a
missing capability or an entry point outside user space, and
`E_ALREADY_IN_USE` for a second process on an address space. Kernel-heap
exhaustion remains fatal.

The code lives under `src/sys/kernel/src`: `mm/phys_blocks/policy.rs` holds
the accounting word with its floors, gates and transitions,
`mm/allocation.rs` the pressure receipts and retry decisions, `uspace/oom.rs`
and `uspace/oom/wait.rs` the scheduler jobs, victim selection and wait
queues, and `init.rs` the arming point. The module map in
[kernel-mm.md](kernel-mm.md) describes the surrounding memory manager.

## Allocation floors and waiting

All sizes are binary; a small page is 4 KiB. The recipient address space
determines the allocation class, including remote mappings, both stacks,
page tables and MM metadata. A process-less address space counts as None.
Request size and the caller's privilege do not change the recipient's class.

| Recipient | Minimum free after a charge | Allocation gate |
|-----------|-----------------------------|-----------------|
| None or Interactive | 512 pages (2 MiB) | Closed during Killing and Latched |
| System | 128 pages (512 KiB) | Closed once the run's System block is set |
| Kernel | 0 | Always open |

The physical pool keeps the used-page count, the phase (Idle, Killing or
Latched), the System block and a generation counter in one atomic word, so
every charge checks policy and changes the count in the same
compare-and-swap:

- A charge that takes free memory below 512 pages while Idle or Latched
  starts Killing and advances the generation. Only System and kernel
  charges can cross that line; a None or Interactive charge is refused at
  its floor instead.
- A floor refusal below 768 pages while Idle also starts Killing, without
  changing the count.
- A System floor refusal below 768 pages while Idle or Killing sets the
  System block for the run, starting the run first if Idle. A kernel charge
  that leaves fewer than 128 pages does the same from any phase. Rising
  above 128 alone does not clear the block.
- A release that reaches 768 pages (3 MiB) while Killing or Latched returns
  the pool to Idle, clears the System block and advances the generation.

Every generation change invalidates the waits and jobs of the previous one,
even when recovery and renewed pressure both happen before any scheduler
looks at the word.

A valid allocating syscall waits when its recipient's gate is closed.
After a physical shortage, it first rolls back and releases its temporary
resources. Below 768 free pages it joins reclamation and retries when both
its wait generation and recipient gate permit. If rollback restored at least
768 pages, it returns `E_OUT_OF_MEMORY`; a large request does not get a
special exemption from the floors. An unsatisfied contiguous request returns
`E_OUT_OF_MEMORY`; an opportunistic huge-page miss falls back to small pages
and keeps the reason of its first refusal. Permanent validation, quota and
virtual address-space errors return their existing codes even under pressure.
Retries re-resolve handles and mappings, so a target closed during a wait
retains its normal error behavior. In an unchanged Latched state, a System
request refused at its floor waits for the next generation change rather
than rescanning the same process set; smaller System requests that fit
proceed. Process creation and start use the separate 4 MiB refusal described
below.

Valid lazy and pager zero-fill faults park on physical pressure and retry
after recovery; invalid faults retain fatal handling. Pager fills keep
completed pages and retry only their unfinished suffix after validating the
mapping identity. Wait registration and draining share one lock, preventing
lost recovery notifications and duplicate resumes. Syscall OOM waits preserve
ordinary wakes intended for the thread's next userspace wait. Killing a
waiter uses normal thread cleanup; no owned resources depend on unwinding its
discarded syscall stack.

## Victims and recovery

While the pool is Killing, scheduler jobs select one victim at a time: the
newest eligible None process by monotonic kernel PID, then the newest
eligible Interactive process once no eligible None remains. Processes
created but not yet started are eligible. System processes, sys-io and its
direct children and grandchildren are protected; actual ancestry supplies
that protection, and it grants no allocation privilege to protected None or
Interactive processes. Paused debuggees are skipped. Processes already
exiting, or left without threads, count as pending reclamation rather than
as candidates.

Selection validates Killing and the generation immediately before committing
a kill. Recovery before that validation cancels the selection; a kill already
committed finishes after recovery. The victim is terminated through the
normal kill path and its memory returns at exit, as described below. Only
one committed victim awaits exit cleanup at a time; the next selection waits
for that cleanup, even across recovery and a new run. Each kill is logged
with the generation, the free count and the victim's name and both PIDs.

When no candidate remains, the job waits for pending exits to finish, then
rechecks the state. At 768 free pages (3 MiB), a release returns the pool to
Idle, clears the System block and advances the generation; scheduler
dispatch then wakes the waiters whose gates allow it. At 512–767 pages the
run ends in Latched: System reopens, None and Interactive stay blocked, and
a later charge below 512 starts a new run. Below 512 pages, with no victim
and no pending reclamation, the kernel prints every remaining process and
aborts the VM, after a final check that the same run is still active below
512 pages.

Floors and runtime OOM transitions are armed immediately before sys-io
starts, after scheduler publication and all wait consumers are installed.
Before that, every class has floor 0 and an allocation that cannot be
satisfied fails with `E_OUT_OF_MEMORY`; the boot exhaustion tests run in
that state. Arming adds no process scan or pool drain; it samples the
initial count in its own compare-and-swap and starts Killing at once if free
memory is already below 512 pages.

## Process identities

Each process has a monotonic `u64` kernel PID and a public user PID.
Kernel PIDs never wrap or repeat; exhausting that counter panics the kernel.
Public PIDs keep their existing positive-i32 range, wrap to 4,096, and skip
IDs still in use. Both IDs are equal before the first public-PID wrap.

The statistics tree keeps kernel-PID and user-PID indexes under the same
children lock, along with the system node's PID counters. Internal child
traversal uses kernel-PID order. Public lookup, process-list pagination, metric
scopes, and per-CPU process statistics continue to use user PIDs and their order.
The shared-page and syscall process-identity formats are unchanged.

## Memory release at exit

The kernel returns a process's memory when it exits rather than when the last
handle to it is dropped. The kernel completes an exit only after every
thread's stacks are unmapped, then retires the executable pager's mappings,
closes the process's IPC endpoints and releases its address space before
waiters see the exit: private frames, page descriptors, the process static
page and cached kernel stacks go back, shared frames stay alive through their
other mappings, and the process's user and kernel memory statistics read
zero. The emptied regions are closed, so a retained process or address-space
handle cannot map or share pages into the dead space, and the pager cannot
fill it; only the page-table root and its kernel entries stay until the last
handle goes. An address space hosts one process: a second process on the
same space is refused with `E_ALREADY_IN_USE`, as the first one's exit frees
what the second would run on. The mechanics are in
[kernel-mm.md](kernel-mm.md).

## Published free memory

`KernelStaticPage::free_pages` is the physical allocator's live count of free
4 KiB pages. The kernel stores one snapshot when the kernel address space is
created, on the BSP before other CPUs allocate, and from then on the block
allocator's `charge` and `release` apply the delta of every small, huge, and
contiguous allocation and free with a relaxed atomic add or subtract. Nothing
samples, no lock is involved, and no stale copy can overwrite a newer one: the
value is exact up to the operations still in flight on other CPUs. Userspace
reads it with one relaxed load through `moto_sys::free_pages()`. Kernel policy
checks use the allocator's authoritative packed word, not this mirror.

There is no published pressure flag. `moto_sys::LOW_MEMORY_PAGES` (1,024
pages, 4 MiB) is the one limit services compare the count against, through
`moto_sys::low_memory()`; the 2 MiB and 3 MiB OOM thresholds belong to the
kernel's atomic OOM state, where recovery and renewed pressure advance the
generation even if no scheduler observed the intervening recovery.
The word at offset 60 that held the flag is reserved, so the boot identity at
offset 64 and `free_pages` at offset 72 keep their offsets.

The `AdmissionStats` query and admission metrics have been removed. Physical
memory statistics, the physical low-water mark, block allocator metrics, and
per-process user/kernel memory statistics remain available.

## Diagnostics and remaining limitations

The kernel logs every transition the scheduler notices and every committed
kill:

```text
OOM: start generation 7, 509 free pages
OOM: generation 7, 503 free pages, kill 'name' pid=1234 kernel_pid=1234
OOM: end generation 7, 801 free pages
OOM: no victims, stopping below 768 pages (600 free)
```

Start and end lines are written when the scheduler observes the new
generation, so a run that starts and ends between two scheduler visits leaves
only its `mem.oom_runs` increment. Before a victimless abort the kernel
prints `OOM: remaining processes, N free physical pages`, one
`OOM: 'name' pid=.. kernel_pid=.. user_bytes=.. kernel_bytes=..` line per
process, and panics with `OOM: no eligible victims or pending reclamation
below 512 free pages`. The per-process byte counts describe tracked virtual
memory, including lazy reservations; they are not resident physical usage,
and shared memory can appear in several processes.

| Metric | Meaning |
|--------|---------|
| `mem.oom_runs` | Started Killing generations, including runs completed before dispatch |
| `mem.oom_kills` | Committed OOM kill requests |
| `mem.oom_parked_syscalls` | Syscall wait registrations |
| `mem.oom_parked_faults` | Fault wait registrations |

System totals use stats scope 0. The two wait counters also have process
attribution; they count registrations, including re-parks, not current queue
lengths or unique threads. `mem.oom_kills` is system-wide only.

Three issues are deferred, with their current behavior described in
[plans/oom-handling.md](plans/oom-handling.md): sys-io parks when it
allocates for a non-System recipient, and a refused pager fill still kills
the faulting thread of a protected process; a debugger pause racing a
committed kill can stall that victim's reclamation and, with it, further
selection; and the abort rule can terminate a guest whose protected processes
legitimately hold the memory while nothing is blocked.

## Services and spawning

Below 4 MiB free, sys-io rejects spawn requests with `E_OUT_OF_MEMORY`,
including those from System processes. The kernel refuses runtime child
creation and the first `Created` to `Running` transition at the same limit,
against its own allocator count, so a delayed wake or queued start cannot
bypass the check. Bootstrap construction stays separate.

Other memory-based refusals have been removed from sys-io networking and
filesystem services, client runtime spawning, russhd, and strobe. Socket errors
and actual allocation failures retain their normal handling. Below the same
4 MiB, every process's allocator returns idle pages eagerly and sys-io releases
unused memfs cache blocks.

## Memfs

For every guest size, memfs write, copy, create, and move requests check the
free-page count. Below 1,024 pages (4 MiB), sys-io releases unused cached
memfs blocks and checks again; if still below 4 MiB it returns `StorageFull`.
At exactly 4 MiB allocating mutations are allowed. This is a check, not a
reservation: it does not promise a lower bound after the request completes.

Reads, stat, list, resize, and delete are served independently of this check.
Memfs resize changes sparse logical length without allocating data blocks.
Deleting or shrinking below the limit releases unused cached blocks. Capability
checks and donated-page cleanup still apply on rejected requests. Mount capacity
and cache sizing are unchanged; `fs.memory_refused` counts memfs refusals after
cache reclamation.

## Validation

Every test runs inside Motor OS and is reached from `src/tests/full-test.sh`.
Debug kernel boots run self-tests on private scratch pools and the production
bookkeeping: `phys_blocks policy tests` cover the floors, gates and every
transition at the 127/128, 511/512 and 767/768 boundaries, plus arming;
`OOM waiter tests` and `OOM dispatch tests` cover registration and draining,
generations, victim cleanup and exit interest; `pager retry tests` cover
completed prefixes and mapping identity; `allocation role tests` cover
recipient-role propagation and claim rollback; the unarmed `exhaustion
tests` cover allocation failure and rollback at every boundary, contiguous
failure and huge-page fallback. `process PID tests` exercise isolated
counter/index state across public-PID wrap and reuse, kernel-ID exhaustion
and both traversal orders. A further self-test releases a populated address
space and checks that every later reservation is refused while a peer's
shared frame survives.

systest covers the exact syscall error codes, mapping and accounting,
concurrent frame churn and public listing pagination. It spawns a child that
maps 8 MiB and exits normally or is killed, and verifies with the handle
still held that its user pages read zero, the pool recovered, a shared page
survived and the dead space takes no new mapping; it also checks that an
address space refuses a second process before and after the first one's
exit. Memfs tests cover mutation classification, the 4 MiB boundary and cache
reclamation; filesystem, network, logging and spawn regressions run with the
old admission gates gone. Quiescent kernel checks compare the shared count
with the allocator's after small, huge and contiguous allocations and frees.

Pressure itself is exercised from the System console of
`test-system-tty.sh` by `systest system-oom-tests`, whose helper holds
`CAP_SYS` from that parent: process creation and delayed-start refusal, large
eager rollback, newest None selection before Interactive, repeated recovery,
syscall waits with spurious wakes and the userspace wake retained,
target-handle closure, permanent size refusal under pressure, lazy-fault
survival and cancellation, System syscall and fault waits, and cleanup of a
killed waiter. The System cases kill four small victims and one larger one
and require all five kills in a single run, which proves the small cleanups
did not reach recovery first. A pressure window that was missed may be
retried at most three times, each miss reported with evidence of a
successful operation and recovery before entry; an observed wait followed by
a wrong result, a leak, a hang or a lost wake is a failure, never a retry.
Pressure tests stay outside `--under-load`.

`full-test.sh` finishes with `test-oom-abort.sh` in a separate guest. Its
System helper inventories roles and ancestry, requires no earlier OOM runs
or kills (hence no pending OOM victim), and drains below 512 pages. Success
requires the helper's setup marker, a below-threshold memory report including
the helper's two PIDs and memory counts, the exact victimless kernel panic,
and guest termination. An arbitrary crash or timeout fails the test.

Changes to this mechanism are gated like other core work: `full-test.sh`
three times in debug and three in release, including at least one real
one-vCPU run per build (`--cpus 1`; the `systest --host-cpus=1` hint only
sizes workloads), then `full-test-dev.sh --release`. The one-vCPU debug gate
currently runs at its 50-minute budget because of a systest poll test
unrelated to memory; see [plans/future-work.md](plans/future-work.md).

### Reproducing the victimless abort

The automated disposable-guest check is:

```sh
src/tests/test-oom-abort.sh --release
```

Standalone, it defaults to 256 MiB and four vCPUs; `MOTO_MEMORY_MIB`,
`MOTO_SMP` and `--vmm qemu|chv|fc` select other guest shapes/runners. Under
`full-test.sh` it inherits the suite's exported guest size: 1 GiB in the
default main gates and 8 GiB under `full-test-dev.sh`. Omit `--release` for
debug. The test deliberately terminates its guest.

For a manual run, build and boot a fresh System-console image. Test images
need an absolute `TEST_IMAGE_ROOT` outside the repository's `vm_images`; the
image and its runners are written under that root:

```sh
root="$(mktemp -d)"
make -j"$(nproc)" system-tty.img systest BUILD=release TEST_IMAGE_ROOT="$root"
MOTO_IMAGE=motor-os-system-tty.img MOTO_MEMORY_MIB=256 "$root/vm_images/release/run-qemu.sh"
```

From another host terminal, copy `build/bin/release/systest` to
`/none/tmp/oom-abort` using the repository's test SSH key:

```sh
chmod 600 src/tests/test.key
scp -F /dev/null -P 2222 -i src/tests/test.key -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
  build/bin/release/systest motor@192.168.4.2:/none/tmp/oom-abort
```

Then run in that guest's System serial console:

```sh
chmod r-xr-xr-x /none/tmp/oom-abort
/none/tmp/oom-abort system-oom-abort
```

Expect the protected-process inventory and `oom-abort: READY`, followed by
`OOM: remaining processes`, per-process memory lines, and a kernel panic
stating that no eligible victims or pending reclamation remain below 512
free pages. The VM then exits. Do this only in the fresh disposable guest;
the helper intentionally retains its pressure allocations until termination.
