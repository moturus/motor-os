# Physical memory pressure and OOM handling

The kernel decides from the live count of free physical pages whether an
allocation proceeds, waits or fails. When free memory gets low, it kills
unprotected processes, newest first, until enough memory comes back. There
is no reservation or admission control. Per-process memory limits,
filesystem capacities, capabilities and socket or channel limits are
separate and unchanged.

All sizes below are binary; a page is 4 KiB.

## Protected services

A process is protected if any of these holds:

- it has the System role;
- it is sys-io;
- its parent or grandparent is sys-io.

Everything else is unprotected. Protection is not inherited further: a
great-grandchild of sys-io is unprotected unless it has the System role.
Parentage is the actual one, also for a spawn that sys-io performs on
another process's behalf. In the shipped image the protected set is sys-io,
sys-init and strobe (System), sys-tty and russhd (Interactive) and
dns-resolver (None). Every program a user starts is a great-grandchild of
sys-io and can be killed.

Protected processes are never chosen as OOM victims and allocate under the
smaller System floor below. Protection changes neither roles nor
capabilities.

The kernel does not defend the guest against a protected service that
misbehaves. If protected services alone use up memory, nothing can be
killed: the guest stays latched or aborts, as described below. An optional
change to that abort policy is recorded in
[future-work.md](plans/future-work.md#optional-change-to-the-victimless-oom-abort-policy).

## Floors

Every physical allocation is charged to the address space that receives the
memory, including mappings made by another process, both stacks, page
tables and memory-manager metadata. The recipient decides the class:

| Recipient                          | Class  | Must leave free     | Blocked                      |
|------------------------------------|--------|---------------------|------------------------------|
| Unprotected process, or an address | User   | 512 pages (2 MiB)   | While killing or latched     |
| space with no process yet          |        |                     |                              |
| Protected process                  | System | 128 pages (512 KiB) | When the System block is set |
| Kernel                             | Kernel | Nothing             | Never                        |

The class is fixed when a process claims its address space. An address
space without a process is User, so sys-io sets up every new executable
image under the User floor, protected or not. Once the process exists its
own class applies, also to the executable pages sys-io fills later.

Two more limits matter:

- 768 pages (3 MiB): killing ends and every blocked allocation retries when
  free memory comes back to this level.
- 1,024 pages (4 MiB), `moto_sys::LOW_MEMORY_PAGES`: below it, process
  creation and start fail with `E_OUT_OF_MEMORY`, memfs refuses allocating
  mutations with `StorageFull` after dropping unused cache blocks (see
  [fs-permissions.md](fs-permissions.md)), and every process's allocator
  returns idle pages eagerly.

## How OOM killing works

The allocator keeps the used-page count, the state (Idle, Killing or
Latched), the System block and a generation counter in one atomic word, so
each charge checks the rules and updates the count in one compare-and-swap.
The counter advances whenever killing starts or ends, so a waiter can tell
whether the killing it waited for is over.

1. **Start.** Killing starts when a charge takes free memory below 512
   pages, or, from Idle, when a request is refused at its floor with fewer
   than 768 pages free. A User charge never crosses 512: it is refused at
   its floor, which starts killing. While killing, a System request refused
   at its floor, or a kernel charge that leaves fewer than 128 pages, sets
   the System block: protected allocations wait too until killing ends.
2. **Choose a victim.** A scheduler job picks the newest unprotected None
   process by kernel PID; when none is left, the newest unprotected
   Interactive process. Processes created but not yet started count.
   Processes paused by a debugger are skipped. Processes already exiting,
   or left without threads, count as memory about to come back.
3. **Kill it.** The victim is killed through the normal kill path and its
   memory returns when its exit completes ([kernel-mm.md](kernel-mm.md),
   "Release at process exit"). A kill whose victim has a debugger-paused
   thread still completes. One victim at a time: the next choice waits for
   the previous victim's exit, even across recovery.
4. **Stop.** A release that reaches 768 pages ends killing: the state
   returns to Idle, the System block clears and every blocked allocation
   retries. If nothing is left to kill with 512 to 767 pages free, killing
   ends in Latched: System allocations that fit proceed, User allocations
   fail, and a later charge below 512 starts killing again. If nothing is
   left to kill below 512 pages, the kernel prints every remaining process
   and aborts the guest.

Floors and killing are armed just before sys-io starts. Before that every
floor is zero and an allocation that cannot be satisfied fails with
`E_OUT_OF_MEMORY`; the boot self-tests run in that state.

Victims are ordered by kernel PID, a monotonic `u64` that never repeats.
The public `i32` PID that userspace sees wraps to 4,096 and skips IDs still
in use; the two are equal until the first wrap.

## What a process sees

- An allocating syscall blocked by killing waits until killing ends, then
  retries. If it still cannot allocate, it returns `E_OUT_OF_MEMORY`. A
  request that fails although at least 768 pages are free after its own
  rollback returns `E_OUT_OF_MEMORY` at once. Large requests get no
  exemption from the floors.
- A page fault on valid memory waits for memory and retries; it never
  returns an error. In Latched, faults in unprotected processes keep
  waiting until free memory recovers to 768 pages. Invalid faults stay
  fatal.
- An executable page that sys-io fills into a protected process retries
  physical shortages until they clear; it never becomes a fatal pager error.
  A fill into an unprotected process that still fails after killing ends is
  a fatal page fault for that process. When sys-io itself cannot allocate
  the buffer for a one-page fill, it yields and retries later instead of
  failing the page.
- A victim is terminated like any killed process; its parent sees the
  killed status.
- Below 4 MiB free, spawns fail with `E_OUT_OF_MEMORY` and memfs mutations
  with `StorageFull`.
- Error codes are unchanged: `E_OUT_OF_MEMORY` for an unsatisfied
  allocation, quota or address-space limit, `E_INVALID_ARGUMENT` for bad
  arguments, `E_NOT_ALLOWED` for a missing capability, `E_ALREADY_IN_USE`
  for a second process on one address space. Kernel-heap exhaustion stays
  fatal.

## Observing it

`KernelStaticPage::free_pages` (offset 72) is the allocator's live free-page
count, kept with one relaxed atomic add or subtract per allocation and free.
Userspace reads it with `moto_sys::free_pages()`; `moto_sys::low_memory()`
compares it with `LOW_MEMORY_PAGES`. The word at offset 60 is reserved.
There is no published pressure flag: the 2 MiB and 3 MiB thresholds live in
the kernel's atomic state.

The kernel logs each transition it observes and each kill:

```text
OOM: start generation 7, 509 free pages
OOM: generation 7, 503 free pages, kill 'name' pid=1234 kernel_pid=1234
OOM: end generation 7, 801 free pages
OOM: no victims, stopping below 768 pages (600 free)
```

Before an abort it prints `OOM: remaining processes, N free physical pages`,
one `OOM: 'name' pid=.. kernel_pid=.. user_bytes=.. kernel_bytes=..` line
per process (tracked virtual memory, not resident usage) and panics with
`OOM: no eligible victims or pending reclamation below 512 free pages`.

| Metric                    | Meaning                                     |
|---------------------------|---------------------------------------------|
| `mem.oom_runs`            | Times killing started                       |
| `mem.oom_kills`           | Committed kills                             |
| `mem.oom_parked_syscalls` | Syscall waits registered, re-parks included |
| `mem.oom_parked_faults`   | Fault waits registered, re-parks included   |

System totals use stats scope 0; the two wait counters also have per-process
values. `fs.memory_refused` counts memfs refusals.

## Code

Under `src/sys/kernel/src`: `mm/phys_blocks/policy.rs` holds the atomic word
with its floors and transitions, `mm/allocation.rs` the refusal receipts and
retry decisions, `uspace/oom.rs` and `uspace/oom/wait.rs` the scheduler
jobs, victim choice and wait queues, and `init.rs` the arming point. sys-io's
fill-buffer retry is in `src/sys/sys-io/src/runtime/fs/spawn/pager.rs`. The
memory manager itself is described in [kernel-mm.md](kernel-mm.md).

## Tests

Every test runs inside Motor OS from `src/tests/full-test.sh`. Debug kernels
run boot self-tests for the floors and transitions, the wait queues, victim
cleanup, pager retry, class propagation and unarmed exhaustion. systest
covers the error codes, release at exit, killing debugger-paused threads and
memfs refusals. Pressure itself is exercised from the System console of
`test-system-tty.sh` by `systest system-oom-tests`: spawn refusal, victim
order, repeated recovery, a paused victim, Latched refusals and System
progress, fault and syscall waits and their cancellation. `full-test.sh`
ends with `src/tests/test-oom-abort.sh`, which drains a separate disposable
guest below 512 pages and requires the exact report and panic above.

Changes here are gated like other core work: `full-test.sh` three times in
debug and three in release, including at least one `--cpus 1` run per
build, then `full-test-dev.sh --release`.

### Reproducing the abort by hand

Build and boot a fresh System-console image. Test images need an absolute
`TEST_IMAGE_ROOT` outside the repository's `vm_images`:

```sh
root="$(mktemp -d)"
make -j"$(nproc)" system-tty.img systest BUILD=release TEST_IMAGE_ROOT="$root"
MOTO_IMAGE=motor-os-system-tty.img MOTO_MEMORY_MIB=256 "$root/vm_images/release/run-qemu.sh"
```

From another terminal, copy `build/bin/release/systest` into the guest as
`/none/tmp/oom-abort` with the repository's test key:

```sh
chmod 600 src/tests/test.key
scp -F /dev/null -P 2222 -i src/tests/test.key -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=src/tests/test-known-hosts \
  build/bin/release/systest motor@192.168.4.2:/none/tmp/oom-abort
```

In the guest's System serial console run `chmod r-xr-xr-x /none/tmp/oom-abort`
and then `/none/tmp/oom-abort system-oom-abort`. Expect the protected-process
inventory, `oom-abort: READY`, the kernel's report and panic, and the VM
exiting. The helper keeps its memory until the guest dies, so use only a
disposable guest.
