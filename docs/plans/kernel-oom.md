# Kernel OOM: simple low-memory admission control

2026-08-05, revised 2026-08-06; simplified the same day after a second review:
global-only sys-io pressure trigger, explicit refusal semantics, floors derived
from total RAM. **Status: revised design awaiting review. No implementation
code has been changed.** Measurements below used temporary instrumentation
that was reverted.

## Summary

One unprivileged process can currently exhaust the physical small-page pool
with a single `SysMem::alloc` call and panic the kernel. A networking workload
can reach the same failure through sys-io.

This plan uses guard bands instead of exact ownership accounting:

1. ordinary processes stop receiving memory while a large system reserve is
   still free;
2. sys-io may continue allocating inside part of that reserve, but stops before
   reaching a lower kernel-only reserve; and
3. sys-io watches global availability and refuses new clients, sockets, and
   other growth while availability is low, so that reaching the lower floor
   stays exceptional.

Admission is atomic and includes a deliberately conservative allowance for
allocator metadata. The design has no `KernelRecovery` class, no exact
per-process metadata attribution, and no attempt to recover after the physical
pool is already empty.

## Failure

An ordinary unprivileged process can kill the machine with one eager
`SysMem::alloc` call:

```text
1: INFO   kernel::mm::phys:52 - phys low-water: 1 small pages
1: ERROR  kernel::mm::phys:499 - OOM: failed to allocate 4K frame.
Total pages: 258940; used pages: 258939 available bytes: 7168.
KERNEL PANIC (cpu: 1): panicked at kernel/src/mm/phys.rs:69:9:
OOM
```

The existing soft-OOM check accounts for requested data pages, but allocation
also consumes page descriptors, page tables, segment nodes, and occasionally a
new global `Frame` slab. The check is also separate from allocation, so
concurrent requests can all pass it.

Measured release-build overhead for eager mappings was:

| requested data pages | pool lost | overhead |
|---:|---:|---:|
| 2,048 | 2,089 | 2.00% |
| 16,384 | 16,797 | 2.52% |
| 65,536 | 67,032 | 2.28% |
| 131,072 | 133,836 | 2.11% |

The worst measured overhead agrees with the current data structures: `Page`
slabs cost about 1.82%, `Frame` slabs about 0.51%, and page tables about 0.20%.
These measurements motivate a conservative admission charge; they are not used
as an exact accounting policy.

## Goals

- An ordinary process cannot exhaust physical small pages.
- sys-io cannot exhaust the kernel's final physical reserve.
- Under pressure, allocation requests fail before the physical allocator is
  empty.
- sys-io remains alive and existing clients and sockets continue to make
  progress within their already admitted memory.
- New sys-io clients, listeners, connections, and sockets are refused while
  pressure remains high.
- Admission is deterministic under concurrency.
- Boot behavior and boot latency do not change.

This is a stability mechanism, not a fairness policy. It does not choose an OOM
victim, promise that every lazy page will eventually receive physical backing,
or attribute shared kernel-heap objects to individual processes.

## Memory zones

There are two non-configurable low-water marks:

```text
available above USER_FLOOR:
    ordinary processes and sys-io may start memory-growing operations

SYS_IO_FLOOR < available <= USER_FLOOR:
    only sys-io may start memory-growing operations

available <= SYS_IO_FLOOR:
    no userspace process, including sys-io, may start one
    the remaining pages are for bounded kernel work already in flight
```

`USER_FLOOR` must be comfortably higher than `SYS_IO_FLOOR`. The difference is
sys-io's operating band. `SYS_IO_FLOOR` is the final kernel reserve.

The floors are computed at boot from total physical memory and clamped to
compile-time minimum and maximum values. Fixed absolute constants would be
about 2% of the 1 GiB test VM but a large fraction of a small one. The clamp
values are selected after measuring the maximum overlapping work on all
configured CPUs. On the 1 GiB test configuration a reasonable starting point
for measurement is 16 MiB for `USER_FLOOR` and 4 MiB for `SYS_IO_FLOOR`; these
are not committed constants in this planning revision. If measurements do not
fit comfortably, increase the floors rather than add a new allocation class.

The floors are kernel safety constants, not configuration. The boot-time
derivation is fixed policy; an operator must not be able to configure the
machine back into physical exhaustion.

## Atomic admission

A sampled check such as this is insufficient:

```text
if available_pages > floor { start_operation() }
```

A large operation can cross the floor after passing the check, and concurrent
operations can all pass together. Instead, the kernel maintains an atomic count
of outstanding admission reservations.

Before a memory-growing operation starts:

```text
charge = conservative_worst_case(operation)
available_for_admission = available_small_pages - outstanding_reservations

admit iff available_for_admission - charge >= applicable_floor
```

The reservation is added with compare/exchange or under one short admission
lock. It is held until the operation completes, then released. Actual allocated
pages remain reflected in `available_small_pages`, so releasing the reservation
does not make consumed memory appear free. Holding the full reservation during
the operation intentionally double-counts pages already allocated by that
operation; this can refuse another request early but cannot admit too much.

All userspace memory-growing operations participate in the same reservation
counter. This includes eager mappings, lazy faults, fixed mappings, shared and
contiguous mappings, stacks, address-space and process creation, thread
creation, and kernel-heap allocations directly induced by a syscall. The
io-manager-only paths (mid-page, contiguous, and MMIO mappings) bypass the
current `oom_for_user` check entirely; under this design they pass admission
like everything else. Mid-page data comes from a separate designated pool, but
its page descriptors and page tables come from the small-page pool, and the
charge counts that small-pool consumption.

A remote operation uses the target address space's class. In particular, sys-io
loading or modifying an ordinary address space does not give that address space
access to sys-io's operating band.

### Conservative charges

Charges are simple upper bounds, not exact bills. For a mapping operation let:

- `D` be the number of new physical data pages; and
- `P` be the number of new page descriptors across all affected address spaces.

The initial mapping charge is:

```text
D + ceil((D + P) / 32) + 64 pages
```

The percentage allowance is deliberately larger than measured aggregate
metadata growth. The fixed 64-page allowance covers unfavorable slab and page-
table boundaries. Lazy and unmapped reservations use `D = 0`; each later lazy
fault receives its own reservation. Shared mappings count descriptors at both
ends in `P`.

Process, thread, sys-object, and IPC creation use fixed conservative charges.
The current 1 MiB process, 256 KiB thread, and 64 KiB object checks are starting
points, but become atomic reservations and are increased if fault-injection or
boundary tests exceed them.

Compile-time structure-size assertions and focused boundary tests protect the
charge assumptions. If a structure grows enough to invalidate an allowance,
the build or test must fail; the implementation must not silently reduce the
guard band.

### What refusal means

Refusal semantics differ by operation type:

- Syscalls (eager mappings, process, thread, sys-object, and IPC creation)
  return `E_OUT_OF_MEMORY` to the caller. Refusal happens before the operation
  starts and has no side effects.
- A refused lazy fault cannot return an error to the faulting instruction. As
  today, the faulting thread is killed. Under sustained pressure a process
  touching a new stack or heap page dies while the kernel and sys-io stay
  alive.

The second point is the accepted cost of having no OOM killer: the design does
not select a victim, so the victim is whichever process faults while
availability is below its floor. This is stated here so it is not mistaken for
a bug during review or testing.

### Allocations not tied to a userspace operation

Boot allocations do not use admission control. Runtime kernel activity that is
not caused by a newly admitted userspace operation consumes the final reserve.
It must be bounded after new userspace work has stopped.

The reserve measurement includes interrupt handling, scheduler activity, TLB
shootdowns, logging and error responses, completion of operations already in
flight, and work on every configured CPU. Generic kernel-heap growth is not
given a special class or permission to ignore these measurements.

If this bounded-work assumption cannot be demonstrated within
`SYS_IO_FLOOR`, stop for design review and raise the floor or remove the
unbounded allocation. Do not add a recovery class that can consume the pool to
zero.

## sys-io pressure control

The kernel floors prevent physical exhaustion, but they cannot keep sys-io
alive on their own. Allocation failure inside sys-io is fatal: its heap grows
through `SysMem::alloc` in the vdso allocator, and a failed Rust
global-allocator call ends in `handle_alloc_error` and process abort. The
kernel floors therefore convert the original kernel panic into a sys-io abort,
not into graceful degradation. Pressure mode exists to stop sys-io's demand
before the kernel refuses it, and the band between `USER_FLOOR` and
`SYS_IO_FLOOR` must absorb sys-io's residual demand after refusals begin. That
is the property patch 3 measures when it sizes the floors.

Pressure mode is driven by global availability alone, with two watermarks for
hysteresis:

```text
enter pressure mode when:  global_available <= SYS_IO_GLOBAL_LOW
leave pressure mode when:  global_available >= SYS_IO_GLOBAL_HIGH
```

`SYS_IO_GLOBAL_LOW` sits well above `USER_FLOOR`, so sys-io begins refusing
new work before ordinary processes are refused and long before sys-io
approaches its own floor. The separation between the two watermarks prevents a
single allocation or free from repeatedly enabling and disabling service.

An earlier revision also tracked sys-io's own heap usage against a second
high/low watermark pair. That pair is dropped: it required instrumenting the
allocator backend, and its only benefit was catching sys-io-internal growth
before it becomes global pressure — which the global watermark also catches,
merely later. This is a stability series, not a fairness policy, and
later-but-caught is acceptable. The kernel's existing per-address-space usage
accounting supplies a usage gauge for metrics without new plumbing.

Admission is checked synchronously before creating each memory-growing
resource; a periodic monitor is not the safety boundary. While in pressure
mode, sys-io:

- refuses new service clients;
- refuses TCP listener binds and outbound TCP connections;
- refuses UDP socket creation;
- defers listener-pool replenishment;
- refuses other requests that would materially grow its heap or caches; and
- continues serving existing connections using their already allocated rings
  and control structures.

Refusals use the existing response object and channel. Entering pressure mode or
reporting `E_OUT_OF_MEMORY` must not allocate memory. When global availability
reaches the high watermark, new work is enabled and deficient listener pools
are re-armed.

Bounded growth matters beyond socket rings: client bookkeeping, network
containers, async tasks, filesystem caches, device buffers, and other sys-io
heap growth. Any structure that can keep growing while pressure mode is active
must be bounded, reclaimed, or added to the refusal set.

The global watermarks are service policy and may be configured within
kernel-enforced safe limits. Defaults derive from total RAM and the measured
steady-state sys-io footprint. Configuration cannot move `SYS_IO_GLOBAL_LOW`
below `USER_FLOOR`, cannot lower the kernel floors, and cannot permit sys-io to
cross `SYS_IO_FLOOR`.

## Failure handling

The purpose of conservative admission is to refuse work before deep physical
allocation fails. This series does not make every page-table and mapping step
newly fallible and therefore does not make all existing partial-rollback paths
ordinary OOM paths.

An admission refusal has no side effects because it happens before the
operation starts. Existing errors unrelated to physical exhaustion retain their
current behavior. Preexisting mapping rollback bugs discovered while reviewing
this issue require a separate reviewed plan; they are not hidden by retries,
timeouts, or ignored failures.

If an admitted operation exceeds its reservation or the physical allocator
still reaches OOM, that is an invariant failure. Tests must expose it and the
charge or unbounded path must be fixed. Production code must not retry the
operation or increase a timeout.

## Metrics

Expose system-wide counters and gauges for:

- ordinary-user admission refusals;
- sys-io admission refusals;
- outstanding reserved pages;
- the physical small-page low-water mark;
- sys-io pressure-mode entries and current state;
- sys-io memory usage (from the kernel's existing per-address-space
  accounting) and the global watermarks; and
- sys-io client and socket refusals.

Admission refusals are distinct from true physical allocator exhaustion. The
latter means a bound or charge is wrong and is always a defect.

## Implementation plan

### Patch 1 -- atomic kernel admission

- Add the two kernel floors and the outstanding-reservation counter.
- Replace the current sampled `oom_for_user` decisions with atomic admission
  guards. The admission sites already exist: the `oom_for_user` call sites in
  `sys_mem.rs`, `sys_cpu.rs`, and `sys_obj.rs`, and the reserve check in
  `fix_pagefault`. The guard is released on every exit path (RAII).
- Bring the io-manager-only mapping paths (mid-page, contiguous, MMIO) under
  admission at the sys-io floor.
- Add conservative charges for mappings, lazy faults, process/thread creation,
  sys-objects, and IPC.
- Classify only the sys-io address space as privileged for the lower floor.
- Use the target address-space class for remote memory operations.
- Add refusal and low-water metrics.
- Add the single-process and synchronized multi-CPU regressions, including the
  lazy-fault-at-the-floor case.

Patch 1 alone delivers the headline guarantee: the kernel cannot be panicked
by userspace allocation. After it lands, the six-listener reproducer no longer
panics the kernel; it drives sys-io toward its floor instead. Land and soak
patch 1 first, and size patch 2's refusal list from the observed refusal
metrics rather than building the full matrix up front.

### Patch 2 -- sys-io pressure mode

- Add the configurable global high/low watermarks with safe defaults.
- Check pressure synchronously at client and socket admission points.
- Refuse new clients and sockets without allocating an error path.
- Defer and later re-arm listener replenishment.
- Bound or include other request-driven sys-io growth.
- Add pressure-state and refusal metrics, with the usage gauge sourced from
  the kernel's existing per-address-space accounting.

### Patch 3 -- tune and validate the floors

- Measure maximum overlapping kernel work after admission closes.
- Include the transient reservation load of concurrent lazy faults on every
  configured CPU (per-fault charge times CPU count) as an explicit input to
  the floor sizing.
- Measure sys-io's residual allocation demand after pressure mode engages and
  confirm the band between the floors absorbs it.
- Exercise every configured CPU and unfavorable allocator boundaries.
- Tune both floors upward if the measured margin is not comfortable.
- Document the final constants and measurement results in this file.
- Check allocation throughput and boot time before committing.

Each patch is kept near 100-300 lines where practical, formatted with
`cargo +nightly fmt`, and introduces no compiler or clippy warnings.

## Regression and acceptance tests

The kernel regression must:

1. record physical availability in a quiescent VM;
2. issue one eager user mapping that would cross `USER_FLOOR`;
3. require `E_OUT_OF_MEMORY`, not a kernel panic or killed process;
4. repeat the refusal and require no downward drift;
5. run synchronized requests on every configured CPU;
6. verify that admitted allocations never cross their floor;
7. verify a service heartbeat and a subsequent small allocation; and
8. drive availability to `USER_FLOOR` and touch a new lazy page: the faulting
   thread is killed, the kernel stays alive, sys-io keeps serving, and
   availability does not drift below the floor.

Allocator metadata may grow permanently on the first high-water run because
global `Frame` slabs are not freed. Tests warm those slabs before recording the
stable baseline, then require no subsequent drift.

Additional tests cover:

- eager, lazy-fault, shared, fixed, contiguous, process, thread, sys-object,
  and IPC admission charges at unfavorable boundaries;
- concurrent ordinary and sys-io admission near both floors;
- sys-io entering pressure mode when global availability crosses the low
  watermark;
- new clients, TCP listeners and connections, and UDP sockets being refused;
- existing TCP and UDP traffic and filesystem service continuing;
- closes or disconnects raising global availability above the high watermark
  and re-enabling admission;
- listener replenishment resuming after pressure clears;
- maximum-size and wildcard listener binds; and
- invariant failure if fault injection makes an operation exceed its charge.

The original oversized-allocation and six-process listener reproducers must
leave the machine serving, return deterministic errors to aggressors, and never
reach true physical allocator OOM.

All tests are included in `src/tests/full-test.sh` directly or transitively.
Before committing each patch, run three successful debug and three successful
release full-test cycles:

```text
src/tests/full-test.sh
src/tests/full-test.sh --release
```

Tests do not add retries, longer timeouts, ignored failures, or workload changes
that conceal a crossed threshold.

## Deliberately not proposed

- `KernelRecovery` or another class that may allocate the pool to zero.
- Exact per-process attribution of page tables, shared slabs, or kernel-heap
  objects.
- A per-address-space memory-limit policy in this safety series. The existing
  `max_memory` limit (atomic add-check-rollback, defaulted to unlimited)
  remains as an orthogonal policy knob; its accounting idiom is the pattern
  the global reservation counter reuses.
- sys-io self-usage watermarks and allocator-backend usage instrumentation
  (dropped in this revision; the global watermark subsumes them).
- An OOM killer.
- A configurable kernel physical reserve.
- Retrying refused allocations.
- Making every low-level mapping operation newly fallible as part of this fix.

The design intentionally spends a larger fixed memory margin in exchange for a
small implementation, deterministic refusal, and a safety argument that can be
validated with direct measurements.
