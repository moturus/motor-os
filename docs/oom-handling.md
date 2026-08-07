# OOM handling: low-memory admission control

Why the mechanism exists, the argument for why it is safe, and what remains
open. The implementation lives in `kernel/src/mm/admission.rs` (floors,
charges, reservations, the pressure flag), `sys-io`'s
`runtime/net/pressure.rs` (service refusals), and rt.vdso's `spawn_impl`
(spawn refusals). Regressions are in `systest` (`admission.rs`,
`pressure.rs`).

## The problem

Allocating N data pages also consumes page descriptors, page tables, segment
nodes, and occasionally a new global `Frame` slab. Before admission control,
the kernel's soft-OOM check counted only the requested data pages and was
separate from allocation, so concurrent requests could all pass it; one
unprivileged eager `SysMem::alloc` could empty the physical small-page pool
and panic the kernel. Measured release-build metadata overhead for eager
mappings:

| requested data pages | pool lost | overhead |
|---:|---:|---:|
| 2,048 | 2,089 | 2.00% |
| 16,384 | 16,797 | 2.52% |
| 65,536 | 67,032 | 2.28% |
| 131,072 | 133,836 | 2.11% |

The worst case agrees with the data structures: `Page` slabs cost about
1.82%, `Frame` slabs about 0.51%, page tables about 0.20%. These numbers
motivate the conservative admission charge below; they are not used as exact
accounting.

This is a stability mechanism, not a fairness policy. It does not choose an
OOM victim, promise that every lazy page will eventually receive physical
backing, or attribute shared kernel-heap objects to individual processes.

## Memory zones

Two non-configurable low-water marks over free small pages:

```text
available above USER_FLOOR:
    ordinary processes and sys-io may start memory-growing operations

SYS_IO_FLOOR < available <= USER_FLOOR:
    only sys-io may start memory-growing operations

available <= SYS_IO_FLOOR:
    no userspace process, including sys-io, may start one
    the remaining pages are for bounded kernel work already in flight
```

The floors are compile-time constants: `USER_FLOOR_PAGES = 256` (1 MiB),
`SYS_IO_FLOOR_PAGES = 128` (512 KiB), validated by measurement (below). They
are kernel safety constants, not configuration: an operator must not be able
to configure the machine back into physical exhaustion. If future
measurements do not fit comfortably, raise the floors rather than add a new
allocation class.

## Atomic admission

Every userspace memory-growing operation is admitted first:

```text
charge = conservative_worst_case(operation)
free_for_admission = available_small_pages - outstanding_reservations

admit iff free_for_admission - charge >= applicable_floor
```

The reservation is CASed into a global counter and held (RAII) until the
operation completes. Allocated pages remain reflected in
`available_small_pages`, so releasing a reservation does not make consumed
memory appear free; holding the full charge for the whole operation
double-counts pages the operation already allocated, which can refuse another
request early but cannot admit too much.

Checking availability and publishing the reservation are two separate atomic
steps, and the counter alone cannot order them: other operations can admit,
allocate, and release inside the window, restoring the counter to its
compared value while the sampled availability is stale (an ABA race that host
vCPU deschedules stretch to milliseconds). The check is therefore repeated
after the reservation is published, reading the counter before availability;
if it no longer holds, the reservation is released and the request refused.
Near the floor this can refuse concurrent requests where serially one would
pass; refusing early is the accepted bias.

Participants: eager, fixed, shared, and contiguous mappings, lazy faults,
stacks, address-space/process/thread creation, sys-objects, IPC, and the
io-manager-only paths (mid-page, contiguous, MMIO — mid-page data lives in a
separate pool, but its descriptors and page tables are charged against the
small pool). A remote operation is charged against the *target* address
space's class, so sys-io loading an ordinary process never widens that
process's guard band. Small per-syscall bookkeeping (wait-object
registration, URL strings) is not individually admitted; it belongs to the
bounded runtime work the floors absorb, and the measurements include it.

### Conservative charges

For a mapping adding `D` physical data pages and `P` page descriptors
(counted at both ends for shared mappings):

```text
charge = D + ceil((D + P) / 32) + 64 pages
```

The divisor buys 128 bytes of metadata per touched page; compile-time
assertions in `phys.rs` and `virt_intrusive.rs` hold the two largest
consumers (`Frame`, `Page`) to 7/8 of that, leaving the rest for page tables
(measured worst case ~104 bytes). The flat 64 pages cover unfavorable slab
and page-table boundaries. Lazy and unmapped reservations use `D = 0`; each
lazy fault is admitted separately at `mapping_charge(1, 0)`. Fixed charges:
process 256 pages (applied at address-space creation and again in
`Process::new_child`), thread 64, sys-object and IPC 16. If a structure grows
enough to invalidate an allowance, the build or test must fail; the guard
band must not silently shrink.

### What refusal means

- Syscalls return `E_OUT_OF_MEMORY` before the operation starts; refusal has
  no side effects.
- A refused lazy fault cannot return an error to the faulting instruction:
  the faulting thread is killed, which kills its process. This is the
  accepted cost of having no OOM killer — the victim is whichever process
  faults while availability is below its floor. It is stated here so it is
  not mistaken for a bug.

### Kernel work outside admission

Boot allocations are not admitted. Runtime kernel activity not caused by a
newly admitted operation (interrupts, scheduler, TLB shootdowns, logging,
completion of in-flight work, on every CPU) consumes the final reserve and
must stay bounded once new userspace work has stopped. If that bounded-work
assumption ever fails to hold within `SYS_IO_FLOOR`, the floor must be raised
or the unbounded allocation removed — never a recovery class that can consume
the pool to zero.

## Pressure mode

The floors alone cannot keep sys-io alive: its heap grows through
`SysMem::alloc` in the vdso allocator, and a failed Rust global-allocator
call aborts the process. The floors convert a kernel panic into a sys-io
abort; pressure mode exists to stop sys-io's demand before the kernel refuses
it.

The kernel owns the state: a `memory_pressure` flag in `KernelStaticPage`
(read-only, mapped into every process), maintained wherever
free-for-admission changes — admission checks, reservation releases, and the
small-page free path (so the flag clears when an aggressor dies without
anyone allocating). A CAS picks a single transition winner. Watermarks, with
hysteresis so one allocation or free cannot flap service:

```text
raise when:  free_for_admission <= PRESSURE_LOW_PAGES   (512 pages, 2 MiB)
clear when:  free_for_admission >= PRESSURE_HIGH_PAGES  (768 pages, 3 MiB)
```

Any process observes pressure with one shared-page load
(`moto_sys::memory_pressure()`), no syscall. While the flag is up:

- rt.vdso refuses process spawns at the top of `spawn_impl` — the parent gets
  a recoverable `E_OUT_OF_MEMORY` before any work is done;
- sys-io refuses TCP listener binds, outbound TCP connects, UDP binds, and
  ICMP echo, allocation-free, at the top of the handlers;
- sys-io drops new service client connections at accept, in both the net and
  fs listeners. The client dies — deliberately: a new client is exactly the
  load being shed, and spawns are refused even earlier. The consumed accept
  slot is replaced so refusals stay prompt;
- listening-pool refills park (one entry per pool); a recovery task re-arms
  them after the flag clears.

Two rules with teeth, both learned the hard way:

- **Nothing that must run during an episode may allocate.** The refusal paths
  are allocation-free by construction; the constraint extends to observers.
  The metrics RPC allocates per query, so even the regression reads refusal
  counters only after recovery — an episode runs ~430 pages from empty, and
  a mid-episode metrics query is itself refused.
- **A fresh client under pressure dies at one of two hands.** An io_channel
  client maps ~130 eager pages (charge ~200) — most of the 256-page gap
  between the user floor and the low watermark — so kernel admission usually
  refuses the mapping before sys-io can accept and drop the connection. Both
  refusers are correct; which fires depends on where in the gap the pool
  sits.

Bounded growth matters beyond socket rings: any sys-io structure that can
keep growing while pressure is active (client bookkeeping, containers, async
tasks, filesystem caches, device buffers) must be bounded, reclaimed, or
added to the refusal set. Entering pressure mode or reporting
`E_OUT_OF_MEMORY` must not allocate.

## The safety argument, measured

(2026-08-06, QEMU/KVM, 4 vCPUs, 1 GiB RAM; full suite including the all-CPU
fault storm.)

**The pool's true minimum never crosses the user floor.** With the floor at
256 pages, the physical low water across the suite is 321; at a provisional
4096-page floor the same measurement read 4161 — the trough tracks the floor,
not the machine. The conservative charges stop admission with a ~65-page
cushion above the floor (the last refused charge exceeds what the last
admitted operation actually consumed), and unadmitted kernel bookkeeping drew
zero new pages at the trough: steady-state churn is absorbed by kernel-heap
slab slack. The measured overlap of unadmitted work below the floor is **0
pages**. The final reserve is still required: a heap at a fresh slab boundary
can pull pages, which is what `SYS_IO_FLOOR` absorbs.

**Residual demand under pressure is zero.** From flag-raise to release, no
sample of free-for-admission sank below the episode's entry value: refusals
stop new growth immediately, and surviving traffic (established TCP round
trips) allocates nothing.

**Concurrent lazy faults bias, they do not endanger.** Each in-flight fault
reserves 66 pages, so 4 CPUs transiently hold up to 264 pages of
reservations — more than the 128-page band between the floors. Reservations
consume no memory; the effect is only that concurrent faults near the floor
refuse each other earlier than a serial ordering would. Machines with many
more CPUs widen that bias proportionally and should raise the floors with CPU
count.

**Admission costs nothing measurable.** Release-build A/B against the
pre-admission baseline (three boots per side, alternating; benched via a
temporary `systest bench-alloc`, since reverted):

| metric | baseline | with admission |
|---|---:|---:|
| eager 16-page alloc+free | ~20.3 us/op | ~19.5 us/op |
| lazy fault (warm) | ~3008 ns/page | ~3018 ns/page |
| kernel up (median) | 162 ms | 162 ms |
| boot to ssh-ready | 1.16-1.23 s | 1.19-1.21 s |

Both workload deltas are inside run-to-run noise (the two global-atomic RMWs
per lazy fault are not measurable at this scale); boot latency is unchanged.

**An actual allocator OOM is always a defect.** Admission refusals are
ordinary operation; the physical allocator running dry means a charge or a
bounded-work assumption is wrong. Production code must not retry the
operation or increase a timeout to paper over either.

Observability: kernel metrics `mem.admission_refused_user`,
`mem.admission_refused_sys_io`, `mem.admission_reserved_pages`,
`mem.small_pages_low_water` (availability at admission checks),
`mem.phys_small_pages_low_water` (the allocator's true minimum — floor
validation reads this one), and the two floor gauges; sys-io metrics
`net.pressure_active`, `net.pressure_entries`, `net.pressure_refused`,
`net.pressure_refused_clients`, `net.pressure_deferred_replenish`, and the
watermark gauges. The `F_QUERY_ADMISSION_STATS` syscall
(`moto_sys::stats::AdmissionStats`) reports availability, reservations,
floors, and watermarks in one call, for tests and observability —
`MemoryStats` counts the mid-page region the small pool does not own, and
the metrics RPC allocates and is unavailable at sys-io startup.

## Regression coverage

`systest` covers: oversized-mapping refusal without drift; the same request
issued simultaneously on every CPU; charge boundaries at slab-unfavorable
mapping sizes (warm pass first — global `Frame` slabs are never freed, so
first-touch growth is permanent); lazy faults at the floor (single-process
and the all-CPU storm, which prints the floor-sizing measurements); the full
pressure episode (flag up, socket and spawn refusals, a client refused by
either refuser, service continuing on an established connection,
kernel-driven recovery from the free path, and refusal counters after
recovery). Every admission regression asserts the floors held, including the
physical low water staying above the sys-io floor.

Two arms are covered by review and soak counters rather than
per-run-deterministically: listening-pool refills parking *during* pressure
(loopback connects are refused, so the test cannot accept a connection then),
and sys-io's client-drop path (usually preempted by kernel admission at the
final floors). Watch `net.pressure_deferred_replenish` and
`net.pressure_refused_clients` in soak.

Tests must not add retries, longer timeouts, ignored failures, or workload
changes that conceal a crossed threshold.

## Open follow-ups

- FS-side request growth (file caches, device buffers) is not yet in the
  refusal set; grow it from observed soak metrics. The per-address-space
  sys-io memory-usage gauge (from the kernel's existing accounting) belongs
  to the same follow-up.
- The fault-injection acceptance test — drive an admitted operation past its
  charge and require the invariant failure to surface — needs a
  fault-injection seam the kernel does not have.

## Deliberately not built

- A `KernelRecovery` class (or anything else) that may allocate the pool to
  zero.
- Exact per-process attribution of page tables, shared slabs, or kernel-heap
  objects.
- A per-address-space memory-limit policy (the existing `max_memory` knob
  remains orthogonal).
- sys-io self-usage watermarks and allocator-backend instrumentation (the
  global watermark subsumes them, merely later — acceptable for a stability
  mechanism).
- An OOM killer.
- A configurable kernel physical reserve.
- Retrying refused allocations.
- Making every low-level mapping operation newly fallible.

The design spends a fixed memory margin in exchange for a small
implementation, deterministic refusal, and a safety argument validated by
direct measurement.
