# Fallible network-channel construction

2026-09-06. Reviewed in conversation. The user selected moto-mpmc, authorized
adding the necessary APIs, and requested a separate commit for this fix.
Performance testing/comparison is explicitly out of scope.

## Failure and scope

The release main-image gate aborts a listener-flood child while allocating
4096 bytes in `NetChannel::with_conn`. The existing
`crossbeam_queue::ArrayQueue<io_channel::Msg>::new(64)` allocates its slots
infallibly. A failed allocation aborts rt.vdso instead of returning the
OutOfMemory bind refusal required by `test_aggregate_listener_exhaustion`.

The captured return address is `0x101d3` in the network pool channel thread.
An unstripped diagnostic runtime has byte-identical `.text` to the failing
runtime. Disassembly identifies the allocation and subsequent queue-slot
initialization. Evidence is in `build/virtio-waitfix.fu76Co/`, especially
`full-test-release-2.log`, `admission-backtrace.txt`, and
`admission-allocation.txt`. See the virtio descriptor plan for the gate history.

## Accepted implementation

The pinned Crossbeam queue has no fallible constructor or caller-supplied
storage API. Merely wrapping `ArrayQueue::new` in a Result cannot catch an
allocation abort. Checking available memory first cannot reserve capacity
against concurrent allocations and is not a fix.

Reuse `src/sys/lib/moto-mpmc`. Add `try_bounded`, covering both the slot-buffer
allocation and the reference-counter allocation, and retain the existing
infallible `bounded` API. Queue operations and their concurrency algorithm
remain unchanged. Store both endpoints in NetChannel, use only `try_send`
and `try_recv`, and retain capacity 64 and the existing async wake protocol.
No blocking waiters are registered through these nonblocking operations.

Alternatives considered but not selected:

- Vendor/patch Crossbeam to add a fallible constructor. This retains the
  complete upstream implementation but imports a substantially larger patch
  and requires deciding which dependency consumers use the patched crate.
- Replace the queue with a preallocated, mutex-protected ring. This is simpler
  code but changes contention and latency behavior on the networking path.
- Extract/reuse the native IPC ring. Its queue is currently embedded in the
  shared-channel representation, not an independently reusable queue API;
  that would expand the change into IPC layout/implementation work.

No changes outside the main repository, to Rust stdlib, or to moto-rt are
planned. No new boot tasks, retries, timeouts, or memory-floor changes.

## Incremental implementation

1. Add moto-mpmc's fallible construction API and focused tests. Keep the
   concurrency algorithm unchanged; verify partial-allocation cleanup.
2. Make `NetChannel::with_conn` return a Result. Make its other owned
   allocations fallible too, or remove unnecessary allocation (the four
   subchannel flags can be inline). Propagate failure through `connect`.
   The existing owned IPC connection must be dropped on every failed
   construction, releasing its mapping and handle.
3. Check pool publication allocations and failure bookkeeping: no leaked
   provisioning count, lost waiter, partially published channel, or leaked
   connection. Route failures through the existing pool error policy.
   This is not a claim that arbitrary runtime/socket operations become
   allocation-failure-safe; any further required runtime redesign needs
   review rather than being silently folded into this patch.
4. Add deterministic failure injection covering actual allocation failure,
   cleanup, and the error returned to callers. Wire all new regressions into
   `src/tests/full-test.sh` directly or through systest.

Keep changes in reviewable increments near 100-300 lines including tests;
call out any larger mechanical adaptation separately. Preserve the existing
virtio work without modifying or staging it.

## Validation and handoff

- Queue tests: capacity/full/empty behavior, wraparound, message ownership
  and drop, concurrent producers, and allocation failure.
- Channel tests: failure during construction releases prior resources,
  returns OutOfMemory, and leaves subsequent channel creation usable.
- Pool tests: failure reaches waiting bind callers and drains provisioning
  bookkeeping without weakening the existing listener-exhaustion test.
- Repository-toolchain formatting, builds, and Clippy without new warnings.
- Three full debug and three full release main-image runs, stopping to
  diagnose failures rather than retrying them to obtain passes.
- Developer-image validation, if run, is release-only. Dependency downloads
  still need the separately requested approval.

Stage only this fix and its tests/documentation after validation. If the
full-test driver also contains unstaged virtio wiring, stage just the network
test hunk. Inspect the final staged diff for unrelated changes, then commit
this fix separately as requested. Do not commit the virtio descriptor work.

## Implementation record

`moto_mpmc::try_bounded` now returns InvalidArgument for zero or
unrepresentable capacities and OutOfMemory for either construction
allocation. It initializes fallibly allocated slot storage before exposing
the channel, and a failed reference-counter allocation drops that storage.
The selected nightly toolchain provides the standard allocator API; the
crate's declared minimum version is updated for the boxed-slice API used.

NetChannel retains both nonblocking endpoints. The four subchannel flags
are inline, and channel ownership uses `Arc::try_new`. Connection ownership
ensures all early-return paths release their IPC mapping and handle. The
pool reserves waiter/publication-vector capacity fallibly and constructs
its client owner fallibly, reporting errors before distributing reservations.
This fixes construction, not every infallible allocation in unrelated
runtime/task/socket operations.

Five host regressions exercise actual allocator refusal at both allocation
sites, zero live storage after cleanup, invalid capacities, queue behavior,
value destruction, and concurrent producer ordering. They pass in debug
and release and are directly included in full-test. The host tests pass
Clippy with warnings denied. A guest regression injects late construction
failure after real IPC connection and queue creation, verifies TCP and UDP
OutOfMemory propagation, checks pool bookkeeping, then verifies recovery.
It runs transitively through systest without changing the exhaustion test.

Full-suite logs are under `build/network-allocation.YuWF2O/`. All three
release and three debug runs passed sequentially, with no failed runs or
retries. Every run passed both pressure checks, aggregate listener
exhaustion, and the new late-construction-failure regression. Motor-target
Clippy for moto-io and rt with netdev enabled also passed with warnings
denied, as did repository-toolchain formatting checks.

These runs used the current checkout, including the unchanged local virtio
patch; that patch is not included in the network fix's commit. Debug runs
1 and 3 exhibited the previously diagnosed network-RX monitor intervention;
this allocation fix does not claim to resolve that separate issue.
No additional performance tests or comparisons were run.

## Follow-up: pool runtime construction

On 2026-09-11, the first unchanged debug gate after a branch merge found the
next allocation gap. A listener-flood child was admitted to spawn a pool
channel thread, then aborted while `LocalRuntime::new` allocated that thread's
executor. The runtime constructor owned four infallible allocations: the timer
queue cancellation counter, two shared scheduler values, and the outer box.

The user reviewed and authorized the follow-up. `LocalRuntime::try_new` now
reports `OutOfMemory` from every construction allocation and drops partial
state. The network pool uses it before connecting to sys-io, fails all parked
waiters through the existing policy, clears the in-flight provision, and exits
the unused thread normally. The infallible constructor remains for callers
whose APIs cannot report allocation failure.

A host allocator regression refuses each of the four allocations and verifies
that no owned bytes remain. A guest injection verifies TCP and UDP error
delivery, empty pool accounting, and recovery after the failure is disabled.

The host regression passed in debug and release, and host and Motor-target
Clippy passed with warnings denied. Three consecutive debug and three
consecutive release main-image suites passed without retries, including the
new guest regression. The release developer-image suite also passed, including
its source-tree and complete Lorry product gates. A test-helper race exposed by
the first debug run was fixed separately in commit `1157c53b`; subsequent
pressure tests reported every attempted write, stat, and lock acquisition as
refused while pressure was active.
