# Vsock simplification plan

Status: first implementation tranche and small-commit workflow approved.
Control scheduling and event-pool changes still require separate review.
Baseline: `d8559ce2` on `vsock`, compared with local `origin/main` at
`290bb9e3`. This plan follows the whole-stack review, not the completed
lifecycle/dispatch fix plan's temporary gate exception.

## Objective and scope

Reduce duplicated state, forwarding layers, and test boilerplate while
preserving ordinary native API behavior and keeping sys-io healthy under
client cancellation, abuse, and death. Simplicity means fewer ownership and
ordering invariants to maintain, not merely fewer physical lines.

The reviewed branch's approximately 20,075 net added lines comprise 6,871
production Rust lines (including shared infrastructure), 8,964 test/harness
lines, 4,112 documentation lines, and 128 build/configuration lines. These
are physical lines including comments/blanks, not 20k lines of runtime
protocol. Report subsequent reductions separately for these categories;
documentation deletion is not a reduction in runtime complexity.

The first tranche is bounded, behavior-preserving work described below.
Control scheduling and event-pool changes are later candidates with explicit
decision checkpoints; approving the first tranche does not approve a new
resource policy or transport design.

All source changes stay inside this repository, in the named vsock modules
and existing test routes. No kernel, moto-rt, rt.vdso, Rust stdlib, libc,
toolchain, VMM/backend, or sibling-repository source changes are planned.
No capability-mask changes, new dependencies, or Lorry work are planned.

## Contracts that stay

Use [the current design](vsock.md) and [native API guide](../vsock.md) as the
behavioral baseline. In particular:

- Keep Virtio DMA ownership, sys-io connection ownership, and client IPC
  ownership separate. Preserve moto-io's `no_std` boundary.
- Keep lazy activation and the unchanged absent/unused-device boot path.
  Add no boot work, polling timer, or background framework.
- Preserve current bounds, capability/handle checks, protocol validation,
  byte-credit accounting, wire/API layouts, and error precedence.
- Preserve ordered RX, accepted-TX drain, directional shutdown, retained
  connection-local errors, and permanent device failure with DMA retention.
- Preserve bounded accepts/shutdowns without retained dispatch tickets,
  safe cross-channel handoff, listener invalidation before yielding teardown,
  and exact stream-slot reclamation after idle-driver client death.
- Keep TCP/UDP behavior unchanged on the shared NET channel. Do not undo
  shared queue, validation, or kernel fixes simply to reduce the branch diff.

Pathological shutdown admission overflow need not preserve a usable native
stream: local closure/RX discard can precede the server's `OutOfMemory`.
The documentation now makes that explicit. Do not add rollback or a new
admission/cancellation protocol for this case. This narrow exception does
not relax ordinary shutdown, cancellation, delivery, or cleanup contracts.

## Documentation cleanup

Replace `vsock.md`'s completed stage diary, obsolete "planned" integration
notes, temporary log paths, and original milestone schedule with current
contracts, component ownership, and required coverage. Preserve D1–D28
identifiers and meaningful decisions. Git retains the historical evidence;
the API guide and measurement report remain separate.

This documentation-only cleanup necessarily exceeds the normal patch-size
target because it removes thousands of obsolete lines. It does not authorize
a similarly large production rewrite. Do not recreate a running transcript
in either plan; update status and durable design decisions only.

## First implementation tranche

Make independently reviewable patches, normally 100–300 changed lines
including tests. Split fixture preparation from its dependent refactor when
necessary, without landing a behavior change without regression coverage.
If an indivisible code patch needs a substantially larger diff, stop for
review of that exception. Prefer one purpose per commit after its gate.

### 1. Fold `EstablishedStream` into `Connection`

Files: `src/sys/sys-io/src/runtime/vsock/{connection,stream}.rs`, the parent
`runtime/vsock.rs`, source-included tests in
`src/sys/tests/virtio-task-tests/src/lib.rs`, and the few imports referring
to `ReadOutcome`.

`Connection` currently delegates through `EstablishedStream` to
`StreamBuffer` and `CreditState`. Move the receive buffer and permanent peer
shutdown flags into `Connection`; make its phase/terminal cause authoritative
instead of retaining a second reset flag. Keep the small buffer and checked
credit helpers. Keep runtime/client ownership and pending-control scheduling
unchanged in this step.

Before removing the intermediate layer, map its existing tests to retained
connection cases. Preserve atomic RX rejection, zero-length reads, buffered
data before peer/protocol reset, immediate discard on device failure, both
half-close directions, and local SEND draining previously accepted TX while
peer RECEIVE forbids publication. Preserve first connection-local cause and
device-failure precedence. Move unique assertions rather than deleting them
because the type disappears.

Success: one protocol state owner, no redundant reset state or forwarding
layer, no new generic abstraction, and equivalent externally visible state
transitions. Further consolidation of buffer/credit helpers is not implied.

### 2. Share identical private IPC success-codec logic

Files: `src/sys/lib/moto-sys-io/src/api_vsock.rs` and
`src/sys/tests/systest/src/vsock.rs`.

Connect and listener-bind success messages have the same handle/local-address
layout. Use small private encode/decode helpers for the repeated layout;
retain public wrappers/types and command-specific checks. Do not merge accept
with them if doing so requires a configurable schema or generic RPC layer.
Preserve request identity, reserved-zero bytes, validation, and the ordering
of command, status, and success-field errors.

Keep independent literal-byte expectations and malformed-message assertions
in the existing guest codec tests. Production helpers must not generate the
tests' expected wire layout. Skip extraction if the helper plus wrappers
does not make the code simpler.

### 3. Consolidate repeated test setup

Files: the existing guest vsock/virtio tests, `virtio-task-tests`,
`src/tests/vsock-peer.rs`, and a small shared test-only source file if useful.

Share host/guest role IDs, frame/action constants, and deterministic payload
construction where currently duplicated. A shared module may be included by
path on both sides; keep host Unix I/O and native guest async I/O separate.
Share plain packet/fixture constructors in the guest tests where useful.
Do not introduce a scenario DSL, generic transport adapter, host-only suite,
or production test hook to save a few lines.

Before removing a repeated case, identify the retained test and assertion
that covers the same boundary. Keep independent wire goldens and all distinct
scenarios, especially exact capacity/reuse, cancellation timing, idle-client
death, reply-backpressured handoff, shutdown saturation, and shared NET
progress. Preserve explicit host/guest barriers, deadlines, and all selected
VMM actions. Never replace exact error assertions with "either error works."

Success: less setup duplication without loss of coverage or obscuring which
boundary a failure exercised. Record the before/after test mapping in the
patch review, not a growing historical section in this plan.

## Later candidates: review before implementation

### 4. Pending control scheduling

The runtime has a global `PendingControl` queue plus per-stream reset and
shutdown requested/queued/published state and queue-space wakeups. Investigate
whether stream-owned pending intent can be submitted directly by the existing
single TX pump, retaining only a bounded queue for stateless refusals.
Do not implement this while flattening `EstablishedStream`.

Before proposing code, document the replacement state transitions and prove:

- the aggregate control bound stays 64; replacing it with 64 stream intents
  plus 64 refusals would silently change the bound;
- RX can retain each required response/refusal before accepting more work,
  including when TX and the refusal queue are saturated;
- REQUEST/RESPONSE precede stream data, accepted TX precedes local SEND,
  reset supersedes obsolete work, and cleanup retains its tuple until the
  required reset publishes;
- coalescing and credit-request suppression retain the necessary wakeups;
- control/data capacity and round-robin fairness cannot strand unrelated
  streams or the shared NET service; and
- device/client failure discards logical work without dropping DMA owners.

Bring the concrete design back for review. If preserving these rules needs
more accounting or state than the existing queue, retain the queue and limit
the change to demonstrable local simplifications. A new actor/scheduler or
generic TCP/vsock framework is not an acceptable substitute.

### 5. Single outstanding event buffer

The only meaningful supported event is terminal transport reset, while the
driver maintains up to four event completions with ordered-pool bookkeeping.
One outstanding completion may remove that bookkeeping without affecting
packet RX ordering. This changes D7's event capacity and requires explicit
approval after the implementation/lifetime design is reviewed.

The proposal must preserve allocation before publication, queue-task setup,
completion wakeups, invalid-event consumption/reposting, and the permanent
failure path that retains unreclaimed DMA. Keep the ordered accessor and
bounded multi-buffer pool for RX packets. Validate the one-buffer path in
guest fixtures and on all three VMMs in both profiles; do not infer that
reset ownership is safe just because ordinary connections still work.

## Validation and commits

During planning change documentation only and run `git diff --check` plus
local reference checks. Before each implementation commit:

1. Format changed Rust using the repository-selected `cargo fmt`; inspect
   the diff and build/lint output for new in-tree warnings.
2. Run the relevant existing guest fixture/native/live-vsock cases in debug
   and release. Keep tests directly or transitively in `full-test.sh`.
3. For every core patch, obtain fresh debug and release builds plus at least
   three passing `src/tests/full-test.sh` runs in each profile on QEMU before
   committing. A source change during validation invalidates earlier passes
   for that final patch. Do not reuse the previous implementation's gate.
4. For control/transport changes, also run focused vsock gates on CHV and
   Firecracker in debug and release. Do not count the other-VMM boot checks
   as protocol coverage. Treat edits under `src/sys`, including core test
   fixtures, as core patches. Host-harness-only patches use their affected
   guest gates in both profiles.

At the end, retain the final core patch's unchanged-tree full-gate results
(rerun if later code changes invalidate them), run focused vsock tests on all
three VMMs in both profiles, and run `src/tests/full-test-dev.sh --release`.
No debug developer-image run or Firecracker developer-image support is added.
Compare existing latency/transfer/footprint checks with the measurement
baseline; investigate regressions rather than trading them for line count.

Preserve original failures and diagnose specific hypotheses before reruns;
add no automatic retries, longer timeouts, or weakened assertions. Follow
AGENTS.md's existing DNS/ping exception only where applicable. Stop after
diagnosing an unrelated preexisting production bug or a non-obvious design
choice. Remove temporary diagnostics before final gates and commits.

Approved workflow: one documentation commit, then small commits per purpose
after their required gates.

## Completion

The first tranche is complete when the redundant stream layer is gone,
useful codec/test duplication is removed, coverage is accounted for, and
the required gates pass on the final source. Report actual production,
test, and documentation reductions separately. Do not promise to halve the
stack or pursue a line target by dropping justified checks and tests.
Later scheduling/event work completes only after its separate design review
and gates; a recommendation to retain an existing mechanism is a valid
outcome if the alternative is not simpler.
