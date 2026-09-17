# Vsock lifecycle and dispatch review fixes

Status: approved on 2026-09-16; implementation in progress.

Reviewed HEAD: `05f24d91`. The working tree was clean before this document.
This follow-up addresses the three findings reported after implementation of
[the vsock plan](vsock.md). The review below is based on source inspection;
no new runtime reproduction or validation pass is claimed.

## Findings

1. **Established streams can leak after client death.**
   `runtime/net.rs::on_connection_done` starts vsock cleanup but leaves stream
   removal to vsock's tasks. In `runtime/net/vsock.rs::vsock_state_task`, a
   failed notification calls `start_vsock_cleanup` and continues before
   checking `terminal_ready_to_drop`. The timer terminalizes the connection
   and requests reset; it does not independently remove established streams.
   Consequently, repeated notification failures can retain terminal streams
   in both the common socket map and the tuple index, consuming the global
   64-stream allowance and retaining channel ownership.

   `moto-ipc/src/io_channel.rs::Receiver::poll_recv` leaves `WaitingToRecv`
   set when it returns Pending. `Sender::send` can publish a message and then
   fail waking a dead peer with that flag set; once the unread ring fills,
   waiting for space also fails. Neither path clears the dead receiver's
   flag. The current exit child in `systest/src/net_driver.rs` blocks on
   synchronous stdin after successful receives, rather than parking another
   receive. The parent checks peer EOF and listener-port reuse, which do not
   independently establish reclamation of stream slots.

2. **Cross-channel accept has an unsafe ownership assertion.**
   `vsock_accept_task` checks the destination client before awaiting its
   response send, then asserts `socket.set_client_sender(sender)` afterwards.
   A send blocked on IPC space can resume after destination-channel teardown;
   publishing to shared memory does not itself prove that the client remains
   in sys-io's client map. `set_client_sender` explicitly returns false for a
   missing or shutting-down destination. The assertion therefore treats an
   expected lifecycle race as fatal. TCP's `process_matched_accept` already
   handles this return value. The exact vsock interleaving has not yet been
   reproduced; ordinary send-error coverage alone will not prove it was hit.

3. **Protocol waits retain NET dispatch tickets.**
   Each NET connection has 64 control-dispatch tickets, returned only after
   `on_msg` completes. `vsock_listener_accept` awaits its oneshot inline and
   `vsock_shutdown` awaits TX drain/control publication inline. At exhaustion,
   ingress waits for a ticket before receiving further messages, so later
   cleanup, queries, and shared TCP/UDP commands can stall on that channel.
   TCP queues an unmatched accept and returns from its dispatch handler.

   One listener permits only eight parked accepts. Accept-only exhaustion
   therefore needs multiple listeners: eight listeners with eight accepts
   each suffice, within the 32-listener limit. Repeated shutdown requests on
   one stream have no separate pending-request bound. Native cancellation
   does not retract already submitted RPCs. This is per-channel dispatch
   starvation, distinct from the global stream-capacity leak above.

## Scope and decisions

Keep the original D10 cleanup policy, D25 accept limits, D26 permanent device
failure, and D28 cancellation policy. A canceled accept may continue occupying
one of its listener's eight pending slots until matching or listener removal.
It must not retain a channel dispatch ticket during that wait.

Expected production changes are confined to sys-io's vsock integration and
its private state helpers, with a narrow NET disconnect hook if needed.
Regression changes belong in guest systest and its existing local UDS peer
and shell harness. Update `docs/vsock.md` for any new admission limit.
No kernel, moto-rt, Rust stdlib, VMM/backend, sibling-repository, or toolchain
source changes are planned. Add no boot tasks, polling, cancellation IPC,
generic quota framework, or external-network test dependencies.

Approved policy: **allow eight outstanding shutdown RPCs per
stream, with `OutOfMemory` for another while those slots are occupied**.
Count a slot until its reply is published or discarded, including replies
waiting for IPC space. Reserve a slot before applying a newly requested
shutdown direction. This matches the small accept-waiter limit and bounds
raw-IPC callers as well as native callers. Merely spawning every shutdown
as a detached task would replace ticket starvation with unbounded tasks.

The user approved small commits, preferably one per reported issue, with
light testing per commit and the full gate at the end. Combine steps 3–4
below into the dispatch-ticket commit. This explicitly replaces the default
per-commit full-gate schedule for this follow-up.

## Incremental implementation

Aim for 100–300 changed lines per patch including tests. Split supporting
test plumbing into another small patch if a coherent change exceeds that
range; do not defer a fix's regression to an unrelated later patch.

1. **Reclaim streams independently of notifications to dead clients.**
   Record client loss on disconnect or IPC failure, stop attempting state
   delivery to that client, and evaluate terminal reclamation independently
   of notification success. Preserve live-client notification ordering,
   buffered-read behavior, accepted-TX drain, the single eight-second cleanup
   deadline, and required reset publication. Avoid repeated self-notification
   after a failed send. Use the existing idempotent map/index removal path;
   submitted device buffers retain their current DMA ownership.

   Add a child with established accepted/outgoing streams whose empty IPC
   receive has actually returned Pending before the parent kills it. Use an
   explicit readiness handshake, not a sleep that guesses driver idleness.
   After peer-confirmed close, exercise exact global stream capacity and
   reuse in the same VM. A single leaked slot must fail this test; peer EOF
   and listener-port reuse alone are insufficient. Retain the existing
   unread-reply/page/TX process-exit coverage as a separate case.

2. **Handle failed accept ownership installation.**
   Replace the assertion with a checked transition. If the destination has
   disappeared, release temporary borrows/locks and reset the still-unaccepted
   child through the existing cleanup path. Install subchannel routing and
   start client tasks only after ownership succeeds. Preserve reply-before-RX
   ordering and the no-await region after successful publication.

   Exercise cross-channel accept with reply backpressure and destination
   teardown while keeping the listener channel alive. Check service survival,
   subsequent accept success, and stream-capacity reuse. Use controlled guest
   scheduling and local peer handshakes where possible. Record separately
   whether execution reached send failure or post-send registration failure;
   a passing stress run alone is not proof of the narrow interleaving.

3. **Queue unmatched accepts without a dispatch task waiting on them.**
   Store the request and destination sender in the existing eight-entry
   listener queue and return from dispatch after admission. Start matched
   reply work when a child is available, bounded by its retained stream.
   Preserve FIFO matching, same-process checks, stale-client rejection,
   listener-drop errors, and cached device-failure errors. Discard requests
   for disconnected channels. Keep teardown/error reply work bounded through
   publication too; do not create unlimited detached error-send tasks as
   listeners are repeatedly created and dropped.

   Extend raw guest IPC coverage to eight listeners with eight pending accepts
   each on one channel. Require a later query, a TCP/UDP control operation,
   and listener-drop requests on that same channel to complete while no peer
   satisfies the accepts. Check the eight-per-listener overflow response,
   every queued cancellation result, and later admission/reuse.

4. **Bound and detach shutdown completion from dispatch.**
   Admit shutdown metadata into the reviewed per-stream bound and return the
   dispatch ticket. Use stream-owned completion work to wait for accepted TX
   drain and shutdown publication, and serialize replies with existing stream
   output. Preserve directional flags, repeated-call completion, terminal
   error precedence, and prompt device-failure handling. Release pending
   metadata on client loss and wake work during socket removal. Queue bounds
   must cover completion work until reply publication/discard, so blocked
   sends cannot evade the limit.

   With a local peer deliberately withholding read/credit progress, admit
   shutdowns up to the limit and assert explicit overflow for further calls.
   Send more than 64 total shutdown requests, including canceled native calls
   where useful, and require unrelated commands and stream close on the same
   NET channel to progress. Resume the peer and verify admitted replies,
   directional behavior, and reuse. This extends the existing peer harness;
   no new host-only or sys-io self-test suite is planned.

## Validation

All regressions must run transitively from `src/tests/full-test.sh` in both
profiles. The existing route is `test-vsock.sh` -> `test-vsock-outgoing.sh`
-> guest systest plus `vsock-peer.rs`; use existing source-included guest
fixtures for small private state helpers if needed.

For each increment, explicitly build fresh `all systest` artifacts in debug
and release, run the affected guest cases and shared native-network tests,
format with the repository-selected `cargo fmt`, and run targeted Clippy for
sys-io/systest and any other changed crate. Check for new warnings and verify
new test markers so stale uploaded binaries cannot count as passes.

After the three issue commits, obtain three passing debug and three passing
release main-image build/full-test runs on the final combined source state.
Run the focused vsock suite on QEMU, Cloud
Hypervisor, and Firecracker in both profiles. Any developer-image gate must
be release-only (`src/tests/full-test-dev.sh --release`).

Preserve original failures and logs. Each diagnostic rerun must test a stated
hypothesis; a later pass alone does not resolve a failure. Add no automatic
retries, timeout extensions, weakened assertions, or ignored failures. Remove
temporary instrumentation before final gates. Report any inability to force
the narrow accept race distinctly from the broader lifecycle test results.

## Progress and evidence

The client-death fix is implemented and focused-tested. The regression keeps
an accepted stream, an outgoing stream, and the existing pending accepts/page
owners alive after polling an empty receive. Leaving `block_on` ends adaptive
IPC spinning and re-arms the receiver's waiting flag before the parent kills
the child. The original stdin/unread-reply exit case is retained separately.
The parent then checks peer EOF, port reuse, and exact 64-stream capacity.

Against unchanged sys-io, the added case failed on rebinding port 70003 with
`AlreadyInUse` after the idle child's peers closed. The first failure is in
`/tmp/vsock-review-gate.zw7gYT/leak-before-release.log`; a diagnostic run
adding exit-mode and port context confirmed the retained tuple in
`leak-diagnosis-release.log`. Neither failure is counted as a passing gate.

The fix records client loss once and allows terminal reclamation without
client notification, retaining the existing TX drain/reset policy. Debug and
release builds, all 20 QEMU peer cases, guest I/O-task fixtures, and the full
native TCP/UDP suite passed. Targeted Clippy and formatting passed with only
preexisting warnings in unchanged code. Logs are `leak-{build,clippy,vsock,
native}-{debug,release}.log` in the same directory. The final full gate remains
pending, as approved by the user.

The cross-channel accept fix now checks ownership installation and resets an
unaccepted child if its destination disappeared. A regression fills the
destination's reply ring before accepting, then tears it down with zero,
one, or all filler replies consumed. Sixteen such rounds keep the listener
channel alive, followed by exact global-capacity/reuse checks. Temporary
diagnostics did not demonstrate the narrow post-send registration-failure
branch; this is backpressure/teardown coverage, not a claimed reproduction
of that exact interleaving. The diagnostics were removed before validation.

Debug and release builds, all 20 QEMU peer cases, I/O-task fixtures, and native
TCP/UDP tests passed. Formatting and targeted Clippy passed without new
warnings. Logs are `accept-{build,clippy,vsock,native}-{debug,release}.log`
in `/tmp/vsock-review-gate.zw7gYT`.

The dispatch-ticket changes are implemented but not committed. Against the
previous handlers, 64 pending accepts reproducibly stalled the following
availability query (`0x564f8040`), preserved in `dispatch-before-release.log`.
With the changes, the debug guest passed the pending-accept regression and
the new stalled-TX test: eight admitted SEND shutdowns, 72 explicit overflow
responses, a successful RX probe after rejected RECEIVE shutdowns, same-channel
query/UDP/close progress, and all admitted replies after peer drain. Existing
peer cases and capacity reuse also passed. The focused gate itself did not
pass: the new host fixture initially had a compile error (fixed), then its
shell assertion looked for the accept marker in `native-accept` instead of
`echo 0` (fixed). Original logs are `dispatch-vsock-debug.log` and
`dispatch-v2-vsock-debug.log`. The corrected complete focused gate, release
tests, and final full gate remain pending.

Implementation paused for review of an additional source-confirmed
ownership race. `net.rs::on_connection_done` drains the old channel's socket
set before reclaiming its sockets. Reclaiming an open TCP socket can await
`device.rs::poll_completion`, leaving that client entry, a vsock listener,
and a matched child in the common map. A cross-channel accept can then
publish its reply to a still-active destination. `socket.rs::set_client_sender`
checks only the destination and asserts that removal from the previous
client's already-drained socket set succeeds. This assertion can still abort
sys-io, independently of the destination-registration check fixed above.
The interleaving is diagnosed from source, not claimed as a runtime
reproduction. The user subsequently approved fixing this additional path.
It will be a separate commit: synchronously remove vsock listeners before
the first TCP teardown await, invalidating matched accepts before another
task can publish success against a closing owner. This preserves active
ownership assertions and avoids rejecting ownership only after a live
destination has received a successful reply.

The corrected dispatch focused gate passed in debug and release, including
all 20 QEMU peer cases, I/O-task fixtures, and native TCP/UDP tests. Formatting
and targeted Clippy found no new warnings. Logs are
`dispatch-v3-{build,clippy,vsock,native}-{debug,release}.log`. This issue's
patch is larger than the preferred range because it keeps both bounded wait
paths and their regressions together. The final full gate remains pending.

The additional ownership fix removes a closing channel's vsock listeners
synchronously, before any TCP teardown await. Matched accept tasks are woken
with their listener already absent; the shared ownership assertions and the
reply-before-RX ordering are unchanged. A controlled regression fills a
separate TCP accept channel's reply ring, blocking its cancellation reply,
then requires the vsock peer to observe listener loss before releasing that
ring. Both TCP and vsock accepts must return `NotConnected`, followed by
listener-port and exact stream-capacity reuse.

The old ordering failed the peer-close check in
`owner-before-v2-release.log`; `owner-before-release.log` records an earlier
compile error in the new fixture, corrected before that reproduction. This
reproduces the unsafe teardown ordering, not the exact ownership assertion.
With the fix, debug/release builds, all 20 QEMU peer cases, I/O-task fixtures,
native TCP/UDP tests, formatting, and targeted Clippy passed without new
warnings. Evidence is `owner-{build,clippy,vsock,native}-{debug,release}.log`
in `/tmp/vsock-review-gate.zw7gYT`. All code fixes are ready for the frozen
final gate.
