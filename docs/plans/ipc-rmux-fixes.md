# rmux IPC review fixes

Status: approved, including mandatory connection wakeups and listener
replenishment on connection notifications.

This implements `ipc-rmux-issues.md` in its listed order, with separate,
test-gated commits and one-line commit messages. Keep patches around
100–300 lines including tests where practical. No changes outside the main
Motor OS repository, to Rust stdlib, or to moto-rt are proposed.

## Findings confirmed during planning

* `shared::get` removes a listener without waking its server.
* `LocalServer::wait` promotes listeners on a wake, and otherwise counts
  silent connections as available listeners.
* rmux checks peer capabilities only after `have_req()` succeeds.
* An exhausted live service returns `E_NOT_FOUND`, just like an absent one.
* rmux closes both connections after the final output poll, even though
  the input RPC can still be in flight.
* `Reader::read` maps every non-timeout RPC error to EOF. However,
  `CMD_OPEN_OUTPUT` runs in `connect()` and already propagates errors;
  finding 5's particular opening-refusal scenario needs correction during
  its implementation. Test the actual error path rather than assume it.

## Approved transport design

Always notify the server when a shared connection succeeds,
and authenticate rmux clients on that notification, before their first RPC.
Reject unauthorized silent peers and replenish the listeners. This belongs
in the kernel plus moto-ipc/rmux because rmux cannot observe a silent
connection using its current wait loop. Increasing the listener count would
only move the exhaustion threshold.

A connection notification is not an RPC. Audit all affected LocalServer
callers before changing notification semantics; the existing ipc_service
systest includes a caller that asserts every returned connection has a
request. Connection wakeups are mandatory, not opt-in. Update callers to
handle a connection notification without a request, and replenish listeners
as connections consume them, within the configured connection limit. Do not
add boot-time polling or unrelated work.

This removes the persistent lockout by unauthorized silent clients. It does
not promise immunity to arbitrary connection floods or to authorized peers
exhausting the configured connection limit. Keep those limits bounded.

For finding 2, use the existing `E_NOT_READY` for an owned service with
no available listener. rmux will wait for refill within its existing
five-second opening budget, then report a busy/timeout error. Only genuine
absence permits starting a server or returning an empty listing. This
bounded retry is approved as part of the transport behavior; it is not a
test retry or longer timeout.

## Ordered patches

1. **Silent connections.** Always wake on successful connection, replenish
   consumed listeners, handle connect-without-request safely, and
   authenticate rmux peers before any request. Add synchronized tests that
   hold unauthorized silent connections and prove legitimate use recovers
   while the holders remain alive. Cover peer close and listener refill.
2. **Empty pool versus absence.** Return `E_NOT_READY` for exhaustion;
   update syscall expectations and rmux discovery/open handling. Exercise
   exhausted, refilled, and absent services, including overlapping clients
   and both list and attach/new paths. Confirm exhaustion never starts a
   second server or reports an empty successful listing.
3. **Closing/input race.** Preserve the input connection until the client
   closes or the existing farewell deadline expires. Define output EOF
   without prematurely ending the pair. Add a synchronized regression for
   final output/exit delivery overlapping an input request, preserving
   exit status 5. Consult the user if this needs a new close protocol.
4. **Service-name delimiters.** Inspect the complete encode/parse/decode
   path and choose an injective escaping fix for semicolons and existing
   escape spellings. Keep the fix local if possible; consult before changing
   a shared encoding contract. Exercise TMPDIR containing semicolons and
   collision-sensitive names through real server discovery.
5. **Refusal errors.** Propagate explicit RPC refusals from `Reader::read`
   while preserving intended EOF semantics. Cover the actual read path and
   the already-propagated opening refusal. Correct the finding's scenario
   in the issue document with the fix.
6. **Timed-out RPC state.** Make moto-ipc reject reuse of an in-flight RPC
   before altering its sequence. Cover both unanswered and late-completed
   timed-out calls, then remove redundant rmux `stuck` state while preserving
   the documented client error behavior. Consult if safe request-buffer
   access requires a broader API change.
7. **Retired endpoint cleanup.** Remove the redundant pre-refill release
   after verifying endpoint ownership and refill-failure behavior; use the
   existing name-retention/admission tests.
8. **Per-RPC allocations.** Copy request bytes only for commands that need
   them, retaining a stable snapshot of untrusted request fields. Copy
   output directly from deque slices into the response and then drain it.
   Cover wrapped deque output and chunk boundaries with existing framing
   tests plus focused regressions where needed.

Record each diagnosis, validation, and commit in the issue document as work
progresses. Diagnose newly encountered failures first; clear and obvious
fixes get separate commits as requested. Stop for non-obvious decisions.

## Gates before every implementation commit

* Format changed Rust crates with repository-selected `cargo fmt`; inspect
  diffs and ensure no new compiler or clippy warnings.
* Wire new regressions into `src/tests/full-test.sh`, directly or via its
  existing rmux host tests and guest systest/probe coverage. Tests must not
  add external network dependencies.
* For any patch under `src/sys`, pass the full main-image suite three times
  in debug and three times in release on the final patch before committing.
* For rmux-only patches, pass rmux's component tests in debug and release
  and the full main-image suite in both modes for real IPC integration.
* Run any developer-image suite only with `--release`. No Lorry changes
  are planned.
* Preserve original failure logs and diagnose failures; no automatic
  retries, timeout increases, or weakened assertions. Existing external
  DNS/ping failures may receive the one retry permitted by AGENTS.md.

The user approved this plan before implementation. The documentation-only
plan commit is gated by a diff/whitespace check; implementation commits use
the gates above.
