# IPC review fixes

Status: approved; implementation in progress.

Scope: the five findings from the review of commits `54dab16b` through
`3b830f14`, excluding merge `a7b901bc`. Make one commit per finding, with a
one-line commit message. Run focused checks before each commit, and the full
three-debug / three-release main-image gate only after all five fixes, as
explicitly requested. Do not include the existing edits to `future-work.md`
or `new-caps.md` in these commits.

## 1. Bound pending-listener allocations

Replace `Service.pending`'s contiguous `VecDeque` with a `BTreeMap` keyed by
the existing server `SysObject` ID. Tree nodes allocate in small increments;
growing a service no longer reallocates its entire listener pool under the
fixed object-admission reservation. Use the first key for accepting a client
and reinsert a failed connection under its original key.

Selection follows endpoint creation order. Returning a failed connection
restores that order instead of putting it ahead of every other listener;
there is no public listener-order guarantee. Preserve owner checks, closed
endpoint checks, and the existing lifetime/lock ordering. Leave the current
scan on close for commit 4, so each issue has its own fix.

Validate growth under memory pressure and the existing failed-connect,
ownership, and takeover behavior. Commit message:
`kernel: bound pending listener allocations`

## 2. Preserve ready handles on a timed-out wait

Treat `E_TIMED_OUT` as a successful wait for purposes of processing the
returned handles. An empty timeout still returns an empty ready list.
Continue reporting bad handles through the existing error path.

Add deterministic host regressions that compile the real `sync.rs` against
small syscall stubs and supply a timeout with active, listening, and external
ready handles. Wire the test runner into `full-test.sh`. Commit message:
`moto-ipc: preserve ready handles when a wait times out`

## 3. Release retired connection resources before refilling

Retirement must release shared mappings and extension data before attempting
another listener allocation. Retain only the minimum endpoint handle needed
to reserve the service name when no other server endpoint holds it. Release
that handle once another endpoint holds the name, and on server destruction.

Keep the existing public disconnect lifetime contract; move resource release
into LocalServer's retirement path, where callers can no longer access the
retired connection. Cover client close, explicit disconnect, repeated refused
refills, name ownership, and final destruction. Commit message:
`moto-ipc: release retired buffers before refilling listeners`

## 4. Remove closed listeners by ID

Pass the closing server object's ID to name cleanup and remove exactly that
entry from the tree introduced in commit 1. Closing a connected endpoint is
an ordinary absent-key removal. Preserve endpoint counting and takeover
protection. Exercise a large pool with closes and failed connects interleaved;
avoid wall-clock assertions for algorithmic performance. Commit message:
`kernel: remove closed listeners by object ID`

## 5. Synchronize the refill recovery test

Make the test observe a refused timed wait while the hoarder still holds
memory before releasing the hoarder. Use explicit test-child state/handshakes
and a deterministic syscall-stub regression where useful; do not depend on
an arbitrary settling delay. Verify that removing the timer prevents the
regression from completing successfully. Preserve the existing deadline.
Commit message:
`systest: synchronize listener refill recovery with memory pressure`

## Validation

Format with the repository-selected toolchain. Build the affected components
and run their Clippy checks, host regressions, and targeted native IPC tests
as applicable before each commit. New tests must run transitively through
`src/tests/full-test.sh`.

After all five commits, run `src/tests/full-test.sh` three times and
`src/tests/full-test.sh --release` three times, sequentially, with separate
logs identifying the tested commit. KVM is available through host execution
outside the sandbox. Diagnose any failure and preserve its original log;
do not count a later unexplained pass as resolution. No developer-image gate
is planned. No runtime/stdlib changes, outside-repository code changes, or
additional boot-time work are planned.
