# Russhd forwarding review fixes

Date: 2026-11-07. Status: complete. The published fork is integrated and the
final integrated gate passed. Local commits are authorized; the user owns
publication.

## Scope

Work from the stable finding IDs in the
[combined review](russhd-forwarding-review.md). Code baselines are Motor
`63c32d6d` and external russh `b45bd26`, the revision `src/bin/russhd/Cargo.lock`
recorded when this plan was reviewed, from branch `motor-v0.65.1`. Motor `85f39f3d` adds only
documentation: it fixes R7 and R8 and closes the original plan, whose design now lives in
[docs/ssh-forwarding.md](../ssh-forwarding.md).

The work crosses the main repository and the **separate russh Git repository at
`build/russh-rebase/fork`**. Proposed fork changes are limited to the close
policy of outgoing credit-mode opens (R1), received-disconnect cleanup (R2, R3),
their regressions, and one moved test (S4). No SDK, runtime, standard-library,
or kernel changes are proposed.

[AGENTS.md](../../AGENTS.md) requires a reviewed plan before code on larger
tasks, and the [forwarding design](../ssh-forwarding.md#the-russh-fork)
requires that further fork changes be proposed first. Approval of this plan
authorizes the local code, build, and test work below, superseding the earlier
analysis-only restriction. The phase 3 disconnect repair and phase 4 recovery
policy are approved, including explicit user approval under AGENTS.md note 1
for phase 4's repeated, rate-limited accepts. The user authorizes local commits
and owns fork publication. The published fixes are `5191061`, `f9b1700`, and
`3891276`; Motor's lockfile integrates the last revision.

The user has confirmed that no pin-specific test suite or runner is wanted,
and that the final gate must follow all code changes. Fork tests stay in the
fork; ordinary Motor component and image tests cover Motor integration.

This document holds design and decisions. Progress is visible in the commits:
do not add per-run records here, and do not commit documentation-only run
records. Update a finding's status in the review inside the commit that fixes it.

## Contracts to preserve

- Receive credit follows downstream consumption; channel windows and queues stay
  bounded, and one stalled forward does not stall unrelated channels.
- Peer close may stop sending but must not acknowledge away undelivered inbound
  payload. Incoming opens select deferral before their acceptance reply;
  outgoing credit-mode opens defer by construction (phase 2).
- Connection termination cancels owned listeners and jobs independently of
  application-held handles. Normal command completion can drain admitted work.
- Remote targets come only from accepted client configuration. Preserve the
  setup reply barrier, bind-key matching, cancellation ordering, and
  partial-family binding policy.
- Upstream russh public API behavior is unchanged. The credit-mode open methods
  are fork additions with two Motor callers; R1 changes their close default and
  documents it.
- Fork behavior is tested in the fork. Motor tests exercise Motor code through
  russh; no fork test is copied into `src/bin/russhd/tests`, and no additional
  pin-specific contract suite or test runner is added.
- Keep shipped forwarding policy, the 16,384-forward ceiling, and existing test
  exclusions. No new boot work, arbitrary timeouts, hidden failures, or
  automatic test retries.

## Incremental work

Aim for 100–300 lines per implementation patch including focused regressions.
Split a phase further when needed; do not accumulate an unrelated refactor into
a correctness fix. Phases 1 and 4 are main-only and can proceed while the fork
changes of phases 2 and 3 wait for review and publication.

### 1. R6: log only validated text

Remove raw rejected bind strings from both the setup and the cancellation
failure logs in `src/bin/russhd/src/main.rs`. Keep the operation, the numeric
port, and safe error context. Prefer this small change to a general sanitizer.
Inspect error formatting so an error object does not reintroduce the rejected
string. Verify both paths with control-character and overlong inputs using the
existing fixtures where practical; do not add a formatting-only mock framework.

### 2. R1: defer close by construction for outgoing credit-mode opens

The defect is ordering: the application sets the deferral flag after the open
future returns, and the session can process a peer close before that. Fix it
where the credit is installed. In the fork's `Msg::ChannelOpenDirectTcpIpWithCredit`
handler (`client/mod.rs`) and `Msg::ChannelOpenForwardedTcpIpWithCredit` handler
(`server/session.rs`), call `defer_close` on the `ReceiveCredit` that
`receive_credit(id)` returns, before it is handed to the application. The
handler runs inside the session loop and sends the open itself, so no peer
message for that channel can be processed first. No new entry points, no message
change, no options framework; document the behavior on both `_with_credit`
methods. Every production credit-mode caller relays, and the one failure path
(a failed SOCKS reply in `client/forwarding.rs`) drops the last credit handle, which
releases the deferral, so the immediate acknowledgement path still covers it.
Opt-in entry points beside the existing methods were considered and not chosen
(decision 1).

Fork regressions, both sides: dispatch the open, suspend its application
consumer, deliver confirmation, payload, EOF, and close, and require the close
acknowledgement to wait until the consumer drains and closes. Add: dropping the
last credit handle releases a pending acknowledgement; cancellation before
confirmation and callback-managed opens are unchanged. `test_channel_close_handshake.rs` sets
deferral after the open; keep it as the post-open path check or drop the now
redundant call.

Motor needs no API switch: `client/forwarding.rs` and `forward/remote.rs`
already use the credit-mode opens. Keep the pre-accept `defer_close` calls in
`forward/open.rs` and `client/remote.rs` and the one at the top of
`forward::relay`; consolidating them is not this fix. In the same patches,
remove the seven copied fork tests from `src/bin/russhd/tests` (the review's S4
table) and move the one Motor-only case,
`refusal_after_a_legacy_open_is_cancelled_keeps_the_transport_alive`, into the
fork's `test_server_open_credit.rs`. Motor keeps its own end-to-end and unit
tests. No replacement pin-specific suite or fork-test runner is required.

### 3. R2 and R3: end resource ownership on a received disconnect

An SSH disconnect packet ends the SSH session, but receiving that packet does
not itself close the underlying TCP connection. A peer can send it and leave
TCP open. R2 additionally needs a blocked writer; R3 can retain the session
even when writes complete. Normal peers close the transport promptly, so these
are primarily robustness/resource-retention defects. P2 stands.

For R2, in the fork client, distinguish a received `SSH_MSG_DISCONNECT` from
locally initiated shutdown. The run loop ends on `disconnected`; after a
received disconnect, skip the unconditional final flush and any other blocking
transport-shutdown step. Preserve disconnect callbacks and returned reasons.

For R3, the fork server leaves its SSH processing loop on receipt of disconnect,
but then shuts down its writer and reads until TCP EOF. Motor disables the
inactivity timer, so a peer withholding EOF can retain the session indefinitely.
Today this retains the handler, forwarding resources, transport, and session
task. Dropping only the handler before that wait would release the forwards but
still retain the transport and task; repeated connections could accumulate them.

The proposed fix is to finish the session task on a received SSH disconnect,
skipping further transport flush, shutdown, or EOF waits on that path. Returning
drops the session's transport and channel state; Motor's existing
`ConnectionHandler::drop` cancels its forwarding jobs. Preserve the separate
locally initiated shutdown path. This applies to disconnecting the whole SSH
session; ordinary forwarding-channel EOF/close still follows its drain contract.

Fork tests, one side at a time: writes blocked and the peer keeping its
transport alive after sending disconnect. Assert that the session task finishes
and its transport and handler drop while the peer still withholds TCP EOF.
Include a server case with writes completing, isolating the EOF wait. Observing
only handler drop is insufficient: the test must catch a retained session task.
Retain the existing locally initiated disconnect, EOF, stalled-transport, login,
and close tests. No Motor copy of these tests.

### 4. R4 and R5: one accept-error policy for both listeners

The policy below is approved (decision 2). Its benefit is keeping a
long-lived listener usable after one incoming connection fails or resources are
temporarily exhausted. Current local forwarding can abort the entire SSH session;
current remote forwarding can lose its listener permanently while retaining the
registration. The first patch classifies errors; the next two apply the policy
to the local and the remote listener. Keep this to a small classifier and a
deadline per listening socket.

Native accept path: `tokio::net::TcpListener` from the Motor tokio fork, mio,
`std::net`, the vdso's `RtTcpListener`, then the SDK `TcpListener` in
`src/sys/lib/moto-sdk/src/io/net/tcp.rs`. The SDK queues one `Err(status)` per
failed accept and returns `E_NOT_CONNECTED` from every accept after a sys-io
channel failure, so a failed connection and a dead listener are already
distinct at the source. Classify by `io::ErrorKind`, with target-specific raw OS
codes where the kind is insufficient. Confirm the Motor mapping
by inspection and record it next to the classifier; do not change core OS code
to accommodate tests.

Three classes, in one shared helper:

- Per-connection: `ConnectionAborted`, `ConnectionReset`, `Interrupted`, plus
  Linux's pending errors on the incoming socket (`ENETDOWN`, `EPROTO`,
  `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`, `EHOSTUNREACH`, `EOPNOTSUPP`,
  `ENETUNREACH`). Linux documents these as recoverable accept results; they
  do not by themselves mean the listening socket is broken. Log at debug and
  continue, retaining cancellation and scheduler progress. Tokio handles
  ordinary `WouldBlock` through readiness polling.
- Exhaustion: `OutOfMemory`, host `ENOBUFS`, `EMFILE` and `ENFILE`, and the
  native statuses the classification confirms. Log at warn and delay that
  socket's next accept by 100 ms, sharing the existing `serve()` duration.
  Store the deadline with the affected socket. Other listening sockets,
  stop/cancellation, and command completion remain runnable. This limits
  repeated exhaustion attempts per socket; it is ongoing recovery until
  success, cancellation, or a permanent error, not a finite retry budget.
- Permanent/unclassified: retire that socket with one warn diagnostic,
  including the sticky native `NotConnected` case. Diagnose an unexpected
  error rather than silently adding it to the recovery class.

The extra Linux cases protect host-run russhd. Motor primarily benefits from
distinguishing a failed incoming connection, temporary memory exhaustion, and
a dead listener. The existing daemon `serve()` loop already survives accept
errors with a 100 ms pause; the proposed forwarding policy scopes recovery and
retirement to the affected socket. OpenSSH likewise keeps listeners across
accept errors and delays descriptor-exhaustion retries.

Retirement, client: `Listeners::accept` round-robins over its sockets and today
returns only the error. Return which socket failed, remove it, and report once
when a `-L` address has no sockets left. The SSH session, a running command, and
other forwards continue. Server: a `Group` tracks its remaining sockets and
releases its registration when none remain, so the key becomes reusable;
partial-family loss stays visible in the log, established relays stay alive,
and cancellation still waits for the listening sockets before replying. Do not
invent an unsolicited cancellation message; the protocol has none.

Tests: narrowly scoped error injection at the existing accept boundary. Cover
isolation, subsequent accepted traffic, healthy listeners accepting while another
socket is paused, prompt command completion and cancellation during a pause,
permanent-failure cleanup, partial-family failure, re-registration after total
loss, and cancellation during failure handling. Avoid a broad mock socket
abstraction.

### 5. Simplifications after correctness, before the final gate

Complete normal fork publication/dependency integration when needed to test these
changes with the repaired fork. The final gate in phase 6 waits until all code
changes are complete; dependency integration need not wait until phase 6.

S1: remove `relay_through` only if direct channel transport passes the existing
full-duplex, starved-window, jump, and cancellation regressions with the
repaired fork. If it stays, update its explanation with the remaining mechanism.
Report buffer-capacity savings separately from measured memory savings.

S2: share only small validation and binding mechanics with matching semantics.

S3 is done: the design lives in `docs/ssh-forwarding.md`, and
`docs/plans/russhd-forwarding.md` was deleted; its gate records and failure
evidence remain in git history.

S4 is done in phase 2. S5 history rewrites and S6 build/evidence cleanup need
separate authorization and are not part of these local fixes.

G1 OpenSSH-server interoperability and G2 native pressure remain the previously
agreed deferrals. G3 native Ctrl+C coverage is a follow-up item; do not claim
the Unix signal test establishes native behavior. New acceptance failures
discovered while fixing R1–R6 are recorded, not hidden behind those deferrals.

### 6. Final gate after all code changes

Follow the existing user-owned fork review and publication workflow. Prepare
reviewable local changes and evidence first. Commit creation is authorized;
publication is user-owned. Run the fork's own tests for its changes, and integrate
the published fork through the normal Cargo dependency/lockfile update. No
additional pin-specific suite or test runner is part of this work.

Per patch: focused fork and russhd tests, repository-toolchain formatting,
component clippy, and native builds. The final integrated gate starts only
after R1–R6, all chosen S1/S2 code changes, and dependency updates are finished:
three debug and three release main-image passes, then the complete
developer-image release gate. This validates the finished implementation.
Defer any remaining code simplification to separate work rather than changing
code after this gate and claiming the earlier passes cover it. Do not
reinterpret historical passes as validation of new code.

Use loopback/private moto-tap fixtures. Do not run the host's `sshd`, introduce
public-network dependencies, rerun a failure just to obtain a pass, or increase
timeouts. Diagnose and retain the original failure evidence before continuing.

## Decisions

1. **R1 is fixed by default, not by opt-in.** Credit-mode opens defer close
   acknowledgement from the moment the credit is installed. The two fork
   methods are Motor additions with two callers, both relays; an opt-in would
   add API for a policy no caller declines and keep a default no relay can use
   safely.
2. **Approved accept-error recovery.** Per-connection errors
   continue, exhaustion delays the affected socket's next accept by 100 ms,
   and permanent/unclassified errors retire that socket. Healthy listeners
   remain runnable. The user explicitly approved this ongoing exhaustion
   recovery under AGENTS.md note 1. No automatic test retries or timeout
   increases are authorized.
3. **Fork tests live in the fork.** The seven copies under
   `src/bin/russhd/tests` are removed in phase 2 and the one Motor-only case
   moves to the fork. The user rejected additional pin-specific test machinery;
   no replacement contract suite or fork-test runner is required. Motor
   regressions exercise Motor code only; no Motor end-to-end reproducer of
   the R1 race is added, because its ordering cannot
   be controlled from outside the process.
4. **One full gate, after everything.** Component tests gate each patch; the
   six main-image passes and the developer-image release gate follow all code
   changes, including chosen simplifications and dependency integration. The
   user confirmed this ordering. The original plan's design now lives in
   `docs/ssh-forwarding.md`; the plan itself is deleted.
