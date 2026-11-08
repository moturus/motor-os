# Combined russhd forwarding review

Date: 2026-11-07. Consolidates `russhd-forward-review-codex.md` and
`russhd-forward-review-claude.md`; this file replaces both individual reports.

## Scope and current status

Reviewed Motor OS branch `russhd` at `63c32d6d`, the
forwarding plan (since replaced by [docs/ssh-forwarding.md](../ssh-forwarding.md)), and the separate russh
repository at `build/russh-rebase/fork`, branch `motor-v0.65.1`, head `b45bd26`.
At review time the main lockfile pinned that fork revision. The fork had 28 commits above upstream
v0.65.1 (`b33092a`), including six replays of earlier server-window work.

The reviews used different main-repository ranges: 78 local commits after
`origin/russhd` (`f8f22e77`), versus 114 commits after `dev`/`origin/dev`
(`4fcde583`). Both counts are correct; they describe different scopes.

All findings are based on static inspection. No builds or tests were run during
either review or this consolidation. Historical validation results are taken from
the implementation record, not independently reproduced. Line references below
refer to the reviewed source snapshot.

The implementation needs substantial flow-control and lifecycle machinery, but
the history and documentation make it look larger than it is. Remaining close,
disconnect, and listener-error issues deserve attention before declaring the
feature complete. The original Claude report's broad conclusion that no data-loss
or deadlock issue exists is not adopted: it does not cover the sequences in
R1–R3 below.

Work has started with reconciliation, source tracing, and the documentation
corrections in R7–R8. The
[remediation plan](russhd-forwarding-review-fixes.md) proposes the code
work separately, including the external fork changes required by R1–R3.
The status table tracks the subsequent fixes; the finding descriptions retain
their original reviewed source snapshot.

| ID | Priority | Finding | Status |
| --- | --- | --- | --- |
| R1 | P1 | Outgoing close deferral starts after the peer can close | Published fork fix integrated at 3891276; final gate pending |
| R2 | P2 | Client protocol disconnect can block in final flush | Published fork fix integrated at 3891276; final gate pending |
| R3 | P2 | Server protocol disconnect retains resources until transport EOF | Published fork fix integrated at 3891276; final gate pending |
| R4 | P2 | Local accept error aborts the entire SSH connection | Approved policy implemented locally with recovery/isolation regressions; final gate pending |
| R5 | P2 | Remote accept error leaves a dead listener registered | Local recovery and registration cleanup with regressions ready; final gate pending |
| R6 | P2 | Rejected remote bind strings enter logs unsanitized | Fixed; rejected text omitted and setup/cancellation log regressions pass |
| R7 | P3 | User documentation says implemented `-R` is unsupported | Corrected in 85f39f3d; text reviewed |
| R8 | P3 | Crate documentation still describes completed publication as pending | Corrected in 85f39f3d against local release records |

## Findings and proposed acceptance criteria

### R1. Select outgoing close policy before exposing the channel open

Both outgoing APIs install application receive credit before transmitting the
open, but leave close deferral disabled: fork `russh/src/client/mod.rs:1741`
and `russh/src/server/session.rs:695`. Motor first enables it when the caller
enters `src/bin/russhd/src/forward.rs:30`.

A peer can send confirmation, payload, EOF, and close before the outgoing opener
resumes. Fork `russh/src/session.rs:330` then takes the immediate acknowledgement
path at line 349, completes the close state, and removes the channel parameters
while received payload remains in the application queue. If the peer disconnects
after receiving that acknowledgement, connection cancellation can discard the
payload before the local socket receives it. This is the failure class that
fork `3eb3ccd` and Motor `4aad569b` intended to prevent.

The Claude report correctly observes that queued bytes can still drain while the
SSH connection remains alive. That does not establish safety when the peer ends
the connection after the acknowledged close. This is a scheduling-dependent
code-inspection finding, not a newly reproduced loss.

Incoming forwards already set the flag before accepting their opens:
`src/bin/russhd/src/forward/open.rs:50` and
`src/bin/russhd/src/client/remote.rs:161`. Those calls are necessary. Merely
consolidating all three calls into the relay would reintroduce the incoming race.

**Acceptance:** select deferred acknowledgement in the session's outgoing-open
dispatch, before peer traffic can be processed. Preserve existing automatic-close
API behavior for callers that did not opt in. Cover both client `direct-tcpip`
and server `forwarded-tcpip`: hold the opener unpolled after dispatch, deliver
confirmation/data/close, assert no acknowledgement before downstream drain, then
allow peer disconnect after the acknowledgement and check complete delivery.
The existing `tests/channel_close_handshake.rs:129` enables deferral before
sending traffic and therefore misses this ordering.

### R2. Client disconnect cleanup must not depend on flushing a blocked peer

Fork `russh/src/client/mod.rs:1480` receives `SSH_MSG_DISCONNECT` and marks the
session disconnected, but the exit path unconditionally calls `flush_or_timeout`
at line 1622. With `inactivity_timeout: None`, a peer that sends disconnect while
our output is blocked and then stops reading can leave the client pending
indefinitely. Its handler remains alive; Motor's `Peer::wait_closed()` and
handler-owned cancellation do not complete. The final flush was introduced by
fork `a9d1a61`.

**Acceptance:** receiving protocol disconnect ends application ownership without
waiting to deliver queued output to the peer. Preserve orderly locally initiated
disconnect behavior. Add a blocked-writer/protocol-disconnect regression that
requires no peer read progress and observes handler/task cleanup. Do not mask
this with a new inactivity timeout.

### R3. Server disconnect cleanup must not wait for peer TCP EOF

Fork `russh/src/server/session.rs:943` breaks on protocol disconnect, but its
epilogue shuts down the writer and reads until transport EOF at lines 1074–1097.
Motor configures no inactivity timeout. A peer can send SSH disconnect and keep
its TCP connection open, retaining the handler and therefore forwarding listeners
and jobs. `src/bin/russhd/src/main.rs:855` cancels jobs when that handler drops.

This lifecycle problem predates the forwarding changes; forwarding increases the
resources it retains. It has been diagnosed, not repaired as unrelated cleanup.

**Acceptance:** logical SSH termination releases the handler and connection-owned
forwarding resources independently of a peer's transport shutdown. Cover remote
listeners and admitted jobs with protocol disconnect while the peer withholds
TCP EOF. Existing blocked-transport coverage exercises read EOF, which does not
establish this contract. Avoid an arbitrary timeout or a broader transport rewrite.

### R4. A local listener error aborts unrelated SSH work

`src/bin/russhd/src/client/session.rs:120` exits the forwarding loop on any
listener accept error. `run_ssh` then aborts the peer and route at lines 21–24,
ending a running command, shell, and other forwards too.

An accept failure can describe one incoming connection rather than a dead
listener. Motor's SDK dispatches individual accept-response errors without
necessarily marking the listener failed (`src/sys/lib/moto-sdk/src/io/net/tcp.rs:195`).
The local OpenSSH reference keeps the listener after accept errors
(`build/russh-rebase/openssh-reference/channels.c:2139`).

**Acceptance:** define recoverable and fatal accept-error behavior explicitly;
one listener failure should not automatically kill unrelated SSH work. Cover a
failed accept followed by valid traffic and cancellation during failure handling.
The original suggestion to unconditionally log and continue is insufficient:
persistent errors could spin and flood logs. No blanket retries or backoff are
approved by this review.

### R5. A remote listener can die while its registration remains active

`src/bin/russhd/src/forward/remote.rs:106` returns on every accept error, dropping
that listening socket. `Listeners.groups` retains its `Group` and completed task
handle. Re-registering the same key reports an existing registration; with two
families, one can disappear independently. The SSH connection and client-side
setup-success state remain alive.

**Acceptance:** distinguish a per-connection error from permanent listener loss;
keep the registration consistent with the remaining bound sockets. When a whole
group is gone, its key must become reusable. Preserve established relays and
cancel/rebind ordering. SSH provides no ordinary unsolicited response that
reverses an earlier successful `tcpip-forward`, so do not promise notification
that the protocol does not provide. Test recoverable failure, total failure,
partial-family failure, and cancellation. Resolve the shared error policy with R4.

### R6. Invalid remote bind addresses can forge or bloat daemon logs

Validation rejects control characters and overlong strings, but failure handlers
log the original address in `src/bin/russhd/src/main.rs:568` and `:586`.
An authenticated peer can supply newlines, terminal control sequences, or an
oversized value. This violates the plan's validated-host logging rule.

**Acceptance:** omit rejected addresses, or bound and escape them before logging.
Prefer omitting untrusted text over introducing a general logging abstraction.
Check both setup and cancellation paths, preserving useful operation/error context.

### R7. Remove obsolete claims that remote forwarding is unsupported

`docs/ssh-client.md:375` and
`img_files/motor-os-dev/devtools/www/commands.html:837` listed `-R` as unsupported
despite documenting it above. Both reviews identified this contradiction.

**Completed:** both copies now list only agent and X11 forwarding in that
unsupported-forwarding sentence. Reviewed the text changes; no tests were run.

### R8. Update the completed SDK publication record

`docs/crates.md` called `moto-sys 0.4.0` and `moto-sdk 0.2.0` prepared releases
and instructed the user to publish the SDK. The forwarding plan records their
publication from `70da7181` and `f8f22e77`, respectively; russhd's lockfile selects
both from the registry.

**Completed:** document publication, replace the obsolete pending publish step,
and use `moto-sdk = "0.2"` in the new-consumer example while retaining the explicit
allowance for existing `0.1` consumers. Verified against local records only;
no package publication or registry access was performed.

## Why there are so many changes

The 78-commit local range has the following source-file classification. Embedded
unit tests count as source changes; this is not a count of production-only work.

| Category | Commits |
| --- | ---: |
| Plan only | 19 |
| Tests, documentation, or configuration without implementation changes | 28 |
| Dependency pins with regression tests | 4 |
| Source-file changes, including embedded unit tests | 27 |
| Total | 78 |

That diff adds 9,153 lines across 59 files: 4,802 in dedicated tests, 3,477 in
source files that also contain unit tests, 865 in docs/configuration, and nine
dependency lines. The earlier report's 114-commit classification and its
"production lines" totals used another base and different treatment of tests;
they should not be combined with these numbers or interpreted as equivalent.
The fork has six replay commits, not nearly half its 28 commits.

Reasons for necessary size:

1. The feature includes server direct forwarding and remote listeners, client
   `-L`, `-D`, `-R`, `-N`, SOCKS4/4a/5, configuration, authorization, cancellation,
   and host/guest coverage. It is much more than one socket-copy loop.
2. Russh required application-controlled receive credit, dispatch that does not
   stall unrelated channels, closed-channel cleanup, correct canceled-open
   ownership, and concurrent transport reads/writes. A plain
   `copy_bidirectional` would inherit those library problems.
3. The repository requests small patches including tests. Approximately
   100–300-line patches naturally produce many commits for this scope.
4. The broader branch includes prerequisites and unrelated repairs: the rebase,
   compression/window work, login grace, SDK publication for pressure APIs,
   Wasm fixture/log-polling and gate-budget changes, an OOM test race, and an
   imager clippy correction. These are not all forwarding implementation.

Avoidable costs include per-gate plan commits, late discovery of close and
transport contracts, and fixture mistakes involving ports, paths, and teardown.
The outgoing-open cancellation change broke valid callback-managed opens and
needed fork `88e1181`. Main commits `618ff767` and `9dde1eea` have behavioral
titles but only change tests. Required repeated image gates explain elapsed work
and evidence, but not a need for a permanent commit per progress update.

## Simplification backlog

| ID | Opportunity | Disposition |
| --- | --- | --- |
| S1 | Remove obsolete jump buffering if current transport makes it unnecessary | Removed locally; component regressions pass with the repaired fork; final gate pending |
| S2 | Share small host-validation and bind-loop mechanics | Host grammar shared locally; binding policies remain explicit |
| S3 | Separate current design from implementation journal | Complete; design is in docs/ssh-forwarding.md and historical gate evidence remains in Git |
| S4 | Reduce copied test fixtures | Seven copies removed locally; unique legacy-open case moved to the fork |
| S5 | Squash bookkeeping and fixup commits | Recommendation for merge preparation; no history rewrite authorized |
| S6 | Clean large ignored build/evidence directory | Inventory and retention decision first; no deletion authorized |

**S1:** `src/bin/russhd/src/client/transport.rs:464` documents a jump-buffer
workaround for the transport flush deadlock subsequently repaired in the fork.
Its duplex pipe allows roughly 8.1 MiB of aggregate buffering per jump at default
settings, plus a detached copy task. This is a buffer limit, not a claim that all
of it is resident immediately. Try direct channel transport only with the
existing full-duplex, starved-window, multi-hop, and cancellation regressions.
Removing it is a hypothesis, not a proven safe deletion.

The local simplification now uses direct channel transport with the repaired
fork. The existing component tests cover full-duplex transfers, starved windows,
jumps, and cancellation. Removing the duplex pipe removes 8.125 MiB of aggregate
buffer capacity and its copy task per jump at default settings; resident-memory
savings have not been measured. Published dependency integration and the final
image gate remain pending.

**S2:** hostname checks in `client/forward_args.rs:147` and `forward/open.rs:8`,
and the bind loops in `client/forwarding.rs:147` and `forward/remote.rs:189`,
overlap. Share mechanics only if a small helper reduces code. Local resolution,
remote GatewayPorts policy, validation limits, and partial-success reporting
must remain explicit. Avoid a general listener framework.

The matching hostname grammar and 255-byte limit now share a helper. The binding
loops stay separate: local name resolution and remote family selection, together
with their diagnostics, do not benefit from a more general binding abstraction.

**S3:** the plan has 2,452 lines, with Goal and scope beginning at line 1,662.
Keep a concise design/decision document and move history to a tracked archive,
retaining failure diagnoses, gate records, publication provenance, and links.
Do not replace the only durable record with an ignored build directory.

**S4:** approximately 1,600 test lines are duplicated or nearly duplicated:

| Fork test under `russh/tests` | Main test under `src/bin/russhd/tests` |
| --- | --- |
| `test_channel_close.rs` | `channel_close.rs` |
| `test_channel_close_handshake.rs` | `channel_close_handshake.rs` |
| `test_client_callback_open.rs` | `client_callback_open.rs` |
| `test_client_open_credit.rs` | `client_open_credit.rs` |
| `test_server_open_credit.rs` | `server_open_credit.rs` |
| `test_transport_backpressure.rs` | `transport_backpressure.rs` |
| `test_transport_stalls.rs` | `transport_stalls.rs` |

The original comparison found exact copies for close, backpressure, and stalls,
and small differences in the others. The fixes plan supersedes the original
replacement-gate recommendation: fork tests stay in the fork, without a new
pin-specific suite or runner. The seven Motor copies are removed locally, and
`refusal_after_a_legacy_open_is_cancelled_keeps_the_transport_alive` moves to
`russh/tests/test_server_open_credit.rs`. Motor retains its relay and end-to-end
tests through `full-test.sh`.

**S5–S6:** the original Claude report suggested 20–25 logical commits and
reported 104 GB/886 entries under `build/russh-rebase`. These are a history-cleanup
proposal and a reported local artifact inventory, respectively, not product
requirements or newly measured figures. Preserve the fork repository, original
failures, and publication mapping before any later cleanup. This consolidation
replaces the two superseded review files; no ignored-artifact cleanup is included.

Keep the shared bounded relay, task reservations/cancellation, login supervisor,
and client remote-forward authorization/setup barrier. These encode necessary
contracts; simplifying them away would weaken correctness or security. Keep the
pre-accept close-deferral calls until an API guarantees that same ordering.

## Coverage gaps and accepted limitations

- **G1: OpenSSH server interoperability.** OpenSSH clients against russhd and
  offline `ssh -G` comparisons do not establish Motor-client interoperability
  with OpenSSH's server. The existing plan defers this and forbids tests using
  the host's `sshd`. Any future test environment needs a separate approved plan.
- **G2: native memory pressure.** Injected host tests establish branch behavior,
  not real Motor pressure shedding and recovery. Native coverage is explicitly
  deferred; the approved 16,384-forward ceiling is not per-session isolation.
- **G3: native Ctrl+C.** Host lifetime tests use Unix `SIGINT`; Motor uses a
  separate registration/wait implementation. Native cancellation needs coverage.
- **G4: final integration.** Local regressions now cover R1–R5's scheduling,
  disconnect, and post-registration accept failures. Published dependency
  integration and the final image gates remain pending.

Two confirmed policy differences from the checked-in OpenSSH reference remain:
oversized channel packets produce a fork protocol error rather than OpenSSH's
log-and-discard behavior (`channels.c:3630`); extended data on a forwarding
channel ends Motor's relay, whereas OpenSSH ignores inappropriate extended data
on a forwarding channel before EOF (`channels.c:3691`). Neither establishes a
failure with a conforming peer. Do not relax these policies without a concrete
compatibility requirement; extended data after EOF has separate OpenSSH rules.

Shipped images enable forwarding and include test credentials. Credential
replacement warnings must remain prominent. This was an approved deployment
choice, not an instruction to disable forwarding now. Boolean server policies,
omitted modes, the count policy, and accepted coupling to blocked shell output
are deliberate limitations, distinct from the bugs above.

The Claude report overstates host bind warnings: IPv4/IPv6 wildcard binds can
overlap on Linux, but the default `127.0.0.1` and `::1` loopback binds are distinct.
Do not suppress all partial-family warnings or change implicit loopback behavior
based on that claim. The plan already documents the wildcard difference.

## Next work

R7 and R8 are documentation-only corrections in 85f39f3d. The remediation plan
is approved; update R1–R6 with their implementation patches, validation, and any
unresolved limitations. Simplifications and deferred coverage are separate work
items, not grounds to discard existing guarantees.
