# TCP forwarding in russhd and ssh

Status: v5, stopped for review after diagnosing step 1's debug-gate timeout.
The approved external compression fix is committed and tested. No forwarding code
has changed.
See "Implementation progress" below and "Decisions" at the end.

## Implementation progress

The implementation request requires three complete debug and three complete release
`full-test.sh` passes per milestone, superseding the lighter milestone gates below.
Developer-image validation remains release-only.

| Step | Progress | Remaining |
|---|---|---|
| 1 | 224 MiB matrix removal `dd716bf4` and complete-line wait fix `0f419641` committed; debug gate timed out after 1,500 s; phase-timing diagnosis complete (see below) | Review existing gate runtime; main-image gates: 0/3 debug, 0/3 release; complete `full-test-dev.sh --release` |
| 2 | Baseline preparation; external test signature fix `ac0e947` and approved compression fix `4fe78f9` committed; full fork suite passes; main-repo compression regression added | External russh close fixes and tests, pin, relay, direct opens, configuration, authentication deadline, milestone gates |
| 3 | Not started | Guest coverage, shipped configuration, docs, main/developer-image gates |
| 4 | Not started | External russh client credit, dispatch and handoff tests, pin, main-repo contract tests, milestone gates |
| 5 | Not started | Client options, connection lifetime, `-L`/`-N` integration and guest coverage, milestone gates |
| 6 | Not started | SOCKS parser, `-D` integration and guest coverage, milestone gates |
| 7 | Not started | Server remote listeners, credit handoff, `gateway_ports`, host/guest coverage, milestone gates |
| 8 | Not started | Client remote-forward authorization and ordering, `-R` integration and guest coverage, milestone gates |

Step 1 focused checks: `cargo test` for `wasm-smoke-suite` (two tests),
`test-wasm-selection.sh`, `test-full-test-size.sh`, and `test-dev-memory-contract.sh`
pass. The regression checks every partial snapshot of an address diagnostic, including
a complete-looking address without its terminating newline.

### Resolved stop: external russh baseline (2026-11-03)

The external checkout is `/tmp/motor-russh-forwarding`, branch `server-window`, based
on `042db50`. No changes were made to the Cargo cache checkout. The first baseline
test build failed because `test_manual_receive_window.rs` still implemented
`check_server_key(&PublicKey)` instead of the trait's `&PublicKeyOrCertificate`.
AGENTS.md permits a small, obvious test-only correction; external commit
`ac0e9479fa60120b2a09093bb704bc7b0ec7eac0` fixes it. Its four receive-window tests
pass. A portable copy of this commit is saved at
`build/forwarding-validation/russh-receive-window-test-fix.patch`. Nothing was pushed.

After that correction, the baseline library tests reported **186 passed, 1 failed**:
`compression::tests::partial_flush_packets_round_trip`. The freshly resolved
dependencies include `flate2 1.1.10` and `miniz_oxide 0.9.1`. Packet 2455 contains
2,455 uncompressed bytes but returns only 2,371. Running that existing test alone
reproduces the failure, ruling out interference from concurrent tests.

Temporary instrumentation showed that all 33 compressed bytes were consumed, but
84 decoded bytes remained buffered. Calling the decoder again with empty input
recovered exactly those 84 bytes. `Decompress::decompress` in the external
`russh/src/compression.rs` stops when input is consumed and the output buffer is
not full; that condition does not establish that this decoder has drained its
output. This is a production compression-path compatibility defect, not an
incorrect assertion in the test. The same existing test passes with Motor's
currently pinned `flate2 1.1.1` and `miniz_oxide 0.8.8`; no failure of that pinned
combination was observed. The dependency comparison is diagnostic evidence, not
a dependency downgrade adopted to bypass the failure.

Reproduce the original failing configuration from the external checkout, using
`build/forwarding-validation/russh-baseline.Cargo.lock` as its `Cargo.lock`:

```sh
RUSTUP_TOOLCHAIN=x86_64-unknown-motor-1.99.1 cargo test --offline -p russh \
  --no-default-features --features flate2,ring,rsa --lib \
  compression::tests::partial_flush_packets_round_trip -- --exact --nocapture
```

Evidence is retained in `build/forwarding-validation/`:
`russh-baseline-build-online.log` (original test compile failure),
`russh-baseline-test.log` (original library failure),
`russh-compression-diagnostic.log` (isolated failure),
`russh-compression-instrumented.log` (buffered-byte diagnosis),
`russh-compression-shipped-deps.log` (pinned-version comparison), and
`russh-receive-window-test.log` (four passing tests after diagnostic removal).
Both diagnostic lockfiles are saved there. At this stop, all temporary
instrumentation had been removed, the external checkout was clean, and its
original dependency set was restored. The main repository's russh pin is unchanged.

The first main-image debug gate was deliberately stopped during preparation
(exit 143), as required by the preexisting-bug stop rule; its log is
`build/forwarding-validation/step1-debug-1.log`. It did not reach the timed tests,
and no main-image pass is claimed. Release and developer-image gates have not run.
No milestone is newly declared complete. Review and authorization for this
additional external-fork compression work were requested before resuming.

The user subsequently approved fixing this defect and resuming implementation.
External commit `4fe78f985942d5b271ebb29d2aa34052a118f487` makes the decompressor
continue until neither input nor output advances, including calls with empty
input. Its output-size bound is unchanged. All six compression tests pass with
both dependency sets, including new partial-flush packet-limit and next-packet
checks. The full fork suite passes: 219 tests, plus eight preexisting ignored
documentation examples. Logs are `russh-compression-fixed.log`,
`russh-compression-full-suite.log`, and `russh-compression-fixed-shipped-deps.log`;
the commit is also saved as `russh-compression-fix.patch` in the evidence directory.
Main commit `d80f90b5` adds `src/bin/russhd/tests/compression.rs`, which passes and
runs transitively from `full-test.sh`. It covers changing packet sizes on the
wire compression path. Its log is `main-compression-regression.log`.

### Current stop: main-image debug gate runtime (2026-11-03)

The resumed main-image debug gate (`step1-debug-2.log`) exited 124 after its
existing 1,500-second test budget expired during stdio-route checks. The TUI,
credential, alternate-VMM boot, Motor SSH client, DNS integration, and complete
`systest` phases had passed. The guest was still progressing through route
checks just before expiry; no assertion or panic preceded the timeout. The
original guest logs are preserved in `step1-debug-2-evidence/` beside that log.
The new main-repo compression regression passed in 0.83 seconds in that run.

A diagnostic run (`step1-debug-timing.log`) added temporary top-level Bash
timestamps (`step1-debug-timing.trace`) to measure phase costs. It reproduced
steady progress without an assertion failure. Measured phases included:

| Existing phase | Seconds |
|---|---:|
| Analyzer checks | 11 |
| vsock checks | 33 |
| HTTP host acceptance | 34 |
| System TTY | 26 |
| TUI | 38 |
| Terminal size | 243 |
| Credential/key installation | 210 |
| All work before launching the main guest, including the other host checks | 696 |

In the original failing run, the main guest had reached about 801 seconds of
uptime and was still advancing when the outer deadline expired. Combined with
the measured 696 seconds before the main guest starts, that leaves essentially
no budget for the remaining checks. The stdio-route checks immediately before
expiry advanced through group, loop, function, and pipeline cases in seconds;
the evidence supports a whole-suite runtime overrun, rather than a stalled
stdio case. No specific production component failure was observed.

The diagnostic run was deliberately stopped after collecting the pre-guest
timings (exit 143), before repeating the long system-test phase. It is not a
retry to obtain a passing result and does not count toward the milestone gate.
Its guest console and a copy of the tracing hook are retained under
`step1-debug-timing-evidence/`; the active temporary hook in `/tmp` was removed.
No test processes or diagnostic VM remain running. No timeout, assertion,
coverage requirement, or production configuration was changed.

AGENTS.md requires review for non-obvious decisions. Repairing this existing
gate's runtime while preserving its timeout and coverage needs separate scope
guidance; silently increasing the timeout, omitting checks, or repeating runs
until one fits would violate the stated constraints. Forwarding work stops
here pending that guidance. The 3+3 main-image gate and developer-image release
gate remain outstanding; the main repository's russh pin is still unchanged.

## Goal and scope

`russhd` refuses every forwarding request, and the Motor `ssh` client rejects `-L`, `-R`,
and `-D`. A Motor OS server cannot be a jump host or the far end of a tunnel, and a Motor
OS client cannot open one. Commit `0355fc70` also removed the only test that moved data
through a jump from a Motor guest, because it needed the host's `sshd`, which is off
limits. This plan adds forwarding at both ends and restores that coverage against
`russhd` itself.

Implement these milestones in order, each in small patches of about 100–300 lines including
tests. A milestone is not a single patch; each patch must leave existing tests passing.

| Step | Work | Gives |
|---|---|---|
| 1 | Remove Wasm tests on 224 MiB VMs; retain both images at 256 MiB | A developer-image gate with no known-failure exception |
| 2 | **russh fork:** channel-close fixes, then `russhd`: local forwarding (`direct-tcpip`) | `ProxyJump`, `-L`, `-D`, and `-W` from OpenSSH clients |
| 3 | Enable shipped forwarding, update guest tests and docs | The coverage `0355fc70` removed |
| 4 | **russh fork:** receive credit in the client | The base for steps 5, 6, and 8 |
| 5 | `ssh`: `-L` and `-N` | Local tunnels from Motor OS |
| 6 | `ssh`: `-D` | A SOCKS proxy on Motor OS |
| 7 | `russhd`: remote forwarding (`tcpip-forward`) | `-R` from OpenSSH clients |
| 8 | `ssh`: `-R` | Remote tunnels from Motor OS |

Step 7 comes before step 8 because `russhd` is the only real server these tests may use.

Out of scope: `ssh -f`, `-W`, and `-R` with no target; Unix-socket, X11, and agent
forwarding; connection sharing and the `~C` command line; per-key or per-destination policy;
several session channels per connection; OpenSSH's `GatewayPorts clientspecified`.

## What russh already provides

The protocol is done at both ends. `russhd` pins `moturus/russh`, branch `server-window`,
commit `042db50`: v0.63.1 plus six receive-window commits. `russhd` overrides none of the
server side, so russh's default drops the reply, and clients see
`AdministrativelyProhibited`.

| Need | russh |
|---|---|
| Server: open a forward | `Handler::channel_open_direct_tcpip`, given the host, port, and a `ChannelOpenHandle` |
| Reply after connecting | `accept` and `reject` only queue a message, so a spawned task can call them later |
| Failure reasons | `ConnectFailed`, `ResourceShortage`, `AdministrativelyProhibited` |
| Server: receive flow control | `Session::receive_credit`, during the open callback: window credit returns only when the application reports bytes consumed |
| Window-aware sending | `Channel::make_writer`, which waits for the peer's window |
| Server: remote forwarding | `Handler::tcpip_forward`, `cancel_tcpip_forward`, `Handle::channel_open_forwarded_tcpip` |
| Client: open a forward | `Handle::channel_open_direct_tcpip`, already used for `ProxyJump` |
| Client: remote forwarding | `Handle::tcpip_forward`, `cancel_tcpip_forward`, `Handler::server_channel_open_forwarded_tcpip` |

**Two areas need changes to the russh fork.** Step 2 starts with fixes for channel-close
leaks and stalls; see "Constraints". Step 4 adds receive flow control to the client, and
steps 5, 6, and 8 depend on it. Credit handoff for locally opened channels needs validation
at both ends; see steps 4 and 7. Any further fork change must be proposed explicitly first.
All such changes are outside the main Motor OS repository and must be identified separately
in patch reviews.

## Constraints

The work is not the protocol but keeping one forward from stalling a connection. A plain
`copy_bidirectional` on `channel.into_stream()` would pass a simple test and then hang in
use. All of a connection's channels share one session loop, at both ends.

**Server, inbound.** Each channel has a queue of 100 messages. When it fills, russh parks
that packet and stops reading the socket for the whole connection
(`pending_channel_data`). The window limits bytes, not packets, so small packets to a
target that is not reading fill the queue long before the window runs out. Every channel
then stops receiving, including the `WINDOW_ADJUST` that a target blocked in a write needs
to make progress. That is a deadlock, the same shape as the one `relay_through` fixed.

The advertised window is not a strict delivery bound in the pinned fork:
`consume_receive_window` tolerates some ordinary data beyond it, with a nominal overrun
allowance of one tenth of the window. A relay must keep receiving channel events even
when its byte queue is full, and close that forward on overflow. Simply copying
`StdinQueue`'s capacity-gated reads would leave this case unhandled.

**Outbound, both ends.** `Handle::data` does not wait for the peer's window. Data past it
parks in `pending_data`, and the session stops taking application messages, for every
channel, until that window reopens. Reads continue, so window adjustments can still arrive,
but it couples channels.

**Client, inbound.** This is worse, and only russh can fix it. `adjust_window_size` refills
the window when data arrives, not when the application consumes it, so the window does not
bound what the application has yet to read. Data reaches a channel through
`chan.send(...).await` inside the session loop, so a full queue stops the loop outright:
nothing is read or written for any channel. One slow local application freezes the
connection, and if it is blocked writing into the tunnel, it deadlocks, because those bytes
need the same loop. A relay cannot avoid this today: if it stops reading, the loop freezes,
and if it keeps reading, it buffers without limit, because the server can always send more.

**Both ends assume one channel.**

- `ConnectionHandler::data` disconnects when there is no shell session, which is a jump
  host's normal state. `channel_eof` takes `stdin_tx` without checking the channel, so EOF
  on a forward would close a running shell's stdin.
- `transport::Handler::channel_close` disconnects the whole connection when any channel
  closes. The first forwarded connection to finish would end the tunnel and any shell on it.
- `run_ssh` runs one `run_channel`, and refuses to run with neither a command nor a terminal.

**Closed channels leak, at both ends.** With no pending outbound data, `Encrypted::close`
removes a channel from `enc.channels`. The peer's `CHANNEL_CLOSE` reply then fails
`is_established_channel` and returns early, so `Session::channels` keeps its `ChannelRef`
and queue until the connection ends. That is harmless with about one channel per connection,
but not with forwards. On Linux, 102,000 open/close cycles kept all 102,000 entries:
329 MiB, about 3.4 KiB per close, whichever side closed first. The forward limit does not
bound this, because closing releases the permit. `Session::channels` is private, and two
relays cannot each wait for the other to close first, so the fix has to go in russh.
Removing the entry only when the peer replies is insufficient: a peer can keep its
transport alive and never acknowledge local closes, accumulating the same retained queues
while the application admits replacement forwards. With such a peer, that approach kept all
12,000 entries of a test run.

**Peer close can leave the whole connection stalled.** With pending outbound data,
`Encrypted::close` only sets `pending_close`. Both incoming `CHANNEL_CLOSE` handlers call
it, so a peer that closes with its receive window at zero can leave `pending_data` in
`enc.channels` forever. No further window adjustment is required from that peer, yet
`has_any_pending_data()` continues to block ordinary application messages for all channels.
Forward writers avoid this queue, but shells still use `Handle::data`, so this path must
be fixed before sharing a connection with forwards. It reproduces at both ends on Linux: the
client can no longer open a channel, and the server stops delivering EOF on other channels.

**Memory.** Both programs run on one thread with a current-thread runtime. A failed
allocation aborts the process, and a refused page kills the faulting thread
(`docs/oom-handling.md`). A backlog that grows under memory pressure can end every session
on `russhd`, including the operator's way in.

## Server design

A new `src/bin/russhd/src/forward.rs` runs each forward as its own task. Forwards use none
of `ConnectionHandler`'s session state, so the one-session rule stays as it is.
The connection owns their cancellation and reaps completed tasks. Dropping its handler or
losing the transport cancels all pending opens, relays, and listeners; completed task
records must not accumulate on a long-lived connection.

### The russh changes (step 2)

In the **external `moturus/russh` fork**, branch `server-window`, fix both client and server
close paths. About 15 lines did this on a scratch copy:

- **Peer close:** add `Encrypted::close_from_peer` in `session.rs`, and use it in place of
  `close` in both incoming `CHANNEL_CLOSE` handlers. It discards unsent outbound
  `pending_data` and its deferred EOF/close state, sends the close reply without waiting for
  window credit, and removes the channel from `enc.channels`. `has_any_pending_data()` then
  stops counting it, so other channels resume. Deliver `ChannelMsg::Close` after previously
  received data. Discarding unsent outbound data must not discard the relay's received bytes
  waiting to reach its local socket; those still drain under the relay rules below.
- **Local close:** `Session::close`, at both ends, also removes the `ChannelRef` from
  `Session::channels`, at once and without waiting for the peer's reply. `Encrypted::close`
  stays as it is, so packets keep their order while outbound data is still being flushed; a
  peer close during that flush takes the immediate-discard path above. Window adjustments
  already tolerate the missing entry. Removing it also ends the local `Channel::wait()`,
  which today never returns after a local close. Clean up pending delivery and credit
  handoff records too.
- **No closing records:** nothing about a channel outlives its local close. russh already
  removes it from `enc.channels` there and ignores a later reply, so a peer that never
  replies costs nothing, and a permit is released when its relay ends. Channel IDs come from
  a wrapping 32-bit counter: reuse takes about 4 billion opens on one connection, and a clash
  then needs a peer that withheld its reply for all of them.
- **Pending opens:** the handlers' early return stays, so a peer's `CHANNEL_CLOSE` cannot
  remove a locally initiated channel waiting for confirmation. Rejection, abandoned opens,
  and disconnect still release their state.

On that Linux scratch copy, these changes kept no closed channels and no memory growth over
102,000 cycles with either side closing first, kept none over 12,000 closes to a peer that
never replied, and cleared the stall at both ends. russh's own test suite could not be built
offline there, so run it first. Add the regressions in "Acceptance", split these changes
into small patches, then update the main repository's pin with `cargo update -p russh`.

### Opening

`channel_open_direct_tcpip` does no network work, so the session loop keeps running:

1. Without `allow_tcp_forwarding`, drop the reply: `AdministrativelyProhibited`.
2. Reject a port above 65535 with `AdministrativelyProhibited`, as OpenSSH does, and a port
   of 0 or a host that fails validation with `ConnectFailed`.
3. Reject with `ResourceShortage` past the limit below, or under `memory_pressure()`.
4. Take a permit and `session.receive_credit(channel.id())`, register the task with its
   connection's cancellation signal, and return.

The task resolves and connects using `tokio::net::lookup_host`, which keeps the blocking
resolver off the loop, and tries each address in order. It adds no timeout of its own, as in
OpenSSH: sys-io gives up on a connect after 123 s (`DEFAULT_CONNECT_TIMEOUT`, six SYN
retransmissions, as on Linux). It sets `nodelay`, then calls `accept`, or `reject` with
`ConnectFailed`. Resolution, connection attempts, and reply completion are cancellable:
after disconnect there must be no later dial or acceptance. Dropping a `lookup_host`
future cannot stop an already-running blocking resolver call; discard its result without
keeping a socket or the connection alive. That worker may finish in the background.

### Relaying

One function, generic over `Channel<S>`, serves both ends. Give it the receive-window bound
and connection cancellation signal along with the channel, socket, and credit. Both ends
currently advertise 2 MiB; derive the bound from the same setting as the advertised window.

- **Channel to socket.** Consume `ChannelMsg` events through `ChannelReadHalf::wait()`,
  keeping that receive branch enabled even at the byte limit and after EOF. Copy data into
  a bounded byte queue and report `credit.consumed` only for bytes written to the socket.
  Empty data is not EOF. Overflow, data after EOF, or unsupported extended data ends that
  forward without a panic or more buffering. Do not retain one allocation per SSH packet.
- **Socket to channel.** Read the socket and write through `make_writer()`, avoiding
  `pending_data` for the forward. A pending write must not prevent channel-event handling
  or cancellation. Preserve any in-progress write until it completes or the relay ends.
- **Half-close.** Channel EOF shuts down the socket's write side after queued bytes drain.
  Socket EOF sends channel EOF after its outstanding write completes. The other direction
  continues. When both directions drain, send channel close and release the socket, without
  waiting for the peer's reply.
- **Peer close.** `ChannelMsg::Close` stops socket-to-channel at once. Queued bytes still go
  to the socket, as after EOF, and then the relay ends.
  [RFC 4254 §5.3](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.3) recommends
  delivering them, and OpenSSH does (`CHAN_OUTPUT_WAIT_DRAIN`). As in OpenSSH, this drain
  has no time limit, so a target that stops reading keeps its forward and permit. The
  receiver ending right after `Close` is normal, not a failure.
- **Abort.** Channel receiver termination without `Close`, connection cancellation, or an I/O
  error ends both directions immediately and releases the socket and permit. Observe these
  independently of socket writes and window waits. `make_reader()` loses the distinction
  between EOF and receiver termination, and a window-blocked writer need not wake on
  transport loss; neither is a substitute for cancellation. Cleanup must not wait
  indefinitely to send EOF or close over a dead connection.

Shells keep using `Handle::data`. A client that stops reading shell output can therefore
pause forwards on that connection until it resumes or closes the shell channel. This
coupling is accepted; changing the terminal output path is outside this plan.

### Limits

Retain the approved 16,384-forward ceiling and no smaller Motor-specific count cap.

- **Count.** Up to 16,384 forwards per connection, OpenSSH's `CHANNELS_MAX_CHANNELS`, and no
  limit per server. Past that, refuse with `ResourceShortage`, where OpenSSH ends the
  connection. Forwards to one device also need sys-io's 16,384 ephemeral ports. Keep the
  count in a per-connection `Semaphore`, with permits owned by the task: connecting forwards
  count, and every exit releases them. Acquire permits without waiting, before spawning;
  do not accumulate tasks waiting for permits. The same budget covers `-L`, `-D`, and `-R`
  connections, including SOCKS handshakes and remote-channel opens. Do not rely on
  `Handler::channel_close`: russh does not deliver closes that `russhd` starts.
- **Memory** is the real ceiling, as on Linux. Every forward's socket reserves sys-io buffers
  from the moment it opens: 256 KiB, or 128 KiB below 256 MiB of RAM and 64 KiB below 128 MiB
  (`docs/networking.md`). Queued payload is bounded by the receive window. Coalesce it into
  lazily allocated 32 KiB blocks, with at most `ceil(window / block_size) + 1` blocks to
  account for partially used ends. Keep block bookkeeping bounded too. Sending and the
  russh queues add bounded buffers that must be included in measurements.
- **Memory pressure** is not a count, and acts only when about 2 MiB remain. Then
  `memory_pressure()` refuses new forwards, and a relay whose queue would have to grow ends
  that forward. Check before each new block, use fallible allocation where available, and
  release drained blocks. Avoid geometrically growing a contiguous backlog: a 1-to-2 MiB
  reallocation can need both allocations at once, exceeding the margin after the check.
  sys-io also refuses outbound connects during pressure, reported as `ConnectFailed`.

Pressure shedding is best effort, not a guarantee that other sessions survive arbitrary
system-wide exhaustion. The flag is not a reservation, and fallible allocation cannot
recover from a refused lazy page fault (`docs/oom-handling.md`). Unlike a process per
connection, russhd's single process shares this risk across all sessions. A guest test of
this behaviour is deferred; see "Deferred: guest pressure test" under "Acceptance". This
adds no boot-time work.

### Configuration

`sshd.toml` gains an optional `allow_tcp_forwarding = true`, the counterpart of OpenSSH's
`AllowTcpForwarding`. It governs both directions, so step 7 must honor it too. OpenSSH
defaults to yes and also takes `local` and `remote`; here a boolean is enough, and absent
means off. Step 2 leaves shipped configs and existing guest fixtures off. Step 3 enables
both shipped configs, so shipped images then match OpenSSH's default, while a custom config
has to opt in. The version stays 2.

Step 7 adds an optional `gateway_ports = true`, the counterpart of OpenSSH's
`GatewayPorts yes`: remote listeners bind every address, whatever the client asked for.
Absent means off, which is OpenSSH's default, and both shipped configs leave it off.
OpenSSH's `clientspecified` is left out: it would have to resolve client-supplied names, and
`tcpip_forward` replies from inside the session loop, so a slow lookup would stall the
connection.

`src/imager/src/set/bare_toml.rs` must list each field in `SERVICE_FIELDS` **in the patch
that adds it**: imager refuses any field it does not list, so otherwise `imager set` would
fail on every image that sets it. Its parser already accepts booleans.
`write_ssh_client_host_config` and any fixture that forwards need `allow_tcp_forwarding` too.
Enable those fixtures in the same patch that replaces their old forwarding-refusal
assertions; there must be no broken-suite interval.

### Handler changes

`data` and `channel_eof` return at once when the channel is not `active_channel`: any other
established channel is a forward, whose task reads it directly. `channel_close` already
checks. The relay observes its own close events, so these callbacks need no set of forward
IDs. Connection-wide cancellation is separate. Update the "one channel at a time" comment
on `ConnectionHandler`.

### Authentication and idle connections

Authenticated tunnels and shells should have no application inactivity timeout. However,
russh also uses the current one-hour `inactivity_timeout` while reading the client's SSH
identification and before authentication. Removing it alone would let a live TCP peer
occupy resources indefinitely without logging in. TCP keepalive only detects dead peers.

In the same patch that sets `inactivity_timeout` to `None`, add a 120 s deadline from TCP
accept through successful authentication, following OpenSSH's
[`LoginGraceTime`](https://man.openbsd.org/sshd_config#LoginGraceTime). Use connection-local
deadline state and the transport-wrapper pattern already used by the client. Clear it only
on authentication completed before the deadline. Expiry must terminate the actual russh
session and transport; dropping a `RunningSession` join wrapper alone is insufficient.
After authentication, sys-io's 20 s keepalive and 300 s timeout detect dead TCP peers.
Test silent identification, stalled authentication, and authenticated idle connections
with a controlled clock; do not add a wall-clock wait of minutes to the suite.

## Client design

### The russh change (step 4)

In `moturus/russh`, branch `server-window`, give the client what the server has:

- Use `consume_receive_window` and `refill_receive_window` in its data paths in place of
  `adjust_window_size`. This also brings the server's window validation to the client.
- Add the credit event to the client session loop, and `client::Session::receive_credit`.
- Stop `chan.send(...).await` from blocking the loop, as `f261f84` did for the server.
- Let a channel enter credit mode before its first data packet.
  `server_channel_open_forwarded_tcpip` has `&mut Session`, but that is not enough yet: the
  client keeps a server-opened channel's parameters in `PendingChannelOpen` until the reply,
  so they are not in `enc.channels` during the callback. Insert them before the callback,
  unconfirmed, and remove them on rejection or an abandoned open, as `8dcf301` did for the
  server. For client-initiated opens, identify forwarding channels at request time and
  arrange the credit handoff before data dispatch. Do not infer their type from which
  waiting task resumes first. Prefer an explicit opt-in when opening the channel over a
  permanent registry of all confirmations. Any temporary handoff keyed by channel ID must be
  cleared on success, refusal, cancellation, and disconnect, including a late confirmation
  after cancellation.

The accounting is shared in `session.rs` and `lib_inner.rs`; reuse it, modelled on
`49428c4` and `f261f84`. Split accounting, nonblocking dispatch, and credit handoff into
reviewable patches with tests. Channels left in automatic mode retain their current
policy. The relay still enforces its own byte bound despite russh's overrun tolerance.
Then `cargo update -p russh`: only `src/bin/russhd/Cargo.lock` pins it. `rust.html` says
russh tracks its default branch, so correct that here too.

### Options

| Option | Setting | Meaning |
|---|---|---|
| `-L [bind:]port:host:hostport` | `LocalForward` | Listen here; the server connects to `host` |
| `-R [bind:]port:host:hostport` | `RemoteForward` | The server listens; connect to `host` from here |
| `-D [bind:]port` | `DynamicForward` | Listen here as a SOCKS proxy |
| `-N` | | Run no command or shell |
| `-g` | `GatewayPorts` | Listen on all interfaces by default |
| | `ExitOnForwardFailure` | Exit 255 if a forward cannot be set up |

The command-line flags belong in `parse_ssh`, not `parse_common`. Share endpoint parsing,
including bracketed IPv6 and `*`, but account for the different configuration syntax:
`LocalForward [bind:]port host:hostport` and `RemoteForward [bind:]port host:hostport` take
two arguments; `DynamicForward [bind:]port` takes one. Update the config parser's current
one-argument restriction and cover `-o` forms too.
See [`ssh_config`](https://man.openbsd.org/ssh_config#LocalForward).

Forwards accumulate across matching blocks, like `IdentityFile`, and run only for `ssh`'s
final destination, never on jump peers. Shared config loading for `scp` and `sftp` must
accept these directives without starting listeners. `ExitOnForwardFailure` governs setup
failures, not a later refused target connection. On setup failure, either warn and
continue, or, when the option is set, release the forwards already set up and exit 255.

### Running forwards

- Give the handler the session channel's ID. Its close callback records session completion
  and stops stdin; it does not disconnect the final peer. A forward's close affects only
  that forward. A jump peer still disconnects when its sole transport channel closes.
- `client::Handle` is not `Clone`, and `Peer::close` consumes it, so listeners and relays
  may share the final hop's `Peer` behind an `Arc`. One connection owner coordinates
  shutdown, reaps tasks, and releases every shared reference before consuming `Peer`.
  Share it only for operations that need the handle; an established relay owns its channel.
  Update `Peer::close` too: a completed session no longer implies a disconnected transport.
- Listeners bind after authentication and before the session channel opens. Each accepted
  socket takes a permit and a spawned task, so a slow target does not hold up accepts. It
  opens a channel with the peer's address as originator, then calls `relay`. A refused
  channel closes the socket and prints one line to stderr.
- `-N` skips `run_channel` and its terminal setup, and runs until the connection ends or
  Ctrl+C. On normal session completion, stop local listeners, reject new remote opens,
  drain already-admitted forwards (including opens in progress), then disconnect and return
  the session's status. Keep SSH running throughout the drain. On transport failure,
  Ctrl+C, or setup failure requiring exit, cancel pending opens and relays immediately and
  release sockets before shutdown.
  Connection termination must be observable even while other tasks hold `Arc<Peer>`.
- The limit matches the server's 16,384 per connection, and OpenSSH's, because `channels.c` is
  shared. `memory_pressure()` stops new forwards.

The session channel stays in automatic mode, so a blocked stdout, as in
`ssh -L ... host cmd | slow`, can still pause forwards until the pipe drains. This coupling
is accepted; `-N` tunnels have no such dependency. Preserve the existing closed-session
stdin regression when removing the callback's unconditional disconnect.

### `-D` (step 6)

A new `client/socks.rs` speaks SOCKS4, 4a, and 5: `CONNECT` only, with no authentication.
The handshake is bounded in size. It has no time limit, as in OpenSSH: a stalled one holds
only its permit and task. Domain names go to the server unresolved, so DNS happens at the
far end. `ChannelOpenFailure` maps to a SOCKS reply, and then the socket goes to `relay`.

### `-R` (step 8)

Override `server_channel_open_forwarded_tcpip`: russh's default **accepts every such
channel**. Keep a list of the forwards the server has accepted, each with its requested
bind, its port, and its target from the client's own options. The server must never supply
the local target. Take the permit and receive credit in the callback, then hand the channel
to a task; do not wait for anything or connect there.

Forwards are set up once, one request at a time, after authentication and before the session
channel opens. Nothing adds or cancels a forward later, so one "setup finished" signal is
enough. A `Handle::tcpip_forward` success wakes its caller, but russh can dispatch a
forwarded open before that caller resumes, so each task waits for the signal before reading
the list. A pending port-0 request therefore authorizes nothing. Waiting tasks hold their
permits and end on cancellation. Validate allocated ports as 1–65535, add the forward, then
print the port to stderr. Dial only on an exact match, and reject anything else. Connections
and replies run outside the handler, using the same cancellation and relay rules as on the
server.

`ssh` never sends `cancel-tcpip-forward`. OpenSSH sends it only from `~C` and connection
sharing, and listeners end with the connection anyway. After the session ends, `ssh` rejects
new opens individually, without disconnecting, while admitted forwards drain.

## Remote forwarding in russhd (step 7)

`tcpip_forward` honors `allow_tcp_forwarding`, validates the bind and port, and checks
pressure before binding. By default, remote listeners stay on loopback, following OpenSSH's
`GatewayPorts no`: explicit `127.0.0.1` or `::1` selects that family, and other valid
requests get both loopback addresses. With `gateway_ports`, every request binds `0.0.0.0` and
`::`, whatever the client asked for, as with `GatewayPorts yes`. All of these are numeric,
so the handler needs no DNS. A multi-family listener group uses one port; port 0 chooses it
from the first successful bind. At least one eligible family must bind, and any
partial-family failure must be reported. This follows
[OpenSSH's listener setup](https://github.com/openssh/openssh-portable/blob/master/channels.c).

Port 0 with `gateway_ports` needs its own path, because Motor OS refuses a wildcard bind with
port 0 (`bind_inner` in `src/sys/lib/moto-sdk/src/io/net/tcp.rs`). Lifting that would change
`src/sys`, so `russhd` picks the port itself: start at a random port in the ephemeral range
and try successive ports on `0.0.0.0` while the bind reports the port taken, failing the
request after 64 tries. Motor OS reports `AlreadyExists` and Linux `AddrInUse`. Use this path
on every platform, so host tests cover it.

Store each listener group on its SSH connection, keyed by the requested bind text and
actual port. Preserve that bind identity in forwarded opens and cancellation; do not
replace `localhost` with an accepted socket's numeric local address. Reject duplicate
active keys and bind conflicts without changing the existing listener. Distinct port-0
requests create distinct registrations. Publish the group before reporting success.

Each accepted socket acquires a forward permit without waiting, then a separate task opens
`Handle::channel_open_forwarded_tcpip` and relays it. A slow channel open cannot block
accepts. `cancel_tcpip_forward` removes only a matching group on that connection, stops
and joins its accept tasks, and releases every listening socket before success. Unknown
registrations fail. Existing forwarded connections continue. Connection loss cancels all
listeners, pending opens, and relays. No separate listener-count cap is added; admission
and bookkeeping still obey the pressure policy.

For these server-initiated channels, take `receive_credit` in `channel_open_confirmation`
and hand it to the opener. The pinned callback runs before the next data packet is
dispatched; prove this with immediate-data and cancelled-open tests, and clean up abandoned
handoffs. If the existing API cannot satisfy this contract, propose the additional
**russh fork change** before implementation rather than silently expanding step 4.

## Security

- Channel opens reach `russhd`'s handler only after authentication, and login names carry
  no different authority. Sessions already hold `CAP_NET`: `russhd` has it (`svc:1020`) and
  passes it on through `PARENT_OWNED_CAPS`. A logged-in user can already dial anything, so
  forwarding adds no authority, and `sshd_config` says the same of OpenSSH's switch. It
  does add convenient reach for anyone holding a credential, including the shipped test
  ones, which is why the switch is still worth having.
- Destinations are unrestricted, loopback included, as with OpenSSH's default.
- A remote listener has no authentication, and leads into the client's network. On loopback,
  only local processes can reach it. `gateway_ports` opens it to every host that can reach
  the server, which is why it is off by default and in shipped configs.
- Hosts are client text. `russhd` accepts at most 255 bytes of `[A-Za-z0-9._:-]`, and logs
  only validated text: one info line per forward, with host and port, never any data.
- A client can chain forwards through one server. Counts and per-forward queues are bounded,
  but aggregate memory use remains a shared-process risk. Pressure shedding reduces that
  risk; it does not provide isolation between sessions.
- A client's listener has no authentication. Any local process with `CAP_NET` can use it to
  reach the destination over the user's SSH connection, as any local user can with OpenSSH.
  This is why listeners default to loopback, and why `-g` is explicit. `-D` is the widest
  case, because it reaches anything the server can.
- `ssh` must parse SOCKS requests from any local process and channels from the server as
  hostile input: fixed bounds, no panics, and the checks in the `-R` section.

## Implementation milestones and patch boundaries

Nothing changes under `src/sys`. Each patch keeps `docs/ssh-client.md`, `commands.html`, and,
for options, `ssh-help.txt` and `client_help.rs` current. That includes the sentences saying
forwarding is unsupported and that a connection runs one channel at a time.

1. **First remove Wasm tests on 224 MiB VMs**, as requested. Keep both `wasm:256` and
   `dev:256`, with all Javy, Wasmtime, Linux identity, and service checks. Remove the
   224 MiB entries from `test-wasm.sh`'s default matrix, accepted selectors, and usage;
   change every Wasm invocation in `full-test-dev.sh`, including preparation and services,
   to the two 256 MiB VMs. Update `test-wasm-selection.sh`, `test-full-test-size.sh`,
   `test-dev-memory-contract.sh`, `docs/build.md`, `docs/wasm.md`, and `wasm.html` in the
   same patch. In a separate patch, fix the race in `wait_output`, in
   `src/tests/wasm-smoke-suite/src/lib.rs`, which this gate can no longer absorb. It returns
   as soon as its text appears, so `address()` in `wasmtime-smoke` can parse a line still
   being written; that failed once at `wasm:256` with `AddrParseError`. Require a complete
   line. Gate with those three shell tests, which already run from `full-test.sh`, and the
   complete `full-test-dev.sh --release`. Finish these patches before any russh or forwarding
   changes.

The matrix removal is done (`dd716bf4`); see the progress table for the complete-line
fix and validation status.

2. Start the **external russh fork** channel-close fixes and their tests, then update the
   main repository's pin. Cover both pending outbound data on peer close and local cleanup
   without a close reply. Build the bounded queue and event-driven relay with focused tests;
   then integrate connection cancellation and direct opens with stalled-peer tests. Add the
   config and imager fields together, with forwarding enabled only in the new host fixtures.
   Separate the authentication-deadline/idle-timeout patch and its tests. Gate patches with
   `cargo test` in `src/bin/russhd` and, when affected, `src/imager`.
3. Add guest coverage, then enable shipped configs and existing forwarding fixtures together
   with replacement of their refusal assertions. Keep the policy-off refusal test in a
   dedicated fixture. Gate with `full-test.sh`, debug and release, and
   the complete `full-test-dev.sh --release`, with no Wasm failure exception.
4. Split the **external russh fork** work into accounting, dispatch, and handoff patches,
   each with tests, then update the main repository's pin. Main-repo integration tests must
   cover the new credit contract too, so `full-test.sh` exercises it. Every `ssh` session
   now runs on changed code; gate the pin with `full-test.sh`, debug and release.
5. Add and test option/config parsing first. Follow with the connection owner and session
   completion handling, then `-L`, `-N`, `-g`, and `ExitOnForwardFailure` integration and
   guest coverage. Keep the old closed-session stdin regression passing at every stage.
6. Add the bounded SOCKS parser and tests, then integrate `-D` and its guest check.
7. Add remote listener registration and cancellation tests, then accepted-socket relaying
   and credit handoff tests. Verify the API contract before proposing any extra fork edit.
   Add `gateway_ports`, its imager field, and its port search in a separate patch.
8. Add the forward list and reply-ordering tests, then `-R` end-to-end and guest coverage.
   Keep its incoming-channel callback nonblocking.

Step 1 replaces v3's exception for the known `typescript-compressed` refused-page failure
on `wasm:224`. The 224 MiB test tier is removed by request; the failure is not fixed or
accepted at 256 MiB. All remaining tests must pass. Do not substitute manual service-only
runs for a complete developer-image gate: they omit ordinary Javy and Wasmtime coverage.
On existing images, `test-wasm.sh` already passes at both 256 MiB VMs, with
`--linux-identity` and with `--services`; `full-test-dev.sh` has not yet run end to end
without the 224 MiB tier.

Gate steps 5 to 8 with host tests and `full-test.sh --release`. The time budgets are tight:
debug last used about 1,390 of 1,500 s. New guest checks must stay small, with negative
cases in host tests.

## Acceptance

No test may run the host's `sshd`. The host's OpenSSH client is fine, including `ssh -G`.
All new tests must run transitively from `full-test.sh`. Use only loopback or the private
moto-tap network, without public DNS. For guest name resolution, use `localhost.`, with the
trailing dot: `rt.vdso` answers exact `localhost` itself, but this name goes through the
resolver and the shipped hosts file to `127.0.0.1`, as a guest `ssh` login to it confirmed.
Sessions cannot add a name, because `/system/cfg` is System-writable. `motor-dns-test` does
not work either: it resolves to `127.0.0.53`, and connections to that address time out.
Host protocol fixtures check that names reach the far end unchanged; resolver-error mapping
uses a deterministic lookup failure in a helper test rather than querying an unknown public
name. DNS wire-protocol testing is outside this forwarding plan.

### Server

Host tests in `client_protocol.rs`, against the real `russhd` binary:

- **Data:** a round trip to an echo listener; half-close in each direction; `ProxyJump`
  streams, `scp`, and `sftp` through a real `russhd` jump. Keep `JumpFixture`: its
  `StarvedWindow` mode provokes a client stall no real server does on demand.
- **Refusals, by reason:** field absent or false; refused port; port 0 and above 65535;
  invalid and overlong hosts. Cover resolver failure with the hermetic helper test above.
  Test permit exhaustion and release on refusal, close, cancellation, and connection loss.
  Cover pressure refusal and queue shedding with an injected signal, because
  `memory_pressure()` exists only on Motor OS.
- **Scale:** 256 forwards at once on one connection, with no refusals.
- **Shared loop:** a shell and a forward together; EOF on a forward leaves the shell's
  stdin open; data on a forward with no shell keeps the connection; many small packets to
  a target that never reads leave a shell responsive, and a target blocked writing can
  still finish. These must fail against a plain `copy_bidirectional`.
- **Flow control:** a conforming client exhausts its window while the target stalls, and
  credit returns as the target drains; a client that stops reading one forward does not
  stall another. A hostile fixture sends tiny packets beyond the full byte queue, within
  russh's tolerated overrun: the relay closes that forward and leaves a shell responsive.
  Also cover empty data, extended data, and data after EOF.
- **Teardown:** SSH loss releases sockets and permits during transfer, with a full inbound
  queue, while waiting for outbound window credit, and during a pending
  resolve/connect/open. Late results start no dial. Channel close releases them while
  waiting for window credit, and after queued bytes reach the target: data, EOF, and close
  sent together all reach a slow target. Repeated open/close cycles retain no task or
  handoff records. With close replies withheld, sockets, relays, and permits still release.
  Use event coordination, not timing guesses, to establish stalls.
- **Authentication/idle:** silent identification and stalled authentication expire, while
  authenticated idle tunnels survive; exercise the production deadline helper with a
  controlled clock and verify real transport teardown.
- **Remote listeners (step 7):** policy denial, bind conflict, duplicate request, allocated
  port, loopback/family restrictions, immediate connection after success, cancellation
  and rebinding, and disconnect cleanup. Another SSH connection cannot cancel the owner's
  listener. Cancellation leaves existing forwards alive and closes all listening sockets.
- **`gateway_ports` (step 7):** on Linux, `127.0.0.2` reaches a wildcard listener but not one
  on `127.0.0.1`. So without the setting, a listener requested on `0.0.0.0` cannot be reached
  there, and with it, one requested on `127.0.0.1` can.
  Cover port 0 with the setting, and test the port search with a taken port as a unit test.
  Linux refuses the second wildcard bind without `IPV6_V6ONLY`, so host tests must expect
  only IPv4, with the partial failure reported. A Motor guest binds both.

Guest tests in `src/tests/test-ssh-config.sh`:

- **Motor client through a jump:** restore what `0355fc70` removed: streams, exit status,
  `scp`, `sftp`, password login, and the `-J` override, with the host-run `russhd` as the
  jump and a second one on host loopback as the target, so that only the jump can reach
  it. Drop the refusal checks that replaced them.
- **Motor OS as the jump:** the host's OpenSSH client with `-J motor@192.168.4.2:2222` to
  the host-run `russhd`, and `-L` to the guest's own port 2222 with a shell open. This is
  the new code running on Motor OS.
- **Scale:** 100 forwards at once through the guest, which also shows sys-io copes.
- **Name resolution:** one forward to `localhost.` port 2222, resolved by `russhd` on the
  guest.
- **`gateway_ports` (step 7):** a second `russhd` on the guest that sets it, started as
  `test-sshd-keys.sh` starts one. The host's OpenSSH client asks for `-R 0:...`, and a host
  connection to the allocated port on `192.168.4.2` reaches the client's target.

### russh fork

For step 2, exercise both client and server close paths:

- Repeated open/close cycles leave no closed channel in `Session::channels`, with either
  side closing first. Check retained entries and queues directly, not just process RSS.
- A peer holds its receive window at zero until `Handle::data` has populated
  `pending_data`, then sends `CHANNEL_CLOSE` and no further window adjustment. The close
  reply arrives, unsent outbound data is discarded, and another channel keeps working on the
  same live transport. For the client path, a server holds `receive_credit` unconsumed; a
  stalled client cannot open another channel. For the server path, use a client with
  `window_size: 0`, because client credit arrives only in step 4. Opens bypass this stall on
  the server, and the second channel has no window either, so send EOF on it: that needs no
  window, and it never arrives if the server is stalled. Include a window-starved shell
  alongside a forward in the main-repository tests, since shells keep using this send path.
- Repeated local closes with delayed or withheld peer replies release `ChannelRef`s,
  payload queues, pending delivery, and handoff state before acknowledgement, and
  `Channel::wait()` ends on the closing side. An in-crate test can check that the entry is
  gone right after `close`, before any reply. Another admitted channel stays usable.
- Peer close still delivers already-received data before `ChannelMsg::Close`; the relay's
  slow-target drain test must keep passing. Local close preserves data-before-close
  ordering unless the peer closes first. Duplicate or late replies are harmless, and
  `CHANNEL_CLOSE` cannot remove a locally opened channel waiting for confirmation.

For step 4, in the style of `test_manual_receive_window.rs` and `test_backpressure.rs`: a
client channel in credit mode gets no window back until the application reports consumption;
a temporarily full channel queue leaves outbound traffic moving and resumes reads when
drained; a window-bounded application pump keeps other channels responsive. Automatic-mode
policy stays unchanged. Cover overrun handling, immediate data after confirmation, abandoned
open/credit handoffs, and taking credit during `server_channel_open_forwarded_tcpip`.
Neither client nor server may return automatic credit before the opener receives its
manual-credit handle.

### Client

Host tests, with the real `ssh` and `russhd` binaries:

- **Parsing:** CLI, two-argument config and `-o` forms, including IPv6, `*`, and invalid
  input. Compare accumulated forwards with `ssh -G`, as `client_config.rs` does. Show they
  skip jump hosts and do not make `scp`/`sftp` config loading fail or start listeners.
- **`-L`:** a round trip; half-close; a refused destination closes the local socket; bind
  failure with and without `ExitOnForwardFailure`; loopback by default, all interfaces with
  `-g`; one forward through a jump. A later setup failure with `ExitOnForwardFailure`
  releases earlier listeners; a later target failure does not terminate the tunnel.
- **Lifetime:** closing one forwarded connection leaves the tunnel and a shell up; `-N` runs
  with no terminal and exits when the connection ends; after a command ends, open forwards
  finish before `ssh` exits with its status. Ctrl+C and connection loss cancel stalled
  handshakes, opens, and relays, release every peer reference, and leave no listening port.
- **Shared loop:** a local application that never reads does not stall another forward or a
  shell; two peers that each write a full window before reading both finish. These must
  fail without step 4.
- **`-D`:** SOCKS4, 4a, and 5 from a Rust test client; a name forwarded unchanged for far-end
  resolution; bad versions, unsupported commands, and oversize requests. A stalled handshake
  leaves other connections working. Pending handshakes consume permits and release them on
  cancellation.
- **`-R`:** a round trip; an allocated port; a server refusal; an unrequested channel from a
  hostile server, using a russh fixture like `JumpFixture`, is rejected and dials nothing.
  Exercise an open dispatched before the allocation caller resumes, invalid allocated
  ports, a failed request, and opens during the final drain. Only an accepted forward's
  target may be dialled, and rejecting an open does not end the connection.

Guest tests, one each for `-L`, `-D`, and `-R`: Motor `ssh` on the guest against the host-run
`russhd`, reaching a host service through the tunnel, and for `-R`, the reverse.

**A gap remains:** the client is tested only against `russhd`, so compatibility with a real
OpenSSH server stays unverified in the suite. A one-off manual check against `sshd` in a
throwaway VM, never the host's, would cover it at review time.

### Deferred: guest pressure test

A guest test of pressure shedding is deferred, and does not gate shipped forwarding. Step 3
therefore enables forwarding without measuring queue growth, refusal, cleanup, or an
existing shell's survival under real pressure. Until this test exists, only the injected
host test above covers that logic.

The test should exercise backlog block growth and shedding under controlled pressure,
followed by cleanup and recovery, and an existing shell must survive it. Record memory
before and after the episode, and do not query allocating metrics during pressure. A failure
requires diagnosis, not retries or weaker assertions. Holding pressure through the flag's
dips is the hard part; see the header of `src/sys/tests/systest/src/pressure.rs`.
`full-test.sh` already uploads `systest` to the guest, but its squeeze is an internal child
mode. So the test needs either a small `systest` change, under `src/sys`, or a helper crate
in `src/tests`.

## Decisions

1. **The russh fork changes** are approved: channel-close fixes (step 2), including pending
   outbound data on peer close and cleanup without a close reply, and receive credit in the
   client (step 4).
2. **`allow_tcp_forwarding`** is approved, as the counterpart of OpenSSH's `AllowTcpForwarding`.
3. **Retain the approved count policy:** 16,384 forwards per connection, no smaller
   Motor-specific cap and no server-wide forward cap. Memory-pressure shedding is best
   effort; it does not guarantee isolation between sessions.
4. **Separate authentication and idle lifetime:** retain OS connect timeouts, add a finite
   authentication deadline, and remove the application idle timeout only alongside that
   protection. Connection and task cancellation must release forwarding resources.
5. **`gateway_ports`** is approved, as the counterpart of OpenSSH's `GatewayPorts yes`.
   Remote listeners stay on loopback unless it is set, and shipped configs leave it off.
   CLI/config parsing and the event-driven relay are shared; session state and forward
   lifetime remain separate.
6. **The guest pressure test is deferred.** Shipped forwarding does not wait for it.
7. **Remove Wasm tests on 224 MiB VMs as step 1.** Retain both images and all checks at
   256 MiB, then require the complete developer-image release gate to pass. This supersedes
   v3's known-failure exception and manual service-only follow-up.
8. **The additional external russh compression fix is approved.** Drain buffered
   decoder output after compressed input is exhausted, preserving packet-size limits,
   then resume the forwarding implementation. Preserve the original failure evidence.

These differences from OpenSSH remain:

- `russhd` runs one session per connection, where `MaxSessions` allows 10. That limits
  sessions, not forwards, so this plan does not depend on it, and lifting it would be a
  separate refactor of `ConnectionHandler`.
- `allow_tcp_forwarding` is a boolean, without OpenSSH's `local` and `remote` values, and
  `gateway_ports` is a boolean, without `clientspecified`.
- Past 16,384 forwards `russhd` refuses the new one, where OpenSSH ends the connection, and
  memory pressure sheds forwards; see "Limits".
