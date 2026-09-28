# rmux IPC transport: review findings

Cumulative review of the `new-caps` branch from 54dab16b to 57224a49
(rmux over capability-checked moto-ipc, plus the kernel and moto-ipc
listener fixes). Reviewed 2026-09-27. No code was changed and no tests
were run.

Findings 1 and 2 share a root cause: a client cannot tell an exhausted
listener pool from an absent server, and the server is never woken to
refill the pool. A fix likely needs either a kernel-side wake on
connect or a distinct error code, so it touches `src/sys` and should
be discussed first.

Implementation follows the approved `ipc-rmux-fixes.md` plan. Connection
wakeups are mandatory, with listener replenishment and early rmux peer
authentication. Findings below retain the original review for context.

### Implementation progress

Finding 1 is fixed in `89a99f74` and gated by three full debug runs and three
full release runs. Successful logs: `/tmp/ipc-rmux-issue1-debug-{2,3,4}.log` and
`/tmp/ipc-rmux-issue1-release-{1,2,3}.log`. The 12 IPC host tests also pass
in both modes, and rmux clippy passes in both modes with warnings denied.
The kernel now always wakes shared servers on connection; LocalServer's
existing next-wait refill replaces consumed listeners even without an RPC.
rmux authenticates connection notifications before inspecting request data.
The guest regression covers silent notification, refill, capacity limits,
and peer close; an rmux probe holds a rejected silent peer open while a
legitimate client lists sessions.

Validation diagnosis: the first sandboxed debug run stopped because an
existing toolchain test needs its generated `../patched-crates` cache.
The subsequent unrestricted run passed the guest IPC regressions but found
an incorrect assertion in the new rmux probe: a close during `SysCpu::wait`
returns a wake (`Ok(())`), whereas an already-closed peer returns
`E_BAD_HANDLE`. The probe now checks peer closure after either result, using
the same deadline and no retry. Original logs are preserved in
`/tmp/ipc-rmux-issue1-debug-1.log` and
`/tmp/ipc-rmux-issue1-debug-1-unsandboxed.log`.

Finding 2 is fixed in `c4de82bb` and gated by three full debug runs and three full release
runs on the final patch. Successful logs:
`/tmp/ipc-rmux-issue2-final-{debug,release}-{1,2,3}.log`. IPC host tests pass
in both modes; rmux clippy passes in both modes with warnings denied.
An exhausted live service now returns
`E_NOT_READY`; rmux waits for listener refill within the existing five-second
opening budget and reports a busy timeout if capacity never returns. Only
actual absence returns `None`. Both halves of a connection use that rule.
The guest ownership/refill tests distinguish exhaustion from absence. The
rmux saturation probe fills all 64 endpoints, proves `connect_or_start`
never invokes its spawn callback, checks busy errors from `ls`, `attach`,
and `new`, then releases the pool and verifies three concurrent listings.

Validation diagnosis: after one debug and two release passes, a debug run
failed at `tcp.rs::read_sys_io_metric` with error 3 (`E_NOT_READY`) opening
the stats IPC connection. `Collector::read` propagates its connect error;
the provider's query response only returns success (or invalid argument for
an unknown command). The existing helper's `E_NOT_FOUND` retry had also
covered pool exhaustion, which the new kernel result now distinguishes.
Its error check now accepts that split result with the same 30-second
deadline, 50 ms interval, and required metric. This is a compatibility
update to finding 2, not a new retry policy. Original failure log:
`/tmp/ipc-rmux-issue2-debug-2.log`. All six final gates passed after this
correction.

Finding 3 is fixed in `569d7147` and gated by full debug and release runs:
`/tmp/ipc-rmux-issue3-{debug,release}.log`. Both final host component suites
pass (`/tmp/ipc-rmux-issue3-host-final-{debug,release}.log`), and Motor-target
clippy passes with warnings denied in both modes. A final
output poll stays pending after the last message. The input connection stays
usable until the client closes either endpoint or the existing five-second
farewell expires; only then does the pending reader see EOF. This matches
the client's ownership: the relay drops its Writer after processing Exit,
which releases the reader thread. No new close message is needed.
The guest probe sends final output and Exit(5), leaves another poll in
flight, verifies an input RPC is acknowledged, and then checks client-close
cleanup. A host relay regression queues a key ahead of Exit(5).

Validation diagnosis: the initial sandboxed component run passed the new
regression but failed nine existing loopback socket tests with `EPERM` at
`TcpListener::bind`. Log: `/tmp/ipc-rmux-issue3-host-debug.log`. The unrestricted
runs passed. Host clippy found an unnecessary clone in the new host-only
regression; it was removed and both component suites rerun. The two remaining
`collapsible_if` warnings are in unchanged Unix startup paths (confirmed
against the parent commit); no new warnings remain.

Finding 4 is fixed and gated by full debug and release suites, including
rmux component tests: `/tmp/ipc-rmux-issue4-resumed-{debug,release}.log`.
Motor-target clippy passes in both modes with warnings denied. rmux escapes
`%`, `;`, `&`, `:`, and `=` in the TMPDIR portion of its service name in one
pass. Escaping percent keeps literal escape spellings distinct. The latter
three characters also need escaping because the common URL encoder turns
them into entities containing semicolons, which the kernel splits before
decoding. Ordinary service names retain their existing spelling; the shared
encoding contract is unchanged. The guest regression starts two servers in
directories containing all delimiters, existing entity spellings, and the
literal encoded counterpart, then checks their separate session listings.

Validation diagnosis: the first debug gate stopped in the new setup because
Motor's `mkdir` accepts exactly one directory argument. The test now uses
one invocation per directory; no production change was needed. Original
failure: `/tmp/ipc-rmux-issue4-debug.log`. Both full gates restart with the
corrected test. The corrected debug run passed the new discovery checks but
was interrupted by the agent daemon restart before the suite reported PASS
(`/tmp/ipc-rmux-issue4-final-debug.log`); no test process or VM survived.
Both resumed gates passed; the interrupted run was not counted as a pass.

The original finding's `%2F` example was inaccurate: slashes are not escaped
by the shared URL encoder. Semicolons still cause the diagnosed parse error.

## Correctness findings, most severe first

### 1. Silent connects can lock out the rmux server

Where: `src/bin/rmux/src/sys/ipc.rs:75` (`MAX_LISTENERS = 4`),
`src/sys/kernel/src/uspace/shared.rs:228`,
`src/sys/lib/moto-ipc/src/sync.rs:644` (`LocalServer::wait` refill).

A kernel `get` on `rmux/<mask>` needs no capability. It pops a pending
listener from the service pool and does not wake the server. The
server authenticates a client only on its first request. Nothing in
`LocalServer` refills a listener that a silent client holds.

Scenario: an unprivileged process runs `SysObj::get` four times against
`rmux/<privileged mask>` and sleeps. Each `get` pops a listener. The
server is never woken because no RPC arrives. The four
`LocalServerConnection`s stay `Listening` in `listeners`, so the
refill condition `listeners.len() < max_listeners` in `wait()` is
false. Every later `rmux new/attach/ls` by the legitimate user gets
`E_NOT_FOUND`, spawns a second server that exits on the name clash,
and fails with "the rmux server did not start". The capability check
that motivated this transport never runs.

This is a pre-existing property of moto-ipc's `LocalServer`. The series
makes it the security boundary of a privileged server, so it now
matters.

### 2. "Pool empty" is read as "no server"

Where: `src/bin/rmux/src/sys/ipc.rs:175` (`open()`),
`src/sys/kernel/src/uspace/shared.rs:225-230,254`.

The kernel returns `E_NOT_FOUND` in two cases: nothing holds the name,
and the name is held but `service.pending` is empty. `open()` maps
both to `Ok(None)`, which `connect_or_start` treats as "no server
runs".

Scenario: three clients attach at once. Each needs two listeners; the
pool holds four and is refilled only on the server's next `wait()`.
The third client's first `open` gets `E_NOT_FOUND`. `connect_or_start`
checks `CAP_SPAWN_DETACHED`, spawns a second server, which fails
`LocalServer::new` and exits, and only then retries. In `ask()`
(`rmux ls`), `question()` returns `None`, so the command prints
nothing and exits 0 as if there were no sessions.

### 3. Closing race with an in-flight input RPC

Where: `src/bin/rmux/src/sys/ipc.rs:637` (`deliver()`),
`src/bin/rmux/src/sys/ipc.rs:591` (`end()`).

`deliver()` ends a closing client as soon as its next poll arrives:
when `outbox.closing && outbox.bytes.is_empty() && outbox.awaiting`,
it calls `end(id)`, which disconnects both the output and the input
connection. The TCP writer waited for the client to close first. This
replacement drops that guarantee.

Scenario: the session runs `exit 5`. The server sends the last
`Write` bytes and `Exit(5)`, then drops `out`; the forwarder sets
`closing`. The client's `read_server` thread polls again at once
(`awaiting = true`) before the relay has dequeued `Exit`. At the same
moment the user presses a key, so the relay's `send()` issues a
`CMD_INPUT` RPC on the input connection. `deliver()` sees the closing
condition and calls `end(id)`, which disconnects the input connection;
the next `wait()` puts the handle. The client's `do_rpc` gets
`E_BAD_HANDLE`, `send(...)?` returns `Err`, and `attached` returns an
error. rmux prints an error and exits with a code other than 5.

### 4. TMPDIR with `;` breaks the service name

Where: `src/bin/rmux/src/sys/ipc.rs:93` (`service_name`),
`src/sys/kernel/src/uspace/sys_obj.rs:115` (`args.split(';')`).

`service_name` embeds `$TMPDIR` verbatim in the kernel's
`shared:url=...;address=...` string. `url_encode` escapes only `&`,
`:` and `=`. The kernel parser splits on `;`.

Scenario: `TMPDIR='/user/tmp;x' rmux new`. `start_listening` builds
`shared:url=rmux/384//user/tmp;x;address=...`. The kernel sees an
`x` entry and returns `E_INVALID_ARGUMENT`, so `LocalServer::new`
fails and the server exits. The client's `connect` also gets
`E_INVALID_ARGUMENT` and reports an OS error. The port-file path
worked for any directory.

### 5. Refusals are reported as silence

Where: `src/bin/rmux/src/sys/ipc.rs:335` (`Reader::read`).

`Reader::read` turns every non-timeout RPC error, including the
server's explicit `E_NOT_ALLOWED`, into `Ok(0)` (EOF). The refusal
reason is lost.

Scenario: a client whose mask lacks a server bit runs `rmux ls`.
`connect()` succeeds, because the `caps == profile` check is
client-side only. The `CMD_OPEN_OUTPUT` reply is `E_NOT_ALLOWED`, so
`request` returns `Err`. In `ask()`, `first_words` gets `Ok(0)` and
`no_answer()` prints "the rmux server did not answer". The server
answered with a refusal. The attached path behaves the same way: the
user is told the server is silent rather than that they are not
allowed.

## Cleanups

### Altitude: `stuck` flags belong in moto-ipc

Where: `src/bin/rmux/src/sys/ipc.rs:132` (Writer and Reader).

The `stuck` flags exist only because `ClientConnection::do_rpc`
asserts `seq & 1 == 0` when called after a timed-out RPC. The
invariant belongs in moto-ipc, which should return an error or expose
the in-flight state, not in every caller. Any other user of
`do_rpc(Some(deadline))` that retries after `E_TIMED_OUT`, such as
rmux-probe's `request` if it ever looped, or a systest helper, hits
the assert and aborts instead of getting `E_INVALID_ARGUMENT`. rmux
tracks the state in two structs and must remember it at every future
call site.

### Redundant `release_retired()` in `LocalServer::wait`

Where: `src/sys/lib/moto-ipc/src/sync.rs:638` and `:656`.

The first call is covered by the second after the refill loop. The
release condition (`retired` set, and any listener or connection
present) can only become true across the refill, never false.
`retire()` has already dropped the mapping. Neither call has a
comment, so a reader has to work out whether the first is
load-bearing.

### Per-RPC copies in `serve()` and `deliver()`

Where: `src/bin/rmux/src/sys/ipc.rs:471`.

`serve()` copies up to 4064 bytes of request data with `to_vec()` for
every request, including every `CMD_POLL`, which carries no data.
`deliver()` copies each chunk twice: `drain().collect()` and then
`copy_from_slice` into the page. Each keystroke and each output poll
allocates on the single IPC thread. Matching on `cmd` before the copy,
or copying straight from `outbox.bytes.as_slices()` into the page,
avoids this.
