# TCP forwarding in russhd and ssh

This is the design of TCP forwarding at both ends: `russhd` as a jump host or
the far end of a tunnel, and the Motor `ssh` client opening one. It was
extracted from the completed implementation plan; that plan's step history and
gate records remain in the git history of `docs/plans/russhd-forwarding.md`.
Open correctness work is tracked in
[docs/plans/russhd-forwarding-review-fixes.md](plans/russhd-forwarding-review-fixes.md);
update this document when those fixes land.

## Scope

`russhd` serves `direct-tcpip` opens (`ProxyJump`, `-L`, `-D`, and `-W` from
OpenSSH clients) and `tcpip-forward` requests (`-R`). The Motor `ssh` client
supports `-L`, `-D`, `-R`, `-N`, `-g`, and `ExitOnForwardFailure`. User
documentation is in [ssh-client.md](ssh-client.md).

Out of scope: `ssh -f`, `-W`, and `-R` with no target; Unix-socket, X11, and
agent forwarding; connection sharing and the `~C` command line; per-key or
per-destination policy; several session channels per connection; OpenSSH's
`GatewayPorts clientspecified`.

## The russh fork

`russhd` depends on `moturus/russh`, branch `motor-v0.65.1`, which carries 31
commits above upstream v0.65.1 (`b33092a`). `src/bin/russhd/Cargo.lock` records
the exact revision. Upstream already provides the protocol at both ends:

| Need | russh |
|---|---|
| Server: open a forward | `Handler::channel_open_direct_tcpip`, given the host, port, and a `ChannelOpenHandle` |
| Reply after connecting | `accept` and `reject` only queue a message, so a spawned task can call them later |
| Failure reasons | `ConnectFailed`, `ResourceShortage`, `AdministrativelyProhibited` |
| Server: remote forwarding | `Handler::tcpip_forward`, `cancel_tcpip_forward`, `Handle::channel_open_forwarded_tcpip` |
| Client: open a forward | `Handle::channel_open_direct_tcpip`, already used for `ProxyJump` |
| Client: remote forwarding | `Handle::tcpip_forward`, `cancel_tcpip_forward`, `Handler::server_channel_open_forwarded_tcpip` |
| Window-aware sending | `Channel::make_writer`, which waits for the peer's window (with upstream #790's accounting for queued writes) |

The fork adds what forwarding needs and upstream lacks:

- **Receive credit at both ends.** `Session::receive_credit` (server) and
  `client::Session::receive_credit` put a channel in credit mode: window
  credit returns only when the application reports bytes consumed, and a full
  channel queue no longer blocks the session loop.
- **Credit-mode opens.** `channel_open_direct_tcpip_with_credit` (client) and
  `channel_open_forwarded_tcpip_with_credit` (server) install the credit before
  the open is sent, so no automatic credit is returned before the opener holds
  its handle. They defer close acknowledgement from dispatch until the
  application drains and closes, or drops the last credit handle. Cancelled
  opens follow OpenSSH: the small unconfirmed protocol
  record stays until the reply or disconnect, application handoff state is
  freed at once, a late success is closed, and unknown confirmations are
  rejected.
- **Close paths.** `Encrypted::close_from_peer` discards unsent outbound data
  on a peer close, replies without waiting for window credit, and removes the
  channel so other channels resume. A local close removes the `ChannelRef` at
  once, ending `Channel::wait()`. A relay that opts into deferred close
  (`ReceiveCredit::defer_close`) drains received payload before the close is
  acknowledged, then waits for the peer's reply with `wait_closed`; dropping
  every credit handle releases that state without waiting.
- **Session abort and transport fixes.** `RunningSession::abort()` for the login
  deadline, concurrent transport reads and writes, blocked-reply limits, and
  the compression repair. A received SSH disconnect releases the session,
  transport and handler without waiting for a flush, shutdown, or peer TCP EOF.
  Locally initiated disconnects retain their orderly shutdown path.

Any further fork change must be proposed explicitly before it is made. Fork
changes live outside the main Motor OS repository and are identified separately
in patch reviews.

## Why a plain copy is not enough

The work is not the protocol but keeping one forward from stalling a
connection. A `copy_bidirectional` on `channel.into_stream()` passes a simple
test and then hangs in use, because all of a connection's channels share one
session loop at both ends.

- **Inbound queues.** Each channel has a queue of 100 messages. Without credit,
  a full queue parks the packet and stops reading the socket for the whole
  connection, including the `WINDOW_ADJUST` another channel needs. The window
  limits bytes, not packets, so small packets to a target that is not reading
  fill the queue long before the window runs out. Credit mode and nonblocking
  dispatch in the fork remove this stall; the relay still enforces its own byte
  bound, because `consume_receive_window` tolerates a nominal overrun of one
  tenth of the window.
- **Outbound data.** `Handle::data` does not wait for the peer's window. Data
  past it parks in `pending_data`, and the session stops taking application
  messages for every channel until that window reopens. Forward relays write
  through `make_writer()` instead; shells still use `Handle::data`, so a client
  that stops reading shell output can pause forwards on that connection. This
  coupling is accepted.
- **Closed channels.** Without the fork's close paths, a closed channel's
  `ChannelRef` and queue stayed in `Session::channels` until the connection
  ended: 102,000 open/close cycles kept 329 MiB on Linux. A peer that closed
  with its window at zero left `pending_data` parked forever and blocked every
  channel. Both are fixed in the fork and covered by its tests.
- **One channel per connection.** `ConnectionHandler::data` and `channel_eof`
  act only on the active session channel; any other established channel is a
  forward whose task reads it directly. The client's close callback records
  session completion and stops stdin; it does not disconnect the final peer.
- **Memory.** Both programs run on one thread with a current-thread runtime. A
  failed allocation aborts the process, and a refused page kills the faulting
  thread (`oom-handling.md`). A backlog that grows under memory pressure can end
  every session on `russhd`, including the operator's way in, so queues are
  bounded and admission is pressure-aware.

## Server design

`src/bin/russhd/src/forward.rs` runs each forward as its own task. Forwards use
none of `ConnectionHandler`'s session state, so the one-session rule stays.
The connection owns their cancellation and reaps completed tasks. Dropping its
handler or losing the transport cancels all pending opens, relays, and
listeners; completed task records do not accumulate on a long-lived connection.

### Opening

`channel_open_direct_tcpip` does no network work, so the session loop keeps
running:

1. Without `allow_tcp_forwarding`, drop the reply: `AdministrativelyProhibited`.
2. Reject a port above 65535 with `AdministrativelyProhibited`, as OpenSSH does,
   and a port of 0 or a host that fails validation with `ConnectFailed`.
3. Reject with `ResourceShortage` past the forward limit, or under
   `memory_pressure()`.
4. Take a permit and `session.receive_credit(channel.id())`, select deferred
   close before the acceptance reply, register the task with its connection's
   cancellation signal, and return.

The task resolves and connects with `tokio::net::lookup_host`, which keeps the
blocking resolver off the loop, and tries each address in order. It adds no
timeout of its own, as in OpenSSH: sys-io gives up on a connect after 123 s
(`DEFAULT_CONNECT_TIMEOUT`, six SYN retransmissions, as on Linux). It sets
`nodelay`, then calls `accept`, or `reject` with `ConnectFailed`. Resolution,
connection attempts, and reply completion are cancellable: after disconnect
there is no later dial or acceptance. Dropping a `lookup_host` future cannot
stop a running blocking resolver call; its result is discarded without keeping
a socket or the connection alive.

### Relaying

One function, generic over `Channel<S>`, serves both ends. It takes the
receive-window bound and the connection's cancellation signal along with the
channel, socket, and credit. Both ends advertise 2 MiB; the bound derives from
the same setting as the advertised window.

- **Channel to socket.** Consume `ChannelMsg` events through
  `ChannelReadHalf::wait()`, keeping that branch enabled at the byte limit and
  after EOF. Copy data into a bounded byte queue of lazily allocated 32 KiB
  blocks and report `credit.consumed` only for bytes written to the socket.
  Empty data is not EOF. Overflow, data after EOF, or unsupported extended data
  ends that forward without a panic or more buffering. No allocation is
  retained per SSH packet.
- **Socket to channel.** Read the socket and write through `make_writer()`.
  Rekeying may defer data temporarily. A pending write does not prevent
  channel-event handling or cancellation, and an in-progress write is
  preserved until it completes or the relay ends; cancelling a reserved write
  and reusing the channel can permanently lose credit.
- **Half-close.** Channel EOF shuts down the socket's write side after queued
  bytes drain. Socket EOF sends channel EOF after the outstanding write
  completes. The other direction continues. When both drain, the relay sends
  channel close, releases the socket, and waits for the peer's reply with
  `wait_closed`, holding only its permit and minimal close state.
- **Peer close.** `ChannelMsg::Close` stops socket-to-channel at once. Queued
  bytes still reach the socket, as after EOF, and then the relay ends.
  [RFC 4254 §5.3](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.3)
  recommends delivering them, and OpenSSH does (`CHAN_OUTPUT_WAIT_DRAIN`). As
  in OpenSSH, this drain has no time limit, so a target that stops reading
  keeps its forward and permit.
- **Abort.** Receiver termination without `Close`, connection cancellation, or
  an I/O error ends both directions immediately and releases the socket and
  permit, independently of socket writes and window waits. Cleanup never waits
  to send EOF or close over a dead connection.

### Limits

- **Count.** Up to 16,384 forwards per connection, OpenSSH's
  `CHANNELS_MAX_CHANNELS`, and no limit per server. Past that, `russhd`
  refuses with `ResourceShortage`, where OpenSSH ends the connection. The
  budget covers `-L`, `-D`, and `-R` connections, including SOCKS handshakes
  and remote-channel opens. Permits are acquired without waiting, before
  spawning, and are owned by the task, so every exit releases them. Forwards
  to one device also need sys-io's 16,384 ephemeral ports.
- **Memory** is the real ceiling, as on Linux. Every forward's socket reserves
  sys-io buffers from the moment it opens (`networking.md`). Queued payload is
  bounded by the receive window: at most `ceil(window / block_size) + 1`
  blocks of 32 KiB, released as they drain. Sending and the russh queues add
  bounded buffers.
- **Memory pressure** is not a count and acts only when about 2 MiB remain:
  `memory_pressure()` reads `moto_sdk::sys::free_pages() < 512`. It refuses
  new forwards, and a relay whose queue would have to grow ends that forward.
  `low_memory()`, whose 4 MiB threshold serves other admission policies, is
  not substituted. Shedding is best effort: a free-page reading is not a
  reservation, and fallible allocation cannot recover from a refused lazy page
  fault, so one process shares this risk across all sessions. A guest test of
  shedding under real pressure is deferred (decision 6).

### Configuration

`sshd.toml` takes an optional `allow_tcp_forwarding = true`, the counterpart of
OpenSSH's `AllowTcpForwarding`. It governs both directions; absent means off.
Both shipped configs enable it, matching OpenSSH's default, while a custom
config has to opt in. The optional `gateway_ports = true` is the counterpart of
`GatewayPorts yes`: remote listeners bind every address, whatever the client
asked for. Absent means off, and both shipped configs leave it off.
`clientspecified` is left out: it would have to resolve client-supplied names
inside the session loop.

`src/imager/src/set/bare_toml.rs` lists each field in `SERVICE_FIELDS`; imager
refuses any field it does not list.

### Authentication and idle connections

`inactivity_timeout` is `None`; there is no application idle timeout. A 120 s
`LOGIN_GRACE` deadline runs from TCP accept through successful authentication,
following OpenSSH's `LoginGraceTime`: `login::Grace` supervises the session,
`auth_succeeded` rejects completion at or after the deadline, and expiry aborts
and awaits the session task, including a suspended authentication callback.
After authentication, sys-io's 20 s keepalive and 300 s timeout detect dead TCP
peers. Tests use a controlled clock, not wall-clock waits.

### Remote forwarding

`tcpip_forward` honors `allow_tcp_forwarding`, validates the bind and port, and
checks pressure before binding. By default remote listeners stay on loopback,
following `GatewayPorts no`: explicit `127.0.0.1` or `::1` selects that family,
and other valid requests get both loopback addresses. With `gateway_ports`,
every request binds `0.0.0.0` and `::`. All of these are numeric, so the
handler needs no DNS. A multi-family listener group uses one port; port 0
chooses it from the first successful bind. At least one eligible family must
bind, and any partial-family failure is reported, as in OpenSSH's listener
setup.

Port 0 with `gateway_ports` has its own path, because Motor OS refuses a
wildcard bind with port 0 (`bind_inner` in the SDK). `russhd` starts at a
random port in the ephemeral range and tries successive ports on `0.0.0.0`
while the bind reports the port taken (`AlreadyExists` on Motor OS, `AddrInUse`
on Linux), failing after 64 tries. This path runs on every platform, so host
tests cover it.

Each listener group is stored on its SSH connection, keyed by the requested
bind text and actual port. That bind identity is preserved in forwarded opens
and cancellation; `localhost` is never replaced by a numeric local address.
Duplicate active keys and bind conflicts are rejected without changing the
existing listener; distinct port-0 requests create distinct registrations. The
group is published before success is reported.

Each accepted socket acquires a permit without waiting, then a separate task
opens `channel_open_forwarded_tcpip_with_credit` and relays it, so a slow open
cannot block accepts. `cancel_tcpip_forward` removes only a matching group on
that connection, stops and joins its accept tasks, and releases every listening
socket before success. Unknown registrations fail. Existing forwarded
connections continue. Connection loss cancels all listeners, pending opens, and
relays. There is no separate listener-count cap.

Local and remote listeners share an accept-error policy. A failed incoming
connection leaves its listener usable; resource exhaustion delays that socket's
next accept by 100 ms. Permanent or unclassified errors retire the affected
socket with a warning. Other sockets, forwards, commands, and cancellation keep
running. A remote group loses its registration when its last socket exits,
allowing the same key to be registered again while admitted relays continue.

## Client design

### Options

| Option | Setting | Meaning |
|---|---|---|
| `-L [bind:]port:host:hostport` | `LocalForward` | Listen here; the server connects to `host` |
| `-R [bind:]port:host:hostport` | `RemoteForward` | The server listens; connect to `host` from here |
| `-D [bind:]port` | `DynamicForward` | Listen here as a SOCKS proxy |
| `-N` | | Run no command or shell |
| `-g` | `GatewayPorts` | Listen on all interfaces by default |
| | `ExitOnForwardFailure` | Exit 255 if a forward cannot be set up |

Endpoint parsing is shared, including bracketed IPv6 and `*`. `LocalForward`
and `RemoteForward` take two arguments in configuration, `DynamicForward` one;
`-o` forms work too. Forwards accumulate across matching blocks, like
`IdentityFile`, and run only for `ssh`'s final destination, never on jump
peers. `scp` and `sftp` accept the directives without starting listeners.
`ExitOnForwardFailure` governs setup failures, not a later refused target
connection: on setup failure `ssh` warns and continues, or, with the option set,
releases the forwards already set up and exits 255.

### Running forwards

- `client::Handle` is not `Clone` and `Peer::close` consumes it, so listeners
  and relays share the final hop's `Peer` behind an `Arc`. One connection owner
  coordinates shutdown, reaps tasks, and releases every shared reference before
  consuming `Peer`. An established relay owns its channel, not the connection,
  and connection termination is observable while other tasks hold `Arc<Peer>`.
- Listeners bind after authentication and before the session channel opens.
  Each accepted socket takes a permit and a spawned task, so a slow target does
  not hold up accepts. The task opens a credit-mode channel with the peer's
  address as originator, then relays. A refused channel closes the socket and
  prints one line to stderr.
- `-N` skips the terminal setup and runs until the connection ends or Ctrl+C.
  On normal session completion, `ssh` stops local listeners, rejects new remote
  opens, drains admitted forwards (including opens in progress), then
  disconnects and returns the session's status. On transport failure, Ctrl+C,
  or a setup failure that requires exit, it cancels pending opens and relays
  immediately and releases sockets before shutdown.
- The limit is the server's 16,384 per connection, and `memory_pressure()`
  stops new forwards.
- The session channel stays in automatic mode, so a blocked stdout, as in
  `ssh -L ... host cmd | slow`, can pause forwards until the pipe drains. This
  coupling is accepted; `-N` tunnels have no such dependency.
- A jump peer still disconnects when its sole transport channel closes.
  `relay_through` buffers the jump hop; whether it is still needed with the
  current fork is S1 in the fixes plan.

### `-D`

`client/socks.rs` speaks SOCKS4, 4a, and 5: `CONNECT` only, no authentication.
The handshake is bounded in size and has no time limit, as in OpenSSH: a
stalled one holds only its permit and task. Domain names go to the server
unresolved, so DNS happens at the far end. `ChannelOpenFailure` maps to a SOCKS
reply; a failed reply drops the channel and credit. Then the socket goes to the
relay.

### `-R`

`ssh` overrides `server_channel_open_forwarded_tcpip`, because russh's default
accepts every such channel. It keeps a list of the forwards the server has
accepted, each with its requested bind, its port, and its target from the
client's own options; the server never supplies the local target. The callback
takes the permit and receive credit, selects deferred close, and hands the
channel to a task without waiting or connecting.

Forwards are set up once, one request at a time, after authentication and
before the session channel opens, so one "setup finished" signal is enough. A
`tcpip_forward` success wakes its caller, but russh can dispatch a forwarded
open before that caller resumes, so each task waits for the signal before
reading the list; a pending port-0 request authorizes nothing. Allocated ports
are validated as 1–65535 and printed to stderr. A task dials only on an exact
match and rejects anything else; rejecting an open does not end the connection.

`ssh` never sends `cancel-tcpip-forward`: OpenSSH sends it only from `~C` and
connection sharing, and listeners end with the connection. After the session
ends, `ssh` rejects new opens individually while admitted forwards drain.

## Security

- Channel opens reach `russhd`'s handler only after authentication, and login
  names carry no different authority. Sessions already hold `CAP_NET`, so
  forwarding adds no authority; it adds convenient reach for anyone holding a
  credential, including the shipped test ones, which is why the switch exists.
- Destinations are unrestricted, loopback included, as with OpenSSH's default.
- A remote listener has no authentication and leads into the client's network.
  On loopback only local processes reach it; `gateway_ports` opens it to every
  host that can reach the server, which is why it is off by default.
- Hosts are client text. `russhd` accepts at most 255 bytes of
  `[A-Za-z0-9._:-]` and logs only validated text: one info line per forward,
  with host and port, never any data.
- A client can chain forwards through one server. Counts and per-forward
  queues are bounded, but aggregate memory use remains a shared-process risk.
- A client's listener has no authentication. Any local process with `CAP_NET`
  can use it to reach the destination over the user's SSH connection, as any
  local user can with OpenSSH. Listeners therefore default to loopback, and
  `-g` is explicit. `-D` is the widest case.
- `ssh` parses SOCKS requests from local processes and channels from the server
  as hostile input: fixed bounds, no panics, and the `-R` checks above.

## Tests

No test runs the host's `sshd`; the host's OpenSSH client is fine, including
`ssh -G`. Tests use only loopback or the private moto-tap network, without
public DNS; guest name resolution uses `localhost.` with the trailing dot. All
tests run transitively from `src/tests/full-test.sh`.

- Host tests in `src/bin/russhd/tests/client_protocol.rs` drive the real
  `russhd` and `ssh` binaries: data and half-close, jumps with `scp` and
  `sftp`, refusals by reason, permit exhaustion and release, 256 concurrent
  forwards, a shell sharing the loop with stalled forwards, flow control with
  conforming and hostile peers, teardown during every stall, the login
  deadline with a controlled clock, remote listeners, `gateway_ports`, option
  parsing against `ssh -G`, `-L`/`-D`/`-R` lifetimes, and a hostile server's
  unrequested `-R` channel. Pressure refusal and shedding use an injected
  signal, because `memory_pressure()` exists only on Motor OS.
- Guest tests in `src/tests/test-ssh-config.sh` run
  the Motor client through a jump, OpenSSH through Motor OS as the jump, 100
  forwards at once, name resolution by `russhd`, `gateway_ports` with `-R 0`,
  and one guest check each for `-L`, `-D`, and `-R`.
- Fork behavior is tested in the fork's own suite; no fork test is copied
  into the Motor tree.

Known gaps: the client is tested only against `russhd`, not an OpenSSH server;
native Ctrl+C is covered only by the Unix signal test; and the guest pressure
test is deferred.

## Decisions

1. **The russh fork changes** are approved: close paths, receive credit in the
   client, credit-mode opens with OpenSSH-style cancellation, the session
   abort for the login deadline, and the transport and compression fixes.
   Further fork changes must be proposed explicitly first.
2. **`allow_tcp_forwarding`** is the counterpart of OpenSSH's
   `AllowTcpForwarding`; a boolean, enabled in shipped configs.
3. **Count policy:** 16,384 forwards per connection, no smaller Motor-specific
   cap and no server-wide cap. Memory-pressure shedding is best effort and does
   not isolate sessions.
4. **Separate authentication and idle lifetime:** OS connect timeouts and the
   finite login deadline, with no application idle timeout. Connection and
   task cancellation release forwarding resources.
5. **`gateway_ports`** is the counterpart of `GatewayPorts yes`; remote
   listeners stay on loopback unless it is set, and shipped configs leave it
   off.
6. **The guest pressure test is deferred.** Shipped forwarding does not wait
   for it.
7. **Canceled outgoing opens follow OpenSSH:** retain the small unconfirmed
   protocol record until the reply or disconnect, free application handoff
   state immediately, close a late success, and reject unknown confirmations.

Differences from OpenSSH that remain:

- `russhd` runs one session per connection, where `MaxSessions` allows 10.
  That limits sessions, not forwards; lifting it would be a separate refactor
  of `ConnectionHandler`.
- `allow_tcp_forwarding` has no `local` and `remote` values, and
  `gateway_ports` has no `clientspecified`.
- Past 16,384 forwards `russhd` refuses the new one, where OpenSSH ends the
  connection, and memory pressure sheds forwards.
