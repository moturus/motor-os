# Native SSH client design

2026-08-28. Design for a small OpenSSH-compatible command family on Motor OS.
This document contains the reviewed design and its implementation plan. The
initial client implements a narrow surface, but uses standard command names
and argument shapes so existing scripts need few Motor-specific branches.

Revised 2026-08-28 after four design reviews against `russhd`, the terminal and
permission documents, the image manifests, the test scripts, the locked
`russh`, `russh-sftp`, `ssh-key`, `tokio`, and `getrandom` sources, and current
OpenSSH Portable behavior on Linux, and after the owner's rulings on the
runtime shape, timeouts, the known-hosts format, and the server-side
permission fix. The findings are folded into the sections below; the choices
they introduced are listed with the original ones in section 10.

## 0. Decision summary

The recommended design is:

- Add the client to the existing `src/bin/russhd` Cargo package. The server and
  client then share one manifest and lockfile, including the existing Motor
  `russh`, `tokio`, `mio`, and `ring` forks and `russh-sftp` version. No new
  external fork or patch is needed, and the host protocol tests reach both
  executables through `CARGO_BIN_EXE_russhd` and `CARGO_BIN_EXE_ssh` inside
  the `cargo test` run `src/tests/full-test.sh` already makes for this package.
- Build a separate `ssh` executable so client-only parsing, terminal, and file
  transfer code is not linked into the long-lived server process. A stripped
  static SSH executable is about 4 MB (`russhd` today), so one more is
  affordable and four more are not.
- Keep the client's own code synchronous on `std`: terminal I/O, prompts,
  local files, name resolution, and the TCP connect. `russh` and `russh-sftp`
  are asynchronous by construction, so one single-threaded tokio runtime
  drives the SSH session under `block_on`, exactly as `russhd` does; nothing
  else in the client is asynchronous.
- Make `ssh` a multicall executable behind small Rush wrappers named `scp`,
  `sftp`, `ssh-keygen`, and `ssh-copy-id`, the shape every `/system/bin`
  command already has around `sysbox`. This avoids four extra static copies of
  the cryptographic and protocol stack while preserving familiar commands.
- Support public-key and password authentication. Use TOFU host-key checking
  backed by a plain `/user/cfg/ssh/known_hosts` that holds only known hosts:
  one literal host token, key type, and key per line, in the form OpenSSH
  writes, with no hashed entries, markers, or patterns. A changed key is
  never accepted; an unknown key is accepted without a prompt only when the
  caller explicitly selects `StrictHostKeyChecking=accept-new`.
- Accept the small set of OpenSSH options that scripts actually pass
  (`IdentitiesOnly`, `StrictHostKeyChecking`, `UserKnownHostsFile`,
  `BatchMode`, `ConnectTimeout`, `ServerAliveInterval`,
  `ServerAliveCountMax`, `-F /dev/null`, `-t`, `-T`), each mapped onto a
  concept the client needs anyway. Everything else is rejected, never
  ignored.
- Implement `scp` on SFTP, as current OpenSSH does by default, and use
  `russh-sftp` directly for both `scp` and `sftp`. Use its raw client API so
  remote directories and file contents are processed incrementally.
- Replace `russhd`'s obsolete one-class SFTP mode folding with the same
  conservative owner/public interpretation used by the client. Private uploads
  remain inaccessible to lower Motor roles during creation, transfer, and
  finalization.
- Use raw terminal bytes for interactive sessions. On Motor OS, consume only
  the replies to the client's own terminal-size requests, forward all other
  input exactly after a bounded escape-prefix disambiguation hold, translate
  Motor's Ctrl+C control event back to byte `0x03` for the remote terminal in
  pty sessions only, and honor `~.` at the start of a line as the one escape
  command.
- Install the commands in the normal and development images, but not the
  deliberately small base image. They perform no boot-time work.
- Test the Motor client against the VM's own `russhd` over loopback first; a
  host-run `russhd` on the private test network covers only what loopback
  cannot.

## 1. Existing SSH stack

`russhd` currently locks these relevant components:

| Component | Existing selection |
| --- | --- |
| SSH | `russh` 0.62.5 from `moturus/russh`, commit `23758e3...` |
| SFTP | `russh-sftp` 2.1.1 from crates.io |
| async runtime | `tokio` 1.47.1 from the existing Motor branch |
| socket reactor | `mio` 1.0.4 from the existing Motor branch |
| crypto backend | `ring` 0.17.14 from the existing Motor branch |

The `russh` revision already contains the client APIs needed here:
`client::connect_stream`, `authenticate_none` for the advertised methods,
password and public-key authentication with `PrivateKeyWithHashAlg` and
`best_supported_rsa_hash`, `Handler::check_server_key`, session channels,
pty/shell/exec/subsystem requests, window changes, separated stdout/stderr
channel data, exit status, and optional keepalive and inactivity timers. Its
workspace enables `ssh-key` with `ed25519`, `encryption`, and the NIST curves,
and `russhd`'s `rsa` feature adds RSA, so Ed25519 generation, OpenSSH encoding,
passphrase encryption, and every common identity type work without new
features. `russh-sftp` 2.1.1 contains an SFTP v3 client over a channel stream,
including raw file I/O, incremental directory reads, metadata, rename, removal,
and explicit handle closure.

Randomness needs no new plumbing. `getrandom` 0.4 has a native Motor backend,
`russh`'s key exchange already draws from `rand::rng()` on Motor, and the
package's `tests/keys.rs` generates an Ed25519 key with
`PrivateKey::random(&mut rand::rng(), ..)`. `ring` still reaches the OS through
`getrandom` 0.2 and the custom registration in `main.rs`; that registration
belongs in the library so both executables carry it.

`russh` and `russh-sftp` are asynchronous by construction: `connect_stream`
spawns the session task on the tokio runtime, `russh-sftp` runs its reader
task and wraps every request in `tokio::time::timeout`, and neither offers a
synchronous API. A tokio runtime is therefore required for the SSH session
itself, and for nothing else in the client. The locked tokio fork compiles
`TcpSocket` out on Motor, but `TcpStream::from_std` works there, and Motor's
std provides `TcpStream::connect_timeout`, `shutdown`, and `set_nonblocking`,
so the TCP connect can be plain std. Motor's socket options are ttl, buffer
sizes, only-v6, non-blocking, and read/write timeouts; there is no TCP
keepalive.

The current server is a useful compatibility target. It supports password and
one configured public key per user, one session channel per connection,
interactive shells with a requested pty, non-pty remote commands (and
`ssh -t host cmd`), and the SFTP subsystem. It refuses a shell request without
a pty. Its SFTP implementation covers the operations needed for file and
recursive directory copies. Its current POSIX-to-Motor permission mapping is an
obsolete compatibility policy that unions the POSIX classes, so this project
replaces it with the role-aware policy in section 7. Motor OS has no symlinks,
so the initial client must not depend on local symlink behavior.

Two environment facts shape defaults. Nothing on Motor sets `$TERM` or `$USER`:
`russhd` exports only `HOME`, `PATH`, `COLUMNS`, and `LINES` to a session. And
the serial console never reports a terminal size, because `sys-tty`
deliberately takes no part in the size protocol (`docs/tui.md`); rush still
exports `COLUMNS`/`LINES` there from its own probing.

## 2. Goals and non-goals

The initial command family must support these forms:

```text
ssh user@host
ssh -p 2222 -o IdentitiesOnly=yes -i PATH motor@192.168.4.2 [COMMAND ...]
scp [OPTIONS] SOURCE... TARGET
sftp [OPTIONS] [user@]host
ssh-copy-id [OPTIONS] [user@]host
ssh-keygen [OPTIONS]
```

The goal is command-line compatibility, not every OpenSSH option. Unsupported
options get a short diagnostic and exit status 255 for `ssh`, or 1 for the
other commands. No option is accepted and then ignored. The one literal
exception is `-F /dev/null`, which asks for exactly the behavior this client
always has: no configuration file.

Initially out of scope are SSH configuration files, agents, certificates,
keyboard-interactive authentication, connection multiplexing, forwarding,
proxy commands, X11, environment forwarding, escape commands other than `~.`
and `~~`, hashed, marker, or pattern entries in `known_hosts`, legacy SCP
protocol, remote-to-remote copies, and non-UTF-8 remote names. No server
protocol, authentication, or configuration behavior changes;
the only server behavior change is the SFTP permission correction in section
7, and the host binary binds its listener explicitly so it can report an
actual ephemeral test address. In particular, `ssh-copy-id` does not alter
`russhd`'s TOML authentication configuration; it installs a key on conventional
remote servers that use `~/.ssh/authorized_keys`.

## 3. Command-line surface

All commands share one strict parser for destinations and connection options.
It accepts DNS names, IPv4, bracketed IPv6, `[user@]host`, and `--` to end
options. The default port is 22. If the destination omits a user, use `$USER`
when set and otherwise the Motor convention `motor`; on Motor today `$USER` is
never set, so `motor` is the effective default. Repeated scalar options use the
first value, as OpenSSH does for command-line settings; repeated `-i` options
append identities in their command-line order.

All commands accept `-i FILE`, `-F /dev/null`, and these `-o` options, each
of which names a concept the shared `ConnectionOptions` of section 5 holds
anyway. The repository's own test scripts pass the first five to OpenSSH, and
the host protocol tests of section 9 cannot run without `UserKnownHostsFile`,
`StrictHostKeyChecking`, and `BatchMode`.

| Option | Accepted values | Maps onto |
| --- | --- | --- |
| `IdentitiesOnly` | `yes`, `no` | whether default identities follow `-i` ones |
| `StrictHostKeyChecking` | `ask` (default), `yes`, `accept-new` | the unknown-key policy |
| `UserKnownHostsFile` | path | the known-hosts file |
| `BatchMode` | `yes`, `no` | whether prompts are permitted |
| `ConnectTimeout` | seconds, default 0 | a fresh TCP-connect budget for each destination address; the successful attempt's remainder bounds the SSH banner exchange and key exchange |
| `ServerAliveInterval` | seconds, default 0 | `keepalive_interval`; 0 disables application keepalives |
| `ServerAliveCountMax` | count, default 3 | `keepalive_max` |

`StrictHostKeyChecking=no` and `off` are rejected: they continue past a changed
key, which section 5 never allows.

`ssh` additionally accepts `-p PORT`, `-t`, and `-T`, including the attached
short-option forms. With no remote command and a terminal on stdin, it
requests a pty using `$TERM` (or `xterm`, which on Motor is always the case)
and the current geometry, then requests a shell. With a command, no pty is
requested unless `-t` is given, and the remaining arguments are joined with
single spaces and sent as the SSH exec command, matching OpenSSH's argv
boundary. `-T` never requests a pty; `-t` without a terminal on stdin is an
error rather than OpenSSH's silent downgrade. A shell request without a
terminal on stdin is rejected initially rather than inventing interactive
behavior: OpenSSH would run a shell without a pty there, but `russhd` refuses
that request anyway, so the deviation affects only non-Motor servers. The
terminal decision looks at stdin (fd 0), not at Motor's fd 3 terminal stream,
because a pty relay takes its bytes from stdin.

`scp` accepts OpenSSH's uppercase `-P PORT` and `-r`. Exactly one side of a
transfer may be remote. Multiple local sources are allowed only when the
destination is a directory. Remote syntax is `[user@]host:path`; an empty path
means `.`. `-p` timestamp preservation is not accepted: an upload to a
non-Motor server could honor it in full, but a download to Motor can preserve
only the mode, and one flag with two meanings is worse than a diagnostic.
Source and destination paths are literal; shell and SFTP glob expansion are
outside the initial surface.

`sftp` accepts `-P` and `-b FILE` (`-` means stdin). Its first interactive
verbs are `pwd`, `lpwd`, `cd`, `lcd`, `ls`, `lls`, `get`, `put`, `mkdir`,
`lmkdir`, `rm`, `rmdir`, `rename`, `help`, `bye`, `exit`, and `quit`; `get -r`
and `put -r` use the same recursive transfer engine as `scp`. The command
tokenizer supports whitespace, quotes, and backslash escapes without invoking
a local shell. The interactive `sftp>` prompt is read by the shared line
reader of section 6, because Motor terminals are raw and echo nothing on their
own. Path arguments are literal rather than glob patterns. Batch mode fails at
the first bad command and returns nonzero.

`ssh-keygen` initially generates Ed25519 keys and accepts the common
`-t ed25519`, `-f FILE`, `-C COMMENT`, `-N PASSPHRASE`, `-q`, and `-y -f FILE`
forms. Omitting `-N` prompts twice; an empty passphrase is valid. `-y` prints
the public key derived from a private key. Other key algorithms and
key-management verbs are explicit non-goals for the first version.

`ssh-copy-id` accepts `-i PUBLIC_KEY` and `-p PORT` besides the shared options.
It defaults to the Ed25519 public key, authenticates normally (usually by
password), resolves the remote home with SFTP `realpath(".")`, creates `.ssh`
when needed, and appends the key only when no existing line carries the same
key type and blob, ignoring comments. It sets the conventional directory/file
modes where the remote SFTP server supports them. This avoids interpolating a
key or path into a remote shell command.

## 4. Source, build, and image shape

Keep `src/bin/russhd` as the package and directory name to avoid a server
rename. Add client modules to its library and one `ssh` binary target. The
binary dispatches internal applets only through a private first argument used
by these image scripts:

```text
/user/bin/scp         -> exec /user/bin/ssh --motor-applet=scp "$@"
/user/bin/sftp        -> exec /user/bin/ssh --motor-applet=sftp "$@"
/user/bin/ssh-keygen  -> exec /user/bin/ssh --motor-applet=ssh-keygen "$@"
/user/bin/ssh-copy-id -> exec /user/bin/ssh --motor-applet=ssh-copy-id "$@"
```

Help and diagnostics use the invoked applet name; the selector is accepted only
as the first argument and is not documented as public API. The wrappers are
regular Rush scripts because Motor FS deliberately has no symbolic or hard
links, and this is the pattern every `/system/bin` command already uses
(`/system/bin/ls` is a Rush script that runs `sysbox ls`). They quote `"$@"`
so arguments with spaces survive, and use `exec`, which Rush emulates by
spawning the command with the current descriptors and exiting with its status.
A wrapper is a terminal-backed non-interactive Rush: it stays in Motor's
default Ctrl+C policy and forwards the event to its foreground child, so the
extra process changes nothing about interrupts or terminal status.

The manifest continues to select `russh` and `russh-sftp` exactly as `russhd`
does today. Client code may add only standard Rust, existing Motor libraries,
and crates already present in the locked SSH stack. It promotes `rand` and
`zeroize` to direct dependencies. It must not add `clap`, another SSH/SFTP
implementation, a terminal crate fork, or a second crypto backend.

Runtime shape: the client is synchronous `std` code around one asynchronous
core. Its `main` builds a `current_thread` tokio runtime and `block_on`s the
SSH session, as `russhd` does; the runtime exists because `russh` and
`russh-sftp` require one, not because the client wants one. Terminal I/O,
prompts, the stdin and Ctrl+C threads, local files, name resolution, and the
TCP connect use `std`; the stdin thread hands bytes to the session through
`tokio::sync::mpsc::Sender::blocking_send`, and local transfer I/O is plain
`std::fs` on the runtime thread. The client enables no tokio feature beyond
those `russh` and `russh-sftp` already require: no `fs`, `process`, `io-std`,
or multi-threaded runtime. A synchronous SSH stack was considered and
rejected: none exists in the locked graph, and `ssh2` would add a C library
and a second implementation.
Key generation calls `PrivateKey::random(&mut rand::rng(), ..)` exactly as
`russh` and this package's tests do; no local `CryptoRng` adapter is needed.
`ring`'s custom `getrandom` 0.2 registration moves from `main.rs` into the
library so both executables link it. Pure POSIX-triplet normalization is shared
between the client and server; applying it to local downloads and to existing
server entries remains separate because creation authority and staging differ.

Build and image plumbing: the Makefile gives `russhd` and `ssh` separate
targets, each building its named Cargo binary into the package's shared target
directory and stripping only that binary. `russhd` remains in `user-base`;
`ssh` joins `user`, so constructing a base image neither installs nor
needlessly builds the client. `/user/bin/ssh` is added to `input_files` of
`motor-os.yaml` and `motor-os-dev.yaml`; the four wrappers live in
`img_files/motor-os/user/bin`, which both manifests stage and where the
`/user/bin` policy makes them Interactive-editable scripts. The manifests also
list `/user/cfg/ssh`.
Shipping the empty directory is harmless, and the client creates it on demand
when absent with exact `rwxrwx---` permissions, never with `create_dir_all` over
an existing directory (`docs/fs-permissions.md`). The base image remains
unchanged. Keeping the server and client as separate executables preserves
process isolation even though Cargo shares their dependency graph. Nothing
starts the client at boot.

## 5. Connection and authentication

A shared `ConnectionOptions` value is the only route from any front end to the
SSH transport. It owns the original host spelling, port, user, selected
identity paths, `IdentitiesOnly`, the host-key policy, the known-hosts path,
the connect timeout, server-alive interval and count, and whether prompts are
permitted (`BatchMode=yes` or no usable terminal turns them off). This keeps
`ssh`, `scp`, `sftp`, and `ssh-copy-id` from developing different security
defaults.

Connecting resolves the destination with the standard library, which is the
VDSO `lookup_host` path to `dns-resolver`, and tries each address in turn.
Like OpenSSH's `ssh_connect_direct`, a nonzero `ConnectTimeout` gives each
address a fresh full budget: record a new deadline immediately before each
`std::net::TcpStream::connect_timeout` call, and move to the next address after
a failed or timed-out attempt. The absolute deadline belonging to the
successful attempt is retained, so only that attempt's remaining time bounds
SSH setup. Zero, the default, uses plain `connect` with the system TCP timeout
and no client setup deadline. The connected stream is set non-blocking,
converted with `tokio::net::TcpStream::from_std`, and handed to
`client::connect_stream`.

The remainder of the budget bounds the SSH banner exchange and key exchange,
as `ssh_config(5)` specifies for `ConnectTimeout`; it does not cover user
authentication or the session. The stream is wrapped in a small client-local
`DeadlineStream` whose read and write polls also poll a `Sleep` at that
deadline and return `TimedOut` when it fires. The handler clears the deadline
on entering `check_server_key`: the trust prompt is user time, OpenSSH does
not time it out, and russh has already received the server's `NEWKEYS` and
completed the network-dependent part of the initial key exchange. The
implementation must not put `connect_stream` itself inside
`tokio::time::timeout`: `connect_stream` spawns its session task before
returning, so dropping its outer future would detach a live connection. A
deadline error from the stream instead propagates through the session task
and lets `connect_stream` return its failure normally.

Application-level keepalives follow OpenSSH's defaults: `ServerAliveInterval`
is 0 (disabled) and `ServerAliveCountMax` is 3, mapped onto
`russh::client::Config`'s `keepalive_interval` and `keepalive_max`
(<https://man.openbsd.org/ssh_config.5#ServerAliveInterval>). Motor has no
TCP keepalive, so with the defaults a silently dead peer is noticed only by
`~.` in a pty session or by an actual TCP failure; a script that needs a
bound sets the interval.

On Motor OS, client state lives in `/user/cfg/ssh`; this follows the existing
credential-storage convention and keeps the directory inaccessible to the
None role. `/user/.ssh` was rejected because the `/user` tree policy would
leave it traversable by None. Defaults are `id_ed25519`, `id_ed25519.pub`, and
`known_hosts` below that directory. Explicit `-i` paths remain ordinary paths,
so existing scripts using a checked-out key work unchanged. A host build has
no default directory at all: it never touches `~/.ssh`, and its callers, the
protocol tests, pass `-i` and `UserKnownHostsFile` explicitly.

The known-hosts file holds only known hosts. Each line is
`host key-type base64-key [comment]`, where the host token is `host` for port
22 or `[host]:port` otherwise, exactly the lines OpenSSH writes, so
`src/tests/test-known-hosts` works unchanged. Blank lines and `#` comments are
allowed. Nothing else is: no hashed hosts, no `@` markers, no wildcards or
negation, no comma-separated host lists. A line outside this grammar is an
error naming the line, not a skipped entry; a file imported from OpenSSH with
hashed or pattern lines is fixed by replacing them with plain ones. Lookup
uses the original destination spelling and port, not a DNS result. Host-key
verification gathers the host's records before deciding:

- a record with the same key type and the same key is accepted, even if a
  stale record of the same type is also present;
- otherwise a record with the same key type makes the presented key
  *changed*, which always aborts, including in interactive mode;
- a host known only under other key types, or not known at all, is *unknown*:
  under `StrictHostKeyChecking=yes` it fails; under `accept-new` it is recorded
  and accepted; under the default `ask` the client prints the key type and
  SHA-256 fingerprint and asks on the terminal, and only an exact affirmative
  answer records and accepts it;
- without a usable terminal, or with `BatchMode=yes`, an unknown key fails
  closed.

Because `russh` negotiates the host-key algorithm, the client lists the key
types already known for the host first in `Preferred.key`, as OpenSSH's
`HostKeyAlgorithms` ordering does. Otherwise a server with both Ed25519 and RSA
host keys could present the type the file lacks and prompt on every
connection.

Updates validate the parent and file, take the standard library's advisory
file lock (`File::lock`, which Motor's std implements over the native
facility), and re-read the matching records while holding the exclusive lock.
If another process recorded the same key, the connection continues without a
duplicate; if it recorded a conflicting same-type key, the connection aborts;
only a still-unknown key is appended as one complete line and flushed. This
closes the concurrent first-use race in which two clients could otherwise
accept and record different keys. Motor OS has no symlink race. A malformed
matching record is an error rather than being skipped as if the host were new.

Authentication probes the server's advertised methods with `authenticate_none`,
tries selected private keys in command-line order, then default keys unless
`IdentitiesOnly=yes`, and finally prompts for a password if the server permits
it and prompts are permitted. Identities may be any type `ssh-key` decodes; RSA
keys sign with the hash `best_supported_rsa_hash` reports. Encrypted private
keys are prompted for on demand. Prompt buffers are zeroized after use and are
never logged. The first release does not retry a rejected password
automatically; the rejection is reported and the connection fails.

Identity permissions are checked before secret bytes are read. On Motor, a
private-key file must be a normal file and must grant the None role no access;
on a Unix host build it must be owned by the effective user and must not grant
group or other permissions, following OpenSSH's private-key rule. An unsafe
identity, explicit `-i` or default, is skipped with a warning and
authentication continues with the remaining methods, as OpenSSH does; under
`BatchMode=yes` that usually ends in failure. Tests that stage the
repository's private test identity create the staged copy with private
permissions rather than weakening this check.

## 6. Session and terminal behavior

One async session loop owns each SSH channel. It applies backpressure in both
directions: local input is not read without a bounded handoff, and channel data
is written before the next message is consumed. `ChannelMsg::Data` goes to
stdout, `ExtendedData` goes to stderr, local EOF sends channel EOF exactly once,
and the loop continues draining output until channel close. A reported remote
exit status becomes the local status; transport/authentication failures and a
close without status return 255.

For a non-pty remote command, stdin and both output streams are byte streams;
there is no newline conversion or terminal parsing.

**Terminal size.** For a pty session, Motor's console is already raw. The
client selects a writable local terminal output, preferring stderr and then
stdout, and writes the mode-2048 query and enable sequences described in
`docs/tui.md` there. It never writes terminal controls into a redirected file.
If neither output is a terminal, it skips negotiation and uses the environment
fallback below.

The client consumes exactly the replies to what it asked: DECRPM replies in
*any* state, because an xterm on the serial console answers the query with
`CSI ? 2048 ; 0 $ y` and that must not reach the remote as keystrokes, and
`CSI 48 ; rows ; cols ; height ; width t` reports. A report is valid only with
non-zero `u16` rows and columns; colon sub-parameters are tolerated and ignored,
and a malformed report is forwarded rather than believed, the same rules the
crossterm Motor backend applies. Each new valid size sends one SSH
window-change request.

The reply recognizer is client-local under `src/bin/russhd`, using the existing
`moto_tooling::mode2048` wire constants but making no change under `src/sys`.
It treats stdin as a byte stream: a possible reply prefix is retained across
arbitrary read boundaries and is limited to 64 bytes. A complete reply is
consumed; a byte that makes the candidate impossible flushes the candidate
unchanged; an overlong candidate is likewise ordinary input. An incomplete
candidate is held for a 50 ms *idle* disambiguation interval, reset by each
candidate byte, and is forwarded unchanged when that interval expires or on
EOF. Thus a split terminal write remains recognizable while a user's lone
Escape key has a small, fixed maximum delay. This timer is protocol framing,
not a retry or a probe timeout. Non-candidate bytes are never delayed. Resize
recognition runs before the `~.` escape recognizer so swallowed control replies
cannot affect its start-of-line state.

There is no polling ladder and no made-up resize. Before the first report, use
valid `COLUMNS`/`LINES`, otherwise 80x24. On the serial console no report ever
arrives, so the remote pty keeps the size rush exported when the command
started: right at launch, stale after a console resize. That is an accepted
first-release limitation.

When negotiation was enabled, the mode is disabled through the same terminal
output on every normal error and exit path. This is an explicit step on the
exit path as well as an RAII guard, because `process::exit` runs no destructors.

**Ctrl+C.** Motor delivers terminal Ctrl+C as a control event rather than
input byte `0x03`, and a process without a handler is terminated with status
130 (`docs/tui.md`). Only a pty session registers the native handler, after the
prompts and once the relay owns the input source; its waiter feeds `0x03` into
the same ordered input queue as keyboard bytes, so Ctrl+C reaches the remote
foreground process instead of killing the local transport. Every other mode, a
non-pty command, a transfer, a batch, a prompt, stays in the default policy
and exits 130, which is what OpenSSH does with SIGINT there and what rush
expects from an interrupted foreground command. Injecting `0x03` into a non-pty
channel would deliver a data byte, not an interrupt.

**Escape.** A pty session honors one escape command: `~.` at the start of a
line (after CR or LF, or as the first input bytes) closes the session, and
`~~` sends a literal tilde. Nothing else after a tilde is interpreted. With
Ctrl+C forwarded to the remote, this is the only local escape from a stalled
pty session unless `ServerAliveInterval` is set; by default it is not, and
Motor has no TCP keepalive (section 5).

**Input and output paths.** Local input is read by a dedicated `std` thread
with a bounded handoff into the session loop (`blocking_send` on a tokio
channel); the Ctrl+C waiter is a second thread feeding the same queue. On
session end the process exits without waiting for a blocked read, and the
VDSO returns unread type-ahead to the terminal source.

**Prompts and line editing.** Motor terminals echo nothing and edit nothing,
so the client has one shared line reader with an echo flag. It serves the
password, passphrase, and trust prompts without echo and the interactive
`sftp>` prompt with echo, handles Backspace and DEL, Ctrl+U, and both CR and
LF as Enter, and leaves Ctrl+C to the default policy. Its source is fd 0 when
that is a terminal, otherwise Motor's read-only terminal fd 3. Prompt output
uses stderr when it is a terminal, otherwise terminal stdout. A prompt is
usable only when both a terminal input and a terminal output exist; otherwise
host-key and authentication prompting fail closed, even if fd 3 alone is
present. Prompts run before a pty relay owns the input source, so two readers
never race for terminal bytes, and a prompt issued from an async callback such
as `check_server_key` runs on `spawn_blocking` so the runtime is not blocked.

## 7. SFTP and copy engine

After authentication, the transfer layer opens a session channel, requests
the `sftp` subsystem, and constructs
`russh_sftp::client::RawSftpSession` from the channel stream. It initializes
SFTP v3 and applies a server's `limits@openssh.com` values when advertised. All
SFTP front ends share path joining, metadata translation, copying, handle
closure, and recursive traversal code.

OpenSSH Portable, which is the normal Linux client, has no independent SFTP
request deadline: its SFTP packet reads wait on the SSH transport and are ended
by a transport failure, an explicitly configured SSH keepalive, or an
interrupt. See
<https://github.com/openssh/openssh-portable/blob/master/sftp-client.c>.
`russh-sftp` unconditionally wraps each request in a timeout and defaults it to
10 seconds, but accepts a `u64` seconds value. The client sets it to `u64::MAX`;
the locked Tokio 1.47.1 converts the resulting unrepresentable deadline to its
far-future sleep (roughly 30 years), effectively giving the OpenSSH behavior
for a process lifetime without a dependency patch. A test locks that
assumption, and any Tokio or `russh-sftp` update must revalidate it. Interrupt
behavior remains bounded by section 6 rather than by an SFTP timer.

The raw API issues one file request at a time, using at most 261,120 bytes or a
smaller advertised server limit. Throughput is therefore about one chunk per
round trip: adequate on the private network and a LAN, slow across a WAN. The
first release accepts this and leaves pipelined reads and writes as later work.

Transfers use one fixed-size buffer and checked byte counters; file length and
offset conversions cannot wrap. Every file and directory handle receives an
explicit `CLOSE`, including on normal EOF, and a `CLOSE` error fails the
operation. A partially written destination is reported, never presented as
success. Local downloads use a sibling staging file with an unpredictable
128-bit suffix and create-new semantics, then rename it after data, metadata,
and handles are finalized. One name collision fails the operation rather than
retrying. An interrupted download therefore does not replace an existing good
file; Motor's `std::fs::rename` replaces an existing target atomically.

Directories are created with private, current-role-writable staging
permissions and receive their translated final permissions only after all
children have completed. Uploads use the same post-order rule remotely, and
files are opened owner-writable before a final `FSETSTAT`/`SETSTAT`. This avoids
making a read-only directory impossible to populate while ensuring temporary
remote permissions never expose content to group or other roles.

Recursive downloads treat every remote directory entry as untrusted. The
client loops over raw `READDIR` responses and consumes each response before
asking for the next, so memory is bounded by one SSH/SFTP packet rather than by
the total directory size; `ls` consequently preserves server order instead of
sorting the entire directory. An entry must be one normal UTF-8 component:
empty names, `.`, `..`, separators, absolute paths, and unsupported file types
are rejected. Recursion is limited to 64 levels, the same depth as OpenSSH, and
never follows symlinks. Upload traversal likewise rejects local non-file,
non-directory entries. This prevents a malicious server or local tree from
escaping the selected destination without imposing an arbitrary total-file
limit on a streaming transfer.

The client and corrected server share the same conservative normalization of
POSIX triplets, replacing the current server policy that collapses any writable
mode to `0666`. Their creation and staging paths remain separate. The transfer
layer applies these directional rules:

- On a download to Motor, remote owner bits map to the client's current role,
  remote other bits map to every lower role, and remote group bits are ignored
  because Motor roles are not Unix groups. Bits that Motor cannot represent
  without granting extra access are removed, and the lower-role value is
  intersected with the owner value to preserve
  `None ⊆ Interactive ⊆ System`. A regular file that requests write and execute
  keeps execute and drops write, matching Motor's permitted one-way `Rw → Rx`
  finalization; directories may retain both because `x` means traversal.
  Staging initially gives the current role write access and lower roles none.
  Strictly higher roles remain `Rwx`, as Motor requires for entries created by
  a lower role and does not permit that creator to narrow later. Thus ordinary
  `0600`, `0644`, and `0755` files become respectively `rwxrw----`,
  `rwxrw-r--`, and `rwxr-xr-x` for an Interactive client. Missing mode metadata
  defaults to private `rwxrw----` for a file and `rwxrwx---` for a directory.
- On an upload from Motor, the current role's bits become the remote owner
  bits, None's bits become remote other bits after the same intersection, and
  remote group bits are zero. A private Motor credential therefore requests
  `0600`; the client itself never broadens that request to `0666`. On a Unix
  host build, uploads and downloads use the ordinary POSIX mode with a private
  staging mode while bytes are being written.
- `ssh-copy-id` requests its conventional remote `0700` directory and `0600`
  file modes directly; a remote server may narrow requested modes through its
  own policy or umask.

Only the mode is translated. Uid, gid, symlinks, and timestamps are not
fabricated, and listings label missing metadata as unknown instead of
substituting plausible values.

### Server-side permission correction

Current `russhd` folds every requested POSIX class into one value: `0600`
becomes `0666`, `0700` becomes `0555`, and `0400` becomes `0444`, and its
tests assert exactly those folded results. Motor has distinct System,
Interactive, and None permissions, so that mapping exposes a nominally private
upload to None; the owner has asked for this to be fixed as part of this
project. This project replaces
the folding in every SFTP path: `OPEN`, `SETSTAT`, `FSETSTAT`, `MKDIR`, `STAT`,
`LSTAT`, `FSTAT`, and directory entries.

For an incoming mode, POSIX owner is the role running `russhd`, POSIX other is
the public value assigned to every lower role, and POSIX group is ignored.
Write or execute without read becomes no access because Motor gates both with
read. The public value is intersected with the owner value. A regular file
requesting both write and execute becomes `Rx`; a directory may be `Rwx`.
Strictly higher roles retain their existing permissions. For a newly created
entry they must be `Rwx`, because the filesystem requires a lower-role creator
to leave higher roles fully permissive. `russhd` normally runs as Interactive,
so representative results are:

| SFTP request | Motor file or directory mode | Mode reported over SFTP |
| --- | --- | --- |
| file `0600` | `rwxrw----` | `0600` |
| file `0644` | `rwxrw-r--` | `0644` |
| file `0700` | `rwxr-x---` | `0500` |
| file `0755` | `rwxr-xr-x` | `0555` |
| file `0400` | `rwxr-----` | `0400` |
| directory `0700` | `rwxrwx---` | `0700` |
| directory `0755` | `rwxrwxr-x` | `0755` |

Outgoing attributes encode the current role as POSIX owner and the intersection
of all strictly lower roles as both group and other; when there is no lower
role, the public value is no access. Duplicating the public value keeps
conventional `0644` and `0755` displays while avoiding a fictitious Unix group
distinction; imported group-only access is deliberately lost. Higher Motor
roles are not exposed as POSIX owner permissions for the connected user.

New Motor files are created through
`FsClient::create_entry_with_permissions`, never through the ordinary default
that initially grants lower-role read access. File staging is
`Rwx` for higher roles, `Rw` for the server role, and no access below it; an
absent requested mode defaults to that private `0600` view. A new directory is
created atomically with its translated final permissions, defaulting to a
private `0700` view when attributes are absent. The server sends no successful
`OPEN` or `MKDIR` reply until this secure state exists.

For an existing file opened for writing, the server snapshots its complete
Motor permissions, narrows all lower roles to no access before acknowledging
the handle, and leaves the current and higher roles unchanged. Every requested
file mode is deferred until `CLOSE`, not only executable modes: the server
first flushes the file and then atomically installs the translated final role
permissions. With no requested mode, a successful close restores the original
lower-role values. A dropped connection leaves the entry private rather than
re-exposing a possibly partial transfer. A mode change that would widen the
server's own role or alter a higher role fails with `PermissionDenied`, as the
Motor filesystem requires.

This narrowing rule is uniform on purpose: it applies to every writable open,
`APPEND` included, and has no special cases. Every `russhd` session is
Interactive, so POSIX owner is always Interactive and POSIX other is always
None; the only party whose access changes during a write, or after a dropped
connection, is a None-role service, and no such service legitimately reads a
file an SFTP client is in the middle of writing. No SSH user ever sees
another SSH user's file narrowed, because there is only one SSH role.

On Unix host builds, `russhd` applies the requested POSIX mode directly and
uses private `0600` staging instead of Motor role translation. This makes the
host protocol fixture behave like a Unix SFTP server rather than retaining the
Motor-only compatibility fold.

## 8. Key-file safety

Key generation creates the destination directory when it is absent, before
opening either file, uses create-new semantics, and refuses to overwrite an
existing private or public key. On Motor the private key is created with its
final mode `rwxrw----` (the required higher-role `Rwx`, Interactive read/write,
None nothing) through
`moto_io::fs::FsClient::create_entry_with_permissions`, the call strobe uses
for its logs, so no secret byte is ever written to a file None can read, even
under `-f` outside `/user/cfg/ssh` where no directory hides it. On other hosts
it is created `0600`. Both files are flushed, and failures remove only
temporary files created by that invocation. The public file contains OpenSSH
text plus the requested comment and is created with the ordinary public file
mode (`rwxrw-r--` on Motor, `0644` subject to umask on Unix).

The `russh`-reexported `ssh-key` implementation supplies Ed25519 generation,
OpenSSH encoding, encryption, decryption, and fingerprints, with randomness
from `rand::rng()`. Secret strings and key material are kept in zeroizing types
where the stack provides them and are not copied into general error values.

## 9. Tests and acceptance gates

Parser, destination, known-host, prompt, terminal recognizer (including the
crossterm parser's malformed-report cases, every read split, the 50 ms expiry,
and the 64-byte cap), SFTP command, incremental `READDIR`, safe path,
bidirectional permission, private-identity, and key-file behavior receive host
unit tests. A paused-time test also advances past 10 seconds and proves the
configured SFTP request remains pending, then completes it normally; this locks
the no-deadline behavior without making the suite wait in real time.

Protocol tests use loopback only and run an actual host build of this package's
`russhd` with a temporary config, host key, user key, and SFTP tree. For these
tests, `russhd` binds its configured `127.0.0.1:0` listener explicitly, obtains
`local_addr()`, logs a stable `Listening on ADDR` readiness line, and passes the
listener to `Server::run_on_socket`. The test reads that line under a process
startup deadline and therefore learns the kernel-selected port without a
bind-close-rebind race or readiness retries. It finds both executables through
`CARGO_BIN_EXE_russhd` and `CARGO_BIN_EXE_ssh` and terminates the child server
at teardown.

These tests run inside the `cargo test` invocation `src/tests/full-test.sh`
already makes for this package. They rely on `UserKnownHostsFile` and
`StrictHostKeyChecking=accept-new`, which is why those options are in the first
release. They cover public-key and password auth, unknown/matching/changed and
duplicate host keys, shell, remote command stdout/stderr/status, stdin EOF,
upload/download, recursive copy, batch SFTP, duplicate `ssh-copy-id`, encrypted
and insecurely-permissioned identities, the shared directional mode mapping,
Unix server mode preservation, secure Motor staging and abandonment, and a
peer that stalls during initial SSH setup. The stalled-setup test also verifies
that timeout closes the peer rather than leaving a detached `russh` session
task.

The existing permission section in `src/tests/test-sftp.sh` is changed from
testing the obsolete union to testing the role-aware contract. On Motor,
uploaded `0600` and `0400` files round-trip with those modes, while a `0700`
regular file reports `0500` after safe `Rw → Rx` finalization and remains
executable. Direct Motor metadata checks assert the complete modes in the table
above, and a None-role child proves private content cannot be opened during or
after a transfer. A deliberately abandoned upload proves it remains private.
The Unix host protocol case separately proves that `0600`, `0700`, and `0400`
are preserved as ordinary POSIX modes.

Motor integration runs the client inside the VM against the VM's own `russhd`
over loopback: `loopback = true` is in the shipped `sys-net.toml`, `russhd`
listens on `0.0.0.0:2222`, and systest already exercises TCP on 127.0.0.1. This
needs no host-side server and exercises both Motor endpoints. It covers the two
required `ssh` command forms, both copy directions, and the initial SFTP verbs.
A host-side setup step uploads the repository's fixed test identity into
`/user/cfg/ssh` and removes it during teardown; the corrected server installs
its requested `0600` mode as `rwxrw----` without an intermediate lower-role
grant, and the private identity is not added to the normal image.
A host-run `russhd` on the VM's private test network, following the host-echo
pattern of `src/tests/test-udp-fragmentation.sh`, is used only for what
loopback cannot provide: a `~/.ssh` tree for `ssh-copy-id` and a second host
key for the changed-key path. Neither contacts the Internet.

The terminal harness nests the Motor client inside the forced-pty host session
that `src/tests/test-terminal-size.sh` and `src/tests/test-tui.sh` already
drive, so a host resize and a host Ctrl+C travel the whole chain. It verifies
raw byte preservation, resize forwarding, Ctrl+C reaching the remote in a pty
session and terminating the client in every other mode, `~.`, and restoration
of the local terminal mode. The test is called by `src/tests/full-test.sh`
directly or transitively.

The recognizer remains under `src/bin/russhd` and this design changes nothing
under `src/sys`, so this is non-core work and the component suite is the primary
gate. The completed image change also receives debug and release main-image
coverage, Clippy with no new warnings, repository `cargo fmt`, and the
release-only developer-image gate `src/tests/full-test-dev.sh --release`. If
implementation unexpectedly requires a `src/sys` change, work stops for review
and the core debug/release three-runs-each gate applies. No test adds retries,
relaxed failures, longer real-time timeouts, or external network access.

## 10. Reviewed design decisions

The implementation plan below assumes these deliberate choices are final:

- keep client and server in one Cargo package/lockfile, but separate ELF
  executables;
- use one client multicall ELF plus Rush wrappers to control image size;
- store Motor client credentials under `/user/cfg/ssh` rather than
  `/user/.ssh`;
- ship the command family in normal and development images, not the base image;
- implement `ssh-copy-id` through SFTP and explicitly leave `russhd`'s TOML
  authentication model unchanged;
- support only Ed25519 generation and the command/options enumerated above in
  the first release, including the seven `-o` options, `-F /dev/null`, and
  `-t`/`-T`;
- keep the client's own code synchronous on `std`, with a single-threaded
  tokio runtime only because `russh` and `russh-sftp` require one;
- match OpenSSH's `ConnectTimeout`: a fresh budget for every destination
  address, with the successful attempt's remainder bounding the banner
  exchange and key exchange;
- match OpenSSH's defaults of no application-level keepalive
  (`ServerAliveInterval` 0, settable) and no independent SFTP request
  deadline; Motor has no TCP keepalive to fall back on;
- keep `known_hosts` to plain `host key-type key` lines with no hashed,
  marker, or pattern entries, and treat any other line as an error;
- retain possible terminal-reply prefixes across reads with a bounded 50 ms
  idle hold and keep that recognizer client-local rather than changing
  `moto-tooling`;
- register the Ctrl+C handler only for pty sessions and stay in the default
  policy everywhere else;
- honor `~.` and `~~` as the only escape commands;
- use raw incremental SFTP operations and the conservative owner/public
  translation in both directions, replacing the server's obsolete permission
  folding with secure staging and role-aware attribute reporting;
- test the Motor client against the VM's own `russhd` over loopback, with a
  host-run `russhd` on the VM's private network only for the two cases guest
  loopback cannot cover.

No implementation choice is intentionally left open. If an API or Motor
behavior assumed above proves unavailable, implementation stops for another
design review rather than substituting a silent compatibility or security
compromise.

## 11. Step-by-step implementation plan

Implement this as the ordered patch series below. Each patch should normally
contain 100–300 lines of production code and its tests, compile on both Linux
and Motor, and leave the package usable at its new level of functionality.
Pure preparatory code must have direct unit coverage; do not land unused
frameworks for later patches. The server permission change is the one likely
exception to the size target: its creation, staging, and close invariants must
remain coherent at every commit. If it needs splitting, land tested pure
translation helpers first, then change all security-sensitive handlers
together rather than exposing a partially converted server.

The intended source layout is `src/client` for shared connection, terminal,
and transfer code; `src/applets` for the five command front ends;
`src/permissions.rs` for pure POSIX/Motor translation shared with the server;
and `src/bin/ssh.rs` for runtime construction and private applet dispatch. Keep
the existing server modules and `src/main.rs` focused on `russhd`.

1. **Create the client binary and common argument model.** Move the Motor
   `getrandom` 0.2 registration into the library, promote `rand` and `zeroize`
   to direct dependencies, add the `ssh` binary, and add the private first-arg
   applet selector. Implement destination parsing and `ConnectionOptions`,
   including all seven `-o` keys, `-i`, and `-F /dev/null`; unit-test DNS,
   IPv4, bracketed IPv6, users, ports, attached options, `--`, defaults,
   duplicate-option precedence, and strict rejection of unsupported input.

2. **Add the five command parsers.** Parse the `ssh`, `scp`, `sftp`,
   `ssh-keygen`, and `ssh-copy-id` surfaces from section 3 into typed applet
   arguments, without performing I/O yet. Cover both required `ssh` forms,
   remote-command joining, remote/local SCP classification, batch SFTP,
   key-generation modes, exit-status conventions, and diagnostics naming the
   selected applet. This patch fixes the accepted API before transport work
   begins.

3. **Introduce and test permission normalization.** Add pure helpers that
   normalize POSIX owner/other triplets, discard group, distinguish files from
   directories, intersect public access with owner access, encode Motor role
   permissions back to SFTP, and preserve ordinary Unix modes. Exhaustively
   unit-test all permission triplets plus the representative table in section
   7. No SFTP handler changes in this patch.

4. **Correct `russhd` SFTP permissions as one security unit.** Replace the
   union mapping in `sftp_session.rs`; use exact POSIX modes and private
   staging on Unix, and on Motor use atomic permission-aware creation for new
   files and directories. Snapshot and narrow existing writable files before
   acknowledging `OPEN`, defer every requested writable-file mode until after
   flush on `CLOSE`, restore the snapshot when no mode was supplied, and leave
   abandoned writes private. Apply the same translation to `SETSTAT`,
   `FSETSTAT`, `STAT`, `LSTAT`, `FSTAT`, and directory entries. Handler tests
   cover create, truncate, append, close failure, absent modes, final modes,
   and ordinary Unix preservation.

5. **Replace the obsolete server integration assertions.** Update
   `src/tests/test-sftp.sh` to assert the role-aware modes, atomic private
   creation, deferred finalization, and abandonment behavior. Use `ls -l` for
   complete Motor metadata and a child launched with
   `MOTOR_OS_CAPS=0x4` (`CAP_SPAWN`, but no role capability) to prove the None
   role cannot read the upload during or after transfer; do not modify
   `src/sys` for this test. Run the package tests and this focused VM SFTP test
   before proceeding with client work.

6. **Add terminal-safe prompting and local security primitives.** Implement
   terminal input/output selection, the echoing and non-echoing line reader,
   zeroized secret input, exact creation of `/user/cfg/ssh`, private-file
   creation, and identity permission validation for Motor and Unix. Unit tests
   cover editing keys, CR/LF, unavailable terminals, secure directory/file
   modes, existing paths, unsafe identities, and cleanup after failures.

7. **Implement known-host parsing and decisions.** Add the literal-line parser,
   canonical host token construction, fingerprint display, algorithm
   preference ordering, matching/changed/unknown classification, and the
   `yes`/`ask`/`accept-new` policies. Add locked re-read-and-append updates and
   tests for comments, malformed input, alternate ports, duplicate matches,
   conflicting concurrent updates, and fail-closed noninteractive behavior.

8. **Make `russhd` a deterministic host protocol fixture.** Bind the
   configured listener explicitly, log `Listening on ADDR`, and pass the
   socket to `run_on_socket` without changing normal server configuration.
   Add test support that spawns `CARGO_BIN_EXE_russhd` on `127.0.0.1:0`, waits
   for that one readiness line under a deadline, supplies temporary host/user
   keys and config, and always terminates the child. There are no connection
   retries or bind-close-rebind window.

9. **Implement TCP setup and SSH deadlines.** Resolve addresses with `std`,
   give every address a fresh `ConnectTimeout`, retain the successful
   attempt's absolute deadline, convert the connected nonblocking stream into
   Tokio, and add `DeadlineStream`. Configure the two server-alive values and
   clear the setup deadline in `check_server_key` after initial KEX. Tests use
   deterministic local listeners to cover address fall-through, a fresh
   budget for a later address, zero timeout, stalled banner/KEX, deadline
   clearing, keepalive defaults, and closure of a timed-out peer without a
   detached russh task. Test the address-attempt policy with an injected clock
   and connector so a simulated first-address timeout is deterministic; use
   real local sockets for the SSH stream and stalled-peer cases.

10. **Implement authentication.** Probe advertised methods, load explicit
    identities in order, conditionally add the default Ed25519 identity, prompt
    for encrypted-key passphrases and one password, and select the supported
    RSA signature hash. Skip unsafe or undecodable identities with diagnostics
    while preserving fail-closed batch behavior. Host protocol tests cover
    unencrypted and encrypted keys, password authentication, method fallback,
    `IdentitiesOnly`, rejection, and absence of usable credentials.

11. **Add non-pty SSH sessions.** Open a session channel, issue an exec request,
    relay stdin with bounded buffering, separate ordinary and extended data,
    send EOF once, drain through close, and map remote or transport status as
    specified. Host protocol tests cover the required scripted command form,
    exact stdin/stdout/stderr bytes, EOF-sensitive commands, remote nonzero
    status, and close without status.

12. **Add pure terminal input recognition.** Implement the bounded mode-2048
    reply recognizer, 50 ms idle expiry, size validation, and the start-of-line
    `~.`/`~~` recognizer as independent state machines. Test every split of
    valid reports, malformed and overlong input, prefix expiry, lone Escape,
    ordering between resize and escape handling, and raw-byte preservation.

13. **Add pty SSH sessions.** Query and enable terminal sizing only on a
    writable terminal, choose environment or 80x24 fallbacks, request the pty
    and shell/exec operation, send window changes, and restore mode 2048 on all
    explicit and guarded exits. Add the Motor-only Ctrl+C waiter after prompts
    and merge its `0x03` events into the ordered bounded input queue. Host tests
    cover pty request parameters and escape termination; Motor terminal-chain
    coverage remains for step 24.

14. **Implement `ssh-keygen`.** Generate Ed25519 private/public key pairs,
    optional OpenSSH passphrase encryption, comments, quiet mode, and `-y`
    public-key extraction using the secure file primitives. Tests cover empty
    and nonempty passphrases, confirmation mismatch, decode round trips,
    comments, refusal to overwrite either output, exact Motor/Unix modes, and
    failure cleanup.

15. **Establish an SFTP client session.** Open the subsystem channel, construct
    and initialize `RawSftpSession`, consume advertised extensions and limits,
    and set its request timeout to `u64::MAX`. A paused-time test advances past
    ten seconds while a mock request remains pending and then completes it;
    add Tokio's test-only time support only for this test, not to the Motor
    binary feature set.

16. **Implement single-file transfers.** Add checked-offset incremental reads
    and writes, explicit handle closure, remote upload staging/final modes, and
    local create-new sibling staging followed by final metadata and rename.
    Tests against the host fixture cover empty, multi-packet, truncated,
    replaced, read-only, executable, interrupted, close-error, and advertised
    smaller-limit cases in both directions.

17. **Implement safe recursive transfer.** Add literal path joining, validation
    of every untrusted remote directory entry, incremental `READDIR`,
    post-order directory finalization, local type rejection, and the depth-64
    bound. Tests cover nested and empty directories, preserved server order,
    malformed and escape components, unsupported types, depth 64/65, bounded
    directory memory, and cleanup/permissions after a child failure.

18. **Expose the SCP applet.** Map one-remote-side SCP syntax onto the shared
    file and recursive engines, including uppercase `-P`, `-r`, multiple local
    sources only for a directory target, empty remote paths, and literal path
    behavior. Host protocol tests cover uploads, downloads, recursion,
    multi-source validation, and rejection of remote-to-remote and unsupported
    OpenSSH options.

19. **Expose the SFTP applet.** Add the quote/backslash tokenizer, interactive
    prompt, batch rules, local and remote working directories, and every verb
    listed in section 3. Reuse the transfer engine for recursive `get`/`put`.
    Unit tests cover parsing and command-state transitions; host protocol tests
    cover all verbs, first-error batch exit, stdin batches, and literal paths.

20. **Expose `ssh-copy-id`.** Read and validate the selected public key, resolve
    the remote home through SFTP, create `.ssh`, compare key type/blob while
    ignoring comments, and append exactly once with `0700`/`0600` requests.
    Host fixture tests cover new and existing files, comments, duplicate keys,
    preservation of unrecognized remote lines, and a home/path containing
    shell metacharacters to prove no remote shell interpolation occurs.

21. **Add build and image integration.** Give `ssh` its own Make target and add
    it to `user`, add `/user/bin/ssh` and `/user/cfg/ssh` to the normal and
    development manifests, and add the four quoted Rush wrappers under the
    normal-image overlay. Extend imager tests to prove that normal/development
    images include the client and wrappers while the base image includes none
    of them. Verify the server and client are separate stripped executables and
    no boot configuration changed.

22. **Add non-terminal Motor client coverage.** Add a focused script under
    `src/tests` and invoke it from `full-test.sh`. Stage the repository's private
    test identity with `0600` through the corrected server, then run the Motor
    client over guest loopback for both required `ssh` forms, exit statuses,
    both SCP directions, batch and representative interactive SFTP verbs, and
    key generation. Remove the staged identity and all transfer fixtures at
    teardown.

23. **Add the private-network compatibility cases.** Start a host `russhd` on
    the existing test-only VM network, with an isolated home and two fixture
    host keys. From the Motor client, cover `ssh-copy-id`, unknown/matching/
    changed host keys, password fallback, and a conventional `.ssh` tree.
    Reuse the established host-service lifecycle and network isolation; do not
    contact the Internet or add readiness retries.

24. **Add end-to-end terminal coverage.** Extend the existing forced-pty
    harness, or add a focused script called by it, to nest the Motor client in
    a host SSH pty. Verify initial size, resize forwarding, byte-transparent
    input/output, Ctrl+C delivery to the remote pty, local status 130 outside a
    pty, `~.` and `~~`, 50 ms prefix expiry, and mode-2048 restoration after
    normal exit, remote failure, and local escape.

25. **Run final acceptance gates.** Run `cargo fmt` with the selected toolchain,
    the `russhd` host tests in debug and release, Motor-target builds and Clippy
    with no new warnings, then `src/tests/full-test.sh` in debug and release and
    `src/tests/full-test-dev.sh --release`. Do not add a debug developer-image
    run because this is not Lorry work. All protocol fixtures remain local, and
    any failure is diagnosed rather than hidden with a retry, timeout increase,
    ignored result, or relaxed assertion.

After every numbered patch, run the narrowest relevant package/unit/protocol
test before committing it. Steps 5, 22, 23, and 24 are wired directly or
transitively into `src/tests/full-test.sh`; the package is already in that
script's host-test loop. Stop for design review if the locked APIs cannot
provide the documented behavior, if a change under `src/sys` becomes
necessary, if an additional dependency/fork/patch appears necessary, or if a
new preexisting non-test bug is found.
