# rmux — a terminal multiplexer for Motor OS

A pure-Rust, dependency-free clone of the useful half of tmux, built to the
defaults in `~/.tmux.conf`, in the manner of `red` and `rush`: raw ASCII over the
console, minimal redraws, behavior checked against the Linux prototype.

This document is the plan. It is meant to be cited from doc comments the way
`rush`'s README is ("a Phase 3 limit", "§0.1"), and to be edited as the phases
land.

---

## 1. What rmux is

A terminal multiplexer: one physical console, many independent programs, each
believing it owns a terminal. rmux runs a **server** that owns those programs,
and a thin **client** that attaches to the server, relays keystrokes to it, and
paints what it sends back. Detaching kills the client; the server and everything
running under it live on.

### 1.1 Goals

- The `~/.tmux.conf` at the head of this project specifies rmux's compiled-in
  **defaults** (§2.1). Every option in it works with no config file present, and
  nothing outside it is built without a reason written down here. Overrides live
  in `/user/cfg/rmux.toml` (§2.2).
- Zero dependencies. Rust `std` only — no crates, not even the in-repo Motor
  ones. `red` manages this and so can rmux (§4.6).
- Minimal redraws. The console is a polled 16550 UART; bytes are not free
  (§6.3). Repainting a pane costs the cells that changed, and nothing else.
- Both platforms, one source. It builds and runs on Linux, where it is tested
  against real tmux, and on Motor OS, where it is used.
- Correctness is *measured*, not asserted: a conformance corpus runs each case
  through both rmux and tmux and requires them to agree (§9.1).

### 1.2 Non-goals

Deliberate omissions, each one an entry in `DIVERGENCES` (§9.1) rather than a
silent gap:

- Mouse support. `set -g mouse on` is commented out in the config; it stays
  commented out here.
- The `#{...}` format language, control mode (`tmux -C`), hooks, `if-shell`,
  layouts by name (`select-layout even-horizontal`), pane marking, window
  linking (a window belongs to one session, §7.3), `choose-tree` (a plain session
  list replaces it, §7.3), session groups, `run-shell`.
- The host clipboard. OSC 52 is not implemented in either direction; copy/paste
  is rmux-internal (§7.6).
- Nested-prefix escaping beyond `send-prefix` (§8.2).
- Wide characters. rmux decodes UTF-8 and stores a `char` per cell, but treats
  every character as one column wide — "pure ASCII treatment", per the project
  brief. `rush`'s test emulator makes the opposite choice deliberately
  (`tests/phase8.rs:191`); rmux's panes are not the line editor and do not need
  it. Documented divergence.
- terminfo. rmux emits a fixed, conservative ANSI vocabulary and assumes the
  same of its panes' programs.

---

## 2. Defaults and configuration

### 2.1 `~/.tmux.conf` specifies rmux's *defaults*

The `~/.tmux.conf` at the head of this project is not a file rmux reads. It is the
specification of what rmux does **out of the box**, with no config file present at
all. A user who has never written an `rmux.toml` gets a `C-a` prefix, `S-Left` and
`S-Right` on windows, `M-`arrows on panes, `|` and `-` on splits, vi copy mode,
renumbered windows, and effectively unbounded history.

This is worth stating plainly because it removes a whole component: **rmux never
parses tmux's configuration language.** No `bind`/`unbind`/`set -g` command
grammar, no `if-shell`, no sourcing. Those semantics are compiled in as the
default tables, and the file below only overrides them.

It also gives the oracle its footing (§9.1): a checked-in copy of that file at
`tests/defaults.tmux.conf` *is* the definition of rmux's defaults, and it is what
the conformance harness feeds real tmux with `-f`. When rmux and `tmux -f
tests/defaults.tmux.conf` disagree, exactly one of them is wrong, and the file
says which behavior was meant. That file is the spec and the oracle's config at
once, so the two cannot drift.

Everything rmux must therefore do, read straight off it:

| Config line | What it demands |
| :--- | :--- |
| `unbind C-b` / `set -g prefix C-a` | A rebindable prefix key, defaulting to `C-b`, set here to `C-a`. |
| `bind C-a send-prefix` | `C-a C-a` sends a literal `C-a` to the pane. |
| `setw -g aggressive-resize on` | A window is sized to the smallest client *viewing it*, not the smallest client attached. Only has meaning because we chose a real client-server split (§4.1) — with one client it is a no-op, with two it is not. |
| `bind -n S-Left/S-Right` | A **root** key table: bindings that fire with no prefix. Previous/next window. |
| `bind -n M-Left/M-Right/M-Up/M-Down` | Directional pane selection, no prefix. |
| `set -g history-limit 9999999` | Effectively unbounded scrollback. Drives the memory design (§7.5). |
| `set -g renumber-windows on` | Closing a window renumbers the rest to close the gap. |
| `bind \| split-window -h` / `bind - split-window -v` | Splits, on the prefix table. `-h` is side-by-side, `-v` is stacked. |
| `unbind '"'` / `unbind %` | The default split bindings are removed — so `unbind` must actually remove, not shadow. |
| `set-window-option -g mode-keys vi` | vi keys in copy mode: the scrollback pager, its motions, its search, and its selection (§7.6). |

Plus, per the brief, copy/paste — which `mode-keys vi` is the configuration of,
and which is therefore in scope rather than an extra.

The tmux defaults that file does *not* override still have to exist, because it
is written against them: the prefix table's `c`, `n`, `p`, `0`-`9`, `,`, `&`, `x`,
`o`, `z`, `d`, `[`, `]`, `:`, and arrow-key pane selection.

### 2.2 `/user/cfg/rmux.toml`

Overrides live in a TOML file, exactly as red's do — same location convention,
same parser, same tolerance:

| Platform | Location |
| :--- | :--- |
| Motor OS | `/user/cfg/rmux.toml` |
| Unix | `$HOME/.config/rmux.toml` |

The file is optional; a missing one is not a problem (§2.1). Only the
`key = value` subset of TOML is understood, plus `#` comments and the three
binding tables below — rmux has no dependencies, so there is no TOML crate behind
this, and the same restraint red documents applies here. A malformed entry is
skipped and reported on the message line; the rest of the file still applies.

Settings are named after their tmux equivalents:

```toml
prefix            = "C-a"      # the prefix key
default-shell     = "sh"       # what a pane runs; dash on Linux, rush on Motor (§4.3)
history-limit     = 9999999    # scrollback lines per pane (see §7.5)
renumber-windows  = true
aggressive-resize = true
mode-keys         = "vi"       # "vi" or "emacs"; only "vi" is implemented
status            = true       # show the status line
```

Bindings are three tables, keyed by key name, valued by a command in tmux's
command vocabulary. An **empty string unbinds** — that is how `unbind '"'` is
expressed:

```toml
[bind]              # the prefix table
"|"  = "split-window -h"
"-"  = "split-window -v"
"\"" = ""           # unbind
"%"  = ""           # unbind
"C-a" = "send-prefix"

[bind-root]         # no prefix needed (tmux's `bind -n`)
"S-Left"  = "previous-window"
"S-Right" = "next-window"
"M-Left"  = "select-pane -L"

[bind-copy]         # copy mode
"q" = "cancel"
```

The example above is deliberately a **no-op**: it restates the defaults. That is
the intended shape of the document — it is what `~/.tmux.conf` looks like once
translated, and it is how the two representations are kept legible against each
other.

Only the commands rmux implements are accepted; an unknown command is a skipped
entry with a message, not a silent no-op. The parser is *not* a command language:
the value is split on whitespace into a name and flags, and nothing more.

Config is **injected, not loaded** by the server core, per red's rationale
(`red/src/editor.rs:121-124`): construction does no file I/O, so tests "are not at
the mercy of the config file on the machine running them" (§9.3).

---

## 3. The terminal model on Motor OS

This section is the load-bearing one. Read it before writing code.

### 3.1 Motor OS has no PTYs, and rmux does not need them

A Unix pty is a kernel object with a master end and a slave end; the slave looks
like a terminal to the process holding it. tmux is built on one pty per pane.
Motor OS has no pty, no tty layer, no termios, no ioctl, and no signals. It has
exactly one console — COM1, a polled 16550 UART at port `0x3F8`
(`src/sys/sys-tty/src/serial.rs:83`) — owned permanently by `sys-tty`, with
ownership explicitly non-transferable (`src/sys/kernel/src/uspace/serial_console.rs:45`:
"We do not support transferring console ownership for now").

None of that matters, because **the thing a pty would buy us is already
available**, and two programs in-tree already do exactly what rmux needs:
`sys-tty` (which owns the real console and spawns your login `rush`) and
`russhd` (which answers SSH pty requests with no OS pty whatsoever).

The reason is `is_terminal()`. On Motor OS it is not a property of a file
descriptor at all — it is an environment variable
(`src/sys/lib/rt.vdso/src/rt_fs.rs:1203`):

```rust
pub extern "C" fn is_terminal(rt_fd: i32) -> i32 {
    if rt_fd < 0 || rt_fd > 2 { return 0; }
    let Some(env_var) = moto_rt::process::getenv(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY)
        else { return 0; };
    if env_var == "TRUE" || env_var == "true" { 1 } else { 0 }
}
```

`STDIO_IS_TERMINAL_ENV_KEY` is `"MOTURUS_STDIO_IS_TERMINAL"`
(`src/sys/lib/moto-rt/src/process.rs:30`). So a pane child spawned on plain
pipes, with that variable set, believes it is on a terminal — which is precisely
what `sys-tty:89` and `russhd`'s `local_session.rs:67` already do.

The whole mapping, with no kernel changes and no Motor-specific API:

| POSIX pty gives | rmux gets it from |
| :--- | :--- |
| master/slave byte channel | `Command::stdin/stdout/stderr(Stdio::piped())` |
| slave `isatty() == true` | `.env("MOTURUS_STDIO_IS_TERMINAL", "true")` |
| `TIOCGWINSZ` | rmux answers `ESC[6n` itself, with the *pane's* size (§3.2) |
| `SIGWINCH` | re-answer `ESC[6n`; rewrite `$COLUMNS`/`$LINES` (§3.2) |
| `SIGINT` to a pane | write byte `0x03` into the pane's stdin pipe |
| kill a pane | `std::process::Child::kill()` |
| line discipline | does not exist on Motor, and is not wanted |

Building real PTYs was considered and rejected. It would mean a device
abstraction, an fd-passing mechanism in `spawn` (which today accepts only the
`STDIO_INHERIT`/`STDIO_NULL`/`STDIO_MAKE_PIPE` sentinels,
`moto-rt/src/process.rs:23-25`), and a line discipline Motor deliberately does
not have — to re-implement what an env var already delivers. The one genuinely
valuable piece, answering `ESC[6n` per pane, is terminal-emulator logic and
belongs in rmux regardless.

**Known wart, not ours to fix:** because `is_terminal` is per-process rather than
per-fd, a program with stdout redirected to a file inside an rmux pane still
reports a terminal. This is pre-existing Motor behavior, identical under sys-tty
today. Record it; do not work around it.

### 3.2 Size, without ioctl or SIGWINCH

Motor has no terminal-size call (`rush/src/sys/mod.rs:46`: "Motor OS has no ioctl
and no terminal-size call at all") and no resize notification of any kind.
Programs learn their width by *asking the terminal over the wire*, and this is
what makes rmux tractable: rmux **is** the terminal for its panes.

Three mechanisms, in the order a pane will use them:

1. **Answer `ESC[6n`.** When a pane's program emits a Device Status Report, the
   pane's emulator replies `ESC[{row};{col}R` into that pane's *stdin* pipe.
   Because the emulator clamps the cursor to the pane's own bounds, the
   `ESC[9999;9999H` + `ESC[6n` idiom that `red` uses (`red/src/terminal.rs:74`)
   returns the pane geometry with no change to red at all. **This is not
   optional**: red ignores `$COLUMNS` entirely, and without an answer it either
   reads the physical console size or hangs waiting for a reply nobody sends.
2. **Set `$COLUMNS`/`$LINES`** in each pane's environment. `rush` re-reads
   `COLUMNS` at every prompt (`rush/src/term.rs:858`), so this is a working
   SIGWINCH substitute for shell panes, for free.
3. **On resize**, update both, and let the pane discover it at its next probe.
   Panes are not notified; nothing on Motor can notify them.

#### The two idioms rmux must satisfy

This is not theoretical: the two programs that will live in rmux's panes ask in
two different ways, and rmux must answer both. Both reduce to the same
requirement — **clamp the cursor to the pane's bounds, then report where it
landed** — which is exactly what a real terminal does and why neither program
needs changing.

`rush` (`term.rs:676`) probes for the width only:

```
ESC[?25l  \r  ESC[999C  ESC[6n  \r  ESC[?25h
          ^          ^       ^
          |          |       +-- DSR: rmux answers ESC[{row};{col}R into stdin
          |          +---------- CUF 999, clamped to the pane's right edge
          +--------------------- CR to column 0
```

`red` (`terminal.rs:74`) probes for rows *and* columns:

```
ESC[?25l  ESC[9999;9999H  ESC[6n
                       ^      ^
                       |      +-- DSR: same answer, into that pane's stdin
                       +--------- CUP, clamped to the pane's bottom-right
```

So the emulator must clamp **CUF** and **CUP** to the pane, not the console, and
DSR must report the post-clamp position. Get that right and rush reports the pane
width and red reports the pane's full geometry, with no cooperation from either.
Get it wrong and red silently sizes itself to the physical console — drawing
outside its pane — or hangs waiting for a reply (§3.1).

DSR is the *only* round-trip either program makes; neither uses Device
Attributes. Any other query a pane emits gets no answer, which is a terminal's
prerogative, and is why rush's never-block discipline exists in the first place.

Two related pane-state traps, both from the sequences above: `ESC[?25l`/`?25h` is
**per-pane** state, and only the active pane's cursor is composited onto the real
screen — an inactive pane hiding its cursor must not hide the user's. And the
reply goes to that pane's **stdin**, never to rmux's own stdout.

For rmux's *own* size on the real console, follow **rush's discipline, not red's
implementation**. red blocks reading stdin for the CPR reply
(`red/src/terminal.rs:79-104`), guarded by a `RAW_MODE_ENABLED` global that
exists only to stop that from hanging `cargo test`. rush never waits
(`rush/src/term.rs:663`): it fires the probe and takes the answer as an ordinary
`Key::CursorReport` off the normal key decoder whenever it turns up. The reason
is written down at `rush/src/term.rs:666-672` — a console with nothing on the
other end that answers CPR would hang the program *at startup*, before the user
can type. rmux needs rows as well as columns, so it uses red's sequence
(`ESC[9999;9999H ESC[6n`) with rush's discipline, behind a
`sys::TermImpl::size() -> Option<(usize, usize)>` that the Linux host answers
from `TIOCGWINSZ` — which is also what makes the pty tests possible without
impersonating a terminal.

### 3.3 The console mangles bytes

`sys-tty`'s serial `send()` rewrites what rmux writes (`sys-tty/src/serial.rs:33-57`):
`\n` becomes `\n\r`, and `0x08`/`0x7F` become a *destructive* backspace
(`BS SP BS`). Therefore: **rmux never emits `\n`, `\r` or `BS` for layout.**
Every cell is placed with an absolute `ESC[{row};{col}H`. This is already how
red paints and costs nothing.

`russhd` bypasses `sys-tty` entirely and does its own LF→CRLF translation
(`local_session.rs:202`), so **the serial console and SSH are two different
terminals** and rmux must be tested on both (§9.3).

### 3.4 Enter arrives as CRLF

`sys-tty`'s stdin pump synthesizes a newline (`sys-tty/src/main.rs:127-132`):

```rust
if c != 13 {
    child_stdin.write_all(&[c]).ok();
} else {
    child_stdin.write_all(&[c, 10]).ok();   // CR -> CR LF
}
```

Two consequences. rmux's key decoder must coalesce `\r\n` into one Enter — both
red (`input.rs:143`) and rush (`term.rs:96-108`) already do, by different means.
And when rmux forwards Enter *to a pane*, it must send `\r\n`, not `\r`, because
that is what rush receives under sys-tty today and rush must behave identically
inside rmux and outside it. This is bug-for-bug compatibility with sys-tty, and
it is deliberate; it lives behind `sys::` so the Unix build can send what a real
pty expects.

### 3.5 sys-tty's `^C` echo must go (prerequisite)

`sys-tty/src/main.rs:124-126` writes a literal `"^C"` **straight to the serial
port** when it sees byte 3, bypassing whatever program owns the screen:

```rust
while let Some(c) = serial::read_serial() {
    if c == 3 {
        write_serial_raw(b"^C");
    }
```

Under rmux this punches stray text through the composited screen at whatever
position the cursor happens to be, invisible to the frame diff, which will then
never repair it. It is also redundant today: `rush` prints its own `^C`
(`rush/src/term.rs:906-922`), so the serial console appears to double-echo it.

**Phase 0 task:** confirm the double-echo on the VM, then remove the echo from
sys-tty, leaving it a clean byte pump. This is a change to the OS, agreed as a
prerequisite. If it is ever reverted, rmux's fallback is a full repaint after any
`^C` — a full-screen repaint over a UART, for a keystroke.

### 3.6 Signals: there are none

`rush/src/sys/motor.rs:8-27` states it flatly: no signal delivery of any kind;
the only thing one process may do to another is terminate it. So:

- `^C` in a pane is byte `0x03` written to that pane's stdin. rush interprets it
  (`term.rs:906`); arbitrary programs may not, and that is their business.
- Killing a pane is `Child::kill()` — unconditional, uncatchable.
- `Child::id()` returns 0 on Motor and `std::process::id()` *panics*
  (`rush/src/sys/mod.rs:174`). rmux therefore keys panes by its own `PaneId`
  allocated from a counter, and never by pid. rush learned this the same way
  (`jobs.rs:10-22`).

---

## 4. Architecture

### 4.1 Client and server

Real client-server, as in tmux, decided deliberately: detach/attach is why a
multiplexer is worth having, and `aggressive-resize` in the config has no meaning
without it.

- The **server** owns everything: the session list, windows, panes, each pane's
  child process, each pane's emulator and scrollback, and the layout. It does all
  rendering.
- The **client** is thin and nearly stateless: put the console in the alternate
  screen, relay input bytes to the server, write the server's bytes to the
  console, and restore the console on exit. A few hundred lines.

This is tmux's split and it is the right one: the server renders because the
server is where the state is, and a dumb client means detach/attach is just a
connection closing and opening.

A client attaches to exactly one **session** (§7.3), not to the server at large,
and may switch between them while attached. The CLI is `rmux`, `rmux new`,
`rmux attach`, `rmux ls`, and `rmux kill-session` (§7.3) — nothing else is
planned.

### 4.2 Transport: loopback TCP

The client and server are unrelated processes, so they need a rendezvous. The
constraint is *standard Rust only*, which rules out `moto-ipc`'s `io_channel`
and `sync` channels (Motor-specific), and Unix domain sockets (Motor sets no
target family, so `std::os::unix::net` does not exist there).

That leaves `std::net`. The server binds `127.0.0.1:0`, writes the port it got to
a file, and the client reads the file and connects. Identical code on Linux and
Motor, no `cfg`, no dependencies.

The protocol is small and framed, and deliberately dumb:

- client → server: `Attach { session: Option<String>, rows, cols }`, `Input(bytes)`, `Resize { rows, cols }`, `Detach`
- server → client: `Write(bytes)` — bytes destined for the console, verbatim — and `Exit(code)`

**Loopback TCP works on Motor OS**, and the test suites prove it in plain `std`,
which is what makes this the transport rather than a gamble:

- `src/sys/tests/systest/src/tcp.rs:35` — `std::net::TcpListener::bind("127.0.0.1:3333")`,
  and line 36 asserts the second bind of the same port *fails*, so the port is
  really claimed.
- `src/sys/tests/systest/src/tcp.rs:241-262` — binds `"127.0.0.1:0"`, reads the
  kernel-assigned port back with `local_addr().unwrap().port()`, and connects to
  it. This is rmux's rendezvous, already exercised on Motor.
- `mio-test/src/tcp_stream.rs:745` and `tokio-tests/src/rt_common.rs` do the same
  over the async stacks.

So no spike, no fallback, no `cfg`. rmux's server binds `127.0.0.1:0`, and the
port file is the only extra machinery.

**Trap, from the same test** (`systest/src/tcp.rs:250`): *"If the server is
dropped now, the write above may not be delivered."* Closing a `TcpStream` can
discard unflushed writes on Motor. The protocol must therefore not rely on a
close to deliver anything — the server's final `Exit` to a client, and a client's
`Detach`, must be acknowledged or drained before either side drops the socket.
This is the same drain-before-close discipline `russhd` needs on its pipes
(`local_session.rs:161-166`), in a second place.

The port file needs a writable path. Motor's convention is `/sys/tmp` (a
`static_dirs` entry in `src/imager/motor-os.yaml`); the Linux host uses
`$TMPDIR`. One `sys::` constant.

### 4.3 What runs in a pane: `sh`

A pane runs **`sh`**, not `rush` and not `/bin/rush`. On Linux that is dash; on
Motor OS it is rush. rmux spawns the bare name and neither knows nor cares which,
which is what keeps `pane.rs` free of `cfg`.

This works because Motor already resolves both halves in the **runtime's** spawn
path, before rmux or rush is involved:

- **PATH lookup** — `rt.vdso/src/rt_process.rs` stats `<dir>/<exe>` across `PATH`,
  so a bare `sh` finds `/bin/sh` exactly as `/bin/cc` is found today.
- **Shebang** — `rt_process.rs:170` matches `SCRIPT_MAGIC = *b"#!/"` and
  `run_script` (`:178`) reads the interpreter line, opens it, and `run_elf`s it
  with the script as an argument.

And `/bin/sh` already exists on the image (`img_files/motor-os/bin/sh`), saying
so itself:

```sh
#!/bin/rush

# /bin/sh: the POSIX shell. Motor OS has no symlinks, so this forwards every
# argument to rush -- `sh -c '...'` (what libc's system()/popen() emit), `sh
# script args`, and a bare interactive `sh` all work.
exec /bin/rush "$@"
```

So `Command::new("sh")` from rmux resolves `/bin/sh`, the runtime reads `#!/bin/rush`,
and rush starts. Nothing to build, and no rmux-side shebang handling.

Three limits of Motor's shebang implementation, worth knowing before writing a
config that trips them (`rt_process.rs:178-205`):

- The magic is `#!/` — the interpreter must be an **absolute path**, so
  `#! /bin/rush` and `#!/usr/bin/env rush` do not work.
- The interpreter line is taken whole and `trim()`ed into one filename, so
  **arguments in a shebang are not supported**: `#!/bin/rush -x` would try to open
  a file literally named `/bin/rush -x`.
- `run_script` calls `run_elf`, so an interpreter that is itself a script fails.
  One level only — which `/bin/sh` → `/bin/rush` (ELF) satisfies.

`default-shell` in `rmux.toml` (§2.2) overrides the choice; `$SHELL` is *not*
consulted, because sys-tty's `env_clear()` (`sys-tty/src/main.rs:88`) means it is
usually not set on Motor and would be a portability trap.

### 4.4 Process model and lifetime

`sys-init` is the daemon precedent (`src/sys/sys-init/src/main.rs:77-88`): it
spawns `strobe` with `Stdio::null()` on all three fds and neither tracks nor
waits for it. rmux's server starts the same way — the client spawns it with null
stdio and does not wait — so it has no console and nothing to die with.

**Phase 0 spike:** confirm a process survives its parent's exit on Motor. The
sys-init precedent strongly suggests yes, but detach/attach is worthless if
orphans are reaped, so it must be verified, not assumed.

### 4.5 Threads, not polling

Motor has an epoll-alike (`moto_rt::poll`), but it is Motor-specific and this
project is standard Rust. The standard answer is also the established one here:
`sys-tty` spawns one pump thread per stream (`main.rs:114/148/163`), and red runs
a reader thread feeding an `mpsc` (`input.rs:33-56`).

So: **one thread per byte source, all funnelling into one `mpsc` into one event
loop.** Per pane, two threads (stdout, stderr); per client, one; plus the
listener. A handful of panes means a handful of threads, which is fine.

One correction to red's pattern: red sends **one byte per channel message**.
A pane under `llvm` output would drown in that. rmux's pumps send
`Vec<u8>` chunks, and the event loop drains every pending message before
rendering once (§6.4).

Pane pipes are **2 KiB and simplex** — a 4 KiB page halved
(`moto-ipc/src/stdio_pipe.rs:46`, `work_buf_len = buf_size >> 1`). A pane
blasting output fills the ring and blocks in `write`, so the pumps must drain
continuously and must never be stalled behind rendering. This is why the pumps
are threads and the renderer is not on their path.

**stdout and stderr are separate pipes**, where a pty would merge them into one
stream. Both feed the same pane emulator, so interleaving at a byte level may
differ from Linux under heavy concurrent output. Documented divergence.

Take `russhd`'s drain-before-close discipline (`local_session.rs:161-166`): a
dead child's pipes may still hold output, so a pane that exits must be drained
before it is closed, or short commands lose all of it.

### 4.6 Dependencies: none

rmux links nothing. The Motor-specific surface is one string literal
(`"MOTURUS_STDIO_IS_TERMINAL"`), set through `Command::env`, which on Linux is
simply an ignored variable. That is the whole reason rmux can be zero-dep where
rush could not: rush needed `moto-sys` for pids and `moto-rt` for error
constants; rmux needs neither, because it keys panes by `PaneId` (§3.6) and
talks to the OS only through `std`.

`Cargo.toml` is red's verbatim, plus `[[bin]]` and a `tests/`-enabling `lib.rs`:

```toml
[package]
name = "rmux"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"

[dependencies]

[target.'cfg(unix)'.dependencies]
libc = "0.2"   # host only: TIOCGWINSZ, and the pty the tests drive

[profile.release]
panic = "abort"
lto = "fat"
strip = true
codegen-units = 1
```

`libc` is host-only and test-facing, exactly as in rush — it never reaches the
Motor build.

Note `panic = "abort"`: the `TerminalGuard`'s `Drop` will **not** run in release.
The panic *hook* is what restores the console, as in red
(`red/src/terminal.rs:22-31`) — and in rmux's client that hook must also leave
the alternate screen, or a panic strands the user on a corrupted screen with a
detached server still running.

### 4.7 Modules

`main.rs` thin, `lib.rs` the root, per rush — that is what lets `tests/` drive
the binary.

| Module | Contents |
| :--- | :--- |
| `sys/{mod,motor,unix}.rs` | The platform seam: `TermImpl::size()`, the is-terminal env key, the tmp path, the Enter encoding. `cfg(unix)`/`cfg(not(unix))`, per rush — **not** `target_os = "motor"` (Motor sets no target family; see `red/src/config.rs:38`). |
| `ansi.rs` | The VT parser: bytes → `Action`. Pure. |
| `grid.rs` | `Cell`, `Grid`, cursor, scroll region, alt screen, scrollback. Pure. |
| `pane.rs` | A pane: the `sh` child (§4.3), pipes, `Grid`, `ansi` parser, `ESC[6n` answering (§3.2). No `cfg` — it spawns a bare `sh` and the platform resolves it. |
| `layout.rs` | The split tree, geometry, directional selection, resize. |
| `window.rs` | The window list, renumbering, `aggressive-resize`. |
| `session.rs` | The session list (§7.3): naming, switching, the attached-client set. |
| `screen.rs` | The compositor and the frame diff: `build_frame`/`diff_row_into`/`draw`, from red. |
| `status.rs` | The status line. |
| `keys.rs` | Console bytes → `Key`, and `Key` → the bytes a pane is sent. |
| `bindings.rs` | The key tables (root, prefix, copy-mode) and the command they name. |
| `config.rs` | `rmux.toml` (§2.2): the `key = value` TOML subset plus the binding tables, and the compiled-in defaults (§2.1). |
| `copy.rs` | Copy mode, vi motions, selection, paste buffers. |
| `server.rs`, `client.rs`, `proto.rs` | The split (§4.1). |

Per this repo's strongest convention — there are no `CLAUDE.md` files anywhere,
and all doctrine lives in module-level `//!` essays (`rush/src/sys/mod.rs`,
`term.rs`, `conformance.rs`) — every module above opens with an essay explaining
*why*, and names its traps. That is not decoration; it is where §3 has to end up.

---

## 5. The terminal emulator

The one genuinely new thing in this project. **There is no ANSI parser in this
repo to reuse** — rush's `read_csi` (`term.rs:186-207`) recognizes input keys and
knows nothing of SGR; the closest prior art is the ~110-line CSI-subset emulator
in rush's *test* file (`tests/phase8.rs:209-318`), which is the right shape but
ignores styling.

### 5.1 Shape

A VTE-style state machine — ground, escape, CSI-entry, CSI-param, CSI-intermediate,
OSC-string — over rush's byte ranges, which are already correct ECMA-48
(`term.rs:186-207`): `0x30..=0x3f` parameters, `0x20..=0x2f` intermediates,
`0x40..=0x7e` final. `ESC[1;31m` is the same grammar as `ESC[1;5C` with a
different final byte.

**The parser is pure**: bytes in, `Action`s out, no I/O, no grid. The grid
consumes `Action`s. This is what makes the whole emulator unit-testable on Linux
over byte slices with no pty — the same trick that makes red's editor and rush's
`read_key` testable (`rush/src/term.rs:88-94`, the `Bytes` trait). It is the most
important structural decision in the module.

### 5.2 What it must implement

Driven by what actually has to run in a pane — `rush`, `red`, and a C toolchain
spewing output:

- **CSI**: `A B C D` cursor motion, `H`/`f` position, `G` column, `d` row,
  `J` erase-in-display (all 3 modes), `K` erase-in-line (all 3 modes),
  `L`/`M` insert/delete line, `@`/`P` insert/delete char, `X` erase char,
  `S`/`T` scroll, `r` DECSTBM scroll region, `m` SGR, `n` DSR (**answer `6n`**,
  §3.2), `h`/`l` including `?1049` alt screen, `?25` cursor visibility, `?7`
  autowrap, `?2004` bracketed paste.
- **ESC**: `7`/`8` save/restore cursor, `D`/`M`/`E` index/reverse-index/next-line.
- **OSC**: `0`/`2` window title — needed, because the status line shows window
  names. `52` (clipboard) is a maybe; parse and ignore the rest.
- **C0**: `\b \t \n \r \x07`, and nothing clever.
- UTF-8 decode to `char`, every char one column (§1.2).

### 5.3 The traps

- **Deferred wrap.** A character written to the last column does not move the
  cursor to the next line; it sets a pending-wrap flag, and the *next* character
  wraps. Getting this wrong is invisible until something draws a box, and then it
  is wrong everywhere. xterm and tmux both do this; the conformance corpus must
  pin it.
- **Alt screen has no scrollback.** `?1049h` switches to a fresh grid whose
  scrolled-off lines are discarded, and saves/restores the cursor. red lives on
  the alt screen (`red/src/terminal.rs:14`), so this is exercised immediately.
- **Scroll region interacts with everything** — `L`, `M`, `\n` at the bottom
  margin, and `?1049`.
- **`ESC[6n` must be answered into stdin, not stdout.** Obvious, and easy to get
  backwards.

---

## 6. Rendering

### 6.1 The frame

Straight from red (`editor.rs:44-53`, `477`, `494`, `524`): build a whole frame of
cells, diff it against the last one, repaint only what changed, flush once.

red's `Cell` holds `style: &'static str` — a reset-prefixed SGR literal — and the
reset prefix is what makes a partial repaint legal: "a cell can be repainted in
isolation without depending on whatever style preceded it on screen"
(`editor.rs:59-62`).

**rmux cannot keep `&'static str`**: a pane composites arbitrary SGR from a child
program. Keep the *invariant*, change the representation: a small `Copy` struct
of packed attributes (fg, bg, bold, reverse, ...) that is `PartialEq` and renders
to a self-contained, reset-prefixed SGR at diff time. Do **not** put a `String`
in a cell.

### 6.2 The diff

red's `diff_row_into` finds the first divergent column, repaints to end of row,
coalesces SGR runs, and appends `ESC[K` if the row shrank. Take it as written,
with two fixes:

- **Cache `cols` with the frame.** red's `draw()` triggers a full repaint only on
  a row-count change (`editor.rs:535`), so a width-only change slips through; it
  gets away with it because its rows are ragged and `ESC[K` cleans up. rmux's
  panes are not ragged. Cache both axes, as rush's `Painted::cols` does
  (`term.rs:589`).
- **Use `Option<Frame>`, not a length check.** rush's formulation is better:
  `None` means "the screen is not ours to reason about, next paint is full"
  (`term.rs:583-586`). Set it to `None` on `^L`, on resize, and after anything
  writes to the console behind the compositor's back.

Absolute `ESC[{r};{c}H` positioning throughout. rush uses relative motion and
documents why (`term.rs:450-457`) — it cannot know its row on the screen without
asking. rmux is a full-screen alt-screen application and owns every row by
construction, so absolute is correct here. Note that divergence in a comment so
the next reader does not think the rule was missed.

### 6.3 Why this matters more here than in red

rmux's output reaches the user through `sys-tty`, which reads it in **80-byte
chunks** (`sys-tty/src/main.rs:150`) and writes it to a polled UART one byte at a
time, spinning on `OUTPUT_EMPTY`. A full 80x24 repaint with styling is several
kilobytes. On emulated hardware this drains fast; on a real UART at 115200 baud
it is roughly a second. The diff is not an optimization, it is the feature.

This is also the argument for the byte-cost tests (§9.2): "switching panes costs
N bytes" is a claim that can regress silently and that only a test can hold.

### 6.4 Coalescing

Render is driven by the event loop, never by a pump thread. The loop drains every
pending message, marks panes dirty, and renders **once**. A pane producing a
megabyte of output must not produce a megabyte of frames — it must produce as
many frames as the console can actually show.

---

## 7. Model

### 7.1 Layout

The tmux model: a session has windows, a window is a binary tree of splits with
panes at the leaves. `split-window -h` splits the current pane left/right,
`-v` top/bottom; each split halves the pane and spends one row or column on a
border.

Borders in ASCII — `|`, `-`, `+` — not the ACS or UTF-8 box characters real tmux
prefers. This is a visible, intended divergence from the oracle, and a
conformance case will have to allow for it (§9.1).

### 7.2 Directional selection

`M-Left`/`M-Right`/`M-Up`/`M-Down` are geometric, not tree-order: from the active
pane's edge, find the pane adjacent in that direction, tie-broken by the most
recently used. This is one of the places where "obviously right" and "what tmux
actually does" differ, so it is oracle-tested rather than reasoned about.

### 7.3 Sessions

Real, multiple, named sessions — not one implicit session with many windows.
A session is an independent list of windows plus a current window; the server
holds many, and a client attaches to exactly one at a time.

This is what makes detach worth having. A session is the unit that survives: you
detach from `build`, attach to `notes`, and the shells in `build` keep compiling.

The surface, and no more:

| | |
| :--- | :--- |
| `rmux` | attach to the most recently used session, or create one if the server has none |
| `rmux new [-s name]` | create a session and attach |
| `rmux attach [-t name]` | attach to a named session |
| `rmux ls` | list sessions: name, window count, attached-or-not |
| `rmux kill-session -t name` | kill it and everything in it |
| `prefix-d` | detach |
| `prefix-(` / `prefix-)` | previous / next session |
| `prefix-$` | rename the current session |
| `prefix-s` | a plain numbered list of sessions to pick from |

Sessions are auto-named `0`, `1`, ... when unnamed, as tmux does, and the status
line's left end shows the current one (tmux's default `status-left` is `[#S]`).

`prefix-s` is a **plain list**, not tmux's `choose-tree` — a numbered menu drawn
over the screen, pick by digit or arrows, `Esc` cancels. The full interactive tree
stays a non-goal (§1.2); with multiple sessions, *some* way to see and switch them
is a basic, and this is the smallest thing that is one.

**A window belongs to exactly one session.** tmux can link one window into
several; that is `link-window`, and it stays a non-goal (§1.2). Without it, the
session tree is a tree, and `renumber-windows` (§7.4) has one list to renumber
rather than several.

Two consequences worth stating before they surprise someone:

- **Paste buffers are server-global, not per-session** (§7.6), as in tmux. Copy in
  one session, paste in another. This is deliberate and is the only state that
  crosses a session boundary.
- **`aggressive-resize` is now genuinely reachable** (§7.4). Two clients attached
  to the *same* session, each looking at a different window, is the case it exists
  for, and it is testable only because sessions are real.

### 7.4 Windows

Create, next, previous, select by number, rename, kill. `renumber-windows on`
means closing a window compacts the numbering. `aggressive-resize on` means a
window is sized to the smallest client *viewing* it — which only bites with two
clients attached to the same session on different windows, and is therefore a
phase-9 concern with a two-client test.

### 7.5 Scrollback, and `history-limit 9999999`

Ten million lines per pane. It is a *cap*, not a preallocation — memory tracks
content — but the representation still has to be honest about it: a naive
`Vec<Vec<Cell>>` at 10M lines x 80 cells x 8 bytes is several gigabytes, on an OS
where that is not available.

So scrollback lines are **not** grids. A line scrolling off the top is converted
to a compact form — the text as UTF-8 bytes, plus a short run-length list of
style spans, with trailing blanks trimmed — and pushed into a ring bounded by the
limit. Typical shell output is mostly unstyled ASCII, which this stores at
roughly one byte per character. The live grid stays `Cell`-based; only history is
compacted. Copy mode (§7.6) reads through an accessor that renders either
representation, so it does not care which side of the boundary a line is on.

### 7.6 Copy mode and paste

`mode-keys vi`, so: `prefix-[` enters, `q`/`Esc` leaves, `hjklwb0$`, `g`/`G`,
`C-u`/`C-d`/`C-f`/`C-b`, `/` and `?` search with `n`/`N`, `Space` starts the
selection, `Enter` copies it and exits. `prefix-]` pastes the top buffer into the
active pane — as *input bytes*, exactly as if typed.

Pasting as keystrokes is what tmux does and it is worth stating plainly: pasted
text goes through the same path as typing, so a paste into a shell runs whatever
newlines it contains. rmux disables bracketed paste on its own console
(`ESC[?2004l`, as red does) but should pass `?2004h` through *from* a pane that
asks for it, wrapping pasted text in the markers that pane expects.

Buffers are a small stack, **server-global** (§7.3): copy in one pane, paste in
any other, in any window, in any session. That is the only state that crosses a
session boundary, and it is what the brief asks for — copy between two `red`s, or
from rush to red.

**The clipboard is rmux's and stops at rmux's edge.** There is no host clipboard
to reach: OSC 52 is out of scope, and rmux neither reads nor writes the clipboard
of whatever terminal the user is sitting at. `52` in §5.2 is therefore parsed and
ignored like any other OSC, not forwarded.

Two things about this will surprise someone, and both are inherent rather than
bugs:

- **Copy mode copies what is *on the screen*, not what the program thinks it
  has.** Copying out of `red` means entering rmux's copy mode and selecting the
  text as *rendered* in that pane — rmux cannot see red's yank register, only the
  cells red painted. This is exactly tmux's behavior and the reason copy mode
  reads the grid (§7.5) rather than talking to the pane.
- **Pasting into `red` pastes keystrokes.** `prefix-]` writes the buffer into the
  pane's stdin as if typed, so pasting into red while it is in normal mode runs
  the text as commands. red must be in insert mode first. There is no fix
  available: bracketed paste is the usual one, and red explicitly disables it
  (`red/src/terminal.rs:14` writes `ESC[?2004l`), so rmux has nothing to wrap the
  paste in that red would honor. Document it; do not try to be clever.

rmux still disables bracketed paste on its *own* console (`ESC[?2004l`, as red
does), and passes `?2004h` through from a pane that asks for it, wrapping pasted
text in the markers that pane expects — for panes that do want it.

---

## 8. Input

### 8.1 Forward bytes, do not re-encode

The temptation is to decode console bytes into a `Key`, then re-encode a `Key`
into bytes for the pane. That round-trip is lossy for everything rmux does not
model, which is most of what a terminal can send.

Instead: rmux scans the input stream for the prefix byte and for the sequences
bound in the root table, and **forwards everything else verbatim** — the raw
bytes, unexamined. The decoder exists only to recognize what is bound; anything
it does not recognize is passed through as-is. rush's `read_csi` already has the
right instinct: on a broken sequence it ungets the byte so "a `^C` mid-escape is
still a `^C`" (`term.rs:200-203`).

The exception is Enter (§3.4), which is re-encoded, because sys-tty's `CR`→`CRLF`
must be reproduced.

### 8.2 Key tables

Three, exactly as tmux: **root** (fires with no prefix — `S-Left`, `S-Right`, the
`M-` arrows), **prefix** (after `C-a`), and **copy-mode** (§7.6). `bind`,
`bind -n`, and `unbind` in the config manipulate them, and `unbind` must remove
rather than shadow, because the config unbinds `"` and `%`.

`bind C-a send-prefix` is the one special command: `C-a C-a` sends one literal
`C-a` to the pane.

### 8.3 The key-encoding trap

`S-Left` is `ESC[1;2D` and `M-Left` is `ESC[1;3D` under xterm conventions — but
Alt-arrow is also legitimately sent as `ESC` `ESC[D` by some terminals, and what
Motor's console actually delivers depends on whatever is on the far end of the
serial line or the SSH session. The config's four `M-` bindings and two `S-`
bindings are useless if the bytes never arrive in the form rmux expects.

**Phase 0 spike:** capture the actual bytes for `S-Left`/`S-Right` and the four
`M-` arrows, on the serial console *and* over SSH, and write them down. Do not
guess; this is cheap to measure and expensive to get wrong.

---

## 9. Testing

### 9.1 The tmux oracle

rush's conformance suite is the model, with real tmux in dash's place. The thesis
transfers exactly (`rush/tests/conformance.rs:1-22`): the corpus states no
expectations, it runs each case through both and requires agreement, so it "can
be extended by anyone who can think of a snippet without having to know the
answer first".

Mechanically:

- `const RMUX: &str = env!("CARGO_BIN_EXE_rmux");` and `const TMUX: &str = "/usr/bin/tmux";`,
  with a `have_tmux()` existence check that **skips rather than fails**, so a
  checkout without tmux still tests clean.
- A case is a **key script**, driven over a pty (lift rush's `Pty` from
  `tests/phase8.rs:37-174` as-is), with both multiplexers given identical
  geometry via `TIOCSWINSZ`, `TERM=xterm`, `LC_ALL=C`, and a private scratch dir.
- Force comparability: `tmux -f tests/defaults.tmux.conf -S $T/sock`, a pinned
  `default-shell` (dash on both sides — `sh` resolves to different shells on
  Linux and Motor, and the corpus tests rmux, not the shell), and
  `new-session -x 80 -y 24`. **Never** the developer's own
  `~/.tmux.conf` — the checked-in copy is what rmux's compiled-in defaults are
  defined to mean (§2.1), so it is the only file that makes the comparison valid.
  A case that also needs an `rmux.toml` override supplies both halves: the TOML
  for rmux, the equivalent tmux directives appended for tmux.
- Compare the **replayed screen grid**, not bytes. Byte-level agreement with tmux
  is neither achievable nor wanted; the *picture* must agree.
- `DIVERGENCES: &[(&str, &str)]` with rush's inverted assertion — each documented
  divergence is asserted to *still* differ, "so a divergence that gets fixed
  cannot quietly stay documented as broken". ASCII borders (§7.1) and the
  omissions in §1.2 go here. **This list is the honest scope statement of the
  project.**

There is a pleasing shortcut available: tmux can be both the pty provider *and*
the screen scraper. Running the case inside an outer `tmux new-session` lets
`tmux capture-pane -p` return the grid the inner multiplexer painted, and
`tmux list-panes -F '#{pane_left},#{pane_top},#{pane_width},#{pane_height}'`
return its geometry — no hand-written reference emulator in the harness at all.
Verified working against tmux 3.4 while writing this plan. Use it for geometry
assertions; use the replayed-grid path for content, since it is what the VM
harness can also do.

### 9.2 Byte-cost tests

rmux-only — tmux is not the oracle for these — and modelled on rush's
`// ---- painting ----` block (`tests/phase8.rs:427-434`), whose rationale is
exactly §6.3's: "erasing a line and drawing it again reaches the identical screen
and flickers the whole way… so it is the bytes that have to be tested".

Claims worth pinning: a keystroke echoed in a pane costs the bytes of that
keystroke; moving between panes repaints no pane content; a status-line clock
tick rewrites only the digits that changed; a full repaint happens only on resize
and `^L`.

### 9.3 Pure unit tests

The emulator (§5.1) and the layout tree are pure and take the bulk of the tests,
in-file as `#[cfg(test)] mod tests`, per both red (`editor.rs:2163`) and rush.
They need no pty and no terminal; they run on Linux in milliseconds. Note red's
enabling trick and copy it: config is *injected*, not loaded, "so that `new` does
no file I/O and tests are not at the mercy of the config file on the machine
running them" (`editor.rs:121-124`).

Test names are full sentences, per rush.

### 9.4 On the real thing

`tests/vm-console-check.py` in rush's mold: boot the image under qemu on a pty,
drive rmux on the actual Motor console through actual sys-tty, replay the stream,
assert the picture and the byte costs. This is where §3.3's byte mangling and
§3.4's CRLF are actually proven.

**TRAP: `C-a` is doubled under qemu.** `run-qemu.sh` passes `-nographic`, which
implies `-serial mon:stdio` and makes **`Ctrl-A` qemu's monitor escape prefix**
(`Ctrl-A x` quits, `Ctrl-A c` switches to the monitor). The config's prefix *is*
`C-a`, so the two collide.

This is a nuisance, not a blocker, and the correction matters because rush's
harness overstates it (`rush/tests/vm-console-check.py:15-23` says `C-a` "never
reaches the guest" — that is true only of a *single* press). qemu's own escape
hatch is documented: **`Ctrl-A Ctrl-A` sends the escape character to the
frontend**, i.e. one literal `C-a` to the guest. So interactively, tmux and rmux
with a `C-a` prefix work fine under `-nographic` — you type the prefix twice —
which is exactly why running tmux in a Linux guest under qemu has never been a
problem. It composes with `send-prefix` too, just verbosely: `C-a C-a` `C-a C-a`
delivers a literal `C-a` to the program in the pane.

For the *harness*, the two options are: send `\x01\x01` for every `\x01`, or pass
`-echr` to move qemu's escape out of the way (`-echr 0x14` for `Ctrl-T`) in a
run-script variant. Prefer `-echr` — the doubling is a footgun that makes a
mistyped test look like an rmux bug one layer down. Verify the prefix arrives
before writing any test that depends on it.

Test over SSH too (§3.3): russhd bypasses sys-tty, so it is a genuinely different
terminal, and it is the path that does not eat `C-a`.

---

## 10. Phases

Each phase ends with something demonstrable and tested.

**M0 — Spikes and scaffolding.** The measurements this plan rests on, both cheap
and both disqualifying if wrong:
1. Orphan survival (§4.4) — detach is worthless without it.
2. The actual key bytes for `S-`/`M-` arrows, serial and SSH (§8.3).
Plus: qemu `-echr` in a run-script variant (§9.4); the crate skeleton; the
`sys::` seam; Makefile + `src/imager/motor-os.yaml` wiring (five edits, see
rush/red's entries); and the sys-tty `^C` patch (§3.5). Loopback TCP needs no
spike — systest already proves it (§4.2).

**M1 — One pane, no UI.** Spawn `sh` (§4.3) on piped stdio with the is-terminal
env var; pump bytes both ways; drain on exit. This is sys-tty reimplemented inside
rmux, and it proves the whole pty-equivalent claim of §3.1 before anything is
built on it. The milestone: an interactive rush, reached through rmux, that
cannot tell the difference — including `is_terminal()`.

**M2 — The emulator.** `ansi.rs` + `grid.rs`, pure, unit-tested on Linux. No
rendering yet. Deferred wrap, scroll regions, alt screen, `ESC[6n`.

**M3 — Rendering.** The compositor and frame diff, one full-screen pane. The
milestone: **`red` runs inside rmux**, sized correctly, because rmux answers its
`ESC[6n`. If red works, the emulator is real.

**M4 — The split.** Server, client, transport, detach, attach, and the session
list (§7.3) — sessions arrive with the server that holds them, not later. Design the seam
from M1 (server core as a library, client thin) and implement it in-process
first, so M4 moves a boundary rather than inventing one.

**M5 — Config and input.** The default key tables (§2.1), the prefix,
`send-prefix`, and `rmux.toml` (§2.2) on top of them. After this the defaults are
compiled in rather than prose, and overridable.

**M6 — Windows and sessions.** Windows: new, next, previous, select, rename,
kill, `renumber-windows`. Sessions: `new`/`attach`/`ls`/`kill-session`, `prefix-(`
and `prefix-)`, `prefix-$`, and the `prefix-s` list (§7.3). Plus the status line,
which is where the session name first becomes visible.

**M7 — Panes.** The split tree, borders, `|` and `-`, directional selection,
resize, zoom, kill.

**M8 — Scrollback and copy mode.** Compact history (§7.5), vi copy mode, search,
selection, paste buffers.

**M9 — Conformance and polish.** The tmux corpus, the divergence list, the VM
harness, byte-cost tests, `aggressive-resize` with two clients, the README.

---

## 11. Risks

Ordered by how much they would hurt.

1. **The emulator is the long pole.** It is the one component with no prior art
   in this repo (§5) and the one whose bugs are invisible until something draws a
   box. Purity + the tmux oracle is the entire mitigation.
2. **Orphans may not survive on Motor** (§4.4). Blocks M4 and only M4; everything
   through M3 is unaffected, which is why the spike is in M0 and the split sits
   in the middle rather than at the start. The `sys-init` precedent
   (`main.rs:77-88`, spawn-and-never-wait) says it works; detach is worthless if
   it does not.
3. **2 KiB pipes and 80-byte console reads** (§4.5, §6.3) make throughput
   structurally tight. The design accounts for it; measurement will tell.
4. **`history-limit 9999999`** is only survivable with compact history (§7.5). A
   naive representation runs the VM out of memory, and it will do it slowly
   enough to look like something else.
5. **sys-tty and SSH are two different terminals** (§3.3). Anything tested on one
   is untested on the other.

---

## 12. Open questions

None outstanding.

**Settled:**

- *Multiple named sessions are in scope* (§7.3), not one implicit session with
  many windows. Sessions are the unit that survives a detach, which is the point
  of the server. This also makes `aggressive-resize` reachable and testable.
- *There is no host clipboard.* Copy/paste lives and dies inside rmux (§7.6):
  server-global paste buffers, no OSC 52, nothing forwarded to the terminal the
  user is sitting at.

- *`rush` stays the default in `/sys/cfg/sys-tty.cfg`.* rmux is a program the user
  runs, exactly as tmux is on Linux — where the shell is what boots and the
  multiplexer is what you choose to start. rmux is therefore never in the boot
  path, and a bug in it cannot cost anyone their console.
- *Loopback TCP is the transport* (§4.2), proven by systest rather than spiked.
