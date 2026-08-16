# rmux — a terminal multiplexer for Motor OS

A pure-Rust, dependency-free clone of the useful half of tmux, built to the
defaults in `~/.tmux.conf`, in the manner of `red` and `rush`: raw ASCII over the
console, minimal redraws, behavior checked against the Linux prototype.

This document is the design, and the record of what was measured to arrive at
it. `README.md` is the summary — what rmux is, how it is used, and what it does
not do; this is the detail behind every line of it. Doc comments throughout the
crate cite it by section ("details.md §3.1"), the way `rush`'s code cites its
README, so a section here is the long answer to a comment there.

It was written first as a plan, and it is left standing because the reasoning
outlived the planning: §3 is the argument that a multiplexer needs no pty, §4.2
is why the transport is loopback TCP, §9 is why conformance is measured against
tmux rather than asserted, and §10 is what each phase actually cost — including
the things that turned out not to be true. Everything in it is built, with the
exceptions listed under §10's last entry.

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
mode-keys         = "vi"       # "vi" or "emacs"
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
(`src/sys/sys-tty/src/serial.rs`) — owned permanently by `sys-tty`, with
ownership explicitly non-transferable (`src/sys/kernel/src/uspace/serial_console.rs`:
"We do not support transferring console ownership for now").

None of that matters, because **the thing a pty would buy us is already
available**, and two programs in-tree already do exactly what rmux needs:
`sys-tty` (which owns the real console and spawns your login `rush`) and
`russhd` (which answers SSH pty requests with no OS pty whatsoever).

The reason is `is_terminal()`. On Motor OS it is immutable metadata on the
descriptor object, fixed when the descriptor is created (`rt.vdso`'s
`rt_fs::is_terminal`; `docs/tui.md` is the model in full):

```rust
pub extern "C" fn is_terminal(rt_fd: i32) -> i32 {
    crate::posix::get_file(rt_fd).is_some_and(|file| file.is_terminal()) as i32
}
```

A provider marks the pipes it creates by spawning the child with
`MOTURUS_STDIO_IS_TERMINAL` (`moto-rt`'s `process::STDIO_IS_TERMINAL_ENV_KEY`).
That is the hint at spawn, not the answer afterwards: what a child observes is
the bit on each of its own descriptors. `sys-tty` and `russhd`'s
`local_session` do exactly this, and so does `sys::spawn_pane` here.

**This paragraph used to say the opposite**, and the correction is worth keeping
because it retired a wart this section used to record: `is_terminal` was once a
bare environment lookup, which made it per-process rather than per-descriptor,
so a pane program with its stdout redirected to a file still reported a terminal
on it. The per-descriptor redesign fixed that, and the wart went with it.

The whole mapping, with no kernel changes and no Motor-specific API:

| POSIX pty gives | rmux gets it from |
| :--- | :--- |
| master/slave byte channel | `Command::stdin/stdout/stderr(Stdio::piped())` |
| slave `isatty() == true` | `.env("MOTURUS_STDIO_IS_TERMINAL", "true")` |
| `TIOCGWINSZ` | `$COLUMNS`/`$LINES` at spawn; `ESC[18t` and `ESC[6n` answered with the *pane's* size (§3.2) |
| `SIGWINCH` | DEC mode 2048: the pane reports its new size in band, to a child that subscribed (§3.2) |
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

### 3.2 Size, without ioctl or SIGWINCH

Motor has no terminal-size call and no signal to deliver a resize with. Both
travel over the wire instead, in the byte stream a program already has, and that
is what makes rmux tractable: rmux **is** the terminal for its panes, so it is
the one that knows.

Three mechanisms and a rule. The order is the design's, not history's: the first
is a push, the second is a fact the child is born with, and the third is a
question — and the third is only reached by a program that did not ask for the
first.

1. **DEC private mode 2048: the subscription.** A program sends `ESC[?2048h` to
   subscribe; rmux reports `ESC[48;{rows};{cols};0;0t` into that pane's *stdin*
   at once and again on every real resize, until `ESC[?2048l` withdraws it.
   `ESC[?2048$p` (DECRQM) asks whether the pane knows the mode. This is the
   platform convention rather than an rmux invention — the host terminal in
   front of `sys-tty`, `russhd`, and rmux all speak it, so nesting composes with
   no special cases (`docs/tui.md`). A pane's program
   learns a new size without a probe and without a prompt.
2. **`$COLUMNS`/`$LINES` in each pane's environment**, which is how a program
   knows its size before it has asked anything — and before it has even started,
   which is the only way a *first* frame can be the right size. rmux sets them
   in `sys::spawn_pane`. They are not a spawn-time fact only: a shell hands its
   environment to everything it runs, so rush writes them back once per command
   from what the terminal last reported (`term::sync_size`, on bash's
   `checkwinsize` rule). Without that, a `$COLUMNS` still holding the width
   before a split handed every command the shell started the size the pane used
   to be, and the program's first frame — the one this mechanism exists to get
   right — was painted at it. Nothing changes on rmux's side: it still sets them
   once, for the child it spawns.
3. **`ESC[18t`, and then `ESC[6n`: the fallback ladder**, for a program that did
   not subscribe, or whose terminal turned out not to know the mode. `ESC[18t`
   is answered `ESC[8;{rows};{cols}t` and moves nothing; the older idiom moves
   the cursor to the far corner and reads it back with DSR, and the emulator
   clamps the cursor to the pane's own bounds so the answer is the pane's
   geometry rather than the console's. Both replies go into that pane's stdin.
   Neither is a notification: a program on this rung finds out about a resize
   when it next asks, which is a poll, and §1 of the plan above is the argument
   against living on it.
4. **And nothing else.** A pane's stdin carries what the user typed. rmux writes
   into it only in answer to a question that pane's program asked.

Mechanism 1 does not weaken rule 4, it satisfies it: the subscription *is* the
question, and a program that did not subscribe is written to exactly as before.
What makes it safe where M11's re-answering was not is that the subscription is
*withdrawn*. crossterm ties it to raw mode, so `rush` — which does ask, while it
is editing a line — sends `ESC[?2048l` from `disable_raw_mode` before it runs a
command and re-asserts it at the next prompt. The `ESC[6n` M11 mistook for
standing permission had no such withdrawal, so the answer went to whatever the
shell was running by then; `top` reads a bare `ESC` as quit
(`sysbox/src/commands/top.rs`), and that is what it cost. A subscriber killed
before it can withdraw leaves the mode set, exactly as it leaves the alternate
screen set — the ordinary terminal limitation, accepted rather than tracked.

**Why rule 4 is a rule, and what it cost to learn.** Before mechanism 1 existed,
a pane resized *while a prompt was up* — which is what every split does to the
pane it divides — kept the old width until the shell next asked. M7 tried to
remove that lag by re-answering unasked: a program that had sent `ESC[6n` once
was sent the answer again whenever its pane changed size, on the reasoning that
having asked proves a parser for the answer. The reasoning is wrong by one word.
It proves the *program that asked* has a parser — and on Motor the program that
asked is a shell, which then hands its terminal to whatever it runs, with no
`exec` for rmux to see. M11 is what that costs: a user split a window, ran `top`
in it and dragged the terminal, and top exited, because it takes a bare `ESC`
for "quit" and rmux had just put one in its stdin.

Mechanism 1 is the same push done correctly, and the difference is entirely in
who is asking and whether they can stop: a subscription is made by the program
that will read the report, and it is withdrawn when that program gives the
terminal up. That is why the lag could be removed in the end and why M7's
version of it could not be kept.

#### And rmux's own console is told, not asked

Everything above is a *pane* being told its size. rmux's own console is the same
problem one layer up, and it used to be worse: what rmux had until M10 was one
answer taken at startup and believed for ever, which is why the status line went
off the bottom of a shrunken window and did not come back when the window did
(§6.2: the frame diff sends what *rmux* changed, and rmux had changed nothing).
M10 made the client ask again on a clock, with DECSC/DECRC around the query so
the cursor did not visibly jump.

The client no longer asks at all. Its size and its resizes are crossterm's
`terminal::size()` and `Event::Resize`, which on the host come from
`TIOCGWINSZ` and `SIGWINCH`, and on Motor OS from a mode-2048 subscription
crossterm's backend opens on its own behalf — the same subscription a pane's
program opens with rmux, one layer further out. So an idle rmux writes nothing
on either platform, and a resize arrives when it happens rather than within an
interval of it. rmux is a client here exactly as its panes' programs are clients
of it, and `test-terminal-size.sh` measures the whole chain in one go: the
console changes shape, and the editor inside a pane inside rmux repaints at the
new size with no key typed.

Two rules survive the change, both in `client.rs`:

- **A size that has not changed is not forwarded.** A `Resize` invalidates the
  client's screen and buys a full repaint (§6.2), so a client that relayed every
  report it received would repaint the whole screen for a report that said
  nothing new.
- **The opening frame waits, briefly, for the console to speak** (`settle_size`,
  200ms). Not a blocking round trip: the answer arrives as an ordinary console
  event and this is a window, not a wait. Without it the first frame is painted
  at 80x24 and then again when the answer turns up, which is a full repaint of
  the whole screen twice over a console where that costs about a second (§6.3).
  A console with nothing on the other end that answers costs this much once, at
  startup, and never again — which is the promise, and is what the console leg
  of `test-terminal-size.sh` exercises, its terminal being far slower than the
  window.

What is left is a window shrunk and restored while nothing was listening — a
program that wrote over rmux's console, say. `prefix r` is the answer to that, as
it is to any other console corruption.

#### The idioms rmux must answer

Neither program in rmux's panes asks for its own size any more; crossterm asks on
their behalf, and what rmux must answer is what crossterm sends. That is mode
2048 first, and then, only if the mode was not confirmed, the ladder: `ESC[18t`,
and after two of those go unanswered, the corner probe.

```
ESC[18t                          -- window op: rmux answers ESC[8;{rows};{cols}t
ESC7 ESC[9999;9999H ESC[6n ESC8  -- CUP to the far corner, DSR, cursor restored
```

The second reduces to one requirement — **clamp the cursor to the pane's bounds,
then report where it landed** — which is exactly what a real terminal does. The
first needs no clamping at all: it is the pane's size asked for directly, and
answering it is what keeps a pane's cursor still, since the corner probe is seen
in the corner in between. Get the clamp wrong and a program silently sizes itself
to the physical console, drawing outside its pane.

DSR is the only round trip either rung makes; neither uses Device Attributes. Any
other query a pane emits gets no answer, which is a terminal's prerogative.

Two related pane-state traps, both from the sequences above: `ESC[?25l`/`?25h` is
**per-pane** state, and only the active pane's cursor is composited onto the real
screen — an inactive pane hiding its cursor must not hide the user's. And every
reply goes to that pane's **stdin**, never to rmux's own stdout.

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

sys-tty's read loop used to write a literal `"^C"` **straight to the serial
port** when it saw byte 3, bypassing whatever program owns the screen:

```rust
while let Some(c) = serial::read_serial() {
    if c == 3 {
        write_serial_raw(b"^C");   // removed in M0
    }
```

Under rmux this punches stray text through the composited screen at whatever
position the cursor happens to be, invisible to the frame diff, which will then
never repair it. It is also redundant today: `rush` prints its own `^C`
(`rush/src/term.rs:906-922`), so the serial console appears to double-echo it.

**Done (M0).** The double-echo was confirmed on the VM (a `^C` at the prompt
printed `^C` twice), then the echo was removed from sys-tty's read loop, leaving
it a clean byte pump; a re-run confirms one `^C` (rush's). This is a change to the
OS, agreed as a prerequisite. If it is ever reverted, rmux's fallback is a full
repaint after any `^C` — a full-screen repaint over a UART, for a keystroke.

### 3.6 Signals: there are none

`rush/src/sys/motor.rs:8-27` states it flatly: no signal delivery of any kind;
the only thing one process may do to another is terminate it. So:

- `^C` in a pane is byte `0x03` written to that pane's stdin. rush interprets it
  (`term.rs:906`); arbitrary programs may not, and that is their business.
- **Kill once, collect once.** `SysCpu::OP_KILL` aimed at a process that has
  already been waited for **does not return** on Motor. rmux hit it by killing
  every pane of a session that was ending, including one whose exit it had just
  collected: the server stopped inside the syscall with the session
  half-torn-down, the client waited on a server that would never speak again,
  and the test suite stalled behind that. `mdbg` named it — the main thread in
  syscall `1:4` while the pane's shell showed no live threads. A pane now
  remembers that it has collected its child, and neither kills nor waits for it
  twice (`pane::Pane::collected`). Worth fixing on the kernel side as well:
  killing something that has already been reaped should be an error, not a wait.
- **Terminate, then collect.** Killing is only half of it. On the host a child
  nobody waited for is a zombie for as long as the server runs. On Motor the
  same omission is worse in principle: process statistics live in a tree where a
  child's entry keeps a *strong* reference to its parent's
  (`kernel/src/xray/stats.rs:376`), so one entry that is never freed pins every
  ancestor with it — a pane's shell would pin the server, the client that
  started it, and the login shell above that, which is the shape of a five-deep
  chain of `DEAD` entries seen once in the wild. That chain could **not** be
  reproduced from a missing `wait`, on either the build that produced it or the
  one after: Motor frees a dropped child's entry without a wait in every case
  that could be constructed, so what pinned it is still unaccounted for and
  probably lives in the kernel's teardown path. `Drop for Pane` closes rmux's
  half regardless, and deliberately does not wait for the pane's *pumps*: a
  grandchild holding the pipes open would make that a hang (§4.5).
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

**Done, corrected after M6.** The discipline has *two* halves, and only one of
them was built. The writer thread waits for the client to close before dropping
the socket — but the server process exiting closes the socket under it, which
discards the same write. `rmux; exit 5` therefore exited 5 about 99 times in 100
and 1 the other time, the client having seen the connection go instead of the
status. The server now waits for its client writers before it goes
(`Server::say_goodbye`), and a client taken off the list keeps its writer thread
until then, because the message that matters most is the `Exit` sent *as* the
client is dropped. Falsified at 2/300 runs with the wait removed, 0/300 with it;
pinned deterministically by two `server::tests`, since a 1-in-100 race is not
something a test can be trusted to catch.

**Also corrected: every question gets an answer.** `kill-session` was handled
silently, and `client::ask` blocks on a reply — so the command hung whenever the
server survived the kill (any other session still open). Killing the *last*
session hid it: the server exits, and the socket closing looked like an answer.
`ToClient::Done` is that answer now.

The port file needs a writable path. Motor defaults to its `/sys/tmp`
convention and, like the Linux host, honors `$TMPDIR` when a test needs a
private server — one `sys::` function. **Correction, measured in M4:**
`/sys/tmp` does *not* exist on the image. `static_dirs` in
`src/imager/motor-os.yaml` names host directories to copy in, not directories
to create, and git cannot track an empty one. `/sys` is writable, so rmux
creates the directory on first use; that is one `mkdir` rather than a change to
the image, and it keeps M4 an rmux-only patch.

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

**Measured (M0), and it forced an OS change.** An *ordinary* orphan does **not**
survive on Motor: unlike Unix's reparent-to-init, the kernel *actively* kills a
process's children when that process is reaped (`KProcessStats::process_dropped`
in `xray/stats.rs`). The `sys-init`/`strobe` precedent works only because `sys-init`
is never reaped — it is the init process and lives forever. A client that spawns
a server and then exits is reaped the moment its parent (the shell) collects it,
and the server dies with it. So detach/attach could not rest on plain orphaning.

The fix, added in M0, is a **detached-spawn primitive**: a spawn flag that reparents
the child to the *kernel*, so it outlives the spawner's exit and reaping — Motor's
equivalent of reparent-to-init. It is gated by a new, non-inherited capability
`CAP_SPAWN_DETACHED` (`moto_sys::caps`): only a spawner that holds the bit may
detach a child, and the bit is passed down explicitly, never by default. rmux's
server is therefore spawned **detached**, and the client can only do that if it
was granted the capability — which is why `rush` reads a `spawn-detached` list
from `/user/cfg/rush.toml` (§2.2) and rmux is on it, and why the root shell and
`russhd` are launched holding the bit (`sys-init.cfg`, sys-tty, russhd's `exec`).

Verified on the VM: a non-detached child is reaped with its parent (its tick log
stops at once), a detached child keeps ticking after the parent exits, and a
spawner lacking `CAP_SPAWN_DETACHED` is refused with `E_NOT_ALLOWED`.

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

**The same is true in the other direction, and M8 built it.** More than 2 KiB
written *to* a pane whose program is not reading blocks the writer, and the
writer of a paste (§7.6) is the event loop. So a pane's input has a thread of
its own too: bytes go into a channel and the thread does the waiting. The host
is the odd one out and in the more dangerous direction — its pty discards what
will not fit and reports success — which is a lossy paste there and a
documented divergence.

**stdout and stderr are separate pipes**, where a pty would merge them into one
stream. Both feed the same pane emulator, so interleaving at a byte level may
differ from Linux under heavy concurrent output. Documented divergence.

Take `russhd`'s drain-before-close discipline (`local_session.rs:161-166`): a
dead child's pipes may still hold output, so a pane that exits must be drained
before it is closed, or short commands lose all of it.

**A timeout is not a clock.** Measured on Motor in M7: `Receiver::recv_timeout`
reports a timeout *before* its duration is up. A condition variable is allowed
to wake spuriously and this one does, so every wait with a deadline has to ask
[`std::time::Instant`] whether the time is really up and go round again if it is
not. What this cost, before it was understood: a 200 ms window for the console's
size answer that ended after about 8 ms, so the first frame was painted at the
fallback size and then again — the exact symptom being fixed. The same mistake
in the other three waits would have been worse than the bugs they close: the
escape-time flush would give up on a half-arrived arrow key and type an `Esc`
and some junk into a pane; the client's "nothing answered" deadline would take
a working session down at random; and the farewell would drop a connection with
the exit code still unread. All four now measure against a clock, and
`proto::timed_out` says so where a caller might be tempted otherwise.

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
libc = "0.2"   # host only: the pane's pty, TIOCGWINSZ, and termios

[profile.release]
panic = "abort"
lto = "fat"
strip = true
codegen-units = 1
```

`libc` is host-only, exactly as in rush — it never reaches the Motor build. It
buys the three things the host has and Motor does not: a pty to give a pane's
child, the ioctls to ask and tell a terminal its size, and the termios to make
a console raw (§10, M1).

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
| `pane.rs` | A pane: the `sh` child (§4.3), pipes, `Grid`, `ansi` parser, `ESC[6n` answering (§3.2). No `cfg` — it spawns a bare `sh` and the platform resolves it. Also holds `Event`, the one channel every byte source funnels into (§4.5), until `server.rs` arrives to own it. |
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
  (`term.rs:583-586`). Set it to `None` on a refresh, on resize, and after anything
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

Borders in the UTF-8 box-drawing characters real tmux draws — `│`, `─`, and the
junction (`┼`, `├`, `┤`, `┬`, `┴`) that says which arms a cell has. Not the ACS
charset: `sys-tty` forwards the bytes it is given untouched, so the console
needs no shift-in/shift-out to render them, and the corpus can compare borders
against the oracle rather than fold them out (§9.1).

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
selection, `Enter` copies it and exits. `mode-keys emacs` is the same commands
under tmux's other table (M9). `prefix-]` pastes the top buffer into the
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

**Measured (M0).** `rmux spike-keys` (a stdin hex dump) was fed the xterm
encodings on both paths — the serial console (qemu → sys-tty) and over SSH
(russhd, which bypasses sys-tty). Both deliver every byte **intact and in order**:
nothing mangles `[`, `;`, the digits, or the `ESC`-prefix form. What differs is
the *framing*.

| Combo    | Bytes                | Serial (sys-tty)              | SSH (russhd)      |
|----------|----------------------|-------------------------------|-------------------|
| `Left`   | `1b 5b 44`           | intact, split across reads    | intact, one read  |
| `S-Left` | `1b 5b 31 3b 32 44`  | intact, split across reads    | intact, one read  |
| `S-Right`| `1b 5b 31 3b 32 43`  | intact, split across reads    | intact, one read  |
| `M-Left` | `1b 5b 31 3b 33 44`  | intact, split across reads    | intact, one read  |
| `M-Right`| `1b 5b 31 3b 33 43`  | intact, split across reads    | intact, one read  |
| `M-Up`   | `1b 5b 31 3b 33 41`  | intact, split across reads    | intact, one read  |
| `M-Down` | `1b 5b 31 3b 33 42`  | intact, split across reads    | intact, one read  |
| `M-Left` (`ESC`-pfx) | `1b 1b 5b 44` | intact, split across reads | intact, one read  |

Two conclusions the decoder is built on:

1. **The xterm encodings are what arrives.** `S-`arrow is `ESC[1;2<D/C>`, `M-`arrow
   is `ESC[1;3<A-D>`, and the alternate Alt form `ESC` `ESC[<A-D>` also arrives
   untouched. rmux emits and decodes exactly these; no Motor-specific dialect.
2. **The decoder must be incremental.** On the serial console sys-tty forwards a
   byte at a time (`main.rs:140`), so a read splits the sequence at *unpredictable*
   points — `1b 5b` then `31 3b 32 44`, or `1b` then `5b 31 3b 32 43`, run to run.
   SSH delivers each sequence whole (one channel packet → one write → one read),
   but rmux cannot depend on that: the key parser buffers bytes and never assumes
   a sequence lands in a single read. This is the same trap rush's VM harness
   documents for `ESC[6n`, now measured for input.

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
  cannot quietly stay documented as broken". The omissions in §1.2 go here.
  **This list is the honest scope statement of the project.**

There is a pleasing shortcut available: tmux can be both the pty provider *and*
the screen scraper. Running the case inside an outer `tmux new-session` lets
`tmux capture-pane -p` return the grid the inner multiplexer painted, and
`tmux list-panes -F '#{pane_left},#{pane_top},#{pane_width},#{pane_height}'`
return its geometry — no hand-written reference emulator in the harness at all.
Verified working against tmux 3.4 before any of this was built. Use it for geometry
assertions; use the replayed-grid path for content, since it is what the VM
harness can also do.

### 9.2 Byte-cost tests

rmux-only — tmux is not the oracle for these — and modelled on rush's
`// ---- painting ----` block (`tests/phase8.rs:427-434`), whose rationale is
exactly §6.3's: "erasing a line and drawing it again reaches the identical screen
and flickers the whole way… so it is the bytes that have to be tested".

Claims worth pinning: a keystroke echoed in a pane costs the bytes of that
keystroke; moving between panes repaints no pane content; a status-line clock
tick rewrites only the digits that changed; a full repaint happens only on a
resize and on `refresh-client`.

One qualification, and only on Motor: an idle rmux there writes the size probe
once a second (§3.2), because there is no other way to find out that a window
was dragged. It is not a paint, and the byte costs discount it by name rather
than absorbing it — a probe that changed would fail the check rather than being
quietly allowed. On the host an idle rmux still writes nothing at all.

### 9.3 Pure unit tests

The emulator (§5.1) and the layout tree are pure and take the bulk of the tests,
in-file as `#[cfg(test)] mod tests`, per both red (`editor.rs:2163`) and rush.
They need no pty and no terminal; they run on Linux in milliseconds. Note red's
enabling trick and copy it: config is *injected*, not loaded, "so that `new` does
no file I/O and tests are not at the mercy of the config file on the machine
running them" (`editor.rs:121-124`).

Test names are full sentences, per rush.

**A test that starts a session must end it.** Learned the hard way: 827 rmux
servers, each holding a live `sh`, accumulated on the development host over a few
hundred runs of the host suite. Not a server bug — a session outliving its client
is what a detach *is* (§7.3), so killing the client is exactly the wrong cleanup.
`tests/host.rs` asks the server to end its sessions through the real
`kill-session` (which is also what reaps the pane's shell, §3.6), and the server
exits when the last one goes. Two consequences worth keeping:

- **Cleanup runs from a destructor, so it must be bounded.** An rmux command that
  hangs there hangs every test after it and the suite reports nothing at all.
  Every command the teardown runs gets a deadline and a kill.
- **A scratch directory is state too.** Each test gets one (`$TMPDIR`, so that
  parallel tests do not meet on one port file) and each removes its own.

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

**M0 — Spikes and scaffolding. Done.** The measurements everything else rests on, both
cheap and both disqualifying if wrong:
1. Orphan survival (§4.4) — detach is worthless without it. Measured: a plain
   orphan *is* reaped on Motor, which forced a new OS primitive — detached spawn,
   gated by `CAP_SPAWN_DETACHED`.
2. The actual key bytes for `S-`/`M-` arrows, serial and SSH (§8.3). Measured: the
   xterm encodings arrive intact on both paths, but the serial console fragments
   them across reads, so the key decoder must be incremental.
Also landed: qemu `-echr` in a run-script variant (§9.4); the crate skeleton; the
`sys::` seam; Makefile + `src/imager/motor-os.yaml` wiring; and the sys-tty `^C`
patch (§3.5). Loopback TCP needed no spike — systest already proves it (§4.2). The
two `spike-` subcommands were deleted once their answers were recorded above, per
plan; the crate is now a clean library seam over a placeholder `run`, ready
for M1.

**M1 — One pane, no UI. Done.** Spawn `sh` (§4.3) on piped stdio with the
is-terminal env var; pump bytes both ways; drain on exit. This is sys-tty
reimplemented inside rmux, and it proves the whole pty-equivalent claim of §3.1
before anything is built on it. The milestone: an interactive rush, reached
through rmux, that cannot tell the difference — including `is_terminal()`.

**Verified on the VM, on both terminals** (§3.3 — they are two different ones):
over SSH and on the serial console through sys-tty, `rmux` starts a pane whose
rush prints its interactive prompt, runs commands, and fires the
`ESC[999C ESC[6n` width probe of §3.2. rmux does not answer that probe yet —
the bytes cross it and whatever is at the far end of rmux's *own* console
answers, or nothing does and rush falls back to its 80-column default. Both are
wrong once there is more than one pane, which is M3's job. Exiting the pane
returns to the outer shell. The §4.3 spawn chain is confirmed in the kernel log
exactly as predicted: `spawn /bin/rmux` → `spawn sh` → PATH finds `/bin/sh` →
its `#!/bin/rush` shebang → `spawn /bin/rush`, with no shebang handling in rmux.

Bytes cross in both directions **unexamined**, which is §8.1's rule rather than
an M1 shortcut. Nothing re-encodes Enter yet (§3.4 — unnecessary while
forwarding is verbatim, because sys-tty's CRLF simply passes through).

**The host got its terminal too.** rmux is meant to run on Linux, not merely
build there, and that needs the three things Motor does not have: a real pty
for the pane (`isatty()` is a property of the descriptor here, so no
environment variable can forge it), `TIOCGWINSZ` to ask the console its size
and `TIOCSWINSZ` to tell the pane, and termios to put rmux's own console in raw
mode — which on Motor it permanently is. All three live in `sys::unix` behind
`spawn_pane`/`console_size`/`RawConsole`, so `pane.rs` has no `cfg` in it.

Two asymmetries survive the seam and are worth stating:

- **A pty cannot be closed from rmux's end.** The master is one open file for
  both directions, so dropping the writing half would take the reading half
  with it and lose the child's last output. "No more input" is therefore a
  closed pipe on Motor and a `^D` on the host — `sys::END_OF_INPUT`.
- **A pty merges stdout and stderr**, where Motor's pipes keep two streams
  (§4.5). The pane pumps however many it is handed.

The host's half is tested the way it has to be — over a pty, by
`tests/host.rs`, which lifts rush's `Pty` (`tests/phase8.rs:37-174`) that §9.1
earmarks for the conformance harness. Each mechanism test was **falsified**
before being believed: disable raw mode, `TIOCSWINSZ`, or `setsid`/`TIOCSCTTY`
in turn and exactly the corresponding test fails. Two of them did *not* fail
the first time and were rewritten, which is the reason to bother:

- a pty **echoes what is typed whether or not the program ever reads it**, so a
  needle that appears in the echoed line tests nothing. Needles now come only
  from a command's output (`echo al""ive` echoes the quotes and prints
  `alive`).
- `^C` **flushes the input queue**, so sending it before the pane has
  demonstrably started the command it is meant to interrupt tests nothing
  either — the command it was supposed to kill never ran.

**M2 — The emulator. Done.** `ansi.rs` + `grid.rs`, pure, unit-tested on Linux.
No rendering yet. Deferred wrap, scroll regions, alt screen, `ESC[6n`.

The split between the two is sharper than §5.1 had to say: **`ansi.rs` emits
syntax, `grid.rs` decides meaning.** An `Action` is a final byte and its
parameters, nothing more. The reason is failure mode, not taste — a sequence
rmux does not implement is then a grid that ignores it, never a parser that
mis-frames the bytes after it. The parser allocates nothing and is incremental
by construction (§8.3), and the grid never learns there is a pipe: `ESC[6n`
comes back out as a `Reply` for the pane to write into its child's stdin.

`ESC[999C ESC[6n` and `ESC[9999;9999H ESC[6n` — rush's probe and red's, verbatim
— are pinned as tests against a grid of a known size, so §3.2's claim is now
checked rather than argued.

Simplifications made here, each deliberate and each a candidate for
`DIVERGENCES` (§9.1) when the corpus lands:

- Tab stops are fixed at every eighth column; `HTS`/`TBC` are not implemented.
- No origin mode (`DECOM`, `?6`): `ESC[H` is the screen's home, never the
  scroll region's.
- `DSR 6` is the only status report answered. Device Attributes and `DSR 5` get
  nothing, which §3.2 establishes is a terminal's prerogative.
- `?47` and `?1047` are treated as `?1049`, so they save the cursor too.
- `:` is parsed as `;` in a parameter list. rmux's vocabulary has no
  sub-parameters, and the alternative is mis-framing an SGR that uses them.
- OSC is parsed and dropped except `0`/`2`, the window title. That includes
  `52`, the clipboard rmux deliberately does not have (§7.6).

**M3 — Rendering. Done.** The compositor and frame diff, one full-screen pane.
The milestone: **`red` runs inside rmux**, sized correctly, because rmux answers
its `ESC[6n`. If red works, the emulator is real.

**It works, on both terminals.** On the host and on the Motor serial console,
red opens inside a pane, sizes itself to that pane rather than to a default,
puts its status line on the pane's last row, and hands the shell's screen back
when it quits — which exercises the pane's own `?1049` (§5.3), since red lives
on the alternate screen. A pane's output is no longer relayed anywhere: it is
parsed into that pane's grid, composited, and diffed.

**The compositor knows what the console is *in*.** Every byte the console
receives comes from `screen.rs`, so where its cursor sits and which SGR is in
force are known rather than guessed, and a repaint states only what changed.
That is what makes the byte-cost claims of §9.2 exact rather than approximate:
**an echoed keystroke costs `ESC[{r};{c}H` and the character — seven bytes**,
and one inside an already-styled run costs *one*, because neither the position
nor the style needs restating. Those are pinned as equalities, so a regression
shows up as the bytes it added. red's reset-prefixed invariant is kept (§6.1);
what changed is that rmux may also rely on what it itself last sent, which is
not a guess.

**The size probe landed** (`keys.rs`), and with it §3.2's second mechanism. The
platform is asked first; where it cannot say — always, on Motor — rmux sends
red's `ESC[9999;9999H ESC[6n` and takes the answer with rush's discipline,
never waiting for it. Until it arrives rmux runs at 24x80, which is a coherent
pane rather than a correct one. The scanner that recognizes the answer is the
first thing in `keys.rs`, and it is careful in two ways the next reader should
not undo: the report must never reach the pane (a shell handed a stray
`ESC[30;90R` prints it), and `ESC[1;2D` is `S-Left` and looks exactly like a
report until its final byte, so what is held back has to be given back in
order.

One trap, found by a test that failed three runs in five: **the final frame is
painted after the exit, not before it.** A pane's waiter reports the exit only
once its output has been drained (§4.5), so the last thing a program printed is
in the grid by then — and breaking out of the loop to leave without painting
throws it away. It is the same loss the drain exists to prevent, one layer up.

Two gaps M3 leaves, both deliberate:

- **Nothing notices a console resize.** On Motor nothing can (§3.2). On the
  host it would take a `SIGWINCH` handler, which is a signal, which is the one
  thing the `sys::` seam has no shape for yet. rmux learns its size once.
  *Closed in M10, and neither by a signal nor by anything Motor grew: the
  client asks, on a clock.*
- **Nothing forces a repaint.** `Screen::invalidate` exists and a resize uses
  it; binding a key to it needs the key tables, which are M5's. It ended up
  waiting until M9, as `prefix r`.

A resize *of a pane* does work, and clips rather than reflows — as tmux does,
and because reflowing rewrites history a program still believes it addressed.

**M4 — The split. Done.** Server, client, transport, detach, attach, and the
session list (§7.3) — sessions arrive with the server that holds them, not
later.

**Verified on Motor, which is where it counts.** On the serial console: start
`rmux`, set a shell variable, press `C-a d`, land back at the outer shell, run
`rmux` again, and the variable is still there. That is the same shell process,
still running, with nothing attached to it in between — detach and attach, over
loopback TCP, with the server spawned detached and outliving the client that
started it. M0's `CAP_SPAWN_DETACHED` exists for exactly this moment.

The shape, and what each piece is for:

- **The server owns everything and renders** (§4.1). The client relays
  keystrokes one way and paints bytes the other, and holds no opinion about
  either. **The prefix is therefore the server's business**: `C-a d` becomes a
  detach there, not in the client. M4 recognizes that and `C-a C-a`
  (`send-prefix`, §8.2); M5 replaces the pair with the real key tables on the
  same seam.
- **The frame diff is per client, not per session.** Two consoles are in two
  different states, so each carries its own `Screen`. Sharing one would mean
  sending a client the difference against a screen it never had.
- **The client owns the console**, because raw mode, the alternate screen and
  the size probe are properties of *this* terminal rather than of the session.
  The probe's answer reaches the server as a `Resize`.
- **A frame is length-prefixed** so a reader can skip a message it does not
  understand rather than losing the stream, and `Frames` never assumes a
  message arrives whole — TCP may split a write anywhere.

Three traps, all measured:

1. **`/sys/tmp` does not exist** (§4.2, corrected above), and neither does the
   directory the *lock* file needs. Creating the lock therefore failed, and the
   client read that failure as "another client is starting a server" and waited
   ten seconds for one nobody was starting. A failed lock now means "start one"
   unless the failure is specifically `AlreadyExists`.
2. **Paint before ending a session.** A pane's exit is reported only once its
   output has been drained (§4.5), so the last thing a program printed is in
   the grid when `Exit` is about to go out — and removing the client first
   throws it away. This is the *same* loss as M3's, one layer up, and it was
   again a test that failed about a third of the time rather than always.
3. **Tests need a server apiece.** A client attaches to whatever the port file
   names, so parallel tests without a `$TMPDIR` each would share one session
   and read each other's output.

Deliberately left for later: the command surface — `new`, `attach`, `ls`,
`kill-session` (§7.3) — is M6's, and `prefix-d` is hardcoded until M5 makes the
tables real. The protocol already carries `List` and `Kill`, so M6 is wiring
rather than design.

**M5 — Config and input. Done.** The default key tables (§2.1), the prefix,
`send-prefix`, and `rmux.toml` (§2.2) on top of them. After this the defaults
are compiled in rather than prose, and overridable.

`bindings::defaults()` **is** §2.1's table, as data — every line of that config
plus the tmux defaults it is written against — and it is tested against that
table entry by entry. §2.2's example config is tested to be a **no-op**, which
is what it claims to be: if applying it changes anything, one of the two
representations has drifted. Moving the prefix with an `rmux.toml` is checked
end to end over a pty, both halves of it: `C-b d` detaches and `C-a` has become
an ordinary byte.

Input routes in three steps (§8.1, §8.2), and the order is the whole of it: a
key equal to the prefix is **held** and reaches nobody; the key after it is
looked up in the **prefix table**; anything else is looked up in the **root
table** and, failing that, goes to the pane as the bytes it was made of.
`send-prefix` is the one command that produces bytes rather than an action, and
what it produces are the prefix's *own* bytes as they arrived — rmux never
re-encodes a key, so there is nothing to get wrong.

Two things worth knowing before they surprise someone:

- **A bound key stops reaching the pane, even when what it names is not
  implemented yet.** The config binds `M-Left` (§2.1), so it was rmux's key
  from M5 on although `select-pane` did not arrive until M7. That is what tmux
  does, and the alternative — leaving it out of the vocabulary — would make the
  config file's own binding an error. A plain arrow is in neither table and still reaches the pane, which
  is what rush's and red's line editing depend on, and both halves are tested.
- **`Esc` is both a key and the start of every other one.** A decoder that
  never gave up would strand red in a pane; one that never waited would turn
  every arrow into an `Esc` followed by junk. A half-arrived sequence is held
  for 50ms and then taken at face value — tmux spends its `escape-time` on the
  same problem — and the server blocks rather than polls whenever nothing is
  held.

Config is **injected, not loaded** by the server core (§9.3): `Config::load` is
the only thing that touches a disk and only `serve` calls it. A malformed entry
is skipped and reported while the rest of the file still applies, because a
typo in one binding must not cost a user their config; the complaints are
carried rather than printed, since the server has no console of its own (§4.4)
and where they belong is the status line, which is M6's. `mode-keys = "emacs"`
is refused rather than accepted-and-ignored: only vi is implemented. (M9 built
the emacs table, and the setting means what it says now.)

**M6 — Windows and sessions. Done.** Windows: new, next, previous, select,
rename, kill, `renumber-windows`. Sessions: `new`/`attach`/`ls`/`kill-session`,
`prefix-(` and `prefix-)`, `prefix-$`, and the `prefix-s` list (§7.3). Plus the
status line, which is where the session name first becomes visible.

**A window number is a user-visible name, not an index.** `prefix 0`-`9`
selects by it and the status line shows it, so killing window 1 of `0 1 2`
leaves `0 2` and window 2 is *still* called 2 — unless `renumber-windows` is on,
which the config sets, and then the list compacts. Both behaviours are one
function apart, and confusing them means `prefix 2` silently selecting somebody
else's shell. A new window takes the lowest free number, as tmux does.

A window's name follows what runs in it — the pane's `OSC 0`/`2` title, which
§5.2 was already collecting — until `prefix ,` takes it over for good. The flag
that remembers a rename is the whole difference between a status line that
tracks reality and one that argues with the user.

`prefix ,`, `prefix $` and `prefix s` are **modes**: while one is up it owns
every key, prefix included, and nothing reaches a pane. The prompt borrows the
status row, as tmux's does; `prefix s` is the plain numbered menu §7.3 asks for,
picked by digit or arrows, `Esc` cancelling — not `choose-tree` (§1.2).

`aggressive-resize on` now means something: a session's window is sized to the
smallest client *viewing* it, and a background window keeps its size until it
comes to the front. With one client it is still a no-op, which is why the size
lives on the client.

Three things this milestone had to fix or add, each found rather than foreseen:

1. **A pane can be killed now**, which meant moving the child handle out of the
   waiter thread and into the pane (§3.6: terminate is the only thing one
   process may do to another, and `Child::kill` needs a handle somebody holds).
   The exit status is now learned when the pipes empty rather than when the
   child dies; a grandchild holding them open delays both, and delayed either
   way.
2. **Input has to take effect in the order it was typed.** `prefix p` and the
   command line typed after it arrive in one read, and delivering all the bytes
   before applying the switch types them into the window the user just left.
   Bytes and commands go into one ordered list rather than two buckets.
3. **`ptsname` answers from a static buffer**, so two panes opening a pty at
   once race on it and one gets a truncated `/dev/pts` — a directory, hence
   `EISDIR`. The test suite found it by spawning panes from a thread apiece.
   The comment that used to excuse it ("only the event loop spawns panes") was
   not an invariant worth resting a data race on; there is a lock now.
   Falsified: without it, 3 runs in 15 fail.

And a fourth instance of the **paint-before-you-drop-the-grid** shape that M3
and M4 each hit once: closing a window removes its grid, so the last thing the
program printed has to be painted first. Three places now do this for the same
reason, which is why the comment at each of them names the other two.

One divergence to record: `prefix &` and `prefix x` kill outright, where tmux
asks `kill-window? (y/n)` first. `confirm-before` is a command rmux does not
have, and inventing a confirmation prompt for two bindings is not worth a mode.

**M7 — Panes. Done.** The split tree, borders, `|` and `-`, directional
selection, resize, zoom, kill. After this a window is a tree of splits with
panes at the leaves (§7.1) rather than one pane wearing a window's name.

**Geometry is a function of the tree, and a split remembers one number.** Ask
`layout` for the boxes with the window's size and every one falls out of the
shape of the tree. The exception is where each split puts its border: M7 stored
nothing at all and halved at every split, which was right while
`resize-pane -Z` — zoom — was the whole of the vocabulary, and wrong the moment
M9 added the other four directions. A split now keeps its border in cells, as
tmux's `layout_cell` does, and `Layout::refit` scales them when a window
changes size. What that costs is an invariant, since a stored size can disagree
with the window that owns it: the area a layout is asked about only ever
changes through a `refit`, and `window.rs` has one place that does either.

The tree holds `PaneId`s and no panes, which is what keeps it pure and its
tests measured in microseconds (§9.3); `window.rs` owns the children and asks
the tree where to put them. Two things fall out of that split of
responsibilities and are worth knowing:

- **A pane's screen is what its program is told the terminal is** (§3.2), so
  the one place a pane learns how big it is — `Window::fit` — is where a split,
  a kill, a zoom and a console resize all end. A pane whose grid is still the
  whole window answers `ESC[6n` with a lie and draws outside its box.
- **The child is told too, where it can be.** `sys::TellSize` is a third
  asymmetry across the seam, beside merged output streams and `END_OF_INPUT`:
  the host has `TIOCSWINSZ`, which sets the pty's size and sends a `SIGWINCH`;
  Motor has no ioctl, no terminal-size call and no signals (§3.6), so the child
  finds out at its next `ESC[6n` and nowhere else. Only when the size really
  changed — every split and kill refits every pane, and a shell redraws its
  prompt whenever it gets a `SIGWINCH`.
- **A pane is born the size of its box**, not of its window. On the host either
  would do, since the resize above corrects it a moment later; on Motor a pane's
  `$COLUMNS`/`$LINES` are fixed when its child is spawned and nothing can change
  them, so being born wrong is permanent. (No longer the whole truth as of
  2026-08-08: a *shell* pane keeps them current itself, §3.2's amendment. Being
  born right still matters — it is what everything before the shell's first
  command sees, and what a non-shell child lives with for good.)

**Three things the host could not have caught, all found by driving the real
thing on Motor** (§9.4, and the reason that step exists):

1. **A pane must turn `\n` into a new line itself.** Motor has no line
   discipline (§3.1) and a pane is a pipe, so nothing stands between a program's
   `\n` and the pane's grid — where a pty's `ONLCR` has already done it on the
   host. `printf 'aa\nbb\ncc\n'` came out as a staircase, each line starting
   where the last one ended. `sys-tty` does this rewrite for the real console
   (§3.3), so a pane must do it too: `sys::PANE_NEWLINE_MODE`, which is the
   grid's LNM. Not a mode a program may change — turning it off on Motor would
   be turning off what the platform's own terminal does unconditionally.
2. **`$COLUMNS` beat the terminal's own answer in rush**, so a shell in a split
   pane kept the width it was spawned with. Fixed in rush, separately: the
   probe is authoritative and `$COLUMNS` is the fallback for a terminal that
   never answers, because on Motor nothing can update it — it is a cache with no
   invalidation. This is the fix that makes the pane a split *divides* correct;
   rmux spawning the new pane at its box size only fixes the new one.
3. **The stray `%` of §3.2**, which is what was left after both -- and what
   forced §3.2's fourth mechanism: a pane answers the size question again, of its
   own accord, for a program that has asked it before. *Reverted in M11, which is
   the phase that shows what it really cost; the `%` was rush's to fix, and rush
   has fixed it by waiting for the answer to its own probe (§3.2).*

**Two borders never share a cell.** A split's border spans only the pane it
divides, and that pane never contains its parent's border — so what borders do
is *meet*: a row border stops against a column border, and the cell it stopped
against grows a third arm that says so — the tee tmux draws there, and a cross
where a border reaches it from both sides (§7.1).

Three behaviours found rather than foreseen:

1. **A killed pane has to leave the layout at once.** A pane is removed when
   its output drains (§4.5), which is right for a program that exited — its
   last output must be painted first. But `prefix x` kills a child, and the
   keys typed in the milliseconds that follow went into a dead pty, because the
   pane was still the one in front. It comes off the layout immediately now and
   is dropped when it drains; asking the layout to close a pane it no longer
   has is what makes the second step harmless.
2. **A zoomed window needs to say so.** It looks exactly like a window with one
   pane, so without tmux's `Z` on the status line a user has no way to tell
   where the others went. The active pane's border is *not* highlighted — tmux
   colours it, rmux does not, and what says which pane is in front is the
   composited cursor (§3.2). Recorded as a divergence.
3. **The pane in front is always on screen.** Whatever changes it unzooms, or
   `Window::cursor` would be asking for the box of a pane that has none.

**Not in this milestone, deliberately:** `resize-pane` in any direction but
`-Z`. It is in neither §2.1's table nor the command vocabulary, and adding a
binding for it would be inventing config the project is not built to. (M9
found that the binding did not have to be invented — tmux binds it on the
modified arrows — and built it.)

**Tests learned something too, and it applies to every test after this one:
the wire is not the picture.** The frame diff sends only the cells that changed
(§6.3), so text already on screen in the right place is never sent — and a test
waiting for those bytes is waiting on a race with whatever program last drew
there. That was a real flake in M6's `prefix c` test (about one run in ten
under load: a new window's prompt lands on the cells the old window's prompt
was on). `tests/host.rs` now replays everything rmux writes into a `Grid` and
asserts on *that*, which is what §9.1 says the conformance harness must do,
with rmux's own emulator doing the replay.

**M8 — Scrollback and copy mode. Done.** Compact history (§7.5), vi copy mode,
search, selection, paste buffers. After this a pane remembers what it has
printed, and the only way to read it — or to take anything out of it — is copy
mode.

**History is not made of grids.** A line that scrolls off the top stops being
cells and becomes text plus a run-length list of styles, with its trailing
blanks not stored at all (§7.5); an unstyled line, which is most of what a
shell prints, keeps no style list either. That is what makes `history-limit
9999999` a cap rather than a promise of gigabytes. The live screen stays
`Cell`-based, and one accessor renders both — so copy mode walks
`0..total_rows` and cannot tell which side of the boundary a row is on. The
limit is enforced where the lines are made rather than where they are counted,
and lowering it takes effect at once, because it is a memory bound and not a
preference.

**Only the whole screen scrolls into history**, which is tmux's rule
(`grid_view_scroll_region_up`) and worth stating because the alternative looks
right: a program with a scroll region is holding a header or a status line
still and moving text *between* them, and those lines never left its screen.
Putting them in the scrollback would interleave a redrawn pager with itself.
The alt screen keeps no history at all (§5.3) — red lives there, and every
repaint would otherwise become scrollback — and copy mode sees none while it
is up, which is the same rule from the reading side: what is above a
full-screen program's screen belongs to the screen *underneath* it, and
showing it would put a shell's old output above red's window. It is still
kept, and it comes back when the program gives the screen back.

**Copy mode is a table, not a key handler.** `h` names `cursor-left` exactly as
`|` names `split-window -h`, in tmux's own `send -X` vocabulary, and
`[bind-copy]` rebinds it (§2.2). `mode-keys` is therefore data like everything
else in §2.1 — it picks which table copy mode starts as, and nothing
downstream of the table can tell which was picked — and a user translating a
tmux config finds the words they already know.

**Pasting is typing** (§7.6), and the one thing rmux re-encodes. Every other
byte a pane receives is forwarded as it arrived (§8.1); a paste was never typed
at a console, so there is nothing to forward and Enter has to be *made* — which
is `\r` on the host and `CR LF` on Motor, sys-tty's own synthesis (§3.4),
behind `sys::ENTER`. A pane that asked for bracketed paste gets the markers it
asked for.

**Writing to a pane has a thread now**, which §4.5 predicted in the abstract:
"a paste will [fill the ring], and will need somewhere to block that is not the
event loop". The measurement sharpened it into two different problems. On Motor
the pipe is a 2 KiB ring that blocks its writer, so a paste into a program that
is not reading would have stopped the server for as long as that program ran.
On the host it does not block at all — a megabyte written at a `sleep` came
back `Ok(())` at once, because a pty *discards* what will not fit in its input
queue. So the channel keeps Motor's event loop moving, and large pastes on the
host are lossy either way: a divergence to record rather than something this
can fix. The test that pins it uses a writer known to block, because the test
that used a real pane passed whether or not the thread was there.

**Found by a test, and the fourth instance of a shape M6 named: what a key
means depends on the state it is *reached* in, not the state it arrived in.**
`prefix [` and the vi keys typed straight after it arrive in one read, and
deciding what every key in that read meant before running any of them sent the
motions to the shell — copy mode not being up yet when the bytes were looked
at. The screen said so plainly: a search needle and a selection command typed at
a prompt, and `sh: 2: ?COPYME: not found`. Deciding per key, as each is
reached, is also less code than the list of pre-decided steps it replaces, and
it keeps M6's own fix — bytes and commands still take effect in the order they
were typed, because whatever is pending is written before a command runs.

Divergences this milestone adds, each an entry for §9.1's list:

- **A mode owns every key, the prefix included.** tmux leaves the prefix table
  live in copy mode, so `C-a c` opens a window from there; rmux does not. It is
  the rule its rename prompt has had since M6, and one rule is better than two:
  `q` first, then the prefix.
- **A word is a run of non-blanks.** No `next-word-end`, and no
  `word-separators` option to make `-` or `_` a boundary.
- **Search is case-sensitive and not incremental.** The needle is typed on the
  status row and acted on at `Enter`; there is no highlighting of the matches
  it did not go to. A search that finds nothing leaves the cursor where it was
  and says so — on the message line, which M9 built for it.
- **The indicator borrows the status row**, where tmux draws it in the pane's
  top-right corner. That row is already chrome (§7.3) and a pane has no
  corner to spare; the cost is that the session name and window list are not
  visible while copy mode is up.
- **The buffer stack is only reachable through `prefix ]`.** tmux's
  `choose-buffer`, `list-buffers` and `copy-pipe` are not there, and neither is
  a rectangle selection.

**M9 — Conformance and polish. Done.** The tmux corpus, the divergence list,
the VM harness, byte-cost tests, `aggressive-resize` with two clients, the
message line, `refresh-client`, `resize-pane`, `mode-keys emacs`, the README.

**The corpus states nothing.** `tests/conformance.rs` drives each case through
both rmux and tmux and requires the two to paint the same picture (§9.1), with
`tests/defaults.tmux.conf` — the checked-in copy of the file §2.1 declares
rmux's defaults to *be* — as tmux's `-f`. Twenty-five cases over the emulator,
the window list and the split tree, and they agree as written; the geometry
lands where tmux puts it, border column included, which is the interesting part
of §7.1 being derived from the tree rather than stored.

Three things the comparison needed, each measured rather than assumed:

- **tmux's paste heuristic.** A binding whose predecessor arrived less than a
  millisecond earlier is forwarded verbatim, and a key script is one write, so
  the prefix went to the shell. `assume-paste-time 0` turns it off. rmux has no
  such heuristic — a bound key is rmux's however it arrived (§8.1).
- **A login shell reads `/etc/profile`**, which is the host's and not the same
  twice, so tmux gets `default-command` rather than `default-shell`.
- **Typing at a shell that has not printed its prompt is a race, not a case.**
  The echo comes from the pane's line discipline and the prompt from the shell,
  and which lands first says nothing about the multiplexer. A case is therefore
  a *script* whose chunks are sent only once the screen has stopped changing.

`DIVERGENCES` holds `prefix &` killing outright (M6), copy mode's indicator on
the status row (M8), and a third found here: **a mode takes the
keys that arrived with it** — `prefix :` and the command typed in the same read
reach the prompt that key opened, where tmux's prompt is not up yet and the
shell gets it.

**`prefix :` runs a command.** Bound since M5 and inert since M5 — the
dispatcher said "`command-prompt` is M9's" — which is worse than unbound,
because a bound key does not reach the pane either. It opens a prompt on the
status row now, and `Command::parse` (§2.2's, unchanged) turns the line into a
command. Not a command *language*: a name and its flags.

**The message line, which §2.2 promised in M5 and nothing built.** A malformed
config entry was skipped correctly and reported to nobody — `serve()` dropped
the complaints on the floor — and three more places had the same problem, each
of them a command whose failure leaves the screen exactly as it was: a split
with no room, a search that finds nothing, and now a `prefix :` line naming a
command rmux does not have. All four say so on the status row, and the *next*
key takes the row back. No timer: tmux's `display-time` means waking the server
on a clock, which is the price §4.5 refuses for a status-line clock and refuses
here for the same reason. The config's complaints go to the client that started
the server and to no other — a client attaching an hour later has not touched
that file. `Server::new` takes the complaints beside the config now, so the
half of §2.2 that was dropped cannot be dropped silently again.

The corpus cannot help with any of that: it drops the status row before
comparing (the two status lines are not the same line), so nothing on the
message line is comparable against tmux, and what pins it is a host test that
reads the row off the replayed screen.

**`refresh-client`, on `prefix r`.** The gap M3 left and every phase since
walked past. It was left out because §2.1's table does not name it and
inventing a binding is what M7 refused to do for `resize-pane` — but the
binding did not have to be invented: `Bindings::defaults` is that table *plus
the tmux defaults it is written against*, and `prefix r` is one of those
(`tmux list-keys` says so). What is **not** bound is `C-l`, in rmux as in tmux:
a shell clears its screen with it, `less` and `vi` redraw with it, and a
multiplexer that took it would take it from every program in every pane. It is
tested arriving in a pane.

**`resize-pane`, in the four directions M7 left out** — and the same discovery
as `refresh-client` above: tmux binds it on the prefix table's modified arrows
(`C-`arrow by one cell, `M-`arrow by five), so no config had to be invented
after all. It cost the one design decision M7 got to avoid. A layout that
stores nothing cannot be resized, so a split now keeps its border in cells as
tmux's `layout_cell` does, and `Layout::refit` scales every border when a
window changes size — a split nobody has moved stays even, since an even split
scaled is still even. The invariant that buys is written down in `layout.rs`:
the area a layout is asked about only ever changes through a `refit`.

**Which border moves is tmux's rule, and reading the source got it wrong.** The
border moved is the one *after* the pane, and only when the pane is last along
that axis the one before it — that part survived. What did not is the direction:
`layout_resize_pane` negates its adjustment for a last pane, which reads as "a
resize always widens the active pane". tmux does not do that. `C-Left` on the
right-hand pane moves the border *left*, and the corpus said so — two of eight
pane cases disagreeing, in exactly the two columns the rule predicts. The
border follows the arrow, whichever side of it the pane is on. That is the
whole reason a resize case is in the corpus rather than only in a unit test:
the unit tests all agreed with each other and with the wrong rule.

**`mode-keys emacs`**, which M5 named and refused. Both vocabularies are data,
so the second one is a second table read off `tmux list-keys -T copy-mode`, and
copy mode itself cannot tell which was chosen. `Config::parse` holds bindings
back until the file has been read, so `[bind-copy]` overrides whichever table
`mode-keys` picked wherever in the file that line sits. One byte had to be
fixed for it: NUL decoded as `` C-` ``, a key nobody can type, where every
terminal means `C-Space` by it and `Key::parse` reads that name — so emacs
mode's `begin-selection` would have been unreachable.

That closes §9.2's last claim. "A full repaint happens only on a resize and on
`refresh-client`" is now whole: the resize half was already pinned, and the
other half is two tests — the render after `prefix r` carries text that was
already on screen, which the diff would otherwise never resend, and the same
thing on the wire through the socket. There is a corpus case too, and it is the
weakest of the three on purpose: the whole point of a redraw is that the
picture does not change, so what tmux can judge is that rmux's redraw does not
*damage* it.

**What a paint costs, end to end.** `screen.rs` pinned §9.2's claims against a
`Frame`; `tests/host.rs` now pins them on the wire, through the server, the
socket and the client. A keystroke echoed in a pane costs **one byte** — not
seven, because the console's cursor is already where the character goes (§6.1)
— moving between panes repaints no pane content, and an idle multiplexer writes
nothing at all, which is what having no clock buys. Falsified by forcing
`Screen::draw` to repaint every frame: the first two fail and the third does
not, which is the right shape. The measurement needed two things: a cost is
only exact between two standstills, and the status line carries a style of its
own, so a
frame ending on it leaves the console in that style and the *next* cell in a
pane pays five bytes rather than one. Whether the first keystroke pays that is a
race with the shell's startup, and it failed once in five runs under load before
the test measured from a style it had put the console in itself.

**`aggressive-resize` finally means something**, because there are two clients
to disagree: a window is sized to the smallest client watching it and grows back
when that client detaches, and a window in the background keeps its size. The
second is the half worth having — a resize clips rather than reflows, so columns
taken off a background window are gone — and it is the half that falsifies, with
`aggressive-resize = false` failing on exactly that.

**On the real thing** (§9.4), `tests/vm-console-check.py` boots the image under
qemu on a pty and drives rmux on the Motor console through sys-tty: eleven
checks then and thirteen now, three of which no host test can make — one
keypress is one Enter although
sys-tty sends CRLF (§3.4), a program's `\n` starts a new line although Motor has
no line discipline (§3.1), and **a keystroke costs one byte on the console that
cost is for** (§6.3). It uses `run-qemu-echr.sh`, since `-nographic` keeps
`Ctrl-A` for qemu (§9.4). Two traps, both measured:

1. **Use a release image.** A debug one logs sys-io's every TCP message to this
   same console — and rmux's client and server talk over loopback TCP (§4.2), so
   *using* rmux is what produces the flood. It lands on a composited screen the
   frame diff will never repair, and it buries the byte costs: the keystroke
   above measured 1 byte on release and 1893 on debug. Same shape as §3.5's `^C`
   echo, and not something rmux can defend against.
2. **A port file outlives its server.** The disk survives a reboot, and this
   qemu is killed rather than shut down, so a removal that has not reached the
   disk did not happen. The next client spends five seconds finding out that
   what answered there is not a server before starting one of its own (§13.2) —
   right, and it makes the first `rmux` of a run pay for the last one, so the
   harness clears the rendezvous first.

Not wired into `full-test.sh`, which already boots a VM of its own; rush's
equivalent is standalone for the same reason.

**M10 — The console changes shape. Done.** The gap M3 named and every phase
since walked past: rmux learned its size once and believed it for ever. Reported
from use, and worth writing down as the user saw it, because the second half is
the interesting one — *split a window, make the terminal smaller, and the status
line goes; make it big again and the status line never comes back.*

The first half is a stale size. The second half is the frame diff working
exactly as designed (§6.2): the terminal destroyed rows rmux had painted, rmux
changed nothing, so rmux sent nothing. **A screen the compositor did not damage
is a screen it cannot repair** — which is why `prefix r` exists, and why a
multiplexer that cannot notice a resize is not merely imprecise but stuck.

The fix was one clock in the client (`client::SizeWatch`, since replaced: the
client is told now rather than asking — §3.2), and what it turned on is what was
already built: a `Resize` invalidates the screen,
`fit_session` reshapes the panes, `Layout::refit` scales the borders, and the
pane is told its new size the way §3.2 says. The client is still thin — it
learns nothing about what any of it means.

Three things it had to get right, and each is a test:

- **A size that has not changed says nothing.** Otherwise the answer to "notice
  a resize" is a full repaint once a second, for ever.
- **A held keystroke is given back, and the answer is still listened for.** The
  probe's answer arrives mixed into input, so `SizeProbe` holds anything that
  might be the start of one — and a console with nothing that answers `CPR` is
  allowed (§3.2). Those are two different clocks, and collapsing them into one
  is wrong in both directions: hold a lone `Esc` on its way to `red` until an
  answer comes and it waits for ever, but stop *listening* after the same window
  and a link slower than 200 ms prints `ESC[30;90R` into a pane once a second.
  So what is held is released after the window; what is expected is expected
  until the next asking.
- **The cursor comes back.** `ESC 7`/`ESC 8` around the probe, because this one
  is fired at a screen with something on it.

The host tests drive it through `TIOCSWINSZ` on the pty, `tests/m1.rs` drives
the Motor shape — a console that is a pipe, where the probe is the only channel
there is — and `tests/vm-console-check.py` is now a terminal that changes what
it answers, which is exactly what a dragged window looks like from inside the
guest. Both halves of the report are pinned, the second by asserting the status
line has *left* the row it was on.

What is deliberately not fixed: a window shrunk and restored between two
askings. Nothing changed as far as rmux can tell, and `prefix r` is the answer —
the same answer as for anything else that writes over rmux's console.

**M11 — A pane's stdin belongs to the user. Done.** Reported from use, one day
after M10 made it easy to hit: *split a window, run `top` in it, resize the
console, and top exits.*

M7's unasked answer (§3.2) is what killed it, and M10 turned "after every split"
into "whenever the terminal moves". The rule that replaces it is one sentence —
**rmux writes into a pane only in answer to a question that pane's program
asked** — and it is not a heuristic to be tuned later, which is what every
candidate for keeping the unasked answer was: retire the question at the CR that
starts a command, or at the `ESC[?25l` a full-screen program writes, or after a
timeout. Each guesses who is reading a pipe rmux cannot see an `exec` on, and a
guess that comes out wrong writes an `ESC` into a program that reads it as a
command. Guessing right most of the time is not worth a multiplexer that
occasionally kills what is running in it.

The cost was paid back to rush: one stray `%` on the first prompt after a resize,
which is §3.2's `PROMPT_SP` arithmetic done with a width rush had already asked
for and not yet read. Fixing it there was a rush change and not an rmux one, and
that is where it was fixed — the prompt waits for the answer to its own probe
(§3.2), which is a wait rush can only make because it is the program that asked.

`pane.rs` pins the rule (a pane that asked once, was answered once, and hears
nothing from a later resize) and the VM harness pins the report: a real `top` on
a real pipe goes on painting *after* the console changes size, which is a claim
only about output that arrives afterwards — top repaints once a second, so what
is on screen at any moment would prove nothing.

**The same rule at the other end**, where M10 had left a smaller hole of the same
shape. The client holds a byte that might begin the console's answer and lets it
go after a window, because a lone `Esc` on its way to `red` looks exactly like
one; what it used to let go was the *sequence* as well. An answer split across
that window — `ESC[30` in one read, `;90R` in the next — therefore had its tail
printed in a pane and its size lost, on top of the `ESC` that had to go. So
`SizeProbe::release` now hands the bytes over without forgetting them
(`released`): the pane gets the prefix once, the tail is recognized as the answer
it is, and rmux learns the size. The `ESC` already gone cannot be recalled, which
is the price of never making a user's `Esc` wait on a console that may never
answer.

---

## 11. The risks, and what became of them

Written before M1, ordered by how much they would have hurt. Kept because what
happened to each is the shortest account of where the effort actually went.

1. **The emulator is the long pole.** It is the one component with no prior art
   in this repo (§5) and the one whose bugs are invisible until something draws
   a box. Purity + the tmux oracle was the entire mitigation, and it was
   enough: the corpus of §9.1 compares pictures against real tmux, and the
   emulator is the half of rmux that has never needed a bug hunt.
2. **Orphans may not survive on Motor** (§4.4). They do not — measured in M0,
   which is what the spike was for. It cost a new OS primitive: detached spawn,
   gated by `CAP_SPAWN_DETACHED`. Had it been found in M4, the fix would have
   been the same and the discovery three phases later.
3. **2 KiB pipes and 80-byte console reads** (§4.5, §6.3) make throughput
   structurally tight. The design accounted for it and M9 measured the result:
   a keystroke echoed in a pane costs one byte, on the host and on the Motor
   console both. What was tight was never the pipe.
4. **`history-limit 9999999`** is only survivable with compact history (§7.5),
   built in M8: a line that scrolls off stops being cells and becomes text plus
   style runs.
5. **sys-tty and SSH are two different terminals** (§3.3). Still true, and it
   is why M1 was verified on both and why `tests/vm-console-check.py` (§9.4)
   drives the serial console specifically — the host tests are all the other
   terminal.

---

## 12. The decisions that shaped everything else

Four questions that were open at the start. Each is answered here rather than
in the section it affects, because each of them affects several.

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

---

## 13. Amendment: the terminal layer is crossterm's (2026-07-30)

`crossterm` was ported to Motor OS (`docs/plans/crossterm.md`), and rmux, `rush`
and `red` were moved onto it. Three sections above are now history rather than
description:

- **§4.6 "Dependencies: none"** is one dependency. It replaces more code than it
  adds: a console that delivers one byte at a time (§8.3), an `ESC[6n` where a
  size call should be (§3.2), and an `escape-time` for a lone `Esc` are exactly
  what crossterm's Motor OS backend is for, and rmux was the third program in
  this tree to implement them. `libc` stays, host-only, for the half that is
  genuinely rmux's: a pane's pty (§3.1).
- **§3.2's size probe** has left the client. Nothing here writes `ESC[6n` at its
  console any more, and `SizeProbe` is gone: the size comes from
  `crossterm::terminal::size()` and a change arrives as a resize event among the
  keys — a `SIGWINCH` on the host, and on Motor OS the answer to the probe
  crossterm asks once a second while waiting for input. The discipline the
  section is really about survives unchanged: a size that has not changed is
  never reported, because every `Resize` is a full repaint (§6.2).
- **§8.1 "Forward bytes, do not re-encode"** is reversed: the client decodes a
  keystroke into a [`keys::Key`] and the server encodes it back into the bytes a
  pane's child is given (`keys::Key::encode`). This is the one place the port
  costs something rather than saving it, and the cost is bounded: rmux enables
  neither mouse reporting nor bracketed paste on its own console, so a pane's
  program asking for either is talking to rmux's emulator and never to the
  terminal; function keys are named ([`keys::Code::F`]) and pass through; and
  what is left — the kitty keyboard protocol, and sequences no terminal on this
  platform emits — nothing on Motor OS sends. §8.3's measured encodings are now
  asserted in the *other* direction, as what a pane is handed.

What did not change: the key tables (§8.2), the emulator (§5), the compositor
and its byte-cost claims (§6), and everything in the server. The protocol
carries `Key` where it carried bytes (§4.2), which is the only change visible
between the two halves.

### 13.1 The size the console really is (2026-07-30)

The port shipped a console that did not fill the terminal: rmux opened at 80x24
and stayed there, over the serial console and over `ssh` alike. Two things in
crossterm's Motor OS backend, neither of them visible on the host:

- **A reply had 50ms to arrive**, after which a cursor position report was taken
  to be somebody else's and the probe that asked for it was never answered. A
  serial console hands the eleven bytes of `ESC[41;121R` over one at a time, and
  `ssh` puts a network between the question and the answer; miss that window and
  the size was never learned. Worse, a probe that went unanswered was the *last*
  probe — the backend asked once more and then gave up for the life of the
  program. One late reply at startup meant 80x24 forever.
- **Probes only went out when something was typed.** The backend asks on its way
  into a wait for input, and a wait for input with nothing to report blocks until
  there is some. A window dragged to twice its size while nothing was being typed
  was noticed at the next keystroke and not before, which is not what §3.2's
  clock promised.

Both are fixed where they belong, in the backend: a reply is owed for as long as
the terminal takes to send it, an unanswered probe slows the clock rather than
stopping it, and the wait for input is capped at the next probe. rmux itself got
back the one thing it had lost in the port — the window `client::settle_size`
holds open before the first frame, so the opening screen is painted once, at the
size the console really is, rather than at the fallback and then again.

### 13.2 The port file is a hint, not a promise (2026-07-31)

`rmux new` on a freshly booted VM failed about half the time with *"the rmux
server did not answer; try again"*, and a second run always worked. Reported
from use; reproduced on the VM at 1 in 6 fresh boots, and then made
deterministic, which is where the real shape of it appeared.

**Nothing was wrong with the server.** There was no server. What the client had
connected to was **itself**, and every part of that is ordinary:

- The port file survives a reboot. §9.4 already noted this for the console-check
  harness — a killed qemu never flushes the removal — but a multiplexer is
  rebooted *with a session running* as a matter of course, and then the removal
  never happens at all.
- `sys-io` allocates an ephemeral port by taking the lowest free one from 49152
  (`runtime/net/device.rs`), for a listener and for the local end of an outgoing
  connection alike. So the port a server binds on a fresh boot is 49152, the
  stale file names 49152, and the first client to connect to it is given 49152
  as its *own* port.
- TCP allows a socket to connect to itself. The connect succeeds, the opening
  request is written into the client's own receive buffer, and nothing will ever
  answer it.

Five seconds later the client said so and removed the file, which is why the
second run worked. Being told was M4's fix for a hang (§4.2); it is the wrong
answer to this, because the machine can serve perfectly well and the user is the
one made to try again.

**So the first word decides** (`client::join_server`). A client sends its
opening and gives whatever answered `FIRST_WORD_TIMEOUT` to say something a
server says. Three things mean it is not one, and none of them can be told apart
from the outside: silence, a connection that ends without a word, and a frame
that is not a `ToClient` — which is exactly what a client that reached itself
reads back, since the tag spaces are disjoint (§4.2) and the server is this same
binary. Any of them and that port is forgotten — only if the file still names
it, because by then it may name a server this client just started — and the
attempt is made once more, which with the file gone means starting a server.

Three things fell out of putting it there rather than in `relay`:

- **The opening frame is in hand before the console is painted.** It is what
  proved this was a server, so it is passed on as the first thing `relay`
  handles, along with whatever the read buffered behind it — a half-read frame
  handed to a fresh `Frames` would have its tail taken for a header.
- **`relay` has no clock at all now.** Its first-word deadline was the only one,
  and a loop that cannot time out cannot time out wrongly.
- **A client that fails still gives the console back.** `run` takes the console
  and returns it whatever happens; before, an error returned straight past
  `leave_console`, so the message about the server was printed onto a blank
  alternate screen the shell then inherited.

Measured, all on release images: planting a stale port file made `rmux new` hang
every time before this and open every time after (9 runs); the natural case — a
session running when the VM goes down — failed twice in the first two attempts
before and not once in 22 fresh boots after. The worst case is one
`FIRST_WORD_TIMEOUT` before the session opens, and the host suite holds it
(`a_client_that_reaches_something_other_than_a_server_starts_one`, where a
listener that never speaks stands in for every cause).

**What is not rmux's to fix**, and worth knowing when reading `sys-io`: a
connect that is handed the destination's own port is a self-connection rather
than a refusal. Excluding the destination port from the ephemeral search, or
randomising it as Linux does, would make this particular collision go away for
every program on the machine — but a rendezvous file that names a port can
always name the wrong one, so rmux would still have to ask.
