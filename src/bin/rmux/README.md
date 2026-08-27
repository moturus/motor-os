# rmux

A terminal multiplexer for Motor OS: one console, many programs, each believing
it owns a terminal. A server owns the programs and does the rendering; a thin
client attaches to it, relays keystrokes and paints what it is sent. Detaching
kills the client and leaves everything else running.

Q: Why another multiplexer?

A: tmux cannot be ported — it is built on one pty per pane, and Motor OS has no
pty, no tty layer, no termios, no ioctl and no signals. It has one console, a
polled 16550 UART owned by `sys-tty`. A multiplexer is what makes that one
console usable, so it had to be written rather than ported. The design is in
`details.md`, which the code cites by section ("§3.1"); this file is the summary.

## Goals

- The `~/.tmux.conf` at the head of this project **is** rmux's compiled-in
  defaults. Every option in it works with no config file present.
- Zero dependencies. Rust `std` only — no crates, not even the in-repo Motor
  ones. The whole Motor-specific surface is one string literal.
- Minimal redraws. The console is a polled UART and bytes are not free: a
  repaint costs the cells that changed and nothing else.
- Both platforms, one source. It builds and runs on Linux, where it is tested
  against real tmux, and on Motor OS, where it is used.
- Correctness measured, not asserted.

## Non-goals

- The mouse; the `#{...}` format language; control mode (`tmux -C`); hooks;
  `if-shell`; layouts by name; pane marking; `link-window`; `choose-tree` (a
  plain session list replaces it); session groups; `run-shell`.
- The host clipboard. OSC 52 is not implemented in either direction; copy and
  paste are rmux-internal.
- Wide characters. rmux decodes UTF-8 and stores a `char` per cell, but treats
  every character as one column wide.
- terminfo. rmux emits a fixed, conservative ANSI vocabulary and assumes the
  same of the programs in its panes.

## How to use

```text
rmux                       attach to the most recent session, or start one
rmux new [-s name]         start a session and attach
rmux attach [-t name]      attach to a named session
rmux ls                    list sessions
rmux kill-session -t name  kill it and everything in it
```

The prefix is `C-a`, as the config says. After it:

| Key | What it does |
| :--- | :--- |
| `c` `n` `p` `0`-`9` `,` `&` | new / next / previous / select / rename / kill a window |
| `\|` `-` | split the pane side by side or one above the other |
| arrows, `o`, `z`, `x` | select a pane, go round them, zoom one, kill one |
| `C-`arrows, `M-`arrows | move the border beside the pane, by one cell or five |
| `(` `)` `$` `s` | previous / next / rename session, and a list to pick from |
| `[` `]` | copy mode, and paste the top buffer |
| `:` | type a command — the same words `rmux.toml` binds |
| `r` | redraw the console from scratch |
| `d` | detach |
| `C-a` | send one literal `C-a` to the pane |

Without the prefix: `S-Left`/`S-Right` change window, and `M-`arrows change
pane. Copy mode is vi by default: `hjklwb0$`, `g`/`G`, `C-u`/`C-d`/`C-f`/`C-b`,
`/` and `?` with `n`/`N`, `Space` to start a selection, `Enter` to take it, `q`
to leave. `mode-keys = "emacs"` swaps in tmux's other table — `C-b`/`C-f`,
`M-b`/`M-f`, `C-Space` and `M-w`, `C-r`/`C-s`.

Overrides go in `/user/cfg/rmux.toml` on Motor OS and `$HOME/.config/rmux.toml`
on Linux. It is the `key = value` subset of TOML plus three binding tables, and
a missing file is not a problem — see `details.md` §2.2, whose example config is
deliberately a no-op restatement of the defaults.

## Status

**A working multiplexer**, used on Motor OS and tested against tmux on Linux.

Conformance is measured, not asserted: `tests/conformance.rs` drives a corpus of
key scripts through **both rmux and tmux** and requires the two to paint the same
picture. What rmux does differently is listed, with reasons, in that file's
`DIVERGENCES` — and each entry is itself tested, so a divergence cannot be
quietly fixed or quietly introduced.

## What works today

- **Panes**: `|` and `-` splits over a binary tree, box-drawing borders,
  geometric pane selection, zoom, and kill. Geometry is a function of the tree
  rather than stored, so a pane's box cannot drift out of step with it.
- **Windows**: new, next, previous, select by number, rename, kill, and
  `renumber-windows`. A window's name follows an explicit `OSC 0`/`2` title or,
  on Linux, the foreground command until a rename takes it over. Rush emits
  those titles for foreground commands in Motor panes.
- **Sessions**: real and multiple, named or auto-numbered, with detach and
  re-attach, `prefix-(`/`)` to move between them and `prefix-s` to pick from a
  list. `aggressive-resize` sizes a window to the smallest client watching it.
- **A terminal emulator** per pane: cursor motion, erases, insert/delete
  line and character, scroll regions, SGR (including the 256-colour palette and
  true colour), the alternate screen, autowrap with deferred wrap, bracketed
  paste, `OSC 0`/`2` titles, and the terminal-size protocol answered with the
  *pane's* geometry — DEC mode 2048, which reports a resize into a subscribed
  pane's stdin, plus `ESC[18t` and `ESC[6n` for a program that did not
  subscribe. This is what lets `red` and `rush` size themselves to a pane.
- **Scrollback and copy mode**: history compacted to text plus style runs, so
  `history-limit 9999999` is a cap rather than a promise of gigabytes; vi
  motions, search, selection, and server-global paste buffers.
- **The status line**: session name, window list, the copy-mode indicator, and
  the prompts — rename, the session list, and `prefix :`, which runs a command
  typed in the same vocabulary a config file binds. It doubles as the message
  line: a config rmux could not read, a split with no room, a needle that is
  not there and a command that does not exist all say so there, until the next
  key takes the row back. It is drawn in near-black on amber — one fixed
  palette, carrying its own background so it reads the same on a dark terminal
  and a light one. The current window takes a deeper amber against the lighter
  bar, and keeps tmux's `*` for a terminal with no colour at all. The lines
  dividing panes are drawn in the same amber, so the chrome reads as one thing.
- **Rendering**: a frame diff over absolute positioning. A keystroke echoed in a
  pane costs one byte, and moving between panes repaints no pane content.
- **Resizing**: `prefix C-`arrow moves a border a cell and `prefix M-`arrow
  moves it five, as tmux's own bindings do, and a window that changes size
  afterwards keeps the shape that was set up. The *console* changing size is
  noticed too, within a second — nothing announces that a terminal window was
  dragged, least of all on Motor, so the client asks on a clock and repaints
  when the answer changes. A window shrunk and restored between two askings is
  the one case that needs `prefix r`.

## Not yet working

- Anything under Non-goals, above.

## Deliberate divergences from tmux

tmux is rmux's reference, and a few things differ on purpose. `prefix &` and
`prefix x` kill outright, where tmux asks first — `confirm-before` is a command
rmux does not have. A mode owns every key, the prefix included, so `q` comes
before the prefix in copy mode. Copy mode's word is a run of non-blanks, its
search is case-sensitive and not incremental, and its indicator borrows the
status row rather than a corner of the pane. The active pane's border is not
highlighted; what says which pane is in front is the cursor. And rmux has no
paste heuristic: a bound key is rmux's however fast it arrived.

## How it works on Motor OS

Motor OS has no pty, and rmux does not need one. `is_terminal()` there is
metadata on the descriptor, set when a provider creates the pipe, so a pane's
child spawned with `MOTURUS_STDIO_IS_TERMINAL=true` is on a terminal as far as
it can tell — which is what `sys-tty` and `russhd` already do. What a pty would
otherwise buy is bought elsewhere: a pane sets `$COLUMNS`/`$LINES`, answers the
size protocol with its own geometry, writes byte `0x03` for an interrupt, and
calls `Child::kill` to kill.

The one thing a pty buys that has no equivalent here is `SIGWINCH`, and the
answer is a subscription rather than a signal: a program sends `ESC[?2048h` and
rmux writes its size into that pane's stdin at once and on every later resize,
until the program withdraws it. That keeps the rule a pane's stdin has always
had — rmux writes into it only to answer a question that pane's program asked —
because the subscription *is* the question, and one that can be taken back.
`docs/tui.md` is the design, which `sys-tty`'s host
terminal and `russhd` implement too, so nesting composes.

The client and server are unrelated processes, so they rendezvous over loopback
TCP: the server binds `127.0.0.1:0` and writes the port to a file. The server is
spawned **detached** — an ordinary orphan on Motor is killed when its parent is
reaped, so detach rests on a spawn flag gated by `CAP_SPAWN_DETACHED`, which is
why rmux is on rush's `spawn-detached` list.

## Testing

| | |
| :--- | :--- |
| unit tests, in-file | the emulator, the layout tree, the key tables, the config, the frame diff and what it costs |
| `tests/host.rs` | rmux on Linux, driven over a pty the way a user drives it |
| `tests/conformance.rs` | the corpus, against real tmux (skipped if tmux is absent) |
| `tests/vm-console-check.py` | rmux on a real Motor OS console under qemu — run it by hand, on a release image |

`cargo test` runs the first three; `src/tests/full-test.sh` runs them and then
drives rmux on the VM over SSH.
