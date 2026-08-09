# Terminals and `is_terminal` in Motor OS

Motor OS has no kernel pty, termios, or line discipline. A "terminal" is a
userspace program that provides terminal behavior — ANSI interpretation,
interactive input, and the terminal-size protocol — over ordinary stdio
pipes. The in-tree terminal providers are:

- `sys-tty`, the serial-console terminal, which is a byte pump: the terminal
  a console program converses with is whatever is on the far end of the wire,
  and sys-tty has no opinion about its size;
- `russhd`, for SSH sessions in which the client requested a pty, whose size
  comes from the SSH client's `pty-req` and `window-change`; and
- `rmux`, which emulates a terminal for each pane, sized by the geometry it
  computes for that pane.

**Size is part of what a provider provides**, and with no `SIGWINCH` to deliver
and no `TIOCGWINSZ` to answer, it travels in band: a program subscribes with
DEC private mode 2048 and its terminal writes the size into its stdin at once
and on every later resize. `$COLUMNS`/`$LINES` carry the first size to a child
an owner spawns, so a program's *first* frame is right without asking anyone,
and a cursor-free `ESC[18t` and the older `ESC[6n` remain as the fallback for
a terminal that does not implement the mode — the physical console in front of
most host terminals. `docs/plans/terminal-size-events.md` is the design and the
reasoning; the providers above are each an implementation of it.

Two consequences worth stating plainly. On the physical console nobody knows
the size before the program starts, so a full-screen program paints its first
frame at the 80x24 fallback and repaints when the terminal's first report
arrives; it never *waits* for one, because a console with nothing on the far
end would never answer. And a program killed too abruptly to restore anything
leaves the subscription enabled, exactly as it leaves the alternate screen or
the cursor mode enabled — the ordinary terminal limitation, accepted rather
than tracked, since no provider owns the physical console's state.

Programs built on `std::io::IsTerminal`, C `isatty`, or crossterm work
unmodified on top of this: what they observe is a stdio pipe whose far end
behaves like a terminal, and `is_terminal()` tells them whether it does.

## What `is_terminal(fd)` means

Terminal status is immutable metadata on the descriptor object, fixed when
the descriptor is created. `is_terminal(fd)` (implemented in the VDSO,
`src/sys/lib/rt.vdso/src/rt_fs.rs`) looks the descriptor up in the process
descriptor table and asks the object. Consequently:

- stdin, stdout, and stderr are independent: `program > file` has a
  terminal stdin and stderr but a non-terminal stdout, exactly as on POSIX
  systems;
- a duplicated descriptor gives the same answer as its source, because
  duplicates share the descriptor object — descriptors above 2 are not
  special;
- invalid descriptors, regular files, sockets, null streams, and ordinary
  pipes answer false; and
- mutating the process environment after startup cannot change any open
  descriptor's answer.

Terminal status belongs to one endpoint of a connection, not to the shared
pipe. The provider's end (the parent-side `ChildStdio` that rmux or russhd
reads and writes) answers false; only the child-side endpoint the provider
created as a terminal (`SelfStdio` with the terminal flag) answers true.

For a command launched by an interactive shell, the resulting per-stream
mask (stdin/stdout/stderr) is the conventional one:

| Child setup | stdin | stdout | stderr |
| --- | :---: | :---: | :---: |
| no redirection | terminal | terminal | terminal |
| `program > file` | terminal | not terminal | terminal |
| `program < file` | not terminal | terminal | terminal |
| `program 2> file` | terminal | terminal | not terminal |
| first pipeline stage | terminal | not terminal | terminal |
| last pipeline stage | not terminal | terminal | terminal |
| background command with null stdin | not terminal | terminal | terminal |

## How the bit is set at spawn

The spawning VDSO derives each of the child's three stream bits
independently from that stream's spawn mode and writes them into the
child's bootstrap data (a flags word beside each stream's pipe data); the
child VDSO reads them when it constructs its stdio objects:

| Spawn mode | Child terminal status |
| --- | --- |
| `STDIO_NULL` | false |
| `STDIO_INHERIT` | copied from the matching parent fd (0, 1, or 2) |
| `STDIO_MAKE_PIPE` | true only with the explicit terminal-launch hint |

(Raw-fd child stdio is not implemented; when it is, the rule is to copy the
passed descriptor's status.)

Inheritance therefore propagates terminal status through arbitrary process
trees with no cooperation from the programs involved: a shell started on
the console passes its terminal streams to the commands it runs, and a
pipeline stage whose stdout was captured reports exactly that stream as
non-terminal.

## The terminal-launch hint

A terminal provider marks the pipes it creates by putting
`MOTURUS_STDIO_IS_TERMINAL=true` in the child's spawn environment. The VDSO
consumes the key during spawn — it is removed from the child's environment
regardless of value and acts only as a launch instruction for
`STDIO_MAKE_PIPE` streams. It is never live process state: reading, setting,
or unsetting it in a running process has no effect on any descriptor. (As a
compatibility guard for older toolchains whose embedded runtime synthesized
the key, the hint is ignored when the child's stdin and stdout are both
inherited — inherited streams always derive from the parent's descriptors.)

Marking a pipe as a terminal is not a capability; the creator is simply
responsible for actually providing the advertised behavior on its end. If a
future provider needs to mark only a subset of newly created streams, the
plan of record is a three-bit native spawn option, not more environment
keys.

## Security properties

`is_terminal()` guarantees descriptor consistency, nothing more. It does
not prove a human is present, identify the peer, or grant authority — a
process creator can always construct an endpoint that claims terminal
behavior, on Motor as on systems with ptys. Programs may use it to decide
whether prompting, colors, or raw-mode editing are practical; code that
authorizes an operation must use an explicit authorization policy.

## Tests

- `src/sys/tests/systest/src/stdio_terminal.rs` covers the invariant
  matrix: mixed redirection masks through `std::process::Command`,
  environment mutation, duplication, the direct-spawn hint, and non-stdio
  descriptors. `systest stdio-terminal-tests` runs just these tests.
- `src/tests/test-tui.sh` validates the real providers end to end: the
  probe (`systest stdio-terminal-report-child`) reports `111` on the serial
  console, in SSH pty sessions, and in rmux panes, and `000` in non-pty SSH
  sessions and their descendants.
- `src/tests/test-terminal-size.sh` validates the size half of the same
  providers, from the application's end: rush and red laid out for the size
  each terminal last reported, and repainted when it changes with no key
  typed, on the serial console, in an SSH pty session, and in an rmux pane —
  including rmux itself as a client, where a console resize travels the whole
  chain to an editor in a pane.

All three run from `src/tests/full-test.sh`.
