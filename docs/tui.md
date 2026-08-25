# Terminals in Motor OS

Motor OS has no kernel pty, no termios, no line discipline, and no signals. A
"terminal" is an ordinary userspace program that provides terminal behavior —
ANSI interpretation, interactive input, and the size protocol below — over
plain stdio pipes. Nothing in the kernel knows what a terminal is. The in-tree
providers are:

- **`sys-tty`**, the serial console. It is a byte pump: the terminal a console
  program converses with is whatever is on the far end of the wire, and
  sys-tty has no opinion about its size and takes no part in the protocol.
- **`russhd`**, for SSH sessions in which the client requested a pty. Its size
  comes from the SSH client, in `pty-req` at the start and `window-change`
  afterwards. A session without `pty-req` — plain `ssh host command` — is not a
  terminal, gets no terminal flag, and its bytes pass through untouched.
- **`rmux`**, which emulates a terminal for each pane, sized by the geometry it
  computes for that pane.

Nesting composes with no special cases: rush inside rmux inside ssh, each hop a
terminal to the next, each one both a provider to what it contains and a client
of what contains it.

Programs built on `std::io::IsTerminal`, C `isatty`, or crossterm work
unmodified on top of this: what they observe is a stdio pipe whose far end
behaves like a terminal, and `is_terminal()` tells them whether it does.

## Terminal size

### Why it travels in the byte stream

On Linux the kernel stores a per-tty `winsize`, answers `TIOCGWINSZ`, and
delivers `SIGWINCH` when someone changes it. The kernel discovers nothing; the
program that *owns* the terminal — a desktop emulator, sshd, a getty probing a
serial line once at startup — feeds the size in, and applications only read it
and react to the change.

Motor OS has neither the ioctl nor the signal, but it keeps the useful half of
that split: **discovery happens once, at the component that owns the terminal;
applications get a first size and a change event.** With no signal available,
the carrier for the change event is the byte stream the program is already
reading.

### The protocol: DEC private mode 2048

A program subscribes, and its terminal thereafter writes the size into the
program's own stdin — immediately, and again on every resize:

| Sequence | Direction | Meaning |
| --- | --- | --- |
| `CSI ? 2048 h` | app → terminal | subscribe; answered at once with a report |
| `CSI ? 2048 l` | app → terminal | unsubscribe |
| `CSI ? 2048 $ p` | app → terminal | DECRQM: do you support this? |
| `CSI ? 2048 ; 1 $ y` / `; 2 $ y` | terminal → app | DECRPM: subscribed / not |
| `CSI 48 ; rows ; cols ; h_px ; w_px t` | terminal → app | the report |

Note **rows before columns**, the opposite order from crossterm's
`(cols, rows)`. The wire helpers are in `src/sys/lib/moto-tooling/src/mode2048.rs`.

This is not a Motor invention: mode 2048 is an emerging convention among
terminals that hit the same wall — foot, Ghostty, iTerm2 and kitty implement
it — which is why Motor OS adopted it rather than inventing a private one. The
specification is at
<https://gist.github.com/rockorager/e695fb2924d36b2bcf1fff4a3704bd83>. It is not
universal, hence the fallbacks below. Because it is opt-in, no program that did
not ask ever finds unexpected bytes in its input.

### The first size comes from the environment

A report cannot be early enough for a program's *first* frame. So an owner that
already knows the size — rmux for a pane, russhd for a pty session — puts it in
`$COLUMNS`/`$LINES` when it spawns the child. crossterm's Motor backend answers
`terminal::size()` from those until a report arrives, so a program under rmux or
ssh paints its opening frame at the right size without asking anyone. Only the
physical console lacks this, because nobody there knows the size in advance.

An interactive shell must keep those variables fresh, or every command it
launches after a resize is handed the size the terminal used to be. rush
re-exports them once per command, on bash's `checkwinsize` rule.

### When the terminal cannot push: the fallback ladder

Most host terminals do not implement mode 2048, so a client tries three rungs
in order and uses a lower one only while the one above goes unanswered:

1. **the subscription** — pushed, no polling, no latency;
2. **`CSI 18 t`** — a one-shot question answered `CSI 8 ; rows ; cols t`, which
   moves nothing;
3. **the corner probe** — `ESC7 ESC[9999;9999H ESC[6n ESC8`, which asks where
   the cursor lands in the bottom-right corner.

The corner probe restores the cursor but is *seen* in the corner in between; on
a slow terminal — nested virtualisation, a serial line — that reads as the
cursor jumping away and back on every probe. Hiding it around the query is not
available, because `Hide`/`Show` are stateless commands: nothing in the backend
knows whether the application wants a cursor, and putting one back would turn it
on for a full-screen program that had turned it off. So rung 2 exists purely to
avoid touching the cursor, and rung 3 is only for terminals that ignore window
operations.

Escalation between rungs runs on a 250 ms clock, because nothing paints at the
right size until something answers. Once escalated, polling is on a ten-second
interval — resize is a human-paced event, and a terminal that cannot push should
not be asked once a second — dropping to thirty after three unanswered probes
and resetting instantly on any answer. **A confirmed subscription silences
polling entirely**, which is the point of the whole exercise.

Confirmation is semantic, not merely a reply: DECRPM states 0 and 4 explicitly
mean *unsupported* and keep the ladder running. Only a supported DECRPM state or
a well-formed report silences it, and a malformed report confirms nothing.

### What each provider does

**`sys-tty`: nothing, deliberately.** A console program converses with the host
terminal directly over the wire, exactly as `ESC[6n` always has. Putting a size
in sys-tty would mean inventing one it does not know.

**`russhd`** tracks the subscription per pty session by scanning the child's
stdout *and* stderr for the mode sequences. It **swallows** them and answers
DECRQM itself: it is the terminal here, and a sequence passed through would be
answered a second time by the user's own terminal, with a different size. All
of it — network input, either scanner, and `window-change` — funnels through one
per-session coordinator that owns the child's stdin, so an enable-time size can
never land after a newer resize.

**`rmux`** implements the mode in each pane's emulator, which already parses
everything else for the grid. It answers the enable (every time, including a
repeat), DECRQM, and `CSI 18 t`, and writes a report after any actual pane
resize — a split, a layout change, or the client's own terminal changing shape.

**crossterm's Motor backend** is the client side for every TUI program here. It
negotiates on entering its event loop, re-asserts after a foreground child that
may have disabled the mode, disables on leaving raw mode, turns a valid report
into `Event::Resize`, and prefers the last valid report for `terminal::size()`.
Applications therefore need no Motor-specific code: red, rush, and the rmux
client all just consume `Event::Resize`.

### Rules that keep it honest

- **Geometry is validated, never wrapped or clamped.** Zero SSH dimensions are
  ignored as RFC 4254 requires, and character dimensions outside `u16` are
  ignored with the last valid value kept.
- **Pixel fields are honest or zero.** rmux reports `0;0` — it knows cells, not
  pixels. russhd preserves whatever nonzero pixel geometry the SSH client sent.
- **A provider is the single authority** for the sequences it implements, which
  is why russhd swallows them rather than forwarding.

### Two consequences worth stating plainly

On the physical console nobody knows the size before the program starts, so a
full-screen program paints its first frame at the 80x24 fallback and repaints
when the first report arrives. It never *waits* for one: a console with nothing
on the far end would never answer, and an application that blocked on that would
hang. The first frame is deliberately allowed to be wrong for a moment on the
one terminal where it cannot be right.

And a program killed too abruptly to restore anything leaves the subscription
enabled, exactly as it leaves the alternate screen or the cursor mode enabled.
This is the ordinary terminal limitation, accepted rather than tracked, because
no provider owns the physical console's state.

## What `is_terminal(fd)` means

Terminal status is immutable metadata on the descriptor object, fixed when
the descriptor is created. `is_terminal(fd)` (implemented in the VDSO,
`src/sys/lib/rt.vdso/src/rt_fs.rs`) looks the descriptor up in the process
descriptor table and asks the object. Consequently:

- stdin, stdout, stderr, and the optional terminal stream at fd 3 are
  independent: `program > file` has a
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

Motor reserves fd 3 as `moto_rt::FD_TERMINAL`. It is present exactly when a
process belongs to a terminal session but its stdin is not that terminal. The
stream is read-only in v1: keys and in-band size reports arrive on it, writes
fail, and reads return EOF when the terminal provider goes away. When it is
absent, fd 3 is unallocated and may be reused by the first ordinary open, so a
program must probe it before opening or closing descriptors.

For a command launched by an interactive shell, the resulting per-stream
mask is conventional, with fd 3 carrying terminal input only when stdin
cannot:

| Child setup | stdin | stdout | stderr | fd 3 |
| --- | :---: | :---: | :---: | :---: |
| no redirection | terminal | terminal | terminal | absent |
| `program > file` | terminal | not terminal | terminal | absent |
| `program < file` | not terminal | terminal | terminal | terminal |
| `program 2> file` | terminal | terminal | not terminal | absent |
| first pipeline stage | terminal | not terminal | terminal | absent |
| last pipeline stage | not terminal | terminal | terminal | terminal |
| background command with null stdin | not terminal | terminal | terminal | absent |

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
| a positive descriptor | the passed descriptor's own status |

The last row is a real file handed to the child rather than a pipe; a regular
file answers false, like any other regular file. How that transfer works, and
why inheriting one is a different mechanism from passing one, is
[Stdio redirection](#stdio-redirection) below.

Inheritance therefore propagates terminal status through arbitrary process
trees with no cooperation from the programs involved: a shell started on
the console passes its terminal streams to the commands it runs, and a
pipeline stage whose stdout was captured reports exactly that stream as
non-terminal.

After preparing the three ordinary streams, the spawning VDSO synthesizes fd
3 when the live parent still has terminal input and the child's prepared stdin
is not that terminal. It relays from the parent's fd 3 when present, otherwise
from terminal fd 0, so terminal-unaware intermediaries propagate the session
without a spawn ABI change. Detached children do not receive it. A spawner can
also suppress it with the consumed launch key
`MOTURUS_STDIO_NO_TERMINAL`; rush does this for background jobs because Motor
has no `SIGTTIN` to stop them from stealing input.

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

## Ctrl+C

Ctrl+C is terminal control, not terminal data. Motor still has no signals or
line discipline: the control state lives in the terminal input pipe, and the
VDSO that owns a foreground relay applies it to the appropriate process.

### Default and explicit handling

Every process with terminal input begins in **Default**. A terminal Ctrl+C
terminates a Default process with status 130, including a process that is
spinning, deadlocked, or never reads stdin. All its threads stop and Rust
stacks are not unwound. Raw mode, `event::read()`, and `is_terminal()` do not
change this policy.

A process that wants different behavior registers its one process-lifetime
handler through `moto_rt::process::ctrl_c_register_handler()` and waits for
the monotonic event sequence with `ctrl_c_wait(last)`. Registration resolves
the live terminal fd 0, otherwise terminal fd 3, and a second registration
fails. There is deliberately no unregister or temporary guard.

Applications normally use one of two adapters instead of the low-level API:

- `ctrlc::set_handler` runs an application callback for every sequence
  advance. On a process without terminal input it succeeds dormantly, since
  no event can arrive there.
- `crossterm::event::enable_ctrl_c_events()` explicitly converts callbacks to
  `KeyCode::Char('c')` with `KeyModifiers::CONTROL`. On other platforms it is
  a no-op. On Motor it must be called during TUI setup before the first event
  wait; merely entering raw mode is not an opt-in.

rmux, interactive rush, Gears, and interactive `sysbox less` opt in only when
they are about to own terminal input. An application chooses the Crossterm
adapter or its own callback, not both, because they share the one handler.
Red will install its own handler in its own change and otherwise needs no
special treatment here.

### The sole scan point and batch rule

Only the provider-side `ChildStdio::write` for a terminal-hinted, newly made
stdin scans for byte `0x03`. This is the boundary where sys-tty, russhd, or
rmux writes terminal input to its child. Relays below it carry a control event
in the pipe header and never rescan data. Consequently `0x03` in an ordinary
pipe or file remains an ordinary byte.

For one terminal write containing one or more Ctrl+C bytes:

- each `0x03` is classified once as Default, Handler, or foreground Forward;
- all bytes through the last `0x03` are consumed and discarded, matching the
  input-flush behavior of an interrupt; and
- bytes after the last `0x03` are written normally, with the write reporting
  the consumed prefix plus however much tail was written.

The event is therefore not delayed by a full child ring, and a partial tail
cannot make a caller retry the Ctrl+C. Type-ahead after the interrupt remains
ordered and is returned to the parent if the interrupted child did not read
it.

### Foreground forwarding

While a VDSO input relay owns the terminal source for a foreground child, it
temporarily overrides its process's Handler or Default state and forwards
Ctrl+C to that child. Chains compose: a provider can forward to rmux, rmux to
a pane's rush, and rush to the foreground leaf. A Default leaf exits 130; a
leaf with a handler is notified. The parent is neither killed nor called back.

An internal helper that is not a foreground terminal application must opt out
of synthesized fd 3 with `MOTURUS_STDIO_NO_TERMINAL=true`; otherwise its relay
would temporarily own Ctrl+C. Gears sets this for its piped `curl` transport,
so its handler can cancel a provider request rather than reporting that its
transport exited 130.

Route teardown intentionally has no lock or drain. If Ctrl+C races the target
child finishing, that event may be lost; it cannot reach the parent or a later
child. Each route has a generation, so an event from an old route cannot be
mistaken for one on the next route.

rmux handles bound `C-c` locally, such as in copy mode. An unbound `C-c` is
re-originated as `0x03` into the pane's terminal-hinted stdin, where the pane
boundary performs the normal classification.

### What rush infers

Interactive rush enables the Crossterm adapter for its own prompt. A
terminal-backed non-interactive rush does not register a handler: it stays
Default between foreground routes and forwards while a child owns the
terminal. Background and detached children receive neither terminal fd 3 nor
a foreground route.

After a foreground wait, rush treats status 130 as Ctrl+C: `$?` stays 130, a
pending `trap INT` runs once, and the rest of the pipeline, list, or loop is
abandoned. This intentionally also treats a voluntary `exit(130)` as an
interrupt; Motor does not retain a separate exit-cause field after collection.

Motor has no process groups and no `SIGTTIN`/`SIGTTOU`. Foreground ownership
is the VDSO relay route, not a process-group broadcast, and suppressing fd 3
is what prevents background jobs from stealing terminal input.

## Stdio redirection

Three of the four spawn modes above give the child a pipe or nothing. The
fourth hands it a *file*, and that case is worth its own section: "redirect
stdout to a file" has two implementations on Motor OS, they are not
interchangeable, and which one a program gets is decided by the shell.

### Why a file cannot just be a pipe

A pipe has no identity. Nothing about it says which file, if any, is on the far
end — so a program that needs to know what its stdout *is* cannot find out.

The case that forced this is ripgrep, which refuses to search the file it is
writing: it compares stdout's identity against every path it walks. Give it a
pipe and there is nothing to compare, so `rg alpha . >> results.txt` finds
`alpha` in its own accumulating output and appends it again. Capturing the
child's bytes and writing the file after it exits — the obvious shell
implementation, and the one Motor OS had — cannot fix this, because during the
search the destination is not the child's stdout at all.

### Two transports

| | direct transfer | relay |
| --- | --- | --- |
| what the child gets | a real `rt_fs::File` | a pipe |
| offset authority | the child, independently | the parent's live `File` |
| chosen when | a positive descriptor is passed | a file-backed stream is inherited |
| `get_file_attr(fd)` | the file's own identity | not a file |
| memory | none beyond the descriptor | one bounded ring |

**Direct transfer** snapshots the parent's open description — its
generation-bearing `EntryId`, current offset, access flags, and per-spawn alias
key — into the child's private bootstrap data. The child constructs the
ordinary `rt_fs::File` from it and does its own filesystem I/O: no pipe, no
relay task, no runtime started. Seek, truncate, metadata, and flush all behave
as they do on any other file. Parent and child offsets, and their advisory-lock
owners, are independent from the moment of spawn. This is the route that makes
ripgrep's identity check work.

**Relay** keeps the parent's `File` as the single offset authority and gives
the child a pipe, with the parent's runtime carrying bytes between the two.

### Why inheritance cannot use a snapshot

A snapshot is safe exactly once. A direct child can spawn sequential
grandchildren, and each `STDIO_INHERIT` would snapshot the same unchanged
offset, so every grandchild would start writing where the last one did and
overwrite it. File-backed inheritance is therefore always a relay through the
one live `File`, which advances as bytes reach it.

Descendants of a relayed child see pipes and keep the normal Motor
inherited-stdio dependency on their parent's lifetime. The directly transferred
process still sees a real file.

Terminal-input relays eagerly claim and pump their source. If a child exits
without reading everything already accepted into its ring, relay teardown
returns those unread bytes to the source ahead of newer input. The same reclaim
applies to ordinary inherited stdin, so type-ahead intended for the next
foreground program is not silently lost. A parent reader waiting behind the
claim sleeps on a generation futex and wakes when the relay returns it; it does
not spin for the child's lifetime.

### Which transport a shell picks

`rush` uses the direct route only where the descriptor genuinely belongs to one
command: a fresh redirect to a regular file, on a single external or background
command. Anything that can hand one descriptor to several commands stays on the
pipe-and-pump path, because a shared offset is what the relay exists to
protect.

| Form | stdout | stderr |
| --- | --- | --- |
| `cmd > f`, `cmd > f &` | direct file | unchanged |
| `cmd 1> f 2>&1` | direct file | direct file, same offset |
| `cmd 2>&1 1> f` | direct file | unchanged — the dup ran first |
| `{ ...; } > f`, `for ...; done > f` | pipe (pumped) | unchanged |
| `g() { ...; }; g > f` | pipe (pumped) | unchanged |
| `a \| b > f` | pipe (pumped) | unchanged |
| a builtin's redirect | pipe (pumped) | unchanged |

This is a documented hybrid, not a claim that the forms are otherwise
equivalent: the pumped ones keep their existing non-streaming staging.
`src/tests/full-test.sh` pins each row, using `systest
stdio-file-direct-kind`, which reports what kind each of its own descriptors
actually is and exits nonzero on a mismatch — so the classifier is tested, not
just the bytes that come out of it.

### Rules that keep a shared offset honest

A file's position lives in a mutex, not an atomic, so a position update and the
I/O it belongs to are one indivisible step. (An atomic was not merely slower to
reason about: concurrent writers through one descriptor previously landed on
the same offsets and lost all but one of them.)

- While any relay is registered on an open description, ordinary
  position-dependent operations on it return `E_ALREADY_IN_USE` rather than
  waiting for the child.
- Output relays may overlap each other, by reserving disjoint ranges.
- An input relay excludes every other relay on that description, in the same
  spawn and across spawns — also `E_ALREADY_IN_USE`.
- One description cannot be both a direct transfer and a relay in a single
  spawn: `E_NOT_IMPLEMENTED`.
- An input relay treats the first EOF from the source as final, so file-backed
  stdin is pipe-like and does not follow later growth of the file.

### Waiting, and what exit does

`wait()` and `status()` include the completion of that child's file relays. A
shell therefore cannot start the next sequential command while the previous
one's output is still in flight. There is no artificial timeout: a descendant
cannot hold the immediate pipe open, but a slow filesystem can legitimately
delay a wait, and hiding that behind a deadline would just lose output.

When a parent with live relays exits, it closes the read end *first*, so the
child's next write fails in the child, and only then drains what is already in
the ring. The order matters: retracting the ring first would discard exactly
the bytes the drain exists to save. The guarantee is one-directional and worth
stating precisely — **bytes a child was told went through are never dropped**;
a child racing an exiting parent can lose only writes it had not yet been told
had succeeded.

### What it costs

Measured on a 64 MiB payload, against a ~500 MiB/s plain sequential write:

| | throughput | peak memory |
| --- | --- | --- |
| direct route | 376 MiB/s | +2.3 MiB |
| relay | 524 MiB/s | +2.9 MiB |
| shell pump | 130 MiB/s | +203 MiB |

The memory column is the point of the relay: a pump's peak tracks the payload,
because it holds the output; both file routes are payload-independent. Through
`rush`, a 64 MiB `cmd > f` went from 483.7 ms on the pump to 174.2 ms direct.
The relay's ring is sized in `rt.vdso`'s `stdio.rs`, where the sweep behind the
number is recorded.

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
  sessions and their descendants. It also injects terminal Ctrl+C into
  Default and handler leaves, verifies fd 0 and fd 3 delivery, foreground
  route restoration, no parent callback, retained type-ahead, the Crossterm
  adapter, and a nested rmux → rush → Default-child chain.
- `src/tests/test-terminal-size.sh` validates the size half of the same
  providers, from the application's end: rush and red laid out for the size
  each terminal last reported, and repainted when it changes with no key
  typed, on the serial console, in an SSH pty session, and in an rmux pane —
  including rmux itself as a client, where a console resize travels the whole
  chain to an editor in a pane.

All three run from `src/tests/full-test.sh`.

`src/sys/tests/systest/src/ctrl_c.rs` provides the focused runtime and
terminal-chain probes. Lower-level atomic classification, route generation,
batch scanning, and fixed-status process interruption are covered in their
own moto-ipc, rt.vdso, moto-rt, and kernel tests, all reached transitively by
`full-test.sh`.

Redirection has its own set, also run from `full-test.sh`:

- `src/sys/tests/systest/src/stdio_file_direct.rs` covers the direct route:
  identity shared with the parent, rename after snapshot still addressing the
  same `EntryId`, access-mode failures, seek/truncate/metadata, a fresh
  advisory-lock owner, and stdout/stderr aliases sharing one child offset.
  It also provides `stdio-file-direct-kind`, the helper `full-test.sh` uses to
  pin rush's classifier.
- `src/sys/tests/systest/src/stdio_file_relay.rs` and `stdio_file_input.rs`
  cover the relayed direction, including the exit-flush guarantee above: the
  child records what it was *told* succeeded, and the test asserts the file
  contains at least that.
- `src/sys/tests/systest/src/fs.rs` keeps the position-mutex invariant, with
  concurrent writers through one descriptor required to lose nothing.
- The ripgrep end-to-end regression runs only when `FULL_TEST_RIPGREP_BIN`
  points at a Motor ripgrep build, since ripgrep lives in its own repository;
  without it that one check is skipped and says so.
