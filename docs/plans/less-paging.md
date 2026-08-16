# Paging piped input: the terminal a pipeline stage does not have

2026-08-13; revised 2026-08-16 after a design review that checked every
mechanism below against the code, and finalized the same day when the
review's questions were answered. `sysbox less` pages a *file* on a terminal,
in-band-resizable, on crossterm like red and rmux. What it cannot do is what
`cat file | less` does everywhere else: page text that arrived on stdin. This
doc is why, what it would take, and the decided design. Nothing is
implemented yet; every decision is folded into the text and recorded under
"Decided" at the end.

## What `less` does today

Paging needs two terminals: one to paint on, and one to read keys from. `less`
requires both — `stdin.is_terminal() && stdout.is_terminal()` — and otherwise
writes the text out unchanged, exactly as `cat` would. So `less file` at a
prompt pages, `less file > out` and `cat file | less` do not.

The second terminal is the one a pipeline cannot supply. crossterm's Motor
backend states the platform rule in its own header
(`event/source/motor/event_source.rs` in the fork): *"Motor OS has no
`/dev/tty`: a program's terminal, when it has one, is its own stdin"*. It
registers `moto_rt::FD_STDIN` and nothing else, because there is nothing else
to register.

## The problem

On Linux, `less` reads the data from stdin and opens `/dev/tty` for the
keyboard. The two are separate objects, and the second is reachable by name
from any process in the session. Motor OS has neither: no `/dev/tty`, no
controlling terminal, no session. A program's three streams are all it gets,
and in a pipeline the one that could carry keys is carrying the document.

This is not specific to `less`. Every interactive program behind a pipe has
it: a pager, an editor invoked as `git diff | red -`, a confirmation prompt, a
fuzzy finder. `less` is simply the first program in this tree to want it.

## Evidence (measured 2026-08-13, debug image, russhd pty session)

**A pipeline's last stage has no terminal stdin.** `/sys/tests/systest
stdio-terminal-mask-child` exits with 64 + its stdin/stdout/stderr mask. Run
as `cat p.txt | ...` under a pty it exits 67 — mask `011`: stdout and stderr
are terminals, stdin is not. This is the row docs/tui.md's table already
predicts for "last pipeline stage".

**Its stdin is spent, not merely non-terminal.** A probe that drains stdin and
then keeps reading, run the same way, while keys were typed at the terminal:

```
PROBE stdin_term=false stdout_term=true stderr_term=true data=Ok(0) bytes=6
PROBE post-EOF read starting; type keys now
PROBE post-EOF read 0 -> Ok(0) []
```

Reads return EOF immediately and forever. rush feeds a pipeline stage from a
thread that writes the upstream bytes and drops the sink (`ChildIn::File` in
`src/bin/rush/src/jobs.rs`; the upstream stage's output is captured to a temp
file first, so the stages are sequential).

**No other descriptor can carry keys.** `open_pipe` in
`src/sys/lib/rt.vdso/src/stdio.rs` builds `StdioPipe::new_reader` only for
`StdioKind::Stdin`; stdout and stderr are writers, and `StdioImpl::read`
returns `E_INVALID_ARGUMENT` for a non-reader. There is no path from a
write-only endpoint back to the terminal.

## Why the obvious fixes are not fixes

- **Page anyway, without keys.** One screenful and then a program that cannot
  be told to quit or scroll. Strictly worse than dumping.
- **Read keys from stderr.** Write-only, per the code above.
- **Have `less` re-exec or spawn a helper.** Inheritance copies the parent's
  streams: the child inherits the same spent stdin.
- **Keep the pipe open and let rush relay keys into it after the data.** Then
  `cat foo | wc` never sees EOF and hangs. The shell cannot know which
  children want a keyboard and which want an end of file.

## Options considered, and where they landed

1. **A fourth inherited stream — chosen**, but with the mechanism revised: the
   VDSO synthesizes it at spawn instead of the spawner passing it through
   `SpawnArgsRt`. The revision and its three reasons are the next section.
2. **A `/dev/tty` equivalent served by the provider** (an
   `open_terminal()`-style API with sys-tty, russhd and rmux each serving a
   second connection). Deferred, not rejected: it is the answer for the few
   cases the fourth stream cannot reach (a process acquiring a terminal it was
   not spawned with, and concurrent terminal readers, both discussed under
   "Scope" below). The fourth stream is specified as *a handle to the
   session's terminal object* precisely so that option 2 can later mint fresh
   handles to the same object without re-plumbing anything.
3. **Shell-side spooling.** rush hands the temp file to the child as stdin and
   the terminal rides... nowhere — the child still has one stdin. Rejected.
4. **Do nothing.** Honest, and it is what POSIX `more` does with no terminal —
   but the pipeline idiom every user has in their fingers does not work, and
   no program can fix it for itself. Rejected.

## The design: stdio:3, synthesized by the VDSO

A process can have a fourth stdio stream, called **stdio:3** here and
`terminal` in code (never `tty` — Motor has no `/dev/tty` and should not
advertise one). Its semantics:

- It is a read handle on the session's terminal: keys and in-band size
  reports arrive there. `is_terminal()` on it is true (the existing
  `StdioData::FLAG_TERMINAL` bit, `rt_process.rs:833`).
- **Invariant: stdio:3 is present iff the process has a terminal and its
  stdin is not that terminal.** An interactive `less file` reads keys from
  stdin exactly as today and has no stdio:3; `cat p.txt | less` has a
  non-terminal stdin and reads keys from stdio:3. Consumers therefore need no
  preference logic: use stdio:3 iff it exists.
- **Its descriptor number is fixed at 3**, published as `STDIO_TERMINAL_FD:
  RtFd = 3` in `moto_rt::libc` beside the `*_FILENO` constants — known the
  way 0/1/2 are known, with no query API. Presence is probed with the
  existing `moto_rt::fs::is_terminal(STDIO_TERMINAL_FD)` (`fs.rs:145`). The
  probe is authoritative at process start: fd 3 is then either the terminal
  stream or unallocated. A program that opens files first can find an
  ordinary file at 3 — `is_terminal` correctly answers false for it — so
  programs that care should capture the answer early, as crossterm's event
  source does by construction.
- Writes to it fail with `E_INVALID_ARGUMENT` in v1. The stream is specified
  as the read side of a bidirectional terminal *object*; the write side
  (control queries, painting while stdout is captured — the fzf pattern) is
  reserved for later and must not be given other meaning.
- Reading it returns EOF (`Ok(0)`) when the session's terminal goes away.

### Why the VDSO synthesizes it instead of the spawner passing it

The 2026-08-13 draft had the spawner pass a fourth `RtFd` in `SpawnArgsRt`
over the `_reserved: i32` slot. Checking the code kills that plan three ways:

1. **`_reserved` is not spare in practice.** Every existing binary — including
   every program built with the current Rust toolchain, whose std embeds an
   old moto-rt copy — hardcodes `_reserved: 0`
   (`src/sys/lib/moto-rt/src/process.rs:272`), and `0` is `FD_STDIN`
   (`lib.rs:103`). A VDSO reading the slot as an fd would see every old caller
   passing its stdin as the terminal. Any explicit-passing scheme must define
   0 as "absent", which forbids ever passing fd 0 there. Workable, but the
   next two points make it moot.
2. **rush cannot pass it anyway.** rush spawns through `std::process::Command`
   (`jobs.rs` builds `Stdio::from(..)` / `Stdio::null()`), which goes through
   the *toolchain's* embedded moto-rt. Until a toolchain refresh, no fourth
   fd fits through that path; "rush passes it on every spawn" was not
   implementable without rewriting rush's spawn-and-wait layer off std.
3. **Chain of custody.** With explicit passing, stdio:3 reaches a process only
   if every intermediate ancestor forwarded it; any spawner built against the
   current toolchain, or any third-party code that constructs stdio by hand,
   breaks the chain — a breakage Linux does not have, because the controlling
   terminal is session state in the kernel, not a descriptor. On Motor the
   analogous always-present layer is the VDSO: every spawn on the system goes
   through `proc_spawn` in the *same VDSO build* (the spawner maps its own
   image into the child, `load.rs:21`), so a rule applied there survives
   arbitrary terminal-unaware intermediaries.

So: **no `SpawnArgsRt` change, no `SpawnResult` change, no moto-rt spawn ABI
change at all.** (`SpawnResult` could not grow anyway: the pid took its
reserved slot and the struct is size-asserted at 24 bytes with callers
allocating it, `process.rs:222`.) There is no new cross-boundary surface of
any kind: the child finds the stream at its fixed descriptor number, and the
existing `fs_is_terminal` vtable call answers whether it is there. The only
moto-rt addition is the constant.

### The synthesis rule

In `create_child_stdio` (`stdio.rs:1040`), after the three streams are
prepared, the spawning VDSO computes:

- `parent_terminal` := this process's own stdio:3 (`SelfStdio` in the new
  `SELF_STDIO` slot) if present; else its stdin `SelfStdio` if
  `is_terminal()`; else none. (A file-backed stdin is never a terminal.)
- `child_stdin_is_terminal` := true iff the child's prepared stdin is
  `PreparedStdio::Inherit(src)` with `posix::get_file(src)` a terminal, or
  `PreparedStdio::MakePipe` with the `terminal_hint` env-var flag set (the
  provider case: sys-tty, russhd and rmux creating a session shell's streams,
  `rt_process.rs:643`).

The child gets stdio:3 — a fourth `StdioData` in `ProcessData`, `TAG_PIPE`
with `FLAG_TERMINAL`, fed by a relay from `parent_terminal` — iff:

1. `parent_terminal` exists, and
2. `child_stdin_is_terminal` is false (this is what makes the invariant hold,
   and it is also what prevents two relays from contending for one source
   object within a single spawn — see "Claims" below), and
3. the child is not detached (`MOTOR_OS_DETACHED`), and
4. the spawner did not opt out via a new consumed-at-spawn env var
   (`STDIO_NO_TERMINAL_ENV_KEY`, handled in the same loop as
   `STDIO_IS_TERMINAL_ENV_KEY`, `rt_process.rs:648-668`). rush sets it for
   background (`&`) jobs — decided 2026-08-13: background jobs get no
   terminal stream, because Motor has no SIGTTIN to stop a background reader
   from silently stealing keys. Opting out the top of the background subtree
   suffices: the background child then has neither a terminal stdin nor
   stdio:3, so nothing propagates to its descendants.

Notes on shapes this produces:

- `less file` interactive: stdin is the terminal, no stdio:3, keys on stdin —
  today's behavior, untouched.
- `cat p.txt | less`: stage 1 inherits the terminal stdin (no stdio:3); stage
  2 gets stdin from the temp file and stdio:3 relaying rush's stdin. Stages
  are sequential, so the two relays never coexist.
- `less < file`, `echo hi | wc`, `cmd < /dev/null`: stdio:3 present, read or
  ignored as the program pleases — same reachability as Linux `/dev/tty`.
- `cat p.txt | less > out`: stdio:3 present, but stdout is not a terminal, so
  `less` still dumps. Same as Linux.
- Old binaries: their VDSO (always current) builds the fourth stream, their
  embedded moto-rt never looks at it, and their own first `open()` gets fd 4
  instead of 3. Harmless: at process start fd 3 is either the terminal stream
  or unallocated, and ordinary opens simply start above the occupied slots.

### Lazy arming: the type-ahead trap

The relay stash does **not** recover bytes already written into a child's pipe
that the child never read — `relay_in`'s `overflow` only collects bytes whose
*write* failed (`stdio.rs:393,398,429`). So an eagerly-pumped stdio:3 for a
child that ignores it (`echo hi | wc`, keys typed during `wc`) would move
type-ahead into a pipe that dies with the child: keystrokes that today wait in
rush's stdin for the next prompt would be silently lost. That is a real
regression and rules out eager pumping.

Therefore the stdio:3 relay **arms lazily**:

- At spawn, the relay task starts but takes no claim and moves no bytes. It
  waits on the child-side pipe handle for either child death (exit, freeing
  the task) or an *interest* edge.
- The interest edge is raised by the child-side VDSO the first time the
  program reads or polls its stdio:3 `SelfStdio` (`poll_add` counts — a TUI
  registers before its first read): it sets a new `reader_interest` word in
  the shared `stdio_pipe` header (next to `reader_counter` /
  `reader_closing`, `moto-ipc/src/stdio_pipe.rs:70-98`; both ends are the
  same build, so the header may grow) and wakes the pipe's IPC handle. The
  parent-side task checks the word on every wake — wakes can be spurious on
  Motor, the word is authoritative.
- On interest, the task enters today's claim-and-pump loop (`relay_in`,
  `stdio.rs:344`) against `parent_terminal`, and returns the claim plus any
  overflow stash when the child exits, exactly as stdin relays do.

A program that never touches stdio:3 costs one idle task and zero bytes
moved. A program that reads it (crossterm registering the descriptor counts)
gets the keys. Bytes pumped after arming that the child leaves unread at exit
are lost the same way an interactive child's unread stdin is today — a
pre-existing class, not widened by this design.

Size reports keep working with no provider change: a provider writes reports
into the session's stdin as today (docs/tui.md); they sit there until some
relay holds the claim, and flow to whichever descriptor that relay feeds —
the interactive stage's stdin, or the armed stdio:3 of a pipeline stage. Raw
mode also needs no change: mode requests travel on the output side, which
still merges up to the provider through stdout.

### Claims: how Linux answers the two-claimants question

The 2026-08-13 draft asked how Linux arbitrates when two pipeline stages both
want the terminal. Answer: **it doesn't.** The tty is one shared kernel
object; `/dev/tty` is another handle to it; all readers in the foreground
process group race byte-by-byte for one input queue. In `cat | less` on
Linux, `cat` (reading terminal stdin) and `less` (reading `/dev/tty`) genuinely
race — press `q` and it may go to `cat`. It works by convention: in a working
pipeline at most one program reads the terminal at a time. Job control
(SIGTTIN) gates *background* groups; it is not an exclusivity claim.

Motor's per-object, one-at-a-time, child-lifetime claim
(`stdio.rs:351-374`) is stronger than Linux and correct for rush's sequential
stages; lazy arming means a claim is only ever held by a stage that actually
reads the terminal. Rule 2 of the synthesis predicate guarantees a single
child never has two relays sourcing one object. If concurrently-running
interactive stages ever matter, the Linux-faithful semantics is per-read
arbitration — a pull model that belongs to option 2's served-terminal design,
not to this relay design. Explicitly out of scope here.

### Scope: what this does not cover, and stdin/stdout keep their meaning

With synthesis closing the terminal-unaware-intermediary gap, the cases only
option 2 can serve shrink to: a process acquiring a terminal it was not
spawned with (Linux `/dev/tty` also fails there without a controlling tty),
concurrent terminal readers, and attach/takeover tooling (rmux already owns
that niche). None justifies building option 2 now.

The review also considered the larger redesign — *stdio:3 always present when
there is a terminal, stdin/stdout/stderr never terminals, all terminal
interaction on stdio:3*. Verdict: adopt its direction, reject its premise.
"Events and interaction ride stdio:3 when it exists" is this design, and the
reserved write side lets Motor-native programs grow toward the full model
(the precedent is the Windows console: `CONIN$`/`CONOUT$` are console handles
distinct from stdio, and crossterm's Windows backend already reads events
from the console handle, not stdin — the fork's stdio:3 rule matches a shape
crossterm already has). But "stdin/stdout are never terminals" breaks two
hard things:

1. `is_terminal(stdout)` is the portable ecosystem's universal gate for
   color, progress and prompting; if it is never true, every portable binary
   degrades to its redirected behavior at an interactive prompt. No platform
   ships that — even Windows, which has the separate console object, presents
   stdout as the console when not redirected. `FLAG_TERMINAL` exists exactly
   to keep this contract.
2. Data on stdout and escapes on stdio:3 would be two streams converging on
   one screen with no serialization point; Linux and Windows never face this
   because data and control meet in one kernel object. It would force an
   "alternate screen only" rule — a wart, not a simplification.

So stdio 0/1/2 semantics are frozen as they are; stdio:3 is the compatible
embedding of the terminal-object model.

## Implementation steps

Patch-sized, in order, each with its test. File and function references are
current as of 2026-08-16.

1. **Child-side plumbing, spawner writing nothing yet.** Add `pub terminal:
   StdioData` to `ProcessData` after `stderr` (`rt_process.rs:928`; the page
   is same-build on both sides — see the `FLAG_TERMINAL` comment at
   `rt_process.rs:827` — so no `version` bump). Add `STDIO_TERMINAL_FD:
   RtFd = 3` to `moto_rt::libc` beside the `*_FILENO` constants. Add
   `StdioKind::Terminal`; grow `SELF_STDIO` to 4 slots; in `init()`
   (`stdio.rs:711`), when `pd.terminal` is not `TAG_NULL`, build its
   `SelfStdio` and `posix::push_file` it after stderr, asserting it lands at
   `STDIO_TERMINAL_FD` exactly as 0/1/2 are asserted (`stdio.rs:744`); when
   absent, slot 3 stays free for ordinary opens. Reads before arming block or
   return `E_NOT_READY` per the nonblocking flag like any pipe stream; writes
   return `E_INVALID_ARGUMENT`. No vtable change: the existing
   `fs_is_terminal` entry already answers for any fd. Test: systest asserts
   `moto_rt::fs::is_terminal(STDIO_TERMINAL_FD)` is false everywhere
   (nothing writes `pd.terminal` yet), and the `stdio-terminal-mask-child`
   mask gains a fourth column that reads absent.
2. **moto-ipc interest word.** `reader_interest: AtomicUsize` in the
   `stdio_pipe` shared header beside `reader_counter` (`stdio_pipe.rs:70`),
   with a setter that stores and wakes the IPC handle, and a getter. Both
   endpoints are always the same build; no protocol version exists to bump.
3. **Synthesis and the lazy relay.** In `spawn_impl` (`rt_process.rs`),
   consume `STDIO_NO_TERMINAL_ENV_KEY` in the existing env loop
   (`rt_process.rs:648`) and pass it down. In `create_child_stdio`
   (`stdio.rs:1040`), apply the four-clause rule above; build the pipe pair
   with `make_pair`, write `pd.terminal`, and spawn a `Terminal` relay task
   (a sibling of `InheritedRelayTask` — note `prepare_inherited_relay`
   panics on fds above 2, so construct the task directly) that waits for
   `reader_interest` or child death before entering the `relay_in` claim
   loop against `parent_terminal` (own `Terminal` slot first, else terminal
   stdin). Child-side: first read or `poll_add` of the `Terminal` `SelfStdio`
   sets the interest word. Tests (systest, all under a pty via the existing
   harness): (a) a child with piped stdin and a terminal parent sees stdio:3
   present, terminal, and reads typed keys from it; (b) an interactive child
   (terminal stdin) has no stdio:3; (c) a child spawned with the opt-out var
   has none; (d) a detached child has none; (e) **type-ahead**: keys typed
   while an `echo hi | wc`-shaped job runs are readable by the parent after
   it exits; (f) polling stdio:3, including through `OP_DUP` — the
   per-handle latch bugs lived exactly here (`test_handle_dup` is the
   model); (g) EOF on stdio:3 when the session terminal closes.
4. **rush.** Set the opt-out env var on background (`&`) spawns — it passes
   through `std::process::Command::env`, so no spawn-layer changes. Nothing
   else: foreground synthesis is automatic.
5. **crossterm fork.** In `event/source/motor/event_source.rs`: if
   `moto_rt::fs::is_terminal(libc::STDIO_TERMINAL_FD)` at event-source init,
   register `STDIO_TERMINAL_FD` for events and size-probe replies instead of
   `FD_STDIN`; the invariant guarantees stdin is not a terminal in that
   case, so no preference logic. `is_terminal` for the paint side stays
   stdout. Needs moto-rt 0.17.3 published (current is 0.17.2; the release
   carries only the new constant — `fs::is_terminal` already exists).
   crossterm-smoke covers it.
6. **`less`.** Page iff `stdout.is_terminal() && (stdin.is_terminal() ||
   moto_rt::fs::is_terminal(STDIO_TERMINAL_FD))` — the one condition in
   `do_command`, probed at startup before any files are opened. Flip
   `test_pipeline_shape` in `sysbox_less.rs` from asserting a dump to
   asserting frames.
7. **docs/tui.md.** Add stdio:3 to the model: the descriptor table gains the
   stream, the mask table gains the column, and the "last pipeline stage" row
   stops being the no-keys row.

## Decided

2026-08-13 (draft annotations) and 2026-08-16 (review answers), all folded
into the text above:

- **The VDSO synthesizes stdio:3**; no spawn ABI changes (2026-08-16).
- **Synthesis is default-on** for every non-detached foreground child whose
  stdin is not a terminal; background (`&`) jobs get no terminal stream
  (2026-08-13), via the opt-out env var rush sets (2026-08-16).
- **v1 is read-only**: writes fail with `E_INVALID_ARGUMENT`; the
  bidirectional-terminal-object semantics are reserved for a later series
  (2026-08-16).
- **The descriptor number is fixed at 3** — the `STDIO_TERMINAL_FD` constant
  in `moto_rt::libc`, known the way 0/1/2 are; no query function. Presence
  is probed with the existing `fs::is_terminal`. This supersedes the
  2026-08-13 lean toward allocate-and-report (2026-08-16).
- **The name is `terminal`, never `tty`**: `StdioKind::Terminal`,
  `ProcessData::terminal`, `STDIO_TERMINAL_FD`, `STDIO_NO_TERMINAL_ENV_KEY`
  (2026-08-16).
- **moto-rt 0.17.3** (current is 0.17.2) ships the one new constant; nothing
  else is needed from a publish (2026-08-16).
- **`poll_add` counts as the interest edge** that arms the relay, alongside
  the first read (2026-08-16).
- **Concurrent pipeline stages** are out of scope; the claims section
  records how Linux behaves and where per-read arbitration would live
  (2026-08-13).

No open questions remain; the design is ready to implement.
