# Paging piped input: the terminal a pipeline stage does not have

2026-08-13. `sysbox less` was added the same day and pages a *file* on a
terminal, in band-resizable, on crossterm like red and rmux. What it cannot do
is what `cat file | less` does everywhere else: page text that arrived on
stdin. This is why, what it would take, and what is recommended. Nothing here
is implemented; the platform half needs a decision before it can be.

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

## Options

### 1. A fourth inherited stream: the controlling terminal (recommended)

Give a process a fourth stdio stream whose only job is to be the terminal:
inherited like the others, absent (`STDIO_NULL`-like) when there is no
terminal to inherit. A shell that is itself on a terminal hands it to every
child, including a pipeline stage whose stdin is a pipe.

Most of the machinery exists. Inheriting a stdio *pipe* on Motor OS is already
not a descriptor handoff but a relay: the spawning VDSO creates a pipe for the
child and pumps the parent's stream into it for the child's lifetime
(`relay_in`, `stdio.rs:339`), handing leftover bytes back on exit (the
`stashed` counter). A fourth stream is another `relay_in` on the same parent
object. Terminal status rides along as it does today —
`StdioData::FLAG_TERMINAL` — so `is_terminal()` on the new descriptor answers
correctly with no new concept.

What it costs:

- `ProcessData` (`rt_process.rs:928`) gains a fourth `StdioData`. The bootstrap
  page is written and read by the same VDSO build — the spawner maps its own
  image into the child, which is why `FLAG_TERMINAL` needed no version bump —
  so this is not a cross-version ABI change.
- `SpawnArgsRt` gains a fourth `RtFd`. It has a spare `_reserved: i32` and
  `RtFd` *is* `i32`, so the struct does not change size; the meaning of that
  word does, which is a moto-rt/VDSO agreement and needs the usual vetting
  (AGENTS.md notes 2 and 3), including the copy embedded in the Rust toolchain.
- rush passes it, as it already passes the other three.
- crossterm's Motor backend prefers it over stdin when stdin is not a terminal:
  one registration in `event_source.rs`, and the same descriptor for the size
  probe replies. Everything above that — `Event::Resize`, `terminal::size()` —
  is unchanged, so red, rush and the rmux client get pipeline support for free.

The size protocol keeps working: a provider writes reports into the session's
stdin, the relay forwards them to the child's terminal stream, and crossterm
parses them there.

### 2. A `/dev/tty` equivalent served by the provider

An API — `moto_rt::fs::open_terminal()`, or a reserved path in the VDSO's
`open` — that returns a fresh endpoint to the session's terminal, with sys-tty,
russhd and rmux each serving a second connection.

This is the POSIX-shaped answer and the more general one: any process reaches
the terminal at any time, not only one that was spawned with it. It is also
strictly more work, and it needs the same inheritance question answered first —
a process must be able to *find* its provider, and nothing today tells it. That
inherited pointer is option 1 in a less useful form, which is why option 1 is
recommended as the first step rather than as a competitor.

### 3. Shell-side spooling

rush already has the upstream data in a temp file before the last stage starts.
It could hand that file to the child as stdin (`ChildIn::DirectFile`, which
exists) and leave the terminal on... nothing — the child still has one stdin.
Passing the path in an environment variable instead only works for programs
that know about the variable, which is a per-program contract, not a platform
one. Rejected.

### 4. Do nothing

`cat file | less` writes the text out; `less file` pages. This is where the
tree is today and it is honest: nothing pretends to be interactive when it
cannot be. It is also what POSIX `more` does with no terminal to read from.
The cost is that the pipeline idiom every user has in their fingers does not
work, and no program can fix it for itself.

## Implementation sketch for option 1

Patch-sized steps, each testable:

1. **VDSO plumbing.** Fourth `StdioData` in `ProcessData`, fourth `RtFd` in
   `SpawnArgsRt` (over `_reserved`), the constant in `moto_rt::process`, and
   the child-side `SelfStdio` for it. Descriptor number: the next free one
   above 2, reported to the program by moto-rt rather than assumed. systest
   asserts the mask table gains a fourth column and that the descriptor is
   absent when the parent has no terminal.
2. **Inheritance.** `relay_in` for the new stream, the claim interacting with
   the existing stdin relay exactly as two children do today. systest drives a
   child that reads the terminal stream while its stdin is a pipe.
3. **rush.** Pass it on every spawn. A `--piped` shell has none to pass.
4. **crossterm fork.** Prefer the terminal stream when stdin is not a terminal;
   `is_terminal` for the paint side stays stdout. crossterm-smoke covers it.
5. **`less`.** Page whenever a key source exists — the one condition in
   `do_command` — and systest gains the pipeline-shaped case now asserted to
   dump (`test_pipeline_shape` in `sysbox_less.rs`) flipped to assert frames.

## Open questions for review

- **Two claimants.** `relay_in` documents that only one child may consume the
  parent's stdin at a time. Sequential pipeline stages are fine, but if rush
  ever runs stages concurrently, the first stage's inherited stdin and the last
  stage's terminal stream both want that claim. Does the terminal stream get a
  separate claim, or is one-at-a-time the rule for it too?
- **Background jobs.** A background child gets a null stdin so it cannot steal
  input (POSIX §2.9.3). Does it get a terminal stream? Linux says yes and lets
  `SIGTTIN` sort it out; Motor OS has no signals, so a background program that
  reads it would silently steal keys. Null for background jobs is the safe
  answer.
- **Descriptor number.** Fixed at 3, or allocated and reported? Fixed is
  simpler and matches how 0/1/2 are known; allocated avoids a program assuming
  3 is a terminal when it is an ordinary file it opened.
- **Scope.** Option 1 only helps programs spawned with a terminal. If the
  intent is that any process can reach its terminal, option 2 should be
  designed now and option 1 built as its first half.
