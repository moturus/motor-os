# Paging piped input, and Ctrl+C: terminal input and control through child chains

This plan is implemented. The resulting terminal contract is documented in
`docs/tui.md`.

Before this work, `sysbox less` paged a *file* on a terminal but could not page
text that arrived on stdin, and Motor treated Ctrl+C as an ordinary byte. A
deadlocked, spinning, or non-reading process therefore could not be
interrupted. Both problems sit at the same boundary — passing the session's
terminal through foreground-child chains. The implementation has two parts
that were designed to be independently landable:

- **Part I, stdio:3**, gives a pipeline stage a handle on the session's
  terminal. It needs nothing from Part II; in a Part-I-only world `0x03` keeps
  flowing as a byte and `less` quits on `Ctrl+Char('c')` exactly as it does
  on a terminal stdin.
- **Part II, Ctrl+C**, makes `0x03` from a terminal a control event that
  terminates the foreground leaf unless it explicitly registered a handler.
  A TUI library can use that handler to produce a normal key event; this is not
  a second runtime subscription. Part II is a system-wide behavior change and
  depends on Part I to reach a foreground child whose stdin is redirected or
  piped.

---

# Part I — stdio:3: the terminal a pipeline stage does not have

## What `less` does today

Paging needs two terminals: one to paint on, one to read keys from. `less`
requires both — `stdin.is_terminal() && stdout.is_terminal()`
(`src/sys/tools/sysbox/src/commands/less.rs:69`) — and otherwise writes the
text out unchanged, as `cat` would. So `less file` at a prompt pages; `less
file > out` and `cat file | less` do not.

The second terminal is the one a pipeline cannot supply. crossterm's Motor
backend states the platform rule in its own header
(`event/source/motor/event_source.rs:1-7` in the fork): *"Motor OS has no
`/dev/tty`: a program's terminal, when it has one, is its own stdin"*. It
registers `moto_rt::FD_STDIN` and nothing else, because there is nothing else
to register.

## The problem

On Linux, `less` reads the data from stdin and opens `/dev/tty` for the
keyboard — two objects, the second reachable by name from any process in the
session. Motor has neither: no `/dev/tty`, no controlling terminal, no session.
A program's three streams are all it gets, and in a pipeline the one that
could carry keys is carrying the document. Every interactive program behind a
pipe has this: a pager, `git diff | red -`, a confirmation prompt, a fuzzy
finder. `less` is simply the first program here to want it.

The measured evidence (a pipeline's last stage has a non-terminal, *spent*
stdin; no other descriptor can carry keys) is in Appendix A. The obvious
non-fixes and the rejected options are in Appendix B.

## The design: stdio:3, synthesized by the VDSO

A process can have a fourth stdio stream, called **stdio:3** here and
`terminal` in code (never `tty` — Motor has no `/dev/tty` and should not
advertise one).

- It is a read handle on the session's terminal: keys and in-band size
  reports arrive there. `is_terminal()` on it is true (the existing
  `StdioData::FLAG_TERMINAL` bit, `rt_process.rs:835`).
- **Invariant: stdio:3 is present iff the process was given a terminal and
  its stdin is not that terminal.** An interactive `less file` reads keys from
  stdin as today and has no stdio:3; `cat p.txt | less` has a non-terminal
  stdin and reads keys from stdio:3. Consumers need no preference logic: use
  stdio:3 iff it exists.
- **Its descriptor number is fixed at 3**, published as `FD_TERMINAL: RtFd =
  3` in the `moto_rt` crate root beside `FD_STDIN`/`FD_STDOUT`/`FD_STDERR`
  (`lib.rs:103-107`) — known the way 0/1/2 are, no query API. It must not go
  in the feature-gated `moto_rt::libc` module (`lib.rs:59-60`): crossterm
  depends on plain `moto_rt`. Presence is probed with the existing
  `moto_rt::fs::is_terminal(FD_TERMINAL)` (`fs.rs:145`). The answer is
  reliable for as long as the program has not closed fd 3: descriptor
  allocation is append-or-reuse-most-recently-closed (`posix.rs:299-311`),
  so at start fd 3 is either the terminal stream or unallocated. When the
  terminal occupies 3, ordinary opens land at 4 and above and only a
  `close(3)` lets a later `open()` take 3; when 3 starts unallocated, the
  first ordinary open takes it. Probe before closing it.
- Writes to it fail with `E_INVALID_ARGUMENT` in v1. The stream is the read
  side of a bidirectional terminal *object*; the write side (control queries,
  painting while stdout is captured — the fzf pattern) is reserved and must
  not be given other meaning.
- Reading it returns EOF (`Ok(0)`) when the session's terminal goes away.

### Why the VDSO synthesizes it

Every spawn on the system goes through `proc_spawn` in the *same VDSO build*:
the spawner copies its own in-memory VDSO image into the child
(`load.rs:21,40-46`, called from `rt_process.rs:630`). A rule applied there
survives arbitrary terminal-unaware intermediaries — including every program
built with the current toolchain, whose std embeds moto-rt 0.17.4 from
crates.io and cannot pass a fourth fd (`rust/library/Cargo.lock:177-179`).
So: **no `SpawnArgsRt` change, no `SpawnResult` change, no spawn ABI change.**
The child finds the stream at its fixed number; the existing `fs_is_terminal`
vtable call answers whether it is there. Why explicit passing was rejected is
in Appendix B.

### The synthesis rule

In `create_child_stdio` (`stdio.rs:1040`; it already receives
`terminal_hint`, `:1044`), after the three streams are prepared, the spawning
VDSO computes:

- `parent_terminal` := this process's own stdio:3 if fd 3 is still that
  terminal in the live POSIX fd table; else its stdin only if fd 0 is still a
  terminal `SelfStdio` in that same table; else none. Do not consult the
  retained `SELF_STDIO` slots alone: both `close(3)` and `close(0)` can be
  followed by reuse, and a closed terminal must not be resurrected into a
  child. A file-backed stdin is never a terminal.
- `child_stdin_is_terminal` := true iff the child's prepared stdin
  (`PreparedStdio`, `stdio.rs:764-770`) is `Inherit(src)` with
  `posix::get_file(src)` a terminal (the test `:1172` already uses), or
  `MakePipe` with `terminal_hint` set (the provider case: sys-tty, russhd and
  rmux creating a session shell's streams). `Null`, `File` (a sole-use
  `< file` redirect, `rush/src/jobs.rs:166`), `Relay` (a shared file source),
  and `MakePipe` without the hint (a pipeline stage, `jobs.rs:165-190`) are
  false.

The child gets stdio:3 — a fourth `StdioData` in `ProcessData`, `TAG_PIPE`
with `FLAG_TERMINAL`, fed by a relay from `parent_terminal` — iff:

1. `parent_terminal` exists, and
2. `child_stdin_is_terminal` is false (this keeps the invariant, and it is
   what prevents one spawn from creating two relays on one source object),
   and
3. the child is not detached (`MOTOR_OS_DETACHED_ENV_KEY`,
   `moto-sys/src/caps.rs:101`).
   Today `detached` is parsed at `rt_process.rs:665-669` and used only for the
   process URL (`:680-682`); it must be plumbed into `create_child_stdio`.
   (rush never sets it; `stdio_file_input.rs:251` is the only in-tree user.)
4. the spawner did not opt out via a new consumed-at-spawn env var
   (`STDIO_NO_TERMINAL_ENV_KEY`, handled in the same loop as
   `STDIO_IS_TERMINAL_ENV_KEY`, `rt_process.rs:655-676`). rush sets it for
   background (`&`) jobs: they get no terminal stream because Motor has no
   SIGTTIN to stop a background reader from
   silently stealing keys. Opting out the top of the background subtree
   suffices: that child has neither a terminal stdin nor stdio:3, so nothing
   propagates to its descendants.

Shapes this produces:

- `less file` interactive: stdin is the terminal, no stdio:3 — untouched.
- `cat p.txt | less`: stage 1 inherits the terminal stdin (no stdio:3);
  stage 2's stdin is a `Stdio::piped()` fed by a rush thread that writes the
  captured bytes and drops the sink (`jobs.rs:149-153,185-190`), and it gets
  stdio:3 relaying rush's stdin. Stages are sequential — `run_pipeline` is a
  `for` loop (`rush/src/exec.rs:1357-1428`) — so the two relays never coexist.
- `less < file`, `echo hi | wc`, `cmd < /dev/null`: stdio:3 present, read or
  ignored as the program pleases — the reachability of Linux `/dev/tty`.
- `cat p.txt | less > out`: stdio:3 present, stdout not a terminal, `less`
  dumps. Same as Linux.
- Old binaries: their VDSO (always current) builds the stream, their embedded
  moto-rt never looks at it, and their first `open()` gets fd 4. Nothing in
  the tree assumes the first open returns 3.

### The relay: eager, with ring reclaim

The stdio:3 relay is a stdin relay pointed at a different descriptor. It is a
task on the per-process relay runtime (`stdio_relay.rs:1-5`: at most one
thread per process, created on demand, gone with the last task), it takes the
source's claim at spawn (`relay_in`, `stdio.rs:344`; claim loop `:356-374`),
pumps bytes non-blockingly in both directions, and joins the child's
completion group so the parent's `wait()` returns only after it has finished
(`rt_process.rs:83` → `stdio_relay::wait_for_child`).

One addition makes eager pumping safe for a child that never reads the stream
(`echo hi | wc`, keys typed during `wc`). Today the overflow stash collects
only bytes whose *write* failed (`:393,398`); bytes already in the child's ring
when it dies are lost, which for stdio:3 would turn type-ahead into silent
loss. But the writer keeps the ring mapped after the reader dies (the frames
are refcounted, `mm/virt_intrusive.rs:590`; the mapping goes only in
`PipeBuffer::drop`, `stdio_pipe.rs:22-27`), and `unwrite()` already rewinds
the unread span `[reader_counter, writer_counter)` on exactly that premise
(`stdio_pipe.rs:202-215`, used at `:446,682,703`). Add
`take_unread() -> Result<Vec<u8>, ErrorCode>` beside it; at child death the
relay reclaims the unread span into `overflow`, which `StdioImpl::read` drains
ahead of the pipe (`stdio.rs:81-93`) and `SelfStdio::readable()` counts
(`:200-206`). Type-ahead therefore returns to the parent's stream exactly as
failed-write overflow does today — and the same reclaim fixes the pre-existing
loss of an interactive child's unread stdin for free.

Reclaim has two ordering requirements. First, a claimed relay must drain the
source `StdioImpl::overflow` before reading its pipe; call through the claimed
`StdioImpl` rather than reading `owned.pipe` directly as `relay_in` does today
(`stdio.rs:378`). Otherwise bytes recovered from one child can be stranded
when the next child takes the claim. Second, on destination death, unread
bytes already accepted into the destination ring precede the relay's current
unwritten chunk, which in turn precedes any source overflow that the same read
did not drain. On destination death, rebuild source overflow as
`destination.take_unread() + unwritten_chunk + remaining_source_overflow`, in
that order; do not merely append to the existing vector. `take_unread` rejects
`writer_counter < reader_counter` or a difference larger than the ring before
copying. On rejection the relay returns only its already-owned safe bytes and
reports the corrupt peer; it never indexes outside the mapping. A small relay
state machine should make these ordering rules explicit rather than relying on
error-path append order.

Eager relaying widens a pre-existing spin. While a relay holds the claim, a
parent thread reading its own stdin spins in `SelfStdio::with_impl` until the
slot is returned (`stdio.rs:182-197`). Today a relay holds that claim for an
inherited-stdin child, so any concurrent parent reader already spins; Part I
extends the same behavior to piped and redirected children. Fix it with a
`claim_generation` futex word per stdio slot (the VDSO already has futexes:
`rt_futex.rs`, used internally at `stdio_relay.rs:80,144,169`): a reader
snapshots the generation, tries to take the slot, and waits on the sampled
value if the slot is absent; a racing return
changes the value, so the futex cannot miss the edge. Every claim return
increments the generation after restoring the slot and wakes the waiters. The
relay's asynchronous claim acquisition can use the same edge or retain its
existing nonblocking task scheduling. This is a separable patch, but it must
land before synthesis activation: Part I newly holds the terminal claim for
redirected and piped children, where a parent continuing to read its own
terminal is plausible, and must not turn that reader into a child-lifetime CPU
spin.

One consequence remains:

- Bytes a *live* child leaves unread are in its ring, not the parent's; they
  come back only when the child exits. Same as today for inherited stdin.

Size reports need no provider change: a provider writes reports into the
session's stdin as today (`docs/tui.md:43-66`); they flow to whichever
descriptor the claiming relay feeds — the interactive stage's stdin, or the
stdio:3 of a pipeline stage. Part I requires no raw-mode change: on Motor it is
bookkeeping only ("consoles are always raw", crossterm fork
`terminal/sys/motor.rs:3-7,82-89`), and the mode-2048 requests it toggles
travel on the output side (`docs/tui.md:114-129`); no relay parses escapes.

### Claims

Motor's per-object, one-at-a-time, child-lifetime claim is stronger than
Linux, where all foreground readers race byte-by-byte for one tty queue (see
Appendix B). It is correct for rush's sequential stages, and robust beyond
them: if stages ever ran concurrently, the second relay would wait in the
claim loop rather than race — a deterministic version of what Linux leaves to
chance. Per-read arbitration for concurrently interactive stages belongs to
the served-terminal design (Appendix B, option 2) and is out of scope.

### Scope

stdio 0/1/2 semantics are frozen: `is_terminal(stdout)` stays the portable
ecosystem's gate for color and prompting, and data and control keep meeting in
one stream. stdio:3 is the compatible embedding of a terminal-object model
(the Windows `CONIN$` precedent; crossterm's Windows backend already reads
events from a console handle distinct from stdio). What only a served
`/dev/tty` equivalent could add — acquiring a terminal one was not spawned
with, concurrent terminal readers, attach/takeover — does not justify building
it now.

## Part I implementation steps

1. **Child-side plumbing, spawner still writing null.** Add `pub terminal:
   StdioData` after `stderr` in `ProcessData` (no version bump: both ends are
   one VDSO build, as `StdioData`'s own comment at `rt_process.rs:832-834`
   notes). Add `FD_TERMINAL: RtFd = 3` at the `moto_rt` crate root. Add
   `StdioKind::Terminal`, grow `SELF_STDIO` (`stdio.rs:39`) to four slots, and
   **add a non-panicking accessor**: `StdioKind::get()` unwraps its slot
   (`:26-34`), and for most processes the fourth slot is `None`. In
   `stdio::init` (`:711-747`) place the terminal stream at fd 3 when
   `pd.terminal` is non-null, asserting the number as for 0/1/2 (`:744`).
   Tests: absence, first-open allocation of fd 3, `is_terminal(3)`.

2. **Ring primitive and source order.** Add `StdioPipe::take_unread()` beside
   `unwrite()` with counter validation, and make the claimed relay drain source
   overflow before its pipe. Tests: a partially-read ring returns only its
   unread tail; corrupt indices return an error without an out-of-bounds read;
   reclaimed bytes flow through the next child before newer pipe bytes.

3. **Relay reclaim.** At child death rebuild overflow from the destination's
   unread ring, the locally held unwritten chunk, and any remaining source
   overflow. This benefits inherited-stdin relays immediately. Tests:
   type-ahead into a child that never reads returns to the parent; ring bytes
   precede a partially written local chunk, which precedes remaining source
   overflow.

4. **Blocking claims.** Add the `claim_generation` waiter so a parent reader
   sleeps rather than spins behind a relay. This is a separate patch from ring
   reclaim but a prerequisite for synthesis activation. Test: a reader waiting
   behind a claim sleeps and wakes on return without a missed edge.

5. **Synthesis plumbing, still dormant.** Define and consume
   `STDIO_NO_TERMINAL_ENV_KEY`, plumb `detached` into `create_child_stdio`, and
   implement the four-clause decision as a tested helper. Continue writing a
   null `pd.terminal` and starting no terminal relay in this patch. Tests cover
   every `PreparedStdio` shape, detached/opt-out, and live fd 0/3 checks.

6. **rush.** Set `STDIO_NO_TERMINAL_ENV_KEY` in `spawn_background`
   (`exec.rs:502-527`). Note the coverage: only a lone simple external command
   is spawned in the background (`lone_simple`, `:234-244`); pipelines,
   compounds and builtins with `&` run in-process and never spawn. `cmd < f &`
   keeps a `DirectFile` stdin rather than the null one `FdSource::Inherit`
   gets (`:1200`), so it is a stdio:3 candidate and needs the opt-out too.

7. **Synthesis activation.** Write `pd.terminal` when the tested predicate is
   true; generalize `prepare_inherited_relay` (`stdio.rs:308-322`, which panics
   on any fd outside 0..2) so a `Terminal` relay task from either source
   descriptor joins the same completion group. Tests: every shape above, EOF
   on provider exit, `close(0)`/`close(3)` followed by descriptor reuse and
   spawn (no resurrection), and relay teardown ordering against `wait()`. This
   activation lands only after blocking claims and rush's background opt-out
   are present.

8. **moto-rt release and crossterm fork.** The in-tree moto-rt is 0.17.4
   (`moto-rt/Cargo.toml:9`); publish 0.17.5 with `FD_TERMINAL`. In the fork
   (locked at `bacb8c9703743dece42ccbe3fac96cbe50a6fa7c` in all six lockfiles,
   workspace patch `src/sys/Cargo.toml:59`), choose `FD_TERMINAL` at
   event-source construction when it is a terminal, else `FD_STDIN`; store it
   and use it in both `poll::add` (`event_source.rs:85`) and `fs::read`
   (`:144`). The stdout-gated resize start (`:102`) stays as is; size-probe
   replies read the selected input. Update standalone rmux/red/rush/gears
   locks and the workspace patch.

9. **`less`.** Page iff `stdout.is_terminal() && (stdin.is_terminal() ||
   moto_rt::fs::is_terminal(FD_TERMINAL))`, probed before any open. Keep the
   "missing filename" error for a terminal stdin with no argument
   (`less.rs:53-58`); with stdio:3 and no argument, the document is stdin.
   Dump mode unchanged when stdout is redirected.

10. **Terminal-backed integration coverage.** `sysbox_less::test_pipeline_shape`
   (`systest/src/sysbox_less.rs:81-98`) runs under the non-PTY systest parent
   with a real file as stdin; it cannot synthesize fd 3 and stays a dump-shape
   test. Add paging-shape coverage on the provider-backed harness already in
   that file (`:160-250`): `less file`, `cat file | less`, `less < file`,
   redirected stdout, navigation, resize, and type-ahead retained across an
   uninterested child. Everything must run from `src/tests/full-test.sh`
   (`AGENTS.md:22`; systest is shipped at `full-test.sh:330` and run at
   `:415-424`).

11. **Documentation.** `docs/tui.md`: add fd 3 to the `is_terminal` contract
   section (`:161-183`) and the terminal-mask table (`:187-195`); describe
   synthesis, the opt-out, and ring reclaim. Also fix the stale comment at
   `systest/src/stdio_terminal.rs:132-133` (`SelfStdio::close` is implemented,
   `stdio.rs:275-278`).

---

# Part II — Ctrl+C: terminal control, not a byte

## The problem

All three providers forward `0x03` as a plain byte into the session shell's
stdin: sys-tty copies serial bytes straight through (`sys-tty/src/main.rs:
129-152`), russhd passes client input verbatim (`russhd/src/local_session.rs:
111,250`), rmux encodes `C-c` as `0x03` into the pane (`rmux/src/keys.rs:212,
289-297`). rush acts on it only in its line editor (`rush/src/term.rs:843-858`
→ `note_signal(SIGINT)`, `$?` = 130, `trap INT`); while a foreground child
runs, rush sits in `child.wait()` (`exec.rs:1159-1170`) and the byte lands in
the child's stdin relay. A child that is deadlocked, spinning, or not reading
stdin cannot be interrupted — the only tool is `kill-pane` or `kill_pid`.
Seven programs compensate with a stdin-listener thread that exits on `0x03`
or EOF: httpd (`main.rs:26-43`), httpd-axum (`:30-47`), rnetbench
(`:114-131`), russhd (`:27-48`), systest (`:936-950`), mio-test (`:17-40`),
and tokio-tests (`:11-57`). They exit 0 or 1, not 130. sysbox also contains an
unused copy of the helper (`main.rs:38-59`).

## The design

### One handler and forwarding

Every process with terminal input starts with no Ctrl+C handler. Normally the
provider's `0x03` scan point selects one of these actions:

- **Default** — terminate the process with status 130. This includes old
  binaries, programs that never read stdin, and TUIs that did not explicitly
  enable Ctrl+C handling.
- **Handler** — wake the process's sole `ctrl_c_wait` listener. A conventional
  application runs its callback there; a TUI adapter turns the notification
  into a key event there.
- **Forward override** — while the process's VDSO owns a foreground terminal
  relay, forward the event to that child instead of notifying or terminating
  the parent.

There is no input subscription and no synthetic byte in stdin. Forward is a
temporary VDSO-owned override, not a public registration mode. With no handler
and no forward override, Default always applies. The one exception to delivery
is an event that races forward-route teardown: it may be dropped rather
than applied to the finishing child, its parent, or a later child.

The complete public low-level API, appended to the VDSO vtable and exposed
from `moto_rt::process`, is:

- `ctrl_c_register_handler() -> Result<u64, ErrorCode>` — register the one
  process-lifetime handler and return the current event sequence as its
  baseline. A second registration fails.
- `ctrl_c_wait(last: u64) -> Result<u64, ErrorCode>` — wait until the monotonic
  handler sequence exceeds `last`, then return the new value. Thus an event
  after registration is latched even if the listener has not blocked yet. If
  the sequence advances by more than one, an adapter invokes its callback once
  for each advance rather than silently coalescing events.

`ctrl_c_register_handler` resolves the same unique live terminal input used by
Part I (terminal fd 0, otherwise terminal fd 3) and fails if neither is still
present in the POSIX fd table; `ctrl_c_wait` uses the registration.
Registration is one-way in v1: there is no unregister, reference count, guard,
final drain, or handler/input interaction to specify. Being one-way, it also
retains an `Arc` to the resolved terminal `StdioPipe` for the life of the
process. This uses the existing mapping — `SELF_STDIO` already retains its
`Arc<SelfStdio>` after descriptor close (`stdio.rs:37-39,275-278`) — rather
than creating a second mapping. The explicit registered `Arc` also means
`ctrl_c_wait` cannot follow a reused fd 0/3. The handler simply outlives the
closed descriptor. When the writer endpoint itself is gone, `ctrl_c_wait`
returns the normal closed-peer error, the listener thread exits, and the
callback never fires again — no event can arrive without a writer.

The moturus `rust-ctrlc` fork is currently only a rustc-build stub
(`rust/Cargo.lock:1010,3914`; `docs/build-rustc.md:702`), but it should gain a
Motor backend over `ctrl_c_register_handler`/`ctrl_c_wait`. It starts the
listener thread first; that thread registers, reports the result to
`set_handler`, and then waits from the returned baseline. Therefore a thread
creation or setup failure leaves the process in Default rather than publishing
a handler with no listener. One mapping is deliberate: when registration fails
because the process has no terminal input — a background (`&`) job, a detached
child — the backend returns `Ok` with a dormant handler instead of an error.
No event can ever arrive there, the near-universal
`ctrlc::set_handler(...).expect(...)` idiom must not turn `httpd &` into a
panic, and Linux's `set_handler` does not fail for lack of a terminal either.
Errors are reserved for real failures: thread creation, double registration.
This supplies the conventional
`ctrlc::set_handler` callback API to applications that choose the dependency;
Motor programs do not all need to depend on it. Put the real backend on a new
immutable tag or pin its exact revision in a new dependency line; do not move
the `motor-os-rustc` branch. Rustc links that branch today, and a backend that
calls new vtable entries would make a fresh rustc build require a VDSO that has
them before that dependency is intentionally advanced.

Raw terminal mode and ordinary event reading are deliberately unrelated.
Neither counts as handling Ctrl+C or suppresses Default. This is stricter than
Unix `ISIG`, but implements Motor's contract: Ctrl+C kills a process unless
that process explicitly handles it.

### TUI adapter: handler to key event

The Motor crossterm fork is the reusable TUI adapter; individual applications
must not build a second stdin reader or poll on a timer. Add an explicit,
process-lifetime `crossterm::event::enable_ctrl_c_events()` call. On Motor it
uses `ctrlc::set_handler` and converts every callback into
`Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))`. On
other targets the call is a no-op because their existing terminal backends
already produce the key event. Merely entering raw mode or calling
`event::read()` does not enable it. Call it during TUI setup, before the first
`event::read()` or `EventStream`, so initialization never contends with the
single global reader while it is blocked.

The current Motor event source already provides the needed fan-in
(`event/source/motor/event_source.rs`, fork revision `bacb8c970374...`): one
global event reader blocks in a poll registry, and its `event-stream` support
adds a Motor `Waker` implemented by a second empty registry — no pipe and no
extra thread. Make that waker unconditional on Motor and always register its
token. The handler increments a pending-event atomic with `SeqCst` and wakes
the source; the event reader also consumes that atomic with `SeqCst`.
`try_read` consumes one pending count and returns the synthetic key **only
when it receives that wake token**; it never consumes pending Ctrl+C at the
top of its loop. `poll::wake` queues exactly one event per wake whether or not
anything is waiting (fork `event/sys/motor.rs:34-42`), so the callback's
ordered pair — increment the count, then wake — remains one pending count plus
one queued wake until the source consumes them together. A wake before a wait
and a burst of Ctrl+C events are therefore not lost and cannot leave stale
wakes. On a wake token, decrement a nonzero pending count and return the key;
with a zero count, retain the existing `Interrupted` result for `EventStream`
shutdown (`event_source.rs:244-250`). The source needs no new shutdown flag.
The event reader and its waker are process-global and live until exit,
matching the one-way handler.

This adds no TUI policy to the VDSO. It also keeps opt-in explicit: rush, rmux,
gears, and the interactive paging path of `sysbox less` call
`enable_ctrl_c_events()` because each already has a tested `C-c` action. An
application chooses either this adapter or its own
`ctrlc::set_handler`; both are deliberately backed by the same single process
handler. Once it opts in, it owns Ctrl+C for the rest of the process lifetime;
there is no runtime timeout, second-press escalation, or watchdog.

### Where a `0x03` is recognized: exactly one place

Terminal input enters a chain at a provider's write into the `ChildStdio`
created for a terminal-hinted `MakePipe` stdin (`stdio.rs:1184-1202`; the hint
marks the child's `StdioData` while the parent side deliberately stays
non-terminal, `:1189-1190`; `write` at `:1310`). That write — and only that
write — scans for `0x03`. Below it, Ctrl+C travels as an *event*, never as a
byte, so no relay scans data and binary `0x03` in non-terminal pipes is
untouched. rmux re-originates: its client explicitly enables crossterm's
Ctrl+C adapter, handles `C-c` where bound (copy mode,
`bindings.rs:508`), and otherwise writes `0x03` into the pane's terminal-hinted
pipe, where the scan happens again for the pane's shell.

The scanning writer is marked by a separate *interrupt-scanning* bit on
`ChildStdio`, not by the terminal flag: the provider's end must keep answering
`is_terminal() == false` (`docs/tui.md:161-183`).

**Batch rule.** A write whose buffer contains `0x03`: every `0x03` starts one
classification (subject only to the route-teardown loss above); bytes
*before the last* `0x03` are discarded (Linux ISIG input flush); bytes after
it are written with the call's ordinary blocking or nonblocking semantics;
the return value is `(index of last 0x03) + 1 + tail_written`. A partial or
`E_NOT_READY` tail therefore never causes a caller to retry a `0x03`, and a
full ring cannot delay the event. Writes with no `0x03` keep today's semantics
unchanged.

The discard is deliberately unconditional: it applies under Handler and
Forward classification too, where raw-mode Linux (no `ISIG`) would deliver
every byte. The alternative — discarding only on Default — would have to
write the preceding bytes and then raise the event, and the event travels out
of band: an adapter checking its pending count before draining stdin would see
the `^C` *before* the keys typed ahead of it. Reordered input is worse than
flushed input, and under Motor's contract that a terminal `0x03` is never
data, "an interrupt flushes the type-ahead written with it" is the coherent
reading.

### The mechanism: one atomic state and one handler sequence

No new IPC pair, bootstrap payload, cacheline, or inter-process lock is needed.
The shared `stdio_pipe` header (byte offsets at `stdio_pipe.rs:30-38`,
accessors `:61-118`; a `version` slot exists and is zero) has three unused
`u64` words at offsets 40, 48, and 56 before the existing `DATA_OFFSET` of 128.
Use two of them on the pipe that is the process's terminal input (terminal
stdin, else stdio:3 — by the Part I invariant never both):

- `ctrl_c_state: AtomicU64`, packing `HANDLER`, `FORWARD`, a route generation,
  and that route's forward-event count;
- `ctrl_c_handler_raised: AtomicU64`.

The two flags use two bits; split the remaining 62 bits evenly between route
generation and event count. Exhausting either 31-bit field requires over a
billion foreground-route transitions or Ctrl+C events in one route and cannot
happen in normal use. Use checked increments and panic with
`"Ctrl+C route generation exhausted"` or
`"Ctrl+C forward-event count exhausted"` rather than wrap to an old state.
Do not add an artificial saturation test. Add compile-time layout and mask
assertions. The third unused header word remains unused.

Handler registration reads `ctrl_c_handler_raised` as its baseline and then
atomically sets `HANDLER`; the baseline-before-publication order means an event
is either Default before registration or visible above the baseline after it.
A second registration sees the already-set bit and fails. `HANDLER` remains
set while `FORWARD` temporarily overrides it.

After taking the terminal data claim, a relay installs a route with one atomic
compare-and-exchange: increment the route generation, reset the event count,
set `FORWARD`, and preserve `HANDLER`. A generation therefore identifies one
route incarnation. The relay records the new generation and a zero last-seen
count. For each scanned `0x03`, the writer:

1. loads `ctrl_c_state`;
2. if `FORWARD` is clear, selects Handler or Default from that snapshot;
3. if `FORWARD` is set, compare-and-exchanges the same generation and flags
   with the event count incremented, then wakes the relay.

If the forward CAS loses only to a concurrent count increment or one-way
`HANDLER` publication while the same generation remains active, it may retry.
If the generation changed or `FORWARD` was cleared, the event raced a route
boundary and is deliberately dropped. Thus the classifier never waits for a
child-controlled lock. Handler-sequence increments, wakes, and Default
interrupts happen after the state snapshot/CAS; a base-state snapshot is the
event's before-or-after point relative to handler or route publication.

Use `SeqCst` for every operation on `ctrl_c_state` and
`ctrl_c_handler_raised`. Ctrl+C and route transitions are rare, so weaker
orderings buy nothing useful here; the single ordering makes publication,
counter-before-wake, and teardown arguments direct. The writer increments the
handler sequence only after observing `HANDLER`, which is set only after the
registration baseline is read, so every post-registration increment lands
above that baseline. No lock or explicit fence is needed.

On the reading side:

- `ctrl_c_wait(last)` duplicates the pipe handle, rechecks the sequence
  through the mapping pinned at registration, and returns when
  `handler_raised > last`. A wake is broadcast to every duplicated handle, and
  each has its own missed-wake latch (broadcast loop at
  `kernel/src/uspace/sysobject.rs:297-320`, per-handle recording in
  `wake_by_object`, `process.rs:1948`; `systest::test_handle_dup`,
  `systest/src/main.rs:70-109`). The sequence, not the wake itself, is
  authoritative; ordinary pipe wakes are harmless.
- The claim-holding relay consumes only its generation's forward-event count
  and applies the writer rule to its child: while its generation remains
  active, every count above its local last-seen value is one event. Chains
  compose: sys-tty → rush → command, or rmux → pane rush → command.
  A Default leaf dies with 130; a handler leaf is notified.

**A terminal relay never stops reading its source.** `relay_in` is already
non-blocking throughout; its one stall is on `E_NOT_READY` from the child's
ring, where it awaits only the child handle (`stdio.rs:391-396`) and so would
miss an event while a hung child's ring is full. Change that branch to select
on {child writable, source readable}, hold the unwritten chunk, and service
pending events from the source header meanwhile.

**Route teardown is intentionally lossy.** Once the child finishes, the relay
atomically clears `FORWARD` and stops; it does not drain-and-recheck. A writer
whose forward CAS won before teardown may have raised an event that the
finishing relay never consumes. A writer whose CAS loses to teardown drops the
event. Both are acceptable: the intended child is already finishing, and the
event must not affect the parent or a later child. The next installation
advances the generation before setting `FORWARD`, so an old writer snapshot
cannot succeed after a later route becomes active. Loss at the boundary
therefore cannot become stale delivery to the next child. A scope guard clears
the route on every relay exit path. Because `wait()` joins the completion
group, a sequential spawner's next child cannot start before restoration.
Concurrent foreground relays serialize on the data claim; only its holder
installs the route. Background and detached children receive neither stdio:3
nor a route (Part I, clauses 3-4).

### Default termination

The writer needs the child's process handle: sys-tty (`main.rs:119`) and rmux
(`pane.rs:93`) hold one in application code; each interrupt-scanning
`ChildStdio` and terminal relay keeps a `RaiiHandle` from
`SysObj::dup(remote_process)` for the link's lifetime. The duplicate is
released on every teardown path, and russhd — which moves its `Child` into the
reaper task (`local_session.rs:276-280`) — needs no change. `OP_DUP` accepts
every object in the process's handle table
(`kernel/src/uspace/sys_obj.rs:453-470`), so this
includes process handles; add a direct test because today's coverage duplicates
only an IPC handle.

Termination is a Ctrl+C-specific `SysCpu::OP_KILL` flag, `F_KILL_CTRL_C`,
exposed as `SysCpu::interrupt(handle)`. It accepts no caller-selected status:
the kernel validates the target exactly as plain `kill(handle)` does — the
caller holds a `Process` handle — and calls
`Process::exit(CTRL_C_EXIT_STATUS)`, where the shared ABI constant is 130
(`kernel/src/uspace/process.rs:630-639`, private today, only caller `:1984`;
widen to `pub(super)`). Keeping this operation
Ctrl+C-specific avoids accidentally creating a general facility for one
process to forge arbitrary exit statuses for another. Two differences from
`kill(handle)` are required, not incidental:

- **It must not wait.** `sys_kill_impl` blocks the caller until the target is
  dead (`kernel/src/uspace/sys_cpu.rs:543-553`). The interrupt is issued from
  sys-tty's serial thread, russhd's single stdin-owner task, rmux's input path,
  or the process's one relay thread; none may stall for a teardown. Relays
  learn of death through the pipe handle; providers through their `wait()`.
- **It reports 130, not `-1`.** A `kill(handle)` today goes through
  `Process::kill` (`process.rs:580,609`; `die()` at `:619-627` is the
  `kill_pid`/`kill_remote` path) and lands on `Exiting(u64::MAX)`, which
  `moto_rt::process::convert_exit_status` (`moto-rt/src/process.rs:309-320`)
  maps to `-1` — the value rush prints for `$?` today
  (`rush/src/sys/motor.rs:112-114`, `expand.rs:386`; asserted in
  `systest/src/spawn_wait_kill.rs:419`). `Process::exit(130)` makes the parent
  observe 130 as if the child had called `std::process::exit(130)`: every
  thread terminated, no Rust stack unwound.

`sys_kill_impl` compares `flags` with `==` per branch (`:482,501,524`); the new
flag is a new branch. `kill_pid` and `kill_remote` (`CAP_IO_MANAGER`) are
unchanged, and no arbitrary-status API is added.

A kernel-free alternative — the parent VDSO remembering "I interrupted this
child" and returning 130 from `status()` (`rt_process.rs:106-121`, which
already consults per-child state in `stdio_relay.rs:176-192`) — works for the
parent but leaves `sysbox ps` and every other observer seeing `-1`. The kernel
change is a dozen lines; take it.

### What the shell must know

A POSIX shell whose foreground child was killed by SIGINT runs its own `trap
INT` *after the child exits* and abandons the enclosing list or loop; a child
that caught Ctrl+C and exited normally triggers neither. For v1, rush treats
status 130 from a foreground child as the interrupt indication: it calls
`note_signal(SIGINT)` (`signal.rs:22-29`; today the line editor's `^C` arm is
its caller, `term.rs:852`, and `$?` = 130 comes from the `Input::Interrupted`
arm, `lib.rs:383-391`) so the pending trap runs at the existing
`run_pending_traps` point (`lib.rs:369`), aborts the rest of the pipeline
(today every stage runs regardless of status, `exec.rs:1417-1427`), and breaks
out of the current list or loop. `$?` remains 130.

This deliberately accepts one ambiguity: a child that voluntarily exits 130
also takes the interrupt path. An exact distinction would require a
lifecycle-bound exit-cause field in the kernel or child state that survives
relay completion until the parent collects status. The current completion
group is removed immediately, so an unbounded pid-to-cause map in the VDSO is
not acceptable. Defer the distinction until there is a concrete consumer that
needs it; do not add `child_interrupted(pid)` without a specified cleanup
point.

rush calls crossterm's Ctrl+C adapter only after it has decided to run an
interactive shell and confirmed that fd 0 or fd 3 is the live terminal. A
non-interactive script never registers the handler, even when it was launched
from a terminal: between child routes it remains Default, and while a
foreground route is installed only the child receives the event. The
interactive prompt keeps using the existing `Key::Ctrl('c')` path, now fed by
the TUI adapter rather than the terminal data ring. An event delivered to an
interactive rush outside the line editor remains queued until its next
`event::read`; v1 does not add generic-event draining or attempt to make shell
builtins interruptible.

### Behavior change

Every process is Default until it explicitly registers the one handler; raw
mode and event reading change nothing. Old binaries and unmodified TUIs die on
`^C` where they previously received a byte. Updated TUIs explicitly enable the
crossterm adapter, which owns that handler and produces the normal key event.
Servers that do not need cleanup remove their stdin listener and exit 130 by
Default; a server that needs graceful handling registers a callback instead. A
`0x03` never reaches a data ring from a terminal source, so an interrupt that
killed a child cannot reappear at the next prompt.

## Part II implementation steps

1. **Ctrl+C-specific, non-waiting interrupt.** Add `F_KILL_CTRL_C` in
   moto-sys, the fixed-status kernel branch calling `Process::exit(130)`, and
   userspace `SysCpu::interrupt(handle)`. systest: interrupt a spinning child,
   observe status 130 with no delay in the caller; reject a non-process or
   unowned handle; verify `kill_pid`/`kill_remote` are unchanged.

2. **Atomic control state.** Put the packed flags, route generation, and
   forward-event count in one atomic header word and the handler sequence in a
   second; leave the third unused and keep `DATA_OFFSET` unchanged. moto-ipc
   tests: layout and mask assertions, Handler and Default classification,
   handler publication, burst forwarding within one generation, a teardown-
   racing event being dropped on either side of its CAS, and an old writer
   snapshot failing after a later route is installed. All operations use
   `SeqCst`; checked field increments panic descriptively on impossible
   exhaustion and need no artificial exhaustion test.

3. **Runtime API.** Append only `ctrl_c_register_handler` and `ctrl_c_wait` to
   the vtable and `moto_rt::process` (publish 0.17.6, or fold into Part I's
   release if the series land together). Do not change `SelfStdio::read` or
   `readable()`. Tests: one notification per sequence advance, burst delivery,
   single process-lifetime registration, registration races against the
   monotonic counter, a handler surviving `close(0)`/`close(3)` on the pinned
   mapping, and `ctrl_c_wait` returning the closed-peer error when the writer
   endpoint is gone, with no sleeps.

4. **Callback adapter.** Add a Motor backend to the moturus `rust-ctrlc` fork
   over the runtime API. Test registration handoff, callback invocation, the
   no-terminal dormant registration returning `Ok`, and the crate's existing
   single-handler policy on Motor.

5. **TUI adapter.** In the crossterm fork, make its existing Motor waker
   available without the `event-stream` feature and add the explicit
   process-lifetime `event::enable_ctrl_c_events()` adapter over
   `ctrlc::set_handler`, with a Motor-only dependency pinned to the immutable
   backend revision from step 4.
   Test wake-before-wait, bursts producing the same number of keys with no
   trailing `Interrupted`, ordinary input plus Ctrl+C, blocking `read`, timed
   `poll`, a pending-zero `EventStream` shutdown wake, interleaved Ctrl+C and
   shutdown wakes, setup failure leaving Default, and a second registration
   failing. Raw mode and generic event APIs remain policy-free.

6. **Forwarding, not yet activated.** Make `relay_in` select on child
   writability and source readability while holding an unwritten chunk;
   install/clear the generation-tagged forward override around the claim.
   Inject header events in tests: a handler leaf; no parent callback during
   forwarding; restore after normal exit and peer death; an event racing route
   removal may be lost but never reaches the parent or a later child;
   type-ahead remains ordered.

7. **rush.** Call `event::enable_ctrl_c_events()` only for an interactive shell
   with live terminal fd 0 or fd 3; non-interactive scripts never initialize
   the adapter. After every foreground wait, treat status 130 as interrupt for
   `$?`, `trap INT`, pipeline abort, and list/loop abort. Drive the shell path
   with a child that exits 130 and verify rush survives and a pending `trap
   INT` runs once. Verify a terminal-backed non-interactive shell does not
   register a handler. This also tests and documents the v1 ambiguity that a
   voluntary exit 130 takes the same path; the real spinning-child case
   belongs to activation step 10.

8. **Programs.** Add explicit `event::enable_ctrl_c_events()` calls to rmux,
   gears, and interactive `sysbox less`. rmux keeps copy-mode `C-c` local and
   re-originates an unbound `C-c` into the pane. red's own handler is a
   prerequisite for activation but outside this plan. All seven active legacy
   stdin-listener programs remain Default: their listeners immediately exit
   and perform no cleanup, so none needs the callback API. Leave those byte
   listeners in place until activation and delete sysbox's unused helper then.
   In `less`, enable only after piped input has been collected and paging is
   about to begin, so Ctrl+C during collection still terminates it.

9. **Scanning writer, still dormant.** Add the interrupt-scanning bit and RAII
   child-process handle to `ChildStdio`, then implement the batch rule in its
   `write`. Normal spawn plumbing continues to pass `false` for the bit in this
   patch; tests construct a scanning endpoint explicitly. Test a child that
   never reads, a full ring, an old/Default child, repeated `^C`, handle
   release, and `0x03` in a non-terminal pipe passing as data.

10. **Activation and terminal-backed integration.** Set the scanning bit only
   on the provider-side terminal-hinted `ChildStdio`. Remove the obsolete
   Ctrl+C stdin listeners and sysbox's unused copy; their EOF behavior is only
   to stop the listener, so removing them does not change process lifetime.
   Test terminal-stdin and stdio:3 default kill; callback and crossterm-handler
   leaves; a terminal-backed non-interactive rush remains Default between
   routes; nested `rmux → rush → spinning child` (only the leaf dies);
   restore after normal exit and after kill; no parent callback while
   forwarding; type-ahead retained across an interrupted child. This is the
   small patch that enables the system-wide behavior after every in-tree
   handler user is ready.

11. **Documentation.** `docs/tui.md` has no Ctrl+C text today; add the explicit
   handler and TUI adapter, single scan point and batch rule, status 130, shell
   heuristic, and the absence of process groups/SIGTTIN.

---

# Appendix A — Evidence (measured 2026-08-13, debug image, russhd pty session)

**A pipeline's last stage has no terminal stdin.** `/devtools/tests/systest
stdio-terminal-mask-child` (`systest/src/stdio_terminal.rs:17-52`) exits with
64 + its stdin/stdout/stderr mask. Run as `cat p.txt | ...` under a pty it
exits 67 — mask `011`: stdout and stderr are terminals, stdin is not. This is
the "last pipeline stage" row of `docs/tui.md:187-195`.

**Its stdin is spent, not merely non-terminal.** A probe that drains stdin
and keeps reading, while keys were typed at the terminal:

```
PROBE stdin_term=false stdout_term=true stderr_term=true data=Ok(0) bytes=6
PROBE post-EOF read starting; type keys now
PROBE post-EOF read 0 -> Ok(0) []
```

Reads return EOF immediately and forever: the feeder thread writes the
captured bytes and drops the sink (`jobs.rs:185-190`).

**No other descriptor can carry keys.** `open_pipe` (`stdio.rs:50-64`) builds
`StdioPipe::new_reader` only for `StdioKind::Stdin`; `StdioImpl::read` returns
`E_INVALID_ARGUMENT` for a non-reader (`:77-80`). There is no path from a
write-only endpoint back to the terminal.

# Appendix B — Rejected alternatives

**Non-fixes for paging.** Page without keys (one screenful, then a program
that cannot be told to quit). Read keys from stderr (write-only). Re-exec or
spawn a helper (inherits the same spent stdin). Keep the pipe open and relay
keys after the data (`cat foo | wc` never sees EOF; the shell cannot know
which children want a keyboard and which an end of file).

**Options considered.** (1) A fourth inherited stream — chosen, VDSO-
synthesized. (2) A `/dev/tty` equivalent served by the provider (`open_
terminal()`, with sys-tty, russhd and rmux each serving a second connection)
— deferred: it is the answer for acquiring a terminal one was not spawned
with and for concurrent readers; stdio:3 is specified as a handle to the
session's terminal object so option 2 can later mint fresh handles to the same
object. (3) Shell-side spooling — the child still has one stdin. (4) Do
nothing — POSIX `more`'s answer, but the idiom every user has in their fingers
does not work and no program can fix it for itself.

**Why not pass the fourth stream through `SpawnArgsRt`.** Three reasons.
`_reserved: i32` is hardcoded to 0 by every existing binary
(`moto-rt/src/process.rs:272`) and 0 is `FD_STDIN`, so any explicit scheme must
define 0 as absent. rush spawns through `std::process::Command`
(`jobs.rs:127-182`), i.e. the toolchain's embedded moto-rt, which cannot carry
a fourth fd until a toolchain refresh. And explicit passing breaks at any
terminal-unaware intermediary, where Linux does not, because the controlling
terminal is kernel session state, not a descriptor — on Motor the always-
present layer is the VDSO. (`SpawnResult` could not grow either: the pid took
its reserved slot and the struct is size-asserted at 24 bytes,
`process.rs:223`.)

**The larger redesign** — stdio:3 always present when there is a terminal;
0/1/2 never terminals — was rejected because `is_terminal(stdout)` is the
ecosystem's universal gate (no platform ships it false at an interactive
prompt, not even Windows with its separate console object), and because data
on stdout plus escapes on stdio:3 would converge on one screen with no
serialization point.

**How Linux arbitrates two claimants.** It doesn't: the tty is one kernel
object, `/dev/tty` is another handle to it, and all foreground readers race
byte-by-byte. In `cat | less`, `cat` and `less` genuinely race for `q`. It
works by convention; SIGTTIN gates background groups only.

**Lazy arming.** The stdio:3 data relay was to take no
claim until the child's first read or `poll_add` set a `reader_interest` word,
to protect type-ahead. Replaced by ring reclaim (Part I): the premise that
bytes in a dead child's ring are unrecoverable was about current code, not a
limit.

**A dedicated control IPC pair, bootstrap slot, and route-generation tokens
(rejected).** State in the existing pipe header is sufficient: wakes already
broadcast to every duplicated handle and `relay_in` is already nonblocking. A
one-sequence/link-count variant could expose a stale event to a later child.
The chosen atomic word instead tags each route and its event count with a
generation; the handler keeps its separate sequence.

**Exact delivery across route teardown.** Rejected as an unnecessary
guarantee. If Ctrl+C races the foreground child's completion, the user no
longer has a useful target for that event; dropping it is preferable to
blocking a terminal provider or applying it to the parent or next child. The
chosen atomic state tags each route with a generation, so accepting loss does
not permit stale delivery.

**A VDSO input subscription.** Rejected. It duplicated the handler policy,
added input raised/consumed counters and read-path behavior to the VDSO, and
allowed one process to register both delivery forms. The crossterm adapter now
owns the only needed conversion from the sole handler to a TUI key event. Its
opt-in remains explicit: generic event reading cannot suppress Default.

**Raw mode as implicit Ctrl+C handling.** Rejected because it makes every
raw-mode process, including a hung TUI that never handles `C-c`, immune to
Ctrl+C. `moto_rt` provides one explicit handler primitive; the moturus
`rust-ctrlc` fork provides the conventional callback, and the crossterm fork
adapts that same callback to a key event when a TUI explicitly asks.

Part I is ready for review and may be accepted on its own. Part II is ready
for review. No implementation of either starts until that part is accepted.
