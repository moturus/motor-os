# Porting crossterm to Motor OS

2026-07-29. Status: **proposed** (awaiting review). No code has been changed.
All experiment results below were measured on 2026-07-29 against a release VM
(`vm_images/release/run-qemu.sh`), with a scratch-built test binary uploaded
over sftp and driven over russhd; the rmux results were driven through
`ssh motor@192.168.4.2 /bin/rmux` the way `src/tests/full-test.sh` drives it.

Companion checkout: the crossterm tree under review is `../crossterm`
(crossterm 0.29.0, edition 2024). File references below of the form
`crossterm/...` point there; bare `src/...` paths point into this repo.

## Problem

Motor OS has no pty and no termios. A program is on a "terminal" when its
stdio pipes lead, through sys-tty or russhd or an rmux pane, to something that
interprets ANSI; everything else — echo, line editing, size discovery, `^C` —
belongs to the program itself. Today every interactive program in the tree
hand-rolls its own escape-sequence layer:

* rush has a byte-level key decoder, a CPR-based width probe and a pushback
  buffer (`src/bin/rush/src/term.rs:123`, `:720-804`);
* red has a second, different decoder and a *blocking* size probe that the
  rmux design doc explicitly calls out as the pattern not to copy
  (`src/bin/red/src/terminal.rs:59-131`, `src/bin/rmux/details.md:390-402`),
  plus a dead `stty` shell-out (`src/bin/red/src/terminal.rs:42-57`);
* rmux has a third implementation — the most careful one — of the same
  probing, escape-time and CPR-extraction machinery (`src/bin/rmux/src/keys.rs`).

Each new TUI program would add a fourth. Meanwhile the Rust TUI ecosystem
(ratatui and essentially everything above it) sits on `crossterm`. Crossterm's
user-visible surface — styling, cursor movement, clearing, alternate screen —
is already pure ANSI on non-Windows targets; only its small `sys` layer talks
to the OS. If that layer can be implemented on Motor's native APIs, Motor gets
the whole ecosystem, and future in-tree tools get one shared, tested terminal
layer instead of a fourth private one.

The port must use only ANSI byte sequences plus native Motor APIs
(`moto-rt`), per AGENTS.md. No termios emulation, no new kernel surface.

## Goals

* `crossterm` (the `../crossterm` fork) builds for `x86_64-unknown-motor`
  with its default feature set (minus Windows), with no new warnings.
* `terminal`, `cursor`, `style` command APIs work unchanged (they are ANSI).
* `event::poll(Duration)` / `event::read()` deliver key events with correct
  timeout semantics on both terminals Motor has: the serial console
  (through sys-tty, bytes arrive one at a time, Enter is CR LF) and ssh
  (through russhd, bytes arrive verbatim from the client's terminal).
* `terminal::size()` returns the pane size inside rmux, the real terminal
  size over ssh, and never blocks the first paint at boot (rush's
  discipline, not red's).
* `cursor::position()` works (it is already a pure ANSI round-trip).
* A smoke-test binary in this repo exercises the port inside a VM and is
  wired into `src/tests/full-test.sh`.
* No busy loops, no boot-time work, no retries that conceal defects.

Non-goals (v1): mouse capture and focus events inside rmux panes (rmux does
not forward them today), the kitty keyboard-enhancement protocol, Windows
code paths, upstreaming to crossterm-rs (the fork comes first; upstreaming is
a separate conversation once the backend has soaked).

## What crossterm needs from an OS

Crossterm's platform surface is four things; everything else is ANSI bytes
written to stdout (`crossterm/src/macros.rs:187` — the non-Windows write path
is unconditional ANSI):

1. **Raw mode** — `terminal/sys/unix.rs:108-140`: termios `cfmakeraw`.
2. **Size** — `terminal/sys/unix.rs:86-105`: `TIOCGWINSZ`, falling back to
   spawning `tput`.
3. **An event source** — `event/source/unix/tty.rs:101-206`: poll the tty fd
   plus a SIGWINCH self-pipe plus a waker pipe, feed bytes to a pure parser.
   The parser (`event/sys/unix/parse.rs`) and the surrounding reader
   machinery (`event/internal.rs`, `event/read.rs`) are OS-free.
4. **A waker** — `event/sys/unix/waker/tty.rs`: cross-thread cancellation of
   a blocked poll (only for the `event-stream` feature).

`cursor::position()` (`cursor/sys/unix.rs:20-65`) is already implemented as
an `ESC[6n` round-trip through the event machinery — it ports for free once
the event source exists.

On `x86_64-unknown-motor`, `cfg(unix)` and `cfg(windows)` are both false
(the target sets no family — `rust/compiler/rustc_target/src/spec/base/motor.rs`),
so today the crate simply has no sys layer there and does not build. All of
crossterm's OS-heavy dependencies (rustix, mio, signal-hook, filedescriptor)
are declared under `[target.'cfg(unix)'.dependencies]` and vanish on Motor.
What remains is `bitflags` and `parking_lot` — verified 2026-07-29:
`parking_lot 0.12.5` compiles for `x86_64-unknown-motor` (parking_lot_core
falls back to its generic spin parker on unknown OSes; see Open questions).

## What Motor OS provides (verified)

Platform facts, from the tree:

* No termios, ioctl, signals, `/dev/tty`, or `TERM`; the console is always
  raw and `isatty` is the per-process env var `MOTURUS_STDIO_IS_TERMINAL`
  read by `moto_rt::fs::is_terminal` → `std::io::IsTerminal`
  (`src/sys/lib/rt.vdso/src/rt_fs.rs:1316-1332`).
* `ESC[6n` (DSR 6 / CPR) is the platform's only size mechanism: rush probes
  with it (`src/bin/rush/src/term.rs:747-780`), rmux probes with it and
  answers it for panes (`src/bin/rmux/src/keys.rs:34,45`,
  `src/bin/rmux/src/grid.rs:504`), red probes with it. `ESC[18t` is used and
  answered nowhere. rmux deliberately answers DSR 6 *only* — DA1 (`ESC[c`)
  gets no reply (`src/bin/rmux/src/grid.rs:501-502`).
* Nothing ever pushes a resize at a program: no SIGWINCH exists, russhd
  ignores `window-change` entirely (no handler; `pty-req` cols/rows are
  stored and never used, `src/bin/russhd/src/main.rs:409-442`), and rmux
  refuses on principle to write unasked bytes into a pane's stdin
  (`src/bin/rmux/details.md:261-288` — the `top` incident). Size changes are
  discovered by re-probing on a clock; red and rmux both settled on 1 s.
* rmux panes get `COLUMNS`/`LINES` at spawn (`src/bin/rmux/src/sys/motor.rs:61-62`);
  sys-tty and russhd children get neither. `$COLUMNS` is "a cache with no
  invalidation" (`src/bin/rush/src/term.rs:705-719`).
* `moto_rt::poll` (`src/sys/lib/moto-rt/src/poll.rs`) is the readiness API:
  registries are `RtFd`s, deadlines are absolute `moto_rt::time::Instant`s,
  and — since the recent stdio-pollability work (`ba6d4811`, `eab548b4`) — a
  process's own `FD_STDIN` is registrable. `rush::sys::stdin_ready`
  (`src/bin/rush/src/sys/motor.rs:57-75`) is the working reference.
* Only `POLL_READABLE` may be *registered* (`rt.vdso/src/runtime.rs:662`
  rejects other interest masks); `POLL_READ_CLOSED` etc. are still
  *delivered* when the peer goes away.
* Byte mangling differs per terminal: sys-tty turns one Enter into CR LF on
  input and `\n` into `\n\r` (plus destructive BS) on output; russhd passes
  input verbatim and does its own `\n` → `\n\r` on output; rmux panes also
  receive CR LF for Enter (`src/bin/rmux/src/sys/motor.rs:42`). The serial
  console delivers input one byte at a time.
* `panic = "abort"`: `Drop` does not run on panic, so terminal restoration
  needs a panic hook (`src/bin/red/src/terminal.rs:20-27`,
  `src/bin/rmux/src/client.rs:129-132`).

Experiment results (2026-07-29; test binary source preserved in the plan
author's session, ~350 LOC, reproducible from the descriptions below):

| # | Experiment | Result |
|---|---|---|
| 1 | `poll::wait` on `FD_STDIN`, idle stdin, timeouts 50/200/1000 ms | Timed out at exactly 50/200/1000 ms, returning `Ok(0)`, **zero early wakes** (the `Condvar`/`recv_timeout` early-wake trap of `rmux/details.md:699-711` does not apply to `poll::wait`) |
| 2 | Zero deadline (`Instant::now()`) | Empty: `Ok(0)` in 22 µs. With unread buffered bytes: `Ok(1)` READABLE in 8 µs. After draining: `Ok(0)`. Exactly crossterm's `poll(Duration::ZERO)` contract |
| 3 | Bytes sent at t≈1 s while blocked in `wait` | Wakes at 971 ms, `POLL_READABLE`, single 5-byte read returns the full `ab ESC [ A` burst |
| 4 | Waker: second registry added to the first, `poll::wake(inner)` from another thread at t=300 ms | Outer `wait` returns at exactly 300 ms with the inner registry's token; a follow-up wait sees **no stale event**. (Waking the *waited-on* registry does nothing — `wake` posts an event to *parent* registries; this is the mio-fork Waker pattern, `mio/src/sys/motor/waker.rs`) |
| 5 | `ESC 7 ESC[9999;9999H ESC[6n ESC 8` over ssh, host driver answering like a real terminal | Probe passes through russhd verbatim, answer `ESC[41;121R` arrives on stdin, parsed rows=41 cols=121 |
| 6 | Same probe inside an rmux pane (input held open) | Answered by rmux's grid in <1 ms. **Cross-talk observed**: the first CPR the program received was the answer to *rush's own* startup width probe (`1;80`), not to its probe — multiple probers share one stdin (see Design: CPR arbitration) |
| 7 | `info` in an rmux pane | `COLUMNS=80 LINES=23` present; over plain ssh: absent. `TERM` absent everywhere; `is_terminal` true on all three fds over russhd |
| 8 | Peer closes stdin while program is parked in `wait` (russhd path) | **The parked wait does not wake.** It runs to its full deadline; the *next* `wait` entry reports `POLL_READ_CLOSED` (0x4) immediately. A read after hangup returns `Ok(0)` |
| 9 | `moto_rt::net::set_nonblocking(FD_STDIN, true)` | Accepted; a dry read then returns `Ok(0)` — not `WouldBlock` — which is indistinguishable from EOF. The port does not rely on nonblocking stdin |
| 10 | `poll::add` with `POLL_READABLE\|POLL_READ_CLOSED` | `InvalidArgument`; register `POLL_READABLE` only |

Result 8 is a platform sharp edge (and possibly a gap in the recent stdio
pollability work — see Open questions). It is not a blocker: a TUI blocked in
`event::read()` simply keeps sleeping after its session dies until its next
wait entry, and russhd kills the child when the session closes.

## Design

### Where the code lives

All port code goes into the `../crossterm` fork as a third sys backend. This
repo gains only the smoke-test binary (last patch). The fork adds:

```toml
[target.'cfg(target_os = "motor")'.dependencies]
moto-rt = "0.16"
```

`moto-rt` is on crates.io; nothing else is needed. No mio, no signal-hook.

### cfg strategy

Follow the discriminator the tree already uses (`red`, `russhd`, std, the
mio fork): `cfg(target_os = "motor")`. Concretely, in the fork:

* Pure-ANSI shared code currently gated `#[cfg(unix)]` widens to
  `#[cfg(any(unix, target_os = "motor"))]`: the parser
  (`event/sys/unix/parse.rs`), the CPR/DA filters (`event/filter.rs`), the
  extra `InternalEvent` variants (`event/internal.rs:69-81`),
  `cursor/sys/unix.rs` (`position()` — rename-in-place, it is ANSI-only),
  and the `Parser` helper struct from `event/source/unix/tty.rs:214-276`
  (hoisted somewhere shareable).
* OS-touching unix files stay `#[cfg(unix)]` untouched: termios raw mode,
  `TIOCGWINSZ`, `tput`, `FileDesc`/`tty_fd`, mio/tty event sources, the
  UnixStream waker.
* New files: `terminal/sys/motor.rs`, `event/source/motor.rs`,
  `event/sys/motor.rs` (waker), selected in `terminal/sys.rs`,
  `event/source.rs`, `event/sys.rs`, `event/read.rs:22-35` with
  `#[cfg(target_os = "motor")]`.

Windows code is untouched.

### terminal::sys::motor — raw mode, size

* `enable_raw_mode` / `disable_raw_mode`: track state in the same
  `Mutex<Option<()>>` shape the unix side uses and otherwise do nothing —
  the console is always raw (`src/bin/rush/src/sys/mod.rs:8-22`). They must
  succeed: TUI apps treat a raw-mode error as fatal. No `stty` shell-out.
* `window_size()` / `size()`: kept synchronous and non-blocking-by-default,
  rush's precedence order (`src/bin/rush/src/term.rs:720-745`):
  1. the most recent CPR probe answer (a process-wide `SizeCache`);
  2. `$COLUMNS`/`$LINES` — correct inside rmux panes at spawn;
  3. `(80, 24)`.
  `size()` also *requests* a fresh probe (see below) so a stale answer heals
  on the next event-loop pass. It waits for the answer — bounded, 50 ms, the
  `PROBE_ANSWER_WAIT` discipline of `src/bin/rush/src/term.rs:61,766-780` —
  **only if a previous probe was answered**; a console with nothing on the
  other end therefore costs nothing after the first unanswered probe, and
  the first paint at boot is never blocked (the repeated in-tree warning:
  `src/bin/rush/src/term.rs:29-34`, `src/bin/rmux/src/keys.rs:38-44`).
  Pixel fields of `WindowSize` are 0.
* `supports_keyboard_enhancement()`: returns `Ok(false)` immediately. The
  standard detection needs a DA1 answer to conclude "no support"; rmux never
  answers DA1 (`src/bin/rmux/src/grid.rs:501-502`), so the honest probe
  would hang ratatui apps for its full 2 s timeout inside every pane. See
  Alternatives.

### The event source

`MotorEventSource` implements `EventSource` (`event/source.rs:13-27`):

* One long-lived poll registry, `FD_STDIN` registered with `POLL_READABLE`
  at construction. Long-lived registration interacts correctly with the
  stdio relay claim: when a spawned child borrows stdin, the vdso resets
  interest and reports not-readable until the claim returns
  (`rt.vdso/src/stdio.rs:322-408`, `:201-205`). (rush builds a registry per
  call instead, but it predates nothing — the vdso handles both; the waker
  requires a persistent registry, experiment 4.)
* `try_read(timeout)`: drain the parser first; then `wait` with the caller's
  deadline (absolute `moto_rt::time::Instant`, honored exactly per
  experiment 1); on READABLE, one blocking `read` into a **2048-byte
  buffer** — the stdio pipe holds at most 2 KiB (`moto-ipc` stdio pipes are
  a 4 KiB page halved), so a single read cannot leave drained-but-unsignaled
  bytes behind; a zero-deadline `wait` (8-22 µs, experiment 2) re-checks for
  a refill before parking again. Feed bytes to the shared `Parser`.
* Hangup: any `POLL_READ_CLOSED`/`POLL_ERROR` bits, or `read` returning
  `Ok(0)` or any error, surface as an `io::Error` from `try_read` once the
  parser is empty — never a busy loop, never a fabricated event. (rush's
  "a read error is as final as EOF", `src/bin/rush/src/term.rs:576-582`.)
  `ErrorKind::Interrupted` does not exist on Motor
  (`rust/library/std/src/sys/io/error/motor.rs`), so crossterm's
  EINTR-retry paths are dead code here — harmless.

Two Motor-specific byte-stream fixes sit between `read` and the parser,
both with pure host-testable logic:

* **CR LF coalescing.** One Enter keypress arrives as `\r\n` from sys-tty
  and rmux panes (`src/bin/rmux/src/sys/motor.rs:42`). Crossterm's parser
  maps `\r` and `\n` each to `KeyCode::Enter`, so without filtering every
  Enter becomes two key events. A one-bit state machine drops an `\n` that
  immediately follows a `\r` — *however much later it arrives*, including in
  the next read (rush's `after_cr`, `src/bin/rush/src/term.rs:109-122`).
  Over ssh a raw-mode client terminal sends `\r` alone; the filter passes it
  through untouched.
* **Lone-ESC hold-back.** The serial console delivers one byte per read, so
  `ESC [ A` arrives as three reads; the parser, told "no more data", would
  emit `Esc` + `[` + `A` as three key events. When the pending buffer ends
  mid-sequence (a trailing `ESC` or unterminated CSI) and the caller's
  budget allows, the source waits up to **50 ms** (`ESCAPE_TIME`,
  `src/bin/rmux/src/server.rs:82` and tmux precedent) for a continuation
  before finalizing. A human Esc press costs 50 ms of latency; a sequence is
  never misparsed. Budgeted waits use the same absolute-deadline `wait` —
  no new mechanism.

### Size probing and `Event::Resize`

All CPR traffic flows through the one stdin the event source owns, so the
source is also the size prober (the cross-talk of experiment 6 makes any
other owner racy):

* The probe is rmux's `SIZE_REPROBE` byte string —
  `ESC 7 ESC[9999;9999H ESC[6n ESC 8` (`src/bin/rmux/src/keys.rs:45`):
  DECSC/DECRC so it never moves the cursor, corner-jump so the clamped
  answer *is* the size. It is written to stdout only when stdout
  `is_terminal()`.
* While an application sits inside `event::poll`/`event::read`, the source
  re-probes at most once per second (red's and rmux's settled interval,
  `src/bin/red/src/main.rs:53-60`, `src/bin/rmux/src/client.rs:78`), updates
  the `SizeCache` from answers, and emits `Event::Resize` **only when the
  size actually changed**. Idle cost on a serial console: 18 bytes/s, the
  same budget rmux already spends (`src/bin/rmux/details.md:315-346`).
  An unchanged size produces no traffic upward and no redraw.
* CPR arbitration: a CPR event is consumed as a probe answer only while the
  source has a probe outstanding *and* no user-level CPR request is pending
  (i.e. no `CursorPositionFilter` poll active — `cursor::position()` sets
  one). When the user asks, the prober stands down until that read
  completes; `cursor::position()` already drains stale CPRs before asking
  (`cursor/sys/unix.rs:36-41`), which covers the reverse direction. The
  startup cross-talk of experiment 6 (rush's own probe answer arriving in a
  child's stdin) is tolerated by design: a corner-probe answer and rush's
  `ESC[999C` answer differ only in plausibility, so the cache accepts any
  CPR that arrives while a probe is outstanding — a wrong early answer is
  corrected by the next probe within a second.

### Waker (`event-stream` feature)

The mio-fork pattern, validated by experiment 4: a second, empty registry
created at source construction and registered inside the main registry with
a reserved token; `Waker::wake` = `moto_rt::poll::wake(inner_fd)`. Wakes are
delivered into the outer registry's pending-event map even when no wait is
parked, so a wake-then-poll sequence returns immediately, and one wake
produces exactly one event. No threads, no pipes.

### Explicitly degraded or unsupported (documented in the fork's README)

* `Event::Resize` arrives only while the app is inside `poll`/`read`, with
  up to 1 s latency, and only from terminals that answer DSR 6 (rmux panes,
  real emulators over ssh; the bare serial console answers if the user's
  emulator does).
* `SetTitle`, mouse capture, focus and bracketed-paste *pass through* as
  ANSI: over ssh they reach a real emulator and work; inside rmux panes,
  mouse/focus reports are not forwarded by rmux today. Not promised in v1.
* `supports_keyboard_enhancement` is a constant `false`.
* `tput` fallback and `/dev/tty` do not exist and are not consulted.
* Apps must install a panic hook to restore the screen (`panic = "abort"`);
  the smoke-test binary demonstrates the pattern.

## Proposed implementation

Five patches, each 100-300 LOC, each leaving every target green. Patches 1-4
land in the `../crossterm` fork (its own git history; motor-os is untouched
until patch 5). Workflow note per AGENTS.md: local changes only, no commits,
until review says otherwise.

### Patch 1 — fork: compile on Motor

`Cargo.toml` target dep on moto-rt; cfg widening of the pure-ANSI shared
code; `terminal/sys/motor.rs` with tracked no-op raw mode and env/fallback
`size()` (no probing yet); minimal `event/source/motor.rs` (poll + 2 KiB
read + parser + hangup-as-error; no coalescing, no probe, no waker);
`supports_keyboard_enhancement` → `Ok(false)`.
Gate: `cargo +dev-x86_64-unknown-motor check --target x86_64-unknown-motor`
clean with default features minus `windows`; existing host `cargo test`
untouched.

### Patch 2 — fork: input correctness

The CR LF coalescer and lone-ESC hold-back as a pure `InputFilter` between
read and parser, plus `POLL_READ_CLOSED` handling. Host-side unit tests
(the filter is byte-in/byte-out, no OS): CR LF split across reads, lone Esc
vs split CSI at every split point, hangup-drains-parser-first.

### Patch 3 — fork: size cache, probing, Resize

`SizeCache`, the answered-before waiting discipline in `size()`, the 1 Hz
re-probe inside `try_read`, CPR arbitration with `cursor::position()`,
Resize suppression when unchanged. Unit tests for the cache precedence
(mirroring `src/bin/rush/src/term.rs:1571-1594`) and for arbitration.

### Patch 4 — fork: event-stream waker

The nested-registry `Waker`, `EventStream` enabled on Motor, and a
wake-before-poll unit test shape (host: API-level; VM: covered by patch 5).

### Patch 5 — this repo: smoke test wired into full-test.sh

`src/sys/tests/crossterm-smoke`: a binary that (a) enters/leaves the
alternate screen, (b) prints `size()`, (c) echoes decoded key events for a
scripted byte diet including split escape sequences and CR LF Enter,
(d) reports a CPR-derived size when the driver answers, (e) installs the
panic-hook pattern. Depends on the fork by path (`../crossterm`) —
build-system decision below is an open question. Makefile target + member +
clippy + `src/imager/motor-os.yaml` entry, invoked from `full-test.sh` both
directly over ssh (russhd path) and inside an rmux pane with input held
open (the harness must keep stdin open — experiment 6's first failure mode —
and must not rely on the guest's `ESC[6n` reaching the host: full-test's
qemu console `sed` strips it, `src/tests/full-test.sh` boot line).

## Validation

1. Fork host tests: `cargo test` (parser, filters, cache — pure logic).
2. Fork Motor build: `cargo +dev-x86_64-unknown-motor check/build --target
   x86_64-unknown-motor`, debug and release, no new warnings; clippy clean.
3. VM focused runs of `crossterm-smoke` over russhd: scripted key bytes
   (including 1-byte-fragmented sequences replayed with delays), CPR driver
   answering `ESC[41;121R`, hangup mid-read.
4. `crossterm-smoke` inside an rmux pane per the full-test rmux pattern,
   asserting pane-size discovery (23x80) and alt-screen enter/leave markers.
5. Manual checklist on the real serial console (qemu `-nographic`, and the
   `vm-console-check.py` pty harness style for automation later): red-style
   editor session via a small ratatui example, Esc latency spot-check,
   Enter-coalescing spot-check. Release image only (debug console noise:
   `src/bin/rmux/tests/vm-console-check.py` header notes).
6. `src/tests/full-test.sh` x3 debug and x3 release, per AGENTS.md, before
   any commit.
7. `cargo +nightly fmt` on the motor-os patch; the fork keeps crossterm's
   own rustfmt config.

## Open questions for review

1. **Parked `poll::wait` misses stdin hangup** (experiment 8). The vdso has
   an async readiness task that is supposed to deliver remote-close edges
   (`rt.vdso/src/runtime.rs:273-293`), and it does deliver them level-wise
   at the next wait entry — but a parked waiter sleeps through the edge.
   If this is a defect in the recent stdio-pollability work, it should be
   fixed in the vdso, not worked around in crossterm; the port as designed
   tolerates either behavior. Guidance requested per AGENTS.md
   (pre-existing-bug rule).
2. **How this repo consumes the fork**: path dependency on `../crossterm`
   (matches the current dual-checkout layout, but makes the build depend on
   a sibling dir), a moturus git URL like the tokio/mio forks (the
   `[patch.crates-io]` pattern the rust fork uses), or vendoring. The plan
   assumes a sibling path dep for the smoke test and defers the policy call.
3. **parking_lot on Motor** parks by spinning (generic parker). Contention
   on crossterm's two global mutexes is negligible for single-threaded TUIs,
   but a second thread calling `event::poll` while another blocks in
   `event::read` would spin for the whole wait. Acceptable for v1? A
   follow-up could swap `try_lock_for` usage for std primitives in the fork.
4. **Resize prober default**: always-on at 1 Hz during waits (proposed,
   matches red/rmux, 18 B/s idle serial cost) vs. opt-in. If rmux ever
   answers `ESC[18t` or russhd forwards `window-change` as bytes-on-request,
   the prober picks it up with no API change; both are out of scope here.

## Alternatives not recommended

* **A termios/pty layer in the kernel or vdso** so crossterm's unix backend
  runs unchanged: rejected — it recreates precisely the machinery Motor
  deliberately does not have (`src/bin/rmux/details.md` §3, `README.md`
  140-158), for the benefit of one crate whose OS surface is four small
  functions.
* **`supports_keyboard_enhancement` doing the real DA1-bounded query**:
  honest, and works over ssh to capable emulators — but every ratatui app
  that calls it inside an rmux pane would stall 2 s at startup because rmux
  answers DSR 6 and nothing else, by design. A constant `false` costs only
  a protocol nobody on Motor emits.
* **A new Motor-native TUI crate instead of the port**: loses ratatui and
  the ecosystem, which is the entire point.
* **Per-app terminal layers** (status quo): the three existing
  implementations already disagree (red's blocking probe vs rush's
  discipline), and a fourth is on the way with any new tool.
