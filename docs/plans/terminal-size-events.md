# Terminal size on Motor OS: in-band resize events (mode 2048)

Status: PLAN OF RECORD, IMPLEMENTATION IN PROGRESS (updated 2026-08-08).
Option A below is the design; B and C are recorded as alternatives considered.
Steps 1--7 and 11 have been implemented; Step 8 (red's client adoption) is the
next piece of work. Both terminal owners are providers now, so every step that
remains is verification of the clients in front of them.

## 1. Problem

Every Motor OS TUI app learns the terminal size by asking the wire: crossterm's
Motor backend sends `ESC[6n` once a second while waiting for input
(`crossterm/src/event/source/motor/probe.rs`), rmux answers it per pane, and
`$COLUMNS`/`$LINES` serve as the floor. This works, but it is polling: 22 bytes
of question per app per second, a probe state machine in every event source,
resize latency up to the probe interval, and no answer at all for programs the
platform cannot answer (ssh without a pty, stdio redirected).

Linux, investigated 2026-08-05, splits the problem differently:

* The **kernel stores** a per-tty `winsize` (`TIOCGWINSZ`) and delivers
  `SIGWINCH` to the foreground process group whenever anyone changes it
  (`TIOCSWINSZ`). The kernel never discovers anything.
* The **terminal owner feeds** it: a desktop emulator or sshd sets the pty size
  on every host resize; systemd v257 probes a serial console once per getty
  spawn (DSR cursor trick, or cursor-free `CSI 18 t`) and writes the result in.
* Apps only read the stored size and react to the change event. No app probes.

The lesson is not the probe — Motor OS already has that — but the split:
**discovery happens once, at the component that owns the terminal; apps get a
query + a change event.** Motor OS has no signals, so the change event needs a
different carrier. The carrier chosen here is the byte stream itself.

## 2. Current state (facts, as of 2026-08-05; the steps below amend them)

* `sys-tty` owns COM1 permanently (`sys-tty/src/serial.rs:83`,
  `kernel/src/uspace/serial_console.rs:45`), spawns the login program on plain
  pipes + `MOTURUS_STDIO_IS_TERMINAL=true`, and shovels bytes. It never
  interprets them: an app's `ESC[6n` goes to the *host* terminal, which answers.
* `russhd` answers pty requests the same way (`local_session.rs`): pipes + env
  var + its own LF→CRLF. It **ignores** the size in `pty-req` and drops
  `window-change` entirely (russh 0.62 surfaces both). It also currently sets
  `MOTURUS_STDIO_IS_TERMINAL=true` for non-pty `exec` sessions. That is a
  preexisting bug: a byte-clean `ssh host command` is not a terminal and must
  neither probe nor have terminal control sequences filtered. Step 2 owns the
  fix rather than leaving it adjacent to this work.
* `rmux` is the terminal for its panes: it answers `ESC[6n` with pane geometry
  and sets `$COLUMNS`/`$LINES` at spawn; `tell_size` is a no-op
  (`rmux/src/sys/motor.rs`), so a resized pane's child finds out at its next
  probe. Its `details.md` §3 documents the whole model.
* crossterm Motor backend: `terminal::size()` = last `6n` answer, else
  `$COLUMNS`/`$LINES`, else 80×24; `Event::Resize` is emitted when a clocked
  probe comes back different.
* All three interactive apps already **consume** `Event::Resize` today: red
  (`input.rs:50` → `main.rs:43` `apply_terminal_size`), rush (`term.rs:768`),
  and the rmux client (`client.rs:422`, forwarded as `ToServer::Resize` for
  relayout). The client side of this plan is therefore mostly adoption and
  verification, not new event handling.
* There are no signals, no ioctl, no pty, and rmux's `details.md` records the
  deliberate decision not to build ptys.

## 3. Goals / non-goals

Goals:

1. Correct size at first paint where the owner knows it before spawn (ssh and
   rmux panes). On the physical console, preserve non-blocking startup and
   converge on the enable-time report as soon as the event loop first runs;
   an application must never hang waiting for a terminal that may not answer.
2. Live resize events: ssh `window-change` and supported host-terminal resizes
   reach apps promptly, without clocked probing.
3. One convention shared by all three terminal owners, honoring the existing
   architecture (owners are the terminal; no kernel involvement).
4. No boot-time cost, no unasked bytes into programs that did not opt in
   (the objection recorded in crossterm's `probe.rs` is real).

Non-goals: ptys, termios, job control, per-fd `is_terminal`.

## 4. Sources of truth

Whoever owns a terminal already knows, or can learn, its size authoritatively:

| Owner  | Source | Live? |
| :--- | :--- | :--- |
| host terminal (console case) | itself | yes, if it supports in-band reports (mode 2048) |
| `russhd` | `pty-req` initial size; `window-change` messages | yes, from every ssh client, for free |
| `rmux` | pane geometry it computes itself | yes |

## 5. The design: DEC mode 2048 as the platform convention

An emerging terminal answer to "SIGWINCH doesn't fit" is in-band resize
notification, DEC private mode 2048
(https://gist.github.com/rockorager/e695fb2924d36b2bcf1fff4a3704bd83;
implemented by several terminals including foot, Ghostty, iTerm2, and kitty,
but not universal): an app sends `CSI ? 2048 h`; the terminal immediately reports
`CSI 48 ; rows ; cols ; height_px ; width_px t` and repeats the report on every
resize; `CSI ? 2048 l` stops it; `DECRQM` (`CSI ? 2048 $ p`) queries support.
Note the order: rows before cols, the opposite of crossterm's `(cols, rows)`.

Motor OS makes this its native protocol. Each terminal owner *is* the terminal
for the mode:

* **crossterm Motor backend** (the client side for rush, rmux client, red,
  kibim…): on entering its event loop, send `CSI ? 2048 $ p` + `CSI ? 2048 h`.
  Track support as unknown/supported/unsupported. A DECRPM status of 0 or 4
  explicitly means unsupported and must leave today's probe ladder running;
  only a supported DECRPM state or a well-formed `CSI 48 t` report silences
  clocked `6n` probing. Translate a valid report with nonzero `u16` rows/cols
  into `Event::Resize(cols, rows)` and cache it for `terminal::size()`; ignore
  colon subparameters as the mode specification requires. The enable-time
  report supplies the first authoritative console size, although red and rush
  may already have painted their non-blocking fallback once. Re-assert the mode
  when raw mode is re-entered after a foreground child ran (the child may have
  disabled it). Send `CSI ? 2048 l` from the Motor `disable_raw_mode()` path
  once the event source has enabled the mode; do not rely on the process-wide
  event source's destructor running.
* **rmux** (provider): its per-pane emulator implements the mode: parse
  `CSI ? 2048 h/l` and DECRQM from pane output (it already parses everything
  for the grid), report DECRPM state 1 when enabled and 2 when disabled, and
  emit the current size into the pane's stdin on every enable (including a
  repeated enable) and on every actual pane resize. The opt-in makes the
  injection safe, answering `probe.rs`'s objection. This is additional to the
  existing `tell_size`: keep that seam for the host's `TIOCSWINSZ`, while the
  `Grid`/`Pane` path owns in-band reports on both platforms. Also answer
  `CSI 18 t` with `CSI 8 ; rows ; cols t` (one-shot query, cursor-free).
* **russhd** (provider): track mode 2048 per pty session by scanning the output
  streams for the enable/disable/DECRQM sequences. stdout and stderr each need
  their own split-safe scanner, but all scanner actions, client input, and
  `window-change` updates go through one per-session coordinator that owns the
  latest geometry, subscription state, and child stdin. It generates reports
  in that single order, so an old enable-time size cannot land after a newer
  `window-change`. Flush an unmatched partial sequence verbatim when its stream
  ends. On `window-change`, and on every enable, inject the latest report into
  the child's stdin. Also set `$COLUMNS`/`$LINES` from valid `pty-req` character
  geometry at spawn and preserve nonzero SSH pixel geometry in reports. None of
  this applies to a session without `pty-req`: its output remains byte-exact and
  it does not get the terminal environment flag.
* **sys-tty**: *no changes.* The console app converses with the host terminal
  directly over the wire, exactly as `6n` works today.

Nesting composes with no special cases: rush inside rmux inside ssh — each hop
is a terminal to the next. Boot latency: zero; nothing runs at boot. Normal raw
mode and panic-cleanup paths disable the mode. A process killed so abruptly
that it cannot restore any terminal mode may leave 2048 enabled on the physical
console, just as it may leave the alternate screen or cursor mode behind; Option
A accepts that ordinary terminal limitation rather than making sys-tty track
process ownership.

## 6. Decisions (review answers, 2026-08-05)

1. **Pixel fields**: rmux reports `0;0`, because it knows pane cells but not
   their pixels. russhd preserves the latest nonzero `pty-req`/`window-change`
   pixel geometry and reports it in height-then-width order; zero remains
   "unknown". Existing Motor OS apps tolerate either.
2. **russhd swallows the mode sequences** (`? 2048 h/l`, DECRQM) rather than
   forwarding them to the client terminal: single authority, no duplicate
   reports. It answers DECRQM itself.
3. **Support confirmation is semantic, not merely a reply**: DECRPM 0 and 4
   mean unsupported and retain fallback probing. A supported DECRPM state or a
   well-formed `CSI 48 t` report confirms support; a malformed report does not.
4. **The crossterm change is one self-contained patch** on the
   `moturus/crossterm` fork (`motor-os-support` branch), written so it can be
   offered upstream: the sequence parsing lives in the shared ANSI parser, the
   Motor event source only wires it up. No dependency on Motor-only crates.
5. **Platform wire helpers live in `src/sys/lib/moto-tooling`**: sequence
   constants, report/DECRPM-reply builders, and the streaming scanner that
   recognizes and removes the canonical standalone 7-bit mode sequences
   crossterm emits, across arbitrary write boundaries. `russhd` consumes them.
   crossterm cannot (decision 4: external and self-contained). rmux deliberately
   keeps its small local interpretation in `Grid`/`Pane`, where its existing
   ANSI parser already provides the parameters and state; it does not add a
   moto-tooling dependency merely to share literals.
6. **SSH session input has one owner**: a coordinator task owns child stdin,
   mode state, and geometry. Network input, scanner actions, and window changes
   are messages to it. This is the ordering rule, not an implementation detail
   left to concurrent stdout/stderr tasks.
7. **Geometry is validated, never wrapped or clamped**: zero SSH dimensions are
   ignored as RFC 4254 requires; character dimensions outside `u16` are ignored
   with the last valid value retained. No invalid report confirms mode support.
8. **First paint is deliberately asymmetric**: owner-known ssh/rmux geometry is
   correct at spawn; the physical console remains non-blocking and may repaint
   once when its immediate report is consumed. rmux may retain its existing
   bounded startup settlement because a double full-screen paint there is
   especially expensive. Red and rush do not reintroduce a startup wait.
9. **The console keeps a slow probe, at ten seconds** (2026-08-07). Steps 5 and
   6 make rmux and russhd providers, so their children never probe. What is left
   is the physical console in front of a host terminal that does not implement
   mode 2048 — the common case, since most terminals do not — and there the
   probe is the only way a resize is ever noticed. It stays, but once per second
   is polling a human-paced event: `PROBE_INTERVAL` becomes 10s, which bounds
   resize latency at ten seconds for terminals that cannot push and cuts the
   unanswerable traffic tenfold. `QUIET_INTERVAL` (30s, after three unanswered
   probes) and its instant reset on any answer are unchanged, and mode 2048
   still silences probing entirely. This is a crossterm-fork change, so it
   carries Step 4's workflow requirement: see Step 11.
10. **The probe asks `CSI 18 t` before it moves the cursor, and never hides it**
    (2026-08-08). The corner probe restores the cursor with DECSC/DECRC, but it
    is *seen* in the corner in between: on a slow terminal — nested
    virtualisation, a serial line — the cursor visibly jumps away and back on
    every probe. Hiding it around the query is not available. `Hide` and `Show`
    are stateless commands with no shared state to read, so nothing in the
    backend knows whether the application wants a cursor, and showing one
    afterwards would turn it on for a full-screen program that had turned it
    off — which the rmux client does whenever its active pane hides one. The
    answer is not to hide the cursor but to stop moving it: `CSI 18 t` reports
    the same geometry and touches nothing, so it is asked first, with the corner
    kept as the fallback for terminals that ignore window operations.
    Escalation between them runs on a 250 ms clock, not `PROBE_INTERVAL`,
    because nothing paints at the right size until one of them answers.

    This does **not** displace mode 2048, and the distinction is the whole point
    of the design: `CSI 18 t` is a question, answered once, while mode 2048 is a
    subscription that pushes on every later resize. Building on the query alone
    would make the polling prettier and leave §1's complaint — every app asking,
    forever, and resize latency bounded by the interval — exactly where it was.
    The three rungs are push (2048), poll without moving the cursor (`CSI 18 t`),
    and poll by moving it; each is used only when the one above goes unanswered.

## 7. Implementation steps

Each core-repository step is a separate small patch (AGENTS.md: 100–300 loc
including tests), independently useful, landed in order. "Patch" means a
reviewable diff, not authorization to commit it. `full-test.sh` must include
every new test directly or transitively and pass 3× debug and 3× release at
every core step. The external crossterm patch follows that repository's tests;
before it is committed or pushed, stop and ask for the required workflow.

**Step 1 — moto-tooling: the shared `mode2048` module.**
Constants for `CSI ? 2048 h/l`, DECRQM/DECRPM, and `CSI 48 t` report formatting
(rows-first); a streaming scanner that detects and optionally removes the
canonical mode sequences from a byte stream, correct across arbitrary write
boundaries. It exposes an EOF flush so an incomplete prefix is never lost.
Unit tests cover every split point, adjacent sequences, false prefixes,
mismatches, byte-exact pass-through, and partial-sequence EOF. Add moto-tooling's
host tests to `full-test.sh`; report parsing stays in the actual clients rather
than becoming an unused shared API.

**Implemented.** Added the shared constants, builders, split-safe scanner, and
host tests; the full suite passed 3× debug and 3× release.

**Step 2 — russhd: make pty state truthful and retain geometry.**
Pass an optional validated pty geometry into `local_session::spawn`. Only a pty
session gets `MOTURUS_STDIO_IS_TERMINAL`, LF→CRLF, `$COLUMNS`, and `$LINES`;
plain `ssh host command` remains byte-exact. Retain the latest valid character
and pixel values from `pty-req` and `window-change` in session state (no report
injection yet), ignoring zero or unrepresentable values rather than wrapping.
Do not reply to `window-change`, whose SSH `want_reply` is false. This fixes
first-paint size over pty-backed ssh on its own and fixes the preexisting
non-pty terminal flag bug. Add russhd's host tests to `full-test.sh`.

**Implemented.** PTY geometry is validated and retained across requests and
window changes; only PTY-backed children receive terminal behavior and size
environment. russhd's host tests now run in the full suite, which passed 3×
debug and 3× release.

**Step 3 — crossterm fork: the client side (self-contained, upstreamable).**
Enable/DECRQM on event-source start, re-assert on raw-mode re-entry, disable on
`disable_raw_mode`; parse `CSI 48;rows;cols;…t` (including ignored colon
subparameters) → `Event::Resize(cols, rows)`; reject zero, overflow, missing,
or malformed character dimensions. DECRPM 0/4 retains the existing probe
ladder; only decision 3's positive confirmation silences it.
`terminal::size()` prefers the last valid report. Unit tests in the fork mirror
`probe.rs`'s style and cover supported/unsupported DECRPM, a report without
DECRPM, colon subparameters, invalid reports, repeated enable reports, raw-mode
re-entry, and cleanup. Run the fork's debug and release tests three times each.

**Implemented.** The Motor backend now negotiates mode 2048, parses and caches
validated reports, emits resize events, retains probing only as the unsupported
fallback, and restores mode state across raw-mode transitions. The fork's tests
passed 3× debug and 3× release.

**Step 4 — core: adopt the crossterm revision.**
After explicit approval to commit/push the fork patch, update the pinned git
revision in `src/sys/Cargo.lock` and the red, rush, and rmux lockfiles. Update
`crossterm-smoke` and `full-test.sh` expectations for the new handshake and
fallback behavior. This is the first core patch that tests the new client in a
Motor image; do not assume a local sibling checkout changes a git-locked build.

**Implemented.** All four lockfiles now pin the mode-2048 client revision, and
the smoke coverage checks its handshake, unsupported-provider fallback,
cleanup, and non-PTY silence (`full-test.sh`, crossterm section, including the
explicit expectation that rmux and russhd stay probe-only until Steps 5 and 6).
The inherited-stdio terminal correction this integration exposed landed
separately as the per-descriptor `is_terminal` redesign — see `docs/tui.md` and
the terminal acceptance suite `src/tests/test-tui.sh`, both now part of
`full-test.sh` — after which the full suite returned to gating every commit.

**Step 5 — rmux: the pane provider.**
Per-pane mode state in the emulator; answer DECRQM; inject the report on
every enable and on every actual pane resize. Keep `tell_size` unchanged for
the host pty and make the in-band write from `Pane` after `Grid` has resized.
Answer `CSI 18 t` with pane size. Extend the pure grid tests and the
`m1.rs`/`host.rs` suites: cover DECRPM state, repeated enable, disable, same-size
resize, `CSI 18 t`, and a pane resize reaching a subscribed child with no probe
round trip.

**Implemented.** `Grid` owns the per-pane mode state and answers the enable
(every time, including a repeat), DECRQM, and `CSI 18 t`; `Pane::resize` writes
the report after the grid has resized, and only for a subscriber, so rule 4 of
rmux `details.md` §3.2 still holds for everyone else. Covered by pure grid tests,
by pane tests that drive a real child through the platform spawn seam, and by a
`host.rs` end-to-end in which a subscribed program reads the report after a
console resize with no probe. `details.md` §3.2 carries the amendment; the
in-VM crossterm check now asserts the client is told the pane size in band and
claims no stray cursor report.

*Validated.* `full-test.sh` passed 3× debug and 3× release, with no new compiler
or clippy warning. On the real thing a pane reports `80x23` in band, and that is
the one and only resize the client sees — under the probe ladder rush's
uncollected `ESC[6n` answer showed up as a second, different one, which is the
reading that changed.

**Step 6 — russhd: the session provider.**
Add the single coordinator from decision 6. Scan both pty-session output streams
with independent moto-tooling scanners; swallow mode sequences, flush partial
prefixes at EOF, answer DECRQM (decision 2), and inject correctly ordered reports
on every enable and stored/arriving `window-change`. Non-pty output bypasses the
scanner. Tests cover both streams, split sequences, EOF flush, enable/change
ordering in both arrival orders, pixel preservation, disable, and byte-exact
non-pty output. Add a `full-test.sh` integration driven through a forced SSH pty
that sends `window-change` to a subscribed child.

**Implemented (2026-08-08).** A session's child stdin has one owner: a task fed
`SessionMessage::Input` by the SSH handler, `Control` by whichever output stream
the child wrote a size sequence on, and `Resized` by `window-change`. Each
message is answered in the order it arrived, which is what decision 6 buys —
stdout, stderr, and the network are three tasks, and the report the child reads
has to be one size rather than a race between them. A geometry with no character
dimensions reports nothing at all: `ssh -tt` from a client with no terminal of
its own sends zeroes, and nobody in the chain knows a size to invent.

The `CSI 18 t` answer decision 10 promised russhd came with it, so
`moto-tooling`'s scanner recognizes a fourth control and the module is no longer
purely about mode 2048. It is swallowed like the other three: russhd is the
terminal, and a query it passed through would be answered by the client's
terminal as well, with a size of its own.

Two `full-test.sh` checks, both on a forced SSH pty. The first is the swallow,
which is directly observable — none of `?2048$p`, `?2048h`, `?2048l` reach the
client any more, and neither does a probe, because a provider that has answered
is not measured again. The second drives the whole chain the way a user does:
`script` gives the ssh client a terminal (without one it reads no size to send
and never notices a resize), `stty` resizes it under the running client, and the
`SIGWINCH` becomes a `window-change` that reaches a subscribed child as
`resize=60x20`. That check is why the pty harness exists: the client's own
geometry is the only part of this design no host-side unit test can supply.

**Step 7 — rush: client adoption.**
rush already handles `Event::Resize` (`term.rs:768`) and re-reads `$COLUMNS`
at the prompt. Verify the owner-known first paint under rmux/ssh and prompt
convergence without a key on a 2048-capable physical console. Then verify live
mid-edit resize in all three environments; fix any gaps the tests expose
without adding a startup wait. Extend the phase-style term tests.

**Implemented (2026-08-08).** rush's *painting* needed no change: it samples the
width at every prompt and takes a resize out of the key stream ahead of the
editor (`term.rs`'s `read_key`), which is exactly the client half this design
asks for, and the three environments now say so at the level a user sees.

One gap, and it was in the direction the paragraph above got backwards: rush
never reads `$COLUMNS` itself — crossterm does, as the last fallback under its
cached report — and rush never *wrote* it either. So the variable was right at
spawn and stale from the first resize onwards, and since rush's exported
variables are the process environment, every program it launched after a resize
was handed the size the terminal used to be. That is decision 8 failing one
hop down: rmux knows a pane is 40 columns before the program exists, and the
program would still paint its first frame at 80. `term::sync_size` closes it
from the interactive loop, once per command, on bash's `checkwinsize` rule --
and on `Shell::set`'s export rule, which is the same rule: the value follows
the variable. Under rmux and over ssh the owner put `$COLUMNS` in the
environment, so the update reaches children; on the console, where nobody set
it, it stays a shell variable, because a console child asks the terminal itself
over the very wire its parent used.

New: `src/tests/test-terminal-size.sh`, an acceptance script for the design
from the application's end, and five phase-8 term tests for the halves a host
pty can drive on its own — a line repainted mid-edit at the new width with no
key typed, the same inside `^R` (where a resize must redraw the search rather
than end it), `$COLUMNS`/`$LINES` reaching a command at the size it is run at,
and the two directions of the export rule.

The script boots its own VM because one of the three terminals is the serial
console, whose stdin `full-test.sh` never connects — and because *this script
is that terminal*: it answers the DECRQM and writes the reports itself, which
is the only way to test the console rung, a fifo having no size and no opinion.
It reads the editor's width off the wire through the prompt marker: rush opens
every prompt with zsh's `PROMPT_SP` trick, a `%` and then a whole row of
spaces, so the run of spaces is the width that prompt was laid out for. The
console converges 80 → 100 → 60 across the three prompts, the fallback probes
stop the moment the subscription is answered, and the ssh session starts at
100 — no convergence there, because russhd knew the size before the child
existed. That asymmetry is decision 8, now observable.

Every assertion is made against the bytes that arrived *before* the next key
was sent, which is the whole difficulty: a key repaints too, so a check that
merely finds the redrawn line proves nothing about what caused it. The console
reads a byte offset in its own log, the ssh session writes a mark to its side
of the pty (never into the session), and the rmux pane is left strictly
untouched between the split and the mark. Each of the three was confirmed
against a build whose `read_key` swallowed `Event::Resize`: all three fail
there and pass here. The `$COLUMNS` checks were confirmed the same way, against
a build with the `sync_size` call removed.

*Validated.* `full-test.sh` passed 3× release and 2× debug, with no new
compiler or clippy warning. The third debug run did not fail a check: it lost
one `ssh` connect to `No route to host` on `tokio-tests`, the suite's last
step, after every test had passed — the VM was still answering ARP-sized frames
for another 460 seconds. That step runs no part of this patch (`sync_size` has
one caller, inside `interactive_loop`, which an SSH exec request never enters),
and both sub-suites that do exercise it had passed 62,000 log lines earlier.
Left open rather than explained away, and worth knowing that the same symptom
has one precedent here with a real cause: `networking-step-by-step.md`'s TSopt
MTU defect, since fixed, which sat on `No route to host` until its timeout.

The reason it cost a 900-second timeout rather than a one-line error is a
harness defect this is the second occasion to notice: `full-test.sh`'s cleanup
runs `vm_ssh shutdown` and then `wait "$VMM_PID"`, so when the VM is
unreachable the shutdown never lands, `wait` blocks on a VM nobody told to
stop, and a clear `ssh` failure becomes an opaque timeout with minutes of
console debug appended after it.

**Fixed (2026-08-08), separately from this step.** `src/tests/vm-cleanup.sh`
holds one bounded teardown for the six places that had the unbounded pair —
`full-test.sh`, `full-test-networking.sh`, and the two acceptance scripts
`full-test.sh` itself runs, which each had it twice. It gives the shutdown a
connect timeout, waits a bounded interval, and then takes the VM down from
outside, naming qemu explicitly: `run-qemu.sh` does not `exec`, so killing the
VMM pid alone reaps the wrapper and leaves the VM holding the tap, which the
next run reads as a boot failure — the failure this was supposed to report,
now displaced onto an innocent run. Measured against a real VM made
unreachable, teardown goes from *never returning* to 24 seconds with the cause
on stderr.

**Step 8 — red: client adoption.**
red already applies `Event::Resize` (`input.rs:50`, `main.rs:43`). Verify the
same three environments: owner-known first paint under rmux/ssh, and one
fallback paint followed promptly by the authoritative size on the physical
console. Confirm no code path depends on the one-second probe cadence. Add a
resize test to red's harness.

**Step 9 — rmux: client adoption end-to-end.**
The rmux client already forwards `Event::Resize` to the server for relayout
(`client.rs:422`, `client.rs:277-281`). Verify the full nesting chain: host
terminal resize → crossterm 2048 report → client → server relayout → pane
reports → subscribed pane children, including over ssh. This is the
integration test for the whole design. Retain and exercise rmux's bounded
initial-size settlement.

**Step 10 — docs.**
Refresh rmux `details.md` §3.1 (pty-mapping table) and §3.2 (size mechanisms:
2048 becomes mechanism 1, the probe drops to fallback), `docs/tui.md`'s
terminal-provider description, and CHANGELOG. (The crossterm plan doc this
step originally named was removed as obsolete on 2026-08-07.) Record that sys-tty intentionally has no role, the physical
console's first paint may use the non-blocking fallback, and abrupt process
death has the same restoration limitation as other terminal modes.

**Step 11 — crossterm fork: the ten-second console probe (decision 9).**
`PROBE_INTERVAL` 1s → 10s in `src/event/source/motor/probe.rs`, plus a test
asserting the cadence itself, because every existing interval test is written in
terms of the constant and none would notice it going back to a second. Also
rewrite `QUIET_INTERVAL`'s justification, which still said `is_terminal` on
Motor OS "is an environment variable rather than a property of the file
descriptor" — false since the per-descriptor redesign (`docs/tui.md`). The
reason for a quiet interval survives that correction: a descriptor can be a
terminal and still have nothing on the far end that answers, because the bit is
inherited through spawn. Ordering is free; this touches nothing Steps 6--10
touch.

It also **stops the probe moving the cursor**, which is the visible half of the
same complaint: `ESC7 ESC[9999;9999H ESC[6n ESC8` restores the cursor but is seen
in the corner in between, and on a slow terminal — nested virtualisation, a
serial line — that reads as the cursor jumping away and back on every probe.
Hiding it around the query is not available: `Hide`/`Show` are stateless
commands, so nothing in the backend knows whether the application wants a cursor,
and putting one back would turn it *on* for a full-screen program that had turned
it off — the rmux client does exactly that whenever its active pane hides one.
So the probe now asks `CSI 18 t` first, which moves nothing, and falls back to
the corner only after `TEXT_AREA_ATTEMPTS` go unanswered. Escalation runs on a
250 ms clock rather than the 10 s one, because until something answers, the
application is painting at the 80x24 fallback.

**Implemented (2026-08-08).** In the fork: `PROBE_INTERVAL`, the `CSI 18 t`
preference with its escalation clock, `InternalEvent::TextAreaSize`, and a
parser that tells `CSI 8;r;c t` from mode 2048's `CSI 48;…t` by selector,
rejecting the other window operations so a position report is never read as a
size. The fork's tests pass 3× debug and 3× release, `cargo fmt --check` clean,
clippy silent. Pushed to `motor-os-support` as `bacb8c9`; the four core
lockfiles (`src/sys` and red, rush, rmux) are re-pinned to it. Note the branch
was rebased first, so the old `0e9de14…` is gone rather than superseded.

Two `full-test.sh` expectations moved with it, both of which assert the literal
bytes the client emits: the forced-SSH-pty check now looks for `ESC[18t` after
the handshake instead of the corner probe — the smoke program quits on the `q`
it is fed long before escalation is due — and additionally asserts the cursor
was *not* moved; the non-pty silence check lists `ESC[18t` alongside `?2048` and
`6n`. The rmux-pane check needed nothing: mode 2048 is confirmed there, so
nothing polls at all.

Step 5's `CSI 18 t` answer stops being merely spec-completeness here: it is what
keeps an rmux pane cursor-free if mode 2048 ever fails to negotiate. russhd gains
the same in Step 6.

## 8. Alternatives considered

**B — out-of-band tty page + poll event** (the Linux-shaped runtime API):
owner-created shared page `{rows, cols, generation, flags}` handed to the child
at spawn, `moto_rt::tty::size()` as the `TIOCGWINSZ` analog, a poll interest as
the `SIGWINCH` analog. Exact answers for programs that never read stdin and a
path to per-fd `is_terminal`, but it touches spawn ABI and rt.vdso, turns
sys-tty into a conversation-multiplexer instead of a byte pump, and still needs
this plan's in-band protocols at the physical console boundary. Deferred, not
rejected: its provider-side plumbing is exactly what Steps 2/5/6 build, so it
remains a purely additive follow-up if living with the in-band design shows
the need.

**C — central tty service (grow sys-tty)**: per-session tty objects behind
moto-ipc. Rejected: an IPC hop and liveness dependency on every terminal
interaction, growth of a boot-critical component, and a contradiction of the
considered "no tty layer" decision in rmux `details.md` §3.1, for no capability
A or B lacks.
