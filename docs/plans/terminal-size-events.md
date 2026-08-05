# Terminal size on Motor OS: in-band resize events (mode 2048)

Status: PLAN OF RECORD, REVISED AFTER REVIEW (2026-08-05). Option A below is
the design; B and C are recorded as alternatives considered. No code has been
changed yet.

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

## 2. Current state (facts)

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

**Step 2 — russhd: make pty state truthful and retain geometry.**
Pass an optional validated pty geometry into `local_session::spawn`. Only a pty
session gets `MOTURUS_STDIO_IS_TERMINAL`, LF→CRLF, `$COLUMNS`, and `$LINES`;
plain `ssh host command` remains byte-exact. Retain the latest valid character
and pixel values from `pty-req` and `window-change` in session state (no report
injection yet), ignoring zero or unrepresentable values rather than wrapping.
Do not reply to `window-change`, whose SSH `want_reply` is false. This fixes
first-paint size over pty-backed ssh on its own and fixes the preexisting
non-pty terminal flag bug. Add russhd's host tests to `full-test.sh`.

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

**Step 4 — core: adopt the crossterm revision.**
After explicit approval to commit/push the fork patch, update the pinned git
revision in `src/sys/Cargo.lock` and the red, rush, and rmux lockfiles. Update
`crossterm-smoke` and `full-test.sh` expectations for the new handshake and
fallback behavior. This is the first core patch that tests the new client in a
Motor image; do not assume a local sibling checkout changes a git-locked build.

**Step 5 — rmux: the pane provider.**
Per-pane mode state in the emulator; answer DECRQM; inject the report on
every enable and on every actual pane resize. Keep `tell_size` unchanged for
the host pty and make the in-band write from `Pane` after `Grid` has resized.
Answer `CSI 18 t` with pane size. Extend the pure grid tests and the
`m1.rs`/`host.rs` suites: cover DECRPM state, repeated enable, disable, same-size
resize, `CSI 18 t`, and a pane resize reaching a subscribed child with no probe
round trip.

**Step 6 — russhd: the session provider.**
Add the single coordinator from decision 6. Scan both pty-session output streams
with independent moto-tooling scanners; swallow mode sequences, flush partial
prefixes at EOF, answer DECRQM (decision 2), and inject correctly ordered reports
on every enable and stored/arriving `window-change`. Non-pty output bypasses the
scanner. Tests cover both streams, split sequences, EOF flush, enable/change
ordering in both arrival orders, pixel preservation, disable, and byte-exact
non-pty output. Add a `full-test.sh` integration driven through a forced SSH pty
that sends `window-change` to a subscribed child.

**Step 7 — rush: client adoption.**
rush already handles `Event::Resize` (`term.rs:768`) and re-reads `$COLUMNS`
at the prompt. Verify the owner-known first paint under rmux/ssh and prompt
convergence without a key on a 2048-capable physical console. Then verify live
mid-edit resize in all three environments; fix any gaps the tests expose
without adding a startup wait. Extend the phase-style term tests.

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
2048 becomes mechanism 1, the probe drops to fallback), the crossterm plan doc,
and CHANGELOG. Record that sys-tty intentionally has no role, the physical
console's first paint may use the non-blocking fallback, and abrupt process
death has the same restoration limitation as other terminal modes.

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
