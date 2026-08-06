# Terminal size on Motor OS: in-band resize events (mode 2048)

Status: PLAN OF RECORD (2026-08-05). Option A below is the design; B and C are
recorded as alternatives considered. No code has been changed yet.

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
  `window-change` entirely (russh 0.62 surfaces both).
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

1. Correct size at first paint, everywhere (console, ssh, rmux pane).
2. Live resize events: ssh `window-change` and host-terminal resizes reach apps
   promptly, without clocked probing.
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

The terminal world's answer to "SIGWINCH doesn't fit" is in-band resize
notification, DEC private mode 2048
(https://gist.github.com/rockorager/e695fb2924d36b2bcf1fff4a3704bd83; shipped
by kitty and Ghostty, in progress in foot/WezTerm; used by neovim): an app
sends `CSI ? 2048 h`; the terminal immediately reports
`CSI 48 ; rows ; cols ; height_px ; width_px t` and repeats the report on every
resize; `CSI ? 2048 l` stops it; `DECRQM` (`CSI ? 2048 $ p`) queries support.
Note the order: rows before cols, the opposite of crossterm's `(cols, rows)`.

Motor OS makes this its native protocol. Each terminal owner *is* the terminal
for the mode:

* **crossterm Motor backend** (the client side for rush, rmux client, red,
  kibim…): on entering its event loop, send `CSI ? 2048 $ p` + `CSI ? 2048 h`.
  If a DECRQM reply or a `CSI 48 t` report arrives, stop the clocked `6n`
  probing entirely and translate reports into `Event::Resize`; the enable-time
  report supplies the initial size. Otherwise keep today's probe ladder
  unchanged (fallback for hosts like current xterm/gnome-terminal). Re-assert
  the mode when raw mode is re-entered after a foreground child ran (the child
  may have disabled it). Disable on exit (`CSI ? 2048 l`).
* **rmux** (provider): its per-pane emulator implements the mode: parse
  `CSI ? 2048 h/l` and DECRQM from pane output (it already parses everything
  for the grid), emit the report into the pane's stdin on enable and on every
  pane resize — the opt-in makes the injection safe, answering `probe.rs`'s
  objection. Replace the no-op `tell_size`. Also answer `CSI 18 t` with pane
  size while here (one-shot query, cursor-free).
* **russhd** (provider): track mode 2048 per pty session by scanning the output
  stream for the enable/disable/DECRQM sequences. On `window-change`, and on
  enable, inject the report into the child's stdin. Also set
  `$COLUMNS`/`$LINES` from `pty-req` at spawn — an independent one-line win.
* **sys-tty**: *no changes.* The console app converses with the host terminal
  directly over the wire, exactly as `6n` works today.

Nesting composes with no special cases: rush inside rmux inside ssh — each hop
is a terminal to the next. Boot latency: zero; nothing runs at boot.

## 6. Decisions (review answers, 2026-08-05)

1. **Pixel fields**: reports carry `0;0` (unknown). Acceptable; existing Motor
   OS apps must and do tolerate it.
2. **russhd swallows the mode sequences** (`? 2048 h/l`, DECRQM) rather than
   forwarding them to the client terminal: single authority, no duplicate
   reports. It answers DECRQM itself.
3. **Any received `CSI 48 t` report counts as support confirmation**,
   regardless of whether a DECRQM reply was seen (covers terminals that
   implement 2048 but not DECRQM).
4. **The crossterm change is one self-contained patch** on the
   `moturus/crossterm` fork (`motor-os-support` branch), written so it can be
   offered upstream: the sequence parsing lives in the shared ANSI parser, the
   Motor event source only wires it up. No dependency on Motor-only crates.
5. **Shared pieces live in `src/sys/lib/moto-tooling`**: the sequence
   constants, the report/DECRQM-reply builders, and the streaming scanner that
   recognizes (and can swallow) the mode sequences across split writes.
   `russhd` consumes them from there. crossterm cannot (decision 4: external,
   self-contained). rmux integrates the mode inside its own emulator either
   taking the constants from moto-tooling or keeping local copies under its
   zero-dependency convention (`details.md` §4.6) — implementer's choice,
   as with `MOTURUS_STDIO_IS_TERMINAL`.

## 7. Implementation steps

Each step is a separate small patch (AGENTS.md: 100–300 loc including tests),
independently useful, landed in order. `full-test.sh` must pass 3× debug and
3× release at every step.

**Step 1 — moto-tooling: the shared `mode2048` module.**
Constants for `CSI ? 2048 h/l`, DECRQM query/reply, `CSI 48 t` report
formatting (rows-first) and parsing; a streaming scanner that detects and
optionally removes the mode sequences from a byte stream, correct across
arbitrary write boundaries. Unit tests, including split-sequence cases.

**Step 2 — russhd: use `pty-req`, retain `window-change`.**
Set `$COLUMNS`/`$LINES` from the `pty-req` geometry at spawn; store the latest
`window-change` size in session state (no injection yet). Fixes first-paint
size over ssh on its own.

**Step 3 — crossterm fork: the client side (self-contained, upstreamable).**
Enable/DECRQM on event-source start, re-assert on raw-mode re-entry, disable on
exit; parse `CSI 48;rows;cols;…t` → `Event::Resize(cols, rows)`; on
confirmation (decision 3) silence the clocked `6n` probe; keep the existing
probe ladder as fallback; `terminal::size()` prefers the last report. Unit
tests in the fork mirroring `probe.rs`'s style.

**Step 4 — rmux: the pane provider.**
Per-pane mode state in the emulator; answer DECRQM; inject the report on
enable and on every pane resize (this replaces the no-op `tell_size`); answer
`CSI 18 t` with pane size. Extend the `m1.rs`/`host.rs` test suites: pane
resize must reach a 2048-subscribed child with no probe round-trip.

**Step 5 — russhd: the session provider.**
Scan pty-session output with the moto-tooling scanner; swallow the mode
sequences, answer DECRQM (decision 2); inject reports on enable and on each
stored/arriving `window-change`. Test with a scripted ssh client driving
`window-change` against a subscribed child.

**Step 6 — rush: client adoption.**
rush already handles `Event::Resize` (`term.rs:768`) and re-reads `$COLUMNS`
at the prompt. Verify live mid-edit resize under: rmux pane, ssh session, and
a 2048-capable host terminal on the console; fix any gaps the tests expose
(expected: none to small). Extend the phase-style term tests.

**Step 7 — red: client adoption.**
red already applies `Event::Resize` (`input.rs:50`, `main.rs:43`). Verify the
same three environments; confirm no code path still depends on the probe
cadence (e.g. first paint before any event). Add a resize test if red's
harness allows.

**Step 8 — rmux: client adoption end-to-end.**
The rmux client already forwards `Event::Resize` to the server for relayout
(`client.rs:422`, `client.rs:277-281`). Verify the full nesting chain: host
terminal resize → crossterm 2048 report → client → server relayout → pane
reports → subscribed pane children, including over ssh. This is the
integration test for the whole design.

**Step 9 — docs.**
Refresh rmux `details.md` §3.1 (pty-mapping table) and §3.2 (size mechanisms:
2048 becomes mechanism 1, the probe drops to fallback), the crossterm plan doc,
and CHANGELOG. Record that sys-tty intentionally has no role.

## 8. Alternatives considered

**B — out-of-band tty page + poll event** (the Linux-shaped runtime API):
owner-created shared page `{rows, cols, generation, flags}` handed to the child
at spawn, `moto_rt::tty::size()` as the `TIOCGWINSZ` analog, a poll interest as
the `SIGWINCH` analog. Exact answers for programs that never read stdin and a
path to per-fd `is_terminal`, but it touches spawn ABI and rt.vdso, turns
sys-tty into a conversation-multiplexer instead of a byte pump, and still needs
this plan's in-band protocols at the physical console boundary. Deferred, not
rejected: its provider-side plumbing is exactly what Steps 2/4/5 build, so it
remains a purely additive follow-up if living with the in-band design shows
the need.

**C — central tty service (grow sys-tty)**: per-session tty objects behind
moto-ipc. Rejected: an IPC hop and liveness dependency on every terminal
interaction, growth of a boot-critical component, and a contradiction of the
considered "no tty layer" decision in rmux `details.md` §3.1, for no capability
A or B lacks.
