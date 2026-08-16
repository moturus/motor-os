# Gears P1 slash commands and manual compaction — plan for review

2026-08-15. Nothing in this plan is implemented yet.

This is a small P1 increment with two outcomes:

1. Every input beginning with `/` is handled or rejected by Gears. It is never
   sent to the model, in line mode or in the TUI.
2. `/compact [instructions]` exposes the compaction machinery Gears already
   uses automatically.

The design bias is toward Pi's small surface: reuse the existing agent,
session, compaction, event, and UI mechanisms; add no dependency, extension
point, configuration family, or new session format.

## Existing behavior and defect

Automatic context management is already complete. Above 75% of the configured
context budget, Gears stubs old tool results and, when that is not enough, asks
the current model to summarize older conversation. The `compaction_v2` session
record makes resume reconstruct the same effective context.

Line mode recognizes `/status`, `/mode`, `/pause`, `/resume`, `/+`,
`/checkpoint`, `/undo`, `/help`, and `/quit` in `ui/terminal.rs`.

The TUI currently sends submitted text directly as `Command::Prompt`. Thus a
slash command typed there can reach the model. This is a defect. Slash-command
ownership is a Gears invariant, not a UI feature.

## Slash-command contract

- Add one small, pure parser that distinguishes an ordinary prompt from every
  built-in slash command.
- Both UIs run the parser before anything can become `Command::Prompt`.
- A known command is executed by Gears. An unknown or malformed slash command
  gets a local error and makes no provider request.
- All currently documented commands work in both interactive UIs. Rendering
  may remain UI-specific; there is no need for a general command framework.
- `/quit`, `/help`, and `/+` remain UI operations. Agent/session operations use
  the existing `Harness` methods and command channel.
- Commands are accepted only while the root agent is idle, except for the
  existing pause, resume, and cancellation controls.

The parser is the shared policy. Keeping the small execution matches near each
UI is simpler than introducing a hierarchy of command handlers and output
types.

## `/compact [instructions]`

The behavior follows [Pi's manual compaction](https://pi.dev/docs/latest/compaction):
the optional text focuses the summary, while Gears chooses the safe cut point
and owns the session update.

Minimal behavior:

1. Preserve leading system messages.
2. Preserve the last user message and everything after it: the newest turn
   remains verbatim.
3. Summarize the complete older turns between those two boundaries. Never cut
   between a tool call and its result.
4. If fewer than four messages are eligible, report `nothing to compact` and
   do not call the provider.
5. Send one summary request to the session's current model with no tools. Reuse
   the existing summary prompt; append the optional instructions as a short,
   clearly marked focus request.
6. On a non-empty response, use the existing `Conversation::compact` and
   `compaction_v2` path. Durable artifact call/result pairs continue to survive
   exactly as they do for automatic compaction.
7. Count the summary completion in the existing usage and run budgets, announce
   how many messages were compacted, and return the UI to idle.
8. Provider failure, cancellation, or an empty response leaves the conversation
   unchanged and reports the existing typed error.

Manual compaction is explicit, so it works when automatic summarization or all
automatic context management is disabled. It still respects an exhausted
whole-run USD/token budget.

The command is not a model tool. It has no preview/approval/undo flow, alternate
summary model, extension hook, special retry, split-turn algorithm, or extra
configuration. Those can be considered only after this small command proves
insufficient.

## Implementation patches

Each patch should remain about 100–300 lines including tests.

### Patch 1 — make slash input Gears-owned

- Add the pure command parser and unit tests for every command, malformed
  syntax, prefixes such as `/compactor`, and unknown names.
- Route both line and TUI submissions through it before `Command::Prompt`.
- Implement the existing command set in the TUI using current `Harness`, gate,
  transcript, and artifact facilities rather than a new framework.
- Add tests proving no slash-prefixed input reaches the mock provider.

Exit: every documented command is locally handled in both UIs; unknown slash
commands are local errors; ordinary prompts are unchanged.

### Patch 2 — expose existing compaction

- Add a pure manual-range selector beside the automatic selector.
- Allow the existing summary request to append optional focus text.
- Extract only enough of `Agent::checkpoint` to call it from a new
  `Command::Compact`; do not redesign automatic compaction.
- Complete through the existing event bus and `TurnEnd`, so streaming,
  cancellation, usage, and UI state use familiar paths.
- Add unit and harness tests for selection, no-op, success, disabled automatic
  management, budget exhaustion, failure, cancellation, empty output, and
  exact resume behavior.

Exit: the harness can compact an idle session and resume with summary plus the
unchanged newest turn.

### Patch 3 — wire `/compact` through both UIs

- Add `/compact [instructions]` to the shared parser, both UI execution
  matches, help, and README.
- Extend line integration and real-PTY TUI tests. After compaction, submit an
  ordinary prompt and assert that the provider receives the summary and recent
  turn, not the replaced messages.

Exit: both Linux interfaces perform the same command and remain usable after
success, no-op, failure, or Ctrl-C.

### Patch 4 — Motor gate and documentation

- Add one deterministic mock scenario to `src/tests/gears-test.sh` that drives
  manual compaction through the built Motor binary and inspects the next
  provider request.
- Keep every automated request on loopback and use no credentials.
- Update `proposal.md` only to mark this narrow P1 increment complete.

Exit: the observable command contract passes through built Linux and Motor
binaries.

## Final checks

- No slash-prefixed input can become a provider message.
- All documented slash commands work in line mode and TUI.
- `/compact` calls the current model once without tools and counts the usage.
- System messages and the newest turn remain byte-for-byte unchanged.
- Resume reconstructs summary plus that same newest turn.
- No-op and failure paths preserve effective history.
- Debug/release Gears tests and `src/tests/gears-test.sh` pass hermetically.
- Formatting and clippy introduce no changes or warnings.
- No dependency, boot work, retry, timeout increase, ignored failure, or
  automatic commit is added.

Before any commit, run `src/tests/full-test.sh` three consecutive times in
debug and three in release, as required by `AGENTS.md`. Implementation patches
remain uncommitted unless the user separately authorizes commits.

## Open questions

None. The user decided that all slash commands are Gears-owned in all UIs and
that simplicity, using Pi as the reference, wins when this plan leaves room
for interpretation.
