# Gears model history and picker plan

## Goal

Remember models in the active user configuration, use the most recently
selected model when `-m` is omitted, and let an idle full-screen Gears session
change models through `/model` without losing its draft or transcript.

The active user configuration is the path supplied by `--config`, or
`Config::default_path()` otherwise (`~/.config/gears.toml` on Unix and
`/user/cfg/gears.toml` on Motor OS). Nothing in the workspace's `.gears`
directory will be used for model preferences.

## Proposed configuration shape

Keep the existing `[provider].model` setting as a backward-compatible initial
default. Add one Gears-managed top-level table:

```toml
[models]
last = "openai/gpt-5"
used = ["openai/gpt-5", "anthropic/claude-sonnet-4.5"]
```

`models.last` wins over the legacy `provider.model` when `-m` is absent.
`models.used` is de-duplicated in most-recently-used order, and the effective
current model is always included. Existing `provider.model` is included in the
in-memory choices even before the first managed history write.

The `[models]` table is separate so Gears can replace only that small owned
section without reserializing the user's TOML and destroying comments,
formatting, or unknown fields. Each save will re-read and validate the current
file, replace or append the exact managed table, write a same-directory staging
file, flush it, and atomically rename it into place. A missing default config
and parent directory will be created with `version = 1`; an explicitly named
missing `--config` remains an error under the existing loading rules.

An explicit `-m MODEL` updates `last` and adds MODEL to `used` before the run
continues. Repeating a model does not duplicate it. A picker selection performs
the same update. A write failure is reported as a configuration error instead
of silently claiming that the choice was remembered.

## Patch 1: user-level model catalog

- Extend the version-1 raw configuration with the optional `[models]` table.
- Add validated access to the effective default, current history, and active
  config path while preserving `Config::load` behavior for callers that only
  need parsed settings.
- Add a small persistence type that owns only model history edits and validates
  model IDs as non-empty, bounded, single-line strings.
- Update startup precedence to `-m`, then `models.last`, then
  `provider.model`, then a resumed session's recorded model.
- Remember `-m` for both agent and `ask` invocations. Ensure self-restart keeps
  using the already selected model through the saved catalog/session state.
- Unit-test missing-file creation, existing-file preservation, de-duplication,
  MRU ordering, malformed/duplicate managed tables, atomic replacement, and
  the Unix/Motor path-independent persistence logic using temporary paths.

## Patch 2: change a live session's model safely

- Add a synchronous `SelectModel` harness command, permitted only while the UI
  is idle, that changes the root `Conversation` model before the next provider
  request.
- Make the model exposed by `Harness::model()` shared with the worker instead
  of a stale startup-only string.
- Update the default model used by future sub-agents; an explicitly named
  sub-agent model remains unchanged.
- Add a version-tolerant session journal record for model changes and teach
  replay to recover the latest one. Existing sessions with only their meta
  record remain valid.
- Test that requests after a switch use the new model, earlier messages remain
  intact, future default sub-agents inherit it, explicit sub-agent models win,
  and resume recovers the last session model when no user-level override is
  present.

## Patch 3: `/model` and the full-screen picker

- Add `/model` to the shared slash-command grammar and help text.
- In the TUI, opening `/model` replaces only the input panel with one model per
  row. The transcript, header, and footer remain visible. The panel uses:

  ```text
  >(x) current/model
   ( ) previous/model
  ```

- Treat the list as a radio group: `(x)` marks its one staged selection and
  `( )` marks every other row. Square brackets are reserved for future
  multiple-selection checkbox controls:
  - Up/Down moves both `>` and `(x)`, scrolling the list when it exceeds
    available rows.
  - Space has no effect.
  - Enter persists and applies the selected model, then restores the exact
    draft and cursor.
  - Escape discards the staged radio selection, keeps the current model, and
    restores the exact draft and cursor.
  - Resize redraws the same selection without closing it.
- Reuse the existing single terminal-event owner; model-picker keystrokes do
  not enter prompt history or reach the model.
- Keep the picker unavailable during an active turn, as ordinary slash commands
  already are.
- In line mode, `/model` shows the current model and the remembered list but
  does not attempt to interpret arrow-key escape sequences; selection is the
  full-screen TUI interaction requested here, while `-m` remains the line-mode
  way to select at startup.
- Unit-test every key transition, the no-op Space key, the exactly-one-selected
  radio invariant, viewport clipping, draft restoration, rendering
  markers/colors, cancellation, and persistence failure. Add a PTY integration
  test that opens the picker, selects a model, returns to input, and confirms
  the next provider request names it.

## Patch 4: documentation and verification

- Update `src/bin/gears/README.md` for model precedence, the `[models]` managed
  table, `-m` persistence, `/model`, picker controls, line-mode behavior, and
  the fact that preferences live outside the workspace.
- Update the command comparison table and any exact help assertions.
- Run `cargo fmt`, the complete Gears `cargo test` suite, Clippy for
  all targets with warnings denied, a release build, and `git diff --check`.

## Review points

1. The plan gives `[models].last` precedence over the existing
   `[provider].model`, retaining the latter as a legacy/initial default.
2. History is shown in most-recently-used order and is not silently truncated.
3. `/model` changes the current idle session, not merely the next invocation.
4. The arrow-key picker is TUI-only; line mode reports the catalog and continues
   to use `-m` for selection.
5. Failure to persist an explicit choice is an error, so Gears never reports a
   remembered selection that was not saved.
