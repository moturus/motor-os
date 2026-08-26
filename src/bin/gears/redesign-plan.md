# Gears redesign implementation plan

This plan implements [redesign.md](redesign.md) as a clean replacement, not
as a migration of the current harness. Intermediate edit states do not need
to preserve the old architecture, CLI, or behavior. The finished
implementation must preserve Linux and Motor OS support, the hermetic backend,
and the useful parts of the current TUI.

## Working rules

- Commit the finished change unless explicitly requested not to. Intermediate
  commits are optional and may be squashed into one final commit.
- Make small local edits and run focused tests where useful, but do not add
  compatibility layers merely to keep the old harness working during the
  rewrite.
- Stop for review if implementation exposes a non-obvious design choice not
  settled by redesign.md.
- Format changed Rust with cargo +nightly fmt and introduce no compiler or
  Clippy warnings.
- Run only local Gears checks during the redesign. Do not add Gears to
  src/tests/ or src/tests/full-test.sh, and do not contact a real provider
  from an automated test.

## What to retain

Reuse code where it remains a good fit:

- Linux and Motor OS platform/network backends;
- OpenAI-compatible HTTP and streaming protocol handling;
- the scripted mock provider and its hermetic scenarios;
- terminal input, editor, scrolling, rendering, and model selection;
- process capture, cancellation, deadlines, and process-tree cleanup.

Everything tied to modes, tasks, checkpoints, verification, mutations, undo,
specialized tools, sub-agents, or embedded behavioral prompts may be deleted
and replaced directly.

## Implementation

### 1. Replace the core model and agent loop

- Define provider-neutral messages, content blocks, tool specifications,
  tool calls/results, usage, and streaming events.
- Keep one OpenAI-compatible provider adapter; keep wire JSON and credentials
  inside it.
- Implement one agent loop: accept input, build context, stream a response,
  authorize and execute tool calls in order, append results, and repeat until
  the model stops.
- Keep cancellation, model selection, cumulative usage, provider errors, and
  a bounded tool-round limit. Remove the old workflow engine and its state.
- Adapt the mock provider and tests to drive text, reasoning, tool calls,
  continuation, usage, cancellation, and errors through the new loop.

### 2. Implement the only built-in tool

- Expose sh(command: string) through a small generic tool registry.
- Run it in the selected workspace using the POSIX shell on Linux and the
  native shell facility (`rush`) on Motor OS.
- Preserve live output, separate stdout/stderr/status, timeout,
  cancellation, process-tree cleanup, and explicit truncation.
- Never pass the provider credential in the environment inherited by sh or
  hook processes.
- Run permission hooks first. If they give no decision, ask the user to allow
  or deny the exact command; non-interactive use denies calls that still need
  input.

### 3. Replace session storage

- Store new versioned, append-only JSONL sessions under
  ~/.gears/sessions/ on Linux and /user/cfg/gears/sessions/ on Motor OS,
  grouped deterministically by workspace.
- Give entries stable id and parent_id fields and derive the active
  conversation from the root-to-selected-leaf path.
- Persist messages, tool calls/results, model changes, names, compactions,
  branch summaries, runtime identity, and namespaced hook state.
- Support new, continue, resume/pick, ephemeral, name/info, tree navigation,
  fork, clone, and compact.
- Enforce a single writer and recover from only a partial final JSONL record.
  Navigation must clearly warn that it does not undo shell side effects.

### 4. Add prompts and hooks

- Move the small default system prompt to a reviewable data file. Rust should
  contain prompt assembly mechanics, not behavioral prompt prose.
- Implement explicitly configured command hooks using one versioned JSON
  event on stdin and one bounded JSON result on stdout. Spawn argument vectors
  directly, without a shell.
- Support the lifecycle and mutation points defined in redesign.md, including
  tool registration/execution, permission, context transformation,
  compaction, notifications, and namespaced session state.
- Run hooks sequentially in configuration order. Reject duplicate names.
  Apply the specified failure behavior, timeouts, output bounds, and
  cancellation.
- Rebuild prompts and hook/tool manifests from current resources on resume,
  append their hashes as runtime identity, and show one notice when they
  change.

### 5. Add context management and connect the UIs

- Implement manual and automatic compaction with the documented output
  reserve and recent-tail defaults. Preserve full history and leave active
  context unchanged if summarization fails.
- Feed the existing line UI and TUI from the new runtime/session events.
- Retain the useful editor, rendering, scrolling, picker, and interrupt code.
  Replace task/mode/checkpoint displays with session, model, context, usage,
  activity, tool, permission, and error displays.
- Expose the session operations in the CLI and appropriate line/TUI commands,
  including session and tree pickers.
- Keep gears ask as a small provider diagnostic outside the session and hook
  runtime.

### 6. Remove the old system and finish the documentation

- Delete the old harness, session implementation, workflow types, specialized
  tools, obsolete events/configuration, tests, and dependencies.
- Ensure compiled Gears code has no remaining mode, task, checkpoint, undo,
  mutation, verification, or sub-agent surface.
- Rewrite the README and related Gears documentation around the new runtime,
  sh, hooks, authorization, sessions, compaction, and the lack of workspace
  confinement.
- Document hermetic Linux and Motor OS smoke tests. Keep any real-provider
  check separate, manual, and explicitly authorized.

## Acceptance tests

Add focused local tests for:

- normalized provider streaming and the scripted backend;
- approved, denied, timed-out, cancelled, and truncated sh calls;
- session branching, resume, fork/clone, writer exclusion, crash tails, and
  workspace grouping;
- hook ordering, state, registration, malformed output, timeout, cancellation,
  and permission aggregation;
- text-only, built-in-tool, hook-tool, provider-error, cancellation, resume,
  and compaction turns;
- prompt/runtime identity changes and secret removal from child environments.

Then run:

    cargo +nightly fmt --manifest-path src/bin/gears/Cargo.toml -- --check
    cargo test --manifest-path src/bin/gears/Cargo.toml
    cargo clippy --manifest-path src/bin/gears/Cargo.toml --all-targets
    cargo test --manifest-path src/bin/gears-mock-provider/Cargo.toml
    make gears
    make gears BUILD=release
    make gears-mock-provider
    make gears-mock-provider BUILD=release

Finally, run the documented mock-backed smoke test on Linux and Motor OS in
debug and release builds. The redesign is complete when both platforms can
stream a hermetic turn, authorize and run sh, use a hook-provided tool, resume
and branch a session, compact context, and cancel cleanly.
