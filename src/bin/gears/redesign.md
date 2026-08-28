# Gears redesign

This document records a direction, not an implementation plan. Gears should
become a small, extensible agent harness rather than a built-in coding
workflow.

## Keep

- One codebase that builds and runs natively on both Linux and Motor OS.
- The hermetic model backend: automated tests must exercise the real protocol
  and streaming paths without Internet access.
- The current TUI as a foundation. Simplify its status and controls as the
  underlying concepts disappear; do not start the terminal UI over.

## Minimal core

The core should own only provider communication, the agent loop, streaming and
cancellation, session persistence, the TUI/line UI, and hook dispatch. It
should not own a prescribed coding process.

Initially the model gets one tool:

```text
sh(command: string) -> stdout, stderr, exit status
```

`sh` starts in the selected workspace through a platform backend: a POSIX
shell on Linux and the native shell facility on Motor OS. It is not confined
to the workspace; once approved, it has the same filesystem authority as the
Gears process. Output remains bounded for model context and fully available to
the UI/session where practical. Timeouts, cancellation, and process-tree
cleanup remain core responsibilities.

Remove modes and their transitions, durable task/checkpoint/verification
state, the specialized built-in file/build/search tools, and behavioral prompt
text embedded in Rust. Features such as planning, review, task tracking,
specialized tools, sub-agents, and project instructions may return as optional
hooks or prompt resources rather than core policy.

## Sessions

Follow [pi's session model](https://pi.dev/docs/latest/sessions), adapted to
Gears' portable filesystem APIs:

- Sessions auto-save as versioned, append-only JSONL and are grouped by
  workspace. On Linux they live under `~/.gears/sessions/`; on Motor OS they
  live under `/user/cfg/gears/sessions/`. Ephemeral sessions are also
  supported.
- Entries have stable `id` and `parent_id` fields. The active conversation is
  the path from the root to the selected leaf; other branches remain in the
  same file.
- Persist messages and tool calls/results plus model changes, compactions,
  branch summaries, labels/names, and namespaced hook entries. Keep extension
  state that enters model context distinct from opaque extension state.
- Support the equivalent of continue, resume/pick, new, name, session info,
  tree navigation, fork, clone, and compact. The TUI should provide the picker
  and tree views; the line UI and CLI can expose simpler equivalents.
- Compaction changes the context sent to the model but never deletes the full
  session history. Only one process may write a session, and a partial final
  JSONL record after a crash must not make earlier records unreadable.

A session tree is a tree of conversation state, not workspace state. Moving to
an older entry does **not** undo commands already run or files already changed;
the UI must say this plainly.

## Hooks

Current harnesses use two main extension styles:

| Harness | Current approach |
| --- | --- |
| [pi](https://pi.dev/docs/latest/extensions) and [OMP](https://github.com/can1357/oh-my-pi/blob/main/docs/skills/authoring-hooks.md) | In-process TypeScript modules register tools, commands, UI, and lifecycle handlers. |
| [OpenCode](https://opencode.ai/docs/plugins/) | In-process TypeScript/JavaScript plugins and custom tools. |
| [Claude Code](https://code.claude.com/docs/en/hooks) | Configured command, HTTP, MCP, prompt-based, and agent-based lifecycle hooks. |
| [Codex](https://developers.openai.com/codex/hooks) | Configured command or MCP lifecycle hooks, also distributable in plugins. |

The in-process approach is convenient for a TypeScript harness but would tie
Gears to a runtime or unstable Rust dynamic linking. Gears v1 should instead
use the common command-hook pattern: explicitly configured executables receive
one versioned JSON event on stdin and return one bounded JSON result on stdout;
stderr is diagnostic output. Gears spawns the executable directly from an
argument vector, without an intervening shell. Project hooks run only after
the user trusts that project configuration.

A hook is ordinary code running with the user's authority. It can contact any
LLM endpoint using its own configuration and credentials, including a model
dedicated to tool approval. Gears should not add a second-model abstraction to
the core. Initially hooks are separate processes per invocation, not persistent
services.

The first hook surface should support:

- `initialize`: contribute system-prompt fragments and register additional
  tool names, descriptions, and JSON schemas;
- `input` and `context`: transform user input or the messages for the next
  request;
- `permission`: decide a tool call before execution;
- `tool_execute`: execute a tool registered by that hook;
- `tool_result`: transform the model-facing result;
- `before_compact` and `after_compact`: replace or observe compaction; and
- read-only session, model, turn, and entry lifecycle notifications, plus
  namespaced session state.

Custom tools use the normal generic TUI rendering in v1. Hook-provided UI code
and renderers can wait until there is a demonstrated need.

### Tool authorization

There are only two decision points. Permission hooks run first. Any `deny`
blocks the call; otherwise any `allow` executes it without a prompt; otherwise
Gears asks the user to allow or deny the exact command in the current
workspace. A missing permission hook is the same as no opinion. A configured
permission hook that times out, crashes, or returns invalid output denies the
call with a visible diagnostic.

Gears does not parse shell strings into a policy, infer safe commands, or add a
sandbox in v1. Approval applies to the exact displayed command. The provider
credential must continue to be passed only to the provider transport, never
through the environment inherited by `sh` or hooks.

### Composition

Use a deliberately small set of rules:

- Hooks are listed explicitly in configuration and run sequentially in that
  order. There is no implicit directory scan or hot reload in v1.
- Hook names and registered tool names are globally unique; a duplicate is a
  startup error rather than an override.
- Every event carries `protocol_version = 1`. New fields may be added and must
  be ignored by older hooks; incompatible changes require a new version.
- Only the event-specific result fields documented above can mutate data.
  Later transform hooks see earlier results.
- Each invocation has one configurable timeout and output bound and follows
  turn cancellation. Observational-hook failure is reported and ignored;
  permission-hook failure follows the deny rule above.
- Hooks are loaded at process start. Namespaced entries from an absent hook
  remain valid session data but have no effect and use generic rendering.
- Each event includes that hook's latest namespaced state, and a result may
  append its successor; there is no hidden persistent process state.

Default prompt text lives in reviewable data files rather than Rust source.

## Prompt behavior on resume

Current terminal harnesses generally preserve the conversation but rebuild
the effective system prompt and extensions from the current binary,
configuration, and project instruction files. For example, pi's
[session format](https://pi.dev/docs/latest/session-format) persists messages
and state entries rather than the system prompt, while
[Claude Code](https://code.claude.com/docs/en/prompt-caching) documents that
resuming after an upgrade uses the new prompt and reprocesses the saved
conversation.

Gears should do the same. Resume loads current prompt resources and hooks; it
does not pin old prompt contents. At each process start, append a small runtime
identity entry containing hashes of the effective prompt fragments and the
hook/tool manifests. If these differ from the last entry, show one notice.
This provides an audit trail without copying the full system prompt into every
turn.

## Context and compaction

Follow the common current policy used by
[pi](https://pi.dev/docs/latest/compaction),
[Claude Code](https://code.claude.com/docs/en/context-window), and
[OpenCode](https://v2.opencode.ai/docs/compaction/):

- Automatically compact before a request would exceed the model context minus
  an output reserve; initially use pi's defaults of a 16,384-token reserve and
  a 20,000-token recent tail.
- Summarize the older active branch, retain the recent tail verbatim, append a
  compaction entry, and build later requests from that checkpoint. The full
  pre-compaction transcript remains in the session file.
- Support `/compact [focus]`. When navigating away from a branch, offer no
  summary, a default summary, or a summary with user-supplied focus.
- If summarization fails, leave the current context unchanged and report the
  failure.

`before_compact` may change the focus and thresholds, cancel compaction, or
return a complete summary and retained tail produced through another endpoint.
`after_compact` observes the committed entry. Returned context remains subject
to the model's hard limit.

## Provider boundary

Use a small internal vocabulary for messages, content blocks, tool specs,
tool calls/results, usage, and streaming events, plus a `Provider` trait that
streams the response to one normalized request. Keep the existing
OpenAI-compatible adapter as the only initial implementation. Sessions and the
agent loop use only the normalized types; wire JSON and authentication stay
inside the adapter.

Do not attempt a universal provider framework in advance. Add capability flags
or new normalized fields only when a second real adapter proves they are
needed. A hook's own LLM calls are independent of this interface.

## Testing during the redesign

Keep the scripted backend and local Gears tests so protocol work can be checked
without Internet access. For now, `src/tests/` contains no Gears-specific
check and does not invoke the Gears or `gears-mock-provider` test suites; run
those tests manually and locally while the design is changing. Developer-image
construction may still compile and package the binaries. Restore
repository-wide gating once the new boundaries stabilize.

Implementation should replace one boundary at a time and keep the harness
runnable on Linux and Motor OS. No automated test may contact a real provider.
