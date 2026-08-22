# Customizing the Gears system prompt

Gears does not have one static prompt file. A normal agent request combines a
durable base system message, current mode and task state, and the tool schemas
available for that request. This document explains how to influence that
contract when using an installed Gears binary and where to change each layer in
the source tree.

## With a compiled or installed Gears

The supported customization point is the project's instruction files. Put an
`AGENTS.md`, a `CLAUDE.md`, or both at the root of the workspace:

```text
project/
├── AGENTS.md
├── CLAUDE.md
└── src/
    └── AGENTS.md
```

The workspace is the directory passed with `--workspace`; without that option,
it is the current directory. For example:

```sh
gears --workspace /path/to/project
```

A root `AGENTS.md` might contain:

```markdown
# Project instructions

- Keep public APIs backward compatible.
- Run `cargo test --workspace` before reporting completion.
- Do not edit generated files under `src/generated/`.
```

Root `AGENTS.md` and `CLAUDE.md` files are appended to the base system message
when a new session is created. Gears identifies each document and tells the
model that project instructions override conflicting general guidance in the
base prompt. They do not override enforced behavior: an instruction cannot add
a tool, enable mutation in a read-only mode, bypass the permission gate, or
reach outside the workspace.

There is currently no global instruction file, `--system-prompt` option, or
configuration key that replaces the built-in prompt. Put shared instructions
in each workspace that needs them. The `gears ask` command is only a provider
spot check; it sends its user message without the agent system prompt, project
instructions, tools, or a session.

### New and resumed sessions

The root instruction text is stored as part of a new session's first system
message. Editing a root instruction file does not rewrite an already-open or
resumed session. Start a new session, without `--resume`, to get a newly
assembled base prompt.

A resumed session deliberately reuses the exact system message with which it
started. This keeps the recorded conversation reproducible even after the
binary or the root instruction files change.

### Nested instructions

Nested `AGENTS.md` and `CLAUDE.md` files apply to paths beneath their directory.
They are not all copied into the initial system message. Instead, the base
prompt directs the model to call `project_instructions` before acting on a
nested path. That tool reads the current applicable files in this order:

1. Workspace root to the target's directory.
2. `AGENTS.md`, then `CLAUDE.md`, within each directory.

Each tool call reads the files again, so an updated nested instruction can take
effect in an existing session after the model reloads it. A root instruction
can also be returned by this tool, but that does not replace the root copy
already stored in the session's base system message.

Instruction documents must be nonempty UTF-8 regular files. Symlinks and files
that change while being read are ignored. Gears hashes the complete file and
includes its SHA-256 identity with the text. It retains at most 24 KiB of each
document in model context and reports how many additional bytes were elided.

## What the model receives

For a normal root-agent request, the model-facing contract has three principal
layers.

### 1. Durable base system message

`src/agent/prompt.rs` assembles this message when a fresh session starts. It
contains:

- Gears' identity and the canonical workspace path.
- The build platform and its Linux or Motor OS contract.
- General tool-use, permission, verification, and reporting guidance.
- Root `AGENTS.md` and `CLAUDE.md` content and identities.

The message is journaled with the conversation. Context compaction preserves
system messages, and session resume restores the recorded message instead of
building it again.

### 2. Current mode and task system message

`src/agent/turn.rs` creates a second system message for every provider request.
It is temporary rather than journaled and is regenerated from current state. It
contains:

- The active `ask`, `plan`, `code`, or `review` profile from
  `src/agent/mode.rs`.
- The exact tool names allowed in that mode and the tool contract version.
- The authoritative durable task state.

This is why changing modes or task state takes effect on the next model round
without rewriting conversation history.

### 3. Tool specifications

Tool descriptions and JSON argument schemas are sent in the request's `tools`
field, not embedded in the base system message. Each implementation under
`src/tools/` owns its model-facing name, description, and schema. The registry
filters these specifications according to the active mode, platform,
sub-agent policy, and configured capabilities.

The user conversation, attachments, assistant messages, and tool results
follow these instruction layers. An `@path` attachment is user-message data;
it is not treated as an instruction document.

### Sub-agents and summaries

Sub-agents get a new conversation. `src/agent/prompt.rs` gives them the same
base and root project instructions, an explicit tool inventory, and additional
wording explaining that only their final response reaches the parent. A
read-only sub-agent also receives the read-only notice. The creation path is in
`src/agent/registry.rs`.

Context summaries are separate, tool-free completions. Their instruction lives
in `src/agent/context.rs`. A summary can replace older conversation content,
but it does not replace the durable base system message or the regenerated
mode/task message.

## Changing the source-level contract

Choose the narrowest owner for the behavior being changed:

| Desired change | Source owner |
| --- | --- |
| Identity, common guidance, or Linux/Motor platform contract | `src/agent/prompt.rs` |
| Root and nested instruction filenames, order, validation, or size bound | `src/tools/instructions.rs` |
| Ask, plan, code, or review wording and enforced mode policy | `src/agent/mode.rs` |
| Per-request mode/tool/task system-message layout | `src/agent/turn.rs` (`task_message`) |
| Tool name, description, schema, or model-facing failure text | The relevant file under `src/tools/` |
| Sub-agent-specific instructions | `src/agent/prompt.rs` and `src/agent/registry.rs` |
| Compaction-summary instruction | `src/agent/context.rs` |
| Fresh-session assembly and resume behavior | `src/agent/harness.rs` |

Do not edit only a captured fixture. The Rust sources above are authoritative.
When changing reviewed model-facing behavior:

- Increment `agent::prompt::VERSION` when the common or platform prompt
  contract changes.
- Increment `agent::mode::VERSION` when a mode profile's model-facing or
  enforcement contract changes.
- Increment `tools::SPEC_VERSION` when a reviewed tool name, description,
  schema, or policy failure changes.
- Review both the Linux and Motor contracts. They intentionally differ.
- Update exact prompt/profile tests and the versioned model-contract fixtures
  only after reviewing the newly generated contract.

The complete captured contracts are:

- `fixtures/model-contract-linux-v1.txt`, containing the system messages and
  identities of every Linux tool specification.
- `fixtures/model-contract-motor-v1.txt`, containing the Motor-specific prompt
  and tool differences from the Linux fixture.

`agent::harness::tests::complete_model_contract_is_a_versioned_review_fixture`
prints the newly assembled fixture between clear markers when it differs. A
contract version change should use correspondingly versioned fixture names and
update the test's `include_str!` references rather than silently redefining an
older contract.

## Verification

Run focused prompt checks while editing:

```sh
cargo test --manifest-path src/bin/gears/Cargo.toml agent::prompt::tests
cargo test --manifest-path src/bin/gears/Cargo.toml agent::mode::tests
cargo test --manifest-path src/bin/gears/Cargo.toml \
  complete_model_contract_is_a_versioned_review_fixture -- --nocapture
```

After reviewing and updating any intentional fixture differences, run the
component gate and warning check:

```sh
cargo +nightly fmt --manifest-path src/bin/gears/Cargo.toml
cargo test --manifest-path src/bin/gears/Cargo.toml
cargo clippy --manifest-path src/bin/gears/Cargo.toml --all-targets -- -D warnings
```
