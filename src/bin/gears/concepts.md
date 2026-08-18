# Gears concepts

Gears is a coding harness, not just a chat client. It keeps explicit state for
the work, separates that state from model conversation, and records the facts
needed to resume or verify the work. This document defines the terms used by
the UI, configuration, session journal, tools, and source code.

The shortest useful map is:

```text
workspace
└── session (durable; may span process runs)
    └── root agent
        ├── conversation
        ├── task (may span user turns)
        │   ├── ordered task items
        │   ├── mode and checkpoints
        │   └── verification evidence
        ├── turn
        │   └── provider round → tool calls → results → next round
        └── sub-agents
            └── private conversation + delegated instruction
```

## Workspace

The **workspace** is the directory supplied by `--workspace`, or the current
directory by default. It is the boundary within which workspace file tools may
read and write. Gears canonicalizes paths and rejects paths or symbolic links
that escape this boundary.

Workspace-local Gears state lives under `.gears/`. It includes sessions,
remembered permissions, artifacts, and private checkpoints. That directory,
provider credentials, and other harness-private files are not exposed through
the model's general file tools.

## Run, session, conversation, and context

These four scopes are related but not interchangeable.

### Run

A **Gears run** is one invocation of the `gears` process. Whole-run token and
spend budgets include the root agent and its sub-agents and are not replenished
when another prompt is entered during the same invocation. The step limit is
different: it applies separately to each turn.

This use of *run* is distinct from the model's `run` tool, which starts one
explicit program with an argument vector in the workspace.

### Session

A **session** is the durable record of work by the interactive agent. It has a
stable ID and an append-only JSONL journal under `.gears/sessions/`. A session
records the root conversation, usage, task snapshots, verification evidence,
mutation audit records, and context compactions.

A session may contain several tasks and may outlive a process. `--resume ID`
loads it into a later Gears run. Resumption continues the recorded system
prompt and task state; changing prompt customizations affects only a fresh
session. See [Customizing the Gears system prompt](prompt-customization.md).

Only one writer may own a session at a time. A sub-agent's private conversation
is not copied into the root transcript, although its workspace mutations and
the result it returns are recorded through the root session.

### Conversation

A **conversation** is one agent's ordered model-message history plus its model
identity and cumulative usage. The root agent and every sub-agent have separate
conversations. A session contains the root conversation durably, but a
conversation is not itself the task or the workspace.

### Context

The **context** is the bounded material sent in one provider request. It is a
working view of a conversation, not necessarily the whole durable transcript.
As a conversation grows, Gears may replace old tool results with stubs and
compact completed turns while preserving current tool calls, task state, and
system instructions. Complete retained data can remain available as artifacts
even when it no longer fits in model context.

## Prompt, task, turn, and round

A **user prompt** is one submitted user message. A **task** is durable workflow
state describing the requested outcome. A **turn** processes one user prompt,
possibly through several **provider rounds**. Consequently, none of these
terms is a synonym for another.

### Task

The root agent's **task** is the authoritative, versioned description of the
requested work and its current workflow state. On the first prompt of a fresh
session, Gears creates a task automatically in the selected mode and copies
the prompt into its first active item. If a task is still open, later prompts
continue it rather than silently replacing it. Once it is complete, the next
prompt begins a new task in the same session.

A task contains:

- the exact original user request;
- an ordered list of task items with stable IDs;
- the active mode;
- an optional pending mode transition or plan checkpoint;
- the exact verification-evidence IDs supporting completion; and
- an optional handoff explaining why control returned before completion.

The user's wording is immutable. The model may retain a separate refinement
for its own execution, but that cannot overwrite what the user asked for.
Every valid task mutation advances a generation number, and the full successor
snapshot is journaled. Gears validates the successor so that unrelated state
cannot change under cover of one transition. A task has at most 256 items and
at most one active item.

Each **task item** is one ordered unit of work. Its state is one of:

| State | Meaning |
| --- | --- |
| `pending` | Known work that has not started. |
| `active` | The single item currently being worked. |
| `completed` | Finished work; this state is terminal. |
| `blocked` | Work that cannot currently proceed but may be reopened. |

The allowed state changes are deliberately narrow: pending items may become
active or blocked; the active item may become completed or blocked; and a
blocked item may return to pending or active. Completed items cannot be
reopened. The root model maintains these items through the `task` tool; they
are not inferred merely from conversational prose.

A **handoff** is durable task state explaining a return to the user. Reasons
include pause, waiting for user input, or reaching a step, token, or spend
limit. A waiting-for-user handoff carries the question that must be answered.
A handoff is different from a blocked item: one describes why agent execution
stopped, while the other describes the state of a particular work item.

### Mode

The task's **mode** is enforced workflow policy, not a display preference.
It changes instructions and which tools the model receives.

| Mode | Contract |
| --- | --- |
| `ask` | Inspect and answer without workspace mutation. |
| `plan` | Inspect and maintain a plan without implementing it. |
| `code` | Implement and verify; mutations remain permission-gated. |
| `review` | Inspect changes and evidence without fixing them. |

`--mode` or `/mode` selects the mode for the next new task; it does not rewrite
an active task. The model requests an active-task transition through the task
workflow. A model-requested transition into code mode needs user approval, and
a plan-to-code transition also needs a recorded plan checkpoint.

### Turn

A **turn** starts when the user submits one prompt and ends when Gears returns
an answer, waits for the user, is cancelled, fails, loses its UI, or records a
limit handoff. A task may therefore span multiple turns. At the end of a turn,
Gears stops any sub-agent that the root agent did not explicitly wait for.

Pausing prevents new work from being scheduled at safe boundaries. Cancelling
an active turn stops that turn at a resumable boundary; it does not erase the
session or imply that the task was completed.

### Provider request, round, and step

A **provider request** is one API call containing the current model context.
A **round**, also called a **step** by the limit configuration, consists of a
provider completion and the resulting batch of tool calls and tool results.
If tools were called, their results enter the conversation and another round
may follow. `max_steps` bounds these rounds within one turn, not within a task
or session.

## Agents and the harness

An **agent** combines a model conversation with a tool registry, workspace
context, limits, and runtime control. Agents decide which available tools to
call; the harness validates and executes those calls.

The **root agent** is attached to the user interface. It owns the durable Task,
verification evidence, completion protocol, and root conversation. When this
document says “the task,” it means this root-owned object.

A **sub-agent** is a temporary delegated worker with its own model conversation
and an instruction supplied by its parent. That instruction is often called
the sub-agent's “task” in ordinary language, but it is not another durable
Gears Task: a sub-agent does not receive the root-only `task` or `completion`
tools. Its final answer returns to the parent when the parent waits for it.

Root and sub-agents have the following boundaries:

| Shared | Private or root-only |
| --- | --- |
| Workspace and resulting file state | Each agent's conversation |
| Run token and spend budgets | Root Task and completion protocol |
| Mutation-generation clock | Sub-agent intermediate model messages |
| Permission enforcement | Delegated instruction and final result |
| Session mutation audit | Per-agent tool availability |

Sub-agents may be read-only or mutation-capable. The same mode, capability,
permission, concurrency, depth, and spend controls still apply; delegation is
not a way around policy. Workspace mutations made by writable sub-agents make
older verification evidence stale just like root-agent mutations do.

The **harness** is the trusted runtime around the agents. It owns the provider
connection, user interface, session writer, tool execution, permission bridge,
pause and cancellation controls, and agent threads. Model output requests
actions; the harness remains responsible for enforcing them.

## Tools, commands, and permissions

A **tool** is a structured operation that the model may request, such as
reading a file, preparing an edit, running a program, updating task state, or
reading an artifact. Tool availability is filtered by the current mode, agent
role, platform capability, and configured policy.

A **slash command** is a local user command such as `/status`, `/pause`, or
`/undo`. The harness handles slash-prefixed input itself and never sends it to
the model. Slash commands therefore are not tools, even when they affect some
of the same runtime state.

Permission is separate from tool availability. A read-only mode omits mutation
tools. In code mode, an available mutation may still require an allow-once,
always-allow, or deny decision. An exact file mutation is prepared first so
the user can inspect its target, digest, and diff before it is applied. A
remembered “always” decision is stored as workspace-local permission policy.

The general `run` tool is necessarily less exact: once the approved process is
dispatched, Gears conservatively treats the workspace as possibly changed,
even if the command exits unsuccessfully.

## Mutations, generations, checkpoints, and undo

A **mutation** is an approved operation that may change workspace state. Gears
maintains a shared, monotonically increasing **mutation generation** for the
root and writable sub-agents. It is a change clock, not the task generation.
Task generations version workflow state; mutation generations version the
workspace state against which verification was performed.

A **checkpoint** is private session state used to restore or prove a workflow
boundary. Gears lazily captures the session's initial file state before its
first exact mutation, and records a plan checkpoint at the plan-to-code
boundary. Checkpoints are harness metadata, not user-named workspace copies.

`/undo` restores files touched by Gears' exact mutation tools to their state at
the beginning of the session. It is session undo, not a one-edit undo stack.
Side effects produced inside an arbitrary process launched with `run` cannot
be reconstructed from exact file-mutation records and are not covered by that
guarantee.

## Verification evidence and completion

**Verification evidence** is a typed record of a native build, test, or
reviewed skip. It includes the candidate command and working directory, the
task/checkpoint/mutation scope, process result, normalized diagnostics, and a
reference to retained raw output. Passed, failed, skipped, and stale are
evidence statuses; a failed build is valid failed evidence, not a malformed
tool call.

Evidence is bound to the mutation generation at which it was collected. Any
later workspace mutation makes older evidence stale, including a mutation by
a sub-agent. A reviewed skip must carry its reason and is explicit evidence,
not an unrecorded claim that verification was unnecessary.

**Completion** is the root agent's evidence-backed terminal report. Gears
accepts it only when every task item is completed, no handoff or mode transition
is pending, the supplied evidence IDs exactly match the task, and none of that
evidence is stale. This protocol is stronger than the model merely saying
“done” in prose.

## Artifacts

An **artifact** is a durable, bounded session blob, such as complete tool
output, a large diff, attachment content, a directory profile, or raw
verification output. The UI and model context may show only an elided view and
an artifact ID; the `artifacts` tool can list artifacts and read bounded slices
without injecting the whole object into context.

An artifact is storage, not proof by itself. Verification evidence may refer
to a raw-output artifact, but it also carries typed scope and status. Likewise,
an artifact is not an ordinary workspace file: it belongs to private session
state under `.gears/` and is accessed through the bounded artifact interface.
