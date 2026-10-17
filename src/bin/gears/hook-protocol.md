# Gears command-hook protocol, version 1

Hooks are explicitly ordered commands from the user configuration. Gears
starts the configured argument vector directly for each event, writes one JSON
object to stdin, closes stdin, and reads one bounded JSON object from stdout.
Stderr is shown as a diagnostic. Hooks inherit the user's authority and the
selected workspace, but never inherit the provider credential.
The bare program `gears-batteries` resolves beside the running executable,
for hooks and every other shared-runner role. It does not search `PATH`.

A hook configuration may select `events = [...]`. Omission receives all events;
an empty list receives none. Unknown or duplicate event names are rejected.
Unsubscribed events do not start a process, including `initialize`; hooks that
register tools must subscribe to both `initialize` and `tool_execute`.

`initialize` carries `reason`, `provider`, `model`, and `subscribed_events`.
The subscription field is the hook's configured event list, or `null` when
all events are subscribed. A hook should register commands only when
`command` is subscribed; older senders omit the subscription field.
Setup runs at startup
and again after new, resumed, forked, or cloned sessions, model/provider changes,
and compaction. Its prompt fragments
and tool registrations replace the previous setup's registrations. Failed
setup leaves the active session and its registrations usable.

`turn_end` carries `status` (`completed`, `cancelled`, or `error`), an optional
`error`, the number of `tool_rounds`, and `last_entry_id` before end-of-turn
hooks run. A round counts a provider reply requesting tools, including calls
that were denied or never started; several calls in one reply count once.

Runtime `permission` events also carry `tool.read_only`, taken from the
enabled directory manifest; hook tools and unknown tools default to false.
For a shell-state tool, `tool.shell_state_directory` names the saved state
without creating it. Its `cwd` file, when present and usable, is the shell's
starting directory; otherwise the shell starts in the selected workspace.
Tool-role `entry` events are sent after the result is saved. They include
its entry `id`, `tool_call`, `tool.read_only`, runtime `outcome`, and
`tool_result`. This covers denied, unknown and otherwise unstarted calls,
including interrupted turns. Entry-notification result text is limited to
64 KiB at a UTF-8 boundary, with `tool_result_truncated`; the saved result
and model context retain their normal limits.

Every event has this envelope:

    {
      "protocol_version": 1,
      "event": "permission",
      "hook": "policy",
      "workspace": "/work/project",
      "session": {
        "id": "session-id",
        "path": "/home/me/.gears/sessions/.../session-id.jsonl",
        "state": {"calls": 3}
      },
      "payload": {"tool_call": {"id": "c1", "name": "sh", "arguments": "..."}}
    }

Every successful invocation returns an object. protocol_version may be omitted
when it is 1. The common optional fields are state, context, and notice.
State replaces that hook's latest namespaced state. Context is a normalized
Gears message that is also added to model context.

Common fields also include `hint` and `question`. A hint is one line of at
most 256 bytes; an empty string clears it. Later hints replace earlier ones.
A question has this shape:

    {"id":"publish-1","text":"Publish this proposal?","choices":[
      {"value":"publish","label":"Publish"},
      {"value":"discard","label":"Discard"}]}

The id and choice values are nonempty lines of at most 64 bytes, the question
text at most 1024 bytes, and labels at most 256 bytes. There must be 2–6 choices
with distinct values. A questioning hook must subscribe to `answer`.
The owning hook receives `{"id":"publish-1","answer":"publish","attended":true,"cancelled":false}`.
A skipped or unattended question has a null answer; unattended runs never read
input. Questions are queued in hook order, with at most 16 pending. Answers
may ask another question; a turn, hook command, or standalone interaction
handles at most 16 questions, then reports and discards further questions.
Question answers do not replace Gears' tool permission decisions.
The line UI accepts a choice number or value, or Enter to skip. The TUI uses
number keys and Enter/Esc to skip; Page Up and Page Down keep the complete
question and labels readable. Ctrl-C cancels the current operation.

Event-specific result fields are:

| Event | Result fields |
| --- | --- |
| initialize | prompt_fragments, tools, commands |
| input | input |
| context | messages |
| permission | decision: allow, deny, ask, or confirm; permission_detail |
| tool_execute | tool_result |
| tool_result | tool_result |
| before_compact | compaction |
| before_stop | message |
| after_compact and lifecycle events | common fields only |

A tool result is {"content":"text","is_error":false}. Registered tools use
{"name":"tool_name","description":"...","parameters":{...JSON Schema...}}.
Permission hooks may add `permission_detail` to the existing approval
description. Gears labels each addition with its hook name and shows the
same detail in the permission event and prompt. The combined additions
are limited to 16 KiB; empty text, NULs or an oversized addition deny the
call. The decision rules and saved-denial precedence are unchanged.
Registered commands use `{"name":"tasks","help":"Show the task list"}`.
Names are 1–64 ASCII letters, digits, underscores or hyphens, without `/`;
help is a nonempty line of at most 256 bytes. Built-in names and duplicate
registrations are rejected. Setup replaces command registrations along with
tools and prompt fragments. A registering hook must receive `command` events.
Both UIs list commands in `/help` and send `{"name":"tasks","argument":"argument text"}`
only to the owning hook. The command is not sent to the model. Common result
fields apply.
A before_compact result may set cancel, focus, output_reserve_tokens,
recent_tail_tokens, or both summary and retained_tail. Supplying a summary
without the complete retained tail is invalid.

After a reply that follows a tool round, `before_stop` receives `tool_rounds`
and `last_entry_id`. A nonempty `message` becomes a saved user-role note and
starts another model request, at most three times per turn. Combined hook
messages are limited to 4096 bytes. Empty replies add no request; hook failures
and oversized messages are reported and skipped. Chat-only turns do not call
this event. The normal tool-round budget still bounds the turn.

Unknown input fields must be ignored. A hook must not return fields that are
invalid for its current event. Incompatible protocol changes require a new
protocol_version.

Hooks run sequentially in configuration order. Later transformations see
earlier ones. Permission aggregation is deny over confirm over allow over ask.
A saved denial refuses the call before permission hooks run. `confirm` requires
a fresh attended answer even when an allowance was saved; unattended calls are
refused. Otherwise hooks may allow the call, followed by saved attended
allowances and the user prompt. A permission hook that fails, times out, or
returns invalid output denies the call.
Observational-hook failures are reported and ignored; failures in transforming
hooks stop the operation rather than silently changing its meaning.
