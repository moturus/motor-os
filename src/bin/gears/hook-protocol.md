# Gears command-hook protocol, version 1

Hooks are explicitly ordered commands from the user configuration. Gears
starts the configured argument vector directly for each event, writes one JSON
object to stdin, closes stdin, and reads one bounded JSON object from stdout.
Stderr is shown as a diagnostic. Hooks inherit the user's authority and the
selected workspace, but never inherit the provider credential.

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

Event-specific result fields are:

| Event | Result fields |
| --- | --- |
| initialize | prompt_fragments, tools |
| input | input |
| context | messages |
| permission | decision: allow, deny, or ask |
| tool_execute | tool_result |
| tool_result | tool_result |
| before_compact | compaction |
| after_compact and lifecycle events | common fields only |

A tool result is {"content":"text","is_error":false}. Registered tools use
{"name":"tool_name","description":"...","parameters":{...JSON Schema...}}.
A before_compact result may set cancel, focus, output_reserve_tokens,
recent_tail_tokens, or both summary and retained_tail. Supplying a summary
without the complete retained tail is invalid.

Unknown input fields must be ignored. A hook must not return fields that are
invalid for its current event. Incompatible protocol changes require a new
protocol_version.

Hooks run sequentially in configuration order. Later transformations see
earlier ones. Permission aggregation is deny over allow over ask. A permission
hook that fails, times out, or returns invalid output denies the call.
Observational-hook failures are reported and ignored; failures in transforming
hooks stop the operation rather than silently changing its meaning.
