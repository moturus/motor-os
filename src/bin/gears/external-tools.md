# Gears external tools

This document proposes the version-1 tool-directory contract. A tool directory
contains the model-facing description, JSON parameter schema, execution
settings, and any optional prompt text that Gears needs to expose and run one
tool. Version 1 supports external process tools. No Rust registration code,
hook, package manager, or in-process plugin runtime is required.

The goals are:

- adding a tool means creating one self-contained directory and naming it in
  the Gears configuration;
- disabled tools are not sent to the model and cannot be called;
- every enabled tool uses the existing permission, cancellation, output, and
  session machinery;
- a tool behaves the same on Linux and Motor OS unless its manifest explicitly
  selects different commands; and
- loading a tool never runs code. Code runs only after the model requests the
  tool and the normal permission decision allows it.

## Tool kinds and forward compatibility

The directory, configuration, enablement, authorization, provider schema, and
UI layers are independent of how a tool executes. `tool.toml` therefore has an
explicit `kind`. Version 1 accepts only:

```toml
kind = "process"
```

A process tool starts a child program and is the "external tool" described by
the rest of this document. A future version may add a loadable kind such as
`kind = "wasm"`, with a kind-specific table naming a WebAssembly module and its
capabilities. That work is deliberately out of scope for version 1: this design
does not select a WebAssembly runtime, ABI, WASI version, host-call surface, or
sandbox policy.

Future kinds must reuse the common tool name, description, parameter schema,
optional prompt, enablement precedence, scoped approvals, runtime identity,
and generic UI events. Each kind supplies only its loader/executor, detailed
result mapping, and an identity contribution for its executable artifact. An
unknown kind is a startup error rather than something Gears guesses how to
run. This separation lets process and loadable tools coexist without changing
the user's `[[tools]]` configuration or the model-facing tool protocol.

## Directory layout

A minimal directory contains two files:

```text
my_tool/
|-- tool.toml
`-- parameters.json
```

It may also contain an executable and a prompt fragment:

```text
my_tool/
|-- tool.toml
|-- parameters.json
|-- prompt.md          # optional
`-- run                # optional; name is chosen by tool.toml
```

`tool.toml` and `parameters.json` must be regular files. A relative executable
path beginning with `./` is resolved inside the tool directory. An absolute
program path may name a standard system command. Bare program names are
rejected: tool behavior and approval identity must not depend on an ambient
`PATH` that can change between invocations. The shipped `gears-batteries`
program is the one exception: Gears resolves that bare name beside its own
executable (`/devtools/bin` on Motor OS).

Gears reads tool directories only when they are explicitly listed in its
configuration. It does not recursively scan a project, download tools, compile
source, or run an installer. Installed copies live under `tools/` in the Gears
directory, `/user/cfg/gears/tools/` on Motor OS and `~/.gears/tools/` on
Linux, and one directory serves both systems: its manifest names a program
path per system and may give a description and argument schema per system,
and a tool that exists on one system only is simply absent on the other.

## Manifest

`tool.toml` has this version-1 shape:

```toml
version = 1
kind = "process"
name = "example"
description = "Describe exactly what the tool does for the model."
parameters = "parameters.json"
prompt = "prompt.md"                 # optional
display = "{path}"                   # optional permission/UI detail
read_only = false                    # optional; true only for read-only tools

[process]
timeout_seconds = 30                 # optional; default 30
max_output_bytes = 1048576           # optional; per stream
stdin = "arguments"                  # optional: arguments or null
output = "shell"                     # optional: shell or stdout
normal_exit_statuses = [0]           # optional; statuses that are normal outcomes

[process.command]
common = ["./run"]
# linux = ["./run-linux"]            # optional platform override
# motor = ["./run-motor"]            # optional platform override

# [motor]                            # optional per-system overrides of
# description = "..."                # description, parameters, prompt
# parameters = "parameters-motor.json"   # and display; [linux] likewise
```

The fields mean:

- `version` is exactly `1`.
- `kind` is exactly `"process"` in version 1. Execution fields live in the
  matching kind-specific table so a later loader does not inherit process-only
  concepts accidentally.
- `name` is the provider-visible tool name. It contains only ASCII letters,
  digits, `_`, and `-`, and must be unique across directory and hook tools.
- `description` is sent to the model and must be non-empty.
- `parameters` names a JSON file in the same directory. It must contain an
  object-valued JSON Schema. The schema is sent to the provider. Version 1
  checks the top-level shape and mapped property types, but does not implement
  a complete JSON Schema validator; the tool must still validate its input.
- `prompt`, when present, names a UTF-8 Markdown file in the same directory.
  Its non-empty contents become a system-prompt fragment only while the tool is
  enabled. Most tools should need only their description and schema.
- `display` is an optional template used for the permission prompt and generic
  TUI rendering. Without it, Gears displays the tool name and compact argument
  JSON.
- `[linux]` and `[motor]` may each give their own `description`, `parameters`,
  `prompt` and `display`, replacing the top-level value on that system. A
  program whose arguments differ between systems, as sysbox's `find` differs
  from GNU `find`, describes each version to the model exactly; a program
  that is the same on both, such as `rg`, needs only the top-level fields.
  `[linux.process.arguments]` and `[motor.process.arguments]` may replace the
  whole common argument mapping table on that system. Gears checks both tables
  against their effective parameter schemas when the directory loads.
- `read_only`, when true, declares that the tool only reads. The batteries
  use this mark when recording evidence. Tools still run in request order.
  A tool that writes, publishes or runs arbitrary commands leaves it false.
- `process.timeout_seconds` is between 1 and 3600.
- `process.max_output_bytes` is between 1024 and 16777216 for each output
  stream.
- `process.stdin = "arguments"` writes the exact tool-call argument JSON to the
  child and closes stdin. `process.stdin = "null"` gives the child an empty,
  closed stdin.
- `process.output = "shell"`, the default, gives the model the exit status
  and the bounded stdout and stderr, as the current `sh` tool does.
  `process.output = "stdout"` gives the model the child's stdout as plain text.
  Both modes retain the raw status and separate stdout and stderr in the result.
  Statuses listed in `normal_exit_statuses` are normal outcomes (`diff` and
  `rg` also list 1); any other status, signal, timeout or start failure is an
  execution error. Stderr alone is never an execution error.
- `process.command.common` supplies the command on both systems.
  `process.command.linux` or `process.command.motor` replaces it on that
  system. The selected vector must not be empty, and its program must be an
  absolute path or begin with `./`. A tool exists on a system when it has a
  command for it. A tool with no command for the running system, such as
  `lorry` on Linux or `cargo` on Motor OS, is still loaded and validated, is
  listed by `/tools` as not available on this system, is never sent to the
  model, and is not an error, so one configuration and one set of tool
  directories serve both systems.

All referenced resource paths are relative, single-file paths inside the tool
directory: absolute paths and `..` are rejected. This keeps the reviewable
parts of a tool together. The command itself may deliberately name an absolute
system program because that is the program the external tool wraps.

### Command arguments

The model supplies typed parameters, never a flag vector. `process.command`
contains only fixed arguments. `process.arguments.before_double_dash` and
`after_double_dash` list parameter names in output order; each name has a
`[process.arguments.NAME]` mapping table. Gears inserts one literal `--`
between the two groups when `after_double_dash` is non-empty. A field omitted
from a tool call adds nothing. Mapped fields must be declared in the JSON
schema, have the matching type, and may not appear twice in the order lists.
The schema's `required` array controls which fields may be omitted. Unmapped
properties are refused for command-mapped tools; tools with a fixed command
and `stdin = "arguments"` may instead validate all parameters themselves.

Mapping types are `string` (one whole argument), `boolean_flag` (a fixed
`flag` when true), `integer_option` (a fixed `flag` followed by a decimal
integer), `enum` (one fixed argument selected by a `values` table), and
`string_list` (one argument per element, only after `--`). Fixed flags and
enum outputs belong to the manifest; only string and list values from the
model are subject to the leading-`-` rule below. Gears never performs shell
interpolation or word splitting. Invalid or missing required values fail
before execution.

For example:

```toml
[process.command]
linux = ["/bin/ls"]
motor = ["/system/bin/sysbox", "ls"]

[process.arguments]
after_double_dash = ["path"]

[process.arguments.path]
type = "string"
```

with `{"path":"directory with spaces"}` runs the equivalent of the following
argument vector, not a shell command:

```text
["ls", "--", "directory with spaces"]
```

For example, a tool with `before_double_dash = ["ignore_case", "count"]`
could map `ignore_case` to `type = "boolean_flag", flag = "-i"` and `count`
to `type = "integer_option", flag = "-m"`; a `mode` field could use
`type = "enum", values = { names = "-l", details = "-a" }`. These fixed
flags appear before `--`, while each value of a `string_list` field appears
after it.

Tools with behavior beyond these mappings may use a fixed command such as
`["./run"]`, select `process.stdin = "arguments"`, and validate the JSON
themselves. Shipped common commands use typed mappings so the schema and
their actual argument vector can be reviewed together.

`display` is presentation only. Its `{name}` placeholders occupy standalone
whitespace-separated fields and refer to schema properties. Values are shown
as JSON, so spaces and control characters are visible. A bad or missing
placeholder makes that tool call fail visibly; it never falls back to
executing an ambiguous command.

A model string value beginning with `-` is refused unless it is placed after
the inserted `--` or is exactly listed in the manifest's `allowed_flags`
(such as `--release` for `lorry`). Allowed values from either group go before
`--`. The shipped manifests
put `--` before free-form paths and patterns; in a prototype, a search path
of `--pre=sh` made `rg` run arbitrary commands. Each shipped common command's
typed parameters are specified before its tool directory is built. GNU
`find -exec` runs commands, so the Linux read-only `find` tool offers only
name, type and path parameters.

## Process execution contract

The child process always starts with its working directory set to the selected
Gears workspace: the `--workspace` directory when supplied, otherwise the
directory from which Gears was started. Relative paths used by the program and
passed by the model therefore resolve in the workspace, not in the tool
package. Gears canonicalizes the workspace while opening the session.

A relative program beginning with `./` is resolved against the tool directory
before the child starts, so changing the child's working directory does not
make a packaged executable disappear. A tool that needs its own data files can
use `GEARS_TOOL_DIR`; it should not assume its package is the working directory.
Gears also provides `GEARS_TOOL_NAME`, `GEARS_WORKSPACE`, `GEARS_SESSION_ID`,
and, when the session is saved to disk, `GEARS_SESSION_PATH`, as hooks
receive it. The provider API key is removed from the environment.

Stdout and stderr are streamed separately to the UI and retained within the
configured bounds. The result keeps both streams and the raw exit status,
separate from its execution-error flag. A status outside the manifest's normal
set, signal, timeout, cancellation, spawn failure, invalid argument object,
or invalid template is an error. Stderr alone is not. Timeout and cancellation
stop the process tree through Gears' shared runner.

External tools are trusted code. Running an approved process tool grants it the
user's filesystem and process authority. The directory format is a packaging
and review boundary, not a sandbox or signature scheme.

For a future loadable tool, "workspace" remains the logical starting directory,
but the loader may expose it through a capability-limited virtual filesystem
rather than as unrestricted host process state. The WebAssembly design must
specify that boundary instead of inheriting process-tool authority by accident.

## Authorization and approval scopes

Enablement and authorization are separate. Enabling a tool makes its schema
available to the model; it does not grant permission to execute it. A global
approval also does not enable a disabled tool.

Every call follows this order:

1. Reject an unknown or disabled tool without executing it.
2. Look up matching session and global grants for the approval identity on
   every call. A session grant beats a global grant; within a scope the latest
   answer wins. A saved denial refuses the call.
3. Run permission hooks. A hook denial or failure refuses the call. A hook's
   `confirm` asks the attended user for fresh confirmation and refuses an
   unattended call. A hook allowance runs the call.
4. Without a hook decision, a saved allowance runs an attended call. Saved
   allowances do not apply in `-p` runs, including workers and jobs. With
   neither, ask the attended user or refuse the unattended call.

The saved answer is checked before a hook can allow anything. A hook's
`confirm` requires fresh confirmation even after a saved allowance.

An interactive approval prompt offers six choices, allow or deny at each of
three scopes:

```text
[y] allow once   [s] allow this tool for this session   [g] allow globally
[n] deny once    [S] deny this tool for this session    [G] deny globally
```

`y` and `n` apply only to the pending call. `s` records an allow grant and then
runs the pending call; `S` records a deny grant and refuses it, and later calls
of the same identity in the session are refused without asking. For a saved
session, a grant survives resume; for an ephemeral session it lasts until that
session ends. A session grant belongs to the whole session rather than its
active conversation branch, so `/tree` does not unexpectedly revoke or
resurrect authority. Starting, forking, or cloning to a new session does not
copy grants.

`g` and `G` record an allow or deny grant for the current user across sessions
and workspaces, then run or refuse the pending call. Global grants are stored
atomically in a separate Gears-owned file:

- Linux: `~/.gears/permissions.toml`
- Motor OS: `/user/cfg/gears/permissions.toml`

A grant records the tool name, kind, owner, complete approval-identity hash,
its direction (allow or deny), and creation time. It does not constrain
arguments: "allow this tool" means all calls and all argument values exposed
by that tool. In particular, a grant for `sh` permits arbitrary shell
commands, so the prompt must distinguish this clearly from allowing the
displayed command once.

If a session or global grant cannot be written, Gears does not run the call
under the requested persistent scope. It reports the write error and returns
to an unapproved state rather than silently treating the choice as `y`.

Grants bind to a tool approval identity, not merely its display name. The
identity includes the name, kind, model-facing schema, owner, execution
settings, prompt, manifest, and hashes of package-controlled executable
resources. A process tool using an absolute system program also includes the
selected command vector and path; its grant deliberately trusts later updates
to that system program. A future WebAssembly tool must include the module hash.
A hook tool includes its owner hook, registered specification, and configured
hook command. Changing an identity makes old grants non-matching and requires
approval again. The same six interactive choices apply to process and hook
tools and, later, to loadable tools.

The following slash commands make persistent authority inspectable and
revocable:

```text
/permissions
/permission revoke NAME
/permission revoke NAME --global
```

`/permissions` shows active session/global grants, each with its direction
and a short approval-identity fingerprint. Session revoke appends a
session-wide revocation; global revoke atomically removes matching global
grants. Stale grants may be displayed for
diagnosis but never match a changed tool.

## Gears configuration

Available tools are listed explicitly:

```toml
[[tools]]
directory = "tools/sh"               # relative to the Gears directory
enabled = true

[[tools]]
directory = "tools/ls"
enabled = false
```

`directory` is absolute, or relative to the Gears directory: `/user/cfg/gears`
on Motor OS and `~/.gears` on Linux. Phase 2.1 moves `gears.toml` into that
directory; phase 3's tool registry reads it there. The directory also holds
`tools.toml`, `permissions.toml`, the tool directories under `tools/`, the
sessions and the batteries' data. Gears reads `gears.toml` from there first
and from the earlier locations, `/user/cfg/gears.toml` and
`~/.config/gears.toml`, when it is absent; `api_key_file` (renamed from
`key_file`, which stays accepted) and
`ca_cert` in it may be relative to the directory as well. `enabled` is the
default when no later override exists. Gears loads and validates every listed
directory at startup, including disabled tools and
tools absent on this system, so a typo or duplicate name is found before a
session begins. No tools are available when the list is empty.

Gears ships reference directories in `src/bin/gears/tools/` for `sh`, `ls` and
the common commands listed under "Shipped reference tools", but does not
silently enable any of them. A development configuration can point directly
at those directories; the developer image places copies under
`/user/cfg/gears/tools/`, and a Linux user copies them under `~/.gears/tools/`.
One configuration lists them all on both systems: a directory whose program a
system lacks is shown by `/tools` as not available there.

### Enablement precedence

Enablement has three layers, from lowest to highest precedence:

1. the `enabled` value in the main configuration;
2. a global override written by an interactive slash command; and
3. the latest override on the active branch of the current session.

Session overrides are append-only session entries. They survive resume, follow
the selected branch, and are copied by fork/clone in the same way as other
session state. An ephemeral session keeps them only in memory.

Global slash commands do not rewrite the user's main TOML, which may contain
comments and deliberate formatting. They atomically update a small,
Gears-owned versioned file:

- Linux: `~/.gears/tools.toml`
- Motor OS: `/user/cfg/gears/tools.toml`

That file maps tool names to booleans and contains no discovery paths or
executable configuration. Removing a global override restores the main
configuration default.

```toml
version = 1

[tools]
sh = true
ls = false
```

Changing enablement rebuilds the effective prompt and provider tool list and
appends the resulting runtime identity to the session. It does not alter old
messages or tool results. A model cannot call a disabled tool because it is
absent from the request; a stale or malformed provider call receives an
`unknown or disabled tool` error and is never executed.

Hook-registered tools are outside this toggle mechanism in version 1. Their
owner hook controls their lifetime. This keeps a directory tool's enablement
independent of whether an unrelated hook happens to be configured.

## Slash commands

Both interactive UIs support the same commands:

```text
/tools
/tool enable NAME
/tool disable NAME
/tool reset NAME
/tool enable NAME --global
/tool disable NAME --global
/tool reset NAME --global
```

`/tools` lists every configured directory tool, its effective state, and the
layer that supplied that state (`config`, `global`, or `session`). Session
enable/disable commands append an override to the current session; session
reset appends an `inherit` value so the global or main-config value applies
again. A global enable/disable updates only the global layer, and global reset
removes that override. A session override remains higher precedence, so a
global change affects the current session immediately only when that session
is inheriting its value.

Commands run only while the UI is idle; they cannot change the advertised tool
set in the middle of a provider turn. Errors are rendered as ordinary visible
notices and leave the previous state unchanged.

## Shipped reference tools

`sh` has one required string parameter, `command`. Its manifest selects `bash -c`
on Linux and `/system/bin/rush -c` on Motor OS, uses `{command}` as the exact
permission detail, gives the child a closed stdin, and retains the current
120-second timeout. Its working directory and exported variables persist
between calls on both systems. Once the registry is implemented, `sh` has no
special execution path in Rust.

`ls` has one required string parameter, `path`. It invokes `/bin/ls` on Linux
or `/system/bin/sysbox ls` on Motor OS directly with a single path argument
and no shell. Its purpose is to demonstrate a narrow external tool whose authority
and model interface are easier to review than arbitrary shell access.

The common commands follow the `ls` pattern, each a manifest naming the
program's path per platform, a one-line description, typed parameters mapped
to a fixed argument vector, and a timeout. The read-only ones, `rg`, `head`,
`tail`, `diff`, `find`, `wc` and `cat`, set `read_only = true`. The ones that
change or publish things, `gix`, `lorry`, `cargo` and `sed`, leave it false.
`curl` fetches one HTTP or HTTPS URL without following redirects.
Running a command as its own tool gives it its own approval identity, so
allowing `lorry` for a session does not allow arbitrary shell commands, and
lets a policy hook allow the read-only ones without asking. Where the two
systems' programs take different arguments, sysbox's `ls`, `find`, `head`,
`tail`, `diff`, `wc` and `cat` against their GNU counterparts, the manifest
gives a description and schema per system. Sysbox-backed Motor OS tools call
`/system/bin/sysbox COMMAND` directly, preserving spaces and literal glob
characters in arguments. `gix` and `lorry` have a command
for Motor OS only and `cargo` for Linux only; on the other system each is
listed as not available and never offered to the model.

Pipeline filters are not shipped as tools: `sort`, `uniq`, `cut` and `tr`
(the batteries plan's sysbox track) do their work between pipes, which
only `sh` has, and `xargs` runs other programs, so it belongs behind the
shell's approval rather than an identity of its own.

## Adding a tool

1. Create a directory and write a `kind = "process"` `tool.toml`.
2. Add an object-valued JSON Schema as `parameters.json`.
3. Add an executable only if a standard system program is insufficient. Make
   it accept argument JSON on stdin and return useful stdout, stderr, and exit
   status.
4. Add `prompt.md` only when the tool genuinely needs instructions beyond its
   description and schema.
5. Add one `[[tools]]` entry to the Gears configuration with `enabled = false`.
6. Start Gears and inspect `/tools`, then enable the tool for a disposable or
   ephemeral session.
7. Exercise valid input, malformed input, denial, non-zero exit, timeout,
   cancellation, and output truncation on Linux and Motor OS before enabling it
   globally.

Repository-provided tools also need hermetic tests that inspect the provider
request and execute against local fixtures only. Automated tests must never use
a real model provider or depend on Internet access.
