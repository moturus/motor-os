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
`PATH` that can change between invocations.

Gears reads tool directories only when they are explicitly listed in its
configuration. It does not recursively scan a project, download tools, compile
source, or run an installer.

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

[process]
timeout_seconds = 30                 # optional; default 30
max_output_bytes = 1048576           # optional; per stream
stdin = "arguments"                  # optional: arguments or null

[process.command]
common = ["./run"]
# linux = ["./run-linux"]            # optional platform override
# motor = ["./run-motor"]            # optional platform override
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
  checks the top-level shape and command placeholders, but does not implement
  a complete JSON Schema validator; the tool must still validate its input.
- `prompt`, when present, names a UTF-8 Markdown file in the same directory.
  Its non-empty contents become a system-prompt fragment only while the tool is
  enabled. Most tools should need only their description and schema.
- `display` is an optional template used for the permission prompt and generic
  TUI rendering. Without it, Gears displays the tool name and compact argument
  JSON.
- `process.timeout_seconds` is between 1 and 3600.
- `process.max_output_bytes` is between 1024 and 16777216 for each output
  stream.
- `process.stdin = "arguments"` writes the exact tool-call argument JSON to the
  child and closes stdin. `process.stdin = "null"` gives the child an empty,
  closed stdin.
- `process.command.common` supplies the command on both systems.
  `process.command.linux` or `process.command.motor` replaces it on that
  system. The selected vector must not be empty, and its program must be an
  absolute path or begin with `./`.

All referenced resource paths are relative, single-file paths inside the tool
directory: absolute paths and `..` are rejected. This keeps the reviewable
parts of a tool together. The command itself may deliberately name an absolute
system program because that is the program the external tool wraps.

### Command templates

An argument that consists entirely of `{field}` is replaced with the string
value of that field from the model's argument object. Substitution produces one
process argument; Gears never performs shell interpolation or word splitting.
Every placeholder must name a present string field. Literal command arguments
are passed unchanged.

For example:

```toml
[process.command]
linux = ["/bin/ls", "--", "{path}"]
motor = ["/system/bin/ls", "--", "{path}"]
```

with `{"path":"directory with spaces"}` runs the equivalent of the following
argument vector, not a shell command:

```text
["ls", "--", "directory with spaces"]
```

Tools needing optional fields, arrays, objects, or richer argument handling
should use a fixed command such as `["./run"]`, select
`process.stdin = "arguments"`, and parse the JSON themselves. Keeping the
template language this small avoids inventing a second shell.

`display` uses the same whole-field placeholders, but is presentation only. A
bad or missing placeholder makes that tool call fail visibly; it never falls
back to executing an ambiguous command.

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
Gears also provides `GEARS_TOOL_NAME`, `GEARS_WORKSPACE`, and
`GEARS_SESSION_ID`. The provider API key is removed from the environment.

Stdout and stderr are streamed separately to the UI and retained within the
configured bounds. The model-facing result contains the exit status and bounded
stdout/stderr, using the same representation that the current `sh` tool uses.
A non-zero exit status, timeout, cancellation, spawn failure, invalid argument
object, or invalid template is an error tool result. Timeout and cancellation
stop the process tree through the existing Linux or Motor OS backend.

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
2. Run permission hooks. Any deny, including failure of a configured
   permission hook, denies the call. Any allow executes it immediately.
3. If all hooks ask, consult matching session and global approval grants.
4. If no grant matches, ask an attended user; an unattended run denies.

Thus a saved grant never overrides a policy hook. External-tool manifests and
future loadable modules cannot bypass the same decision path.

An interactive approval prompt offers four choices:

```text
[y] allow once  [n] deny  [s] allow this tool for this session  [g] allow globally
```

`y` and `n` apply only to the pending call. `s` records an allow grant and then
runs the pending call. For a saved session, the grant survives resume; for an
ephemeral session it lasts until that session ends. A session grant belongs to
the whole session rather than its active conversation branch, so `/tree` does
not unexpectedly revoke or resurrect authority. Starting, forking, or cloning
to a new session does not copy grants.

`g` records an allow grant for the current user across sessions and workspaces,
then runs the pending call. Global grants are stored atomically in a separate
Gears-owned file:

- Linux: `~/.config/gears/permissions.toml`
- Motor OS: `/user/cfg/gears/permissions.toml`

A grant records the tool name, kind, owner, complete approval-identity hash,
and creation time. It does not constrain arguments: "allow this tool" means
all calls and all argument values exposed by that tool. In particular, a grant
for `sh` permits arbitrary shell commands, so the prompt must distinguish this
clearly from allowing the displayed command once.

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
approval again. The same four interactive choices apply to process and hook
tools and, later, to loadable tools.

The following slash commands make persistent authority inspectable and
revocable:

```text
/permissions
/permission revoke NAME
/permission revoke NAME --global
```

`/permissions` shows active session/global grants and a short approval-identity
fingerprint. Session revoke appends a session-wide revocation; global revoke
atomically removes matching global grants. Stale grants may be displayed for
diagnosis but never match a changed tool.

## Gears configuration

Available tools are listed explicitly:

```toml
[[tools]]
directory = "/home/me/.config/gears/tools/sh"
enabled = true

[[tools]]
directory = "/home/me/.config/gears/tools/ls"
enabled = false
```

`directory` must be absolute. `enabled` is the default when no later override
exists. Gears loads and validates every listed directory at startup, including
disabled tools, so a typo or duplicate name is found before a session begins.
No tools are available when the list is empty.

Gears ships reference `sh` and `ls` directories in `src/bin/gears/tools/`, but
does not silently enable them. A development configuration can point directly
at those directories. An installed configuration can point at copies placed in
the user's chosen location.

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

- Linux: `~/.config/gears/tools.toml`
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

`sh` has one required string parameter, `command`. Its manifest selects `sh -c`
on Linux and `/system/bin/rush -c` on Motor OS, uses `{command}` as the exact
permission detail, gives the child a closed stdin, and retains the current
120-second timeout. Once the registry is implemented, `sh` has no special
execution path in Rust.

`ls` has one required string parameter, `path`. It invokes `/bin/ls` on Linux
or `/system/bin/ls` on Motor OS directly with a single path argument and no
shell. Its purpose is to demonstrate a narrow external tool whose authority
and model interface are easier to review than arbitrary shell access.

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
