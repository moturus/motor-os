# Gears

Gears is a small extensible agent harness that runs on Linux and Motor OS. Its
core owns provider streaming, one agent loop, cancellation, sessions, terminal
UIs, command hooks, and configured directory tools. It does not prescribe a
coding workflow.

## Run

Set OPENROUTER_API_KEY or put the key in the configured key file, select a
model, and run:

    gears --model provider/model
    gears -p "answer once" --model provider/model
    gears ask --model provider/model "provider diagnostic"

Gears chooses the full-screen UI when both input and output are terminals.
Use --ui line or --ui tui to choose explicitly.

The optional `tools/sh` directory receives one string command and runs it in
the selected workspace through `bash -c` on Linux or `/system/bin/rush -c` on
Motor OS. It is not a
sandbox: an approved command has the same filesystem authority as Gears and
may leave the workspace. Stdout, stderr, status, timeout, cancellation, and
truncation remain distinct.

Gears checks saved permission grants before hooks. A saved denial or hook
denial blocks the call. A hook may allow it or require fresh confirmation.
Otherwise a saved allowance runs only in an attended UI, which asks when no
answer is saved. The choices are `y/s/g` to allow once, for this session, or
globally, and `n/S/G` to deny at those scopes. Session grants survive resume;
new, forked, and cloned sessions do not inherit them. In `-p` runs, saved
allowances are ignored and calls without hook authority are denied. Gears does
not infer safe shell commands. The provider credential is removed from the
environment inherited by tool and hook processes.

## Configuration

The default configuration is ~/.gears/gears.toml on Linux and
/user/cfg/gears/gears.toml on Motor OS. A minimal file is:

    version = 1

    [provider]
    base_url = "https://openrouter.ai/api/v1"
    model = "provider/model"

No directory tool is enabled by default. To add the shipped shell tool, copy
`tools/sh` into the Gears directory and add:

    [[tools]]
    directory = "tools/sh"
    enabled = true

    [models]
    used = ["provider/model", "another/model"]

[config/gears.toml](config/gears.toml) lists all shipped directories with tools
disabled. Copy it and `tools/` into the Gears directory for the complete
example. Linux manifests for `rg` and `cargo` use `/usr/bin`; adjust their
absolute executable paths for other installations.

Important optional fields are:

    [net]
    egress_allowlist = ["openrouter.ai"]

    [provider]
    key_file = "/absolute/path/to/key"
    ca_cert = "/absolute/path/to/ca.pem"

    [runtime]
    max_tool_rounds = 32

    [context]
    window_tokens = 128000
    output_reserve_tokens = 16384
    recent_tail_tokens = 20000

The optional batteries coding workflow has a separate sample configuration,
[`config/gears-batteries.toml`](config/gears-batteries.toml). Install it in
your Gears directory with the contents of `tools/`, and install
`gears-batteries` beside `gears`.
The developer image supplies those files. Start from your workspace with:

```sh
gears --config /user/cfg/gears/gears-batteries.toml --model MODEL
```

On Linux, use `~/.gears/gears-batteries.toml` as the configuration path.
The sample selects OpenRouter and reads `openrouter.key` beside the config.
For a local OpenAI-compatible server, set `providers.local.base_url` and
select `--provider local --model MODEL`. Only loopback HTTP is enabled.
If the server uses another host, add it to both `net.egress_allowlist` and
`net.plain_http_allowlist` when using HTTP.
Put the local server's key in `local.key` beside the config; for a server
that ignores authentication, that file can contain a placeholder such as
`local`. Explicit keys are required for HTTP providers.
The sample registers project instructions and `todo`, enables the six
batteries tools plus shell, Gix, Lorry and curl, and applies the batteries
approval policy. Declare a literal check vector in the workspace's
`.gears/batteries.toml`, for example `check = ["lorry", "test"]` on Motor OS
or `check = ["cargo", "test", "--offline"]` on Linux.
See the [batteries guide](batteries.md) for check evidence,
file-read requirements and policy limits.

Hooks are listed in execution order:

    [[hooks]]
    name = "project_policy"
    command = ["/absolute/path/to/hook", "--json"]
    events = ["permission", "tool_result"]
    timeout_seconds = 30
    max_output_bytes = 1048576

Omitting `events` receives every event. An explicit list starts the hook only
for those events; `events = []` disables its invocations. Include `initialize`
to register prompt fragments or tools, and `tool_execute` to execute its tools.

Configured hooks are trusted code and run with the user's authority. There is
no directory scan, shell interpolation, hot reload, or in-process extension
runtime. See [hook-protocol.md](hook-protocol.md) for the version-1 protocol.

Hooks can register slash commands with help text. Their one-line hints appear
in the TUI status line and after turns or hook commands in the line UI. An
empty hint clears the current text; JSONL exposes updates as `hint` records.

## Sessions

Saved sessions are versioned append-only JSONL trees grouped by canonical
workspace:

- Linux: ~/.gears/sessions/
- Motor OS: /user/cfg/gears/sessions/

Each entry has an id and parent_id. Selecting an earlier entry changes only
the conversation branch; it does not undo commands or filesystem changes.
Only one process may write a saved session. A partial final record is ignored
after a crash, while earlier corruption is reported.

Interactive UIs display the saved active branch when a session is opened or
selected, including messages from before compaction. The full-screen UI
keeps the latest 1 MiB of display text; Page Up and Page Down scroll it.
Displaying history does not rerun tools or request a model response.
One-shot text and JSONL output contain only the new run's output.

Gears also locks its user directory for the lifetime of the run. A second
independent Gears is refused; nested runs share their checked ancestor's lock.
Stale locks are replaced when their owner is gone or identified as another
program. Motor OS exposes a short command name rather than an executable
identity, so a live owner with a truncated or unreadable name keeps its lock
until it exits.

Library callers can use `session::read_snapshot(path)` or `Store::read(id)`
while the owning process writes. The immutable snapshot includes the usable
complete prefix, omits unfinished records and tool rounds, and leaves the
source file and writer lock untouched. `Store::clone_active_with_options`
can copy that snapshot into a saved or ephemeral child session.
The CLI accepts `--fork ID --ephemeral -p 'summarize this work'` to read a live
parent's usable history and run a child without saving its conversation.
Add `--fork-entry ENTRY` to end the copy at an exact saved entry, including
one from before a later compaction. An unknown entry or unfinished tool round
is refused; the source session remains unchanged and writable.

For machine-readable one-shot output, use `-p PROMPT --output jsonl`.
Version 1 starts with a `session` record containing `session_id`, `path`
(null for an ephemeral session), and `session_format_version`. Streaming
records have types `text`, `reasoning`, `tool_start`, `tool_output`,
`tool_result`, `permission`, `notice`, `usage`, and `turn_end`. Tool results
include the call id, error flag, and three-state outcome. Every record is
one flushed JSON line; embedded newlines are escaped.

The last `final` record contains `success`, `answer`, `error`, and numeric
`usage` for this run, including compaction requests. `session_usage` includes
earlier history too. Unknown cost is null; `cost_is_partial` identifies a
partly priced total. A failed turn produces a final error and a nonzero
exit status. Errors before a session is ready use stderr. JSONL runs are
unattended and follow the same permission rules as other `-p` runs.

Useful startup options are --continue, --resume ID, --session ID,
--fork ID, --ephemeral, and --name NAME. Interactive commands include /new,
/resume, /name, /session, /tree, /label, /fork, /clone, /compact, /tools,
/tool, /permissions, and /permission. Use
/label ENTRY [TEXT] to set or clear an entry label. Fork selects an earlier
user prompt; clone copies the current active branch into a new file.
Use `/tool enable|disable|reset NAME [--global]` to change a directory tool's
effective state and `/permission revoke NAME [--global]` to remove grants.

Compaction summarizes older active-branch context and retains a recent tail.
It appends a compaction entry but never deletes history. /compact accepts optional
focus text. Automatic compaction uses the configured context limit, output
reserve, and recent-tail size.

Prompt resources and hook/tool manifests are loaded from the current
installation when a session is opened. Their hashes are appended as a runtime
identity; a change produces one notice.

## A llama.cpp server on the VM host

Build and boot the development image from the repository root after setting
up the Motor toolchain:

    make -j"$(nproc)" dev.img BUILD=release
    vm_images/release/run-dev.sh

With the standard TAP setup, the host address is 192.168.4.1 and the guest is
192.168.4.2. Restore the TAP after a host reboot with
`vm_images/release/create-tap.sh` if needed. On the host, start llama.cpp with
your model, using a context size the model supports:

    llama-server -m /absolute/path/to/model.gguf --alias local \
      --host 192.168.4.1 --port 8080 --ctx-size 32768 --parallel 1 --jinja

Tool use requires a model and chat template supporting tool calls. Inside
Motor OS, create a separate placeholder credential for an unauthenticated
local server and clear any inherited cloud credential:

    mkdir -p /user/cfg/gears
    echo local-llama > /user/cfg/gears/local-llama.key
    unset OPENROUTER_API_KEY

Save this as `/user/cfg/gears.toml`:

```toml
version = 1

[provider]
base_url = "http://192.168.4.1:8080/v1"
model = "local"
key_file = "/user/cfg/gears/local-llama.key"

[net]
egress_allowlist = ["192.168.4.1"]
plain_http_allowlist = ["192.168.4.1"]

[context]
window_tokens = 32768
output_reserve_tokens = 4096
recent_tail_tokens = 8192
```

The HTTP list must be a subset of the egress list. Both use exact host
matching: an entry permits any port on that host, not just port 8080. HTTP
sends prompts and any bearer key without encryption. HTTPS remains the
default; a TLS failure never falls back to HTTP. A plaintext `base_url`
whose host is missing from either list is refused when the config loads.
OpenRouter receives earlier assistant reasoning on subsequent turns. Other
hosts omit it by default; set `reasoning_echo = true` or `false` under
`[provider]` or a named `[providers.NAME]` to override the host default.

Gears refuses implicit default-key-file fallback over HTTP. An explicit key
file is allowed, but `OPENROUTER_API_KEY` takes precedence even if inherited
from the shell. Keep it unset for the file-based setup, or explicitly use
`OPENROUTER_API_KEY=local-llama` for a one-off invocation. If the server uses
authentication, supply its matching key instead of the placeholder.

Check the host connection and start Gears from the desired guest workspace:

    /system/bin/curl --proto =http http://192.168.4.1:8080/health
    /devtools/bin/gears ask "Reply with a short hello."
    /devtools/bin/gears

Use `--ui line` for the line interface or `-vv` for transport diagnostics.
Gears appends `/chat/completions` to the configured API root. Match the Gears
context settings to the server's context capacity.

## Local tests

Automated tests never use an Internet provider:

    bash src/tests/test-gears-http.sh
    bash src/tests/test-gears-http.sh --release
    cargo fmt --manifest-path src/bin/gears/Cargo.toml -- --check
    cargo test --manifest-path src/bin/gears/Cargo.toml
    cargo clippy --manifest-path src/bin/gears/Cargo.toml --all-targets
    cargo test --manifest-path src/bin/gears/Cargo.toml --example mock-provider

The component gate runs the package's tests and the mock provider's tests,
and selects the host build of Motor curl through `MOTOR_CURL_TEST_PROGRAM` for
the provider regression; plain `cargo test` uses upstream curl there. The
developer-image gate also runs guest curl and Gears against the host mock's
HTTP endpoint on the TAP address:

    src/tests/full-test-dev.sh --release

Build the development-image binaries and test programs, including the
`gears-mock-provider` TLS backend (the `mock-provider` example), with:

    make gears

For a manual Linux smoke test, start that backend with
src/bin/curl/tests/server-cert.pem and server-key.pem:

    cargo run --manifest-path src/bin/gears/Cargo.toml --example mock-provider -- \
      --addr 127.0.0.1:9443 --scenario streamed-text \
      --cert src/bin/curl/tests/server-cert.pem \
      --key src/bin/curl/tests/server-key.pem

Point a temporary config at https://127.0.0.1:9443/v1, set provider.ca_cert to
src/bin/curl/tests/test-ca.pem, allowlist 127.0.0.1, and run Gears with any
non-empty test key. It is installed as gears-mock-provider in the
Motor OS development image under /devtools/tests/gears/; copy the three test
certificate files into the VM and repeat with /devtools/bin/gears.

Use the streamed-text, sh-round, hook-round, compaction, interrupt-stream,
usage, malformed-response, and error scenarios as appropriate. `--plain`
serves the same scenarios over HTTP without certificates, `--allow-non-loopback`
permits a non-loopback bind address and peer, and `--expect-model <name>`
also checks the model the client configured. A real-provider
check is separate, manual, and must be explicitly authorized.
