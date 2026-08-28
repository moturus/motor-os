# Gears

Gears is a small extensible agent harness that runs on Linux and Motor OS. Its
core owns provider streaming, one agent loop, cancellation, sessions, terminal
UIs, command hooks, and one built-in tool named sh. It does not prescribe a
coding workflow.

## Run

Set OPENROUTER_API_KEY or put the key in the configured key file, select a
model, and run:

    gears --model provider/model
    gears -p "answer once" --model provider/model
    gears ask --model provider/model "provider diagnostic"

Gears chooses the full-screen UI when both input and output are terminals.
Use --ui line or --ui tui to choose explicitly.

The sh tool receives one string command and runs it in the selected workspace
through sh -c on Linux or /system/bin/rush -c on Motor OS. It is not a
sandbox: an approved command has the same filesystem authority as Gears and
may leave the workspace. Stdout, stderr, status, timeout, cancellation, and
truncation remain distinct.

Permission hooks run before a tool call. Any deny wins; otherwise any allow
wins; otherwise an attended UI asks about the exact command. An unattended
run denies a call that still needs an answer. Gears does not infer safe shell
commands. The provider credential is removed from the environment inherited
by sh and hook processes.

## Configuration

The default configuration is ~/.config/gears.toml on Linux and
/user/cfg/gears.toml on Motor OS. A minimal file is:

    version = 1

    [provider]
    base_url = "https://openrouter.ai/api/v1"
    model = "provider/model"

    [models]
    used = ["provider/model", "another/model"]

Important optional fields are:

    [net]
    egress_allowlist = ["openrouter.ai"]

    [provider]
    key_file = "/absolute/path/to/key"
    ca_cert = "/absolute/path/to/ca.pem"

    [runtime]
    sh_timeout_seconds = 120
    max_tool_rounds = 32

    [context]
    window_tokens = 128000
    output_reserve_tokens = 16384
    recent_tail_tokens = 20000

Hooks are listed in execution order:

    [[hooks]]
    name = "project_policy"
    command = ["/absolute/path/to/hook", "--json"]
    timeout_seconds = 30
    max_output_bytes = 1048576

Configured hooks are trusted code and run with the user's authority. There is
no directory scan, shell interpolation, hot reload, or in-process extension
runtime. See [hook-protocol.md](hook-protocol.md) for the version-1 protocol.

## Sessions

Saved sessions are versioned append-only JSONL trees grouped by canonical
workspace:

- Linux: ~/.gears/sessions/
- Motor OS: /user/cfg/gears/sessions/

Each entry has an id and parent_id. Selecting an earlier entry changes only
the conversation branch; it does not undo commands or filesystem changes.
Only one process may write a saved session. A partial final record is ignored
after a crash, while earlier corruption is reported.

Useful startup options are --continue, --resume ID, --session ID,
--fork ID, --ephemeral, and --name NAME. Interactive commands include /new,
/resume, /name, /session, /tree, /label, /fork, /clone, and /compact. Use
/label ENTRY [TEXT] to set or clear an entry label. Fork selects an earlier
user prompt; clone copies the current active branch into a new file.

Compaction summarizes older active-branch context and retains a recent tail.
It appends a compaction entry but never deletes history. /compact accepts optional
focus text. Automatic compaction uses the configured context limit, output
reserve, and recent-tail size.

Prompt resources and hook/tool manifests are loaded from the current
installation when a session is opened. Their hashes are appended as a runtime
identity; a change produces one notice.

## Local tests

Automated tests never use an Internet provider:

    cargo fmt --manifest-path src/bin/gears/Cargo.toml -- --check
    cargo test --manifest-path src/bin/gears/Cargo.toml
    cargo clippy --manifest-path src/bin/gears/Cargo.toml --all-targets
    cargo test --manifest-path src/bin/gears-mock-provider/Cargo.toml

Build both development-image binaries with:

    make gears
    make gears-mock-provider

For a manual Linux smoke test, start the standalone TLS backend with
src/bin/curl/tests/server-cert.pem and server-key.pem:

    gears-mock-provider --addr 127.0.0.1:9443 --scenario streamed-text \
      --cert src/bin/curl/tests/server-cert.pem \
      --key src/bin/curl/tests/server-key.pem

Point a temporary config at https://127.0.0.1:9443/v1, set provider.ca_cert to
src/bin/curl/tests/test-ca.pem, allowlist 127.0.0.1, and run Gears with any
non-empty test key. The same gears-mock-provider binary is installed in the
Motor OS development image under /devtools/tests/gears/; copy the three test
certificate files into the VM and repeat with /devtools/bin/gears.

Use the streamed-text, sh-round, hook-round, compaction, interrupt-stream,
usage, malformed-response, and error scenarios as appropriate. A real-provider
check is separate, manual, and must be explicitly authorized.
