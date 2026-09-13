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
    cargo test --manifest-path src/bin/gears-mock-provider/Cargo.toml

The component gate runs the three crates' tests and selects the host build
of Motor curl through `MOTOR_CURL_TEST_PROGRAM` for the provider regression;
plain `cargo test` uses upstream curl there. The developer-image gate also
runs guest curl and Gears against the host mock's HTTP endpoint on the TAP
address:

    src/tests/full-test-dev.sh --release

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
usage, malformed-response, and error scenarios as appropriate. `--plain`
serves the same scenarios over HTTP without certificates, `--allow-non-loopback`
permits a non-loopback bind address and peer, and `--expect-model <name>`
also checks the model the client configured. A real-provider
check is separate, manual, and must be explicitly authorized.
