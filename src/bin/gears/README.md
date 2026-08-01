# gears

An agentic coding harness for Motor OS: it drives frontier models over the
network and uses local tools — files, processes, the native toolchain — to do
real work on the machine it runs on. `proposal.md` is the design document and
`step-by-step-plan.md` the build order.

**Status: under construction.** The transport, the provider client, key
handling and the file tools exist (plan steps 0–3); the agent loop and the
REPL do not yet, so a plain `gears` invocation still says so and exits — which
also means nothing drives the tools described below. What works today is
`gears ask`. Development happens on the Linux host — gears is a standalone
crate, built and tested with plain `cargo test`, and no test ever talks to a
real model provider.

## Usage

```
gears ask [-m MODEL] PROMPT     one prompt, one answer
gears [OPTIONS]                 the agent loop (not implemented yet)

  --config PATH     read configuration from PATH instead of the default
  --workspace DIR   operate on DIR (default: the current directory)
  --log-file PATH   append a debug/wire trace to PATH
  -m, --model ID    model id for 'ask'
```

`ask` is the spot check: it sends one prompt to the configured endpoint and
prints the answer as it streams, with none of the agent loop in the way. Use it
to prove an endpoint, a key and a model work.

## Configuration

TOML, at `~/.config/gears.toml` on the host and `/user/cfg/gears.toml` on Motor
OS, or wherever `--config` says. Every field is optional except `version`, and
unknown fields are ignored so that a newer config still loads in an older
binary.

```toml
version = 1

[provider]
# Any OpenAI-compatible chat-completions endpoint. OpenRouter is the default
# and the only one tested against a real key; others work but are untested.
base_url = "https://openrouter.ai/api/v1"
model = "anthropic/claude-sonnet-4.5"   # no default: name one, or pass -m
key_file = "/home/you/.config/gears/openrouter.key"   # optional; see below

[net]
# The hosts gears may talk to, matched exactly — a subdomain is not implied by
# its parent. Pointing base_url elsewhere means adding that host here.
egress_allowlist = ["openrouter.ai"]

[trace]
file = "/tmp/gears.log"
level = "info"   # error, warn, info, debug
```

There is one more `[net]` field, `allow_plain_http_loopback`, which lets gears
speak plain HTTP to `127.0.0.1`. **It exists for gears' own test suite**, whose
mock endpoint is an in-process HTTP server, and there is no reason to set it
otherwise: real traffic is HTTPS, the allowlist still applies, and on Motor OS
the curl crate refuses plain HTTP outright.

## Tools

What the model is allowed to do. The file tools exist today; `run`, the
toolchain wrappers, `fetch` and version control follow in later steps, and
every mutating call will pass an interactive permission gate.

| Tool | |
|---|---|
| `read_file` | one file; a file too long to return whole comes back with its middle elided |
| `write_file` | create or replace a file, creating parent directories |
| `edit_file` | replace one *exact* occurrence of a string; ambiguity is refused, not guessed |
| `list_dir` | one directory; `/` marks directories, `@` symlinks |
| `grep` | literal search — not a regex — with an optional `*.rs`-style filter |

The **workspace** — `--workspace DIR`, default the current directory — is the
boundary: no tool reads or writes outside it, whether the path climbs with
`..`, arrives absolute, or goes through a symlink pointing out of the tree.
Two things inside it are off limits as well: `.gears/`, gears' own state, and
the API key file. `.git/`, `target/` and `.gears/` are skipped when listing and
searching, though an explicit path into `target/` still works.

This is policy inside gears, not enforcement by the OS — the honest v1 posture.
`run`, when it lands, is the deliberate escape hatch from all of it, which is
why it is gated per command.

## The API key

gears reads one secret, and only over one path.

* **`OPENROUTER_API_KEY`** in the environment wins when it is set — the
  one-off, "just this run" form. gears removes it from its own environment at
  startup, so tools it later spawns (cargo, git, whatever a model asks it to
  run) do not inherit it.
* Otherwise the **key file**: `provider.key_file`, or
  `~/.config/gears/openrouter.key` on the host and
  `/user/cfg/gears/openrouter.key` on Motor OS. One line, trailing newline
  fine. Paths are taken literally — `~` is not expanded.

The variable keeps that name whichever endpoint you point gears at: it is one
name for one secret, not a claim about the vendor.

The key never reaches an argument vector — the transport hands it to its curl
child through the environment and expands it into the `Authorization` header
there — and never reaches a log or the terminal: it is registered for redaction
as soon as it is read, so even an endpoint that quotes it back in an error
message gets `[redacted]` instead. The agent's own file tools will not be able
to read the key file either: its path goes on their deny-list when they arrive
(plan step 3).

Two further practices, neither of which needs anything from gears:

* **Budget-capped provisioned keys.** Mint a runtime key with a hard spend
  limit (OpenRouter's provisioning API does this) and give gears that one. A
  leaked key is then a bounded loss rather than an open account — worth doing
  on a VM, where the VM itself is the trust boundary.
* **A host-side auth proxy.** Point `base_url` at a small forwarder on the host
  that injects the real key, and add its host to the egress allowlist. The key
  never enters the VM at all. The same shape covers a local inference server:
  no cloud egress, and no key anywhere.

## Development

```
cargo test              # everything; never touches the network beyond loopback
cargo +nightly fmt
cargo clippy --all-targets
```

The test suite drives the real `curl` binary against an in-process mock server
that serves scripted, deliberately fragmented responses. Runs against a real
provider are manual, and `gears ask` is the tool for them. Host curl 8.3 or
newer is required — that is where `--expand-header` arrived, which is what
keeps the key off the command line.
