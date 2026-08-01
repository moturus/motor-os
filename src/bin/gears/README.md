# gears

An agentic coding harness for Motor OS: it drives frontier models over the
network and uses local tools — files, processes, the native toolchain — to do
real work on the machine it runs on. `proposal.md` is the design document and
`step-by-step-plan.md` the build order.

**Status: under construction, but it runs.** The transport, the provider
client, key handling, the file tools and the agent itself exist (plan steps
0–4): gears reads, writes and edits files under permission, keeps a session it
can be resumed from, and can put back everything it changed. Running commands,
the toolchain wrappers, version control, sub-agents and the Motor OS port are
still ahead (plan steps 5–10). Development happens on the Linux host — gears is
a standalone crate, built and tested with plain `cargo test`, and no test ever
talks to a real model provider.

## Usage

```
gears [OPTIONS]                 the interactive agent
gears -p PROMPT [OPTIONS]       one prompt, then exit
gears ask [-m MODEL] PROMPT     one prompt straight to the model

  --config PATH     read configuration from PATH instead of the default
  --workspace DIR   operate on DIR (default: the current directory)
  --log-file PATH   append a debug/wire trace to PATH
  --resume ID       continue the session with this id
  -p, --prompt TEXT answer one prompt and exit
  -m, --model ID    model id (default: provider.model in the config)
```

With no prompt gears reads them from the terminal, streaming the answer as it
arrives and asking before it changes anything:

```
$ gears
- session 1785595957-4023629
- anthropic/claude-sonnet-4.5 in /home/you/project
- /help for commands
gears> add a doc comment to parse_args
* read_file src/cli.rs
  4213 bytes
* edit_file src/cli.rs
allow edit_file src/cli.rs? [y]es / [n]o / [a]lways: y
  edited src/cli.rs
Done — parse_args now says what it does with `--`.
gears> /status
session 1785595957-4023629 | anthropic/claude-sonnet-4.5 | /home/you/project
2 completions, 6114 + 288 tokens, $0.0231 | 1 files changed
gears> /quit
```

Commands: `/status`, `/undo`, `/help`, `/quit`. A `^C` during a turn cancels
it; a `^C` at the prompt leaves.

`ask` is the spot check underneath all of it: one prompt to the configured
endpoint, the answer as it streams, no tools and no session. Use it to prove
an endpoint, a key and a model work before blaming anything else.

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

[permissions]
# "ask" (the default) puts every change to you. "auto-approve" puts nothing to
# you: it exists for gears' own test suite, which has no user to answer, and
# with it set a model can change any file in the workspace without a word.
mode = "ask"

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
toolchain wrappers, `fetch` and version control follow in later steps.

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

## Permission, and getting back

Every call that would **change** something is put to you before it runs:
`y` allows it once, `n` refuses it, `a` allows everything under that key from
now on. An "always" answer is remembered in
`<workspace>/.gears/permissions.toml`, one line per key — delete a line to be
asked about it again. A refusal is not an error: the model is told, in the
tool result, and can do something else or say why it needed to.

A one-shot `gears -p` has nobody at the keyboard, so anything the gate has not
already been told is refused, out loud. Scripted runs that are *meant* to go
through use `permissions.mode = "auto-approve"`.

gears does not commit on your behalf — it works on your checkout, and making
commits in one uninvited is invasive. Instead it copies each file the first
time it is about to change it, under `<workspace>/.gears/undo/<session>/`, and
`/undo` puts every one of them back the way the session found them. Files it
created are removed. (When `run` lands, what a *command* does is outside this;
that is what the gate is for.)

## Sessions

Every run keeps a transcript in `<workspace>/.gears/sessions/<id>.jsonl`,
written as it happens, and prints the id on the way in. `gears --resume <id>`
picks one up where it stopped — including after a failure, a cancelled turn or
a crash, because a turn that does not finish is not recorded as if it had. One
gears at a time per session, enforced by a lockfile that knows a stale one when
it sees it.

`<workspace>/.gears/` holds all of this. Add it to your `.gitignore`.

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
