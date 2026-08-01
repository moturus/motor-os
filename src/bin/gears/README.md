# gears

An agentic coding harness for Motor OS: it drives frontier models over the
network and uses local tools — files, processes, the native toolchain — to do
real work on the machine it runs on. `proposal.md` is the design document and
`step-by-step-plan.md` the build order.

**Status: under construction, but it runs.** The transport, the provider
client, key handling, the file tools, the agent itself, the process tools and
the version-control tools exist (plan steps 0–6): gears reads, writes and edits
files, runs commands, builds and tests crates, fetches URLs and commits what it
changed — all under permission — keeps a session it can be resumed from, and
can put back every file it changed. Sub-agents, context management,
self-hosting and the Motor OS port are still ahead (plan steps 7–10).
Development happens on the Linux
host — gears is a standalone crate, built and tested with plain `cargo test`,
and no test ever talks to a real model provider.

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
gears> add a doc comment to parse_args, then check it still builds
* read_file src/cli.rs
  [+] 4213 bytes
* edit_file src/cli.rs
allow edit_file src/cli.rs? [y]es / [n]o / [a]lways: y
  edited src/cli.rs
* build
allow build? [y]es / [n]o / [a]lways: a
  [+] 312 bytes
Done — parse_args now says what it does with `--`, and it still builds.
gears> /+
--- build (312 bytes) ---
exit status 0
   Compiling demo v0.1.0 (/home/you/project)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.61s
gears> /status
session 1785595957-4023629 | anthropic/claude-sonnet-4.5 | /home/you/project
2 completions, 6114 + 288 tokens, $0.0231 | 1 files changed
gears> /quit
```

Commands: `/status`, `/+`, `/undo`, `/help`, `/quit`. A `^C` during a turn
cancels it; a `^C` at the prompt leaves.

A finished call gets one line, and a result too big for one — a file, a build
log, a page of search hits — is reported by size. **`[+]` means the model got
more than the screen is showing**, and `/+` prints that result whole, under a
header naming the call it came from; `/+ 2` reaches the one before it, and so
on back through the last quarter-megabyte or so. A bare `+` does the same.
The full result is in the session transcript either way — this only saves
going to look.

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
# with it set a model can change any file in the workspace, run any command
# and fetch any host without a word.
mode = "ask"

[tools]
# How long a command may run before it and everything it started are killed.
# A build is given minutes because that is what a build takes; an hour is the
# most gears will wait for anything.
run_timeout_seconds = 120
build_timeout_seconds = 900

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

What the model is allowed to do.

| Tool | |
|---|---|
| `read_file` | one file; a file too long to return whole comes back with its middle elided |
| `write_file` | create or replace a file, creating parent directories |
| `edit_file` | replace one *exact* occurrence of a string; ambiguity is refused, not guessed |
| `list_dir` | one directory; `/` marks directories, `@` symlinks |
| `grep` | literal search — not a regex — with an optional `*.rs`-style filter |
| `run` | run a program, no shell; stdout and stderr merged, killed on timeout |
| `build`, `test` | compile and test a crate with the native toolchain, diagnostics verbatim |
| `git_status`, `git_diff`, `git_log` | what has changed, as a patch, and what has been committed |
| `git_commit`, `git_restore` | commit it, or throw it away — both put to you every time |
| `fetch` | one GET; hosts off the egress allowlist have to be approved |

The **workspace** — `--workspace DIR`, default the current directory — is the
boundary: no file tool reads or writes outside it, whether the path climbs with
`..`, arrives absolute, or goes through a symlink pointing out of the tree.
Two things inside it are off limits as well: `.gears/`, gears' own state, and
the API key file. `.git/`, `target/` and `.gears/` are skipped when listing and
searching, though an explicit path into `target/` still works.

This is policy inside gears, not enforcement by the OS — the honest v1 posture.
`run` is the deliberate escape hatch from all of it, which is why it is gated
per command rather than per tool.

## Running things

`run` takes a program and an argument vector. **There is no shell**: no pipes,
no redirection, no globbing, no `&&`, no variable expansion — one program at a
time, with nothing between the question you were asked and what runs. It works
the same on Motor OS, which is not a machine gears may assume has a shell.

stdout and stderr come back merged, in arrival order, and the first line of a
result says how the command ended (`exit status 0`, `exit status 101`, `killed
by signal 9`, `timed out after 120s and was killed`). **A non-zero status is
not an error** — a failing build is the whole point of building — so the model
gets the compiler's own diagnostics to work from rather than a tool failure.
Very long output keeps both ends and says how much fell out of the middle.
What reaches the *screen* is one line and a `[+]`; `/+` opens it up.

Every command has a deadline: 120s for `run` and 900s for `build`/`test` by
default, per call and per config, one hour at the outside. When it runs out the
command's whole process group is killed, so a `cargo` that is off compiling
does not outlive the tool that started it.

One gap, and it is on purpose: a `^C` does not stop a command that is already
running — the turn is cancelled when the command returns. Stopping a running
tool arrives with sub-agents (plan step 7), which need it per agent and on a
platform with no signals at all.

## Permission, and getting back

Every call that would **change** something is put to you before it runs:
`y` allows it once, `n` refuses it, `a` allows everything under that key from
now on. An "always" answer is remembered in
`<workspace>/.gears/permissions.toml`, one line per key — delete a line to be
asked about it again. A refusal is not an error: the model is told, in the
tool result, and can do something else or say why it needed to.

The key is what "always" means, and it is not always the tool. `write_file`
covers every write, but a command is remembered as `run:cargo` — and as
`run:/tmp/cargo` if that is what was asked for, because those are not the same
sentence. `fetch` is keyed by host, and is the one tool that asks without
changing anything: a host on `net.egress_allowlist` goes through in silence,
and anything else is a question. Saying yes lets that host past the egress
policy for the rest of the run, but does not add it to your config.

A one-shot `gears -p` has nobody at the keyboard, so anything the gate has not
already been told is refused, out loud. Scripted runs that are *meant* to go
through use `permissions.mode = "auto-approve"`.

gears makes no commits of its own accord — it works on your checkout, and
making commits in one uninvited is invasive. It can be *asked* to, and then it
asks you (see below), but the automatic safety net is something else: it copies
each file the first time it is about to change it, under
`<workspace>/.gears/undo/<session>/`, and
`/undo` puts every one of them back the way the session found them. Files it
created are removed. What a *command* does is outside this — a `run` that
deletes something has no snapshot behind it, which is what the per-command gate
is for.

## Version control

The git tools exist only where there is something for them to work on: gears
asks git on the way in whether the workspace is in a work tree, and where the
answer is no — an unversioned directory, or Motor OS, which has no git — they
are not registered and the model is never shown version control that is not
there. The undo log works either way.

What they do is bounded by the workspace rather than by the repository. gears
may be working in one directory of a checkout, and a commit then takes what is
under that directory and nothing else; `.gears/` is kept out of all of them,
gitignored or not.

`git_commit` writes under **your** identity — the repo's own `user.name` and
`user.email` — with a `Co-authored-by: gears` trailer saying how it was
written. It stages what it is committing first, so a file just created is
included, and a commit that names no paths is everything under the workspace:
that is what saying `y` to one means. `git_restore` goes the other way and
throws uncommitted changes away, so each file it is about to discard goes into
the undo log first and `/undo` can still put it back. What `/undo` cannot do is
remove a commit that has been made.

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
to read the key file either: its path is on their deny-list. Nor does the
`fetch` tool carry the key — it is given a transport of its own, with nothing
to hand to whatever host it is pointed at.

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
keeps the key off the command line — and, for the git tools and the tests that
drive them, a git with `git restore` in it (2.23 or newer).
