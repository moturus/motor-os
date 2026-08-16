# gears

An agentic coding harness for Motor OS: it drives frontier models over the
network and uses local tools — files, processes, the native toolchain — to do
real work on the machine it runs on. `proposal.md` is the design document and
roadmap. Completed implementation plans remain available in git history.

**Status: P0 complete, and running on Linux and Motor OS.** The dependable
inspect → plan → edit → verify → review slice and its hermetic quality
gates are complete. The first narrow P1 increment adds harness-owned slash
commands in both UIs and explicit context compaction. gears reads and changes
files, runs commands and native toolchains, fetches URLs, and puts sub-agents
on pieces of the work — all under permission. It keeps resumable sessions and
session undo, manages long context,
and can build, keep, and restart into new versions of itself.

**A real model has driven it.** On 2026-08-01 gears, pointed at OpenRouter with
a real key, was asked for a hello-world Rust application and wrote a working
one. That is the first end-to-end run against something other than the mock.

Linux and Motor OS paths are exercised against scripted endpoints in the
hermetic test gate. No automated test talks to a real model provider; real-key
runs remain manual and, so far, few. The self-hosting loop in particular has
been driven only by a script.

## Where gears fits (August 2026)

There are two different comparisons to make: how much policy a harness puts in
its core, and how mature the whole product is. gears sits roughly in the middle
on the first axis. It is more opinionated than a minimal, extension-led core,
but much smaller than the integrated coding products. On maturity and breadth,
gears has completed its P0 slice but remains early-stage and does not yet match
any of the three reference harnesses.

| Harness | Center of gravity | Compared with gears today |
| --- | --- | --- |
| [pi](https://pi.dev/docs/latest) | A deliberately minimal, multi-provider terminal core extended through TypeScript modules, skills, prompt templates, packages, an SDK, and RPC/event-stream modes. | pi leaves more workflow policy to extensions. gears builds an inspect → plan → edit → verify → review workflow, exact mutation approval, session undo, and evidence-based completion into its core; pi nevertheless has a much broader customization and programmatic surface today. |
| **gears** | A small Rust harness with explicit task state, permissions, bounded artifacts, atomic edits, native verification, resumable sessions, and sub-agents. Its distinctive constraint is one auditable core that behaves truthfully on both Linux and Motor OS. | More built-in workflow and safety policy than pi's core, but fewer providers, integrations, extension points, interfaces, and daily-use conveniences than the other harnesses. |
| [Claude Code](https://code.claude.com/docs/en/features-overview) | An integrated Claude coding environment with built-in tools and a large extension model: instructions, skills, hooks, MCP, code intelligence, sub-agents, agent teams, and plugins, across terminal and other product surfaces. | Far broader and more mature. gears borrows the ideas of explicit workflow and delegated agents, but does not yet have Claude Code's extension ecosystem, code intelligence, integrations, or product polish. |
| [Codex](https://learn.chatgpt.com/docs/codex/cli) | An OpenAI coding system spanning an interactive and non-interactive CLI, sandboxing and approvals, project rules, skills, MCP, sub-agents, review, automation, cloud execution, and integrations. | Far broader and more mature, especially in containment, automation, review, and local/cloud workflows. gears is narrower and local-first, with native Motor OS execution as a first-class requirement. |

So “in the middle” describes gears' design scope, not a feature ranking: it is
more batteries-included than pi's core, while intentionally much smaller than
Claude Code or Codex. The near-term goal is to gain the missing daily-coding
capabilities without losing the compact Rust implementation, explicit security
boundaries, hermetic tests, or Linux/Motor OS platform contract.

## Usage

```
gears [OPTIONS]                 the interactive agent
gears -p PROMPT [OPTIONS]       one prompt, then exit
gears ask [-m MODEL] PROMPT     one prompt straight to the model

  --config PATH     read configuration from PATH instead of the default
  --workspace DIR   operate on DIR (default: the current directory)
  --log-file PATH   append a debug/wire trace to PATH
  --resume ID       continue the session with this id
  --mode MODE       start the next task in ask, plan, code, or review mode
  --ui UI           use auto, tui, or line (default: auto)
  -p, --prompt TEXT answer one prompt and exit
  -m, --model ID    model id (default: provider.model in the config)
```

`--ui auto` opens the full-screen TUI when both input and output are terminals.
It selects line mode for pipes and one-shot runs. `--ui tui` requires both
terminal sides; `--ui line` bypasses all TUI capability checks.
The direct `gears ask` endpoint check has no agent UI and rejects `--ui`.

Agent prompts accept `@path` to attach a workspace file or a shallow directory
profile before the first model request. Use `@"path with spaces"` for whitespace
and `@@` for a literal `@`; inside quotes, only `\"` and `\\` are escapes. A
missing, malformed, denied, or workspace-escaping reference fails before the
provider is called. Gears shows each resolved path, kind, size, SHA-256 identity,
and durable artifact number. Inline attachment bytes share the configured
per-prompt bound; complete snapshots remain available through the artifact tool.
Referenced content is data, not an instruction source.

In the TUI, Enter submits; Alt+Enter or Ctrl+J inserts a newline; Up and Down
traverse session-local prompt history. Bracketed paste preserves newlines and
filters terminal controls. Ctrl+C exits while idle and cancels an active turn;
Ctrl+P toggles pause. PageUp and PageDown browse the bounded transcript and
tool output. A draft is limited to 1 MiB, and history keeps at most 100 entries
and 1 MiB for the current process. The status area reports the model, mode,
task progress, exact provider-counted context use, cumulative usage and cost,
pause state, current activity and active sub-agents. Permission questions use a
dedicated view showing the requesting agent, cwd, permission scope, exact argv
or mutation digest and diff. PageUp and PageDown browse wrapped approval text
and the complete diff in bounded artifact pages before a decision is sent.

With no prompt gears reads them from the terminal. The line interface streams
the answer as it arrives and asks before it changes anything:

```
$ gears --ui line
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

Use `--mode plan` for a one-shot planning task, or `/mode plan` before the next
interactive task. An active task changes modes through its durable workflow;
`/mode` does not override it.

Commands: `/status`, `/mode`, `/pause`, `/resume`, `/+`, `/undo`,
`/compact [instructions]`, `/help`, `/quit`. Every slash-prefixed
input is handled or rejected by gears; none is sent to the model. A `^C`
during a turn cancels it; a `^C` at the prompt leaves.

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
# ca_cert = "/absolute/path/to/provider-ca.pem"       # optional custom CA

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

[limits]
# What one run of gears may do. The step cap is per turn — the backstop against
# a model that calls tools forever — while the budgets are the whole run's, and
# are not restored by typing again. Neither budget is set by default: gears
# cannot know what your quota is, and a guess would stop honest work as often
# as it saved anything. Set one if the endpoint you are on has a small quota.
max_steps = 64       # tool rounds in a single turn (1-1000)
budget_usd = 5.0     # USD, where the endpoint prices its completions
budget_tokens = 2000000   # tokens, which every endpoint reports

[agents]
# What sub-agents are allowed, out of the run's budget above rather than beside
# it. max_depth = 0 turns them off: the two tools are then not registered at
# all.
max_depth = 1        # how deep spawning goes (0-4)
max_concurrent = 4   # how many may run at once (1-32)
# What they may spend between them, per run — USD where the endpoint prices
# its completions, tokens where it does not. Neither is set by default.
budget_usd = 2.0
budget_tokens = 400000

[context]
# How many input tokens your model's context window will take. gears cannot
# ask the endpoint, so this is the one number it has to be told; 0 turns
# context management off and leaves the conversation alone.
budget_tokens = 128000
# Whether the oldest part of a long conversation may be replaced by the
# model's own summary of it, which costs one completion.
summarize = true

[quality]
# Policy for the explicit performance-quality gate. It takes at least three
# samples; noisy metrics are reported, while stable regressions beyond this
# percentage fail the gate. These settings add no work to normal startup.
max_regression_percent = 10
stable_samples = 3

[selfhost]
# Whether gears may build, keep and start new versions of itself. Off unless
# you say so. The three tools are registered either way — with this off they
# refuse and name this setting, so that a model told to update itself finds out
# why it cannot instead of improvising something expensive.
enabled = false
# Where promote_candidate installs. Default: the binary this gears is running.
install = "/home/you/.cargo/bin/gears"

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
| `read_file` | a bounded byte or line range, with an identity that detects stale content |
| `list_dir` | one directory; `/` marks directories, `@` symlinks |
| `grep` | bounded literal or regex search, path search, globs, and stable result paging |
| `project_instructions`, `repository_profile` | applicable nested rules and bounded repository/check discovery |
| `artifacts` | list or precisely read durable, bounded evidence retained outside model context |
| `write_file`, `edit_file` | exact single-file changes with prepared diff approval |
| `patch` | atomically create, edit, delete, rename, or change modes across a file set |
| `run` | run an argument vector without an implicit shell; stream bounded output and honor cancellation/timeouts |
| `build`, `test` | use Cargo on Linux or `lorry` from `PATH` on Motor; retain normalized and raw evidence |
| `task`, `completion` | journal workflow state and produce an evidence-derived completion report |
| `stage_candidate`, `promote_candidate`, `restart` | only with `selfhost.enabled`; see [Self-hosting](#self-hosting) |
| `fetch` | one GET; hosts off the egress allowlist have to be approved |
| `spawn_agent` | start another agent on one piece of work; put to you first |
| `wait_agents` | collect what those agents said |

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

`run` takes a program and an argument vector. **There is no implicit shell**:
no pipes,
no redirection, no globbing, no `&&`, no variable expansion — one program at a
time, with nothing between the question you were asked and what runs. Motor OS
does provide the substantially POSIX-compatible `rush`; invoke it explicitly
when a shell is appropriate, without assuming that every POSIX API exists.

stdout and stderr come back merged, in arrival order, and the first line of a
result says how the command ended (`exit status 0`, `exit status 101`, `killed
by signal 9`, `timed out after 120s and was killed`). **A non-zero status is
not an error** — a failing build is the whole point of building — so the model
gets the compiler's own diagnostics to work from rather than a tool failure.
Very long output keeps both ends and says how much fell out of the middle.
What reaches the *screen* is one line and a `[+]`; `/+` opens it up.

Every command has a deadline: 120s for `run` and 900s for `build`/`test` by
default, per call and per config, one hour at the outside. At the deadline,
Linux kills the command's process group; Motor OS kills the direct child and
reports the descendant-cleanup limitation.

`^C` cancels an active provider request or foreground command. Linux terminates
the command's process group. Motor OS terminates the direct child promptly but
reports that it cannot yet guarantee descendant cleanup; the session remains
resumable in either case.

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

The automatic safety net records each file the first time gears is about to
change it. `/undo` puts every one of them back the way the session found them;
files it created are removed. What a *command* does is outside this — a `run`
that deletes something has no snapshot behind it, which is what the
per-command gate is for.

## Version control and named checkpoints

Neither is part of the core gears surface. There are no dedicated Git tools or
named-checkpoint commands/tools; both belong in future extensions. Where a
`git` executable exists, the model can still request an explicit argument
vector through `run`, under the normal per-command permission gate. Motor OS
currently has no `git` executable. `/undo` remains a core session safety
command, backed by private snapshots rather than a user-visible checkpoint
abstraction.

## Sub-agents

gears can put agents of its own on pieces of the work. `spawn_agent` starts one
and comes straight back; `wait_agents` collects what they said. Each has its
own conversation and sees nothing of the one that sent it — which is the point:
a search through a large tree comes back to the parent as one tool result
instead of as a filled context window.

```
gears> what do the TODOs say, and does it still build?
* spawn_agent list every TODO and what it is about
allow spawn_agent list every TODO and what it is about? [y]es / [n]o / [a]lways: y
  agent 1 started
* spawn_agent build the crate and report the warnings
allow spawn_agent build the crate and report the warnings? [y]es / [n]o / [a]lways: y
  agent 2 started
* wait_agents
[1] * grep TODO
[2] * build
[1]   [+] 812 bytes
[2]   [+] 2144 bytes
[1] Three, all in the parser: …
[1] - done
[2] It builds, with one warning about …
[2] - done
  [+] 1203 bytes
Three TODOs, all in the parser, and it builds with one warning: …
```

Everything except the conversation is shared: the workspace, the undo log, the
permission gate, the connection to the endpoint. **Output is marked with the
agent's number** — `[1]`, `[2]` — and so is its permission question, because
"allow write_file notes.txt?" is a different question depending on who is
asking. The agent you are talking to is unmarked.

Three guardrails, all under `[agents]` above:

* **How deep.** One level by default: an agent gets to start agents, and those
  do not. `max_depth = 0` turns the whole thing off, and the two tools stop
  being registered.
* **How many at once.** Four by default. Past that, `spawn_agent` tells the
  model to wait for one.
* **What they may spend.** Counted from what the endpoint reports — dollars
  where it prices completions, tokens where it does not — and checked before
  every sub-agent completion. It is a pocket inside the run's budget below
  rather than a second budget beside it: what a sub-agent spends, the run has
  spent. `/status` shows the total either way.

A **read-only** agent (`read_only: true`) gets only the tools that change
nothing: reading, listing, searching, fetching, and inspecting repository
instructions and structure. It cannot start an agent that is not read-only,
because starting an agent is itself a change and so is not one of the tools it
has. That is the cheap-scout, careful-builder shape, and the cheap part is
real: `spawn_agent` takes a model id, so a scout can run on something small.

An agent nobody waits for is stopped when the turn ends — its answer has
nowhere to go — and a `^C` stops the lot, including a parent that is sitting in
`wait_agents`.

## What a run may cost

One prompt is not one request. A turn is a loop — the model calls tools, reads
what they say, and goes round again — so "make this work" can be twenty requests
before it is anything. Two limits bound that, both under `[limits]`:

* **`max_steps`**, 64 by default: how many tool rounds a *single turn* may take
  before gears stops it and says so. It is a backstop against a model that
  never answers, not a budget — a turn that needs sixty rounds is rare, and one
  that needs a thousand is broken.
* **`budget_usd` / `budget_tokens`**, unset by default: what the *whole run* may
  spend, checked before every request, sub-agents included. It is not restored
  by typing again — the quota it stands for is not either — so a run that
  reaches it stops until you start gears afresh.

Neither budget has a default because gears has no way to learn what your quota
is, and a number it invented would stop honest work as often as it saved
anything. If you are on a small quota, set one. `^C` is still the fastest way to
stop a turn you are watching go wrong.

## Long conversations

A conversation grows until the model's window will not take it, and then every
request fails. gears works from the endpoint's own numbers to stop that
happening: every completion reports what the request it answered came to in
tokens, so the size of the last thing sent is always known — no tokenizer, no
guessing. Past three quarters of `context.budget_tokens`, the conversation is
cut back *before* the next request goes out, and the endpoint's next count says
whether it was cut back enough.

What goes, in order:

* **The oldest tool results**, replaced by a line saying one was dropped and
  how big it was. The call that asked for it stays, so the transcript is still
  one the model can be asked from, and the model can run the call again if it
  turns out to still need it. The results of the round it is working on now are
  never touched.
* **A summary**, once there is nothing left to drop. The model is asked to
  write down what its later self will need, and that summary stands where the
  oldest part of the conversation was. It costs one completion, which is why it
  is second; `summarize = false` turns it off.

Both are announced on screen as they happen. **The session file keeps the
whole thing** — dropping a result changes what is *sent*, not what is
recorded — with one exception: a summary is recorded as such, so that resuming
picks up the conversation as it was compacted rather than as it was first
written. A resumed session also reads back the endpoint's count for the last
request it made, so the first request after a resume is measured too rather
than being the one nobody checked.

`/compact` performs the summary step immediately, even when automatic context
management or automatic summaries are disabled. It keeps system messages and
the newest user turn exact, summarizes only complete older turns, and makes no
provider request when fewer than four messages are eligible. Optional text,
as in `/compact emphasize unresolved test failures`, focuses the summary
without changing the boundary. The summary is one ordinary, budgeted
completion with no tools; failure, cancellation, or an empty answer leaves the
conversation unchanged.

The default budget is 128000 tokens, which is a cap on gears' own behaviour
rather than a claim about your model: set it to what your window really is.
Too low costs a little detail, too high leaves the endpoint to refuse the
request.

## Sessions

Every run keeps a transcript in `<workspace>/.gears/sessions/<id>.jsonl`,
written as it happens, and prints the id on the way in. `gears --resume <id>`
picks one up where it stopped — including after a failure, a cancelled turn or
a crash, because a turn that does not finish is not recorded as if it had. One
gears at a time per session, enforced by a lockfile that knows a stale one when
it sees it.

`<workspace>/.gears/` holds all of this. Add it to your `.gitignore`.

## Self-hosting

gears can work on its own source: edit it, build it, check what it built, and
carry on in the result. **This is off by default** — set `selfhost.enabled`
before asking gears to update itself.

| Tool | |
|---|---|
| `stage_candidate` | keep a freshly built gears as a numbered candidate, out of the way of later builds |
| `promote_candidate` | install a candidate where gears itself lives |
| `restart` | stop this gears and start another on the same session |

The three are registered whether or not it is on; with it off they refuse and
say so, naming the setting. That is deliberate, and it is the first thing a real
run taught: asked to update itself by a gears that had no way to, a model does
not conclude it cannot — it improvises with the tools it does have, which meant
building and running gears over and over until the quota was gone. A tool that
answers "no, and here is why" costs one round and ends the attempt.

```
gears> add the elapsed time to /status, build it and try it
* edit_file src/ui/terminal.rs
* build
  [+] 812 bytes
* test
  [+] 2144 bytes
* stage_candidate target/self/debug/gears
  candidate 1 is gears 0.1.0 (/w/.gears/candidates/gears-1)
* restart 1
allow restart 1? [y]es / [n]o / [a]lways: y
  gears will restart into /w/.gears/candidates/gears-1 and carry on session 17-3
Built and staged; restarting into it.
gears: restarting into /w/.gears/candidates/gears-1
- resumed session 17-3: 9 messages, …
```

Four things hold this together.

* **A candidate has to say what it is.** `stage_candidate` runs the binary with
  `--version` before keeping it, so something that does not build into a
  working gears is refused there rather than after the restart. Candidates live
  in `.gears/candidates/`, where the file tools cannot reach them.
* **Validate before you adopt.** The *old* binary runs the tests, as an ordinary
  `test` call, while it is still the one in charge. What that proves is
  therefore yours to decide: a bounded slice is enough to try a candidate, the
  whole suite is what a promotion deserves.
* **Promotion is separate, and it is asked about.** `promote_candidate` writes
  the new binary in beside the old one and renames it over the top — a file
  that is being executed cannot be written to, and a rename is atomic — keeping
  what it replaced at `.gears/candidates/previous`. That is what to go back to
  if a promoted gears turns out not to work.
* **Restarting is not `exec`.** The session is closed and its lock released,
  then the new gears is started on the same session with `--resume` and waited
  for, so the terminal is only ever owned by one process. What the model said
  before the restart is in the transcript the new binary reads.

If you restart into a candidate to try it, gears is then *running* from
`.gears/candidates/`, and there is nowhere for a promotion to go: say where
gears really lives with `selfhost.install`. Promoting first and restarting into
the installed binary needs no configuration at all.

`cargo test` runs the whole loop against a scripted model and real cargo, up to
but not including the promotion — an automated test that overwrote a binary
would be overwriting its own. Promoting after a full-suite validation, and the
same loop driven by a real model, are done by hand.

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

The release performance and resource-quality gate is documented in
`tests/performance-baseline.md`. Its checked-in machine-readable reference is
`tests/performance-quality-baseline.txt`. Run
`src/tests/gears-test.sh --release --baseline` to compare against it and reject
stable regressions beyond the configured limit. These are test inputs, not
temporary measurement output.

The test suite drives the real `curl` binary against an in-process mock server
that serves scripted, deliberately fragmented responses. Runs against a real
provider are manual. The versioned P0 capability scenario is under
`evaluations/p0-normalize-label-v1/`; its HUMAN-ONLY instructions require a
person to supply and authorize the provider, model, credentials, and finite
budget. Automated tests only dry-validate its local failing fixture and never
start Gears or contact a provider. `gears ask` is the endpoint spot-check tool.
Host curl 8.3 or newer is required — that is where `--expand-header` arrived,
which is what keeps the key off the command line.

`tests/interrupt.rs` holds one test and has to keep holding one. The interrupt
flag is a process-global that the agent loop *takes* rather than reads, so
anything that sets it needs a process nobody else is running an agent in — an
integration binary is how you get one.

## Built-in tools and commands

This inventory is the compiled-in Gears surface, not proposed roadmap work.
Tools are calls the model can make; commands are slash-prefixed user input that
Gears handles locally and never sends to the model. Availability can still be
narrowed by mode, read-only agent policy, workspace capabilities, permissions,
or configuration.

The Pi comparison is against [Pi's documented core tools and commands as of
August 2026](https://pi.dev/docs/latest/usage), not its extensions or packages.
Pi core has seven model tools: `read`, `bash`, `edit`, `write`, `grep`, `find`,
and `ls`. Its `bash` tool can invoke programs such as git, curl, or Cargo, but
that does not make those programs dedicated Pi tools.

### Model tools

| Gears tool | Purpose and availability | Pi core counterpart |
| --- | --- | --- |
| `read_file` | Bounded byte or line reads with content identity. | Yes: `read`. |
| `write_file` | Create or completely replace a file through the mutation gate. | Yes: `write`. |
| `edit_file` | Replace one exact, uniquely matching piece of a file. | Yes: `edit`. |
| `list_dir` | Bounded directory listing with generated/vendor exclusions. | Yes: `ls`. |
| `grep` | Bounded literal or regex content search and file-name search, with paging and globs. | Yes: `grep`; file-name mode also covers Pi's `find` role. |
| `patch` | Review and atomically apply a versioned multi-file patch. | No dedicated equivalent; `edit` is the closest core tool. |
| `project_instructions` | Discover the applicable nested instruction files for a path. | No tool. Pi loads context files itself. |
| `repository_profile` | Report bounded repository roots, languages, manifests, exclusions, and candidate checks. | No. |
| `run` | Execute one explicit argument vector with bounded streaming output and a deadline. | Approximately `bash`, though Pi deliberately gives its tool a shell. |
| `fetch` | Policy-gated HTTPS fetch with an allowlist and no provider credential. | No dedicated tool; `bash` can run curl. |
| `artifacts` | List and reopen bounded ranges from durable large results and approval material. | No. |
| `build` | Run the native Rust build backend: Cargo on Linux, Lorry on Motor OS. | No dedicated tool; `bash` can run a build command. |
| `test` | Run the native Rust test backend and retain verification evidence. | No dedicated tool; `bash` can run tests. |
| `stage_candidate` | Validate and retain a candidate Gears binary; refusing stub when self-hosting is disabled. | No model tool; Pi's CLI updater is not an agent tool. |
| `promote_candidate` | Atomically install a retained candidate; refusing stub when self-hosting is disabled. | No. |
| `restart` | Close the session and continue it under a selected candidate binary. | No. |
| `task` | Update durable task items and explicit ask/plan/code/review transitions. Root agent only. | No; Pi intentionally has no built-in plan mode or to-do system. |
| `completion` | Record reviewed verification skips or emit the evidence-backed completion report. Root agent only. | No. |
| `spawn_agent` | Start a budgeted sub-agent, optionally read-only, when configured depth permits. | No; Pi intentionally has no core sub-agents. |
| `wait_agents` | Collect selected or all outstanding sub-agent results. | No. |

The three self-hosting names remain visible but refuse while
`selfhost.enabled` is false. Read-only sub-agents receive only non-mutating
tools and cannot recursively spawn agents.

### Harness slash commands

| Gears command | Local behavior | Pi core counterpart |
| --- | --- | --- |
| `/status` | Show session, model, workspace, usage, changed-file count, pause state, and durable task. | Partial: Pi's `/session` shows session and usage information. |
| `/mode MODE` | Select ask, plan, code, or review mode for the next new task. | No; Pi has no core task modes. |
| `/pause` | Pause before the next model or tool operation. | No; Pi supports abort and queued steering, not this pause boundary. |
| `/resume` | Continue work paused in this Gears process. | No semantic match: Pi's same-spelled `/resume` selects an earlier session. |
| `/+ [N]` | Expand the newest, or Nth-newest, retained full tool result. Bare `+` is an alias. | No. |
| `/undo` | Restore every file to its first state in this session. | No. |
| `/compact [instructions]` | Summarize complete older turns while preserving system messages and the newest turn exactly. | Yes: `/compact [prompt]`. |
| `/help` | Show the Gears command summary. `/?` is an alias. | Partial: `/hotkeys` documents input bindings, but Pi has no listed `/help`. |
| `/quit` | Leave Gears; `/exit` and `/q` are aliases. | Yes: `/quit`. |

The executable also has interactive `gears`, one-shot harness
`gears -p PROMPT`, and direct provider spot-check `gears ask PROMPT` entry
points. Pi has corresponding interactive and `-p` modes, but no exact core
equivalent of `gears ask`, which deliberately bypasses the agent harness.

## Current Motor OS gaps relative to Linux

These are known platform gaps in implemented Gears, not differences hidden
behind a claim of parity:

| Area | Motor OS gap |
| --- | --- |
| Native self-build | Lorry cannot yet build Gears' dependency graph natively. The complete edit → build → validate → promote → restart self-hosting loop therefore works only on Linux. |
| Executable bits | Motor OS exposes no reviewed portable API for Unix mode bits. Patches cannot request executable-bit changes, and mutation/undo records cannot preserve or restore those bits. |
| Undo replacement detection | Linux compares device/inode identity, in addition to type, size, modification time, and mode, while capturing private undo state. Motor OS has no equivalent stable-file identity check, so that one replacement-race guard is absent. |
| Process-tree cancellation | Linux starts commands in their own process group and kills the group on cancellation or timeout. Motor OS can kill only the direct child and reports that descendants may survive; it also has no signal number to report. |
| Rust build/test options | Motor OS uses Lorry, a strict Cargo subset. `target_dir` is unsupported, builds are already offline, and arbitrary Cargo-only options may be refused instead of translated. Direct `run cargo ...` is rejected on Motor OS just as direct `run lorry ...` is rejected on Linux. |

The remaining features share their cross-platform implementation or have a
Motor OS backend. The native Gears gate exercises their principal Motor OS
paths, including provider streaming, TLS-backed fetch, slash commands, manual
and automatic compaction, tool-call continuation, filesystem/search/patch
tools, artifacts, build/test through Lorry, undo, mode enforcement,
TUI operation, and bounded read-only sub-agents.
