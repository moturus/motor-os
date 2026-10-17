# Gears batteries

Optional coding workflows for Gears, implemented by the
[Gears batteries plan](plans/gears-batteries.md) as the `batteries` module of
the `gears` package and its `gears-batteries` binary. Install that binary
beside `gears`; the Motor OS developer image installs both in `/devtools/bin`.
The hook reads `AGENTS.md` (or `.gears.md`) only at the selected workspace
root. Instructions are limited to 20,000 characters; oversized files retain
their beginning and end. Prompt fragments (instructions, memory, the skill
list) are saved by content hash when a session starts and reused on resume,
fork, provider changes and other setup, until compaction or a new session
takes a fresh snapshot. A failed optional setup is reported and leaves the
previous hook state unchanged.

The file tools read numbered pages, search with `rg`, and write or patch
atomically after complete reads of the current file. The `todo` hook tool
keeps tasks in branch-aware session state.

The hook automatically allows workspace reads and its task list. Writes
and ordinary commands use Gears' grants and prompts. Its short static
command list refuses protected deletions and common fork bombs, including
shell wrappers and saved shell directories. Commands that may publish or
discard work require fresh confirmation. This prevents accidents and makes
no confinement claim. A malformed policy request denies the call; optional
recording and setup failures report notices and preserve their prior state.
The default `gears.toml` keeps optional tools disabled. The developer image
also installs `/user/cfg/gears/gears-batteries.toml`, which enables the
batteries hook and coding tools. Select it explicitly:

```sh
gears --config /user/cfg/gears/gears-batteries.toml --model MODEL
```

On Linux, install that sample and the `tools` directories in `~/.gears`,
with `gears-batteries` beside `gears`. Use `~/.gears/gears-batteries.toml` as
the config path. See [Gears setup](README.md) for provider selection
and explicit key files. The bare batteries program name resolves beside the
Gears executable for tools and hooks. The shipped hook subscribes to
`initialize`, `permission`, `tool_execute`, `tool_result`, `turn_start`,
`entry`, `before_stop`, `turn_end` and `answer`; it registers no slash
commands and needs no after-turn command.

Run `src/tests/test-gears-batteries.sh` from the Motor OS repository root for
the hermetic workflow gate; `test-gears-http.sh` runs the package's tests. It
builds Linux `rg` offline from the sibling `../ripgrep` checkout into
`build/gears-batteries-host-rg`, then supplies it to the tests and workflow
through their PATH. A system-installed `rg` is not required for this gate.
`--prepare` builds that dependency without running tests; the full-test
preparation phase invokes it before timing the suite. Direct `cargo test`
and ordinary Linux use still need `rg` on PATH.

The release developer-image gate exercises the installed binary, and Lorry
rebuilds the packaged source and runs its tests natively. The portable
workflow fixture uses a scripted provider to drive real file tools, a Rust
compiler check, task branching, the bounded missing-check reminder, the
memory question, frozen prompts, memory files in both formats, the
`history` and `status` commands and skill loading. The host and native
workflow tests make no provider or Internet requests.

## The check

Declare one check at the workspace root in `.gears/batteries.toml`:

```toml
check = ["cargo", "test", "--offline"]
```

For platform overrides, use `[check]` with `linux = [...]`, `motor = [...]`
and an optional `common = [...]` fallback. Every item is a literal argument;
use a program or script directly. Shell `-c` declarations are refused.
The declaration is limited to 128 items and 8 KiB of serialized JSON.
Lorry builds are already offline; a Motor OS declaration can use
`check = ["lorry", "test"]`. For a workspace tested on both systems:

```toml
[check]
linux = ["cargo", "test", "--offline"]
motor = ["lorry", "test"]
```

The check approval prompt shows the declared vector. Its first run and each
changed declaration require fresh confirmation; a denied call does not
record approval. Only a completed check receipt matching that request
establishes evidence. Later calls to tools that may write make it stale.
After workspace work, a missing, failed or stale check gets at most three
`before_stop` reminders per turn. A passing check is development evidence;
whether the task is done is the user's call, in conversation.

## Memory

The batteries hook registers `memory`, `skill_view` and `todo`. Memory
lives in three plain text files the user may edit by hand:
`batteries/USER.md` (facts about the user) and `batteries/MEMORY.md` (facts
about this computer) in the Gears directory, and `.gears/MEMORY.md` in the
workspace (facts about this project, with paths relative to the workspace).

```
# Gears memory v2
§ k7f2 2026-10-15 01J9Q3M8R6W2Z4
In red, run `cargo test --offline`; the VM has no network.
§ m3a8
Written by hand; the date and session are optional.
```

Each entry starts with a `§ ` line holding its id, its date and the session
that proposed it (`-` or nothing for an entry written by hand), then its
text. A text line may not start with `§ `. Files in the previous
`# Gears memory v1` format with JSON headers are still read; the first
change rewrites them in the current format. An unreadable or oversized file
is reported as a notice and left out of the prompt.

The `memory` tool takes `action = list | add | replace | remove` and
`target = user | global | workspace`, with `id` for replace and remove and
`text` for add and replace. It changes one entry at a time. When the model
proposes a change, Gears shows the exact entry and asks one question with
two answers, yes and no:

```
Proposed workspace memory entry:
In red, run `cargo test --offline`; the VM has no network.
Remember this? [yes/no]
```

Yes writes the file at once; no does not. Both answers are appended to
`batteries/changes.jsonl` and reported back to the model. When nobody can
answer (a `-p` run, or a cancelled question) nothing is written or logged
and the model is told so. A replacement or removal fails with a message if
the entry changed meanwhile, and an entry that already exists is reported
as already remembered without a question. The file tools refuse the Gears
directory and the workspace's `.gears/` directory, so the tool is the only
way the agent writes memory.

Memory and skill changes of every kind appear in the next session, after
`/new` or after a compaction; a running session keeps the prompt it started
with. A workspace `.gears/MEMORY.md` that arrives with a clone is used as it
is, like the clone's `AGENTS.md`.

User-wide settings come from `batteries.toml` in the Gears directory
(distinct from the workspace's `.gears/batteries.toml` check declaration):

```toml
version = 1
[memory]
user_chars = 1375
memory_chars = 2200
offer_lessons = false
[skills]
skill_chars = 20000
notes_chars = 4000
```

Each limit must be 1–65,536 characters and counts entry text only;
`memory_chars` applies separately to global and workspace memory. With
`offer_lessons = true`, the prompt tells the model that after finishing a
task whose check passed it may offer at most one thing worth remembering
next time, a mistake and its fix or a procedure that ran and worked, and
otherwise offers nothing. The instruction lists the last five declined
entries so they are not offered again. With offers off, the model proposes
memory only when the user asks it to remember something.

## Skills

Skills are directories the user writes under `batteries/skills/NAME/` in
the Gears directory, with a `SKILL.md` in the
[Agent Skills](https://agentskills.io/specification) format and an optional
`NOTES.md` beside it. `SKILL.md` needs YAML `name` and `description`; the
optional fields are `license`, `compatibility`, `metadata` (a
string-to-string mapping) and `allowed-tools`, which grants no permissions.
On Motor OS, only skills whose `metadata.platforms` names `motor` are listed:

```markdown
---
name: rust-checks
description: >-
  Run the project's declared Rust check after a code change.
metadata:
  platforms: motor linux
---
## When it applies
After changing Rust source in this workspace.
## Steps
Read the check declaration and finish the intended edits.
## How to check
Run the check tool and inspect its receipt.
## Pitfalls
A passing check is development evidence; the user decides whether the task is done.
```

The prompt lists the available names and descriptions. `skill_view` loads
one skill and its notes by name, or lists them when called without a name,
and refuses a fourth distinct skill in one session. Files use UTF-8 and LF
endings; an invalid, oversized or symlinked skill is reported and skipped.
The skill size limit includes the front matter; notes have their own limit.
There is no approval step: add, edit and remove skill files directly.

## Commands

```sh
gears-batteries history --offset 0 --limit 20
gears-batteries status
```

`history` lists the yes and no answers oldest first, with `total`,
`next_offset` and the number of log lines it could not read. `status` shows
whether offers are on, how many entries each memory file holds, which
skills are available and how many decisions the log holds. Both accept
`--workspace PATH` and `--root PATH` (the Gears directory); the defaults are
the current directory and the usual Gears directory. The commands are read
only and may run while Gears is open.
