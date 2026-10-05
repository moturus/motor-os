# Gears batteries

Optional coding workflows for Gears, implemented by the
[Gears batteries plan](../gears/plans/gears-batteries.md). Install the binary
beside `gears`; the Motor OS developer image installs both in `/devtools/bin`.
The hook reads `AGENTS.md` (or `.gears.md`) only at the selected workspace
root. Instructions are limited to 20,000 characters; oversized files retain
their beginning and end. Prompt fragments are saved by content hash and
reused on resume, fork, provider changes and other setup, until compaction
or a new session takes a fresh snapshot. A failed optional setup is reported
and leaves the previous hook state unchanged.

The file tools read numbered pages, search with `rg`, and write or patch
atomically after complete reads of the current file. The `todo` hook tool
keeps tasks in branch-aware session state. Turn records keep saved entry
ids, tool outcomes, failures, repeated calls, written paths, compactions
and interruptions in `batteries/sessions/SESSION/turns.jsonl`. A partial
record supports up to 512 tool calls; exceeding this limit reports that
tracking is unavailable without granting or changing tool authority.

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

On Linux, install that sample and both crates' tool directories in `~/.gears`,
with `gears-batteries` beside `gears`. Use `~/.gears/gears-batteries.toml` as
the config path. See [Gears setup](../gears/README.md) for provider selection
and explicit key files. The bare batteries program name resolves beside the
Gears executable for tools, hooks and after-turn commands.

Run `src/tests/test-gears-batteries.sh` from the Motor OS repository root for
the hermetic host gate. It builds Linux `rg` offline from the sibling
`../ripgrep` checkout into `build/gears-batteries-host-rg`, then supplies it
to the tests and workflow through their PATH. A system-installed `rg` is not
required for this gate. `--prepare` builds that dependency without running
tests; the full-test preparation phase invokes it before timing the suite.
Direct `cargo test` and ordinary Linux use still need `rg` on PATH.

The release developer-image gate exercises the installed binary and rebuilds
the packaged source with Lorry. The portable workflow fixture uses a scripted
provider to drive real file tools, a Rust
compiler check, task branching and the bounded missing-check reminder.
It also verifies saved approval details, the mechanical turn journal, pending
memory, frozen prompts, removal notes and imported workspace admission.
The host and native workflow tests make no provider or Internet requests.

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
`before_stop` reminders per turn. Review, worker and job runs are excluded.

The batteries hook registers `memory` alongside `todo`.
`batteries/USER.md`, `batteries/MEMORY.md` and workspace
`.gears/MEMORY.md` use `# Gears memory v1` followed by entries. Each entry
starts with `§ ` and a one-line JSON header containing `id`, `kind`
(`user`, `observed`, `inferred`), `scope`, `source` (session and entry ids),
`date_ms` (Unix epoch milliseconds) and optional `applies_to`. Plain Markdown
follows the header. A body line beginning with `§ ` is reserved. USER entries
must have kind `user`; all headers and bodies count toward the file's
character limit. Invalid or oversized optional memory is reported and skipped.

User-wide limits come from `batteries.toml` in the Gears directory (distinct
from the workspace's `.gears/batteries.toml` check declaration):

```toml
version = 1
[memory]
user_chars = 1375
memory_chars = 2200
```

Each limit must be 1–65,536 characters. Missing settings use the shown
defaults; `memory_chars` applies separately to global and workspace memory.

`memory` accepts `action = list | add | replace | remove` and
`target = user | global | workspace`. Add/replace take entry `text`, optional
`kind`, `applies_to` and `source_entries`; replace/remove require an existing
`id`. Every change is staged first and shown with approve/deny/postpone.
One-shot runs leave it pending. The calling entry is recorded along with
any cited source ids; the kind is a provenance claim for the user to review.
The user's answer is sent back to the model. Copy the updated sample config,
or add `answer` and `context` to the batteries hook's event list, to receive
questions and memory correction notes.


New sessions and compaction include approved memory in their saved prompt
snapshot. Additions approved during a session appear at the next new session
or compaction. Resume, fork and provider changes keep the frozen entries,
while replacing or removing entries that have changed since the snapshot.
A running branch receives one context note for each correction or removal;
its original system prefix stays unchanged. Past text remains in history.
Current user and project instructions take precedence over memory, and
approval does not establish that an entry is true or useful.

Workspace `.gears/MEMORY.md` is used only when its exact content hash has a
local approval in `batteries/changes.jsonl`. Cloned or hand-edited contents
are shown to the user at initialization and excluded from the model prompt
until approved. A changed file requires another approval. USER and global
memory are local user files; valid hand edits are read directly.

Review postponed changes from the workspace root:

```sh
gears-batteries pending
gears-batteries pending --list
gears-batteries pending --approve FULL_CONTENT_HASH
gears-batteries history --offset 0 --limit 20
gears-batteries status
```

`pending` shows the full before/after entry, its cited evidence (up to 512
characters per message), unavailable sources, and saved sessions whose
snapshots contain the old entry. Snapshot membership does not prove that a
model used it. Each item asks for `approve`, `deny` or `postpone`; empty or
closed input postpones. `--list` makes no decisions. Explicit `--deny ID`
and `--postpone ID` are also available. The same command displays and admits
imported workspace files by their complete content hash. Memory changes
made by the tool always edit individual entries.

All three commands accept `--workspace PATH` and `--root PATH`; defaults are
the current directory and the Gears directory. Global pending changes and
the selected workspace's changes are included. History is oldest first,
with pages of 1–100 decisions and `next_offset` for the next page. Status
reports pending counts and workspace approval; reviews and evals are marked
unimplemented until their later phases.

Approval validates the captured entry against the current file before
writing any decision. It then appends the decision, replaces the memory
file atomically, and removes pending. Denial appends its decision and removes
pending; postponement changes nothing. A write failure stops the operation.
A crash can leave a logged approval unapplied or an applied change still
pending. There is no automatic replay or transaction across these files.
As specified by the plan, standalone commands assume one writer; run them
when Gears is idle. Skills and their admission remain phase 6.5 work.
