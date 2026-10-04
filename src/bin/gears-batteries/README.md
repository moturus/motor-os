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
It also verifies saved approval details and the mechanical turn journal.
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
