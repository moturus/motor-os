# Gears batteries: design and implementation plan

Status: implementation through phase 7, including installed native skills
and `/accept` validated with the selected `dev.3` SDK. Phase 8 has model-pair
settings, durable marks, exact saved-entry snapshots, review tool policy and
command/compaction triggers, the resume question, a durable proposal cap and a
connected runner that preserves the saved prefix after compaction, and explicit
cutoff-based cleanup proposals with approval-only archival. Phase 9's manual
multi-task evaluation command, frozen workspace/state copies, repeated arms and
reports pass focused host/native fixtures and the release developer-image gate;
the first real-model run is pending.
Sysbox S1–S5 are complete and core-gated, including local sort-key modifiers.
The utility track continues with `xargs`. Its default-command choice is pending
(see the remaining-work checklist).
Design revised 2026-10-06. See the
[remaining-work checklist](gears-batteries-progress.md#what-remains) for current
status; that document also retains the implementation history. Two questions wait
for later phases: question 7 is needed before the first real-model evaluation, and
question 10 when phase 12 is. Tool confinement is deferred (see "Deferred:
tool confinement").

## Purpose and scope

Make Gears a useful personal coding agent on Motor OS and Linux, with file
and shell tools, project instructions, task tracking, searchable sessions,
and optional memory and skills. Then measure whether reviewing its work and
proposing improvements makes subsequent work better. The everyday agent
must remain useful with automatic learning disabled.

The direction fits the [Gears redesign](../redesign.md): Gears owns the
agent loop, providers, sessions, cancellation and user interfaces; optional
batteries supply coding workflows. Worker orchestration, web tools,
scheduling and gateways are separate optional features. They should not be
prerequisites for useful memory or evidence that learning works.

The [research review](../../../../docs/self-improving-agents-review.md)
supports testing bounded, evidence-grounded updates and measuring their
cost and effect. It does not establish that checking always makes learning
helpful, that unverified learning always hurts, or that a particular model
size or number of confirming sessions is a reliable threshold. Results
come from different tasks and budgets, and much of the literature has not
been independently reproduced. Treat the learning loop as an experiment.
Task acceptance uses the user's explicit `/accept` command,
as recorded in [the acceptance decision](gears-acceptance-vcs.md).

[Earlier notes](gears-batteries-notes.md) retain investigation history,
mock-provider prototypes and reproductions of the Gears defects fixed in
phase 1 (notes §4.4); they are not evidence of real-model usefulness. The
previous version of this plan, commit `ef8a1ce3`, is history: where this
document differs, this document wins. Hermes supplied useful examples of
tools, skills, prompt caching and failure handling, not an implementation to
port; its learning loop is not followed. Preserve its MIT notice if reusing
text.

Not in this plan: tool confinement (deferred, below); an `undo` command or
other rollback of memory, skills or workspace files (a capable model can
reverse its own changes from the session history, and the user keeps the
workspace in git or gix); Anthropic's Messages API; MCP; a pass in which the
model rewrites tool descriptions; running read-only tools in parallel;
model-written scripts; guest users; and commands that keep running after
their tool call ends.

## Retained decisions

- Keep the names `gears` and `gears-batteries`. One new Rust crate,
  `src/bin/gears-batteries`, builds one program whose first argument picks
  its role: `hook`, `tool NAME` and `review` for the roles Gears starts;
  `pending`, `history`, `status`, `cleanup`, `eval` and
  `orchestrate` for the user; `cron` and `gateway` for the optional
  services. It uses Gears as a library, and Gears runs every model/tool
  loop, including workers and reviews. It is installed beside the `gears`
  executable (`/devtools/bin` on Motor OS, the directory holding `gears` on
  Linux). The shipped manifests and hook configuration name it by the bare
  name `gears-batteries`, which Gears resolves to that sibling; this is the
  one exception to the contract's rule against bare program names.
- Support Motor OS and Linux. Ship with the developer image; do not add
  automatic boot work. Use Rust and native Motor OS APIs, with dependencies
  that build on Motor OS. Changes to the OS or Lorry need a separate design
  decision.
- Support named local and OpenAI-compatible providers, including OpenRouter,
  and provider/model switching. Preserve reasoning and cache metadata where
  the selected protocol requires them. Direct Anthropic Messages support
  remains deferred until there is a concrete need.
- Provider retries are bounded and visible, including in interactive use.
  Report each failure and wait; never silently switch providers, retry a
  user cancellation, or retry after part of an answer has become visible.
- Keep six tool approval choices: allow or deny once, for the session, or
  globally, tied to the tool's approval identity. Session grants take
  precedence over global grants. Saved denials apply to unattended runs;
  saved allowances do not apply to one-shot `-p` runs, including workers
  and jobs, whose authority comes from the batteries' hook policy instead.
  Publishing or discarding work can require fresh confirmation through the
  hook's `confirm` answer. No tool runs before Gears has looked up the
  user's saved answer for it, whatever a hook says (question 1).
- Only one Gears runs per Gears directory, apart from the reviews and
  workers it starts itself (question 4). Gears alone owns and checks the
  lock file; `gears-batteries` does not check it. Independently launched
  batteries commands are the user's responsibility.
- Each run has one selected workspace root, shared by its tools, hooks,
  reviews and workers. There are no nested workspaces or per-subdirectory
  instructions. Assume one writer and no concurrent external modifications;
  no additional coordination is needed. A shell `cd` does not change the
  workspace root.
- Keep a small `USER.md` and global `MEMORY.md`, plus workspace memory in
  `.gears/MEMORY.md`. User data lives in the Gears directory,
  `/user/cfg/gears/` on Motor OS and `~/.gears/` on Linux, which also holds
  `gears.toml`, the sessions, the lock file and the batteries' data.
  `--config FILE` selects another configuration file for one run; it does
  not move the Gears directory. Relocating existing sessions between
  workspace paths or systems is deferred: this plan adds no migration or
  relocation gate. New batteries data uses relative paths as described in
  "Layout", but existing Gears session paths keep their current behavior.
- Add `mkdir -p`, `sort`, `uniq`, `cut`, `tr` and `xargs` to sysbox, written
  in Rust with the standard library; use `rg` directly, with no `grep` front
  end. These are general shell utilities, separate from the learning design.
- Validate real usefulness by user-run sessions with a local model and an
  OpenRouter model, at the end of phase 5. What the user does in those
  sessions is the user's choice. Automated tests remain hermetic; real-model
  trials and learning evaluations are explicit, separately budgeted
  activities.

## Deferred: tool confinement

The user will address the filesystem-permission problem separately: a role
can widen its own `r-x` to `rwx`, so a read-only workspace does not confine
a tool that holds `CAP_FS_WRITE` (see
[filesystem permissions](../../../../docs/fs-permissions.md#runtime-behavior-and-remaining-limits)).
Until a confinement design is agreed, this plan makes no confinement claim:

- every tool, hook and worker runs with the user's authority, as Gears' `sh`
  and hooks do today, and keeps network access;
- the provider key is kept out of child environments, as today, but a tool
  can still read files the user can read, the key file included;
- the destructive-command list and the file tools' refusal to touch the
  Gears directory prevent accidents; they are not security boundaries;
- every tool process starts through one process runner, so that a later
  design can apply a capability mask in one place; manifests carry no
  `profile` or `spawn` fields until then.

Code in the workspace that Gears is working on (for example a build script
or test) modifying memory behind the batteries' back is out of scope for
now. Preventing that belongs to the later sandbox design; do not add a
separate defense against it here. Explicit approval of memory proposals and
memory imported with a workspace still applies.

Inputs for the later design, recorded 2026-10-02:

- The user: one sandbox per Motor OS VM; assume that every None-role process
  was started by Gears or is trusted (for example the DNS resolver).
- The user: network access is granted through the usual six approval
  choices; `lorry vendor` run as None keeps its vendored crates separate
  from the cache the user's own (Interactive) runs create. Open details:
  approvals are per tool, not per capability; Lorry asks interactively
  before admitting changed dependencies, which a tool cannot answer; and
  denying `CAP_NET` also denies loopback, which some tests need.
- From reading the kernel, not tested: `sys_dbg_attach` refuses only pids
  below 2 and the caller's ancestors, and `F_KILL_PID` protects only
  `CAP_SYS` processes. A None tool could therefore debug or kill an
  Interactive process that is not its ancestor, such as a hook or a worker.

## Runtime guarantees in Gears

These hold for every Gears session, with or without the batteries, and
each gets a regression test. Rules 2, 3, 6 and 7 fix defects reproduced in
September 2026 (notes §4.4).

1. The model's request to run tools is saved before any tool runs. Gears
   already does this.
2. During a running session, every tool call gets exactly one result, in
   one of three states:
   completed (with the tool's own status), not started (an interrupt, a
   denial or an error before the process started), or interrupted with an
   unknown outcome (the process was running when the turn ended). A resumed
   session never runs an interrupted call again; the model sees that its
   outcome is unknown and decides what to do. After a crash, incomplete
   updates are discarded as described in guarantee 12 instead of trying to
   reconstruct missing outcomes.
3. When a tool round is cut short, the next request includes a short
   assistant note saying so, generated when the request is built and never
   stored. Without it, models read the user's next message as part of the
   interrupted work.
4. An empty reply from the model is never stored or sent back. Message
   content of unknown kinds is skipped, not fatal. Parallel tool calls that
   a server sends under the same index (Ollama does) stay separate calls.
5. A failed request is not retried once the user has seen part of the
   answer, and a request the user interrupted is never retried.
6. Lifecycle hooks (`turn_end`, `session_end`, `session_start`) still run
   after a cancellation, and the user sees "cancelled", not "broken pipe".
7. Compaction either shrinks the conversation or reports that it could not.
   What it sends to the summarizer has a size limit, so one huge tool
   result cannot make every later turn fail.
8. Cancellation and exit stop every child process Gears owns: tools, hooks,
   the after-turn command, workers and reviews, including their descendants.
   The process ownership and cleanup rules are below.
9. A failed permission decision prevents execution. Failures of optional
   features are reported, never silent.
10. A permission revocation applies before the next tool call.
11. Only one Gears runs per Gears directory. Gears keeps a lock file there,
    `gears.lock`,
    holding its pid. At startup, if the file names a running Gears process,
    Gears refuses to start and says which pid holds it; a file that names no
    running Gears process is left over from a crash and is replaced. Gears
    processes that the running Gears starts itself, reviews and workers,
    find the holder's pid in their environment and run under its lock after
    checking that the holder is their ancestor. Only Gears owns and checks
    this lock. `gears-batteries` commands neither acquire nor check it;
    independent invocations do not receive concurrency guarantees.
12. Each long-term file (memory, skills, pending items, saved grants, the
    provider choice) is written through a temporary file renamed over the
    old one; startup deletes temporary files left behind. This protects
    individual file writes, not a transaction across files. Memory decisions
    use the simple write order in "Storage" below.
    Append-only files, such as sessions and the change log, ignore a
    half-written last line when reading and discard it before appending.

    Crash cleanup has one goal: Gears can start and work in the workspace
    again. On startup, clear stale Gears and session locks, remove leftover
    temporary files, and discard incomplete session updates as needed to
    leave a usable history with paired tool calls and results. Preserve
    usable completed records and briefly report what was discarded.
    Inconsistent optional batteries state is reported and skipped rather
    than preventing startup. Do not add a recovery journal or reconstruct
    what a crashed tool did; never replay tool calls or undo workspace
    changes during cleanup.

### Process ownership and cancellation

Each direct child that the top-level Gears starts owns one process tree.
The same runner owns its timeout, cancellation and cleanup; it stops the
tree and waits for its direct child before returning or letting a new turn
write anything. A normally completed child must not leave descendants
running either. Commands that detach or deliberately escape this ownership
are unsupported while confinement is deferred.

- On Linux, the runner starts the child in a new process group. Nested
  Gears instances and their runners inherit that group instead of creating
  new groups. The owning group is passed through the child environment and
  checked against the actual process group before it is reused. Killing
  the group therefore stops the wrapper, nested Gears and all their tools.
  Only the outer owner cleans up the whole group on normal completion;
  a successful nested tool does not trigger group cleanup.
- On Motor OS, use the existing native descendant-tree cleanup, which
  retains parent relationships after a parent stops. For a nested timeout,
  first stop the nested runner's child tree, then end the nested Gears run;
  the outer owner cleans up any remaining descendants before returning.
  A process must not attempt to walk and kill a tree containing itself.
- Cancellation or a timeout inside a worker or review stops that whole
  owned tree, even if this also ends the nested Gears instance. Its caller
  records the interrupted worker or review; it does not wait for a final
  JSONL record that the killed process cannot send. This deliberately avoids
  a separate cancellation protocol between Gears instances.
- Cleanup failure is reported and blocks starting another turn or writer;
  it is never treated as successful cancellation. No automatic restart is
  part of cleanup.

Test both systems with a worker or review running a tool that has its own
child. Cancel from the parent and trigger a nested timeout; in both cases
the entire owned tree must stop before the caller continues.

## Tools

The [external-tools plan](gears-external-tools.md) and
[contract](../external-tools.md) are the starting point. Phase 0 brings
them in line with this document. Requirements on tool definitions:

- **Arguments.** The model never writes a flag vector. As in Claude Code's
  `Grep` and pi's `grep` and `find` tools, each common command exposes typed
  parameters, and the manifest maps them to a fixed argument vector: a
  string parameter fills one whole argument, a boolean adds a fixed flag or
  nothing, an integer fills a flag's value, an enumerated parameter selects a
  subcommand (`gix`, `lorry`, `cargo`), and a list parameter expands after
  `--`. A value that starts with `-` is refused unless it stands after `--`
  or is listed exactly in the manifest's `allowed_flags` (for example
  `--release` for `lorry`), in which case it is placed before `--`. Each
  common command's parameters are written down before its directory is
  built (phase 3.2). The schema, the expansion and the program's real
  behavior must agree. A tool's name does not establish its effects: GNU
  `find -exec` runs commands, so on Linux a read-only `find` tool exposes
  only name, type and path parameters (sysbox's `find` has no `-exec`).
  A tool that only reads is marked `read_only` in its manifest; "Evidence"
  uses the mark.
- **Platforms.** Differences belong in the tool definition: a manifest may
  give the description, parameters and command per system under `[linux]`
  and `[motor]`, and a tool with no command for the running system is
  listed as not available, never sent. A materially changed definition gets
  a new approval identity.
  On Motor OS, sysbox-backed tools invoke `/system/bin/sysbox COMMAND`
  directly, bypassing the shell wrappers so arguments containing spaces or
  literal glob characters remain intact. This plan does not change those
  existing wrappers.
- **Outcomes.** A result keeps the raw exit status, stdout and stderr, and
  separately says whether the call was an execution error. A manifest lists
  the exit statuses that are normal outcomes (`diff` and `rg` exit 1 for
  "differences" and "no match"); any other status, a timeout, a signal or a
  failure to start is an error. Stderr alone is never an error.

The tools, all run by Gears' process runner. Gears ships `sh`, `ls` and the
common commands as tool directories; the batteries' tools run
`gears-batteries tool NAME`, which reads the arguments as JSON and prints
what the model sees.

| Tool | From | What it does |
| --- | --- | --- |
| `sh` | Gears | runs a shell command, `bash` on Linux and rush on Motor OS, keeping the directory and exported variables between calls |
| `ls` | Gears | lists one directory |
| `rg`, `head`, `tail`, `diff`, `find`, `wc`, `cat` | Gears | read-only common commands, each with its own approval identity |
| `gix`, `lorry` (Motor OS), `cargo` (Linux), `sed` | Gears | common commands that change or publish things |
| `curl` | Gears | fetches one URL over HTTP or HTTPS; the interim way to search and read the web until phase 11 |
| `read_file`, `write_file`, `patch`, `search_files` | batteries | file tools shaped for the model |
| `check` | batteries | runs the workspace's declared check and records the result |
| `todo` | batteries hook | the task list, carried out by the hook so it follows conversation branches |
| `session_search` | batteries | searches saved sessions |
| `memory`, `skill_view`, `skill_manage` | batteries | phase 6 |
| `worker` | batteries | phase 10, optional |
| `web_search`, `web_extract` | batteries | phase 11, optional |

The `wc` directory takes one required string `path` and an optional `mode`
selected from `lines`, `words`, and `bytes`. The modes map to `-l`, `-w`, and
`-c` respectively; omitting the mode uses the program's default counts.
Both systems pass the path after `--`, so spaces, glob characters, and leading
dashes stay literal.

The `cat` directory takes one required string `path`. Linux passes it after
`--`; Motor OS's sysbox `cat` does not recognize that delimiter, so it passes
the path directly. On Motor OS a path beginning with `-` must be written with
a `./` prefix. Spaces and glob characters remain literal on both systems.

The `curl` directory takes one required string `url`. Its manifest fixes the
HTTP and HTTPS protocol set, one request, the 30-second transfer limit, and
response headers; the model cannot add flags or request data.

The `find` directory takes one required `path` and optional `name` and `type`.
`name` is one pattern passed after `-name`; `type` selects `file` or
`directory`, mapped to `-type f` or `-type d`. The path precedes both filters.
Neither platform's mapping exposes command execution. Because sysbox `find`
has no `--`, a leading-dash path must use a `./` prefix.

Details:

- **`read_file`** returns numbered lines in pages of about 30 KB and refuses
  binary files.
- **`write_file`** writes through a temporary file and a rename, keeps
  Windows line endings and byte-order marks, creates missing directories,
  and refuses to overwrite a file unless every page of it was read since it
  last changed. The file tools record their own writes, so the agent can
  edit a file it has just written.
- **`patch`** tries, in order, an exact match, then ignoring trailing spaces,
  runs of spaces, indentation, and escaped `\n` and `\t`. It accepts only a
  unique match, re-indents the new text and returns a diff. There is no
  fuzzy matching.
- **`search_files`** runs `rg --json --no-config -e PATTERN -- PATH`.
- The file tools refuse paths inside the Gears directory, except the current
  session's saved tool results.
- **`sh`** is Gears' tool directory with a script per system, `bash` on
  Linux and rush on Motor OS. The script loads the saved variables, sets
  `PATH` to a fixed value, enters the saved directory (or the workspace if
  that is gone), runs the command with the model's timeout, and saves `pwd`
  and `export -p`. It does not save `PATH`, Gears' own variables, or values
  over 4,092 bytes, which crash rush when set. Its Motor OS description
  lists the commands Motor OS has and how they differ from GNU: `rg` instead of
  `grep`, sysbox's `head`, `tail`, `diff`, `find`, `wc`, `cat` and `less`
  (no `tail -f`), `sed` on the developer image, `gix` instead of `git`, and
  the sysbox additions once they land. For commands not provided it gives
  replacements: `awk` → `sed`, `rg -o -r` or `cut`; `touch` → `: > FILE`;
  `basename`/`dirname` → `${x##*/}`/`${x%/*}`; `tee` → a redirection;
  `timeout` → the tool's own timeout; `mktemp` → a fixed name under
  `/user/tmp`.
- **`check`** runs the argument vector the workspace declares as `check`
  (or `check.motor` / `check.linux`) in `.gears/batteries.toml`, directly,
  never through a shell, and records the outcome. The hook never allows it
  without asking; the permission prompt shows the vector, and the hook
  answers `confirm` whenever the vector differs from the one the user last
  approved in the session, so a grant cannot be reused for a rewritten
  declaration. See "Evidence".
- **`session_search`** scans every branch of every session file, marking
  hits off the current branch, and returns each hit with its session and
  entry id. It scans each time; an index waits until scanning is slow.
- **Git** goes through `gix`. Commands that publish or discard work (`push`,
  and `checkout` or `restore` over uncommitted changes) get the hook's
  `confirm` answer, even when `gix` is allowed for the session.
- **`curl`** takes one parameter, the URL, and runs `curl --disable --silent
  --show-error --max-time 30 --globoff --proto =http,https
  --disallow-username-in-url --include --url URL`, with `/system/bin/curl`
  (Motor OS's own curl-compatible client) on Motor OS and the system's curl
  on Linux. Both HTTP and HTTPS are allowed. Curl performs one fetch and
  never follows redirects: no `--location`, and `--disable` prevents a
  Linux curl configuration file from enabling it. The response includes
  status and headers so a redirect's `Location` is visible. The batteries
  handle redirects in their phase 11 fetch helper, not in curl itself.
  The model cannot supply a request body, request headers, uploads or output
  files, and the URL may not contain a user name or password. Its description
  tells the model how to search through a search page that returns plain
  HTML; pages come back as raw HTML within the tool's output limit. It is
  not allowed without asking, and its output is untrusted (see "Provenance").
  When phase 11's web tools arrive, the user decides whether to keep it.

Tool descriptions are kept short, because small local models have about
32,000 tokens of context; a test keeps the default tool list under a fixed
token budget.

## The batteries' hook

One hook process serves every feature; Gears starts it for each event it
subscribed to. A failure in one feature is reported and the others carry on:
the hook returns that feature's previous state unchanged, its tool list never
depends on a feature succeeding, and setup catches every feature's errors so
a broken skill file cannot stop Gears. A permission question the hook cannot
answer is a denial. Hook state is small and returned only when it changed:
snapshot hashes, the task list, the current turn's partial record and the
reminder count. Everything larger goes to the per-session data.

| Event | What the batteries do |
| --- | --- |
| `initialize` | adds project instructions, memory and the skill list (the prompt snapshot); registers `todo`, `/accept` and `/review`; on resume, asks whether to run an unfinished review |
| `permission` | applies the approval rules below |
| `tool_execute` | runs `todo` |
| `tool_result` | updates the turn record; wraps `curl` output as untrusted; asks the user about a memory change the agent just made |
| `context` | adds a note once when remembered material was removed or corrected (see "Memory") |
| `before_stop` | reminds the model to run the check (see "Evidence") |
| `turn_end` | closes the turn record |
| `before_compact` | marks a review as due when reviews are on |
| `command` | records the user's `/accept` signal in the saved session, or carries out `/review` |
| `answer` | applies the user's answer to a question the hook asked |

**Project instructions** come only from `AGENTS.md` at the selected
workspace root, or `.gears.md` there in its place, limited to 20,000
characters (the first 70% and the last 20% are kept). The hook loads them at
`initialize`. It does not search parent directories or discover instructions
in subdirectories when tools touch files. Project configuration, memory and
task data also belong to this one workspace root.

**Approval rules.** The hook allows without asking: reading and searching
inside the workspace, the read-only common commands, `session_search`,
`todo`, `skill_view`, and `memory`/`skill_manage` calls (which apply the
admission rules themselves). It refuses a short list of destructive
commands even if the user would approve: recursive `rm` of `/`, `/system`,
`/user`, `/user/cfg` or `/devtools`, any `rm` under `/user/cfg`, and fork
bombs, also when hidden behind `sh -c`, `rush -c`, `sysbox rm`, a full path
or an earlier `cd`. It answers `confirm` for commands that publish or
discard work. It applies the worker, review and job policies in `-p` runs.
Everything else is left to the user's saved grants and prompts.

**The turn record** is one JSON line per turn in the per-session data: the
turn number and last entry id; counts of tool calls, execution errors and
repeated calls (same tool and arguments as one of the two previous calls);
the names of failing tools; files the file tools wrote; check runs with
their results; and whether the turn was compacted or interrupted. It is
mechanical and costs no model calls. It is a list of events with entry ids,
not a judgment: a failure followed by a pass is not by itself a lesson.

**The prompt snapshot.** Gears rebuilds the system prompt when it opens a
session, so a memory change would change the prompt and lose the provider's
cache. When a session starts, the hook saves its fragments to a snapshot
named by content hash and remembers the hash; on resume, fork, review and
setup re-runs it returns the same text, so the prompt stays byte-identical
until the next compaction, which takes a fresh snapshot. Additions appear in
the next session. Removals and corrections do not wait (see "Memory").

## Evidence

Keep three different claims separate:

| Claim | What supports it | What it does not establish |
| --- | --- | --- |
| An operation succeeded | A runtime-recorded tool outcome | The user's task is complete |
| A task was accepted | The user's explicit `/accept` signal in the saved session | Correctness beyond the available checks, or that a proposed lesson will help later |
| A lesson improves performance | Evaluation on other representative tasks, including regressions and cost | Universal usefulness across models or projects |

**Check results.** Only the `check` tool produces a check result: it records
the argument vector, the system, the exit status, the duration and the
session entry id. Shell text that resembles the check is not recognized, so
`lorry test || true` in `sh` counts for nothing. A check result is current
until any later call to a tool that can change the workspace (`write_file`,
`patch`, `sh`, or any external tool not marked `read_only`); after that it
is stale. Agent-editable tests can support development, but a passing check is
not by itself acceptance.

**Task acceptance** (question 5). The user types `/accept` to give an
unambiguous signal that they accept the current task's result. The command
records that signal in the saved session and replies "Task accepted."
It takes no arguments and leaves the session open for the next task.
A later review cites the saved entry as evidence of acceptance. The system
does not infer an acceptance signal from ordinary conversation, an agent's
claim that it is done, a passing check or permission to run a tool.

This is a small hook command using existing session storage. It needs no
separate `gears-batteries accept` CLI, acceptance file, UI reminder, commit
or hash of uncommitted changes. It does not depend on Git or Gix, require a
current passing check, make a model request or schedule a review. Check
receipts retain their independent meaning as development evidence.

**The `before_stop` reminder.** When a check is declared, a tool that can
change the workspace ran this turn, and no current passing check exists,
the hook answers `before_stop` with a one-line reminder, at most three times
per turn. It is feedback so the model sees the missing or failed check and
can act; it is not a verifier. It is never sent in reviews, workers or
jobs.

**Provenance.** Approval to run a command does not make its output
trustworthy. Text from `curl`, web tools, workers and session-search hits
from sessions that contain such text is wrapped in an untrusted marker (the
hook wraps `curl` results at its `tool_result` event); any copy
of the marker inside the text is defused. Every route keeps the source:
session-search hits carry session and entry ids, worker summaries carry the
worker's session id. A content scan can flag planted instructions or leaked
secrets but cannot certify anything as trusted.

## Memory and skills

**Kinds of memory.** Each memory entry records its kind: *user* (the user
said so), *observed* (a recorded tool outcome shows it) or *inferred* (the
model or a review concluded it). It also records its source (session and
entry ids), scope (global or this workspace), the project or tool versions
it applies to when that matters, and its date. Entries are separated by `§`
and start with a header line holding these fields; the text follows.
`USER.md` and each `MEMORY.md` have a size limit set in `batteries.toml`
(defaults 1,375 and 2,200 characters), which is resource policy, not a
research result.

**Admission** (question 3). Nothing enters memory without the user's
approval. When the agent adds, changes or removes a memory entry in an
interactive session, for example because the user asked it to remember
something, the change goes to `pending` and Gears shows it to the user at
once, with the number of other memory changes waiting, and offers three
answers: approve, deny or postpone. A postponed change stays in `pending`.
In a `-p` run, and for reviews, nobody is asked and changes wait in
`pending` until the user runs `gears-batteries pending`. Skills written or
changed by the agent are hidden until the user approves that exact version,
`NOTES.md` included. The `memory` tool tells the model the user's answer.
Replacing a whole file is refused. Approval authorizes use; it does not
establish usefulness.

**The `memory` tool** adds, replaces or removes single entries by id in
`USER.md`, the global `MEMORY.md` and the workspace's `.gears/MEMORY.md`.
Its description says that workspace facts go to the workspace file with
paths relative to the workspace, that a fact true on one system names it,
and that facts about the machine go to the global file. Exact duplicates are
ignored.

**Skills** are directories with a `SKILL.md` in the agentskills.io format,
optionally with a `NOTES.md` of quirks seen in use. `skill_view` loads one
approved skill; `skill_manage` proposes new skills and edits. A `SKILL.md`
the agent writes must have four sections: when it applies, the steps, how
to check that it worked, and its pitfalls; its size limit is configurable.
On Motor OS, only skills whose `metadata.platforms` string names `motor`
are listed (whitespace-separated platform names in the standard metadata
extension map).
The description tells the model to load at most a few skills per task.
Successful use is recorded as an observation, not as proof that the skill
caused it, and age alone never makes a skill true or false.

**Storage** (question 4). Memory assumes one writer and no concurrent
modifications. Gears checks its own lock (runtime guarantee 11);
`gears-batteries` adds no locking or versioning. Memory files and skills are
plain files, written as runtime guarantee 12 describes. Each pending change
is a file of its own. Approving a pending change that replaces or removes an
entry that has since been changed or removed fails, and the user is told
why. The user may edit memory files by hand; Gears reads them as they are.

For approval, first validate the pending change against the current file,
then append the approval to `changes.jsonl`, write the approved memory or
skill files, and finally remove the pending item. The approval records the
change, its source and date, and the resulting workspace-memory hash when
applicable. For denial, append the decision and then remove the pending
item; postponement leaves it alone. Stop and report any write failure.
A crash can leave a recorded approval not yet applied, or an applied change
still pending; neither prevents Gears from starting, and the user can
inspect the files and history. There is no
transaction or automatic recovery across these writes. `history` shows the
decisions, reviews read denials so they do not propose them again, and the
user or agent can find where an entry came from.

**Layout.** Under the Gears directory, `batteries/` holds `USER.md`,
`MEMORY.md`, `skills/`, `archived-skills/`, `pending/`, `changes.jsonl`,
`skill-loads.jsonl`, `snapshots/`,
`sessions/<id>/` (turn records, `sh` state, file-read records and review
marks) and `eval/`. `batteries.toml` in the Gears directory holds the
user-wide settings: memory size limits, the review models and the proposal
cap. A workspace's `.gears/` holds its `MEMORY.md`, its own `pending/`,
`tasks/` for orchestration, and `batteries.toml` with the project's `check`
command. Paths inside new batteries data files are relative to the Gears
directory or the workspace top; ids are opaque; text is UTF-8 with `\n`;
names are ASCII;
there are no symbolic links; every file carries a format version. An
absolute path in these files appears only where the user wrote one; if it
is missing here, the item is shown as unavailable and skipped, never
deleted. Existing Gears sessions and their workspace-path identity are not
migrated by this plan.

**Workspace memory from elsewhere.** A `.gears/MEMORY.md` that arrives with
a clone is not locally approved because it was cloned. `changes.jsonl` in
the Gears directory records the hash of each workspace memory file the user
approved. When a workspace's `MEMORY.md` has a hash not recorded there,
whether it came with a clone or was edited by hand, it is not used, and
Gears asks the user at session start whether to approve it as it is. A user
who copies the Gears directory along with the workspace keeps the approvals.
Live modification by code in the workspace is deferred with confinement,
as described above.

**Removals and corrections.** Current user and project instructions take
precedence over remembered heuristics. When an entry or skill is removed or
corrected, it stops being used everywhere: at each `context` event, every
Gears process running the hook (interactive, resumed, forked, worker or
review) compares its snapshot with the current files and, once, adds a note
saying which material was removed and what replaces it. An ordinary resumed
or forked session whose snapshot holds removed material gets a fresh snapshot,
at the cost of one cache miss. A saved-prefix review retains the resource
references checkpointed at the actual request and delivers current corrections
after that prefix, including after compaction. Its current permissions and
review role remain in force. A removal affects future use, not past actions, and
cannot make a model forget text it has already seen.

**User commands.** `gears-batteries pending` lists the waiting changes and
approves, denies or postpones each, showing it against what it replaces, the
evidence it cites, and which past sessions used the old version. `history`
lists decisions. `status` shows on one screen whether reviews are on and for
which models, what is pending, and the last review and eval results. `cleanup`
proposes archiving unused agent-written skills and points out skills whose
"when" sections overlap; it never archives or merges on its own. Invoke it
with `cleanup --since YYYY-MM-DD`, an explicit midnight-UTC cutoff. It stages
only approved agent-written current versions without recorded loads or loaded
snapshots since that cutoff. Recent approvals, unavailable origin evidence,
damaged history and prior archival denials protect a version. The proposal
states the inspected history and its limits; deleted sessions and old ephemeral
runs cannot be reconstructed. Identical normalized "when" sections are only
inspection hints. `pending` supplies the separate archival decision.
Approved skill removals retain both files in a versioned, content-addressed
archive before withdrawing the live version. Successful `skill_view` loads
are recorded separately from saved conversations, including ephemeral runs;
these are load observations, not evidence of usefulness.

## Reviews

A review is a background `gears --fork SESSION --ephemeral --output jsonl -p
INSTRUCTIONS` run in which the model reads a copy of the conversation and the
turn records and proposes changes. Reviews are off by default and are an
experiment until phase 9 says otherwise; turning them on names the executor
and reviewer models in `batteries.toml`, because the decision depends on that
pair and the workload, not on whether a model is hosted or how large it is.

- **When.** A review is marked due before a compaction and when the user
  asks with `/review [focus]`; the focus sentence takes priority over the
  general instructions. A session may hold several tasks and a task may
  take several turns, so turns are not review boundaries. `/accept` records
  the user's signal and does not create a review mark. Marks are stored
  in the per-session data with the session id and the last entry at the
  time, so an interrupted or repeated review handles each mark once.
- **Who runs it** (question 6). Gears' after-turn command starts
  `gears-batteries review` after a completed turn and after a hook command
  such as `/review`; it runs the session's due reviews and is stopped if
  the user starts another turn; the review then runs after that turn. A
  review still due or running when Gears exits is stopped. When the user
  later resumes that session, Gears asks whether to run it; if not, the
  mark is dropped. A new session never runs reviews left over from other
  sessions, so a review marked just before the user quits runs only if the
  user resumes that session.
- **What it is told.** "Nothing to save" is the default outcome. Every
  proposal cites the entry ids that support it. A procedure may be proposed
  when the conversation shows it run and working, including a successful new
  procedure. The user's saved `/accept` signal is evidence that they
  accepted the result; it does not establish that a skill caused success.
  A restarted worker may reflect a spent budget rather than a bad
  procedure. The review also receives the changes the user denied, so it
  does not propose them again.
- **What it may do.** Read-only file tools, session reading and proposals
  through `memory` and `skill_manage`. All of its output is pending; it never
  writes live memory or skills and cannot run the check. The number of
  proposals per review is capped in `batteries.toml` (default 4), as
  resource policy.

Keep the stable system instructions and tool definitions separately from
conversation history. A review reuses the prefix saved at its marked parent
entry and appends its review instructions after that prefix. Compact oversized
history while retaining the prefix; the original saved branch remains readable.
Unchanged tool schemas may be advertised while review policy still denies
writes and commands. Changed schemas or a different model/provider can reduce
cache reuse. Cache hits are measured, not guaranteed.

## Measuring whether learning helps

Compare a fixed baseline against the same setup plus automatically proposed
and accepted learning. Keep user instructions, `user` memory entries and
human-curated skills in both arms; "all memory versus no memory" answers a
different question. Freeze learning during evaluation (reviews off) and use
isolated copies of repositories, sessions and memory. Holdout answers must
not leak through session search, review records or another run's artifacts.

**Tasks** live in `eval/tasks/<name>.toml`: the repository and commit to
start from (or a workspace to copy), the prompt, and acceptance criteria a
program can evaluate, including regression protection, not only a passing
build or a matching string. The batteries may propose tasks from sessions
whose result the user accepted; the user approves them in `pending`. A
held-back set is written by the user and never shown to reviews.

The manual command is `gears-batteries eval --task FILE [--task FILE ...]
--config FILE --provider NAME --model NAME --trials N --seconds N
--command-seconds N --criterion TEXT --output DIR`, with optional `--root DIR`
and `--gears PROGRAM`. Current execution uses workspace copies; repository-at-
commit cloning remains an alternative. It captures all task templates, approved
learning and tool definitions before model requests, pins executable versions,
checks each starting workspace's regressions, alternates arm order and preserves
per-task and aggregate reports. Regular fixtures use loopback models only.

**Runs.** Each run clones the repository with `gix` (or copies the
workspace) into a temporary directory and runs `gears --config EVAL
--ephemeral --output jsonl -p PROMPT` with the model, configuration,
starting state and budgets pinned, repeating each arm the configured number
of times. Because `--config` does not move the Gears directory, the eval
points each run at its isolated copy with `--gears-dir DIR`, a flag added
in phase 9 for this purpose only.
The flag requires an explicit configuration, a prompt and a fresh ephemeral
session; it rejects resume and fork. Relative directory paths become absolute
before startup. Descendants inherit the selected directory, with a separate
lock owner when a nested Gears selects another directory.
Repeating a few tasks does not create
broad coverage: a small
personal suite can find large failures but cannot establish general
improvement.

**Report.** Accepted-task rate, regressions, elapsed time, model and tool
cost, and human review effort including denied proposals and the cost of
reviews and evaluation, attributed to particular memory and tool versions.
The user assesses improving, degrading, equivalent within a stated tolerance,
or insufficient evidence against the criterion recorded before the run; failing
to detect a difference is not equivalence. The initial command's report remains
`insufficient_evidence`: its free-text criterion is not an executable statistical
rule, and missing historical review/tool cost or human time stays unknown. It
never changes review settings. The eval uses a real model, is run by hand and is never part of
`full-test`. Useful tools and curated memory stay available whatever it
finds.

## Optional orchestration and services

**Workers and the supervisor.** The `worker` tool starts `gears --config
WORKER --output jsonl -p GOAL` with a saved session, the provider and model
it names, explicit scope and a budget. A reading worker has the read-only
tools; a writing worker also has `write_file`, `patch`, `sh` and `check`;
neither has `worker`, `memory`, `skill_manage`, web tools or publishing
`gix` commands. Its authority comes from the hook's worker policy, since
saved allowances do not apply in `-p` runs. Only one agent writes a shared
workspace at a time, the supervisor included; readers record the source
state they read. A worker returns a summary written for its goal, with links
to its session and precise excerpts where needed, never raw dumps; its
summary is untrusted text.

The supervisor remains responsible for the original task and keeps a task
file, `.gears/tasks/<id>.toml`, written only through the `worker` and
`todo` tools: the request, work items with their scope and acceptance
check, attempts with session ids, usage and check results, verdicts, budget
and spend. Finishing or dropping every work item is not enough: dropping
required work leaves the task incomplete unless the user changes its scope,
and a narrowed check does not replace task-level acceptance. Design and
review tasks need an acceptance rubric rather than a token build command.
An optional evaluator, a separate `gears -p` run with the reading policy
that sees the request, the diff and the check output but not the plan,
adds scrutiny but may share the same model's blind spots; its opinion is
not independent experimental evidence. Budgets cover the supervisor,
workers and evaluator together.

**Scheduler.** Jobs are created by the user in a file the agent has no tool
for, each with a schedule, a prompt, a budget and an explicit tool policy.
Each run is `gears --config JOB --ephemeral --output jsonl -p PROMPT` with no
standard input. The scheduler advances a due job's next run time before
starting it, so a slot never runs twice.

**Gateway.** Single-user: an OpenAI-compatible HTTP API on the VM's address,
later Telegram. It maps each conversation to a Gears session it issued
(session id only, no client-supplied history), forwards approval questions
as one-time-code messages or response events offering allow once and deny,
and treats no answer as deny. Stateful session and approval extensions
cannot be assumed to work with any OpenAI-compatible client. It compares its
API key in constant time and limits request size, connections and header
time before checking it.

Services are optional, run in the foreground, and add no boot work.

## Testing and gates

- Whole-turn tests use Gears' recording mock provider (`gears::mock`, and
  `gears-mock-provider` in the VM) to check prompts, cache markers and
  approval flows. No automated test reaches a real provider or the
  Internet; web and Telegram mocks are local Rust servers.
- The regression backlog in notes Appendix D supplies scenarios: interrupt
  or kill mid-round then resume; hooks across an interrupt, `/new` and
  `/quit`; a reply cut off inside a tool call; a reply with only reasoning;
  a result larger than the context against a mock that rejects large
  requests; a compaction that cannot shrink; a call and its result on either
  side of the compaction point; malformed tool arguments.
- Crash-cleanup tests leave stale locks, temporary files, a partial final
  session record and an unfinished tool round. Gears must start again and
  complete a new mock-provider turn without replaying old calls or needing
  manual file repair.
- Process cleanup tests run on Linux and Motor OS: cancel a worker or review
  while its tool has a child of its own, exercise a nested timeout, and
  verify that no descendant remains before another turn or writer starts.
- Tool argument tests in the VM cover spaces and literal glob characters
  through direct sysbox invocation. Local HTTP tests cover a plain HTTP
  fetch and a redirect returned without following it; phase 11 tests the
  batteries' bounded redirect handling separately.
- Gears changes run Gears' own tests and `test-gears-http.sh`. The batteries
  add `src/tests/test-gears-batteries.sh` to `full-test.sh` and a VM test,
  `test-gears-batteries-vm.sh`, run like `test-gears-http-vm.sh` when
  `FULL_TEST_VERIFY_DEV_SOURCES=1`. Gears and the batteries are non-core
  components: their gate is these tests plus `full-test-dev.sh --release`.
- The sysbox utilities are core OS patches: each passes `full-test.sh` three
  times in debug and three times in release before it is committed.
- Real-model sessions and the eval are user-run, outside `full-test`.

## Implementation plan

Each step is one or a few patches of 100 to 300 lines with their tests, and
every phase leaves a working Gears. Phases 1, 2 and the sysbox track can
proceed in parallel. Phase 3 needs 0 and 1; 4 needs 1; 5 needs 3 and 4; 6
needs 5; 7 needs 5; 8 needs 6 and 7; 9 needs 8; 10 to 12 are optional and
need 5.

**Phase 0. Reconcile the companion documents.** Update
`src/bin/gears/external-tools.md` and `gears-external-tools.md`: remove the
`profile` and `spawn` fields from version 1 (confinement is deferred);
replace `parallel_safe` with `read_only`, since parallel tool runs are out
of scope; add the exit-status rule and the typed-parameter, `allowed_flags`
and `--` rules from "Tools"; make `sh` run `bash -c` on Linux and keep the
directory and exported variables on both systems; add the `gears-batteries`
sibling rule and direct sysbox invocation on Motor OS; state that the
configuration move belongs to phase 2.1 and that step 1 only reads the moved
file; apply the permission order decided
in question 1; replace references to the old G and Q labels and to "step
8a" with this plan's phase and question numbers. Documents only, one patch.

**Sysbox track (independent).** Small patches, with command regressions in
sysbox's `examples/utility-tests.rs`, a `docs/tools.md` entry, a wrapper in
`img_files/motor-os-base/system/bin` and the developer image's command list.
The sysbox-owned test executable runs from `full-test.sh` in both profiles.
Per the user's 2026-10-06 scope restriction, do not modify any other Motor OS
crate except Gears; build/test scripts, documentation and packaging can connect
the utilities without changing `systest` or OS libraries.
Each covers the flags models use, matches GNU's output and exit statuses for
them, and refuses any other flag with a message naming it.
- S1. `mkdir -p` through `create_dir_all`.
- S2. `sort`: `-n -r -u -k -t -f -h -s -c -o`, byte order, no locale, in
  four patches. First add byte comparisons, `-r -u -f -s -c -o`, literal
  operands and output handling; then exact numeric/human comparisons
  (`-n -h`); then field ranges and separators (`-k -t`); finally local key
  modifiers (`b/n/h/f/r`). Each patch receives the full core gate.
- S3. `uniq`: `-c -d -u -i`.
- S4. `cut`: `-b -c --complement`, followed by `-d -f -s` field selection.
- S5. `tr`: single-set `-d -s -c`, ranges and POSIX classes; then translation
  and two-set deletion/squeezing.
- S6. `xargs`: `-0 -d -n -I -r -t`, running the command directly, never
  through a shell.

**Phase 1. Turn and data integrity in Gears.** Guarantees 2 to 4, 6, 7, 9,
11 and 12, and guarantee 8 for the children Gears starts today; later phases
meet guarantee 8 for the children they add.
- 1.1 Tool-call results in three states; the closing note for a cut-short
  round; no empty replies; unknown content skipped; same-index calls kept
  apart; no re-execution on resume. Discard incomplete updates left by a
  crash only as needed to restore usable session history (guarantee 12).
  Tests that fail on today's Gears.
- 1.2 Lifecycle hooks after cancellation: clear the cancellation before
  `turn_end`, `session_end` and `session_start`; route the turn loop's error
  exits through one function so hooks see the interrupted turn's error entry;
  report "cancelled".
- 1.3 Bounded compaction input: send the summarizer a shortened text of the
  old messages, limited in proportion to the model's context; cap each kept
  tool result.
- 1.4 Replace the `unreachable!` at the end of the turn loop
  (`runtime.rs:329`) with the normal "too many rounds" error, which retries
  in phase 2 could otherwise reach.
- 1.5 The lock file: refuse a second Gears, replace a lock left by a crash
  (the pid is not running, or is not Gears: `/proc` on Linux, the process
  list on Motor OS), and let reviews and workers run under their ancestor's
  lock. Only Gears checks it; batteries commands do not participate.
- 1.6 One helper for writing long-term files (temporary file, rename,
  startup cleanup), used by every Gears-owned file; the batteries reuse it.
  Apply guarantee 12's minimal crash cleanup so leftover inconsistent state
  does not require manual repair before Gears can start again.
- 1.7 Implement the process ownership and cancellation rules above in the
  shared runner, including cleanup after normal exit. Later phases reuse
  these rules when adding nested Gears processes.
- Done when the notes §4.4 reproductions pass as regression tests and a
  second interactive Gears on the same directory is refused; after a crash,
  Gears starts again in that workspace and completes a new turn.

**Phase 2. Providers.**
- 2.1 Named providers in `gears.toml`, which moves into the Gears directory,
  `/user/cfg/gears/gears.toml` and `~/.gears/gears.toml` (the old locations
  are read as a fallback); `api_key_file` (the old
  `key_file` accepted) and `ca_cert` may be relative to it;
  `default_provider` and `default_model`; `--provider`; `/provider` and
  `/model` in both UIs, with `--default` writing the Gears-owned
  `provider.toml`. A switch applies at the next turn, is recorded in the
  session and resets the cache identity.
- 2.2 Reasoning echo where the provider requires it (per host, with a
  configuration override).
- 2.3 Cache markers on the system prompt and the last two messages, and
  `prompt_cache_key` derived from the prompt's start.
- 2.4 Bounded retries for rate limits, server errors and network failures,
  only before any output is visible, honoring `Retry-After`, shown as
  notices with reason and wait; a cancel during the wait ends the turn.
- Done when a mock-provider test switches between two providers mid-session
  and recorded requests show reasoning, markers and retries as specified.

**Phase 3. External tools.**
- 3.1 Steps 1 and 2 of the external-tools plan: the registry and the process
  executor replacing the built-in `sh` path, with the typed-parameter,
  `allowed_flags` and `--` rules, per-system manifest tables, exit-status
  outcomes and the one process runner.
- 3.2 Step 6: shipped directories for `sh` (`bash` on Linux, rush on Motor
  OS, with the saved directory and variables and the Motor OS description
  from "Tools"), `ls`, the common commands and `curl`; each common command's
  parameters are written down first. Sysbox-backed Motor OS commands call
  sysbox directly and have VM tests for spaces and literal glob characters.
  The `curl` test fetches plain HTTP from a local server and verifies that a
  redirect is returned without a request to its destination.
- 3.3 Steps 3 to 5: enablement, the six approval choices, the hook's
  `confirm` answer, and both UIs, with this order for every call: Gears
  first looks up the user's saved answer (a session answer replaces a global
  one). A saved denial or a hook's denial refuses the call. A hook's
  `confirm` asks the user, or refuses when nobody can answer. Otherwise the
  call runs if a hook allows it or, in an attended run, the user saved
  "allow"; with neither, Gears asks the user, or refuses in an unattended
  run. Grants are read for every decision, so a revocation applies to the
  next call.
- Done when the external-tools plan's step 7 gate passes.

**Phase 4. Extension points in Gears.** Each is useful on its own.
- 4.1 A hook names the events it wants.
- 4.2 The `before_stop` event: after a reply that follows at least one tool
  round, a hook may answer with a short message, which Gears stores as a
  user-role note before running one more round, at most three times per
  turn.
- 4.3 Hook setup re-runs after `/new`, `/resume`, `/fork`, `/clone`, a
  provider switch and a compaction, with the reason, provider and model in
  `initialize`.
- 4.4 A public function reads a session that another process is writing;
  `--fork` may be combined with `--ephemeral`.
- 4.5 `--output jsonl` for `-p` runs: a first record with session id, path
  and format version; records for text, reasoning, tool starts, output and
  results, notices, usage and turn end; a final record with success, error
  or answer, and usage.
- 4.6 An after-turn command, interactive interfaces only, started after the
  end-of-turn hooks of a completed turn and after a hook command, with the
  session path and configuration path; Gears stops it and waits before the
  next turn writes anything, when the session changes and at exit, using
  the process-tree ownership rules above, including for nested Gears and
  its tools. `turn_end` gains the number of tool rounds and the last entry id.
- 4.7 Hook commands, questions and hints. At `initialize` a hook may register
  slash commands with a one-line help; Gears lists them in its help and
  sends them to the hook as a `command` event instead of to the model. A
  hook's result may ask the user a question with a few labeled answers;
  Gears shows it in both UIs and sends the answer back as an `answer` event.
  In a `-p` run nobody is asked and the hook is told so. A hook may also set
  a one-line hint, which the TUI shows in its status line and the line UI
  prints after the turn.

**Phase 5. The batteries crate and everyday coding.**
- 5.1 The crate, its build (repeating Gears' `[patch.crates-io]` entries)
  and packaging: the Makefile, `full-test-prepare.sh`, the developer image's
  program and source lists, and the Lorry build in `test-dev-sources.sh`.
- 5.2 The hook skeleton with failure isolation, workspace-root project
  instructions and the prompt snapshot; no parent or subdirectory discovery.
- 5.3 `read_file`, `write_file`, `patch`, `search_files`.
- 5.4 `todo`, the turn record, the approval rules and the destructive list.
- 5.5 `check`, its declaration in `.gears/batteries.toml`, current/stale
  check results and the `before_stop` reminder.
- 5.6 `session_search`.
- Done when a VM test with a scripted mock model reads a crate, patches it
  and runs `check`, and a mock model that finishes without a check gets the
  reminder. **Decision point:** the user's real-model sessions; continue,
  change course or stop.

**Phase 6. Memory and skills.**
- 6.1 Data layout, `pending/` and `changes.jsonl`.
- 6.2 The `memory` tool with kinds, pending changes and the immediate
  approve/deny/postpone question, using the write order in "Storage".
- 6.3 Snapshots of memory, workspace-memory approval by hash, and the note
  for removed or corrected material.
- 6.4 `pending`, `history` and `status`.
- 6.5 `skill_view`, `skill_manage` and exact-version skill approval.
- 6.6 Optional: a reviewed import of Hermes skills that suit Motor OS, with
  its MIT notice.
- Done when an entry the user approved in one session appears in the next
  session's prompt but not the current one's; a postponed entry stays in
  `pending` and a denied one appears in `history`; a resumed session sends
  the same prompt; a removed entry disappears from a running session's next
  request through the note and from resumed sessions' snapshots; a cloned
  workspace's unapproved `MEMORY.md` is not used; and approving a change to
  an entry removed in the meantime fails with a message.

**Phase 7. Task acceptance.** The small `/accept` hook command, as "Task
acceptance" describes. Done when it is listed in help, records the user's
signal in the saved session, replies "Task accepted." and preserves the
signal on resume without running a check or making a model request.
No repository inspection or separate acceptance CLI is needed.

**Phase 8. Reviews** (off by default; question 7 is discussed in this phase).
- 8.1 Review marks, the after-turn runner, `/review [focus]`, and the
  question on resume.
- 8.2 The review configuration and instructions, adapted from Hermes's with
  "nothing to save" as the default, cited evidence, the proposal cap and
  the denied changes.
- 8.3 `cleanup` proposals.
- Done when a review of a session with nothing notable proposes nothing, a
  proposal over the cap is refused, a review request shares the parent's
  saved stable prefix even after history compaction, an interrupted review leaves nothing half-written and
  handles its mark once, and a new session does not run another session's
  review.

**Phase 9. Measurement** (question 7 is required for its first real-model run). Task
format, isolated copies of the Gears directory and repositories, the two
arms, repeated trials and the report; then the user's first run. Its
result decides whether reviews are turned on for a given pair of models.

**Phase 10 (optional). Orchestration.** The `worker` tool with reading
workers first, then one writing worker, the task file, budgets, and the
optional evaluator. Done when a VM test with two mock models sees a worker
fail its first attempt, the supervisor restart it with a changed
instruction, the evaluator reject once and accept the second time, and
interrupting the supervisor leaves no process behind.

**Phase 11 (optional). Web tools** built on `curl`, with no separate service
(question 8): `web_search` fetches a search page from a URL template the
user configures and returns the results' titles and links as text;
`web_extract` fetches one page and returns its text without the HTML. Both
refuse private addresses, unless the configuration allows them, and URLs
containing a known secret. Their shared fetch helper invokes curl once per
hop, with HTTP and HTTPS enabled and redirect following disabled. The
batteries resolve `Location` against the current URL for 301, 302, 303, 307
and 308 responses, and apply the URL checks again before each new fetch.
Allow at most five redirects within one 30-second deadline and the tool's
total output limit; a missing or invalid destination, a loop or an exceeded
limit is a reported error. No change to curl's redirect support is needed.
Done when local HTTP tests cover direct fetches, relative and absolute
redirects, rejected destinations, loops, limits and cancellation.

**Phase 12 (optional). Scheduler and gateway** (needs question 10).
Approvals and cancel over standard input for `-p` runs (Gears prints a
`permission_request` record and reads the answer as a line; closed input
denies; `cancel` stops the turn); the scheduler; the HTTP API; Telegram. The
services run in an rmux pane or are started from the user's `rush.toml`
(`spawn-detached`), never at boot (question 9). Done when a VM test
holds a Telegram conversation with a mock Bot API, with one approved and one
denied call, and a scheduled job runs once.

## Open questions

Numbered in the order of the phases they affect. Questions 1 to 6, 8 and 9
were decided on 2026-10-02; the decisions are written into the sections
above. Questions 7 and 10 are open and will be discussed when phases 8 and
12 are reached.

1. **When a hook and the user's saved answer disagree, which wins?**
   *Decided:* no tool runs before Gears has looked up the user's saved
   answer for it, whatever a hook says. A saved denial always refuses the
   call. When the user has no saved answer for the tool, a hook may still
   allow the call; this is how the batteries allow read-only tools without
   asking and how workers run. The full order is in phase 3.3.

2. **Does workspace recovery belong in the product?** *Decided:* no. The
   user keeps the workspace in git or gix, and Gears adds no checkpoints or
   rollback.

3. **What may the agent add to memory without asking the user?**
   *Decided:* nothing. A memory change the agent makes in an interactive
   session goes to `pending` and is shown to the user at once, with the
   number of other changes waiting, to approve, deny or postpone (see
   "Memory and skills").

4. **How are memory writes handled?** *Decided:* assume one writer and no
   concurrent modifications. Gears alone owns and checks its pid lock file
   (runtime guarantee 11); batteries commands do not check it, and independent
   invocations are the user's responsibility. Use temporary-file replacement
   for individual files (guarantee 12), and the simple decision-log, content,
   pending-removal order in "Storage". No additional locking, transactions,
   automatic recovery across files, version store or `undo`.

5. **What counts as a finished task, and who says so?** *Decided:* the user,
   with the explicit `/accept` signal, saved in the session and acknowledged
   with "Task accepted." No repository inspection or check gate is required
   (see "Task acceptance").

6. **What happens to a review that has not run when Gears exits?**
   *Decided:* it is stopped. When the user resumes that session, Gears asks
   whether to run it; new sessions never pick up other sessions' reviews.
   So a review marked just before the user quits runs only if the user
   resumes that session.

7. **What result should turn reviews on?** (discussed in phase 8, needed
   before its first real-model run) Reviews may make the agent better, make no difference,
   or make it worse, and they cost money. The eval in phase 9 runs the same tasks twice, once with what
   reviews taught the agent and once without, and compares the results.
   Before the first run, the user writes down what result would be good
   enough, for example: "With model A doing the work and model B writing
   the reviews, on my 15 tasks, at least two more tasks succeed, no task
   that used to succeed now fails, and reviews cost less than $10 a month."
   Recommendation: keep reviews off until a run meets the user's bar.

   *Deferred:* the user considers this complicated; it is discussed when
   phase 8 is reached.

8. **Which web services?** *Decided:* none; the agent uses `curl`, as a
   tool from phase 3 and inside phase 11's web tools.

9. **How do services keep running?** *Decided:* in an rmux pane or started
   from the user's `rush.toml`; nothing at boot.

10. **Can the scheduler and gateway run while the user is in Gears?**
    (before phase 12) Each scheduled job and each gateway message runs
    Gears. Because only one Gears may run per Gears directory, a job would
    be refused while the user has Gears open, and the user could not open
    Gears while a job runs. Recommendation: a job waits until no Gears is
    running, and is skipped with a log line if it is still waiting when its
    next run is due; a gateway message waiting longer than a minute gets the
    reply "Gears is busy on this computer, try again later"; and an
    interactive Gears started while a job runs says which job holds the
    lock.

    *Deferred:* reviewed when phase 12 is reached.
