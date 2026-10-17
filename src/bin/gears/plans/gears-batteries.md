# Gears batteries: design and implementation plan

Status (2026-10-16): the batteries were simplified on 2026-10-15 (commit
`d9921bb2`). The background reviewer, the queue of proposals, agent-written
skills, the turn records and the evaluation harness are gone; what stays is
the everyday agent and a memory the user controls one entry at a time.
"What remains" lists the open items. Phases 0–9 of the previous plan were
implemented and gated before this change; that plan is in git history
(commit `34c3a012`).

## Purpose and scope

Make Gears a useful personal coding agent on Motor OS and Linux, with file
and shell tools, project instructions, task tracking, searchable sessions,
a small memory and user-written skills. Learning is limited to what the
user can see and judge in the session: the agent proposes one memory entry
at a time and the user says yes or no.

The direction fits the [Gears redesign](../redesign.md): Gears owns the
agent loop, providers, sessions, cancellation and user interfaces; optional
batteries supply coding workflows.

Not in this plan: tool confinement (deferred, below); an `undo` command or
other rollback of memory, skills or workspace files (a capable model can
reverse its own changes from the session history, and the user keeps the
workspace in git or gix); a background reviewer; agent-written skills;
measuring whether learning helps; worker orchestration, web tools, a
scheduler or a gateway; Anthropic's Messages API; MCP; a pass in which the
model rewrites tool descriptions; running read-only tools in parallel;
model-written scripts; guest users; and commands that keep running after
their tool call ends.

## The 2026-10-15 simplification

Until 2026-10-15 the plan had a second model review each session in the
background and propose memory and skill changes into a queue, with a test
harness to measure whether that was worth its cost. Asked how a person
would use the harness (ten task files with check scripts and forty agent
runs per measurement), the user found the workflow too complicated. The
background reviewer was the one choice everything else followed from: the
reviewer model pair, review marks, the after-turn runner, the queue, the
evidence files, the question on resume, and finally the harness and the
question of which result would turn reviews on. That stack was about two
thirds of the batteries code and held all five bugs deferred on 2026-10-07.

The [research review](../../../../docs/self-improving-agents-review.md)
finds that self-written material helps only when it is checked before it
is kept, that small models lose the most, and that an unmeasured loop
should stay off. Its clearly positive results all had executable tests
checking what the agent wrote. Gears never had that; it had the user's
approval. The new design keeps the one check Gears has, the user, and makes
it the only one:

- Learning happens only while the user is in the session. The agent
  proposes a memory entry, the user answers yes or no at once, and nothing
  is written otherwise. Nothing is queued for later.
- The agent proposes either because the user asked it to remember
  something or, when the user turns offers on, at most one lesson after a
  task whose check passed. Offers are off by default, as the research
  advises for small models.
- Skills are written by the user. Human-written skills are the research's
  strongest positive result; agent-written skills without executable tests
  are its clearest negative one.
- Gears makes no claim that learning helps and does not measure it. The
  user keeps offers on only if they are worth a yes often enough.

What this gives up: a separate and possibly stronger reviewer model (one
study found the extractor had to be stronger than the actor), learning
while the user is away, and measurement. What it keeps from the research:
writes only with evidence the user has seen, small bounded edits one entry
at a time, "nothing to save" as the default, dated and sourced entries, a
log of declined proposals shown to the agent, little in the prompt, and
the checks (the project's check, the destructive-command list) out of the
agent's reach.

How the agent writes memory, and why it cannot do so at will: the `memory`
tool is the only way. The hook intercepts every call, shows the user the
exact entry, writes it only on yes, and records yes or no in a log. The
file tools refuse the Gears directory and `.gears/`; shell commands need
the user's permission like any other command, and confinement is deferred.
There is no second approval and no slash command for approval: the
question the hook asks is the approval.

## Retained decisions

- Keep the names `gears` and `gears-batteries`. The `gears` package
  (`src/bin/gears`) builds a second binary, `gears-batteries`, from its
  `batteries` module; its first argument picks its role: `hook` and
  `tool NAME` for the roles Gears starts, `history` and `status` for the
  user. It uses Gears as a library, and Gears runs every model/tool loop.
  It is installed beside the `gears` executable (`/devtools/bin` on Motor
  OS, the directory holding `gears` on Linux). The shipped manifests and
  hook configuration name it by the bare name `gears-batteries`, which
  Gears resolves to that sibling; this is the one exception to the
  contract's rule against bare program names.
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
  saved allowances do not apply to one-shot `-p` runs, which can only do
  what the hook allows without asking. Publishing or discarding work can
  require fresh confirmation through the hook's `confirm` answer. No tool
  runs before Gears has looked up the user's saved answer for it, whatever
  a hook says (decision 1).
- Only one Gears runs per Gears directory, apart from nested runs it starts
  itself (decision 4). Gears alone owns and checks the lock file;
  `gears-batteries` does not check it. Independently launched batteries
  commands are the user's responsibility.
- Each run has one selected workspace root, shared by its tools and hooks.
  There are no nested workspaces or per-subdirectory instructions. Assume
  one writer and no concurrent external modifications; no additional
  coordination is needed. A shell `cd` does not change the workspace root.
- Keep a small `USER.md` and global `MEMORY.md`, plus workspace memory in
  `.gears/MEMORY.md`. User data lives in the Gears directory,
  `/user/cfg/gears/` on Motor OS and `~/.gears/` on Linux, which also holds
  `gears.toml`, the sessions, the lock file and the batteries' data.
  `--config FILE` selects another configuration file for one run; it does
  not move the Gears directory. Relocating existing sessions between
  workspace paths or systems is deferred. New batteries data uses relative
  paths as described in "Layout", but existing Gears session paths keep
  their current behavior.
- `mkdir -p`, `sort`, `uniq`, `cut`, `tr` and `xargs` were added to sysbox
  in Rust with the standard library; `rg` is used directly, with no `grep`
  front end. These are general shell utilities, separate from the batteries.
- Validate real usefulness by user-run sessions with a local model and an
  OpenRouter model. What the user does in those sessions is the user's
  choice. Automated tests remain hermetic; real-model trials are explicit,
  separately budgeted activities.

## Deferred: tool confinement

The user will address the filesystem-permission problem separately: a role
can widen its own `r-x` to `rwx`, so a read-only workspace does not confine
a tool that holds `CAP_FS_WRITE` (see
[filesystem permissions](../../../../docs/fs-permissions.md#runtime-behavior-and-remaining-limits)).
Until a confinement design is agreed, this plan makes no confinement claim:

- every tool and hook runs with the user's authority, as Gears' `sh` and
  hooks do today, and keeps network access;
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
separate defense against it here.

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
  Interactive process that is not its ancestor, such as a hook.

## Runtime guarantees in Gears

These hold for every Gears session, with or without the batteries, and
each has a regression test. Rules 2, 3, 6 and 7 fixed defects reproduced in
September 2026.

1. The model's request to run tools is saved before any tool runs.
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
8. Cancellation and exit stop every child process Gears owns: tools, hooks
   and nested Gears runs, including their descendants. The process
   ownership and cleanup rules are below.
9. A failed permission decision prevents execution. Failures of optional
   features are reported, never silent.
10. A permission revocation applies before the next tool call.
11. Only one Gears runs per Gears directory. Gears holds an exclusive file
    lock on `gears.lock` there for its whole run and writes its pid into it.
    A second Gears cannot take the lock, exits with "Another gears session
    PID is running. Exiting." and starts nothing. The system releases the
    lock when Gears exits or is killed, so a crash leaves nothing to
    replace; the file itself is never removed. Gears processes that the
    running Gears starts itself find the holder's pid in their environment
    and run under its lock after checking that the holder is their ancestor.
    Only Gears owns and checks this lock. `gears-batteries` commands neither
    acquire nor check it; independent invocations do not receive concurrency
    guarantees.
12. Each long-term file (memory, saved grants, the provider choice) is
    written through a temporary file renamed over the old one; startup
    deletes temporary files left behind. This protects individual file
    writes, not a transaction across files. Append-only files, such as
    sessions and the change log, ignore a half-written last line when
    reading and discard it before appending.

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

Each runner, in the top-level Gears or in a nested one, owns the process
tree of each child it starts. The same runner owns its timeout, cancellation
and cleanup; it stops the tree and waits for its direct child before
returning or letting a new turn write anything. A normally completed child
must not leave descendants running either. Commands that detach or
deliberately escape this ownership (a new session that is also orphaned)
are unsupported while confinement is deferred.

- On Linux, every runner starts each child in a new process group. After a
  normal exit it kills that group, which stops background jobs the child
  left behind. To stop a running child it first freezes the child's
  descendant tree with `SIGSTOP`, so nothing can fork or be re-parented
  while the tree is walked, then kills every process and every process
  group in it. This reaches a nested Gears' own tool groups.
- On Motor OS, use the existing native descendant-tree cleanup, which
  retains parent relationships after a parent stops.
- No environment variables pass ownership between Gears instances, and no
  library code exits the process. A nested timeout stops only that tool; the
  nested run reports it to its model like any other timeout. Cancelling a
  nested run from its caller stops the whole tree below it; the caller
  records the interruption and does not wait for a final JSONL record that
  the killed process cannot send. A process never walks or kills a tree
  containing itself.
- Cleanup failure is reported and blocks starting another turn or writer;
  it is never treated as successful cancellation. No automatic restart is
  part of cleanup.

Both systems are tested with a nested Gears running a tool that has its
own child: cancel from the parent, trigger a nested timeout, and leave a
background job behind a normally finished nested tool. The owned tree, or
only the timed-out tool's tree, must stop before the caller continues, and
the nested run's next tool call must still run.

## Tools

The [external-tools contract](../external-tools.md) is the starting point.
Requirements on tool definitions:

- **Arguments.** The model never writes a flag vector. As in Claude Code's
  `Grep` and pi's `grep` and `find` tools, each common command exposes typed
  parameters, and the manifest maps them to a fixed argument vector: a
  string parameter fills one whole argument, a boolean adds a fixed flag or
  nothing, an integer fills a flag's value, an enumerated parameter selects a
  subcommand (`gix`, `lorry`, `cargo`), and a list parameter expands after
  `--`. A value that starts with `-` is refused unless it stands after `--`;
  fixed flags come from boolean, option and enumerated parameters. The
  schema, the expansion and the program's real behavior must agree. A tool's
  name does not establish its effects: GNU `find -exec` runs commands, so on
  Linux a read-only `find` tool exposes only name, type and path parameters
  (sysbox's `find` has no `-exec`). A tool that only reads is marked
  `read_only` in its manifest; "Evidence" uses the mark.
- **Platforms.** Differences belong in the tool definition: a manifest may
  give the description, argument mapping and command per system under
  `[linux]` and `[motor]`, over one parameter schema, and a tool with no
  command for the running system is listed as not available, never sent. A
  materially changed definition gets a new approval identity.
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
| `curl` | Gears | fetches one URL over HTTP or HTTPS |
| `read_file`, `write_file`, `patch`, `search_files` | batteries | file tools shaped for the model |
| `check` | batteries | runs the workspace's declared check and records the result |
| `todo` | batteries hook | the task list, carried out by the hook so it follows conversation branches |
| `session_search` | batteries | searches saved sessions |
| `memory` | batteries hook | proposes one memory entry change; the user says yes or no |
| `skill_view` | batteries hook | loads one of the user's skills |

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
  session's saved tool results, and the workspace's `.gears/` directory.
- **`sh`** is Gears' tool directory with a script per system, `bash` on
  Linux and rush on Motor OS. The script loads the saved variables, sets
  `PATH` to a fixed value, enters the saved directory (or the workspace if
  that is gone), runs the command with the model's timeout, and saves `pwd`
  and `export -p`. It does not save `PATH` or Gears' own variables. Its
  Motor OS description lists the commands Motor OS has and how they differ
  from GNU: `rg` instead of `grep`, sysbox's `head`, `tail`, `diff`,
  `find`, `wc`, `cat` and `less` (no `tail -f`), `sed` on the developer
  image, `gix` instead of `git`, and the sysbox additions. For commands not
  provided it gives replacements: `awk` → `sed`, `rg -o -r` or `cut`;
  `touch` → `: > FILE`; `basename`/`dirname` → `${x##*/}`/`${x%/*}`;
  `tee` → a redirection; `timeout` → the tool's own timeout; `mktemp` → a
  fixed name under `/user/tmp`.
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
  status and headers so a redirect's `Location` is visible; the model
  decides whether to fetch it. The model cannot supply a request body,
  request headers, uploads or output files, and the URL may not contain a
  user name or password. Its description tells the model how to search
  through a search page that returns plain HTML; pages come back as raw
  HTML within the tool's output limit. It is not allowed without asking,
  and its output is untrusted (see "Provenance").

Tool descriptions are kept short, because small local models have about
32,000 tokens of context; a test keeps the default tool list under a fixed
token budget.

## The batteries' hook

One hook process serves every feature; Gears starts it for each event it
subscribed to. A failure in one feature is reported and the others carry on:
the hook returns that feature's previous state unchanged, its tool list never
depends on a feature succeeding, and setup catches every feature's errors so
a broken skill file cannot stop Gears. A permission question the hook cannot
answer is a denial. Hook state is small: snapshot hash, the task list, check
state, the names of loaded skills, the reminder count and the one memory
proposal waiting for an answer.

| Event | What the batteries do |
| --- | --- |
| `initialize` | adds project instructions, memory, the skill list and, when offers are on, the offer instruction with recent declines (the prompt snapshot); registers `todo`, `memory` and `skill_view` |
| `permission` | applies the approval rules below |
| `tool_execute` | runs `todo`, `memory` and `skill_view` |
| `tool_result` | wraps `curl` output as untrusted; asks the user about the memory change the agent just proposed |
| `turn_start`, `entry`, `turn_end` | keeps the check result current or stale and resets the reminder count |
| `before_stop` | reminds the model to run the check (see "Evidence") |
| `answer` | applies the user's yes or no |
| `command` | runs `/remember` and `/remember-host`, which write the user's text to workspace or host memory at once |

The shipped configuration subscribes the hook to exactly these events.

**Project instructions** come only from `AGENTS.md` at the selected
workspace root, or `.gears.md` there in its place, limited to 20,000
characters (the first 70% and the last 20% are kept). The hook loads them at
`initialize`. It does not search parent directories or discover instructions
in subdirectories when tools touch files. Project configuration, memory and
task data also belong to this one workspace root.

**Approval rules.** The hook allows without asking: reading and searching
inside the workspace, the read-only common commands, `session_search`,
`todo`, `skill_view`, and `memory` (which asks its own question). It refuses
a short list of destructive commands even if the user would approve:
recursive `rm` of `/`, `/system`, `/user`, `/user/cfg` or `/devtools`, any
`rm` under `/user/cfg`, and fork bombs, also when hidden behind `sh -c`,
`rush -c`, `sysbox rm`, a full path or an earlier `cd`. It answers `confirm`
for commands that publish or discard work. Everything else is left to the
user's saved grants and prompts; in a `-p` run nobody can answer, so such a
call is refused.

**The prompt snapshot.** Gears rebuilds the system prompt when it opens a
session, so a memory change would change the prompt and lose the provider's
cache. When a session starts, the hook saves its fragments to a snapshot
named by content hash and remembers the hash; on resume, fork and setup
re-runs it returns the same text, so the prompt stays byte-identical until
the next compaction, which takes a fresh snapshot. Memory and skill changes
of every kind, additions, corrections and removals, appear in the next
session, after `/new`, or after a compaction. A running session keeps the
text it started with.

## Evidence

Keep two claims separate:

| Claim | What supports it | What it does not establish |
| --- | --- | --- |
| An operation succeeded | A runtime-recorded tool outcome | The user's task is complete |
| A memory entry is worth keeping | The user said yes to it | That it is true, or that it will help later |

**Check results.** Only the `check` tool produces a check result: it records
the argument vector, the system, the exit status, the duration and the
session entry id. Shell text that resembles the check is not recognized, so
`lorry test || true` in `sh` counts for nothing. A check result is current
until any later call to a tool that can change the workspace (`write_file`,
`patch`, `sh`, or any external tool not marked `read_only`); after that it
is stale. Agent-editable tests can support development, but a passing check
is not by itself acceptance; only the user decides that, in conversation.

**The `before_stop` reminder.** When a check is declared, a tool that can
change the workspace ran this turn, and no current passing check exists,
the hook answers `before_stop` with a one-line reminder, at most three times
per turn. It is feedback so the model sees the missing or failed check and
can act; it is not a verifier.

**Provenance.** Approval to run a command does not make its output
trustworthy. Text from `curl` and session-search hits from sessions that
contain such text is wrapped in an untrusted marker (the hook wraps `curl`
results at its `tool_result` event); any copy of the marker inside the text
is defused. Session-search hits carry session and entry ids. A content scan
can flag planted instructions or leaked secrets but cannot certify anything
as trusted.

## Memory and skills

**Files.** `batteries/USER.md` (facts about the user), `batteries/MEMORY.md`
(facts about this computer) and the workspace's `.gears/MEMORY.md` (facts
about this project, with paths relative to the workspace). Each is a plain
text file the user may edit by hand:

```
# Gears memory v2
§ k7f2 2026-10-15 01J9Q3M8R6W2Z4
In red, run `cargo test --offline`; the VM has no network.
§ m3a8 2026-10-15 01J9Q3M8R6W2Z4
Buffer::from_bytes must handle zero lines; empty files hit this.
```

An entry starts with a `§ ` line giving its id, its date and the session
that proposed it (`-` for an entry the user wrote by hand), and continues
with its text. A hand-written entry may give only the id. Ids are short
ASCII; the tool generates four-character ones. Each file has a character
limit set in `batteries.toml` (defaults 1,375 for `USER.md` and 2,200 for
each `MEMORY.md`), counting entry text only. A file with another header
(including the `v1` format that reviews wrote), an unreadable file or an
oversized one is reported and skipped.

**The `memory` tool** takes `action` (`list`, `add`, `replace`, `remove`),
`target` (`user`, `global`, `workspace`), `id` for replace and remove, and
`text` for add and replace. It changes one entry; replacing a whole file is
refused. Its description tells the model which file each kind of fact goes
to and that a fact true on one system should name it.

**The question.** When the model calls `memory` with a change, the hook
keeps the proposed change in its state, and at `tool_result` asks the user
one question showing the exact entry (and, for a replacement or removal,
the entry it affects) with two answers, yes and no. On yes the hook writes
the file and tells the model "remembered"; on no it tells the model
"declined". Both answers are appended to `batteries/changes.jsonl` with the
entry, the target, the session and the date. When nobody answers (a `-p`
run, or a cancelled question) nothing is written or logged and the model is
told so. An identical entry that already exists is reported as a duplicate
without a question. A replacement or removal whose entry changed meanwhile
fails with a message.

**The user's own entries.** `/remember TEXT` adds an entry to workspace
memory and `/remember-host TEXT` to `batteries/MEMORY.md` in the Gears
directory, at once and without a model call (added 2026-10-17). They are
logged as yes answers.

**Offers.** `batteries.toml` may set `[memory] offer_lessons = true`
(default false). When it is on, the prompt snapshot includes an
instruction: after finishing a task whose check passed, the model may offer
at most one thing worth remembering for next time, a mistake and its fix or
a procedure that ran and worked, through the `memory` tool, and otherwise
offers nothing. The instruction also lists the last five declined entries
(each cut to 120 characters) so they are not offered again. With offers
off, the model proposes memory only when the user asks it to remember
something.

**Skills** are directories the user writes under `batteries/skills/NAME/`,
with a `SKILL.md` in the agentskills.io format (YAML `name` and
`description`) and an optional `NOTES.md`. On Motor OS, only skills whose
`metadata.platforms` names `motor` are listed. The prompt lists the
available names and descriptions; `skill_view` loads one skill and its
notes by name, or lists them when called without a name, and refuses a
fourth distinct skill in one session. The hook reads the skills directory
when a session starts and when a skill is loaded; an invalid, oversized or
symlinked skill is reported and skipped. Size limits are `[skills]
skill_chars` and `notes_chars` in `batteries.toml` (defaults 20,000 and
4,000). There is no approval step, no load log and no archive: the user
adds, edits and removes skill files directly.

**Workspace memory from elsewhere.** A `.gears/MEMORY.md` that arrives with
a clone is used as it is, exactly like the clone's `AGENTS.md`: both are
project files from a repository the user chose to work in.

**Layout.** Under the Gears directory, `batteries/` holds `USER.md`,
`MEMORY.md`, `skills/`, `changes.jsonl`, `snapshots/` and `sessions/<id>/`
(file-read records and saved check output). `batteries.toml` in the Gears
directory holds the user-wide settings: the memory and skill size limits
and `offer_lessons`. A workspace's `.gears/` holds its `MEMORY.md` and
`batteries.toml` with the project's `check` command. Paths inside batteries
data files are relative to the Gears directory or the workspace top; text
is UTF-8 with `\n`; there are no symbolic links; every file carries a
format version.

**User commands.** `gears-batteries history [--offset N] [--limit N]`
lists the yes and no decisions, oldest first, and reports how many lines of
the log it could not read instead of failing. `gears-batteries status`
shows whether offers are on, how many entries each memory file holds,
which skills are available and how many decisions the log holds. Both take
`--workspace PATH` and `--root PATH`.

## Not planned

Worker orchestration, web search and page extraction, a scheduler and a
gateway were optional phases of the previous plan and were never
implemented. Their designs are in that plan's git history. If any of them
is wanted later it gets its own plan; the single-Gears lock (decision 4)
and the lack of unattended approval are the first questions it must answer.

## Testing and gates

- Whole-turn tests use Gears' recording mock provider (`gears::mock`, and
  `gears-mock-provider` in the VM) to check prompts, cache markers and
  approval flows. No automated test reaches a real provider or the
  Internet.
- Crash-cleanup tests leave stale locks, temporary files, a partial final
  session record and an unfinished tool round. Gears must start again and
  complete a new mock-provider turn without replaying old calls or needing
  manual file repair.
- Process cleanup tests run on Linux and Motor OS: cancel a nested run
  while its tool has a child of its own, exercise a nested timeout, and
  verify that no descendant remains before another turn or writer starts.
- Tool argument tests in the VM cover spaces and literal glob characters
  through direct sysbox invocation. Local HTTP tests cover a plain HTTP
  fetch and a redirect returned without following it.
- The batteries' workflow fixture (`examples/workflow-smoke`) drives real
  file tools, a compiler check, the task list, the reminder, the memory
  question with yes, no and no answer, frozen prompts and skill loading
  with a scripted provider.
- Gears changes run Gears' own tests, `test-gears-http.sh` and
  `test-gears-batteries.sh`. Only `full-test-dev.sh` includes the
  Gears/batteries host and native test gates; its developer-source phase
  runs `test-gears-http-vm.sh` and `test-gears-batteries-vm.sh` in its
  owned VM, then builds the packaged source and runs `lorry test` there.
  Tests that start Gears select a temporary Gears directory with
  `GEARS_DIRECTORY`, never the user's own. `full-test.sh` has no
  Gears-specific steps. Gears and the batteries are non-core components:
  their gate is these tests plus `full-test-dev.sh --release`.
- Real-model sessions are user-run, outside `full-test`.

## Implementation

The simplification landed as one change (commit `d9921bb2`) and passed
`full-test-dev.sh --release`. It removed the evaluation harness with Gears'
`--gears-dir` flag, reviews and their marks, `/accept`, the turn records,
the proposal queue with the `pending` and `cleanup` commands, agent-written
skills and the workspace-memory approval by hash. It added memory format
`v2`, the yes/no question kept in hook state, `v2` records in
`changes.jsonl`, the `offer_lessons` setting and the reshaped `history`
and `status` commands.

On 2026-10-17 the Gears features that only reviews used were removed: the
after-turn command, `--preserve-prefix` with the request prefixes it read
back, and `--hook-state`. Memory files in the `v1` format and prompt
snapshots in older formats are no longer read.

An ephemeral session's `sh` state moved from `/tmp/gears-sh-*` to
`sessions/ephemeral/` in the Gears directory, which startup cleans up, so a
killed Gears no longer leaves it behind.

## What remains

| Work | Status and next step |
| --- | --- |
| Hands-on validation | Finish the Linux and Motor OS interactive checklist: tool enablement, approvals, revocation, resume, screen rendering and the memory question in both UIs. No live local-model result has been reported. |

## Decisions

Numbered as in the previous plan; the 2026-10-15 column says what changed.

1. **Hook versus saved answer.** No tool runs before Gears has looked up the
   user's saved answer; a saved denial always refuses; with no saved answer
   a hook may allow. Unchanged.
2. **Workspace recovery.** None; the user keeps the workspace in git or gix.
   Unchanged.
3. **What the agent may add to memory without asking.** Nothing. *Changed
   2026-10-15:* the question is asked at once and has two answers, yes and
   no; there is no queue, no "postpone" and no `pending` command, because
   nothing proposes memory when the user is away.
4. **Memory writes.** One writer, Gears' own lock, temporary-file
   replacement, no transactions, no `undo`. Unchanged.
5. **What counts as a finished task.** *Dropped 2026-10-15:* nothing needs
   to know; `/accept` is removed. The agent's offer, if offers are on,
   comes after its own check passed and costs the user at most a "no".
6. **Reviews left unfinished at exit.** *Dropped 2026-10-15* with reviews.
7. **What result turns reviews on.** *Dropped 2026-10-15* with reviews and
   the harness; the user judges offers by hand and can turn them off.
8. **Web services.** None; the agent uses `curl`. Unchanged; the web tools
   that were to build on it are no longer planned.
9. **How services keep running.** Moot; no services are planned.
10. **Scheduler versus the single-Gears lock.** Moot; see "Not planned".

Also decided 2026-10-15: removals and corrections take effect at the next
session rather than being pushed into running ones; a cloned
`.gears/MEMORY.md` is trusted like `AGENTS.md`; the review and harness code
is deleted rather than kept as an unsupported extra; memory entries record
their id, date and session, not a model-chosen kind (the hook cannot tell a
user-requested entry from an offered one, so it does not pretend to).
