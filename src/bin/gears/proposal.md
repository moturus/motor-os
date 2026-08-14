# gears: a native agentic harness for Motor OS

Status updated 2026-08-13. `README.md` is the user guide. This document
outlines the features gears should have and the rough order of work. After
this proposal is approved, `step-by-step-plan.md` will be rewritten with the
execution detail and exit criteria. Detailed design discussion for completed
work remains available in git history.

gears is an agentic coding harness that runs on Linux and Motor OS. It drives
OpenAI-compatible models and uses local tools to inspect, change, build, and
test software. The present implementation is close to a proof of concept; the
main work now is turning it into a dependable daily coding agent.

## Done

- Linux and Motor OS builds, with gears installed in `motor-os-dev.img`.
- OpenAI-compatible streamed completions through host curl and Motor
  `/bin/curl`, with key redaction, usage accounting, budgets, and egress
  policy.
- Workspace-confined file tools, command execution, fetch, build, test, host
  git tools, permissions, and per-session undo.
- Persistent sessions, resume, context compaction, expandable tool output,
  and the line-oriented REPL.
- Concurrent, budgeted, optionally read-only sub-agents.
- Linux self-build, candidate validation, promotion, and restart on the same
  session.
- Motor process support, sessions, file tools, HTTPS, and build/test through
  `lorry`; missing Motor git support is reported explicitly.
- Hermetic host tests, a real-model Linux smoke run, and Motor VM smoke runs.

## Two future tracks

### Track A — native self-build with Lorry: future work

Making Lorry build gears natively on Motor OS is postponed future work. It has
no active gears milestones and does not block Track B; revisit it when Lorry
and Motor OS can support the dependency graph gears has at that time. Until
then, "self-hosting" means that gears can edit, build, validate, promote, and
restart itself on Linux on the same session, without compiling itself inside
the VM.

### Track B — a full agentic coding harness: main track

The active goal is to turn the current proof of concept into a coding harness
that is useful for sustained, real repository work, and credible against the
harnesses people already use. Native execution on Motor OS remains a
requirement, but native compilation of gears itself does not.

The reference products are Codex CLI, Claude Code, and pi. They are reference
points rather than compatibility targets: gears should keep its small Rust
core, explicit security boundaries, Motor-native platform seam, and hermetic
tests. Useful reference capabilities include repository-aware review and
automation in [Codex CLI](https://learn.chatgpt.com/docs/codex/cli), the
skills/hooks/MCP/subagent extension model in
[Claude Code](https://code.claude.com/docs/en/features-overview), and pi's
reloadable tools, commands, UI, events, and persistent extension state in
[pi extensions](https://pi.dev/docs/latest/extensions).

## Constraints

These carry over from the previous plan and bind the work below.

- Automated tests are hermetic. No automated test contacts a real provider.
- Do not add retries, ignored failures, or longer timeouts to hide defects. A
  bounded retry is allowed only for a documented transient failure and with
  explicit user action or a previously approved per-run policy. It must be
  visible and counted, and must not replay potentially side-effecting work.
- Keep the push-shaped `HttpClient` seam. Motor drives `/bin/curl`; gears does
  not link the curl crate.
- Do not make automatic commits. The per-session copy-before-write undo log is
  the default safety net.
- A configured-off or platform-missing capability runs and refuses with a
  reason. Silence that would mislead the model is a defect.
- Select platform code with `cfg(unix)` / `cfg(not(unix))`; Motor has no Unix
  target family. This Rust target distinction does not mean that Motor lacks
  POSIX functionality: `rush` provides a substantially POSIX-compatible shell,
  and some POSIX APIs are available through `moto-rt` and `moto-rt-cabi`.
- Resolve `lorry` by name through `PATH`; do not encode its current filesystem
  location. The root filesystem layout is not a gears interface. Motor OS
  resolves naked filenames against `$PATH` when spawning, and fails the spawn
  when `$PATH` is unset — gears must report that case actionably rather than
  as a bare spawn failure.
- gears ships only in `motor-os-dev.img`, so its tests and gates belong to the
  dev lane, `src/tests/full-test-dev.sh`, not the main-image lane.

### Dependency budget

The previous plan pinned gears to `serde`, `serde_json`, `toml`, plus `libc`
or `moto-sys`, and deferred crossterm to post-v1. That rule existed to keep a
native Lorry self-build reachable. With Track A parked, it is relaxed
deliberately rather than by accident:

- A new dependency is judged on security and auditability, license,
  maintenance health, dependency size, startup and memory cost, offline and
  hermetic behavior, build scripts and native dependencies, and whether it
  **cross-compiles for and runs on Motor OS**. Whether Lorry can build it is
  not an admission criterion while Track A is parked. Unix or Windows FFI,
  unported parts of Tokio, and dependencies that require network access at
  build or test time remain out.
- crossterm is pre-approved: the Motor port is in-tree
  (`moturus/crossterm`, branch `motor-os-support`) and `rush`, `red`, and
  `rmux` already ship on it.
- `sha2` 0.10.8 is approved without default features and with `force-soft`
  and `std`. Gears uses it for stable file-content identities: it is
  pure Rust, has no build script or native dependency, is already built on
  Motor OS by Lorry, and avoids timestamps or collision-prone custom hashes
  when deciding whether previously read content is stale.
- `regex` from the 1.12 line is approved without default features and with
  `std`, `perf`, and Unicode support. It is the portable, bounded search
  backend on both Linux and Motor OS; an external `rg` is only an optional
  accelerator and cannot be required for correct search behavior.
- Every other new dependency is named and justified here before it is added.
- Each admitted dependency widens the Track A gap. That is an accepted cost,
  not an invisible one.

### Decisions this proposal reverses

- **Native provider dialects were out of scope.** Now in scope (§6): prompt
  caching, reasoning content, and tool-call fidelity are hard to reach through
  one gateway dialect, and depending on a gateway is itself a risk.
- **The dependency allow-list and "no crossterm until post-v1".** Superseded
  by the budget above.

## Rough order of work

Priorities describe product importance:

- **P0** — required to graduate from proof of concept.
- **P1** — required for a mature daily-use harness.
- **P2** — valuable after the core experience is dependable.

Concretely, **P0 is one dependable inspect → plan → edit → verify → review
vertical slice** with a proper TUI. It includes the built-in modes and
journaled task state, observable and interruptible foreground tools, atomic
edits with diff review and checkpoints, repository-aware search and reads,
project-appropriate verification, platform-specific model guidance and
toolchain routing, and an honest completion contract. The existing provider,
session, and permission implementations are sufficient for P0 once that slice
is reliable. Background jobs, code intelligence, richer provider adapters,
declarative permissions, and extensibility are P1 or later.

P0 exits when hermetic Linux and Motor scenarios can drive that slice through
the TUI: start and resume a session, select a mode, inspect a fixture, record
and approve a plan when required, make and review an atomic edit, restore a
checkpoint, run a relevant check, cancel foreground work, and finish with a
truthful report. The scenarios must also verify that Linux selects Cargo,
Motor selects `lorry` through `PATH`, and mistaken Cargo use on Motor produces
actionable guidance. The Motor scenario belongs in `full-test-dev.sh`.

The order below is approximate and exists to say what depends on what, not to
schedule patches. `step-by-step-plan.md` will carry the numbered steps after
this proposal is approved.

1. **Finish the Motor OS port.** The unfinished half of the previous plan's
   step 10: Motor mid-turn Ctrl-C, a Motor-native loopback provider mock, and
   gears coverage in `full-test-dev.sh`. This comes first because every later
   feature otherwise gets verified on Motor by hand and then re-verified from
   scratch once the lane exists.
2. **The P0 harness.** The interactive TUI and the inspect → plan → edit →
   verify → review workflow that makes gears dependable: built-in modes, a
   journaled task object, observable and interruptible foreground tool
   execution, atomic patching with diff review and checkpoints, better search
   and precise reads, project-appropriate verification, normalized
   diagnostics, platform-specific model guidance and toolchain routing, and a
   completion contract. The modes are built in; the framework for defining
   new ones (§9) is later.
3. **Depth.** Background jobs; host code intelligence with explicit Motor
   fallbacks; session ergonomics; real provider adapters; review workflows.
4. **Trust, extension, and integration.** Declarative permissions and
   workspace trust; skills, hooks, commands, and MCP; sub-agent roles;
   `gears exec` and the event protocol.

Measurement (§13) runs alongside all of these rather than after them, and the
standing release rule is unchanged from the previous plan.

## Feature roadmap

### 1. Interaction and task control — P0; live-turn steering P1

- Support interrupt, pause, resume, and cancellation consistently on Linux and
  Motor OS, including while the model, a sub-agent, or a tool is running. On
  Motor this means detecting an in-band `0x03` during a live turn without
  competing with prompt input. Pausing means stopping agent scheduling after
  the current atomic operation; it does not promise that an arbitrary running
  child process can be suspended and resumed. Cancellation may terminate the
  active provider request, sub-agent, or tool where the platform permits it.
- Make tool activity observable while it happens. Long commands should stream
  bounded output and show elapsed time instead of leaving a silent terminal.
- Allow prompts to reference files and directories directly, for example
  `@src/main.rs`, without first spending a model round discovering the path.
- Preserve the current line mode for scripts and recovery, but add a
  crossterm-based interactive UI. This is large enough to land in stages: the
  P0 core is multiline editing, paste handling, history, a bounded transcript
  and tool-output viewer, and a clear status area for model, context, cost,
  tools, and agents. Completion, richer scrollback navigation, Markdown, and
  syntax highlighting are refinements that follow.
- **P1:** let the user steer a live turn — queue a follow-up, amend the current
  task, or stop after the current tool call without discarding the session.
- **P1:** add a structured question/elicitation path so the agent can request a
  small decision, receive the answer, and continue the same turn. In P0, the
  agent may instead finish the current turn with a question and resume the
  recorded task after the user's next reply.

### 2. Task workflow and modes — P0

These are workflows built into gears, not content loaded from somewhere. The
mechanism for *adding* new ones is the skills framework in §9 and is later
work; a small set of good built-in modes is what P0 needs.

- Add explicit **ask**, **plan**, **code**, and **review** modes. Each mode
  should have a defined prompt, tool set, mutation policy, and transition
  rather than relying on the model to infer the workflow. Ask and plan are
  non-mutating; review is read-only, and a request to fix a finding transitions
  explicitly to code mode.
- Generate a concise platform contract in the system prompt and reinforce it
  in tool descriptions. On Linux, Rust build and test use Cargo. On Motor OS,
  they use `lorry` resolved through `PATH`; Lorry supports a strict subset of
  Cargo behavior and must not be presented as Cargo. Keep the model-facing
  `build` and `test` tools independent of that backend.
- Describe Motor OS precisely: it is neither Linux nor a Rust Unix-family
  target, but `rush` supplies a substantially POSIX-compatible shell and
  `moto-rt` / `moto-rt-cabi` supply some POSIX APIs. The model must inspect the
  documented API or project instructions instead of assuming either complete
  POSIX compatibility or no POSIX support. The `run` tool still executes an
  argument vector without an implicit shell; a model may invoke `rush`
  explicitly when a shell is appropriate.
- Do not install a `cargo` wrapper that forwards to Lorry. If a model requests
  raw Cargo on Motor, return an actionable error directing it to `build`,
  `test`, or a supported `lorry` command. This prevents Cargo-aware tools and
  models from inferring capabilities such as workspaces, metadata, or feature
  selection that Lorry does not provide.
- Make verification part of the workflow rather than something the model
  remembers to do. Select checks from the task and repository — for example
  formatting, linting, building, targeted tests, or static inspection — and
  feed their results back into the task object and completion contract. Do
  not run project code merely because a fixed workflow stage says "run".
- Add a journaled task/plan object with pending, active, completed, and blocked
  items. It must survive resume and remain visible to the user without being
  confused with free-form model prose.
- Provide an approval checkpoint between planning and implementation when the
  requested work or risk warrants one.
- Add a standard completion contract: inspect the final diff, run the relevant
  checks, report what changed, name unverified assumptions, and never claim a
  test was run when it was not.
- Define what happens when a turn exhausts its step, token, or budget limit. A
  task too large to finish must hand off deliberately, with its state
  recorded, rather than stopping mid-edit.
- **P1:** add first-class review workflows for uncommitted changes, a commit,
  or a branch, with findings tied to paths and lines and ordered by severity.
  Review *mode* is P0 — it is the last stage of the P0 slice; these richer
  review targets are the "Depth" step of the order above.

### 3. Repository exploration — P0; code intelligence — P1

- Expand search beyond literal grep: regex, include/exclude globs, file-name
  search, bounded result paging, and a fast native/external backend where one
  is available.
- Add precise file reads by line or byte range and stable references that can
  be reopened after tool output has been compacted.
- Understand repository structure: nested instruction files, manifests,
  language/toolchain detection, generated/vendor directories, and the checks
  normally used by the project.
- **P1:** symbol definition, references, workspace symbols, and live
  diagnostics through a small code-intelligence seam, with an LSP backend.

Code intelligence matters because grep-and-read makes the model spend turns
and tokens rediscovering structure the toolchain already knows, and a harness
that cannot answer "where is this used" keeps making locally plausible,
globally wrong edits. It is P1 rather than P0 because the first dependable
vertical slice can use explicit search and compiler diagnostics.

Define the seam first and implement the initial LSP backend with
rust-analyzer on Linux. On Motor OS, use repository search, precise reads, and
compiler diagnostics as explicit fallbacks; report that semantic navigation
is unavailable rather than inventing results. A native rust-analyzer port is
a separate Motor OS feasibility and planning project, not a Track B milestone
or a prerequisite for a mature gears harness. The client seam should still
model server lifecycle, JSON-RPC framing, document synchronization, capability
negotiation, absence, failure, warm-up, and partial capability honestly so a
future Motor backend can fit without changing model-facing semantics.

### 4. Safe, precise editing — P0

- Add an atomic patch tool for multi-hunk and multi-file changes, including
  create, delete, rename, and mode changes. A failed hunk must leave the whole
  requested operation unchanged.
- Show the user a readable diff before approving consequential writes, and
  record the exact approved change in the session.
- Keep copy-before-write undo, but add named checkpoints and restoration of a
  selected checkpoint rather than only whole-session `/undo`.
- Detect conflicting edits and changed-on-disk inputs before overwriting them,
  especially when sub-agents work concurrently.
- Store oversized generated patches and tool results as bounded artifacts the
  model can inspect in slices instead of losing the middle permanently.

### 5. Process and tool execution — foreground P0; managed/interactive P1

- Stream stdout and stderr with bounds while retaining the final combined
  result and exact exit status.
- **P1:** Add managed background jobs: start, list, poll, read new output,
  send input, and stop. Jobs must belong to the session and be cleaned up
  deliberately.
- **P1:** Support interactive commands when the platform permits them without
  giving two processes uncontrolled ownership of the terminal.
- Keep the argument-vector execution path as the safe default. If a shell
  adapter is added, make it a distinct, more strongly gated capability and
  show the exact command and working directory before approval.
- Normalize compiler and test diagnostics into locations and severities while
  retaining the original output. Adopt machine-readable Lorry diagnostics
  when Lorry provides them.
- Improve cancellation semantics so stopping a tool stops its descendants
  where the platform supports that; document and surface Motor's direct-child
  limitation where it does not.

### 6. Providers, models, and multimodal input — P1

- Turn the provider seam into real protocol adapters rather than assuming one
  OpenAI-compatible chat-completions dialect. At minimum, support the current
  OpenAI Responses-style tool stream and Anthropic's native tool stream in
  addition to the existing endpoint. Note that §13 requires every adapter to
  pass the same conformance corpus, so each dialect is a recurring cost.
- Maintain model metadata: context and output limits, supported input types,
  tool/parallel-call support, reasoning controls, and optional price data.
- Let the user switch model and reasoning level during a session and choose
  defaults by role, including sub-agent roles.
- Add image/file inputs with explicit size and type limits so the agent can
  inspect screenshots, diagrams, and build artifacts.
- Add connection reuse and prompt-caching support where the provider exposes
  them, with usage accounting that distinguishes cached and uncached tokens.
- Preserve typed provider failures, request identifiers, retry-after details,
  and any safely parsed partial response. Do not claim generic stream
  resumability or hide failures behind automatic retries.
- For a documented transient failure, preserve the failed or partial turn and
  offer a bounded retry. Retry only on explicit user action or under a
  previously approved per-run policy; show, count, and record every attempt.
  Never automatically replay a tool call or other potentially side-effecting
  work. A rate-limit response may expose its retry-after time without silently
  waiting and retrying.
- Support multiple named endpoint/auth profiles while keeping secrets out of
  prompts, process arguments, transcripts, and child environments.

### 7. Sessions, context, and durable state — P1

- Add session list, name, inspect, search, archive, and delete commands, and
  resume-by-recency, rather than requiring users to copy opaque IDs from
  terminal output.
- Allow a session to fork from a message or checkpoint, rewind without
  destroying history, and export/import a portable transcript for handoff.
- Expose context composition: instructions, pinned messages, tool schemas,
  compacted ranges, estimated headroom, and why an item was evicted.
- Add manual compaction and a reviewable summary boundary. Summaries must keep
  provenance and never separate a tool request from its result.
- Define global, user, workspace, and nested-directory instruction scopes with
  deterministic precedence. Keep large reference material out of every model
  request until it is needed.
- Add durable agent-owned project memory, stored outside project instructions
  by default. Each entry needs provenance, timestamp, scope, and expiry or
  revalidation rules; writes must be reviewable and refusable. Promoting an
  entry into version-controlled repository instructions requires explicit
  user approval.
- Persist task state, background-job metadata, checkpoints, extension state,
  and agent outcomes as versioned session records that older gears versions
  can skip safely.

### 8. Permissions, trust, and containment — P1

- Replace the current coarse remembered approvals with declarative
  allow/ask/deny rules for tool, command, path, host, agent, and extension.
  Deny must win, and rules need one-call, session, workspace, and managed
  scopes.
- Add a workspace-trust decision before loading project instructions,
  extensions, hooks, or executable configuration from an unfamiliar tree.
- Make approval prompts show the relevant diff, command, cwd, environment
  names, network destination, and requesting agent.
- Extend secret detection and redaction across tool output, artifacts, session
  records, traces, hooks, and external tool protocols.
- Keep a concise audit trail of approvals, denials, mutations, network access,
  spawned processes, and configuration changes.
- Add capability-restricted or sandboxed tool execution when the host or Motor
  OS exposes the necessary primitives. Motor OS does not currently expose to
  gears the child-process restriction and resource-limit interface this needs
  — Lorry warns that even its own build scripts run unisolated there — so this
  depends on Motor OS work outside gears. The UI permission gate remains
  useful, but must not be described as OS containment.

### 9. Extensibility — P1

This section is the machinery for adding capabilities without rebuilding gears.
It is distinct from, and later than, the built-in modes in §2: P0 needs a few
good workflows, not a framework for defining more.

- Add Markdown-based skills: named, discoverable instruction/workflow bundles
  whose descriptions are cheap to advertise and whose full content loads only
  when invoked.
- Add lifecycle hooks around session start/end, prompt submission, tool
  approval/use/result, compaction, agent start/stop, and task completion.
  Hooks need typed input, bounded output, timeouts, and explicit permissions.
- Add an MCP client for external tools and resources, with per-server trust,
  transport isolation, schema discovery, secret handling, and the same gate as
  built-in tools. Most published MCP servers are Node or Python programs and
  will not run on Motor OS, so the client must degrade explicitly.
- Support project and user custom commands/prompts, plus external-process tools
  with a versioned JSON protocol. Avoid requiring unsafe in-process dynamic
  Rust loading.
- Package skills, hooks, commands, agent profiles, and MCP configuration in a
  versioned plugin manifest with deterministic precedence and compatibility
  checks.
- Support safe reload of declarative resources and external integrations, and
  add dynamic tool discovery so a large extension catalog does not put every
  schema in every model request.

### 10. Sub-agents and parallel work — P1

- Build on the existing sub-agent core with named role profiles containing a
  model, instructions, skills, tools, permissions, and budget.
- Make sub-agents read-only unless write access is granted explicitly. The
  registry already supports the filter, and it is the cheap, portable answer
  to concurrent writers.
- Show each agent's task, state, context use, cost, current tool, and outcome;
  allow the user or parent to steer, interrupt, or stop one agent independently.
- Add dependency-aware task assignment and structured results instead of only
  free-form task strings and final text.
- Isolate concurrent writers with git worktrees on capable hosts or another
  explicit workspace strategy; reconcile results and surface conflicts before
  merging them into the user's tree. This is host-only and sits beside the
  "no automatic commits" rule, so it needs a deliberate design.
- Add optional agent-to-agent messages and shared task ownership only after the
  simpler parent/sub-agent path is dependable and observable.

### 11. Version control and review — P1

- Present status and diffs in the UI with file/hunk selection and a clear
  distinction between user changes and changes made in the current session.
- Add host-side checkpoint branches/worktrees and safe restore workflows
  without making automatic commits the default.
- Generate commit messages and pull-request summaries from the verified diff,
  but require explicit permission for commit, push, or any remote mutation.
- Record the tested revision and dirty state so later summaries do not imply
  that checks covered changes made after the test.
- Keep Motor's lack of git explicit. Rich host git support must not make the
  Motor implementation pretend that undo is full version control.

### 12. Automation and integration surfaces — P1/P2

- Add a non-interactive `gears exec` interface with deterministic exit codes,
  JSONL events, final structured output, session/resume identifiers, and no
  hidden permission prompts.
- Add configuration profiles and command-line overrides for model, mode,
  permissions, tools, budget, and output format without weakening secret
  handling.
- Define a stable event/control protocol so an IDE, test harness, or remote UI
  can drive the same agent core without scraping terminal output.
- Support notifications when long tasks finish or need input, with external
  delivery implemented through permissioned hooks or plugins rather than
  built into the core.
- Make recorded sessions and tool events sufficient for deterministic UI
  replay and regression analysis, while never replaying side effects.

### 13. Quality, security, and performance gates — P0 except where noted

- Add the Motor-native loopback provider mock and gears-specific
  `full-test-dev.sh` coverage. Automated tests must never contact a real
  provider, every automated request stays on loopback, and TLS dependencies
  stay out of the gears binary itself. The separate, development-image-only
  `gears-mock-provider` uses `rustls` 0.23 without default features and with
  `ring` and `std`, `rustls-pemfile` 2, and the shared `moturus/ring`
  `motor-os-0.17.14` branch. Its committed certificate and private key are
  prominently test-only; the regular image and production provider path
  contain none of these additions.
- Add a hermetic scenario suite that measures task completion, edit accuracy,
  permission behavior, cancellation, context compaction, and recovery from
  malformed provider/tool data.
- **P1, with §6:** test every provider adapter against the same
  fragmented-stream, tool-call, error, and cancellation corpus. P0 consolidates
  the existing endpoint cases into that reusable conformance corpus; it grows
  with each adapter.
- Add fuzz/property tests for parsers, path confinement, patch application,
  session recovery, redaction, and permission matching.
- Track startup time, memory, request/context size, and tool latency. Avoid
  adding boot work or eagerly loading extension content and schemas.
- Keep budget-capped manual real-model smoke runs for interoperability, but do
  not substitute them for deterministic regression tests.

The gates above measure whether gears is *correct*. Three more items measure
whether it is *good*, and they run alongside the rest of the roadmap rather
than after it:

- **A real-model evaluation set.** Everything else here is hermetic, which
  says nothing about agent capability. Add a small, versioned, budget-capped
  set of real repository tasks — most of them in the motor-os tree — run
  manually against real models in isolated fixture copies or worktrees. Record
  the repository commit, task fixture and input, model and version,
  configuration, budget, expected assertions and grading rubric, pass rate,
  token cost, wall-clock, and turn count. This is the reproducible artifact a
  prompt or tool change is compared against. It is not a CI job and must not
  become one.
- **Treat the system prompt and tool descriptions as a reviewed artifact.**
  They are the largest single determinant of harness quality. Version them,
  review changes like code, and measure against the evaluation set. This
  includes model-facing error text: what a failed tool returns decides whether
  the model recovers or flails.
- **Token and cost efficiency as work, not just a metric.** The bullets above
  track request and context size; nothing yet reduces it. Reuse file content
  only while its identity is known to be unchanged, prefer patches to
  whole-file writes, represent oversized results with stable artifacts, and
  exploit prompt caching once §6 provides it. Efficiency must never use stale
  content or separate a tool request from the result needed to interpret it.

## Definition of a good gears harness

Track B is successful when a user can give gears a non-trivial repository
task and can:

- understand and approve the plan and risky actions;
- observe, steer, pause, or cancel the work at any time;
- review exact edits and restore a checkpoint;
- see which checks ran and which revision they covered;
- resume, fork, or hand off the session without losing state;
- extend the harness with reviewed skills, hooks, tools, and integrations; and
- get the same truthful behavior on Motor OS, with unsupported platform
  capabilities stated explicitly.

And one outcome rather than a feature: gears is used for real work on the
motor-os tree in preference to the alternatives, with §13's recorded evaluation
results saying why.
