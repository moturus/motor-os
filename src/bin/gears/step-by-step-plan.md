# gears P0 step-by-step plan

Status updated 2026-08-15. `proposal.md` is the governing design document and
`README.md` is the user guide. This file covers only the P0 work required to
turn gears from a proof of concept into one dependable
inspect → plan → edit → verify → review vertical slice.

## Status

Overall: **Steps 0–10 are complete; Step 11 is current and the remaining P0 work
is planned.**
Completed implementation history is available in git and in
`step-by-step-plan.prev.md`; it is not repeated here.

Current: **Step 11 now journals native check commands, complete raw-output
artifacts within resource policy, workspace scope, staleness, and confined
diagnostics.**

Next: **finish reviewable check/skip selection and the structured completion
contract.**

### Done

- Linux and Motor OS harness baseline.
- Provider, tools, sessions, permissions, undo, sub-agents, and line UI.
- Linux self-hosting and initial host/VM smoke coverage.
- Hermetic Motor test lane and POC baselines.
- Linux/Motor platform contract and native toolchain routing.
- Deterministic terminal input, cancellation, and atomic-boundary pause/resume.
- Observable/cancellable foreground work with bounded live and final output.
- Validated resource-policy defaults and overrides.
- Session-state names are confined to their versioned workspace directory.
- Lazy, symlink-safe internal-state path construction.
- Session and permission persistence use the shared state boundary.
- Undo state and manifest destinations are confined and symlink-safe.
- Self-host candidates, backups, and promotion staging are confined and safe.
- Durable artifacts, precise file reads, and compaction-safe references.
- Bounded repository exploration, nested instructions, and profile evidence.
- Exact, journaled file mutations with diff approval and input revalidation.
- Atomic multi-file patches with retained approval evidence and recovery.
- Named checkpoints with exact approved restore and session-start undo.
- Journaled typed tasks with durable question, pause, and limit handoffs.
- Enforced versioned ask, plan, code, and review workflows.

### Planned

| Step | State | Work | Exit summary |
|---|---|---|---|
| 0 | Complete | Hermetic Motor test lane and image prerequisites | `gears-test.sh` passes hermetically; both images contain `/bin/rg` |
| 1 | Complete | Platform contract and toolchain routing | Linux uses Cargo; Motor finds `lorry` through `PATH` and explains Cargo mistakes |
| 2 | Complete | Input ownership and turn control | One input owner supports prompt input and Motor mid-turn Ctrl-C |
| 3 | Complete | Observable foreground execution | Model and tool work streams, reports elapsed time, and cancels safely |
| 4 | Complete | Durable artifacts and precise reads | Large results have stable bounded references and files support range reads |
| 5 | Complete | Repository exploration and profile | Search, instructions, manifests, exclusions, and relevant checks are discovered |
| 6 | Complete | Prepared mutations and diff approval | Writes are previewed, approved exactly, journaled, and revalidated |
| 7 | Complete | Atomic patching | Multi-file patch operations either complete together or leave inputs unchanged |
| 8 | Complete | Named checkpoints | Users can inspect and restore a selected workspace checkpoint |
| 9 | Complete | Journaled task state | Typed task state survives resume, questions, pauses, and limit exhaustion |
| 10 | Complete | Built-in modes | Ask, plan, code, and review have enforced tool and mutation policies |
| 11 | Current | Verification and completion evidence | Relevant checks and the exact state they cover are recorded and reported |
| — | Planned | *Mid-P0 audit* | *The core slice is proved in line mode and Steps 12–16 are re-reviewed* |
| 12 | Planned | TUI foundation | A crossterm UI starts and exits safely on Linux and Motor OS |
| 13 | Planned | P0 TUI interaction | Multiline input, transcript browsing, status, approvals, and control are usable |
| 14 | Planned | Prompt path references | Bounded `@file` and `@directory` references work without discovery turns |
| 15 | Planned | P0 quality gates | Provider corpus, adversarial/property tests, and performance budgets are in place |
| 16 | Planned | P0 end-to-end gate | The complete slice passes hermetically on Linux and Motor OS |

No P1 or P2 work is hidden in this table. In particular, live-turn follow-up
steering, same-turn structured elicitation, background jobs, interactive child
processes, LSP, new provider dialects, richer session management, declarative
permissions, extensions, richer VCS review, and automation protocols remain
outside this plan. Native Lorry self-build on Motor OS remains future work.

## Rules for every step

Each numbered step is a product increment, not permission for one large patch.
Split it into patches of roughly 100–300 lines including tests. A patch should
introduce one seam or one user-visible behavior and leave the tree working.

- Use standard Rust and native Motor OS APIs. The dependency approvals recorded
  below amend the P0 dependency list in `proposal.md`; mirror them into that
  document before changing a manifest. Any other dependency still requires a
  proposal update and review before it is added.
- Keep automated tests hermetic. A test must not contact a real provider or
  any non-loopback network service.
- Preserve line mode as a recovery and non-interactive interface. Core agent,
  task, tool, and approval behavior must not depend on the TUI.
- Keep model-facing failures typed and actionable. Unsupported Motor behavior
  is reported, never silently approximated.
- Do not add automatic retries, longer timeouts, ignored failures, or other
  mechanisms that can conceal a defect.
- Gears itself must not make automatic git commits in a user's repository.
  File restoration remains independent of git.
- Do not add eager startup work. Repository discovery and large artifacts are
  loaded lazily or bounded.

### Explicit approvals recorded 2026-08-13

- The user approved a separate, dev-image-only `gears-mock-provider` using
  `rustls` 0.23 without default features and with `ring` and `std`,
  `rustls-pemfile` 2, the existing Motor `ring` patch, and committed credentials
  prominently marked test-only. These dependencies must not enter the Gears
  executable or production provider path; Axum and Tokio are not needed.
- The user approved the pure-Rust `regex` crate from the existing 1.12 line,
  with `std`, `perf`, and Unicode support, as Gears' portable regex backend.
- The user approved `sha2` 0.10.8 without default features and with
  `force-soft` and `std` for stable file-content identities. It is already
  exercised on Motor OS by Lorry and adds no native dependency or build
  script.
- The user approved configurable regex defaults of 10 MiB compiled size,
  2 MiB DFA cache, nesting limit 250, and 16 MiB per searched file. Step 5
  gives the exact configuration keys.
- The user approved `--ui auto|tui|line` with `auto` as the default; the TUI
  keys and prompt-reference syntax are fixed in Steps 13–14.
- The user approved `russhd` with `pty-req` as the Motor TUI test carrier.
  Crossterm may enable any features Gears actually needs. A Motor backend fix
  must be made in the shared crossterm source and validated across Gears, red,
  rmux, and rush; it must not be a Gears-only fork.
- The user approved the resource numbers in Steps 3–5 and 13–15 as defaults,
  with every number exposed in the existing `gears.toml` configuration. The
  default locations are `~/.config/gears.toml` on Linux and
  `/user/cfg/gears.toml` on Motor OS; `--config` may select another file.
- The user approved an in-tree deterministic property-test generator without a
  fuzzing dependency, and the three-sample, 10% performance-regression default.
- The user approved autonomous implementation in verified 100–300-line
  patches. The implementing agent may commit each passing patch, update this
  status table, and continue. Before a commit it runs `gears-test.sh` once in
  debug and three consecutive times in release; neither `full-test.sh` nor
  `full-test-dev.sh` is a per-patch gate for Gears.
- After the Step 11 audit, the implementing agent may continue autonomously
  through Steps 12–16. The ordinary stop conditions in this plan and
  `AGENTS.md` still apply.
- `build-motor-os.sh` remains a large, infrequent, manually run new-host build.
  It is not an automated dependency-refresh service, and this plan adds no test
  harness for the script. When it clones a branch-based dependency on an empty
  host it receives the current remote branch; any incidental lockfile updates
  are reported and left uncommitted for a human to review and manage.
- The user approved one narrow exception to that clone-once policy: ripgrep is
  cloned when absent and an existing clean `master` checkout is fast-forwarded
  from `https://github.com/moturus/ripgrep` on each run. Dirty, detached,
  locally-ahead, and diverged checkouts must stop for manual resolution. This
  is not approval for a general dependency-refresh framework.
- If an external Motor fork needs changes, the implementing agent clones it as
  an uncommitted sibling checkout under `../`, temporarily points every
  affected Motor OS consumer at that local path, implements and validates the
  shared change, and stops for review. The temporary path overrides also remain
  uncommitted. A human commits and pushes the external change. The agent then
  restores every consumer to its GitHub branch, refreshes the affected locks,
  revalidates, and continues. The agent never commits or pushes the external
  repository.
- Only a human may run a real-model or other real-world provider evaluation.
  Automated tests use mock providers, never seek credentials, and never make
  non-loopback requests. P0 must deliver a reproducible manual scenario but
  does not require an automated or agent-initiated real-model run.

Before each autonomous implementation commit:

1. Format with `cargo +nightly fmt` and run the affected targeted tests.
2. Run `cargo test --locked --offline` and
   `cargo test --release --locked --offline` in `src/bin/gears`.
3. Run clippy for the affected Linux and Motor builds with no new warnings.
4. Run `src/tests/gears-test.sh` once in debug and
   `src/tests/gears-test.sh --release` three consecutive times. This explicit
   user approval replaces the repository-wide full-test gate for Gears work.
5. In the same patch/commit, update the status date, Overall, Current, Next,
   and the table state; update Done only when a step completes. Keep each
   completed step to one short outcome and remove obsolete detail. Detailed
   implementation and test logs belong in git history or the review record,
   not this status section.

The product, test-policy, and external-dependency workflow decisions are
resolved. No open design question remains at the end of this file.

Two early review gates, so a long plan does not run on unresolved assumptions:

- After Step 11 the core inspect → plan → edit → verify → review workflow is
  provable in line mode. Record an audit of progress and re-review Steps 12–16
  there, then continue autonomously. Path references, quality gates, and final
  integration still remain in addition to the UI.
- Step 0 retires the crossterm-on-Motor risk with a retained, reproducible
  proof rather than discovering it at Step 12. See Step 0.

## Step 0 — establish the hermetic Motor test lane

Do this first so every later feature is exercised on Motor incrementally.

Work:

1. Add `src/tests/gears-test.sh` as the direct Gears gate in debug and release
   configurations. It owns the Gears host-crate suite, dev-image build/boot,
   mock lifecycle, and Gears-specific Motor scenarios. Do not put those steps
   in ordinary `full-test.sh` or add Gears to the main-image test lane.
2. Change `full-test-dev.sh` so the broad dev-image suite calls
   `gears-test.sh` in the matching build mode instead of `exec`ing away the
   opportunity to do so. This makes Gears coverage transitively discoverable
   from the broad suite; implementation agents call `gears-test.sh` directly
   and are not required to run either full-test script.
3. Add the explicitly approved, development-only `gears-mock-provider` crate
   to the dev image. Reuse Gears' standard-library-only scripted scenario
   definitions and support deterministic streamed text, fragmented SSE,
   tool-call, usage, malformed-response, and error cases. Give the mock
   `rustls` 0.23 with `default-features = false, features = ["ring", "std"]`,
   `rustls-pemfile` 2, and the shared `moturus/ring`
   `motor-os-0.17.14` branch already used by `russhd` and `httpd-axum`. Commit a
   certificate and private key conspicuously marked test-only. None of these
   dependencies enter the Gears executable or production provider path.
4. Use the explicitly approved `russhd` session with `pty-req` as the Motor
   terminal carrier for later TUI scenarios. `full-test.sh` never connects the
   serial console's stdin, so `gears-test.sh` must request and verify the PTY
   rather than exercise Gears through an ordinary non-PTY SSH command. Steps 13
   and 16 inherit this carrier.
5. Prove gears' exact crossterm 0.29 dependency shape on Motor OS before Step
   12 depends on it. gears is not a member of the `src/sys` workspace, so that
   workspace's dependency override does not apply to it; see Step 12. Select
   the minimal features Gears actually needs, retain Gears' manifest, lockfile,
   and a one-frame smoke target, and test the same shared Motor source used by
   red, rmux, and rush. Do not create a Gears-only crossterm fork. If the shared
   backend or any other external Motor fork needed by P0 needs a fix, clone it
   under `../`, leave its changes uncommitted, temporarily point every affected
   Motor OS consumer at the local path, and run the relevant development and
   integration coverage. Stop for review. After a human commits and pushes the
   external change, point all consumers back to the GitHub branch, refresh the
   affected locks, revalidate, and continue. Complete this dependency audit in
   Step 0 so later steps do not stop on known porting work.
6. Package the approved Motor port of ripgrep (`rg`) from
   `https://github.com/moturus/ripgrep`. Extend `src/build-motor-os.sh` to build
   the current `master` branch after cloning it on a new/empty host or safely
   fast-forwarding an existing clean `master` checkout, and stage it as
   `img_files/generated/rg/bin/rg`; include
   `img_files/generated/rg` in both image YAML files, producing `/bin/rg` in
   regular and dev images. Do not add a global refresh phase or a test harness
   for `build-motor-os.sh`, and never invoke it from `gears-test.sh`.
   Because this step changes the script, the implementing agent may run it
   manually; report and preserve any incidental lockfile changes for human
   handling rather than including them in an autonomous commit.
   Convert the existing optional uploaded-ripgrep coverage in `full-test.sh` to
   exercise the packaged binary.
7. Add a VM scenario that starts the mock, runs gears against it, asserts exit
   status and resulting files, and always stops the mock.
8. Make the scenario fail if a request targets a non-loopback address. Do not
   rely only on configuration intent; assert the observed destination.
9. Check in a lightweight measurement method and record the current POC's
   startup-time, memory, and foreground-tool-latency baselines on Linux and
   Motor. Take three samples and mark a metric noisy rather than selecting a
   favorable sample or adding retries. Step 15 turns these into the complete
   P0 measurement gate. The current method and record are in
   `performance-baseline.md`.
10. Give later steps a single place to extend the host and VM P0 scenario,
   including the terminal carrier from item 4.

Exit criteria:

- `src/tests/gears-test.sh` directly runs the Gears host tests and a
  Gears-specific Motor VM scenario in either build mode; `full-test-dev.sh`
  calls it, while ordinary `full-test.sh` contains no Gears gate.
- The direct Gears gate passes once in debug and three consecutive times in
  release before each Gears implementation commit.
- The dev image contains the approved TLS mock and its conspicuously test-only
  credentials; the regular image and the Gears executable contain neither.
- The Motor terminal carrier is chosen, documented, and demonstrated by a
  scenario that reaches Gears through a `russhd`-allocated PTY.
- The retained crossterm proof builds locked and offline on Linux and Motor OS
  and paints one frame in the VM. Its shared dependency is reused by Step 12;
  any required backend fix passes Gears, red, rmux, and rush coverage.
- Every P0 external Motor fork either works from its shared GitHub branch or
  has completed the sibling-checkout review workflow. No temporary local path
  override remains before Step 1 starts.
- `build-motor-os.sh` gains only the ripgrep clone/build/staging work: no
  dependency-refresh framework or script test harness. `gears-test.sh` treats
  its generated outputs as prerequisites and never invokes the script.
- Both regular and dev images contain executable `/bin/rg` from the current
  Motor `master` branch, and the existing ripgrep filesystem regression runs
  against it.
- The VM completes a fragmented streamed response and one tool-call round
  entirely against the in-VM mock.
- The test asserts observable state and exit codes, not incidental rendering.
- The test succeeds with external networking unavailable and fails on any
  attempted non-loopback request.
- The checked-in measurement command reproduces the three-sample Linux and
  Motor baseline or reports which metric is too noisy to gate.
- Debug and release invocations of `gears-test.sh` both cover the scenario.

## Step 1 — make the platform contract executable

The model should see generic tools while gears selects the correct native
backend and explains the platform accurately.

Work:

1. Change the Motor toolchain backend from an absolute executable path to the
   naked name `lorry`, resolved by the process environment's `PATH`.
   `resolve_exe` in `src/sys/lib/rt.vdso/src/rt_process.rs` performs that
   search for names containing no `/`, and falls back to the name as given for
   anything else.
2. Report an unset, empty, or unsuitable Motor `PATH` as an actionable failure
   to locate Lorry, including the command gears attempted. Motor establishes
   no system-wide default `PATH`; each launcher controls the inherited
   environment. The standard dev-image `russhd` currently supplies `/bin`,
   while direct or console launch paths may not. The diagnostic belongs in the
   same patch as the switch to a naked name.
3. Until the root filesystem layout is redesigned, have launch paths that do
   not already supply it inject the current dev-image `PATH`. That value is a
   launcher/image property, not a gears interface, and gears must not encode a
   fallback location. Revisit it when the filesystem layout changes.
4. Generate a short platform contract in the system prompt:
   - Linux Rust build and test use Cargo.
   - Motor Rust build and test use Lorry, which implements a strict Cargo
     subset and is not Cargo.
   - Motor is neither Linux nor a Rust Unix-family target, while `rush` and
     selected `moto-rt` / `moto-rt-cabi` APIs provide some POSIX behavior.
   - The model must inspect repository instructions and documented APIs rather
     than assuming complete POSIX compatibility or no POSIX support.
5. Make the `build` and `test` tool descriptions name the selected backend and
   describe backend-specific argument limits without changing their generic
   tool names.
6. If `run` is asked to execute raw `cargo` on Motor, refuse with guidance to
   use `build`, `test`, or a supported `lorry` command. Do not install or
   emulate a Cargo wrapper.
7. Keep `run` as argument-vector execution. A model that needs shell syntax
   may explicitly run `rush`; gears does not insert a shell.

Exit criteria:

- Linux build/test command tests produce Cargo argument vectors.
- Motor build/test command tests produce `lorry` argument vectors containing
  no filesystem location for Lorry.
- The VM resolves Lorry through the standard `russhd` environment and through
  an explicitly configured direct-launch environment, and returns a targeted
  diagnostic naming the attempted command when `PATH` is unset, empty, or does
  not contain Lorry.
- No gears source encodes an absolute path to Lorry; any current filesystem
  location lives in the image or launch environment only.
- A scripted model that asks for Cargo on Motor receives the intended guidance
  and does not spawn a process named `cargo`.
- System-prompt snapshots distinguish the platforms without claiming that
  Motor is either fully POSIX or devoid of POSIX APIs.

## Step 2 — give terminal input one owner

Motor delivers Ctrl-C as the byte `0x03`. The current prompt reader cannot see
that byte during a live turn, and adding a second reader would race it.

Work:

1. Introduce one terminal-input owner that remains active at the prompt and
   during a turn. It emits typed input and control actions to the selected UI.
   Define it as the seam crossterm implements at Step 12 — crossterm owns raw
   mode and supplies its own event stream, so an owner written only against
   line mode is rewritten ten steps later. The typed input and control actions
   are the interface; how bytes or key events arrive is the implementation.
2. Keep the host SIGINT path and Motor in-band byte path behind the platform
   seam. Both must raise the same agent cancellation request.
3. Represent pause separately from cancellation. Pause stops scheduling after
   the current atomic model or tool operation; it does not suspend a running
   OS process. Resume permits the next operation.
4. Ensure input collected for a later prompt cannot be consumed by a
   permission question or by the active turn.
5. Preserve prompt-time Ctrl-C behavior and session resumability after a
   mid-turn cancellation.

Exit criteria:

- A test proves that only one component reads terminal input in every UI
  state.
- Host SIGINT and Motor `0x03` both cancel a live mock completion and end the
  turn with a resumable, structurally valid transcript.
- Ctrl-C at an idle prompt retains its documented prompt/exit behavior.
- A pause request raised during a model or tool operation takes effect before
  another operation starts; resume continues from the recorded task state.
- Bytes typed for the next prompt remain intact while a turn is active.
- The Motor VM scenario covers mid-turn Ctrl-C rather than only unit-testing
  the byte parser.

## Step 3 — make foreground work observable and cancellable

The existing tool API reports only start and end. P0 needs bounded live output,
elapsed time, cancellation, and an exact final result.

Work:

1. Add a tool-execution context carrying an event sink, cancellation handle,
   deadline, and agent identity. Migrate tools without changing their outputs.
2. Extend UI events with bounded stdout/stderr chunks and progress/elapsed
   updates. Do not put terminal formatting in the event types.
3. Change foreground process capture to drain stdout and stderr concurrently,
   stream bounded chunks, and retain a bounded final combined result with the
   exact exit status.
4. On cancellation, stop the provider request or foreground child promptly.
   Linux stops the process group; Motor stops the direct child and reports that
   descendants cannot be guaranteed.
5. Propagate cancellation through sub-agent waits and prevent a cancelled
   agent from beginning another tool call.
6. Treat a non-zero command status as execution evidence, not a tool protocol
   error. Preserve timeout, cancellation, spawn, and protocol failures as
   distinct outcomes.

Exit criteria:

- A command that alternates stdout and stderr produces live events before it
  exits and a final bounded result containing both streams and its status.
- Output exceeding every live and retained bound does not grow memory without
  limit, deadlock a pipe, or lose the beginning/end elision markers.
- Elapsed time becomes visible while a silent command is still running.
- Cancellation latency is bounded by process shutdown rather than the normal
  command timeout.
- Linux tests prove descendant cleanup; Motor tests prove direct-child cleanup
  and the explicit limitation message.
- Provider, root-agent, sub-agent, build, test, and raw-run cancellation leave
  sessions resumable with no unmatched tool request/result records.

## Step 4 — add durable artifacts and precise reads

Large results and generated patches must remain inspectable without filling
every model request or depending on ephemeral TUI memory.

Work:

1. Extend the existing version-1 `gears.toml` schema with a validated
   `[resources]` table. Use these explicitly approved configurable defaults:
   `max_artifact_bytes = 16777216`,
   `max_session_artifact_bytes = 268435456`,
   `max_live_render_queue_bytes = 1048576`,
   `max_range_read_bytes = 1048576`,
   `max_inline_attachment_bytes = 65536`,
   `search_default_results = 100`,
   `search_max_results_per_page = 1000`,
   `regex_size_limit_bytes = 10485760`,
   `regex_dfa_size_limit_bytes = 2097152`,
   `regex_nest_limit = 250`, and
   `search_max_file_bytes = 16777216`. Reject zero, overflow, and internally
   inconsistent values actionably; omitted fields retain the approved
   defaults.
2. Add a versioned, session-owned artifact store under `.gears` with stable
   identifiers, type, size, origin, and creation metadata.
3. Enforce the configured 16 MiB per-artifact and 256 MiB per-session defaults
   with deterministic refusal or eviction. Never silently truncate the stored
   artifact while calling it complete.
4. Add a read-only model tool for listing artifact metadata and reading a byte
   or line slice. Tool schemas must make bounds explicit.
5. Extend `read_file` with mutually consistent line- and byte-range reads,
   capped by the configured 1 MiB default, total-size metadata, and a stable
   content identity that changes when the file changes.
6. Store oversized tool results and patch previews as artifacts and put only
   their summary/reference into subsequent context.
7. Apply existing credential redaction before model-visible or durable output
   is recorded. Keep each tool request paired with the result or artifact that
   explains it.

Exit criteria:

- A result larger than the context cap can be reopened in non-overlapping
  slices after a session resume.
- File line and byte ranges have tested boundary, empty-file, invalid-UTF-8,
  and changed-on-disk behavior.
- A stale file identity is detected rather than reused as current content.
- Artifact quotas are enforced deterministically and cannot escape the
  workspace/state boundary through names or symlinks.
- Default and overridden `[resources]` values round-trip through config tests;
  invalid or inconsistent values fail before any session or artifact is opened.
- Session compaction preserves the artifact reference and its originating
  tool-call/result relationship.

## Step 5 — make repository exploration deliberate

P0 does not include LSP, but it must avoid repeated blind directory walks and
literal-only search.

Work:

1. Extend search with include and exclude globs, case control, file-name
   search, configurable result limits, and stable paging cursors. Defaults are
   100 results and at most 1,000 results per page, from `[resources]`.
2. Add the explicitly approved pure-Rust `regex` 1.12 dependency with
   `default-features = false` and `std`, `perf`, and Unicode support. It is the
   portable backend on Linux and Motor OS, so search never depends on an
   external executable. Add literal/regex selection and one result contract.
3. Resolve `rg` by name through `PATH` and use packaged ripgrep as an optional
   accelerator when available. It is present as `/bin/rg` in Motor regular and
   dev images after Step 0, but Gears must not encode that location and Linux
   installations without ripgrep must retain identical native behavior. Apply
   the same exclusions, limits, ordering, paging, and output normalization to
   both backends. Enforce the approved configurable defaults: 10 MiB compiled
   regex size, 2 MiB DFA cache, nesting limit 250, and 16 MiB per searched
   file. Report an oversized skipped file rather than silently omitting it.
4. Keep every traversal workspace-confined, do not follow directory symlinks,
   and skip generated, vendor, VCS, build, and gears-state directories by
   default. Explicit safe paths remain addressable.
5. Discover repository roots, manifests, languages/toolchains, generated and
   vendor directories, and conventional verification commands without running
   those commands.
6. Load root and applicable nested project instructions in deterministic
   root-to-leaf order. Record the source path of each instruction block and
   refresh it when its content identity changes.
7. Expose a compact repository profile to the system prompt/task workflow and
   retain its detailed evidence as an artifact.

Exit criteria:

- The same fixture produces equivalent ordered search results through the
  native backend and an enabled `rg` backend; absence of `rg` is a normal,
  tested native-fallback case.
- Regex, multiple include/exclude patterns, file-name-only search, paging, and
  result caps have positive and adversarial tests.
- Native and `rg` backends enforce equivalent configured regex, file-size, and
  result limits and report every limit refusal or skipped input.
- Searches never enter denied paths, skipped trees, or escaping symlinks.
- A nested-instruction fixture proves which instructions apply to files at
  the root and below nested directories, including refresh after modification.
- Rust fixtures identify Cargo on Linux and Lorry on Motor as the selected
  backend while preserving other relevant project checks as candidates only.
- Discovery performs no network access, compilation, test execution, or eager
  whole-repository content load.

## Step 6 — prepare mutations before approval

The current permission gate sees a one-line tool description before the tool
computes its edit. P0 approval must refer to the exact proposed change.

Work:

1. Split mutating tool execution into prepare and apply phases. Preparation is
   read-only and produces an immutable change set, input identities, readable
   diff, permission key, and digest.
2. Show the diff or a bounded preview plus artifact reference in the approval
   UI. Record the exact change set and decision in the session.
3. Revalidate every input identity after approval and immediately before
   apply. A mismatch returns a conflict and requires a newly prepared diff.
4. Migrate `write_file` and `edit_file` to the prepared-mutation path without
   weakening workspace confinement or undo behavior.
5. Keep remembered approvals scoped by their existing permission keys, but
   record every exact mutation even when the user previously selected always.
6. Add failure injection around preparation, approval-channel closure, and
   apply so no failure path writes an unapproved change.

Exit criteria:

- The bytes applied are exactly the bytes represented by the approved digest.
- Modifying an input between prepare and apply produces a conflict and writes
  nothing.
- Denial or a dropped UI reply leaves all files and task state unchanged apart
  from the recorded denial.
- `write_file` and `edit_file` approvals display exact diffs for create and
  replace operations, including oversized diffs through artifacts.
- Resume shows what was proposed, approved, denied, applied, or failed without
  replaying any operation.

## Step 7 — add the atomic patch tool

Build the patch engine on the prepared-mutation protocol rather than teaching
the model to perform a fragile series of independent edits.

Work:

1. Define a versioned structured patch request containing ordered file
   operations and text hunks. Do not parse arbitrary shell commands as patches.
2. Support create, exact-hunk edit, delete, and rename everywhere. Support the
   Unix executable-bit change on Linux. On Motor OS, refuse mode changes with
   an actionable explanation until a reviewed portable API exists; do not
   approximate the operation.
3. Validate the complete request, paths, input identities, hunk uniqueness,
   rename graph, and final destinations before the first mutation.
4. Stage replacement contents, apply the approved set, and roll back from
   private backups if any filesystem operation fails. Recovery metadata must
   make an interrupted apply detectable on the next start.
5. Reject duplicate targets, overlapping/conflicting hunks, escaping symlinks,
   changes under denied state, and concurrent stale inputs.
6. Store large patch requests and complete diffs as artifacts.

Exit criteria:

- One request successfully creates, edits, renames, deletes, and—where
  supported—changes a mode across multiple files.
- Any invalid hunk or destination leaves every requested input byte-for-byte
  and mode-for-mode unchanged.
- Injected failures at each apply stage either restore the original state or
  leave recovery metadata that startup resolves before accepting new work.
- Two prepared writers against the same input cannot silently overwrite one
  another; one succeeds and the stale one reports a conflict.
- The approved diff, applied diff, and recorded session digest agree.
- Linux tests cover executable-bit changes; Motor tests cover the explicit
  refusal. Both platforms cover every other supported operation.

## Step 8 — make undo a set of named checkpoints

Checkpoints extend the existing copy-before-write safety net; they do not turn
git commits into an automatic workflow.

Work:

1. Define a versioned checkpoint containing a name/id, creation time, task and
   mutation generation, file identities, contents or absence, modes where
   supported, and rename relationships.
2. Add create, list, inspect-diff, and restore operations. Create a checkpoint
   before the plan-to-code transition and allow explicit user checkpoints.
3. Restore through the same prepared-mutation and conflict machinery as an
   ordinary edit. Do not overwrite changes made since the checkpoint without
   showing and approving the restore diff.
4. Retain the existing whole-session `/undo` behavior as the initial
   checkpoint, expressed through the new implementation.
5. Apply artifact-style bounds and cleanup to checkpoint storage without
   deleting the only recovery copy for an unfinished mutation.

Exit criteria:

- A fixture can create two checkpoints, inspect both diffs, restore either,
  and then restore the original session state.
- Restore handles created, deleted, renamed, edited, and mode-changed files.
- External modification after a checkpoint causes a conflict/approval diff,
  not silent data loss.
- Checkpoints survive process exit and session resume and are isolated between
  sessions.
- A failed or interrupted restore satisfies the same recovery invariant as an
  atomic patch.

## Step 9 — journal typed task state

Task state is durable program data, separate from free-form model prose and
forward-compatible with older session readers.

Work:

1. Add versioned session records for a task, ordered items, state transitions,
   active mode, checkpoint, verification evidence, pause state, and handoff.
2. Support pending, active, completed, and blocked items with validated
   transitions. Preserve user-authored wording separately from model updates.
3. Expose task state to the model in a compact form and to both UIs without
   resending the entire task history on every completion.
4. When a turn reaches its step, token, or spend limit, finish the current
   atomic operation, record a handoff with the remaining items and reason, and
   return control without claiming completion.
5. Allow P0 questions to end a turn in a waiting-for-user state; the next user
   reply resumes the same task. Do not implement P1 same-turn elicitation.
6. Make pause take effect only at an atomic boundary and persist it so an
   accidental restart does not resume work silently.

Exit criteria:

- Create, transition, block, resume, pause, and complete task fixtures survive
  session close/resume with identical visible state.
- Invalid or duplicate transitions are rejected and do not corrupt the JSONL
  transcript.
- Unknown future task records are skipped and reported under the existing
  forward-compatibility rule.
- Step, token, and spend exhaustion each produce an explicit handoff with no
  active mutation and no unsupported claim of completion.
- A question-ended turn resumes after the next reply without re-deriving or
  losing the plan.

## Step 10 — enforce the built-in modes

Modes are code-owned P0 workflows. User-defined modes and skills remain P1.

Work:

1. Define ask, plan, code, and review as typed modes with versioned prompt
   fragments, allowed tools, mutation policy, entry conditions, and explicit
   transitions.
2. Ask and plan receive only non-mutating tools. Review is read-only and
   examines the task's proposed/applied diff and verification evidence. A
   request to fix a finding transitions explicitly to code.
3. Code may use prepared mutating tools through the permission gate. Entering
   code from a mutating plan requires the plan checkpoint and an approval
   checkpoint unless the user directly requested code mode for that task.
4. Make current mode and pending transition visible in line mode, the session,
   and later the TUI. A resumed task returns to its recorded safe mode.
5. Keep tool lists honest: a forbidden tool is absent rather than described
   and then silently ignored.
6. Version and snapshot-test the common system prompt, platform contract, mode
   fragments, tool descriptions, and model-facing failure text.

Exit criteria:

- A scripted provider cannot cause ask, plan, or review mode to invoke a
  mutating tool, even by emitting a syntactically valid call for one.
- Plan-to-code approval records the approved plan and checkpoint before the
  first mutation.
- Review mode can inspect exact edits and recorded checks but cannot fix them
  without a visible transition to code.
- Mode and transition state survive resume, cancellation, and handoff.
- Linux and Motor receive identical mode semantics plus their correct platform
  contract and tool inventory.

## Step 11 — make verification evidence part of completion

Verification is selected from the task and repository, not a fixed
build → run → test sequence.

Work:

1. Turn discovered checks into reviewable candidates. Select checks based on
   the task, changed paths, project instructions, and platform; do not execute
   arbitrary repository configuration merely because it was discovered.
2. Record each check's backend, argument vector, cwd, start/end, exit status,
   output artifact, task/checkpoint generation, and git revision when present.
3. Mark evidence stale after a later gears mutation. Report external changes
   detected through prepared-input identities instead of implying they were
   covered.
4. Normalize Cargo/rustc and current Lorry compiler/test diagnostics into path,
   line/column where present, severity, message, and source tool. Retain the
   complete raw output artifact. Adopt machine-readable Lorry diagnostics when
   Lorry supplies them; do not require them for P0.
5. Enforce a completion contract: inspect the final applied diff, account for
   every task item, run relevant approved checks or record why each was not
   run, name unverified assumptions, and report only recorded evidence.
6. Keep project execution conditional. A check named `run` is never inserted
   merely because code mode reached a fixed stage.

Exit criteria:

- Rust fixtures select Cargo checks on Linux and Lorry checks on Motor without
  passing unsupported backend flags.
- A source-only task, documentation-only task, failing-check task, and task
  with no applicable executable check each produce the intended evidence and
  completion report.
- Diagnostics link to valid workspace paths/ranges while malformed lines
  remain available in raw output.
- A mutation after a successful check marks that check stale and prevents the
  final report from presenting it as current.
- A scripted model cannot claim an unrecorded check through the structured
  completion path; the UI distinguishes passed, failed, skipped, and stale.

## Step 12 — add the TUI foundation

The TUI is a view/controller over existing events and task state, not a second
agent implementation.

Work:

1. Reuse the shared crossterm dependency proved in Step 0 and verify the
   refreshed lock on Linux and Motor before building UI behavior on it. Gears
   is a standalone crate and not a member of the `src/sys` workspace, so its
   manifest must point to the same `moturus/crossterm` `motor-os-support`
   branch used by red, rmux, and rush. That manifest override is not a
   Gears-specific source fork. Keep default features disabled when practical
   and enable every feature the implemented UI actually needs. Any Motor
   backend change belongs in the shared source and must pass all four consumer
   suites. The git source widens the parked Track A gap because Lorry rejects
   git dependencies.
2. Separate UI-neutral state reduction from terminal drawing and input so it
   can be tested with recorded events and a fake terminal.
3. Add the explicitly approved `--ui auto|tui|line`, defaulting to `auto`.
   `auto` selects TUI only for a suitable interactive terminal;
   non-interactive and recovery use line mode. Document the exact spelling in
   `--help` and `README.md`.
4. Enter and leave raw/alternate-screen state safely on ordinary exit,
   cancellation, initialization error, and panic where unwinding is available.
5. Handle resize and terminals without optional capabilities without spawning
   probes or adding startup latency.
6. Keep secrets and raw control bytes out of rendered status and diagnostics.

Exit criteria:

- Fake-terminal tests cover setup, resize, redraw, teardown, setup failure, and
  output failure without snapshot dependence on timing.
- Linux PTY and Motor terminal scenarios show a TUI frame and restore the
  original screen and input mode on every tested exit path, reached through the
  terminal carrier chosen in Step 0. `full-test.sh` already asserts
  alternate-screen enter/exit and restoration for the existing terminal
  programs; reuse that assertion shape rather than matching rendered text.
- Piped input/output and `--ui line` use the existing line UI; `--ui auto`
  selects it when either terminal side is unsuitable.
- Starting line mode does not initialize crossterm or add terminal probes.
- The TUI consumes the same recorded `Event` stream and task state used by
  line-mode tests.

## Step 13 — complete the P0 TUI interaction

Work:

1. Add multiline editing, bracketed-paste handling, session-local prompt
   history, and safe handling of invalid UTF-8/control input. Use the explicitly
   approved bindings: Enter submits, Alt+Enter or Ctrl+J inserts a newline,
   Ctrl+C cancels active work and retains the existing idle behavior, and
   Ctrl+P pauses.
2. Add a bounded transcript and tool-output viewer backed by session events and
   artifacts. P0 needs basic navigation; Markdown, syntax highlighting, and
   richer search/copy navigation remain refinements.
3. Add a status area for model, mode, task progress, context headroom, usage
   and cost, current tool and elapsed time, pause state, and active sub-agents.
   Hide or mark fields the provider cannot supply.
4. Render streamed model/tool output through the configurable live render
   queue, whose approved default maximum is 1 MiB. A fast producer coalesces
   live chunks instead of growing the queue without bound; the final artifact
   remains inspectable.
5. Add approval views that show the exact command or mutation diff, cwd,
   requesting agent, permission scope, and artifact-backed overflow before the
   decision is sent.
6. Integrate cancellation and pause controls with Steps 2–3. Do not add P1
   queued follow-ups or mid-turn task amendments.
7. Resume a session by rebuilding the visible transcript/task/checkpoint state
   from durable records, not from stale terminal buffers.

Exit criteria:

- Automated key/event tests cover Enter submit, Alt+Enter and Ctrl+J newline,
  paste containing newlines, history traversal, Ctrl+C cancellation and idle
  behavior, Ctrl+P pause/resume, approval, denial, resize, and transcript
  navigation.
- A long silent command shows elapsed time; a noisy command remains responsive
  and its full retained result can be opened.
- A large diff can be browsed before approval and the decision applies to the
  displayed digest.
- Status accurately distinguishes idle, model, foreground tool, paused,
  cancelled, failed, and completed states.
- Linux and Motor hermetic scenarios drive the same essential interaction
  sequence through their real terminal paths.

## Step 14 — add direct prompt path references

This feature works in both UIs and one-shot mode; it is not TUI markup.

Work:

1. Implement the explicitly approved syntax: `@path` for an unquoted path,
   `@"path with spaces"` for a quoted path, and `@@` for a literal `@`.
   Document escaping inside quoted paths and make nonexistent, malformed, or
   ambiguous references fail before submission.
2. Resolve references through `Workspace`, including denied paths and symlink
   confinement. Do not let prompt parsing become another filesystem boundary.
3. Attach at most the configured inline amount, 64 KiB by default, directly to
   the user message with path, content identity, and artifact metadata. A
   directory reference attaches a bounded listing/profile, not every file's
   contents.
4. Store large referenced content as an artifact that the model can inspect in
   slices. Do not silently substitute stale content after the file changes.
5. Show the resolved references and sizes to the user before submission and in
   the session transcript.

Exit criteria:

- References to a small file, large file, empty file, directory, quoted path,
  escaped literal, missing path, denied path, and escaping symlink have tests.
- A model receives a small referenced file in the first completion request
  without a discovery tool round.
- Large files and directories remain within request/context limits and expose
  stable artifact references for further reads.
- Editing a referenced file invalidates its old identity; resume preserves the
  exact content/reference originally sent rather than silently rereading it.
- Line, TUI, and one-shot modes use the same parser and attachment records.

## Step 15 — install the P0 quality gates

Work:

1. Consolidate the existing fragmented-stream, parallel-tool-call, typed-error,
   timeout, and cancellation cases into one reusable provider conformance
   corpus. Run the current OpenAI-compatible adapter through it.
2. Add hermetic scenarios for malformed provider data, malformed tool calls,
   cancellation at every safe boundary, compaction, task recovery, mutation
   conflicts, approval loss, and interrupted patch/checkpoint recovery.
3. Add deterministic adversarial/property suites for path confinement, range
   and search paging, patch application, session/task decoding, redaction, and
   permission matching. Use the explicitly approved in-tree deterministic
   generator; each parser also gets a bounded arbitrary-byte input harness.
   Do not add a fuzzing dependency.
4. Add machine-readable measurements for startup time, peak or sampled memory,
   request/context bytes, retained/artifact bytes, render queue depth, and tool
   latency. Extend Step 0's checked-in method and add a validated `[quality]`
   config table with the approved defaults
   `max_regression_percent = 10` and `stable_samples = 3`. A regression greater
   than 10% is blocking only after three stable samples; a noisy metric is
   reported with its samples and remains non-blocking. Both numbers are
   configurable in `gears.toml`.
5. Add tests proving repository discovery and extension-free startup are lazy
   and add no avoidable Motor boot work.
6. Version system prompts and tool descriptions as reviewed fixtures. Measure
   request size and ensure content identities prevent reuse of stale files.
7. Add a conspicuously manual real-model scenario and manifest containing the
   repository commit, isolated fixture/worktree, task input, provider and
   model/version, configuration, required finite budget, expected assertions,
   grading rubric, result, tokens, cost, time, and turns. It must require an
   explicit human-only acknowledgement and human-supplied provider, model,
   credentials, and budget; no automated script calls it, and an implementing
   agent never runs it. P0 validation assumes no credentials exist.

Exit criteria:

- The current provider adapter passes the shared conformance corpus through
  unit and real loopback-transport paths.
- Every listed security/correctness surface has deterministic adversarial or
  property coverage and bounded resource use.
- Performance output records all named metrics on Linux and Motor; configured
  budget violations fail clearly rather than being averaged away or retried.
- Prompt/tool fixture changes produce focused review diffs and request-size
  comparisons.
- A human can reproduce a budget-capped real-model evaluation from one
  scenario and manifest. P0 requires the scenario, dry validation of its local
  setup, and documentation—not a completed real-provider run.
- No automated test attempts external network access.

## Step 16 — run the P0 end-to-end gate

Extend the Step 0 fixture rather than creating an unrelated demonstration.

The scripted task must:

1. Start a new session in the P0 TUI and identify the correct platform.
2. Select plan mode, inspect root and nested instructions, use precise/search
   reads, and record a task plan.
3. Approve the plan-to-code transition and checkpoint.
4. Apply an atomic multi-file change after reviewing its exact diff.
5. Run the relevant native verification through Cargo on Linux and Lorry from
   `PATH` on Motor, retaining normalized and raw evidence.
6. Enter review mode, inspect the applied diff and evidence, and produce the
   structured completion report.
7. Restore a named checkpoint, reapply the change, and prove conflicts are not
   overwritten.
8. Cancel one live model response and one foreground command, resume the same
   task/session, and finish without corrupting the transcript.
9. Exercise a large artifact and an `@file` reference without exceeding the
   configured context/artifact bounds.

Final exit criteria:

- The complete scenario passes hermetically through the real Linux and Motor
  terminal/process/toolchain paths through `src/tests/gears-test.sh`;
  `full-test-dev.sh` calls that direct gate as part of its broader suite.
- Linux selects Cargo; Motor resolves `lorry` through `PATH`; raw Cargo on
  Motor receives actionable guidance; no test installs a Cargo shim.
- Every approved mutation matches its recorded digest, and checkpoint restore
  returns the exact expected bytes/modes.
- Every claimed check has recorded, current evidence tied to the tested task
  generation; skipped or stale checks are reported as such.
- Cancellation, pause, resume, question handoff, session resume, and limit
  exhaustion all stop at valid atomic boundaries.
- Startup, memory, request/context, artifact, render-queue, and tool-latency
  measurements remain within the approved P0 budgets.
- `cargo +nightly fmt`, the required clippy and locked/offline crate tests,
  one debug `gears-test.sh` run, and three consecutive release
  `gears-test.sh` runs complete with no new warnings. The full-test scripts are
  not a Gears P0 completion gate.
- `README.md`, `proposal.md`, and this status table are updated to the observed
  result. Completed step details remain in git history rather than growing the
  status section.

At that point P0 is complete. Start P1 only after a separate review of the
remaining roadmap in `proposal.md`.

## Open questions

None.
