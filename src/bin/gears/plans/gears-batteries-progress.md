# Gears batteries implementation record

Updated 2026-10-06. The design in [gears-batteries.md](gears-batteries.md)
remains authoritative. Work proceeds in small patches with one-line commits.
All Gears defects found during implementation are in scope.

## Current position

The phase 0 companion documents and the phase 1–4 implementations are in
place. Phase 5.1–5.6 are implemented. The real-binary workflow passes on
Linux and Motor OS, and the updated release developer-image gate passes.
The user reports that native OpenRouter use works and has requested
continuation, clearing the phase 5 decision point. A local-model result has
not been reported. Phase 6.1–6.4 memory storage, admission, prompt handling
and user commands are implemented. Phase 6.5 skills and phase 7's explicit
`/accept` pass the host gates and installed native workflow using the stock
`dev.3` SDK. The SDK rollout is complete: three debug and three release
main-image gates and `full-test-dev.sh --release` pass, including native
packaged-source builds. Phase 8 has settings, marks, saved-entry snapshots,
tool policy, triggers, the resume question, the proposal cap and the connected
review runner. Real-binary compacted reviews preserve the saved prefix on both
systems, with historical resource checkpoints and current withdrawal corrections
after resume. Real in-flight interruption and session isolation pass. Phase 8.3
cleanup stages explicit-cutoff archival proposals and passes the real CLI workflow.
Sysbox step S1 is implemented and passes the focused native regression;
its final source passes three debug and three release full core gates.
Those gates exposed a preexisting TCP test isolation defect; its small
test-only correction is committed and validated. The first S2 patch is
committed in `399cf0a5`: byte-order `sort` with `-r -u -f -s -c -o`, literal
operands and a quoted executable wrapper. Its native regression and
warnings-denied Clippy pass, as do three debug and three release full core
runs after the diagnosed kernel-log test correction (`9adb3ddf`). The second
S2 patch adds exact numeric and human-size sorting and passes the same six
core gates with the stock `dev.3` SDK. Field keys, S3–S6 and the remaining
phase 8–12 work are pending.

The phase 3 manual checklist is not marked complete. Automated host tests
cover the runtime and both UIs; native gates cover shipped tools, literal
arguments, local HTTP, the six line-interface approval choices, process
ownership and the directory lock. Complete native interactive UI checks
before declaring that checklist finished.

## Implemented extensions

- Immutable live-session snapshots and ephemeral forks.
- Structured tool outcomes, usage and JSONL one-shot output.
- Hook event subscriptions and bounded `before_stop` follow-ups.
- Hook setup after session changes, provider/model changes and compaction.
- An owned after-turn runner, stopped and joined before runtime writes,
  session changes and exit; interactive interfaces opt in explicitly.
- Hook slash commands, bounded questions and hints in both interactive
  interfaces, with unattended answers for one-shot runs.
- Tool-round counts and last entry ids in end-of-turn metadata.

These changes reuse Gears' shared process runner. Children do not receive
the provider key; cleanup uncertainty prevents subsequent writers or spawns.
Nested timeout behavior is tested with real Gears running a shell child and
grandchild on Linux and Motor OS.

## Everyday coding batteries

- Workspace-root `AGENTS.md`, falling back to `.gears.md`, and bounded,
  content-addressed prompt snapshots. Resume, fork and provider changes reuse
  the snapshot; new sessions and compaction refresh it.
- Numbered UTF-8 `read_file` pages and read coverage tied to the whole file's
  version. Existing files require complete current reads before replacement.
- Literal `search_files` paths with bounded ripgrep output; atomic
  `write_file` and `patch` preserving BOM, newline style and caller access.
  Patches use unique matches and original byte positions for normalized
  matching, and return bounded diffs.
- Protected Gears state paths, with a read exception for the current
  session's saved tool results. File tools refuse symlink traversal.
- Branch-aware `todo` state and durable mechanical turn records, including
  saved entry ids, actual outcomes, failures, repeated calls, writes and
  checks. Incomplete final journal lines are removed before appending.
- Workspace read approvals, ordinary write/command prompts, a short static
  destructive-command list, and fresh confirmation for publishing or
  discarding work. Shell policy uses the shell's saved working directory.
- Literal check vectors with Linux/Motor/common selection in workspace-root
  `.gears/batteries.toml`. Approval details show the selected vector;
  only a matching completed receipt records its execution. Later writer
  calls stale the evidence. Missing, failed or stale checks can add at most
  three follow-ups in a turn.
- Paged `session_search` across all saved branches and workspaces, using
  immutable snapshots. Hits retain session/entry ids and identify off-branch
  text. Curl output and externally sourced history are marked untrusted;
  copied provenance delimiters are defused.
- The opt-in `config/gears-batteries.toml` selects OpenRouter or a local
  provider, registers the hook and enables the coding tools. Developer-image
  packaging merges both tool directories and installs the workflow fixture.

These policies prevent accidents; they do not confine tools. Native atomic
replacement preserves the caller's access rather than every role's metadata.
Checks provide development evidence, not user acceptance. Reviews, workers,
scheduling and gateways remain later work. The user has simplified
acceptance to a small explicit `/accept` command, as recorded below.

The portable workflow uses the actual CLI, shipped manifests and shared
Gears runtime with a scripted provider. It reads a deliberately broken Rust
crate, searches source and sessions, writes a literal filename, patches the
assertion and compiles it. It verifies the saved check, approval details and
turn journal, restores earlier tasks on a fork, then proves a model can get
only three missing-check reminders. No provider or Internet request is made.
It also postpones a model's memory proposal, then exercises memory commands
and prompt transitions in a separate isolated workspace on both systems.

## Memory through phase 6.4

- Versioned entry files distinguish user, observed and inferred claims,
  with session/entry sources, scope, date and optional applicability.
  User-wide character limits include metadata. Invalid optional files are
  reported and skipped independently.
- The `memory` hook tool stages add/replace/remove proposals by content hash.
  Whole-file changes are refused; exact duplicates are ignored. Interactive
  questions display the proposal and other pending counts. Approval, denial
  and postponement are delivered to the model; unattended runs leave pending
  intact without asking.
- Approval validates the captured entry before logging a decision, then
  atomically replaces the memory file and removes pending. Changed or removed
  entries fail before logging. Write failures stop the operation. The agreed
  single-writer order has no transaction or automatic recovery across files.
- New sessions and compaction snapshot approved memory. Additions do not
  change the current session's prefix. Resume and fork retain frozen entries
  while reconciling corrections and removals. Running branches get one note
  for each change, preserving their original prefix; resumed prefixes omit
  removed material. This cannot erase past text from model history.
- Imported or hand-edited workspace memory requires local approval of the
  exact file hash. Initialization displays it to the user while excluding it
  from the model prompt. Entry approval cannot incidentally admit other
  unreviewed contents of that file.
- `pending` shows before/after entries, bounded source excerpts and sessions
  whose snapshots contain the old entry. Unavailable evidence is identified;
  snapshot membership does not prove a provider request used it. Closed input
  postpones; `--list` makes no decisions. Explicit approve/deny/postpone by
  complete hash also works for imported workspace files. `history` streams
  bounded decision pages; `status` reports pending and workspace approval,
  with later review/eval features explicitly unimplemented.

The sample hook now subscribes to `answer` and `context`. Users updating an
existing installation must copy the updated sample or add both events.
See the [batteries README](../../gears-batteries/README.md) for command syntax,
file format, limits and failure behavior. Approval admits future use and
does not certify truth or usefulness.

## Recent defects and their evidence

- Motor shell state restoration assumed `/dev/null` existed. The original
  developer-image gate failed; removing that redirect restored the native
  shipped-tool gate (`e77e3e5a`).
- Explicit Cargo example metadata prevented the packaged Gears source from
  building with Lorry. Automatic example discovery resolved it (`c0266402`).
- A forced TUI one-shot run could ask for approval. Unattended runs now deny
  without reading input; modified shortcut keys cannot save grants
  (`753fe8c9`).
- A cancelled hook answer still saw the process-wide interrupt flag and
  never reached its hook. A dedicated regression verifies delivery and
  preservation of the original interrupt (`da3c55d3`).
- Scrolling past the beginning blanked the TUI transcript. The renderer now
  clamps scrolling and keeps complete questions readable (`8e81469f`).
- Raw line input discarded bytes queued after a newline and split UTF-8
  characters on backspace. Byte-stream regressions cover queued lines,
  UTF-8 editing and split CRLF input (`b71fe348`).
- A nested Motor OS tool timeout let Gears request another model answer
  and finish successfully. The runner now validates inherited process
  ownership, reaps the child tree and ends the interrupted nested process
  (`83d1521d`). Original failure: `/tmp/gears-owned-vm-sftp-repro.log`;
  fixed native regression: `/tmp/gears-owned-vm-fixed.log`.
- Motor OS command names include arguments and may be truncated. Gears
  misidentified a live lock holder and let a second instance contact the
  model. Complete names now recognize Gears with arguments; ambiguous live
  names preserve the lock (`b0e8eaeb`). Original failure:
  `/tmp/gears-lock-vm-original.log`; fixed native regression:
  `/tmp/gears-lock-vm-fixed.log`.
- Bare hook commands searched PATH for `gears-batteries`, bypassing the
  sibling executable required by the design. Shared-runner resolution now
  covers hooks and after-turn commands as well as tools (`bca70fa5`). The
  original competing-PATH failure is in
  `/tmp/gears-batteries-sibling-original.log`.
- The new opt-in sample omitted loopback egress permission and an explicit
  local key. A direct configuration load caught both policy requirements;
  the corrected sample has a parsing regression (`7d1ba369`).
- The sibling regression's executable copy occasionally failed to start
  with Linux `ETXTBSY`. A syscall trace showed parallel spawns while its
  writable copy descriptor was open. Fixture preparation now runs in its
  own test process (`8a6c7049`), preserving the original assertions and
  timeouts. Original failure:
  `/tmp/gears-batteries-config-complete-host-gate.log`; fixed component gate:
  `/tmp/gears-batteries-sibling-isolated-host-gate.log`.
- The batteries host gate assumed `rg` was installed. The earlier passing
  run found Codex's bundled binary; the user's ordinary host PATH failed
  with `cannot run rg: No such file or directory`. The same failure is
  reproduced in `/tmp/gears-batteries-missing-rg-original.log`. The gate now
  builds a Linux binary offline from the existing sibling ripgrep checkout,
  stores it under Motor OS `build/`, and supplies it to the test processes.
  Full-test preparation builds it before the timed suite. The standalone
  release gate passes without Codex's PATH
  (`/tmp/gears-batteries-provisioned-rg-host-gate.log`). This changes no
  ripgrep source or batteries runtime behavior. The corrected full release
  developer-image gate passes in the same ordinary host environment,
  including the installed workflows, native source builds and Lorry's
  complete product suite (643 seconds). Its log is
  `/tmp/gears-batteries-host-rg-dev-release.log`.
- The user's first native OpenRouter conversation claimed access to
  `execute_command`, `fetch_web_page` and `view_image`, none of which are
  shipped Gears tools. Source review and the existing provider/runtime
  regressions confirm that enabled tool names and schemas are passed
  through without these substitutions. The system prompt now states that
  the request's tool definitions are the complete available list, requires
  exact names and declared capabilities, and explains the no-tools case.
  The user confirmed that all tools were disabled in that conversation,
  and that `/tool enable sh` and `/tools` report the enabled/disabled states.
  Actual shell execution and the batteries workflow have not yet been
  reported from that session. The default sample disables every directory
  tool; the separate batteries configuration also registers its hook.
  The Gears release gate
  passes (`/tmp/gears-tool-inventory-prompt-host-gate.log`), as does the native
  release build (`/tmp/gears-tool-inventory-prompt-motor-build.log`). This is
  prompt hardening; the reported real-model response has not been retested.
- The user's resume trial found a blank screen. Sessions restored model
  context, but neither interactive UI displayed saved messages; the TUI also
  kept stale transcript text when changing sessions or branches. Saved
  active-branch history now loads on interactive startup and session/branch
  selection, preserving older visible messages across compaction. Displaying
  it neither runs tools nor changes model context. Full-screen history keeps
  the existing 1 MiB limit, including the end of an oversized reply; one-shot
  output does not replay history. The original regressions are preserved in
  `/tmp/gears-resume-blank-original.log` and
  `/tmp/gears-resume-line-valid-original.log`. The complete Gears host gate
  passes (`/tmp/gears-resume-validated-host-gate.log`), as do host/Motor Clippy
  with warnings denied, formatting and the native release build. New screen
  and real-binary CLI regressions run transitively in `full-test.sh` through
  the Gears gate. A visual retry on the user's updated VM remains pending.

## Validation boundaries

Each Gears code patch passes `test-gears-http.sh`, formatting and Clippy.
The latest ownership and lock patches also pass Motor-target Clippy, a
native release build and the focused VM regressions. Their portable smoke
tests are included transitively in `full-test.sh` and the installed native
shipped-tools gate.

The release developer-image gate passed after phase 3 packaging
(`0d4a98c2`), with Gears code through `c0266402`. Its log is
`/tmp/gears-phase3-dev-release-compatible.log`. Later phase 4 code is not
covered by that earlier image result. The phase 5.1 release developer-image
gate now passes with Gears through `b0e8eaeb` and the initial batteries
protocol skeleton, including both installed component tests and native
source builds. Its log is `/tmp/gears-batteries-scaffold-dev-release.log`.
That image result does not cover later batteries features.

Phase 5 patches pass the batteries host gate, formatting, and host/Motor
Clippy with warnings denied. The complete workflow passes the focused native
gate (`/tmp/gears-batteries-workflow-native-gate.log`). The installed opt-in
configuration also passes a native startup check, with no model request
(`/tmp/gears-batteries-installed-config-fixed-native-gate.log`). The updated
`full-test-dev.sh --release` gate passes, including installed Gears and
batteries workflows, native HTTP regressions, packaged-source builds with
Lorry, and Lorry's complete product suite (649 seconds). Its log is
`/tmp/gears-batteries-coding-dev-release.log`. The native workflow is included
transitively in `full-test.sh` when testing the developer image. The gate
covers all production changes and the fixture fix. The final setup and
progress documentation was updated afterward.

The corrected release developer-image gate also passes without Codex's
tool directory on PATH, after provisioning the batteries' host `rg` in
the test preparation and component gate. Its log is
`/tmp/gears-batteries-host-rg-dev-release.log`. This supersedes the earlier
host-dependency assumption; the original missing-`rg` failure is preserved
above.

The atomic lock-publication race remains recorded separately in
`docs/plans/future-work.md`, as requested. Do not hide diagnostic failures
with retries, longer timeouts or weaker assertions.

Phase 6.1–6.4 patches pass the batteries host component gate, formatting and
host/Motor Clippy with warnings denied. Real-binary regressions cover all
admission answers, unattended runs, stale entry approvals, decision pages,
workspace hashes, and running/resumed prompt behavior. They run transitively
in `full-test.sh` through the existing batteries gate. The latest debug host
gate is `/tmp/gears-batteries-phase6-portable-gate.log`; final release evidence
is `/tmp/gears-batteries-phase6-release-gate.log`. The two sample event-list
changes also passed the Gears component gate.

The native release build passes
(`/tmp/gears-batteries-phase6-portable-motor-build.log`). The focused native
component gate passes with uploaded current binaries, including the extended
memory workflow and updated sibling-binary/config startup
(`/tmp/gears-batteries-phase6-native-gate-fixed.log`). The initial native
setup tried to upload into read-only `/devtools/bin` and failed before tests
(`/tmp/gears-batteries-phase6-native-gate.log`). The corrected harness uses
the gate's existing binary overrides in a user temporary directory. QEMU
snapshot mode keeps the base image unchanged. These results do not claim a
rebuilt developer-image or full developer-image gate for phase 6.

## Skills through phase 6.5

The user authorized `yaml_serde` if Agent Skills permits optional fields.
The [standard](https://agentskills.io/specification) does: license,
compatibility, string-valued metadata and experimental allowed-tools.
`yaml_serde` 0.10.7 with `libyaml-rs` 0.3.0 parses frontmatter while preserving
original bytes. These are Rust dependencies with no C build step; optional
tool metadata grants no authority. No external dependency source was edited.

Skill proposals, exact SKILL.md plus NOTES.md approval, imports, configurable
limits, Motor platform filtering, frozen catalogs, loading and once-per-branch
correction/withdrawal notes are implemented. Pending review includes saved
source entries and sessions that loaded the exact old version. The portable
real-hook fixture covers proposal approval, a new session's catalog, notes
loading and correction, unapproved-version withdrawal, resume and check
observations. Those tests run transitively in the existing host and native
batteries gates.

All code patches passed the batteries host component gate and host/Motor
Clippy with warnings denied. The final debug gate is
`/tmp/gears-batteries-skills-observation-timing-gate.log`; the release host
gate passes in `/tmp/gears-batteries-skills-release-gate.log`.

Two batteries defects found during integration are fixed: state tools
(memory and skills) no longer mark passing workspace checks stale, and skill
observations are captured when the check result arrives instead of at turn
end, which could credit a later load. Original regressions are preserved in
`/tmp/gears-batteries-skills-check-stale-original.log` and
`/tmp/gears-batteries-skills-observation-timing-original.log`. A new symlink
unit assertion initially expected different diagnostic wording; the exact
checked-state diagnostic now passes. Its original failure remains in
`/tmp/gears-batteries-skills-store-gate.log`.

### Native release blocker: missing runtime strlen

The native release link fails with undefined `strlen` from libyaml-rs:
`/tmp/gears-batteries-skills-motor-build.log`. An independent 15-line Rust
program without YAML reproduces the issue: debug links, release fails when
LLVM replaces a byte-scanning loop with `strlen`. Rust core documents this
symbol as a runtime requirement; the runtime exports originally omitted it.
The sources and logs are `/tmp/gears-yaml-strlen-probe.rs`,
`/tmp/gears-yaml-strlen-probe-debug.log` and
`/tmp/gears-yaml-strlen-probe-release.log`.

A temporary probe with the missing Rust export links in release, and its
assembly contains a loop with no recursive strlen call. Logs:
`/tmp/gears-yaml-strlen-probe-with-runtime-symbol.log` and
`/tmp/gears-yaml-strlen-probe-with-runtime-symbol-assembly.log`.
A proposed weak moto-rt export and system regression were prepared in
`/tmp/gears-yaml-strlen-moto-rt.patch`. The user approved the runtime change;
the implementation and native regression are complete, and the final patch
passed the full core gate three times each in debug and release. See
[the runtime fix record](gears-yaml-runtime.md).
Systest explicitly enables the in-tree runtime's libc feature to test the
new export. Formatting, runtime and focused systest Clippy with warnings
denied, and the native release systest build pass. The release strlen
regression also passes in a native VM. The initial full debug gate failed
in a preexisting test isolation bug: a global channel baseline of six fell
to three while earlier connections finished cleanup. The unchanged exact
channel assertion now runs in systest's initial checks, after logging
verifies stats readiness and before networking fixtures. Original and
diagnostic failures are preserved in
`/tmp/gears-strlen-full-debug-1.log` and
`/tmp/gears-strlen-full-debug-diagnostic.log`; final gates use the
`/tmp/gears-strlen-full-*-ready.log` names. The first fresh-VM invocation
passed a complete debug gate but failed before stats registration in
release; the final placement uses the existing logging metric assertions
as its readiness prerequisite, without adding waits or retries. All six
final gates include passing channel and strlen regressions. The broader systest lint
invocation reported existing dependency lints, including a RefCell warning
despite an explicit drop before await; its original output is preserved in
`/tmp/gears-strlen-systest-clippy.log`.

The selected toolchain embeds published moto-rt 0.17.6, not the local tree.
Rebuilding it alone will not update that dependency. The user has since
published the fixed runtime as 0.17.7; the Rust library lock update and new
toolchain tuple remain follow-up work. No external source or installed
toolchain has changed. This corrects the
initial suggestion of simply rebuilding the embedded runtime.
The full release developer-image gate is not rerun while that link is known
to fail. Installed-build phase 6.5 validation remains incomplete.

### Native skills validation with the fixed runtime

A temporary archive of commit `8b55c381` selects the fixed runtime with its
`libc` feature enabled. Only the temporary manifests change: candidate
moto-rt version 0.17.7 and Gears' dependency selection. Both the batteries
workflow and Gears build in native release mode. The existing batteries VM
gate passes in a release developer-image snapshot with the uploaded current
binaries, including skill approval, loading, correction, withdrawal, resume
and check observations. Current sibling binaries also pass configuration
startup. Logs: `/tmp/gears-skills-local-runtime-build.log` and
`/tmp/gears-skills-local-runtime-native-gate.log`.

This establishes native skills behavior with the fixed runtime. It does not
claim that the installed SDK or packaged-source build has been updated. The
temporary dependency selection is diagnostic, not a shipping manifest edit.
The runtime release candidate packages and verifies offline; publication and
the external Rust fork/SDK rollout were requested separately for approval.
The user has since completed publication of 0.17.7, and the published
package's checksum and weak strlen export are verified.
See [the runtime record](gears-yaml-runtime.md) for the reviewable artifact.

## Sysbox step S1 and its core gates

S1 is complete in `41f5e494`. It adds parent creation, multiple operands,
option termination, literal paths, explicit unsupported-option errors and
the native systest, quoted wrapper and command notes. The regression runs
transitively in the full core suite.

The first combined Cargo build failed because systest enabled async-fs's
`std` feature, changing the metadata error type seen by sysbox. The normal
separate Makefile builds pass; the original invocation failure is preserved
in `/tmp/gears-mkdir-native-build.log`. The first native test exposed the new
command's empty-operand diagnostic gap: Motor reports InvalidFilename while
mkdir requires No such file or directory. The command now handles that
operand explicitly; its assertion is unchanged and the focused native gate
passes. Original and corrected logs are `/tmp/gears-mkdir-focused-native.log`
and `/tmp/gears-mkdir-focused-native-fixed.log`. Formatting and warnings-denied
Clippy pass for both changed packages. A temporary host probe agrees with the
installed uutils mkdir on creation behavior and exit statuses for 17 cases;
this is not a claim of testing against an installed GNU binary. Its log is
`/tmp/gears-mkdir-host-reference.log`.

The initial series passed three release and two debug full gates, including
mkdir. The third debug gate failed in `test_failed_tcp_setup_rolls_back_socket`:
the global live socket count fell from 14 to 13. The failure's socket listing
contains only SSH sockets and closed TIME-WAIT sockets whose owner has exited;
no socket belongs to the test process. A global count equality can fail when
unrelated sockets expire, and can also hide a new leak if another socket
expires simultaneously. The small test-only fix compares socket IDs and
checks for newly created sockets owned by the test while its connection is
still alive, retaining the exact creation-counter assertion. It adds no
waits, retries or production networking changes. The original failure is
preserved in `/tmp/gears-mkdir-full-debug-3.log`. A diagnostic build deliberately
omitted rollback; the corrected assertion caught its leaked socket by ID and
owner (`/tmp/gears-mkdir-tcp-negative-control-native.log`). Restoring rollback
passes the existing native cancellation suite
(`/tmp/gears-mkdir-tcp-isolation-native.log`). The first diagnostic attempt
started before the stats provider's documented one-second boot registration;
its startup failure remains in
`/tmp/gears-mkdir-tcp-negative-control-startup.log`. The diagnostic uses the
normal suite's existing startup tests, with their unchanged assertions, as
prerequisites. All temporary source changes are restored. The test-only
correction is committed separately in `1a75bb04`.

The final source passed `src/tests/full-test.sh` three times each in debug
and release before either code commit. Every run includes the mkdir and
failed-connect regressions, plus the Gears and batteries host component
gates. Logs use `/tmp/gears-mkdir-full-{debug,release}-{1,2,3}-isolated.log`.
Source hashes were checked afterward, including the unchanged production
rollback. Formatting, diff checks and warnings-denied Clippy pass.

| Profile | Testing duration for runs 1, 2, 3 |
| --- | --- |
| Debug | 22.6, 22.6, 22.7 minutes |
| Release | 10.5, 10.6, 10.6 minutes |

## Sysbox step S2: byte-order sort

Commit `399cf0a5` adds byte-order sorting with `-r -u -f -s -c -o`, raw-byte
order diagnostics, literal operands, and output opened only after reading
the inputs. Its native systest runs transitively in the full core suite.
Numeric/human comparison is the second patch below; field keys remain a
separate subsequent patch.
The focused native regression and warnings-denied Clippy pass. A temporary
host build agrees with GNU for 555 input, flag, file and output cases.

The initial full-gate preparation failed because the rust-analyzer smoke
fixture still locked local moto-rt 0.17.6 after its approved version bump.
The mechanical test-only lock refresh is committed in `e82159f7`, and the
existing release smoke gate passes without weakening `--locked` checks.
The original failure is `/tmp/gears-sort-full-release-1-isolated.log`;
the smoke gate is `/tmp/gears-sort-ra-fixture-gate.log`. The restarted six
full runs use `/tmp/gears-sort-full-{debug,release}-{1,2,3}-runtime-lock.log`.
All three release and the first two debug runs passed. The third debug run
failed at `kernel_log::file_mode_end_to_end` before sort ran; its original
log is `/tmp/gears-sort-full-debug-3-runtime-lock.log`. Targeted native
instrumentation showed that whole-file reads and byte scans consumed 45.6
of 47.7 seconds while the test emitted only 1.42 MiB. Rotation itself occurred
at the existing 4 MiB limit. Whether the old flood loop fills the file in
time therefore depends on its starting size and debug scan cost. The small
test-only correction in `9adb3ddf` retains the 60-second deadline and all
assertions, and emits several paced bursts between scans; each burst fits
in the ring. The corrected focused native test passes. Temporary diagnostics
are removed, and the final unchanged sources pass three debug and three
release full runs. Every run passes both the rotation and sort regressions.
The original failure and diagnostic log
(`/tmp/gears-kernel-rotation-diagnostic-run.log`) remain preserved.

Final full-gate logs:
`/tmp/gears-sort-full-{debug,release}-{1,2,3}-rotation-fixed.log`.

| Profile | Testing times |
| --- | --- |
| Debug | 22.1, 21.9, 21.7 minutes |
| Release | 11.0, 10.6, 10.6 minutes |

Field-key sort and `uniq` remain prepared only in temporary source trees.
Their host comparisons with GNU and native builds and Clippy pass; native
execution and each patch's full core gate remain before shipping.

The field work is split further to keep each shipping patch small: field/byte
ranges first, then per-key ordering flags. The first projection is
`/tmp/gears-sort-key-ranges.rs` (118 lines), with its combined command prototype
in `/tmp/gears-sort-key-ranges-prototype.rs`. It matches GNU sort 9.11 in 3,888
output/status/diagnostic comparisons (`/tmp/gears-sort-key-ranges-gnu.log`).
Its standalone driver initially lacked Cargo's package-version environment;
setting that build metadata fixes the harness. This projection has no native
or full core gate yet and changes no installed utility.

### Exact numeric and human sorting

`sort -n` compares decimal prefixes without floating-point rounding, including
long mantissas and numbers beyond 2^53. `-h` compares human-size suffix ranks
then exact mantissas. Both retain reverse, stable, unique, ASCII folding,
order checks and full-line tie breaking where appropriate. Conflicting modes
are refused before opening an output file.

The native systest covers signs, zero, junk prefixes, decimal ties, units,
300-digit numbers, flag combinations and preserving output on invalid options.
It passes in three debug and three release full core gates with the stock
`dev.3` SDK. Source hashes match across all six runs; the release developer
suite passes too. Warnings-denied native sysbox and systest Clippy pass.
The host driver agrees with GNU sort 9.7 in 2,112 output/status/diagnostic
comparisons (`/tmp/gears-sort-runtime-numeric-gnu.log`). Native golden cases
also pass in the host harness (`/tmp/gears-sort-runtime-numeric-fixture.log`).
Full logs use `/tmp/gears-sdk-runtime-full-{debug,release}-{1,2,3}.log`.

## Task acceptance decision

The user wants `/accept` as a clear signal rather than inferring acceptance
from natural language. Phase 7 is a small hook command that records this
signal in the saved session, replies "Task accepted." and leaves the
session open. It makes no model request and does not run or require a check.
A review may cite the saved signal; check receipts remain development
evidence and do not imply acceptance or a skill's usefulness.

The separate acceptance CLI, UI hint, acceptance file and repository
fingerprint proposal remain superseded. There is no Gix binary or library
decision to make for acceptance. `/accept` does not schedule a review;
optional reviews retain compaction and explicit `/review` triggers.
The command is implemented through the existing hook command and context
entry mechanisms. No new state file or session format is needed. Its saved
entry keeps the user's signal with the active branch's session history.
See [the acceptance decision](gears-acceptance-vcs.md).

### Phase 7 validation

The portable real-hook workflow verifies command registration, explicit
acceptance rather than natural-language inference, rejection of arguments,
saved entry ids, resume, branch isolation and repeated acceptance. Its
scripted provider sees only the ordinary conversation request; commands
make no further requests, preserve hook state and do not run the deliberately
failing workspace check. Debug and release batteries gates pass, as does
the Gears host gate. Host and Motor-target Clippy pass with warnings denied.
Logs: `/tmp/gears-accept-host-{debug,release}-final.log`,
`/tmp/gears-accept-gears-host-debug.log` and
`/tmp/gears-accept-clippy-{host,motor}-final.log`.

Native release builds and the existing batteries VM workflow pass using a
temporary source archive linked to the approved local runtime with `libc`
enabled. Uploaded sibling binaries and the updated sample config also pass
startup, `/help`, `/accept` and continuation through `/session`. The initial
extra CLI assertion wrongly treated the normal `gears:` notice prefix as
an error; the corrected assertion requires the exact sole success notice.
The original log is `/tmp/gears-accept-native-gate.log`; final logs are
`/tmp/gears-accept-native-build.log` and
`/tmp/gears-accept-native-gate-validated.log`. This component validation
was an early component check. The later stock-SDK installed workflow and
packaged-source developer-image gate now pass; no runtime override is needed.

### Acceptance upgrade compatibility

The first `/accept` implementation registered a command even when an older
configuration did not subscribe to `command`, making Gears reject the entire
hook at startup. `89d14ee7` fixes this defect: initialization reports the
configured subscriptions, and batteries register `/accept` only when allowed.
Older configurations keep their other tools and receive an enabling notice;
older Gears senders receive an upgrade notice. Startup and resume, unrestricted
subscriptions, saved acceptance and preserved tool requests pass in the real
portable workflow on Linux and Motor OS. Unit, integration and warnings-denied
Clippy gates pass. Original failure:
`/tmp/gears-accept-subscriptions-original.log`; native validation:
`/tmp/gears-accept-subscriptions-native-gate.log`.

### Review settings groundwork

Phase 8's user-wide `[reviews]` parser is implemented. Reviews default to
off with a proposal cap of four. Enabling requires named executor and
reviewer provider/model pairs; eligibility matches the executor pair exactly.
Invalid versions, misspelled fields, zero caps and invalid names are refused.
Marks, saved-entry snapshots, tool policy and triggers are implemented below;
the runner and proposal cap remain later phase 8 patches.

The host debug and release batteries gates pass, including the real-binary
workflow. Host and Motor-target Clippy pass with warnings denied. The actual
batteries release binary now links against the validated `dev.3` SDK's stock
standard library, without the temporary runtime-feature override. Logs are
`/tmp/gears-review-config-{host-debug,host-release,host-clippy,native-clippy,native-build}.log`.
The SDK's host/native tools, images, tracked selector and full cutover gates
now pass, including installed workflow execution.

### Durable review marks

Review marks now persist by session, saved entry, trigger, focus and executor
pair. Duplicate triggers retain completion or dismissal; interrupted runs
leave a mark due. New sessions cannot consume another session's marks.
Damaged, oversized or changed records are refused without overwriting them.
The portable workflow tests these rules in both host profiles; host and
Motor-target Clippy and the native release build pass. Native execution is
included in the passing release developer-image gate. Triggers are now
implemented below; this storage API itself does not start reviews.

### Reviews at saved entries

`Snapshot::at` reads the branch ending at a mark's exact entry. Later turns,
compaction and prompt refreshes cannot change that view; an unfinished tool
round is refused. An ephemeral fork retains the original prompt snapshot
while the parent remains writable and unchanged. The Gears debug host gate,
both batteries workflow profiles, host and Motor-target warnings-denied
Clippy and native release workflow build pass. Logs use
`/tmp/gears-review-anchors-*`; installed native execution passes in the
release developer-image gate.

### Review tool policy

Review runs may use memory and skill proposals, session reading and declared
read-only tools. Shell, check, task-state and file-writing calls are denied,
including before check preparation. Ordinary runs retain their authority.
The portable fixture passes both host profiles, warnings-denied host and
Motor-target Clippy, and the native release build. The initial fixture omitted
the path in its ordinary writer case; correcting that input preserves every
assertion. Its original failure is
`/tmp/gears-review-policy-host-debug-original.log`; final logs use
`/tmp/gears-review-policy-*`. The runner and proposal cap remain later patches.

### Review triggers

`/review [focus]` and the subscribed `before_compact` event now record a
durable mark at the current saved entry. Reviews stay off by default and
require the configured executor pair to match the session. Repeated commands
retain handled marks; review runs cannot schedule reviews. Ephemeral sessions
cannot create persistent marks. Recording a mark leaves the conversation
unchanged and makes no provider request; the runner remains a later patch.

Both host batteries profiles, host and Motor-target warnings-denied Clippy,
and the native release build pass. The portable trigger fixture is included
in the existing workflow and passing release developer-image gate. Logs use
`/tmp/gears-review-triggers-*`.

### Review settings in status

`gears-batteries status` now reports the requested model pair, enabled flag
and proposal limit under `review_settings`, while `reviews` still explicitly
says execution is not implemented. Invalid configuration is reported beside
the unaffected pending-change counts. Both host profiles, warnings-denied
host/Motor Clippy and the native release build pass. The first new CLI test
used a plain write into a nonexistent state directory; using the existing
atomic state writer fixes that setup without changing assertions. The
original log is `/tmp/gears-review-status-host-debug-original.log`; final
logs use `/tmp/gears-review-status-*`.

### Developer source-build diagnosis

The stock `dev.3` SDK passes three debug and three release main-image gates,
and the release developer-image repository suite and installed batteries
workflow pass. Its source-build phase then fails before compiling batteries:
Lorry rejects `lib.doc-scrape-examples = false` in `libyaml-rs 0.3.0`.
The original failure remains in `/tmp/gears-sdk-runtime-full-dev-release.log`.
This documentation setting has no build effect. Lorry's local instructions
put discovered Lorry issues in scope; the narrow compatibility patch accepts
only false, with metadata and native identity regression coverage. The focused
contract, complete Lorry suite, warnings-denied host/Motor Clippy and corrected
release developer-image gate pass. The successful rerun is
`/tmp/gears-sdk-runtime-full-dev-release-fixed.log`; the original remains
preserved. Core/SDK hashes match the six successful main-image runs. Both the
runtime link gap and source-vendoring blocker are resolved.

### Unfinished reviews on resume

Startup and `/resume` ask whether to run or dismiss this session's unfinished
marks through the existing hook-question flow. An unanswered or unattended
question keeps them paused. Accepting preserves due marks for the future runner;
dismissal changes only the displayed marks to dropped. Initialization of a new
or cloned session clears inherited question state without touching other
sessions' marks. Workspace-memory admission precedes the review question.

The real-hook fixture exercises cancellation, acceptance, bounded dismissal,
new-session isolation and repeated resume without making a provider request or
running a check. Host debug/release, warnings-denied host/Motor Clippy, native
release build and the release native VM component gate pass. It runs through the
existing workflow included in full-test.sh. The original fixture failure is
preserved in `/tmp/gears-review-resume-host-debug-original.log`: an empty file
lacked the required memory header. Encoding a valid empty Document fixes setup;
the two-question assertion is unchanged. Final logs use
`/tmp/gears-review-resume-*`, with `host-debug-fixed` for the corrected gate.

### Saved-entry CLI forks

`gears --fork SESSION --fork-entry ENTRY --ephemeral` reads the branch ending
at the marked entry even after the parent compacts or continues. This exposes
the existing snapshot API to the future background runner. Unknown entries,
invalid option combinations and duplicate selectors are refused.

Host debug/release provider gates, warnings-denied host/Motor Clippy and the
native release build pass. The real CLI fixture passes on Linux and Motor OS:
it displays the original conversation after compaction, makes no provider
request and leaves the parent unchanged and writable. It runs through the
existing shipped-tools fixture in full-test.sh. The debug gate was supplemented
with the newly added exact CLI test; the release gate includes it. Logs use
`/tmp/gears-fork-entry-*` (`host-cli-fixture-exact` is the targeted debug run).

### Durable review proposal limits and citations

Review proposals carry an optional review-mark hash alongside their parent
session and saved entry ids. Old source records still parse and serialize
unchanged. Review tools cite the marked parent entry and check any additional
citations against that historical branch, instead of citing an unsaved child
calling entry. A handled mark or disabled executor pair cannot propose.

Memory and skills share `max_proposals`. Counting existing pending files and
complete decision records preserves the limit after interruption, denial or
approval; no counter or recovery journal is added. Ordinary proposals and
other marks keep separate budgets. All review output remains pending.

The portable workflow covers both proposal types, refusal over the cap,
decisions followed by a restarted child, another mark, historical citation
bounds, parent immutability and backwards-compatible source JSON. Host
debug/release, warnings-denied host/Motor Clippy, native release build and
release native VM component gates pass. Existing workflow drivers include
these regressions in full-test.sh. Logs use `/tmp/gears-review-proposals-*`;
the first successful debug run is `host-debug-original.log`.

## SDK rollout and next steps

### Saved stable request prefixes

Actual agent requests save system fragments and tool schemas independently of
history, once per change. Compaction leaves that record available; historical
forks select the prefix at their exact saved entry. Old sessions return no
snapshot, and malformed records fail explicitly. OpenRouter's routing key now
uses the stable system/tool prefix rather than the first conversation message.

The portable shipped-tools fixture checks automatic compaction, exact marked
entries, changed prefixes, deduplication and malformed records. Host debug and
release HTTP gates, warnings-denied host/native Clippy, the native release
build and the release snapshot VM's shipped-tools gate pass. Logs use
`/tmp/gears-stable-prefix-*`; the first host-gate attempt was blocked by the
filesystem sandbox before testing curl, and the authorized gate passes in
`host-debug-authorized.log`. Reusing the prefix in the review child follows.

Ephemeral forks now accept `--preserve-prefix`. The runtime uses the saved
system fragments and advertised tool schemas through history compaction and
counts that prefix when checking the input limit. An oversized prefix fails
before a provider call; new sessions clear the override. Execution continues
through current tools and permission hooks. Missing legacy snapshots produce
an explicit notice and use reconstructed instructions.

The portable fixture covers a compacted review, unchanged parent bytes,
oversized-prefix refusal and new-session isolation. The actual fork CLI also
exercises the legacy fallback. Host debug/release HTTP gates, warnings-denied
host/native Clippy, native release build and the release snapshot VM shipped
gate pass. Logs use `/tmp/gears-preserved-prefix-*`. The initial fixture build
after changing Capture's shape left one old field access; `focused-final.log`
preserves that compile failure and `focused-fixed.log` contains the corrected
test with unchanged behavioral assertions.

### Role metadata before hook initialization

Ephemeral one-shot forks accept bounded `--hook-state NAME=JSON` overlays.
They retain unrelated inherited fields and apply the selected fields before
the first hook initialization. Unknown hooks and invalid, duplicate or
oversized inputs are refused. The parent is never modified.

The real CLI fixture verifies the first initialization event, retained source
state, unknown-hook refusal without another model request, and parent bytes.
Host debug/release HTTP gates, warnings-denied host/native Clippy, the native
release build and release snapshot VM shipped gate pass. Logs use
`/tmp/gears-fork-hook-state-*`. Original fixture setup failures (a short-lived
test string, a sandbox-denied loopback listener and redundant JSON formatting)
are retained; final focused logs end in `fixed`/`authorized`, and final host
Clippy uses `host-clippy-fixed.log`. This supplies review authority metadata;
the batteries runner has not yet been connected.

### Review launch preparation

The runner can prepare a literal ephemeral saved-entry fork with the preserved
prefix and review role installed before hooks initialize. Disabled, handled,
paused and review-role marks do not launch. Foreign sources, inconsistent
executor metadata, missing reviewers and incomplete policy subscriptions fail
before a provider request. Historical marks retain their original executor even
when the parent later changes models.

The portable fixture covers these checks, custom hook names, literal paths,
configured limits and unchanged parent bytes. Both host batteries profiles,
warnings-denied host/native Clippy, the native release build and the release
snapshot VM workflow pass. Logs use `/tmp/gears-review-launch-*`. Execution and
review instructions are the next patches; this preparation API starts no child.

### Review instructions and evidence

The compiled review instructions default to "Nothing to save", require saved
citations and successful execution evidence for procedures, and distinguish
acceptance, check results and co-occurrence from causal claims. User focus,
current denials and mechanical records follow the preserved prefix. Completed
turns after the mark are excluded; an in-progress turn is labeled partial.
Quoted evidence cannot close its provenance marker. Evidence over 64 KiB is
refused explicitly, leaving the mark due rather than omitting user denials.

Both host batteries profiles, warnings-denied host/native Clippy, the native
release build and release snapshot VM workflow pass. The portable fixture
covers denial delivery, later-turn exclusion, source quoting, partial evidence,
unchanged parent bytes and oversized refusal. Logs use
`/tmp/gears-review-instructions-*`. Runner execution is next.

### Owned review execution and completion

The review library runs due marks under the shared owned process runner.
Cancellation, failed exits and incomplete or invalid final JSONL leave a mark
due. A successful final record completes it once, then atomically records the
answer and reported usage; an unavailable cost remains unknown. Failure to
update the latest-result display cannot resurrect a completed mark.

Both host profiles, warnings-denied host/native Clippy, the native release
build and release snapshot VM workflow pass. Final logs use
`/tmp/gears-review-runner-elf-*`. Original setup failures remain in the earlier
`gears-review-runner-*` logs: a fixture closure lifetime, a missing driver call,
and a native script without execute permission. The corrected fixture copies
a compiled child, preserving its permissions. CLI and sample wiring are next.

### Connected real-binary reviews

The companion `review` command uses Gears' after-turn environment and a sibling
Gears executable. The sample now starts it after foreground turns and hook
commands; review settings remain disabled by default. The component gate builds
both actual binaries and passes Gears to the portable workflow. Native packaging
reuses its existing workflow executable and installed Gears binary.

The loopback fixture forces history compaction, then verifies the exact saved
system prefix, reviewer model, absence of later parent turns, unchanged parent
bytes, no new pending proposals and no model call for a handled mark. Both host
batteries and Gears profiles, warnings-denied batteries host/native Clippy,
the native release build and release snapshot VM workflow pass. Logs use
`/tmp/gears-review-cli-*`; no external provider is contacted.

### Latest review status

`status` marks review execution experimental and reports the latest completed
mark, model pair, bounded answer and provider-reported usage. Missing data is
null; damaged, unsupported or oversized optional data is reported independently
without hiding pending changes or modifying the file. Unknown cost stays null.

Both host profiles, warnings-denied host/native Clippy, the native release build
and release snapshot VM workflow pass. Logs use `/tmp/gears-review-status-*`;
the corrected debug gate is `host-debug-fixed.log`. The original debug log
preserves two CLI assertions for the old unimplemented placeholder; they now
assert the experimental value. The portable fixture covers optional-record
failure isolation and unchanged damaged bytes.

### Real review interruption and session isolation

The actual companion/Gears pair now has a loopback regression that starts a
separate saved session without consuming the parent's mark, interrupts a review
after its model request starts, and completes the remaining due mark on a later
invocation. Further invocations make no request. Parent bytes, pending counts
and the previous completed result survive cancellation. Completed review usage
includes the auxiliary summary request.

Both host profiles, warnings-denied host/native Clippy, the native release build
and release snapshot VM workflow pass. Logs use `/tmp/gears-review-interruption-*`.
The subsequent invocation is an explicit part of the interruption scenario;
there is no automatic retry or timeout change. Cleanup still needs the requested
cutoff guidance; evaluation still needs question 7's quality/cost criterion.

### Visible review diagnostics

A reproduced legacy-session review succeeded while hiding Gears' explicit
missing-prefix fallback notice. The companion now displays bounded child stderr
and JSONL notices and retains them in the completed result. UTF-8 diagnostics
are capped with an explicit truncation marker. The real legacy-fork fixture
verifies that the fallback notice reaches the user and parent bytes stay intact.

Both host profiles, warnings-denied host/native Clippy, the native release build
and release snapshot VM workflow pass. Logs use `/tmp/gears-review-diagnostics-*`.
`original.log` preserves the successful-but-silent child result that failed the
notice assertion; the fixed and final debug gates preserve that assertion.

### Reviewer attribution stays with the launched model

A regression changes reviewer settings while the owned child is running. The
completed result previously attributed its usage and answer to the new setting.
The launch now retains its selected reviewer and passes it to completion, so
status records the model actually launched.

Both host profiles, warnings-denied host/native Clippy, the native release build
and release snapshot VM workflow pass. Logs use `/tmp/gears-review-attribution-*`.
`original.log` preserves the wrong-model assertion failure; the fixed host and
native gates retain the settings-change regression.

### Corrections after a frozen prefix

A focused resume-before-review regression reproduced lost withdrawal baselines:
normal initialization had already removed memory and skills from current hook
snapshots while the last actual prefix still contained them. Batteries now
restores only historical prompt and skill references from `prefix_state`,
retaining current permissions and review metadata. An absent historical hook
starts with empty resource snapshots; current project instructions are delivered
as context instead of being mistaken for part of the saved prefix.

Both batteries host profiles, warnings-denied host/native Clippy, the native
release build and release snapshot VM workflow pass. Logs use
`/tmp/gears-prefix-resources-*`; `original.log` preserves the lost-baseline
assertion failure. The portable regression covers resume before preservation,
simultaneous withdrawals and compaction; the actual CLI covers adding batteries
after the last saved request while retaining exact prefix bytes.
The complete `src/tests/full-test-dev.sh --release` gate also passes, including
installed Gears/batteries, native packaged-source builds and the bounded Lorry
suite; its log is `full-dev.log`. The build-generated updates to unrelated
lockfiles are restored; the user's existing `src/sys/Cargo.lock`
change is retained.

Each actual request now records a small hook-state checkpoint, including when
prefix bytes are unchanged. Preserved forks receive only their own hook's
historical state alongside current state. The session regression checks changed
resources, selected entries, compaction and unchanged parent bytes; the real
CLI checks historical resources without losing its current review-role overlay
or exposing another hook's state. Legacy checkpoints fall back explicitly to
the prefix's creation snapshot.

Both host Gears HTTP profiles, warnings-denied host/native Clippy, the native
release build and release snapshot VM shipped-tool workflow pass. Logs use
`/tmp/gears-prefix-checkpoints-*`. An initial standalone example-test command
lacked Cargo's integration-test executable variable; the regular component
gate runs these fixtures through `tests/shipped_tools.rs` and passes.

Batteries hooks recognize `preserve_prefix` during initialization. They retain
the historical prompt and skill snapshots, deliver withdrawals through current
context, and reset correction views after compaction so removed notes are sent
again. Changed project instructions follow the shared prefix as current context.
The existing context merger retains simultaneous memory and skill corrections.

The portable workflow covers withdrawn memory and skills, changed project
instructions, stable prompt fragments, repeated context and compaction. Both
host batteries profiles, warnings-denied host/native Clippy, native release
build and the release snapshot VM workflow pass. Logs use
`/tmp/gears-prefix-corrections-batteries-*` and the combined
`native-gate.log`. An earlier direct workflow invocation used a relative binary
path, which cannot resolve from the fixture workspace; the component script's
absolute paths fix setup. The initial unused-mut warning is removed. The Gears
initialization patch supplies this flag before the first hook call.

Gears now installs a preserved prefix before initialization, rather than after
hooks have rebuilt their snapshots. The initialization payload includes
`preserve_prefix: true` at startup and compaction; ordinary sessions retain the
previous payload shape. The runtime checks ephemeral use and prefix capacity
before initializing any hook. The real CLI fixture verifies the first hook's
flag and the exact system text sent to the mock provider.

Host debug/release HTTP gates, warnings-denied host/native Clippy, native
release build and the combined release snapshot VM's Gears/batteries gates
pass. Logs use `/tmp/gears-prefix-corrections-gears-*` and `native-gate.log`.
The original debug failure is preserved: an ordinary-hook contract rejected
the extra false field. Omitting that field fixes compatibility without changing
its assertion; the corrected debug log is `host-debug-fixed.log`.

The user published moto-rt 0.17.7 and pushed the authorized external Rust-fork
commit `f046f257239`. It changes only std's runtime version and checksum;
compiler, LLVM and std implementation sources are unchanged. The managed
`dev.3` producer, host/native SDKs, add-on tools and all three release images
pass. The repository selects the new SDK, whose weak `strlen` links both the
original optimized NUL-scan reproducer and the actual batteries release binary
without a runtime-feature override.

Three debug and three release main-image gates pass with frozen core/SDK
sources, followed by `src/tests/full-test-dev.sh --release`. Installed skills,
explicit acceptance, review prerequisites and native packaged-source builds
pass. See [the rollout record](gears-yaml-runtime.md#rollout-sequence) for the
exact SDK name and logs. The earlier failures remain preserved in that record.

The independent sysbox track continues with field keys and S3–S6 after the
numeric/human patch. Phase 8 continues with cleanup proposals. Cleanup will
require a cutoff when invoked, without setting an automatic retention period.
Phase 9 requires
the user's quality/cost criterion in question 7; keep reviews disabled until
an explicit model-pair decision and real-model evidence justify enabling them.

The user approved keeping the stable prefix separately from compactable history;
see [review context and cache reuse](gears-review-context.md). A saved-entry fork
can compact oversized history without discarding the marked parent's instructions.
The auxiliary summary request is separate from the actual review request.

The optional Hermes import has not been performed. Automated mock tests
establish behavior, not real-model usefulness. Keep the outstanding native
interactive checklist visible; do not mark it complete from component tests
alone.

Cleanup foundations now record successful skill loads independently of saved
sessions, including ephemeral runs. Approved removals retain exact SKILL.md
and NOTES.md bytes in `batteries/archived-skills/`; the pending display names
that archive. Postponement, denial and stale approval leave live files intact.
The portable workflow checks these cases on both platforms. Host debug/release,
warnings-denied host/native Clippy, native release build and the release snapshot
VM component gate pass; logs use `/tmp/gears-cleanup-retention-*`.

Cleanup candidate analysis retains only locally approved current versions.
Agent ownership comes from an approved proposal; manual admission supersedes
it even for identical bytes, and an unapproved edit is excluded. Literal
overlap hints compare the `When it applies` sections after case/whitespace
normalization without claiming semantic equivalence. Cutoffs parse explicit
calendar dates at midnight UTC, with leap-year validation. Portable fixtures,
both host profiles, warnings-denied host/native Clippy, native release build
and release snapshot VM pass; logs use `/tmp/gears-cleanup-candidates-*`.

Cleanup usage scanning reads saved skill-view results across all branches and
the separate ephemeral-load journal. It reports malformed or incomplete history,
without repairing a file or taking its writer lock, and requires source entries
to be available before an archival proposal can cite them. Session sizes, count
and total entries are bounded. Portable fixtures, both host profiles,
warnings-denied host/native Clippy, native release build and release snapshot VM
pass; logs use `/tmp/gears-cleanup-usage-*`.

Cleanup now stages archival proposals with their explicit cutoff, observation
dates, inspected session count and history limitations. Recent loads or loaded
snapshots, unavailable origin evidence, incomplete history and prior denials
protect a version. Repeated proposals deduplicate; no live skill is changed.
Portable proposal fixtures, both host profiles, warnings-denied host/native
Clippy, native release build and release snapshot VM pass; logs use
`/tmp/gears-cleanup-proposals-*`.

`cleanup --since YYYY-MM-DD` now exposes the complete flow. A real-process
fixture rejects missing, invalid, repeated and future cutoffs, inspects the
pending cutoff and origin evidence, and separately approves archival while
checking exact preserved bytes. No live file changes during cleanup.

Canonical-layout coverage exposed a Gears batteries bug: history discovery
skipped the real `<gears-dir>/sessions/` container. The unchanged assertion
failed with zero rather than one archival candidate. Discovery now handles
that container and the existing direct layout; usage and CLI fixtures use the
canonical layout. Failures remain in `/tmp/gears-cleanup-canonical-original.log`
and the pre-fix `gears-cleanup-cli-host-release.log`. Both fixed host profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; logs use `/tmp/gears-cleanup-cli-*`. Measurement infrastructure is next;
the quality/cost criterion is required before its first real-model run.

Phase 9's state-directory foundation shares the root used by configuration,
provider choice, tool/permission settings, locks and sessions. The internal
`GEARS_DIRECTORY` override is inherited by child processes; explicit selection
does not fall back to legacy configuration elsewhere. The actual-process
fixture checks selected defaults, malformed selected tool settings, startup
cleanup, saved sessions and invalid roots against a loopback mock.
Both host Gears profiles, warnings-denied host/native Clippy, native release
build and the release snapshot VM shipped-tool gate pass; logs use
`/tmp/gears-eval-directory-*`. The CLI flag and batteries root connection follow.

`--gears-dir DIR` now selects an absolute inherited directory before startup.
It requires explicit configuration and a fresh ephemeral prompt, rejecting
resume/fork and incomplete invocations before creating state. A nested Gears
switching directories acquires its own lock; same-root descendants keep the
existing ownership checks. The real-process fixture exercises both nested
directories and an untouched inherited directory on Linux and Motor OS.
Both host profiles, warnings-denied host/native Clippy, native release build
and release snapshot VM pass; logs use `/tmp/gears-eval-directory-cli-*`.
The initial compilation and misplaced-validation failures are preserved in
`host-debug.log` and `host-debug-fixed.log`; final validation keeps the failing
assertions and adds a real-process check before directory creation.

Batteries now uses Gears' shared directory API. A real hook/CLI fixture selects
another directory over the inherited root, verifies the selected user guideline
in the actual provider request, and checks snapshots, turn journals and pending
items stay in the copy. The inherited guideline remains unchanged. Both host
batteries profiles, warnings-denied host/native Clippy, native release build and
release snapshot VM pass; logs use `/tmp/gears-eval-directory-batteries-*`.

Evaluation task inputs now validate a versioned workspace source, prompt,
explicit copy exclusions and literal check/acceptance/regression commands.
Relative workspace paths resolve beside the task file; exact task bytes have
an identity for later reports. Criteria remain separate from model prompts.
Portable fixtures cover strict parsing, relative sources, changed byte hashes,
traversal, symlinks and size limits. Both host batteries profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; logs use `/tmp/gears-eval-tasks-*`.

Workspace copying creates separate fresh destinations with bounded traversal,
literal exclusions, ordered content identities and preserved executable access.
Portable fixtures execute a copied compiled program, compare independent copies,
check writes leave source/other-arm bytes intact, and reject existing/nested or
linked destinations. Batteries adds a native-only dependency on the existing
moto-rt permission API; no runtime, SDK or external-fork code changed.
Both host profiles, warnings-denied host/native Clippy, native release build and
release snapshot VM pass; logs use `/tmp/gears-eval-copies-*`. Initial build
failures (fixture variable and missing native dependency) are preserved; fixed
host logs use the `fixed` suffix.

Evaluation state capture separates exact approved non-user entry proposals
from user entries and manual curation, retaining the latter in both arms.
Manual workspace admission supersedes agent provenance; approved current skill
provenance uses the cleanup analysis. Capture rejects incomplete history and
unapproved workspace memory, freezes selected versions and disables reviews
only in captured settings. Portable fixtures, both host profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; logs use `/tmp/gears-eval-state-capture-*`.

Frozen state installs into separate workspace copies and fresh state directories.
Both arms retain user memory, manual curation and curated skills; only the
learning arm adds exact approved agent versions. Minimal admission records make
workspace memory and skills usable without importing source conversations,
pending proposals, old snapshots or review artifacts. Version manifests identify
selected entries, skill contents and shared settings. Portable fixtures, both
host profiles, warnings-denied host/native Clippy, native release build and
release snapshot VM pass; logs use `/tmp/gears-eval-state-install-*`.

Fresh trial roots can grant narrowly scoped unattended authority to file tools,
todo, skill viewing and the exact declared check. Saved sessions, edits to
instructions/state, outside paths, shell/publishing tools, learning changes and
historical search are excluded. Changed check declarations fail while normal
check signatures/receipts remain intact. Task validation now also applies the
existing check declaration limits. Portable fixtures, both host profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; logs use `/tmp/gears-eval-policy-*`.

Evaluation configuration pinning resolves resource paths, copies permitted tool
definitions with identities, validates the direct batteries hook/subscriptions,
and removes after-turn work/live tracing from the copy. Source edits leave the
pinned configuration/tools unchanged. Portable fixtures, both host profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; final logs use `/tmp/gears-eval-config-*-component-guard.log` and
`gears-eval-config-native.log`. Initial TOML-iterator/needless-borrow failures
remain. A targeted assertion reproduced symbolic traversal followed by `..`;
raw components are now checked before reading. The unchanged assertion passes;
its original failure is `/tmp/gears-eval-config-symbolic-original.log`.

Trial preparation connects frozen inputs, configuration/tool pinning, separate
workspaces/state, manifests and scoped authority. Held-back task files and
runtime/VCS metadata are omitted from the source template; later source changes
and prior trial answers cannot enter subsequent file copies. Existing/nested
output and repeated trial destinations fail. Internal reserved exclusions do not
reduce the task format's 64 user exclusions. Portable fixtures, both host profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; logs use `/tmp/gears-eval-prepare-*`.

The owned evaluation actor runs real Gears with pinned configuration, selected
state, explicit provider/model/deadline and JSONL. It stores events outside the
workspace and records outcomes, tool failures, checks, elapsed time, truncation
and partial usage. Portable tests run real writes/checks in both arms, verify
actual requests include learning only in its arm, and preserve source files.
The initial host fixture had separate binary build directories; its tool failures
are retained in `gears-eval-actor-host-debug.log` and the original fixture artifact.
The corrected sibling layout keeps the tool-success assertions. Both host
profiles, warnings-denied host/native Clippy, native release build and release
snapshot VM pass; logs use `/tmp/gears-eval-actor-*`, fixed debug/native builds
and Clippy use `siblings`.

Acceptance and regression programs now run separately from the conversation as
literal vectors against each copied workspace. Original judge programs are
omitted from model copies; authors must also exclude their expected answers and
other judge dependencies. Portable fixtures exercise acceptance, rejection and
a missing program without shell expansion or provider-key inheritance. Both
host profiles, warnings-denied host/native Clippy, native release build and
release snapshot VM pass; logs use `/tmp/gears-eval-criteria-*`.

Descriptive reports now aggregate both arms without turning missing cost/time
into zero or treating equal observed rates as equivalence. Acceptance includes
independent regression protection. Source approval/denial counts and latest
review usage include explicit coverage limitations; total historical review
cost and human time are unknown. Portable fixtures, both host profiles,
warnings-denied host/native Clippy, native release build and release snapshot
VM pass; logs use `/tmp/gears-eval-report-*`.

Paired execution now connects starting-regression preflight, alternating repeated
arms, fresh copies, independent criteria and incremental reporting. Portable
fixtures run four real loopback actors, retain a deliberate acceptance failure,
verify actual learning-arm order and prove failed preflight/cancellation make
no additional model requests. Both host profiles, warnings-denied host/native
Clippy, native release build and release snapshot VM pass; logs use
`/tmp/gears-eval-suite-*`. The runner and shared actor fixture exceed 300 added
lines because their end-to-end assertions exercise the complete paired flow.

Executable pinning now copies the Gears/batteries pair into an owned sibling
layout, records hashes/lengths and preserves native execute access. The bounded
file copier is shared with workspace snapshots. Portable fixtures execute both
pinned binaries and reject an existing destination/non-file source. Both host
profiles, warnings-denied host/native Clippy, native release build and release
snapshot VM pass; logs use `/tmp/gears-eval-binary-*`.
