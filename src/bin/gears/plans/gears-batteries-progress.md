# Gears batteries implementation record

Updated 2026-10-05. The design in [gears-batteries.md](gears-batteries.md)
remains authoritative. Work proceeds in small patches with one-line commits.
All Gears defects found during implementation are in scope.

## Current position

The phase 0 companion documents and the phase 1–4 implementations are in
place. Phase 5.1–5.6 are implemented. The real-binary workflow passes on
Linux and Motor OS, and the updated release developer-image gate passes.
The user reports that native OpenRouter use works and has requested
continuation, clearing the phase 5 decision point. A local-model result has
not been reported. Phase 6.1–6.4 memory storage, admission, prompt handling
and user commands are implemented. Phase 6.5 skills is implemented and passes
the host gates and a native workflow linked to the fixed in-tree runtime.
Phase 7's explicit `/accept` command is implemented and passes the same
host and native component gates. Installed builds still need the SDK
rollout described below.
Sysbox step S1 is implemented and passes the focused native regression;
its final source passes three debug and three release full core gates.
Those gates exposed a preexisting TCP test isolation defect; its small
test-only correction is committed and validated. The first S2 patch is
committed in `399cf0a5`: byte-order `sort` with `-r -u -f -s -c -o`, literal
operands and a quoted executable wrapper. Its native regression and
warnings-denied Clippy pass, as do three debug and three release full core
runs after the diagnosed kernel-log test correction (`9adb3ddf`). Numeric,
human and field-key sorting, steps S3–S6 and phases 8–12 remain.

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
Numeric/human comparison and field keys are separate subsequent patches.
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

Numeric/human and field-key sort, plus `uniq`, are prepared only in temporary
source trees. Their host comparisons with GNU and native builds and Clippy
pass; native execution and each patch's full core gate remain before shipping.
No additional sysbox implementation is installed by those temporary builds.

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
does not update the installed SDK or replace the pending packaged-source
developer-image gate.

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

## Next steps

The independent sysbox track continues with numeric/human sort, then field
keys and S3–S6. The batteries track needs the SDK rollout below.

The user has published moto-rt 0.17.7; its registry checksum and weak strlen
export are verified in [the runtime record](gears-yaml-runtime.md#published-runtime-verification).
Select the fixed runtime in the SDK, then finish native skills validation.
The in-tree runtime gap is fixed and core-tested; rebuilding
the current SDK tuple alone will not update std's locked dependency.
The user explicitly authorized the Motor OS Rust fork update without the
Rust checkout's AGENTS.md gate. External commit `f046f257239` changes only
the runtime version and checksum; the published archive checksum and exact
parsed lockfile difference are verified. The Motor OS SDK declaration is
prepared as `dev.3`, and its offline runtime, managed-source, key, bootstrap
and version contracts pass. The installed SDK selector is unchanged.
GitHub push authentication is unavailable in this session, so the user has
been asked to push the completed fork commit before the managed SDK build.
See [the rollout record](gears-yaml-runtime.md#rollout-sequence).
Phase 7 is complete at the
component level. Phase 8 will discuss question 7; phase 9 requires the
user's criterion before evaluation.

The optional Hermes import has not been performed. Automated mock tests
establish behavior, not real-model usefulness. Keep the outstanding native
interactive checklist visible; do not mark it complete from component tests
alone.
