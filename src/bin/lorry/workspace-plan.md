# Lorry workspace support

Status: implementation in progress. This plan was updated after review on
2026-10-02 and revises the committed v3 (`3c90c8cf`).

The four first patches and milestone 1 are committed. The selected package's
library, binaries, test harnesses, integration tests, and check targets use
one unit planner and executor. Cargo build, test, and check unit graphs and
byte identity are covered. The complete Lorry suite passed in 556 seconds
on 2026-10-02, including native Motor self-build and identity checks.
Milestone 2 is complete. An artifact lock now serializes builds and clean
for one target directory, Cargo's target-directory precedence is supported,
unsupported build-setting environment variables fail explicitly, and selected
libraries use the verified local unit cache with dep-info. Selected-library
cache entries track external dep-info inputs, including edits and symlink
retargets. Compiler units publish into the final profile after validation,
and build scripts use a stable published `OUT_DIR`. Successful units survive
a later failure. Published compiler units reuse their validated artifacts in
place. Published unit directories and cache entries now record package
ownership. Unchanged ordinary build and run commands reuse a validated
completed profile without starting build scripts or compilers.
Completed-profile freshness records are scoped by package path so members
can coexist in the shared profile. Top-level executables also carry owner
sidecars. Members now use the shared profile, and `clean -p` removes only the
selected package's owned files and project-local cache entries. The old Lorry
artifact tree is reset under the artifact lock on first use.
An interrupted compiler-unit replacement restores its previous completed
directory before the next build tries to reuse it; after child-lifetime proof,
the next build discards that unit's abandoned staging.
On Linux, a lease passed only to compiler and build-script children keeps
subsequent Lorry commands from entering the artifact tree while a child
survives a killed parent.
On Motor, an owner-PID record and retained process-tree query make the next
command wait for interrupted children before touching artifacts. The native
probe kills Lorry during compilation, checks recovery after its child exits,
verifies a controlled live child holds the barrier, and checks abandoned
staging removal. The complete Lorry suite passed in 566 seconds on
2026-10-03, including online native vendoring and Motor self-build. An earlier
parallel Rust-test run intermittently failed to execute a just-published
workspace-member binary with `ETXTBSY`. A deterministic reproducer now shows
that a forked child inherits the writable staging descriptor and keeps the
published executable busy after the parent closes its descriptor. The owner
approved Cargo's policy, and Linux executable publication now stages an
atomic hard link, with a copy fallback when linking is unavailable. Motor
retains independent copies. The regression launches the executable while
the fork child is still held before exec. The full suite passed with 362
Rust tests and 10 intentionally ignored contract tests; the latter run in
their dedicated drivers. The Lorry-local `AGENTS.md` makes preexisting Lorry
issues part of this work.
The milestone-2 native measurements are recorded: cold `sysbox check` took
22.623 seconds, warm check 1.424 seconds, and resolved metadata 1.411 seconds.
They exposed and led to fixes for inert `lib.doc-scrape-examples` metadata
and sparse-index/manifest dependency-order mismatches. The final milestone
gate covers both fixes and executable publication.
Published check units retain and replay compiler messages, keeping
rust-analyzer flycheck diagnostics visible when those units are reused.

Milestone 3 is complete. Build, check, run, and
test share Cargo JSON reporting and approved format combinations. Run and
test finish the build stream before starting children; `test --no-run`
reports harness executables. Programs and harnesses receive Cargo package
metadata, run preserves its caller's directory, and global presentation
options work after command names. Offline commands now accept `--locked`,
`--offline`, and `--frozen`; metadata defaults to version 1 with Cargo's
warning. Compiler commands accept Cargo's positive, relative negative, and
`default` job counts, and build scripts receive the effective `NUM_JOBS`.
These patches passed focused CLI, metadata, workspace, and script contracts.
The owner approved `--lorry-messages`; its usage, failure, and interrupted
error records are emitted on stderr, separately from Cargo JSON stdout.
`test NAME` and the default/plain locate-project forms are implemented.
Published units and library-cache restores replay warnings, and completed
profiles replay Cargo events without starting compilers or build scripts.
Diagnostic paths are translated back to physical sources, and programs and
harnesses receive Cargo runtime library search paths. The paired Cargo
contracts cover cold and fresh build/check/test streams and failed builds.
They found and fixed the build-script artifact's `executable` field; Cargo
reports null there. Check comparisons explicitly account for the plan's
deferred metadata-only dependency checking. The complete Lorry suite passed
in 629 seconds on 2026-10-03: 371 Rust tests, 3 own-message integration
tests, the dedicated contracts, Cargo native/cross identity, and native
Motor self-build, cross/native identity, and child-recovery checks. Online
vendoring succeeded without retries. Strict Clippy validation also passed.
The first milestone run failed when a procedural macro printed plain text:
the newly shared reporter incorrectly parsed compiler stdout as JSON.
Diagnosis against the pinned Cargo source and an actual Cargo build showed
that stdout is forwarded without caching, while plain stderr is replayed.
Lorry now preserves compiler stdout's existing human presentation, forwards
it unchanged in JSON mode, and replays only stderr. The enhanced procedural
macro contract proves cold output and fresh stderr-only replay. The original
failure and diagnosis are retained in the milestone evidence below.

Milestone 4 is complete. Clippy manifest lints and sibling-driver
discovery are committed. The driver must embed the selected rustc, and its
content hash binds member compiler caches. `clippy` now uses the check path,
with separate outputs and incremental state. The paired Cargo contract covers
member dependencies and build scripts, external-package exclusion, fresh
warnings, `--no-deps`, and denied trailing lint arguments. Configuration
freshness also tracks parent-directory files and absent candidates. Cargo
comparisons prove edits, nearer-file creation/removal, and a relative
`CLIPPY_CONF_DIR` override. A metadata lint also matches Cargo and reaches
Lorry through `$CARGO`. The native driver compiled from the selected Rust
sources, passed compiler-identity and ELF validation, and is staged in the
new keyed assembly and release developer image. Its stripped size is
131,375,832 bytes, compared with rustc's 119,030,776 bytes. The full debug
gate passed with 0.9 minutes of preparation and 16.8 minutes of testing.
The full release gate passed with 0.6 minutes of preparation and 9.6 minutes
of testing. The release developer-image gate passed, including native Clippy
human and JSON diagnostics, metadata linting, and denied-lint own messages.
Its repository phase took 0.2 minutes of preparation and 12.8 minutes of
testing; the complete Lorry suite passed in 516 seconds with 377 Rust tests
and 3 own-message integration tests. Online vendoring needed no retries.
The first developer gate exposed an ordering assumption in the failed-build
contract. Diagnosis showed that Cargo stops before an independent warning
unit when the other binary fails first. The committed test fix puts that
warning in the failing binary's prerequisite and retains exact comparisons.

[workspace-plan-details.md](workspace-plan-details.md) is the reference. It
has the evidence, the contract of each milestone, the list of defects, the
policy choices, the decisions, and the reason for each revision.

Milestone 5 is complete. Builds and source metadata now share membership
discovery and default-member rules. Implicit path members receive Clippy
coverage. Focused Cargo contracts prove implicit membership, duplicate-name
rejection, exclusions, singleton defaults, and package-limit accounting.
The shared discovery also serves path/Git dependency inheritance. All 16
package fields inherit, with rebased file paths and Cargo's readme and publish
rules. Focused metadata comparisons and strict Clippy validation passed.
Workspace dependencies and all lint namespaces now inherit too. Cargo
configuration follows the invocation directory, while project policy belongs
at the workspace root. Parent manifest discovery, manifest paths on every
reading command, version/ID/pattern package selectors, ignored member settings,
unused profiles, custom metadata, and example/bench descriptions have focused
Cargo coverage. Compiler queries work at virtual and empty roots without
selecting a package. Metadata rejects package selectors and source metadata
always describes every member. The full milestone gate passed in 677 seconds
on 2026-10-04: 381 Rust tests, three own-message tests, all host contracts,
Cargo native/cross identity, and native Motor self-build, identity, and
child-recovery checks. Host and native online vendoring needed no retries.

Repeated package selectors, workspace exclusions, and shared Cargo feature
syntax are implemented, with explicit errors for execution or feature
resolution still assigned to later milestones. Editable member files use
Cargo package boundaries and participate in cache and completed-profile
freshness, including external reads and symlink retargets. The local corpus
scan matches all 128 source-metadata projections. Build-capable loading was
audited separately and reports the remaining target/dependency restrictions.

## Goal

Make Lorry build, check, and test Cargo workspaces on Linux and on Motor.

- Find the same members and select the same packages as the pinned Cargo
  1.99. This includes inheritance, `default-members`, repeated `-p`,
  `--workspace`, and `--exclude`.
- Resolve one shared lock. Compile the same packages with the same
  features as Cargo.
- Describe the whole workspace with exact Cargo metadata.
- Support members with build scripts, build-dependencies,
  dev-dependencies, procedural macros, examples, and benches. Support the
  crate types and profile settings that the acceptance projects need.
- Report Cargo's JSON messages. Name real files in diagnostics. Give
  programs the environment that Cargo gives them.
- Lint with `lorry clippy` the way `cargo clippy` does.
- Keep today's byte-identity guarantees, against Cargo and between Linux
  and Motor.
- Keep downloads explicit. Code that runs at build time stays subject to
  policy and admission.

A command or manifest feature that Lorry does not support must fail with a
clear message. An option must never be accepted and then ignored.

## Acceptance

The work is done when all of these pass:

- **Selection and features.** Lorry agrees with Cargo for virtual roots,
  roots that are also packages, commands run from a member, default
  members, repeated `-p`, `--exclude`, and resolvers 1, 2, and 3.
- **Build and test.** A fixture workspace has member build scripts, a
  procedural macro, dev-dependencies, examples, and a dev-dependency
  cycle. Building, checking, and testing several members agree with Cargo.
  So does the JSON output.
- **Admission.** An existing lock can be fetched, reviewed, and built. Its
  bytes do not change, and no Git branch moves. `vendor --locked --offline`
  repeats the review when the sources are present.
- **Artifacts.** Two commands at once, a member that fails, and a killed
  command all leave finished outputs intact.
- **Freshness.** Editing a file that a member includes from outside its
  directory rebuilds the units that read it, and their dependents.
  An unchanged `build` or `run` starts no build-script processes in cases
  covered by today's fast path, with input and policy validation intact.
- **Identity.** A small workspace fixture passes the Cargo byte-identity
  suite and the cross/native Motor identity suite.
- **Tools and agents.** An agent drives `build`, `test`, and `clippy`
  through JSON and Lorry's own messages. It parses no text from Lorry.
  What a test or a program prints stays plain text, as under Cargo.
- **Clippy.** `lorry clippy` agrees with `cargo clippy` on a fixture on
  Linux, and runs natively on Motor.
- **Real projects, on Motor.** sed builds and tests. ripgrep builds in
  release mode and runs `test --workspace --exclude grep-pcre2`. Helix
  builds with `-p helix-term --bin hx --release --no-default-features`.
  Each project's tool grants and settings are written down.
- **Editor, on Motor.** After `lorry fetch` in `src/sys`, Helix jumps
  between members and into dependencies. After admission, saving a `sysbox`
  file shows compiler diagnostics, and Helix finds the code that build
  scripts generate. Metadata and the build-script pass use consistent
  feature and target settings; the pass uses its configured target directory.

There is one earlier checkpoint. Two selected members share a library, and
`build --workspace` and `check --workspace` run through one unit graph. It
lands in milestone 7.

`src/sys` stays a member-by-member build. Even Cargo cannot check it as one
workspace for Motor. Its `kernel` and `rt` builds need features outside
this plan.

## Scope

Not included:

- Documentation tests, custom JSON targets, `build-std`, alternative
  registries, `[replace]`, and `package.workspace`.
- Selecting a dependency that is not a member with `-p`.
- Cargo commands that Lorry does not have: `doc`, `bench`, `install`,
  `publish`, `add`, `remove`, and `update`. Running Cargo aliases.
- Source changes in `src/sys`, the Helix or rust-analyzer forks, Rust's
  standard library, or moto-rt.

Separate work, which does not hold up this plan:

- `lorry fmt`, and `clippy --fix`.
- Inverse dependency trees, and a general option to override
  configuration. The option to raise the package limit for one run is the
  narrow `--max-packages N`.
- Speed work beyond what the milestones need.

Left for later: more JSON rendering modes, the `rustc-link-arg-*` forms for
one kind of target, per-package profile overrides, `cdylib` and `dylib` on
Linux, one test bundle for several members, and checking dependencies
without building them fully.

## Decisions

Decisions 1 to 14, 19, and 36 are in the details file, word for word. These
were added on 2026-10-02, after the review of v2:

- **Be more like Cargo.** Lorry accepts `CARGO_TARGET_DIR` and
  `build.target-dir`. It accepts an `[alias]` table and still runs no
  alias. It looks for `Cargo.toml` in parent directories. It uses one
  output layout for every selection. The spec changes with each of these.
- **Clippy and Lorry's own messages** are part of this plan again.
- **Order.** The milestones are in the order that is simplest to
  implement. The editor does not have to come first.
- **First patches.** Early fixes 7, 9, 11, and 15 land before milestone 1.
- **Fetch** downloads the complete lock by default. It is the simpler rule.
- **A fresh unit** in the target directory is reused where it is.
- **No size estimates and no risk list** in this plan.
- **Structured output is milestone 3.** This replaces the timing in
  decision 10, which placed it second. It comes after milestones 1 and 2
  because it builds on both, and before all workspace work.

## Milestones

Each milestone is a series of small patches, normally 100 to 300 lines with
their tests. Each patch updates the spec for the behavior it changes. The
single-package contracts keep passing throughout.

Milestones 1 and 2 come first, because everything else builds on them.
Each later feature is then written once.

| # | Milestone | Result |
|---|---|---|
| 1 | One unit graph | The selected package's own targets run on the same planner and executor as its dependencies |
| 2 | Per-unit publication | Each finished unit is published by itself and reused in place. One output layout, one lock |
| 3 | Structured output | Cargo's JSON for `build`, `test`, and `run`. Lorry's own messages. Cargo options that scripts expect |
| 4 | `lorry clippy` | Clippy lints on Linux and on Motor |
| 5 | Workspace model and selection | One reader for workspaces, inheritance, Cargo's configuration and selection rules |
| 6 | Shared resolution, metadata, and admission | One complete lock, exact metadata, explicit fetch, one admission record |
| 7 | Workspace builds | `build` and `check` across several members |
| 8 | Remaining targets and commands | Member build scripts, dev-dependencies, examples, benches, workspace tests, `run`, `clean` |
| 9 | Editor integration and native acceptance | Full rust-analyzer support, and the acceptance cases on Motor |

For milestone 2, build scripts use Cargo's stable `OUT_DIR` for the same
unit. A failed replacement may change files there; Lorry invalidates its
freshness before rerunning the script and never reuses a failed result.
Other completed units survive an unrelated failure.

### First patches

Four small fixes depend on nothing else. They land before milestone 1.

- **Fix 7.** Cap lints for Git dependencies, as for crates.io
  dependencies.
- **Fix 9.** Allow up to 1,024 described targets in a dependency. The
  limit of 64 blocks every graph that contains tokio.
- **Fix 11.** Reject the lint level `force-warn`. Today it makes Lorry
  panic.
- **Fix 15.** Leave three variables out of the cache key. Lorry removes
  them before it starts rustc, so they cannot change a build. Today they
  keep rust-analyzer's two kinds of check from sharing what they build.

### 1. One unit graph

- A unit is one compiler run or one build-script run. It names its
  package, target, mode, platform, features, and settings.
- Move the selected package's library, binaries, test harnesses, and check
  targets onto the existing planner and executor. Move one kind in each
  patch. Then delete the separate code that compiles the selected package.
- Compile a package inside the workspace root the way Cargo does: rustc
  runs in the workspace root and gets a relative path (early fix 5). Add a
  member to the Cargo byte-identity fixture.
- Nothing else changes for the user. The byte-identity suites and the
  existing contracts are the proof.

### 2. Per-unit publication

- Use one layout below `<target-dir>/lorry/` for every selection. The old
  per-member directories go away, with an explicit migration.
- Publish each finished unit by itself. Stop replacing the whole profile
  directory. Outputs of an earlier selection stay. So do the outputs of a
  command that fails later.
- Report a file only after it exists in its final place.
- Reuse a fresh unit where it is in the target directory. Do not copy it
  from the cache again. Preserve the existing unchanged-build shortcut
  for `build` and `run`, including its input and policy validation.
  Outside that shortcut, scripts run as today; general script-result
  caching remains optional.
- One lock for each target directory covers every change to its files.
  `clean` takes the same lock. Lorry releases it before it runs a program
  or a test.
- A killed command must not damage the next one. Lorry removes leftover
  files only when no process can still write to them. This is checked on
  Motor.
- A unit is fresh only if every file it really read is unchanged. That
  includes files outside its package.
- Accept `--target-dir`, `CARGO_TARGET_DIR`, and `build.target-dir`. Reject
  Cargo settings in the environment that change a build and that Lorry
  does not implement (early fix 14).
- `clean -p` removes only what belongs to that package.

### 3. Structured output

- `build`, `test`, and `run` accept `--message-format json`. One writer
  serves them and `check`.
- Diagnostics name real files. A unit that is not rebuilt prints its
  stored warnings again.
- `run` and `test` give the program the environment that Cargo gives it
  (early fix 6).
- Lorry's own errors become messages behind a separate option.
  rust-analyzer never sees them. `vendor`'s change summary follows in
  milestone 6.
- Accept the Cargo options that scripts pass out of habit, such as
  `--locked`, `--offline`, `-j`, and `test NAME`.
- Describe all of this for tools and agents in the README.

### 4. `lorry clippy`

- `lorry clippy` is `check` run through `clippy-driver`, with the same
  options and messages.
- Units of workspace members go through the driver. Other packages are
  compiled by plain rustc. Later milestones widen which packages count as
  members. The Clippy code does not change for that.
- Pass `[lints.clippy]` and the options after `--` the way Cargo does.
- Build a native `clippy-driver` and put it into the developer image. This
  is toolchain and image work outside Lorry. It is approved, it has a
  long lead time, and it can start at any time.

### 5. Workspace model and selection

- One piece of code reads the `[workspace]` table for every command.
  `metadata` describes every member, also one that Lorry cannot build,
  such as `kernel`.
- Inheritance from `workspace.package`, `workspace.dependencies`, and
  `workspace.lints`.
- Members that are listed, and members that are found through path
  dependencies. `default-members`, `exclude`, and glob patterns.
- A member may read files outside its own directory, as the selected
  package can today. Lorry decides which files belong to a member the way
  Cargo does. It follows symbolic links, and it stops at another package's
  directory.
- Cargo configuration is read from the directory the command runs in. The
  project's `lorry.toml` is read from the workspace root or above.
- `--manifest-path` works on every command. Without it, Lorry looks for
  `Cargo.toml` in the current directory and its parents.
- One selector for packages and features serves every command that takes
  them.
- Example and bench targets appear in `metadata`.
- A member's `[profile]`, `[patch]`, or `[replace]` table gets Cargo's
  warning and is then ignored. An `[alias]` table in Cargo's configuration
  is accepted, and no alias is run.
- `check -p MEMBER` works from the workspace root. Selecting several
  members, or naming a target that Lorry cannot build yet, is an error.

### 6. Shared resolution, metadata, and admission

Three graphs stay apart:

1. The complete lock graph: all members, every optional feature of a
   member, all kinds of dependency, all platforms.
2. The reviewed graph: what the admission record covers.
3. The build graph: what this command builds.

- One resolver serves all three. The reviewed graph and the build graph
  reuse the packages that the lock names.
- `fetch` reads the lock and never changes it. It approves nothing. By
  default it downloads the complete lock. `--target` limits the download
  to those platforms and the host.
- Resolved `metadata` stays offline. It gives Cargo's exact answer, or it
  says what is missing. It never gives a partial answer.
- `vendor --locked` reviews the existing lock and moves no Git branch.
  With `--offline` it uses no network at all. Deliver both before requiring
  admission records for compilation.
- One admission record covers the workspace. A build checks that what it
  needs is covered, including on cache hits. The same requirement applies
  to Clippy and `check --compile-time-deps`. Policies A and B below define
  the record and its use.
- The first record covers the whole workspace with default features. A
  smaller review can follow. It never changes the lock or `metadata`.
- The package limit applies to the complete lock graph. The developer
  image's limit becomes 384. `--max-packages N` raises it for one run.
- Resolver 3 prefers versions that suit the members' `rust-version`, as
  Cargo does. A new lock gets the format version that Cargo would write
  (early fix 10).
- `vendor` can print its change summary as one of Lorry's own messages.

### 7. Workspace builds

- `build` and `check` accept `--workspace`, repeated `-p`, `--exclude`, and
  the default members.
- Several selected members are planned as one unit graph. A member can be
  selected and be a dependency at the same time.
- Start with ordinary libraries and binaries. This is the first working
  multi-member build.
- Messages name every selected member.

### 8. Remaining targets and commands

- Build scripts and build-dependencies of members, under policy C below.
- Procedural-macro members, `staticlib` and `rlib`, examples, and benches.
- Dev-dependencies for tests, examples, and benches, with Cargo's feature
  rules.
- Cargo's options for choosing targets, `required-features`, and the
  profile settings that the acceptance projects need.
- Workspace tests run in Cargo's order, with `--no-run`, `--no-fail-fast`,
  and one bundle for each selected member.
- `run`, `clean`, and `new` follow Cargo's rules for workspaces.

### 9. Editor integration and native acceptance

- `check --compile-time-deps` runs build scripts and builds procedural
  macros, and skips everything else. It includes members' own build
  scripts. Cargo's own pass succeeds on `src/sys`.
- The developer image's Helix configuration passes that option to
  rust-analyzer's build-script pass. The override explicitly supplies the
  complete invocation; rust-analyzer does not append its configured
  features or target directory. Projects with different settings supply
  a complete project override. Test nondefault features and a custom
  target directory.
- `check.workspace = false` is set for the Motor OS checkout only.
- A member's manifest starts to stand for the whole workspace in
  `metadata` and `locate-project`. This switch waits until here, so the
  editor never loses what works today.
- Run the acceptance cases on Motor. Bring the README, `design.md`, and
  the editor documentation up to date.

## Defects and performance

The details file keeps all 25 findings and the early-fix numbers. Four
fixes land first. Fix 13 is optional. Every other open fix lands with the
milestone that touches its code. A table in the details file says which.

Today checks and rebuilds copy every cached dependency file into a new
directory. Milestone 2 stops that and preserves the unchanged-build
shortcut. Measure on Motor after it: cold and warm `check`, `metadata`,
and disk use.

More speed-ups are possible, such as reuse of build-script results,
reading cached artifacts in place, and tracking only the variables that
rustc reads (fix 13). Each needs its own proof. Add one only if the
measurements call for it.

## Policy decisions

The recommended answers to A, B, and C are incorporated after the v3
review. They define the planned behavior; this revision changes no code.
The details file records their trust implications and alternatives.

| Policy | Answer | Implemented in |
|---|---|---|
| A. Source access and admission (v1 questions 40 and 49) | Metadata may read verified sources without a record. Compilation using crates.io or Git packages requires admission, including Clippy, the compile-time pass, and cache hits. The explicit `--use-cargo-registry` mode keeps its rules | Milestone 6 |
| B. Record contents (v1 question 53) | Exact outside-package/source identities, verified content, host/target contexts, features, grants, and review scope. Omit members' declaration text; verify the recorded review, then check the requested build's coverage | Milestone 6 |
| C. Member build-time code (v1 questions 20, 21, and 56) | Named member grants; unpinned native-tool grants only for editable workspace members; caller-variable allowlists on the relevant package rules, empty by default. Keep nonmember restrictions and treat project configuration as trusted input | Milestone 8 |

V1 had forty open questions. The six combined into A, B, and C now have
answers. Of the other thirty-four, some were decided and the rest are
written into the milestones as proposals. Approving the plan approves
those remaining proposals. The details file gives each one's status.

These proposals are more than "do what Cargo does", and none has been
confirmed one by one:

- One admission record covers the workspace. An old per-member record is
  rejected with instructions (milestone 6).
- `vendor` can later review less than the whole workspace, and `vendor -p`
  changes its meaning. A build outside the reviewed graph is an error
  (milestone 6).
- The developer image's package limit rises from 192 to 384 (milestone 6).
- A `lorry.toml` inside a member becomes an error (milestone 5).
- `check.workspace = false` is set for the Motor OS checkout only, in a
  new `.helix/languages.toml` (milestone 9).
- For `src/sys`, Git ignores local `.lorry/` state, `src/sys/lorry.toml`
  carries the grants for member build scripts, and no admission record is
  committed (milestones 6 and 9).
- The test gates in "Validation".

## Changes outside Lorry

| Change | Where | When |
|---|---|---|
| A native `clippy-driver` | The toolchain build and the developer image | Milestone 4 |
| Package limit of 384 | The developer image's `lorry.toml` | Milestone 6 |
| The build-script command with `--compile-time-deps` | The developer image's Helix configuration | Milestone 9 |
| `check.workspace = false` | A new `.helix/languages.toml` in the Motor OS checkout | Milestone 9 |
| Ignore local `.lorry/` state, and grants for member build scripts | Motor OS's `.gitignore` and `src/sys/lorry.toml` | Milestones 6 and 9 |
| Grants, tool settings, and allowed variables for each project | The Helix, ripgrep, and sed checkouts, or the user's configuration | Milestone 9 |
| Native acceptance cases | The image's test entry points and the rust-analyzer smoke test | Milestones 2, 4, 7, and 9 |
| Documentation | `docs/helix.md`, `docs/build-rustc.md` | Milestones 4 and 9 |

Helix, ripgrep, and sed are repositories outside Motor OS. Any change
there must be named before it is made.

## Validation

- Compare with Cargo, offline: membership, selection, metadata, features,
  lockfiles, messages, and command behavior.
- Compare Lorry's unit plan with Cargo's `--unit-graph` output for `build`,
  `check`, and `test`. Compare the units, the edges between them, and
  their settings.
- Add a selected member to the Cargo identity fixture in milestone 1. Add
  shared and multi-member builds in milestone 7. Add the same small
  workspace to the cross/native Motor suite.
- Test what can go wrong with outputs: a failed build, a killed command,
  two commands at once, `clean`, and an edit to a file outside the
  package.
- Prove that unchanged builds skip build-script processes without skipping
  input or policy validation. Test editor-generated code with nondefault
  features and a custom target directory.
- Run focused contracts while developing, and `tests/test-all.sh` for
  every code patch, within its 30-minute budget. Markdown-only changes
  need no test.
- Run `src/tests/full-test-dev.sh --release` for changes to native editor
  behavior and for native acceptance. Changes outside Lorry follow the
  repository's gates for their scope. The native Clippy driver needs the
  full debug and release gates.
- Keep regular tests offline. The one approved manual fetch on a copy of
  `src/sys` stays a separate check.
- Diagnose failures. Do not add retries, longer timeouts, or weaker
  checks.
