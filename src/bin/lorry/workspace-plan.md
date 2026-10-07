# Lorry workspace support

This file records the project that added Cargo workspace support to Lorry.
The project is complete. All nine milestones were done as of commit
`9fbc95ea`.

The per-milestone history lives in git history, in the commit messages.
This file keeps the goal, the decisions, and what each milestone built.
[workspace-plan-details.md](workspace-plan-details.md) keeps the reference
material, such as Cargo's rules, the policies, and the numbered decisions.

## Status

The real projects passed on Motor as shown below. The user approved each
listed limit. Deferred tests are not counted as passing. The details file
records each project's
[commands, grants, and tool settings](workspace-plan-details.md#real-project-acceptance-settings).

| Project | Passed natively on Motor | Accepted limits and required settings |
| --- | --- | --- |
| sed | Release build | Upstream tests deferred. Test-only dependencies (errno through uucore, and tempfile) lack Motor support. |
| ripgrep | Release build, library tests, and the `rg` binary's unit tests | The known `ignore` leading-dot-slash test failure is allowed. The symlink integration helper is deferred. |
| Helix | Online vendoring, release build, and startup | Uses Motor's cc-rs fork. The native fixture sets an explicit Rust/C runtime linker for host and target units. |

The project also made these changes outside Lorry, each as a separate commit:

- Helix, an external checkout: `73c0876c` changes only `Cargo.toml` and
  `Cargo.lock`, to select Motor's existing cc-rs fork.
- Kernel: `4debacaa` adds a random boot ID. Lorry stores it with an
  artifact owner's PID, so a PID reused after a reboot is not taken for
  the old owner.
- sys-io: `8be0fc76` fixes a filesystem deadlock found by the native editor
  tests.
- Kernel: `baa0349e` and `80c216f2` fix a thread reference leaked when a
  thread is killed during a direct CPU handoff. The leak kept a dead
  process in its parent's child list.

## Goal

The goal was to make Lorry build, check, and test Cargo workspaces on Linux
and on Motor. Lorry had to:

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
- Keep the byte-identity guarantees, against Cargo and between Linux and
  Motor.
- Keep downloads explicit. Keep code that runs at build time subject to
  policy and admission.

A command or manifest feature that Lorry does not support must fail with a
clear message. An option must never be accepted and then ignored.

## Acceptance

The project was done when all of these passed:

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
  An unchanged `build` or `run` starts no build-script processes in the
  cases the fast path covers, with input and policy validation intact.
- **Identity.** A small workspace fixture passes the Cargo byte-identity
  suite and the cross/native Motor identity suite.
- **Tools and agents.** An agent drives `build`, `test`, and `clippy`
  through JSON and Lorry's own messages. It parses no text from Lorry.
  What a test or a program prints stays plain text, as under Cargo.
- **Clippy.** `lorry clippy` agrees with `cargo clippy` on a fixture on
  Linux, and runs natively on Motor.
- **Real projects, on Motor.** sed and ripgrep build in release mode.
  Helix builds with `-p helix-term --bin hx --release --no-default-features`.
  ripgrep runs its applicable workspace tests, excluding `grep-pcre2`. The
  status section lists the approved test limits. Each project's tool
  grants and settings are written down.
- **Editor, on Motor.** After `lorry fetch` in `src/sys`, Helix jumps
  between members and into dependencies. After admission, saving a `sysbox`
  file shows compiler diagnostics, and Helix finds the code that build
  scripts generate. Metadata and the build-script pass use the same
  feature and target settings. The pass uses its configured target
  directory.

`src/sys` stays a member-by-member build. Even Cargo cannot check it as one
workspace for Motor. Its `kernel` and `rt` builds need features outside
this project.

## Scope

Not included:

- Documentation tests, custom JSON targets, `build-std`, alternative
  registries, `[replace]`, and `package.workspace`.
- Selecting a dependency that is not a member with `-p`.
- Cargo commands that Lorry does not have: `doc`, `bench`, `install`,
  `publish`, `add`, `remove`, and `update`. Running Cargo aliases.
- Source changes in `src/sys`, the Helix or rust-analyzer forks, Rust's
  standard library, or moto-rt.

Separate work, not part of this project:

- `lorry fmt`, and `clippy --fix`.
- Inverse dependency trees, and a general option to override
  configuration. The option to raise the package limit for one run is the
  narrow `--max-packages N`.
- Speed work beyond what the milestones needed.

Left for later: more JSON rendering modes, the `rustc-link-arg-*` forms for
one kind of target, per-package profile overrides, `cdylib` and `dylib` on
Linux, one test bundle for several members, and checking dependencies
without building them fully.

## Decisions

Decisions 1 to 14, 19, and 36 are
[in the details file](workspace-plan-details.md#decisions-1-to-14-19-and-36),
word for word. These were added on 2026-10-02, after the review of v2:

- **Be more like Cargo.** Lorry accepts `CARGO_TARGET_DIR` and
  `build.target-dir`. It accepts an `[alias]` table and still runs no
  alias. It looks for `Cargo.toml` in parent directories. It uses one
  output layout for every selection. The spec changed with each of these.
- **Clippy and Lorry's own messages** are part of the plan again.
- **Order.** The milestones are in the order that is simplest to
  implement. The editor did not have to come first.
- **First patches.** Early fixes 7, 9, 11, and 15 landed before
  milestone 1.
- **Fetch** downloads the complete lock by default. It is the simpler rule.
- **A fresh unit** in the target directory is reused where it is.
- **No size estimates and no risk list** in the plan.
- **Structured output is milestone 3.** This replaces the timing in
  decision 10, which placed it second. It came after milestones 1 and 2
  because it builds on both, and before all workspace work.

## Milestones

Each milestone was a series of small patches, normally 100 to 300 lines
with their tests. Each patch updated the spec for the behavior it changed.
The single-package contracts kept passing throughout.

Milestones 1 and 2 came first, because everything else builds on them.
Each later feature was then written once.

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

### First patches

Four small fixes depended on nothing else. They landed before milestone 1.
Fix 7 caps lints for Git dependencies. Fix 9 allows up to 1,024 described
targets in a dependency, which tokio needs. Fix 11 rejects the lint level
`force-warn`, which used to make Lorry panic. Fix 15 leaves out of the
cache key three variables that rustc never sees.

### 1. One unit graph

- A unit is one compiler run or one build-script run. It names its
  package, target, mode, platform, features, and settings.
- The selected package's library, binaries, test harnesses, and check
  targets moved onto the existing planner and executor, one kind in each
  patch. The separate code that compiled the selected package was then
  deleted.
- A package inside the workspace root is compiled the way Cargo does it.
  rustc runs in the workspace root and gets a relative path (early fix 5).
  A member was added to the Cargo byte-identity fixture.
- Nothing else changed for the user. The byte-identity suites and the
  existing contracts were the proof.

### 2. Per-unit publication

- One layout below `<target-dir>/lorry/` serves every selection. The old
  per-member directories are gone. The old artifact tree is reset under
  the artifact lock on first use.
- Each finished unit is published by itself. Lorry no longer replaces the
  whole profile directory. Outputs of an earlier selection stay. So do the
  outputs of a command that fails later.
- A file is reported only after it exists in its final place.
- A fresh unit is reused where it is in the target directory. It is not
  copied from the cache again. The unchanged-build shortcut for `build`
  and `run` stayed, with its input and policy validation. Outside that
  shortcut, scripts run as before. General script-result caching remains
  optional.
- Build scripts use Cargo's stable `OUT_DIR` for the same unit. A failed
  replacement may change files there. Lorry invalidates the script's
  freshness before it reruns the script, and never reuses a failed result.
- One lock for each target directory covers every change to its files.
  `clean` takes the same lock. Lorry releases it before it runs a program
  or a test.
- A killed command does not damage the next one. Lorry removes leftover
  files only when no process can still write to them. On Linux, a lease
  held by compiler and build-script children blocks the next command
  while such a child lives. On Motor, a record of the owner's PID and boot
  ID, and a query of the process tree, do the same.
- A unit is fresh only if every file it really read is unchanged. That
  includes files outside its package.
- Lorry accepts `--target-dir`, `CARGO_TARGET_DIR`, and `build.target-dir`.
  It rejects Cargo settings in the environment that change a build and
  that it does not implement (early fix 14).
- `clean -p` removes only what belongs to that package.

### 3. Structured output

- `build`, `test`, and `run` accept `--message-format json`. One writer
  serves them and `check`.
- Diagnostics name real files. A unit that is not rebuilt prints its
  stored warnings again.
- `run` and `test` give the program the environment that Cargo gives it
  (early fix 6). `run` keeps the caller's working directory.
- Lorry's own errors are messages behind a separate option,
  `--lorry-messages`. They go to stderr, apart from Cargo's JSON on stdout.
  rust-analyzer never sees them. `vendor`'s change summary followed in
  milestone 6.
- Lorry accepts the Cargo options that scripts pass out of habit, such as
  `--locked`, `--offline`, `-j`, and `test NAME`.
- The README describes all of this for tools and agents.

### 4. `lorry clippy`

- `lorry clippy` is `check` run through `clippy-driver`, with the same
  options and messages.
- Units of workspace members go through the driver. Other packages are
  compiled by plain rustc. Later milestones widened which packages count
  as members. The Clippy code did not change for that.
- `[lints.clippy]` and the options after `--` are passed the way Cargo
  passes them.
- A native `clippy-driver` is built from the selected Rust sources and
  staged in the developer image. This was approved toolchain and image
  work outside Lorry.

### 5. Workspace model and selection

- One piece of code reads the `[workspace]` table for every command.
  `metadata` describes every member, also one that Lorry cannot build,
  such as `kernel`.
- Members inherit from `workspace.package`, `workspace.dependencies`, and
  `workspace.lints`.
- Members can be listed, or found through path dependencies.
  `default-members`, `exclude`, and glob patterns work.
- A member may read files outside its own directory. Lorry decides which
  files belong to a member the way Cargo does. It follows symbolic links,
  and it stops at another package's directory.
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
- `check -p MEMBER` works from the workspace root. At this milestone,
  selecting several members, or naming a target that Lorry could not build
  yet, was an error. Milestones 7 and 8 lifted those limits.

### 6. Shared resolution, metadata, and admission

Three graphs are kept apart:

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
  With `--offline` it uses no network at all. Both came before admission
  records became required for compilation.
- One admission record covers the workspace. A build checks that what it
  needs is covered, including on cache hits. The same applies to Clippy
  and `check --compile-time-deps`. Policies A and B below define the
  record and its use.
- The first record covers the whole workspace with default features. A
  smaller review can follow. It never changes the lock or `metadata`.
- The package limit applies to the complete lock graph. The developer
  image's limit is 384. `--max-packages N` raises it for one run.
- Dependency depth has no cap unless `max-depth` is configured, as in
  Cargo. The owner chose this after the native gate found a depth of 20.
- Resolver 3 prefers versions that suit the members' `rust-version`, as
  Cargo does. A new lock gets the format version that Cargo would write
  (early fix 10).
- `vendor` can print its change summary as one of Lorry's own messages.

### 7. Workspace builds

- `build` and `check` accept `--workspace`, repeated `-p`, `--exclude`, and
  the default members.
- Several selected members are planned as one unit graph. A member can be
  selected and be a dependency at the same time.
- Ordinary libraries and binaries came first. This was the first working
  multi-member build.
- Messages name every selected member.

### 8. Remaining targets and commands

Milestone 8 added the rest:

- Build scripts and build-dependencies of members, under policy C below.
- Procedural-macro members, `staticlib` and `rlib`, examples, and benches.
- Dev-dependencies for tests, examples, and benches, with Cargo's feature
  rules.
- Cargo's options for choosing targets, `required-features`, and the
  profile settings that the acceptance projects need.
- Workspace tests in Cargo's order, with `--no-run`, `--no-fail-fast`, and
  one bundle for each selected member.
- Cargo's workspace rules for `run`, `clean`, and `new`.

### 9. Editor integration and native acceptance

- `check --compile-time-deps` runs build scripts and builds procedural
  macros, and skips everything else. It includes members' own build
  scripts.
- The developer image's Helix configuration passes that option to
  rust-analyzer's build-script pass. The override supplies the complete
  command, because rust-analyzer does not add its configured features or
  target directory to it. Projects with different settings supply a
  complete project override. Tests cover nondefault features and a custom
  target directory.
- `check.workspace = false` is set for the Motor OS checkout only.
- A member's manifest stands for the whole workspace in `metadata` and
  `locate-project --workspace`. This switch waited until this milestone,
  so the editor never lost what worked before.
- The acceptance cases ran on Motor. The README, `design.md`, and the
  editor documentation were brought up to date.

## Defects and performance

The plan tracked defects by early-fix number, 1 to 15. Fixes 1 to 4 were
done before the plan. Fixes 7, 9, 11, and 15 landed first. Fix 13 was
optional and was not done. Each other fix landed with the milestone that
touched its code. The details file lists
[every fix and its outcome](workspace-plan-details.md#early-fixes).

Before the project, checks and rebuilds copied every cached dependency
file into a new directory. Milestone 2 stopped that and kept the
unchanged-build shortcut. On Motor, after milestone 2, a cold `sysbox`
check took about 23 seconds. A warm check and resolved metadata each took
about 1.4 seconds. More speed-ups are possible, such as reuse of
build-script results, reading cached artifacts in place, and fix 13. Each
needs its own proof.

## Policy decisions

The recommended answers to A, B, and C were adopted after the v3 review.
[The details file](workspace-plan-details.md#policy-decisions) records
their trust implications and the alternatives.

| Policy | Answer | Implemented in |
|---|---|---|
| A. Source access and admission (v1 questions 40 and 49) | Metadata may read verified sources without a record. Compilation using crates.io or Git packages requires admission, including Clippy, the compile-time pass, and cache hits. The explicit `--use-cargo-registry` mode keeps its rules | Milestone 6 |
| B. Record contents (v1 question 53) | Exact outside-package/source identities, verified content, host/target contexts, features, grants, and review scope. Omit members' declaration text. Verify the recorded review, then check the requested build's coverage | Milestone 6 |
| C. Member build-time code (v1 questions 20, 21, and 56) | Named member grants. Unpinned native-tool grants only for editable workspace members. Caller-variable allowlists on the relevant package rules, empty by default. Keep nonmember restrictions and treat project configuration as trusted input | Milestone 8 |

V1 had forty open questions. Six became A, B, and C. The owner decided
some others. The milestones answered the rest, and approving the plan
approved them. These answers went beyond "do what Cargo does", and none
was confirmed one by one:

- One admission record covers the workspace. An old per-member record
  gives no approval. It needs a new review from the workspace root
  (milestone 6).
- `vendor` can review less than the whole workspace, and `vendor -p`
  changed its meaning. A build outside the reviewed graph is an error
  (milestone 6).
- The developer image's package limit rose from 192 to 384 (milestone 6).
- A `lorry.toml` inside a member is an error (milestone 5).
- `check.workspace = false` is set for the Motor OS checkout only, in
  `.helix/languages.toml` (milestone 9).
- For `src/sys`, Git ignores local `.lorry/` state, `src/sys/lorry.toml`
  carries the grants for member build scripts, and no admission record is
  committed (milestones 6 and 9).
- The test gates in "Validation".

## Changes outside Lorry

The plan named these changes. The status section lists the others.

| Change | Where | When |
|---|---|---|
| A native `clippy-driver` | The toolchain build and the developer image | Milestone 4 |
| Package limit of 384 | The developer image's `lorry.toml` | Milestone 6 |
| The build-script command with `--compile-time-deps` | The developer image's Helix configuration | Milestone 9 |
| `check.workspace = false` | A new `.helix/languages.toml` in the Motor OS checkout | Milestone 9 |
| Ignore local `.lorry/` state, and grants for member build scripts | Motor OS's `.gitignore` and `src/sys/lorry.toml` | Milestones 6 and 9 |
| Grants, tool settings, and allowed variables for each project | The acceptance fixtures, recorded in the details file | Milestone 9 |
| Native acceptance cases | The image's test entry points and the rust-analyzer smoke test | Milestones 2, 4, 7, and 9 |
| Documentation | `docs/helix.md`, `docs/build-rustc.md` | Milestones 4 and 9 |

Helix, ripgrep, and sed are repositories outside Motor OS. The only change
made in their checkouts is Helix commit `73c0876c`.

## Validation

- Offline comparisons with Cargo covered membership, selection, metadata,
  features, lockfiles, messages, and command behavior.
- Lorry's unit plan was compared with Cargo's `--unit-graph` output for
  `build`, `check`, and `test`. The comparison covered the units, the edges
  between them, and their settings.
- Milestone 1 added a selected member to the Cargo identity fixture.
  Milestone 7 added shared and multi-member builds. The same small
  workspace is in the cross/native Motor suite.
- Tests cover what can go wrong with outputs: a failed build, a killed
  command, two commands at once, `clean`, and an edit to a file outside
  the package.
- Tests prove that unchanged builds skip build-script processes without
  skipping input or policy validation. Editor-generated code is tested
  with nondefault features and a custom target directory.
- Patches used focused contracts. Milestone gates used `tests/test-all.sh`,
  within its 30-minute budget.
- Native editor behavior and native acceptance used
  `src/tests/full-test-dev.sh --release`. Changes outside Lorry followed
  the repository's gates for their scope. The native Clippy driver used
  the full debug and release gates.
- Regular tests stay offline. The one approved manual fetch on a copy of
  `src/sys` was a separate check.
- Failures were diagnosed. No retries, longer timeouts, or weaker checks
  were added.
