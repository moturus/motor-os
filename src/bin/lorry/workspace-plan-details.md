# Lorry workspace support: details

Reference for [workspace-plan.md](workspace-plan.md). The project is
complete. This file keeps the material that stays useful after it:

- The terms the plan uses.
- What the real workspaces needed.
- How Cargo treats each kind of package.
- The settings used for real-project acceptance.
- The early fixes and their outcomes.
- The policy decisions and the numbered decisions.

The per-milestone history is in git history, in the commit messages.

The Cargo rules here were read from the pinned Cargo `1.99.0-dev`
(`eb98b54bc`). Early-fix numbers and v1 question numbers come from v1 of
the plan. Milestone numbers are v3's unless marked v1.

## Terms and graph boundaries

- **Member:** a package that belongs to the workspace.
- **Selected package:** a member selected for this command. Membership and
  selection are independent. A selected member can also be another
  selected member's dependency.
- **Workspace root:** the directory of the manifest with `[workspace]`.
  A virtual root has no package of its own.
- **Unit:** a compiler invocation or build-script execution, with its
  package, target, mode, compilation platform, features, and effective
  settings. "Member" is not a new unit kind.
- **Complete lock graph:** the dependency resolution for all members,
  including every optional member feature, dependency kind, and platform.
  It determines one shared `Cargo.lock`.
- **Reviewed graph:** the locked packages, feature sets, host/target
  contexts, and capabilities covered by admission. It need not include
  every inactive package in the lock.
- **Build graph:** the units needed for this invocation's selected members,
  target kinds, feature options, profile, host, and target platform.
- **Admission record:** `.lorry/dependencies-v2.toml`. The filename is
  historical. The workspace record uses a newer review format, which the
  spec describes. Path packages remain outside portable dependency
  admission.
- **Dependency repository:** Lorry's source store, not the project's Git
  repository.
- **Contract:** a test under `tests/`, often comparing Lorry with the
  pinned toolchain's Cargo.
- **Resolution oracle:** the paired test of Cargo and Lorry lock resolution.
- **Unit oracle:** a comparison with Cargo's build/check/test unit graphs.
- **Bundle:** a self-extracting test executable produced by `test --bundle`.

## What the real workspaces need

This comes from a scan of all 124 local manifests in the Helix, ripgrep,
sed, and Motor OS checkouts, made in the review of 2026-10-01. The last
column names the milestone that provided each need.

| Need | Helix | ripgrep | sed | `src/sys` | Milestone |
|---|---|---|---|---|---|
| `[workspace.package]` inheritance | yes | yes | | | 5 |
| `[workspace.dependencies]` | yes | | yes | | 5 |
| `default-members` | yes | | | | 5–6 |
| A workspace table with no `members` | | | yes | | 5 |
| Members found through path dependencies | | | | yes | 5 |
| A member that repeats `resolver` | | | | yes | 5 |
| Extra profiles in the manifest | yes | yes | yes | | 5, 8 |
| `debug` in the release profile | | yes | | | 8 |
| `[lints.clippy]` | | | yes | | 4, 5 |
| `[alias]` in `.cargo/config.toml` | yes | | | | 5 |
| Build scripts in members | 7 | 1 | 1 | 3 | 8 |
| A build script that runs a C and a C++ compiler | 1 | | | | 8 |
| A build script that reads files outside its package | 1 | | | 1 | 8 |
| Build-dependencies | yes | | yes | | 8 |
| Dev-dependencies | 8 | 7 | yes | 3 | 8 |
| `[[test]]` tables, `autotests = false` | | yes | | | 8 |
| Examples or benches | | yes | yes | | 5, 8 |
| `staticlib` | | | | 1 | 8 |
| Feature options on the command line | yes | | | yes | 5–8 |
| Source files included from outside the package | yes | | | | 2, 5 |
| Tests that read `CARGO_BIN_EXE_*` when they run | | yes | | | 3 (fix 6) |
| A dependency with more than 64 test files | yes | | | yes | first patches (fix 9) |
| A dependency's build script that compiles C | | 2 | | | already supported, with tool grants |
| A build script that reads the caller's environment | 2 | | | 1 | 8 |
| A symbolic link in a package directory | | yes | | | 5 |
| A member directory inside another member | | | | yes | 5 |
| `CARGO_TARGET_DIR` or `--target-dir` in its `Makefile` or scripts | yes | | | yes | 2 |
| A smaller review than the whole workspace | useful | | | | 6 |

Details behind the table:

- No local manifest uses a member glob, `workspace.exclude`, `[replace]`,
  `[workspace.lints]`, or `links`.
- Helix's build runs `-p helix-term --bin hx --release --locked --offline
  --no-default-features`. One member depends on another member as a
  build-dependency. `helix-loader` includes `../../languages.toml`, a file
  at the workspace root. Helix's Motor graph has 224 packages from outside
  the workspace, with 24 build scripts. sed's graph has 142. The image's
  limit was then 192. Milestone 6 raised it to 384.
- Helix's `helix-static-grammars` script compiles C and C++ sources from
  `vendor/grammars` at the workspace root. Its grant includes a C++
  compiler.
- Two build scripts run `git` to put a commit hash into the program:
  `helix-loader`'s and ripgrep's. Both carry on without it.
- ripgrep's release profile sets `debug = 1`. Its `globset` bench uses the
  unstable `test` crate. Its root build script prints `rustc-link-arg-bin`
  only when it builds for Windows.
- sed has `[workspace.dependencies]` and no `members` key. Its bench sets
  `harness = false`. Its Motor build sets
  `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`.
- `src/tests/full-test.sh` passes
  `--features stdio-pipe,moto-async/host-construction-test` and
  `--manifest-path <member>`.
- Helix's real build needs far less than its whole workspace. For Motor,
  `-p helix-term --no-default-features` needs 145 packages from outside
  the workspace. The whole workspace with default features needs 224. Most
  of the difference is the `gix` graph. It comes in through the `xtask`
  member and through `helix-term`'s default `git` feature. The Motor build
  never compiles it. This is why a smaller review is useful for Helix.
- ripgrep's `grep-pcre2` member depends on `pcre2-sys`, whose build script
  compiles the PCRE2 C sources. ripgrep's lock also has
  `tikv-jemalloc-sys`, for musl targets.
- The Motor OS `Makefile` sets `CARGO_TARGET_DIR` in 38 places, one
  directory for each recipe. Lorry used to reject that variable.
  Milestone 2 made Lorry accept it.

## How Cargo treats each kind of package

Several milestones depend on these rules. "Selected" means named by `-p`,
`--workspace`, or the default members.

| Rule | Selected package | Other member | Path package outside the workspace root | crates.io or Git package |
|---|---|---|---|---|
| Directory rustc runs in | workspace root | workspace root | package root | package root |
| Source path passed to rustc | relative to the workspace root | relative to the workspace root | absolute | absolute |
| What the identity hash names | path relative to the workspace root | path relative to the workspace root | absolute path | registry or Git URL |
| Lints | package's `[lints]`, no cap | package's `[lints]`, no cap | package's `[lints]`, no cap | `--cap-lints allow` |
| `CARGO_PRIMARY_PACKAGE` | set | not set | not set | not set |
| Clippy driver | runs and lints | runs; lints unless `--no-deps` | not used | not used |
| Dev-dependencies | built for its tests, examples, and benches | not built | never | never |
| Files copied to the profile directory | all its outputs | none | none | none |
| Stored warnings printed again | yes | yes | yes | no |

Three notes:

- For the last two columns, Lorry differs from Cargo in the first three
  rows. Lorry runs rustc in the workspace root. It tells rustc to print a
  made-up path of the form `.lorry/<kind>/sha256/<digest>/source/…` in
  place of the real one. That makes a build on Linux and a build on Motor
  produce the same bytes. Lorry keeps this difference.
- Cargo also copies a `dylib` output of any package. Motor has no dynamic
  libraries, so the table leaves that out.
- A member is a package that the workspace lists, or that a member depends
  on by path from inside the workspace root. Exclusion prevents implicit
  discovery. An explicitly listed member wins over exclusion.

## Real-project acceptance settings

Acceptance ran natively on Motor, in isolated copies of sed, ripgrep, and
Helix. Each copy had exact grants for its locked packages and sources. It
was then admitted with
`lorry vendor --workspace --locked --offline --accept-all`. Helix also
passed `--no-default-features` to that command. No configuration gave a
broad grant to unreviewed dependency code.

| Project | Build | Tests |
| --- | --- | --- |
| sed | `lorry build --release --locked --offline` | Deferred, see below |
| ripgrep | `lorry build --release --locked --offline` | Applicable workspace tests, excluding `grep-pcre2`. Also `lorry test -p ripgrep --bin rg --locked --offline` |
| Helix | `lorry build -p helix-term --bin hx --release --no-default-features --locked --offline` | Not required |

| Project | Exact grant records | Build-script / macro grants | Extra tools and caller environment |
| --- | ---: | ---: | --- |
| sed | 39 | 27 / 13 | None |
| ripgrep | 18 | 17 / 1 | None |
| Helix | 74 | 60 / 14 | `helix-static-grammars`: C, C++, archiver. `tree-house-bindings`: C, archiver. `helix-term`: `HELIX_DEFAULT_RUNTIME`, `HELIX_DISABLE_AUTO_GRAMMAR_BUILD` |

Tool settings:

- The C compiler is `/devtools/bin/cc`, a wrapper over LLVM, with
  `--target=x86_64-unknown-motor`.
- The archiver is `/devtools/llvm/bin/llvm` with the `ar` prefix argument
  and no extra flags.
- Helix's C++ compiler is `/devtools/bin/c++`, with
  `--target=x86_64-unknown-motor` and `stdlib = "c++"`.
- Helix's build sets `HELIX_DEFAULT_RUNTIME=/devtools/helix/runtime` and
  `HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1`.

### Helix: cc-rs and the linker

Crates.io's cc 1.2.29 refuses to build on Motor. Helix commit `73c0876c`
adds a root `[patch.crates-io]` entry for Motor's existing cc-rs fork
(cc 1.4.0 at `02932efc`). Only `Cargo.toml` and `Cargo.lock` changed.

rustc links with `-nostartfiles -nodefaultlibs`. That drops Clang's C and
C++ runtime libraries. Helix's YAML grammar has a C++ scanner, so the link
of `helix-term`'s build script failed on `__gxx_personality_v0`. Target
Rust flags did not help, because they do not reach the host build script.

The fixture's Cargo configuration names an explicit linker. It applies to
both host and target units:

```toml
[target.x86_64-unknown-motor]
linker = "<fixture>/motor-rust-cc"
```

The linker is a Rush script with one command. It adapts the Linux
cross-build's Rust/C linker recipe to native paths:

```sh
exec /devtools/llvm/bin/llvm clang --target=x86_64-unknown-motor "$@" -Wl,--start-group /devtools/llvm/lib/crt1.o -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 -Wl,--end-group
```

The resulting `hx` starts, and `hx --health yaml` finds its parser and
queries.

### Deferred and allowed tests

- **sed.** Its tests reach errno's unsupported-platform guard. errno comes
  in through uucore's rustix dependency. The tests also use tempfile's
  `NamedTempFile`, whose Motor backend is not supported. Porting these
  test-only dependencies is separate work.
- **ripgrep, `ignore`.** The test `leading_dot_slash_impacts_matching`
  fails on Motor. The non-Unix `strip_prefix` in
  `crates/ignore/src/pathutil.rs` normalizes path components, so it drops
  a `./`. A fix would add a Motor version that strips the literal prefix,
  like the Unix one.
- **ripgrep, integration helper.** It uses `std::os::unix::fs::symlink`,
  which Motor does not have. It is deferred.
- **ripgrep, library tests.** Two test-only platform mistakes, in globset
  and grep-cli, were corrected in the isolated copy only. The ripgrep
  checkout is unchanged.

## Early fixes

The plan tracked defects by early-fix number. Fixes 1 to 14 come from v1.
Fix 15 was new in v3.

| Fix | What it does | Outcome |
|---|---|---|
| 1 | Reaching the package cap stops resolution. It cannot fall back to an older, smaller graph | Done before the plan |
| 2 | The cap error names the setting and its source. Workspace members do not count | Done before the plan. Milestone 5 also leaves implicit members out of the count |
| 3 | `--max-packages N` raises the cap for one run, within system limits | Done before the plan |
| 4 | Reject a selected package's build script until it is supported | Done before the plan. Milestone 8 added support |
| 5 | Build a package inside the workspace root the way Cargo does | Done in milestone 1 |
| 6 | Give `run` and `test` Cargo's program environment. Keep `run`'s working directory | Done in milestone 3. Milestone 8 added build-script values |
| 7 | Cap Git dependency lints like registry ones | Done in the first patches |
| 8 | Keep package and workspace metadata tables | Done in milestone 5 |
| 9 | Allow up to 1,024 described targets in a dependency. Keep 64 for a selected package | Done in the first patches |
| 10 | Match resolver 3's member MSRV rules and Cargo's lock-format choice | Done in milestone 6 |
| 11 | Reject `force-warn` as a manifest error, without a panic | Done in the first patches |
| 12 | Lock the artifact tree, keep finished units, and recover interrupted publication safely | Done in milestone 2 |
| 13 | Track only the environment variables that rustc reads, and rebuild dependents when they change | Not done. It stays an optional speed-up |
| 14 | Reject unsupported Cargo settings in the environment. Implement the target directory and profile settings | Done in milestone 2. Milestone 8 added profile settings |
| 15 | Leave out of the cache key the three variables that Lorry removes before it starts rustc | Done in the first patches |

## Policy decisions

The recommended answers to A, B, and C were adopted after the v3 review.
Each section below gives the decision, its effects, and the alternatives
that were not chosen.

### A. Source access and mandatory admission

This combines v1 questions 40 and 49.

**Decision:** allow resolved metadata to read verified sources without an
admission record. Require admission before compilation uses outside
crates.io or Git packages. Enforce this through the shared build machinery
for build/check/clippy/test/run and `check --compile-time-deps`, including
cache hits and unchanged-build shortcuts. Retain the explicit
`--use-cargo-registry` compatibility mode with its documented rules.

Metadata executes no package code. Fetch verifies source integrity,
obeys denies and system constraints, and grants no execution capability.
A stale record must not prevent source navigation after fetch. It must
still prevent an unapproved build.

This changed two earlier behaviors. Metadata no longer requires a current
record. A permissive policy alone no longer allows an ordinary build from
fetched outside sources without admission. The lock-preserving
`vendor --locked` path and its `--offline` support had to exist before
the second change.

The alternative was to keep policy-only builds. That preserves the
permissive mode but does not guarantee that a fetch is followed by review
before compilation. A separate fetch-only source store would enforce
that distinction through storage, with more duplication.

### B. What the record commits to

This is v1 question 53.

**Decision:** commit to exact outside-package and source identities, verified
content, host/target contexts, enabled features, and grants. Record the
review scope. Omit members' raw dependency declarations and feature tables.

A harmless declaration edit does not make the whole workspace stale.
Changes to reviewed outside code, contexts, features, or capabilities do.
Validation must reconstruct the review scope, verify it, and then check
coverage of the requested build. A cached success cannot skip those
checks.

The record no longer attests to the exact member declaration that
requested each package. The review display can still list users.
Path packages and their build-time code remain governed by policy C
and existing path rules, not by portable outside-package admission.

The alternative was to keep declaration hashes and require a new
admission after even an unused feature edit. `vendor --locked --offline`
would make that safe from lock updates, but would not remove the
workspace-wide interruption.

### C. Editable member code, tools, and environment

This combines v1 questions 20, 21, and 56.

**Decision:** retain the existing trusted-project configuration model,
with grants scoped to the relevant package:

- Require a named `source = "path"` rule for a member build script or
  procedural macro, as for path dependencies. Suggest a package name,
  not a blanket rule covering all path packages.
- Let editable workspace members receive native-tool grants without a
  source-tree digest pin. Retain the existing rules for nonmember path
  dependencies. Add a C++ compiler role only when implementing Helix's
  grammar build.
- Put an explicit caller-variable allowlist on each relevant package
  rule. Expose no caller variables by default. A grant for one package
  does not expose those variables to every dependency script. Passed
  values, including unset/empty distinctions, become script inputs.
  Keep tool-selection and Lorry-provided variables under their existing
  controls. An allowlist must not override those controls.
- When a script reports `rerun-if-env-changed` for a caller-set variable
  that was hidden, warn with the name and the required configuration.
  Do not print its value or rerun the script with newly exposed variables.

Project-local `lorry.toml` remains trusted input and may carry these
grants. The project must already be trusted before its build-time code
is allowed to execute. Named grants make capabilities visible in the
checkout. They do not make opening an arbitrary checkout safe. Motor does
not sandbox build scripts. A project-controlled environment allowlist
also cannot, by itself, protect the caller's secrets. Never print the
values of allowed or hidden caller variables in policy diagnostics.

One alternative would accept execution, tool, and environment grants
only from user or system configuration, or from an explicit review of
the workspace. That would change the existing trust model, so it was
not part of this project. Refusing only unpinned project tool grants
would leave the pinned self-grants available.

Keeping digest pins for editable members was another alternative, at the
cost of changing grants on every source edit. Automatically granting
member scripts all tools or the caller's entire environment was outside
this decision.

## Decisions

### Decisions 1 to 14, 19, and 36

These are word for word as first recorded. The milestone numbers inside
them are v1's.

Milestone 1, workspace metadata:

- **1.** `lorry fetch` is acceptable as a download step that approves
  nothing.
- **2.** Match Cargo. A member's manifest gives the whole workspace in
  `metadata`, and `locate-project --workspace` returns the workspace root.
- **3.** Match Cargo: one resolver run for all members.
- **4.** The package limit counts only packages from outside the workspace.
  When the limit is reached, Lorry must say what happened and how to raise
  the limit. A command-line option should raise it for one run (early fixes
  2 and 3).
- **5.** One manual `lorry fetch` run with network access may validate
  milestone 1 on the real `src/sys`.

Milestone 2, structured output:

- **6.** Only `json` and `json-diagnostic-rendered-ansi` for now, as `check`
  has today.
- **7.** Lorry-only messages need a separate option, so rust-analyzer and
  Helix see only Cargo's messages. AI agents should use that option and
  learn Lorry's messages.
- **8.** Test results work as in Cargo. Lorry adds no test-result messages.
- **9.** `vendor` follows `--accept-all`, no matter who runs it.
- **10.** Structured output stays milestone 2.

Milestone 3, `lorry clippy`:

- **11.** Clippy may be added to the native toolchain build and staged in
  the developer image, with the repository's full debug and release gates.
- **12.** Helix keeps rust-analyzer's default check on save (`check`), as on
  Linux.
- **13.** `lorry clippy --fix` comes later (milestone 3, patch 8).
- **14.** Use the simplest option that matches Cargo. The driver finds
  `clippy.toml` itself. Lorry sets `CARGO_MANIFEST_DIR` and passes
  `CLIPPY_CONF_DIR` through.

Milestone 7, root package features:

- **19.** Fix the root `build.rs` defect right away. Done in `12793598`.

Early fixes:

- **36.** Fix the package cap and its error message right away. Done in
  `3939755d`.

The v1 milestones map to v3 as follows. V1 milestone 6 became milestones 1
and 2. V1 milestones 2 and 3 became milestones 3 and 4. V1 milestones 4
and 5 fed milestone 5. V1 milestones 1, 8, and 9 fed milestones 5 and 6.
V1 milestone 10 was split between milestones 7 and 8, and v1 milestone 7
went into milestone 8. V1 milestone 11 became milestone 9. V1 milestone 12
became separate work.

Where each decision landed in v3:

| Decision | V3 placement |
|---|---|
| 1 | Milestone 6 |
| 2 | Milestones 6 and 9, behind the editor integration gate |
| 3 | Milestone 6 |
| 4 | Milestones 5 and 6, with `--max-packages N` |
| 5 | Milestone 6, on a copy of `src/sys` |
| 6, 8 | Milestone 3 |
| 7 | Milestones 3 and 6 |
| 9 | Milestone 6 |
| 10 | Milestone 3. Replaced by a decision of 2026-10-02 |
| 11, 14 | Milestone 4 |
| 12 | Milestones 4 and 9 |
| 13 | Separate work, after milestone 4 |
| 19 | Done before v3 |
| 36 | Done before v3 |

### Decisions of 2026-10-02

Given after the review of v2. The quoted words are the owner's.

- **Cargo-like behavior.** "Keep the changes that make lorry behave more
  like cargo." This covered four changes to rules that the spec stated
  at the time:
  - Lorry accepts `CARGO_TARGET_DIR` and `build.target-dir`.
  - Lorry accepts an `[alias]` table in Cargo configuration. It still does
    not run aliases.
  - Lorry looks for `Cargo.toml` in parent directories.
  - Lorry uses one output layout for every selection. The per-member
    `target/lorry/packages/<name>/` directory goes away.
- **Clippy and Lorry's own messages.** "Put them back in the plan." Clippy
  is milestone 4. Lorry's own messages are in milestones 3 and 6.
- **Order of work.** "Sequence milestones in a way that is the
  easiest/simplest to implement." The editor does not have to come first.
  The same answer covers the order of the engine work.
- **Sizes and risks.** "Don't bother; this does not add much to the plan."
  The plan carries no size estimates and no risk list.
- **First patches.** Early fixes 7, 9, and 11 land before milestone 1. So
  does the new early fix 15.
- **Fetch scope.** "Whatever is simpler." `fetch` downloads the complete
  lock by default.
- **Reuse in place.** A fresh unit in the target directory is reused where
  it is.
- **Structured output.** "Structured output as milestone 3 is ok." This
  replaces the timing in decision 10, which placed it second. It follows
  milestones 1 and 2, which it builds on, and comes before all workspace
  work.
