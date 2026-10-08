# Lorry Technical Specification

Status: **Current product requirements**

This document defines Lorry's current technical behavior. Implementation
history and future work do not belong here.

Normative words such as "must", "must not", and "may" describe requirements.
If historical notes conflict with this specification, this specification wins.

## Product definition

Lorry is a small, strict Rust package creation, build, test, run, and
dependency-vendoring tool for Linux and Motor OS. It is implemented by
`src/bin/lorry` and is intended for:

- Motor OS developers who need a native Rust build and packaging tool without
  porting Cargo;
- Linux Rust developers who want a deliberately smaller Cargo-compatible
  surface and explicit supply-chain controls.

Lorry is a supported subset of Cargo, not a Cargo reimplementation. It adds a
capability only for a concrete supported-project need whose security,
correctness, performance, and complexity costs are acceptable. Unsupported
semantics must be rejected explicitly rather than ignored.

Cargo must never be an operational dependency. Lorry must not invoke Cargo for
resolution, lockfile creation, fetching, building, testing, or running. Tests
may invoke Cargo only as an independent compatibility oracle.

Normal operation reads `Cargo.toml`, `Cargo.lock`, supported Lorry/Cargo
configuration, the selected rustc toolchain, and configured Lorry repository
objects. The explicit `--use-cargo-registry` mode may instead read a local
Cargo archive/source cache after establishing or loading Lorry evidence; it
still does not invoke Cargo or use the network. Cargo oracle programs and
captures, VM profiles, image construction, SSH staging, and guest-layout
checks are validation infrastructure and are not operational Lorry inputs.

## Current capability baseline

Lorry builds dependency-free and locked crates.io, Git, and path graphs. It
supports multiple binaries, selected workspace members, build scripts, and
compiler-host procedural macros. It vendors crates.io and Git sources,
maintains compact admission state, caches dependency units, and builds and
runs test harnesses. It operates on Linux, Linux-to-Motor, and native Motor.

Workspace membership and inheritance, shared resolution, metadata, fetch,
tree, and scoped root admission are implemented. Build, check, Clippy, run,
and test share one workspace graph with CLI feature resolution. They run
selected member build scripts under named path grants. Custom and build-std
targets are unsupported. `full-native-build.md` is a non-normative audit of
the remaining gaps exposed by the repository `Makefile`.

## Platforms, toolchains, and compatibility

- Lorry must run natively on Linux and Motor OS and build Linux and
  `x86_64-unknown-motor` targets.
- Development may iterate on Linux, but portability-sensitive changes
  require Linux-to-Motor and native-Motor coverage.
- Linux compiler discovery follows Cargo-compatible precedence: a leading
  `+toolchain` asks rustup only to locate that toolchain's `rustc`; otherwise
  `RUSTC` precedes `rustc` from `PATH`.
- Motor defaults to `/devtools/bin/rustc`. A controlled `RUSTC` or
  absolute configured override may be allowed unless system policy locks the
  compiler.
- Missing rustup/toolchain/compiler selections must produce actionable errors.
- `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` use Cargo-compatible precedence and
  are compilation-identity and cache inputs.
- `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER` are unsupported and must be
  rejected when set.
- Lorry accepts installed target triples only. Custom JSON targets and Cargo's
  multiple-default-target form are unsupported.
- For Cargo unit identity only, a host unit compiled by
  `x86_64-unknown-motor` uses the paired `x86_64-unknown-linux-gnu` compiler
  host identity. Compiler selection and execution and the independent
  compiler/cache audit inputs remain the actual Motor values.

For supported projects, clean release builds must produce byte-identical final
executables under equivalent source, manifest, lock, compiler/toolchain,
target, profile, native-tool, and host inputs:

- Linux Cargo and Linux Lorry native builds must match.
- Linux Cargo and Lorry cross-builds for Motor must match where both builds are
  supported.
- Native-Motor Lorry and Linux-to-Motor Lorry builds must match.

The paired Cargo identity fixture covers a selected workspace member with a
path dependency, its library and binary, and its library, binary, and
integration-test harnesses and program.

The sole supported metadata compatibility family is Cargo 1.99, selected by
the current Motor Rust toolchain. Lorry must infer it from a Rust 1.99
compiler, accept `cargo-compat-version = "1.99"` for an equivalent custom or
unpaired toolchain, and reject every other family. Native Motor target units
use the logical identity of an explicit
`x86_64-unknown-motor` target even when `--target` was omitted.
Resolved metadata matches dependency declarations by alias, package, kind,
and platform condition. Crates.io sparse-index positions are not manifest
positions, since the index can interleave dependency kinds omitted by the
build manifest reader.
Resolved metadata uses the complete workspace lock and computes node features
across dependency kinds and platforms. `--filter-platform` limits reachable
package pairs, retaining all declarations of each retained pair and the
complete feature lists. Cargo's `build.target` does not filter metadata.
Metadata reads verified sources without reconstructing an execution admission
record or preparing compilation units. Explicit denies and source resource
limits still apply. Locks and admission records are never changed.
Target `required-features` preserves absent, explicitly empty, and nonempty
declarations in the JSON document.
Outside path packages retain their development declarations and all described
targets in metadata, without activating development edges for resolution.
Targets follow Cargo's library, binary, example, test, bench, and build-script
ordering.
Cargo registry description loading verifies the same archives, markers, and
source trees as compilation loading, without imposing build-target restrictions.
This includes local crates.io patches: source description retains their dev
declarations and crate types without first loading a compiler manifest.
Resolved packages and nodes follow Cargo's package identity ordering; described
dependencies follow its table, platform, kind, and alias ordering. Node edges
are ordered by destination identity rather than by dependency alias.
Source-only workspace preparation retains registry target descriptions and
development declarations through evidence inspection and publication.
Locked Git descriptions retain those same fields and bind internal development
paths to the verified locked Git source, without moving branch references.
Dependency JSON omits `path` for registry and Git sources, matching Cargo.

Debug builds must reproduce Cargo-equivalent compilation semantics but need
not be byte-identical across hosts because paths and debug information can
differ. Cross-host identity applies only to deterministic packages that do not
embed host paths, timestamps, randomness, `OUT_DIR`, or arbitrary build-script
observations. Bundle launchers and intermediate archives are not covered by
the final-executable identity promise.

Debug root crates and mutable path dependency units must pass stable
target-specific directories below `target/lorry/.incremental/` to rustc on
Linux and Motor. Release units default to non-incremental compilation;
explicit profile settings may enable it for editable packages. Immutable
dependency units remain non-incremental. Incremental state is a disposable compiler
cache, is never an integrity authority, and is removed by `lorry clean`.

## Command-line interface

The current command surface is:

```text
lorry [+toolchain] [GLOBAL] build  [-p NAME] [--bin NAME]
                                  [--release|-r] [--target TRIPLE]
                                  [--target-dir DIRECTORY] [--strict-validation]
lorry [+toolchain] [GLOBAL] cache clean
lorry [+toolchain] [GLOBAL] check  [-p NAME|PACKAGE_ID] [--manifest-path PATH]
                                  [--target-dir DIRECTORY] [--target TRIPLE]
                                  [--workspace] [--keep-going]
                                  [--all-targets|--lib|--bins|--tests|--benches|--bin NAME|--test NAME|--examples|--example NAME|--bench NAME]
                                  [--message-format FORMAT] [--release|-r]
lorry [+toolchain] [GLOBAL] clean  [-p NAME]
                                  [--release|-r] [--target TRIPLE]
                                  [--target-dir DIRECTORY]
lorry [+toolchain] [GLOBAL] new PATH
lorry [+toolchain] [GLOBAL] locate-project [--workspace] [--manifest-path PATH]
                                          [--message-format json|plain]
lorry [+toolchain] [GLOBAL] metadata [--format-version 1]
                                    [--manifest-path PATH] [--no-deps]
                                    [--filter-platform TRIPLE]
lorry [+toolchain] [GLOBAL] review [--manifest-path PATH]
lorry [+toolchain] [GLOBAL] run    [-p NAME] [--bin NAME|--example NAME]
                                  [--release|-r] [--target TRIPLE]
                                  [--target-dir DIRECTORY] [--strict-validation] [-- ARGS...]
lorry [+toolchain] [GLOBAL] test   [NAME] [-p NAME]
                                  [--release|-r] [--target TRIPLE]
                                  [--target-dir DIRECTORY]
                                  [--strict-validation] [--test NAME]
                                  [--no-run] [--no-fail-fast] [--bundle]
                                  [-- ARGS...]
lorry [+toolchain] [GLOBAL] vendor [-p NAME] [--accept-all]
                                  [--locked] [--offline] [--workspace]
                                  [--exclude NAME] [FEATURE OPTIONS]
lorry [+toolchain] [GLOBAL] fetch [--manifest-path PATH] [--target TRIPLE]
                                 [--locked|--offline|--frozen]
lorry [+toolchain] [GLOBAL] tree   [-p NAME] [--manifest-path PATH] [--target TRIPLE]
lorry [+toolchain] [GLOBAL] rustc -Z unstable-options --print cfg --target TRIPLE -- -O
lorry [+toolchain] [GLOBAL] rustc -Z unstable-options --print target-spec-json
                                --target TRIPLE -- -Z unstable-options
lorry [+toolchain] [GLOBAL] vendor [-p NAME] upgrade PACKAGE[@OLD_VERSION] --to VERSION
lorry --help|-h
lorry --version|-V
lorry help [COMMAND]
```

Global options are `--quiet|-q`, `--verbose|-v`,
`--color auto|always|never`, and the offline local-Cargo-cache option
`--use-cargo-registry` for `build`, `check`, `run`, `test`, resolved `metadata`,
and `tree`. Long value options
accept both `--name value` and `--name=value`.

The global `--lorry-messages` option emits Lorry errors as newline-delimited
JSON on stderr. Objects have `reason: "lorry-error"`, `kind` (usage, failure,
or interrupted), `text`, nullable `file`, `line`, and `help`, and `exit_code`
(1, 101, or 130). Known locations remain separate from the message text.
Cargo JSON and command output remain on stdout. The option also applies to
parse errors, stops at child arguments after `--`, and does not suppress
progress; pair it with `-q` when only machine-readable errors are wanted.
For vendor, the option suppresses human progress and emits
`reason: "lorry-vendor-change"` with the previous commitment and its
availability, added/removed source evidence, added/removed capabilities, and
the complete candidate canonical review as a TOML string. Source items include
exact identities, checksums where applicable, tree hashes, licenses, and
build-time code flags; capability items include native-tool roles. Roles use
the canonical alphabetical order. Human and JSON modes use the same approval
rules, including nonterminal rejection and explicit `--accept-all`.

`build`, `check`, `run`, `test`, `clean`, `metadata`, and `tree` accept
`--locked`, `--offline`, and `--frozen`. Those commands already prohibit
acquisition and lock-file changes, so the flags preserve their existing
constraints. Fetch is always locked; offline fetch verifies retained inputs.
Vendor accepts `--locked` and `--offline`, with offline requiring locked;
locked vendor verifies the complete lock before reviewing its selected scope.
`metadata` defaults to format version 1 and warns when `--format-version`
is omitted, except in quiet mode, as Cargo does.
`--max-packages N` sets the positive outside-package resolution bound for one
run. It does not change other resource limits or any configuration file, and
trusted system constraints on `policy`, `policy.limits`, or the package limit
reject the override. Limit failures identify whether the value came from a
configuration file, this CLI option, or the default.

`locate-project` defaults to JSON and accepts plain output. With no explicit
manifest, it finds the nearest `Cargo.toml` in the working directory or its
parents. A member locates its own manifest by default; `--workspace` returns
the containing workspace's root manifest, matching Cargo. Source and resolved
metadata already describe every member when invoked through a member manifest.
The two `rustc` query forms above are read-only compatibility queries; other
`cargo rustc` forms are rejected. Build, check, run, and test share the message
formats described below, and accept their options after the command name.

`build`, `check`, `run`, and `test` accept `-j N` and `--jobs N`.
A positive count sets compiler concurrency, a negative count subtracts from
available CPUs with a minimum of one, and `default` uses available CPUs.
Zero and malformed counts are usage errors. An explicit option overrides
`LORRY_JOBS`; otherwise the existing positive environment setting applies.
Build scripts receive the effective count in `NUM_JOBS`. Completed-profile
freshness includes that count, so changing it reruns scripts that may read it.

Normal build output reports every dependency unit, build script, and root
target when that operation starts. Quiet mode suppresses those progress lines.
Verbose mode retains them and additionally reports commands, configuration,
and elapsed phases.

Verbose `build`, `run`, and `test` output includes monotonic elapsed-time
records on stderr. Each `[lorry +SECONDS]` record gives time since command
dispatch and, in parentheses, time since the preceding record. Records cover
toolchain queries, dependency and admission verification, cache execution,
root compilation, freshness validation, and artifact publication.

- Duplicate, unknown, missing, conflicting, or command-inapplicable options
  are usage errors.
- `--strict-validation` is a build option shared by `build`, `run`, and
  `test`. It is rejected by commands that do not build a package. Ordinary
  mode trusts atomically published local state and detects mutable source
  changes from bounded path/size/mtime metadata. Strict mode rehashes retained
  sources, tools, cache payloads, rustc dep-info inputs, and installed
  artifacts. Both modes retain structural, policy, admission, and resource
  checks.
- `clean` with no selection removes the complete `target/lorry` artifact tree
  without touching Cargo's adjacent artifacts. `--release` removes the
  selected release profile and `--target TRIPLE` removes the selected target;
  either selective form also removes the project-local mutable-unit cache so a
  later build cannot restore a mutable artifact that was explicitly cleaned.
  `clean -p NAME` removes that package's owned units, top-level executables,
  freshness record, and project-local cache entries in the selected profile.
  It leaves other packages' and shared dependencies' outputs intact.
  Project cleaning never removes the per-user immutable-unit cache.
- `build`, `check`, `run`, `test`, and `clean` serialize artifact reads and
  mutations for one target directory with `target/.lorry-artifacts.lock`.
  The lock file remains outside the cleanable `lorry/` tree. `run` and `test`
  release the lock before starting a program or harness.
  On Linux, compiler and build-script children inherit a read-only lease. If Lorry is killed,
  the next command waits for surviving children before changing the tree.
- `cache clean` requires no current package and removes exactly
  the configured global cache directory. Its default is `$HOME/.cache/lorry`
  on Linux and `/devtools/lorry/cache` on Motor. An absent cache is success. A
  cache root that is a file or symbolic link is rejected rather than traversed
  or removed.
- `new PATH` creates Cargo's default edition-2024 binary package template.
  The package name is the final path component. VCS initialization and the
  other `cargo new` options are unsupported. It also creates the canonical
  dependency-free version-4 Cargo.lock so the package can immediately be
  built, run, and tested by Lorry without Cargo.
- `run` selects one binary across the selected default members. A unique
  `package.default-run` filters those members by that target name; otherwise
  exactly one available binary is required. Explicit `--bin NAME` must also
  match exactly one target. Ambiguous selections report the available binaries.
  Run forwards arguments after `--`, preserves the caller's working directory,
  and executes with the selected member's package and build-script environment.
  `--example NAME` selects exactly one executable example and enables its
  dev-dependencies. Library examples cannot be executed. Run rejects target
  glob patterns and simultaneous binary/example selectors, as Cargo does.
- `-p NAME`/`--package NAME` selects matching workspace members for
  build, check, Clippy, clean, run, test, and vendor. Supported repeated
  selectors combine and deduplicate their selections.
- `review` is offline and non-mutating. It reconstructs and verifies the
  committed canonical dependency review, then writes its exact TOML to stdout.
  The review covers the scope recorded by `vendor`, so package and feature
  selectors are usage errors. It also rejects `--use-cargo-registry`.
- `test` builds all selected harnesses before running them in Cargo-compatible
  fail-fast target order: packages by name, then each package's library,
  binaries by name, and integration tests by name. Ordinary tests accept the
  shared workspace/package/feature selectors and dev-dependencies. Each harness
  runs at its package root with its owning script's output environment. A
  failing harness's exit code is propagated, as in Cargo; termination without
  an exit code returns 101. Arguments after `--`
  go to every executed harness. No enabled harnesses is a successful build.
- `test --no-fail-fast` runs every selected target after runtime failures,
  reports the failed targets, and returns 101 if any failed. Compilation still
  finishes successfully before any test executes. `test --keep-going` remains
  an error with guidance to use `--no-fail-fast`.
- `test NAME` passes the name filter to each harness before arguments after
  `--`. As with Cargo, `--no-run` accepts those arguments without running a harness.
- `test --test NAME` selects matching integration tests across selected
  packages and their required library/program graph.
- Named binary/test/example/bench selectors for build/check/test accept Cargo
  glob patterns across the selected members. Each pattern must match a target;
  overlaps are compiled once. Plural groups and all-targets take precedence
  over names and patterns for the corresponding target kinds.
- Ordinary `test --no-run` builds separate harnesses and prints deterministic
  paths. `test --bundle --no-run` builds one bundle for each selected package
  with enabled harnesses and prints its path in package order.
- Cross-target run/test uses the configured runner as an argument vector,
  never a shell command.
- `vendor upgrade PACKAGE[@OLD_VERSION] --to VERSION` accepts one complete
  semantic version and a locked transitive crates.io package. `OLD_VERSION` is
  required when Cargo.lock contains more than one version with that name.
  Direct dependencies must be edited in Cargo.toml and reconciled with
  ordinary `vendor`.
- Tool, build, and operational failures return 101, including a failed write
  to stdout or stderr. Usage errors return 1, help and version return 0, and
  POSIX-style interruption returns 130 where supported.
- Build, check, run, test, and clean select a target directory in this order:
  `--target-dir`, `CARGO_TARGET_DIR`, Cargo `build.target-dir`, then the
  workspace's `target/`. Relative CLI and environment paths use the invocation
  directory; a relative Cargo config path uses the directory containing its
  `.cargo` directory. Lorry writes only below that target directory's `lorry/`
  subtree.
- Unimplemented `CARGO_PROFILE_*`, `CARGO_BUILD_*`, `CARGO_UNSTABLE_*`,
  and `CARGO_INCREMENTAL` build settings are errors. The supported
  `CARGO_BUILD_TARGET` and `CARGO_BUILD_RUSTFLAGS` settings remain accepted.

## Package and manifest model

Build, check, Clippy, and test execute shared graphs for their selected members;
clean respects package ownership, and run selects one executable. Vendor and
review use the workspace-root record; fetch and resolved metadata use the
complete workspace lock, independent of admission scope.
The current package is selected by its `Cargo.toml`; `-p NAME` selects matching
members from the containing workspace. Builds and source metadata share the
membership reader: a root package and recursively reached normal, build,
dev, and target-specific path dependencies below the root are members.
`members` may be absent or include `"."`. Exclusions are directory prefixes;
explicitly listed members take precedence. Root `default-members` apply
at the workspace root, while a member invocation defaults to itself.
Build, check, and Clippy execute ordinary targets for every default member.
Empty selections fail explicitly. Manifest discovery searches
the working directory and its parents. `--manifest-path` establishes the
workspace independently of `-p`, which may select any member.
Package selectors accept names, partial or full `name@version`, Cargo
file package IDs, and member-name patterns. An unmatched selector fails;
build, check, Clippy, and test execute all matching members together.
Build, check, Clippy, test, and tree accept `--workspace` and repeated
`--exclude`; clean accepts `--workspace`. Exclusions require `--workspace`.
Clean supports repeated package selections through source-only discovery and
removes their owned units, programs, and local cache entries. Unselected clean
removes the shared artifact tree, including at an empty workspace root.
New packages inside a containing workspace omit member-local lockfiles and
report how to add the member without rewriting existing workspace files.
Excluded destinations remain standalone packages with their own lockfiles.
Cargo's workspace precedence applies: without exclusions `-p` is validated
but all members are selected; with exclusions `-p` is ignored. Unmatched
exclusions warn, except in quiet mode. Run accepts one `-p` and
rejects package patterns. Package IDs do not require a manifest-path option.
Build, check, Clippy, run, test, tree, metadata, and vendor share
repeated `--features`/`-F`, comma/space lists, qualified and weak dependency
features, `--all-features`, and `--no-default-features`. Explicit `dep:`
names and multiple slashes fail as in Cargo. Source-only metadata describes
declared features regardless of selection. Metadata, tree, and vendor resolve
those flags. Build, check, Clippy, run, and test resolve them across selected
members through the shared graph, keeping feature unions when a member is a
dependency too. Several selected members use one unit graph,
package-specific primary compiler roles and Cargo JSON IDs, and binary owner
records. Shared execution reuses individual units. Completed-profile reuse
needs a `build` or `run` of one member with default features and no member
build script.
Selected binaries with the same top-level output name produce Cargo's collision
warning before compilation, unless quiet mode is selected. Each unit retains its
own published executable and package identity; the shared top-level path is
replaced as binaries are installed.
`build --keep-going` and `check --keep-going` continue independent units after a
compiler failure, retain successful per-unit artifacts, and still return failure.
Run and test reject `--keep-going`, matching Cargo's command option boundaries.
Editable members use Cargo's package file discovery: Git ignores and tracked
files, include/exclude rules, symbolic links, and nested package boundaries.
A member's source walk fails above 20,000 files or 128 MiB, the default
path-package limits.
Git file discovery calls Cargo's `gix-dir` walker directly with gix's index,
ignore stack, pathspecs, and filesystem capabilities.
Compiler dep-info permits member reads outside their directories and tracks
those inputs through unit-cache restores and completed-profile reuse.
Completed profiles also track the workspace manifest and member compiler
dep-info, including host-profile paths.
Every manifest-reading command accepts --manifest-path. Relative paths use
the invocation directory; package selection and configuration discovery
remain independent of that path.
Rustc configuration queries use descriptive workspace loading and require
no selected package, lockfile, or admission. They work at virtual and empty
roots, while retaining invocation-directory Cargo configuration.
Member profiles, patches, and replacements are ignored with Cargo-style
warnings. An explicit conflicting member resolver also warns. A virtual
workspace without a resolver uses version 1 and warns when a member's edition
implies a newer default. Root replacements and package.workspace are rejected.
Unused profiles may contain additional Cargo settings. Unsupported keys in
the selected dev or release profile, or an explicit test-profile override,
fail before compilation. Known profile values still receive type validation.
Package and workspace custom metadata are preserved in metadata JSON,
including nested tables, arrays, and Cargo's TOML datetime serialization.
Examples and benches are described from explicit tables and automatic file
or directory discovery. Explicit names and paths override inferred targets;
auto flags and edition 2015's defaults follow Cargo. Examples and
benchmarks compile through the shared graph under `check --all-targets`,
including their dev-dependencies, target editions, required features, and
script outputs. `check --examples` checks binary, `lib`, `rlib`, and `staticlib`
examples, including packages with only example targets. `--example NAME` and
`--bench NAME` check named targets across the selected members. Named check
selectors can be repeated and combined; `--all-targets` takes precedence over
their names. `--tests` and `--benches` select targets marked for each group,
including examples and integration tests. Plural groups override corresponding
named filters. Default tests compile enabled examples, run
examples and benchmarks marked `test = true`, and include those test targets
in the owning member's bundle. Named integration-test selections omit examples
and benchmarks.
Members and default-members accept component globs `*`, `?`, and `[...]`,
including negated character classes. `**` and paths outside the root are
rejected. Matching files are ignored; matching directories need manifests,
and unmatched patterns fail. Explicit paths override exclusion, while glob
matches do not. Source metadata can describe an empty virtual workspace;
resolved metadata rejects one with no packages. All metadata forms report
the configured target directory, including `CARGO_TARGET_DIR`, without
creating it or invoking a compiler for `--no-deps`. `fetch` accepts Cargo's
existing empty lockfile and preserves its bytes.
All manifest modes inherit Cargo's 16 package fields from `workspace.package`
when the member sets `workspace = true`: authors, categories, description,
documentation, edition, exclude, homepage, include, keywords, license,
license-file, publish, readme, repository, rust-version, and version.
Inherited readme and license-file paths are normalized relative to the member.
Workspace dependencies inherit sources relative to the workspace root and
add member features. Only member declarations may make them optional.
Legacy `default_features` dependency fields follow Cargo: editions before 2024
accept them with a compatibility warning, preferring `default-features` when
both are present; edition 2024 rejects the old spelling. Inherited member
aliases are normalized before merged-dependency validation, as in Cargo.
Edition 2024 members may override inherited default-features; older editions warn
and ignore false unless the workspace already disabled defaults. Manifest
warnings are collected and reported once, outside compiler JSON output.
Readme discovery and boolean forms match Cargo; an explicit false suppresses
discovery, and inheriting a disabled workspace readme is an error. Metadata
preserves publish's boolean/array meaning. Include/exclude arrays are retained
for member file selection. Inherited type errors identify the workspace
value's source line. `[lints] workspace = true` inherits the root's
`workspace.lints` and rejects additional member lint tables. Rust, Clippy,
and rustdoc namespaces retain Cargo's lint flags and priorities, even when
the corresponding lint tool is not active. Dependency inheritance follows.
`new` and `cache clean` do not inspect
a current package.

A workspace shares its root Cargo.lock, resolver, dev and release profiles,
crates.io patches, and `target/lorry` ownership. Every selected member uses the
same `target/lorry` output layout. The first command after upgrading resets
the previous Lorry artifact tree under the artifact lock, records the shared
layout version, and reports the migration. Portable admission belongs at the
workspace root. Vendoring resolves every member together, including optional,
development, and all-platform edges; selectors change review/acquisition scope
without narrowing complete resolution or its outside-package cap.

A package may contain one library and at most 1,024 targets of each other
kind: binary, example, test, and bench. One routine infers all four kinds as
Cargo does: `src/main.rs` for binaries, then `NAME.rs` files and `NAME/main.rs`
directories in `src/bin`, `examples`, `tests`, and `benches`. Hidden and
non-UTF-8 entries are skipped. A symbolic link to a file is followed, and a
symbolic link to a directory is not treated as a target directory. A missing
target directory, or a file in its place, has no targets.
Explicit `[[bin]]`, `[[example]]`, `[[test]]`, and `[[bench]]` tables share
one parser and require `name`. Explicit names and source paths suppress
matching inferred targets; several explicit targets may still share a source
file. An explicit target without a path uses the matching inferred file or
directory, even with its `auto*` flag set to false. When none or two match,
a binary is an error. A test, example, or bench is dropped from a dependency,
as Cargo drops targets whose files a published crate excludes; a workspace
member rejects it. `edition` is accepted on
every kind with a deprecation warning. `crate-type` is rejected on binaries
and ignored on tests and benches. Integration-test names must also differ
after `-` becomes `_`. Edition 2015 retains Cargo's explicit-table discovery
default and warned legacy binary paths. Source target paths are normalized
without resolving symbolic links, as Cargo presents them.
`doc-scrape-examples` accepts a boolean on every target kind
as inert documentation metadata;
it does not change build, check, or test units.
The inert `[badges]` table is accepted in selected packages too.
Integration tests, examples, and benches of a package used only as a
dependency are described but not built.

`build` defaults to libraries and binaries. It shares check's target selectors:
`--lib`, `--bins`, `--tests`, `--examples`, `--benches`, `--all-targets`, and repeated
named `--bin`, `--test`, `--example`, and `--bench` selections. Plural groups and
all-targets override corresponding named filters. Test/benchmark groups compile
harnesses without running them. Development dependencies use the shared graph.
Auxiliary outputs are published in their unit directories and named in JSON.
Ordinary binary and library examples also publish unqualified output names under
the profile's `examples/` directory. Default compile-only test examples do too.
These files have package owner records, and `clean -p` removes only the selected
owners' examples while preserving other members' outputs.
A single exact `--bin` can use the completed-profile fast path. `test` builds
every enabled binary harness and defines `CARGO_BIN_EXE_<name>` for every
program while compiling integration tests.
Run resolves member build scripts under the same grants as build, and passes
that member's published `OUT_DIR` and script environment to the program. It
compiles only the selected binary. Completed-profile reuse keeps admission
checks and skips dependency scripts.
Test uses those same target selectors, including repeated names and combined
groups. Explicit library, binary, and example selections run harnesses even
when their `test` flag is false. Plural tests/benches filter the corresponding
manifest flags; default tests retain compile-only examples. Each selection
supports no-run and per-member bundles, and participates in bundle layout identity.

The supported manifest surface includes:

- Rust editions 2015, 2018, 2021, and 2024;
- resolver versions 1, 2, and 3, including edition defaults and explicit root
  `resolver`;
- `package.rust-version`, enforced during selection;
- `[lints.rust]` and `[lints.clippy]` levels `allow`, `warn`, `deny`, and
  `forbid`, ordered together by priority as Cargo does;
- the default development profile and supported release-profile settings;
- implicit library/binary discovery, explicit binaries, `autobins`,
  `default-run`, exact build/run `--bin`, and root `[lints.rust]`;
- normal crates.io, Git, and path dependencies in string/table forms, renaming,
  optional dependencies, default-feature control, feature-to-dependency
  forwarding, and target-conditioned dependency tables;
- exact local path `[patch.crates-io]` replacements required by policy;
- root `[patch.crates-io]` Git entries with a matching exact Git source in
  Cargo.lock, materialized without modifying any input manifest;
- dependency libraries declared with `[lib] proc-macro = true`; these are
  compiler-host units and require an explicit procedural-macro grant.

Crates.io dependencies require a version requirement. Path dependencies may
omit one; when supplied, it must match the selected local package. Root
dev-dependencies, including target-conditioned declarations, are retained and
remain inactive for ordinary library/binary build/check targets. Test harnesses,
integrations, examples, and benchmarks activate their required dev graph.
Approved build-dependencies compile on the host for member and dependency
build scripts.

Compiler manifests keep top-level and target-qualified build dependencies.
The shared planner creates the member's host script compiler, per-target
script execution, and output edges to its library and binaries, including
binary-only members. Build, check, Clippy, run, and test execute these units
after validating admission and named path grants. Script outputs provide
cfgs, environment, search paths, and `OUT_DIR` to every consuming target.
Link libraries follow Cargo: the package library receives them when present;
otherwise its other targets receive them. Descriptive commands accept these
manifests without execution.

Libraries support `lib`, `rlib`, `staticlib`, and mixed `rlib`/`staticlib`
outputs. Static archives consume upstream object code and participate in
staging, cache restoration, freshness, and artifact messages. Archive member
object bytes agree with Cargo; rustc's random temporary object-name suffixes
remain outside the final-executable byte-identity promise.
Release LTO runs on pure static libraries. Mixed libraries and their Rust
dependencies retain both object code and bitcode, matching Cargo's planner.
On Motor, declared dynamic types retain their Cargo identities while rustc
warns and drops unsupported outputs. Builds fail if no usable type remains;
metadata-only checks can still succeed. Linux dynamic execution is unsupported.

Explicit `[[test]]` tables, `autotests`, and `harness = false` for libraries,
binaries, and integration tests
are supported. Test discovery follows the edition defaults, explicit targets
replace inferred names/paths, and unavailable required features skip implicit
tests or reject named selections. Harness-free tests use Cargo's `test` cfg
and run at the package root with the Cargo package environment.
Binaries also support `required-features`: implicit build/check/test selections
skip unavailable targets, and named selections report the complete required
feature list. Dependency-qualified requirements use the resolved dependency
features. A build with every implicit target disabled succeeds without compiler
units or artifact messages.

Lorry rejects dynamic/procedural-macro example types, unsupported profile keys,
artifact dependencies, alternative registries, and non-crates.io patches.
Build, run, and test reject an unmaterialized crates.io Git patch and direct
the user to `lorry vendor`; they never fetch or modify it themselves.
Documentation tests are not run because native Motor has no `rustdoc`; the
omission must be reported.

Manifest keys are classified as supported build semantics, recognized inert
publication/metadata, or unsupported build semantics. Unknown or unsupported
behavioral keys must name their source location and a supported rewrite or
deferred capability when possible.

Dev and release profiles support `debug`, `opt-level`, `lto`, `strip`,
`codegen-units`, `debug-assertions`, `overflow-checks`, and `incremental`.
Numeric strings are rejected just as in Cargo. `panic` accepts `unwind` and `abort`. The selected strategy enters
unit identity and rustc arguments for ordinary target crates, while test,
build-script, and procedural-macro units use unwind.
Debug and optimization values follow Cargo. Omitted stripping preserves debug
information when requested, and host debug reduction requires matching
effective runtime settings before a unit can be shared.
`check` and `clippy` accept `--release` (or `-r`) and apply the release profile
to metadata units while retaining the required host-tool profiles.
`check --compile-time-deps` retains executable procedural macros, every planned
build-script run (including members' own scripts), and their dependencies.
It skips ordinary compiler units and selected macro metadata-only checks.
Filtering follows full unit planning so Cargo profile sharing and identities
remain intact. Package/feature/target selection, JSON, cache validation, and
execution admission apply normally; Clippy rejects this check-only option.
Tests default to the `test` profile, which inherits `dev`; release tests use
`release`. Profile inheritance follows Cargo, including chains and explicit
errors for cycles, missing parents, and unsupported active settings. Test/bench
panic overrides are validated before being ignored with Cargo's warning. Inherited compiler settings
and output-directory names are distinct: built-in test outputs remain in debug.
Build/check/clippy/run/test accept `--profile NAME`, conflicting with `--release`.
Custom build/run/test outputs publish beneath the named profile directory;
dev/test map to debug and bench maps to release. Build-script PROFILE reflects
the inherited dev/release root. Profile names follow Cargo's reserved-name and
path-character rules.
Completion messages name the active profile for build, check, and test,
including named profiles and selections that produce no targets.
Supported `CARGO_PROFILE_<NAME>_<KEY>` settings override the corresponding
manifest profile layer before inheritance. Profile/key hyphens map to
underscores and names are uppercased as in Cargo. Unsupported active variables
fail explicitly; inactive profile variables do not alter the build.
`clean --profile NAME` removes the named profile, with package ownership when
combined with package/workspace selectors. It preserves other profile outputs
and accepts deferred build-only profile settings because it does not compile.
The legacy Cargo `check --profile test` form checks the selected library/binary
harnesses; custom profiles inheriting test retain ordinary check target modes.

## Cargo configuration

Lorry reads only Cargo's compilation-related configuration for:

- default build target;
- exact-triple and `cfg(...)` target linker;
- rustflags;
- target runner.

It follows Cargo's discovery/merge behavior and supported
`CARGO_TARGET_<TRIPLE>_*` environment forms for that subset. Registry,
credential, network, unstable, and other output-affecting unsupported
settings must be rejected rather than adopted or ignored.
Cargo configuration is discovered from the invocation directory and its
parents, then CARGO_HOME. Package selection and --manifest-path do not move
that search. An alias table may exist; Lorry does not execute aliases.
Project lorry.toml is found at or above the workspace root, layered over
user/system settings. A member-local lorry.toml fails with the workspace
location to which its settings should move. System constraints still apply.

## Locking, resolution, and source selection

- Every build, run, and test requires a present, current Cargo.lock in format
  1 through 4, including dependency-free projects. These commands treat it as
  read-only, remain offline, and never repair it.
- `lorry vendor` creates a missing lock or repairs a stale lock while
  preserving compatible locked versions. An unchanged lock is preserved
  byte-for-byte; repair retains its format. A fresh lock uses Cargo's member
  Rust-version thresholds: below 1.41 selects V1, below 1.53 V2, below 1.83
  V3, otherwise V4. Without declared member versions, V4 is used.
  When portable admission state exists, an ordinary vendor operation
  reconciles dependency-intent or lock-graph drift only after interactive
  review or complete-candidate approval with `--accept-all`.
  If the visible inputs no longer reconstruct the committed review, it shows
  the prior commitment and complete verified candidate instead of claiming a
  semantic diff.
- An explicit upgrade changes only the selected package and packages forced to
  move by its requirements. Every other compatible locked identity remains
  preferred.
- Before normal resolution, `lorry vendor` materializes the exact locked Git
  sources needed by direct Git dependencies and root crates.io Git patches.
  Both retain their Cargo-compatible Git identities; no input manifest is
  modified.
- Resolver versions 1, 2, and 3 must follow Cargo-compatible feature,
  target, yanked-version, candidate-ordering/backtracking, and Rust-version
  behavior for complete and selected workspace graphs. Resolver 3 ranks
  unlocked versions by compatibility with declared member Rust versions;
  compatible locked identities and their parent edges remain preferred.
  Complete resolution and metadata follow weak dependency feature references
  without activating the corresponding implicit feature. Selected compilation
  retains Cargo's deferred optional activation.
- An omitted path/Git version accepts any source package version, including
  prereleases. An explicit `version = "*"` keeps Cargo's semver prerelease
  exclusion. Inherited dependencies retain that distinction.
- Resolver 1 unifies selected requests across host/target kinds, inactive
  platforms, and workspace member development dependencies before filtering
  the units to build. A unified feature change reaches dependencies in every
  active compilation kind. Resolvers 2/3 keep host and target requests
  separate and enable development requests when needed. Platform-specific
  build dependencies are evaluated against the host.
- Resolution creates the complete all-target Cargo-compatible lock graph.
  Search stores queued-edge continuation and backtracking state on the heap;
  a wide graph cannot exhaust the process stack through queued-edge recursion.
  Forced choices do not retain unnecessary backtracking frames.
  Vendor acquisition includes its normalized review scope's feature closure
  selected by the union of `[vendor].targets` and, by default, the current host.
- Default vendor targets are `x86_64-unknown-linux-musl` and
  `x86_64-unknown-motor`; the rustc host is included unless explicitly
  disabled.
- Crates.io's sparse HTTPS index is the only supported registry. Its SHA-256 is
  authoritative, and Lorry preserves Cargo's canonical crates.io lock source.
- A locked checksum that conflicts with the index or archive is an integrity
  failure and must never be repaired silently.
- Locked resolution constrains every dependency to its parent package's lock
  edges. It never substitutes an already-selected compatible version when
  that parent names a different locked identity.
- Git dependency references omit the commit. In Cargo lock formats 1 and 2,
  they also omit `?branch=master`, while package sources retain it. Validation
  and canonical review accept that legacy spelling only for those formats;
  Git source identities and modern dependency references remain distinct.
- Builds never fall back to Cargo's cache or the network. Missing selected
  objects must identify the package/version/source and recommend
  `lorry fetch`.
- The explicit `--use-cargo-registry` mode is offline. Its first use verifies
  Cargo's cached archive and extracted source against each other and
  Cargo.lock, then atomically records the resulting Lorry evidence below the
  target tree. Later ordinary builds trust Cargo's completed-cache marker and
  that evidence; strict builds repeat the content comparison. The mode never
  fetches, repairs, or weakens policy and is used for physical-path
  compatibility comparisons.
- A validation-only host helper may prepare a disposable Cargo oracle view
  containing checksum-pinned inactive Cargo.lock entries. This is not a Lorry
  command or normal packaging input. Those entries must not enter Lorry's
  production repository, repository fingerprint, or admission policy.

`Lorry.lock` is unsupported and must be rejected.

Normal repository builds must present immutable dependency sources through
host-independent logical paths without changing their physical storage:

- each crates.io object has the logical root
  `.lorry/registry/sha256/<locked-checksum>/source`;
- a path package inside the workspace root keeps its workspace-relative
  source path and package identity, with no source remapping. Its rustc and
  dep-info paths are relative to the workspace root, including when selected;
- each path dependency outside the workspace root has the logical root
  `.lorry/path/sha256/<source-tree-sha256>/source`;
- dependency rustc runs from the workspace root and receives an internal
  `--remap-path-prefix` from the physical source root to the
  workspace-relative logical root for remapped packages;
- an approved C compiler receives the equivalent
  `-ffile-prefix-map=<physical-root>=<workspace-relative-logical-root>`.
  Archivers and other native tools are unchanged;
- source reads, integrity and policy checks, build-script working directories,
  and sandbox roots remain physical. Dep-info paths under a logical root are
  translated back to physical paths only for containment validation;
- no logical source directory, copy, or symlink is materialized. Ambiguous,
  non-absolute, colliding, or unrepresentable mappings are hard errors; and
- physical and logical roots, effective Rust/native arguments, working
  directory, build-script environment, tool identity, and outputs remain
  cache and audit inputs.

`--use-cargo-registry` preserves Cargo's physical-path compatibility and adds
no source remapping, including for path dependencies. The root package is not
remapped.

Targeted fetch inspects a registry package's source description before following
its dependencies. Discovery of a procedural macro recomputes its host context
before choosing child archives; neither inspection nor acquisition runs code.
Git resolution descriptions come from the exact locked source trees, which
may be materialized before platform projection, as in Cargo. Locked Git/path
patches supply crates.io requirements without a sparse-index entry for the
replaced package. Locked vendoring never advertises or refreshes branch refs;
cached sources let both locked and offline locked reviews run without curl.

Locked acquisition retains digest-protected sparse resolution inputs for the
complete lock independently of downloaded source objects. This lets an offline
selected build or tree use a targeted fetch without downloading inactive
platform archives. Index records are checked against locked names, versions,
and checksums; they supply no source evidence or execution approval. Resolved
metadata still requires every reachable package's verified sources and errors
with an explicit `lorry fetch` instruction if those sources are missing.

`tree` resolves selected members against the complete workspace lock and reads
verified source descriptions. It accepts feature selection, remains offline,
and does not require or reconstruct admission. Explicit source vetoes and
resource limits apply; tree neither compiles package code nor needs build-time
execution grants.
The developer image's Lorry policy and native product fixture allow 384 outside
packages in the complete lock. The ordinary default remains 64; the one-run
`--max-packages N` override obeys configured system constraints.

Path-root allowlists constrain outside path packages. Editable members are
recognized by their canonical workspace membership, including selected roots;
explicit named denies still apply to those members.

## Portable dependency admission state

`Cargo.toml` is the only project dependency file intended for human editing.
`Cargo.lock` is the Cargo-compatible resolved graph and may be generated by
Cargo or Lorry. Lorry owns `.lorry/dependencies-v2.toml`; it is deterministic,
portable, intended to be committed, and must be changed only by Lorry.

The compact state is an approval record, never an additional version
requirement and never trusted evidence. The workspace record contains:

- the SHA-256 commitment to the canonical review document defined below,
  which Lorry reconstructs from Cargo.toml, Cargo.lock, and verified repository
  objects before synthesizing any generated policy;
- the normalized member/feature review scope;
- the reviewed `(host, target)` build contexts; and
- the explicit build-script, procedural-macro, and native-tool capability
  grants that must stay visible in a source diff.

Compilation using registry/Git dependencies requires an exact reviewed
host/target context. It reconstructs the canonical document for every recorded
context, verifies its digest and grants, and checks the requested package and
feature coverage before reuse or compilation. Missing, corrupt, conflicting, or extra evidence fails
closed, and an explicit configured deny always wins over committed admission.
Ordinary non-root path dependency edits remain governed by path policy and
source verification and do not require dependency upgrades.

Generated state must contain no timestamps, usernames, physical repository
paths, installed-tool paths, or other host observations. Keys, ordering,
string encoding, and duplicate rejection are canonical and bounded. Unknown
format versions or keys are hard errors.

### Workspace migration

A successful workspace review writes one root record with review format 4.
Plain vendor retains the stored normalized member/feature scope and prints it
in human mode. Any package or feature selector replaces that scope as a whole;
operational options do not reset it. Unused member declarations preserve the
commitment when the resolved outside packages, contexts, features, and grants
are unchanged.
The plain-text human review summarizes source and grant changes, then lists
each locked registry/Git package once with its transitive member users, locked
dependencies, verified source evidence, and host/target feature contexts.
Sources outside the scoped closure are labeled explicitly. If prior inputs
cannot reconstruct the previous commitment, the report identifies that
limitation and shows the complete candidate instead of claiming a semantic
comparison.
Old per-member records require explicit review with workspace-root
`vendor --locked`; their presence never supplies workspace approval.
A root record in the retired single-package review format 3 is rejected by
every command that reads admission. Workspace-root `vendor --locked` treats
it as absent and writes a new review; the old contexts are not kept.
Before confirmation, vendor names the selected members' records that the
new scope replaces. After publishing root approval, it removes those exact
records and reports their paths. Member records are not parsed. Unselected
members, nonmembers, and unrelated state files remain untouched. Symlinks,
non-regular files, and records changed during review fail closed. With
`--lorry-messages`, proposed and completed migration reports use
`reason = "lorry-admission-migration"`, `stage`, and `replaced_records` fields
on stderr.

### Compact admission format

The compact file is UTF-8 TOML. Its allowed top-level keys are exactly
`format-version`, `review-format-version`, `review-sha256`, `review-scope`,
`context`, and `capability`. All but `capability` are required, with at least
one context. Their exact scalar values and the table schemas are:

```toml
# Generated by Lorry. Do not edit.
format-version = 3
review-format-version = 4
review-sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[review-scope]
packages = []
features = []
all-features = false
no-default-features = false

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"

[[capability]]
package = "libc"
version = "0.2.186"
checksum = "68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66"
build-script = true
proc-macro = false
native-tools = ["archiver", "c-compiler"]
```

The scope fields occur in the order shown. Arrays and booleans are always
present; arrays are sorted and duplicate-free. Empty packages mean every
member; otherwise entries are exact member names. Features are normalized CLI
requests. There are at most 64 member names and the existing feature-count
bound applies. The scope table precedes the contexts in both compact and
canonical documents.

The machine writer emits the generated comment, scalars, scope, contexts, and
capabilities in that order, with one empty line before each table and exactly
one final LF. The parser accepts insignificant TOML whitespace and comments,
but table and array element order must already be canonical.

Contexts are sorted and unique by `(host, target)`. They describe build
topology, so Linux-to-Motor and Motor-to-Motor are distinct reviews.
Capabilities are sorted and unique by `(package, version, checksum)`, must
refer to a selected verified crates.io or Git identity, and must grant at
least one capability. The checksum field is the registry checksum for a
crates.io package and SHA-256 of the canonical Cargo.lock source string for a
Git package. `native-tools` is sorted and duplicate-free, recognizes only the
roles defined by this specification, and requires `build-script = true`.
Optional `caller-env` names are sorted, unique, and require `build-script = true`.
Omission means no caller grants and remains omitted in canonical output,
preserving old empty-grant commitments. Names use the same controlled-variable
validation as package policy. Both review and compact state bind these grants;
human and machine change reviews show additions and removals without values.
Every capability has explicit `build-script` and `proc-macro` booleans and at
least one must be true. Each true value requires matching verified source
evidence. Packages with no exceptional capability do not appear in the
compact file.

### Canonical review format 4

The review document is reconstructed rather than stored. It is UTF-8 TOML
with LF line endings, contains no comments or host observations, and has
exactly one final LF. SHA-256 covers its exact bytes. It begins with these
four keys in this order, followed by the review scope table:

```toml
review-format-version = 4
source-tree-format-version = 1
cargo-lock-format-version = 4
resolver-version = 2
```

`cargo-lock-format-version` names Lorry's canonical lock representation. A
version-3 compatibility input is normalized to these version-4 semantics before
the review is reconstructed.

`resolver-version` is the supported resolver selected by the root manifest.
The scope table is followed by repeated tables in the order below. Fields
within each table occur in the listed order. There is one empty line before
each table and no trailing space.

| Table | Fields in exact order | Canonical sort key |
|---|---|---|
| `context` | `host`, `target` | `(host, target)` |
| `locked-registry` | `name`, `version`, `checksum`, `dependencies` | `(name, version, checksum)` |
| `locked-git` | `name`, `version`, `source`, `dependencies` | `(name, version, source)` |
| `context-registry` | `host`, `target`, `name`, `version`, `checksum`, `compile-kinds`, `host-features`, `target-features` | `(host, target, name, version, checksum)` |
| `context-git` | `host`, `target`, `name`, `version`, `source`, `compile-kinds`, `host-features`, `target-features` | `(host, target, name, version, source)` |
| `registry-source` | `name`, `version`, `checksum`, `license`, `source-tree-sha256`, `build-script`, `proc-macro` | `(name, version, checksum)` |
| `git-source` | `name`, `version`, `source`, `license`, `source-tree-sha256`, `build-script`, `proc-macro` | `(name, version, source)` |
| `capability` | `package`, `version`, `checksum`, `build-script`, `proc-macro`, `native-tools` | `(package, version, checksum)` |

The sections record, respectively, reviewed build contexts; every registry
and Git lock node including inactive nodes; per-context selection, compile
kinds, and features; verified evidence for the union of selected immutable
identities; and explicit execution grants. Raw member dependency declarations
and feature tables are not recorded. Context selection, verified source
evidence, and capabilities describe the review scope. Compilation verifies
that recorded review before checking requested coverage. Path packages remain
outside portable admission and retain their independent policy and source-tree
checks.

The `registry-source` and `git-source` booleans are verified manifest evidence.
The matching `capability` booleans are explicit grants and may be true only
when the corresponding evidence is true. A procedural-macro-only capability has
`build-script = false`, `proc-macro = true`, and no native tools.

Compile kinds are `host` and `target`. Every array is present, including
when empty. A locked registry
dependency is rendered as exactly `SOURCE NAME VERSION`, where `SOURCE` is
`crates.io`, `git`, or `path`; original Cargo.lock dependency spelling is first
resolved to one exact semantic node. Locked Git dependencies retain sorted,
duplicate-free Cargo.lock spellings. An empty dependency array is inline. A
non-empty dependency array has one four-space-indented quoted value and
trailing comma per line.

Canonical strings are TOML basic strings. Quote, backslash, LF, CR, and tab use
`\"`, `\\`, `\n`, `\r`, and `\t`; other control characters use uppercase
four- or eight-digit Unicode escapes. Other Unicode scalar values are emitted
unchanged and are not normalized. Integers are unsigned decimal and booleans
are `true` or `false`.

Inline arrays use comma-space separation. Set-valued arrays are sorted by
UTF-8 bytes and reject duplicates, except that compile kinds use `host` before
`target`, native tools use `archiver`, `c-compiler`, then `cxx-compiler`, and dependency
references sort by `(source, name, version)` with `crates.io` before `git`
before `path`.
Repeated tables reject duplicate complete keys. Semantic versions use the
pinned `semver` implementation's canonical display.
Checksums and tree digests are exactly 64 lowercase hexadecimal characters.

Changing canonicalization or review meaning requires a new
`review-format-version`. A compact-TOML-only syntax change requires a new
`format-version`. The following format limits are fixed independently of
project policy; lower project limits still apply:

| Resource | Limit |
|---|---:|
| compact TOML bytes / nodes / nesting | 4 MiB / 100,000 / 64 |
| canonical report bytes | 16 MiB |
| scalar fields and array elements | 1,000,000 |
| bytes in one decoded string | 65,536 |
| reviewed contexts | 64 |
| distinct registry or Git lock nodes / selected packages / source entries / capabilities | 4,096 each |
| Cargo.lock dependency edges | 131,072 |
| context/package memberships | 65,536 |
| feature values and activated-feature occurrences | 262,144 combined |

The writer enforces the report byte bound incrementally and never hashes or
returns a truncated document.

Build, run, and test never create or modify portable state. Before source
lookup or compilation, they compare it with registry/Git dependency semantics,
the Cargo.lock immutable-source graph, and the selected target. Ordinary paths
remain exact policy/source inputs outside this registry state.
A mismatch fails closed and reports the
old and new exact package identities and directs the user to `lorry vendor`.
Formatting-only changes to Cargo.toml or Cargo.lock do not invalidate semantic
state.

Exact state entries act as generated allow rules during policy evaluation.
They may satisfy default-deny admission but must never override an explicit
deny, system constraint, resource limit, source-integrity check, or native-tool
restriction. Prepared source evidence must reproduce the
state exactly. A project without portable state uses the existing configured
policy as a compatibility mode; its next successful ordinary vendor operation
creates state.

## Dependency reconciliation and transitive selection

An update may start from an edited Cargo.toml, an externally updated
Cargo.lock, or the transitive selector. Lorry independently resolves the
candidate and does not trust another tool's resolution without reproducing it.
The transitive selector never edits Cargo.toml: it removes only the selected
old lock preference, adds the requested exact version preference, and retains
unrelated compatible preferences. The selected package must be a locked
transitive crates.io identity and must appear at the requested version in the
resulting graph.

Before visible project changes, vendoring enforces explicit denies, system
constraints, HTTPS and archive integrity, source identity, and all resource
limits. Lorry presents a deterministic graph and evidence
difference including requirements, package additions/removals, checksums,
licenses, source digests, build scripts, and native-tool roles.

An existing package's previous capability set may be proposed but is never
silently carried to a new identity. Interactive approval covers the displayed
package and capability changes. A new native-tool role requires an existing
administrator grant. `--accept-all` approves all displayed package and
capability changes that survive explicit policy, integrity, and resource-limit
checks; it grants no capability that those checks reject.

Verified immutable repository objects may be published before project files.
Vendoring atomically replaces Cargo.lock when needed and writes portable state
last as the commit marker. A crash before the lockfile replacement leaves the
visible graph unchanged. A crash after it leaves stale admission that
build/run/test reject until ordinary vendoring reconstructs, reviews, and
commits the visible graph.

## Lorry configuration

Every present `lorry.toml` declares `config-version = 1`; unknown keys are
errors. Paths are absolute and are canonicalized before use.

Motor merges:

1. `/devtools/cfg/lorry.toml`;
2. `/user/cfg/lorry.toml`;
3. the nearest ancestor repository `lorry.toml`.

Linux merges:

1. `$HOME/.config/lorry/lorry.toml`;
2. the nearest ancestor repository `lorry.toml`.

Linux must not read or write `/etc` or redirect its control root through
`XDG_CONFIG_HOME`. Tables merge recursively; later scalars/arrays replace
earlier values. Policy rule IDs accumulate and cannot erase earlier denies.
System constraints may lock keys or table prefixes against weaker later
configuration.

Configuration version 1 defines compiler selection, the three repository
roles, retention flags, the global cache directory, vendor targets/host
inclusion, curl and CA paths, test extraction root, target-specific native
tools, admission rules/limits, and system constraints.

`cache.directory` is an absolute normalized path owned by system or user
configuration; repository-local configuration cannot set it. It defaults to
`$HOME/.cache/lorry` on Linux and `/devtools/lorry/cache` on Motor. It must not
be a filesystem root or overlap a dependency repository. Lorry creates it on
the first build that needs cache storage.

Repository roles are layer-owned:

- `repositories.system` is trusted/base-owned and read-only to Lorry;
- `repositories.user` is user/base-owned and writable;
- `repositories.local` is repository-config-owned and writable.

Canonical repository paths must be distinct and non-nesting. Lookup order is
local, user, then system. Vendoring writes local when configured, otherwise
user, and fails if neither writable role exists.

## Dependency repository and vendoring

Repository format 1 uses SHA-256-addressed immutable objects:

```text
<repository>/
  repository.toml
  objects/
    crates-io/sha256/<prefix>/<archive-sha256>/
  .staging/  # writable repositories only
```

Crates.io objects record canonical package metadata, the exact sparse-index
record, and retained archive/source forms. Complete source trees use the canonical
`lorry-source-tree-v1` digest and manifest. Ordinary builds trust bounded
object metadata and the digest established by immutable publication. Strict
builds fully reverify every retained archive and source tree before use.

The `lorry-source-tree-v1` digest is framed exactly as:

```text
ASCII "lorry-source-tree-v1" followed by one NUL byte
u64 big-endian entry count
for each entry in ascending unsigned UTF-8 relative-path byte order:
    u8  kind: 1 = directory, 2 = regular file
    u8  executable: 0 or 1 (directories require 0)
    u32 big-endian path byte length
    path bytes, with "/" separators and no leading/trailing "/"
    u64 big-endian file length (directories require 0)
    32 raw SHA-256 bytes (directories require 32 zero bytes)
```

The root is not an entry; all explicit and implied directories are. Paths must
be canonical UTF-8 relative paths and must reject empty, `.`, `..`, NUL,
backslash, control, absolute, and platform-prefix forms. The executable value
records whether any source execute bit was set. Ownership, timestamps, other
mode bits, and filesystem allocation are excluded.

Crates.io `.crate` input is one gzip member containing a tar archive with one
exact `<name>-<version>/` root. The reader accepts v7/ustar regular
files and directories, ustar prefixes, GNU long names, and per-entry POSIX PAX
`path` and `size` records. It validates header checksums, gzip CRC/length,
numeric fields, padding, UTF-8 names, canonical paths, duplicates, and all
resource limits. Concatenated gzip members, trailing nonzero data, global or
unknown PAX fields, sparse files, and every unlisted entry type are rejected.

`keep-artifacts` and `keep-sources` default to true and must not both be false.
Archive-only objects are safely extracted into ephemeral Lorry cache storage.
Source-only objects retain their source integrity manifest.

`lorry vendor` must:

1. hold a project-scoped `std::fs::File::lock` for the full transaction;
2. resolve and apply pre-fetch policy before visible changes;
3. privately stage bounded index records, archives, extraction, evidence, and
   a complete lockfile;
4. verify HTTPS, checksums, archive structure, source identity, and post-fetch
   policy;
5. present deterministic evidence and require one approval of the complete
   candidate, or apply `--accept-all` only after all policy/integrity checks
   pass;
6. fsync and atomically publish immutable objects with no replacement;
7. atomically replace Cargo.lock when needed, then write portable state last.

Git acquisition works identically on Linux and Motor. Lorry uses embedded gix
repository and pack handling with a blocking smart-HTTP transport backed by
the configured curl executable. It never invokes a Git executable. The gix
repository is opened in isolated mode, and the transport rejects credentials,
proxies, extra HTTP configuration, hooks, filters, and credential helpers.
Requests are anonymous canonical HTTPS; response and pack/object processing
remain bounded by policy. Git service uploads are limited to 8 MiB.

A direct Git declaration accepts an anonymous canonical HTTPS `git` URL,
optional `package` and `version`, and at most one of `branch`, `tag`, or `rev`,
plus the ordinary supported dependency feature, optional, and target
semantics. Its Cargo.lock package must use the matching canonical `git+`
source with an exact 40-lowercase-hex commit. Branch, tag, revision, or default
HEAD is update intent; Lorry always fetches and verifies the exact locked
commit. All locked Git sources reachable from a root direct Git declaration
are materialized, and multiple package manifests may be selected from one
repository snapshot. An object is published at
`.lorry/vendor/git/<sha256-cargo-source>/source` with `git.toml` provenance.

A root `[patch.crates-io]` Git entry accepts the same URL and selector surface.
Its package must have a matching exact `git+` source in Cargo.lock. Lorry
materializes that locked source in the same content-addressed Git object
layout, marks the selected package as a crates.io replacement, and preserves
the Git identity in resolution, review, and lock rendering. Input workspace
and member manifests remain byte-identical. Explicit path patches keep their
declared path identities.

On every networked vendor run, default HEAD, branch, tag, and named `rev`
patch selectors are resolved from the advertised remote refs. A 7- through
40-digit hexadecimal `rev` is an exact pinned commit and is not advanced.
Moved selectors and first materializations are verified as one candidate.
The review lists each affected patch, its old and new full commit, Git tree,
source digest, and graph/capability effects; a moved tag is prominently marked
as retargeted. An interactive run asks once and defaults to no. A
non-interactive changed candidate fails unless `--accept-all` approves the
whole candidate. Explicit policy denials, integrity checks, and limits always
retain precedence.

Both dependency forms use a shallow depth-one fetch and record the canonical
URL, request, exact commit, Git tree, canonical source SHA-256, file count,
and bytes. Extraction accepts bounded portable UTF-8 paths and regular blobs
and directories only. Symbolic links, submodules, special modes, and traversal
are rejected. Build, run, and test remain offline and verify the published
source tree and provenance before resolving or compiling it.

A decline or failure may leave an unreferenced, completely verified immutable
Git object, but exposes no changed manifest, lock, or admission state.
Concurrent publication may accept an independently published destination only
after full identity verification. A corrupt higher-priority object is a hard
error, not a reason to fall through or repair.

New non-path packages are default-deny. Any matching deny vetoes admission;
with default deny, at least one allow must match. Integrity checks cannot be
disabled. Policy may constrain package identity, version/source/checksum,
exact license expression, build-script presence, source digest, path roots,
procedural-macro presence, sizes, file counts, dependency depth, package
count, and native-tool roles. Build scripts and procedural macros always
require their respective explicit allows, even under default allow.
Policy rules express those grants with `allow-build-script = true` and
`allow-proc-macro = true`; neither grant implies the other. Native-tool roles
additionally require the build-script grant.
Editable workspace members require a named `source = "path"` rule for each
build-script or procedural-macro capability. Their native-tool grants may omit
`source-tree-sha256`; a same-named nonmember path package still requires that pin
before receiving native tools. Missing-grant diagnostics suggest the member's
name, and do not suggest pinning mutable member source trees.
Named build-script rules may grant `caller-env = ["NAME"]`. Only matching
script grants expose those variables, with an empty allowlist by default.
Unset and empty values remain distinct script/cache inputs. Compiler, Cargo,
native-tool, loader, and temporary-directory control variables cannot be
overridden through this allowlist. If a script tracks a caller-set variable
that was hidden, Lorry warns with its name and configuration advice, never its
value. Crates.io and Git caller grants must match the portable capability
record; changed grants require another vendor review before compilation.

Dependency depth has no default cap, matching Cargo. An explicitly configured
`policy.limits.max-depth` bounds resolution, source preparation, and admission.
Default limits are 64 outside packages, 16 MiB compressed and
128 MiB/20,000 files extracted per package, 256 MiB compressed and 1 GiB
extracted per transaction, and 300 seconds/8 MiB captured output per build
script. The package limit counts packages from outside the workspace; the
selected package and other explicit workspace members do not count.
Reaching it stops resolution at once, without trying older versions, and
the error names `max-packages` and the configuration file that set it. Archives admit regular files and directories only and reject links,
special files, traversal, malformed metadata, duplicates, and limit evasion.

## HTTPS acquisition and redirect trust

Lorry invokes a curl-compatible executable directly without a shell, adapter,
or private helper protocol. Linux requires upstream curl 7.63.0 or newer;
Motor uses `/system/bin/curl` by default. Motor's default CA bundle is
`/system/cfg/ssl/ca-certificates.crt`. Absolute `[network]` overrides are allowed
subject to system policy.

`[network].curl`, when present, is an absolute executable. Otherwise Linux
resolves `curl` once through the invoking `PATH`, while Motor uses `/system/bin/curl`.
Lorry converts the selection to an absolute path before clearing the child
environment. On Linux, curl may use its compiled-in system trust configuration
unless `[network].ca-bundle` is set. Motor always supplies its default or
configured absolute CA bundle.

One curl process performs one public HTTPS request attempt using these separate
common arguments:

```text
--disable
--silent
--show-error
--globoff
--http1.1
--proto =https
--noproxy *
--disallow-username-in-url
--tlsv1.2
--tls-max 1.3
--connect-timeout 30
--max-time 300
--speed-limit 1
--speed-time 30
--user-agent lorry/<lorry-version>
--header "Accept-Encoding: identity"
--output -
--write-out <control-trailer>
[--cacert <absolute-ca-bundle>]
[--header <validated-Git-header>]...
[--data-binary @-]
--url <validated-url>
```

Sparse and archive acquisition uses GET without the conditional arguments.
Git smart HTTP may add only `Accept`, `Content-Type`, `Git-Protocol`, and
`User-Agent` headers. A request body selects POST, is supplied on stdin, has
an exact content length, and is bounded to 8 MiB.

`--disable` is first so curl configuration files cannot affect the request.
The child receives only a deterministic locale; proxy, netrc, credential,
home/config, and TLS environment variables are absent. Lorry deliberately
omits `--location`. It retries curl timeout status 28 at most twice, using a
fresh process and empty response staging for each attempt. It retries no other
curl status and starts another curl for a redirect only after it has validated
that redirect.

Curl stdout is only the response body. Lorry drains it incrementally into a
privately created staging file, enforces the request-specific limit, and
computes the required digest. Curl stderr contains a bounded human diagnostic
followed by this write-out trailer, with one unpredictable per-process nonce:

```text

LORRY-CURL-1 <nonce>
status=<response_code>
url=<url_effective>
redirect=<redirect_url>
size=<size_download>
END-LORRY-CURL-1 <nonce>
```

The Git form uses distinct `LORRY-CURL-GIT-1` markers and adds
`type=<content_type>` before `size`; Lorry validates the service response
content type before gix consumes the body.

Lorry drains both pipes concurrently and spills diagnostic stderr above 64 KiB
to a private temporary file. The spill is bounded to 2 MiB by default;
`LORRY_CURL_STDERR_SPILL_LIMIT_BYTES` may raise that bound. Lorry requires one
well-formed trailer with unique nonce-bound opening and closing markers;
runtime diagnostics before or after the trailer remain diagnostics. Control
values must be UTF-8 without control characters, decimal fields must be
canonical, and the reported size must equal the observed body byte count.
Lorry terminates curl as soon as the body limit is exceeded; it does not rely
on a declared content length or curl's newer `--max-filesize` behavior.

A nonzero curl status is a transport failure and a partial body is discarded;
only timeout status 28 receives the two bounded retries above. With a zero curl
status, Lorry applies HTTP policy itself: a final sparse-index, archive, or Git
service response must be 200; 301, 302, 303, 307, and 308 may provide one valid
redirect; every other status fails. A Git POST may follow only 307 or 308 and
never follows a redirect after the first Git request.
Redirects are limited to five hops.
Each destination must be HTTPS, contain no user information or fragment, avoid
loops, and have an allowed canonical site before curl receives it. URL query
data is redacted from diagnostics.

The selected curl must report the required upstream-compatible transport
statuses: malformed URL 3, name resolution 6, connection failure 7, local
write failure 23, timeout 28, TLS connection failure 35, and certificate
verification failure 60. Motor curl must propagate standard-output write and
flush errors to the transfer so a closed output pipe produces status 23.

The canonical `index.crates.io` and `static.crates.io` URLs are initial
destinations, not redirect approvals. Redirect sites are lowercase hosts plus
a non-default port; port 443 is omitted. Persistent sorted allow/deny lists
start empty and are stored outside repository-controlled configuration at
`$HOME/.config/lorry/redirect-sites.toml` on Linux and
`/user/cfg/lorry-redirect-sites.toml` on Motor. Conflicting or malformed state
is an error, and updates lock, merge, and atomically replace the file.

An unknown site requires one of four terminal decisions: allow for this
operation, allow always, deny for this operation, or deny always. EOF and
invalid input deny the operation. A noninteractive operation that needs a
decision fails before the redirected request. `--accept-all` applies to
package approval, not redirect trust. Site approval never weakens checksums,
download limits, source policy, or repository transactions.

Motor curl needs only this contract: public HTTPS GET and bounded POST over
blocking HTTP/1.1;
TLS 1.2/1.3 with CA-chain and hostname verification; supported DNS and IP;
content-length, chunked, and connection-close response bodies; caller headers,
`--data-binary @-`, the options and write-out variables above; `--help`;
`--version`; and the listed exit codes. Proxying, authentication, cookies,
general uploads, compression, HTTP/2, curlrc, FTP, curl-owned redirects, and
libcurl compatibility are outside the required surface.

## Compilation and build-time code

Lorry constructs a deterministic unit DAG and invokes rustc directly without a
shell. Unit identity includes package/source, target kind/name, host or target
compile kind, features, profile/panic/LTO mode, compiler and compatibility
family, effective flags/linker/lints, build-script results, and dependency
metadata. Distinct host/target, feature, profile, panic, and harness contexts
are distinct units.
Each unit key carries its normal or test profile context. Test plans rekey
units and dependency edges only where their effective panic profile differs,
so normal and test plans share host tools and build-script runs while a build
can name separate abort-profile and unwind-profile target libraries.
The key also names the compiler mode, keeping build, test harness, and check
invocations of the same target distinct.
Equivalent units from those contexts merge into one dependency DAG; conflicting
edges for the same unit key are rejected.
The test planner includes normal-profile programs and test-profile
libraries and harnesses in that DAG. It deduplicates shared dependency units
before computing identities.
Selected integration harnesses are distinct test targets in the test plan.
They depend on test-profile Rust libraries and normal-profile program
artifacts, and the program edges do not become rustc `--extern` arguments.
The integration compiler invocation receives `CARGO_BIN_EXE_<name>` for each
program in its own package and `CARGO_TARGET_TMPDIR` from the selected test
environment. Program maps are keyed by package identity, so another member's
same-named binary cannot replace that path or contribute extra variables.
Temporary-directory maps are also keyed by package identity, permitting
separate member bundle extraction paths. Runtime environment construction
accepts the owning script's output, preserving `OUT_DIR` and `rustc-env` values
while retaining Cargo's package-metadata precedence.

The shared workspace test planner selects library and binary harnesses by
their `test` flags. A named integration selection omits those harnesses and
selects matching targets across members, including `test = false` targets.
Required features still apply to explicit selections. The prepared graph
computes these units' source remaps and identities through the common planner.
Procedural-macro library harnesses compile for the host with host features,
`prefer-dynamic`, and the `proc_macro` extern. Their scripts compile as host
tools and run with Cargo's consumer profile; optimized macro harnesses and
ordinary macro dependencies can require separate script executions.
The common planner splits these script contexts for optimized dev profiles and
release profiles, while retaining one execution for equivalent contexts. A
selected macro's ordinary compiler unit also stays distinct from its host-tool
dependency unit when their optimization settings differ.

For `build`, the selected package's library is compiled on the same unit DAG
and executor as its normal dependencies. Its dependency edges retain the
declared extern aliases, and its source identity is the package path relative
to the workspace root. Selected libraries use the project-local unit cache;
the completed-profile record also covers an unchanged `build` or `run`.
An offline unit-graph oracle compares a selected workspace member's library,
binary, and renamed path dependency with Cargo's `build --unit-graph` nodes,
edges, aliases, roots, and development profile.

When `test` needs the selected library in its test profile, that library is
also scheduled on the dependency DAG and uses the project-local unit cache.
The planner distinguishes library and binary `--test` harnesses from ordinary
library and binary units, retaining their test-mode profiles and dependency
edges.
Artifact collection is scoped to one package and orders its harnesses by
library, binary target name, and integration-test target name, independently
of compiler scheduling order.
Selected library and binary harnesses execute on that DAG during `test`.
When selected integration tests need program binaries, those executables are
installed into the selected profile before the test artifacts are published.
An integration test with no program binaries needs only the test-profile
closure.
`build`, `test`, and `check` run selected compiler targets on the unit DAG.
Each compiler unit writes into a private sibling directory, then replaces
its planned unit directory only after rustc succeeds, its outputs and dep-info
are validated, and any cache entry is stored. Downstream units and artifact
messages use the published path. Successful units remain available if a
later unit fails. Build scripts run against their stable published `OUT_DIR`,
including replacement runs after `build.rs` changes. A failed script can
change files there, as in Cargo. Lorry removes the completed-profile freshness record before rebuilding
and writes a new one last, after successful compilation and validation.
The check planner represents selected libraries, binaries, and enabled test
harnesses with distinct check modes. It gives integration checks test-profile
library dependencies without program-artifact edges. Workspace all-target and
named integration checks use the shared harness graph, including selected dev
edges, features, and scripts. Editable library dependencies reached from check
roots also use metadata units; other dependency libraries still compile fully.
Integration checks define `CARGO_BIN_EXE_<name>` as `placeholder:<name>` because
no executable is linked, and use the target root's `tmp` directory.
Checked units request rustc metadata and dep-info only. Their metadata output
is a distinct artifact type, and checked dependents use `.rmeta` paths for
their Rust externs.
The prepared check plan uses the same source remapping and manifest validation
as build and test plans.
Selected `check` targets run through that planner and executor, including
Cargo-format compiler messages when requested. With `--keep-going`, units
independent of a failed unit continue; without it, no new units start after
the first observed failure.
`check --examples` checks enabled examples; an empty selection succeeds without
compiling a target, as Cargo does. Explicit names must exist and satisfy their
required features.

`clippy` uses check's options, planner, and Cargo messages. It requires a
matching sibling `clippy-driver` and uses separate `clippy` output and
incremental directories. Workspace members, including implicit dependency
members and their build scripts, use the driver; outside packages use
plain rustc. `--no-deps` lints only the selected package. Arguments after
`--` are passed through `CLIPPY_ARGS`. `--fix` is unsupported.
The driver discovers `.clippy.toml` and `clippy.toml`, starting at
`CLIPPY_CONF_DIR` when set or the package directory otherwise, and walking
parents. Lorry preserves that environment setting and fingerprints searched
candidates, including absent files, resolved symlink paths, and file contents.
Member dependencies may read the discovered configuration above their package;
those external inputs are validated on cache hits too.
Member compiler freshness includes the driver's path and content hash. For
the shipped Motor launcher, the hash also covers the native driver payload.
Clippy lints that request `$CARGO metadata` invoke Lorry.

`build` and `check` share the Cargo message writer. Both accept
`--message-format json` and `json-diagnostic-rendered-ansi`, including the
comma-separated combination and equals option form. The stream identifies
packages and targets exactly as metadata does, reports completed artifacts
and build-script results, and ends with one `build-finished` event, including
on failure. Progress and Lorry errors remain on stderr.
`run` and `test` accept the same formats and emit `build-finished` after
compilation, before starting programs or harnesses. Its success describes
the build even when the child later fails. Child stdout remains plain text.
`test --no-run` emits harness artifact paths with `profile.test = true`
without adding human path lines to the Cargo stream.
All published compiler units and restored library cache entries retain and
replay their diagnostics. Completed profiles retain the Cargo event stream,
so unchanged ordinary build and run commands report fresh artifacts and
warnings without starting build scripts or compilers. Paths in nested
diagnostic spans and rendered locations are translated back to physical
sources; immutable sources have persistent content-addressed views.

Programs started by `run` and ordinary test harnesses receive `CARGO`,
`CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH`, and the selected package's
`CARGO_PKG_*` values. Runtime library search paths contain native search
directories below the target profile, the profile and artifact directories,
and the compiler's target library directory. Inherited paths remain intact,
with Cargo's rule for avoiding a repeated prefix. Completed profiles retain
these paths, so warm runs need no additional compiler query.
Integration harnesses also receive `CARGO_BIN_EXE_*`
for the built programs. `run` preserves the caller's working directory;
harnesses use their package root. Test bundles retain their launcher rules.
Each ordinary harness uses its own compilation platform for runtime library
paths and runner selection. Host procedural-macro harnesses run directly with
host libraries even when the invocation specifies a cross target and runner.
The global `-q`/`--quiet`, `-v`/`--verbose`, and `--color` options also
work after the command name. Arguments following `run --` or `test --`
remain child arguments, including strings starting with `+`.

For `build` and `run`, selected binaries are distinct named units on that
same DAG. Each binary has edges to its normal dependencies and the selected
library when present. Its hashed executable is installed at the selected
profile's top level after compilation.

Each rustc unit writes into a private sibling directory below the profile's
`build` tree, then publishes to its deterministic unit path. Lorry passes one
`-L dependency` search path for every
unit in the complete transitive Rust dependency closure and passes direct
artifacts through exact `--extern` paths. A unit's own output directory is
never one of its dependency search paths, and completed unit directories are
not modified later in the build. This follows Cargo's current per-unit output
layout while retaining the selected compatibility family's unit identities
and artifact names.

A dependency manifest with `[lib] proc-macro = true` produces a first-class
procedural-macro unit. Lorry must compile it with `--crate-type proc-macro`
for the compiler host, compile its normal and build dependency closure for
that host, and pass the host artifact through `--extern`. This applies equally
when a test, example, or benchmark selects the macro through a dev-dependency.
On Linux that
artifact is rustc's ordinary dynamic library. On Motor it is a static PIE
executable carrying rustc's registration metadata and private stdio protocol
entry point. Resolver 2
and 3 host features remain separate when the same package is also selected as
a target dependency. Proc-macro unit and cache identity includes its distinct
target kind, compiler host, and exact rustc identity. Selected member macros
also use host library and harness units, with named member execution grants.

Rustc arguments, environment, Cargo-compatible metadata/extra-filename hashes,
target search paths, `--extern` paths, lints/check-cfg, profile/LTO behavior,
and primary output handling must match Cargo compatibility family 1.99.
Registry and Git dependencies receive Cargo's `--cap-lints` setting.
Verbose builds pass Cargo 1.99's diagnostic-only `--verbose` flag to rustc;
the flag does not alter unit identity or executable bytes. Default output is isolated below
`target/lorry/`, with Cargo-shaped native or explicit-target debug/release
subdirectories.

Every supported Linux build script runs in a mandatory sandbox that:

- denies network access;
- makes source, dependency, and toolchain inputs read-only;
- permits writes only to its assigned `OUT_DIR`, private temporary area, and
  the exact `/dev/null` device needed for child stdio;
- starts from a cleared environment and exposes only documented values;
- permits only explicitly approved child tools.

The script runner can also receive an explicit workspace root as a read-only
input. In that mode, `rerun-if-changed` may name workspace files or directories;
canonical paths still reject symlink escapes. `rustc-link-search` remains
restricted to the script's `OUT_DIR`. The executor supplies this capability
only for editable members. Dependency scripts may additionally read and track
the exact workspace `Cargo.lock`; they receive no additional workspace directory
access. A lock symlink must stay within the workspace. Completed profiles track declared script inputs,
including recursive directory contents and canonical identities, so edits,
additions, removals, and symlink retargets invalidate reuse. Script directives
retain their declared paths after validating their current canonical locations.

As under Cargo, a build script runs again only when something it depends on
changes: its executable, the toolchain, its environment, or its granted tools;
a path it names with `rerun-if-changed`; or, when it names no `rerun-if`
directive, any file of its path package. Its `OUT_DIR` must also be unchanged.
A run is not recorded when a named input changed while the script ran. A
reused run replays only its warnings.

The supported directive protocol accepts both `cargo:` and `cargo::` forms of
`rustc-cfg`, `rustc-check-cfg`, `rustc-env`, `rustc-link-lib`, `rustc-link-arg`,
`rustc-link-search`, `rerun-if-changed`, `rerun-if-env-changed`, `warning`,
and `error`. Unknown directives, unsafe paths, malformed/oversized output,
timeout, sandbox violation, or nonzero exit are hard failures. An
`rerun-if-env-changed` name absent from the cleared safe environment is tracked
as explicitly absent; ambient values remain inaccessible.
Common link arguments reach every target of the emitting package, preserving
their order after link libraries. Target-specific `rustc-link-arg-*` forms
remain unsupported.

Lorry supports `c-compiler`, `cxx-compiler`, and `archiver` native-tool roles. They are
configured per target as absolute executable, fixed prefix-argument array, and
flag array; they are never discovered from ambient `PATH`, `CC`, `CFLAGS`,
`CXX`, `CXXFLAGS`, `AR`, or `ARFLAGS`. A package rule must grant each role explicitly and pin a
source-tree digest unless it names an editable workspace member. Tool bytes,
path, identity, arguments, environment, and
outputs are build/cache/audit inputs. For a granted C or C++ compiler, Lorry exposes
the canonical sibling `lib` directory of its `bin` directory read-only when
present, and exposes each absolute existing directory named by an exact
`--sysroot=<path>` flag read-only. These are the only implicit compiler
resource roots; an invalid configured sysroot fails before the build script
runs. Neither root is exposed without the corresponding compiler grant. The C++ role
projects target-qualified `CXX` and `CXXFLAGS`, and receives the same scoped
source-path remapping as the C compiler. Its optional `stdlib` setting projects
`CXXSTDLIB_<target>`; an empty string tells cc-rs to omit its C++ runtime library,
and omission preserves cc-rs's target default. Named libraries use portable
ASCII library names. This setting is rejected on other tool roles and cannot
come from caller-variable grants.
Undeclared helpers must be denied. Linux acceptance must include a native tool
that exists in target configuration but is absent from the package grant: it
receives neither an environment entry nor execute permission. This
distinguishes package admission from mere administrator configuration.
The cc-rs member contract exercises Helix's C++ scanner pattern, generated Rust
code, and linking. Native Linux and cross-Motor executables match Cargo bytes;
JSON comparisons account for separate verified registry source locations.

Motor runs build scripts without isolation and emits an explicit warning for
every sandbox application. This is not a sandboxed mode and must not be
described as one. The warning remains mandatory until equivalent native
isolation is implemented.

On Linux, procedural macros execute within rustc and have the same access as
that compiler process; Lorry adds no separate proc-macro sandbox. On Motor,
rustc starts the static proc-macro executable and uses bounded, versioned
frames on the child's stdin/stdout for the existing token/span bridge. Bytes
outside protocol frames retain ordinary proc-macro stdout behavior, and the
child inherits stderr. Process separation is not a sandbox: the child inherits
rustc's environment, working directory, and authority. Spawn, protocol, EOF,
and child-exit failures must be human-readable compiler diagnostics naming the
artifact; they must not become a Lorry panic or a missing-output error.

## Build cache

Lorry stores verified library and procedural-macro outputs plus build-script
`OUT_DIR`/directive results.
Immutable crates.io and Git units are stored in the
per-user cache below
`$HOME/.cache/lorry/v1/units/sha256/` on Linux and
`/devtools/lorry/cache/v1/units/sha256/` on Motor, unless `cache.directory`
selects another root. Mutable path-package units, including selected package
libraries, are stored in the project below `target/lorry/.cache/v1/units/sha256/`.
Selected binaries, tests, and incremental state are not unit-cache entries.

Cache keys cover Lorry/cache schema, compiler identity, normalized rustc
arguments, the variables Lorry sets for rustc, package source identity,
dependency unit identities, build-script executable/environment/directives/output,
and approved native tools.
Like Cargo, a key does not cover the rest of the process environment.
rustc reports each variable that a unit reads with `env!` or `option_env!`
(`# env-dep:` lines in dep-info). Lorry records those values with the
published unit and its cache entry. A unit is reused only while every recorded
variable keeps its value.
Every key also covers `RUSTC_BOOTSTRAP`, `RUSTC_FORCE_RUSTC_VERSION`, and
`RUST_TARGET_PATH`, which rustc reads itself. As in Cargo, a variable read by
a proc macro without tracking, or by the linker, is not covered. The project root and diagnostic-only rustc verbosity
are normalized so an immutable unit can be reused by compatible projects and
between ordinary and verbose builds. Ordinary keys trust immutable crates.io
identity, use bounded path/size/mtime fingerprints for mutable path packages,
and compose dependency cache keys without rereading rlib/rmeta bytes. Strict
keys hash rustc, sysroot, tools, source trees, dependency artifacts, and
manifests.
A member's keys do not cover its sources. As in Cargo, each member unit
depends on the inputs its rustc dep-info lists, so editing one binary's source
rebuilds only that binary. Member cache entries and published units retain
the dep-info and a digest of every listed input, including each resolved path
and file contents. An edit, removal, or symlink retarget makes the unit stale;
after a successful rebuild, the project-local entry is atomically replaced.
A dependent's key covers each dependency's key, recorded variable values, and,
for a member unit, its input digest. A change to any of them rebuilds the
dependents too.
Each published compiler unit carries a local success fingerprint. It binds
its compiler-input identity to installed artifacts; member units also bind
dep-info and its inputs. A matching unit is reused at its published path
without copying from the cache. Missing or stale libraries and proc macros
are restored from a verified cache entry or recompiled; other compiler units
are recompiled on a miss.
Check units retain their compiler stdout and stderr. Reuse validates and
replays those messages, so a fresh check still reports human or JSON
diagnostics.
Published compiler and build-script unit directories carry a package-owner
record keyed by name, version, and source. A missing or different owner
prevents compiler-unit reuse. The record also identifies which unit directories
belong to a package when cleaning a shared profile.
Cache entries used by a package carry the same owner record, so a selective
clean can remove its project-local entries without removing another package's.
Top-level selected executables have sidecar owner records. Installing a new
executable invalidates its old owner record before atomically replacing the
file, then records the new owner.
Lorry removes the Cargo-client variables `CARGO_LOG`, `RUSTUP_TOOLCHAIN`,
and `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS` before starting rustc, so
a unit always sees them unset.

After a successful build or run, the completed root profile contains a
freshness record. Each selection keeps its own record, named by the owning
package, the selected members of a shared workspace build, and the target and
binary selection. So alternating selections, such as `build` and
`run --bin NAME`, stay fresh. A shared build also digests every selected
member's manifest and the feature requests. `clean -p` removes every record of
the package. An
ordinary unchanged `build` or `run` validates parsed manifest, lock, compact
admission, configuration, compiler, target, flags, tracked variables, and
tool metadata plus rustc dep-info and mutable path-source path/size/mtime
fingerprints. Tracked variables are those that any unit read and the caller
variables granted to build scripts. It checks the size and mtime of each
installed root artifact, so a binary that another selection reinstalls
invalidates the record. It does not read artifact or dependency source
contents. A matching record is checked after
admission verification. The profile is then reused without invoking build
scripts, rustc, native tools, or the linker. Strict mode also rehashes all of
those contents before reuse. A missing, malformed, stale, or differently-modeled
record causes a normal rebuild. Test harnesses and bundle launchers are not
reused by this profile-level check.
A plain `check` keeps the same kind of record in its check profile. Its
digest also covers the check target selection, and reuse replays the recorded
diagnostics. Clippy and `--compile-time-deps` checks always visit their units.
The completed-profile record and each top-level selected binary use private
file staging and atomic installation, so a failed staging or record write
leaves the preceding complete file in place. On Linux, executable staging
hard-links completed compiler output, preserving its permissions and sharing
the inode with the unit artifact, as Cargo does. This avoids writable
descriptors inherited by fork children keeping the installed executable busy.
Filesystems that cannot hard-link fall back to a copy, as Cargo does. Motor
uses independent copies. A reinstall whose bytes and owner match the installed
file keeps it, so its mtime, and other selections' records, stay valid.
Staging names use one leading dot even when the destination is a hidden file,
so they remain valid on Motor.
Copied executables are made read/execute on Motor before publication.
On Motor, a build or clean writes its kernel boot identity and PID to an atomic
version-2 owner record beside the artifact lock before starting children. Normal
lock release removes that exact record. The kernel's nonzero `boot_random_id` is
immutable within one boot. A record from a different boot cannot name a surviving
writer and is replaced under the lock without interpreting its PID. For the same
boot, the next command waits for that owner's child process records to disappear
before changing artifacts.
A missing kernel boot identity, malformed record, process-list error, or child
still present after 30 seconds fails without changing artifacts. Older kernels
leave `boot_random_id` zero; Lorry rejects that value.
If a compiler-unit replacement is interrupted between preserving the old
directory and installing the new one, the next build restores the previous
completed directory under the artifact lock. It leaves abandoned staging
untouched until the lock has established that no child still writes there.
Before reusing or replacing that unit, it removes only matching abandoned
staging directories under the unit's parent.

Unit-cache writers publish atomically. A member library entry is replaced
when a dep-info input changes; other entries are never replaced.
Partial entries are ignored. Ordinary reads require the exact entry structure
and required regular files, then trust the atomically published payload.
Strict reads compare the payload with its content manifest; corrupt entries
are warned about, quarantined within the cache that owns them, and rebuilt.
Repository
corruption found by strict validation is fatal and is never treated as cache
corruption. Cache contents remain writable per-user performance state and are
never an integrity authority for immutable dependency sources.

Source views of immutable dependencies are copied into the global cache
without flushing each file. Every use hashes a view against its content
address. A view that a crash left torn, or that changed later, is warned
about, quarantined, and published again.

The first shared-cache miss in a non-quiet build prints `Rebuilding global
dependency cache` exactly once for that command. Project-local cache misses do
not print this status, and a project `clean` followed by a fully cached rebuild
does not print it.

## Tests and bundles

Ordinary tests preserve separate root library, root binary, and integration
harness crates.

Bundle mode packages each selected member's harness executables and required
program binaries into a separate self-extracting executable. Host-only macro
harness bundles use the host profile, compiler/linker settings, extraction root,
and runtime environment, even during a cross invocation. Target harness bundles
retain their target-machine runtime rules. A member's selection that mixes host
and target harnesses during cross compilation is rejected before compilation;
select `--lib` or `--test NAME` separately, or use ordinary tests. Harnesses for
the same platform may share a bundle.
Integration compile-time program/temporary paths refer to that member's
extraction directory. Layout identity also includes prepared build inputs,
so feature, dependency, configuration, and environment changes do not
reuse another build's extraction. Compiler executable hashes are shared across
member layouts within an invocation. Bundles compile privately, then publish
through the atomic executable installer with package ownership. It must verify its
embedded payload table, extract beneath a configurable absolute private root
using race-resistant exclusive operations, reject links/unexpected files/
tampering, invoke payloads without a shell, forward harness arguments, and
aggregate failures. Unix platforms additionally enforce private directory,
manifest, and executable modes.
Motor seals each extracted executable through `File::set_permissions`, using
the running launcher's read/execute permissions and the existing open file.
Generated launchers require no libc permission entry point.

## Image, dependency, and licensing boundary

Lorry's executable does not bootstrap an OS image. Motor's development image
installs a user configuration for its writable repository and a system
configuration for network and native-tool paths, limits, and exact
executable-code grants. It installs an empty writable repository under
`/devtools/lorry/vendor`, but no dependency objects: a fresh project must run
networked `vendor` before its offline build. Imager inputs, debug/release image
selection, VM launch, and layout validation remain outside this product
boundary.

Lorry's source pins the reviewed non-derive Clap, pure-Rust flate2, Motor
gitoxide fork, semver, serde/serde_json, SHA-256, and TOML parser graph, plus
target-specific first-party Motor support and Linux libc bindings, documented
by Cargo.toml and Cargo.lock. Every third-party crates.io requirement is
exact, and Cargo.lock pins the gitoxide fork's commit. These two
machine-readable files, not duplicated version
numbers in prose, are authoritative for direct versions and selected features.
Every dependency and graph change must record purpose, source identity,
license, selected features, and transitive justification in generated
admission evidence; first-party use grants no policy bypass.

Motor curl uses Rustls with patched `ring` 0.17.14, `std`, and TLS 1.2,
plus `rustls-pemfile` and `getrandom` 0.2.17's custom Motor entropy callback.
The `ring` source is the pinned Motor Git fork, selected through a root Git
patch. Curl is cross-built by Linux-hosted Cargo because ring performs source
generation from Git checkouts; curl is outside Lorry's Motor-native build
surface.

The pinned `ring` inputs are:

- `https://github.com/moturus/ring.git` commit
  `b1dad2579de791d0c31ad33300187e584ba6c268`, tree
  `824d5b8e9755603070a8167e0c5529acb627d956`;
- Cargo.lock pins that commit for the reproducible host cross-build.

New Lorry and Motor curl code uses `MIT OR Apache-2.0`.

## Diagnostics and validation

Progress and diagnostics use stderr; executed child stdout remains available
to the caller. Errors must lead with a concise cause, identify relevant
package/target/source context, and provide an actionable correction when one
exists. Output and verbose commands must not expose credentials or secret
environment values.

The requirements below govern validation coverage, not inputs or behavior of
an installed Lorry command. `tests/test-all.sh` runs every distinct product
boundary once and must finish within a hard 30-minute wall-clock budget:

- the Rust suite covers parsing, resolution, admission, policy, acquisition,
  archives, repositories, cache behavior, sandboxing, compilation, execution,
  vendoring, review, and failure cases;
- focused contracts prove multiple targets, selected workspaces, and
  procedural-macro host execution/cache reuse in Linux-native and
  Linux-to-Motor builds;
- a live check through the exact current Motor Cargo retains the supported
  lockfile-family contract, while a dependency-free fixture proves native and
  Linux-to-Motor release artifact identity against the paired Cargo;
- one fresh real registry acquisition followed by one warm reuse proves the
  external download and immutable-publication boundary;
- one built curl graph exercises every ignored production curl-process case;
  and
- one release Motor VM proves that the cross-built Lorry executes, self-builds
  byte-identically, builds/runs/tests the compact native fixture, and reuses
  one persistent incremental root across two native debug compilations.

Debug/release unit duplication, repeated clean runs, downstream Red/Rush
campaigns, custom validation images, duplicate repositories, second Lorry
generations, and separate Motor registry campaigns are not part of normal
Lorry validation. Their Lorry semantics are already covered by focused tests;
their application, image-layout, and OS behavior belongs to those components.

## Deferred capabilities

Deferred capabilities include building the complete `httpd-axum` and
`russhd` graphs, alternative-registry sources, custom targets and build-std,
dynamic and procedural-macro example types, general C/C++/native-tool
discovery, arbitrary build-script processes, Cargo wrappers, and
linked-artifact cache reuse. `design.md` holds accepted future design
directions. `full-native-build.md` records the repository-specific gap
analysis; its findings are not product commitments.
