# Lorry

Lorry is Motor OS's small, strict Rust package builder. It creates, vendors,
inspects, builds, checks, lints, runs, and tests a deliberately limited
Cargo-compatible package model on Linux and Motor OS. Unsupported Cargo
behavior is rejected explicitly.

Lorry never invokes Cargo during normal operation. Builds are offline and use
only verified sources already present in configured Lorry repositories.

This README is the short user guide. `spec.md` defines the supported behavior,
`design.md` explains the implementation and deferred design choices, and
`full-native-build.md` audits the remaining work needed to replace the Cargo
builds reached from the repository `Makefile`.

## Operational and validation boundaries

Normal Lorry operation consumes a package's `Cargo.toml` and `Cargo.lock`, the
supported parts of Lorry and Cargo configuration, a rustc toolchain, and
configured Lorry repositories. `lorry fetch` and `lorry vendor` use the configured
curl executable for sparse-registry and Git smart-HTTP traffic. With the
explicit `--use-cargo-registry`
option, build, check, clippy, run, test, metadata, and tree may instead verify and read
an already populated local Cargo archive/source cache. Lorry records its
evidence on first use and trusts that evidence during later ordinary builds.
None of these operations invokes Cargo.

Motor development images install Lorry, curl, the native toolchain, supported
first-party source snapshots, and small system and user configurations. Curl is
cross-built by Linux-hosted Cargo because ring's Git checkout performs a
host-only source-generation step; curl source is not included in the native
snapshot set. The images do not preinstall a dependency repository. On a fresh
image, run `lorry fetch` for source navigation, or `lorry vendor` (or
`lorry vendor --accept-all`) with network access once for each project; build,
run, test, and review then consume the verified local state offline. Lorry does
not create VM images or inspect image profiles/layouts.

Everything called a Cargo "oracle" is validation-only: tests run supported
Cargo versions or compare retained Cargo results to check Lorry compatibility.
Oracle fixtures are not runtime inputs, repositories, caches, or fallback
implementations. VM profiles, dedicated images, guest-layout assertions, and
self-host generations likewise belong to the test harness under `tests/` and
`src/tests/`, not to normal Lorry operation.

## Package requirements

Lorry finds the nearest `Cargo.toml` in the working directory or its parents.
Use `-p NAME` to select a workspace member. Manifest-reading commands
accept `--manifest-path`; it establishes the workspace independently
of the member selected by `-p`.

A supported package has:

- one or more selected members for ordinary build, check, and Clippy;
- at most one library and 64 binary targets;
- optional `tests/*.rs` and `tests/*/main.rs` integration tests;
- a current Cargo.lock in Cargo format 1 through 4, including for
  dependency-free packages; locked commands preserve its exact bytes; and
- only supported crates.io, Git, and local-path dependency declarations.

The supported dependency model includes renamed and optional dependencies,
default and forwarded features, target-conditioned dependencies, dependency
build scripts, procedural-macro dependencies, and root crates.io patches.
Root build scripts and root build-dependencies are not operationally
supported. `build`, `run`, `test`, `check`, and `clippy` reject a selected package
that has a build script, including a workspace member selected with `-p`. Alternative registries, selecting a
procedural-macro package as the root, root dev
dependencies selected for the build target, examples, benches, explicit test
targets, and CLI feature selection for run and test are not supported. Build,
check, Clippy, metadata, tree, and vendor support CLI feature selection. Ordinary
workspace build, check, and Clippy share one compilation graph for default
members, `--workspace`, repeated `-p`, and `--exclude`. Workspace test, example,
and bench target selection remains deferred. A target-conditioned
root dev-dependency for a different target is ignored.

## Create a package

```sh
lorry new hello
cd hello
lorry run
```

`lorry new` creates an edition-2024 binary package and its dependency-free
Cargo.lock, so it is immediately buildable without Cargo.

## Build, run, and test

```text
lorry build [--release|-r] [--target TRIPLE] [--bin NAME] [--strict-validation]
lorry run   [--release|-r] [--target TRIPLE] [--bin NAME] [--strict-validation] [-- ARGS...]
lorry test  [NAME] [--release|-r] [--target TRIPLE] [--strict-validation]
            [--test NAME] [--no-run] [--bundle] [-- ARGS...]
```

Package commands accept Cargo names, package IDs, versions, and member-name
patterns. A member invocation defaults to itself; workspace-root invocations
use Cargo's default members. Repeated `-p`, `--workspace`, and `--exclude`
select members, but compilation still requires exactly one until multi-member
execution lands. Members share the root lockfile, resolver, profiles, patches,
and target ownership. Membership, package/dependency/lint inheritance, and
component globs follow the rules below. External members remain unsupported.

The dev profile accepts `panic = "unwind"` or `panic = "abort"`. The release
profile additionally accepts Lorry's documented `lto`, `strip`, and
`codegen-units` keys. A panic strategy applies to ordinary root and target
dependency crates; Cargo-compatible test, build-script, and procedural-macro
units continue to unwind.

Examples:

```sh
lorry build --release
lorry run -- one "two words"
lorry test
lorry test --test cli -- --nocapture
lorry test --bundle --no-run
```

Binary discovery follows Cargo's ordinary `src/main.rs`, `src/bin/*.rs`, and
`src/bin/*/main.rs` layouts and merges explicit `[[bin]]` targets. Set
`package.autobins = false` to disable discovery. `build` compiles every binary
unless one exact `--bin` is selected. `run` selects `--bin`, then
`package.default-run`, then a sole binary; otherwise it reports the ambiguity.

`run` returns the program's status. Ordinary tests build separate library,
binary, and integration-test harnesses, then run them in order and stop at the
first failure. Positional `NAME` filters test names in each harness;
`--test NAME` selects one integration-test target. `--no-run` prints
the built harness paths.

Normal builds report dependency verification and preparation, then each
dependency unit, build script, and root target when that work starts. `--quiet`
suppresses this progress, while `--verbose` also prints commands,
configuration, and timings.

Ordinary builds trust previously published per-user dependency and
project-local artifact state, matching Cargo's local-cache model. An unchanged
`build` or `run` checks parsed inputs and root/path-source size and modification
metadata, verifies admission and requested coverage, then reuses the existing
profile without starting build scripts or compilers.
`--strict-validation` instead rehashes repository and Cargo-cache sources,
mutable path sources, tools, cache entries, root inputs, and artifacts before
reuse. Structural checks, policy, admission identity, and resource limits are
never disabled.

`--bundle` packages the selected harnesses and required package binary into a
single target-native self-extracting executable. Bundle arguments are sent to
every harness and all harness failures are aggregated.

Build output is owned by Lorry and stored below the chosen target directory's
`lorry/` subtree. `--target-dir` takes precedence over `CARGO_TARGET_DIR`,
then Cargo's `build.target-dir`, then the workspace's `target` directory.
`build`, `check`, `run`, and `test` accept `-j N` or `--jobs N`.
Positive counts set the worker limit; negative counts subtract from available
CPUs, with at least one worker. `default` uses the available CPU count.
An explicit option overrides `LORRY_JOBS`. Build scripts receive the effective
count as `NUM_JOBS`, and changing it invalidates completed-profile reuse.
Debug root crates and mutable path dependencies use persistent rustc state
below `target/lorry/.incremental/<target-triple>/`; release and immutable
registry units do not use incremental compilation.

Compiled crates.io and Git dependencies, including host procedural-macro
dynamic libraries, are reused from the
per-user cache at `$HOME/.cache/lorry` on Linux and
`/devtools/lorry/cache` on Motor. Mutable path-dependency units remain in
`target/lorry/.cache`; root artifacts, tests, and incremental state are always
project-local. The cache is a performance aid, not a source integrity
authority: ordinary builds trust complete entries atomically published by
Lorry, while `--strict-validation` rehashes their payloads.

The first missing immutable dependency prints `Rebuilding global dependency
cache`; a build after project-local `lorry clean` does not print it when those
dependencies remain cached. User or system `lorry.toml` may override the
default with an absolute path:

```toml
[cache]
directory = "/data/lorry-cache"
```

Lorry creates the configured directory when a build first needs it. Project
`lorry.toml` files cannot redirect the global cache.

```text
lorry clean [--release|-r] [--target TRIPLE]
lorry cache clean
```

Project `clean` removes only selected state below `target/lorry`, so it does
not force immutable dependencies to be recompiled. `lorry cache clean` may be
run outside a package and removes the configured global Lorry cache. It
succeeds when the cache is already absent.

## Tools and agents

For tools and agents, `--lorry-messages` emits Lorry's own errors as one JSON
object per line on stderr. Each `lorry-error` object carries `kind`, `text`,
`file` and `line` when known, `help`, and `exit_code`. Usage errors exit 1,
failures 101, and interrupted operations 130. Pair the option with `-q` to
suppress human progress. Cargo events selected with `--message-format=json`
stay on stdout; programs and test harnesses keep their ordinary output.
For an unattended build, use `lorry -q build --locked --offline
--message-format=json --lorry-messages`. The compile commands never prompt or
download; dependency acquisition and review are explicit `vendor` operations.
The separate streams let an agent read Cargo events on stdout and Lorry
errors on stderr. Successful commands need not emit an own-message event.

Build, check, clippy, run, and test accept `json`, `json-diagnostic-rendered-ansi`, and
their comma-separated combination. Each stream ends with one `build-finished`
event. On run and test it describes compilation, before the child starts;
the child's exit status remains the command's result. Use `test --no-run` to
avoid harness output. As under Cargo, procedural macros can still print text
on stdout during JSON compilation. Fresh units and completed build profiles
replay their warnings and report artifacts with `fresh: true`. Diagnostic
spans and rendered locations refer to actual source files, including the
persistent source views used for immutable dependencies.

Programs and ordinary harnesses receive Cargo package variables and a library
search path containing the target profile, its artifact directories, native
search directories below that profile, and the target's standard library.
Inherited library search paths are preserved. Test bundles retain their
separate execution rules.

## Inspect and check

```text
lorry metadata [--format-version 1] [--manifest-path PATH] [--no-deps]
               [--filter-platform TRIPLE] [--locked|--offline|--frozen]
lorry tree [--manifest-path PATH] [--target TRIPLE]
lorry locate-project [--workspace] [--manifest-path PATH]
                     [--message-format json|plain]
lorry check [-p NAME|PACKAGE_ID] [--manifest-path PATH]
            [--target-dir DIRECTORY] [--target TRIPLE]
            [--workspace] [-q|--quiet] [--keep-going]
            [--all-targets|--lib|--bins|--examples]
            [--bin NAME] [--test NAME]
            [--message-format json|json-diagnostic-rendered-ansi]
lorry clippy [CHECK OPTIONS] [--no-deps] [-- LINT OPTIONS...]
```

`build`, `check`, `clippy`, `run`, `test`, `clean`, `metadata`, and `tree` accept
`--locked`, `--offline`, and `--frozen`; those commands already run offline
and preserve Cargo.lock. Acquisition and admission remain part of `vendor`.

`metadata` emits the Cargo metadata version-1 schema. Omitting
`--format-version` selects version 1 and warns, as Cargo does; `-q` suppresses
that warning. `--no-deps` describes
source targets and declared dependencies without requiring Cargo.lock,
compiler discovery, or dependency preparation. In a workspace it describes
all members, including when invoked with a member manifest. Metadata rejects
package selectors, as Cargo does. Path dependencies below the workspace root are members
too. Source metadata can describe library crate types, development
dependencies, and binary `required-features` outside Lorry's build admission
rules.

Source metadata reads only workspace membership: `members` (which may list
`"."`), `exclude`, and `default-members`. An empty `[workspace]` table is
accepted. Build-only tables, such as profiles and patches, are ignored.
All 16 Cargo package fields can inherit from `workspace.package`; inherited
readme and license-file paths are relative to the member. Explicit
`readme = false` disables discovery. Members and default-members accept
component globs `*`, `?`, and `[...]`; recursive `**` is rejected.
`[lints] workspace = true` inherits Rust, Clippy, and rustdoc settings from
`workspace.lints`; member overrides alongside inheritance are rejected.
Workspace dependencies inherit sources and add member features. Examples and
benches are described, with explicit targets and Cargo's auto-discovery rules;
their compilation remains deferred.

Cargo configuration follows the invocation directory and its parents;
selecting a package or supplying `--manifest-path` does not move that search.
Cargo alias tables are accepted, but aliases are not executed. Project
`lorry.toml` belongs at the workspace root or above it. A member-local file
is rejected with the location to which its settings should move.

`locate-project` emits `{"root":"/absolute/path/Cargo.toml"}`, or the path
alone with `--message-format plain`. The manifest is discovered in the
working directory or its parents, or supplied with `--manifest-path`. Both
with and without `--workspace`, a selected member still locates itself;
workspace-root lookup arrives in milestone 9.

Without `--no-deps`, metadata verifies and resolves the whole workspace against
the complete lock, then publishes stable content-addressed source views needed
by consumers such as rust-analyzer. It accepts Cargo feature flags and filters
reachability separately from feature lists. Admission and execution grants are
unnecessary. Missing sources require explicit fetch; a stale lock requires
vendor. Every metadata form preserves the lock and admission state.

`tree` accepts member and feature selectors and prints the selected target's
resolved normal and build dependency graph
in Cargo's deterministic text form. It includes path and Git identities,
marks procedural macros, groups build dependencies, and uses `(*)` when an
already displayed non-leaf subtree repeats. It emits no color and requires
verified sources without execution admission.

`check` uses the ordinary development dependency plan, then compiles selected
root targets to metadata without linking them. `--all-targets` includes the
library, binaries, integration tests, and test-mode library and binaries;
`--keep-going` continues independent root targets after an error. An explicit
target directory owns a separate `DIRECTORY/lorry/check` profile. The two JSON
message formats produce newline-delimited Cargo-compatible messages on stdout
and keep progress on stderr; the ANSI form changes only rendered diagnostics.

`--bin NAME` or `--test NAME` selects a named binary or integration test plus
its library dependencies. Combining a named selector with `--all-targets`
still checks all supported targets. For rust-analyzer's save checks, `-p`
also accepts the exact Cargo package ID emitted by `metadata`, with an explicit
`--manifest-path` selecting that same package. Mismatched IDs and unknown target
names are rejected before compiler discovery.

`clippy` uses the check planner with the selected rustc's sibling
`clippy-driver`. The driver must embed that exact compiler. Member libraries,
targets, and dependency build scripts are linted; packages outside the
workspace use rustc. `--no-deps` limits linting to the selected package's
primary targets. Trailing arguments, such as `-- -D clippy::needless_return`,
go to Clippy. Manifest Rust and Clippy lint levels and priorities apply.
`clippy --fix` is not supported.

Clippy outputs and incremental state are separate from check's. Fresh units
replay warnings. Configuration discovery follows the driver, including
`.clippy.toml` or `clippy.toml` above the package and `CLIPPY_CONF_DIR`.
Editing a configuration or creating a nearer one invalidates the affected
units. On Motor, the development image supplies the matching driver through
`/devtools/bin/clippy-driver`.

## Vendor dependencies

Ordinary commands never use the network. Populate the configured immutable
repository and create or repair Cargo.lock with:

```sh
lorry vendor
```

Vendoring resolves every member together, including optional, development,
and platform dependencies. It accepts Cargo lock formats 1 through 4 and
preserves an unchanged lock byte-for-byte. Repair retains its existing format;
a fresh lock follows Cargo's member Rust-version thresholds. Resolver 3 prefers
versions compatible with members' declared Rust versions.

`vendor --locked` verifies an existing complete lock without changing its bytes
or moving Git references. `vendor --locked --offline` additionally requires
all resolution inputs and scoped sources to be present. Missing or stale inputs
fail before replacing existing approval.

Normal vendoring reports graph resolution and source verification phases, plus
each Git source, sparse-index entry, and crate archive when its acquisition
starts. `--quiet` suppresses this progress.

Curl diagnostics spill from memory to a private temporary file and are limited
to 2 MiB by default. `LORRY_CURL_STDERR_SPILL_LIMIT_BYTES` may raise that limit
for unusually verbose environments; its value is an integer byte count of at
least 2097152.

Review lists each locked registry/Git package once with its member users,
checksum or exact Git source, dependencies, verified evidence, and feature
contexts. Source and capability changes are summarized. Packages outside the
scoped closure are labeled explicitly.
Interactive approval is required whenever the complete candidate differs from
committed admission, even if its immutable objects already exist.
`--accept-all` approves every policy-compliant dependency and capability
change, but it cannot bypass integrity checks, policy denials, redirect trust,
or native-tool restrictions.

`src/tests/full-test.sh` does not run Lorry tests. Test selection and VM-image
coverage are contributor-validation concerns described by `AGENTS.md`; they
do not change Lorry command behavior.

Commit Cargo.lock and the generated `.lorry/` dependency state with the
project. Do not edit files below `.lorry/`; Lorry writes them deterministically.

`vendor --lorry-messages` emits `lorry-vendor-change` on stderr, including
package/source and capability additions/removals, the prior commitment and
whether its review was reconstructed, and the complete canonical candidate.
Human and machine modes use the same confirmation rules. `--accept-all`
permits automation; an unapproved nonterminal review fails without waiting.

## Fetch locked sources

```sh
lorry fetch --locked
lorry fetch --locked --target x86_64-unknown-motor
```

Fetch acquires the complete lock by default, or the requested target's closure
with host build-time dependencies. It preserves the lock and approval bytes,
uses exact locked Git commits, and requires no execution grants. It never runs
package code. Explicit source denials and resource limits still apply.
`--offline` verifies existing inputs; `--frozen` combines locked and offline.
Targeted fetch retains complete resolution inputs, but full metadata can still
need sources outside that target closure.

The ordinary complete-graph limit is 64 outside packages. The developer image
uses 384; `--max-packages N` overrides it for one command subject to system
constraints. A scoped review does not reduce complete resolution or its cap.
Dependency depth has no default cap, matching Cargo. An explicit
`policy.limits.max-depth` imposes an optional bound on resolution and review.

## Compact dependency review

Build, run, test, and vendor use compact generated state at
the workspace root's `.lorry/dependencies-v2.toml`. The compact file contains
a SHA-256 commitment, normalized member/feature scope, explicitly reviewed
`(host, target)` contexts, and exceptional
execution capabilities such as build-script, procedural-macro, or native-tool
grants:

```toml
format-version = 3
review-format-version = 4
review-sha256 = "..."

[review-scope]
packages = []
features = []
all-features = false
no-default-features = false

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"
```

The hash commits to a deterministic canonical review document reconstructed
from Cargo.toml, Cargo.lock, verified repository objects, and the compact
capabilities. It omits raw member dependency declarations and feature tables,
and records every locked registry/Git node and edge, the selected features in
each build context, verified source evidence, and explicit execution grants. It is not
checked in, because doing so would recreate the large synchronized state that
the compact format removes.

Compilation using registry/Git dependencies requires a reviewed host/target
pair. It reconstructs every recorded context, verifies the commitment, then checks the requested
graph's package/feature coverage, including on cache hits. Reviewed Motor
contexts require a Motor-capable rustc even for host-only builds. Cargo.lock
remains the graph authority, repository objects remain the source-integrity
authority, and explicit policy denials continue to override committed
admission. The compact commitment is not a signature; authorization against
an untrusted committer would require a separate signing design.

The first vendor review covers the whole workspace with default features and
all supported target kinds. Later member or feature selectors replace that
scope as a whole. Plain vendor repeats the stored scope; operational flags
do not reset it. `vendor --locked --workspace` restores the whole-workspace
default scope. Unused local feature declarations do not invalidate approval.
Legacy member records require explicit root review; only records replaced by
the accepted scope are then removed.

The offline, non-mutating `lorry review` command reconstructs the committed
document, verifies its hash, and writes exact canonical TOML to stdout:

```sh
lorry review > dependency-review.toml
```

CI can retain this file as a review artifact, and retained reports can be
compared with ordinary tools such as `diff`. The command fails before writing
stdout if state, resolution, evidence, or the commitment is stale.

## Upgrade a dependency

Cargo.toml remains the only dependency file intended for human editing. Lorry
records the reviewed contexts, capabilities, and review commitment in
`.lorry/dependencies-v2.toml`. That file is an admission record, not another
version requirement.

Upgrade a direct dependency by editing its requirement and vendoring:

```sh
# Edit libc's requirement in Cargo.toml.
lorry vendor
```

Lorry independently resolves and updates Cargo.lock, acquires and verifies new
sources, shows the previous admission commitment and complete candidate for
review, and updates `.lorry` state after interactive approval. Compatible
unrelated locked packages are preserved. Offline graph commands remain
read-only and reject the edited manifest until vendoring completes.

The explicit upgrade form selects only a transitive locked crates.io package
when its dependency requirements permit the requested version. If Cargo.lock
contains more than one version of that package, disambiguate it as
`NAME@OLD_VERSION`:

```sh
lorry vendor upgrade transitive-name@1.2.3 --to 1.2.4
```

If another tool has already changed Cargo.lock, ordinary `lorry vendor`
reproduces, verifies, reviews, and reconciles that graph; it does not treat the
other tool's output as approval. Until vendoring succeeds, build/run/test fail
with a diagnostic like:

```text
error: dependency admission state is stale

Cargo.lock selects libc 0.2.187, but Lorry approved libc 0.2.186.
Review and adopt the change with:
  lorry vendor
```

Restore Cargo.toml and Cargo.lock to the old version if the change was not
intentional.

Dependency changes to an existing admission record require one interactive
confirmation of the displayed identity and capability changes. In automation,
`--accept-all` approves the complete policy-compliant candidate without a
prompt.

## Toolchains and targets

A leading rustup-style selector chooses an installed compiler on Linux:

```sh
lorry +motor-1.99.0-beta-f47d5bb-dev.2-<full-toolchain-key> build
lorry +motor-1.99.0-beta-f47d5bb-dev.2-<full-toolchain-key> \
  build --target x86_64-unknown-motor
```

Without a selector, `RUSTC` takes precedence over `rustc` from `PATH` on
Linux. Motor OS normally uses `/devtools/bin/rustc`. Only installed
target triples are supported; custom JSON targets are rejected.

Lorry supports only Cargo compiler-identity compatibility family 1.99, the
family selected by the current Motor Rust toolchain. It infers that family
from a Rust 1.99 compiler. Installation configuration must set
`cargo-compat-version = "1.99"` for an equivalent custom or unpaired
toolchain; older and newer families are rejected until Lorry and the Motor
toolchain advance together.

Cross-target run and test require a configured target runner. Lorry executes
the runner as an argument vector and never through a shell.

`RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` use Cargo-compatible precedence.
Rust compiler wrappers are unsupported.

## Configuration and repositories

Normal package authors do not need a project `lorry.toml`. Installation
configuration supplies repository locations, compiler policy, network tools,
test extraction roots, the global cache location, and approved native tools.
Linux reads the user Lorry configuration below `$HOME/.config/lorry`; Motor OS
layers system and user configuration below `/devtools/cfg` and
`/user/cfg`.

Repository lookup order is local, user, then system. System repositories are
read-only. Vendoring writes the configured local repository, or the user
repository when no local repository exists. Repository objects are immutable,
content-addressed, and fully verified before publication. Ordinary builds
trust their bounded metadata and recorded digests; `--strict-validation`
rehashes retained archive and source contents before use.

The global `--use-cargo-registry` option is a special offline compatibility
mode for build, check, run, test, metadata, and tree. Its first use verifies
Cargo's already populated archive/source cache and atomically records Lorry
evidence below `target/lorry/.cargo-evidence`; later ordinary builds trust
Cargo's completion marker and that evidence. Strict validation performs the
archive/source comparison again. Lorry never fetches or repairs this cache,
and it is not the normal Lorry repository workflow.

## Git dependencies and patches

`lorry vendor` supports direct Git dependencies and root
`[patch.crates-io]` Git entries on Linux and Motor OS. Lorry uses its embedded
gix client with the configured curl executable; it never invokes a `git`
executable. Git transport is anonymous canonical HTTPS with credential,
proxy, hook, filter, and ambient Git configuration disabled.

A direct Git dependency must already have an exact 40-hex commit in
Cargo.lock. Its branch, tag, `rev`, or default-HEAD selector remains update
intent, while the locked commit is the immutable identity. Lorry supports
renaming, version requirements, features, optional and target-conditioned
direct dependencies, and multiple packages selected from one repository. It
stores the verified snapshot below:

```text
.lorry/vendor/git/<cargo-source-sha256>/source
```

A root Git patch may select a branch, tag, revision, or default HEAD. Its
package must already have a matching exact Git source in Cargo.lock. Vendoring
uses that commit as the immutable identity and stores the verified snapshot in
the same content-addressed layout as a direct Git dependency:

```text
.lorry/vendor/git/<cargo-source-sha256>/source
```

The patch remains a first-class Git source throughout resolution, review, and
lock rendering. Lorry never modifies an input workspace or member Cargo.toml;
legacy explicit path patches continue to use their declared paths.

Every networked `lorry vendor` checks mutable Git-patch selectors: default
HEAD, branches, tags, and named `rev` references. Full or abbreviated
hexadecimal commit `rev` values remain pinned. If a selector moves, or a
locked Git object needs first materialization, Lorry verifies every candidate
and presents one combined dependency and capability review; moved tags carry
an explicit retargeting warning. Interactive approval defaults to no and is
requested exactly once. Non-interactive changed runs fail unless
`--accept-all` approves the complete policy-compliant candidate.

Both forms use a shallow fetch and record the canonical URL, requested
selector, commit, Git tree, canonical source digest, file count, and byte
count. Materialization accepts only bounded regular files and directories;
submodules and symbolic links are rejected. Offline graph commands verify the
materialized source and provenance before use.

## Package build-script security

Cargo package `build.rs` programs are part of Lorry's supported package model;
they are unrelated to OS image-build scripts. On Linux, dependency build
scripts run without network access, with read-only
sources and toolchains, a cleared environment, and writes limited to their
private output and temporary directories. Child tools require explicit
compiler or archiver grants.

Motor OS currently prints an explicit warning and runs build scripts without
that isolation. Do not interpret the warning mode as sandboxed.

## Procedural macros

A dependency crate may declare `[lib] proc-macro = true`. Lorry compiles that
crate and its dependency closure for the compiler host, keeps resolver-2/3
host features separate from target features, and passes the resulting host
artifact to rustc. Linux rustc uses its ordinary dynamic-library artifact.
Motor rustc uses a static PIE executable and exchanges the existing private
proc-macro bridge messages with it over framed stdin/stdout. Selecting a
procedural-macro crate itself as the root package remains unsupported.

Procedural macros execute dependency code inside rustc and therefore require
an explicit matching policy rule:

```toml
[policy.rules.example-derive]
action = "allow"
name = "example-derive"
source = "crates.io"
allow-proc-macro = true
```

Vendoring records the exact grant in compact admission state. Proc macros
inherit the rustc process authority; the Motor executable transport is process
separation, not a sandbox. A Linux-to-Motor build still uses a Linux dynamic
library because procedural macros always run on the compiler host.

## Global options and status codes

```text
-q, --quiet
-v, --verbose  # commands, configuration, and elapsed phase timings
    --color auto|always|never
    --use-cargo-registry
```

For `build`, `run`, and `test`, verbose timing records use a monotonic clock.
The timestamp is elapsed time since command dispatch; the parenthesized value
is the duration of the preceding phase.

Global options precede the command. Long value options accept `--name value`
and `--name=value`.

Command-line usage errors return 1. Build, vendoring, policy, and operational
failures return 101. Help and version return 0. Run and test return the
executed program or harness status; POSIX interruption returns 130 where the
platform supports it.
