# Lorry

Lorry is Motor OS's small, strict Rust package builder. It creates, vendors,
builds, runs, and tests a deliberately limited Cargo-compatible package model
on Linux and Motor OS. Unsupported Cargo behavior is rejected explicitly.

Lorry never invokes Cargo during normal operation. Builds are offline and use
only verified sources already present in configured Lorry repositories.

## Operational and validation boundaries

Normal Lorry operation consumes a package's `Cargo.toml` and `Cargo.lock`, the
supported parts of Lorry and Cargo configuration, a rustc toolchain, and
configured Lorry repositories. `lorry vendor` additionally uses the configured
curl executable and sparse registry. With the explicit `--use-cargo-registry`
option, build, run, and test may instead verify and read an already populated
local Cargo archive/source cache. Lorry records its evidence on first use and
trusts that evidence during later ordinary builds. None of these operations
invokes Cargo.

The `bootstrap/` directory is an OS-packaging utility, not part of the Lorry
executable. Motor's toolchain build uses it to preinstall an offline system
repository and system configuration so the shipped development environment
can rebuild Lorry and curl. Lorry can operate with other correctly configured
repositories; it does not create VM images or inspect image profiles/layouts.

Everything called a Cargo "oracle" is validation-only: tests run supported
Cargo versions or compare retained Cargo results to check Lorry compatibility.
Oracle fixtures are not runtime inputs, repositories, caches, or fallback
implementations. VM profiles, dedicated images, guest-layout assertions, and
self-host generations likewise belong to the test harness under `tests/` and
`src/tests/`, not to normal Lorry operation.

## Package requirements

Run Lorry from the directory containing the package's `Cargo.toml`. Lorry does
not search parent directories and does not support workspaces or
`--manifest-path`.

A supported package has:

- one root package;
- at most one library and one binary;
- optional top-level `tests/*.rs` integration tests;
- a current Cargo.lock version 4, including for dependency-free packages; and
- only supported crates.io and local-path dependency declarations.

The supported dependency model includes renamed and optional dependencies,
default and forwarded features, target-conditioned dependencies, dependency
build scripts, and configured required local patches. Root build scripts must
be dependency-free. Direct Git dependencies, alternative registries,
procedural macros, root build/dev dependencies selected for the build target,
examples, benches, explicit test targets, multiple binaries, and CLI feature
selection are not supported. A target-conditioned root dev-dependency for a
different target is ignored.

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
lorry build [--release|-r] [--target TRIPLE] [--strict-validation]
lorry run   [--release|-r] [--target TRIPLE] [--strict-validation] [-- ARGS...]
lorry test  [--release|-r] [--target TRIPLE] [--strict-validation]
            [--test NAME] [--no-run] [--bundle] [-- ARGS...]
```

Examples:

```sh
lorry build --release
lorry run -- one "two words"
lorry test
lorry test --test cli -- --nocapture
lorry test --bundle --no-run
```

`run` returns the program's status. Ordinary tests build separate library,
binary, and integration-test harnesses, then run them in order and stop at the
first failure. `--test NAME` selects one integration test. `--no-run` prints
the built harness paths.

Ordinary builds trust previously published per-user dependency and
project-local artifact state, matching Cargo's local-cache model. An unchanged
`build` or `run` checks parsed inputs and root/path-source size and modification
metadata, then accepts the existing profile before reopening dependency
repositories.
`--strict-validation` instead rehashes repository and Cargo-cache sources,
mutable path sources, tools, cache entries, root inputs, and artifacts before
reuse. Structural checks, policy, admission identity, and resource limits are
never disabled.

`--bundle` packages the selected harnesses and required package binary into a
single target-native self-extracting executable. Bundle arguments are sent to
every harness and all harness failures are aggregated.

Build output is owned by Lorry and stored below `target/lorry`. Setting
`CARGO_TARGET_DIR` or Cargo's `build.target-dir` is an error.
Debug root crates and mutable path dependencies use persistent rustc state
below `target/lorry/.incremental/<target-triple>/`; release and immutable
registry units do not use incremental compilation.

Compiled crates.io dependencies and reviewed required-patch dependencies are
reused from the per-user cache at `$HOME/.cache/lorry` on Linux and
`/user/cfg/lorry/cache` on Motor. Mutable path-dependency units remain in
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

## Vendor dependencies

Build, run, and test never use the network. Populate the configured immutable
repository and create or repair Cargo.lock with:

```sh
lorry vendor
```

New packages are displayed with their exact version, checksum, license,
build-script status, sizes, and new dependency edges. Interactive approval is
required unless every candidate already exists. `--accept-all` approves all
policy-compliant packages, but it cannot bypass integrity checks, policy
denials, redirect trust, or native-tool restrictions.

`src/tests/full-test.sh` does not run Lorry tests. Test selection and VM-image
coverage are contributor-validation concerns described by `AGENTS.md`; they
do not change Lorry command behavior.

Commit Cargo.lock and the generated `.lorry/` dependency state with the
project. Do not edit files below `.lorry/`; Lorry writes them deterministically.

## Compact dependency review

Build, run, test, and vendor use compact generated state at
`.lorry/dependencies-v2.toml`. The compact file contains a SHA-256
commitment, explicitly reviewed `(host, target)` contexts, and exceptional
execution capabilities such as build-script or native-tool grants:

```toml
format-version = 2
review-format-version = 1
review-sha256 = "..."

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"
```

The hash commits to a deterministic canonical review document reconstructed
from Cargo.toml, Cargo.lock, verified repository objects, and the compact
capabilities. That document records direct dependency semantics, every locked
registry node and edge, the packages and features selected in each build
context, verified source evidence, and explicit execution grants. It is not
checked in, because doing so would recreate the large synchronized state that
the compact format removes.

Build, run, and test require their exact host/target pair to be reviewed and
verify the commitment for every recorded context before generating dependency
allow rules or compiling anything. Because motor contexts are recorded, these
commands need a Motor-capable rustc even for host-only builds. Cargo.lock
remains the graph authority, repository objects remain the source-integrity
authority, and explicit policy denials continue to override committed
admission. The compact commitment is not a signature; authorization against
an untrusted committer would require a separate signing design.

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
unrelated locked packages are preserved. Build, run, and test remain read-only
and reject the edited manifest until vendoring completes.

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
confirmation of the displayed identity and capability changes. `--accept-all`
cannot approve them.

## Toolchains and targets

A leading rustup-style selector chooses an installed compiler on Linux:

```sh
lorry +nightly build
lorry +dev-x86_64-unknown-motor build --target x86_64-unknown-motor
```

Without a selector, `RUSTC` takes precedence over `rustc` from `PATH` on
Linux. Motor OS normally uses `/sys/tools/rust/bin/rustc`. Only installed
target triples are supported; custom JSON targets are rejected.

Lorry supports Cargo compiler-identity compatibility families 1.97, 1.98,
and 1.99. It infers the family from a conventionally paired rustc. Installation
configuration must set `cargo-compat-version` for a custom or unpaired
toolchain.

Cross-target run and test require a configured target runner. Lorry executes
the runner as an argument vector and never through a shell.

`RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` use Cargo-compatible precedence.
Rust compiler wrappers are unsupported.

## Configuration and repositories

Normal package authors do not need a project `lorry.toml`. Installation
configuration supplies repository locations, compiler policy, network tools,
test extraction roots, the global cache location, and approved native tools.
Linux reads the user Lorry configuration below `$HOME/.config/lorry`; Motor OS
layers system and user configuration below `/sys/tools/rust/cfg` and
`/user/cfg`.

Repository lookup order is local, user, then system. System repositories are
read-only. Vendoring writes the configured local repository, or the user
repository when no local repository exists. Repository objects are immutable,
content-addressed, and fully verified before publication. Ordinary builds
trust their bounded metadata and recorded digests; `--strict-validation`
rehashes retained archive and source contents before use.

The global `--use-cargo-registry` option is a special offline compatibility
mode for build, run, and test. Its first use verifies Cargo's already populated
archive/source cache and atomically records Lorry evidence below
`target/lorry/.cargo-evidence`; later ordinary builds trust Cargo's completion
marker and that evidence. Strict validation performs the archive/source
comparison again. Lorry never fetches or repairs this cache, and it is not the
normal Lorry repository workflow.

## Git patch workflow

Build, run, and test reject an unmaterialized root `[patch.crates-io]` Git
entry and tell you to run `lorry vendor`. On Linux, vendor can fetch one
anonymous canonical HTTPS Git patch pinned by an optional branch, tag, or
revision. It displays the resolved commit, Git tree, source digest, file count,
and byte count before approval, then rewrites only that patch to:

```text
.lorry/vendor/<patch>/source
```

Motor OS does not run Git. Materialize the patch on Linux, then copy both the
rewritten project and the populated Lorry repository to Motor OS. Direct Git
dependencies remain unsupported.

## Package build-script security

Cargo package `build.rs` programs are part of Lorry's supported package model;
they are unrelated to OS image-build scripts. On Linux, dependency build
scripts run without network access, with read-only
sources and toolchains, a cleared environment, and writes limited to their
private output and temporary directories. Child tools require explicit
compiler or archiver grants.

Motor OS currently prints an explicit warning and runs build scripts without
that isolation. Do not interpret the warning mode as sandboxed.

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
