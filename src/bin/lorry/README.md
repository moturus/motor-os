# Lorry

Lorry is Motor OS's small, strict Rust package builder. It creates, vendors,
builds, runs, and tests a deliberately limited Cargo-compatible package model
on Linux and Motor OS. Unsupported Cargo behavior is rejected explicitly.

Lorry never invokes Cargo during normal operation. Builds are offline and use
only verified sources already present in configured Lorry repositories.

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
procedural macros, root build/dev dependencies, examples, benches, explicit
test targets, multiple binaries, and CLI feature selection are not supported.

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
lorry build [--release|-r] [--target TRIPLE]
lorry run   [--release|-r] [--target TRIPLE] [-- ARGS...]
lorry test  [--release|-r] [--target TRIPLE]
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

`--bundle` packages the selected harnesses and required package binary into a
single target-native self-extracting executable. Bundle arguments are sent to
every harness and all harness failures are aggregated.

Build output is owned by Lorry and stored below `target/lorry`. Setting
`CARGO_TARGET_DIR` or Cargo's `build.target-dir` is an error.

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

Lorry's repository integration gate is standalone; `src/tests/full-test.sh`
does not run Lorry tests.

Commit Cargo.lock and the generated `.lorry/` dependency state with the
project. Do not edit files below `.lorry/`; Lorry writes them deterministically.

## Compact dependency review (Step 8)

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

A planned offline, non-mutating `lorry review` command will reconstruct the
committed document, verify its hash, and write its exact canonical TOML to
stdout so CI can retain it as a review artifact and two retained reports can
be compared with ordinary tools such as `diff`.

## Upgrade a dependency

Cargo.toml remains the only dependency file intended for human editing. Lorry
records the reviewed contexts, capabilities, and review commitment in
`.lorry/dependencies-v2.toml`. That file is an admission record, not another
version requirement.

Upgrade an exact direct dependency with one command:

```sh
lorry vendor upgrade libc --to 0.2.187
```

The command may update the dependency's Cargo.toml version, independently
resolve and update Cargo.lock, acquire and verify new sources, show the graph
and security-relevant difference, and update `.lorry` state after approval.
Compatible unrelated locked packages are preserved.

The same form can select a transitive locked package when its dependency
requirements permit the requested version. If Cargo.lock contains more than
one version of that package, disambiguate it as `NAME@OLD_VERSION`:

```sh
lorry vendor upgrade transitive-name@1.2.3 --to 1.2.4
```

You may instead edit Cargo.toml first and run the same command. If
`cargo update` has already changed Cargo.lock, review the Cargo-selected graph
with:

```sh
lorry vendor upgrade --from-cargo-lock
```

Lorry reproduces and verifies that graph; it does not treat Cargo's output as
approval. Until the explicit upgrade succeeds, build/run/test fail with a
diagnostic like:

```text
error: dependency admission state is stale

Cargo.lock selects libc 0.2.187, but Lorry approved libc 0.2.186.
Review and adopt the change with:
  lorry vendor upgrade libc --to 0.2.187
```

Restore Cargo.toml and Cargo.lock to the old version if the change was not
intentional. An unfinished upgrade is recorded below `.lorry/transactions`;
rerun the identical command to validate and complete it. Lorry never builds
while such a transaction is unfinished.

Dependency upgrades require one interactive confirmation of the displayed
identity and capability changes. `--accept-all` is intentionally unavailable
for upgrade commands.

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
test extraction roots, and approved native tools. Linux reads the user Lorry
configuration below `$HOME/.config/lorry`; Motor OS layers system and user
configuration below `/sys/tools/rust/cfg` and `/user/cfg`.

Repository lookup order is local, user, then system. System repositories are
read-only. Vendoring writes the configured local repository, or the user
repository when no local repository exists. Repository objects are immutable,
content-addressed, and fully verified before every use.

The global `--use-cargo-registry` option is a special offline compatibility
mode for build, run, and test. It verifies and uses Cargo's already populated
archive/source cache at Cargo's physical paths. It never fetches or repairs
that cache and is not the normal Lorry repository workflow.

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

## Build-script security

Linux dependency build scripts run without network access, with read-only
sources and toolchains, a cleared environment, and writes limited to their
private output and temporary directories. Child tools require explicit
compiler or archiver grants.

Motor OS currently prints an explicit warning and runs build scripts without
that isolation. Do not interpret the warning mode as sandboxed.

## Global options and status codes

```text
-q, --quiet
-v, --verbose
    --color auto|always|never
    --use-cargo-registry
```

Global options precede the command. Long value options accept `--name value`
and `--name=value`.

Command-line usage errors return 1. Build, vendoring, policy, and operational
failures return 101. Help and version return 0. Run and test return the
executed program or harness status; POSIX interruption returns 130 where the
platform supports it.
