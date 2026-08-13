# Lorry design

This document explains the structure and invariants of the current Lorry
implementation. `README.md` is the user guide. `spec.md` is the normative
behavioral contract. This document describes how the implementation realizes
that contract.

## Design goals

Lorry is deliberately smaller than Cargo. Its design favors a closed package
model, deterministic inputs, explicit rejection, verified immutable sources,
and direct `rustc` execution. It must run on both Linux and Motor OS without
making Cargo an operational dependency.

Three boundaries organize the implementation:

1. Parsing turns CLI, TOML, lockfiles, configuration, and repository metadata
   into bounded typed data. Unsupported behavior is rejected here.
2. Planning resolves packages and features, applies policy, and creates a
   complete compilation plan without executing package code.
3. Execution prepares verified sources, runs approved build scripts and native
   tools, invokes `rustc`, verifies outputs, and publishes cache entries.

The build path is offline. Network access exists only in `vendor`, and source
objects do not become usable merely because they were downloaded.

## Main control flow

`main.rs` parses the CLI and dispatches to one of four areas:

- `new_package` creates a minimal binary package and version-4 lockfile;
- `review` reconstructs and verifies the committed canonical dependency
  review without mutating project or repository state;
- `vendor` resolves, acquires, verifies, reviews, and publishes dependency
  sources and generated dependency state; or
- `engine` implements build, run, and test.

For build, run, and test, `engine` performs these operations in order:

1. reject an unfinished dependency-upgrade transaction;
2. load and validate `Cargo.toml`, `Cargo.lock`, and generated admission state;
3. merge Lorry and Cargo configuration and discover the compiler/target;
4. resolve the selected locked graph and verify it offline;
5. prepare source trees and perform the second policy pass with full evidence;
6. create compilation units and their dependency order;
7. compile or restore eligible library/build-script results from cache;
8. link root executables or test harnesses; and
9. run, print, or bundle outputs according to the command.

No build operation repairs dependency metadata or performs acquisition.

## Input model

`manifest.rs` owns the supported Cargo manifest subset and default target
discovery. `toml.rs` wraps TOML parsing with byte, nesting, and node limits and
retains source locations for diagnostics. `config.rs` merges the supported
Lorry and Cargo configuration layers while enforcing which layer may control
security-sensitive settings. `toolchain.rs` discovers `rustc`, identifies the
Cargo-compatibility family, and evaluates target `cfg` expressions.

The root is one package, with at most one library, one binary, and discovered
top-level integration tests. Dependency manifests are parsed through a wider
but still explicit subset needed to compile the selected graph. Recognized
metadata is inert; unknown build semantics are errors.

`Cargo.lock` version 4 is the interoperability format. Builds require it to be
present and current. Vendoring may create or repair it. Lorry renders the
complete all-target lock graph, then separately computes the union of closures
selected for configured vendor targets.

Cargo compatibility is an explicit family (`1.97`, `1.98`, or `1.99`), either
inferred from a paired rustc or supplied by installation configuration. The
family selects Cargo-shaped compiler identity behavior and is part of every
build-cache key, so adding support requires Cargo invocation, identity, and
resolution oracles rather than only accepting a new version string.

## Resolution and source identity

`resolver.rs` implements the supported Cargo resolver behavior. The catalog
contains crates.io records and local candidates. Lockfile identities are
preferences, not unconditional choices: requirements, target predicates,
features, Rust versions, checksums, patches, links uniqueness, graph depth,
and package limits still apply.

Every package has a logical identity independent of its installation path:

- crates.io packages use name, semantic version, and archive checksum;
- ordinary paths use their canonical source-tree digest; and
- required patches use configured upstream and patched-tree provenance.

Repository source paths are physical storage details. Compiler path remapping
presents stable `.lorry/...` logical paths so equivalent builds do not acquire
host-specific source names.

## Repositories and vendoring

`repository.rs` implements layered immutable content-addressed repositories.
Lookup verifies object metadata and retained content. Writers stage complete
objects privately and publish with no replacement; an existing different
object at the same identity is corruption.

The ordinary vendor flow is:

1. take the project vendor lock;
2. materialize a supported Linux Git patch if one is still declared;
3. load sparse index data on demand and resolve the complete/selected graphs;
4. run policy preflight before archive acquisition;
5. download missing archives with the bounded curl client;
6. verify checksum, archive structure, manifest identity, license, sizes, and
   canonical source-tree digest;
7. show the candidate review and newly acquired packages and obtain approval;
8. publish immutable repository objects and the lockfile; and
9. write `.lorry/dependencies-v2.toml` last from the committed graph.

`curl.rs`, `redirect.rs`, `archive.rs`, `sparse.rs`, and `source_tree.rs`
implement the acquisition boundary. Redirect trust is separate from package
admission. A trusted site cannot bypass checksum or policy checks.

## Generated dependency admission

`.lorry/dependencies-v2.toml` is committed, deterministic machine-owned state.
It records only:

- the SHA-256 commitment to the canonical review document specified in
  `step-8-review.md`;
- the reviewed `(host, target)` build contexts; and
- the explicit build-script and native-tool capability grants.

The canonical review document itself is reconstructed, never stored: its
direct semantics come from Cargo.toml, its locked graph from Cargo.lock, its
per-context selections from offline resolution, and its source evidence from
verified repository objects. Path dependencies and required patches remain
governed by their source digests and configured policy rather than being
copied into registry admission.

At build time `engine.rs` requires the discovered host and selected target to
be an exact reviewed context, and `dependency.rs` reconstructs the canonical
document for every recorded context and compares its digest with the
commitment. Only then does `admission_state.rs` translate reconstructed
evidence and explicit capabilities into exact generated allow rules. Policy
evaluation still considers every matching explicit deny, so a generated allow
cannot override administrator policy, required patches, resource limits,
integrity checks, or unavailable native-tool grants. Repository lookup during
reconstruction is inspection, not admission: nothing compiles or enters a
build cache until the commitment and policy both pass. Each repository object
is content-verified once per process: `RepositorySet` remembers the objects
it has verified, which is sound because objects are content-addressed and
never replaced in place, and every new process re-verifies from disk.

Projects with no generated state use the configured-policy compatibility path.
Their next successful ordinary vendor operation creates state.

## Dependency upgrades

`vendor upgrade PACKAGE --to VERSION` creates a candidate manifest in memory.
For a direct crates.io dependency, `upgrade.rs` replaces only the TOML source
span of its version value; the visible manifest is untouched during review. A
transitive selection may use `NAME@OLD_VERSION` when Cargo.lock contains more
than one version.

The resolver removes only the selected old transitive lock preference, adds
the requested exact version preference, and retains unrelated preferences. A
direct exact requirement itself forces its new version. The resulting graph
must actually contain the requested identity.

Upgrade review temporarily supplies exact candidate allow rules so full
evidence can be collected under default-deny policy. Explicit denies and all
other constraints remain active. The review shows requirement, locked graph,
admission evidence, build-script, and native-tool changes. `--accept-all` is
not accepted for upgrades; one interactive confirmation authorizes the shown
identity and capability changes.

The visible commit uses `.lorry/transactions/dependency-upgrade-v1`:

1. stage the candidate manifest, lockfile, state, and a bounded exact-key
   journal;
2. record original and candidate SHA-256 identities and fsync the staging;
3. publish already verified immutable repository objects;
4. install Cargo.toml, Cargo.lock, then admission state; and
5. remove and persist the transaction directory.

The state file is the commit marker. Build/run/test refuse to proceed while
the journal exists. Repeating the identical upgrade validates every staged and
current identity and completes only missing replacements. A different command
or external edit stops recovery.

`vendor upgrade --from-cargo-lock` uses the same review and transaction but
does not add version intent. Cargo.lock versions remain resolver preferences;
Lorry independently reproduces and verifies the supported graph.

## Policy and package code

`policy.rs` has two passes. Preflight uses facts known from resolution to
reject definite denials and impossible admission before expensive work.
Inspection adds license, source-tree, archive, file-count, build-script, and
other evidence and requires the exact graph to be unchanged between passes.

Build scripts are compiled as host units. `build_script.rs` accepts a bounded
subset of Cargo directives and constructs a cleared, explicit environment.
`native_tool.rs` exposes only configured compiler/archiver roles and includes
their identities and arguments in build/cache identity. Linux applies the
filesystem/network/process sandbox in `sandbox.rs`. Motor currently warns and
runs the same logical contract without isolation.

## Compilation, cache, tests, and bundles

`unit.rs` converts a resolved graph into ordered host/target compilation
units. `identity.rs` and `compile.rs` reproduce the supported Cargo rustc
argument and metadata conventions. `executor.rs` validates inputs, invokes
children without a shell, and verifies expected outputs.

`cache.rs` stores only verified library artifacts and build-script results.
Cache keys include normalized compiler inputs, sources, dependencies,
configuration, native tools, and build-script observations. Root linked
executables, harnesses, bundle launchers, and build-script executables are
rebuilt. Cache publication is atomic/no-replace; corruption is quarantined
inside Lorry's target tree, while repository corruption is fatal.

Ordinary tests remain separate Rust harnesses. `bundle.rs` creates one
target-native self-extracting executable containing the selected harnesses and
required package binary. The launcher verifies its payload table and extracts
only beneath its configured private root.

## Platform boundary and bootstrap

Platform-specific behavior is kept narrow: compiler discovery, runner
configuration, atomic no-replace publication, filesystem permissions, process
sandboxing, and Motor runtime support. The Lorry crate otherwise uses standard
Rust and `src/sys/lib` Motor APIs.

The bootstrap directory creates the immutable system seed used before Lorry
can vendor for itself. Its manifest is the union of the Lorry and curl lock
graphs plus separately reviewed patched Git objects and Cargo-oracle-only
objects. Bootstrap tests derive graph membership from the lockfiles so version
changes cannot leave stale membership such as a dependency appearing only in
the curl graph.

## Where to change behavior

- CLI syntax and command applicability: `cli.rs`, then `main.rs` help.
- Cargo manifest/lock compatibility: `manifest.rs`, `lockfile.rs`.
- dependency selection: `resolver.rs`, `patch.rs`.
- generated admission and upgrades: `admission_state.rs`, `upgrade.rs`,
  `vendor.rs`.
- configuration or policy: `config.rs`, `policy.rs`.
- source acquisition/integrity: `curl.rs`, `archive.rs`, `repository.rs`,
  `source_tree.rs`.
- compiler behavior or cache identity: `unit.rs`, `compile.rs`, `identity.rs`,
  `executor.rs`, `cache.rs`.
- test execution/bundling: `engine.rs`, `bundle.rs`.

Behavioral changes must update the user README when workflow changes, the
technical spec when the contract changes, and this design when an invariant or
component boundary changes.
