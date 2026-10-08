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

`main.rs` parses the CLI and dispatches to command-specific modules:

- `new_package` creates a minimal binary package and version-4 lockfile;
- `clean` removes project-local artifacts and `cache_clean` removes the
  per-user dependency cache;
- `review` reconstructs and verifies the committed canonical dependency
  review without mutating project or repository state;
- `fetch` acquires exact locked sources without execution admission;
- `vendor` resolves, acquires, verifies, reviews, and publishes dependency
  sources and generated dependency state;
- `metadata` and `tree` describe the locked workspace without execution
  admission; or
- `engine` implements build, check, Clippy, run, and test.

The engine, `metadata`, and `tree` open the locked workspace through one
shared setup, `dependency::LockedContext`. It holds the registry source, the
locked Git sources, and the resolver options. The registry source is Cargo's
cache or Lorry repositories; `cargo_registry::selected` chooses it. A command
that finds Cargo's cache lacking reports a marked error, and
`cargo_registry::with_fallback` runs it again with Lorry repositories unless
the command line asked for Cargo's cache.

For build, run, and test, `engine` performs these operations in order:

1. load and validate `Cargo.toml` and `Cargo.lock`, merge Lorry and Cargo
   configuration, choose the registry source, and load generated admission
   state when the source is Lorry repositories;
2. discover the compiler/target;
3. for an unchanged build, run, or plain check, reuse a completed profile
   whose record matches, and stop;
4. with Lorry repositories, reconstruct and verify the root admission scope
   and requested coverage;
5. resolve the selected locked graph and verify source and policy evidence;
6. create compilation units and their dependency order;
7. compile or restore eligible library, procedural-macro, and build-script
   results from cache;
8. link root executables or test harnesses; and
9. run, print, or bundle outputs according to the command.

No build operation repairs dependency metadata or performs acquisition.

Ordinary builds use Cargo's local trust boundary for previously published
repository, cache, and artifact state. `--strict-validation` selects complete
content verification without changing compilation identity or output paths.

## Input model

`manifest.rs` owns the supported Cargo manifest subset. `manifest/targets.rs`
discovers all four target kinds with one Cargo-compatible model for members
and dependencies. `manifest/profiles.rs` resolves the selected profile once
per command. `toml.rs` wraps TOML parsing with byte, nesting, and node limits
and retains source locations for diagnostics. `config.rs` merges the supported
Lorry and Cargo configuration layers while enforcing which layer may control
security-sensitive settings. `toolchain.rs` discovers `rustc`, identifies the
Cargo-compatibility family, and evaluates target `cfg` expressions.

Compilation selects members and targets from one workspace model. Each package
has at most one library and bounded sets of binaries, integrations, examples,
and benchmarks. Shared membership discovery supplies inheritance, defaults,
and selectors. The workspace provides one lock, resolver, profiles, patches,
artifact parent, and root admission record. Selected members coexist in the
shared profile with per-package ownership. Unit planning carries package and
target identity through publication, freshness, runtime environments, and
bundles. Dependency manifests are parsed through a wider but still explicit
subset needed to compile the selected graph. Recognized metadata is inert;
unknown build semantics are errors.

Selected members' build scripts and build-dependencies use the shared unit
planner and executor. Named path grants admit member execution; caller
environment allowlists belong to each package. Editable scripts may read
workspace inputs but write only their private outputs. Registry and Git
scripts retain narrower input roots, with read/watch access to the exact
workspace lock file. Script directives and observations enter
dependent unit identities and completed-profile freshness.

Lorry reads Cargo lock formats 1 through 4 without rewriting valid locked
inputs. Ordinary vendoring preserves compatible parent dependency edges and
retains the existing format when repair is needed. A fresh lock follows Cargo's
member Rust-version thresholds. Complete resolution follows weak dependency
feature references too; selected compilation can leave those optional edges
inactive. Acquisition and admission project their feature/platform closures
from the complete graph.

Cargo compatibility is the explicit current Motor family (`1.99`), either
inferred from a paired rustc or supplied by installation configuration. The
family selects Cargo-shaped compiler identity behavior and is part of every
build-cache key. Cargo invocation and the identity/resolution oracles used to
qualify a new family are test infrastructure only; the selected compatibility
behavior contains no Cargo invocation at runtime.

## Resolution and source identity

`resolver.rs` implements the supported Cargo resolver behavior. The catalog
contains crates.io records and local candidates. Lockfile identities are
preferences, not unconditional choices: requirements, target predicates,
features, Rust versions, checksums, patches, links uniqueness, an optional
configured graph-depth bound, and package limits still apply. Dependency depth
has no default cap, matching Cargo. As in Cargo, candidates are tried in
preference order and then from the highest version; a selected package keeps
its place in that order instead of being tried first. Dependencies are also
resolved in Cargo's order. Each selected package adds a group of its
dependencies, sorted by candidate count, with ties in Cargo's manifest order
for path and Git packages and in index order for registry packages. The next
dependency comes from the group whose next dependency has the fewest
candidates, and ties go to the older group.

Every package has a logical identity independent of its installation path:

- crates.io packages use name, semantic version, and archive checksum;
- Git packages use their canonical source identity and resolved commit; and
- ordinary paths use their canonical source-tree digest.

Repository source paths are physical storage details. Compiler path remapping
presents stable `.lorry/...` logical paths so equivalent builds do not acquire
host-specific source names.

Registry index records do not identify a package as a procedural macro, so
resolution and evidence preparation form a bounded refinement loop. The first
resolution selects source identities; verified manifests annotate those
identities as procedural macros; resolution repeats until host/target
selection is stable. A dependency edge to a procedural macro, including a
development edge, becomes a compiler-host edge before activating that package's
closure. Resolver 2 and 3 therefore
keep the macro's host features separate if the same dependency is also used by
target code.

## Repositories and vendoring

`repository.rs` implements layered immutable content-addressed repositories.
Lookup verifies object metadata and retained content. Writers stage complete
objects privately and publish with no replacement; an existing different
object at the same identity is corruption.

The ordinary vendor flow is:

1. take the project vendor lock;
2. refresh mutable Git-patch selectors and materialize the candidate's locked
   Git sources;
3. load sparse index data on demand and resolve the complete/selected graphs;
4. run policy preflight before archive acquisition;
5. download missing archives with the bounded curl client;
6. verify checksum, archive structure, manifest identity, license, sizes, and
   canonical source-tree digest;
7. show one combined Git/dependency/capability review when required and obtain
   one interactive approval, or apply `--accept-all` to the complete candidate;
8. publish immutable repository objects and the lockfile; and
9. write `.lorry/dependencies-v2.toml` last from the committed graph.

Direct dependencies and crates.io Git patches share one verified,
content-addressed object catalog below the project-local vendor tree. Both
retain their immutable Git source identity; input manifests are never
rewritten. Explicit path patches retain their declared path identity.

`curl.rs`, `redirect.rs`, `archive.rs`, `sparse.rs`, and `source_tree.rs`
implement the acquisition boundary. Redirect trust is separate from package
admission. A trusted site cannot bypass checksum or policy checks.

Curl is an ordinary separately installed executable, not a Lorry-specific
helper. Lorry resolves it once, supplies a cleared environment and fixed
argument vector, streams the body from stdout, and reads a nonce-delimited
control trailer from stderr. Lorry itself owns redirects, HTTP status policy,
download limits, staging, hashing, and publication. The exact executable and
stream contract is part of `spec.md`.

## Git source model

Direct Git dependencies have a first-class immutable source identity:
canonical URL, exact locked commit, Git tree, canonical Lorry source-tree
digest, and package path within the snapshot. Branches, tags, and `rev` values
are update intent and provenance; they never replace the locked commit.
Resolution, lockfile parsing/rendering, canonical review records, admission,
logical source paths, and cache keys all retain that identity rather than
treating Git as crates.io or as an ordinary mutable path. A single snapshot
may contribute multiple monorepo packages.

Root crates.io Git patches use the same immutable source model and verified
objects as direct Git dependencies. The resolver marks their selected Git
packages as crates.io replacements without changing their source identity or
rewriting a workspace manifest. Build, run, and test remain entirely offline.
Networked vendoring advertises mutable patch refs without fetching history,
then resolves moved commits in an in-memory lock candidate. Exact hexadecimal
`rev` selectors remain pinned. Candidate objects are verified before one
default-no review; a moved tag is labeled as retargeted. Only acceptance
commits the candidate lock and admission state.

Both Linux and Motor use gix for repository negotiation, pack/object
processing, and tree traversal. A small injected blocking transport sends
anonymous smart-HTTP requests through Lorry's bounded configured-curl client,
so transport follows the same redirect, status, environment, and response-size
rules as registry acquisition. No Git executable, credential helper, proxy,
hook, filter, or ambient Git configuration is used. Checkout accepts only
portable trees, materializes only safe internal links as regular files, and
rejects escaping or unresolved links and submodules before atomic publication.

## Generated dependency admission

Metadata resolves the shared complete lock and projects its requested features
without constructing a compilation plan. `dependency::workspace::PreparedSources`
owns inspected manifests and extracted sources but carries no execution
admission. Its policy passes enforce explicit vetoes, source identity, package
counts, explicitly configured dependency depth, and artifact/transaction sizes without requiring
build-script or proc-macro grants. `metadata::graph::workspace` filters package
reachability separately from feature resolution. A stale execution record
therefore does not prevent source navigation.

`.lorry/dependencies-v2.toml` is committed, deterministic machine-owned state.
It records only:

- the SHA-256 commitment to the canonical review document specified in
  `spec.md`;
- the normalized workspace member/feature scope;
- the reviewed `(host, target)` build contexts; and
- the explicit build-script, procedural-macro, and native-tool capability
  grants.

The canonical review document is reconstructed, never stored. Review format 4
omits raw member declaration text. The complete locked graph comes from
Cargo.lock, scoped per-context selections from offline resolution, and source
evidence from verified repository objects. Unused member declarations therefore
do not force readmission. Path dependencies remain governed by their
source digests and configured policy rather than being copied into immutable
dependency admission.

Builds from Cargo's cache skip this section: they read no admission state,
and `Config::trust_cargo_cache` sets a policy flag that removes the default
deny, the build-script and procedural-macro grants, and Lorry's default
package limit. Explicit denies and configured limits still apply. Their
trusted build scripts get the native tools configured for the target.

With Lorry repositories, `engine.rs` requires the discovered host and selected
target to be an exact reviewed context. Before anything compiles,
`dependency::workspace::admission` reconstructs the canonical document for
every recorded context, verifies the digest and grants, and checks the
requested graph's package/feature coverage. An ordinary completed profile is
reused before this check. Its record is written only after a build that passed
admission or used Cargo's cache, and it covers the registry source, admission
state, lock, manifests, configuration, and policy. Reuse compiles and runs nothing new. Only after verification does
`admission_state.rs` translate reconstructed
evidence and explicit capabilities into exact generated allow rules. Policy
evaluation still considers every matching explicit deny, so a generated allow
cannot override administrator policy, resource limits, integrity checks, or
unavailable native-tool grants. Repository lookup during
reconstruction is inspection, not admission: nothing compiles or enters a
build cache until the commitment and policy both pass.

Complete resolution uses every workspace member, optional/development edges,
and platforms before selected feature projection. `fetch` acquires exact locked
sources without approval, while vendor projects a review scope and publishes
root approval last. Digest-protected sparse inputs are retained independently
of source objects so a targeted fetch can support selected offline builds.
They supply resolution information alone; source objects remain the integrity
authority and neither metadata nor fetch grants execution capabilities.

`RepositorySet` separates bounded object/schema/path parsing from content
verification. Ordinary reads trust digests recorded by immutable publication;
strict reads rehash retained archives and source trees. The explicit Cargo
cache bridge similarly stores Lorry evidence below `target/lorry` after its
first archive/source comparison and trusts Cargo's completion marker plus that
evidence ordinarily. Strict mode always repeats the comparison.

Projects with no generated state use the configured-policy compatibility path.
Their next successful ordinary vendor operation creates state.

## Dependency upgrades

Cargo.toml is the only human-edited dependency declaration. A direct update is
an ordinary manifest edit followed by `vendor`. The
`vendor upgrade PACKAGE[@OLD_VERSION] --to VERSION` convenience form accepts
only a locked transitive crates.io identity and feeds that selection to the
same vendoring implementation without editing Cargo.toml.

The resolver removes only the selected old transitive lock preference, adds
the requested exact version preference, and retains unrelated preferences.
The resulting graph must actually contain the requested identity.

Dependency change review temporarily supplies exact candidate allow rules so full
evidence can be collected under default-deny policy. Explicit denies and all
other constraints remain active. The review shows requirement, locked graph,
admission evidence, build-script, and native-tool changes. `--accept-all`
approves the complete displayed candidate without a prompt; one interactive
confirmation otherwise authorizes the shown identity and capability changes.

Vendoring stages the lockfile, publishes verified immutable repository objects,
atomically installs Cargo.lock when it changed, and atomically writes compact
admission last as the commit marker. An interruption before the lock commit
leaves visible project inputs unchanged. An interruption after it leaves stale
admission that build/run/test reject and ordinary `vendor` can reconstruct and
review. There is no separate dependency-upgrade journal or recovery path.

## Policy and package code

`policy.rs` has two passes. Preflight uses facts known from resolution to
reject definite denials and impossible admission before expensive work.
Inspection adds license, source-tree, archive, file-count, build-script,
procedural-macro, and other evidence and requires the exact graph to be
unchanged between passes. Both executable-code forms need separate explicit
grants; native tools remain available only to build scripts.

Build scripts are compiled as host units. Procedural macros are distinct host
units whose normal dependency closure is also compiled for the compiler host,
including macros reached through a selected target's dev-dependencies.
Linux uses rustc's normal in-process dynamic-library client. Motor uses a
static PIE executable and the same private proc-macro bridge serialization over
framed stdin/stdout; this is process separation but not a sandbox. Rustc keeps
one child per artifact and serializes ordinary invocations. A nested invocation
of the same active artifact uses a temporary child so a macro waiting for a
bridge response cannot deadlock itself. The private frames are versioned and
bounded; malformed frames, premature EOF, spawn failure, and abnormal exit are
compiler diagnostics rather than Lorry panics.
`build_script.rs` accepts a bounded subset of Cargo
directives and constructs a cleared, explicit environment.
`native_tool.rs` exposes only configured compiler/archiver roles and includes
their identities and arguments in build/cache identity. Linux applies the
filesystem/network/process sandbox in `sandbox.rs`. Motor warns and runs the
same build-script contract without isolation. Linux proc macros execute
inside rustc; Linux-to-Motor uses the same host artifact and execution path.

Motor's native compiler toolchain is an installed platform capability, not a
Lorry bootstrap responsibility. Standard development images provide `/devtools/bin/cc`
and `/devtools/bin/c++`, the `/devtools/llvm/bin/llvm` multicall with Clang, LLD, and
LLVM binutils, and the complete C/C++ sysroot below `/devtools/llvm`. Lorry
binds and admits these existing entry points through configured native-tool
roles. A multicall role keeps its fixed subcommand in `prefix-args`; it never
broadens into ambient PATH discovery. Tools for non-LLVM input formats, such
as the kloader's current NASM source, remain separate explicit capabilities
unless those inputs are converted.

## Compilation, cache, tests, and bundles

`unit.rs` converts a resolved graph into ordered host/target compilation
units. `identity.rs` and `compile.rs` reproduce the supported Cargo rustc
argument and metadata conventions. `executor.rs` validates inputs, invokes
children without a shell, and verifies expected outputs.

`check --compile-time-deps` filters the fully planned graph to executable
procedural macros, build-script runs, and their dependency closures. Member
scripts are included. Filtering after planning preserves ordinary identities
and profile sharing; execution admission and freshness checks still apply.

An artifact lock serializes builds and clean for each target directory. On
Linux, compiler and script children inherit a lease so a surviving child keeps
the barrier after its Lorry parent is killed. Motor records the kernel boot
identity and owner PID, then queries retained descendants before recovery.
Records from earlier boots cannot identify a current owner. Same-boot children
must exit before any artifact changes; malformed records and failed queries
remain errors. Interrupted-unit recovery finishes before parallel compiler
workers begin. Compilation and publication can then proceed in parallel.

Compilation units use Cargo's current private per-unit output layout. Direct
and transitive Rust dependencies are exposed as separate search directories,
so concurrently executing rustc processes never scan a directory another
unit is changing. Direct `--extern` arguments still name exact artifacts, and
the Cargo 1.99 compatibility selection continues to control unit hashes
and filenames rather than the output-directory topology.

`cache.rs` stores only verified library/procedural-macro artifacts and
build-script results.
It routes immutable crates.io and Git units to
`$HOME/.cache/lorry` on Linux or `/devtools/lorry/cache` on Motor by default,
while mutable path units stay in the project's `target/lorry/.cache`.
`cache.directory` may replace the global root from system or user
configuration; `config.rs` resolves and validates that root for both package
builds and package-independent cleanup. Cache keys include normalized compiler
inputs, sources, dependencies, configuration, native tools, and build-script
observations; shared keys additionally normalize the project root and
diagnostic-only rustc verbosity. Ordinary keys use immutable registry identity,
metadata fingerprints for mutable paths, and upstream cache keys; ordinary
reads structurally validate and trust atomic publication. Strict keys and
reads hash source, tool, sysroot, dependency, and payload contents and
quarantine mismatches within the owning cache. Root linked executables,
harnesses, bundle launchers, and build-script executables are not unit-cache
entries.

Root profile records complement the unit cache. Ordinary records contain
rustc dep-info plus mutable path metadata and are checked before admission
is rebuilt. Strict records contain content hashes and are checked after
admission. Debug root and mutable
path units use stable target-specific rustc incremental directories below
`target/lorry/.incremental`; output publication never replaces that
disposable compiler state. On Linux, library units compile in place so that
their dependents can start on their metadata, as Cargo pipelines. Other units,
strict builds, and every unit on Motor publish through a sibling staging
directory. Release and immutable registry units omit incremental compilation.

Clippy reuses the check planner and executor. Toolchain discovery verifies
the sibling driver's embedded rustc and hashes the driver. Member unit keys
include that identity and the encoded lint arguments; nonmember units keep
plain rustc. Clippy uses separate profile and incremental directories.
Configuration discovery fingerprints both candidate spellings at each
searched directory, including their absence, so a newly created nearer file
invalidates the lint result. Discovered configuration files and the workspace
manifest may appear in member dep-info outside the package directory.
On Motor the shipped sibling is a launcher; its identity also includes the
native driver payload's hash.

Ordinary tests use one workspace graph with dev-dependencies and legal dev
cycles. Compilation finishes before execution; harnesses run in Cargo package
and target order with their owning package's environment. `bundle.rs` creates
one self-extracting executable per member containing its selected harnesses
and required package binary. Host-only macro bundles use the host plan and
runtime. The launcher verifies its payload table and extracts only beneath its
configured private root.

## Platform and image boundary

Platform-specific behavior is kept narrow: installed configuration locations,
compiler discovery, runner configuration, atomic no-replace publication,
filesystem permissions, process sandboxing, and Motor runtime support. The
Lorry crate otherwise uses standard Rust and `src/sys/lib` Motor APIs. It does
not know about imager YAML, VM profiles, image staging roots, SSH transport, or
guest-layout assertions.

The Motor development image supplies an installed curl, CA bundle, native
tools, a writable user-repository location, and explicit executable-code
grants. It deliberately contains no dependency objects. A first `vendor`
operation populates the writable repository and project-local Git trees over
the network; all compilation commands remain offline. Cargo comparisons and
the release-VM lifecycle are validation code under `tests/`, not product
inputs. Curl remains an installed transport but is cross-built by Linux-hosted
Cargo and is intentionally outside the Motor-native source snapshot set.

## Where to change behavior

- CLI syntax and command applicability: `cli.rs`, then `main.rs` help;
  cleanup behavior: `clean.rs` and `cache_clean.rs`.
- Cargo manifest/lock compatibility: `manifest.rs`, `lockfile.rs`.
- target discovery and profiles: `manifest/targets.rs`, `manifest/profiles.rs`.
- dependency selection: `resolver.rs`, `patch.rs`.
- shared locked-workspace setup: `dependency.rs`, `dependency/workspace.rs`.
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
