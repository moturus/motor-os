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

## Capability stages

The initial end-to-end stages are:

1. Stage 1 builds, runs, and tests the dependency-free `src/bin/red` package
   on Linux, from Linux for Motor, and natively on Motor. The dependency-free
   Stage-1 Lorry must also build itself.
2. Stage 2 builds and tests `src/bin/rush`, including its target-specific
   dependencies, build script, library and binary, and integration tests. It
   adds locked registry resolution, policy-controlled vendoring, immutable
   repositories, a content-addressed build cache, test bundles, and
   self-hosting from Lorry's repository. Stage 2 is complete: Lorry builds curl
   on Linux and Motor, the bounded suite exercises curl's production request
   contract and fresh/warm repository acquisition, and the native gate proves
   cross/native self-hosting and the supported package surface without
   multiplying those independent boundaries into one end-to-end matrix.
3. Stage 3 will target `src/bin/httpd-axum`. Its exact package, Git-acquisition,
   and sandbox increments remain subject to the review in `stage3-design.md`.

## Platforms, toolchains, and compatibility

- Lorry must run natively on Linux and Motor OS and build Linux and
  `x86_64-unknown-motor` targets.
- Development may iterate on Linux, but portability-sensitive changes and
  milestone closure require Linux-to-Motor and native-Motor coverage.
- Linux compiler discovery follows Cargo-compatible precedence: a leading
  `+toolchain` asks rustup only to locate that toolchain's `rustc`; otherwise
  `RUSTC` precedes `rustc` from `PATH`.
- Motor defaults to `/sys/tools/rust/bin/rustc`. A controlled `RUSTC` or
  absolute configured override may be allowed unless system policy locks the
  compiler.
- Missing rustup/toolchain/compiler selections must produce actionable errors.
- `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` use Cargo-compatible precedence and
  are compilation-identity and cache inputs.
- `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER` are unsupported through Stage
  3 and must be rejected when set.
- Stages 1 and 2 accept installed target triples only. Custom JSON targets and
  Cargo's multiple-default-target form are unsupported.
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

The supported metadata compatibility families are Cargo 1.97, 1.98, and 1.99.
Lorry must infer the family for conventionally paired Linux toolchains, accept
`cargo-compat-version` for custom or unpaired toolchains, and reject unknown
families. Native Motor target units use the logical identity of an explicit
`x86_64-unknown-motor` target even when `--target` was omitted.

Debug builds must reproduce Cargo-equivalent compilation semantics but need
not be byte-identical across hosts because paths and debug information can
differ. Cross-host identity applies only to deterministic packages that do not
embed host paths, timestamps, randomness, `OUT_DIR`, or arbitrary build-script
observations. Bundle launchers and intermediate archives are not covered by
the final-executable identity promise.

Debug root crates and mutable path dependency units must pass stable
target-specific directories below `target/lorry/.incremental/` to rustc on
Linux and Motor. Release units and immutable registry dependency units must
not use incremental compilation. Incremental state is a disposable compiler
cache, is never an integrity authority, and is removed by `lorry clean`.

## Command-line interface

The current command surface is:

```text
lorry [+toolchain] [GLOBAL] build  [--release|-r] [--target TRIPLE]
                                  [--strict-validation]
lorry [+toolchain] [GLOBAL] cache clean
lorry [+toolchain] [GLOBAL] clean  [--release|-r] [--target TRIPLE]
lorry [+toolchain] [GLOBAL] new PATH
lorry [+toolchain] [GLOBAL] review
lorry [+toolchain] [GLOBAL] run    [--release|-r] [--target TRIPLE]
                                  [--strict-validation] [-- ARGS...]
lorry [+toolchain] [GLOBAL] test   [--release|-r] [--target TRIPLE]
                                  [--strict-validation] [--test NAME]
                                  [--no-run] [--bundle]
                                  [-- ARGS...]
lorry [+toolchain] [GLOBAL] vendor [--accept-all]
lorry [+toolchain] [GLOBAL] vendor upgrade PACKAGE[@OLD_VERSION] --to VERSION
lorry --help|-h
lorry --version|-V
lorry help [COMMAND]
```

Global options are `--quiet|-q`, `--verbose|-v`,
`--color auto|always|never`, and the offline local-Cargo-cache option
`--use-cargo-registry` for `build`, `run`, and `test`. Long value options
accept both `--name value` and `--name=value`.

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
  Project cleaning never removes the per-user immutable-unit cache.
- `cache clean` requires no current package and removes exactly
  `$HOME/.cache/lorry` on Linux or `/user/.cache/lorry` on Motor. An absent
  cache is success. A cache root that is a file or symbolic link is rejected
  rather than traversed or removed.
- `new PATH` creates Cargo's default edition-2024 binary package template.
  The package name is the final path component. VCS initialization and the
  other `cargo new` options are unsupported. It also creates the canonical
  dependency-free version-4 Cargo.lock so the package can immediately be
  built, run, and tested by Lorry without Cargo.
- `run` forwards arguments after `--` and executes without a shell.
- `review` is offline and non-mutating. It reconstructs and verifies the
  committed canonical dependency review, then writes its exact TOML to stdout.
  It accepts no command-specific arguments and rejects
  `--use-cargo-registry`.
- `test` builds all selected harnesses before running them in Cargo-compatible
  fail-fast target order. Arguments after `--` go to every executed harness.
- `test --test NAME` selects one discovered integration test and its required
  library/program graph.
- Ordinary `test --no-run` builds separate harnesses and prints deterministic
  paths. `test --bundle --no-run` builds one bundle and prints its path.
- Cross-target run/test uses the configured runner as an argument vector,
  never a shell command.
- `vendor upgrade PACKAGE[@OLD_VERSION] --to VERSION` accepts one complete
  semantic version and a locked transitive crates.io package. `OLD_VERSION` is
  required when Cargo.lock contains more than one version with that name.
  Direct dependencies must be edited in Cargo.toml and reconciled with
  ordinary `vendor`.
- Tool/build/operational failures return 101, usage errors return 1,
  help/version return 0, and POSIX-style interruption returns 130 where
  supported.
- `CARGO_TARGET_DIR` and Cargo `build.target-dir` must be rejected because
  Lorry owns an isolated artifact tree.

## Package and manifest model

Build, clean, run, test, and vendor operate on `Cargo.toml` in the current
directory. They do not perform upward manifest discovery and do not support
`--manifest-path` or workspaces. `new` and `cache clean` are the exceptions:
they do not inspect a current package.

A root package may contain at most one library and one binary, implicit or
explicit. `[lib]` and the single `[[bin]]` accept the Cargo-defaulted `name`,
`path`, and `test` fields needed by the supported packages. Lorry discovers
top-level `tests/*.rs` integration crates automatically.

The supported manifest surface includes:

- Rust editions 2015, 2018, 2021, and 2024;
- resolver versions 1, 2, and 3, including edition defaults and explicit root
  `resolver`;
- `package.rust-version`, enforced during selection;
- the default development profile and supported release-profile settings;
- implicit library/binary discovery, the single explicit binary, root
  `[lints.rust]`, and dependency-free root build scripts;
- normal crates.io and path dependencies in string/table forms, renaming,
  optional dependencies, default-feature control, feature-to-dependency
  forwarding, and target-conditioned dependency tables;
- exact local path `[patch.crates-io]` replacements required by policy.
- root `[patch.crates-io]` Git entries accepted only as input to Linux
  `lorry vendor`, which rewrites them to local path patches before resolution.

Crates.io dependencies require a version requirement. Path dependencies may
omit one; when supplied, it must match the selected local package. Root
build-dependencies and dev-dependencies are unsupported. A target-conditioned
root dev-dependency is inert when its selector does not match the selected
target, and produces the unsupported-dependency diagnostic when it does.
Stage 2 may compile approved transitive build-dependencies for dependency
build scripts.

Stages 1 and 2 reject multiple binaries, `--bin`, explicit `[[test]]`,
examples, benches, custom crate types, `harness`, `required-features`,
`autobins`, `autotests`, `default-run`, custom profiles, workspace inheritance,
artifact dependencies, direct Git dependencies, alternative registries,
non-crates.io patches, procedural macros, and CLI feature-selection flags.
Build, run, and test reject an unmaterialized crates.io Git patch and direct
the user to `lorry vendor`; they never fetch or rewrite it themselves.
Documentation tests are not run because native Motor has no `rustdoc`; the
omission must be reported.

Manifest keys are classified as supported build semantics, recognized inert
publication/metadata, or unsupported build semantics. Unknown or unsupported
behavioral keys must name their source location and a supported rewrite or
deferred capability when possible.

## Cargo configuration

Lorry reads only Cargo's compilation-related configuration for:

- default build target;
- exact-triple and `cfg(...)` target linker;
- rustflags;
- target runner.

It follows Cargo's discovery/merge behavior and supported
`CARGO_TARGET_<TRIPLE>_*` environment forms for that subset. Registry,
credential, alias, network, unstable, and other output-affecting unsupported
settings must be rejected rather than adopted or ignored.

## Locking, resolution, and source selection

- Every build, run, and test requires a present, current Cargo.lock version 4,
  including dependency-free projects. These commands treat it as read-only,
  remain offline, and never repair it.
- `lorry vendor` creates a missing lock or repairs a stale lock while
  preserving compatible locked versions. When portable admission state exists,
  an ordinary vendor operation reconciles dependency-intent or lock-graph
  drift only after interactive review; `--accept-all` cannot approve a change.
  If the visible inputs no longer reconstruct the committed review, it shows
  the prior commitment and complete verified candidate instead of claiming a
  semantic diff.
- An explicit upgrade changes only the selected package and packages forced to
  move by its requirements. Every other compatible locked identity remains
  preferred.
- Before normal resolution on Linux, `lorry vendor` materializes supported
  root crates.io Git patches and atomically rewrites them to local path
  patches. Motor returns a not-supported diagnostic only when this preliminary
  Git step is required.
- Resolver versions 1, 2, and 3 must follow Cargo-compatible feature,
  target, yanked-version, candidate-ordering/backtracking, and Rust-version
  behavior for the supported single-root model.
- Resolution creates the complete all-target Cargo-compatible lock graph.
  Acquisition includes only the default-feature closure selected by the union
  of `[vendor].targets` and, by default, the current host.
- Default vendor targets are `x86_64-unknown-linux-musl` and
  `x86_64-unknown-motor`; the rustc host is included unless explicitly
  disabled.
- Crates.io's sparse HTTPS index is the only Stage-2 registry. Its SHA-256 is
  authoritative, and Lorry preserves Cargo's canonical crates.io lock source.
- A locked checksum that conflicts with the index or archive is an integrity
  failure and must never be repaired silently.
- Builds never fall back to Cargo's cache or the network. Missing selected
  objects must identify the package/version/source and recommend
  `lorry vendor`.
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
  production repository, repository fingerprint, generated admission policy,
  or Motor image seed.

Required source rules are layered `lorry.toml` data, not hard-coded crate
exceptions. A selected required patch must have a semantically matching root
`[patch.crates-io]` path entry and Cargo.lock path-package node. Its logical
path is `.lorry/vendor/<rule-id>/source`; Lorry resolves that exact identity
through its repositories without materializing the path in the project.
Build/run/test must reject missing or incorrect declarations and must not edit
them. `Lorry.lock` is unsupported and must be rejected.

Normal repository builds must present immutable dependency sources through
host-independent logical paths without changing their physical storage:

- each crates.io object has the logical root
  `.lorry/registry/sha256/<locked-checksum>/source`;
- a required patch retains its declared
  `.lorry/vendor/<rule-id>/source` logical root;
- each ordinary non-root path dependency has the logical root
  `.lorry/path/sha256/<source-tree-sha256>/source`;
- dependency rustc runs from the workspace root and receives an internal
  `--remap-path-prefix` from the physical source root to the
  workspace-relative logical root;
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

## Portable dependency admission state

`Cargo.toml` is the only project dependency file intended for human editing.
`Cargo.lock` is the Cargo-compatible resolved graph and may be generated by
Cargo or Lorry. Lorry owns `.lorry/dependencies-v2.toml`; it is deterministic,
portable, intended to be committed, and must be changed only by Lorry.

The compact state is an approval record, never an additional version
requirement and never trusted evidence. Format 2 contains only:

- the SHA-256 commitment to the canonical review document defined below,
  which Lorry reconstructs from Cargo.toml, Cargo.lock, and verified repository
  objects before synthesizing any generated policy;
- the reviewed `(host, target)` build contexts; and
- the explicit build-script and native-tool capability grants that must stay
  visible in a source diff.

Build, run, and test require the discovered host and selected target to be an
exact reviewed context, reconstruct the canonical document for every recorded
context, and compare its digest with the commitment before any generated
allow rule exists. Missing, corrupt, conflicting, or extra evidence fails
closed, and an explicit configured deny always wins over committed admission.
Ordinary non-root path dependency edits remain governed by path policy and
source verification and do not require dependency upgrades.

Generated state must contain no timestamps, usernames, physical repository
paths, installed-tool paths, or other host observations. Keys, ordering,
string encoding, and duplicate rejection are canonical and bounded. Unknown
format versions or keys are hard errors.

### Compact admission format 2

The compact file is UTF-8 TOML. Its allowed top-level keys are exactly
`format-version`, `review-format-version`, `review-sha256`, `context`, and
`capability`. The three scalar keys and at least one context are required;
capabilities are optional. Their exact scalar values and the table schemas are:

```toml
# Generated by Lorry. Do not edit.
format-version = 2
review-format-version = 1
review-sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[context]]
host = "x86_64-unknown-linux-gnu"
target = "x86_64-unknown-motor"

[[capability]]
package = "libc"
version = "0.2.186"
checksum = "68ab91017fe16c622486840e4c83c9a37afeff978bd239b5293d61ece587de66"
build-script = true
native-tools = ["archiver", "c-compiler"]
```

The machine writer emits the generated comment, scalars, contexts, and
capabilities in that order, with one empty line before each table and exactly
one final LF. The parser accepts insignificant TOML whitespace and comments,
but table and array element order must already be canonical.

Contexts are sorted and unique by `(host, target)`. They describe build
topology, so Linux-to-Motor and Motor-to-Motor are distinct reviews.
Capabilities are sorted and unique by `(package, version, checksum)`, must
refer to a selected verified registry identity, and must grant at least one
capability. `native-tools` is sorted and duplicate-free, recognizes only the
roles defined by this specification, and requires `build-script = true`. A
build-script grant requires matching verified source evidence. Packages with
no exceptional capability do not appear in the compact file.

### Canonical review format 1

The review document is reconstructed rather than stored. It is UTF-8 TOML
with LF line endings, contains no comments or host observations, and has
exactly one final LF. SHA-256 covers its exact bytes. It begins with these
four keys in this order:

```toml
review-format-version = 1
source-tree-format-version = 1
cargo-lock-format-version = 4
resolver-version = 2
```

`resolver-version` is the supported resolver selected by the root manifest.
The scalar keys are followed by repeated tables in the order below. Fields
within each table occur in the listed order; bracketed `target` is the only
optional field. There is one empty line before each repeated table, no trailing
space, and no placeholder when `target` is absent.

| Table | Fields in exact order | Canonical sort key |
|---|---|---|
| `context` | `host`, `target` | `(host, target)` |
| `direct-registry` | `alias`, `package`, `requirement`, `kind`, [`target`], `optional`, `default-features`, `features` | all rendered semantic fields |
| `root-feature` | `name`, `values` | `name` |
| `crates-io-patch` | `alias`, `package` | `(alias, package)` |
| `locked-registry` | `name`, `version`, `checksum`, `dependencies` | `(name, version, checksum)` |
| `context-registry` | `host`, `target`, `name`, `version`, `checksum`, `compile-kinds`, `host-features`, `target-features` | `(host, target, name, version, checksum)` |
| `registry-source` | `name`, `version`, `checksum`, `license`, `source-tree-sha256`, `build-script` | `(name, version, checksum)` |
| `capability` | `package`, `version`, `checksum`, `build-script`, `native-tools` | `(package, version, checksum)` |

The sections record, respectively, reviewed build contexts; direct registry
semantics; root feature definitions; crates.io patch aliasing; every registry
lock node including inactive nodes; per-context selection, compile kinds, and
features; verified evidence for the union of selected registry identities;
and explicit execution grants. Path packages and required patches remain
outside registry admission and retain their independent policy and source-tree
checks.

`kind` is `normal`, `build`, or `development`. Compile kinds are `host` and
`target`. Every array is present, including when empty. A locked dependency is
rendered as exactly `SOURCE NAME VERSION`, where `SOURCE` is `crates.io` or
`path`; original Cargo.lock dependency spelling is first resolved to one exact
semantic node. An empty dependency array is inline. A non-empty dependency
array has one four-space-indented quoted value and trailing comma per line.

Canonical strings are TOML basic strings. Quote, backslash, LF, CR, and tab use
`\"`, `\\`, `\n`, `\r`, and `\t`; other control characters use uppercase
four- or eight-digit Unicode escapes. Other Unicode scalar values are emitted
unchanged and are not normalized. Integers are unsigned decimal and booleans
are `true` or `false`.

Inline arrays use comma-space separation. Set-valued arrays are sorted by
UTF-8 bytes and reject duplicates, except that compile kinds use `host` before
`target`, native tools use `archiver` before `c-compiler`, and dependency
references sort by `(source, name, version)` with `crates.io` before `path`.
Repeated tables reject duplicate complete keys. Semantic versions and version
requirements use the pinned `semver` implementation's canonical display.
Checksums and tree digests are exactly 64 lowercase hexadecimal characters.

A target triple is emitted after normal triple validation. A `cfg(...)`
selector is parsed into name, `name = "value"`, `all`, `any`, and `not` nodes.
Its renderer removes whitespace, writes values as `name="value"`, recursively
sorts and deduplicates `all` and `any` children by canonical bytes, and requires
one `not` child. Empty `all()` and `any()` retain their true/false meanings.
Escapes in cfg string values are unsupported.

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
| direct dependencies / root features / patches | 4,096 each |
| distinct registry lock nodes / selected packages / source entries / capabilities | 4,096 each |
| Cargo.lock dependency edges | 131,072 |
| context/package memberships | 65,536 |
| feature values and activated-feature occurrences | 262,144 combined |
| cfg-expression nodes / depth | 4,096 / 64 per selector |

The writer enforces the report byte bound incrementally and never hashes or
returns a truncated document.

Build, run, and test never create or modify portable state. Before source
lookup or compilation, they compare it with registry dependency semantics,
the Cargo.lock registry graph, and the selected target. Required patches and
ordinary paths remain exact policy/source inputs outside this registry state.
A mismatch fails closed and reports the
old and new exact package identities and directs the user to `lorry vendor`.
Formatting-only changes to Cargo.toml or Cargo.lock do not invalidate semantic
state.

Exact state entries act as generated allow rules during policy evaluation.
They may satisfy default-deny admission but must never override an explicit
deny, system constraint, required-patch rule, resource limit, source-integrity
check, or native-tool restriction. Prepared source evidence must reproduce the
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
constraints, required patches, HTTPS and archive integrity, source identity,
and all resource limits. Lorry presents a deterministic graph and evidence
difference including requirements, package additions/removals, checksums,
licenses, source digests, build scripts, and native-tool roles.

An existing package's previous capability set may be proposed but is never
silently carried to a new identity. Interactive approval covers the displayed
package and capability changes. A new native-tool role requires an existing
administrator grant. `--accept-all` cannot approve a change to existing
admission or grant a new build-script or native-tool capability.

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

1. `/sys/tools/rust/cfg/lorry.toml`;
2. `/user/cfg/lorry.toml`;
3. the nearest ancestor repository `lorry.toml`.

Linux merges:

1. `$HOME/.config/lorry/lorry.toml`;
2. the nearest ancestor repository `lorry.toml`.

Linux must not read or write `/etc` or redirect its control root through
`XDG_CONFIG_HOME`. Tables merge recursively; later scalars/arrays replace
earlier values. Policy rule and required-patch IDs accumulate and cannot erase
earlier denies/requirements. System constraints may lock keys or table
prefixes against weaker later configuration.

Configuration version 1 defines compiler selection, the three repository
roles, retention flags, vendor targets/host inclusion, curl and CA paths, test
extraction root, target-specific native tools, admission rules/limits, required
patches, and system constraints.

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
    seeded-git/sha256/<prefix>/<source-tree-sha256>/
  .staging/  # writable repositories only
```

Crates.io objects record canonical package metadata, the exact sparse-index
record, and retained archive/source forms. Seeded Git provenance objects
record the pinned URL, commit/tree evidence, patch inputs, and resulting
source-tree digest. Complete source trees use the canonical
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
exact `<name>-<version>/` root. The Stage-2 reader accepts v7/ustar regular
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
5. present deterministic evidence and require per-new-package approval, or
   apply `--accept-all` only after all policy/integrity checks pass;
6. fsync and atomically publish immutable objects with no replacement;
7. atomically commit Cargo.lock last.

The Linux-only Git-patch bridge is a preliminary, separately durable
transaction. It accepts only an inline root `[patch.crates-io]` entry with an
anonymous canonical HTTPS `git` URL, optional `package`, and at most one of
`branch`, `tag`, or `rev`. Lorry invokes the installed Git executable with an
empty environment and configuration, no credential or terminal prompting,
an 8 MiB combined-output bound, and a 300-second deadline. A matching
40-hex-digit Cargo.lock commit is retained; otherwise the requested ref is
resolved once. Lorry records URL, request, commit, Git tree, canonical source
SHA-256, file count, and bytes before approval, publishes the bounded source at
`.lorry/vendor/<alias>/source`, and rewrites only the corresponding manifest
value. A later registry-vendoring failure may therefore leave this completed
local-path materialization in place; a rerun resumes from it. Direct Git
dependencies remain unsupported.

Motor never invokes Git in Stage 2. A project requiring this step must be
vendored on Linux, after which the rewritten project and its populated Lorry
repository are transferred together. Native builds consume only those local
sources and verified repository objects. Stage 3 source-model and native
transport options are reviewed separately in `stage3-design.md`.

Decline or failure before commit must expose no new object or lock. Concurrent
publication may accept an independently published destination only after full
identity verification. A corrupt higher-priority object is a hard error, not
a reason to fall through or repair.

New non-path packages are default-deny. Any matching deny vetoes admission;
with default deny, at least one allow must match. Integrity checks cannot be
disabled. Policy may constrain package identity, version/source/checksum,
exact license expression, build-script presence, source digest, path roots,
sizes, file counts, dependency depth, package count, and native-tool roles.
Build scripts always require an explicit allow, even under default allow.

Default limits are 64 selected packages, depth 16, 16 MiB compressed and
128 MiB/20,000 files extracted per package, 256 MiB compressed and 1 GiB
extracted per transaction, and 300 seconds/8 MiB captured output per build
script. Archives admit regular files and directories only and reject links,
special files, traversal, malformed metadata, duplicates, and limit evasion.

## HTTPS acquisition and redirect trust

Lorry invokes a curl-compatible executable directly without a shell, adapter,
or private helper protocol. Linux requires upstream curl 7.63.0 or newer;
Motor uses `/bin/curl` by default. Motor's default CA bundle is
`/sys/cfg/ssl/ca-certificates.crt`. Absolute `[network]` overrides are allowed
subject to system policy.

One curl process performs one public HTTPS GET. Lorry owns URL validation,
redirect handling, status/final-URL/trailer parsing, stream bounds, staging,
hashing, policy, and commit. Curl does not follow redirects; Lorry may perform
at most five validated redirect requests. Ambient curl configuration,
credentials, proxies, compression, and retries are disabled. The exact
argument, environment, stream, error, and conformance contract is normative in
`curl-interaction.md`.

The selected curl must report the required upstream-compatible transport
statuses: malformed URL 3, name resolution 6, connection failure 7, local
write failure 23, timeout 28, TLS connection failure 35, and certificate
verification failure 60. Motor curl must propagate standard-output write and
flush errors to the transfer so a closed output pipe produces status 23.

Persistent redirect allow/deny lists start empty and are stored outside
repository-controlled configuration. An unknown canonical HTTPS site requires
a separate operation-only or persistent allow/deny decision.
`--accept-all` applies to package approval, not redirect trust.

## Compilation and build scripts

Lorry constructs a deterministic unit DAG and invokes rustc directly without a
shell. Unit identity includes package/source, target kind/name, host or target
compile kind, features, profile/panic/LTO mode, compiler and compatibility
family, effective flags/linker/lints, build-script results, and dependency
metadata. Distinct host/target, feature, profile, panic, and harness contexts
are distinct units.

Rustc arguments, environment, Cargo-compatible metadata/extra-filename hashes,
target search paths, `--extern` paths, lints/check-cfg, profile/LTO behavior,
and primary output handling must match the selected Cargo compatibility
family, with one diagnostic-only exception: verbose Lorry builds pass
`--verbose` to rustc for Cargo 1.97 compatibility even though Cargo 1.97 does
not. Cargo 1.98 and 1.99 both pass that flag, and the flag does not alter unit
identity or executable bytes. Default output is isolated below
`target/lorry/`, with Cargo-shaped native or explicit-target debug/release
subdirectories.

Every supported Linux build script runs in a mandatory sandbox that:

- denies network access;
- makes source, dependency, and toolchain inputs read-only;
- permits writes only to its assigned `OUT_DIR`, private temporary area, and
  the exact `/dev/null` device needed for child stdio;
- starts from a cleared environment and exposes only documented values;
- permits only explicitly approved child tools.

The supported directive protocol accepts both `cargo:` and `cargo::` forms of
`rustc-cfg`, `rustc-check-cfg`, `rustc-env`, `rustc-link-lib`,
`rustc-link-search`, `rerun-if-changed`, `rerun-if-env-changed`, `warning`,
and `error`. Unknown directives, unsafe paths, malformed/oversized output,
timeout, sandbox violation, or nonzero exit are hard failures. An
`rerun-if-env-changed` name absent from the cleared safe environment is tracked
as explicitly absent; ambient values remain inaccessible.

Stage 2 has only `c-compiler` and `archiver` native-tool roles. They are
configured per target as absolute executable, fixed prefix-argument array, and
flag array; they are never discovered from ambient `PATH`, `CC`, `CFLAGS`,
`AR`, or `ARFLAGS`. A package rule must grant each role explicitly and pin a
source-tree digest. Tool bytes, path, identity, arguments, environment, and
outputs are build/cache/audit inputs. For a granted C compiler, Lorry exposes
the canonical sibling `lib` directory of its `bin` directory read-only when
present, and exposes each absolute existing directory named by an exact
`--sysroot=<path>` flag read-only. These are the only implicit compiler
resource roots; an invalid configured sysroot fails before the build script
runs. Neither root is exposed when the package lacks the `c-compiler` grant.
Undeclared helpers must be denied. Linux acceptance must include a native tool
that exists in target configuration but is absent from the package grant: it
receives neither an environment entry nor execute permission. This
distinguishes package admission from mere administrator configuration.

During Stage 2, Motor runs build scripts without isolation and emits an
explicit warning for every sandbox application. This is not a sandboxed mode
and must not be described as one. Enforcing the same observable contract as
Linux is deferred to Stage 3; the warning remains mandatory until then.

## Build cache

Stage 1 does not reuse artifacts. Stage 2 stores verified library outputs and
build-script `OUT_DIR`/directive results. Immutable crates.io units and
reviewed required-patch units are stored in the per-user cache below
`$HOME/.cache/lorry/v1/units/sha256/` on Linux and
`/user/.cache/lorry/v1/units/sha256/` on Motor. Mutable path-package units are
stored in the project below `target/lorry/.cache/v1/units/sha256/`. Root linked
artifacts, tests, and incremental state are not unit-cache entries.

Cache keys cover Lorry/cache schema, compiler identity, normalized rustc
arguments and child environment, package source identity, dependency unit
identities, build-script executable/environment/directives/output, and
approved native tools. The project root and diagnostic-only rustc verbosity
are normalized so an immutable unit can be reused by compatible projects and
between ordinary and verbose builds. Ordinary keys trust immutable crates.io
identity, use bounded path/size/mtime fingerprints for mutable path packages,
and compose dependency cache keys without rereading rlib/rmeta bytes. Strict
keys hash rustc, sysroot, tools, source trees, dependency artifacts, and
manifests.

After a successful non-test build, the completed root profile contains a
freshness record. An ordinary unchanged `build` or `run` validates parsed
manifest, lock, compact admission, configuration, compiler, target, flags,
environment, and tool metadata plus rustc dep-info and mutable path-source
path/size/mtime fingerprints. It requires the installed artifact to exist but
does not read artifact or dependency source contents. A matching record is
accepted before dependency repository opening and admission reconstruction,
then reuses the profile without invoking build scripts, rustc, native tools,
or the linker. Strict mode reconstructs admission and rehashes all of those
contents before reuse. A missing, malformed, stale, or differently-modeled
record causes a normal rebuild. Test harnesses and bundle launchers are not
reused by this profile-level check.

Unit-cache writers publish atomically with no replacement. Partial entries are
ignored. Ordinary reads require the exact entry structure and required regular
files, then trust the atomically published payload. Strict reads compare the
payload with its content manifest; corrupt entries are warned about,
quarantined within the cache that owns them, and rebuilt. Repository
corruption found by strict validation is fatal and is never treated as cache
corruption. Cache contents remain writable per-user performance state and are
never an integrity authority for immutable dependency sources.

## Tests and bundles

Ordinary tests preserve separate root library, root binary, and integration
harness crates. Integration compilation receives Cargo-compatible
`CARGO_BIN_EXE_<name>` and `CARGO_TARGET_TMPDIR`.

Bundle mode packages selected harness executables and required program
binaries into one target-native self-extracting executable. It must verify its
embedded payload table, extract beneath a configurable absolute private root
using race-resistant exclusive operations, reject links/unexpected files/
tampering, invoke payloads without a shell, forward harness arguments, and
aggregate failures. Unix platforms additionally enforce private directory,
manifest, and executable modes.

## Bootstrap, dependency, and licensing boundary

Lorry's executable does not bootstrap an OS image. The host-side files under
`bootstrap/` are packaging utilities used by the Motor toolchain build to
preinstall a verified system repository and system configuration. The shipped
seed provides offline/self-hosting convenience; it is not required when Lorry
is supplied another valid configuration and repositories. Imager inputs,
debug/release image selection, VM launch, and layout validation remain outside
this product boundary.

The historical Stage-1 source had no third-party dependency and was directly
bootstrap-compilable with rustc. The current source pins the reviewed
non-derive Clap, pure-Rust flate2, semver, serde/serde_json, SHA-256, and TOML
parser graph, plus target-specific first-party Motor support and Linux libc
bindings, documented by Cargo.toml and Cargo.lock. Every third-party direct
requirement is exact. These two machine-readable files, not duplicated version
numbers in prose, are authoritative for direct versions and selected features.
Every dependency and graph change must record purpose, source identity,
license, selected features, and transitive justification in generated
admission evidence; first-party use grants no policy bypass.

Stage-2 Motor curl uses Rustls with patched `ring` 0.17.14, `std`, and TLS 1.2,
plus `rustls-pemfile` and `getrandom` 0.2.17's custom Motor entropy callback.
The `ring` source is the exact crates.io archive plus the two reviewed Git
replacement blobs, selected through an explicit logical path patch and
verified as a seeded object. No generic Git dependency support is implied.

The pinned `ring` inputs are:

- crates.io archive SHA-256
  `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7`;
- `https://github.com/moturus/ring.git` commit
  `b1dad2579de791d0c31ad33300187e584ba6c268`, tree
  `824d5b8e9755603070a8167e0c5529acb627d956`;
- Git replacement blobs `build.rs` and `src/rand.rs`;
- resulting `lorry-source-tree-v1` digest
  `c05dbfa4d748bce2b66093633c0a644cc1e5f480d73f3b0a975e409f69386af6`.

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
- live Cargo 1.97/1.98/1.99 resolution checks retain the supported lockfile
  family contract, while a dependency-free fixture proves native and
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

Stage 2 is closed. Stage-3 scope remains provisional pending review of
`stage3-design.md`. Capabilities not accepted by that review remain deferred,
including workspaces, `httpd-axum`, `russhd`, procedural macros, general
Git/alternative-registry acquisition, CLI feature selection, custom targets,
broad target declarations, general C/C++/native-tool discovery, arbitrary
build-script processes, Cargo wrappers, and linked-artifact cache reuse.
