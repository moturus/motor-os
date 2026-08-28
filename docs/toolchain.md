# Versioned and reproducible Motor OS toolchain

This document defines how the Motor OS LLVM and Rust toolchain is versioned,
built, and reported, and the procedures for updating it. The design was
implemented on the `toolchain-1.99.0-beta` branch and merged into `main` on
2026-08-28; the investigation of the workflow it replaced and the
implementation plan are in this file's history, as `docs/plans/toolchain.md`.
The user-facing build procedure is in [build.md](build.md) and
[build-motor-os.md](build-motor-os.md).

## Status

The beta tuple of section 3.4 is implemented:

- the Motor Rust and LLVM branches are replayed on the exact beta bases,
  dependency selections are disambiguated and pinned, and all four required
  source branches are published;
- managed and authoring source resolution, deterministic bootstrap inputs,
  immutable key-qualified host prefixes, keyed assemblies, native tools, and
  complete manifests are implemented and covered by the offline toolchain
  tests;
- the repository selects its exact root toolchain and uses keyed
  per-component outputs, keyed generated image roots, and bare Cargo
  commands; and
- Lorry supports only the current Motor Cargo 1.99 family and passes its full
  host, oracle, registry, curl, and native self-hosting product suite.

The stable release (section 6.1) is deferred: upstream Rust 1.99.0 is
scheduled for 2026-10-01 and does not yet have a stable tag. The beta
artifacts and refs must not be renamed or published as `1.99.0-motor.1`.

## 1. Summary

Motor OS publishes one source-defined compiler lineage with a clear upstream
lineage, and locally assembles the complete toolchain from that source tuple:

1. The first stable Motor toolchain baseline is Rust `1.99.0`.
2. Until that release exists, the Rust 1.99 beta commit pinned in section 3.4
   is the porting and validation baseline.
3. Motor LLVM is the exact `rust-lang/llvm-project` commit pinned by that Rust
   revision plus the Motor LLVM patches, on a Motor LLVM development branch.
4. Motor Rust is that Rust commit plus the Motor std and rustc patches, on one
   Motor Rust development branch. Its LLVM gitlink points at the Motor LLVM
   commit, its LLVM submodule URL points at the Motor fork without a
   branch-following rule, and it keeps the Cargo gitlink that the Rust
   revision selects.
5. Standalone LLVM/Clang and rustc's LLVM are built from that same Motor LLVM
   commit.
6. From that one Rust revision, Linux-host rustc/rustdoc, Cargo, host std,
   Motor std, Clippy, rustfmt/`cargo-fmt`, and `rust-src` are built and
   installed into an immutable tuple-keyed prefix, registered as the one
   versioned Motor rustup toolchain, and used for every repository build and
   test. The C sysroot is built with it, then the native Motor rustc from the
   same revision.
7. When the Rust `1.99.0` stable tag is published, both Motor forks are
   rebased onto the final Rust and Rust-pinned LLVM commits, the complete
   tuple is rebuilt and revalidated, and only then are the immutable source
   refs for `1.99.0-motor.1` published in the Motor Rust and LLVM GitHub
   forks. Binary toolchain archives are not published.

Reproducibility is the mechanism that enforces this version policy, not the
only purpose of the policy.

The important rules are:

- rustc/rustdoc, `core`, `alloc`, `std`, `proc_macro`, Cargo, Clippy,
  rustfmt/`cargo-fmt`, and the native Motor rustc come from one Motor Rust
  source revision;
- every formal Motor Rust source tag descends from the declared stable Rust
  tag;
- every formal Motor LLVM source tag descends from the exact LLVM gitlink in
  that stable Rust tag;
- standalone LLVM/Clang and rustc's LLVM use the same effective LLVM revision
  and source tree;
- Rust's Stage 0 compiler is the only bootstrap-only input; it is selected by
  the Rust revision's `src/stage0`, recorded, and never chosen by Motor OS;
- mlibc and separately versioned runtime inputs such as both copies of
  `moto-rt` are recorded;
- Cargo, Clippy, rustdoc, rustfmt/`cargo-fmt`, and `rust-src` are components of
  the Motor toolchain, not rustup fallbacks selected from installed channels;
- the same versioned Motor toolchain drives Linux-host work (host tools, host
  unit tests, the boot loaders, formatting) and Motor cross-compilation;
- Lorry supports one Cargo compatibility family at a time: the Cargo selected
  by the current Motor Rust revision (the `1.99.0-dev` Cargo built from
  `MOTOR_CARGO_REV`, compatibility family 1.99, for the current tuple); its implementation,
  specification, and oracle tests advance together with that toolchain;
- ordinary build scripts never advance toolchain source branches or explicitly
  refresh dependency selections; and
- semantic versions describe upstream lineage, while full commits enforce it.

The semantic toolchain ID describes the compiler lineage. Two derived keys
identify local outputs: the toolchain key covers the compiler tuple, and the
assembly key additionally covers the C sysroot inputs. A `moto-rt` or mlibc
maintenance update therefore changes the keys without requiring a rustc or
LLVM rebase or a new compiler-lineage release. The source-release record and
the generated local assembly manifest report:

```text
Motor compiler lineage 1.99.0-motor.1
  based on upstream Rust 1.99.0 @ UPSTREAM_RUST_REV (Stage 0 @ UPSTREAM_STAGE0_REV)
  rustc + rustdoc + rust-std + Cargo + Clippy + rustfmt/cargo-fmt + rust-src @ MOTOR_RUST_REV
  Cargo CLI MOTOR_CARGO_VERSION from source @ MOTOR_CARGO_REV (gitlink in MOTOR_RUST_REV)
  based on Rust's LLVM 23.x snapshot @ RUST_LLVM_BASE_REV
  LLVM/Clang/lld/libc++/compiler-rt @ MOTOR_LLVM_REV
  Rust std moto-rt @ STDLIB_MOTO_RT_VERSION/checksum
  toolchain key MOTOR_TOOLCHAIN_KEY
Local assembly @ MOTOR_ASSEMBLY_KEY (MOTOR_ASSEMBLY_STATE)
  mlibc @ MLIBC_REV
  local moto-rt/moto-sys/moto-rt-cabi @ MOTOR_OS_RUNTIME_TREE at MOTOR_OS_REV
```

A local assembly is identified by the complete tuple and not by the semantic
compiler-lineage version alone. `MOTOR_OS_REV`, `MOTOR_OS_RUNTIME_TREE`, and
both keys exist only in generated manifests; they do not imply that a binary
assembly is published.

The toolchain covers compiler and runtime inputs only. Development
applications such as ripgrep and Lua are not versioned or pinned by it; they
build with the Motor toolchain like everything else. The one product decision
that follows from it is Lorry's: its Cargo-compatibility contract is the Motor
Cargo alone, because a compatibility family that no repository test can
exercise is not a supported family, and Lorry and the toolchain advance
together.

In particular:

- the initial upstream baseline is the exact Rust 1.99 beta tuple recorded in
  section 3.4, with the Motor patches replayed on top;
- there is one Motor Rust development branch and no bootstrap-only Motor
  toolchain; Rust's own Stage 0 download is the only bootstrap compiler, and
  Cargo is built by Rust bootstrap from the Cargo gitlink that the Rust
  revision selects;
- `src/build-motor-os.sh` is the one user-facing workflow; it runs two `x.py`
  invocations from the same Rust revision, the Linux-host toolchain before the
  C sysroot and the native Motor rustc after it, because only the native
  compiler links mlibc;
- compiler publication is source-only through GitHub fork refs and tags; all
  built host tools and sysroots are local artifacts;
- Rust bootstrap uses no Cargo lockfile-immutability enforcement; existing
  application and offline-test lock policies are unchanged;
- Rust std keeps a crates.io `moto-rt` dependency, and a dependency-only Rust
  maintenance commit permits `moto-rt` updates between compiler releases
  without a local path in the compiler fork; and
- stale local outputs are preserved in tuple-keyed directories so incremental
  invalidation defects remain observable, and every authoring compiler carries
  a distinct identity so its outputs cannot be mistaken for a managed build's.

## 2. Goals and scope

- Make clean and incremental compiler/runtime builds select the same reviewed
  sources and use tuple-keyed output directories.
- Give each published Motor compiler source tag a stable Rust release baseline
  and the corresponding Rust-pinned LLVM baseline.
- Use that Motor toolchain for host compilation, host tests, the boot loaders,
  Motor cross-compilation, and native-tool source identity instead of a
  separate host nightly.
- Reject non-declared or dirty source checkouts for a formal source tag; let an
  explicitly selected authoring mode build current local Rust and LLVM commits
  plus uncommitted edits; and never switch, reset, stash, or delete a developer
  worktree.
- Make every version change an explicit checked-in diff.
- Build the whole toolchain from one Motor Rust revision through the single
  user-facing `src/build-motor-os.sh` entry point.
- Put the exact source tuple in compiler output and the dev image.
- Keep normal tests offline and add no retries, ignored failures, or wrapper
  cleanup of reusable outputs that could conceal a defect. The only deletion
  the build performs is replacing a generated image-staging tree it fully
  owns.

The toolchain provides reproducible source resolution, not bit-for-bit binary
reproducibility: Ubuntu packages, host compilers, paths, timestamps, and a
hermetic build environment are not pinned. The two `x.py` invocations are not
merged into one, the standalone LLVM build is not used as rustc's LLVM
through `llvm-config`, and the latest upstream release is not adopted
automatically.

## 3. Version roles

There are two build-time Rust roles, both derived from the selected Rust
baseline rather than an independently selected host channel. During the beta cycle that baseline is an exact Rust 1.99 beta commit; the
formal compiler source release will use the final stable `1.99.0` tag:

1. Rust `x.py` downloads the Stage 0 compiler and Cargo recorded, with hashes,
   in the selected Rust commit's `src/stage0`. This compiler exists only to
   bootstrap the chosen Rust source; nothing in the repository selects it.
2. The Motor Rust source produces Linux-host rustc, Cargo, host and Motor std,
   Clippy, rustfmt, `rust-src`, and the native Motor rustc/std artifacts. The
   Linux-host set is the one Motor toolchain for all repository work.

There is no third role: no host nightly or other rustup channel takes part
in the build, and the global rustup default is neither selected nor changed.

Each fork has one development branch per upstream baseline
(`motor-os-1.99.0-beta-f47d5bb` today, declared in `src/toolchain-versions.sh`)
and, for releases, new immutable versioned tags rather than moved or
force-rebased public branches.

### 3.1 Stable source does not mean stock stable-channel behavior

The Motor Rust fork must be based on an exact stable Rust patch tag. Rust is a
monorepo: that tag identifies rustc, the matching `library/` sources, the
in-tree Clippy and rustfmt sources, and the Cargo submodule gitlink. The Motor
compiler and std remain one source revision after Motor patches are applied.

Motor OS nevertheless uses unstable language features, and the boot loaders
(`src/boot/x64.{mbr,boot,kloader}/build.sh`) build with `-Zbuild-std`,
`-Zbuild-std-features`, and `-Zjson-target-spec` against JSON target files.
Until those uses are removed, the Motor compiler and Cargo must expose `dev`
or nightly feature behavior, and the toolchain must ship `rust-src` because
`-Zbuild-std` compiles `core`/`alloc` from the sysroot's
`lib/rustlib/src/rust/library`. This is not the same as tracking a moving
nightly source branch. The accurate description is "Motor Rust based on stable
Rust X.Y.Z, built with unstable features enabled."

### 3.2 One Motor toolchain

The semantic rustup toolchain-name base (`motor-1.99.0-beta-f47d5bb-dev.1`
during the beta, `motor-1.99.0-motor.1` for the stable release) identifies the
compiler lineage. The exact registered name appends the full
`MOTOR_TOOLCHAIN_KEY`; for example,
`motor-1.99.0-motor.1-<MOTOR_TOOLCHAIN_KEY>`. This prevents a maintenance
commit from silently repointing the same rustup name to different contents.
That exact toolchain contains:

- Linux-host rustc and rustdoc;
- Linux-host Cargo;
- Linux-host standard libraries;
- Motor target standard libraries;
- Clippy and its driver;
- rustfmt and `cargo-fmt`;
- `rust-src` (`lib/rustlib/src/rust/library`) for the boot loaders'
  `-Zbuild-std`; and
- the built-in Motor target support.

It is an installed, immutable, tuple-keyed prefix outside the `x.py` build
tree, not `build/<host>/stage2`, which every later `x.py` invocation recreates.
Once registered, all host and cross-target repository commands select it
through the root override or its exact name: the Makefile's
`DO_BUILD`/`DO_CLIPPY` and imager rules, `src/sys/lib/rt.vdso/build.sh`, the
boot-loader `build.sh` scripts, the host unit tests in
`src/tests/full-test.sh`, Lorry's ordinary tests, and `cargo fmt`. Native Motor
rustc is a different binary because it runs on a different host, but it comes
from the same effective Rust and LLVM revisions as the host toolchain.

There is no bootstrap-only Motor rustup toolchain. Rust `x.py` consumes the
Stage 0 compiler and Cargo selected by `src/stage0` while creating the Motor
toolchain; those are bootstrap inputs, not repository toolchains, and no
repository command may select them. Lorry itself and its ordinary equivalence
tests build with the Motor toolchain. Its resolution-oracle test executes only
that toolchain's exact Cargo. For the initial beta tuple this is the Cargo
built from the gitlink recorded by `MOTOR_CARGO_REV`; it reports
`cargo 1.99.0-dev`, not `-beta`, because the Motor build uses the `dev`
channel, and Lorry maps any `1.99.0-*` release to family 1.99. It is never an
ambient `beta` or `nightly` channel. Cargo 1.97 and 1.98 are not in Lorry's supported compatibility surface.

### 3.3 Rust supplies the LLVM baseline

Official Rust builds use an exact commit of `rust-lang/llvm-project`. Rust's
LLVM fork is based on an upstream LLVM `release/N.x` branch, not LLVM `main`,
and may include selected upstream backports or CI workarounds. The exact commit
can therefore be newer than an `llvmorg-X.Y.Z` tag while still having a clear
stable LLVM lineage.

For a selected stable Rust tag, call its LLVM gitlink
`RUST_LLVM_BASE_REV`. Motor LLVM is:

```text
RUST_LLVM_BASE_REV + Motor LLVM patches = MOTOR_LLVM_REV
```

In a managed build, the Motor Rust commit changes the upstream Rust gitlink from
`RUST_LLVM_BASE_REV` to `MOTOR_LLVM_REV`. The Rust checkout's initialized
`src/llvm-project` submodule is the only LLVM source tree: the standalone
LLVM/Clang, compiler-rt, libc++, native LLVM, and rustc's LLVM builds all read
it, so the build must require that submodule, the standalone LLVM artifacts,
and rustc's built LLVM to all come from `MOTOR_LLVM_REV`. Because the generated
bootstrap configuration sets `submodules = false`, Rust bootstrap never
touches the submodule; the checkout helper of section 5.1 owns its state.

Rust patch releases may change their LLVM gitlink to deliver a correctness
backport. Therefore an upgrade from, for example, Rust 1.99.0 to 1.99.1 must
compare the two LLVM bases and replay Motor patches when it changes.

### 3.4 First baseline: 1.99 beta, then 1.99.0 stable

The first policy-conforming Motor release targets Rust `1.99.0`. Rust 1.99
entered beta on 2026-08-14 and is scheduled to become stable on 2026-10-01.
Motor OS uses the beta period to perform and test the port, and publishes
only after rebasing onto the final stable tag.

The initial porting baseline was resolved from the official Rust `beta` branch
on 2026-08-25 and is immutable for the beta cycle:

```text
Rust 1.99.0 beta  f47d5bb13648d5c859f5b438eb7dc834b9729961
Rust LLVM gitlink 21cf28432798952d942bacc6bcee3a328faa3638
Rust Cargo gitlink eb98b54bc9f3c74519f43d066cb3fd02ebc88df0
Rust Stage 0      08d5b675a9b2abdca5e2fe4eabe0e07bbda15d49
```

These values were verified against GitHub on 2026-08-25: that commit's
`src/version` is `1.99.0` and `src/ci/channel` is `beta`, and its
`src/llvm-project` and `src/tools/cargo` gitlinks and its `src/stage0`
(`compiler_version=beta`, `compiler_date=2026-07-13`) match the pins. The LLVM
base commit is dated 2026-07-22 in `rust-lang/llvm-project`.

The Motor LLVM and Motor Rust patch sets are replayed onto those exact bases
on the development branch `motor-os-1.99.0-beta-f47d5bb` in both forks (the
LLVM branch name records which Rust baseline chose its base), and
`motor-1.99.0-beta-f47d5bb-dev.1` is the local rustup toolchain-name base. The
registered name also includes the full toolchain key, and the central manifest
records full commits. A deliberately selected later beta baseline gets a
new commit-qualified branch and a new `dev.N` name base; do not force-rewrite
an existing branch onto a different upstream baseline or reuse an exact name
for a different tuple.

The beta phase follows the same reproducibility rules as a release:

- resolve the Rust beta ref to a full commit and pin it; never build a moving
  beta branch;
- read and pin that commit's exact LLVM gitlink;
- create clearly named, non-release Motor Rust and LLVM development refs;
- give generated toolchains a distinct beta/development identity that includes
  the pinned source tuple; and
- do not create stable Motor toolchain tags or distribute beta artifacts as the
  `1.99.0-motor.1` release.

"Convert to stable" does not mean renaming the tested beta binaries. When the
`1.99.0` tag exists, record its exact commit, rebase the Motor Rust patches onto
that tag, and read the tag's LLVM gitlink again. If it differs from the beta
pin, rebase the Motor LLVM patches onto the final pin and update the Motor Rust
gitlink. Re-read the Stage 0 and Cargo identities from the stable Rust tree,
rebuild every compiler and library artifact, and repeat the complete
validation. Only that result is `1.99.0-motor.1`.

This choice avoids establishing a short-lived 1.97.1 or 1.98.0 baseline. Rust
1.97.1 and the 1.98 line use LLVM 22, while the Motor Rust work is already
based on post-1.99-branch development sources and LLVM 23. The 1.99 beta is
therefore the closest release-line starting point for the existing Motor
patches.

## 4. The manifest

The declared manifest is `src/toolchain-versions.sh`; a generated manifest is
written per build (section 5.5). Their shape, shown with the values a stable
release will carry (the beta tuple declares
`MOTOR_TOOLCHAIN_ID="1.99.0-beta-f47d5bb-motor.dev.1"`,
`MOTOR_TOOLCHAIN_MATURITY="beta"`, `UPSTREAM_RUST_REF="refs/heads/beta"`, and
the commits of section 3.4):

```sh
MOTOR_TOOLCHAIN_ID="1.99.0-motor.1"
MOTOR_RUSTUP_TOOLCHAIN_BASE="motor-1.99.0-motor.1"
MOTOR_TOOLCHAIN_MATURITY="stable"

UPSTREAM_RUST_VERSION="1.99.0"
UPSTREAM_RUST_REF="refs/tags/1.99.0"
UPSTREAM_RUST_REV="<full commit for the upstream Rust tag>"
UPSTREAM_STAGE0_REV="<compiler_git_commit_hash in src/stage0 at UPSTREAM_RUST_REV>"

RUST_LLVM_VERSION="23.x"
RUST_LLVM_BASE_REV="<src/llvm-project gitlink at UPSTREAM_RUST_REV>"

MOTOR_LLVM_REF="refs/tags/motor-toolchain-1.99.0-motor.1"
MOTOR_LLVM_REV="<RUST_LLVM_BASE_REV plus Motor patches>"

MOTOR_RUST_REF="refs/tags/motor-toolchain-1.99.0-motor.1"
MOTOR_RUST_REV="<UPSTREAM_RUST_REV plus Motor std/rustc patches and the gitlink change>"
MOTOR_RUST_CHANNEL="dev"
MOTOR_CARGO_VERSION="<Cargo CLI release produced by Rust bootstrap>"
MOTOR_CARGO_REV="<src/tools/cargo gitlink at MOTOR_RUST_REV>"
MOTOR_RUST_ROOT_LOCK_SHA256="<committed Cargo.lock at MOTOR_RUST_REV>"
MOTOR_RUST_LIBRARY_LOCK_SHA256="<committed library/Cargo.lock at MOTOR_RUST_REV>"

MOTOR_MLIBC_REF="<durable Motor mlibc ref>"
MOTOR_MLIBC_REV="<full Motor mlibc commit>"

STDLIB_MOTO_RT_VERSION="<published crates.io version used by Rust std>"
STDLIB_MOTO_RT_CHECKSUM="<registry checksum>"
LOCAL_MOTO_RT_VERSION="<local moto-rt package version; must equal STDLIB_MOTO_RT_VERSION>"
```

```sh
MOTOR_SOURCE_MODE="managed"             # or authoring
SELECTED_UPSTREAM_RUST_REV="<base Rust commit used for this build>"
SELECTED_STAGE0_REV="<src/stage0 compiler hash at that base>"
SELECTED_RUST_LLVM_BASE_REV="<LLVM gitlink at that base>"
SELECTED_MOTOR_CARGO_VERSION="<Cargo CLI release derived from the selected Rust version/channel>"
SELECTED_MOTOR_CARGO_REV="<Cargo gitlink at that base>"
SELECTED_RUSTUP_TOOLCHAIN_BASE="<managed base or generated authoring base>"
SELECTED_TOOLCHAIN_DESCRIPTION="<managed ID or generated authoring description>"
EFFECTIVE_MOTOR_RUST_REV="<actual Rust HEAD used>"
EFFECTIVE_MOTOR_LLVM_REV="<actual LLVM HEAD used>"
AUTHORING_SOURCE_DIGEST="none"          # or full SHA-256 in authoring mode
MOTOR_TOOLCHAIN_KEY="<digest of the compiler tuple, section 5.5>"
MOTOR_RUSTUP_TOOLCHAIN="<SELECTED_RUSTUP_TOOLCHAIN_BASE>-<MOTOR_TOOLCHAIN_KEY>"
MOTOR_ASSEMBLY_KEY="<digest of the compiler tuple plus sysroot inputs>"
MOTOR_ASSEMBLY_STATE="clean"            # or development-authoring/development-dirty
MOTOR_RUST_TREE_STATE="clean"           # or a digest of the uncommitted diff
MOTOR_LLVM_TREE_STATE="clean"
MOTOR_MLIBC_TREE_STATE="clean"
MOTOR_RUST_ROOT_LOCK_SHA256_START="<...>"   # observed before the build
MOTOR_RUST_ROOT_LOCK_SHA256_END="<...>"     # observed after the build
MOTOR_RUST_LIBRARY_LOCK_SHA256_START="<...>"
MOTOR_RUST_LIBRARY_LOCK_SHA256_END="<...>"
MOTOR_OS_REV="<Motor OS commit containing the local runtime sources>"
MOTOR_OS_RUNTIME_TREE="<digest of runtime crates plus their workspace build inputs>"
```

Repository URLs and expected tool/runtime identities also belong in the
declared block. Cargo is a submodule whose exact revision is selected by the
Rust tree, while its reported CLI release is set by Rust bootstrap from the
selected Rust version and channel; the Cargo package version in the submodule
does not define that CLI release. Clippy and rustfmt are in-tree sources selected
directly by `MOTOR_RUST_REV`. None is an independently selected host tool. The
manifest
must assert for managed builds that `UPSTREAM_RUST_REV` is an ancestor of
`MOTOR_RUST_REV`, `RUST_LLVM_BASE_REV` is an ancestor of `MOTOR_LLVM_REV`, the
LLVM gitlink in `MOTOR_RUST_REV` equals `MOTOR_LLVM_REV`, the Cargo gitlink in
`MOTOR_RUST_REV` equals `MOTOR_CARGO_REV`, and the `src/stage0` compiler hash
at `UPSTREAM_RUST_REV` equals `UPSTREAM_STAGE0_REV`. Recheck this layout when
selecting a new upstream Rust release. A durable tag is a useful fetch locator,
but the full commit must still be stored and checked because tags can move. In
managed mode the effective revisions equal the declared revisions and the
starting lock hashes equal the declared ones. The selected base identities also
equal their declared counterparts, `SELECTED_RUSTUP_TOOLCHAIN_BASE` equals
`MOTOR_RUSTUP_TOOLCHAIN_BASE`, and the selected description equals
`MOTOR_TOOLCHAIN_ID`. The explicit authoring-mode rules in section 5.1 permit a
different exact base and different effective local revisions without changing
the declared release tuple.

`STDLIB_MOTO_RT_VERSION` is the crates.io package used by Rust std.
`LOCAL_MOTO_RT_VERSION` and `MOTOR_OS_RUNTIME_TREE` identify the local
`moto-rt`, `moto-sys`, and `moto-rt-cabi` sources and their workspace-level
build inputs used to assemble the C sysroot. For a reproducible local assembly,
the relevant Motor OS paths must be clean and their digest must match the files
at `MOTOR_OS_REV`. A development build may use dirty local runtime sources, but
the manifest must record the resulting content digest and set
`MOTOR_ASSEMBLY_STATE` to `development-dirty` rather than silently attributing
it only to the Git commit. The build requires the local and Rust-stdlib
`moto-rt` package versions to match before building `moto-rt-cabi`, and a clean
assembly also verifies package-content equivalence as specified in section 5.4.

Formal compiler source tags remain immutable. Between compiler releases,
`moto-rt` may be published at a new crates.io version and the Rust development
branch may receive a small lock-only maintenance commit selecting it. The Motor
OS manifest then pins that exact Rust commit and matching local runtime version.
This changes `MOTOR_RUST_REV` and both keys, but does not require an LLVM
rebase or a new semantic compiler-lineage version. The next formal source
branch and tag carry the reviewed dependency selection forward when the Motor
patches are replayed.

## 5. Design

### 5.1 Central manifest and exact checkout helper

`src/toolchain-versions.sh` is a data-only file, sourced by the build scripts.
It contains the Motor toolchain ID, rustup-name base, and maturity; upstream Rust
target version, ref, revision, and Stage 0 hash; Rust's LLVM display version and
base revision; Motor Rust, LLVM, and mlibc revisions; repository URLs; durable
refs; expected Cargo/runtime identities; the explicit set of relevant Motor OS
runtime and workspace build-input paths; the canonical key formats; and the
generated-manifest schema version, plus the hashes of the committed Rust
lockfiles at `MOTOR_RUST_REV`, so that a clean managed key is computable from
the declared data alone. It does not contain `MOTOR_OS_REV`, tree-state
digests, observed lock hashes, the exact rustup name, or either derived key,
because a source file cannot pin the commit that contains itself. Do not
duplicate declared values in scripts, tests, and prose.

Managed mode, the default, uses dedicated, independent ordinary checkouts
under `$MOTORH/toolchain-src/{rust,mlibc}`; LLVM lives only in
`toolchain-src/rust/src/llvm-project`, so there is no separate LLVM checkout to
keep in agreement. A managed checkout owns its object database, refs,
worktree, and bootstrap/build state; it is never an undissociated reference
clone or a `git worktree add` of another repository, so maintenance or
deletion of any other checkout under `$MOTORH` cannot affect it. An explicitly
requested authoring mode may instead use a developer's Rust checkout as
described below; it is never selected merely because a managed checkout
happens to be dirty.

During the beta it records a `beta` maturity state, a distinct non-release
toolchain ID, and the exact beta Rust commit; stable source publication
rejects that state. The stable conversion (section 6.1) changes the state
to `stable`, the upstream ref to `refs/tags/1.99.0`, and the toolchain ID to
`1.99.0-motor.1` only after all final commits have been selected and verified.

The managed-checkout helper:

1. clones the expected repository if absent;
2. verifies an existing worktree and remote;
3. fetches the declared durable ref without changing the worktree;
4. for a formal tag, verifies the ref resolves to the full expected commit; for
   a development branch, verifies the expected commit remains reachable from
   the fetched branch without requiring it to be the current tip;
5. inspects tracked and untracked state before any checkout;
6. when clean, checks out the expected commit detached, and otherwise stops
   without modifying the checkout; and
7. verifies `HEAD` and clean tree state immediately before building.

Managed and formal source builds reject every tracked or untracked change.
The helper must never reset, stash, or delete work, or switch a dirty
worktree. Tests use local temporary Git repositories and no network. Separate ancestry checks prove:

```text
UPSTREAM_RUST_REV    is an ancestor of MOTOR_RUST_REV
RUST_LLVM_BASE_REV   is an ancestor of MOTOR_LLVM_REV
```

For Rust's submodules, read the gitlinks in `UPSTREAM_RUST_REV` and require
them to equal `RUST_LLVM_BASE_REV` and the upstream Cargo gitlink; then require
the gitlinks in `MOTOR_RUST_REV` to equal `MOTOR_LLVM_REV` and
`MOTOR_CARGO_REV`. The helper initializes `src/llvm-project` and
`src/tools/cargo` itself and sets `submodules = false` in the generated
bootstrap configuration so bootstrap never re-fetches or resets them. The submodule has `HEAD` detached at `MOTOR_LLVM_REV` before any LLVM or
`x.py` build runs. The standalone LLVM, compiler-rt,
libc++-family, and native LLVM build directories live outside the source tree
in keyed roots. Rustc's LLVM build remains under the `x.py`-owned Rust `build/`
tree described in section 5.5; it is incremental across commits and is not
separately keyed. The LLVM source submodule must be clean for every managed
build.

#### Source-authoring mode

Patch development is a separate, explicit input mode, not an exception hidden
inside managed checkout resolution. Invoke it as:

```sh
src/build-motor-os.sh \
    --source-mode authoring \
    --rust-source /absolute/path/to/rust \
    --authoring-base <full-upstream-Rust-commit>
```

The option spelling is part of the implementation contract. The full
`--authoring-base` commit is the exact upstream Rust commit onto which this
patch stack is being replayed; for the initial work it is the beta commit in
section 3.4. From the local Rust object database, the orchestrator reads that
commit's Rust version, Stage 0 identity, LLVM gitlink, and Cargo gitlink. It
derives the expected bootstrapped Cargo CLI release from that Rust version and
the configured `dev` channel, and separately verifies and records the Cargo
gitlink; it does not treat Cargo's `0.x` package version as the CLI release. It
records all of them as the selected base tuple. It rejects a short or missing
commit and cross-checks a selected base equal to
`UPSTREAM_RUST_REV` against all centrally declared values. This also supports
authoring a later Rust update before changing the current managed tuple.

The supplied Rust checkout and its initialized `src/llvm-project` submodule
are the authoritative authoring worktrees. The orchestrator uses that one LLVM
worktree for both the standalone LLVM/Clang build and rustc's LLVM build;
accepting an unrelated sibling LLVM checkout would split the LLVM identity. The Cargo submodule must be initialized, clean,
and exactly at the gitlink in the effective Rust `HEAD`; that gitlink must
remain the Cargo revision derived from `--authoring-base`. The effective
tree's `src/stage0` identity must likewise remain the one derived from the
authoring base. Cargo and Stage 0 authoring are outside this mode.

Authoring mode:

1. verifies repository identity and the configured remotes but performs no
   fetch, checkout, branch switch, reset, stash, clean, or submodule update;
2. accepts a current Rust `HEAD` that is a local or unpushed commit, provided
   the exact authoring-base Rust commit is its ancestor, and accepts the LLVM
   submodule's current `HEAD` provided the LLVM gitlink derived from that base
   is its ancestor;
3. accepts tracked changes, untracked files, and an LLVM submodule `HEAD` that
   has not yet been recorded as the Rust gitlink, because those are normal
   states while creating the two patch stacks;
4. sets `EFFECTIVE_MOTOR_RUST_REV` and `EFFECTIVE_MOTOR_LLVM_REV` from the two
   actual `HEAD`s and canonically hashes each worktree's changed-path record:
   tracked contents, modes, and deletion markers plus every permitted untracked
   path, mode, and content;
5. verifies both `HEAD`s and content digests immediately before and after each
   consuming build step, rejecting all produced artifacts if the source changed
   while a build was running; and
6. passes a generated configuration outside the source tree to `x.py`, while
   leaving normal ignored compiler build outputs in the author's Rust checkout.

Ignored files under the reviewed Rust `build/` and
`src/bootstrap/__pycache__/` compiler-output roots do not enter the digest,
and neither does an ignored root `bootstrap.toml`, because the configuration
passed through `--config` overrides it. Every Python process invoked while
building Rust, LLVM, or the native assembly redirects cache lookup and output
to the keyed toolchain state directory, so a source-tree bytecode cache cannot
affect the build. Reject any other ignored path, rather than assuming it cannot
affect the build. Untracked source inputs do enter the digest, and the
authoring allowlist rejects nested repositories other than the declared LLVM
and Cargo submodules, sockets, devices, and other unsupported file kinds.
Rust's superproject digest records its `HEAD` gitlink for LLVM, while the
effective LLVM revision and tree digest record what is actually built. This
makes an uncommitted gitlink update unambiguous. If `x.py` changes a tracked
lockfile, the post-build rejection in section 5.4 still applies; the script
reports the change for the author to review and does not revert it.

An authoring build always sets `MOTOR_SOURCE_MODE=authoring`, uses the effective
revisions and selected base tuple rather than substituting the declared release
revisions in both keys, and derives a non-release rustup-name base such as
`motor-authoring-1.99.0-f47d5bb13648`. Its compiler description is based on the
selected upstream version and gains
`+authoring.<full-AUTHORING_SOURCE_DIGEST>` even when both worktrees are clean.
That digest is computed before the bootstrap configuration from the selected
base, effective revisions, and Rust/LLVM tree states, avoiding a key/description
cycle. The description never claims the current managed lineage ID when
authoring a different upstream base.
A clean local patch stack has `MOTOR_ASSEMBLY_STATE=development-authoring`; any
uncommitted Rust, LLVM, mlibc, or relevant Motor OS input makes it
`development-dirty`. The result receives its own key-qualified rustup name; the
orchestrator exports that exact name and never edits the tracked root
`rust-toolchain.toml`.

Authoring artifacts cannot satisfy stable publication checks, update the
declared revisions automatically, replace the clean root override, or be
promoted into a managed prefix. Once the patch stacks are ready, push durable
Rust and LLVM refs, update the central manifest to their full commits and
gitlinks in a reviewed Motor OS change, and rebuild from clean managed
checkouts. Release validation applies only to that fresh managed build.

The intended editing loop is therefore: create the LLVM branch in
`rust/src/llvm-project` at the LLVM gitlink derived from the selected authoring
base, replay or edit the Motor LLVM commits, update the enclosing Rust gitlink,
and replay or edit the Rust commits on a Rust branch based at that authoring
base. Run authoring mode at any point, including before either worktree is
clean or pushed. Commit and push both stacks only when they are ready; no build
policy forces publication in order to test a patch.

The Motor OS checkout is different because it is the worktree containing the
orchestrator itself. `MOTOR_OS_RUNTIME_TREE` covers the exact `moto-rt`,
`moto-sys`, and `moto-rt-cabi` package inputs plus every workspace-level input
that affects their build: at least `src/sys/Cargo.toml`, the canonical
`src/sys/Cargo.lock` package entries in `moto-rt-cabi`'s resolved dependency
closure, applicable `.cargo/config.toml` files, target specifications actually
consumed, compiler/linker wrapper templates, and the shim build recipe. Derive
and test that closure offline with the Motor Cargo; fail if the lock cannot
describe the manifests. Do not hash unrelated workspace lock entries, which
would force a full C-sysroot rebuild after unrelated application dependency
updates. Hash canonical source recipes and semantic arguments, not generated
wrappers containing absolute sysroot paths; serialize such paths as named
placeholders. Keep this as an explicit reviewed path list; do not hash the whole
repository or silently discover a different set.
`MOTOR_OS_REV` is derived from the checked-out `HEAD`, and both are written
only to generated manifests. A local assembly attributed to formal source tags
requires those paths to be clean at that revision; local development assembly
is allowed but must be marked dirty and identified by the content digest.

### 5.2 One Motor toolchain from one Rust revision

No separate general host Rust toolchain is installed or selected: rustup is
installed with `--default-toolchain none` when it is absent, and `rustup
default` is never run. Rust `x.py` bootstraps directly from the Stage 0 compiler and
Cargo specified, with hashes, by the selected Rust source. That is
`MOTOR_RUST_REV` in managed mode and `EFFECTIVE_MOTOR_RUST_REV` in authoring
mode. Stage 0 is an implementation input to compiler bootstrap, not the
repository toolchain, and the scripts must not override it.

The one user-facing entry point is `src/build-motor-os.sh`. `build-base.sh` is
a private host-provisioning helper called only by that entry point: Ubuntu
packages, rustup installation without a default, and the tap/KVM setup. The
build sequence is:

1. Resolve every source checkout according to the selected mode (section 5.1)
   and verify its ancestry, submodule, and tree-state relationships. Print the
   declared tuple, effective tuple, and source mode.
2. Build the standalone cross LLVM/Clang/lld from the Rust checkout's
   `src/llvm-project` at the selected LLVM revision and tree, into a keyed
   build directory outside the source tree, and write the
   `motor-clang`/`motor-clang++`/`motor-rust-cc` wrappers. The wrappers
   reference the sysroot directory, which may still be empty.
3. Generate the bootstrap configuration (below) and run one `x.py` invocation
   from the selected Rust revision and tree. It builds the Linux-host compiler,
   std for both targets, Cargo from the `src/tools/cargo` gitlink, Clippy, and
   rustfmt, with LLVM built from the same effective `src/llvm-project` source
   state used in item 2, and installs the result into a tuple-keyed prefix
   (section 5.3). Register that prefix under the exact
   `${SELECTED_RUSTUP_TOOLCHAIN_BASE}-${MOTOR_TOOLCHAIN_KEY}` name. Validate
   its full key and prefix before anything else uses it.
4. Build `moto-rt-cabi` with the Motor toolchain, then compiler-rt builtins,
   mlibc, libunwind/libc++abi/libc++, the native LLVM multicall, and Lua, into
   assembly-keyed directories.
5. Run the second `x.py` invocation from the same revision for the native Motor
   rustc (`--host x86_64-unknown-motor`). Its own stage sysroot is
   `build/x86_64-unknown-motor/stage2`, and it may also recreate the Linux
   `stage2`; the installed prefix is unaffected either way.
6. Stage the generated image roots with manifests, build ripgrep and the OS
   with the Motor toolchain, and build the images.

After validating and registering the prefix, export its exact key-qualified
rustup name for every later repository command. Invoking the installed Cargo
by absolute path is not sufficient to select its sibling compiler: for every
direct assembly Cargo invocation, also set `RUSTC` and `RUSTDOC` to the
absolute executables in that validated prefix.

After the installed host toolchain is validated, all later host and
cross-target repository commands select it through a root
`rust-toolchain.toml` (or the explicitly exported authoring name), including
while the second `x.py` invocation builds native rustc. For example:

```toml
[toolchain]
channel = "motor-1.99.0-motor.1-<full MOTOR_TOOLCHAIN_KEY>"
```

During beta development, the base is the beta toolchain name from section 3.4
instead. For a clean declared tuple, this tracked file contains the exact
derived name and changes in the same reviewed patch as the tuple. A build from
authoring Rust or LLVM tree registers a different key-qualified name and the
orchestrator exports that exact toolchain for all of its subprocesses; it does
not rewrite the tracked root override or silently replace the clean
toolchain's link.

This file deliberately fails before the custom toolchain has been provisioned;
rustup cannot download a Motor-named toolchain from the public Rust servers.
The provisioning path must therefore never invoke a repository-default `cargo`
or `rustc` before `rustup toolchain link` has run; the only Rust commands
before that point are `x.py` and its Stage 0 tools. The manifest and an offline
test keep the toolchain name in the TOML file synchronized with
the clean tuple's derived `MOTOR_RUSTUP_TOOLCHAIN` and verify that the link
target is the prefix carrying the same full key.

The complete bootstrap configuration is generated deterministically from a
template and the manifest into a keyed generated-state directory, and its
absolute path is passed to `x.py --config`. `bootstrap.toml` is never created
or replaced in an authoring source checkout, and an existing generated
configuration is validated against the template rather than accepted because
it contains a marker. The identity-relevant settings are:

```toml
[build]
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]
description = "<SELECTED_TOOLCHAIN_DESCRIPTION>"
submodules = false                      # source-mode resolution validates both submodules
extended = true                         # x.py install installs tools only if set
tools = ["cargo", "clippy", "rustdoc", "rustfmt", "src"]
docs = false                            # default true: install would build all docs
optimized-compiler-builtins = false     # default depends on the channel; std has no C
locked-deps = false                     # stated explicitly; see section 5.4

[install]
prefix = "<tuple-keyed prefix under $MOTORH/toolchains>"
sysconfdir = "etc"                      # the default "/etc" is absolute and unwritable

[rust]
channel = "dev"
omit-git-hash = false

[llvm]
download-ci-llvm = false                # the library profile defaults it to true
targets = "X86"
```

The remaining settings (the `library` profile, `deny-warnings`, `incremental`,
`experimental-targets`, `static-libstdcpp`, and the
`[target.x86_64-unknown-motor]` wrapper paths) are fixed by the template as
well.
The exact key placement must match the pinned Rust bootstrap schema. The
settings above were checked against the bootstrap sources: the `Docs` install
step is gated by `build.docs`, not by `tools`; `install.sysconfdir` is joined
onto the prefix only when it is relative; and `optimized-compiler-builtins`
defaults to `false` only for the `dev` channel, so it must be pinned rather
than inherited from the channel.
`build.description` participates in the compiler's identity: bootstrap
documents that changing it changes crate IDs and symbol mangling and
invalidates incremental caches, and it appears in `rustc -vV`, which Cargo
fingerprints. It therefore stays constant for a managed snapshot and changes
with the release ID. Authoring mode uses the selected-base description and the
full `+authoring.<AUTHORING_SOURCE_DIGEST>` suffix defined in section 5.1, so a
local compiler can never be mistaken for the declared one by Cargo or by a
reader.
`omit-git-hash = false` makes `rustc -vV` report the effective Rust `HEAD`,
which distinguishes different committed patch stacks.

The compiler is built with the `dev` channel until Motor's unstable feature
usage has been removed; it is not an unmodified stock stable compiler.

### 5.3 Deterministic Rust tools and the installed prefix

Cargo, Clippy, and rustfmt are all ordinary Rust bootstrap tool steps: Cargo
builds from the `src/tools/cargo` gitlink that the effective Rust `HEAD`
records, and Clippy and rustfmt from the in-tree sources. `x.py install` builds
and installs them in the same invocation as the compiler and both stds; a
separate Cargo build outside bootstrap is unnecessary.

The linked toolchain is an installed prefix, not the `build/<host>/stage2`
sysroot, because bootstrap's `Sysroot` step removes that directory at the
start of every invocation. It is produced by `x.py install` with
`[install] prefix` pointing at `$MOTORH/toolchains/<MOTOR_RUSTUP_TOOLCHAIN>`,
whose exact name already includes `MOTOR_TOOLCHAIN_KEY`; this gives the
standard component layout including `rust-src`. Bootstrap's install steps
build with the compiler one stage below `--stage`, so `x.py install --stage 2`
installs the stage-2 artifacts. The stage sysroot is never copied by hand:
that would omit installer behavior and the vendored, reduced `rust-src`
component.

`x.py install` never runs into an existing prefix. An existing prefix is
reused only after its complete manifest passes validation; otherwise the
target must be absent, and an adjacent `<prefix>.building` lock directory is
created atomically before installation; the build stops if another process
owns it. After `x.py` returns, every component and the post-build lock hashes
are validated, the complete manifest is written inside the prefix, and only
then are the marker removed and the rustup link created. An interrupted,
invalid, or lock-rewrite prefix is marked rejected and never reused or
linked; the script reports it but does not delete it. A changed tuple
installs a new prefix under a new exact name. Later `x.py` invocations,
including the native rustc build, cannot damage it.

This does not port these tools to run on Motor; it supplies the Linux-host
tools that drive and check Motor cross-builds. Native Motor tools remain
separate binaries built from the same pinned source tuple. All resulting host
binaries and sysroots are local build artifacts; only the source refs and tags are published.

The required validation, all of which resolves inside the linked prefix and
reports the recorded identities without a rustup fallback notice:

```text
rustup which rustc --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
rustc +"$MOTOR_RUSTUP_TOOLCHAIN" -vV        # commit-hash = effective Rust HEAD
rustup which rustdoc --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
rustup which cargo --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
cargo +"$MOTOR_RUSTUP_TOOLCHAIN" -Vv       # commit-hash = selected Cargo revision
rustup which cargo-clippy --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
rustup which clippy-driver --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
rustup which cargo-fmt --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
rustup which rustfmt --toolchain "$MOTOR_RUSTUP_TOOLCHAIN"
rustc +"$MOTOR_RUSTUP_TOOLCHAIN" --print sysroot   # lib/rustlib/src/rust/library exists
```

plus a compile probe for each target and the existing strong-symbol checks on
the Motor std rlibs. Using Cargo from a separate stable or nightly installation
for repository work is not acceptable. Lorry's ordinary artifact-equivalence
tests and its resolution-oracle test use this exact Cargo. The oracle verifies
the full `cargo -Vv` identity against `SELECTED_MOTOR_CARGO_REV` (which equals
`MOTOR_CARGO_REV` in managed mode); it does not install or execute older Cargo
families or select `stable`, `beta`, or `nightly` aliases.
`remote-test-server` is not part of the toolchain and is not built.

### 5.4 Dependency selection and `moto-rt` maintenance

Normal builds run no `cargo update`, and Rust bootstrap enforces no lock
immutability (`locked-deps` is `false`). This policy is limited to the Rust
build; application and offline-test uses of `--locked` or `--locked --offline`
are their owning components' policy. The committed Rust root and library
lockfiles are the starting dependency selection, but `x.py` does not force
them to be immutable. If Cargo rewrites one because a manifest changed, the
diff stays visible. A formal source tag requires any such change to have been reviewed and
committed before a successful build.

Dependency resolution for the Rust tree happens inside `x.py`: bootstrap's
early `cargo metadata` pass runs with `--no-deps` and resolves nothing, so the
first Cargo build of the run, using the Stage 0 Cargo without `--locked`, is
what may rewrite a lockfile. There is no separate preflight; running Cargo
before `x.py` would need a repository toolchain that does not exist yet. Both
lockfiles are hashed at the start of the run and again after the build. The
provisional key and install path use the starting hashes. If either hash
differs afterwards, the run does not register or use that prefix, write a
valid stamp, or continue into the C sysroot and OS build: the prefix is
marked rejected, both hashes and the rewritten file are reported, the diff and
build outputs are preserved, and the build stops. The next run starts from the rewritten lock and derives a new key; it may
succeed only if the locks then remain unchanged. This ensures every accepted
prefix was actually built from the locks in its key. A formal tag requires
committed locks, so a release never starts from a lock that the build has to
rewrite.

Motor OS workspace lockfiles remain ordinary Cargo inputs. The `src/sys`
workspace manifest and the lock entries in `moto-rt-cabi`'s resolved closure
enter `MOTOR_OS_RUNTIME_TREE` because they affect the shim installed into the C
sysroot; unrelated lock entries and application locks are recorded in the image
manifest but do not enter either compiler/runtime key.

The Rust fork's Git patch declarations point at reviewed Motor fork sources.
For the beta tuple, `stacker`, `libloading`, and `libc` are pinned by full Git
revision as well as in the lockfile; `ctrlc` is on its named Motor branch,
with the lockfile recording the exact resolved commit. The forked `stacker`
provides Motor's allocation-based stack guard. The `libloading` and `libc`
forks carry distinct build-metadata versions (`0.9.0+motor.1` and
`0.2.186+motor.1`) so that multi-workspace vendoring cannot collide with their
crates.io counterparts; rustc LLVM keeps its `cc = "=1.2.16"` selection. Normal build scripts do not
run a dependency-refresh operation; advancing any selected dependency is an
explicit maintenance change.

Rust std depends on published crates.io `moto-rt`; the GitHub Rust
fork must never contain a path dependency or generated patch pointing to
`../motor-os`. To bump `moto-rt` between compiler-lineage releases (section 6.3 gives the
same procedure from the maintainer's side):

1. Bump the local `moto-rt` package version, validate it, and publish that
   version to crates.io.
2. Update the Rust fork's std dependency selection and `library/Cargo.lock` to
   the published version in a small maintenance change.
3. Commit that dependency-only change on the Motor Rust development branch. It
   does not require rebasing rustc, changing LLVM, or creating a new formal
   compiler tag.
4. Update `MOTOR_RUST_REV`, the std package version/checksum, and the matching
   local runtime version in the Motor OS manifest.
5. Before building `moto-rt-cabi`, require the local package version to equal
   the version resolved for Rust std. For a clean/formal assembly, also compare
   the publishable local package file set and per-file hashes with the exact
   cached registry package selected by `library/Cargo.lock`; equal version
   strings alone do not prove equal source. This verification is offline and
   does not fetch during a normal build. Concretely, verify the cached `.crate`
   file's SHA-256 against the lock checksum, extract it to a temporary
   directory, compare local `Cargo.toml` with `Cargo.toml.orig`, and compare
   the path set and hashes reported by the Motor Cargo's `cargo package --list`
   with every non-generated archive entry. Treat only Cargo's normalized
   `Cargo.toml`, generated `Cargo.lock`, and `.cargo_vcs_info.json` as
   generated entries. A development-dirty assembly may use differing local
   contents, but must say so explicitly. Record the registry checksum,
   package-comparison result, and local runtime content digest in the generated
   manifest.

Published compiler tags stay immutable. The next formal compiler source tag
carries the reviewed dependency selection forward; until then the exact
development-branch commit and the keys identify local builds.

### 5.5 Keys, version checks, stamps, and the image manifest

Before expensive work, the build prints and verifies every declared or
source-derived input:
the compiler-lineage ID; the selected upstream Rust version/ref/commit and
Stage 0 hash; expected Motor host rustc/rustdoc/Cargo/Clippy/rustfmt
identities; the declared and effective Motor Rust commits and tree state; Rust
LLVM base and declared and effective Motor LLVM commits and tree state; source
mode; mlibc; both `moto-rt` identities; the Motor OS runtime tree; the Rust
gitlinks; ancestry relationships; and lockfile hashes. Any existing reusable artifact is verified against those expectations.

All keys and content digests use SHA-256 and lowercase 64-character hexadecimal
output. The canonical serializer starts with its schema identifier and emits
fields in one documented order as length-prefixed name/value byte strings; it
never hashes ambiguous shell concatenation. File-tree entries are sorted by
repository-relative byte path and include path, file kind and executable mode,
content length, and contents (the link target for a symlink), with a distinct
kind for a tracked deletion; reject sockets, devices, and other unsupported
special files. Locale, filesystem enumeration order, absolute checkout path,
and mtime do not participate. Offline tests cover
embedded newlines, delimiter-like values, executable-bit and symlink changes,
input reordering, and the same tree in two absolute locations.

Two keys are derived from that canonical serialization:

- `MOTOR_TOOLCHAIN_KEY` covers what determines the compiler and its
  libraries: `MOTOR_TOOLCHAIN_ID`, `MOTOR_RUSTUP_TOOLCHAIN_BASE`,
  `MOTOR_SOURCE_MODE`, the selected rustup-name base and description, the
  selected upstream Rust/Stage 0/LLVM-base/Cargo identities, the effective Rust
  and LLVM revisions and their tree states, `AUTHORING_SOURCE_DIGEST`, the Rust
  root and library lock hashes at the start of the run, and the
  identity-relevant bootstrap settings (channel, description, targets, tools,
  LLVM options), but no host absolute paths. The declared Motor revisions are
  also recorded and included, including in authoring mode when they differ
  from the effective revisions.
- `MOTOR_ASSEMBLY_KEY` covers the toolchain key plus everything that
  determines the C sysroot and native artifacts: `MOTOR_MLIBC_REV` and its
  tree state, `MOTOR_OS_RUNTIME_TREE`, `LOCAL_MOTO_RT_VERSION`, and the
  standalone LLVM/compiler-rt/mlibc/libc++ configuration digest, canonically
  normalized to exclude host absolute paths.

The exact `MOTOR_RUSTUP_TOOLCHAIN` name is derived from the selected base plus
the full toolchain key after the key is computed; it is not itself a key input.
Absolute install and wrapper paths in the generated bootstrap configuration
are serialized using named placeholders when hashing the configuration,
avoiding both host-path identity and a key/name/prefix cycle.

For a clean managed build every toolchain-key input is either declared in
`src/toolchain-versions.sh` or fixed by the bootstrap template, so the offline
test recomputes the key and the exact rustup name from the declared data alone
and checks the tracked `rust-toolchain.toml` against them without any
checkout. A tuple update therefore ships the recomputed name in the same
reviewed patch, and the build refuses a tracked name that does not match the
key it derives.

The distinction matters for Motor OS development. `moto-rt`, `moto-sys`, and
`moto-rt-cabi` are ordinary workspace sources that Cargo already tracks; keying
the OS build's Cargo output directories by their content digest would force a
full OS rebuild after every `moto-rt` edit, so those directories change only
when the compiler changes. The runtime
digest belongs to the sysroot, whose `libmoto_rt_cabi.a` is built from it.

Directories are keyed by the narrowest set of inputs that determines them, and
the manifest records the mapping:

- the installed toolchain prefix: `MOTOR_TOOLCHAIN_KEY`;
- Motor OS Cargo outputs (`build/obj/<profile>`, the boot-loader and imager
  target directories, and `build/native-toolchain/*`): `MOTOR_TOOLCHAIN_KEY`,
  which the Makefile reads from the stamp inside
  `$(rustc --print sysroot)` rather than recomputing;
- the standalone cross LLVM build: the effective LLVM revision and tree state
  plus its normalized CMake/toolchain configuration digest;
- the C sysroot, builtins, libc++, native LLVM, Lua, native rustc staging, and
  the generated image roots: `MOTOR_ASSEMBLY_KEY`.

The mlibc producer extracts the tracked tree at `MOTOR_MLIBC_REV` into an
assembly-keyed source snapshot and runs Meson there. Meson's wrap lock and
commit-pinned subproject checkouts may populate that snapshot, but never the
authoritative managed mlibc checkout used to derive and verify the assembly
identity.

The Rust `build/` tree is owned by `x.py`, which is incremental across
commits; it is not re-keyed. The build scripts do not use `src/sys/target`; every Cargo invocation they
make sets `CARGO_TARGET_DIR` under the keyed roots. The same tuple may reuse its directory. A changed tuple gets a
different directory; the build must not delete or silently reuse the old one.
Each mutable keyed build root has an atomic per-key lock directory; a concurrent
producer for the same key stops rather than sharing a partially written tree.
An abandoned lock is reported for explicit inspection and is never removed as
part of automatic cleanup.

After building, the build validates at least `rustc -vV`, `cargo -Vv`, `clippy-driver
--version`, `rustfmt --version`, `clang --version`, `llvm-config --version`,
the rustc sysroot, and the Motor target library directory, and verifies that
the host and native rustc report `EFFECTIVE_MOTOR_RUST_REV` and the
description required by the source mode.

A versioned machine-readable manifest is written into the toolchain prefix,
every generated root, and the dev image, at this on-image path:

```text
/devtools/toolchain/manifest
```

It includes both meaningful upstream versions and exact source revisions, both
keys, source mode, declared and effective revisions, the Motor OS runtime
digest, tree-state and dirty markers, lock hashes, target, compiler channel,
and compiler version output. Authoring mode uses `development-authoring` when
all relevant worktrees are clean and `development-dirty` otherwise. A
permitted uncommitted lockfile diff present at the start of the build or another
dirty tree uses `development-dirty`; a lockfile rewrite during the build rejects
the run as described in section 5.4. Host absolute paths and identity-changing timestamps are excluded.

`build-motor-os.sh` sources the central manifest and rejects missing or
mismatched generated manifests instead of checking only for file presence. On
mismatch it names the stale directory and directs the user to the correctly
keyed build; it does not broadly clean it. Tests cover both a no-op incremental build with an unchanged tuple and selection of a fresh directory
when any tuple member changes.

## 6. Update workflow

A normal build never advances source refs or explicitly refreshes dependencies.
An update is a reviewed operation:

### 6.1 The first stable release: Rust 1.99.0

The beta baseline of section 3.4 is in place: the commit-qualified
development branches carry the replayed Motor patches, the declared revisions
point at them, and every further Rust or LLVM patch is developed in authoring
mode with the exact beta commit as `--authoring-base`, the declared revisions
being updated only when a stack is ready. Any move to a later beta commit is
an explicit reviewed tuple update. Development branches may be visible in the
GitHub forks, but no beta binaries are published and no beta ref is labeled
`1.99.0-motor.1`. When the upstream `1.99.0` tag is published:

1. Record its commit and compare its Stage 0, LLVM gitlink, Cargo gitlink,
   in-tree tools, and locks with the pinned beta tuple.
2. Rebase the Motor LLVM patches if the final LLVM pin changed. Rebase the
   Motor Rust branch onto the stable tag in all cases, update the LLVM gitlink,
   and resolve any changes explicitly.
3. Change the manifest from beta to stable and assign `1.99.0-motor.1`; build
   every artifact in new keyed output directories without repointing the beta
   root override. After the stable prefix and tuple pass, change
   `rust-toolchain.toml` to the stable key-qualified name and run the complete
   validation matrix through that override.
4. Create immutable source tags in the Rust and LLVM forks only after the stable
   tuple passes. Beta binaries are never promoted, relabeled, or published.

### 6.2 Subsequent stable updates

After the first release, selecting another stable Rust patch is a reviewed
operation:

1. Select an exact stable Rust patch release and record its tag commit and
   Stage 0 hash.
2. Read that tag's exact `src/llvm-project` gitlink and reported LLVM release
   line. This is `RUST_LLVM_BASE_REV`; Motor does not choose an independent
   nearby LLVM tag.
3. In a Rust authoring checkout based at the new `UPSTREAM_RUST_REV`, initialize
   `src/llvm-project` at the derived `RUST_LLVM_BASE_REV`, create a new
   versioned Motor LLVM branch there, and replay the minimal Motor patches. Do
   not force-rebase an already published toolchain branch or tag.
4. Create the new versioned Motor Rust branch at `UPSTREAM_RUST_REV`, replay
   the Motor std/rustc patches, and update the LLVM gitlink as the LLVM stack
   changes. Throughout steps 3-5, build with `--source-mode authoring`, the
   authoring Rust checkout, and the full new `UPSTREAM_RUST_REV` as
   `--authoring-base`; neither branch has to be clean or pushed to be tested.
5. Record the Cargo gitlink and verify the Clippy/rustfmt sources selected by
   the rebased Rust tree. Apply any deliberate Motor tool patches in that tree
   and record the resulting identities. Select the exact mlibc commit and
   deliberately update Git dependencies, `moto-rt`, and locks. When both patch
   stacks are ready, commit the LLVM gitlink, push the LLVM branch first, and
   push the Rust branch second.
6. Update the central manifest to the pushed full commits as one tuple and show
   old versus new versions, commits, and LLVM base. Do not copy or promote an
   authoring artifact.
7. Verify both ancestry relationships and require standalone LLVM and rustc's
   LLVM to use `MOTOR_LLVM_REV` exactly.
8. Build from clean source checkouts. If Cargo changes a dependency lock because
   a manifest changed, review and commit it before tagging. Install the
   complete versioned Motor rustup toolchain locally. After its manifest passes,
   change `rust-toolchain.toml` to the new key-qualified name and use it for all
   remaining host and cross-build commands.
9. Run version checks, toolchain tests, and required Motor OS tests.
10. Create immutable Motor source tags in the Rust and LLVM forks and verify all
    tags resolve to the recorded commits. Do not publish binary archives.
11. Commit the tuple and updated documentation together.

For a Rust patch upgrade such as 1.99.0 to 1.99.1, always compare the upstream
LLVM gitlinks. A Rust patch release can update LLVM for a correctness backport;
if it does, rebuild the Motor LLVM commit on the new base rather than retaining
the old LLVM because its major version is unchanged.

### 6.3 Runtime maintenance between compiler releases

A `moto-rt` update does not wait for the next Rust/LLVM lineage release:

1. Publish the tested new `moto-rt` crate version to crates.io; do not add a
   local path override to the Rust fork.
2. On the Motor Rust development branch, select that version for std, update the
   library lockfile, and commit the dependency-only change normally. Do not
   rewrite an existing formal tag.
3. Update the Motor OS manifest to the exact new Motor Rust commit and the
   matching local `moto-rt` version. Record the crates.io checksum,
   `MOTOR_OS_REV`, and local runtime content digest.
4. Require the local and std package versions and clean package contents to
   match, build into new keyed directories without repointing the old root
   override, and run the runtime/toolchain compatibility tests, including the
   three debug and three release full-test runs required for the local
   `src/sys` runtime change. After the new prefix passes, update
   `rust-toolchain.toml` to its key-qualified name.
5. Keep the semantic compiler-lineage ID unchanged. The exact Rust revision and
   the keys distinguish this build, and the next formal compiler branch and tag
   carry the reviewed dependency selection forward.

Managed and release workflows never select `latest` or a branch `HEAD`; they
use the exact revisions in reviewed files. Explicit authoring mode is the only
path that selects a current local `HEAD`, and it records that `HEAD` plus the
tree digest in a non-release generated manifest.

## 7. Properties

The implementation has the properties below; those that concern the upstream
stable tag, formal Motor source tags, or `1.99.0-motor.1` publication describe
the stable release of section 6.1 and are not yet exercised.

- The first published compiler source tags are based on the exact upstream Rust
  `1.99.0` stable tag, not a beta commit or binaries built from beta.
- Beta development uses an exact commit and distinct identity; it never follows
  beta `HEAD` or satisfies stable source-publication checks.
- The source tags and branches are published through the Motor Rust and LLVM
  GitHub forks; host binaries, sysroots, and image artifacts remain local.
- Clean and incremental compiler/runtime builds select the same exact tuple.
  Reusable output directories are keyed by that tuple, and the build performs
  no broad automatic target cleanup.
- Explicit authoring mode can build the current Rust `HEAD`, its current LLVM
  submodule `HEAD`, and their uncommitted source changes without fetching,
  switching, resetting, stashing, cleaning, or updating either worktree. Local
  and unpushed commits are valid authoring inputs; their effective revisions
  and content digests produce a distinct, non-release toolchain identity.
- Every declared managed Motor Rust revision descends from its declared stable
  Rust patch release; every declared managed Motor LLVM revision descends from
  the LLVM commit pinned by that stable Rust release; the Rust gitlink is
  reachable from a pushed Motor LLVM ref. Authoring revisions satisfy the same
  relationships against their explicitly selected authoring base.
- No normal build advances a toolchain source branch or explicitly refreshes
  dependency selections. Rust bootstrap does not enforce lock immutability;
  this does not remove component-owned `--locked`/offline test policy.
- The global rustup default is unchanged and may be absent.
- `src/build-motor-os.sh` is the single user-facing workflow. It builds the
  whole toolchain from one Motor Rust revision with two `x.py` invocations,
  and `build-base.sh` provisions the host only.
- No independently selected host Rust or Cargo remains in repository build,
  ordinary test, or formatting paths: the Makefile, the boot loaders, the
  imager, the host unit tests, Lorry itself, and `cargo fmt` all resolve to the
  same versioned Motor toolchain through the root override or its exact name.
  Rust's Stage 0 is used only inside `x.py`.
- Cargo, Clippy, rustdoc, rustfmt/`cargo-fmt`, and `rust-src` resolve inside
  that toolchain and cannot fall back to unrelated nightly, beta, or stable
  installations.
- The linked toolchain is an installed keyed prefix that no `x.py` invocation
  modifies. Its rustup name includes the full toolchain key, and the link,
  prefix manifest, and clean root override agree on that key.
- Lorry's implementation, specification, ordinary equivalence coverage, and
  resolution oracle support only the current Motor Cargo family. For this
  tuple that is the `1.99.0-dev` Cargo (family 1.99) at `MOTOR_CARGO_REV`; no
  1.97/1.98 or ambient-channel compatibility lane remains.
- Host and native rustc share one effective Rust revision and report it in
  `rustc -vV`; the standalone LLVM build and rustc LLVM build consume one
  effective LLVM revision and tree. Managed builds also require the declared
  Rust gitlink to equal that LLVM revision.
- Every authoring compiler carries a distinct description containing its full
  `AUTHORING_SOURCE_DIGEST` and is marked `development-authoring` or
  `development-dirty`. It cannot update the root override, satisfy
  source-publication checks, or be promoted; publishing the refs and updating
  the manifest is followed by a fresh clean managed build.
- Rust std uses published crates.io `moto-rt`, never a local path override. Its
  resolved version equals the local `moto-rt` version used for `moto-rt-cabi`,
  a clean assembly verifies the local publishable contents against that
  registry package, and both identities are present in the assembly manifest.
- A dependency-only `moto-rt` maintenance commit can advance the exact Motor
  Rust development revision and the keys without changing LLVM or the semantic
  compiler-lineage version; published source tags remain immutable.
- A `moto-rt` source edit changes the assembly key but not the toolchain key,
  so it does not force a full OS rebuild.
- Any dependency-lock rewrite remains visible and rejects the prefix produced
  by that run; no linked or stamped artifact is identified by pre-rewrite lock
  hashes. A formal source tag contains the reviewed committed result.
- Generated outputs, the toolchain prefix, and the dev image contain a
  validated manifest with the complete compiler/runtime tuple and both keys.
- `build-motor-os.sh` rejects stale or mismatched inputs.
- The toolchain tests are offline and run as part of `src/tests/full-test.sh`.

## References

- [Rust release schedule](https://forge.rust-lang.org/)
- [Pinned Rust 1.99 beta commit](https://github.com/rust-lang/rust/commit/f47d5bb13648d5c859f5b438eb7dc834b9729961)
- [Pinned Rust LLVM commit](https://github.com/rust-lang/llvm-project/commit/21cf28432798952d942bacc6bcee3a328faa3638)
- [Pinned Rust Cargo commit](https://github.com/rust-lang/cargo/commit/eb98b54bc9f3c74519f43d066cb3fd02ebc88df0)
- [Rust compiler bootstrapping](https://rustc-dev-guide.rust-lang.org/building/bootstrapping/what-bootstrapping-does.html)
- [Rust bootstrap configuration (`bootstrap.example.toml` at the pinned commit: `build.description`, `build.tools`, `install.prefix`, `rust.omit-git-hash`)](https://github.com/rust-lang/rust/blob/f47d5bb13648d5c859f5b438eb7dc834b9729961/bootstrap.example.toml)
- [Rust LLVM update and release-branch policy](https://rustc-dev-guide.rust-lang.org/backend/updating-llvm.html)
- [Rust Git submodule pinning](https://rustc-dev-guide.rust-lang.org/git.html#git-submodules)
- [rustup components](https://rust-lang.github.io/rustup/concepts/components.html)
- [rustup custom-toolchain Cargo fallback](https://rust-lang.github.io/rustup/concepts/toolchains.html)
- [rustup overrides and `rust-toolchain.toml`](https://rust-lang.github.io/rustup/overrides.html)
- [Cargo `-Zbuild-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std)
- [Cargo dependency resolution and offline behavior](https://doc.rust-lang.org/cargo/commands/cargo-build.html)
- [Cargo Git dependency revisions](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
