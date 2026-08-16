# Versioned and reproducible Motor OS toolchain

2026-08-13. Investigation and implementation plan for defining, building, and
reporting a meaningfully versioned Motor OS LLVM and Rust toolchain, with exact
source resolution enforcing that version policy. This document is for review
before implementation. No build scripts or source code were changed during the
investigation.

## 0. Decision summary

Motor OS should publish and build one atomic toolchain release with a meaningful
upstream lineage:

1. Target Rust `1.99.0` as the first stable Motor toolchain baseline.
2. When Rust 1.99 beta is published, pin an exact beta commit and use it as the
   temporary porting and validation baseline.
3. Read the exact `rust-lang/llvm-project` commit pinned by that Rust revision.
4. Start a new Motor LLVM development branch at that commit and replay the Motor
   patches on top.
5. Start new Motor Rust development branches at the beta commit, replay the
   Motor rustc and std patches, and point its LLVM gitlink at the resulting
   Motor LLVM commit.
6. Build standalone LLVM/Clang and rustc's LLVM from that same Motor LLVM
   commit.
7. Package Linux-host rustc, Cargo, host std, Motor std, Clippy, and rustfmt as
   one versioned Motor rustup toolchain and use it for all repository builds
   after bootstrap.
8. When the Rust `1.99.0` stable tag is published, rebase both Motor forks onto
   the final Rust and Rust-pinned LLVM commits, rebuild and revalidate the
   complete tuple, and only then publish `1.99.0-motor.1`.

Reproducibility is the mechanism that enforces this version policy, not the
only purpose of the policy.

The important rules are:

- final rustc, `core`, `alloc`, `std`, `proc_macro`, Clippy, and rustfmt come
  from the same Rust source revision;
- every published Motor Rust revision descends from the declared stable Rust
  tag;
- every published Motor LLVM revision descends from the exact LLVM gitlink in
  that stable Rust tag;
- standalone LLVM/Clang and rustc's LLVM use the same exact Motor LLVM commit;
- bootstrap-only Rust inputs are named separately from the shipped toolchain;
- mlibc and separately versioned runtime inputs such as `moto-rt` are recorded;
- Cargo is explicit, not a rustup fallback selected from installed channels;
- the same versioned Motor toolchain drives Linux-host work and Motor
  cross-compilation after it has bootstrapped;
- ordinary builds never advance branches or update dependency locks; and
- semantic versions describe upstream lineage, while full commits enforce it.

The public identity should report both the recognizable upstream versions and
the exact fork commits:

```text
Motor toolchain 1.99.0-motor.1
  based on upstream Rust 1.99.0 @ UPSTREAM_RUST_REV
  rustc + rust-std + Clippy + rustfmt @ MOTOR_RUST_REV
  Linux-host Cargo @ MOTOR_CARGO_REV
  based on Rust's LLVM 23.x snapshot @ RUST_LLVM_BASE_REV
  LLVM/Clang/lld/libc++/compiler-rt @ MOTOR_LLVM_REV
  mlibc @ MLIBC_REV
  moto-rt @ locked version/checksum
```

If rustc and rust-std are shown as separate rows, both must name the same Rust
revision. `moto-rt` can have its own version.

One decision remains before implementation:

1. Whether the first scope includes dev applications such as ripgrep and Lua,
   or only compiler/runtime inputs.

## 1. Goals and scope

- Make clean and incremental builds select the same reviewed sources.
- Give each published Motor toolchain a stable Rust release baseline and the
  corresponding Rust-pinned LLVM baseline.
- Use that Motor toolchain for host compilation, Motor cross-compilation, and
  native-tool source identity instead of selecting a separate host nightly.
- Reject stale, dirty, or mismatched inputs without deleting developer work.
- Make every version change an explicit checked-in diff.
- Preserve the existing two-phase Rust bootstrap initially.
- Put the exact source tuple in compiler output and the dev image.
- Keep normal tests offline and add no retries, ignored failures, or automatic
  cleanup that could conceal a defect.
- Implement in reviewable patches of roughly 100-300 lines including tests.

The initial work provides reproducible source resolution, not bit-for-bit
binary reproducibility. Pinning Ubuntu packages, host compilers, paths,
timestamps, and a hermetic build environment is future work. It also does not
change Rust stdlib or `moto-rt` APIs, remove the bootstrap dependency cycle, or
automatically adopt the latest upstream release.

## 2. Correct version roles

There are three build-time Rust roles, all derived from the selected Rust
baseline rather than an independently selected host nightly. During the first
implementation cycle that baseline is an exact Rust 1.99 beta commit; the
published toolchain uses the final stable `1.99.0` tag:

1. Rust `x.py` downloads the older Stage 0 compiler and Cargo recorded, with
   hashes, in the selected Rust commit's `src/stage0`. This compiler exists only
   to bootstrap the chosen Rust source.
2. The first-pass Motor Rust source creates enough of the versioned Motor
   toolchain to build later LLVM/mlibc stages.
3. The final Motor Rust source produces Linux-host rustc and Cargo, host and
   Motor std, Clippy, rustfmt, and the native Motor rustc/std artifacts.

The current first-pass and final development branches are `motor-os-rt-v17` and
`motor-os-rustc`. Policy-conforming releases should use new immutable,
versioned refs for both phases rather than moving or force-rebasing those public
branches.

### 2.1 Stable source does not mean stock stable-channel behavior

The final Motor Rust fork must be based on an exact stable Rust patch tag. Rust
is a monorepo: that tag identifies both rustc and the matching `library/`
sources. The Motor compiler and std remain one source revision after Motor
patches are applied.

Motor OS nevertheless uses unstable language features and Cargo options such
as `-Zbuild-std` and `-Zjson-target-spec`. Until those uses are removed, the
Motor compiler and Cargo must expose `dev` or nightly feature behavior. This is
not the same as tracking a moving nightly source branch. The accurate
description is "Motor Rust based on stable Rust X.Y.Z, built with unstable
features enabled."

### 2.2 One Motor toolchain after bootstrap

The stable versioned rustup toolchain `motor-1.99.0-motor.1` must contain:

- Linux-host rustc and Cargo;
- Linux-host standard libraries;
- Motor target standard libraries;
- Clippy and its driver;
- rustfmt; and
- the built-in Motor target support.

After `x.py` has created and the build has registered that toolchain, all host
and cross-target repository commands use it explicitly. Native Motor rustc is a
different binary because it runs on a different host, but it comes from the
same `MOTOR_RUST_REV` and uses the same `MOTOR_LLVM_REV`.

There are two unavoidable exceptions to "one toolchain everywhere":

- compiler bootstrapping uses the older Stage 0 selected by `src/stage0`; and
- a compatibility test may explicitly invoke an older Rust/Cargo as a named
  fixture. For example, Lorry's Cargo 1.98 tests may retain
  `nightly-2026-06-19`, but it must be named as a test fixture and must not be
  the repository or host build toolchain.

### 2.3 Rust supplies the LLVM baseline

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

The final Motor Rust commit changes the upstream Rust gitlink from
`RUST_LLVM_BASE_REV` to `MOTOR_LLVM_REV`. The build must require the sibling
LLVM checkout, initialized Rust submodule, standalone LLVM artifacts, and
rustc's built LLVM to all equal `MOTOR_LLVM_REV`.

Rust patch releases may change their LLVM gitlink to deliver a correctness
backport. Therefore an upgrade from, for example, Rust 1.99.0 to 1.99.1 must
compare the two LLVM bases and replay Motor patches when it changes.

### 2.4 First baseline: 1.99 beta, then 1.99.0 stable

The first policy-conforming Motor release targets Rust `1.99.0`. Rust 1.99 is
scheduled to enter beta on 2026-08-14 and become stable on 2026-10-01. Motor OS
will use the beta period to perform and test the port, then publish only after
rebasing onto the final stable tag.

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
gitlink. Re-read Stage 0 and Cargo identities from the stable Rust tree, rebuild
every compiler and library artifact, and repeat the complete validation. Only
that result is `1.99.0-motor.1`.

This choice avoids establishing a short-lived 1.97.1 or 1.98.0 baseline. Rust
1.97.1 and the current 1.98 beta use LLVM 22, while the current Motor Rust work
is already based on Rust 1.99 development sources and LLVM 23. The 1.99 beta is
therefore the closest release-line starting point for the existing Motor
patches.

## 3. Current observed tuple

This was observed in sibling checkouts and artifacts on 2026-08-13. It predates
the stable-lineage policy above. It can be pinned as a temporary development
snapshot, but it is not the intended first policy-conforming release.

| Role | Observed identity | Current enforcement |
|---|---|---|
| Legacy general host Rust (current defect) | `nightly-2026-06-19`; rustc 1.98.0-nightly (`bc2112ed5`) | Exact date, but installed as global default |
| Legacy host Cargo (current defect) | 1.98.0-nightly (`598ab48ec`) | Installed but not used by inspected `cargo +dev` |
| Bootstrap Rust source | `607430137e0855530b5af17350c0d0db33437046` | Branch/local checkout only |
| Final rustc and std | 1.99.0-dev at `4e81c4818fb73d233030eb2af0d2cdfe7e8bf1b5` | Branch/local checkout only |
| Rust Stage 0 | beta `08d5b675a9b2abdca5e2fe4eabe0e07bbda15d49`, 2026-07-13 | Pinned by Rust commit |
| LLVM/Clang | 23.0.0git at `88ea5aa2a7b4f634c6698e7674eafa2367e1aad4` | Branch/local checkout plus major check |
| Rust LLVM gitlink | `88ea5aa2a7b4f634c6698e7674eafa2367e1aad4` | Exact in current Rust commit, but script uses sibling `HEAD` |
| mlibc | `52fd5e0ffb2c9ae4cad0a20388e2655826f301d2` | Branch/local checkout only |
| `moto-rt` used by std | 0.17.2, checksum `4bd9f2a3dda6c3a6800f30bdd2f313bafcb45a7857fb6a7cf1295e05141bd3ec` | Lockfile, but normal build updates it |
| Cargo used by `cargo +dev` | 1.99.0-nightly (`3efb1f477`), 2026-07-17 | Floating rustup fallback on this machine |

The Stage 2 compiler currently reports `rustc 1.99.0-dev`, LLVM 23.0.0, and
`commit-hash: unknown`. Rust dev builds omit Git metadata by default, making
different compilers look identical. The current Rust history contains an
upstream "Update to LLVM 23" commit, but the released stable Rust tag must be
the authority for the first stable-based Motor rebase.

The June nightly is historical provisioning state, not a meaningful member of
this tuple: it is neither the selected final Rust release nor the Stage 0 named
by that release. It must disappear from the general build path. A deliberately
old compatibility test may keep it only under a fixture-specific name.

A policy-conforming release manifest should have this shape after the final
stable tag is selected:

```sh
MOTOR_TOOLCHAIN_ID="1.99.0-motor.1"
MOTOR_RUSTUP_TOOLCHAIN="motor-1.99.0-motor.1"

UPSTREAM_RUST_VERSION="1.99.0"
UPSTREAM_RUST_REF="refs/tags/1.99.0"
UPSTREAM_RUST_REV="<full commit for the upstream Rust tag>"

RUST_LLVM_VERSION="23.x"
RUST_LLVM_BASE_REF="<rust-lang LLVM release branch or durable ref>"
RUST_LLVM_BASE_REV="<LLVM gitlink from UPSTREAM_RUST_REV>"

MOTOR_LLVM_REF="refs/tags/motor-toolchain-1.99.0-motor.1"
MOTOR_LLVM_REV="<RUST_LLVM_BASE_REV plus Motor patches>"

BOOTSTRAP_RUST_REF="refs/tags/motor-bootstrap-1.99.0-motor.1"
BOOTSTRAP_RUST_REV="<bootstrap Motor commit based on UPSTREAM_RUST_REV>"

MOTOR_RUST_REF="refs/tags/motor-toolchain-1.99.0-motor.1"
MOTOR_RUST_REV="<UPSTREAM_RUST_REV plus Motor rustc/std patches>"
MOTOR_RUST_CHANNEL="dev"
MOTOR_CARGO_REV="<Cargo gitlink recorded by MOTOR_RUST_REV>"

MOTOR_MLIBC_REF="<durable Motor mlibc ref>"
MOTOR_MLIBC_REV="<full Motor mlibc commit>"
```

Repository URLs and expected tool/runtime identities also belong there. In the
inspected Rust source, Cargo is a submodule whose exact revision is selected by
the Rust tree, while Clippy and rustfmt are in-tree sources selected directly
by `MOTOR_RUST_REV`. None is an independently selected host tool. The manifest
must assert that `UPSTREAM_RUST_REV` is an ancestor of both Motor Rust phases,
`RUST_LLVM_BASE_REV` is an ancestor of `MOTOR_LLVM_REV`, the LLVM gitlink in
`MOTOR_RUST_REV` equals `MOTOR_LLVM_REV`, and the Cargo gitlink equals
`MOTOR_CARGO_REV`. Recheck this layout when selecting a new upstream Rust
release. A durable tag is a useful fetch locator, but the full commit must
still be stored and checked because tags can move.

## 4. Problems found

### 4.1 Sources are selected by branch or local state

`src/build-motor-os.sh::clone_repo` checks out `motor-os-rustc` only for a new
clone. An existing LLVM or mlibc checkout is accepted without verifying remote,
branch, commit, or cleanliness. A new clone gets the branch tip available that
day. LLVM is checked only for the Motor triple and major version 23.

`src/build-base.sh` and `update_rust` similarly accept local Rust branches at
any commit. The Rust LLVM submodule is forced to the sibling LLVM checkout's
`HEAD`, so the sibling checkout—not a central declaration or Rust gitlink—is
currently authoritative. An existing rustup link is accepted by name without
checking its target path or compiler revision.

### 4.2 `cargo +dev` is floating

The custom `dev-x86_64-unknown-motor` Stage 2 `bin` directory contains
`rustc`, `cargo-clippy`, and `clippy-driver`, but no Cargo. Rustup consequently
borrows Cargo from an installed release channel, preferring floating nightly.
On the inspected machine it selected July Cargo 1.99 rather than the declared
June Cargo 1.98. Selection can differ based on unrelated installed toolchains.

This affects the root Makefile and scripts that invoke:

```text
cargo +dev-x86_64-unknown-motor ...
```

It is a reproducibility and clean-provisioning defect.

### 4.3 Normal builds mutate dependency selection

`update_rust` runs `cargo update` for four Git-patched crates and `moto-rt`,
suppresses output, and ignores failure with `|| true`. The root lock currently
pins exact Git commits, and the library lock selects `moto-rt` 0.17.2, but these
commands can move them. Normal builds must consume reviewed locks; updates
belong in a separate maintenance workflow. Ignored update failure also violates
the repository rule against concealing defects.

### 4.4 Global/config/generated state is weakly controlled

`build-base.sh` runs `rustup default nightly-2026-06-19`, changing the user's
global configuration. There is no root `rust-toolchain.toml`.

That nightly is unrelated to both the current final compiler and Rust's
source-selected Stage 0. Keeping it as a third general compiler adds a
compatibility variable without providing a meaningful version relationship.

Existing `bootstrap.toml` files are accepted using broad marker checks rather
than complete validation. `build-dev.sh` checks only that generated tool files
exist, not which sources produced them. No canonical version manifest is staged
in the image.

Ripgrep also fast-forwards `master` on each build. Lua has a named version but
should have a checked download checksum if it joins the reproducibility scope.

## 5. Proposed design

### 5.1 Central manifest and exact checkout helper

Add a data-only `src/toolchain-versions.sh`, sourced by relevant scripts. It
contains the Motor toolchain ID and maturity; upstream Rust target version, ref,
and revision; Rust's LLVM display version and base revision; final Motor Rust
and LLVM revisions; repository URLs; durable refs; expected Cargo/runtime
identities; and generated-manifest schema. Do not duplicate values in scripts,
tests, and prose.

For the initial beta work, it also records a `beta` maturity state, a distinct
non-release toolchain ID, and the exact beta Rust commit. Release packaging must
reject that state. The October conversion changes the state to `stable`, the
upstream ref to `refs/tags/1.99.0`, and the toolchain ID to
`1.99.0-motor.1` only after all final commits have been selected.

Replace branch-only source handling with a helper that:

1. clones the expected repository if absent;
2. verifies an existing worktree and remote;
3. stops on tracked or unexpected untracked changes;
4. fetches the declared durable ref;
5. verifies the ref resolves to the full expected commit;
6. checks out that commit detached; and
7. verifies `HEAD` immediately before building.

It must never reset, stash, or delete developer work. Tests use local temporary
Git repositories and no network. Separate ancestry checks must prove:

```text
UPSTREAM_RUST_REV    is an ancestor of BOOTSTRAP_RUST_REV
UPSTREAM_RUST_REV    is an ancestor of MOTOR_RUST_REV
RUST_LLVM_BASE_REV   is an ancestor of MOTOR_LLVM_REV
```

For Rust LLVM, read the gitlink in `UPSTREAM_RUST_REV` and require it to equal
`RUST_LLVM_BASE_REV`. Then require the gitlink in `MOTOR_RUST_REV` to equal
`MOTOR_LLVM_REV`. Seeding from sibling LLVM may remain a transfer optimization,
but the final submodule must be detached at the declared Motor commit.

### 5.2 One Motor rustup toolchain and bootstrap configuration

Do not install or select a separate general host Rust toolchain. Rust `x.py`
must bootstrap directly from the Stage 0 compiler and Cargo specified, with
hashes, by the selected `UPSTREAM_RUST_REV`/`MOTOR_RUST_REV` source. Stage 0 is
an implementation input to compiler bootstrap, not the repository toolchain.
The scripts must not override it with a date chosen by Motor OS.

After the final `x.py` build and installation, register its sysroot under the
exact `MOTOR_RUSTUP_TOOLCHAIN` name. It must contain the host rustc, Cargo,
host std, Motor std, Clippy, rustfmt, and their required drivers/libraries.
Add a root `rust-toolchain.toml` whose channel is that custom name, for example:

```toml
[toolchain]
channel = "motor-1.99.0-motor.1"
```

This file deliberately fails before the custom toolchain has been provisioned;
rustup cannot download a Motor-named toolchain from the public Rust servers.
The provisioning path must therefore use `x.py` and its explicit Stage 0 paths,
then run `rustup toolchain link` without invoking a repository-default rustc or
Cargo first. The manifest and an offline test must keep the toolchain name in
the TOML file synchronized with `MOTOR_TOOLCHAIN_ID`.

Generate the complete `bootstrap.toml` deterministically or validate it against
a template. Do not accept arbitrary configuration containing one marker. Set:

```toml
[build]
description = "<MOTOR_TOOLCHAIN_ID>"

[rust]
omit-git-hash = false
```

The exact placement must match the pinned Rust bootstrap schema. The description
participates in compiler/crate identity, so it remains stable for a snapshot
and deliberately changes with the release ID to invalidate stale artifacts.

Preserve the two Rust phases initially, but base and pin both
`BOOTSTRAP_RUST_REV` and `MOTOR_RUST_REV` on `UPSTREAM_RUST_REV`. The shipped
rustc and std are verified after the final phase. Build the final compiler with
the approved `dev`/nightly-capable channel until Motor's unstable feature usage
has been removed; do not describe it as an unmodified stock stable compiler.

### 5.3 Deterministic Rust tools

Initialize the Cargo submodule recorded by `MOTOR_RUST_REV`; build it plus the
in-tree Clippy and rustfmt sources for the Linux host through Rust bootstrap;
and install the verified binaries in the final custom toolchain after the last
sysroot-mutating `x.py` step. This does not port these tools to run on Motor; it
supplies the Linux-host tools that drive and check Motor cross-builds. Native
Motor tools remain separate binaries built from the same pinned source tuple.

Required validation:

```text
rustup which cargo --toolchain motor-1.99.0-motor.1
cargo +motor-1.99.0-motor.1 -Vv
rustup which clippy-driver --toolchain motor-1.99.0-motor.1
rustup which rustfmt --toolchain motor-1.99.0-motor.1
```

They must resolve inside the linked Motor sysroot and report the recorded
source identities without a rustup fallback notice. Using Cargo from a
separate stable or nightly installation is not an acceptable final design. A
named, offline compatibility test fixture may invoke an older Cargo, but the
fixture must not be reachable from normal build commands.

### 5.4 Locked dependencies

Remove both `cargo update` commands from normal builds. Use the committed Rust
root and library lockfiles with `--locked` where bootstrap permits it, and fail
if either lock changes during a build. Fetching dependencies and updating them
are separate operations.

For defense in depth, change the Rust fork's Git patches from branch selectors
to exact `rev` values or durable tags during an explicit fork update. The
library lock can remain authoritative for `moto-rt`, or the fork can use an
exact requirement. Either way, ordinary builds never update it.

### 5.5 Version checks, stamps, and image manifest

Before expensive work, print and verify the release ID; upstream stable Rust
version/tag/commit; the versioned Motor host rustc/Cargo/Clippy/rustfmt;
bootstrap/final Motor Rust commits; Rust Stage 0 metadata; Rust LLVM base and
final Motor LLVM versions/commits; mlibc; Rust and tool gitlinks; ancestry
relationships; and lockfile hashes.

After building, validate at least `rustc -Vv`, `cargo -Vv`, `clang --version`,
`llvm-config --version`, the rustc sysroot, and Motor target library directory.
Verify final rustc and std came from `MOTOR_RUST_REV`, not the bootstrap branch.

Write a versioned machine-readable manifest into generated roots and the dev
image, with a canonical on-image path such as:

```text
/sys/tools/toolchain/manifest
```

Include both meaningful upstream versions and exact source revisions, plus lock
hashes, target, compiler channel, and compiler version output. Exclude host
absolute paths and identity-changing timestamps. Add small source-tuple stamps
to reusable build directories.

`build-dev.sh` sources the central manifest and rejects missing or mismatched
generated manifests instead of checking only for file presence. On mismatch it
names the stale directory and directs the user to rebuild; it does not broadly
clean it.

## 6. Changes by file

- New `src/toolchain-versions.sh`: authoritative stable Rust lineage, Rust LLVM
  base, Cargo gitlink, final Motor tuple, and schema.
- New root `rust-toolchain.toml`: select the versioned custom Motor toolchain;
  validate its name against the central manifest.
- `src/build-base.sh`: source pins; no separately installed host compiler and
  no global default change; exact bootstrap Rust checkout; use the Stage 0
  selected by that source; deterministic bootstrap configuration.
- `src/build-motor-os.sh`: exact LLVM/mlibc/final Rust checkout; enforce
  upstream ancestry and both LLVM gitlink relationships; remove updates/ignored
  failures; build Cargo/Clippy/rustfmt; assemble and register the complete
  versioned toolchain; embed identity; write manifests and stamps.
- `src/build-dev.sh`: require the exact generated tuple before image assembly.
- Makefiles/component scripts: replace `cargo +dev` and independent host
  selections with the root override or the exact
  `MOTOR_RUSTUP_TOOLCHAIN` name.
- `docs/build-motor-os.md`, `docs/build-rustc.md`, and recipes: identify the
  stable Rust and Rust-LLVM baselines, distinguish bootstrap versus final
  versions, and document inspection/update procedures.

## 7. Incremental implementation and tests

Each numbered item is a separate reviewable patch.

1. After Rust 1.99 enters beta, resolve the beta ref to an exact commit, read its
   LLVM gitlink, and create new non-release Motor LLVM and Rust development
   branches. Do not force-rebase the existing public development branches.
2. Add the approved manifest and an offline shell test for required fields,
   full commit formats, ancestry, LLVM/Cargo gitlinks, maturity state, and
   schema/toolchain ID. Test that beta state cannot produce a stable release.
3. Remove the host-nightly installation and global-default mutation. Make
   bootstrap use only the Stage 0 declared by the pinned Rust source; test its
   identity and checksum handling.
4. Pin bootstrap Rust and validate its ancestry from the selected beta or
   stable baseline and its deterministic bootstrap configuration.
5. Add exact LLVM/mlibc checkout handling. Test locally: new/correct checkout,
   stale commit, ref/SHA mismatch, wrong remote, dirty/untracked state, and
   missing commit.
6. Pin final Rust, verify its selected-baseline ancestry, and require its LLVM
   gitlink to equal the Motor LLVM pin built on Rust's declared LLVM base.
7. Remove normal `cargo update`; add offline lockfile immutability tests.
8. Build/install pinned Cargo, Clippy, and rustfmt; register the complete custom
   toolchain; add `rust-toolchain.toml`; update repository commands; and test
   that rustup cannot fall back to nightly/beta/stable.
9. Enable Rust Git metadata and release description; test version output and
   intentional cache identity.
10. Write generated manifests/stamps; test acceptance of the exact tuple and
   rejection of changed Rust, LLVM, mlibc, Cargo, lock hashes, or schema.
11. When Rust 1.99.0 is published, rebase onto its exact tag and LLVM pin,
    update all transitive identities, switch the manifest to stable, rebuild
    from clean outputs, and repeat the entire validation matrix.
12. Package the stable manifest, smoke-test host and native tools, and create
    immutable `1.99.0-motor.1` release tags.
13. Separately decide broader pinning for ripgrep, Lua checksums, and host input
    reproducibility.

Real-toolchain smoke coverage should compile a minimal Motor executable, run
Clippy through the custom toolchain, verify final Motor std artifacts, inspect
native rustc/LLVM versions in the dev VM, and compare the packaged manifest to
the host source tuple. New tests must be offline and included in
`src/tests/full-test.sh` directly or transitively. Run the debug/release build
and test coverage appropriate to each affected build path without adding
warnings.

## 8. Explicit update workflow

A normal build never advances the toolchain. An update is a reviewed operation:

### 8.1 First release: Rust 1.99 beta to Rust 1.99.0

1. Wait for the Rust 1.99 beta branch to be published, resolve it to a full
   commit, and record that exact commit rather than following beta `HEAD`.
2. Read the beta commit's LLVM and Cargo gitlinks, create non-release Motor
   development refs, replay the Motor patches, and build the beta Motor tuple.
3. Use the beta period to implement the manifest, deterministic checkout,
   unified rustup toolchain, version validation, and all required tests. Any
   move to a later beta commit is an explicit reviewed tuple update.
4. Do not publish beta binaries or refs as `1.99.0-motor.1`.
5. When the upstream `1.99.0` tag is published, record its commit and compare
   its Stage 0, LLVM gitlink, Cargo gitlink, in-tree tools, and locks with the
   pinned beta tuple.
6. Rebase the Motor LLVM patches if the final LLVM pin changed. Rebase both
   Motor Rust phases onto the stable tag in all cases, update the final LLVM
   gitlink, and resolve any changes explicitly.
7. Change the manifest from beta to stable and assign `1.99.0-motor.1`; rebuild
   every artifact from clean outputs and run the complete validation matrix.
8. Create immutable release tags only after the stable tuple passes. Beta
   binaries are never promoted or relabeled.

### 8.2 Subsequent stable updates

After the first release, selecting another stable Rust patch is a reviewed
operation:

1. Select an exact stable Rust patch release and record its tag commit.
2. Read that tag's exact `src/llvm-project` gitlink and reported LLVM release
   line. This is `RUST_LLVM_BASE_REV`; Motor does not choose an independent
   nearby LLVM tag.
3. Create a new versioned Motor LLVM branch at `RUST_LLVM_BASE_REV` and replay
   the minimal Motor patches, producing `MOTOR_LLVM_REV`. Do not force-rebase an
   already published toolchain branch or tag.
4. Create a new versioned Motor Rust branch at `UPSTREAM_RUST_REV`, replay the
   bootstrap and final Motor rustc/std patches, and change the final Rust LLVM
   gitlink to `MOTOR_LLVM_REV`.
5. Verify the Cargo gitlink and Clippy/rustfmt sources selected by the rebased
   Rust tree. Apply any deliberate Motor tool patches in that tree and record
   the resulting identities. Select the exact mlibc commit and deliberately
   update Git dependencies, `moto-rt`, and locks.
6. Update the central manifest as one tuple and show old versus new versions,
   commits, and LLVM base.
7. Verify both ancestry relationships and require standalone LLVM and rustc's
   LLVM to use `MOTOR_LLVM_REV` exactly.
8. Build from clean checkouts, require unchanged lockfiles, assemble the
   complete versioned Motor rustup toolchain, and use it for all remaining host
   and cross-build commands.
9. Run version checks, toolchain tests, and required Motor OS tests.
10. Create immutable Motor release tags and verify all tags resolve to the
    recorded commits.
11. Commit the tuple and updated documentation together.

For a Rust patch upgrade such as 1.99.0 to 1.99.1, always compare the upstream
LLVM gitlinks. A Rust patch release can update LLVM for a correctness backport;
if it does, rebuild the Motor LLVM commit on the new base rather than retaining
the old LLVM because its major version is unchanged.

The workflow never selects `latest` or branch `HEAD` without recording the
resolved exact revisions in reviewed files.

## 9. Completion criteria

- The first published toolchain is based on the exact upstream Rust `1.99.0`
  stable tag, not a beta commit or binaries built from beta.
- Beta development uses an exact commit and distinct identity; it never follows
  beta `HEAD` or satisfies stable release packaging checks.
- Clean and incremental builds select the same exact tuple.
- Every final Motor Rust revision descends from its declared stable Rust patch
  release.
- Every Motor LLVM revision descends from the LLVM commit pinned by that stable
  Rust release.
- No normal build follows a moving branch or runs `cargo update`.
- The global rustup default is unchanged.
- No independently selected host Rust or Cargo remains in the normal build.
- The source-selected Stage 0 is used only for bootstrap.
- The root override and explicit build commands resolve to the same versioned
  Motor rustup toolchain.
- Cargo, Clippy, and rustfmt resolve inside that toolchain and cannot fall back
  to unrelated nightly, beta, or stable installations.
- Final rustc/std share one Motor Rust revision; the final Rust gitlink,
  standalone LLVM build, and rustc LLVM build share one Motor LLVM revision.
- rustc reports its commit and Motor release ID.
- lockfiles remain unchanged during normal builds.
- generated outputs and the dev image contain a validated manifest.
- `build-dev.sh` rejects stale or mismatched inputs.
- all new tests are offline, integrated, and pass with the required build/test
  matrix and no new warnings.

## References

- [Rust release schedule](https://forge.rust-lang.org/)
- [Rust compiler bootstrapping](https://rustc-dev-guide.rust-lang.org/building/bootstrapping/what-bootstrapping-does.html)
- [Rust LLVM update and release-branch policy](https://rustc-dev-guide.rust-lang.org/backend/updating-llvm.html)
- [Rust Git submodule pinning](https://rustc-dev-guide.rust-lang.org/git.html#git-submodules)
- [rustup components](https://rust-lang.github.io/rustup/concepts/components.html)
- [rustup custom-toolchain Cargo fallback](https://rust-lang.github.io/rustup/concepts/toolchains.html)
- [rustup overrides and `rust-toolchain.toml`](https://rust-lang.github.io/rustup/overrides.html)
- [Cargo locked/offline behavior](https://doc.rust-lang.org/cargo/commands/cargo-build.html)
- [Cargo Git dependency revisions](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
