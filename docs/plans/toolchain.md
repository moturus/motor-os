# Versioned and reproducible Motor OS toolchain

2026-08-13, updated 2026-08-26. Investigation and implementation plan for
defining, building, and reporting a meaningfully versioned Motor OS LLVM and
Rust toolchain, with exact source resolution enforcing that version policy.
This document is for review before implementation. No build scripts or source
code were changed during the investigation or during the 2026-08-25 review.

The 2026-08-25 review checked every claim below against `src/build-base.sh`,
`src/build-motor-os.sh`, the Makefile and test scripts, the sibling Rust, LLVM,
and mlibc checkouts, and the pinned upstream commits on GitHub. Its main design
change is section 4.6: the Motor toolchain is built from one Motor Rust source
revision, and the separate bootstrap branch, bootstrap-only Cargo, and
bootstrap-only rustup toolchain of the previous revision of this plan are
dropped. Section 5.5 also separates the compiler identity that keys Motor OS
build outputs from the wider assembly identity that keys the C sysroot.

A second pass on the same day re-verified the bootstrap mechanics of section 5
against the Rust bootstrap sources: `x.py install` semantics, the settings that
must be explicit (`docs`, `optimized-compiler-builtins`, a relative
`install.sysconfdir`), and the fact that bootstrap's own `cargo metadata` pass
runs with `--no-deps`, which replaced the lock-resolution preflight with lock
hashing before and after the build.

The 2026-08-26 revalidation retained that design and closed the remaining
gaps: Lorry supports only the Cargo selected by the current Motor toolchain;
managed source checkouts are exact while an explicit authoring mode builds a
developer's current Rust and LLVM worktrees without switching them; an `x.py`
run that rewrites a Rust lockfile cannot register an artifact under the
pre-rewrite key; the local runtime digest includes the workspace-level inputs
that affect `moto-rt-cabi`; exact rustup names include the toolchain key; and
the new path is prepared side-by-side before an atomic selector cutover.

The 2026-08-26 review of that revalidation kept its additions and corrected
them where the sources disagree: the Motor Cargo reports `1.99.0-dev`, not
`-beta`, because the fork builds on the `dev` channel; Lorry's narrowed
compatibility contract is declared as the one development-application change
beyond selector migration instead of contradicting the scope statement; the
Rust checkout's `src/llvm-project` submodule is the only LLVM source tree in
managed mode as well, so no separate LLVM checkout has to agree with it; the
committed Rust lock hashes are declared so a clean managed key and the
key-qualified `rust-toolchain.toml` name are computable offline; and the cost
of the side-by-side migration is stated.

## 0. Decision summary

Motor OS publishes one source-defined compiler lineage with a clear upstream
lineage, and locally assembles the complete toolchain from that source tuple:

1. Target Rust `1.99.0` as the first stable Motor toolchain baseline.
2. Use the Rust 1.99 beta commit pinned in section 2.4 as the temporary porting
   and validation baseline.
3. Read the exact `rust-lang/llvm-project` commit pinned by that Rust revision.
4. Start a new Motor LLVM development branch at that commit and replay the four
   Motor LLVM patches on top.
5. Start one new Motor Rust development branch at the beta commit, replay the
   Motor std and rustc patches, point its LLVM gitlink at the resulting Motor
   LLVM commit, point the LLVM submodule URL at the Motor fork without a
   branch-following rule, and keep the Cargo gitlink that the Rust revision
   selects.
6. Build standalone LLVM/Clang and rustc's LLVM from that same Motor LLVM
   commit.
7. From that one Rust revision, build and install Linux-host rustc/rustdoc,
   Cargo, host std, Motor std, Clippy, rustfmt/`cargo-fmt`, and `rust-src` into
   an immutable tuple-keyed prefix, register it as the one versioned Motor
   rustup toolchain, and use it for every repository build and test. Build the
   C sysroot with it, then build the native Motor rustc from the same revision.
8. When the Rust `1.99.0` stable tag is published, rebase both Motor forks onto
   the final Rust and Rust-pinned LLVM commits, rebuild and revalidate the
   complete tuple, and only then publish the immutable source refs for
   `1.99.0-motor.1` in the Motor Rust and LLVM GitHub forks. This plan does not
   publish binary toolchain archives.

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
  `MOTOR_CARGO_REV`, compatibility family 1.99, for this plan); its
  implementation, specification, and oracle tests advance together with that
  toolchain;
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

The first implementation covers only compiler and runtime inputs in the
toolchain. Versioning or pinning development applications such as ripgrep and
Lua is outside this plan. Changes to development applications are limited to
removing independent toolchain selection from their build and test commands,
with one deliberate exception: Lorry's Cargo-compatibility contract narrows to
the Motor Cargo (section 4.4), because a compatibility family that no
repository test can exercise is not a supported family. That is a Lorry
product decision, confirmed on 2026-08-26 and recorded here so that Lorry and
the toolchain advance together.

The implementation-readiness review is resolved as follows:

- the initial upstream baseline is the exact Rust 1.99 beta tuple recorded in
  section 2.4, with the Motor patches replayed on top;
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

## 1. Goals and scope

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
  cleanup of reusable outputs that could conceal a defect. Retain only the
  narrowly scoped generated-tree replacement described in section 4.5.
- Implement in reviewable patches of roughly 100-300 lines including tests.

The initial work provides reproducible source resolution, not bit-for-bit
binary reproducibility. Pinning Ubuntu packages, host compilers, paths,
timestamps, and a hermetic build environment is future work. It also does not
change Rust stdlib or `moto-rt` APIs, merge the two `x.py` invocations into
one, use the standalone LLVM build as rustc's LLVM through `llvm-config`, or
automatically adopt the latest upstream release.

## 2. Correct version roles

There are two build-time Rust roles, both derived from the selected Rust
baseline rather than an independently selected host channel. During the first
implementation cycle that baseline is an exact Rust 1.99 beta commit; the
formal compiler source release uses the final stable `1.99.0` tag:

1. Rust `x.py` downloads the Stage 0 compiler and Cargo recorded, with hashes,
   in the selected Rust commit's `src/stage0`. This compiler exists only to
   bootstrap the chosen Rust source; nothing in the repository selects it.
2. The Motor Rust source produces Linux-host rustc, Cargo, host and Motor std,
   Clippy, rustfmt, `rust-src`, and the native Motor rustc/std artifacts. The
   Linux-host set is the one Motor toolchain for all repository work.

Today a third role exists: the June 2026 host nightly installed as the global
rustup default, plus whatever floating `nightly` and `stable` channels happen
to be installed. Section 3 lists exactly what they compile. They are
provisioning state, not members of the tuple, and they disappear.

The current development branches are `motor-os-rt-v17` (the std patch) and
`motor-os-rustc` (the same std patch plus the compiler patches). The
policy-conforming layout is one development branch per fork and, for releases,
new immutable versioned tags rather than moved or force-rebased public
branches.

### 2.1 Stable source does not mean stock stable-channel behavior

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

### 2.2 One Motor toolchain

The semantic rustup toolchain-name base `motor-1.99.0-motor.1` identifies the
compiler lineage. The exact registered name appends the full
`MOTOR_TOOLCHAIN_KEY`; for example,
`motor-1.99.0-motor.1-<MOTOR_TOOLCHAIN_KEY>`. This prevents a maintenance
commit from silently repointing the same rustup name to different contents.
That exact toolchain must contain:

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
ambient `beta` or `nightly` channel. Cargo 1.97 and 1.98 are removed from
Lorry's supported compatibility surface rather than retained as historical
test fixtures.

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

In a managed build, the Motor Rust commit changes the upstream Rust gitlink from
`RUST_LLVM_BASE_REV` to `MOTOR_LLVM_REV`. The Rust checkout's initialized
`src/llvm-project` submodule is the only LLVM source tree: the standalone
LLVM/Clang, compiler-rt, libc++, native LLVM, and rustc's LLVM builds all read
it, so the build must require that submodule, the standalone LLVM artifacts,
and rustc's built LLVM to all come from `MOTOR_LLVM_REV`. Because the generated
bootstrap configuration sets `submodules = false`, Rust bootstrap never
touches the submodule (today's generated file already sets it); the checkout
helper of section 5.1 owns its state.

This is not the current situation. The current Motor LLVM branch is four
commits on an upstream LLVM `main` commit, not on Rust's snapshot, and the Rust
fork's committed gitlink is an amended commit that no Motor LLVM ref reaches
(section 3). The gitlink is therefore not usable as an authority today, which
is why the script forces the submodule to the sibling checkout's `HEAD`.

Rust patch releases may change their LLVM gitlink to deliver a correctness
backport. Therefore an upgrade from, for example, Rust 1.99.0 to 1.99.1 must
compare the two LLVM bases and replay Motor patches when it changes.

### 2.4 First baseline: 1.99 beta, then 1.99.0 stable

The first policy-conforming Motor release targets Rust `1.99.0`. Rust 1.99
entered beta on 2026-08-14 and is scheduled to become stable on 2026-10-01.
Motor OS will use the beta period to perform and test the port, then publish
only after rebasing onto the final stable tag.

The initial porting baseline was resolved from the official Rust `beta` branch
on 2026-08-25 and is now immutable for this implementation cycle:

```text
Rust 1.99.0 beta  f47d5bb13648d5c859f5b438eb7dc834b9729961
Rust LLVM gitlink 21cf28432798952d942bacc6bcee3a328faa3638
Rust Cargo gitlink eb98b54bc9f3c74519f43d066cb3fd02ebc88df0
Rust Stage 0      08d5b675a9b2abdca5e2fe4eabe0e07bbda15d49
```

The review re-verified these values against GitHub on 2026-08-25: `beta` still
resolves to `f47d5bb1` ("Auto merge of #161261 - cuviper:beta-next",
2026-08-17); that commit's `src/version` is `1.99.0` and `src/ci/channel` is
`beta`; its `src/llvm-project` and `src/tools/cargo` gitlinks and its
`src/stage0` (`compiler_version=beta`, `compiler_date=2026-07-13`) match the
pins. The LLVM base commit is dated 2026-07-22 in `rust-lang/llvm-project`.
The beta commit is not present in the local Motor Rust clone, which has no
`rust-lang` remote; the branch work in section 7 starts by fetching it.

Replay the Motor LLVM and Motor Rust patch sets onto those exact bases. Use
`motor-os-1.99.0-beta-f47d5bb` as the development-branch name in both forks
(the LLVM branch name records which Rust baseline chose its base) and
`motor-1.99.0-beta-f47d5bb-dev.1` as the first local rustup toolchain-name base.
The registered name also includes the full toolchain key. The central manifest
still records full commits. A deliberately selected later beta baseline gets a
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

## 3. Current observed tuple

Observed in sibling checkouts, installed rustup toolchains, and build artifacts
on 2026-08-13 and rechecked on 2026-08-25. It predates the stable-lineage
policy above and is retained as evidence; nothing in it may be selected instead
of the beta tuple in section 2.4.

| Role | Observed identity | Current enforcement |
|---|---|---|
| Global default host Rust (defect) | `nightly-2026-06-19`: rustc 1.98.0-nightly (`bc2112ed5`), Cargo 1.98.0-nightly (`598ab48ec`), plus `rust-src` | `rustup default`, set by `build-base.sh` |
| Floating `nightly` channel (defect) | Cargo 1.99.0-nightly (`3efb1f477`, 2026-07-17) | None; reached by rustup fallback and `+nightly` |
| Floating `stable` channel (defect) | Cargo 1.97 | None; reached by Lorry's oracle test |
| Motor Rust source | `motor-os-rustc` at `9fd149a944bf7787bf2db9db05748f0c6d333eb6` (1.100.0-dev); `motor-os-rt-v17` at `8550ca5e5608`; both directly on upstream `8925ea358a0` (2026-08-19) | Branch/local checkout only |
| Host rustc and std in use | `rustc 1.100.0-dev`, `commit-hash: unknown`, LLVM 23.0.0, linked from `rust/build/x86_64-unknown-linux-gnu/stage2` | rustup link accepted by name |
| Rust Stage 0 | recorded by the Rust commit; at `9fd149a9` it is the 1.99 beta `f47d5bb1` of 2026-08-18 | Pinned by the Rust commit |
| Motor LLVM/Clang | 23.0.0git at `7e58a8983122ecfc9d152a7904e8b0caa7f60b92`: four Motor commits on upstream `main` `53069acdb946` | Branch/local checkout plus Motor-triple and major-23 greps |
| Rust LLVM gitlink | `88ea5aa2a7b4f634c6698e7674eafa2367e1aad4` committed by the compiler patch; unreachable from any Motor LLVM ref; the submodule work tree is forced to sibling `HEAD` (`7e58a898`) and shows as modified | Not enforced |
| Rust Cargo gitlink | `514c56dd7321eecbfdcf9b6479519cf4edfab906` at `9fd149a9` | Never initialized or built |
| mlibc | `motor-os-rustc` at `62f9495700537ded14a2a6fae9373227fe5ec5ca` | Branch/local checkout only |
| `moto-rt` used by std | 0.17.4 committed in `library/Cargo.lock`; 0.17.5 (checksum `0d957efc93bb603844e45d66f45c9b999168ff8f7630da91f3a7308c498a7ccc`) as an uncommitted lock update; the root lock also carries an uncommitted `ctrlc` bump | Lockfile, rewritten by the normal build |
| Local `moto-rt` | 0.17.5 in `src/sys/lib/moto-rt`, a path dependency of `moto-rt-cabi` | Never compared with std's version |
| Cargo used by `cargo +dev-x86_64-unknown-motor` | the floating nightly's Cargo (`info: falling back to .../nightly-x86_64-unknown-linux-gnu/bin/cargo`) | Rustup fallback |

The 2026-08-13 values (host rustc 1.99.0-dev at `4e81c4818fb7`, bootstrap
source `607430137e08`, LLVM `88ea5aa2` in the sibling checkout, std `moto-rt`
0.17.2) are superseded by the table; they show how quickly branch-selected
inputs drift.

The observed Stage 2 compiler reports `commit-hash: unknown` because Rust dev
builds omit Git metadata by default (`rust.omit-git-hash` defaults to `true`
when the channel is `dev`), making different compilers look identical to Cargo
and to a reader.

### 3.1 What each toolchain compiles today

- `make` builds every OS component with `cargo +dev-x86_64-unknown-motor`, so
  the Motor rustc plus the floating nightly's Cargo.
  `src/sys/lib/rt.vdso/build.sh` does the same.
- `src/boot/x64.{mbr,boot,kloader}/build.sh` run bare `cargo`, so the global
  default June nightly compiles the MBR, boot sector, and kloader with that
  nightly's `rust-src`, `-Zbuild-std`, and `-Zjson-target-spec`. This is why
  `build-base.sh` installs `rust-src`.
- The imager (`cargo run` in `src/imager`) and every host unit test in
  `src/tests/full-test.sh` (imager, rnetbench, the `src/bin` crates, sys-init,
  moto-sys, moto-tooling, motor-fs) run bare `cargo`, so the June nightly.
- The netstack tests in `full-test.sh` and `full-test-networking.sh` run
  `cargo +nightly test`, so the floating nightly.
- Lorry's product suite (`test-all.sh`, `cargo-identity.sh`,
  `proc-macro-contract.sh`, `review-contract.sh`, `curl-contract.sh`,
  `test-native.sh`) selects the June nightly explicitly, and
  `verify-stage2-resolution-oracle.sh` runs `stable`, the June nightly, and the
  floating nightly Cargo. `cargo-identity.sh` defaults the Motor linker to an
  absolute path under `/home/posk/motor-dev`.
- `AGENTS.md` formats with `cargo +nightly fmt`, so the floating nightly's
  rustfmt.
- `update_rust` runs `cargo update` inside the Rust fork with bare `cargo`, so
  the June nightly's Cargo rewrites the fork's lockfiles.
- `build-base.sh` also builds `src/tools/remote-test-server` for both targets;
  nothing in the repository uses it.

### 3.2 Patch stacks to replay

- Motor Rust, `motor-os-rustc`, on upstream `8925ea358a0`:
  `736c4c253be library: motor: bump moto-rt ABI ver to 17 and implement several
  missing methods` (12 files, +215/-75, all under `library/`);
  `38e0108f5d7 compiler: make rustc run natively on Motor OS` (rustc, one
  bootstrap file, one std path file, and the LLVM gitlink; most of its 1329
  deleted lines remove `.github` templates); `099d8b6740d rustc: flock for
  Motor OS` (+36); `9fd149a944b rustc: Run Motor proc macros over stdio`
  (+414/-34). `motor-os-rt-v17` is the same base plus the same std patch as
  `8550ca5e560`; it is not an ancestor of `motor-os-rustc`.
- Motor LLVM, `motor-os-rustc`, on upstream `main` `53069acdb946`:
  `41cb5179ddf0 [Triple] Add target triple support for Motor OS`,
  `6cc6cbd22e61 clang/Driver: add Motor OS`, `43b4813044e6 [libc++] minor
  fixes to support motor/mlibc`, `7e58a8983122 clang/Driver, misc: minor
  tweaks to support Motor OS`. The clone has no `rust-lang` remote and no
  upstream tags. The replay onto `21cf2843` is the first time Motor LLVM sits
  on Rust's release-branch-based snapshot rather than on `main`; expect small
  conflicts and a full LLVM rebuild.

Replay these onto the exact beta tuple and commit the `moto-rt` 0.17.5 and
`ctrlc` lock selections as an explicit reviewed dependency commit on the new
branch. Do not select the 1.100 checkout or attribute its uncommitted lockfile
changes to `9fd149a9`.

### 3.3 Manifest shape

A policy-conforming stable manifest has this shape after the final stable tag
is selected. The first block is declared in `src/toolchain-versions.sh`; the
second is generated per build (section 5.5):

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

## 4. Problems found

### 4.1 Sources are selected by branch or local state

`src/build-motor-os.sh::clone_repo` checks out `motor-os-rustc` only for a new
clone. An existing LLVM or mlibc checkout is accepted without verifying remote,
branch, commit, or cleanliness. A new clone gets the branch tip available that
day. LLVM is checked only for the Motor triple and major version 23.

`src/build-base.sh` and `update_rust` similarly accept local Rust branches at
any commit. The Rust LLVM submodule is forced to the sibling LLVM checkout's
`HEAD` because the committed gitlink points at an amended commit that no Motor
LLVM ref reaches, so the sibling checkout, not a central declaration or the
Rust gitlink, is currently authoritative, and the Rust work tree permanently
shows `src/llvm-project` as modified. An existing rustup link is accepted by
name without checking its target path or compiler revision.

The only version checks on the Motor OS checkout itself are greps for specific
source strings in `rt.vdso` and a partition-size field in the imager
configuration (`rustc_verify_prereqs`). They are ad hoc stand-ins for the
manifest this plan introduces.

### 4.2 The host nightly is a hidden member of the build

The custom `dev-x86_64-unknown-motor` Stage 2 `bin` directory contains
`rustc`, `cargo-clippy`, and `clippy-driver`, but no Cargo. Rustup consequently
borrows Cargo from an installed release channel, preferring the floating
nightly. On the inspected machine every `cargo +dev-x86_64-unknown-motor`
command prints a fallback notice and runs the July Cargo 1.99 rather than the
declared June Cargo 1.98. Selection can differ based on unrelated installed
toolchains.

That is only the most visible use. Section 3.1 shows that the June nightly also
compiles the boot loaders, the imager, and every host unit test, that its
`rust-src` is what `-Zbuild-std` compiles into the boot loaders, that the
floating nightly runs the netstack tests and `cargo fmt`, and that the June
nightly's Cargo rewrites the Rust fork's lockfiles. None of these compilers has
a version relationship to the Motor compiler or to the Stage 0 that the Rust
source selects.

The current workflow installs the June nightly as the global default, runs
`x.py` from the first-pass `motor-os-rt-v17` source with CI-downloaded LLVM to
create host rustc, both stds, Clippy, and `remote-test-server`, builds
`moto-rt-cabi` with that toolchain and the borrowed Cargo, builds LLVM, mlibc,
and libc++, switches the same checkout to `motor-os-rustc`, invokes `x.py` for
the native rustc (building LLVM twice more, for the Linux host and for Motor),
and invokes `x.py` again to rebuild both stds and Clippy in place, replacing
the first-pass toolchain under the same rustup name. It then rebuilds the shim
and deletes the Motor OS Cargo caches because Cargo cannot tell the two
compilers apart.

### 4.3 Normal builds mutate dependency selection

`update_rust` runs `cargo update -p libloading -p stacker -p libc -p ctrlc` in
the Rust root workspace and `cargo update -p moto-rt` in `library/`. (The
previous revision of this plan reported that their output was suppressed and
failure ignored with `|| true`; that was removed earlier and is no longer the
case.) The commands still advance the four Git-patched crates to their branch
tips and `moto-rt` to the newest published `0.17.x` on every run, and they run
under whichever Cargo is the global default. Normal scripts should start with
the committed dependency selections and must not explicitly refresh them;
deliberate updates belong in a separate maintenance workflow.

### 4.4 Global, generated, and test state is weakly controlled

`build-base.sh` runs `rustup default nightly-2026-06-19`, changing the user's
global configuration. There is no root `rust-toolchain.toml`.

Existing `bootstrap.toml` files are accepted using broad marker checks (the
presence of `download-ci-llvm`) rather than complete validation, and the
first-pass configuration is written only when absent. `build-motor-os.sh`
checks only that generated tool files exist, not which sources produced them.
No canonical version manifest is staged in the image.

Repository commands outside the main build select their own toolchains
(section 3.1). Lorry currently declares Cargo 1.97, 1.98, and 1.99 compatibility
families and its oracle test reaches ambient `stable` and `nightly` channels.
That is broader and less deterministic than the intended product contract.
Lorry must instead support only the Cargo selected by the current Motor Rust
revision: the `1.99.0-dev` Cargo at `MOTOR_CARGO_REV` (compatibility family
1.99) for the initial tuple. This is the one change to a development
application beyond selector migration (section 0).
Its README, specification, compatibility representation, configuration
validation, cache identity, and tests change together to remove the 1.97/1.98
contract. The frozen Stage 2
resolution fixture may remain, but it is regenerated or verified only by the
exact `MOTOR_CARGO_REV` executable and never by ambient channel aliases. A
later Motor toolchain update deliberately advances Lorry's sole supported
Cargo family in the same reviewed tuple change.

### 4.5 Broad cleanup hides cache-invalidation defects

After rebuilding rustc, the current workflow deletes `build/obj/release` and
`src/sys/target`. These are local artifacts, not published outputs. Deleting
them is still problematic because a clean rebuild can pass even when the build
system lacks the dependency edge or compiler-identity check needed to reject a
mixed old/new incremental tree. That makes the cleanup mask the invalidation
defect instead of demonstrating that an incremental toolchain change is safe.

The complete list of deletions in `build-motor-os.sh` today:

- `build_images`: `build/obj/release` and `src/sys/target` (Cargo caches);
- `rebuild_shim`: `build/native-toolchain/moto-rt-cabi` (Cargo cache);
- `build_cxx_runtimes`: `llvm-project/build-motor-cxx` ("stale try_compile
  results are poison");
- `build_mlibc`: `meson setup --wipe` when the cross file's hash changes;
- `build_native_llvm`: `rm -f build-motor-native/bin/llvm` to force a relink,
  plus a comment instructing the user to `rm -rf build-motor-native` when the
  sysroot's set of archives changes;
- `llvm_stage_image` and `rustc_stage_image`: the generated image roots
  `img_files/generated/{llvm,libc,rustc}` and the legacy
  `img_files/motor-os/devtools/rust`; `build_ripgrep`: `img_files/generated/rg`.

The replacement is not to reuse incompatible artifacts. Reusable directories
are keyed by a digest of the inputs that determine them (section 5.5). An
unchanged tuple reuses its directory; a changed tuple selects a new directory.
The build reports obsolete directories but does not remove them
automatically. This costs disk space, but preserves evidence and makes clean
and incremental behavior testable. In addition, every authoring compiler
carries a distinct `description`, so Cargo itself distinguishes it from the
managed build and no cache can be silently reused across the two.

This does not prohibit Rust bootstrap from recreating its own stage sysroot or
an image-staging step from replacing its destination tree. Those operations are
defined producers of a complete generated tree, not wrapper cleanup of a cache
whose invalidation is under test. Retain image-root replacement for the staging
trees the script fully owns. Replace the Cargo-cache deletions, the mlibc
`--wipe` path, the libc++ build-tree deletion, and the native-LLVM relink and
cleanup guidance with keyed build directories. Document any other retained
deletion with the single generated tree it owns.

### 4.6 Two branches and two Rust phases are historical, not required

The previous revision of this plan kept a bootstrap Motor Rust branch, a
bootstrap-only Cargo, and a temporary bootstrap-only rustup toolchain because
"the first-pass Motor compiler is needed to build `moto-rt-cabi`, which
participates in mlibc/C++ sysroot construction. That sysroot is needed before
the final native and cross compiler artifacts can be completed." The second
sentence is only half true, and the half that is false carries all the
complexity.

What actually depends on what:

- The mlibc/libc++ sysroot needs `libmoto_rt_cabi.a`, which needs a
  Motor-target Rust toolchain.
- The native Motor rustc, the native LLVM multicall, and Lua link against that
  sysroot; they must come after it.
- The Linux-host toolchain (host rustc, both stds, Cargo, Clippy, rustfmt)
  needs only the Motor LLVM, which `x.py` builds from the submodule, and
  `moto-rt` from crates.io. Motor std depends on `moto-rt` alone (AGENTS.md
  note 2), contains no C, and `x.py build library` links no Motor executables.
  The `[target.x86_64-unknown-motor]` `cc`/`linker` entries are consulted only
  when linking a Motor executable, which happens only in the native phase. The
  first-pass `build-base.sh` build already proves this: it builds Motor std
  with no sysroot at all.

So the order is: exact checkouts, standalone cross LLVM/Clang, the complete
Linux-host Motor toolchain from the one Motor Rust revision, the shim and C
sysroot built with that toolchain, native LLVM and Lua, the native rustc from
the same revision, staging, images. One Rust revision, two `x.py` invocations,
no bootstrap branch, no bootstrap Cargo, no throwaway toolchain, and no
CI-LLVM download. The two branches exist today only because `build-base.sh`
predates the rustc port and wanted CI-downloaded LLVM, which requires the
upstream gitlink; section 3.2 shows they share the same base and the same std
patch.

The previous design also left a gap: a bootstrap branch that keeps the upstream
LLVM gitlink builds its host compiler against a CI-downloaded LLVM artifact
whose identity the manifest never recorded, while one that points at the Motor
LLVM needs a third full LLVM build. Both problems disappear with one branch.

One assumption must be verified in the first build patch (section 7, item 9):
that `x.py build library cargo clippy rustfmt` for both targets from the Motor
Rust branch succeeds with no sysroot present. If a component turns out to need
the sysroot, the fallback is still one revision with a split invocation, never
a second branch.

## 5. Proposed design

### 5.1 Central manifest and exact checkout helper

Add a data-only `src/toolchain-versions.sh`, sourced by relevant scripts. It
contains the Motor toolchain ID, rustup-name base, and maturity; upstream Rust
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

Use dedicated, independent ordinary checkouts for the new path under
`$MOTORH/toolchain-src/{rust,mlibc}`; LLVM lives only in
`toolchain-src/rust/src/llvm-project`, so there is no separate LLVM checkout to
keep in agreement. Seed them from the existing sibling repositories with an
ordinary local clone whose expected remote is then configured and verified, or
clone the expected URL with `--reference-if-able <legacy> --dissociate`, to
avoid duplicate network transfer. Never use an undissociated reference clone
or `git worktree add`: the managed checkout must own its object database, refs,
worktree, and bootstrap/build state so that legacy repository maintenance or
deletion cannot affect it. This is what makes the pre-cutover implementation
genuinely side-by-side: it never detaches, switches, fetches into, or rewrites
the legacy `$MOTORH/{rust,llvm-project,mlibc}` repositories. The price is a
second complete toolchain build (several hours and tens of gigabytes of build
trees) on the implementing machine until cutover; accept it rather than sharing
build state with the legacy path. At cutover the dedicated paths become
authoritative; the legacy checkouts remain untouched and may be deleted by
their owner. This is managed mode, the default. An explicitly requested
authoring mode may instead use a developer's Rust checkout as described below;
it is never selected merely because a managed checkout happens to be dirty.

For the initial beta work, it records a `beta` maturity state, a distinct
non-release toolchain ID, and the exact beta Rust commit. Stable source
publication must reject that state. The October conversion changes the state
to `stable`, the upstream ref to `refs/tags/1.99.0`, and the toolchain ID to
`1.99.0-motor.1` only after all final commits have been selected and verified.

Replace branch-only source handling with a managed-checkout helper that:

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
worktree. Tests use local temporary Git repositories and no network. Separate
ancestry checks must prove:

```text
UPSTREAM_RUST_REV    is an ancestor of MOTOR_RUST_REV
RUST_LLVM_BASE_REV   is an ancestor of MOTOR_LLVM_REV
```

For Rust's submodules, read the gitlinks in `UPSTREAM_RUST_REV` and require
them to equal `RUST_LLVM_BASE_REV` and the upstream Cargo gitlink; then require
the gitlinks in `MOTOR_RUST_REV` to equal `MOTOR_LLVM_REV` and
`MOTOR_CARGO_REV`. The helper initializes `src/llvm-project` and
`src/tools/cargo` itself and sets `submodules = false` in the generated
bootstrap configuration so bootstrap never re-fetches or resets them. Seeding
`src/llvm-project` from the legacy sibling LLVM clone remains a transfer
optimization, but the submodule must have `HEAD` detached at `MOTOR_LLVM_REV`
before any LLVM or `x.py` build runs. The standalone LLVM, compiler-rt,
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
section 2.4. From the local Rust object database, the orchestrator reads that
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
accepting an unrelated sibling LLVM checkout would reintroduce the split
identity this plan removes. The Cargo submodule must be initialized, clean,
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
Derive `MOTOR_OS_REV` from the checked out `HEAD`, and write both only to
generated manifests. A local assembly attributed to formal source tags
requires those paths to be clean at that revision; local development assembly
is allowed but must be marked dirty and identified by the content digest.

### 5.2 One Motor toolchain from one Rust revision

Do not install or select a separate general host Rust toolchain. Install
rustup with `--default-toolchain none` when it is absent and never run
`rustup default`. Rust `x.py` bootstraps directly from the Stage 0 compiler and
Cargo specified, with hashes, by the selected Rust source. That is
`MOTOR_RUST_REV` in managed mode and `EFFECTIVE_MOTOR_RUST_REV` in authoring
mode. Stage 0 is an implementation input to compiler bootstrap, not the
repository toolchain, and the scripts must not override it.

Expose one user-facing entry point: `src/build-motor-os.sh`. Reduce
`build-base.sh` to a private host-provisioning helper called only by that
entry point: Ubuntu packages, rustup installation without a default, and the
tap/KVM setup. It no longer clones or builds Rust, and its standalone workflow
leaves the contributor documentation. The build sequence is:

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

During beta development, the base is the beta toolchain name from section 2.4
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

Generate the complete bootstrap configuration deterministically from a
template and the manifest into a keyed generated-state directory, and pass its
absolute path to `x.py --config`. Never create or replace `bootstrap.toml` in
an authoring source checkout. Validate an existing generated configuration
against the template instead of accepting one that contains a marker. The
identity-relevant settings are:

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
`[target.x86_64-unknown-motor]` wrapper paths) carry over from today's file.
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

Build the compiler with the `dev` channel until Motor's unstable feature usage
has been removed; do not describe it as an unmodified stock stable compiler.

### 5.3 Deterministic Rust tools and the installed prefix

Cargo, Clippy, and rustfmt are all ordinary Rust bootstrap tool steps: Cargo
builds from the `src/tools/cargo` gitlink that the effective Rust `HEAD`
records, and Clippy and rustfmt from the in-tree sources. `x.py install` builds
and installs them in the same invocation as the compiler and both stds; a
separate Cargo build outside bootstrap is unnecessary.

The linked toolchain must be an installed prefix, not the `build/<host>/stage2`
sysroot, because bootstrap's `Sysroot` step removes that directory at the start
of every invocation. The preferred mechanism is `x.py install` with
`[install] prefix` pointing at
`$MOTORH/toolchains/<MOTOR_RUSTUP_TOOLCHAIN>`, whose exact name already includes
`MOTOR_TOOLCHAIN_KEY`; it produces the standard component layout including
`rust-src`. Bootstrap's
install steps build with the compiler one stage below `--stage`, so
`x.py install --stage 2` installs the same stage-2 artifacts that today's
`stage2` link exposes. Do not fall back to manually copying the stage sysroot:
that would omit installer behavior and the vendored, reduced `rust-src`
component. If `x.py install` is unsuitable, stop and revise this plan around
Rust's component installers.

Never run `x.py install` into an existing prefix. Reuse an existing prefix only
after its complete manifest passes validation; otherwise require the target to
be absent and atomically create an adjacent `<prefix>.building` lock directory
before installation; stop if another process owns it. After `x.py` returns,
validate every component and the post-build lock hashes,
write the complete manifest inside the prefix, and only then remove the marker
and create the rustup link. An interrupted, invalid, or lock-rewrite prefix is
marked rejected and never reused or linked; the script reports it but does not
delete it. A changed tuple installs a new prefix under a new exact name. Later
`x.py` invocations, including the native rustc build, cannot damage it, so the
"last sysroot-mutating `x.py`" constraint of the previous plan revision is no
longer load-bearing.

This does not port these tools to run on Motor; it supplies the Linux-host
tools that drive and check Motor cross-builds. Native Motor tools remain
separate binaries built from the same pinned source tuple. All resulting host
binaries and sysroots are local build artifacts; only the source refs and tags
are published by this plan.

Required validation, all of which must resolve inside the linked prefix and
report the recorded identities without a rustup fallback notice:

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
`remote-test-server` is not part of the toolchain and is no longer built
unless a consumer appears.

### 5.4 Dependency selection and `moto-rt` maintenance

Remove both explicit `cargo update` commands from normal builds and add no lock
enforcement to Rust bootstrap; `locked-deps` stays `false`. This policy is
limited to the Rust build. Existing application and offline-test uses of
`--locked` or `--locked --offline` remain unless their owning component changes
that policy separately. The committed Rust root and library lockfiles remain
the starting dependency selection, but `x.py` does not force them to be
immutable. If Cargo must rewrite one because a manifest changed, leave the diff
visible. A formal source tag requires any such change to have been reviewed and
committed before a successful build.

Dependency resolution for the Rust tree happens inside `x.py`: bootstrap's
early `cargo metadata` pass runs with `--no-deps` and resolves nothing, so the
first Cargo build of the run, using the Stage 0 Cargo without `--locked`, is
what may rewrite a lockfile. There is no separate preflight; running Cargo
before `x.py` would need a repository toolchain that does not exist yet. Hash
both lockfiles at the start of the run and again after the build. The
provisional key and install path use the starting hashes. If either hash differs
afterwards, the run must not register or use that prefix, write a valid stamp,
or continue into the C sysroot and OS build: mark the prefix rejected, report
both hashes and the rewritten file, preserve the diff and build outputs, and
stop. The next run starts from the rewritten lock and derives a new key; it may
succeed only if the locks then remain unchanged. This ensures every accepted
prefix was actually built from the locks in its key. A formal tag requires
committed locks, so a release never starts from a lock that the build has to
rewrite.

Motor OS workspace lockfiles remain ordinary Cargo inputs. The `src/sys`
workspace manifest and the lock entries in `moto-rt-cabi`'s resolved closure
enter `MOTOR_OS_RUNTIME_TREE` because they affect the shim installed into the C
sysroot; unrelated lock entries and application locks are recorded in the image
manifest but do not enter either compiler/runtime key.

Keep the Rust fork's Git patch declarations on named Motor branches so that
updating the Motor dependencies remains manageable. The lockfiles record the
exact commits resolved from those branches. Normal build scripts do not run a
dependency-refresh operation; advancing a branch-selected dependency is an
explicit maintenance change.

Rust std continues to depend on published crates.io `moto-rt`; the GitHub Rust
fork must never contain a path dependency or generated patch pointing to
`../motor-os`. To bump `moto-rt` between compiler-lineage releases:

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

Before expensive work, print and verify every declared or source-derived input:
the compiler-lineage ID; the selected upstream Rust version/ref/commit and
Stage 0 hash; expected Motor host rustc/rustdoc/Cargo/Clippy/rustfmt
identities; the declared and effective Motor Rust commits and tree state; Rust
LLVM base and declared and effective Motor LLVM commits and tree state; source
mode; mlibc; both `moto-rt` identities; the Motor OS runtime tree; the Rust
gitlinks; ancestry relationships; and lockfile hashes. Verify any existing
reusable artifact against those expectations; a clean provision has no such
artifact yet.

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
the OS build's Cargo output directories by their content digest, as the
previous plan revision did, would force a full OS rebuild after every `moto-rt`
edit. Those directories change only when the compiler changes. The runtime
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
commits; it is not re-keyed. `src/sys/target` stops being used by the build
scripts; every Cargo invocation they make sets `CARGO_TARGET_DIR` under the
keyed roots. The same tuple may reuse its directory. A changed tuple gets a
different directory; the build must not delete or silently reuse the old one.
Each mutable keyed build root has an atomic per-key lock directory; a concurrent
producer for the same key stops rather than sharing a partially written tree.
An abandoned lock is reported for explicit inspection and is never removed as
part of automatic cleanup.

After building, validate at least `rustc -vV`, `cargo -Vv`, `clippy-driver
--version`, `rustfmt --version`, `clang --version`, `llvm-config --version`,
the rustc sysroot, and the Motor target library directory. Verify that the
host and native rustc report `EFFECTIVE_MOTOR_RUST_REV` and the description
required by the source mode.

Write a versioned machine-readable manifest into the toolchain prefix, every
generated root, and the dev image, with a canonical on-image path such as:

```text
/devtools/toolchain/manifest
```

Include both meaningful upstream versions and exact source revisions, both
keys, source mode, declared and effective revisions, the Motor OS runtime
digest, tree-state and dirty markers, lock hashes, target, compiler channel,
and compiler version output. Authoring mode uses `development-authoring` when
all relevant worktrees are clean and `development-dirty` otherwise. A
permitted uncommitted lockfile diff present at the start of the build or another
dirty tree uses `development-dirty`; a lockfile rewrite during the build rejects
the run as described in section 5.4. Exclude host absolute paths and
identity-changing timestamps.

`build-motor-os.sh` sources the central manifest and rejects missing or
mismatched generated manifests instead of checking only for file presence. On
mismatch it names the stale directory and directs the user to the correctly
keyed build; it does not broadly clean it. Tests must cover both a no-op
incremental build with an unchanged tuple and selection of a fresh directory
when any tuple member changes.

## 6. Changes by file

- New `src/toolchain-versions.sh`: authoritative Rust lineage and Stage 0
  hash, semantic rustup-name base, Rust LLVM base, Motor Rust/LLVM/mlibc
  revisions and refs, the Cargo gitlink, declared runtime inputs, canonical key
  formats, and schema; no self-referential Motor OS commit, tree state, exact
  rustup name, or derived key.
- New root `rust-toolchain.toml`: select the versioned custom Motor toolchain;
  for a clean tuple, validate its full key-qualified name against the central
  manifest and generated key.
- `src/build-base.sh`: private host-provisioning helper used only by
  `build-motor-os.sh`: packages, rustup without a default toolchain, tap/KVM.
  No Rust clone, build, `rustup default`, or `remote-test-server`.
- `src/build-motor-os.sh`: exact Rust and mlibc checkout and Rust submodule
  handling in managed mode, with `src/llvm-project` as the only LLVM source
  tree; explicit non-mutating Rust/LLVM worktree selection
  in authoring mode; declared/effective ancestry, gitlink, and tree-state
  verification; the ordered single-revision build of section 5.2;
  deterministic external bootstrap configuration; installed and registered
  toolchain; removal of `cargo update`, the Cargo-cache deletions, the
  mlibc/libc++/native-LLVM wipe paths, and the ad hoc source greps; keyed output
  directories; manifests and stamps; and the exact generated tuple required
  before image assembly.
- Motor Rust fork `library/std/Cargo.toml` and `library/Cargo.lock`: retain a
  crates.io `moto-rt` dependency and accept explicit dependency-only
  maintenance commits; never reference the local Motor OS checkout.
- `Makefile`: replace `cargo +dev-x86_64-unknown-motor` in `DO_BUILD` and
  `DO_CLIPPY` and the bare `cargo` in the imager rules with the root override;
  derive `OBJ_DIR` from the toolchain key stamp.
- `src/sys/lib/rt.vdso/build.sh` and `src/boot/x64.{mbr,boot,kloader}/build.sh`:
  drop the explicit selector or the reliance on the global default; the root
  override applies.
- `src/tests/full-test.sh` and `full-test-networking.sh`: remove the
  `+nightly` selectors; the host unit tests already run through bare `cargo`
  and follow the root override.
- `src/bin/lorry/{README.md,spec.md,src,tests}`: make the current Motor Cargo
  family the sole compatibility contract (the `1.99.0-dev` Cargo at
  `MOTOR_CARGO_REV`, family 1.99, for this tuple); remove the 1.97/1.98
  configuration, implementation variants, and
  oracle lanes; select the Motor toolchain by exact name in temporary working
  directories; verify and log its Cargo's full `-Vv` output and
  `MOTOR_CARGO_REV`; derive the Motor linker and sysroot paths from the manifest
  instead of a hard-coded home directory; and remove ambient `stable`/`nightly`
  selection.
- `AGENTS.md`: format with rustfmt from the Motor toolchain (`cargo fmt`
  under the root override) rather than a separately selected nightly.
- `docs/build.md`, `docs/build-motor-os.md`, `docs/build-rustc.md`,
  `docs/build-llvm.md`, and the recipes: identify the stable Rust and
  Rust-LLVM baselines, describe the single entry point and single Rust
  revision, replace the branch-switch and "repurposes the dev toolchain"
  narratives and the cache-clearing guidance, document the inspection and
  update procedures, and state that publication is source-only.

## 7. Incremental implementation and tests

Each numbered item is a separate review unit. Land it in 100-300-line patches
including tests; split the unit further when necessary. For fork rebases,
preserve the existing small commit boundaries instead of squashing the replayed
patch stack. Items 1 and 2 happen in the forks; items 3 onward are Motor OS
patches. Items 3-11 prepare and validate the new path alongside the legacy
provisioning in the dedicated `toolchain-src` checkouts without changing
repository selectors or the legacy sibling worktrees. Item 12 is the atomic
cutover: only after the installed replacement has passed its own checks does it
change the root override and remove the legacy path. Thus every intermediate
commit retains a working clean-provision route. Prepare selector-aware helpers
in earlier no-behavior-change patches so item 12 remains within 100-300 lines if
possible; if the atomic removal/cutover cannot safely be split, it is the one
documented exception and must contain only the tightly coupled wiring and
deletion.

1. In a Motor Rust authoring checkout, configure the Motor Rust fork as
   `origin` and upstream Rust as `rust-lang`, fetch `f47d5bb1`, create
   `motor-os-1.99.0-beta-f47d5bb`, and initialize its LLVM and Cargo submodules.
   Normalize `src/llvm-project` the same way regardless of the URL inherited
   from upstream `.gitmodules`: the Motor LLVM fork is `origin` and Rust's LLVM
   repository is `rust-lang`. Fetch `21cf2843`, create the matching Motor LLVM
   branch, and replay the four Motor LLVM commits. Do not force-rebase the
   existing public development branch or use a different sibling LLVM worktree
   for test builds.
2. In the enclosing Rust branch, replay the std patch and the three compiler
   patches with their reviewable boundaries, point the LLVM gitlink at the item
   1 commit, set `.gitmodules` to the Motor LLVM URL without a moving `branch`
   selector, keep the Cargo gitlink `eb98b54b`, and add one reviewed dependency
   commit selecting `moto-rt` 0.17.5 and the current `ctrlc` revision. Push the
   LLVM branch first and the Rust branch second so the gitlink is reachable.
3. Add the central data manifest and a small offline shell test for required
   fields, full commit formats, beta/stable maturity, schema/toolchain ID, and
   canonical key generation. Test that beta state cannot authorize stable
   source publication.
4. Add managed and authoring source modes and their offline
   temporary-repository tests. Managed cases cover a new/correct checkout,
   advanced development branch retaining the pinned commit, stale formal tag,
   ref/SHA mismatch, wrong remote, dirty/untracked rejection without switching,
   submodule gitlink verification, and a missing commit. Authoring cases cover
   local/unpushed Rust and LLVM commits, dirty and untracked content, a pending
   LLVM gitlink update, exact Cargo-gitlink enforcement, ancestry failure,
   initial and later full authoring-base commits with identities derived from
   each base, canonical content hashing, repeat verification before use,
   distinct keys, and proof that the helper changes no authoring worktree or
   ref.
5. Make `src/build-motor-os.sh` the sole documented user-facing orchestrator
   and make `build-base.sh` private, but retain its legacy provisioning behind
   that orchestrator until item 12. Add a small entry-point test; do not yet
   change the working clean-build path or repository selectors.
6. Add the exact mlibc checkout, Rust submodule initialization at
   `MOTOR_LLVM_REV` and `MOTOR_CARGO_REV`, and Rust LLVM-base verification to
   the new path in the orchestrator, using the helper from item 4. Keep that
   path side-by-side with the legacy branch-selected path until cutover.
7. Pin the Motor Rust revision, verify the ancestry relationships and both
   gitlinks, record Stage 0, and generate the external bootstrap configuration
   deterministically with Git metadata, the managed release description, the
   authoring suffix, tools, `docs`/`optimized-compiler-builtins`, and the
   install layout. Test its exact schema and both source-mode identities.
8. Remove the dependency-refresh commands. Add starting/post-build lock hashing
   and derive `MOTOR_TOOLCHAIN_KEY` and the exact rustup name from the starting
   state. Add rejection of any prefix produced while a lock changed, the
   crates.io/local `moto-rt` version and clean-package-content checks, and
   offline tests for rejection without linking, re-keying on the next run, and
   the explicit runtime-maintenance workflow. Do not add Rust-bootstrap
   lockfile immutability enforcement or remove application/test `--locked`
   policy.
9. Build the Linux-host toolchain with one `x.py` invocation from the pinned
   revision, before the C sysroot, install it into a new keyed prefix, validate
   its unchanged locks and components, and register it side-by-side under the
   full key-qualified name without changing the root override. Write the prefix
   manifest/key stamp and run the section 5.3 validation. This is where the
   section 4.6 assumption is proven; if a
   component needs the sysroot, split the invocation within this item. Test
   name/prefix synchronization, interrupted or rejected prefix handling,
   rejection of rustup fallback, `cargo fmt`, `rust-src` presence, and a clean
   provision of this path with no unrelated installed Rust channel. Also build
   one explicitly selected local Rust/LLVM authoring tuple, verify its effective
   revisions and unique description, and prove it neither changes the root
   override nor qualifies for managed artifact reuse.
10. Derive `MOTOR_ASSEMBLY_KEY`, move reusable outputs to their keyed
    directories, stop using `src/sys/target`, and route the existing shim,
    builtins, mlibc, libc++,
    native LLVM, and Lua producers through the side-by-side exact toolchain and
    their keyed directories without replacing the legacy sysroot or image
    staging roots. Remove the Cargo-cache deletions and the
    mlibc/libc++/native-LLVM wipe paths in component-sized subpatches, ending
    with a validated C sysroot, per-root assembly manifests/stamps, and native
    prerequisites for item 11. Test no-op reuse for an unchanged tuple and
    selection of a new directory for each changed tuple class, and that a
    `moto-rt` source edit changes the assembly key but not the toolchain key.
11. Build the native Motor rustc from the same revision after the sysroot,
    verify the host and native compiler identities, Git metadata, and release
    description, and stage it in the new assembly-keyed root without replacing
    the legacy image root. Stage the on-image manifest there and test rejection
    of changed Rust, LLVM, mlibc, Cargo, either `moto-rt` identity, Motor OS
    runtime content, lock hashes, tree state, or schema. Confirm the installed
    prefix is unchanged by this invocation.
12. Cut over in one core patch: add the exact key-qualified
    `rust-toolchain.toml`; switch `Makefile` `DO_BUILD`/`DO_CLIPPY` and imager
    rules, `src/sys/lib/rt.vdso/build.sh`, the three boot-loader scripts, the
    orchestrator's Cargo commands, and `full-test.sh`/`full-test-networking.sh`;
    reduce `build-base.sh` to host provisioning without a host nightly or
    global-default mutation; make the validated keyed sysroot and staging roots
    authoritative; and remove the legacy two-branch/toolchain path.
    Refuse the cutover unless the item 9 prefix and item 11 native artifacts
    validate. This changes how every component under `src/sys` and `src/boot`
    is compiled, so before committing run `src/tests/full-test.sh` three times
    each for debug and release as required by `AGENTS.md`.
13. Migrate remaining non-core selectors, `AGENTS.md`, contributor instructions,
    and build documentation, with their component-specific checks.
14. Separately migrate Lorry's implementation, specification, build, and tests
    to the current Motor Cargo as their sole compatibility family. Remove the
    Cargo 1.97/1.98 variants and oracle lanes, replace ambient channel aliases
    with the exact Motor Cargo path and revision check, remove hard-coded host
    paths, and run Lorry's specific test gate.
15. When Rust 1.99.0 is published, rebase onto its exact tag and LLVM pin,
    update all transitive identities, switch the manifest to stable, rebuild in
    newly keyed output trees, and repeat the entire validation matrix.
16. Smoke-test host and native tools, verify the stable source manifest, and
    create the immutable Rust and LLVM source tags named by the manifest for
    `1.99.0-motor.1`. Do not publish the locally assembled binaries or sysroot.

Real-toolchain smoke coverage should compile a minimal Motor executable, build
one boot loader with `-Zbuild-std` through the custom toolchain, run Clippy and
`cargo fmt --check` through it, verify the Motor std artifacts, inspect native
rustc/LLVM versions in the dev VM, and compare the image manifest to the host
source tuple. The binaries tested here are local build artifacts. New tests
must be offline and included in `src/tests/full-test.sh` directly or
transitively.
Keep every implementation patch to roughly 100-300 lines, including tests;
split an item further if necessary. Run the debug/release build and test
coverage appropriate to each affected build path without adding warnings.

## 8. Explicit update workflow

A normal build never advances source refs or explicitly refreshes dependencies.
An update is a reviewed operation:

### 8.1 First release: Rust 1.99 beta to Rust 1.99.0

1. Start from the exact Rust beta, LLVM, Cargo, and Stage 0 commits recorded in
   section 2.4 rather than following beta `HEAD`.
2. Create the commit-qualified non-release Motor development branches, replay
   the initial Motor patches, push the LLVM branch, update the Rust gitlink,
   push the Rust branch, and pin their resulting full commits. This initial
   mechanical replay bootstraps the manifest before the new authoring path
   exists; later commits are never required to be pushed merely to test them.
3. Use the beta period to implement the manifest, deterministic checkout,
   installed rustup toolchain, keyed outputs, version validation, and all
   required tests. As soon as source-authoring mode is available, use the exact
   beta commit as `--authoring-base` for every further Rust/LLVM patch
   iteration; push and update the declared revisions only after a stack is
   ready. Any move to a later beta commit is an explicit reviewed tuple update.
4. Development branches may be visible in the GitHub forks, but do not publish
   beta binaries or label any beta ref as `1.99.0-motor.1`.
5. When the upstream `1.99.0` tag is published, record its commit and compare
   its Stage 0, LLVM gitlink, Cargo gitlink, in-tree tools, and locks with the
   pinned beta tuple.
6. Rebase the Motor LLVM patches if the final LLVM pin changed. Rebase the
   Motor Rust branch onto the stable tag in all cases, update the LLVM gitlink,
   and resolve any changes explicitly.
7. Change the manifest from beta to stable and assign `1.99.0-motor.1`; build
   every artifact in new keyed output directories without repointing the beta
   root override. After the stable prefix and tuple pass, change
   `rust-toolchain.toml` to the stable key-qualified name and run the complete
   validation matrix through that override.
8. Create immutable source tags in the Rust and LLVM forks only after the stable
   tuple passes. Beta binaries are never promoted, relabeled, or published.

### 8.2 Subsequent stable updates

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

### 8.3 Runtime maintenance between compiler releases

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

## 9. Completion criteria

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
- All new tests are offline, integrated, and pass with the required build/test
  matrix and no new warnings. The core selector patch passes the full debug and
  release test suite three times each before commit.

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
