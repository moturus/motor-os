# Full native build gap analysis

Status: repository audit updated on 2026-08-18. This is a findings document, not a
normative Lorry design. Accepted behavior belongs in `spec.md` and implementation
rationale belongs in `design.md`.

## Question and scope

The milestone audited here is to run Lorry **on Motor OS** and have it build
and Clippy-check every Motor-target crate reached from the repository-root
`Makefile`, except every crate below `src/boot`. This includes the kernel and
vdso commands embedded in their `build.sh` files, all ordinary `DO_BUILD` and
`DO_CLIPPY` packages, the Motor-target Lorry, curl's existing Lorry build, and
the imager. Native image assembly uses `lorry run` for the imager. The required
user-facing validation command is `lorry clippy`.

The following are deliberately out of scope:

- `src/boot/x64.mbr`, `src/boot/x64.boot`, and `src/boot/x64.kloader`;
- the Linux-host `host-lorry` build; and
- replacing Make, `strip`, or VM scripts with Lorry features.

The native VM is assumed to contain the prebuilt boot binaries and the prebuilt
LLVM/Rust compiler binaries, trees, and sources needed as image/build inputs.
Lorry is not expected to produce those artifacts. Motor has no Python, so the
existing Python preparation utilities will need shell replacements before the
complete native workflow can run. Designing or implementing those replacements
is explicitly outside this document; their prepared outputs are inputs to the
imager step described here.

This boundary removes every current NASM and standalone GNU `as` invocation,
as well as the boot-only `objcopy` steps. It does not remove the kernel's
custom JSON target or its `build-std=core,alloc` requirement.

The Motor development image already contains the native LLVM toolchain
described in `docs/build-llvm.md`: `/devtools/llvm/bin/llvm` dispatches Clang,
LLD, and the LLVM binutils, `/devtools/bin/cc` and `/devtools/bin/c++` are compiler-driver front
ends, and `/devtools/llvm` is a complete C/C++ development sysroot. Lorry
therefore needs to configure and admit those installed tools, not package
another LLVM toolchain. The supplied Rust tree must include rust-src matching
the native rustc. A matching Motor-native Clippy driver must also be staged.

`curl` is not a Cargo build in the Makefile: it is cross-built by the host
Lorry today, and its native Lorry build is already a Stage-2 validation case.
It remains part of the desired native end state but is not a remaining
compatibility gap.

## Short answer

Lorry cannot yet build and Clippy-check the complete in-scope Rust surface or
run the imager natively. Ordinary installed-target packages are close, but the
milestone has seven real gaps:

1. Root `build.rs` is parsed but never run. This silently misbuilds the in-scope
   `dns-resolver` root and must be fixed before expanding compatibility.
2. The repository uses Cargo.lock v3, a Cargo profile environment override,
   and root feature flags that Lorry rejects or cannot express.
3. The DNS root script needs `rustc-link-arg`, controlled environment/resource
   inputs, and admission of Motor's installed Clang/LLVM tools.
4. Several selected graphs exceed the default 64-package policy limit and all
   projects except Lorry still need reviewed admission state and an offline
   repository seed.
5. The kernel requires a custom JSON target and a narrow equivalent of Cargo's
   `-Z build-std` pipeline.
6. The imager's current source/dependency graph is not Motor-buildable: it uses
   a file-block-device module disabled on Motor and lacks the Motor Tokio patch.
7. Lorry has no `clippy` command, and the development image does not yet stage
   a Motor-native Clippy driver paired with its native rustc.

Multiple binaries, selected-member workspaces, crates.io/Git/path dependencies,
root Git patches, dependency build scripts,
procedural macros (including native Motor executable macros), target
dependencies, rustflags, linkers, and Linux/Motor rustc execution are already
present. Workspace-wide commands are not required by the current Makefile.

## Build inventory

The dependency counts below are Cargo metadata closures for
`x86_64-unknown-motor`, excluding the root package. They measure the currently
locked selection, not Lorry policy approval. All measured depths are at most
15, so the default depth limit of 16 is sufficient. The counts are evidence
for a configured package limit, not a reason to silently weaken the default.

| Make target | Cargo package | Dependencies | Important requirements |
|---|---|---:|---|
| `kernel` | `kernel` in `src/sys` | 31 | shared lock v3; custom target; `build-std=core,alloc`; workspace Git entries |
| `vdso` | `rt` in `src/sys` | 47 | shared lock v3; `--features netdev`; library plus binary |
| `sys-io` | `sys-io` | 77 | over default package limit; dependency scripts/proc macros |
| `sys-init` | `sys-init` | 30 | shared lock v3 |
| `strobe` | `strobe` | 30 | shared lock v3 |
| `sys-tty` | `sys-tty` | 33 | shared lock v3 |
| `dns-resolver` | `dns-resolver` | 30 | root script, custom clang/SDK environment, `rustc-link-arg`, release-LTO override |
| `sysbox` | `sysbox` | 62 | crossterm Git patch; close to default package limit |
| `mdbg` | `mdbg` | 19 | proc macro; shared lock v3 |
| `systest` | `systest` | 44 | dependency scripts/proc macros |
| `crossbench` | `crossbench` | 38 | proc macro; shared lock v3 |
| `mio-test` | `mio-test` | 19 | mio Git patch |
| `crossterm-smoke` | `crossterm-smoke` | 19 | crossterm Git patch and proc macro |
| `tokio-tests` | `tokio-tests` | 25 | mio/tokio Git packages and native proc macro; local rustflags config |
| `rush` | `moto-rush` | 11 | crossterm Git patch |
| `russhd` | `russhd` | 199 | direct `russh` Git dependency/monorepo, three Git patches, nine proc macros, one `links` package |
| `httpd` | `httpd` | 39 | ring Git patch, proc macro, `links` package |
| `httpd-axum` | `httpd-axum` | 103 | ring/mio/tokio Git packages, four proc macros, `links` package |
| `kibim` | `kibim` | 1 | lock v3 |
| `red` | `red` | 9 | crossterm Git patch |
| `rmux` | `rmux` | 9 | crossterm Git patch; root library plus binary |
| `rnetbench` | `rnetbench` | 30 | proc macro |
| `gears` | `gears` | 22 | proc macro and dependency scripts |
| `lorry` | `lorry` | 33 | already supported on Motor; Make output path differs |
| image recipes | `imager` | at most 110 locked | native `run`; external path dependencies, proc macros, local rustflags; Motor file backend/Tokio preparation required; exact closure unavailable because cached `slab 0.4.11` is absent |

The excluded boot crates and the host-only `host-lorry` build are not
implementation targets for this milestone. The Motor-native imager is. Curl is
an in-scope native proof, but is omitted from the remaining-gap inventory
because it already builds natively with Lorry.

The `src/sys` virtual workspace has 29 explicit members, no member globs or
inheritance, and therefore fits existing W1 workspace support and the
64-member bound. Each Make recipe selects one member; no `--workspace` build
is needed.

## Cargo command surface used by Make

Lorry already covers `build`, `run`, `--release`, installed `--target`,
arguments after `run --`, `RUSTFLAGS`, and target linker configuration. Its
local Cargo-configuration support must preserve the imager's
`--cfg tokio_unstable`. It always treats Cargo.lock as locked, so Cargo's
`--locked` does not require a flag.

The missing command/profile surface is:

- the `lorry clippy` command with the same package, target, profile, target
  selection, and feature selection used by `lorry build`;
- `--features netdev` for `rt.vdso`;
- `--no-default-features` as used by the kernel script (currently a no-op for
  that manifest, but still part of the invoked contract);
- `CARGO_PROFILE_RELEASE_LTO=false` for `dns-resolver`; and
- custom JSON `--target` plus `-Zjson-target-spec`, `-Zbuild-std`, and
  `-Zbuild-std-features` for the kernel.

The in-scope release manifests use only the `panic`, `lto`, `strip`, and
`codegen-units` fields that Lorry already models. The extra `opt-level`,
`debug`, and `overflow-checks` work identified in the wider audit was needed
only by excluded boot crates.

Profile and feature values must enter unit identity, cache identity,
admission/freshness input, build-script environment, and rustc arguments. The
bounded initial CLI should support exact feature names, `--all-features`, and
`--no-default-features`; Cargo glob/package feature syntax is not needed by
Make. Profile environment support can initially be limited to fields Lorry
already models plus the new fields above, with unknown `CARGO_PROFILE_*`
variables rejected.

## Root build scripts and native tools

This is the first correctness increment. `dns-resolver` is the only in-scope
root with a build script. Lorry records the path but creates build-script units
only for resolved dependencies. It then compiles the root without the generated
bridge object or link argument.

Root scripts should reuse the existing host compile/run path with
`CARGO_PRIMARY_PACKAGE=1`, a private OUT_DIR, the selected target/profile
environment, bounded output, freshness inputs, and native-tool admission. Their
directives must be applied to each applicable root target and included in the
root fingerprint. The DNS root has no build-dependencies, so root
build-dependencies are not required for this milestone.

The directive parser needs `rustc-link-arg` for the DNS bridge object. It must
validate the path and target applicability rather than accepting an arbitrary
opaque linker command. `rustc-link-arg-bins` is a boot-only need and is no
longer part of this milestone. Dependency graphs inspected in this audit use
only the already supported directive set.

Native execution must remain explicit. DNS reads `MOTOR_DNS_CLANG`,
`MOTOR_DNS_SDK`, and `MOTOR_DNS_SYSROOT` and starts clang. Lorry currently
exposes only absolute `c-compiler` and `archiver` roles and clears ambient
variables/PATH.

Motor already supplies the necessary C/C++ and LLVM pieces. `/devtools/bin/cc` can be
the exact C compiler entry point, `/devtools/llvm/bin/llvm` provides fixed
`clang`, `ld.lld`, `ar`, `strip`, and `objcopy` subcommands, and the headers,
startup object, and libraries live below `/devtools/llvm`. For the DNS root,
the native bindings can consequently select `/devtools/bin/cc`, `/devtools/llvm`, and
the Motor root filesystem as the compiler, SDK, and sysroot inputs. These are
installed platform resources, not Lorry bootstrap payloads.

The secure integration still needs explicit, identity-tracked build-script
environment bindings. A multicall tool must either be admitted with an
enforced fixed subcommand or exposed through an exact approved wrapper; it
must not become ambient PATH access. The DNS SDK/sysroot must be declared
read-only resource roots, and every tool, argument, environment value, and
resource path must be part of cache/audit identity. Native Motor still emits
the existing unsandboxed warning until its build-script sandbox exists. No
in-scope crate invokes NASM or standalone `as`.

## Locks, sources, admission, and limits

The in-scope build reads version-3 locks for `src/sys` and `kibim`. Lorry
accepts v3 as read-only compatibility input. Vendor preserves a current v3
lock and writes v4 when dependency changes require replacing it. The
alternatives considered were:

- accept v3 as a read-only compatibility input and continue rendering v4 from
  `vendor`; or
- regenerate and commit every repository lock as v4 before conversion.

Read-only v3 support builds the checkout exactly as it exists today and is a
small, bounded compatibility increment.

The Git source work identified by the original audit is complete. Vendor now
materializes root Git patches before ordinary manifest loading and represents
direct Git and monorepo packages as first-class immutable sources. The same
gix smart-HTTP path runs on Linux and Motor, while build/run/test consume and
verify the resulting snapshots offline. Building the full `russhd` graph still
depends on the separate package-limit and admission preparation described
below.

Only `src/bin/lorry` currently has committed compact admission state. A full
offline build therefore also needs a packaging operation that, for every root
context, vendors/reviews the selected graph and installs the union of immutable
objects plus member-local admission files. This is bootstrap/image input, not
logic in `lorry build` and not a reason for Lorry to understand imager YAML.

System policy must explicitly admit each registry/Git package, every build
script and proc macro, required patches, and native tools. Configure
`max-packages` above the measured 199-dependency `russhd` closure (with review
headroom); do not raise Lorry's global default. The default depth 16 is enough
for the measured graphs. Aggregate download/extraction limits must be measured
during a dry-run vendor campaign because a 200-package transaction may exceed
the current 256 MiB compressed total.

## Custom targets and build-std

The custom-target milestone is substantially larger than ordinary package
compatibility. Lorry currently rejects `.json` targets and assumes the target
string is a portable installed triple. The only in-scope custom target is the
kernel's x86-64 freestanding `kernel.json`. Its build asks Cargo to rebuild
`core` and `alloc` with `compiler-builtins-mem`.

A narrow implementation needs to:

1. canonicalize and parse a bounded target JSON file, query rustc cfg, and use
   a stable logical target name plus the file digest in identity/admission;
2. pass the necessary nightly JSON-target opt-in to rustc without admitting
   arbitrary unstable Cargo flags;
3. locate a matching rust-src tree and build the requested `core`/`alloc` and
   compiler-builtins graph for that target;
4. implement the compiler-builtins feature and sysroot wiring used by these
   exact commands;
5. keep host build scripts/proc macros on the compiler host; and
6. publish/reuse the resulting target libraries under an identity containing
   rustc, rust-src, target JSON, build-std set, and features.

The VM-provided Rust source tree must consequently expose the exact rust-src
used by rustc in a location Lorry can select. Prebuilt custom-target libraries
would reduce implementation work but would not reproduce what Cargo currently
builds after a clean and would make the target JSON/toolchain coupling an
external packaging contract.

## Make and native integration

Lorry should keep ownership of `target/lorry`; adding Cargo's arbitrary
`CARGO_TARGET_DIR` is not required. Make recipes can consume the documented
workspace/member paths and copy/strip the final artifacts. The host-only Lorry
recipe remains Cargo-driven and outside this native milestone. The imager
recipe instead becomes a native `lorry run` consumer.

Parallel `make -j` will start multiple Lorry processes against the shared
`src/sys/target/lorry` and global cache. Atomic cache publication is designed
for this, but the complete 29-member concurrent workload needs a correctness
test. A bounded `-j`/jobserver integration may later prevent oversubscription;
it is performance work, not a prerequisite for serial correctness.

### Native imager

The imager is an in-scope Motor package. Lorry must build and Clippy-check it
for `x86_64-unknown-motor`, and `lorry run -- ...` must execute it with the
same arguments the current Make recipes pass to Cargo. Its Cargo.lock is
already version 4, and its command uses Lorry features that otherwise exist:
external path dependencies, procedural macros, local rustflags, and run
arguments. Its complete dependency graph still needs ordinary offline
repository/admission preparation.

The current source graph cannot yet compile for Motor, independently of Lorry:

- `imager` directly imports `async_fs::file_block_device`, while `async-fs`
  exposes that module only under `cfg(not(target_os = "motor"))`; and
- the standalone imager manifest/lock selects crates.io Tokio rather than the
  reviewed Motor Tokio patch used by `src/sys`.

The first issue needs a Motor-capable file-backed block-device implementation
or a small imager-specific alternative. The second needs the normal immutable
Motor Tokio source selection and admission. These are source/dependency
preparation tasks, not reasons to special-case imager inside Lorry. Once fixed,
the native run must be validated by creating an image from the prebuilt MBR,
boot, kloader, LLVM, and Rust payloads supplied in the VM and comparing its
structure with the existing host-built image contract.

`prepare_dev_sources.py` is currently an input-preparation step before the
imager runs. Its eventual shell replacement stays outside this analysis. The
native imager consumes the prepared directory; neither `lorry build` nor
`lorry run` should learn Python, source-staging, or image-layout policy.

### Native Clippy

Clippy is part of the milestone, not an optional host validation path. Lorry
must provide `lorry clippy`, and the kernel/vdso scripts plus the root `clippy`
target must be able to replace their in-scope `cargo clippy` commands with it.
The `src/imager` Clippy invocation is also in scope and must use the same Motor
dependency selection as its native build/run.

`lorry clippy` should be a Lorry graph operation, not a call to Cargo or
`cargo-clippy`. It must resolve the same selected package, target, target kind,
profile, features, rustflags, linker, build scripts, proc macros, and host/target
closures as `lorry build`. It should reuse valid dependency and build-script
cache entries, invoke Clippy for the source units Cargo would lint, propagate
diagnostics and the nonzero exit status, and keep Clippy completion records
separate from successful artifact-build records. The kernel invocation must use
the same custom target and build-std graph as its build; the vdso invocation
must retain `--features netdev`.

The compiler toolchain must supply a Motor-native `clippy-driver` built from
the same Rust source/toolchain tuple as the selected native rustc. Lorry should
select it as the exact sibling of that rustc, hash it into Clippy execution
identity, and fail with an actionable mismatch/missing-tool diagnostic. It is
a trusted compiler component, not a package build-script capability. The
development image currently stages only the native `rustc`, so its Rust
toolchain packaging must also stage the matching native driver and any private
compiler libraries it needs. Prefer a statically linked Motor executable, as
with native rustc; `cargo-clippy` itself is unnecessary because Lorry owns the
front end.

For a genuinely Motor-hosted full build, image packaging already provides
Clang, LLD, the LLVM archiver/strip/objcopy tools, and the Motor C/C++
SDK/sysroot. The native build must point its approved-tool configuration and
post-processing commands at that multicall installation. Packaging still needs
the matching Motor-native Clippy driver, the complete Lorry repository and
admission state, and all in-scope source trees. The VM-provided matching
rust-src and prebuilt boot/LLVM/Rust payloads are explicit inputs. NASM,
standalone `as`, and boot-source packaging are not required. Replacing Python
input preparation is separate shell-script work outside this document.

## Recommended implementation order

1. Make root `build.rs` fail closed, then implement dependency-free root
   execution and the DNS `rustc-link-arg` directive.
2. Add lock v3 input, bounded root feature flags, required profile fields, and
   the DNS LTO environment override.
3. Bind and admit the installed Motor LLVM/SDK resources, add explicit
   root-script environment/resource admission, and prove the DNS root script
   natively.
4. Prepare admission/repository state, raise only installation policy limits,
   and build every installed-Motor-target package, including `russhd` from the
   same reviewed Git snapshot on Linux-to-Motor and native Motor.
5. Add custom target/build-std support and build the kernel natively.
6. Prepare the imager's Motor file backend and Motor Tokio source, admit its
   offline graph, then build and run it natively against the prebuilt payloads.
7. Build and stage the paired Motor-native Clippy driver, implement `lorry
   clippy`, and prove the ordinary, vdso-feature, proc-macro, build-script, and
   kernel custom-target cases, plus the imager.
8. Switch in-scope Make build, run, and Clippy recipes to Lorry paths and
   commands, then validate parallel publication. Leave boot and host-only
   recipes alone.

Each Lorry-only increment should use focused contracts and
`src/bin/lorry/tests/test-all.sh`. A patch that changes Make, image contents,
toolchain packaging, or another system component must use the broader system
gate required by the applicable `AGENTS.md`.

## Decisions needed before implementation

- Use fixed-prefix admission for Motor's LLVM multicall or exact image wrappers?
- What portable canonical name should admission use for a custom JSON target?
- Which Motor-capable file-backed block-device implementation should imager
  use?
- Should the paired native Clippy driver be required beside rustc, or selected
  through an explicit toolchain configuration field?

None of these decisions is needed to fix the two current fail-closed defects
or to begin the ordinary installed-target compatibility work.
