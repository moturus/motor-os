# Rust toolchains for Motor OS

The Linux-host Motor toolchain and the native Motor rustc are built by
`src/build-motor-os.sh` from one Rust revision. This document describes their
identity, layout, and link model; there is no separate `build-rustc.sh` or
legacy dev-toolchain handoff.

## One Rust source revision

`src/toolchain-versions.sh` is the source of truth for the exact upstream Rust,
Motor Rust, Cargo, and Motor LLVM commits. Generated manifests record the
effective revisions and keys actually built; do not infer them from a branch
name or copy a historical revision from documentation.

The fork uses Rust's `dev` channel. Its compiler description identifies the
Motor beta tuple, and its Cargo reports `1.99.0-dev` plus the exact Cargo
commit. Rust's downloaded Stage 0 compiler is only a bootstrap input selected
by that Rust revision's `src/stage0`; repository commands never select Stage 0
or an independent nightly/stable Cargo.

## Linux-host toolchain

Before building the C sysroot, Rust bootstrap installs an immutable Stage 2
toolchain under:

```text
$MOTORH/toolchains/<exact-rustup-name>/
```

The exact rustup name appends the 64-character toolchain key. The installed
prefix contains:

- Linux-host rustc and rustdoc;
- Cargo from the Rust revision's Cargo gitlink;
- host and `x86_64-unknown-motor` standard libraries;
- Clippy and `cargo-clippy`;
- Linux-host rust-analyzer and its matching proc-macro server;
- rustfmt and `cargo-fmt`;
- `rust-src` for boot-loader `-Zbuild-std` builds.

It is an installer-produced prefix, not Rust's mutable
`build/x86_64-unknown-linux-gnu/stage2` directory. A later native-compiler
bootstrap cannot replace it. The workflow validates component paths, full
`rustc -vV` and `cargo -Vv` identities, the reported sysroot, both target
compile probes, and its immutable manifest before registering the rustup link.

The root `rust-toolchain.toml` selects this exact managed name. Consequently,
repository work uses bare commands:

```sh
rustc -vV
cargo -Vv
cargo fmt --manifest-path src/sys/Cargo.toml --all --check
make clippy
```

Do not use the removed `+dev-x86_64-unknown-motor` selector or borrow Cargo,
rustfmt, or Clippy from an ambient channel.

## Using host rust-analyzer

The installed rust-analyzer runs on Linux and analyzes both Linux-host and
ordinary Motor userspace projects. It is distinct from the native server
packaged in the development image. From the repository, obtain the exact name and
server path with:

```sh
rustup show active-toolchain
rustup which rust-analyzer
```

Configure the editor's language-server command as `rustup run
<exact-active-name> rust-analyzer`, with the Cargo project as its working
directory. This prevents an editor-bundled server or an ambient Rust channel
from replacing the server selected by `rust-toolchain.toml`.

For a trusted Motor userspace Cargo project, pass these rust-analyzer LSP
initialization options:

```json
{
  "cargo": {
    "target": "x86_64-unknown-motor",
    "targetDir": true,
    "sysroot": "discover",
    "buildScripts": { "enable": true }
  },
  "check": {
    "targets": ["x86_64-unknown-motor"]
  },
  "procMacro": { "enable": true }
}
```

For a Linux-host project, leave `cargo.target` and `check.targets` unset.
Use a separate rust-analyzer process, normally a separate editor workspace or
window, for each target context. The pinned server does not apply a per-root
`cargo.target` from `rust-analyzer.toml` while loading multiple Cargo graphs,
so one process cannot accurately combine Motor and Linux projects. Opening
the repository root as one homogeneous workspace is also unsupported: the
kernel and loader use custom JSON targets outside this integration's scope.

Enabling build scripts and procedural macros executes project code on the
Linux host. Keep them enabled only for this trusted checkout or another
trusted project; disable both options when inspecting untrusted code.

The matching Linux proc-macro server is discovered under the selected
prefix's `libexec`; no `procMacro.server` override is needed. Keep the server,
proc-macro server, and `rust-src` from the same immutable toolchain.

The host also accepts an inline Project JSON object in `linkedProjects`.
Supply absolute normalized `sysroot`, `sysroot_src`, and crate `root_module`
paths, plus each crate's edition, target, cfgs, environment, source roots,
and dependency indices/names. A Motor object still needs
`cargo.target = "x86_64-unknown-motor"` in initialization options so sysroot
loading selects the same platform. This seam is tested without build scripts
or procedural macros; the native server uses Lorry metadata instead.

Custom JSON targets remain unsupported because the pinned analyzer's rustc
cfg and target-data queries cannot pass their required unstable flags. A
project can appear loaded with an empty cfg set. Substituting the userspace
Motor target or hard-coding `cargo.cfgs` does not correctly describe kernel
or loader code.

The offline host gate covers Motor Cargo, Linux Cargo, and inline Motor
Project JSON, with wrong-target sentinels, std navigation, and a 60-second
deadline per case. The Motor Cargo case also checks local proc-macro
expansion. Run `src/tests/test-rust-analyzer.sh` and its `--release` variant
after host LSP changes; both run through the corresponding full-test profile.
The harness sets `CARGO_NET_OFFLINE=true` for Cargo children and retains
bounded protocol and stderr evidence.

## Native Motor rust-analyzer

The developer image packages `/devtools/rust/bin/rust-analyzer` and matching
sources below `/devtools/rust/lib/rustlib/src/rust/library`. The standard
image contains neither. The native server uses `/devtools/bin/lorry`, not
Cargo; it does not replace the Linux-host component above.

Launch the binary directly over stdio, with an absolute project working
directory and this environment:

```text
CARGO=/devtools/bin/lorry
PATH=/devtools/bin:/system/bin
RUSTFMT=/devtools/rust/bin/rustfmt
TMPDIR=/devtools/tmp
```

An editor that owns a session terminal must additionally pass
`MOTURUS_STDIO_NO_TERMINAL=true` when spawning its background server so the
editor retains keyboard and Ctrl+C ownership. This launch instruction is
consumed by Motor before rust-analyzer starts.

Analysis cancellation requires Rust unwinding. The selected `.dev.2` toolchain
supplies the pure Rust unwinder in the standard Motor sysroot, and the
analyzer builds directly against the installed std. Older `.dev.1` images
rebuilt a private copy of the pinned Rust library for the analyzer; images
with recipe `motor-native-rust-analyzer-v1` abort on ordinary
cancellation and must be rebuilt. See
[the current runtime contract](toolchain.md#rust-runtime-and-native-formatting).

For an admitted, trusted Lorry package, use:

```json
{
  "cargo": {
    "target": "x86_64-unknown-motor",
    "targetDir": true,
    "sysroot": "discover",
    "buildScripts": { "enable": true, "useRustcWrapper": false }
  },
  "check": { "targets": ["x86_64-unknown-motor"] },
  "procMacro": { "enable": false },
  "files": { "watcher": "client" }
}
```

The client must report document saves and relevant filesystem changes.
Multiple packages use absolute manifest paths in `linkedProjects`; they share
the Motor target context. Native procedural-macro expansion in the analyzer
is disabled; Lorry's existing compiler-side proc-macro support is separate.
Build scripts and checks run with the invoking user's existing authority.
Opening a project is not a sandbox boundary, and `lorry vendor` remains an
explicit developer action.

Lorry's [inspect and check commands](../src/bin/lorry/README.md#inspect-and-check)
define the Cargo-compatible boundary, including `metadata`, JSON `check`
output, named targets, and `tree`. The analyzer also uses the supported
`locate-project` and read-only `rustc --print` queries. Metadata describes one
selected package per invocation; input manifests remain immutable. Client
notifications of manifest or lock changes trigger metadata reloads, and
build-script input changes trigger a new build-script pass. Run/test/debug
runnables remain upstream Cargo command templates outside native acceptance.

### Native server build

The server is built from the selected Rust tree's standalone analyzer
workspace without `in-rust-tree`, against installed Motor std. Its recipe
in `src/toolchain-native-rust-analyzer.sh` uses `opt-level=s` and
`motor-clang` with `-C link-self-contained=no -C default-linker-libraries=yes`.
mlibc startup executes the inventory registrations in `.init_array`.
Using the bootstrap `motor-rust-cc` wrapper with those default-library flags
would duplicate the startup object.

Motor fork changes disable implicit analyzer user-configuration lookup
(`dirs` is compiled only off Motor), stitch the matching `rust-src` directly
without a sysroot Cargo query, and stream child stdout/stderr through two
reader threads with a bounded chunk queue. Project metadata still uses
Lorry. File URI support and constructor registration use the checked-in
[URL and inventory patches](../src/patches/README.md). Their archive, patch,
and prepared-tree identities participate in toolchain validation; regular
builds and tests remain locked and offline.

The staged analyzer retains its `.comment` compiler identity. Packaged
`rust-src` comes from the selected installed prefix, with executable bits
cleared only on the staged copy. Native procedural expansion cannot use
Lorry's static proc-macro helper protocol: the analyzer expects a
compiler-private server and dynamic libraries. No such server is packaged,
though rustc may run an admitted static helper during a Lorry check.

### Native acceptance

Native acceptance is integrated under the developer-image branch of
`src/tests/full-test.sh`, reached by `src/tests/full-test-dev.sh --release`.
The latter defaults to 8192 MiB for the repository-suite VM and retains
4096 MiB for its separate developer-source phase; `MOTO_MEMORY_MIB` overrides
both. `test-rust-analyzer-native.sh` exercises project loading, build-script
results, semantic requests, saved diagnostics and clearing, multiple roots,
and shutdown. String hover exercises MIR evaluation and is sensitive to the
[allocator's](frusa.md) performance; it is included in the native gate.

The resource and size checks retain these limits for the two-project native
fixture on four vCPUs and 8 GiB of RAM:

| Measurement | Upper limit |
|---|---:|
| Complete native case | 90 seconds |
| Analyzer sampled virtual memory / threads | 2 GiB / 32 |
| Individual descendant Lorry check sampled virtual memory / threads | 64 MiB / 16 |
| Whole-VM sampled physical memory | 3 GiB |
| Stripped analyzer | 32 MiB |
| rust-src regular-file bytes | 80 MiB |
| Fresh image growth attributable to the analyzer overlay | 128 MiB |

These are fixture regression limits, not production capacity guarantees.
The sampler targets 100 ms intervals and records observed gaps and missing
measurements. Virtual memory is not RSS, sampled maxima are not exact peaks,
and sampled descendants are not an exhaustive execution audit. Phase timings
remain measurements. A limit failure requires diagnosis rather than retries,
worker caps, or automatic threshold increases.

### Helix on the developer image

Boot the release developer image with `vm_images/release/run-dev.sh`; this
launcher provides 8 GiB of guest RAM by default. In Motor OS, `hx` uses the
packaged native server configuration automatically. Try the dependency-free
example, which requires no downloads:

```sh
cd /devtools/src/helix-rust-demo
hx src/main.rs
```

Wait for initial source loading and indexing before semantic navigation.
Native rustfmt provides `:format` and format-on-save. The
[Helix guide](helix.md) covers commands, project configuration, port
limitations, save recovery, and regression coverage.

## Native Motor rustc

After LLVM, mlibc, compiler-rt, and libc++ are available in the keyed assembly
sysroot, a second `x.py` invocation builds rustc for
`x86_64-unknown-motor` from the same effective Rust and LLVM trees. The build
verifies that this invocation leaves the installed host prefix byte-for-byte
unchanged.

The development image packages these native Rust files:

```text
/devtools/rust/bin/rustc
/devtools/rust/bin/rustfmt
/devtools/rust/lib/rustlib/x86_64-unknown-motor/lib/*.rlib
/devtools/bin/rustc          PATH launcher
/devtools/bin/rustfmt        PATH launcher
/devtools/bin/cc             native linker driver supplied by the C toolchain
```

Use the launcher for formatting from the native shell; it supplies rustfmt's
writable temporary directory:

```sh
/devtools/bin/rustfmt --version
/devtools/bin/rustfmt src/main.rs
/devtools/bin/rustfmt --check src/main.rs
```

rustfmt discovers `rustfmt.toml` from the source path and its ancestors. A
syntax error produces a diagnostic and does not replace the source file.

Inside the development VM:

```sh
/devtools/bin/rustc --version
/devtools/bin/rustc /devtools/src/hello-world/hello.rs -o /user/tmp/hello
/user/tmp/hello
```

Pure Rust links remain independent of mlibc. The target passes
`-nostartfiles -nodefaultlibs`; Rust std's weak `motor_start` supplies the
entry point. A Rust program that intentionally links C opts into the C runtime:

```sh
/devtools/bin/rustc \
  -C link-self-contained=no \
  -C default-linker-libraries=yes \
  foo.rs -o foo
```

Rust code that uses C++ also passes `-C link-arg=-lc++`. In that link mode,
mlibc's strong entry point and runtime win over Rust std's weak fallbacks.

### Panic strategy and unwinding

The selected `.dev.2` Motor target defaults ordinary Rust applications to
`panic=unwind`. A program can catch a panic and continue:

```rust
let result = std::panic::catch_unwind(|| panic!("example"));
assert!(result.is_err());
```

Use an explicit Cargo profile for binaries that must terminate immediately or
minimize their runtime footprint:

```toml
[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
```

For a direct native rustc invocation, pass `-C panic=abort` to opt out:

```sh
/devtools/bin/rustc -C panic=abort app.rs -o app
```

Motor OS system binaries declare abort profiles explicitly; the kernel, boot
code, VDSO, and the `moto-rt` C ABI shim remain abort-only.

Rust std registers the executable's unwind metadata finder from Motor's
`std::rt::init` path. Binaries linked through mlibc also register it through an
early constructor so C++ static constructors can unwind before Rust `main`.
This covers normal Rust executables and Rust/C++ programs. An abort-only
static library that supplies neither a Rust entry point nor constructors has
no standalone unwinding initialization.

The [toolchain runtime contract](toolchain.md#rust-runtime-and-native-formatting)
describes the single unwind provider for Rust/C++ programs and required ELF
layout.

## Compiler dependency identities

The Rust fork keeps Motor-only patches in the main compiler workspace while
allowing independently vendored workspaces to resolve their own crates.io
packages:

- `stacker` uses `moturus/stacker` at
  `426b6a5af4a1da12026fcc2e8ecdb76a18850ac0`; this fork supplies Motor's
  allocation-based stack guard.
- `libloading` uses `moturus/rust_libloading` at
  `fb65a92af40bb114deee370ecf4164be74c3fb65` and version
  `0.9.0+motor.1` in the main Rust workspace.
- `libc` uses `moturus/libc` at
  `22836a72e660c7000b1b00db2f0a345fff4e52b6` and version
  `0.2.186+motor.1` in the main Rust workspace.
- rustfmt needs no patched dependency: the Motor fork resolves
  `/user` and `/user/cfg` behind `cfg(target_os = "motor")` and compiles
  `dirs` only off Motor.
- rustc LLVM retains its exact `cc = "=1.2.16"` dependency.
- Rust std uses published crates.io `moto-rt` 0.17.6, never a path into the
  Motor OS checkout.

The `+motor.1` versions give the forked `libloading` and `libc` distinct Cargo
package identities. Cargo's own vendored workspace can therefore keep its
crates.io `libloading 0.9.0`, while Rust's library workspace independently
keeps its crates.io `libc 0.2.189`; neither is redirected to the compiler
workspace's Motor fork. These selections are lockfile inputs and normal builds
do not refresh them.

## Building, authoring, and validation

Build the declared managed tuple:

```sh
src/build-motor-os.sh --source-mode managed
```

Test local Rust and LLVM changes without mutating the managed checkouts:

```sh
src/build-motor-os.sh \
  --source-mode authoring \
  --rust-source /absolute/path/to/rust \
  --authoring-base FULL_40_CHARACTER_BASE_COMMIT
```

An authoring compiler records the current commits and canonical dirty-tree
digest in a distinct non-release identity. It never updates the checked-in root
selector or qualifies for source publication.

The installed host prefix contains `MOTOR-TOOLCHAIN-MANIFEST`; the matching
assembly and development image contain `MOTOR-ASSEMBLY-MANIFEST` with both host
and native identities and hashes. Run the full repository tests after compiler
changes:

```sh
src/tests/full-test.sh
src/tests/full-test.sh --release
```

The final rebase and immutable `1.99.0-motor.1` source tags remain deferred
until upstream Rust 1.99.0 is published. Beta-built binaries are not renamed or
published as that stable release.
