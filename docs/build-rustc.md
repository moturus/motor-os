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
TMPDIR=/devtools/tmp
```

An editor that owns a session terminal must additionally pass
`MOTURUS_STDIO_NO_TERMINAL=true` when spawning its background server so the
editor retains keyboard and Ctrl+C ownership. This launch instruction is
consumed by Motor before rust-analyzer starts.

Analysis cancellation requires Rust unwinding. The native analyzer recipe
rebuilds a private copy of the pinned Rust library with a pure Rust unwinder;
the installed compiler's default abort strategy is unchanged. Older images
with recipe `motor-native-rust-analyzer-v1` abort on ordinary cancellation and
must be rebuilt. See [the diagnosis and build scope](plans/rust-unwinding.md).

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

Native acceptance is integrated under the developer-image branch of
`src/tests/full-test.sh`, reached by `src/tests/full-test-dev.sh --release`.
The latter defaults to 8192 MiB for the repository-suite VM and retains
4096 MiB for its separate developer-source phase; `MOTO_MEMORY_MIB` overrides
both. Native server acceptance is complete, including the string-hover case
resolved by the allocator work recorded in the
[implementation plan](plans/rust-analyzer.md#437-string-hover-investigation-allocator-scalability-review-stop).

### Helix on the developer image

Boot the release developer image with `vm_images/release/run-dev.sh`; this
launcher provides 8 GiB of guest RAM by default. In Motor OS, `hx` uses the
packaged native server configuration automatically. Try the dependency-free
example, which requires no downloads:

```sh
cd /devtools/src/helix-rust-demo
hx src/main.rs
```

Starting `hx` without arguments and opening `src/main.rs` with `:o` also works.

After initial source loading and indexing, place the cursor on `ANSWER`: `Space k`
shows documentation, `g d` opens its definition, and `Ctrl-o` returns.
`Ctrl-x` requests completion in insert mode. Change the `answer` binding's
type from `u32` to `bool` and save with `:w` to see a compiler diagnostic;
restore `u32` and save to clear it. `Space d` opens document diagnostics.
The `rt_version` call navigates into the installed Motor standard library.
Native rustfmt is not packaged, so Rust automatic formatting is disabled;
saving still runs the compiler check.

For other projects, select an admitted Lorry package and prepare its dependencies
with `lorry vendor` explicitly. A virtual workspace root is not a Lorry package.
Server options are in `/user/.config/helix/languages.toml`, with normal Helix
project overrides in `.helix/languages.toml`. A custom `XDG_CONFIG_HOME` needs
the native settings copied into its own `helix/languages.toml`.
Use `hx --health rust` for discovery, `:log-open` for logs, and `:lsp-restart`
after changing server settings or project metadata. The
[Helix integration record](plans/helix-rust-analyzer.md) tracks editor acceptance.

## Native Motor rustc

After LLVM, mlibc, compiler-rt, and libc++ are available in the keyed assembly
sysroot, a second `x.py` invocation builds rustc for
`x86_64-unknown-motor` from the same effective Rust and LLVM trees. The build
verifies that this invocation leaves the installed host prefix byte-for-byte
unchanged.

The development-image layout is:

```text
/devtools/rust/bin/rustc
/devtools/rust/lib/rustlib/x86_64-unknown-motor/lib/*.rlib
/devtools/bin/rustc          PATH launcher
/devtools/bin/cc             native linker driver supplied by the C toolchain
```

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
