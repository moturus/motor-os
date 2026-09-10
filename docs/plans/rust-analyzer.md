# rust-analyzer for Motor OS development

Stage 1 is complete. Section 3 is maintained documentation for the supported
Linux-host service; it contains no remaining implementation plan. Section 4
is the implementation plan for a native Motor OS rust-analyzer. It was
reviewed against the selected Motor Rust tree, the Lorry sources, and the
imager configuration on 2026-09-02, and its design questions were answered
the same day in section 4.14. On 2026-09-02 U. Lasiotus expanded the scope to
include Cargo-compatible `lorry metadata`, `lorry tree`, and
`lorry check --message-format=json`; section 4 reflects that scope. The native
server is complete; section 4 retains its implementation and validation record.
Lorry prerequisite
patches 1-16 in section 4.12 are complete and gated. `lorry metadata`,
`lorry check`, including Cargo-compatible JSON messages, and `lorry tree` are
implemented, and the pinned host rust-analyzer passes the exact Lorry
acceptance contract. The first Motor Rust portability patch excludes the
native config-directory dependency and stitches the native sysroot without a
Cargo query. The completed Lorry work makes `lorry vendor` keep every input
`Cargo.toml` immutable and removes Lorry's unused required-patch feature,
which U. Lasiotus authorized on 2026-09-02.

## 0. Status and architecture

Both stages are required:

| Stage | Server host | Analyzed targets | Status |
|---|---|---|---|
| 1. Host | Linux | Motor and Linux host | Complete and gated |
| 2. Guest | Motor OS | Motor only | Complete and gated, including native Helix integration (§4.38); frusa_v2 resolved string hover (§4.37) |

The stages share a pinned source revision and an LSP test harness, but produce
different executables and have different project-loading boundaries. Stage 1
uses Cargo on Linux. Stage 2 runs without native Cargo: Lorry answers the
`cargo metadata`, `cargo check --message-format=json`, and narrow read-only
Cargo compatibility queries that rust-analyzer issues, so the same workspace
loader serves both hosts.

The two outputs are distinct even though they use the same pinned source:

```text
$MOTORH/toolchains/<toolchain-key>/bin/rust-analyzer
    Linux executable; part of the immutable host Rust toolchain

$MOTORH/assemblies/<assembly-key>/images/rust-analyzer/
    Motor executable and rust-src overlay; development image only
```

Both builds consume the standalone rust-analyzer manifest and lock, so that
lock is a toolchain-key input. The native artifact additionally depends on the
assembly sysroot, linker, mlibc startup, and native dependency ports, so its
recipe and output belong to the assembly key. One executable cannot serve
both hosts.

## 1. Common goals and constraints

Both stages:

- use the in-tree `src/tools/rust-analyzer` snapshot from the same effective
  Motor Rust revision as rustc;
- analyze `cfg(target_os = "motor")` with the matching Motor standard-library
  sources rather than an ambient stable or nightly sysroot;
- in Stage 1, also analyze the checkout's Linux host programs for
  `x86_64-unknown-linux-gnu` with the same keyed toolchain's host std;
- keep generated artifacts in exact key-qualified locations;
- keep normal tests offline and deterministic;
- introduce no boot-time work;
- use editor-neutral standard LSP and Cargo-compatible `metadata` and
  `check --message-format=json` contracts, with Lorry standing in for Cargo
  on Motor rather than a future client owning the project description;
- treat every project and workspace `Cargo.toml` as an immutable input to all
  Lorry commands, including `vendor`;
- keep each implementation patch near 100-300 lines including tests, except
  for the explicitly identified cross-cutting, mostly-deletion patch; and
- introduce no compiler or Clippy warnings and format Rust changes with the
  repository-selected toolchain.

Stage 2 will not:

- make the repository root one homogeneous Rust workspace or assign one target
  to Linux host tools, Motor userspace, the kernel, and the loader;
- support custom JSON target specifications, including the kernel and loader
  targets, or any analyzed target other than `x86_64-unknown-motor` and, in
  Stage 1 only, `x86_64-unknown-linux-gnu`;
- port Cargo to Motor OS beyond the Cargo-compatible subset of `metadata`,
  `check`, and `tree` and the exact read-only rust-analyzer compatibility
  queries that Lorry implements;
- port, configure, or otherwise modify a text editor, Helix, Red, Gears, or
  any other LSP consumer as part of Stage 2;
- add dynamic linking or constructor execution to the pure-Rust Motor startup
  path;
- support native procedural-macro dylibraries in Stage 2;
- run rust-analyzer during boot;
- add a polling filesystem watcher; or
- hide failures with retries, longer timeouts, ignored errors, or automatic
  server restarts.

## 2. Existing toolchain pipeline

`src/build-motor-os.sh` resolves one exact Rust/LLVM/Cargo source tuple and
defines:

```text
HOST=x86_64-unknown-linux-gnu
TARGET=x86_64-unknown-motor
TOOLCHAIN_PREFIX=$MOTORH/toolchains/<toolchain-key>
ASSEMBLY_ROOT=$MOTORH/assemblies/<assembly-key>
```

The host toolchain is installed transactionally by one command:

```sh
./x.py --config "$BOOTSTRAP_CONFIG" install --stage 2
```

The generated bootstrap configuration has `extended = true` and now installs
rustc, rustdoc, Cargo, host and Motor std, Clippy, rustfmt, `rust-src`, and the
Stage 1 Linux-host rust-analyzer components.

The selected Rust bootstrap already has first-class steps for both host
components needed here:

- `rust-analyzer`, built as a host `ToolRustcPrivate` tool with the
  `in-rust-tree` feature; and
- `rust-analyzer-proc-macro-srv`, built when rust-analyzer is enabled and
  installed below the compiler sysroot's `libexec` directory.

Rust-analyzer searches that `libexec` directory for the proc-macro server. The
completed prefix is validated before it is linked through rustup. The shared
standalone LLVM supplies all 14 bootstrap tools: `llvm-cov`, `llvm-nm`,
`llvm-objcopy`, `llvm-objdump`, `llvm-profdata`, `llvm-readobj`, `llvm-size`,
`llvm-strip`, `llvm-ar`, `llvm-as`, `llvm-dis`, `llvm-link`, `llc`, and `opt`.
The build and identity details are maintained in `docs/toolchain.md`.

After the host prefix has been completed and linked through rustup, the
pipeline builds the assembly, including native LLVM, mlibc, and a Stage 2 rustc
whose host is `x86_64-unknown-motor`. That later native-compiler bootstrap is
why the two rust-analyzer builds must remain separate.

## 3. Stage 1 (complete): rust-analyzer on the Linux host

Stage 1 has no remaining implementation items. It is the supported way to run
rust-analyzer on Linux while developing ordinary Motor OS userspace code, and
it also supports the repository's Linux-host Rust projects. The concise
user-facing setup is maintained in `docs/build-rustc.md`; this section records
the service boundary, configuration contract, and acceptance coverage that
Stage 2 builds upon.

### 3.1 Installed server and toolchain selection

The managed Rust build installs three related inputs from the same selected
Rust revision:

```text
$TOOLCHAIN_PREFIX/bin/rust-analyzer
$TOOLCHAIN_PREFIX/libexec/rust-analyzer-proc-macro-srv
$TOOLCHAIN_PREFIX/lib/rustlib/src/rust/library
```

The first two are Linux executables. They analyze Motor code by invoking the
matching compiler and reading the matching Motor standard library; they are
not native Motor OS programs. The prefix is immutable and keyed by the
compiler inputs. Its component paths and identities are validated before the
toolchain is linked through rustup.

From the repository, verify selection with:

```sh
rustup show active-toolchain
rustup which rust-analyzer
rust-analyzer --version
rustc --print sysroot
```

`rustup which rust-analyzer` and `rustc --print sysroot` must resolve below
the same keyed prefix. Configure an editor or another LSP client to launch:

```sh
rustup run <exact-active-name> rust-analyzer
```

Use the Cargo project as the server's working directory. This explicit command
prevents an editor-bundled server or an ambient Rust channel from replacing
the version selected by the repository's `rust-toolchain.toml`. Do not copy a
server, proc-macro server, or `rust-src` from another toolchain into the
prefix; rebuild or provision the managed toolchain instead.

Rust-analyzer discovers its matching proc-macro server in the prefix's
`libexec` directory. No `procMacro.server` override is needed for the
supported configuration.

### 3.2 Supported target and workspace boundaries

The host service supports these project contexts:

| Project context | Status |
|---|---|
| Ordinary Cargo project for `x86_64-unknown-motor` | Supported |
| Cargo project for `x86_64-unknown-linux-gnu` | Supported |
| Inline Project JSON describing an ordinary Motor crate | Supported and covered by the smoke test |
| Kernel or loader project using a custom JSON target | Unsupported |
| The repository root treated as one homogeneous workspace | Unsupported |

Run Motor and Linux project contexts in separate rust-analyzer processes,
normally separate editor workspaces or windows. The pinned server treats
`cargo.target` as workspace-scoped but reuses one target-neutral Cargo-loader
configuration for every Cargo graph in a process. It therefore cannot
accurately combine Motor and Linux Cargo roots. A per-root
`rust-analyzer.toml` does not repair that behavior.

This restriction does not prevent a client from using several independent
standard-LSP server processes. Stage 1 defines no editor-specific session
manager and no repository-wide project-discovery command.

### 3.3 Ordinary Motor Cargo projects

For a trusted Motor userspace Cargo project, pass these standard
rust-analyzer LSP initialization options:

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

The `cargo.target` setting selects Motor cfgs and dependencies during project
loading. `check.targets` makes the flycheck use the same target.
`cargo.targetDir = true` gives rust-analyzer a separate Cargo artifact
directory so editor checks do not contend with ordinary command-line builds.
`cargo.sysroot = "discover"` selects the std sources installed with the active
keyed compiler.

For a Linux-host Cargo project, leave `cargo.target` and `check.targets` unset.
The server then uses `x86_64-unknown-linux-gnu` and the host std from the same
keyed toolchain.

Build scripts and procedural macros execute project code on the Linux host.
Keep them enabled only for this trusted checkout or another trusted project.
When inspecting untrusted code, disable both
`cargo.buildScripts.enable` and `procMacro.enable`. This is a host trust
boundary, not a Motor OS sandbox.

### 3.4 Project JSON contract

The pinned server also accepts a Project JSON object directly in
`linkedProjects`. Stage 1's inline fixture supplies:

- absolute, normalized `sysroot` and `sysroot_src` paths from the selected
  keyed toolchain;
- an absolute `root_module` for each crate;
- `edition`, `target`, `cfg`, `env`, and source include/exclude roots; and
- dependency indices and names admitted by the project description.

For a Motor Project JSON object, the initialization options must still set
`cargo.target` to `x86_64-unknown-motor`. The crate's `target` field describes
that crate, while the workspace setting selects the platform when
rust-analyzer loads sysroot metadata through Cargo.

The Stage 1 fixture deliberately has no build-script output or procedural
macros. Stage 2 does not use this seam: the native server loads Motor
projects through its Cargo workspace loader with Lorry answering for Cargo
(section 4).

### 3.5 Custom JSON targets remain unsupported

The kernel and loader targets
(`src/sys/kernel/kernel.json` and
`src/boot/x64.kloader/kloader.json`) are outside both stages.

The pinned Cargo and rustc require unstable flags for JSON target
specifications. Rust-analyzer adds the necessary flag to its Cargo metadata
query, but its rustc cfg and target-data queries cannot receive equivalent
extra arguments. The result can be a project that appears to load while
silently carrying an empty target cfg set. Do not work around this by
substituting `x86_64-unknown-motor` or hard-coding `cargo.cfgs` for a kernel
or loader crate. Correct support requires a separate design for either a
Motor rust-analyzer change or a project-description bridge that supplies all
target data consistently.

### 3.6 Offline acceptance test

The maintained Stage 1 acceptance test consists of:

- `src/tests/test-rust-analyzer.sh`;
- the Rust harness in `src/tests/rust-analyzer-smoke/`; and
- its three dependency-free semantic fixtures.

`serde_json` is the harness's only external dependency. Its use is an
explicitly approved test-only exception: implementing another JSON stack in
Rust or delegating the protocol to Python would add more risk and code. Its
locked packages are already selected by the pinned rust-analyzer sources; the
harness is built and run with `--locked --offline`.

The semantic cases prove:

| Case | Required result |
|---|---|
| Motor Cargo | Motor cfgs, one completed flycheck, `std::os::motor` definition, vendored `moto_rt` definition, and local proc-macro expansion |
| Linux Cargo | Linux cfgs, one completed flycheck, and `std::os::linux` definition |
| Inline Motor Project JSON | Motor cfgs and `std::os::motor` definition without Cargo project discovery, build scripts, or proc macros |

Every case also contains a wrong-target sentinel. The harness launches the
exact selected server, uses bounded LSP frames, pending requests, diagnostic
state, and stderr retention, and applies a 60-second total deadline to each
case. It drains stderr concurrently, waits for server quiescence and the
expected flycheck completion, performs `shutdown`/`exit`, and kills and reaps
a server that fails the lifecycle. It does not retry.

The server's Cargo children receive `CARGO_NET_OFFLINE=true`. Consequently,
missing cached inputs fail visibly rather than reaching a registry or Git
repository. Run the focused gate in both profiles with:

```sh
src/tests/test-rust-analyzer.sh
src/tests/test-rust-analyzer.sh --release
```

`src/tests/full-test.sh` invokes the matching profile transitively.

### 3.7 Maintenance rules

Keep `docs/build-rustc.md` as the short user-facing launch and configuration
guide. Update that guide and this section together if the supported target,
toolchain-selection, trust, or process boundary changes.

Changes to the Rust revision, bootstrap component set, proc-macro server,
`rust-src` contents, or standalone LLVM inputs must flow through the managed
toolchain key and validation pipeline described in `docs/toolchain.md`. Never
repair a prefix in place. Changes to host LSP behavior must keep the focused
test offline and pass it in both debug and release profiles before the normal
repository gates.


## 4. Stage 2: native Motor OS guest design

### 4.1 Scope and design

Stage 2 cross-builds rust-analyzer as a Motor OS process, packages it only in
the development image, and lets rust-analyzer's ordinary Cargo workspace
loader drive Lorry the way it drives Cargo on Linux. It analyzes only
`x86_64-unknown-motor`. The server speaks the ordinary rust-analyzer stdio LSP
protocol; Stage 2 adds no proxy, socket protocol, or Motor-specific LSP
messages.

Stage 2 has three deliverables:

1. an assembly-keyed native `rust-analyzer` plus the matching `rust-src`;
2. three Cargo-compatible Lorry commands: `lorry metadata`, `lorry check`
   with `--message-format=json`, and `lorry tree`. The first two answer
   rust-analyzer's Cargo workspace-loader and flycheck invocations; Lorry also
   answers the exact `locate-project` and read-only `cargo rustc --print`
   probes needed by that loader. `tree` is the developer's view of the same
   graph and is a required deliverable even though rust-analyzer does not run
   it. U. Lasiotus requested this scope on 2026-09-02. It replaces the earlier
   design of a Lorry-generated `rust-project.json`; and
3. repository tests that drive the native server over stdio through SSH and
   prove project load, build-script results, diagnostics, and semantic
   results in the developer image (dev.img) in an 8 GiB VM.

This stage contains no consumer. It does not port or configure Helix, Red,
Gears, an agent harness, or an editor extension, and it does not design client
restart policy, buffer synchronization, UI behavior, or project refresh UX. A
future consumer launches this server with the configuration in section 4.6.

The design rests on one **execution rule**, referenced by that name below: on
Motor, rust-analyzer requests the same Cargo operations it requests on Linux,
with Lorry answering in place of Cargo. Lorry applies its normal admission,
cache, limits, and offline rules. Its Linux build-script sandbox remains in
force on Linux; Motor's documented warning mode remains unsandboxed and must
not be described as isolation. Rust-analyzer never executes dependency code
inside its own process. An admitted `lorry check` may start build scripts and
may cause rustc to start a Motor proc-macro helper with the same authority as
an interactive `lorry build`. Section 4.7 enumerates the direct invocations
and their permitted descendants.

These boundaries were reviewed and confirmed in section 4.14; do not reopen
them without a new design review recorded there:

- use mlibc process startup to execute `.init_array`; do not change
  `motor_start` or the Rust standard library;
- carry the rust-analyzer changes in the selected Motor Rust fork and use
  pinned crates.io releases of `url` and `inventory`, patched locally;
- change no rust-analyzer defaults in the fork; a client sends the
  configuration and the `CARGO` environment variable in section 4.6;
- expose no implicit native user-configuration directory;
- load the sysroot by stitching `rust-src` directly, without `cargo metadata`;
- implement the Cargo-compatible subset of `metadata`, `check`, and `tree` in
  Lorry rather than port Cargo; Lorry keeps its own identity, layout, policy,
  and CLI conventions and adds only the argument forms listed in section 4.7;
- make `lorry vendor` preserve every input project/workspace manifest
  byte-for-byte, including when it materializes a Git patch; and
- publish no proc-macro server or proc-macro dynamic library.

### 4.2 Implementation baseline

Always derive versions from the effective Motor Rust tree selected by
`src/toolchain-versions.sh`; do not copy a revision or dependency-version
snapshot into this plan. At the start of implementation, record the selected
Rust revision and the SHA-256 of `src/tools/rust-analyzer/Cargo.lock` in the
toolchain inputs and assembly manifest.

The selected tree was checked on 2026-09-02. It has four compile-time native
gaps and one sysroot runtime behavior to address; each is specified with its
proof in section 4.4:

- `dirs` is used at one site, for the implicit user configuration directory;
- `stdx::process::read2`, which streams the output of every Cargo invocation,
  has only Unix, Windows, and wasm32 implementations;
- `url` has no Motor file-path conversion;
- `inventory` emits no Motor constructor entries; and
- for the sysroot, rust-analyzer runs `cargo metadata` on the
  `library/Cargo.toml` inside `rust-src`, logs an error when that fails, and
  only then stitches the sysroot.

The same tree fixes the JSON contracts Lorry must satisfy: rust-analyzer
locks `cargo_metadata` 0.23.1, whose `Metadata` type defines the
`cargo metadata --format-version 1` document and whose `Message` type defines
the `--message-format=json` stream. Rust-analyzer resolves the Cargo
executable from `$CARGO_HOME/bin/cargo`, then the `CARGO` environment
variable, then `PATH`, so an environment variable selects Lorry without any
cargo-named file in the image.

The pinned loader also runs `cargo locate-project --workspace` before
metadata and first attempts two `cargo rustc --print` queries for cfgs and
target data. Those calls are part of the supported Lorry boundary in section
4.7. They must not fail and rely on rust-analyzer's direct-rustc fallback: the
fallback logs warnings, starts additional processes, and would contradict the
native process contract.

Earlier feasibility work proved that a native static PIE completes the stdio
LSP lifecycle once the compile-time gaps are addressed and `.init_array` is
executed. Production acceptance still depends on the exact source pins, the
Lorry commands, the semantic tests, and the resource measurements below.

### 4.3 Source, dependency, and identity model

The native binary uses `$RUST/src/tools/rust-analyzer` from the exact
effective Motor Rust revision selected by `src/toolchain-versions.sh`. Unlike
the Stage 1 bootstrap tool, it is built without `in-rust-tree`. The native
closure therefore uses the standalone workspace lock and `ra-ap-rustc_*`
crates rather than dynamically linking the bootstrap compiler's
`librustc_driver`.

Source changes are maintained as follows:

- the rust-analyzer target conditionals, the sysroot-loading change, and the
  Motor child-pipe implementation live in the Motor Rust fork beside the
  in-tree rust-analyzer source;
- `url` and `inventory` use exact crates.io versions and archive SHA-256
  checksums recorded with checked-in Motor OS patch files. Provisioning
  unpacks and patches those releases below `$MOTORH/patched-crates/`, beside
  the toolchains and ripgrep directories (normally `../`). These are local
  source copies of published crates, not Git clones or new GitHub forks;
- `dirs` is not forked: rust-analyzer does not compile it for Motor; and
- no source is patched in place under a managed checkout, copied from `/tmp`,
  or fetched by a regular test.

This explicitly requires changes outside the Motor OS repository: the Motor
Rust fork and generated patched `url` and `inventory` source directories under
`../patched-crates/`. The patch files and provisioning recipe live in Motor
OS; no human-created dependency forks are needed. Follow Motor OS's root
`AGENTS.md` for this work, including work in the external sources, as directed
by U. Lasiotus. No Stage 2 change to `src/sys`, Rust std,
`moto-rt`, or mlibc is planned; finding that one is necessary is a
design-review stop.

Prepare each patched crate from its checksum-verified published archive in a
fresh staging directory. Apply the checked-in patch with exact context and
fail on mismatch; never patch the Cargo registry cache or managed Rust tree.
Publish only a complete verified source tree, keyed by the upstream archive
and patch digest, and verify its contents before reuse. Do not overwrite a
modified source tree. Preserve upstream licenses. Provisioning may download
missing archives; regular tests use local fixtures or already acquired
archives and never download them.

Select the prepared sources using Cargo `[patch.crates-io]` path overrides,
scoped to the standalone rust-analyzer workspace. Update and commit its lock
once during implementation to record the path sources; ordinary builds must
not regenerate the lock. Use the same overrides for Stage 1 host bootstrap
and the native build, preparing the sources before either begins. The path
entries do not authenticate source contents, so the archive, patch, recipe,
and prepared-tree digests are explicit build inputs. Do not use registry
source replacement to represent modified crates as unchanged originals.

The complete provisioning command may acquire the locked registry and Git
sources while it is already in its managed network-enabled source-provisioning
phase. Before the native build, it runs the selected host Cargo's equivalent
of `cargo fetch --locked --target x86_64-unknown-motor` for the standalone
rust-analyzer manifest. The check and build themselves use `--locked
--offline`. Authoring mode uses the supplied Rust tree and the same lock
contract; neither mode may rewrite the lock.

Identity changes are fail-closed:

- add the standalone rust-analyzer `Cargo.lock` digest to the declared source
  tuple, generated toolchain state, and toolchain-key fields by extending the
  existing before/after-bootstrap check that already covers the root and
  library locks; the Stage 1 `in-rust-tree` build also consumes this
  workspace and must not rewrite its lock;
- let the assembly key inherit that lock through the toolchain key, and add a
  native rust-analyzer recipe version to the assembly native-configuration
  schema;
- add every new Motor OS helper used by that recipe to
  `MOTOR_OS_RUNTIME_INPUTS` rather than leaving unkeyed executable logic;
- let the effective Motor Rust revision identify the in-tree source and exact
  workspace declarations, including dirty authoring state through the existing
  source digest; include the patched-crate pins, patch contents, preparation
  logic, and prepared-tree digests in the toolchain key (not just the native
  assembly key), because the host server uses them too; and
- record the final version string, binary SHA-256, standalone lock SHA-256,
  rust-src tree digest, patched-crate versions and archive/patch/tree digests,
  and native recipe version in
  `MOTOR-ASSEMBLY-MANIFEST` and each assembly image manifest.

An existing assembly is reusable only when those fields and the staged files
all validate. A missing or changed binary, rust-src tree, manifest field, or
active/rejected producer marker rejects reuse.

### 4.4 Native portability patches

Keep the native patch set small and target-specific. Revalidate each item
against the newly selected Rust revision before editing because rust-analyzer
and its dependency lock move together.

| Area | Native implementation | Required proof |
|---|---|---|
| Configuration | Compile `dirs` only for non-Motor targets and make `Config::user_config_dir_path()` return `None` on Motor. Change no other default. | The Motor dependency graph has no `dirs-sys` edge; initialization with no HOME/XDG variables succeeds and reads no implicit config file. |
| Sysroot loading | On Motor, `Sysroot::load_workspace` does not attempt `cargo metadata` on the sysroot library manifest and stitches `rust-src` directly. The stitched sysroot lists the standard crates without std's private dependency crates, which is sufficient for userspace analysis. Project metadata still goes through `$CARGO`. | Server stderr contains no sysroot `cargo metadata` error; go-to-definition into `std::os::motor` resolves; the Linux behavior is unchanged. |
| Child stdout/stderr | Add a Motor `read2` using two standard reader threads and a bounded chunk channel; the coordinator alone invokes callbacks and propagates the first read or join failure. Compile it as the implementation for targets with no Unix, Windows, or wasm32 branch and compile the module on every target so Linux tests cover it. Every `lorry metadata` and `lorry check` invocation on Motor streams through this path, so it is production code, not a stub. | A Linux unit test of the portable module covers interleaved output, either pipe closing first, and output above pipe capacity on each pipe. The guest acceptance test streams JSON on stdout and progress on stderr concurrently. |
| File URIs | Patch the pinned `url` release to add Motor to its slash-rooted file-path implementation without making `cfg(unix)` true. Preserve the crate's existing authority, absoluteness, percent-encoding, and UTF-8 rules. | Unit tests round-trip root, spaces, `%`, `#`, and non-ASCII names and exercise the crate's existing negative cases; the guest semantic test opens a non-ASCII path. |
| Salsa registration | Patch the pinned `inventory` release to emit Motor constructor pointers in `.init_array`. Link rust-analyzer through the assembly wrapper so mlibc startup walks the array. Do not add constructor walking to Rust startup. | A small native inventory fixture observes more than one registration; ELF validation requires nonempty `.init_array`; the LSP database reaches quiescence. |
| Allocator and workers | Leave optional jemalloc/mimalloc features off. Verify `num_cpus` against Motor's standard-library result and use an explicit native default worker count only if the 8 GiB measurements require it. | Record available CPUs, rust-analyzer threads, and peak memory; a worker cap needs its own measured justification. |
| Filesystem changes | Keep the upstream client-watcher mode, which is already the default. Do not add a polling watcher or port a host notify backend. | Project load performs no periodic filesystem scan or watcher child process; standard `didOpen`/`didChange`/`didSave` drive the semantic test. |

The pipe channel bounds queued chunks, not total command output. Existing
rust-analyzer callers still own their final output buffers.

### 4.5 Native build and development-image layout

Build after the final host compiler, Motor std, assembly sysroot, and
`motor-clang` wrapper have validated. Use the installed keyed Linux-host
Cargo and rustc to cross-compile; do not try to run the Motor-host rustc on
Linux and do not invoke `x.py` again.

The recipe is equivalent to:

```sh
RUSTC="$TOOLCHAIN_PREFIX/bin/rustc" \
CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/rust-analyzer" \
CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$ASSEMBLY_SYSROOT/bin/motor-clang" \
CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS="-C link-self-contained=no -C default-linker-libraries=yes" \
CFG_RELEASE="$RUST_ANALYZER_RELEASE" \
CFG_RELEASE_CHANNEL="$MOTOR_RUST_CHANNEL" \
  "$TOOLCHAIN_PREFIX/bin/cargo" build --release --locked --offline \
  --manifest-path "$RUST/src/tools/rust-analyzer/Cargo.toml" \
  --target x86_64-unknown-motor -p rust-analyzer
```

Derive `RUST_ANALYZER_RELEASE` from the same selected Rust version/channel
logic used by bootstrap and require it to equal the release portion reported
by the validated Stage 1 server. Do not obtain it from an ambient Cargo or
rust-analyzer. Use both codegen flags for this driver-managed libc link.
mlibc's strong `motor_start` replaces Rust std's weak entry and walks
`.init_array` before calling main. The native inventory fixture must prove
that registration actually runs; a nonempty ELF section alone is not enough.

Use the same `motor-clang`/default-library combination as native Lorry.
The bootstrap-specific `motor-rust-cc` wrapper explicitly adds `crt1.o` and
runtime libraries; using it with default libraries enabled duplicates the
startup object. The inventory cross-link reproduced that recipe error and
passed with `motor-clang`; no wrapper or runtime modification is required.

The implementation must use argument arrays/environment assignments already
available to the build shell; it must not synthesize a Cargo config in the
source tree. Cargo output stays under the assembly build root. Strip a copy
with the assembly's LLVM tool, preserving its non-allocated `.comment`
section for compiler identity (`--keep-section=.comment`), and stage only
the copy.

The producer atomically publishes:

```text
$MOTORH/assemblies/<assembly-key>/images/rust-analyzer/
  devtools/rust/bin/rust-analyzer
  devtools/rust/lib/rustlib/src/rust/library/...
  devtools/toolchain/manifest
```

Copy `rust-src` from the validated installed prefix's
`lib/rustlib/src/rust/library`, not from an ambient rustup toolchain and not
from a second checkout. Clear executable bits on the staged source files:
they are analysis inputs, including host-only CI scripts, not guest tools.
Preserve their contents and leave the installed prefix unchanged. The guest
paths are consequently fixed:

```text
server:      /devtools/rust/bin/rust-analyzer
rustc:       /devtools/bin/rustc, discovered on PATH; sysroot /devtools/rust
lorry:       /devtools/bin/lorry, selected through CARGO
sysroot-src: /devtools/rust/lib/rustlib/src/rust/library
```

Mechanical validation rejects a server that:

- is not the expected x86-64 Motor static PIE;
- has a dynamic `NEEDED` entry or interpreter;
- has an executable stack, undefined dynamic symbol, or text relocation;
- lacks a nonempty `.init_array`;
- does not contain the effective Rust revision and selected release
  description.

The assembly producer cannot execute a Motor binary on Linux. Native
`--version`, constructor execution, and the inventory fixture are therefore
guest release gates, not host-side assembly-reuse checks.

Add `rust-analyzer` to `assembly_dirs` and its binary to
`assembly_required_executables` only in `src/imager/motor-os-dev.yaml`. The
base and standard image configurations must reject `/devtools` as before and
must not contain the server or rust-src. No file named `cargo` is added to
any image. Nothing launches rust-analyzer during image construction or boot.

### 4.6 Runtime and LSP contract

The supported server command is exactly the native binary in stdio mode. It
uses LSP/JSON-RPC framing on stdin/stdout and diagnostics/logging on stderr.
There is no daemon, TCP listener, shell wrapper, Lorry proxy, or custom
framing. Standard initialize, initialized, text-document, progress,
configuration, shutdown, and exit messages remain rust-analyzer's upstream
protocol.

The server process environment carries `CARGO=/devtools/bin/lorry`, a `PATH`
that contains `/devtools/bin`, and `TMPDIR`. Rust-analyzer reads `CARGO` from
its own environment when it locates the Cargo executable, before it searches
`PATH`; the `cargo.extraEnv` setting reaches child processes only and cannot
select the executable. A client that omits the variable gets upstream
behavior: rust-analyzer looks for `cargo` on `PATH`, finds none, and reports
the failed metadata query visibly.

A terminal editor spawning the server as a background helper must also set
`MOTURUS_STDIO_NO_TERMINAL=true` in that spawn's environment. Motor consumes
this launch instruction before server startup; it prevents the synthesized
terminal-input relay from taking the editor's keyboard stream. The non-PTY
SSH acceptance transport has no session terminal to inherit. See
`docs/tui.md` (Foreground forwarding) and the
[native Helix integration record](helix-rust-analyzer.md).

Every supported client, including the acceptance harness, sends this
configuration explicitly. It is the Stage 1 Motor configuration with two
differences:

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

`cargo.buildScripts.useRustcWrapper` is off because Lorry rejects
`RUSTC_WRAPPER` and the wrapper only shortens a Cargo build that Lorry's unit
cache already shortens. `procMacro.enable` is off for the reason in section
4.9. `cargo.targetDir = true` keeps editor checks in `target/rust-analyzer`,
away from `target/lorry`; Lorry's global unit cache makes that second
artifact tree cheap. `check.workspace` keeps its default of true. Saving a
binary or integration test still emits `-p <package-id>` with a named target;
the Helix integration extends Lorry to accept the exact selected manifest's
metadata ID and `--bin NAME`/`--test NAME` (see
[Lorry's integration record](../../src/bin/lorry/helix-integration.md)).
The Motor fork changes no defaults. The acceptance client
advertises the experimental `colorDiagnosticOutput` capability, which selects
the ANSI flycheck form; clients without it use the supported plain-JSON form.

Sysroot discovery runs `rustc --print sysroot` through `PATH` and yields
`/devtools/rust`; the fork then stitches `rust-src` without Cargo. Project
loading runs `$CARGO metadata`, build-script collection and flycheck run
`$CARGO check --message-format=json`, and cfg and target data come from
`/devtools/bin/rustc` through Lorry's exact read-only query handlers. Under the
execution rule, section 4.7 is the complete list of Cargo-shaped processes
rust-analyzer starts. Direct sysroot discovery may start rustc; Lorry may
start rustc, admitted build scripts, approved native tools, and admitted
proc-macro helpers as documented descendants.

A consumer may later send standard configuration changes, file notifications,
and multiple linked projects. How it presents server failures or bounds its
own queues is outside Stage 2. Project refresh mirrors Linux: rust-analyzer
re-runs `metadata` when the client reports a changed `Cargo.toml` or
`Cargo.lock`, and it re-runs `check` on save and after build-script inputs
change.

### 4.7 Lorry Cargo-compatible boundary

Lorry already owns package selection, target evaluation, default features,
dependency resolution, admission evidence, source remapping, build-script
execution, the rustc environment, and rustc's JSON diagnostics, which it
already requests with `--error-format=json`. The three commands use those
structures directly and must not reinterpret Cargo.toml, Cargo.lock,
`.cargo` configuration, target cfg expressions, or dependency aliases. They
remain ordinary Lorry commands with Lorry's global options and package
selection; the only Cargo-form additions are the argument forms below.

**Project-manifest immutability prerequisite.** The current Git-patch path is
not acceptable for this work. `lorry vendor` calls
`materialize_manifest_patches`, which materializes a root
`[patch.crates-io]` Git source, rewrites that entry to a local path, commits a
replacement root `Cargo.toml`, and rewrites matching `Cargo.lock` nodes as
path packages before the rest of vendoring completes. This means a later
failure can leave both user-authored dependency intent and lock identity
changed.

Before adding the commands below, change that model as follows:

- represent root crates.io patches in the ordinary Lorry manifest model as a
  source enum with path and Git variants; remove the separate parse-and-rewrite
  path in `git.rs`;
- resolve a Git selector to one exact commit during `vendor`, construct the
  same canonical `git+<url>[?<selector>]#<commit>` source identity Cargo uses,
  and publish the verified tree through the existing content-addressed direct
  Git object layout below `.lorry/vendor/git/<source-sha256>/`;
- return an in-memory verified patch catalog from materialization. Mark its
  Git candidates as crates.io replacements independently of their source kind,
  so a Git patch satisfies a crates.io dependency while remaining a Git
  package for policy, admission, metadata, and lockfile identity;
- render the final Cargo.lock with that Git source and no registry checksum,
  and commit it only through the existing final vendor transaction. Do not
  perform an early lockfile rewrite;
- make offline `build`, `run`, `test`, `review`, `metadata`, `check`, and
  `tree` load and verify the content-addressed object against the persistent
  Git declaration and locked commit without network access;
- on every networked `lorry vendor`, check each Git patch's declared remote
  selector. The default branch, an explicit branch, a tag, and a `rev` that
  names a remote reference such as `refs/pull/493/head` are mutable selectors.
  A `rev` that is a full or abbreviated commit object ID is pinned: like an
  ordinary `cargo update` of that declaration, vendoring resolves the same
  immutable commit and never offers a successor merely because the repository
  has newer commits. Selecting a different exact commit requires changing the
  manifest declaration; Lorry adds no analogue of `cargo update --precise`.
  The selected Cargo permits `cargo update <pkg> --precise <other-commit>` to
  override only the lock without changing the manifest, but a later ordinary
  update returns to the manifest-declared commit, so that exception is not
  Lorry's refresh model;
- compare every mutable selector's remote commit with its locked commit,
  treating a patch with no locked/materialized object as pending work. If no
  selector moved, every declaration is unchanged, and every locked object is
  present and verified, reuse the published objects without prompting. If one
  or more patches require first materialization or a commit change, first
  materialize and verify the complete candidate and render one combined review
  containing every affected patch's alias and package, canonical URL and
  selector, old commit if any, new full commit ID, source tree identity,
  dependency-graph changes, and admission/capability changes. A moved tag must
  be labeled prominently as a retargeted tag. Do not classify branch or named
  `rev` movement as fast-forward or rewritten: Lorry retains source trees, not
  Git history, and that classification would require potentially unbounded
  history acquisition;
- compare the complete vendor candidate with the committed state, not just
  the Git-patch subset. When stdin is an interactive terminal, ask exactly
  once for any changed candidate, defaulting to no. Without an interactive
  terminal, an unchanged run succeeds and any dependency or capability
  change fails unless the existing `--accept-all` flag is present.
  `--accept-all` approves the complete displayed candidate, including changes
  unrelated to Git patches and candidates in which no Git selector moved,
  and new build-script, proc-macro, and native-tool capability grants that
  policy allows. U. Lasiotus confirmed on 2026-09-02 that `--accept-all` means
  accept every displayed change; patch 5 rewrites the spec sentences that
  currently say it cannot approve a change or grant a capability. It
  bypasses the interactive review only: explicit policy denies, system
  constraints, source-integrity checks, and resource limits remain enforced.
  A declined or policy-rejected candidate publishes no Cargo.lock, admission,
  or referenced vendor-state change;
- after approval, publish or reuse each newly keyed immutable object and
  update Cargo.lock and admission state only through the final vendor
  transaction. A failure before final publication may leave an unreferenced
  complete immutable object, but never a changed manifest, an early
  path-converted lock, or a successful admission record. Final lock and state
  publication retains Lorry's existing transaction semantics; and
- retain explicit path patches, including old manifests already rewritten by
  an earlier Lorry, as ordinary path patches. Do not attempt to infer or
  restore their lost Git declaration.
- delete the required-patch feature: the `required-patches` configuration
  table, the manifest matcher and resolver guard that required a
  `.lorry/vendor/<id>/source` path patch, the seeded-Git repository object
  type and its `objects/seeded-git` directories, and their documentation. Its
  matcher assumed the rewritten path layout, no configuration in this tree
  uses it, no command produces its objects, and admission policy rules already
  deny a package by name, version, and source. U. Lasiotus authorized the
  deletion on 2026-09-02.

Every project/workspace input `Cargo.toml` must remain byte-identical after a
successful, declined, failed, or killed `lorry vendor`. Do not generate a
shadow project manifest as an implementation shortcut. Dependency source
trees naturally retain their own upstream manifests below the immutable object
root; the invariant applies to the user's input manifests.

**Invocation contract.** The argument vectors were copied from the pinned
rust-analyzer source on 2026-09-02 and are re-checked whenever the Rust
revision changes. Bracketed items are conditional on configuration.

| Invocation | Issued by rust-analyzer as | Lorry behavior |
|---|---|---|
| Workspace query | `$CARGO locate-project --workspace --manifest-path <abs>`, cwd the manifest directory | Validates the selected package and prints `{"root":"<abs selected manifest>"}`. Unlike Cargo, it deliberately preserves a selected member manifest rather than returning a virtual workspace root, because subsequent Lorry commands remain single-package operations. |
| Version query | `$CARGO --version`, expecting `cargo <semver>` | Prints `lorry <version>` as today. Rust-analyzer logs a warning that it could not parse a Cargo version and continues. The resulting unknown toolchain version deliberately selects rust-analyzer's compatibility argument forms: no `--compile-time-deps`, lockfile-path option, or JSON-target-spec flag. Do not print a Cargo version string. |
| Config probe | `$CARGO -Z unstable-options config get --format toml --show-origin` | Fails with the ordinary unknown-option error and nonzero status. Rust-analyzer treats a failed probe as "no Cargo config". |
| Cfg query | `$CARGO rustc -Z unstable-options --print cfg --target <triple> -- -O`, cwd the selected package, env sets `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly` | Supports only this read-only form. Lorry selects its configured rustc, invokes `rustc --print cfg -O --target <triple>` with the effective Cargo-compatible target rustflags, removes the Cargo-internal channel override from the rustc environment, and copies stdout and status without resolving or compiling the package. |
| Target-data query | `$CARGO rustc -Z unstable-options --print target-spec-json --target <triple> -- -Z unstable-options`, cwd the selected package, env sets `RUSTC_BOOTSTRAP=1` | Supports only this read-only form. Lorry invokes the configured rustc with the equivalent rustc arguments and effective Cargo-compatible target rustflags, sets `RUSTC_BOOTSTRAP=1` for that invocation only, and copies stdout and status without resolving or compiling the package. |
| Metadata | `$CARGO metadata --format-version 1 [--no-deps] --manifest-path <abs> [--filter-platform <triple>] [--locked]`, cwd the manifest directory, env may carry `RUSTUP_TOOLCHAIN` | Supported. Rejects `--features`, `--all-features`, `--no-default-features`, `--config`, `-Z`, and `--lockfile-path` with the ordinary error. A virtual workspace manifest, including the sysroot's `library/Cargo.toml` that an unpatched Linux server asks about, is rejected immediately with the ordinary error. |
| Build-script pass | `$CARGO check --quiet --workspace --message-format=json --manifest-path <abs> [--target-dir <abs>] --target <triple> --keep-going [--all-targets]`, cwd the workspace root | Supported. |
| Flycheck | `$CARGO check [--workspace \| -p <package-id>] --message-format=json-diagnostic-rendered-ansi --manifest-path <abs> --keep-going --target <triple> [--all-targets \| --lib --bins --examples] [--bin NAME \| --test NAME] [--target-dir <abs>]`, cwd the workspace root, env carries `CARGO_LOG` | Supported. Package IDs must exactly match metadata for the explicit manifest. Rejects `--example`, `--bench`, feature flags, `--lockfile-path`, and `-Z`. |
| `tree` | Not issued by rust-analyzer | `lorry tree [-p NAME] [--target TRIPLE] [--manifest-path <abs>]`. |

The accepted product-command options are deliberately finite. `metadata`,
`check`, and `tree` retain Lorry's existing global options and `-p NAME`
selection; the table lists only the Cargo-form options added by this stage:

| Command | Accepted Cargo-form options added by this stage |
|---|---|
| `metadata` | `--format-version 1`, `--no-deps`, `--manifest-path`, `--filter-platform`, and `--locked` |
| `check` | `--manifest-path`, `--target-dir`, `--target`, `--workspace`, `--quiet`/`-q`, `--keep-going`, `--all-targets` or the documented root-target selectors, and the two documented `--message-format` values |
| `tree` | `--manifest-path` and `--target` |
| `clean` | `--target-dir` |

Rules shared where the corresponding option is accepted:

- `--manifest-path` must name the selected package's own `Cargo.toml`. A
  virtual workspace root manifest is rejected with the existing guidance to
  run from the root with `-p`. This is the only Cargo-form selection Lorry
  adds; it still performs no general parent discovery. Lorry's existing
  `-p NAME` may accompany it only when both select the same package; otherwise
  selection fails before resolution or source access. Cargo package-ID syntax
  is not accepted as a Lorry package name.
- For `check` and `clean`, `--target-dir D` replaces the `target` directory,
  so artifacts live at `D/lorry[/packages/<name>]/...`. `metadata` and `tree`
  do not accept the option.
- On `check`, `--workspace` means the selected package, `--examples` is an
  accepted no-op because Lorry has no examples, and `--quiet` is `-q`.
  `--keep-going` continues checking the remaining root targets after one
  fails; a failed dependency unit still stops the command. On `metadata`,
  `--locked` is an accepted no-op because Lorry is always locked.
- Rust-analyzer can set `RUSTUP_TOOLCHAIN` to the discovered sysroot root on
  Cargo invocations and `CARGO_LOG` on flycheck. An explicit direct `RUSTC` or
  configured rustc wins normally and is unaffected by `RUSTUP_TOOLCHAIN`. If
  Linux Lorry instead falls back to a rustup-proxy `rustc`, preserve
  `RUSTUP_TOOLCHAIN` only while resolving that proxy with `rustup which rustc`,
  matching Cargo/rustup behavior. After obtaining the direct compiler path,
  do not forward `RUSTUP_TOOLCHAIN` or `CARGO_LOG` to rustc, build scripts,
  native tools, or proc macros. Native Lorry has no rustup fallback and invokes
  its configured rustc directly. Lorry's existing rejection of
  `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, and `CARGO_TARGET_DIR` is
  unchanged.
- Unknown options fail as today. Every command is offline, writes only its
  own outputs, invokes no Cargo or shell, contacts no network, and alters no
  input manifest, lockfile, admission record, or vendor object. The check
  command may atomically publish its own check profile and reusable completed
  unit-cache entries; it never alters an ordinary build profile.

All Lorry compilation paths and both read-only rustc queries use one effective
rustflags resolver matching the selected Cargo. The four sources are mutually
exclusive and the first applicable source wins: `CARGO_ENCODED_RUSTFLAGS`,
then `RUSTFLAGS`, then the nonempty concatenation of the exact
`target.<triple>.rustflags` entry and every matching
`target.'cfg(...)'.rustflags` entry, then `build.rustflags` (including its
`CARGO_BUILD_RUSTFLAGS` environment override). An explicitly present empty
encoded or plain environment value selects no flags; an empty target
concatenation falls through to the build value, as Cargo does. In particular,
nonempty target flags replace rather than append to `build.rustflags`.
Within a configuration source, Cargo environment contributions append to the
file values: `CARGO_BUILD_RUSTFLAGS` extends `build.rustflags`, and an exact
`CARGO_TARGET_<TRIPLE>_RUSTFLAGS` value extends that exact target entry before
the sorted matching cfg entries. This configuration layering does not change
the mutually exclusive precedence above.
Decode `CARGO_ENCODED_RUSTFLAGS` by U+001F separators. Parse plain `RUSTFLAGS`
exactly as the selected Cargo does: split on literal ASCII spaces, trim and
discard empty pieces, and do not apply shell quoting or escape processing.

The compilation plan applies the selected flags to the same units Cargo does.
With an explicit target, target units receive them while host build scripts
and proc macros do not; without a separate target, all rustc invocations
receive them. Lorry does not add Cargo's unstable host-rustflags configuration.
The target-data and cfg-query tests snapshot both rustc argv and environment,
including the query-specific variable handling above.

**`lorry metadata`.** Prints one `cargo metadata --format-version 1`
document for the selected package and target on stdout, terminated by one
newline, with progress on stderr. Section 4.8 defines every field. Two runs
over unchanged inputs produce byte-identical output. With `--no-deps` it
describes the selected package only, sets `resolve` to null, and publishes no
sources. Without `--no-deps` it resolves the graph exactly as `lorry build`
would and publishes the sources that the document references.

Rust-analyzer reads `manifest_path` and `targets[].src_path` after the
command exits, so registry and Git package sources need stable paths, as
Cargo's `~/.cargo/registry/src` provides on Linux. Lorry extracts each
verified package once into a content-addressed, immutable directory below
the global cache root:

```text
<global-cache>/sources/<name>-<version>-<source-tree-sha256>/
```

Use Lorry's complete lowercase SHA-256 of the verified extracted source tree,
not a registry archive checksum, Git commit, or truncated prefix, so distinct
source trees cannot collide by path. Publication is atomic and re-verified
against that source-tree digest before reuse; `lorry cache clean` removes the
tree.
Selected workspace packages and path dependencies are described at their
admitted live roots so edits remain visible. Filesystem locations consumed as
paths are canonical absolute UTF-8 paths; non-UTF-8 or escaping paths are
rejected. Cargo reports the descriptive `license_file` and `readme` values in
their manifest-relative spelling, so those two manifest strings are
deliberately not absolutized.

**`lorry check`.** Prepares the graph and executes the development
dependency plan exactly as a non-release `lorry build` does, with the same
cache, sandbox, limits, and admission, then compiles each selected root
target with `--emit=dep-info,metadata` instead of linking it. `--all-targets`
checks the library, the binaries, and the integration tests, and the library
and binaries again in test mode, as Cargo's `--all-targets` does. Without a
message format, diagnostics are rendered as `lorry build` renders them.
Exit status is nonzero when any unit fails, after `--keep-going` has been
honored.

Named `--bin NAME` and `--test NAME` selectors check that target plus its
library dependencies. Combining them with `--all-targets` still checks all
supported targets. Unknown names and mismatched Cargo package IDs fail before
compiler discovery; a package ID requires an explicit `--manifest-path`.

With `--message-format=json` or `--message-format=json-diagnostic-rendered-ansi`,
stdout carries one JSON object per line in `cargo_metadata::Message` form and
nothing else; progress stays on stderr and `--quiet` silences it:

| Message | Content |
|---|---|
| `compiler-artifact` | One per restored or compiled unit, with every field required by `cargo_metadata::Artifact`: `package_id`, `manifest_path`, `target`, `profile`, `features`, `filenames`, `executable`, and `fresh`. Target/profile/features come from the compilation plan; filenames are real artifact paths; `fresh` is true for a restored unit. A Motor proc-macro unit reports its static helper path, which rust-analyzer does not treat as a dynamic library. |
| `build-script-executed` | One per build-script result consumed by the plan, whether newly executed or restored, with `package_id`, `cfgs`, `env`, `out_dir`, `linked_libs`, and `linked_paths`. `out_dir` must be a path in the published check profile that outlives the command. |
| `compiler-message` | One per rustc diagnostic, with `package_id`, `target`, and rustc's JSON diagnostic object unchanged. Lorry passes `--json=diagnostic-rendered-ansi` to rustc only for the ANSI format, so `rendered` is plain text otherwise. |
| `build-finished` | Last line, `success` reflecting the exit status. |

Package ids and target descriptors in the stream are the same strings that
`lorry metadata` emits. A `lorry check` that rust-analyzer cancels by killing
the child publishes no successful root/check profile. Fully completed atomic
unit-cache entries may remain reusable; incomplete unit or profile staging is
discarded by the next run. Editor checks in `target/rust-analyzer` and shell
builds in `target/lorry` never share staging; shared global cache entries are
already published atomically. Lorry's unit cache key currently digests the
whole process environment, and rust-analyzer's environment differs from an
interactive shell's, so cache sharing between editor checks and shell builds
is not guaranteed. That is an existing Lorry property, recorded here and left
out of scope.

**`lorry tree`.** Prints the resolved dependency tree for the selected
package and target on stdout in `cargo tree` form: `name vX.Y.Z (path)`
lines under `├──`, `└──`, and `│` connectors, `(proc-macro)` after
proc-macro packages, a `[build-dependencies]` group for host-context edges,
and `(*)` for a subtree already printed. Output is deterministic and has no
color or other decoration.

### 4.8 Exact metadata mapping

Generate the document from Lorry's manifests, selected `Resolution`, and
development `CompilationPlan`, not from artifact filenames. The schema is
`cargo_metadata` 0.23.1 as locked by the pinned rust-analyzer; the mapping
is:

| `cargo metadata` field | Lorry source of truth |
|---|---|
| `version` | `1`. |
| `workspace_root` | The Lorry workspace root; the package root for a standalone package. |
| `workspace_members`, `workspace_default_members`, `resolve.root` | The selected package id only. Lorry describes one selected package per invocation, as every Lorry command does. |
| `target_directory`, `build_directory` | Both are `<workspace_root>/target`, matching the keyed Cargo for Lorry's supported profiles. Rust-analyzer appends `rust-analyzer` to `target_directory` for `--target-dir`. |
| `packages[]` | The selected package and every resolved package from both feature contexts; only the selected package with `--no-deps`. Emit each package's exact name, version, and edition from its prepared manifest. |
| `id` in `packages` and `resolve` | Cargo's package-id specification form: `path+file://<root>#<name>@<version>`, `registry+https://github.com/rust-lang/crates.io-index#<name>@<version>`, or `git+<url>[?<selector>]#<name>@<version>`. For any URL-shaped path or Git ID, Cargo omits the name when it exactly equals the URL's final path segment: `path+file://<root>#<version>` and, for a same-named Git repository, `git+<url>[?<selector>]#<version>`. Do not limit this omission to path packages; conversely, a URL ending in `<name>.git` does not equal `<name>`. The Git selector is Cargo's canonical `branch`, `tag`, or `rev` query when one was declared. The same strings appear in every `check` message. |
| `source` | Null for path packages; `registry+https://github.com/rust-lang/crates.io-index`; or `git+<url>[?<selector>]#<commit>`, using the same canonical Git source identity as Cargo.lock. |
| `manifest_path`, `targets[].src_path` | The live root for the selected and path packages; the content-addressed source directory for registry and Git packages. |
| `targets[]` | `lib`, `proc-macro`, `bin`, `test`, and `custom-build` targets from the manifests with Cargo-compatible `kind`, `crate_types`, `edition`, and `src_path`; `required_features` is empty because Lorry rejects that feature. Retain the recognized `doctest`, `test`, and `doc` values in Lorry's target model instead of replacing them with generic defaults. |
| `features` | The declared feature table of each prepared manifest. |
| `dependencies[]` | Each declared dependency: `name` as declared, `req`, `kind` null, `dev`, or `build`, `optional`, `uses_default_features`, `features`, `target` cfg expression or null, `rename`, `path` for path dependencies, and `source`; `registry` null. |
| `resolve.nodes[]` | One node per resolved package id. `deps[].name` is the rustc-visible crate name after renaming and dash-to-underscore normalization; `deps[].pkg` the dependency id; `dep_kinds[]` the `{kind, target}` pairs from Lorry's edges; `dependencies[]` the dependency ids; `features` the activated set. Lorry keeps host and target feature contexts separate while this schema has one node per id; emit the union, which is what `cargo metadata` reports for resolver 2 packages. |
| `metadata` on the workspace and on packages | Null. |
| Descriptive package fields | Preserve `authors`, `description`, `license`, `license_file`, `readme`, `repository`, `homepage`, `documentation`, `rust_version`, `links`, and `default_run` from Lorry's prepared manifest. Preserve Cargo's manifest-relative spelling for `license_file` and `readme`; they are descriptive manifest values, not source locations consumed by rust-analyzer. |
| Recognized but unretained fields | `categories` and `keywords` are empty and `publish` is null. These fields do not affect rust-analyzer or Lorry's build model; retaining them later is a compatible fidelity improvement. |

Serialize with Lorry's existing `serde` and `serde_json` dependencies and
dedicated private output structs; this adds no product dependency. Use manual
`Serialize` implementations so the native product graph does not activate
`serde_derive`. A separate
test crate under `src/bin/lorry/tests/`, with its own lockfile, depends on
exactly `cargo_metadata` 0.23.1 and deserializes every golden document before
inspecting it; Lorry's own manifest and lockfile gain no dependency, so its
review state and native self-build are unaffected. Order packages and resolve
nodes by package id. Package targets and declared dependencies retain the
prepared manifest's deterministic order; node dependencies are ordered by
normalized crate name and package id, dependency ids lexicographically, dependency
kinds as normal/dev/build and then target, and activated features lexicographically.
Build maps from `BTreeMap`. Reject a package count above Lorry's existing limit, an
edge to an unresolved package, an alias that collides after normalization, an
unsupported custom target, or a path or value that cannot be represented
losslessly in JSON.

The goal is as close to keyed Cargo output as Lorry's deliberately smaller
manifest and workspace model permits. The Linux differential test in section
4.11 compares the complete graph, target, feature, build-relevant, and retained
descriptive projections. It may normalize IDs, source roots, artifact roots,
and the explicitly defaulted fields above; it must list every normalized field
in the test and fail on any new difference. Do not claim byte equality with
Cargo for deliberately unretained publication metadata.

### 4.9 Procedural macros, checks, and refresh boundary

Lorry supports Motor-native procedural macros by compiling each proc macro as
a static PIE helper and using a private framed stdio registration protocol
between rustc and that helper. `lorry check` compiles those units when the
dependency plan needs them and reports them as ordinary artifacts.

That helper is not a rust-analyzer proc-macro artifact. Rust-analyzer's pinned
`rust-analyzer-proc-macro-srv` is an `in-rust-tree` compiler-private binary
that loads compiler-produced proc-macro dynamic libraries. The standalone
non-`in-rust-tree` native build cannot provide it. Stage 2 therefore:

- keeps `procMacro.enable` off in the supported configuration;
- packages no `rust-analyzer-proc-macro-srv`; and
- tests that rust-analyzer records no proc-macro dynamic library for a
  proc-macro dependency and directly starts no proc-macro server or helper.

This does not make checks proc-macro-free. When root code uses an admitted
procedural macro, `lorry check` starts rustc and Motor rustc may start Lorry's
static proc-macro helper. That descendant execution follows Lorry's existing
policy and warning-mode rules and is a permitted descendant in the process
evidence described in section 4.11.

Declarative macros continue to work. Code requiring procedural expansion is
visibly incomplete rather than executed through an incompatible protocol. An
adapter or native compiler-private proc-macro server is separate future work,
not a hidden Stage 2 subtask.

Checks on save are supported through the flycheck invocation in section 4.7,
exactly as on Linux. Rust-analyzer owns cancellation and serialization of
its own check runs. Run, test, and debug runnables still exist only as
rust-analyzer's default Cargo command templates; Stage 2 does not test them,
and a future consumer decides whether to expose them.

Project refresh mirrors Linux and needs no Lorry watch mode: rust-analyzer
re-runs `metadata` on manifest and lockfile changes reported by the client
and re-runs the build-script pass when its inputs change. `lorry vendor`
remains an explicit developer action.

### 4.10 Security and resource rules

The native server runs with the invoking user's authority and is not a boot or
privileged service. The supported path is deliberately narrow:

- use absolute executable and project paths and process argument arrays;
- give the test process a minimal explicit environment: `CARGO`, `PATH`,
  `TMPDIR=/devtools/tmp`, and no Cargo network variables;
- keep failures visible and add no automatic restarts, retries, ignored
  errors, or longer timeouts;
- retain the Stage 1 harness's frame, stderr, message, progress, and total
  deadline bounds; and
- add no executable compression or startup decompression.

Motor's documented unsandboxed build-script warning mode applies to
editor-initiated checks as it does to shell builds. Sending the supported
configuration explicitly authorizes those admitted checks, so consumers must
enable it only for a trusted project and reviewed Lorry state. Rust-analyzer
adds no authority beyond the invoking user, but opening or saving a project
can exercise that existing authority without a separate shell invocation.

Record the following in the final gate on a four-vCPU, 8 GiB VM: stripped
binary size, rust-src and total image growth, time to initialize, time to
quiescence including the startup build-script pass, latency of one flycheck
on save, first completion latency, sampled virtual-memory and thread maxima
of the server and observed `lorry check` children, and sampled whole-VM
physical memory use. Record the sampling interval and limitations: observed
maxima are not exact peaks, and virtual memory is not per-process RSS.
Per-process resident accounting and exhaustive execution auditing are
[deferred OS work](future-work.md#recorded-deliberately-not-scheduled),
not prerequisites for this server (section 4.22). The first
maintained measurement establishes explicit future regression thresholds; do
not choose a worker cap or hide a failure merely to meet an unreviewed
number. Memory optimization is not a Stage 2 goal: a result that needs the
full 8 GiB is recorded, not treated as a failure or a reason to stop.

### 4.11 Test design

The tests are layered so a failure is attributable before a full image run.

**Motor Rust and dependency tests**

- Run the exact standalone workspace's relevant host unit tests, then
  `cargo check --release --locked --offline --target
  x86_64-unknown-motor -p rust-analyzer`.
- Test the Motor pipe implementation with a Linux unit test covering
  interleaved output, either pipe closing first, and output above pipe
  capacity on each pipe.
- Test the exact patched URL crate's path conversion helpers and inventory's
  registration list; do not rely only on rust-analyzer startup.
- Assert the standalone lock remains byte-identical and the Motor graph has no
  `dirs-sys` edge or optional allocator feature.

**Lorry focused and product tests**

- Add Git-patch vendor tests that snapshot every input workspace/member
  `Cargo.toml` byte-for-byte and make them read-only. Cover first
  materialization, unchanged reuse without a prompt, a default-branch update,
  an explicit branch update, a moved tag warning, a mutable named-`rev`
  update, and a commit-hash `rev` that remains locked after newer commits are
  added. Move multiple selectors in one run and require one complete prompt,
  not one prompt per patch. Cover yes, default-no, network or resolution
  failure after materialization, and killed vendoring. On non-interactive
  stdin require success for an unchanged graph, failure with no committed
  state change when any dependency or capability change exists, and
  successful application of the complete changed candidate with
  `--accept-all`. Exercise an unrelated dependency and capability change both
  without Git movement and combined with a Git update, and prove that
  `--accept-all` approves each complete displayed candidate, while a separate
  explicit-deny fixture proves it cannot bypass policy. Manifests never
  change; Cargo.lock retains
  Cargo-compatible Git source identities; completed immutable objects may
  remain after failure; and build, review, metadata, check, and tree consume
  them offline. Retain a legacy explicit path-patch fixture.
- Remove the required-patch unit tests and fixtures with the feature, and add
  one test that a `required-patches` table in Lorry configuration is rejected
  as an unknown key.
- Add CLI tests for every argument vector in section 4.7: accepted forms
  succeed, rejected forms fail with the ordinary error, the config probe
  fails cleanly, `locate-project` preserves the selected member manifest, the
  two `rustc` queries invoke only the configured compiler, and `--version`
  prints Lorry's own version. Snapshot query argv and environment: the cfg
  query removes Cargo's channel-override variable, the target-data query alone
  sets `RUSTC_BOOTSTRAP=1`, and neither leaks `RUSTUP_TOOLCHAIN` or `CARGO_LOG`
  to a descendant. Prove that a direct keyed `RUSTC` wins despite an ambient
  `RUSTUP_TOOLCHAIN`, while a fake rustup-proxy fallback receives the variable
  for `rustup which rustc` and removes it after resolving the direct compiler.
- Before the guest test, drive the pinned Stage 1 Linux rust-analyzer through
  the existing LSP harness with `CARGO` selecting the just-built Linux Lorry
  and `RUSTC` selecting the absolute keyed compiler path, against a
  Motor-target fixture. Avoid a rustup proxy in this acceptance test so the
  compiler identity is deterministic; cover proxy fallback separately in a
  focused Lorry test. This is a Stage 2 test that happens to run on Linux, not
  a supported Linux configuration: Linux users keep real Cargo.
  Record the server's actual child argument vectors and require them to equal
  section 4.7. This source-driven integration test, rather than a manually
  copied argv list alone, is the drift detector when the selected Rust
  revision changes. The Linux server carries no Motor sysroot patch, so it
  asks Lorry for `metadata` on the sysroot's `library/Cargo.toml`; Lorry
  rejects that virtual workspace manifest with its ordinary error, and
  rust-analyzer logs a sysroot error and stitches `rust-src`. The selected
  server loads the sysroot once initially and once after applying build-script
  results, so the acceptance test expects exactly those two identical errors
  and nothing else on the sysroot path. The rejection must be immediate, with
  no resolution, network, or vendor access.
- Add a Linux differential fixture with a verified registry dependency, a
  path dependency, a build script that emits `rustc-cfg`, `rustc-env`, and
  generated `OUT_DIR` Rust, a proc-macro dependency, and one deliberate
  warning and one deliberate error. Run the keyed Cargo and Lorry on it with
  `--filter-platform x86_64-unknown-motor` and `--target x86_64-unknown-motor`
  and require: both metadata documents deserialize with `cargo_metadata`
  0.23.1; their section 4.8 projections are equal after only the documented
  normalizations; every check line deserializes as a non-text
  `cargo_metadata::Message`; the streams carry equal build-script cfg, env,
  and `OUT_DIR` contents and equal diagnostic objects apart from `rendered`;
  exit statuses are equal; and `tree` output is identical apart from path
  prefixes. Include path and Git packages whose names both match and differ
  from their source URL's final path segment, and compare their exact package
  IDs rather than normalizing them.
- Unit-test `--no-deps`, `--target-dir` with `clean`, `--keep-going`,
  `--all-targets`, determinism of two consecutive runs, offline operation
  under the existing rules, that `check` links nothing and produces only
  metadata for root targets, that a killed `check` publishes no successful
  profile while retaining only completed atomic unit entries, that restored
  build-script results are still emitted, and every fail-closed case in
  section 4.8. Differential-test the effective rustflags precedence against
  keyed Cargo for empty and nonempty encoded flags, plain `RUSTFLAGS`, exact
  target plus all matching target-cfg entries, and `build.rustflags`; require
  the same flags for builds and both read-only queries, and require explicit
  target builds to leave host build-script and proc-macro compilation
  unflagged. Include quotes, backslashes, repeated spaces, and a tab in the
  plain-`RUSTFLAGS` cases so Lorry cannot retain its current shell-word parser.
- Extend the native Lorry fixture to run `metadata`, `check
  --message-format=json`, and `tree` on Linux-cross and Motor-native Lorry.
  Normalize only host roots and sysroot paths, then require identical
  documents, message sets, and trees.

**Native rust-analyzer semantic test**

Extend `src/tests/rust-analyzer-smoke`; do not create a second LSP protocol
harness. Its session type already takes a `Command`; add a transport that
runs `/devtools/rust/bin/rust-analyzer` through the existing SSH path while
keeping the harness on Linux. SSH carries no environment, so the remote
command sets `CARGO` and `TMPDIR` by explicit prefix as Lorry's native test
does.

The fixture uses path dependencies only, one of them with a small build
script, plus one non-ASCII module file and one deliberate error in the root
package; the native startup check and analysis run in the 8 GiB VM.
Registry-dependency coverage belongs to the Lorry fixtures above. Stage the
fixture under `/devtools/tmp` and initialize rust-analyzer on its
`Cargo.toml` with the section 4.6 configuration; no Lorry command is run by
the harness itself.

The accepted session must prove:

1. `--version` matches the assembly manifest;
2. initialize/initialized and workspace health reach `ok` and quiescent, and
   the workspace loaded as a Cargo workspace, which proves `lorry metadata`
   and the startup `lorry check` succeeded;
3. a build-script `cfg` and an `OUT_DIR` include resolve in hover and
   definition;
4. the deliberate error appears as a flycheck diagnostic after `didSave`
   and disappears after the fix is saved;
5. hover, go-to-definition into Motor std, and completion return semantic
   results;
6. the non-ASCII file URI round-trips correctly;
7. two separately selected Lorry packages load together as two
   `linkedProjects` manifests;
8. server stderr contains no sysroot metadata or Cargo-query fallback error;
   retain the existing RA command/discovery logs as diagnostic evidence,
   without asserting their exact text (section 4.33); sampled descendants match the documented
   Lorry/rustc/build-script/native-tool/proc-macro processes, with sampling
   limitations recorded rather than claiming an exhaustive audit; and
   stdout JSON and stderr progress from `lorry check` were streamed
   concurrently; and
9. shutdown, exit, EOF, stderr capture, and child status complete within the
   existing bounded deadline.

This is a server acceptance test, not an editor test. No test launches Helix,
Red, Gears, or another consumer.

### 4.12 Incremental patch sequence

Keep each implementation patch near 100-300 changed lines including focused
tests. Patch 1 is the explicit exception: the obsolete feature is intertwined
with ordinary path-patch code and repository bookkeeping, so one buildable,
mostly-deletion patch is safer than intermediate states that compile but retain
only part of its security contract. The repositories and review stops are
explicit:

1. **Lorry: remove required patches (complete).** Delete the feature as listed in section
   4.7: the configuration table and its parser, the manifest matcher and
   resolver guard, the seeded-Git repository object type, the
   `objects/seeded-git` directories in Lorry, `src/imager/motor-os-dev.yaml`,
   and the test fixtures, the unit tests, and the spec, design, and README
   text, including `src/bin/lorry/full-native-build.md`. A leftover
   `required-patches` table then fails as an unknown configuration key.
   Authorized by U. Lasiotus on 2026-09-02.
2. **Lorry: Git-patch manifest model (complete).** Replace the vendor-only Git-patch
   parser with path/Git variants in the ordinary manifest model. Make the
   resolver's crates.io-patch marker independent of physical source kind and
   make lock rendering preserve a Git package identity. Cover this with pure
   manifest, resolver, and lockfile tests.
3. **Lorry: immutable Git-patch vendoring (complete).** Reuse the content-addressed direct
   Git object machinery for patches, return an in-memory patch catalog, remove
   manifest and early lock rewriting, update admission identity, and add the
   read-only/byte-identity product tests in section 4.11. Preserve legacy
   explicit path patches. Stop for review of this pre-existing behavior
   correction and update Lorry's README/spec only when the tests pass.
4. **Lorry: Git-patch refresh resolution (complete).** Check every mutable patch selector
   during `vendor`, compare it with the locked commit, and distinguish
   commit-ID `rev` selectors from mutable named `rev` references. Return a
   verified set of old/new source candidates without retaining or fetching
   history for ancestry classification. Unit-test the default branch, an
   explicit branch, a tag, a named remote `rev`, full and abbreviated commit
   IDs, first materialization, and an unchanged remote.
5. **Lorry: Git-patch review and automation (complete).** Feed all refreshed candidates
   through one complete vendor review and implement the interactive default-no
   and non-interactive `--accept-all` contract from section 4.7. Change
   Lorry's design/spec wording so `--accept-all` approves the whole displayed
   dependency/capability candidate, whether or not a Git selector moved, while
   all explicit policy and limit checks remain enforced. Cover batching,
   unrelated changes alone and simultaneous with Git movement, moved-tag
   labeling, explicit denial, decline, non-interactive failure, and atomic
   publication/failure.
6. **Lorry: Cargo-compatible rustflags (complete).** One effective-rustflags
   helper is used by the existing build paths and is ready for the two planned
   queries. It matches Cargo's mutually exclusive precedence and configuration
   layering, including target flags replacing `build.rustflags`. Differential
   tests compare compiler argv and build-script environment against the keyed
   Cargo, including the former append and shell-word parsing bugs.
7. **Lorry: Cargo-form selection and compatibility queries (complete).** Add
   the exact `locate-project` and two read-only `rustc` query forms,
   `--manifest-path`, `--target-dir`, `clean --target-dir`, and the shared
   no-op options, with CLI tests. Unknown `cargo rustc` forms remain rejected.
8. **Lorry: source view (complete).** Publish content-addressed immutable
   package sources below the global cache under their full source-tree SHA-256
   with atomic publication, digest re-verification, and `cache clean`
   integration.
9. **Lorry: metadata wire types (complete).** Add complete private output types and, in
   a separate test crate, deserialize golden documents with `cargo_metadata`
   0.23.1.
10. **Lorry: metadata graph mapping (complete).** Add the section 4.8 mapping,
   `--no-deps`, and `--filter-platform`, with Cargo differential and negative
   tests. Stop for review of the schema mapping and every documented
   normalization.
11. **Lorry: `check` (complete).** Add the command with rendered output, root
   `--emit=metadata`, `--all-targets`, `--keep-going`, and no-link tests.
12. **Lorry: `check --message-format=json` (complete).** Add complete message
   types, the ANSI variant, restored-result emission, killed-child semantics,
   and tests that parse every line with `cargo_metadata` 0.23.1.
13. **Host rust-analyzer/Lorry acceptance (complete).** Drive Lorry with the pinned Stage 1
    server on Linux, capture the actual invocation contract, and prove project
    load, build-script data, and flycheck before introducing guest variables.
    This is a Stage 2 test on Linux, not a supported Linux configuration; it
    expects exactly the two sysroot metadata errors described in section 4.11.
14. **Lorry: `tree` and differential tests (complete).** Add the required `tree` command,
    the complete Linux differential fixture against keyed Cargo, and README
    documentation.
15. **Lorry native equivalence (complete).** Extend the native product fixture to the
    compatibility queries and all three required commands.
16. **Motor Rust: configuration and sysroot (complete).** Make `dirs` non-Motor, return
    no native implicit config directory, and skip the sysroot `cargo metadata`
    attempt on Motor.
17. **Pinned URL patch and source preparation (complete).** Add checksum-verified
    crates.io source preparation under `../patched-crates/`, with offline
    shell contract tests. Check in the small lossless Motor file-path patch
    and conversion tests. Record the exact upstream version/checksum.
    Preparation contract tests pass; the URL patch passes 67 host
    and 61 Motor unit tests through the developer-image gate. The host/native
    runner is wired into `full-test.sh`; formatting passes and Clippy reports
    only two unchanged upstream parser warnings. The full release developer-image
    gate passes after the approved resolver snapshot optimization (see below).
    The earlier unreproduced native self-build stall remains tracked separately.
18. **Pinned inventory patch (complete).** Check in Motor `.init_array` registration and
    native fixture tests; record the exact upstream version/checksum. Prepare
    both patched sources and commit the standalone rust-analyzer path-source
    lock changes, without changing ordinary-build locks at runtime.
    The pinned patch passes both host and Motor registration tests
    through `full-test.sh`; the full release developer-image gate passes.
    The four-line standalone lock change validates with `--locked --offline`.
19. **Motor Rust: child pipes (complete; reviewed).** Add the thread-based Motor implementation and
    its Linux unit test. Cross-check rust-analyzer offline. Stop for review of
    the complete external patch stack.
    Committed in the authoring worktree described below; host tests and both
    host/Motor checks pass. U. Lasiotus approved the external stack after its
    conversational summary; proceed with integration, subject to the new
    bootstrap-scoping decision below.
20. **Toolchain/assembly identity and acquisition (complete).** Add the standalone lock
    to toolchain identity and validation, record it in assembly manifests, add
    patched-source identity and workspace-scoped overrides for both host and
    native builds, native recipe identity, locked source fetch, and shell contract tests,
    then select the reviewed Motor Rust revision. Keep the Stage 1
    host-component behavior unchanged.
21. **Native build and validation (complete).** Cross-build, strip, ELF-check, hash, and
    atomically stage rust-analyzer and rust-src under the assembly key.
22. **Development image (complete).** Add only the new assembly root to the dev image and
    test required/missing/changed overlays and standard-image exclusion.
23. **Native LSP acceptance (complete).** Add the SSH transport, dev-image guest staging,
    flycheck and build-script assertions, multi-root case, diagnostic logs,
    descendant sampling, and measurements. Stop for review of the first native
    results and choose the regression thresholds. The limits were approved;
    the final packaged formatter-only server passes (sections 4.32–4.33).
24. **Release integration and documentation (complete).** Wire the accepted server test
    into the dev-image gate and make `full-test-dev.sh` give the repository
    suite's developer-image VM 8192 MiB by default while retaining the
    developer-source phase's existing 4096 MiB default. Add a shell-contract
    test for both assignments and the caller override. Update toolchain/build
    documentation and this status, then run the gates below. Keep this document
    as an active plan until the final queued hover investigation is finished.
25. **Investigate the deferred hover timeout last.** After all other native
    rust-analyzer work is complete, investigate the `env!`-derived string hover
    recorded in section 4.30. Compare plain integer, plain string, and
    macro-derived string hovers on Motor and Linux, diagnose the underlying
    cause, and add the appropriate regression coverage. Removing the current
    extra assertion is temporary sequencing, not a fix or a declaration that
    Stage 2 is complete. Restore coverage once the issue is addressed; do not
    lengthen the existing deadlines to hide it.

No patch in this sequence contains consumer code. Do not combine the Motor
Rust fork changes, Lorry command changes, image publication, and native
semantic test into one unreviewable cutover.

### 4.13 Gates and completion criteria

While iterating, run the focused fork, shell, imager, Lorry, or LSP test owned
by the patch. Every Lorry behavior patch is ultimately gated by the single
bounded product suite:

```sh
src/bin/lorry/tests/test-all.sh
```

Before final cutover, perform one clean managed toolchain/assembly build so the
network-enabled provisioning path and then-offline native build are both
tested. Preserve its timing and manifest. Run the repository gates without
duplicating Lorry's profile-independent product suite:

```sh
src/tests/full-test.sh
src/tests/full-test.sh --release
src/tests/full-test-dev.sh --release
```

The native LSP acceptance runs in an 8 GiB developer-image VM. The wrapper now
passes an 8192 MiB default to the repository suite that hosts native acceptance,
retains 4096 MiB for the separate developer-source phase, and preserves an
explicit caller override. A shell contract test exercises both assignments.
Native acceptance is wired only under `full-test.sh`'s developer-image branch,
so the ordinary base/standard image gates do not look for the native server.
The new component and native analyzer probes are offline. The existing
approved networking tests and network-enabled developer-source/Lorry
integration phases retain their established behavior. Any new compiler or
Clippy warning fails its owning patch. This wiring still needs the final
packaged artifact and complete developer-image gate; see section 4.33.

Stage 2 is complete only when all of the following are true:

- the assembly validates and records the exact native server, lock, rust-src,
  and recipe identities;
- only the development image contains the server and rust-src overlay, and
  no image contains a file named `cargo`;
- cross-check, ELF checks, URL, pipe, and inventory tests pass;
- `lorry vendor` leaves every input project/workspace `Cargo.toml`
  byte-identical on success, reuse, update, declined review, failure, and
  interruption; Git patches retain Cargo-compatible Git identities in
  Cargo.lock and remain consumable offline by every Lorry product command;
  mutable selectors are checked remotely and reviewed once per run, exact
  commit `rev` selectors remain pinned, every changed candidate fails
  non-interactively without approval, `--accept-all` approves all dependency
  and capability changes but no policy denial, and the documented interactive
  cases all pass;
- the required-patch feature, its seeded-Git object type, and its repository
  directories are gone from Lorry, the dev image configuration, the test
  fixtures, and Lorry's documentation;
- `lorry metadata`, `lorry check --message-format=json`, and `lorry tree`
  are deterministic and offline; all documents and messages parse with the
  pinned `cargo_metadata` schema; the documented semantic projection matches
  keyed Cargo on Linux; and Linux-cross and Motor-native Lorry are equivalent;
- the pinned host rust-analyzer loads the fixture through Lorry with exactly
  the one expected sysroot metadata error, and its observed Cargo-shaped
  calls exactly match the accepted and rejected invocation contract in
  section 4.7;
- native standard-LSP lifecycle, build-script, flycheck, hover, definition,
  completion, non-ASCII, and multi-root tests pass; unexpected discovery
  errors are rejected and sampled descendants conform to sections 4.6-4.7, without claiming an
  exhaustive execution audit;
- the clean build and three final gates pass; and
- resource measurements and future regression thresholds are recorded.

### 4.14 Decisions and open questions

The maintainer approved these decisions on 2026-09-02. The detailed contracts
and rationale live in the referenced sections; this table is the concise
review record.

| Area | Decision |
|---|---|
| Target | Support ordinary `x86_64-unknown-motor` userspace only; kernel, loader, and custom JSON targets remain out of scope. |
| Lorry changes | Modify Lorry. Rust-analyzer uses Lorry through `$CARGO`; do not add a `rust-project.json` exporter or port Cargo. |
| Required commands | Implement `lorry metadata`, `lorry check --message-format=json`, and `lorry tree`; `tree` is required even though rust-analyzer does not invoke it. |
| Compatibility queries | Implement the exact `locate-project` and read-only `cargo rustc --print` forms in section 4.7. Do not rely on rust-analyzer's warning-producing fallbacks. |
| Cargo fidelity | Match keyed Cargo as closely as Lorry's smaller model permits. Preserve the graph, build-relevant and retained descriptive metadata, package/source identities, and JSON message schema; allow only the documented defaults and normalizations in section 4.8. |
| Input manifests | Every project/workspace `Cargo.toml` is immutable. Git patches retain their Git declarations and Cargo-compatible lock identity; vendoring uses verified content-addressed objects and never rewrites an input manifest. |
| Git-patch refresh | Every networked `lorry vendor` checks mutable Git-patch selectors. Show one complete interactive review, defaulting to no. Non-interactive runs succeed only when the complete candidate is unchanged; otherwise they fail or approve every displayed dependency/capability change with the existing `--accept-all`, whether or not a Git selector moved. Policy and limits still apply. Commit-ID `rev` selectors remain pinned; named remote `rev` references remain mutable; moved tags receive a prominent warning. Do not fetch history merely to classify ancestry. `--accept-all` means accept every displayed change, including capability grants that policy allows; U. Lasiotus confirmed this on 2026-09-02. |
| Rustflags | Correct Lorry to use Cargo's mutually exclusive precedence for every build and both compatibility queries: encoded environment, plain environment, all matching target entries, then build configuration. Target flags replace rather than append to build flags. |
| Toolchain environment | An explicit direct compiler wins. A Linux rustup-proxy fallback honors rust-analyzer's `RUSTUP_TOOLCHAIN` only while resolving the proxy, then descendants receive the direct compiler without that variable. Native Lorry invokes its configured compiler directly. Host acceptance sets an absolute keyed `RUSTC`. |
| Required patches | Delete the feature: its matcher depended on the manifest rewrite, nothing in the tree uses it, no command produces its seeded objects, and policy rules already deny a package by name, version, and source. Authorized by U. Lasiotus on 2026-09-02. |
| Rust fork | Change no rust-analyzer defaults. Skip sysroot Cargo metadata on Motor and stitch the keyed `rust-src` directly. |
| Dependency patches | As approved by U. Lasiotus on 2026-09-04, use pinned crates.io releases of `url` and `inventory`, unpack and patch them locally under `../patched-crates/`, and build against those prepared sources. Keep the patches in Motor OS; no separate forks. Record checksums and patch/tree identity, precommit the path-source lock, and preserve locked/offline builds. Motor OS's root `AGENTS.md` governs the external-source work too. |
| Build scripts | `lorry check` may execute admitted build scripts with the same authority and policy as `lorry build`. Motor warning mode is unsandboxed, so clients enable checks only for trusted projects and reviewed Lorry state. |
| Procedural macros | Keep direct rust-analyzer proc-macro expansion disabled and package no proc-macro server or dylibrary. A check may still execute an admitted Motor proc-macro helper as a rustc descendant. |
| Targets and refresh | Metadata includes every supported root target; `--all-targets` checks them. Use rust-analyzer's normal client-watcher refresh and flycheck paths; add no watch mode or custom launcher. |
| Resources | Measure in the 8 GiB developer-image VM and choose numeric regression thresholds at the native-acceptance review stop. Patch 24 gives the hosting repository-suite VM 8192 MiB by default and leaves the separate developer-source phase at 4096 MiB. Memory optimization is not a Stage 2 goal. |
| Gates | Keep the developer-image gate release-only; the ordinary main-image gate still runs in debug and release. |

#### Open questions

The local DNS/TCP TIME-WAIT prerequisite and the harness retry that masked
it are fixed in `a3d1bae0`, validated by three debug and three release
full-suite passes after rebasing onto the kloader staging fix `f4b5db67`.
The earlier assembly/tap prerequisites are resolved too.

**New stop: native Lorry self-build liveness (2026-09-05).** The subsequent
`full-test-dev.sh --release` run passed the URL tests (67 host, 61 Motor),
the repository suite, and native developer-source builds, including Lorry
in the 4-vCPU/4-GiB VM. Lorry's final product fixture then timed out in
`native-lorry-self-gate` at its existing 1,200-second limit, exit 124, in
the 8-vCPU/8-GiB VM. Its host preparation passed in 202.820 seconds; native
vendoring completed and verified `Cargo.lock`, but the first native release
build stopped producing output after dispatching initial dependencies through
`bisync 0.3.0`.

A diagnostic SSH `ps` request also stopped responding. At a host-side sample,
all eight vCPUs were waiting in KVM, with no console panic. The host had about
20 GiB available and no swap in use; QEMU's resident memory was about 7.7 GiB.
These observations establish a liveness failure, not its cause: guest memory
pressure, a lost wake, or another OS/runtime issue remain unproven. No test
limit, job count, or retry policy was changed. The harness stopped the VM;
the stalled diagnostic SSH client was terminated separately.

Evidence is retained under
`src/bin/lorry/target/lorry/native-self-tests/self-20260905T165416Z-421811/`
(`summary.txt`, `timings.tsv`, `native.log`, `qemu.log`, `lorry-cross`), with
the complete run in `/tmp/motor-ra-url-dev-rebased.log`. The DNS fix is
committed; URL/helper work remains uncommitted. Inventory has only been
cross-linked in a temporary fixture, not executed natively or integrated.

**Maintainer approved investigation and repair (2026-09-05).** Diagnose and
fix the native self-build stall before continuing rust-analyzer. Do not
bypass it by increasing the timeout or reducing the gate's concurrency.
The failure is outside the URL/inventory portability patch. Reproduction
uses the retained guest workspace in a disposable disk snapshot, with the
same 8-vCPU/8-GiB configuration, and captures guest memory/process samples
plus QEMU monitor state without repeating network vendoring.

Diagnostic results, all at 8 vCPUs/8 GiB:

- Resuming the retained build passed.
- A local probe passed 32 rounds of eight synchronized `rustc --print=cfg`
  launches (256 total).
- A fully cold release build passed in 540.137 seconds: dependency
  verification/preparation took about 228 seconds, dependency compilation
  114 seconds, and the remaining root build/publication about 198 seconds.
- Fresh Git-patch materialization, native `vendor --accept-all`, and a cold
  release build passed together in approximately 1,115 seconds, under the
  unchanged 1,200-second limit. Vendoring took about 581 seconds. This was
  the vendor/build prefix, not the fixture's subsequent equivalence/tests.
- Both preserved cold native binaries are byte-identical to the original
  cross-build, SHA-256
  `7a702c25fb9982ba7a09d62b96563d0779063d990128f5df2bed022f0261fa33`.

None reproduced the original stall or recorded a kernel memory-admission
refusal. These are diagnostic results, not a repair or replacement for the
failed gate. Logs are `/tmp/motor-lorry-diag-build.log`,
`/tmp/motor-lorry-diag-samples.log`,
`/tmp/motor-lorry-diag-spawn-stress.log`,
`/tmp/motor-lorry-diag-cold-build.log`, and
`/tmp/motor-lorry-diag-vendor-build{,-timestamps}.log`. Resident counter logs
are `/tmp/motor-lorry-diag-resident{,-v2,-interactive,-foreground}.log`.
The gap in the interactive log was host terminal job control stopping SSH
after input to a non-foreground `timeout`, not evidence of a guest timer
failure; the replacement used `timeout --foreground`. A separate debugger
sample is `/tmp/motor-lorry-diag-vendor-stacks.log`.

The diagnostic VM used a disposable disk snapshot. Cache, target, and Git
source directories were renamed within that snapshot, not deleted from the
original disk. The VM has been shut down; host logs and the two native
binaries remain in `/tmp`. Production code, gate limits, and concurrency
remain unchanged. No implementation changes were committed in this
investigation, and the original liveness failure remains open.

**Approved follow-up: resolver snapshot optimization.** There is a separate measured
verification/resolution cost, but reducing it must not be presented as proof
that the unreproduced hang is fixed. The maintainer approved this focused
Lorry-only change and then continuing rust-analyzer implementation:

1. Share immutable `Candidate` data between resolver `State` snapshots
   (for example, `Node::record: Arc<Candidate>`), while keeping activation,
   edge, and selection state branch-local. Currently `State::clone` deeply
   copies candidates, including full local manifests, during recursive
   `solve` calls. Preserve all candidate ordering, backtracking, admission,
   and Cargo-compatibility semantics; do not redesign the solver or change
   the allocator as part of this patch.
2. Test shared immutable records and independent mutable branch state;
   run the resolver/Cargo-oracle contracts, then measure the same cold
   native fixture and run the unchanged release developer-image gate.
3. Keep the original liveness failure tracked separately unless evidence
   establishes its cause. The maintainer approved resuming rust-analyzer
   after this optimization with that failure still unresolved.

Implementation complete: resolver nodes now share immutable candidates
with `Arc`; mutable activation/edge/selection data is still cloned per branch.
A regression test checks sharing, isolation, and final resolution both with
and without a surviving snapshot. All 26 focused resolver tests pass, including
the frozen Cargo-resolution oracle; Clippy passes with warnings denied.

`src/tests/full-test-dev.sh --release` passes with unchanged limits and
concurrency. Lorry's host suite reports 333 passed and 10 pre-existing ignored
tests; the complete product suite, Cargo differential contracts, and native
equivalence pass. The native self-build phase takes 535.133 seconds (8m55s)
including fresh vendoring, release build, byte-for-byte cross/native comparison,
command equivalence, proc-macro and incremental tests. Host preparation takes
199.119 seconds; the complete Lorry product suite takes 1028 seconds. Evidence:
`src/bin/lorry/target/lorry/native-self-tests/self-20260905T203023Z-481815/`
and `/tmp/motor-ra-resolver-dev-release.log`.

This passing fresh-workspace gate is not a controlled before/after benchmark
against the separately cache-cleared diagnostic runs, nor proof that the
original liveness failure is repaired. No timeout, retry, allocator, or OS
change was made in the optimization. Continue rust-analyzer as approved.

### 4.15 Implementation map

Where each patch does its work. Paths under `src/bin/lorry/src/` are Lorry
product code; paths under `crates/` are inside the pinned Motor Rust tree's
`src/tools/rust-analyzer/`. Function names are anchors for search; do not
rely on line numbers.

| Patch | Files and entry points |
|---|---|
| 1 remove required patches | `config.rs`: `RequiredPatch`, `merge_required_patches`, the `required_patches` field. `patch.rs`: `configure`, `configure_cargo_registry`, `load_required_patch*`, `verify_required_object`, `required_manifest_error`. `resolver.rs`: `RequiredPatchGuard`, `Catalog::register_required_patch`, `required_patch_allows`, `registry_candidate_is_patched`, `required_patch_failure`. `repository.rs`: `SeededGitObject`, `lookup_seeded_git`, `verify_seeded_git_object`, the `objects/seeded-git` layout. `src/imager/motor-os-dev.yaml`: the `seeded-git` directories. `tests/registry-contract.sh`. Docs: `README.md`, `spec.md`, `design.md`, `full-native-build.md`. |
| 2 Git-patch manifest model | `manifest.rs`: `Manifest`, `PathPatch`, `parse_patches`. `git.rs`: `parse_git_patches`, `parse_locked_source`. `resolver.rs`: `ResolvedSource`, `Catalog::insert_path_patch`, the `patched_crates_io` marker. `lockfile.rs`: lock rendering. |
| 3 immutable Git-patch vendoring | `git/direct.rs`: `DirectCatalog`, `materialize_locked_dependencies`, `materialize_one`, `locked_package`, and the shared Git object layout. `git.rs`: `parse_locked_source`. `patch.rs`: `configure`. `resolver.rs`: `Catalog::insert_git_patch` and locked-repository patch selection. `vendor.rs`: `execute_reconcile`. `admission_state.rs`: the existing Git and crates.io-patch review records. `tests/git-patch-contract.sh`. |
| 4, 5 refresh and review | `vendor.rs`: candidate review and approval, `VendorOptions` in `cli.rs`. `prompt.rs`. The `git/` module for selector resolution. `spec.md` and `design.md` for the `--accept-all` sentences. |
| 6 rustflags | `config.rs`: `environment_rustflags`, `split_words`, `apply_cargo_environment`, `build_rustflags`, `target_options`. `engine.rs`: the composition after `target_options` in `execute`. `build_script.rs`: the U+001F-joined rustflags handed to scripts. |
| 7 selection and queries | `cli.rs`: `Cli::parse`, `Command`, `BuildOptions`. `main.rs`: `run`, `print_help`. `toolchain.rs`: `Toolchain`, the `--print cfg` query, `resolve_rustup_proxy`. `process.rs`: `query`. `engine.rs`: `artifact_root`, `profile_destination`. `clean.rs`. |
| 8 source view | `dependency.rs`: `PreparedGraph`, `PreparedPackage` and its extracted archive. `archive.rs`. `source_tree.rs`: `Tree`, limits. `config.rs`: the global cache root. `cache_clean.rs`. |
| 9, 10 metadata | New module. Inputs: `manifest.rs` (`Manifest`, `PackageMetadata`, `Dependency`, targets), `resolver.rs` (`Resolution`, `ResolvedPackage`, `ResolvedSource`, `root_edges`, `CompileKind`, `FeatureContext`), `unit.rs` (`UnitGraph`, `UnitKey`, `UnitEdge`, `CompilationPlan`), `json.rs`, `toolchain.rs` (`--print cfg`, `evaluate_selector`). Golden test crate: a new directory under `tests/` with its own `Cargo.toml` and lockfile, like `tests/native-fixture`. |
| 11, 12 check | `engine.rs`: `build`, `root_dependencies`, `finish_build`, the rustc `--emit` argument builder. `executor.rs`: `execute`, `execute_reusing`, `Outputs`, `ExecutedBuildScript`, `RustcOutput`. `compile.rs`: the `--error-format=json` and `--json=` arguments. `diagnostic.rs`. `cache.rs`: `BuildCaches`, `UnitInput`, `BuildScriptInput`. |
| 13 host acceptance | `src/tests/rust-analyzer-smoke/src/`: `case.rs` (`SemanticCase::start`), `session.rs`, `process.rs`, `transport.rs`, `semantic.rs` (`Toolchain::discover`), `main.rs`. `src/tests/test-rust-analyzer.sh`. |
| 14 tree and differential tests | New module over `resolver.rs` and `unit.rs`. `tests/test-all.sh` and `tests/current-toolchain.sh` for the keyed Cargo (`LORRY_TEST_CARGO`). `tests/oracles/`. |
| 15 native equivalence | `tests/test-native.sh` (`remote_command`, the env-prefix pattern), `tests/native-fixture/`. |
| 16 fork: config and sysroot | `crates/rust-analyzer/src/config.rs`: `Config::user_config_dir_path`. `crates/rust-analyzer/Cargo.toml`: the `dirs` dependency. `crates/project-model/src/sysroot.rs`: `Sysroot::load_workspace`, the `CargoMetadata` branch. |
| 17 url patch | `src/toolchain-patched-crates.sh`, `src/patches/`, `src/tests/test-toolchain-patched-crates.sh`; the prepared crate's file-path conversion module and slash-rooted target conditions (currently url 2.5.8). |
| 18 inventory patch | `src/patches/`; the prepared crate's `.init_array` section target list (currently inventory 0.3.24); native test fixture and standalone rust-analyzer `Cargo.lock`. |
| 19 fork: child pipes | `crates/stdx/src/process.rs`: the `read2` implementations under `cfg(unix)`, `cfg(windows)`, and `cfg(target_arch = "wasm32")`, and their callers `streaming_output` and `spawn_with_streaming_output`. |
| 20 toolchain identity | `src/toolchain-versions.sh`: the `*_LOCK_SHA256` values, `MOTOR_OS_RUNTIME_INPUTS`. `src/toolchain-state.sh`: the before/after lock check. `src/toolchain-lib.sh`: `toolchain_key`. `src/toolchain-sources.sh`: provisioning. `src/toolchain-assembly.sh`: `toolchain_render_assembly_manifest`, `toolchain_validate_assembly_outputs`. Tests: `src/tests/test-toolchain-*.sh`. |
| 21 native build | `src/toolchain-native-rust-analyzer.sh`, `src/toolchain-assembly.sh` (`ASSEMBLY_IMAGE_ROOT` and artifact manifests), `docs/toolchain.md`, `docs/libc.md` for the startup-path statement. |
| 22 development image | `src/imager/motor-os-dev.yaml`: `assembly_dirs`, `assembly_required_executables`. `src/imager/src/`. `src/tests/test-dev-sources.sh`. |
| 23 native LSP acceptance | `src/tests/rust-analyzer-smoke/` (the SSH transport), `src/tests/full-test.sh` (the developer-image selection and `vm_ssh`), `src/tests/full-test-dev.sh`, `src/vm_scripts/run-qemu.sh` (`MOTO_MEMORY_MIB`). |
| 24 release integration | `src/tests/full-test-dev.sh`, `docs/build-rustc.md`, `docs/toolchain.md`, this document. |

Read-only references the Lorry patches depend on, all in the pinned
rust-analyzer tree:

- `crates/project-model/src/workspace.rs`: the `locate-project` call and
  the sysroot loading branch for Cargo workspaces;
- `crates/project-model/src/cargo_workspace.rs`: `FetchMetadata`, the
  `cargo metadata` argument construction, and `CargoWorkspace::from_metadata`,
  which lists every metadata field rust-analyzer reads;
- `crates/project-model/src/build_dependencies.rs`: the build-script `check`
  invocation and its `Message` handling;
- `crates/rust-analyzer/src/flycheck.rs`: `check_command` and
  `CargoOptions::apply_on_command`;
- `crates/project-model/src/toolchain_info/`: `rustc_cfg.rs`,
  `target_data.rs`, `version.rs`, and `target_tuple.rs`;
- `crates/project-model/src/cargo_config_file.rs` and `env.rs`: the config
  probe and its tolerance of failure;
- `crates/toolchain/src/lib.rs`: `Tool::path`, `Tool::prefer_proxy`, and
  `cargo_use_targets`, which define how `CARGO` is found;
- the `cargo_metadata` 0.23.1 source in the Cargo registry cache
  (`src/lib.rs`, `src/messages.rs`, `src/dependency.rs`,
  `src/diagnostic.rs`): the exact deserialization contract; and
- the keyed Cargo binary itself, reached through `LORRY_TEST_CARGO`, which is
  the differential oracle. Cargo's source is not required.

### 4.16 Stage 19 external-stack review

The authoring worktree is `../toolchain-src/rust-ra-portability`, on the
`motor-ra-portability` branch of the existing Motor Rust fork. The selected
checkout at `../toolchain-src/rust` remains unchanged at the current toolchain
baseline. No new GitHub fork, std, moto-rt, mlibc, or core OS change is involved.

Fork commits above the selected baseline are `9ea84a28c3e` (configuration and
sysroot), `fc3a0529b7f` (standalone path-source lock), and `f040c09547a`
(child pipes and the config-import warning cleanup). Review their combined
diff against `3c9729fb797`; the authoring branch is not selected for builds yet.

Review the complete stack before step 20 selects it:

| Change | Scope and behavior |
|---|---|
| Configuration and sysroot | Existing step 16 changes disable implicit native user config and sysroot Cargo metadata only on Motor. The follow-up qualifies the non-Motor `std::env` use to avoid a Motor-only unused import. |
| URL | `src/patches/url-2.5.8-motor.patch` adds lossless slash-rooted Motor file paths. The checksum-pinned source is prepared under `../patched-crates/`; 67 host and 61 Motor tests pass. |
| Inventory | `src/patches/inventory-0.3.24-motor.patch` adds Motor to `.init_array` registration. Two tests pass on host and Motor; registrations from separate modules must both be visible. Native tests use the same `motor-clang` and default-library flags planned for the server. |
| Standalone lock | Only the registry source/checksum fields for URL and inventory are removed: four lines, no version changes or machine-specific paths. Both host and Motor commands receive the same workspace-scoped prepared-source overrides and use `--locked --offline`. |
| Child pipes | `crates/stdx/src/process/portable.rs` uses two standard reader threads and a queue of at most eight 8-KiB chunks. Only the coordinator invokes callbacks. Completed readers are joined; a read/spawn/join error returns without waiting for a blocked peer, allowing the caller's existing child guard to terminate the child. Dropping the receiver stops the remaining reader at its next send. A completion guard also reports panics rather than silently losing a reader. |

The portable module is compiled on Linux for tests and selected on Motor (and
other targets without a Unix, Windows, or wasm32 implementation). Tests cover
both EOF orders, coordinator-only callbacks, read errors and panics while the
peer is blocked, and interleaved real-child output of 256 KiB on each pipe.
The host `stdx` suite passes all 10 tests. A narrow test-only Clippy expectation
allows launching its own executable with an explicit working directory;
the higher-level `toolchain::command` helper depends on `stdx` and cannot be
used here. No production lint suppression is added.

Offline host and Motor rust-analyzer checks pass with the same patched-source
overrides. Host and Motor Clippy pass for the pipe module and inventory tests;
formatting passes. The inventory test ELF is an x86-64 PIE with a 64-byte
`.init_array` and non-executable stack. Upstream's build script
warns that it cannot locate `.git/HEAD` in a Git worktree (whose `.git` is a
file); this authoring-layout warning is recorded, not suppressed or patched.
The ordinary selected checkout has a `.git` directory. This cross-check is
not a linked or executed native server, and does not validate LSP behavior.
The host check also reports an upstream future-incompatibility warning for
unchanged `nix` 0.31.3. Logs are `/tmp/motor-ra-{host,native}-check.log`,
`/tmp/motor-ra-pipes-{host,clippy,native-clippy}.log`, and
`/tmp/motor-inventory-native-clippy.log`.

The full `src/tests/full-test-dev.sh --release` gate passes with inventory
included: `/tmp/motor-ra-inventory-dev-release.log`. Its final native Lorry
phase takes 531.632 seconds with unchanged limits and byte-identical native
and cross-built binaries; the complete Lorry product suite takes 890 seconds.
Evidence is in
`src/bin/lorry/target/lorry/native-self-tests/self-20260905T210732Z-546183/`.
This is the second passing release developer-image gate after the resolver
optimization, not a resolution of the separately tracked original hang.

**Review approved:** U. Lasiotus approved this external stack and continuation
with toolchain integration and the native build. Carry the fork's
portable-pipe unit tests into the selected-source test integration; the current
full developer-image gate tests the published crate patches, not this still
unselected authoring worktree. Native LSP/resource acceptance and its separate
threshold review remain in step 23. The original unexplained native Lorry
hang remains tracked separately as agreed above.

### 4.17 Approved integration decision: bootstrap patch scoping

Step 20 inspection found an integration choice not covered by the reviewed
external stack. In the pinned Rust bootstrap:

- `src/bootstrap/src/core/builder/cargo.rs` runs tool Cargo commands from the
  Rust source root, including commands with a rust-analyzer `--manifest-path`;
- `src/bootstrap/src/core/build_steps/tool.rs::prepare_tool_cargo` constructs
  those manifest arguments for both rust-analyzer and its host proc-macro
  server; neither call currently supplies the local crate overrides; and
- the existing per-tool bootstrap configuration supports extra features, not
  arbitrary Cargo configuration arguments.

A `.cargo/config.toml` under rust-analyzer would not be read from that working
directory, and generating one in the source tree is prohibited by this plan
anyway. Global Cargo patch configuration would also affect unrelated Rust-root
builds (the root lock contains URL), violating the workspace-scoped contract.

**Approved:** add a small, opt-in hook in the Motor Rust fork's
`prepare_tool_cargo`. For rust-analyzer workspace tool paths only, it reads
an explicitly named Motor build environment variable carrying an external
Cargo config path and passes that path via `--config`. The Motor OS build
script generates the config outside the source tree with only the two verified
crate path overrides. Cover the server and proc-macro-server paths, unrelated
tool exclusion, and safe argument handling in tests. Enforce the standalone
lock contract and include the new helper/config-generation logic in identity.
No global Cargo config, runtime wrapper, or std/runtime change is involved.

The alternative is a build-only Cargo wrapper, selected via bootstrap's
existing `build.cargo`, which inspects each invocation and injects the same
arguments only for rust-analyzer. It avoids a bootstrap source patch but adds
argument-dispatch machinery around every bootstrap Cargo invocation.

U. Lasiotus approved the scoped hook, including the external Rust bootstrap
file scope. The hook uses `MOTOR_RUST_ANALYZER_CARGO_CONFIG`; its tests cover
the analyzer and proc-macro server, unrelated tools and parent traversal,
an unset variable, and passing paths with spaces and shell metacharacters
as a single unmodified argument. Toolchain integration is proceeding with
this choice; no build-only Cargo wrapper is needed.

### 4.18 Step 20 prerequisite: bootstrap path validation

The scoped hook is implemented in the authoring worktree's
`src/bootstrap/src/core/build_steps/tool.rs` and
`tool/motor_rust_analyzer.rs`. Its four focused unit tests and an offline
`cargo check` of the complete bootstrap crate pass. Main-repository work adds
external config generation and checksum/tree-verified crate preparation, with
its shell contract test wired into `full-test.sh`; the developer-image crate
tests also use that preparation helper. The hook is committed as
`d454849e203` in the Motor Rust fork; the preparation and identity helpers
are committed as `83bfd301` in Motor OS. The new fork revision is not selected
for provisioning yet.

The new negative-path test exposed a **pre-existing production bug** in
`src/toolchain-bootstrap.sh::toolchain_bootstrap_absolute_path`. Its first
`case` calls `toolchain_die` for a relative path without returning; the second
`case` then returns success for an otherwise ordinary string. Callers use
`|| return`, so Bash's conditional error handling does not stop the function.
Both the validator and `toolchain_render_bootstrap_config relative /sysroot
/llvm test-id` print the rejection but return status 0. Thus the existing
bootstrap renderer can accept a relative prefix. The new analyzer config
test correctly fails with `unsafe TOML path accepted`.

U. Lasiotus approved fixing this prerequisite and continuing. Commit
`0fb58a46` adds an explicit failure return in the relative-path branch, with
regression tests for both direct validation and the existing bootstrap
renderer. No Rust source, runtime, or core OS expansion was needed for this
fix. The prerequisite is resolved and release-gated.

The first validation attempt (`/tmp/motor-ra-bootstrap-dev-release.log`)
is invalid: the agent inserted the identity-test entry into `full-test.sh`
while Bash was executing it. The live file edit disrupted execution: after
the release terminal-size test passed, Bash ran its debug branch and then
reported an unexpected `fi`. The on-disk script passes `bash -n`; this was an
agent test-execution error, not an OS failure. The run exited with status 2
and left no VM running. Validation must restart with all scripts frozen; no
retry, timeout, or OS-code workaround was added.

The subsequent frozen-script `src/tests/full-test-dev.sh --release` run
passes completely: `/tmp/motor-ra-bootstrap-dev-release-frozen.log`. It
includes both new shell suites, host and Motor URL/inventory tests, developer
source builds, and the complete Lorry suite. Host preparation takes 228.175
seconds; the native self-test takes 539.726 seconds; the full Lorry suite
takes 927 seconds. Evidence is in
`src/bin/lorry/target/lorry/native-self-tests/self-20260905T225508Z-657958/`.
Bootstrap's four hook tests also pass inside its full unit-test harness;
its offline check and selected-toolchain formatting check pass. This does
not claim a newly selected host toolchain or a linked/executed native server.

### 4.19 Reviewed Rust stack published; build/image integration complete

U. Lasiotus published the four reviewed commits (`9ea84a28c3e`,
`fc3a0529b7f`, `f040c09547a`, and `d454849e203`) in the existing Motor Rust
fork. On 2026-09-06, `git ls-remote` verified that
`motor-os-1.99.0-beta-f47d5bb` points to
`d454849e2030eb09bcce9e367264fa5f7984bcb1`. Managed provisioning updated
`../toolchain-src/rust` to that exact clean revision and verified its
submodules. This resolves the publication boundary; no new fork is needed.

Step 20 implementation now includes the standalone lock and patched-source
digest in the toolchain key, all three before/after lock checks, manifests,
locked source acquisition, and workspace-scoped bootstrap configuration.
The replacement host toolchain passed bootstrap, source/lock checks, and
prefix validation, and the root selector now names the registered key
`f67a50fb6cfc5572b25be0f48172f8ad72a437e1e338fbd8f2fe33e618642f23`.
The server reports `rust-analyzer 1.99.0-dev (d454849e203 2026-09-05)`.
The actual portable-pipe tests (10), bootstrap-hook tests (4), native graph
exclusion check, and selector-cutover test pass. Both external test groups
are wired into the repository suite. Stage 1 semantic acceptance passes in
both debug and release. The selected standalone Motor graph also passes
`cargo check --release --locked --offline --target x86_64-unknown-motor
-p rust-analyzer`. Evidence: `/tmp/motor-ra-host-provision.log`,
`/tmp/motor-ra-selected-source-tests.log`,
`/tmp/motor-ra-selected-host-lsp.log`, and
`/tmp/motor-ra-selected-native-check.log`. Full gates subsequently pass as
recorded in sections 4.20-4.21.

Steps 21-22 implementation adds the offline native build, ELF validation,
atomic binary/rust-src staging, assembly provenance, and developer-only
overlay. Focused shell contracts cover identity changes, corrupt/missing
artifacts, ELF failures, command arguments, source-check order, and failed
build/strip publication. Assembly publication and the full release
developer-image gate pass; steps 23-24 remain pending.
The first native semantic results and resource thresholds still require
the planned step 23 review.

The first native link passes ELF validation. Its strip probe found a recipe
error: default LLVM stripping removes `.comment`, including the Motor compiler
description. The server's own commit and release survive. The corrected
recipe retains that non-allocated section, and the real stripped binary then
passes every validator check. The command contract requires the keep-section
flag. No fork, std, startup, or runtime change was needed. The active assembly
producer was stopped before editing; its partial
`c07d260ceeaa2d7ca456b89c6865e7ef0c384229ab7a70abc332a3f1bab5a9ae`
tree is preserved and marked rejected. A new assembly key must consume the
corrected recipe. Evidence: `/tmp/motor-ra-native-server-build.log`,
`/tmp/motor-ra-native-elf-proof.log` (failed default-strip probe), and
`/tmp/motor-ra-native-elf-preserved-proof.log` (passing corrected probe).

### 4.20 Pre-existing CPU-statistics stop

While checking the existing measurement interfaces, the agent confirmed the
already-recorded `CpuStatsV1::entry` defect in `docs/plans/future-work.md`,
item 9. The kernel writes `num_cpus` counters per process, but the userspace
reader constructs the slice with `num_entries` (process count). The slice can
therefore extend into subsequent records or be too short for CPU indexing.
At that stop the code was unchanged at HEAD; no unsafe reproducer was run
and no core source was modified.

Root `AGENTS.md` requires stopping on pre-existing bugs. The two active
compilation groups were paused intact pending guidance.

U. Lasiotus approved the simple correction on 2026-09-06. It changes the
slice length to `num_cpus` and adds three safe, synthetic snapshot tests in
`moto-sys`, already reached by `full-test.sh`. The unequal-count tests fail
on the original implementation and pass after the fix. Because this changes
a runtime input, both paused producers were terminated before editing; the
partial `0c9c868ea7e32c7e31f97ce36d585295ad29799fc611ef7e70a3a1a5a5b5b52e`
assembly is preserved and marked rejected. A new assembly must be built.
The correction requires three passing debug and three passing release
`full-test.sh` runs before its separate commit, plus the previously requested
release developer-image gate. No stdlib, `moto-rt`, package publication,
or external source edit is included. All three debug and three release
full-suite runs pass, as does the release developer-image gate. Logs are
`/tmp/motor-cpustats-full-debug-{1,2,3}.log`,
`/tmp/motor-cpustats-full-release-{1-warm,2,3}.log`, and
`/tmp/motor-cpustats-dev-release.log`. The initial release timeout and
approved unchanged retry are recorded below.

The replacement assembly `4694483acf92fe124ea12f80c4214969250204b1ddd4cf92fa0a6f15c66759ed`
passed publication and produced the base and standard images. Developer-image
creation then correctly rejected a rust-src host CI script whose executable
bit was copied unchanged, but which has no shebang. This is a new staging
recipe defect, unrelated to CpuStats. A regression reproduces it; the recipe
now clears executable bits only on staged source files, preserving both
contents and installed-prefix permissions. The image permission classifier
is unchanged. The assembly remains intact for diagnosis but must be replaced
under the corrected recipe's new key before the remaining gates.

The corrected assembly
`c60907870e5a3ab92b2855a6e1c8d47fe23f7717c71b8c8f6e6e00d8be01f08a`
passes publication, source/lock/ELF checks, and all three release image builds,
including the developer image. The previously rejected CI script is `0644`
in staging and remains `0755` in the installed prefix. Evidence:
`/tmp/motor-cpustats-source-modes-assembly.log` and
`/tmp/motor-cpustats-source-modes-native-ra.log`. Native semantic acceptance
is still pending; image construction is not an LSP acceptance result.

### 4.21 Release gate budget stop

The first release `full-test.sh` run exits 124 at its existing 900-second
total deadline. It includes cold host-test compilation under the newly
selected compiler; the network-stack test target alone takes 119 seconds,
and quiet SSH/filesystem test builds also compile fresh artifacts. The main
VM starts around 14:48:42 local time on 2026-09-06, with approximately 160
seconds left before the 14:51:23 deadline. Guest `systest` finishes successfully
at 14:50:48, followed by the ripgrep regression. The remaining integration
checks do not finish. There is no guest panic or failed assertion in the
captured output; a final SSH routing error accompanies timeout teardown.
All VM and test processes have exited. This is not a passing release gate
and is not classified as an Internet DNS/ping flake.

Read-only follow-up timing also finds that hashing the newly staged rust-src
tree through the existing content serializer takes 36.214 seconds per call
on this host (Helix's existing tree takes 10.048 seconds). Thus source
validation adds prelude cost as well as the cold compilation. Do not hide
either cost by extending the timeout or skipping integrity checks.

Evidence: `/tmp/motor-cpustats-full-release-1.log`,
`/tmp/motor-cpustats-release-1-console.log`, and
`/tmp/motor-cpustats-release-1-systest.log`. The subsequent gates stopped
automatically. No source or timeout changes were made in response.

U. Lasiotus approved rerunning the unchanged release gate with the now-built
host artifacts. That run passes at the same 900-second limit, followed by
the third debug run, two further release runs, and the complete release
developer-image gate. This closes the stop; the original failed log remains
preserved, not counted as a pass. No integrity checks were skipped and the
host serializer was not changed.

The developer gate passes its repository suite, native developer-source
builds, and complete Lorry product suite. Lorry's native self-build gate
takes 537.337 seconds and its complete suite takes 1,152 seconds. The earlier
unexplained self-build stall did not recur; this does not diagnose or erase
that separately tracked issue. Evidence: `/tmp/motor-cpustats-dev-release.log`.
Steps 20-22 and the CpuStats correction are gated; native LSP semantics and
steps 23-24 are not yet accepted.

### 4.22 Resolved: OS instrumentation deferred

Read-only inspection after the CpuStats fix finds a mismatch between the
step 23 acceptance requirements and the current measurement interfaces:

- `memory_usage` in `src/sys/kernel/src/xray/stats.rs` is
  `(pages_user + pages_kernel) << 12`. `sysbox ps` explicitly documents it as
  virtual memory, including lazily mapped stacks and shared mappings. The
  metric catalog exposes no per-process resident-memory or memory/thread
  high-water metric. `MemoryStats::get()` exposes system-wide physical use,
  not per-process RSS. A sampler can report observed maxima, not exact peaks.
- `ProcessInfoV1::list` explicitly allows completed processes without running
  descendants to disappear; its debug names are capped at 32 bytes. Sampling
  it cannot prove an exhaustive descendant executable/argument history.
  Existing RA invocation logs and Lorry command logging provide additional
  evidence, but are not an OS-wide execution audit. A clean snapshot must not
  be described as proof that no unobserved short-lived child existed.

U. Lasiotus directed that both OS instrumentation items be moved to
[future work](future-work.md#recorded-deliberately-not-scheduled) on
2026-09-06. They no longer block native rust-analyzer. Sections 4.10-4.13
use existing measurements and process evidence with explicit limitations;
they require neither new kernel/runtime instrumentation nor replacement of
the supported executable paths with test wrappers.

The native binary and rust-src are built and packaged, but step 23's native
LSP acceptance and step 24's developer-image gate integration remain
unfinished. The first probe and its review stop are recorded below. Keep
this document as a plan until those functional tests and
final gates pass; deferring instrumentation does not establish native
semantic acceptance. Convert it to maintained documentation only then.

### 4.23 Native probe: workspace-loading timeout and stdlib review stop

The first maintained-harness probe uses the packaged native server in a
four-vCPU, 8-GiB snapshot VM. `--version` matches the assembly manifest.
The existing LSP harness now has initial guest-text/save helpers and a
`--native NEW_EVIDENCE_DIRECTORY` entry point. Host harness tests pass;
the native probe is incomplete, uncommitted, and not wired into the gate.
No native acceptance success is claimed.

The path-only fixture is staged via SFTP, with an admitted build script,
Motor std call, non-ASCII module, and deliberate type error. No Lorry
command is invoked directly by the acceptance harness. The session reaches
sysroot discovery and Motor cfg queries but exhausts its 90-second total
bound while loading the workspace, before semantic assertions. A process
snapshot shows the native server and an exited `lorry metadata` child.
The server's sampled virtual memory is 334,512 KiB; this is neither RSS nor
a measured peak. Logs: `/tmp/motor-ra-native-first.log` and
`/tmp/motor-ra-native-first/server.stderr`; manifest/version evidence lives
in the same directory. No retry or timeout increase was used.

Separate bounded diagnostics narrow, but do not resolve, the timeout:

- Running the metadata command directly succeeds and produces 3,059 bytes
  of JSON (`/tmp/motor-ra-native-metadata-direct.log`). This diagnostic is
  not counted as acceptance coverage.
- A temporary Motor binary using the exact published portable reader also
  drains that command's stdout/stderr and exits successfully
  (`/tmp/motor-ra-streaming-probe.log`). Thus a simple two-pipe reproduction
  does not explain the full server's failure.
- The server's command logs contain blank commands. Source inspection and
  `/tmp/motor-ra-pipe-lifetime-probe.log` confirm that Motor's existing
  `std::sys::process::Command` debug formatter returns `Ok(())` without
  writing anything. This blocks the planned invocation-log assertions;
  it is not established as the cause of the timeout.

Root `AGENTS.md` requires review of pre-existing bugs and stdlib changes.
No OS, stdlib, `moto-rt`, or fork source was edited. The snapshot VM was
shut down and host evidence retained; no failed work was committed.

**Review requested:** approve fixing the empty command debug formatter in
the existing `moturus/rust` fork's
`library/std/src/sys/process/motor.rs` (with focused formatting tests),
and continuing diagnosis of the native workspace-loading hang. Any runtime
or additional stdlib fix discovered during that diagnosis still requires
its own concrete proposal before implementation. Steps 23-24 and final
gate/documentation conversion remain pending.

### 4.24 Diagnosed: killing an already-waited child blocks in the kernel

U. Lasiotus approved the formatter fix and continued diagnosis on 2026-09-06.
The formatter and four regression tests are now implemented only in
`../toolchain-src/rust-ra-portability/library/std/src/sys/process/motor.rs`.
Normal formatting reports program, escaped arguments, cwd, and explicit
environment changes; alternate formatting reports structured fields. It
does not enumerate inherited environment variables. All four tests fail
against the original empty formatter and pass against the replacement in
debug and optimized host checks. These checks extract the actual formatter
and tests with the actual `CommandEnv` source and a field/getter-only host
adapter; they are not native stdlib validation. Logs:
`/tmp/motor-command-debug-{before,host,host-release}.log`.
The patch remains uncommitted and is not selected by provisioning; native
validation and eventual full-suite coverage remain required. The managed
checkout, installed compiler, and packaged server are unchanged.

A diagnostic rerun of the native probe retains the 90-second bound and
captures stacks with `mdbg`. The metadata thread is blocked in this path:

```text
FetchMetadata::exec
  -> spawn_with_streaming_output
     -> JodChild::drop
        -> Child::kill -> moto_rt::process::kill -> SysCpu::OP_KILL
```

Rust-analyzer has already waited for the successful metadata command;
`JodChild::drop` then calls `kill()` and `wait()` as normal defensive cleanup.
A minimal independent Motor program reproduces the failure: `child.wait()`
returns exit code 0, then `child.kill()` never returns before the diagnostic's
10-second bound. A distinct repeated-wait probe (without kill) succeeds, so
the second wait itself is not the blocker. The earlier raw pipe-reader
diagnostic passed because it lacked `JodChild`'s kill-on-drop behavior.

Root cause: `src/sys/kernel/src/uspace/sys_cpu.rs::sys_kill_impl` always
registers a termination wait after requesting the kill. It wakes immediately
only for an unconsumed wake count. An earlier successful wait consumed that
wake; an already-exited process emits no new one. The ordinary `sys_wait_impl`
already handles this by also testing `obj.sys_object.done()`. The kill path
omits that terminal-state check. No kernel or runtime source has been edited.

Evidence: `/tmp/motor-ra-native-thread-stacks.log`,
`/tmp/motor-ra-native-stacks-ps.log`, `/tmp/motor-kill-after-wait.log`, and
`/tmp/motor-repeat-wait-v2.log`. A first attempt to upload the repeated-wait
diagnostic over the still-in-use executable was rejected; that attempt is
not evidence for repeated-wait behavior. The corrected diagnostic used a
distinct executable path. The snapshot VM is shut down, clearing its blocked
diagnostic processes; host evidence is preserved. No gate passed or commit
was made for this work, and no timeout increase or acceptance retry was used.

**Review requested:** approve the small kernel correction to make the kill
wait recognize `target_obj.sys_object.done()`, matching the ordinary wait
path, with a regression for wait-then-kill and repeated cleanup of an exited
child. This fixes the general syscall defect rather than special-casing
rust-analyzer cleanup. Run three debug and three release full-system gates
and the release developer-image gate before committing; then resume native
acceptance and the approved formatter's toolchain integration. This is a new
core-OS change and requires the explicit approval prescribed by `AGENTS.md`.

U. Lasiotus subsequently approved implementing and staging this kernel fix,
but explicitly prohibited committing it pending review. The done-state check
and `systest test-kill-after-wait` regression are staged together. The test
covers exit codes 0 and 1234, forced termination, and repeated std/native
kill-and-wait cleanup, preserving the original status. It hangs on the old
kernel and passes on the rebuilt debug and release kernels. Logs:
`/tmp/motor-kill-regression-{before,debug,release}.log`. Both image builds
and changed-file formatting checks pass. The three full-system runs per
profile and release developer-image commit gates remain outstanding; no
commit was made. Other rust-analyzer work remains unstaged pending this review.

### 4.25 Kernel validation: logging RPC stall and investigation stop

U. Lasiotus reviewed the staged kernel patch and approved continuation on
2026-09-07. Validation resumed with the same source inputs throughout:
one debug and one release `full-test.sh` run pass, including
`test_kill_after_wait`. Logs are `/tmp/motor-kill-full-debug-1.log` and
`/tmp/motor-kill-full-release-1.log`. The second debug run stalls in the
existing logging rotation test, before reaching the new kill regression.
The kernel patch remains staged and uncommitted: the required three passes
per profile and release developer-image gate are not complete.

Read-only diagnostics narrow the stall as follows:

- `systest` prints `logging::basic test PASS` at approximately 89 seconds
  after boot, then produces no further test output for more than six minutes.
  Its main-thread stack is `logging::rotation_and_space_cleanup` at
  `logging.rs:306` -> `rpc_result` -> `ClientConnection::do_rpc` ->
  `SysCpu::wait`. It is waiting for a logging reply, not in `SysCpu::kill`.
- At approximately 328 and 460 seconds, `systest-0-rotation.log` remains
  exactly 216,624 bytes, with no rotated counterpart. In the same interval,
  `kernel.log` grows from 721,852 to 850,168 bytes. SSH and filesystem reads
  remain responsive. Strobe is therefore still processing other records;
  this is not evidence of a complete logging-service deadlock.
- Strobe's writer is sampled first in a flush and later in a write, both
  while processing kernel raw records through the runtime's filesystem
  bridge. These observations do not establish a stuck flush as the cause.
  The available debugger gives no usable user stack for its running main
  thread and correctly refuses attachment to protected `sys-io`.

The existing test finishes in the first debug and release runs. The evidence
does not yet establish whether the intermittent fault is in logging IPC,
wake delivery, or another component, nor conclusively exclude an interaction
with the reviewed kernel change. Do not change production code or classify
the stall as a test-only defect without further diagnosis.

Evidence is retained in `/tmp/motor-kill-full-debug-2.log`,
`/tmp/motor-kill-debug-2-{console,systest,ps}.log`,
`/tmp/motor-kill-debug-2-systest-stacks-uploaded.log`,
`/tmp/motor-kill-debug-2-strobe-stacks-{uploaded,later}.log`, and
`/tmp/motor-kill-debug-2-log-files{,-later}.log`. The first debugger requests
used a path absent from the standard image; they are not stack evidence.
The already-built debugger was then uploaded under a unique temporary guest
path, and successful captures resumed their targets normally.

The stalled gate was deliberately terminated with status 143, not allowed
to pass and not reported as a timeout. Its VM and the sequential gate runner
have exited; no later gates ran. No retry, longer timeout, test workaround,
or production edit was made. Native LSP acceptance, formatter integration,
and documentation conversion remain pending.

**Review requested:** approve further diagnosis of this logging RPC stall.
Any production fix beyond the already-reviewed kill correction must receive
its own concrete proposal. This is the `AGENTS.md` investigation stop, not
completion of rust-analyzer or acceptance of the kernel patch's full gates.

U. Lasiotus directed continuation without investigating or fixing this stall:
leave logging/IPC unchanged and validate the native rust-analyzer work. This
overrides the investigation stop for this recorded issue, not other stop
conditions. Preserve the interrupted run as non-passing evidence; do not
silently skip a test or change a timeout. Resume native acceptance on the
reviewed kernel and complete the remaining applicable validation separately.

### 4.26 Native semantic progress on the reviewed kernel

The rebuilt release developer image gets past the old metadata-child cleanup
hang. The first probes expose two mistakes in the new test fixture, not new
production defects: a deliberate type error during startup makes the startup
build-script check unsuccessful, and an out-of-line non-ASCII Rust module
requires an explicit `#[path = "café.rs"]`. The fixture now starts valid,
uses that explicit path, and introduces its deliberate type error by saving
an edit after startup. No production source or test deadline changed.

The single-project semantic/save case passes on the packaged native server:

- manifest-matched version, initialization, healthy/quiescent workspace, and
  completed startup flycheck;
- go-to-definition into Motor std, hover resolving generated integer `42`,
  and a non-ASCII file URI resolving to the staged module;
- a rustc error after saving the deliberately invalid edit, then cleared
  diagnostics after saving the correction; and
- orderly LSP shutdown, EOF, and child exit within the 90-second case bound.

Recorded times are 107.4 ms to initialize, 17.713 s to quiescence, and 2.113 s
for the saved-error check. Evidence:
`/tmp/motor-ra-native-explicit-unicode-path.log` and the matching directory.
These are initial functional measurements, not approved regression limits
or a complete step 23 result.

The extended two-`linkedProjects` case reaches healthy quiescence in 25.425 s
but times out at the unchanged 90-second bound. A separately instrumented,
bounded diagnostic reaches quiescence in 25.218 s and identifies the pending
request as `textDocument/hover` at `ENVIRONMENT`: an extra assertion asking
for the value of an `env!`-generated string constant. The required generated
integer hover and generated definition finish before this request. A worker
stack is actively in `handle_hover` and syntax/AST analysis; this is not the
earlier child-cleanup wait. No panic or complete-server deadlock is established.
The failed cases remain non-passing evidence, not retries counted as gates.

Evidence: `/tmp/motor-ra-native-multiroot.log`,
`/tmp/motor-ra-native-request-diagnostic.log`, their matching directories,
and `/tmp/motor-ra-native-request-{ps,stacks}.log`. The startup process
snapshot reports 466,112 KiB virtual memory and 19 active server threads;
neither is a peak or RSS measurement. Completion and the second project's
generated-definition assertion follow the expensive string hover and have
not yet been reached by this extended native case.

The WIP harness also gains a bounded Motor-only resource sampler using
existing `moto-sys`/`moto-stats` interfaces, not new OS instrumentation. It
samples at 100 ms plus collection overhead, retains at most 32,768 process
rows, and uses stdin EOF for orderly stop. Reports retain raw timestamps,
virtual bytes, active threads, truncated process identities, and whole-VM
physical bytes. A process disappearing between enumeration and query is
recorded with missing measurements. Host summary tests cover observed
ancestry, exclusion of unrelated processes, maxima, gaps, and missing data.
The native sampler's standalone lifecycle test passes; its report contains
six samples. Logs: `/tmp/motor-ra-resource-sampler-{frames,stderr}.log` and
`/tmp/motor-ra-resource-summary-tests.log`. Integration with a complete
passing native LSP case and the developer gate is still pending.

### 4.27 Approved formatter: actual Motor stdlib validation

The formatter still lives only in
`../toolchain-src/rust-ra-portability/library/std/src/sys/process/motor.rs`.
An isolated authoring-toolchain build completed for dirty source digest
`7a2b40efe32ef889921a1baef4f793a766dab648895dd77a76f9df1371584176`,
toolchain key
`2a8ef6828d084699a76f2321cdc2f3dd1355107795ae3e00cf34b2845f8ee1a3`.
It does not select an assembly or change the repository's selected compiler.
The build first required authoring-worktree setup: six local submodule
copies at the existing gitlink commits, plus `rust-lang` remote aliases.
Rust's alias is shared Git metadata with the managed worktree; managed
tracked source files and revisions are unchanged. No new fork was created.

The completed stage1 compiler and matching newly built Motor stdlib run
the public `std::process::Command` regressions in
`src/tests/rust-analyzer-smoke/fixtures/command-debug.rs` successfully in the
guest: all four tests pass in both unoptimized and optimized test binaries.
The same public regression binary against the selected old Motor stdlib
fails with exit 255 (not a timeout). Unlike the earlier host adapter checks,
these successful runs exercise the actual native stdlib formatter through
the public API. Logs: `/tmp/motor-command-debug-native-{before,after,optimized}.log`.

The complete authoring prefix passed the existing installation, source/lock,
component, and manifest validation and was registered without selecting it.
The build completed successfully in 22 minutes 10 seconds; its log is
`/tmp/motor-command-debug-authoring-host.log`. The fork patch is uncommitted,
and no packaged rust-analyzer has yet been rebuilt against this stdlib.
Maintained formatter-test wiring, keyed integration, final native invocation-log
assertions, and resource limits are still required. The kernel/developer gates
subsequently passed (section 4.28). Both initial diagnostic snapshot VMs shut
down normally with exit 33.

A separate diagnostic native server build uses that accepted authoring
prefix, the unchanged selected assembly's libc linker/sysroot, the pinned
patched-crate configuration, and a fresh target directory
`/tmp/motor-ra-command-debug-diagnostic`. Its locked, offline Cargo build
completed in 8 minutes 43 seconds, limited to two jobs while the kernel gates
ran; the log is
`/tmp/motor-ra-command-debug-diagnostic-build.log`. This is not an accepted
assembly or a replacement for the required keyed integration: no selected
prefix, assembly, or packaged binary is overwritten.
Both the unstripped executable and `/tmp/motor-ra-command-debug-native`
pass the existing native ELF and embedded-identity validator. The stripped
diagnostic executable's SHA-256 is
`c154078e1c5cb73e11e23d7bea6325ccf6bc710993ad6f810e924459de24ac83`.
Guest execution of this new server subsequently passed the focused diagnostic
in section 4.29; it remains separate from packaged-server acceptance.
The same isolated compiler/build tree also compiled `stdx`'s native unit-test
binary with locked, offline Cargo (`--no-run`), without source changes.
`/tmp/motor-ra-stdx-native-test-build.log` records that build. Its bounded
dual-pipe capacity and EOF-order tests both passed on Motor OS:
`/tmp/motor-ra-stdx-native-tests.log` (one test executed in each focused run).

### 4.28 Validation resumed after the logging/IPC exclusion

The unchanged reviewed kernel patch passed the second release main-image
gate (`/tmp/motor-kill-resumed-release-2.log`), including logging rotation
and the kill-after-wait regression. The first debug and release passes remain
in `/tmp/motor-kill-full-{debug,release}-1.log`. The interrupted second debug
run remains a failure, not a pass. The resumed debug run also passed
(`/tmp/motor-kill-resumed-debug-3.log`), including logging rotation and the
kill-after-wait regression. The third release run passed as well
(`/tmp/motor-kill-resumed-release-3.log`). The final debug run passed
(`/tmp/motor-kill-resumed-debug-4.log`), completing three full passes in each
main-image profile. The complete `full-test-dev.sh --release` gate passed:
its developer-image repository suite, native developer-source builds, and
Lorry product suite. The combined log is
`/tmp/motor-kill-resumed-dev-release.log`; Lorry's native self-build took
530.070 seconds and its complete product suite took 929 seconds.
The reviewed kernel fix and regression tests are committed as `cbb9e15b`.
No retry, timeout change, or logging-test exclusion was added.

The current host rust-analyzer acceptance suite and host/native-sampler
Clippy checks pass without new warnings:
`/tmp/motor-ra-current-host-acceptance.log`,
`/tmp/motor-ra-host-clippy.log`, and `/tmp/motor-ra-sampler-clippy.log`.
The source snapshot stayed unchanged throughout these gates; only
documentation of completed results was updated. The unfinished native
acceptance harness and external formatter remain separate from that commit.

### 4.29 Post-gate native diagnostics

A fresh 8 GiB, four-CPU developer-image snapshot ran the separately named
diagnostic server `/devtools/tmp/ra-command-debug`. Its runtime version is
`rust-analyzer 1.99.0-dev (d454849e203 2026-09-05)`; the selected packaged
server and assembly were not overwritten. A temporary driver under
`/tmp/motor-ra-invocations.ZFTCoD` reuses the existing `SemanticCase` and LSP
transport. It independently checks command logging, completion, and multi-root
navigation; it does not replace or reorder the failing string-hover assertion
in the maintained WIP native case.

The focused probe passed within its 90-second bound:

- both linked projects reached healthy quiescence and completed startup
  flychecks at 25.309 seconds;
- completion returned `GENERATED` and `ENVIRONMENT` at 25.311 seconds;
- the second project's definition resolved into its own generated output at
  25.312 seconds;
- shutdown, exit, EOF, and successful child status completed at 38.824 seconds;
- command logs contain program/arguments, cwd, metadata/check calls, and the
  direct sysroot query. The only discovery warnings are the explicitly
  accepted Cargo-config rejection and Lorry-version parse warning.

Evidence: `/tmp/motor-ra-command-debug-probe.log` and
`/tmp/motor-ra-command-debug-probe-evidence/`. The post-probe process snapshot
contains no remaining analyzer or compiler descendants
(`/tmp/motor-ra-command-debug-post-probe.log`); this is a cleanup observation,
not an execution audit. The diagnostic VM shut down normally with exit 33.

The existing sampler and host summary code also processed real analyzer
processes successfully. Its independent 45-second window contains 446 samples,
a maximum observed gap of 134.302 ms, 203 observed analyzer/descendant process
identities, and one process that disappeared before its metric query.

| Diagnostic sampled maximum | Observed value |
|---|---:|
| Analyzer virtual memory | 910,647,296 bytes (868.46 MiB) |
| Analyzer active threads | 26 |
| Descendant `lorry check` virtual memory | 27,037,696 bytes (25.79 MiB) |
| Descendant `lorry check` active threads | 8 |
| Whole-VM physical memory | 1,284,055,040 bytes (1,224.57 MiB) |

These are **not acceptance thresholds or complete-lifetime peaks**. The server
first appears at sampler time 17.172 seconds and is still active at the last
sample, 44.982 seconds: the window covers loading and the semantic probes,
but not all of shutdown. The fixture also omits the full acceptance case's
save/error/fix sequence and string hover. Per-process values are virtual
memory, not RSS. Raw frames and summary remain in
`/tmp/motor-ra-diagnostic-resource-{frames.log,summary.json}`. The complete
passing acceptance case must supply the baseline before numeric limits are
chosen. The stripped diagnostic server is 29,252,208 bytes; image-growth
measurement and final keyed publication remain pending.

### 4.30 Work queue: investigate the hover timeout last

U. Lasiotus directed that the `env!`-derived string hover be queued behind all
remaining rust-analyzer steps. Temporarily remove that extra assertion from
the native acceptance case, keep the existing 90-second bound and failed
evidence, and proceed with the other work. Once this is the only remaining
item, investigate it; it is not being moved out of Stage 2 or considered fixed.

The pending hover concerns `pub const ENVIRONMENT: &str =
env!("GENERATED_ENV")`, whose expected value is `"from-build-script"`.
Healthy workspace loading took about 25 seconds; earlier integer-hover and
definition requests succeeded, but this request remained pending at the
90-second **whole-case** deadline. The captured worker was in hover/syntax
analysis, not the previously fixed child-cleanup wait. A completed hover
duration, root cause, and Linux comparison have not been established.

Before this investigation, retain the planned generated-integer hover,
build-script compilation/configuration checks, completion, definition,
save/error/fix, multi-root, invocation, and resource coverage. The first
complete native baseline still requires the existing regression-limit review
before final test-gate integration. No other review stop is waived.

### 4.31 Complete native baseline with the queued hover omitted

The maintained native case now passes against the selected, packaged server
in a fresh release developer-image snapshot with four CPUs and 8192 MiB.
Only the extra `env!`-derived string-hover assertion was removed. Generated
integer hover, Motor std definition, generated-source definitions in both
linked projects, completion, Unicode paths, save/error/fix diagnostics, and
shutdown/exit/EOF/status checks all pass under the unchanged 90-second total
deadline. This does not resolve the queued hover issue.

The harness saves phase timings to `timings.json`, including completed
measurements if a later semantic assertion fails. The sampler starts before
the server and stops after successful server exit, taking a final observation
when its stdin closes. The first and last observations in this run contain
no analyzer process. Sampling covers the case's lifecycle, but can still miss
short-lived processes and between-sample peaks; it is not an execution audit.

| Measurement | Observed value |
|---|---:|
| Initialize response | 75.4 ms |
| Healthy quiescence and both startup flychecks, from launch | 25.952 s |
| First completion response after workspace loading | 0.812 ms |
| Rustc error diagnostic after save | 2.171 s |
| Rustc diagnostic cleared after corrective save | 2.175 s |
| Shutdown request through successful process exit | 13.631 s |
| Total, including staging and resource collection | 45.079 s |
| Analyzer sampled virtual memory / active threads | 910,696,448 bytes (868.51 MiB) / 26 |
| Descendant `lorry check` sampled virtual memory / active threads | 27,041,792 bytes (25.79 MiB) / 8 |
| Whole-VM sampled physical memory | 1,365,135,360 bytes (1,301.89 MiB) |
| Samples / nominal interval / maximum observed gap | 436 / 100 ms / 135.592 ms |
| Missing process measurements | 0 |

Evidence is `/tmp/motor-ra-complete-baseline.log` and
`/tmp/motor-ra-complete-baseline/`, including the assembly manifest, version,
stderr, raw resource report, summary, and timings. The preceding passing run
is preserved in `/tmp/motor-ra-queued-hover-acceptance{.log,/}`; it used the
same semantic assertions but did not yet save every timing or explicitly
take a post-exit sample. Neither run is a retry of the omitted hover failure.

The selected stripped server is 29,237,496 bytes (27.88 MiB). Its rust-src
overlay contains 3,608 regular files totaling 71,949,277 bytes (68.62 MiB).
Fresh, otherwise identical release developer images measure 445,251,584 bytes
without the analyzer overlay and 566,493,184 bytes with it: **121,241,600 bytes
(115.625 MiB) of qcow2 file-length growth**, including filesystem overhead.
Both retain the same 4,297,928,192-byte virtual disk capacity. This compares
fresh images, not a guest-mutated image against a fresh one.

Measurement configs/logs are under `/tmp/motor-ra-image-growth.yHrCAM/`;
images are `vm_images/release/ra-image-growth-yHrCAM-{with,without}.qcow2`.
The first diagnostic config incorrectly requested publication across the
workspace-to-`/tmp` filesystem boundary: the imager built the baseline but
its atomic rename failed with `EXDEV`. The completed qcow2 was validated and
moved within the workspace; the comparison config uses a distinct filename
on that same filesystem. No imager code, selected image, or failure handling
was changed.

Host harness tests pass (14 unit, four process, two session tests); the native
sampler builds, and host/sampler Clippy passes with warnings denied. Logs are
`/tmp/motor-ra-baseline-{host-tests,host-build,sampler-build,host-clippy,sampler-clippy}.log`.
These component checks are not a claim that the new native case is already
wired into `full-test-dev.sh`. No new commit is made at this review point.

The selected packaged server still uses the old stdlib formatter. The approved
formatter's separate native tests and diagnostic invocation probe passed
(sections 4.27–4.29); clean keyed integration and maintained invocation-log
assertions remain to be completed. Repeat the acceptance measurements against
that final packaged artifact before declaring the integration complete.

### 4.32 Approved initial regression limits

Step 23 calls for review of the first native results before step 24 wires the
final gate. U. Lasiotus approved the limits below and continuation. They
are initial regression guardrails for this fixture and VM configuration, not
production capacity guarantees or a reason to optimize memory in Stage 2.

| Measurement | Approved upper limit |
|---|---:|
| Whole native case | Existing 90 seconds; unchanged |
| Analyzer sampled virtual memory / active threads | 2 GiB / 32 |
| Individual descendant `lorry check` sampled virtual memory / active threads | 64 MiB / 16 |
| Whole-VM sampled physical memory | 3 GiB |
| Stripped server | 32 MiB |
| rust-src regular-file bytes | 80 MiB |
| Fresh qcow2 growth attributable to the analyzer overlay | 128 MiB |

For simplicity, keep individual phase timings and sampling gaps as recorded
measurements rather than adding more timeout assertions. Memory limits allow
roughly twice the observed usage; size limits allow smaller, explicit growth
above the pinned source/artifact baseline. A future limit failure requires
diagnosis and review, not a retry, worker cap, or automatic threshold increase.
The final keyed artifact must be measured against these limits before it is
accepted as the baseline. An initial result requiring more of the approved
8 GiB VM is still a review result, not a demand for memory optimization.

**Approved:** enforce these limits, retaining measurement-only phase timings.
Finish keyed formatter integration, invocation assertions, developer-gate
wiring, and the remaining release validation. Keep section 4.30's hover
investigation last.

### 4.33 Formatter publication and invocation coverage

U. Lasiotus dropped the additional tracing patch and published only
`75940756edd423d88ba353ce720770f3061b285a` to the existing
`moturus/rust` branch. A read-only remote check confirms that revision on
`refs/heads/motor-os-1.99.0-beta-f47d5bb`; the authoring worktree is clean.
The selected source tuple now names this formatter-only revision. It changes
`library/std/src/sys/process/motor.rs`, including four focused tests.
No additional rust-analyzer query-logging patch is selected.

**Approved simplification:** exact invocation arguments remain covered by the
Linux Lorry acceptance contract. Native acceptance proves workspace loading,
build-script cfg/environment/output data, multi-root semantics, completion,
save diagnostics, and successful shutdown. It retains stderr and rejects
unexpected errors and query-fallback warnings, but does not require an exact
set of debug-formatted command lines. This intentionally gives up exact native
argv-log coverage; sampled processes and logs are not an exhaustive audit.
The tracing-dependent native checker has been removed, not bypassed.

Local gate integration includes approved resource and size limits, sampled
descendant classification, the native semantic case under the developer-image
branch, public native formatter tests, and the 8192/4096 MiB wrapper defaults
with their explicit-override contract. Before the simplification, host harness
tests, host/native-sampler Clippy, wrapper/size contracts, and the fresh-image
size gate passed. The old selected artifact measured 29,237,496 binary bytes,
71,949,277 rust-src bytes, and 121,241,600 bytes of qcow2 growth
(`build/ra-image-growth.IvA5Rr/`). The simplified tests and final selected
artifact require fresh validation.

The discarded trace patch's diagnostic build/probe remain historical evidence
in `/tmp/motor-ra-query-logging-{build,probe}.log` and
`/tmp/motor-ra-query-logging-evidence/`. They are not evidence for the final
formatter-only assembly and do not justify restoring that patch.

A clean managed formatter-only toolchain/assembly build passed; its log is
`/tmp/motor-ra-formatter-managed-build.log`. The host build completed in
20 minutes 25 seconds and its installation/identity checks passed. The new
host key is `50df587e90f781a28d420f9b5e47135ea78508dd83bdac9f487a410fcd330500`;
the accepted managed/clean native assembly is
`bb0c6cf93e6c036368ff6eaaf738067f16a8eabeb62bb79595b0b2386d2c53d5`.
The fork/source tests, host LSP acceptance, and host/native-sampler Clippy
pass against the validated new prefix. Their logs are
`/tmp/motor-ra-final-{host-sources,host-acceptance,host-clippy,sampler-clippy}.log`.
Native rustc, rust-analyzer, assembly validation, and all three release images
passed; the complete build took 3785.08 seconds. The root selector now names
the new toolchain and its matching assembly is pinned. Validate the packaged
server and resource limits, and run the
final debug/release main-image and release developer-image gates. Commit the
Motor OS integration in small patches only after those gates. Keep the hover
issue last; do not replace the final artifact with a diagnostic executable.

The final packaged formatter-only artifact passed the offline patched `url`/
`inventory` tests, all four public native formatter tests, and the maintained
native semantic/resource case in a fresh four-CPU, 8192 MiB release snapshot.
Logs are `/tmp/motor-ra-final-native-{crates,acceptance}.log`; native evidence
is `/tmp/motor-ra-native.14I2YY/case/`. Total time was 44.985 seconds, with
25.627-second workspace readiness, 1.362 ms completion, 2.018-second error
save, 2.031-second corrective save, and 14.252-second shutdown. Sampled
maxima were 910,475,264 virtual bytes / 26 threads for the analyzer,
27,025,408 virtual bytes / eight threads for an individual `lorry check`, and
1,393,139,712 physical bytes for the whole VM. All approved resource limits
passed; 436 observations had no missing process measurements and a maximum
131.354 ms sampling gap. The queued string-hover assertion remains omitted.
Final full-suite and fresh-image-size validation are still pending.

### 4.34 Final debug gate: local TCP reply/reset stop

The final `src/tests/full-test.sh` debug gate failed, not timed out. Evidence
is `/tmp/motor-ra-final-main-debug.log`. Host analyzer/source tests, terminal
and TUI checks, logging protocol/basic/rotation checks, memory-pressure tests,
filesystem tests, and the async-runtime tests passed before the failure.
The previously excluded logging/IPC stall did not recur in this run.

`test_mio_accept_pump_progress` failed on its second peer in the normal
(`poison_rearm = false`) case. The parent accepted the connection, read the
four-byte `ping`, returned successfully from `write_all(b"pong")`, and
dropped the stream. The peer then panicked at
`src/sys/tests/systest/src/poll.rs:147` because `read_exact` returned
`ConnectionReset`; the parent subsequently failed its child-success assertion
at line 191. Both connections are loopback-only (`127.0.0.1`). This is neither
the test's accept-pump readiness timeout nor an Internet/DNS failure.

The failing test predates this work (`3da0bb44`); no `src/sys` files are
modified by the current integration. Read-only inspection localizes the
symptom to reply delivery during TCP write/close teardown, but does not prove
the exact race or its originating component. The client destructor explicitly
intends to queue pending writes before close, and the sys-io close path has
abort decisions; further focused diagnosis is needed to distinguish them.
Do not call this an obvious test-only defect or mask it with a delay/retry.

This triggers the `AGENTS.md` preexisting-bug stop, separately from the user's
logging/IPC exclusion. No retry, production fix, release gate, or integration
commit was made after this failure. The gate shut down its VM. Resume only
after review of whether to investigate/fix this local TCP issue or explicitly
exclude it; the final release/developer gates and last-in-queue hover work
remain outstanding. Native analyzer component acceptance above remains valid,
but the full integration is not yet gated or complete.

### 4.35 Validation resumed after the TCP-fix rebase

U. Lasiotus rebased the branch and approved resuming full validation, with
diagnosis and trivial fixes allowed for further test failures. The rebased
HEAD is `12ca4000`; the existing TCP fix is `dc37ef4b` (including regression
tests). It preserves accepted queued writes when last-socket channel teardown
overtakes TX drain, under the existing orphan-linger cap and deadline. This
matches the prior failure's write/drop/reset symptom; the resumed full gate
must establish whether it resolves that observed failure.

The formatter-only toolchain selector and native integration changes survived
the rebase. No new core changes are being made. Run fresh debug/release
main-image gates and the release-only developer-image gate on this source
snapshot; keep the failed pre-rebase evidence above. The resumed debug log is
`/tmp/motor-ra-rebased-main-debug.log`. The queued hover remains last.

The resumed debug main-image gate passed completely, including
`test_mio_accept_pump_progress`, `systest`, mio, and Tokio. The pre-rebase TCP
failure did not recur. Formatting and host/native-sampler Clippy also pass
with warnings denied (`/tmp/motor-ra-rebased-{host,sampler}-clippy.log`).
Release main-image validation (`/tmp/motor-ra-rebased-main-release.log`)
reached the unchanged 900-second outer deadline without an earlier assertion
failure. The run included cold release builds; host netstack-test compilation
alone took two minutes. Terminal tests and system checks progressed, and the
previously failing accept-pump test passed before timeout interrupted the
remaining poll tests. This is an incomplete gate, not a pass. The subsequent
SSH cleanup error occurred during timeout teardown.

No timeout or failure handling was changed. Approval was requested for one
fresh main-release run with the now-built artifacts and the same deadline;
retain the cold-run failure regardless of that result. The independently
required release developer-image gate is running in
`/tmp/motor-ra-rebased-dev-release.log`, not substituted for the missing
main-release pass.

The developer gate also reached its unchanged 900-second repository-suite
deadline, after cold developer-tool builds. It was still progressing through
system tests and had no preceding assertion failure. Its subsequent native
source-build and Lorry product-suite phases did not run. Do not report
`full-test-dev.sh --release` as passed or commit the integration yet.

Before that interruption, the developer gate passed the final artifact size
check, patched-crate/native formatter tests, and native semantic/resource
acceptance on the rebased OS. Size evidence is `build/ra-image-growth.X35xQo/`:
29,245,528 binary bytes, 71,952,945 rust-src bytes, and 121,569,280 bytes of
fresh qcow2 growth (444,989,440 without; 566,558,720 with). All approved caps
passed. Native evidence is `/tmp/motor-ra-native.D0RLqC/case/`: 43.688 seconds
total, 24.962-second readiness, 1.299 ms completion, 2.007/1.977-second
error/fix saves, and 13.681-second shutdown. Sampled maxima were 910,700,544
analyzer virtual bytes / 26 threads, 27,025,408 `lorry check` virtual bytes /
eight threads, and 1,385,070,592 whole-VM physical bytes; 425 observations,
no missing measurements, maximum gap 130.114 ms. The extra string hover is
still deliberately queued last.

Both release gates now need fresh complete runs. Request approval to run
them with the built artifacts and the existing deadlines, preserving both
cold-build timeout logs. No retries, larger timeouts, skipped tests, or new
code fixes have been applied to obtain a passing result. Changing the gate's
build/time-budget policy is not an obvious test-only correction and requires
review instead of an incidental change in this integration.

U. Lasiotus approved fresh runs of both release gates with the now-built
artifacts and unchanged tests/deadlines. The approved main-image run is
`/tmp/motor-ra-rebased-main-release-warm.log`; preserve both earlier timeout
logs as incomplete cold-build results. Run the developer gate sequentially
after the main-image VM exits.

The approved warm main-release run passed completely, including the TCP
teardown and accept-pump regressions, `systest`, mio, and Tokio. Debug and
release main-image gates now both pass on the rebased source snapshot.
The approved release developer-image run is in
`/tmp/motor-ra-rebased-dev-release-warm.log` and remains pending.

The approved warm developer repository phase also reached 900 seconds.
Native analyzer, formatter/patched-crate, size/resource checks, and all of
`systest` passed; timeout interrupted mio's TCP-listener tests. No preceding
assertion failed. This is not a complete developer gate, and no further retry
or deadline change is authorized by the one-run approval.

Timing from retained file creation/modification timestamps: main-release
completed in about 555 seconds (11:51:15–12:00:30 local on 2026-09-08).
Developer validation started at 12:00:44, reached native acceptance at
12:11:07 (about 624 seconds), and completed that case at 12:11:53. This left
under four minutes for the remaining system/application/mio/Tokio checks.
The actual two-image construction portion of the size check took 15.4 seconds
(12:05:24–12:05:40), excluding its preceding assembly resolution. Existing
repeated content validation adds prelude cost (section 4.21); this warm result
must not be attributed solely to cold compilation. Optimizing that work or
changing the gate's phase/budget policy requires a concrete reviewed change,
not dropped integrity checks or another hope-for-a-pass run.

Run the still-unexecuted release developer-source and Lorry product phases
independently to complete their component evidence, with their existing
limits. Logs are `/tmp/motor-ra-rebased-dev-sources-release.log` and
`/tmp/motor-ra-rebased-lorry-product.log`. Their results do not substitute for
the incomplete developer repository gate. No integration commit yet; the
queued string-hover remains last.

The separately run release developer-source phase passed, including packaged
source checks and native gears/Lorry builds. The complete Lorry product suite
also passed in 1156 seconds, including its 541.139-second native self-build
gate. All separately run component phases pass, but the complete developer
repository phase still needs a successful bounded run; no integration commit
was made. For review, prefer investigating a faster byte-identical content
serializer before changing gate budgets: the current serializer invokes
`wc` and `cat` separately per file, repeatedly across assembly validation.
Any replacement must preserve path ordering, file/symlink handling, mode and
content bytes, error propagation, and the existing digest format; bootstrap
availability also needs an explicit design. No serializer implementation or
gate-budget change is authorized or applied at this stop.

### 4.36 Approved byte-compatible serializer optimization

U. Lasiotus approved optimizing file-tree hashing without changing checks,
digest values, or deadlines. Keep the existing `find`/NUL-sort enumeration
and shell executable-access checks. Pass NUL-delimited path/kind/mode records
to a dependency-free Rust helper that streams the identical length-prefixed
content fields. Compile it afresh in the digest call's private temporary
directory: no persistent executable cache or new toolchain identity input.
Before an installed selected Rust compiler is available, retain the original
shell serialization for bootstrap. Once available, compilation/serialization
errors are fatal, not fallback triggers. This is host-only work in the main
repository, with no native runtime or external-fork changes.

Compare fast and original output/digests on binary data, unusual filenames,
symlinks, executable modes, overlapping roots, and rejected inputs; include
the checks transitively in `full-test.sh`. Benchmark the selected rust-src
and Helix trees and validate the unchanged assembly identity. Then rerun the
release developer gate with its existing deadlines. Keep hover investigation
last and retain all previous timeout evidence.

The implementation passes byte-level compatibility, binary/non-UTF-8/Unicode
path, symlink, mode, overlap, compiler-failure, unreadable/missing/special-file
checks and Rust Clippy with warnings denied. An existing conditional-call
error-propagation bug was exposed: failed enumeration could fall through to
a digest when Bash `errexit` was disabled by an `if` caller. Explicitly check
the enumeration pipeline (and content writes); both fast and bootstrap paths
now reject those inputs. This is a small host-tool correctness fix, not a
weakened test. Assembly, selection, patched-crate, native, and analyzer-identity
contract tests pass.

Selected-tree measurements (`/tmp/motor-tree-serializer-benchmark.log`) retain
exactly identical SHA-256 values: rust-src 36.324 seconds to 1.386 seconds;
Helix 9.437 seconds to 0.643 seconds, including helper compilation. No content
digest or assembly key changes. The final compatibility log is
`/tmp/motor-tree-serializer-final-contract.log`; selected-assembly validation
is `/tmp/motor-tree-serializer-selected-assembly.log`. Proceed with the
unchanged release developer gate on this implementation before committing.

The optimized developer repository phase passed completely under the original
900-second deadline, including native acceptance and all system/mio/Tokio
tests. Evidence is `/tmp/motor-tree-serializer-dev-release.log`; native-case
evidence is `/tmp/motor-ra-native.yStJE5/case/`. The full developer gate is
continuing through its source-build and Lorry product phases. No timeout,
integrity-check, or test-coverage relaxation was needed.

The complete `src/tests/full-test-dev.sh --release` run passed, including
developer-source builds and the full Lorry product suite (887 seconds for
the product suite; native self-build 537.851 seconds). All original bounds
remain unchanged. This closes the developer-gate budget blocker. Commit the
serializer and previously gated native integration in reviewable patches,
then investigate the final queued hover issue.

The gated implementation is committed: `cac39325` (serializer), `6668c580`
(published formatter selection), `8a42abea` (LSP document/save helpers),
`6c47e5c6` / `39b2f5c4` (resource checks/sampler), `d757e460` (image and VM
contracts), and `2f361e7d` (native acceptance). The native acceptance patch is
one intentionally larger atomic change so its SSH transport, semantic
assertions, CLI, and full-gate entry point compile and run together. All other
code patches are small; the sampler's 309-line diff includes 167 generated
lockfile lines. No tracing patch or external source changes were added.
Step 24 is complete. Step 25, the string-hover diagnosis, was the last
implementation item; §4.37 records its resolution.

### 4.37 String-hover investigation: allocator scalability review stop

See [the Frusa scalability plan](frusa.md) for the investigation evidence,
optimization proposal, validation requirements, and decisions awaiting review.

Resolved on 2026-09-09: the runtime now uses `frusa_v2`, and the queued
`env!`-derived string-hover assertion is restored in the native case, where
the hover completes in 920 ms; see frusa.md §10.

### 4.38 Native Helix integration

Completed on 2026-09-10. The developer image configures Helix to run the native
server through Lorry and includes `/devtools/src/helix-rust-demo`. Actual editor
acceptance proves hover, local and Motor std navigation, completion, compiler
diagnostics on save, clearing, and shutdown. The complete release developer
gate passes, including native analyzer acceptance, developer-source builds,
and the full Lorry product suite. The necessary runtime child-pipe fix passed
three debug and three release main-image gates before commit.

See the [integration record](helix-rust-analyzer.md) for patches, evidence,
continued stop conditions, and the earlier unresolved sys-io abort. Native
rustfmt remains uninstalled, and Rust automatic formatting is disabled.
