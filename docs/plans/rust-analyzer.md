# rust-analyzer for Motor OS development

Stage 1 is complete. Section 3 is maintained documentation for the supported
Linux-host service; it contains no remaining implementation plan. Section 4
is the implementation plan for a native Motor OS rust-analyzer. It was
reviewed against the selected Motor Rust tree, the Lorry sources, and the
imager configuration on 2026-09-02, and its design questions were answered
the same day in section 4.14. On 2026-09-02 U. Lasiotus expanded the scope to
include Cargo-compatible `lorry metadata`, `lorry tree`, and
`lorry check --message-format=json`; section 4 reflects that scope. It is
ready to implement. Stage 2 implementation is in progress: Lorry prerequisite
patches 1-10 in section 4.12 are complete and gated. `lorry metadata` is
implemented; `lorry check`, `lorry tree`, and native rust-analyzer work have not
started. The completed
Lorry work makes `lorry vendor` keep every input `Cargo.toml` immutable and
removes Lorry's unused required-patch feature, which U. Lasiotus authorized on
2026-09-02.

## 0. Status and architecture

Both stages are required:

| Stage | Server host | Analyzed targets | Status |
|---|---|---|---|
| 1. Host | Linux | Motor and Linux host | Complete and gated |
| 2. Guest | Motor OS | Motor only | In progress; Lorry patches 1-10 complete |

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
  exact-revision Motor forks only for `url` and `inventory`;
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
- the locked `url` and `inventory` packages use minimal Motor forks pinned to
  full Git revisions by the standalone rust-analyzer workspace and its
  lockfile;
- `dirs` is not forked: rust-analyzer does not compile it for Motor; and
- no source is patched in place under a managed checkout, copied from `/tmp`,
  or fetched by a regular test.

This explicitly requires changes outside the Motor OS repository: the Motor
Rust fork and the exact Motor forks of `url` and `inventory`. A human creates
the fork repositories. The changes are reviewed and landed there first, then
selected by full revisions here. No Stage 2 change to `src/sys`, Rust std,
`moto-rt`, or mlibc is planned; finding that one is necessary is a
design-review stop.

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
  fork declarations, including dirty authoring state through the existing
  source digest; and
- record the final version string, binary SHA-256, standalone lock SHA-256,
  rust-src tree digest, external fork revisions, and native recipe version in
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
| File URIs | In the exact `url` fork, add Motor to its slash-rooted file-path implementation without making `cfg(unix)` true. Preserve the crate's existing authority, absoluteness, percent-encoding, and UTF-8 rules. | Fork unit tests round-trip root, spaces, `%`, `#`, and non-ASCII names and exercise the crate's existing negative cases; the guest semantic test opens a non-ASCII path. |
| Salsa registration | In the exact `inventory` fork, emit Motor constructor pointers in `.init_array`. Link rust-analyzer through the assembly wrapper so mlibc startup walks the array. Do not add constructor walking to Rust startup. | A small native inventory fixture observes more than one registration; ELF validation requires nonempty `.init_array`; the LSP database reaches quiescence. |
| Allocator and workers | Leave optional jemalloc/mimalloc features off. Verify `num_cpus` against Motor's standard-library result and use an explicit native default worker count only if the 8 GiB measurements require it. | Record available CPUs, rust-analyzer threads, and peak memory; a worker cap needs its own measured justification. |
| Filesystem changes | Keep the upstream client-watcher mode, which is already the default. Do not add a polling watcher or port a host notify backend. | Project load performs no periodic filesystem scan or watcher child process; standard `didOpen`/`didChange`/`didSave` drive the semantic test. |

The pipe channel bounds queued chunks, not total command output. Existing
rust-analyzer callers still own their final output buffers.

### 4.5 Native build and development-image layout

Build after the final host compiler, Motor std, assembly sysroot, and
`motor-rust-cc` wrapper have validated. Use the installed keyed Linux-host
Cargo and rustc to cross-compile; do not try to run the Motor-host rustc on
Linux and do not invoke `x.py` again.

The recipe is equivalent to:

```sh
RUSTC="$TOOLCHAIN_PREFIX/bin/rustc" \
CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/rust-analyzer" \
CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$ASSEMBLY_SYSROOT/bin/motor-rust-cc" \
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
rust-analyzer. The two codegen flags are required: selecting the linker alone
does not opt a Rust binary into mlibc startup. Without them the binary uses
the pure-Rust `motor_start`, `.init_array` is not walked, and Salsa's
`inventory` registrations are absent at runtime.

The implementation must use argument arrays/environment assignments already
available to the build shell; it must not synthesize a Cargo config in the
source tree. Cargo output stays under the assembly build root. Strip a copy
with the assembly's LLVM tool and stage only the copy.

The producer atomically publishes:

```text
$MOTORH/assemblies/<assembly-key>/images/rust-analyzer/
  devtools/rust/bin/rust-analyzer
  devtools/rust/lib/rustlib/src/rust/library/...
  devtools/toolchain/manifest
```

Copy `rust-src` from the validated installed prefix's
`lib/rustlib/src/rust/library`, not from an ambient rustup toolchain and not
from a second checkout. The guest paths are consequently fixed:

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
artifact tree cheap. `check.workspace` keeps its default of true; the
single-package `-p` form that rust-analyzer emits when it is false is not
accepted by Lorry. The Motor fork changes no defaults.

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
| Flycheck | `$CARGO check --workspace --message-format=json-diagnostic-rendered-ansi --manifest-path <abs> --keep-going --target <triple> [--all-targets \| --lib --bins --examples] [--target-dir <abs>]`, cwd the workspace root, env carries `CARGO_LOG` | Supported. Rejects `-p <package-id>`, `--example`, `--bench`, feature flags, `--lockfile-path`, and `-Z`. |
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
policy and warning-mode rules and is included in the process audit.

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
on save, first completion latency, resident/virtual peak memory of the server
and of the largest `lorry check` child, and maximum thread count. The first
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
- Test the exact URL fork's path conversion helpers and the inventory fork's
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
  rust-analyzer logs one sysroot error and stitches `rust-src`. The test
  expects exactly that one error and nothing else on the sysroot path; the
  rejection must be immediate, with no resolution, network, or vendor access.
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
   the RA log shows exactly the Cargo-shaped invocations and direct rustc
   discovery in sections 4.6-4.7; the process audit contains only their
   documented Lorry/rustc/build-script/native-tool/proc-macro descendants; and
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
11. **Lorry: `check`.** Add the command with rendered output, root
   `--emit=metadata`, `--all-targets`, `--keep-going`, and no-link tests.
12. **Lorry: `check --message-format=json`.** Add complete message types, the
   ANSI variant, restored-result emission, killed-child semantics, and tests
   that parse every line with `cargo_metadata` 0.23.1.
13. **Host rust-analyzer/Lorry acceptance.** Drive Lorry with the pinned Stage 1
    server on Linux, capture the actual invocation contract, and prove project
    load, build-script data, and flycheck before introducing guest variables.
    This is a Stage 2 test on Linux, not a supported Linux configuration; it
    expects exactly the one sysroot metadata error described in section 4.11.
14. **Lorry: `tree` and differential tests.** Add the required `tree` command,
    the complete Linux differential fixture against keyed Cargo, and README
    documentation.
15. **Lorry native equivalence.** Extend the native product fixture to the
    compatibility queries and all three required commands.
16. **Motor Rust: configuration and sysroot.** Make `dirs` non-Motor, return
    no native implicit config directory, and skip the sysroot `cargo metadata`
    attempt on Motor.
17. **URL fork and lock.** Add lossless Motor file-path conversion and tests;
    pin the full fork revision in the standalone rust-analyzer lock.
18. **Inventory fork and lock.** Add Motor `.init_array` registration and
    tests; pin the full fork revision.
19. **Motor Rust: child pipes.** Add the thread-based Motor implementation and
    its Linux unit test. Cross-check rust-analyzer offline. Stop for review of
    the complete external patch stack.
20. **Toolchain/assembly identity and acquisition.** Add the standalone lock
    to toolchain identity and validation, record it in assembly manifests, add
    the native recipe identity, locked source fetch, and shell contract tests,
    then select the reviewed Motor Rust revision. Keep the Stage 1
    host-component behavior unchanged.
21. **Native build and validation.** Cross-build, strip, ELF-check, hash, and
    atomically stage rust-analyzer and rust-src under the assembly key.
22. **Development image.** Add only the new assembly root to the dev image and
    test required/missing/changed overlays and standard-image exclusion.
23. **Native LSP acceptance.** Add the SSH transport, dev-image guest staging,
    flycheck and build-script assertions, multi-root case, descendant-process
    audit, and measurements. Stop for review of the first native results and
    choose the regression thresholds.
24. **Release integration and documentation.** Wire the accepted server test
    into the dev-image gate and make `full-test-dev.sh` give the repository
    suite's developer-image VM 8192 MiB by default while retaining the
    developer-source phase's existing 4096 MiB default. Add a shell-contract
    test for both assignments and the caller override. Update toolchain/build
    documentation and this status, then run the gates below.

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

The native LSP acceptance runs in an 8 GiB developer-image VM. Today the first
`full-test-dev.sh` invocation inherits `run-qemu.sh`'s 1024 MiB default, while
only `test-dev-sources.sh` receives the wrapper's 4096 MiB default; that does
not satisfy this gate. Patch 24 passes an 8192 MiB default to the repository
suite that hosts the native acceptance, retains 4096 MiB for the separate
developer-source phase, and preserves an explicit caller override. Add the
native acceptance to `src/tests/full-test.sh` only under its existing
developer-image selection, so the ordinary base/standard image gates do not
look for `/devtools/rust/bin/rust-analyzer`. All ordinary component and system
tests remain offline. Any new compiler or Clippy warning fails its owning
patch.

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
  completion, non-ASCII, and multi-root tests pass with no child other than
  the direct processes and permitted descendants in sections 4.6-4.7;
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
| Rust fork | Change no rust-analyzer defaults. Skip sysroot Cargo metadata on Motor and stitch the keyed `rust-src` directly. Carry exact-revision Motor forks for `url` and `inventory`. |
| Build scripts | `lorry check` may execute admitted build scripts with the same authority and policy as `lorry build`. Motor warning mode is unsandboxed, so clients enable checks only for trusted projects and reviewed Lorry state. |
| Procedural macros | Keep direct rust-analyzer proc-macro expansion disabled and package no proc-macro server or dylibrary. A check may still execute an admitted Motor proc-macro helper as a rustc descendant. |
| Targets and refresh | Metadata includes every supported root target; `--all-targets` checks them. Use rust-analyzer's normal client-watcher refresh and flycheck paths; add no watch mode or custom launcher. |
| Resources | Measure in the 8 GiB developer-image VM and choose numeric regression thresholds at the native-acceptance review stop. Patch 24 gives the hosting repository-suite VM 8192 MiB by default and leaves the separate developer-source phase at 4096 MiB. Memory optimization is not a Stage 2 goal. |
| Gates | Keep the developer-image gate release-only; the ordinary main-image gate still runs in debug and release. |

#### Open questions

None at present. Record any newly discovered non-obvious decision here and
stop for maintainer review before implementing past it.

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
| 17 url fork | The fork's file-path conversion module, the `cfg` list that admits slash-rooted targets. Pin in the workspace `Cargo.lock` (currently url 2.5.8). |
| 18 inventory fork | The fork's `.init_array` section `cfg` list. Pin in the workspace `Cargo.lock` (currently inventory 0.3.24). |
| 19 fork: child pipes | `crates/stdx/src/process.rs`: the `read2` implementations under `cfg(unix)`, `cfg(windows)`, and `cfg(target_arch = "wasm32")`, and their callers `streaming_output` and `spawn_with_streaming_output`. |
| 20 toolchain identity | `src/toolchain-versions.sh`: the `*_LOCK_SHA256` values, `MOTOR_OS_RUNTIME_INPUTS`. `src/toolchain-state.sh`: the before/after lock check. `src/toolchain-lib.sh`: `toolchain_key`. `src/toolchain-sources.sh`: provisioning. `src/toolchain-assembly.sh`: `toolchain_render_assembly_manifest`, `toolchain_validate_assembly_outputs`. Tests: `src/tests/test-toolchain-*.sh`. |
| 21 native build | `src/toolchain-native.sh`, `src/toolchain-assembly.sh` (the `rustc` image recipe and `ASSEMBLY_IMAGE_ROOT`), `docs/toolchain.md`, `docs/libc.md` for the startup-path statement. |
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
