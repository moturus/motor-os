# rust-analyzer for Motor OS development

Status 2026-08-31: Stage 1 is complete and gated. Section 3 is now maintained
documentation for running rust-analyzer on a Linux host while developing
Motor OS; it is no longer an implementation plan or patch history. Section 4
contains the detailed implementation design for Stage 2, the native Motor OS
guest. Stage 2 has not been implemented or gated, and this plan does not
define a product Stage 3.

2026-08-29. Initial investigation and staged plan for using the rust-analyzer
snapshot embedded in the Motor Rust source tree. Stage 1 has since delivered
the Linux-host service documented in section 3. Stage 2 will run
rust-analyzer inside a Motor OS development VM.

Revised 2026-08-30: Stage 1 analyzes two targets from the same keyed
toolchain, `x86_64-unknown-motor` and the Linux host target
`x86_64-unknown-linux-gnu`; Stage 2 analyzes `x86_64-unknown-motor` only.
Custom JSON target specifications are out of scope in both stages. Section 3.5
records the verified reason and the deferred boundary.

An earlier investigation on 2026-08-13 proved that a patched rust-analyzer can
compile, link, and complete an LSP lifecycle natively on Motor OS. Temporary
source copies and dependency patches under `/tmp` were used for that prototype;
none of them are repository state.

## 0. Staging decision

Both stages are required:

| Stage | Server host | Analyzed targets | Status |
|---|---|---|---|
| 1. Host | Linux | Motor and Linux host | Complete; maintained documentation |
| 2. Guest | Motor OS | Motor only | Detailed design; not implemented |

Stage 1 supplies a maintained Linux-host rust-analyzer, repeatable semantic
fixtures, an exact project schema, and a bounded LSP harness. Section 3
documents that current host capability. Section 4 uses it as the baseline for
the native build, Lorry project export, patch sequence, tests, and release
gates. Review that design before beginning Stage 2 implementation.

The two outputs are distinct even though they use the same pinned source:

```text
$MOTORH/toolchains/<toolchain-key>/bin/rust-analyzer
    Linux executable; part of the immutable host Rust toolchain

$MOTORH/assemblies/<assembly-key>/images/rust-analyzer/
    Motor executable and rust-src overlay; development image only
```

The host artifact is keyed by compiler inputs. The native artifact also
depends on the assembly sysroot, linker, mlibc startup, and native dependency
ports, so it belongs to the assembly key. Do not copy one artifact into the
other location or try to make one executable serve both hosts.

## 1. Common goals and constraints

The complete effort will:

- use the in-tree `src/tools/rust-analyzer` snapshot from the same effective
  Motor Rust revision as rustc;
- analyze `cfg(target_os = "motor")` with the matching Motor standard-library
  sources rather than an ambient stable or nightly sysroot;
- in Stage 1, also analyze the checkout's Linux host programs for
  `x86_64-unknown-linux-gnu` with the same keyed toolchain's host std;
- keep generated artifacts in exact key-qualified locations;
- keep normal tests offline and deterministic;
- introduce no boot-time work;
- use editor-neutral standard LSP and `rust-project.json` contracts, with
  Lorry owning the native project description rather than a future client;
- keep each implementation patch near 100-300 lines including tests; and
- introduce no compiler or Clippy warnings and format Rust changes with the
  repository-selected toolchain.

The initial effort will not:

- make the repository root one homogeneous Rust workspace or assign one target
  to Linux host tools, Motor userspace, the kernel, and the loader;
- support custom JSON target specifications, including the kernel and loader
  targets, or any analyzed target other than `x86_64-unknown-motor` and, in
  Stage 1 only, `x86_64-unknown-linux-gnu`;
- port Cargo to Motor OS;
- port, configure, or otherwise modify a text editor, Helix, Red, Gears, or
  any other LSP consumer as part of Stage 2;
- add dynamic linking or general ELF constructor execution to the pure-Rust
  Motor process startup;
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
macros. This is the stable, editor-neutral project-description seam reused by
the Stage 2 Lorry export. Generated descriptions must contain current
key-qualified absolute paths; do not check a developer home directory or a
toolchain key into a static JSON file.

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

### 4.1 Scope and fixed design choices

Stage 2 cross-builds rust-analyzer as a Motor OS process, packages it only in
the development image, and gives it an exact Motor crate graph generated by
Lorry. It analyzes only `x86_64-unknown-motor`. The server speaks the ordinary
rust-analyzer stdio LSP protocol; Stage 2 adds no proxy, socket protocol, or
Motor-specific LSP messages.

Stage 2 has three deliverables:

1. an assembly-keyed native `rust-analyzer` plus the matching `rust-src`;
2. a deterministic `lorry rust-project` command that publishes the selected
   Lorry package as the pinned rust-analyzer `rust-project.json` schema; and
3. repository tests that drive the native server over stdio through SSH and
   prove project load and semantic results in the normal 1 GiB VM.

This stage deliberately contains no consumer. In particular, it does not port
or configure Helix, Red, Gears, an agent harness, or an editor extension. It
also does not design client restart policy, buffer synchronization, UTF-16
position conversion, UI behavior, or project refresh UX. A future consumer may
launch this server and use the generated project file through standard LSP and
rust-analyzer configuration, but that is a separate plan.

The following choices are part of this design rather than deferred decisions:

- use mlibc process startup to execute `.init_array`; do not change
  `motor_start` or the Rust standard library;
- carry the minimal rust-analyzer changes in the selected Motor Rust fork and
  use exact-revision Motor forks only for the two registry crates that require
  target support;
- generate a stable project file with Lorry rather than port Cargo;
- allow no implicit native user-configuration directory initially;
- disable rust-analyzer build-script execution, proc-macro expansion, checks,
  and server-side filesystem watching by default on Motor; and
- omit run/check/test commands from the project description.

### 4.2 Baseline evidence

The maintained Stage 1 baseline is currently:

```text
Motor Rust revision: 3c9729fb79778d71daabbff78319a8b9535c340b
rust-analyzer:        1.99.0-dev (3c9729fb797 2026-08-29)
inventory:            0.3.24
url:                  2.5.8
dirs:                 6.0.0
salsa:                0.28.2
ra-ap-rustc_*:        0.166
```

The implementation will necessarily select a later Motor Rust revision that
contains the native patches, so these values are the reviewed starting point,
not hard-coded final output. The final binary's version, Rust revision,
standalone lock digest, and fork revisions must be recorded by the assembly.

The 2026-08-13 prototype used the same native architecture. After temporary
compatibility changes for `dirs`, rust-analyzer's child-pipe reader, and `url`,
this cross-check completed:

```sh
RUSTC="$RUST/build/$HOST/stage2/bin/rustc" \
  cargo check --locked --offline \
  --manifest-path "$RUST/src/tools/rust-analyzer/Cargo.toml" \
  --target x86_64-unknown-motor -p rust-analyzer
```

A pure-Rust-linked executable was approximately 28 MiB stripped and answered
`--version` and `initialize`, but Salsa registrations were absent because
`inventory` emitted no Motor ELF constructors. Classifying Motor as an ELF
`.init_array` platform and linking through `motor-rust-cc` produced an
approximately 29 MiB static PIE. In a 1 GiB, four-vCPU VM it answered
`--version`, initialized, loaded an inline project, became quiescent, shut
down, and exited cleanly.

That result proves the basic process, pipe, thread, file-URI, Salsa, and LSP
lifecycle. It does not replace the production source pinning, Lorry graph,
semantic tests, or resource measurements below.

### 4.3 Source, dependency, and identity model

The native binary uses
`$RUST/src/tools/rust-analyzer` from the exact effective Motor Rust revision
selected by `src/toolchain-versions.sh`. Unlike the Stage 1 bootstrap tool, it
is built without `in-rust-tree`. The native closure therefore uses the
standalone workspace lock and `ra-ap-rustc_*` crates rather than dynamically
linking the bootstrap compiler's `librustc_driver`.

Source changes are maintained as follows:

- rust-analyzer target conditionals and the Motor child-pipe implementation
  live in the Motor Rust fork beside the in-tree rust-analyzer source;
- `url 2.5.8` and `inventory 0.3.24` use minimal Motor forks pinned to full Git
  revisions by the standalone rust-analyzer workspace and its lockfile;
- `dirs` is not forked: rust-analyzer does not compile that dependency for
  Motor and returns no implicit user configuration directory there; and
- no source is patched in place under a managed checkout, copied from `/tmp`,
  or fetched by a regular test.

The complete provisioning command may acquire the locked registry and Git
sources while it is already in its managed network-enabled source-provisioning
phase. Before the native build, it runs the selected host Cargo's equivalent
of `cargo fetch --locked --target x86_64-unknown-motor` for the standalone
rust-analyzer manifest. The check and build themselves use `--locked
--offline`. Authoring mode uses the supplied Rust tree and the same lock
contract; neither mode may rewrite the lock.

Identity changes are fail-closed:

- add the standalone rust-analyzer `Cargo.lock` digest to toolchain state and
  key validation so an authoring lock change cannot reuse a host prefix;
- increment the native-configuration identity schema and include a native
  rust-analyzer recipe version in it;
- add every new Motor OS helper used by that recipe to
  `MOTOR_OS_RUNTIME_INPUTS` rather than leaving unkeyed executable logic;
- let the effective Motor Rust revision identify the in-tree source and exact
  fork declarations; and
- record the final version string, binary SHA-256, standalone lock SHA-256,
  rust-src tree digest, and native recipe version in
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
| Configuration | Compile `dirs` only for non-Motor targets. `Config::user_config_dir_path()` returns `None` on Motor. Motor defaults turn off build scripts, proc macros, checks, and server watching; explicit LSP configuration remains possible. | Cross-check has no `dirs-sys` Motor edge; initialize with no HOME/XDG variables succeeds and reads no implicit config file. |
| Child stdout/stderr | Add a Motor branch to `stdx::process::read2` using two standard Rust reader threads and a bounded chunk channel. Both pipes are drained concurrently; the coordinator alone invokes callbacks and propagates the first read/join failure. There is no polling, retry, shell, or dependency on Unix file descriptors. | A platform-neutral unit test covers interleaved output, either pipe closing first, partial final lines, output above pipe capacity, and reader error; a guest child test covers the Motor branch. |
| File URIs | In the exact `url` fork, treat Motor as an absolute, slash-rooted, UTF-8 path platform. Reject relative paths, authorities, invalid UTF-8, and malformed percent escapes; never classify Motor as Unix or use Unix `OsStrExt`. | Fork unit tests round-trip root, spaces, `%`, `#`, and non-ASCII names and reject the negative cases; the guest semantic test opens a non-ASCII path. |
| Salsa registration | In the exact `inventory` fork, emit Motor constructor pointers in `.init_array`. Link rust-analyzer through the assembly wrapper so mlibc startup walks the array. Do not add constructor walking to Rust startup. | A small native inventory fixture observes more than one registration; ELF validation requires nonempty `.init_array`; the LSP database reaches quiescence. |
| Allocator and workers | Leave optional jemalloc/mimalloc features off. Verify `num_cpus` against Motor's standard-library result and use an explicit native default worker count only if the 1 GiB measurements require it. | Record available CPUs, rust-analyzer threads, and peak memory; a worker cap needs its own measured justification. |
| Filesystem changes | Keep the upstream client-watcher mode. Do not add a polling watcher or port a host notify backend in Stage 2. | Project load performs no periodic filesystem scan or watcher child process; standard `didOpen`/`didChange` drives the semantic test. |

The pipe channel bounds queued chunks, not total command output. Existing
rust-analyzer callers still own their final output buffers. Native defaults do
not start Cargo-like commands; the only required child commands are exact
`/devtools/bin/rustc` queries for sysroot, target cfg, and target metadata.

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
  "$TOOLCHAIN_PREFIX/bin/cargo" build --release --locked --offline \
  --manifest-path "$RUST/src/tools/rust-analyzer/Cargo.toml" \
  --target x86_64-unknown-motor -p rust-analyzer
```

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
rustc:       /devtools/bin/rustc
sysroot:     /devtools/rust
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
must not contain the server or rust-src. Nothing launches rust-analyzer during
image construction or boot.

### 4.6 Runtime and LSP contract

The supported server command is exactly the native binary in stdio mode. It
uses LSP/JSON-RPC framing on stdin/stdout and diagnostics/logging on stderr.
There is no daemon, TCP listener, shell wrapper, Lorry proxy, or custom
framing. Standard initialize, initialized, text-document, progress,
configuration, shutdown, and exit messages remain rust-analyzer's upstream
protocol.

For the Stage 2 supported profile, initialization names one or more generated
project files through rust-analyzer's `linkedProjects` setting and leaves
Cargo discovery disabled. Native defaults are:

- `cargo.buildScripts.enable = false`;
- `procMacro.enable = false`;
- `checkOnSave = false`; and
- `files.watcher = "client"`.

The project file itself supplies sysroot, sysroot source, crate roots, and
compile context. Rust-analyzer may query `/devtools/bin/rustc`, but it must not
invoke Lorry, Cargo, a build script, a proc macro, a check command, or a
workspace-discovery command during the accepted session. Tests inspect the
process tree and Lorry trace rather than assuming this from a quiet log.

A consumer may later send standard configuration changes, file notifications,
and multiple linked projects. How it discovers the project-file path, decides
when to regenerate/reload it, bounds its own queues, or presents server
failures is outside Stage 2.

### 4.7 Lorry ownership and command boundary

Lorry already owns the exact package selection, target evaluation, default
features, dependency resolution, admission evidence, source remapping,
build-script directives, and rustc environment. The project exporter must use
those structures directly. It must not independently reinterpret Cargo.toml,
Cargo.lock, `.cargo` configuration, target cfg expressions, or dependency
aliases.

Add this machine-stable command:

```text
lorry rust-project [-p NAME] [--target TRIPLE] [--strict-validation]
```

There is intentionally no `--release`, `--bin`, child-argument, run, or watch
mode. The graph represents Lorry's development/test analysis view with the
selected package's default feature set. Package selection and target defaults
match existing Lorry commands: on Motor the native default is
`x86_64-unknown-motor`; a Linux test requests that target explicitly.

On success the command atomically publishes one directory beneath the selected
package's existing Lorry artifact root:

```text
target/lorry[/packages/<package>]/rust-project/<triple>/
  rust-project.json
  state
  sources/...
  out/...
```

Stdout contains only the absolute UTF-8 path to `rust-project.json` followed by
a newline. Progress and diagnostics use stderr and existing color/verbosity
rules. `state` is a Lorry-owned versioned identity record; no nonstandard field
is added to the rust-analyzer JSON. `lorry clean` removes the analysis tree
when it removes the corresponding all-target or selected-target Lorry tree.

`lorry rust-project` is offline and may write only its generated analysis tree.
It may resolve, verify, extract, copy, and restore cache data, but it must not:

- invoke Cargo or a shell;
- compile a crate;
- execute a build script, proc macro, target binary, or other package code;
- contact a registry, Git remote, or other network resource; or
- alter a manifest, lockfile, admission record, vendor object, or normal build
  profile.

Use Lorry's existing `serde` and `serde_json` dependencies with dedicated
private output structs matching the pinned `ProjectJsonData` schema. This adds
no product dependency. Serialize vectors in defined order and maps from
`BTreeMap`, terminate the file with one newline, and use the existing atomic
directory and safe-path machinery.

### 4.8 Stable source and build-output views

Rust-analyzer needs source paths that remain valid after the command exits.
Lorry's current crates.io preparation extracts verified archives into a build
staging directory owned by `PreparedGraph`; those paths disappear when the
prepared graph is dropped. The exporter must therefore publish an analysis
source view before dropping it.

The source rules are:

- selected workspace packages and ordinary path dependencies point to their
  admitted live physical roots so edits remain visible;
- verified registry and immutable Git packages are copied into
  `sources/<source-identity>/<package-identity>` under the analysis directory;
- source identity includes Lorry's checksum/tree evidence, not merely name and
  version;
- an existing immutable source view is reused only after its state and tree
  digest validate; and
- copies retain admitted files and relevant modes but never hard-link mutable
  workspace input into generated state or follow a link outside an admitted
  root.

Apply existing package count, tree byte, entry, path-length, and file-size
limits to the published view. All paths placed in JSON are canonical absolute
UTF-8 paths inside the sysroot, selected workspace/path roots, or the freshly
published analysis directory. Reject non-UTF-8, missing, linked-root, escaping,
duplicate-identity, and overlapping-root cases.

Dependency build scripts need a separate rule. A manifest-only graph can be
wrong when a script supplies `rustc-cfg`, `rustc-env`, `OUT_DIR`, or generated
Rust source. The exporter therefore asks a new cache-only executor to restore
the exact development dependency plan into analysis staging:

- if the graph has no dependency build scripts, no cache restoration is
  required;
- if every required unit and build-script result is present and validates in
  Lorry's existing caches, restore it without spawning a process;
- copy only required `OUT_DIR` trees into `out/` for final publication and
  discard restored compiler artifacts from staging; and
- if any required record is missing, stale, malformed, non-UTF-8 where JSON
  needs text, or inconsistent with the selected graph, fail and tell the user
  to run the corresponding explicit `lorry build` first.

Running `lorry build` is the user's explicit authorization to compile and run
admitted dependency build scripts. `lorry rust-project` never turns a cache
miss into execution. Cache-only mode shares unit identity, freshness,
admission, output limits, directive parsing, and path relocation with the
normal executor; it is not a second cache format.

For language analysis, retain `rustc-cfg` directives, `rustc-env` values, and
the relocated `OUT_DIR`. Link search/library/argument directives and Cargo
metadata affect linking or downstream build scripts, not the crate graph, and
are omitted. Add each relevant `OUT_DIR` to that crate's source include set so
`include!` and generated modules can load.

### 4.9 Exact project-graph mapping

Generate the crate array from Lorry's selected `Resolution` and development
`CompilationPlan`, not from artifact filenames. Every reachable
`UnitKind::Library` or `UnitKind::ProcMacro` with a distinct compile kind or
feature set is a distinct project crate. Build-script compile/run units are not
project crates. Append selected root targets in the stable order library,
binaries by name, then integration tests by name.

The mapping is:

| rust-analyzer field | Lorry source of truth |
|---|---|
| `sysroot` / `sysroot_src` | The selected toolchain sysroot and its validated rust-src. Native output uses the fixed `/devtools/rust` paths. |
| `display_name`, `version`, `edition` | Prepared package or selected root manifest; crate names are normalized exactly as Lorry passes them to rustc. |
| `root_module` | Target path restored to a stable physical source root, never the logical path used only for rustc remapping. |
| `deps[].crate` | Index of the exact dependency unit selected by the Lorry unit edge. |
| `deps[].name` | The edge alias visible to rustc after Lorry's dash-to-underscore normalization. Duplicate visible aliases are errors. |
| `cfg` | Selected target's `rustc --print cfg`, unit `feature="..."` values, semantic `--cfg` rustflags, and restored `rustc-cfg` output. `cfg(test)` and `rust_analyzer` are left to rust-analyzer for workspace members. |
| `target` | Exact installed triple; Stage 2 accepts only `x86_64-unknown-motor`. |
| `env` | Lorry's shared pure Cargo/rustc environment helper plus restored `rustc-env` and relocated `OUT_DIR`; omit linker/runtime-only variables. |
| `source` | Minimal admitted package root plus relocated generated source, with `target`, `.git`, and unrelated Lorry artifact trees excluded. |
| `is_workspace_member` | True only for selected root targets. Every dependency is false, including another declared workspace member reached as a path dependency; Lorry analyzes that package as a dependency unless it is selected separately. |
| `is_proc_macro` | True for a Lorry proc-macro unit; `proc_macro_dylib_path` is omitted in Stage 2. |
| `repository` | Valid UTF-8 package metadata when present. |
| `build` | Opaque stable Lorry label, defining Cargo.toml path, and `lib`, `bin`, or `test` target kind. |
| `runnables` | Always an empty array in Stage 2. |

Root binaries and integration tests depend on the selected package library
when it exists, using the library crate name Lorry passes through `--extern`.
Root normal dependencies attach using `Resolution::root_edges`. Dependency
libraries attach only their applicable normal edges. Use Lorry's currently
supported root dependency model; do not silently add ignored root
dev-dependencies or root build-dependencies to make the analysis graph look
more Cargo-like than the build graph.

Use one shared cfg group for the base Motor target cfg and per-crate additions
for features and build output. Stable crate ordering is dependency-plan order
followed by root-target order; dependency indices are assigned only after that
order is fixed. Reject a missing root, edge to an omitted unit, invalid crate
alias, feature/context mismatch, unsupported custom target, or semantic env
value that cannot be represented losslessly in JSON.

One Lorry invocation describes one selected package. A multi-root LSP session
uses multiple generated paths in `linkedProjects`; Lorry does not merge
unrelated selected packages or invent a workspace-discovery protocol.

### 4.10 Procedural macros, checks, and refresh boundary

Lorry now supports Motor-native procedural macros: it compiles a proc macro as
a static PIE helper and rustc communicates with that helper using Lorry's
private framed stdio registration protocol. The previous claim that Lorry
needed general dylibrary support is obsolete.

That helper is nevertheless not a rust-analyzer proc-macro artifact.
Rust-analyzer's pinned `rust-analyzer-proc-macro-srv` is an `in-rust-tree`
compiler-private binary that loads compiler-produced proc-macro libraries. The
standalone non-`in-rust-tree` native build cannot provide it, and the project
schema field remains named `proc_macro_dylib_path`. Stage 2 therefore:

- preserves proc-macro crate source and dependency edges with
  `is_proc_macro = true`;
- emits no `proc_macro_dylib_path`;
- does not package `rust-analyzer-proc-macro-srv`;
- defaults `procMacro.enable` to false; and
- tests that no Lorry proc-macro helper is launched by rust-analyzer.

Declarative macros continue to work. Code requiring procedural expansion is
visibly incomplete rather than executed through an incompatible protocol. An
adapter or native compiler-private proc-macro server is separate future work,
not a hidden Stage 2 subtask.

Likewise, Stage 2 emits no flycheck, run, test, debug, or discovery runnable
and never starts `lorry check` on save. A future consumer/check design must
define cancellation, diagnostic JSON, concurrency with foreground builds, and
authorization before adding those commands.

The generated file is a snapshot. `lorry rust-project` regenerates it
atomically when explicitly invoked. Automatic file watching, server reload,
and restart policy belong to the consumer; Stage 2 only proves that a fresh
file can be loaded at initialization and that two files can be loaded as a
multi-root session.

### 4.11 Security and resource rules

The native server runs with the invoking user's authority and is not a boot or
privileged service. Even so, the supported path is deliberately inert:

- use absolute executable and project paths and process argument arrays;
- give the test process a minimal explicit environment with
  `TMPDIR=/devtools/tmp` and no Cargo network variables that could enable
  access;
- accept project paths only from Lorry's admitted roots and validated generated
  state;
- perform no package execution while generating or loading the project;
- keep failures visible and do not add automatic restarts, retries, ignored
  errors, or longer timeouts;
- retain the Stage 1 harness's frame, stderr, message, progress, and total
  deadline bounds; and
- add no executable compression or startup decompression.

Lorry's existing policy limits bound package count/depth and source/output
trees. Add explicit JSON byte and crate/edge counts derived from those same
limits, with checked arithmetic before allocation. The project exporter must
reject an output that exceeds them rather than truncate it.

Record the following in the final gate on a four-vCPU, 1 GiB VM: stripped
binary size, rust-src and total image growth, time to initialize, time to
quiescence, first completion latency, resident/virtual peak memory, and maximum
thread count. The prototype's approximately 29 MiB binary is the comparison
point. The first maintained measurement establishes explicit future regression
thresholds; do not choose a worker cap or hide a failure merely to meet an
unreviewed number.

### 4.12 Test design

The tests are layered so a failure is attributable before a full image run.

**Motor Rust and dependency tests**

- Run the exact standalone workspace's relevant host unit tests, then
  `cargo check --release --locked --offline --target
  x86_64-unknown-motor -p rust-analyzer`.
- Test the portable pipe coordinator on Linux and the Motor implementation in
  a guest helper whose stdout and stderr each exceed pipe capacity.
- Test the exact URL fork's path conversion helpers and the inventory fork's
  registration list; do not rely only on rust-analyzer startup.
- Assert the standalone lock remains byte-identical and the Motor graph has no
  `dirs-sys` edge or optional allocator feature.

**Lorry focused and product tests**

- Unit-test stable ordering and every field in section 4.9, including renamed
  dependencies, target-specific edges, distinct host/target feature contexts,
  selected-root membership, binaries, integration tests, non-ASCII paths,
  cfg/env escaping, and all fail-closed cases.
- Add a contract fixture with a verified registry dependency, a path
  dependency, generated `OUT_DIR` Rust, and build-script cfg/env. Prove a cold
  project export refuses to execute, an explicit build populates the cache,
  and a later export restores only admitted analysis data.
- Trace child creation and network entry points so the no-execution/no-network
  rule is affirmative, not inferred from successful output.
- Extend the native Lorry fixture to generate the same supported
  proc-macro-free project on Linux-cross and Motor-native Lorry. Normalize only
  declared host roots/sysroot paths, then require identical crate identities,
  edges, cfgs, env, and source digests.
- Add a negative proc-macro fixture proving the graph marks the crate but emits
  no executable/dylib path.

**Native rust-analyzer semantic test**

Extend `src/tests/rust-analyzer-smoke`; do not create a second LSP protocol
harness. Add a child-command transport that can run
`/devtools/rust/bin/rust-analyzer` through the existing SSH path while keeping
the harness on Linux. Stage fixtures under a known guest workspace, run native
`lorry rust-project`, read its one-line path, and initialize rust-analyzer with
that generated path.

The accepted session must prove:

1. `--version` matches the assembly manifest;
2. initialize/initialized and workspace health reach `ok` and quiescent;
3. one real Motor diagnostic is published;
4. hover, go-to-definition into Motor std, and completion return semantic
   results;
5. a non-ASCII file URI and UTF-16 request position round-trip correctly in
   the test harness;
6. two separately selected Lorry packages load together through two
   `linkedProjects` entries;
7. rust-analyzer starts only the allowed rustc queries and no Cargo, Lorry,
   build-script, proc-macro, check, or watcher process; and
8. shutdown, exit, EOF, stderr capture, and child status complete within the
   existing bounded deadline.

This is a server acceptance test, not an editor test. No test launches Helix,
Red, Gears, or another consumer.

### 4.13 Incremental patch sequence

Keep each implementation patch near 100-300 changed lines including focused
tests. The repositories and review stops are explicit:

1. **Motor Rust: native configuration boundary.** Make `dirs` non-Motor,
   return no native implicit config directory, and set inert Motor defaults.
2. **URL fork and lock.** Add lossless Motor file-path conversion and tests;
   pin the full fork revision in the standalone rust-analyzer lock.
3. **Inventory fork and lock.** Add Motor `.init_array` registration and tests;
   pin the full fork revision.
4. **Motor Rust: child pipes.** Add the standard-thread Motor pipe reader and
   portable coordinator tests. Cross-check rust-analyzer offline. Stop for
   review of the complete external patch stack.
5. **Toolchain identity and acquisition.** Add the standalone lock/key fields,
   native recipe identity, locked source fetch, and shell contract tests;
   select the reviewed Motor Rust revision.
6. **Native build and validation.** Cross-build, strip, ELF-check, hash, and
   atomically stage rust-analyzer and rust-src under the assembly key.
7. **Development image.** Add only the new assembly root to the dev image and
   test required/missing/changed overlays and standard-image exclusion.
8. **Lorry project model.** Add private deterministic JSON types and pure
   mapping from prepared resolution/unit data, with golden and negative unit
   tests. Stop for review of the schema mapping.
9. **Lorry analysis sources.** Atomically materialize verified stable source
   views with existing limits, identities, and clean integration.
10. **Lorry cache-only outputs.** Restore required build-script results without
    execution and map cfg/env/OUT_DIR; fail on a cache miss.
11. **Lorry command.** Add CLI/help/dispatch, final publication/state, one-line
    output contract, README documentation, and Linux contract fixture.
12. **Lorry native equivalence.** Extend the native product fixture and add
    the proc-macro-path negative case.
13. **Native LSP acceptance.** Extend the bounded Stage 1 harness, dev-image
    guest staging, multi-root case, semantic assertions, process audit, and
    measurements. Stop for review of the first native results.
14. **Release integration and documentation.** Wire the accepted server test
    into the dev-image gate, update toolchain/build documentation and this
    status, then run the gates below.

No patch in this sequence contains consumer code. Do not combine the Motor
Rust fork changes, Lorry graph changes, image publication, and native semantic
test into one unreviewable cutover.

### 4.14 Gates and completion criteria

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

The dev-image repository phase runs the native LSP acceptance in the normal 1
GiB VM; the later native-source/Lorry phase may use its established 4 GiB
compiler profile. All ordinary component and system tests remain offline. Any
new compiler or Clippy warning fails its owning patch.

Stage 2 is complete only when all of the following are true:

- the assembly validates and records the exact native server, lock, rust-src,
  and recipe identities;
- only the development image contains the server and rust-src overlay;
- cross-check, ELF checks, URL, pipe, and inventory tests pass;
- `lorry rust-project` is deterministic, offline, cache-only, atomically
  published, and semantically equivalent across the supported Linux-cross and
  Motor-native fixture;
- build-script-dependent graphs are exact after an explicit build and fail
  visibly without the required cache state;
- native standard-LSP lifecycle, diagnostic, hover, definition, completion,
  non-ASCII, and multi-root tests pass with no forbidden child process;
- the clean build and three final gates pass; and
- resource measurements and future regression thresholds are recorded.
